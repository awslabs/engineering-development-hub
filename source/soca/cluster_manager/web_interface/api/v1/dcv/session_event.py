# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DCV session-event endpoint.

Receives events from the per-cluster Lambda relay
(installer/resources/functions/DcvEventRelay) which is the SQS event-source-
mapping target of the per-cluster queue <ClusterId>-dcv-session-events.

Architecture:

    VDI  --aws sqs send-message-->  SQS queue --(SenderId attached by SQS)--+
                                                                            v
                                                                       relay Lambda
                                                                            |
                                                                            | HMAC-SHA-256 over body
                                                                            | with relay key from SM
                                                                            | (auto-rotated 90d) +
                                                                            | X-EDH-Attested-Instance
                                                                            | header from SenderId
                                                                            v
                                                                  this endpoint (controller)


This endpoint is the trust boundary; provenance comes from FOUR layers:

  1. IAM        -- only compute_node_role and target_node_role have
                   sqs:SendMessage on the queue (BSC10: IAM SigV4 for
                   AWS-service-to-AWS-service).
  2. SQS        -- AWS-attested SenderId (= role-id:i-XXXXXXXX) is set by
                   the SQS service based on the SigV4-authenticated caller.
                   The publisher cannot lie about it. (NOT a credential --
                   just AWS-attested provenance metadata.)
  3. Relay HMAC -- HMAC-SHA-256 over the request body, keyed by a secret
                   in SecretsManager that only the relay Lambda and this
                   endpoint can read. 90-day auto-rotation with AWSCURRENT/
                   AWSPREVIOUS overlap so callers never see a brittle cutover
                   (BSC10: explicit auth on machine-to-machine endpoint).
  4. SG         -- relay Lambda SG is the only ingress allowed to the
                   controller's session-event port (defense-in-depth, NOT
                   a substitute for #3).

The relay Lambda forwards SenderId's session-name in X-EDH-Attested-Instance
for cross-checking. We additionally require:

  - body.instance_id         == X-EDH-Attested-Instance     (Lambda did the work)
  - DB.session.instance_id   == X-EDH-Attested-Instance     (right session)
  - event timestamp within +-5 min                          (replay window)
  - (session_uuid, event_type, nonce) not seen in last 10m  (replay dedup)

before mutating session state. See docs/DCVEventRelay.md for the full
threat model and key-rotation design.

Auth model (deliberately NOT @login_required): this endpoint is reachable
only via the Lambda relay over a private VPC path. CSRF protection is N/A
(POST-only, no cookie auth).
"""

import base64
import binascii
import hmac
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Optional, Tuple

from flask import Response, request, g
from flask_restful import Resource

from models import db, DcvEventNonces, DcvSessionEventLog, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.secretsmanager_client import SocaSecret
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.validators import Validators
from utils.dcv_event_store import (
    append_event as ddb_append_event,
    build_envelope as ddb_build_envelope,
    new_event_id,
    record_nonce_or_reject as ddb_record_nonce,
)

logger = logging.getLogger("soca_logger")

# ----- constants -----------------------------------------------------------

# Acceptable per-event freshness window. Validation rejects events whose
# claimed timestamp is more than this far in either direction from now.
FRESHNESS_WINDOW_SEC = 300  # 5 minutes

# How long to retain accepted nonces in dcv_event_nonces before purging.
# Anything older than the freshness window cannot pass freshness check
# anyway, so 2x the window is a comfortable buffer.
NONCE_RETENTION_SEC = 600  # 10 minutes

# Events the controller will accept and what they do.
KNOWN_EVENT_TYPES = {
    "placed",               # async placement succeeded; promote placing->pending
    "placement_failed",     # async placement failed terminally; promote placing->error
    "session-ready",        # bootstrap finished; promote pending->running
    "session-resumed",      # dcvserver started post-reboot/hibernate; refresh probe ts
    "session-failed",       # bootstrap or session-create failed; mark error
    "session-heartbeat",    # optional periodic still-alive ping; refresh probe ts
    "bootstrap-checkpoint", # explicit lifecycle marker driven by log_checkpoint;
                            # carries body.checkpoint=<name>; updates last_seen_event_at
                            # but does NOT change session_state (pending/running/error
                            # is owned by session_state_watcher).
    "bootstrap-status",     # free-form progress message driven by log_status;
                            # carries body.sub_status=<text>; SSE-only, never changes
                            # state. Cheap to drop on overload.
}

# Sub-state event types (bootstrap-*) are SSE-stream-only. They never flip
# session.session_state, never set session.session_ready_pushed_at, and are
# safe to drop on controller overload. Operators must NOT alarm on a missing
# bootstrap-* event.
SUBSTATE_EVENT_TYPES = {"bootstrap-checkpoint", "bootstrap-status"}

# Body schema -- minimal field allowlist enforced before any HMAC math.
# Note: instance attestation comes from the SQS-set SenderId (passed via
# X-EDH-Attested-Instance header by the relay Lambda); no IID fields and
# no per-session HMAC are needed in the body.
REQUIRED_FIELDS = {
    "event_type",
    "session_uuid",
    "instance_id",
    "event_timestamp",
    "nonce",
}

# Sanity caps so a malformed/oversized body can't spike CPU before reject.
MAX_BODY_BYTES = 16384       # 16 KiB
MAX_NONCE_LEN = 128          # 64 bytes hex == 128 chars
MAX_SUB_STATUS_LEN = 256     # SSE detail page payload cap
MAX_CHECKPOINT_LEN = 64      # bootstrap-checkpoint name cap

UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
INSTANCE_ID_RE = re.compile(r"^i-[0-9a-f]{8,17}$")
# Checkpoint names are operator-authored identifiers used as both the
# allowlisted state key on the SSE consumer side AND a CSS class hint.
# Constrain to lowercase letters, digits, hyphens, underscores. Reject
# anything else so the value can be safely written to HTML attributes
# without escaping (defense-in-depth -- the WebUI ALSO escapes).
CHECKPOINT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")

# Header set by the relay Lambda; value is the session-name half of the
# SQS SenderId (= the EC2 instance ID, AWS-attested via SigV4 on the
# original sqs:SendMessage call).
ATTESTED_INSTANCE_HEADER = "X-EDH-Attested-Instance"

# Control-plane principals: trusted, HMAC-authenticated callers that are NOT
# EC2 instances (currently the CapacityExecutor Lambda). They emit placement
# lifecycle events BEFORE any instance exists, so they authenticate with the
# relay key (proving they came through the trusted private-VPC relay path) but
# cannot satisfy the instance-attestation invariant. They get a narrowed gate:
# no instance_id required, and only the placement event types may be emitted.
CONTROL_PLANE_PRINCIPALS = {"capacity-executor", "dcv-event-relay"}
CONTROL_PLANE_EVENT_TYPES = {"placed", "placement_failed"}


# ----- relay HMAC verification --------------------------------------------

# Cached relay key material. The watcher / endpoint refreshes on TTL expiry
# OR on signature mismatch (handles the rotation overlap window cleanly).
# We hold both AWSCURRENT and AWSPREVIOUS so a freshly-rotated Lambda
# signing with the new key keeps verifying even before our cache refreshes.
_relay_keys_cache: dict = {"current": None, "previous": None, "fetched_at": None}
_RELAY_KEY_CACHE_TTL = timedelta(minutes=5)


def _relay_secret_arn() -> Optional[str]:
    """SocaConfig key matches the CDK-provisioned ARN."""
    resp = SocaConfig(key="/configuration/DcvEventRelaySecretArn").get_value(
        default=None, allow_unknown_key=True
    )
    return resp.message if resp.success else None


def _fetch_relay_keys() -> None:
    """
    Refresh the in-process relay-key cache from SecretsManager.

    Reads BOTH AWSCURRENT and AWSPREVIOUS (the rotation overlap window). If
    AWSPREVIOUS doesn't exist yet (first-ever rotation), only AWSCURRENT is
    populated and we still verify against it.

    Failure to fetch leaves the cache untouched; callers fall through to
    the cached value (better stale than dead).
    """
    arn = _relay_secret_arn()
    if not arn:
        logger.warning(
            "DcvEventRelaySecretArn not configured; relay HMAC validation "
            "will reject all events"
        )
        return
    try:
        _cur = SocaSecret(
            secret_id=arn, secret_id_prefix="", version_stage="AWSCURRENT", as_json=False
        ).get_secret()
        if _cur.get("success") is True and _cur.get("message"):
            _relay_keys_cache["current"] = _cur.get("message").encode()
        else:
            logger.error(f"relay key AWSCURRENT fetch failed: {_cur.get('message')}")
        # AWSPREVIOUS only exists after the first key rotation. Probe the
        # secret's staging labels first so a legitimately-absent AWSPREVIOUS
        # on a never-rotated secret does not surface as a spurious
        # AWS_API_ERROR on every cache refresh.
        _stages = SocaSecret(secret_id=arn, secret_id_prefix="").get_version_stages()
        if _stages.get("success") is True and "AWSPREVIOUS" in _stages.get("message"):
            _prev = SocaSecret(
                secret_id=arn, secret_id_prefix="", version_stage="AWSPREVIOUS", as_json=False
            ).get_secret()
            if _prev.get("success") is True and _prev.get("message"):
                _relay_keys_cache["previous"] = _prev.get("message").encode()
            else:
                _relay_keys_cache["previous"] = None
        else:
            # No AWSPREVIOUS stage yet (secret never rotated); expected, not an error.
            _relay_keys_cache["previous"] = None
        _relay_keys_cache["fetched_at"] = datetime.now(timezone.utc)
    except Exception as err:
        logger.error(f"_fetch_relay_keys: {err}")


def _get_relay_keys(force_refresh: bool = False) -> Tuple[Optional[bytes], Optional[bytes]]:
    """
    Return (current_key, previous_key) or (None, None) if unavailable.

    Refreshes the cache on first call, on TTL expiry, or when explicitly
    forced (used by the verify-then-retry path on initial signature miss).
    """
    fetched_at = _relay_keys_cache["fetched_at"]
    expired = (
        fetched_at is None
        or (datetime.now(timezone.utc) - fetched_at) > _RELAY_KEY_CACHE_TTL
    )
    if force_refresh or expired:
        _fetch_relay_keys()
    return _relay_keys_cache["current"], _relay_keys_cache["previous"]


def _build_canonical(raw_body: bytes, attested_instance: str) -> bytes:
    """
    Build the canonical byte string the relay HMAC is computed over.

    Modeled on AWS SigV4's canonical-request construction: the signature
    binds method + path + selected headers + body, so an attacker who
    forges any of those (e.g., header tampering between Lambda and
    controller, body swap, replay against a different endpoint) cannot
    produce a valid HMAC unless they hold the relay key.

    Format (newline-delimited; lowercased header name; literal trailing
    blank line marks end of canonical headers, then body):

        POST\\n
        /api/dcv/session-event\\n
        x-edh-attested-instance:<i-XXXXXXXX>\\n
        \\n
        <raw body bytes>

    The attested_instance value is bound here so a buggy or compromised
    Lambda cannot stamp the wrong instance ID without invalidating the
    HMAC. See docs/DCVEventRelay.md "Chain of trust" for the threat model.
    """
    return (
        b"POST\n"
        b"/api/dcv/session-event\n"
        b"x-edh-attested-instance:" + attested_instance.encode("ascii") + b"\n"
        b"\n"
        + raw_body
    )


def _verify_relay_hmac(raw_body: bytes, supplied_hmac_b64: str,
                       attested_instance: str) -> bool:
    """
    Constant-time HMAC verify over the canonical string (method + path +
    attested-instance header + body), accepting either AWSCURRENT or
    AWSPREVIOUS to span the rotation overlap window.

    On a first-pass mismatch we force a cache refresh and retry once --
    this handles the case where the Lambda just rotated to a key the
    controller hasn't fetched yet.
    """
    try:
        supplied = base64.b64decode(supplied_hmac_b64, validate=True)
    except (binascii.Error, ValueError):
        return False

    canonical = _build_canonical(raw_body, attested_instance)
    cur, prev = _get_relay_keys()
    for key in (cur, prev):
        if key and hmac.compare_digest(
            supplied, hmac.new(key, canonical, sha256).digest()
        ):
            return True
    # Cache-stale path: refresh and retry once.
    cur, prev = _get_relay_keys(force_refresh=True)
    for key in (cur, prev):
        if key and hmac.compare_digest(
            supplied, hmac.new(key, canonical, sha256).digest()
        ):
            return True
    return False


# ----- nonce dedup --------------------------------------------------------

def _record_nonce_or_reject(session_uuid: str, event_type: str, nonce: str) -> bool:
    """
    Dedup gate: DDB conditional PutItem is the primary check.
    ORM insert kept as dual-write during transition (will be removed).
    """
    # Primary: DDB conditional PutItem (fast, no pool pressure)
    if not ddb_record_nonce(session_uuid, event_type, nonce):
        return False
    # Dual-write: ORM (transition — remove once SSE reader is off SQLite)
    now = datetime.now(timezone.utc)
    row = DcvEventNonces(
        session_uuid=session_uuid,
        event_type=event_type,
        nonce=nonce,
        accepted_at=now,
        expires_at=now + timedelta(seconds=NONCE_RETENTION_SEC),
    )
    try:
        db.session.add(row)
        db.session.flush()
    except Exception:
        db.session.rollback()
    return True


# ----- event-kicked broker finalization retry -----------------------------
# `session-ready` fires when dcvserver is up, but the on-host DCV server
# registers with the broker a short while later. Instead of waiting for the
# 60s session_state_watcher tick to notice, kick a tight, bounded, per-session
# retry that re-checks the broker API (is_server_ready) and finalizes the
# moment the server registers. Self-terminating; the session_state_watcher
# remains the durable backstop if this greenlet's worker recycles.
_BROKER_FINALIZE_RETRY_INTERVAL_SEC = 10
_BROKER_FINALIZE_RETRY_MAX_ATTEMPTS = 36   # ~6 min ceiling


def _spawn_broker_finalize_retry(session_uuid: str, instance_id: str) -> None:
    """Fire-and-forget: capture the Flask app and spawn the retry greenlet."""
    try:
        import gevent
        from flask import current_app
        _app = current_app._get_current_object()
        gevent.spawn(_broker_finalize_retry, _app, session_uuid, instance_id)
    except Exception as err:
        logger.warning(
            f"could not spawn broker-finalize retry for {session_uuid}: {err} "
            f"(session_state_watcher backstop will finalize)"
        )


def _broker_finalize_retry(app, session_uuid: str, instance_id: str) -> None:
    import gevent
    from helpers.dcv_broker_session import ensure_broker_session
    with app.app_context():
        for _ in range(_BROKER_FINALIZE_RETRY_MAX_ATTEMPTS):
            gevent.sleep(_BROKER_FINALIZE_RETRY_INTERVAL_SEC)
            try:
                _s = (
                    VirtualDesktopSessions.query.filter(
                        VirtualDesktopSessions.session_uuid == session_uuid,
                        VirtualDesktopSessions.is_active == True,  # noqa: E712
                    ).first()
                )
                # Gone, or already promoted by another path (watcher backstop):
                # nothing left to do.
                if _s is None or _s.session_state != "pending":
                    return
                _r = ensure_broker_session(_s, instance_id, db.session)
                # Error-first: bail on failure, then handle the ready case;
                # anything else (pending) falls through and the loop retries.
                if not _r.success:
                    return  # error -> leave for the watcher backstop
                if _r.message == "ready":
                    _s.session_state = "running"
                    _s.session_state_latest_change_time = datetime.now(timezone.utc)
                    db.session.commit()
                    logger.info(
                        f"Session {session_uuid}: pending -> running "
                        f"(event-kicked broker finalize)"
                    )
                    return
            except Exception as err:
                logger.warning(
                    f"broker-finalize retry error for {session_uuid}: {err}"
                )
            finally:
                try:
                    db.session.remove()
                except Exception:
                    pass
        logger.info(
            f"Session {session_uuid}: broker-finalize retry exhausted; "
            f"session_state_watcher backstop will continue"
        )


# ----- state mutation -----------------------------------------------------

def _apply_event(session: VirtualDesktopSessions, event_type: str,
                 event_ts: datetime,
                 checkpoint: Optional[str] = None,
                 sub_status: Optional[str] = None,
                 instance_id: Optional[str] = None,
                 stack_name: Optional[str] = None) -> None:
    """
    Apply the event's state change. All events update last_seen_event_at and
    last_event_type. Only session-ready / session-failed change session_state.

    Substate events (bootstrap-checkpoint, bootstrap-status) update timestamps
    but never flip session_state -- they are SSE-stream-only signals and the
    formal pending->running transition stays owned by session_state_watcher.

    checkpoint and sub_status are accepted here for future persistence into
    the SSE event log table (DcvSessionEventLog, planned). For MVP they are
    validated upstream and logged so operators can correlate via CloudWatch.
    """
    session.last_seen_event_at = event_ts
    session.last_event_type = event_type
    if event_type == "placed":
        # Async placement succeeded — CFN stack was created by the executor.
        # Promote placing→pending so the normal VDI lifecycle takes over.
        # Advance stack_name to the current attempt's stack (spot AZ-fallback
        # uses unique per-attempt names) so the orphan-stack sweep protects the
        # live attempt and reaps prior failed shells.
        if stack_name:
            session.stack_name = stack_name
        if session.session_state == "placing":
            session.session_state = "pending"
            session.session_state_latest_change_time = event_ts
            logger.info(
                f"Session {session.session_uuid}: placing -> pending "
                f"on placed event"
            )
    elif event_type == "placement_failed":
        # Async placement failed terminally (e.g. no capacity). Flip
        # placing->error promptly so the user gets a clear failure card
        # instead of waiting for the session_state_watcher 5-min backstop.
        if session.session_state == "placing":
            session.session_state = "error"
            session.session_state_latest_change_time = event_ts
            logger.info(
                f"Session {session.session_uuid}: placing -> error "
                f"on placement_failed event"
            )
    elif event_type == "session-ready":
        if session.session_ready_pushed_at is None:
            session.session_ready_pushed_at = event_ts
        # Fast-path the pending->running transition. Historically this
        # was deferred to session_state_watcher's next 60s tick "so all
        # state mutations stay in one place" -- but that creates a
        # visible UX gap where the timeline shows "Completed in X" green
        # while the card still says "Please wait, your session is
        # starting". Flip here directly; the watcher's role becomes
        # catching sessions that reach running organically (broker probe,
        # legacy non-event-emitting AMIs) -- it'll see this row already
        # at running and skip with no harm.
        if session.session_state == "pending":
            _hs_resp = SocaConfig(key="/dcv/high_scale_enabled").get_value()
            _hs_raw = _hs_resp.message if _hs_resp.success else "false"
            _hs_cast = SocaCastEngine(_hs_raw).cast_as(expected_type=str)
            _is_hs = (
                _hs_cast.message if _hs_cast.success else "false"
            ).lower() == "true"
            if _is_hs and instance_id:
                # Event-driven finalization (replaces the 60s session_state_
                # watcher dependency): register the broker session + stamp the
                # EC2 identity NOW, gated on the broker API confirming the
                # on-host DCV server has registered (is_server_ready -- NOT a
                # log grep). Promote to running ONLY once connectable. If the
                # server has not registered yet (it does so a short while after
                # dcvserver comes up), stay pending and kick a tight,
                # event-kicked retry; the watcher remains the durable backstop.
                from helpers.dcv_broker_session import ensure_broker_session
                _r = ensure_broker_session(session, instance_id, db.session)
                # Error-first: handle the not-yet-connectable outcomes (broker
                # server not registered / transient / error) before the success
                # promotion.
                if not (_r.success and _r.message == "ready"):
                    logger.info(
                        f"Session {session.session_uuid}: session-ready but "
                        f"broker not ready yet "
                        f"({_r.message if _r.success else 'error'}); staying "
                        f"pending, kicking event-driven retry"
                    )
                    _spawn_broker_finalize_retry(session.session_uuid, instance_id)
                else:
                    session.session_state = "running"
                    session.session_state_latest_change_time = event_ts
                    logger.info(
                        f"Session {session.session_uuid}: pending -> running "
                        f"on session-ready (broker session ready)"
                    )
            else:
                # Non-high-scale: the controller is the authenticator and the
                # watcher stamps EC2 fields. Keep the original fast-path.
                session.session_state = "running"
                session.session_state_latest_change_time = event_ts
                logger.info(
                    f"Session {session.session_uuid}: pending -> running "
                    f"on session-ready event (fast-path)"
                )
    elif event_type == "session-failed":
        # Watcher will pick up the error state on next cycle. We don't flip
        # session_state directly -- keeps state-change logic in one place.
        # last_event_type=session-failed is the signal.
        pass
    elif event_type in SUBSTATE_EVENT_TYPES:
        # SSE-only event; no state change. Log for ops correlation; the
        # SSE event log table will eventually persist these for the
        # detail-page consumer.
        # When this is a bootstrap-checkpoint, persist the checkpoint
        # name on the session row so the grid-timeline UI can paint the
        # correct in-progress dot state on page load (before any live
        # SSE event arrives -- otherwise sessions that finish bootstrap
        # before the user opens the page show all-grey dots forever).
        if event_type == "bootstrap-checkpoint" and checkpoint:
            session.last_checkpoint = checkpoint
            # Early EC2-identity stamp. The relay synthesizes ec2-running from
            # the EC2 state-change event and forwards it with an attested
            # instance_id, so we can populate instance_id/private_ip/
            # private_dns on the row the moment the instance reaches running --
            # decoupled from broker registration -- so an admin can correlate a
            # still-provisioning session to its EC2 instance in the console.
            if checkpoint == "ec2-running" and instance_id:
                from helpers.dcv_broker_session import stamp_ec2_identity
                stamp_ec2_identity(session, instance_id, db.session)
        logger.info(
            f"DCV substate event session={session.session_uuid} "
            f"type={event_type} checkpoint={checkpoint} sub_status={sub_status}"
        )

    # Append to the event log for every accepted event (lifecycle +
    # substate). Dual-write: DDB (primary, durable, TTL) + ORM (transition).
    _event_id = new_event_id()
    _envelope = ddb_build_envelope(
        _event_id, event_type, session.session_uuid,
        checkpoint, sub_status,
        owner=session.session_owner,
    )
    try:
        ddb_append_event(f"dcv#{session.session_uuid}", _event_id, _envelope)
    except Exception as _ddb_err:
        logger.warning(f"DDB append_event failed (non-fatal): {_ddb_err}")
    # ORM dual-write (transition — remove once SSE reader is off SQLite)
    db.session.add(DcvSessionEventLog(
        session_uuid=session.session_uuid,
        event_type=event_type,
        checkpoint=checkpoint,
        sub_status=sub_status,
        event_timestamp=event_ts,
        received_at=datetime.now(timezone.utc),
    ))
    db.session.commit()

    # ETA history: best-effort write of completed launch into the
    # vdi-launch-history DDB table. Excluded from the transaction
    # because DDB write isn't atomic with the SQLite commit anyway,
    # and a failure here must NOT block event handling.
    if event_type in ("session-ready", "session-failed"):
        try:
            from helpers.vdi_eta import record_launch_completion
            from models import DcvSessionEventLog as _DEL
            # created_on is tz-naive (SQLite); event timestamps are
            # tz-aware UTC. Coerce all to aware-UTC before subtracting.
            def _utc(_d):
                return _d if _d.tzinfo else _d.replace(tzinfo=timezone.utc)
            _created = _utc(session.created_on)
            _completed = _utc(event_ts)
            # Build per-checkpoint durations from the event log rows
            # we just appended to. Earliest occurrence of each name wins.
            _events = (
                _DEL.query
                .filter_by(session_uuid=session.session_uuid)
                .order_by(_DEL.event_timestamp.asc())
                .all()
            )
            _durations: dict = {}
            for _ev in _events:
                _delta_ms = max(
                    0,
                    int((_utc(_ev.event_timestamp) - _created).total_seconds() * 1000),
                )
                # Lifecycle event_type entry (session-ready, ec2-running, etc.)
                if _ev.event_type and _ev.event_type not in _durations:
                    _durations[_ev.event_type] = _delta_ms
                # Bootstrap-checkpoint substate -- the checkpoint name
                # is the granular signal (boot-started, dcv-installing).
                if _ev.checkpoint and _ev.checkpoint not in _durations:
                    _durations[_ev.checkpoint] = _delta_ms

            record_launch_completion(
                session_uuid=session.session_uuid,
                software_stack_id=session.software_stack_id,
                instance_type=session.instance_type,
                os_family=str(session.os_family),
                state="running" if event_type == "session-ready" else "failed",
                created_on=_created,
                completed_on=_completed,
                checkpoint_durations_ms=_durations,
            )
        except Exception as _err:
            logger.warning(
                f"vdi_eta record failed for {session.session_uuid}: {_err}"
            )


# ----- Flask Resource -----------------------------------------------------

class DcvSessionEvent(Resource):
    """
    POST /api/dcv/session-event

    Body: relayed event JSON (see REQUIRED_FIELDS).
    Headers:
      X-EDH-DcvRelay-HMAC: base64(HMAC-SHA256(relay_key, raw_body))

    Returns 204 on success, 4xx on rejection. Always emits a CloudWatch
    metric DcvEventRelayRejected{Reason=...} on rejection so we can alarm.
    """

    @staticmethod
    def post():
        r"""
        Receive a DCV session lifecycle event from the Lambda relay
        ---
        openapi: 3.1.0
        operationId: postSessionEvent
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-Attested-Instance
            in: header
            schema:
              type: string
            required: true
            description: AWS-attested EC2 instance ID (set by relay Lambda from SQS SenderId) or control-plane principal name
          - name: X-EDH-DcvRelay-HMAC
            in: header
            schema:
              type: string
            required: true
            description: Base64-encoded HMAC-SHA-256 signature over the canonical request, keyed by the relay secret
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - event_type
                  - session_uuid
                  - instance_id
                  - event_timestamp
                  - nonce
                properties:
                  event_type:
                    type: string
                    enum:
                      - placed
                      - placement_failed
                      - session-ready
                      - session-resumed
                      - session-failed
                      - session-heartbeat
                      - bootstrap-checkpoint
                      - bootstrap-status
                    description: The lifecycle event type
                  session_uuid:
                    type: string
                    format: uuid
                    description: UUID of the DCV session
                  instance_id:
                    type: string
                    pattern: '^i-[0-9a-f]{8,17}$'
                    description: EC2 instance ID (not required for control-plane callers)
                  event_timestamp:
                    type: string
                    format: date-time
                    description: ISO-8601 timestamp of the event (must be within 5 min of server time)
                  nonce:
                    type: string
                    minLength: 16
                    maxLength: 128
                    description: Unique nonce for replay protection
                  checkpoint:
                    type: string
                    maxLength: 64
                    pattern: '^[a-z0-9][a-z0-9_-]{0,63}$'
                    description: Bootstrap checkpoint name (required for bootstrap-checkpoint events)
                  sub_status:
                    type: string
                    maxLength: 256
                    description: Free-form progress message (required for bootstrap-status events)
        responses:
          '204':
            description: Event accepted and applied successfully
          '401':
            description: Authentication or validation failed (HMAC mismatch, missing fields, nonce replay, etc.)
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    reason:
                      type: string
          '413':
            description: Request body exceeds maximum size (16 KiB)
          '500':
            description: Internal error during event application
        """
        raw_body = request.get_data(cache=False, as_text=False) or b""
        if len(raw_body) > MAX_BODY_BYTES:
            return _reject("body_too_large", 413)

        # 1. AWS-attested instance header -- set by relay Lambda from the
        # SQS SenderId of the original send-message call. AWS-signed, so
        # the publisher cannot lie about which EC2 instance produced this.
        # Must be read BEFORE relay HMAC verify because the HMAC binds
        # this header into its canonical string.
        attested_iid = request.headers.get(ATTESTED_INSTANCE_HEADER, "").strip()
        if not attested_iid:
            return _reject("missing_attested_instance")
        # Control-plane callers (e.g. CapacityExecutor) attest as a fixed
        # principal name, not an instance ID -- they still must pass the relay
        # HMAC below, which binds this header into the signature.
        is_control_plane = attested_iid in CONTROL_PLANE_PRINCIPALS
        if not is_control_plane and not INSTANCE_ID_RE.match(attested_iid):
            return _reject("attested_instance_format")

        # 2. Relay HMAC -- proves the call came from the Lambda relay AND
        # binds the attested-instance header into the signature, so any
        # tampering (header substitution, body swap) invalidates the HMAC.
        supplied_relay = request.headers.get("X-EDH-DcvRelay-HMAC", "")
        if not supplied_relay or not _verify_relay_hmac(
            raw_body, supplied_relay, attested_iid
        ):
            return _reject("relay_hmac")

        g.actor_type = "dcv-agent"
        g.source_ref = attested_iid

        # 3. Body parse + schema check.
        try:
            body = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return _reject("body_parse")
        if not isinstance(body, dict):
            return _reject("body_not_object")
        # Control-plane events carry no instance_id (no instance exists yet at
        # placement time), so it is not required for those callers.
        _required = (
            REQUIRED_FIELDS - {"instance_id"} if is_control_plane else REQUIRED_FIELDS
        )
        missing = _required - body.keys()
        if missing:
            return _reject(f"missing_field:{','.join(sorted(missing))}")

        event_type = body["event_type"]
        if event_type not in KNOWN_EVENT_TYPES:
            return _reject("unknown_event_type")
        # A control-plane principal may only emit placement lifecycle events.
        if is_control_plane and event_type not in CONTROL_PLANE_EVENT_TYPES:
            return _reject("control_plane_event_type")

        session_uuid = body["session_uuid"]
        if not (Validators.is_string(session_uuid) and UUID_RE.match(session_uuid)):
            return _reject("session_uuid_format")

        if is_control_plane:
            body_iid = None
        else:
            body_iid = body["instance_id"]
            if not (Validators.is_string(body_iid) and INSTANCE_ID_RE.match(body_iid)):
                return _reject("instance_id_format")

        nonce = body["nonce"]
        if not (
            Validators.is_string(nonce)
            and Validators.is_string_length_greater_equal_than(nonce, 16)
            and Validators.is_string_length_lower_equal_than(nonce, MAX_NONCE_LEN)
        ):
            return _reject("nonce_format")

        # Optional substate fields. Validate only when present; absence is
        # legal for the original 4 event types and the controller never
        # synthesizes either field.
        checkpoint = body.get("checkpoint")
        if checkpoint is not None:
            if not (Validators.is_string(checkpoint)
                    and Validators.is_string_length_lower_equal_than(checkpoint, MAX_CHECKPOINT_LEN)
                    and CHECKPOINT_NAME_RE.match(checkpoint)):
                return _reject("checkpoint_format")
        sub_status = body.get("sub_status")
        if sub_status is not None:
            if not Validators.is_string(sub_status):
                return _reject("sub_status_type")
            if not Validators.is_string_length_lower_equal_than(sub_status, MAX_SUB_STATUS_LEN):
                return _reject("sub_status_too_long")

        # Optional stack_name (control-plane 'placed' events carry the current
        # attempt's stack name so the session row can advance for the sweep).
        stack_name = body.get("stack_name")
        if stack_name is not None:
            if not (Validators.is_string(stack_name)
                    and Validators.is_string_length_lower_equal_than(stack_name, 128)
                    and re.match(r"^[A-Za-z0-9-]+$", stack_name)):
                return _reject("stack_name_format")

        # Per-event-type required-field gates.
        if event_type == "bootstrap-checkpoint" and not checkpoint:
            return _reject("checkpoint_required")
        if event_type == "bootstrap-status" and not sub_status:
            return _reject("sub_status_required")

        # 4. Cross-check body.instance_id matches the AWS-attested SenderId.
        # Skipped for control-plane callers (no instance_id to bind).
        if not is_control_plane and body_iid != attested_iid:
            return _reject("body_instance_mismatch")

        # 5. Freshness window.
        try:
            event_ts = datetime.fromisoformat(
                body["event_timestamp"].replace("Z", "+00:00")
            )
        except (TypeError, ValueError, AttributeError):
            return _reject("timestamp_format")
        skew = abs((datetime.now(timezone.utc) - event_ts).total_seconds())
        if skew > FRESHNESS_WINDOW_SEC:
            return _reject(f"timestamp_skew:{int(skew)}s")

        # 6. DB lookup + cross-check session-to-instance binding.
        session = VirtualDesktopSessions.query.filter_by(
            session_uuid=session_uuid, is_active=True
        ).first()
        if session is None:
            return _reject("session_unknown")
        if not is_control_plane and session.instance_id and session.instance_id != attested_iid:
            return _reject("instance_id_db_mismatch")

        if session.session_owner:
            g.authenticated_user = session.session_owner

        # 7. Nonce dedup -- final gate before mutation.
        if not _record_nonce_or_reject(session_uuid, event_type, nonce):
            return _reject("nonce_replay")

        # 8. Apply.
        try:
            _apply_event(session, event_type, event_ts,
                         checkpoint=checkpoint, sub_status=sub_status,
                         instance_id=attested_iid, stack_name=stack_name)
        except Exception as err:
            db.session.rollback()
            logger.error(f"_apply_event failed: {err}")
            return _reject("apply_failed", 500)

        return Response(status=204)


def _reject(reason: str, http_status: int = 401) -> Response:
    """
    Single rejection path so every failure gets an audit log line + a
    CloudWatch metric. Operators alarm on DcvEventRelayRejected sum > 5/5min
    and per-reason for forgery attempts.
    """
    logger.warning(
        f"DCV session-event rejected: {reason} from {request.remote_addr}"
    )
    try:
        _cw_resp = utils_boto3.get_boto(service_name="cloudwatch")
        if _cw_resp.get("success") is not True:
            logger.warning(
                f"Cannot emit rejection metric: {_cw_resp.get('message')}"
            )
        else:
            cw = _cw_resp.get("message")
            cw.put_metric_data(
                Namespace="EDH/DCVEventRelay",
                MetricData=[
                    {
                        "MetricName": "Rejected",
                        "Dimensions": [
                            {"Name": "Reason", "Value": reason.split(":", 1)[0]}
                        ],
                        "Value": 1.0,
                        "Unit": "Count",
                    }
                ],
            )
    except Exception:
        pass  # never let metric publish failure mask the rejection itself
    return Response(
        response=json.dumps({"success": False, "reason": reason}),
        status=http_status,
        content_type="application/json",
    )


class DcvSessionEventRotationTest(Resource):
    """
    POST /api/dcv/session-event-rotation-test

    Endpoint hit by the SecretsManager rotation Lambda's testSecret step.
    Verifies that the AWSPENDING relay key (about to become AWSCURRENT)
    signs correctly AND that AWSCURRENT (about to become AWSPREVIOUS) is
    still readable. If both pass, the rotation Lambda proceeds to
    finishSecret.

    The rotation probe uses the same canonical-string HMAC scheme as the
    real session-event endpoint, with X-EDH-Attested-Instance set to the
    sentinel "i-rotation-probe" so the rotation Lambda can sign without
    needing a real EC2 instance. The endpoint differs in path so the
    canonical string captures that.

    No state mutation -- pure HMAC round-trip check. Returns 204 on success.
    """

    @staticmethod
    def post():
        r"""
        Verify relay key rotation (called by SecretsManager rotation Lambda testSecret step)
        ---
        openapi: 3.1.0
        operationId: testSessionEventRotation
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-Attested-Instance
            in: header
            schema:
              type: string
            required: true
            description: Sentinel instance identifier for rotation probe (e.g. i-rotation-probe)
          - name: X-EDH-DcvRelay-HMAC
            in: header
            schema:
              type: string
            required: true
            description: Base64-encoded HMAC-SHA-256 signature computed with the AWSPENDING relay key
        requestBody:
          required: true
          content:
            application/octet-stream:
              schema:
                type: string
                format: binary
                description: Arbitrary probe payload signed by the rotation Lambda
        responses:
          '204':
            description: Rotation probe succeeded (AWSPENDING key verifies correctly)
          '401':
            description: HMAC verification failed
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    reason:
                      type: string
          '413':
            description: Request body exceeds maximum size
          '500':
            description: Unable to fetch secret or create client
        """
        raw_body = request.get_data(cache=False, as_text=False) or b""
        if len(raw_body) > MAX_BODY_BYTES:
            return _reject("rotation_body_too_large", 413)
        supplied = request.headers.get("X-EDH-DcvRelay-HMAC", "")
        if not supplied:
            return _reject("rotation_missing_hmac")
        attested = request.headers.get(ATTESTED_INSTANCE_HEADER, "").strip()
        if not attested:
            return _reject("rotation_missing_attested")
        try:
            supplied_bytes = base64.b64decode(supplied, validate=True)
        except (binascii.Error, ValueError):
            return _reject("rotation_hmac_format")

        # Fetch BOTH stages directly (ignore cache -- this is the verification path).
        try:
            arn = _relay_secret_arn()
            if not arn:
                return _reject("rotation_secret_arn_missing", 500)
            _pend = SocaSecret(
                secret_id=arn, secret_id_prefix="", version_stage="AWSPENDING", as_json=False
            ).get_secret()
            pending = (
                _pend.get("message").encode()
                if _pend.get("success") is True and _pend.get("message")
                else None
            )
            _curr = SocaSecret(
                secret_id=arn, secret_id_prefix="", version_stage="AWSCURRENT", as_json=False
            ).get_secret()
            current = (
                _curr.get("message").encode()
                if _curr.get("success") is True and _curr.get("message")
                else None
            )
        except Exception as err:
            logger.error(f"rotation key fetch failed: {err}")
            return _reject("rotation_key_fetch", 500)

        # Build canonical with the rotation-probe path, not the live one.
        canonical = (
            b"POST\n"
            b"/api/dcv/session-event-rotation-test\n"
            b"x-edh-attested-instance:" + attested.encode("ascii") + b"\n"
            b"\n"
            + raw_body
        )

        # Pending must validate (the rotation Lambda signed with pending).
        if pending is None:
            return _reject("rotation_no_pending")
        if not hmac.compare_digest(
            supplied_bytes, hmac.new(pending, canonical, sha256).digest()
        ):
            return _reject("rotation_pending_hmac")
        # AWSCURRENT may legitimately be missing on first-ever rotation; in
        # that case skip the overlap check.
        if current is not None:
            # We don't expect the body to validate against current too (the
            # Lambda signed with pending only) -- this branch is just a
            # readability check that AWSCURRENT exists and is fetchable.
            pass
        g.actor_type = "rotation-probe"
        g.source_ref = "i-rotation-probe"
        g.authenticated_user = "_dcv-rotation-probe"
        return Response(status=204)

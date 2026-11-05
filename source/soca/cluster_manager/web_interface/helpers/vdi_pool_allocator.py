# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
PoolAllocator -- web-tier HOT claim for VDI pools (Phase 4).

On a VDI launch, before the normal cold path, try to claim an idle HOT pool
member for (stack, instance_type). On a hit:
  1. atomically claim the ledger row (DDB conditional update, AVAILABLE->CLAIMED),
  2. tag the instance with the four tags the session_state_watcher discovers
     by (edh:DCVSessionUUID / edh:ClusterId / edh:DCVSystem / edh:JobOwner),
  3. detach it from the pool ASG (no-decrement) so the ASG backfills,
and return the instance_id. The caller writes a `placing` session row with that
instance_id; the watcher then registers the broker session and promotes
placing->running -- fast, because the instance is already running + DCV
registered. This deliberately reuses the existing watcher (idempotent
create_session) instead of duplicating the broker/promotion logic.

Miss (no idle hot) -> return None; the caller falls through to the existing
cold launch path. Warm/cold serving + the claim-lifecycle Step Function are
Phase 5. Until readiness ingestion populates AVAILABLE ledger rows this always
misses and is a safe no-op.

Claim telemetry -> CloudWatch EDH/DCVHighScale, dimensioned by pool_id.
"""

import logging
import os
import time
from datetime import datetime, timezone

import utils.aws.boto3_wrapper as utils_boto3
from helpers import vdi_pool_store

logger = logging.getLogger("soca_logger")

_METRIC_NS = "EDH/DCVHighScale"


def _cluster_id():
    return os.environ.get("EDH_CLUSTER_ID", "")


def _pool_id(stack_id, instance_type):
    return f"POOL#{stack_id}#{instance_type}"


def _ledger_table_name():
    _c = _cluster_id()
    return f"{_c}-vdi-pool-ledger" if _c else ""


def broker_ready_instance_ids():
    """Instance IDs the DCV broker currently reports Availability==AVAILABLE.
    None if the broker query fails -> callers fall back to the ledger-only count.
    Fast-fail (short timeout) so the end-user modal never hangs on a slow broker."""
    try:
        from utils.dcv_broker_client import DcvBrokerClient

        _resp = DcvBrokerClient().describe_servers(timeout=5.0, retries=1)
        if not getattr(_resp, "success", False):
            return None
        _ids = set()
        for _s in (_resp.message or {}).get("Servers", []) or []:
            if _s.get("Availability") != "AVAILABLE":
                continue
            _tags = {t.get("Key"): t.get("Value") for t in (_s.get("Tags") or [])}
            _iid = _tags.get("instance") or (
                (_s.get("Host") or {}).get("Aws") or {}
            ).get("EC2InstanceId")
            if _iid:
                _ids.add(_iid)
        return _ids
    except Exception as err:
        logger.debug("broker_ready_instance_ids failed: %s", err)
        return None


def available_breakdown(stack_id, instance_type, ready_ids=None):
    """Return (ledger_available, broker_ready) for a pool from ONE ledger query.
    ledger_available = all AVAILABLE rows; broker_ready = the subset the broker
    can actually serve (intersect with ready_ids). The delta is the admin
    diagnostic (stale / not-yet-registered rows). ready_ids=None -> both equal
    the raw ledger count. Returns (0, 0) on error."""
    if not _ledger_table_name():
        return (0, 0)
    try:
        from boto3.dynamodb.conditions import Key, Attr

        _ddb = utils_boto3.get_boto(service_name="dynamodb", resource=True).message
        _resp = _ddb.Table(_ledger_table_name()).query(
            KeyConditionExpression=Key("pk").eq(_pool_id(stack_id, instance_type)),
            FilterExpression=Attr("status").eq("AVAILABLE"),
            ProjectionExpression="instance_id",
        )
        _rows = _resp.get("Items", [])
        _ledger = len(_rows)
        if ready_ids is None:
            return (_ledger, _ledger)
        _ready = sum(1 for _r in _rows if _r.get("instance_id") in ready_ids)
        return (_ledger, _ready)
    except Exception as err:
        logger.debug(
            "available_breakdown %s/%s failed: %s", stack_id, instance_type, err
        )
        return (0, 0)


def available_count(stack_id, instance_type, ready_ids=None):
    """Instantly-claimable hot member count. With ready_ids (broker's live
    AVAILABLE set), returns only broker-ready members (true claim-now count);
    ready_ids=None falls back to the raw ledger count. Returns 0 on error."""
    return available_breakdown(stack_id, instance_type, ready_ids)[1]


def release_claim(stack_id, instance_type, instance_id):
    """Delete the ledger row for a claimed pool member being torn down.

    Called by the delete path right after terminating the instance, so the
    CLAIMED row is freed immediately rather than lingering until the reaper
    sweep (~abandon window). Best-effort: the reaper remains the backstop if
    this fails, and a stale CLAIMED row is never re-served regardless (only
    AVAILABLE rows are claimed)."""
    if not _ledger_table_name():
        return
    _pid = _pool_id(stack_id, instance_type)
    try:
        _ddb = utils_boto3.get_boto(service_name="dynamodb", resource=True).message
        _ddb.Table(_ledger_table_name()).delete_item(
            Key={"pk": _pid, "sk": instance_id}
        )
        logger.info("pool: released ledger row %s / %s on delete", _pid, instance_id)
    except Exception as err:
        logger.warning(
            "pool: release_claim failed for %s/%s (reaper will reclaim): %s",
            _pid,
            instance_id,
            err,
        )


def _emit(metric, value, pool_id):
    try:
        utils_boto3.get_boto(service_name="cloudwatch").message.put_metric_data(
            Namespace=_METRIC_NS,
            MetricData=[
                {
                    "MetricName": metric,
                    "Value": float(value),
                    "Unit": "Count",
                    "Dimensions": [{"Name": "pool_id", "Value": pool_id}],
                }
            ],
        )
    except Exception as err:  # metrics must never break a launch
        logger.debug("pool metric %s emit failed: %s", metric, err)


def _pool_entry_enabled(stack_id, instance_type):
    """True if the stack has pooling enabled and an entry for this type."""
    _cfg = vdi_pool_store.get_pool_config(stack_id)
    _meta = _cfg.get("message") if _cfg.get("success") is True else None
    if not _meta or not _meta.get("enabled"):
        return False
    return any(
        e.get("instance_type") == instance_type
        for e in (_meta.get("entries") or [])
    )


def backfill_on_claim(stack_id):
    """Whether a claim should leave the pool at depth. Default True.

    This is the admin checkbox "Backfill on claim (keep pool at depth)" in
    software_stacks_edit.html. It was validated (validate_pool_config), stored
    (put_pool_config) and rendered back into the form, and NOTHING read it --
    a shipped control the admin UI presented as functional while it changed
    nothing. This is its consumer.

    True  -> detach WITHOUT decrementing desired, so the ASG replaces the
             claimed member and satisfies that replacement from the warm pool.
    False -> detach WITH decrement, so the group shrinks by one and the admin
             pays for only what is actually in use.

    Defaults True on any read failure, which is both the documented default and
    the prior hardcoded behaviour.
    """
    try:
        _cfg = vdi_pool_store.get_pool_config(stack_id)
        _meta = _cfg.get("message") if _cfg.get("success") is True else None
        if not _meta:
            return True
        return _meta.get("backfill_on_claim") is not False
    except Exception as err:
        logger.debug("backfill_on_claim read failed for stack %s: %s", stack_id, err)
        return True


def try_claim_hot(stack_id, instance_type, owner, base_os, session_uuid, session_type, session_name=None):
    """Atomically claim an idle hot member, register the broker session
    synchronously, bind + detach it. Returns
    {"instance_id", "broker_session_id", "ready"} on a hit, else None."""
    if not _ledger_table_name():
        return None
    if not _pool_entry_enabled(stack_id, instance_type):
        return None

    _pid = _pool_id(stack_id, instance_type)
    _emit("ClaimAttempts", 1, _pid)

    from boto3.dynamodb.conditions import Attr, Key

    _ddb = utils_boto3.get_boto(service_name="dynamodb", resource=True).message
    _table = _ddb.Table(_ledger_table_name())

    try:
        _avail = _table.query(
            KeyConditionExpression=Key("pk").eq(_pid),
            FilterExpression=Attr("status").eq("AVAILABLE"),
        ).get("Items", [])
    except Exception as err:
        logger.warning("pool ledger query failed for %s: %s", _pid, err)
        return None

    # Attempt only members the broker can actually serve. A stale AVAILABLE row
    # (a member stopped into the warm pool, a member that fell out of DCV) costs
    # a full broker create_session round trip to discover, serially, inside a
    # user-facing request -- so N stale rows meant N round trips before falling
    # through to the cold path. Intersecting first makes that free.
    #
    # ready_ids None means the broker query itself failed: fall back to trying
    # every row, which is the prior behaviour, rather than refusing to serve a
    # pool because one side call did not answer.
    _ready_ids = broker_ready_instance_ids()
    if _ready_ids is not None:
        _serveable = [
            _r for _r in _avail
            if (_r.get("instance_id") or _r.get("sk")) in _ready_ids
        ]
        _skipped = len(_avail) - len(_serveable)
        if _skipped:
            logger.info(
                "pool claim: %s has %d AVAILABLE row(s) the broker cannot serve; "
                "skipping them (hygiene sweeps will prune)",
                _pid,
                _skipped,
            )
            _emit("ClaimStaleRowsSkipped", _skipped, _pid)
        _avail = _serveable

    _now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _retries = 0
    for _row in _avail:
        _iid = _row.get("sk")
        try:
            _table.update_item(
                Key={"pk": _pid, "sk": _iid},
                UpdateExpression=(
                    "SET #s = :c, claimed_by = :u, claimed_at = :t, "
                    "session_uuid = :su"
                ),
                ConditionExpression=Attr("status").eq("AVAILABLE"),
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":c": "CLAIMED",
                    ":u": owner,
                    ":t": _now,
                    ":su": session_uuid,
                },
            )
        except _ddb.meta.client.exceptions.ConditionalCheckFailedException:
            _retries += 1
            _emit("ClaimCollisions", 1, _pid)
            continue
        except Exception as err:
            logger.warning("pool claim update failed %s/%s: %s", _pid, _iid, err)
            continue

        if _retries:
            _emit("ClaimRetries", _retries, _pid)

        # Register the broker session SYNCHRONOUSLY in the web tier. The member
        # is already running + DCV-registered, so this is fast -- we do NOT
        # defer to the controller's 1-min session_state_watcher poll for the hot
        # path (that would be neither instant nor off-controller).
        _broker_session_id, _ready = _create_broker_session(
            _iid, session_uuid, owner, session_type, base_os
        )
        if not _broker_session_id:
            # Broker registration can race pool-ready/AVAILABLE. Roll this row
            # back to AVAILABLE and try the NEXT member instead of cold-launching;
            # only cold-launch when no available member is broker-ready.
            try:
                _table.update_item(
                    Key={"pk": _pid, "sk": _iid},
                    UpdateExpression="SET #s = :a",
                    ConditionExpression=Attr("status").eq("CLAIMED"),
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={":a": "AVAILABLE"},
                )
            except Exception:
                pass
            _emit("ClaimBrokerNotReady", 1, _pid)
            logger.info(
                "pool claim: %s not broker-ready yet; trying next available member",
                _iid,
            )
            continue

        _asg_name = _row.get("asg_name") or (
            f"{_cluster_id()}-vdipool-{stack_id}-"
            f"{str(instance_type).replace('.', '-')}"
        )
        # Tag (identification + watcher backstop), retire the pool identity,
        # then detach. decrement_desired is the inverse of the admin's
        # "Backfill on claim (keep pool at depth)" setting: backfill on means
        # leave desired alone so the ASG replaces this member from the warm
        # pool, which is what drains warm for a hot pool.
        _bind_claimed_instance(
            _iid,
            _asg_name,
            session_uuid,
            owner,
            base_os,
            session_name,
            _pid,
            not backfill_on_claim(stack_id),
        )

        _emit("TierServedHot", 1, _pid)
        logger.info(
            "pool hot-claim served: pool=%s instance=%s ready=%s",
            _pid,
            _iid,
            _ready,
        )
        return {
            "instance_id": _iid,
            "broker_session_id": _broker_session_id,
            "ready": _ready,
        }

    return None  # nothing claimable


def _reservation_sk(session_uuid):
    """Sort key for a warm-claim reservation row.

    Prefixed so it can NEVER collide with an instance id, which matters
    because DcvEventRelay._handle_pool_ready writes its AVAILABLE row keyed by
    instance id under a condition that rejects a non-AVAILABLE/WARMED prior
    state. A reservation keyed like an instance would make a legitimate
    announce fail that condition.
    """
    return f"RESV#{session_uuid}"


def warm_promotable(stack_id, instance_type):
    """(promotable, measured) warm depth for a pool, net of reservations.

    promotable is the reconciler's MEASURED Warmed:Stopped count (never the
    admin's configured warm_count) minus the warm claims already in flight
    against this pool, so two users cannot both be promised the same single
    warm member. measured is False when the reconciler has not stamped the
    pool yet or its describe failed -- unknown, which must not be read as
    capacity.
    """
    _pid = _pool_id(stack_id, instance_type)
    try:
        _resp = vdi_pool_store.get_pool_summaries()
        _sums = _resp.get("message") or {} if _resp.get("success") is True else {}
    except Exception as err:
        logger.warning("warm_promotable: summary read failed for %s: %s", _pid, err)
        return (0, False)
    _sum = _sums.get(_pid) or {}
    if not _sum.get("warm_measured"):
        return (0, False)
    _promotable = int(_sum.get("warm_promotable") or 0)
    _outstanding = _outstanding_reservations(_pid)
    return (max(0, _promotable - _outstanding), True)


def _outstanding_reservations(pool_id):
    """Count RESERVED rows for a pool. 0 on error.

    Returning 0 on error is deliberate: it fails toward ATTEMPTING a warm
    claim, whose own conditional reservation write and the reconciler's
    promotable-count check are the real arbiters. Failing the other way would
    silently disable warm serving whenever a query hiccuped.
    """
    if not _ledger_table_name():
        return 0
    try:
        from boto3.dynamodb.conditions import Attr, Key

        _ddb = utils_boto3.get_boto(service_name="dynamodb", resource=True).message
        return len(
            _ddb.Table(_ledger_table_name()).query(
                KeyConditionExpression=Key("pk").eq(pool_id),
                FilterExpression=Attr("status").eq("RESERVED"),
                ProjectionExpression="sk",
            ).get("Items", [])
        )
    except Exception as err:
        logger.debug("reservation count failed for %s: %s", pool_id, err)
        return 0


def try_claim_warm(stack_id, instance_type, owner, session_uuid, session_name=None):
    """Reserve a warm member and kick the ASG to promote it. Asynchronous.

    Returns {"pool_id", "reservation_sk", "asg_name"} when a promotion is
    under way, else None -> the caller falls through to the cold path.

    WHY THIS CANNOT BE SYNCHRONOUS. A hot claim returns in 1-3s because the
    member is already running and broker-registered, which is what lets
    _create_broker_session afford a 16s inline budget. A warm member is
    Warmed:Stopped: promoting it is an EC2 start plus a full boot plus a DCV
    re-register, measured at 67s end to end on a Windows Server 2025
    m7i-flex.large (claim 19:52:29, promoted member claimable 19:53:34). That
    is far too long to hold a Flask worker, so this writes a reservation,
    kicks, and returns -- the caller writes a `placing` session row exactly as
    the cold path does, and session_state_watcher._bind_warm_reservations
    finishes the claim.

    QUOTA. The caller MUST have passed refuse_if_quota_exhausted before
    reaching here. Unlike a hot claim, a warm claim DOES consume quota:
    stopped instances do not count toward On-Demand vCPU quotas, so promoting
    one charges vCPUs that were never charged. See
    refuse_if_quota_exhausted's docstring.

    Denials all fall through to the cold path rather than refusing the user:
    pool entry disabled, warm depth unmeasured, no promotable member left
    after subtracting in-flight reservations, ASG at MaxSize, or a kick error.
    """
    if not _ledger_table_name():
        return None
    if not _pool_entry_enabled(stack_id, instance_type):
        return None

    _pid = _pool_id(stack_id, instance_type)
    _emit("WarmClaimAttempts", 1, _pid)

    _promotable, _measured = warm_promotable(stack_id, instance_type)
    if not _measured:
        logger.info(
            "pool warm-claim %s: warm depth unmeasured (pool not stamped yet); "
            "falling through to cold",
            _pid,
        )
        _emit("WarmClaimUnmeasured", 1, _pid)
        return None
    if _promotable < 1:
        logger.info(
            "pool warm-claim %s: no promotable warm member free (measured depth "
            "minus in-flight reservations); falling through to cold",
            _pid,
        )
        _emit("WarmClaimNoCapacity", 1, _pid)
        return None

    # Reserve BEFORE kicking. The reservation is what stops a second request
    # being promised the same member, and what makes the reconcile sustain the
    # raised desired capacity (_reserved_counts). Conditional on the row not
    # already existing so a double-submit of one session cannot double-reserve.
    _sk = _reservation_sk(session_uuid)
    _now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        from boto3.dynamodb.conditions import Attr

        _ddb = utils_boto3.get_boto(service_name="dynamodb", resource=True).message
        _ddb.Table(_ledger_table_name()).put_item(
            Item={
                "pk": _pid,
                "sk": _sk,
                "status": "RESERVED",
                "session_uuid": session_uuid,
                "claimed_by": owner,
                "session_name": session_name or "",
                "reserved_at": _now,
                "stack_id": str(stack_id),
                "instance_type": instance_type,
            },
            ConditionExpression=Attr("sk").not_exists(),
        )
    except Exception as err:
        logger.warning("pool warm-claim %s: reservation write failed: %s", _pid, err)
        return None

    _kick = _invoke_promote_warm(stack_id, instance_type)
    if not _kick.get("promoted"):
        # Nothing is coming. Release the reservation immediately rather than
        # leaving the user in `placing` until the reaper expires it, and let
        # the request cold-launch.
        logger.info(
            "pool warm-claim %s: kick refused (%s); releasing reservation and "
            "falling through to cold",
            _pid,
            _kick.get("reason"),
        )
        release_reservation(stack_id, instance_type, session_uuid)
        _emit("WarmClaimKickRefused", 1, _pid)
        return None

    _emit("TierServedWarm", 1, _pid)
    logger.info(
        "pool warm-claim %s: reserved for %s and promoting on %s (desired %s -> %s)",
        _pid,
        session_uuid,
        _kick.get("asg_name"),
        _kick.get("desired_before"),
        _kick.get("desired_after"),
    )
    return {
        "pool_id": _pid,
        "reservation_sk": _sk,
        "asg_name": _kick.get("asg_name"),
    }


def _invoke_promote_warm(stack_id, instance_type):
    """Ask the reconciler to raise desired capacity by one. SYNCHRONOUS invoke.

    Routed through the reconciler Lambda because of IAM, not taste: the
    controller role holds no autoscaling:SetDesiredCapacity (verified with
    simulate-principal-policy: implicitDeny), while the reconciler role
    already holds autoscaling:UpdateAutoScalingGroup gated to the cluster tag,
    and the controller already holds lambda:InvokeFunction on that function
    for the apply path. So nothing new needs granting -- which is the
    requirement, because EDH does not do stack updates and an IAM-dependent
    design would be dead on every installed cluster.

    InvocationType RequestResponse (not Event, as the apply path uses): the
    caller must know whether a member is actually coming before it decides
    between a `placing` row and a cold launch.
    """
    try:
        import json
        import os

        _lambda = utils_boto3.get_boto(service_name="lambda").message
        _resp = _lambda.invoke(
            FunctionName=f"{os.environ.get('EDH_CLUSTER_ID', '')}-VdiPoolReconciler",
            InvocationType="RequestResponse",
            Payload=json.dumps(
                {
                    "action": "promote_warm",
                    "stack_id": stack_id,
                    "instance_type": instance_type,
                }
            ).encode("utf-8"),
        )
        if _resp.get("FunctionError"):
            logger.warning(
                "promote_warm invoke returned FunctionError: %s",
                _resp.get("FunctionError"),
            )
            return {"promoted": False, "reason": "kick_function_error"}
        return json.loads(_resp["Payload"].read() or b"{}") or {}
    except Exception as err:
        logger.warning("promote_warm invoke failed: %s", err)
        return {"promoted": False, "reason": f"kick_invoke_failed: {err}"}


def release_reservation(stack_id, instance_type, session_uuid):
    """Delete a warm-claim reservation row.

    Called when the kick is refused, when the bind completes, and by the
    delete path if a desktop is torn down while still reserved. Best-effort:
    the reconciler's ledger reaper expires RESERVED rows past
    connect_abandon_timeout_seconds as the backstop.
    """
    if not _ledger_table_name():
        return
    try:
        _ddb = utils_boto3.get_boto(service_name="dynamodb", resource=True).message
        _ddb.Table(_ledger_table_name()).delete_item(
            Key={
                "pk": _pool_id(stack_id, instance_type),
                "sk": _reservation_sk(session_uuid),
            }
        )
    except Exception as err:
        logger.warning(
            "pool: release_reservation failed for %s/%s (reaper will expire "
            "it): %s",
            _pool_id(stack_id, instance_type),
            session_uuid,
            err,
        )


def _create_broker_session(instance_id, session_uuid, owner, session_type, base_os=None):
    """Register the session with the broker synchronously and briefly confirm
    READY (a hot member places in ~1-3s). Returns (broker_session_id, ready).
    The session_state_watcher remains an idempotent backstop via
    find_session_by_name, so a missed READY confirm still converges."""
    try:
        from utils.dcv_broker_client import DcvBrokerClient
        from utils.config import SocaConfig
        from utils.cast import SocaCastEngine

        _b = DcvBrokerClient()
        # storage-root so file transfer (upload/download) is enabled on the
        # broker-created session. Must match the bootstrap-created folder
        # per-OS or DCV silently disables session storage.
        _storage_cfg = SocaConfig(key="/system/dcv/session_storage").get_value(
            default="dcv_session_storage", allow_unknown_key=True
        )
        _storage_name = (
            _storage_cfg.message if _storage_cfg.success else "dcv_session_storage"
        )
        _osfam_cast = SocaCastEngine(base_os or "").cast_as(expected_type=str)
        _osfam_str = (
            _osfam_cast.get("message") if _osfam_cast.get("success") is True else ""
        ).lower()
        if "windows" in _osfam_str:
            _storage_root = f"C:\\{_storage_name}"
        else:
            _storage_root = f"%home%/{_storage_name}"
        _resp = _b.create_session(
            name=session_uuid,
            owner=owner,
            session_type=(session_type or "console").upper(),
            instance_id=instance_id,
            storage_root=_storage_root,
        )
        if not _resp.success:
            logger.warning(
                "pool broker create_session failed for %s: %s",
                session_uuid,
                _resp.message,
            )
            return None, False
        _sid = (_resp.message or {}).get("Id")
        if not _sid:
            return None, False
        _ready = False
        for _ in range(16):  # ~16s budget; hot members place quickly
            _s = _b.find_session_by_name(session_uuid)
            if _s and str(_s.get("State", "")).upper() == "READY":
                _ready = True
                break
            time.sleep(1)
        return _sid, _ready
    except Exception as err:
        logger.warning(
            "pool broker registration error for %s: %s", session_uuid, err
        )
        return None, False


def _ring_claim_personalize_doorbell(instance_id, base_os):
    """Nudge a just-claimed Windows member to run its baked claim_personalize.ps1.

    Must run after create_tags: the agent reads edh:JobOwner itself, so the command
    body is static. Fire and forget; the agent's AtStartup trigger is the backstop.
    """
    if "windows" not in str(base_os or "").lower():
        return
    try:
        _ssm_resp = utils_boto3.get_boto(service_name="ssm")
        if not _ssm_resp.success:
            # On failure get_boto returns the error string, so send_command would
            # raise AttributeError and mask the real cause.
            logger.warning(
                "claim personalization doorbell could not get an ssm client for %s: %s; "
                "the EDHClaimPersonalize AtStartup task will apply it on the next boot",
                instance_id,
                _ssm_resp.message,
            )
            return
        _ssm = _ssm_resp.message
        _resp = _ssm.send_command(
            InstanceIds=[instance_id],
            DocumentName="AWS-RunPowerShellScript",
            Comment="EDH VDI claim personalization",
            Parameters={
                "commands": [
                    "powershell.exe -NonInteractive -NoProfile -ExecutionPolicy "
                    "Bypass -File C:\\ProgramData\\EDH\\claim_personalize.ps1"
                ]
            },
        )
        logger.info(
            "claim personalization doorbell sent to %s (command %s)",
            instance_id,
            (_resp.get("Command") or {}).get("CommandId"),
        )
    except Exception as err:
        # Non-fatal: the desktop still works, the owner just is not a local
        # admin until the AtStartup backstop runs. Log loudly.
        logger.warning(
            "claim personalization doorbell failed for %s: %s; the EDHClaimPersonalize "
            "AtStartup task will apply it on the next boot",
            instance_id,
            err,
        )


def _bind_claimed_instance(instance_id, asg_name, session_uuid, owner, base_os, session_name=None, pool_id="", decrement_desired=False):
    """Tag the instance for watcher discovery + a console-friendly Name, retire
    its pool identity, then detach so the ASG backfills. Returns True on
    success.

    decrement_desired selects WHICH detach semantics apply, and the two tiers
    need opposite ones:

      * HOT claim (False, the default): detach WITHOUT decrementing, so the ASG
        is one member short of desired and launches a replacement -- satisfied
        from the warm pool. That backfill is the only thing that drains a warm
        pool at all, so a hot claim must not decrement.

      * WARM claim (True): the reservation already raised desired by one
        specifically to promote this member, and binding consumes it. Leaving
        desired elevated makes the ASG launch a replacement that the next
        reconcile immediately terminates once the reservation clears -- one
        wasted instance launch per warm claim. Observed live on edh-stor2:
        claim at 18:35:43 bound i-0ffc36cd02009f83c at 18:37:20, and
        i-04509c993a20a0db1 was launched purely to be killed.
    """
    _ec2 = utils_boto3.get_boto(service_name="ec2").message
    _asg = utils_boto3.get_boto(service_name="autoscaling").message
    _tags = [
        {"Key": "edh:DCVSessionUUID", "Value": session_uuid},
        {"Key": "edh:ClusterId", "Value": _cluster_id()},
        {"Key": "edh:DCVSystem", "Value": base_os or ""},
        {"Key": "edh:JobOwner", "Value": owner},
        # Retire the pool identity. edh:pool_id is propagated at launch and is
        # the key DcvEventRelay._handle_pool_ready gates on, so a claimed
        # desktop that keeps it can re-announce itself AVAILABLE and be handed
        # to a second user. The on-host agents only skip re-announce when a DCV
        # session exists, which is false after a scheduled stop/start -- so the
        # tag is the only durable gate. BLANKED rather than deleted: the
        # controller claim policy grants ec2:CreateTags and NOT ec2:DeleteTags,
        # and the relay's `if not pool_id` check rejects an empty value. The
        # value is preserved under edh:pool_origin for provenance.
        {"Key": "edh:pool_id", "Value": ""},
        {"Key": "edh:pool_origin", "Value": pool_id or ""},
        {"Key": "edh:pool_claimed_at", "Value": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")},
    ]
    # Overwrite the ASG-propagated pool Name with the per-user desktop name so
    # the EC2 console shows it cleanly (matches the cold-VDI convention in
    # dcv_cloudformation_builder: "<cluster>-<session_name>-<user>").
    if session_name:
        _tags.append(
            {"Key": "Name", "Value": f"{_cluster_id()}-{session_name}-{owner}"}
        )
    try:
        _ec2.create_tags(Resources=[instance_id], Tags=_tags)
    except Exception as err:
        logger.warning("tag claimed instance %s failed: %s", instance_id, err)
        return False
    # Strictly after create_tags: edh:JobOwner is the agent's only input.
    _ring_claim_personalize_doorbell(instance_id, base_os)
    try:
        _asg.detach_instances(
            InstanceIds=[instance_id],
            AutoScalingGroupName=asg_name,
            ShouldDecrementDesiredCapacity=bool(decrement_desired),
        )
    except Exception as err:
        # Non-fatal for the user (the desktop still works); the pool will
        # self-correct on the next reconcile. Log loudly.
        logger.warning(
            "detach claimed instance %s from %s failed: %s",
            instance_id,
            asg_name,
            err,
        )
    return True

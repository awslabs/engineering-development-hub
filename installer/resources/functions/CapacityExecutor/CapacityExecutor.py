# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
CapacityExecutor Lambda — Step 3 of the async placement pipeline.

Triggered by PLACEMENT_RESULT_QUEUE (SQS FIFO). For each message:
  1. Read placement result (session_uuid, subnet_id, odcr_id OR error)
  2. If success: fetch placement_context from the session DB row, call CreateStack
  3. If failure: update session state to 'error', emit placement_failed event
  4. Emit notification fabric event (placed / placement_failed)

Environment variables:
  EDH_CLUSTER_ID        — cluster identifier
  NOTIFICATIONS_TABLE   — DDB notifications table name
  CONTROLLER_API_URL    — controller base URL for DB reads (or use DDB directly)
  AWS_DEFAULT_REGION    — region
"""

import base64
import hashlib
import hmac as _hmac
import http.client
import json
import logging
import os
import ssl
import time
import urllib.parse
import uuid
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

_REGION = os.environ.get("AWS_DEFAULT_REGION", "us-east-2")
_CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")
_NOTIFICATIONS_TABLE = os.environ.get(
    "NOTIFICATIONS_TABLE", f"{_CLUSTER_ID}-notifications"
)
_CONTROLLER_URL = os.environ.get("CONTROLLER_API_URL", "")
_RELAY_SECRET_ID = os.environ.get(
    "RELAY_SECRET_ID", f"/edh/{_CLUSTER_ID}/DcvEventRelayKey"
)

cfn = boto3.client("cloudformation", region_name=_REGION)
ddb = boto3.client("dynamodb", region_name=_REGION)
_sm = boto3.client("secretsmanager", region_name=_REGION)
_relay_key_cache = None
_relay_key_fetched_at = 0.0
# Refetch the relay key periodically so a rotated key is picked up without
# waiting for a Lambda cold start. Warm containers can otherwise sign with a
# stale key indefinitely; if the controller drops AWSPREVIOUS after rotation,
# every relay POST from a warm container would then fail auth.
_RELAY_KEY_TTL_SEC = 300


def _get_relay_key() -> bytes | None:
    """Fetch HMAC relay key from SecretsManager (cached with a short TTL)."""
    global _relay_key_cache, _relay_key_fetched_at
    if _relay_key_cache and (time.time() - _relay_key_fetched_at) < _RELAY_KEY_TTL_SEC:
        return _relay_key_cache
    try:
        resp = _sm.get_secret_value(SecretId=_RELAY_SECRET_ID)
        _relay_key_cache = resp["SecretString"].encode("utf-8")
        _relay_key_fetched_at = time.time()
        return _relay_key_cache
    except Exception as e:
        logger.error(f"Cannot fetch relay key: {e}")
        # Fall back to the last-known key (if any) so a transient SecretsManager
        # error does not break signing mid-cycle.
        return _relay_key_cache


def _post_event_to_controller(session_uuid: str, event_type: str, checkpoint: str = "", sub_status: str = "", stack_name: str = ""):
    """POST a session event to the controller (same HMAC signing as DcvEventRelay)."""
    if not _CONTROLLER_URL:
        logger.warning("CONTROLLER_API_URL not set; skipping relay POST")
        return
    key = _get_relay_key()
    if not key:
        return
    # The controller's /session-event endpoint requires an ISO-8601
    # event_timestamp (freshness window) and rejects an empty checkpoint /
    # sub_status (when present they must satisfy the name/length caps), so
    # only include the optional fields when non-empty.
    payload = {
        "session_uuid": session_uuid,
        "event_type": event_type,
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "nonce": uuid.uuid4().hex,
    }
    if checkpoint:
        payload["checkpoint"] = checkpoint
    if sub_status:
        payload["sub_status"] = sub_status
    if stack_name:
        payload["stack_name"] = stack_name
    body = json.dumps(payload).encode("utf-8")
    attested = "capacity-executor"
    canonical = (
        b"POST\n/api/dcv/session-event\n"
        b"x-edh-attested-instance:" + attested.encode() + b"\n\n" + body
    )
    sig = base64.b64encode(_hmac.new(key, canonical, hashlib.sha256).digest()).decode()
    parsed = urllib.parse.urlparse(_CONTROLLER_URL)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        conn = http.client.HTTPSConnection(parsed.hostname, parsed.port or 8443, context=ctx, timeout=5)
        conn.request("POST", "/api/dcv/session-event", body=body, headers={
            "Content-Type": "application/json",
            "X-EDH-DcvRelay-HMAC": sig,
            "X-EDH-Attested-Instance": attested,
        })
        resp = conn.getresponse()
        resp.read()
        conn.close()
        if resp.status < 300:
            logger.info(f"Relay POST {event_type} for {session_uuid}: {resp.status}")
        else:
            logger.warning(f"Relay POST {event_type} returned {resp.status}")
    except Exception as e:
        logger.error(f"Relay POST failed: {e}")


def _emit_event(session_uuid: str, event_type: str, detail: str, owner: str = ""):
    """Best-effort write to notification fabric DDB table."""
    try:
        # ULID (Crockford base32 of 48-bit ms + 80-bit randomness). MUST match
        # the controller's `ulid` keyspace: the SSE stream advances its cursor
        # with lexical `id > :c`, so a non-ULID id (e.g. epoch-ms "1780...")
        # sorts ABOVE every ULID ("01K...") and poisons the cursor, freezing
        # the live event stream (dots stop animating). Generate inline so this
        # Lambda needs no `ulid` dependency.
        _C32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
        _n = (int(time.time() * 1000) << 80) | int.from_bytes(os.urandom(10), "big")
        event_id = "".join(_C32[(_n >> (5 * _i)) & 31] for _i in range(25, -1, -1))
        envelope = {
            "id": event_id,
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "dcv",
            "source": "capacity-executor",
            "severity": "info" if "fail" not in event_type else "error",
            "scope": {"user": owner, "cluster": _CLUSTER_ID},
            "title": f"{event_type}: {session_uuid[:8]}",
            "body": detail,
            "resource": f"dcv:session:{session_uuid}",
            "payload": {
                "session_uuid": session_uuid,
                "event_type": event_type,
                "checkpoint": event_type,
                "sub_status": detail,
            },
        }
        ddb.put_item(
            TableName=_NOTIFICATIONS_TABLE,
            Item={
                "scope": {"S": f"dcv#{session_uuid}"},
                "id": {"S": event_id},
                "envelope": {"S": json.dumps(envelope)},
                "ttl": {"N": str(int(time.time()) + 7 * 86400)},
            },
        )
    except Exception as err:
        logger.warning(f"emit_event failed (non-fatal): {err}")


def handler(event, context):
    """SQS FIFO trigger handler."""
    for record in event.get("Records", []):
        body = json.loads(record["body"])
        session_uuid = body["session_uuid"]
        success = body.get("success", False)
        subnet_id = body.get("subnet_id")
        odcr_id = body.get("odcr_id")
        capacity_reservation_source = body.get("capacity_reservation_source", "auto")
        attempt = int(body.get("attempt", 1) or 1)
        error_msg = body.get("error", "")

        logger.info(f"Processing placement result: {session_uuid} success={success}")

        if not success:
            _emit_event(session_uuid, "placement_failed", error_msg)
            _post_event_to_controller(session_uuid, "placement_failed", sub_status=error_msg[:256])
            logger.error(f"Placement failed for {session_uuid}: {error_msg}")
            continue

        # Fetch placement_context from the session table via the controller
        # For now: read directly from the SOCA SQLite via an internal API call
        # TODO: once Aurora is live, read from Aurora/DDB directly
        # For hot-patch validation: the controller exposes the session row
        # We'll use a simpler approach: store placement_context in DDB too
        # at enqueue time, keyed by session_uuid

        # Read placement_context from DDB (parked by async_placement.enqueue)
        try:
            ctx_resp = ddb.get_item(
                TableName=f"{_CLUSTER_ID}-notifications",
                Key={
                    "scope": {"S": f"placement_ctx#{session_uuid}"},
                    "id": {"S": "context"},
                },
            )
            ctx_item = ctx_resp.get("Item")
            if not ctx_item:
                raise ValueError("placement_context not found in DDB")
            placement_ctx = json.loads(ctx_item["envelope"]["S"])
        except Exception as err:
            _emit_event(session_uuid, "placement_failed", f"Context fetch error: {err}")
            _post_event_to_controller(session_uuid, "placement_failed", sub_status=f"Context fetch error: {err}"[:256])
            logger.error(f"Cannot read placement_context for {session_uuid}: {err}")
            continue

        # Call CreateStack with the parked context + ODCR placement result
        stack_name = placement_ctx["stack_name"]
        if attempt > 1:
            stack_name = f"{stack_name}-r{attempt}"
        template_body = placement_ctx["template_body"]
        cfn_tags = placement_ctx["cfn_tags"]
        notification_arns = placement_ctx.get("cfn_notification_arns", [])

        _stack_params = [
            {"ParameterKey": "SubnetId", "ParameterValue": subnet_id},
            {"ParameterKey": "CapacityReservationId", "ParameterValue": odcr_id or ""},
            {"ParameterKey": "CapacityReservationSource", "ParameterValue": capacity_reservation_source},
        ]
        # On a retry, give the launch template a unique name so it cannot
        # collide with the prior attempt's not-yet-deleted LT (async rollback).
        # Attempt 1 relies on the template's "" default, keeping older parked
        # templates (which lack this parameter) safe.
        if attempt > 1:
            _stack_params.append(
                {"ParameterKey": "LaunchTemplateNameSuffix", "ParameterValue": f"-r{attempt}"}
            )

        try:
            cfn.create_stack(
                StackName=stack_name,
                TemplateBody=template_body,
                Parameters=_stack_params,
                Tags=cfn_tags,
                NotificationARNs=notification_arns,
                Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
            )
            _emit_event(session_uuid, "placed", f"CFN stack {stack_name} creating (subnet={subnet_id}, odcr={odcr_id})")
            # Event-driven state promotion: POST 'placed' to controller so
            # session_state flips placing->pending without polling.
            _post_event_to_controller(session_uuid, "placed", sub_status=f"Stack {stack_name} creating", stack_name=stack_name)
            logger.info(f"CreateStack succeeded: {stack_name}")
        except Exception as err:
            _emit_event(session_uuid, "placement_failed", f"CreateStack error: {err}")
            _post_event_to_controller(session_uuid, "placement_failed", sub_status=f"CreateStack error: {err}"[:256])
            logger.error(f"CreateStack failed for {session_uuid}: {err}")

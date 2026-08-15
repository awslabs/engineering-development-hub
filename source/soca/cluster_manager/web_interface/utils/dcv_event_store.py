# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DDB-backed event store for the Notification Fabric.

Replaces the SQLAlchemy DcvSessionEventLog + DcvEventNonces ORM models
with DynamoDB PutItem/Query operations. TTL handles expiry (no cron).

Tables:
  {cluster_id}-notifications  PK=scope  SK=id (ULID)
  {cluster_id}-event-nonces   PK=nonce_key
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Optional

try:
    import ulid as _ulid_mod
    _HAS_ULID = True
except ImportError:
    _HAS_ULID = False
    import uuid as _uuid_mod

from utils.aws import boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

_CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")
_NOTIFICATIONS_TABLE = f"{_CLUSTER_ID}-notifications"
_NONCES_TABLE = f"{_CLUSTER_ID}-event-nonces"
_DEFAULT_TTL_DAYS = 7
_NONCE_TTL_SECONDS = 600  # 10 min


def _ddb():
    return utils_boto3.get_boto(service_name="dynamodb").message


def new_event_id() -> str:
    """Generate a ULID string (time-sortable, unique). Falls back to timestamp+uuid."""
    if _HAS_ULID:
        return str(_ulid_mod.ULID())
    # Fallback: zero-padded epoch-ms + random suffix (sorts correctly)
    ms = int(time.time() * 1000)
    return f"{ms:013d}-{_uuid_mod.uuid4().hex[:16]}"


def append_event(
    scope: str,
    event_id: str,
    envelope: dict,
    ttl_days: int = _DEFAULT_TTL_DAYS,
) -> None:
    """Write one event to the notifications table."""
    ttl_epoch = int(time.time()) + (ttl_days * 86400)
    _ddb().put_item(
        TableName=_NOTIFICATIONS_TABLE,
        Item={
            "scope": {"S": scope},
            "id": {"S": event_id},
            "envelope": {"S": json.dumps(envelope)},
            "ttl": {"N": str(ttl_epoch)},
        },
    )


def record_nonce_or_reject(session_uuid: str, event_type: str, nonce: str) -> bool:
    """
    Attempt to record a nonce. Returns True if accepted (new), False if
    duplicate (replay). Uses conditional PutItem — no IntegrityError dance.
    """
    nonce_key = f"{session_uuid}#{event_type}#{nonce}"
    ttl_epoch = int(time.time()) + _NONCE_TTL_SECONDS
    try:
        _ddb().put_item(
            TableName=_NONCES_TABLE,
            Item={
                "nonce_key": {"S": nonce_key},
                "ttl": {"N": str(ttl_epoch)},
            },
            ConditionExpression="attribute_not_exists(nonce_key)",
        )
        return True
    except _ddb().exceptions.ConditionalCheckFailedException:
        return False
    except Exception as err:
        # ClientError for ConditionalCheckFailed via low-level client
        if "ConditionalCheckFailedException" in str(type(err).__name__):
            return False
        raise


def query_events_since(scope: str, cursor: str = "", limit: int = 50) -> list[dict]:
    """
    Query events for a scope after the given cursor (ULID string).
    Returns list of envelope dicts, ascending order.
    """
    kwargs = {
        "TableName": _NOTIFICATIONS_TABLE,
        "ExpressionAttributeNames": {"#s": "scope"},
        "Limit": limit,
        "ScanIndexForward": True,
    }
    if cursor:
        kwargs["KeyConditionExpression"] = "#s = :s AND id > :c"
        kwargs["ExpressionAttributeValues"] = {
            ":s": {"S": scope},
            ":c": {"S": cursor},
        }
    else:
        kwargs["KeyConditionExpression"] = "#s = :s"
        kwargs["ExpressionAttributeValues"] = {":s": {"S": scope}}
    resp = _ddb().query(**kwargs)
    return [json.loads(item["envelope"]["S"]) for item in resp.get("Items", [])]


def recent_events(scope: str, limit: int = 50) -> list[dict]:
    """
    Get the N most recent events for a scope (descending), then reverse
    to chronological order for SSE replay.
    """
    kwargs = {
        "TableName": _NOTIFICATIONS_TABLE,
        "KeyConditionExpression": "#s = :s",
        "ExpressionAttributeNames": {"#s": "scope"},
        "ExpressionAttributeValues": {":s": {"S": scope}},
        "Limit": limit,
        "ScanIndexForward": False,
    }
    resp = _ddb().query(**kwargs)
    items = [json.loads(item["envelope"]["S"]) for item in resp.get("Items", [])]
    items.reverse()
    return items


def build_envelope(
    event_id: str,
    event_type: str,
    session_uuid: str,
    checkpoint: str | None,
    sub_status: str | None,
    owner: str | None = None,
    cluster_id: str | None = None,
) -> dict:
    """Build a Notification Fabric envelope for a DCV event."""
    now = datetime.now(timezone.utc).isoformat()
    return {
        "id": event_id,
        "ts": now,
        "type": "dcv",
        "source": "dcv-event-relay",
        "severity": "info",
        "scope": {
            "user": owner,
            "cluster": cluster_id or _CLUSTER_ID,
        },
        "title": f"{event_type}: {checkpoint or session_uuid[:8]}",
        "body": sub_status,
        "resource": f"dcv:session:{session_uuid}",
        "payload": {
            "session_uuid": session_uuid,
            "event_type": event_type,
            "checkpoint": checkpoint,
            "sub_status": sub_status,
        },
    }


def normalize_ts(ts) -> SocaResponse:
    """
    Normalize a notification-envelope ``ts`` to an ISO-8601 string a browser's
    ``Date.parse()`` can read.

    ``build_envelope`` emits ISO-8601, but the CapacityExecutor Lambda's inline
    envelope emits an epoch-seconds float string (e.g. ``"1781069974.666"``).
    The timeline parses this as a date, so an epoch string is unparseable.
    Convert epoch values to ISO; pass ISO values through unchanged. (Mirrors
    event_stream._normalize_event_timestamp, which normalizes the live SSE
    path -- this serves the server-rendered detail page.)

    Returns a SocaResponse: ``success=True`` with the normalized string in
    ``message`` when parseable; ``success=False`` for empty/unparseable input
    (a normal case the caller renders as "no timestamp", not an error).
    """
    if not ts:
        return SocaResponse(success=False, message=None)
    _ts = SocaCastEngine(ts).cast_as(expected_type=str)
    if _ts.get("success") is not True:
        return SocaResponse(success=False, message=None)
    _s = _ts.get("message").strip()
    if not _s:
        return SocaResponse(success=False, message=None)
    # ISO-8601 carries a date/time 'T' separator; a missing 'T' marks a
    # legacy epoch-seconds string.
    if "T" in _s:
        return SocaResponse(success=True, message=_s)
    _epoch = SocaCastEngine(_s).cast_as(expected_type=float)
    if _epoch.get("success") is not True:
        # unrecognized format -- surface it rather than drop it
        return SocaResponse(success=True, message=_s)
    return SocaResponse(
        success=True,
        message=datetime.fromtimestamp(_epoch.get("message"), tz=timezone.utc).isoformat(),
    )

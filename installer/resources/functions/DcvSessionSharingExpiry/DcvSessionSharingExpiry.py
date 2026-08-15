# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
SharingExpiry Lambda -- revokes expired session-sharing grants.

Fires every 15 min via EventBridge. Queries the grants table for
ACTIVE grants past their expires_at, calls the DCV broker to revoke
permissions, and marks the grant EXPIRED.
"""

import json
import logging
import os
import urllib3
from base64 import b64encode
from datetime import datetime, timezone

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

http = urllib3.PoolManager(cert_reqs="CERT_NONE")
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

GRANTS_TABLE = os.environ["GRANTS_TABLE"]
BROKER_ENDPOINT_PARAM = os.environ["BROKER_ENDPOINT"]
BROKER_PORT_PARAM = os.environ["BROKER_PORT"]

dynamodb = boto3.resource("dynamodb")
ssm = boto3.client("ssm")


def _query_all(table, **kwargs):
    """Paginate a DynamoDB query, following LastEvaluatedKey, so a >1MB result
    page (many sessions/grants expiring on the same boundary) is fully read
    instead of silently truncated."""
    items = []
    while True:
        resp = table.query(**kwargs)
        items.extend(resp.get("Items", []))
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    return items


def _get_broker_url():
    """Resolve broker URL from SSM parameters."""
    resp = ssm.get_parameters(Names=[BROKER_ENDPOINT_PARAM, BROKER_PORT_PARAM])
    params = {p["Name"]: p["Value"] for p in resp["Parameters"]}
    host = params.get(BROKER_ENDPOINT_PARAM, "")
    port = params.get(BROKER_PORT_PARAM, "8443")
    return f"https://{host}:{port}"


def _build_session_perm(table, session_id, owner):
    """Build a .perm from all currently-ACTIVE grants on the session (owner + guests)."""
    items = _query_all(
        table,
        IndexName="session-index",
        KeyConditionExpression="session_id = :sid",
        FilterExpression="#s = :active",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":sid": session_id, ":active": "ACTIVE"},
    )
    lines = ["[permissions]", "%owner% allow builtin"]
    for g in items:
        perms = g.get("permissions", [])
        flags = " ".join(perms)
        if g.get("unsupervised") and "unsupervised-access" not in perms:
            flags += " unsupervised-access"
        if flags:
            lines.append(f"{g['guest_username']} allow {flags}")
        # Supervised guests need an explicit deny to arm DCV's supervised
        # auto-disconnect (requires [security] supervision-control=enforced on
        # the host). Keep this rebuild byte-identical to the controller's.
        if not g.get("unsupervised"):
            lines.append(f"{g['guest_username']} deny unsupervised-access")
    return "\n".join(lines) + "\n"


def _push_perm(broker_url, session_id, owner, perm_content):
    """Push a rebuilt .perm to the session via the broker."""
    payload = json.dumps([{
        "SessionId": session_id,
        "Owner": owner,
        "PermissionsFile": b64encode(perm_content.encode()).decode(),
    }]).encode()
    resp = http.request(
        "PUT",
        f"{broker_url}/sessionPermissions",
        body=payload,
        headers={"Content-Type": "application/json"},
    )
    if resp.status >= 400:
        raise RuntimeError(
            f"Broker updateSessionPermissions failed: {resp.status} {resp.data.decode()}"
        )
    return resp.status


def handler(event, context):
    """Lambda entry point."""
    table = dynamodb.Table(GRANTS_TABLE)
    now = datetime.now(timezone.utc).isoformat()

    # Query expiry-index: status=ACTIVE, expires_at <= now (paginated)
    items = _query_all(
        table,
        IndexName="expiry-index",
        KeyConditionExpression="#s = :active AND expires_at <= :now",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":active": "ACTIVE", ":now": now},
    )

    logger.info(f"Found {len(items)} expired grants to revoke")

    # Phase 1: flip all expired grants to EXPIRED in DDB so the session
    # rebuild sees only the grants that should remain.
    expired_sessions = {}  # session_id -> owner_username
    flipped = 0
    errors = 0
    for item in items:
        grant_id = item["pk"]
        try:
            # Condition on status still being ACTIVE so we don't clobber a grant
            # that was concurrently REVOKED between the query and this write
            # (which would lose the revoked_by/revoked_at audit and the human
            # intent). If the condition fails, the grant is already terminal --
            # skip it, the revoke path owns it.
            table.update_item(
                Key={"pk": grant_id, "sk": item.get("sk", "GRANT")},
                UpdateExpression="SET #s = :expired, expired_at = :now",
                ConditionExpression="#s = :active",
                ExpressionAttributeNames={"#s": "status"},
                ExpressionAttributeValues={
                    ":expired": "EXPIRED",
                    ":active": "ACTIVE",
                    ":now": now,
                },
            )
            expired_sessions[item.get("session_id", "")] = item.get("owner_username", "")
            flipped += 1
        except dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
            # Grant was revoked (or otherwise left ACTIVE) concurrently -- not an
            # error; leave the existing terminal status untouched.
            logger.info(
                f"Grant {grant_id} no longer ACTIVE at expiry time; "
                f"skipping EXPIRED flip (likely concurrently revoked)"
            )
        except Exception as err:
            errors += 1
            logger.error(f"Failed to mark grant {grant_id} EXPIRED: {err}")

    # Phase 2: rebuild each affected session's .perm once from remaining
    # ACTIVE grants (owner + any guests whose grants have not expired).
    broker_url = None
    rebuilt = 0
    for session_id, owner in expired_sessions.items():
        if not session_id:
            continue
        try:
            if broker_url is None:
                broker_url = _get_broker_url()
            perm = _build_session_perm(table, session_id, owner)
            _push_perm(broker_url, session_id, owner, perm)
            rebuilt += 1
            logger.info(f"Rebuilt .perm for session {session_id} after expiry")
        except Exception as err:
            errors += 1
            logger.error(f"Failed to rebuild .perm for session {session_id}: {err}")

    logger.info(f"Expiry run complete: {flipped} expired, {rebuilt} sessions rebuilt, {errors} errors")
    return {"expired": flipped, "sessions_rebuilt": rebuilt, "errors": errors}

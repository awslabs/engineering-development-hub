# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
config_audit_store -- append-only audit trail for the Configuration Editor.

Mirrors helpers/dcv_session_sharing_store.py: a lazy boto3 DynamoDB table
resource built from EDH_CLUSTER_ID. Table: {cluster_id}-config-audit.

  base table   pk = "{cluster_id}#{param_key}"   sk = ISO timestamp
  activity GSI gsi_pk = "{cluster_id}#{YYYY-MM-DD}"  gsi_sk = ISO timestamp

Every successful config write records one immutable row (who/when/old->new/
version/source). Attribution comes from the Flask session user, NOT the IAM
principal (all writes go through the web-tier role). All functions degrade
gracefully (no cluster id / table absent -> no-op) so audit never blocks a
config write.
"""

import logging
import os
from datetime import datetime, timedelta, timezone

import utils.aws.boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")

_ACTIVITY_INDEX = "activity-index"
_ddb_resource = None


def _cluster_id():
    return os.environ.get("EDH_CLUSTER_ID", "")


def _ddb():
    global _ddb_resource
    if _ddb_resource is None:
        _resp = utils_boto3.get_boto(service_name="dynamodb", resource=True)
        if _resp.success is False:
            logger.error("config_audit: could not get dynamodb resource: %s", _resp.message)
            return None
        _ddb_resource = _resp.message
    return _ddb_resource


def _table():
    cid = _cluster_id()
    if not cid:
        return None
    resource = _ddb()
    if resource is None:
        return None
    return resource.Table(f"{cid}-config-audit")


def record(param_key, old_value, new_value, ssm_version, actor, source="ui"):
    """Append one immutable audit row. Best-effort: returns True/False, never raises."""
    t = _table()
    if t is None:
        return False
    cid = _cluster_id()
    now = datetime.now(timezone.utc)
    ts = now.isoformat()
    _ov = SocaCastEngine(old_value).cast_as(str)
    _nv = SocaCastEngine(new_value).cast_as(str)
    old_str = "" if old_value is None else (_ov.message if _ov.success else "")
    new_str = "" if new_value is None else (_nv.message if _nv.success else "")
    item = {
        "pk": f"{cid}#{param_key}",
        "sk": ts,
        "gsi_pk": f"{cid}#{now.strftime('%Y-%m-%d')}",
        "gsi_sk": ts,
        "param_key": param_key,
        "old_value": old_str,
        "new_value": new_str,
        "ssm_version": ssm_version if ssm_version is not None else 0,
        "edh_admin": actor or "unknown-user",
        "source": source,
        "cluster_id": cid,
    }
    try:
        t.put_item(Item=item)
        return True
    except Exception as e:
        logger.error("config_audit.record failed for %s: %s", param_key, e)
        return False


def history_for(param_key):
    """Return {ssm_version(int): {edh_admin, source, timestamp, old_value, new_value}}
    for a param (newest row per version wins). Empty on any error/absence."""
    t = _table()
    if t is None:
        return {}
    cid = _cluster_id()
    out = {}
    try:
        resp = t.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": f"{cid}#{param_key}"},
            ScanIndexForward=False,
            Limit=100,
        )
        for it in resp.get("Items", []):
            v = it.get("ssm_version")
            if v is None:
                continue
            _iv = SocaCastEngine(v).cast_as(int)
            if not _iv.success:
                continue
            iv = _iv.message
            if iv not in out:
                out[iv] = {
                    "edh_admin": it.get("edh_admin"),
                    "source": it.get("source"),
                    "timestamp": it.get("sk"),
                    "old_value": it.get("old_value"),
                    "new_value": it.get("new_value"),
                }
    except Exception as e:
        logger.warning("config_audit.history_for %s failed: %s", param_key, e)
    return out


def recent_activity(days=7, limit=200):
    """Cluster-wide recent changes (newest first) via the activity GSI, walking
    back `days` date-partitions. Empty on any error/absence."""
    t = _table()
    if t is None:
        return []
    cid = _cluster_id()
    out = []
    emitted = 0
    today = datetime.now(timezone.utc).date()
    for d in range(max(1, days)):
        day = (today - timedelta(days=d)).strftime("%Y-%m-%d")
        try:
            resp = t.query(
                IndexName=_ACTIVITY_INDEX,
                KeyConditionExpression="gsi_pk = :gpk",
                ExpressionAttributeValues={":gpk": f"{cid}#{day}"},
                ScanIndexForward=False,
            )
            for it in resp.get("Items", []):
                _sv = it.get("ssm_version")
                _svc = SocaCastEngine(_sv).cast_as(int) if _sv is not None else None
                out.append({
                    "param_key": it.get("param_key"),
                    "old_value": it.get("old_value"),
                    "new_value": it.get("new_value"),
                    "ssm_version": _svc.message if (_svc is not None and _svc.success) else None,
                    "edh_admin": it.get("edh_admin"),
                    "source": it.get("source"),
                    "timestamp": it.get("sk"),
                })
                emitted += 1
                if emitted >= limit:
                    return out
        except Exception as e:
            logger.warning("config_audit.recent_activity %s failed: %s", day, e)
    return out

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
        # Tag (identification + watcher backstop) + detach (no-decrement) so the
        # ASG backfills.
        _bind_claimed_instance(
            _iid, _asg_name, session_uuid, owner, base_os, session_name
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


def _bind_claimed_instance(instance_id, asg_name, session_uuid, owner, base_os, session_name=None):
    """Tag the instance for watcher discovery + a console-friendly Name, then
    detach (no-decrement) so the ASG backfills. Returns True on success."""
    _ec2 = utils_boto3.get_boto(service_name="ec2").message
    _asg = utils_boto3.get_boto(service_name="autoscaling").message
    _tags = [
        {"Key": "edh:DCVSessionUUID", "Value": session_uuid},
        {"Key": "edh:ClusterId", "Value": _cluster_id()},
        {"Key": "edh:DCVSystem", "Value": base_os or ""},
        {"Key": "edh:JobOwner", "Value": owner},
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
    try:
        _asg.detach_instances(
            InstanceIds=[instance_id],
            AutoScalingGroupName=asg_name,
            ShouldDecrementDesiredCapacity=False,
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

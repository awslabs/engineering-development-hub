# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DynamoDB persistence for VDI pool per-(stack, instance_type) config.

Backs the {cluster}-vdi-pool-config table (created in CDK by
helpers/vdi_pools.py). One item layout per software stack:

    pk = STACK#<stack_id>
      sk = "META"               -> stack-level fields + audit + apply status
      sk = "TYPE#<instance_type>" -> one per per-type entry

PUT is a declarative replace: the new entry set is written and stale TYPE#
items are removed, so the stored state always matches the submitted config.

The store records the authenticated principal (updated_by) on every write --
the audit-actor hook for the future VDI-admin persona -- and stamps the pool
PENDING_APPLY so the (later) PoolController reconcile picks it up.

Mirrors the get_boto + cluster-id-from-env pattern of helpers/vdi_eta.py.
Returns SocaResponse (this is IO, not an input-validation helper).
"""

import logging
import os
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional

import utils.aws.boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


def _clean(obj: Any) -> Any:
    """Recursively convert DynamoDB Decimal values to int/float so the
    result is JSON-serializable (Flask jsonify cannot handle Decimal)."""
    if isinstance(obj, Decimal):
        return int(obj) if obj % 1 == 0 else float(obj)
    if isinstance(obj, list):
        return [_clean(v) for v in obj]
    if isinstance(obj, dict):
        return {k: _clean(v) for k, v in obj.items()}
    return obj

_META_SK = "META"
_TYPE_SK_PREFIX = "TYPE#"

_ddb_resource = None


def _table_name() -> str:
    cluster_id = os.environ.get("EDH_CLUSTER_ID", "")
    return f"{cluster_id}-vdi-pool-config" if cluster_id else ""


def _get_table():
    """Lazily build a boto3 DynamoDB resource (shared per worker)."""
    global _ddb_resource
    if _ddb_resource is None:
        _ddb_resource = utils_boto3.get_boto(
            service_name="dynamodb", resource=True
        ).message
    return _ddb_resource.Table(_table_name())


def _pk(stack_id: int) -> str:
    return f"STACK#{stack_id}"


def get_pool_config(stack_id: int) -> SocaResponse:
    """Read the assembled pool config for a stack.

    Returns SocaResponse(success=True, message={...}) with the stack-level
    META fields plus an `entries` list, or message=None when no config has
    been saved for the stack yet.
    """
    if not _table_name():
        return SocaResponse(success=False, message="EDH_CLUSTER_ID not set")

    try:
        from boto3.dynamodb.conditions import Key

        resp = _get_table().query(
            KeyConditionExpression=Key("pk").eq(_pk(stack_id))
        )
    except Exception as err:
        logger.warning(f"vdi_pool_store.get stack={stack_id} failed: {err}")
        return SocaResponse(success=False, message=str(err))

    items = resp.get("Items", [])
    if not items:
        return SocaResponse(success=True, message=None)

    meta: Dict[str, Any] = {}
    entries = []
    for it in items:
        if it.get("sk") == _META_SK:
            meta = {k: v for k, v in it.items() if k not in ("pk", "sk")}
        elif str(it.get("sk", "")).startswith(_TYPE_SK_PREFIX):
            entries.append({k: v for k, v in it.items() if k not in ("pk", "sk")})

    meta["stack_id"] = stack_id
    meta["entries"] = entries
    return SocaResponse(success=True, message=_clean(meta))


_SWEEP_LOCK_PK = "LOCK#vdi-pool-spec-sweep"
_SWEEP_LOCK_SK = "LEASE"


def get_pool_input_hash(stack_id: int) -> SocaResponse:
    """Cheap projected read of a pool's stored spec_input_hash + enabled flag
    (META item only). Used by the convergence sweep's drift pre-gate so a
    no-drift cycle never pulls the full (large) launch_spec.

    Returns message={"enabled": bool, "spec_input_hash": str|None} or
    message=None when no config exists for the stack.
    """
    if not _table_name():
        return SocaResponse(success=False, message="EDH_CLUSTER_ID not set")
    try:
        resp = _get_table().get_item(
            Key={"pk": _pk(stack_id), "sk": _META_SK},
            ProjectionExpression="enabled, spec_input_hash",
        )
    except Exception as err:
        return SocaError.AWS_API_ERROR(
            service_name="dynamodb",
            helper=f"get_pool_input_hash stack={stack_id} failed: {err}",
        )
    item = resp.get("Item")
    if not item:
        return SocaResponse(success=True, message=None)
    _enabled_cast = SocaCastEngine(item.get("enabled")).cast_as(expected_type=bool)
    return SocaResponse(
        success=True,
        message={
            "enabled": _enabled_cast.get("message")
            if _enabled_cast.get("success")
            else False,
            "spec_input_hash": item.get("spec_input_hash"),
        },
    )


def cas_update_launch_spec(
    stack_id: int,
    launch_spec: Dict[str, Any],
    expected_input_hash: Optional[str],
    updated_by: str = "spec-convergence",
) -> SocaResponse:
    """Compare-and-set refresh of the META launch_spec + spec_input_hash when
    the render inputs have drifted. Does NOT touch the TYPE# entry items (a
    template/AMI/config re-render changes only the rendered launch_spec, never
    the instance-type set) -- so the admin PUT path (put_pool_config) remains
    the only writer that adds/prunes entries.

    The write is conditional on the stored spec_input_hash still equalling
    `expected_input_hash` (the value the caller read before re-rendering), so
    two racing writers -- the periodic sweep vs the stack-edit hook, or two
    controller hosts -- cannot double-apply: the first flips the hash and the
    second's condition fails and no-ops.

    Returns success=True (applied), success=False message='raced' when another
    writer won the CAS, or success=False on a real error.
    """
    if not _table_name():
        return SocaResponse(success=False, message="EDH_CLUSTER_ID not set")
    _new_hash = (launch_spec or {}).get("spec_input_hash")
    if not _new_hash:
        return SocaResponse(
            success=False, message="launch_spec missing spec_input_hash"
        )
    _now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        table = _get_table()
        _values = {
            ":ls": launch_spec,
            ":nh": _new_hash,
            ":pa": "PENDING_APPLY",
            ":ub": updated_by or "spec-convergence",
            ":ts": _now,
        }
        if expected_input_hash is None:
            # No prior stamp on this pool yet -- first stamp wins. DDB rejects a
            # None-typed attribute value, so we must not bind :eh in this case.
            _condition = (
                "attribute_exists(pk) AND attribute_not_exists(spec_input_hash)"
            )
        else:
            _condition = (
                "attribute_exists(pk) AND "
                "(attribute_not_exists(spec_input_hash) OR spec_input_hash = :eh)"
            )
            _values[":eh"] = expected_input_hash
        table.update_item(
            Key={"pk": _pk(stack_id), "sk": _META_SK},
            UpdateExpression=(
                "SET launch_spec = :ls, spec_input_hash = :nh, "
                "apply_status = :pa, updated_by = :ub, updated_at = :ts"
            ),
            ExpressionAttributeValues=_values,
            ConditionExpression=_condition,
        )
        logger.info(
            f"vdi_pool_store.cas_update stack={stack_id} applied "
            f"spec_input_hash={_new_hash} by={updated_by}"
        )
        return SocaResponse(
            success=True,
            message={"stack_id": stack_id, "spec_input_hash": _new_hash},
        )
    except Exception as err:
        # Mirror dcv_event_store: detect the conditional-check miss by exception
        # type name (works for both the resource and low-level client paths).
        if "ConditionalCheckFailed" in type(err).__name__:
            logger.info(
                f"vdi_pool_store.cas_update stack={stack_id} raced "
                "(another writer won the CAS); no-op"
            )
            return SocaResponse(success=False, message="raced")
        logger.warning(
            f"vdi_pool_store.cas_update stack={stack_id} failed: {err}"
        )
        return SocaError.AWS_API_ERROR(
            service_name="dynamodb",
            helper=f"cas_update_launch_spec stack={stack_id} failed: {err}",
        )


def acquire_spec_sweep_lease(ttl_seconds: int, owner: str) -> SocaResponse:
    """Best-effort distributed singleton lease for the pool-spec convergence
    sweep, so only ONE controller host runs it per cycle on a multi-host web
    tier. The conditional PutItem succeeds only when no live lease exists (item
    absent, or lease_expiry already passed -- a dead leader auto-releases).

    Correctness does NOT depend on this lease: cas_update_launch_spec is the
    race backstop. The lease only avoids N hosts each doing the same wasted
    renders. Stored as a LOCK# item in the pool-config table (never matches a
    STACK# item; ignored by get_enabled_pool_configs).

    Returns success=True (acquired), success=False message='held' when another
    host holds a live lease, or success=False on a real error.
    """
    if not _table_name():
        return SocaResponse(success=False, message="EDH_CLUSTER_ID not set")
    import time

    _now_cast = SocaCastEngine(time.time()).cast_as(expected_type=int)
    _now = _now_cast.get("message") if _now_cast.get("success") else int(time.time())
    _ttl_cast = SocaCastEngine(ttl_seconds).cast_as(expected_type=int)
    _ttl = _ttl_cast.get("message") if _ttl_cast.get("success") else 1
    _expiry = _now + max(_ttl, 1)
    try:
        _get_table().put_item(
            Item={
                "pk": _SWEEP_LOCK_PK,
                "sk": _SWEEP_LOCK_SK,
                "lease_owner": owner,
                "lease_expiry": _expiry,
            },
            ConditionExpression="attribute_not_exists(pk) OR lease_expiry < :now",
            ExpressionAttributeValues={":now": _now},
        )
        return SocaResponse(
            success=True, message={"lease_owner": owner, "lease_expiry": _expiry}
        )
    except Exception as err:
        if "ConditionalCheckFailed" in type(err).__name__:
            return SocaResponse(success=False, message="held")
        logger.warning(f"vdi_pool_store.acquire_spec_sweep_lease failed: {err}")
        return SocaError.AWS_API_ERROR(
            service_name="dynamodb",
            helper=f"acquire_spec_sweep_lease failed: {err}",
        )


def get_enabled_pool_configs() -> SocaResponse:
    """Scan the (small) config table and return all ENABLED pools.

    Returns SocaResponse(success=True, message=[{stack_id, entries:[...]}, ...]).
    Used by the end-user launch modal's availability endpoint to know which
    (stack, instance_type) entries are pooled (+ their label/warm_count).
    """
    if not _table_name():
        return SocaResponse(success=False, message="EDH_CLUSTER_ID not set")
    try:
        table = _get_table()
        resp = table.scan()
        items = resp.get("Items", [])
        while resp.get("LastEvaluatedKey"):
            resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
    except Exception as err:
        logger.warning(f"vdi_pool_store.get_enabled_pool_configs failed: {err}")
        return SocaResponse(success=False, message=str(err))

    by_pk: Dict[str, Dict[str, Any]] = {}
    for it in items:
        grp = by_pk.setdefault(it.get("pk"), {"meta": None, "entries": []})
        if it.get("sk") == _META_SK:
            grp["meta"] = it
        elif str(it.get("sk", "")).startswith(_TYPE_SK_PREFIX):
            grp["entries"].append(it)

    out = []
    for grp in by_pk.values():
        meta = grp["meta"] or {}
        if not meta.get("enabled"):
            continue
        out.append(
            {
                "stack_id": _clean(meta.get("stack_id")),
                "entries": [
                    _clean({k: v for k, v in e.items() if k not in ("pk", "sk")})
                    for e in grp["entries"]
                ],
            }
        )
    return SocaResponse(success=True, message=out)


def put_pool_config(
    stack_id: int,
    normalized: Dict[str, Any],
    updated_by: str,
    launch_spec: Optional[Dict[str, Any]] = None,
) -> SocaResponse:
    """Declaratively persist a validated+normalized pool config for a stack.

    `normalized` is the output of vdi_pool_config.validate_pool_config().
    Writes the META item + one TYPE# item per entry and removes stale TYPE#
    items. Stamps updated_by/updated_at (audit) and apply_status=PENDING_APPLY.
    """
    if not _table_name():
        return SocaResponse(success=False, message="EDH_CLUSTER_ID not set")

    _now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    _pk_val = _pk(stack_id)
    _new_type_sks = {
        f"{_TYPE_SK_PREFIX}{e['instance_type']}" for e in normalized["entries"]
    }

    try:
        table = _get_table()
        from boto3.dynamodb.conditions import Key

        # Find existing TYPE# items to prune any no longer present.
        _existing = table.query(KeyConditionExpression=Key("pk").eq(_pk_val))
        _stale_sks = [
            it["sk"]
            for it in _existing.get("Items", [])
            if str(it.get("sk", "")).startswith(_TYPE_SK_PREFIX)
            and it["sk"] not in _new_type_sks
        ]

        # Omit spec_input_hash from the META item when absent: boto3 stores a
        # Python None as a DDB NULL attribute, which *exists* -- that would
        # defeat cas_update_launch_spec's first-stamp condition
        # attribute_not_exists(spec_input_hash) and wedge the pool in a
        # permanent "raced" state, never converging.
        _spec_hash = (launch_spec or {}).get("spec_input_hash")

        with table.batch_writer() as batch:
            # META: stack-level config + audit + apply status.
            batch.put_item(
                Item={
                    "pk": _pk_val,
                    "sk": _META_SK,
                    "stack_id": stack_id,
                    "enabled": normalized["enabled"],
                    "pool_state": normalized["pool_state"],
                    "allow_recycle": normalized["allow_recycle"],
                    "backfill_on_claim": normalized["backfill_on_claim"],
                    "show_interruptible_hint": normalized[
                        "show_interruptible_hint"
                    ],
                    "capacity_reservation_group_arn": normalized[
                        "capacity_reservation_group_arn"
                    ],
                    "capacity_reservation_fallback_to_od": normalized[
                        "capacity_reservation_fallback_to_od"
                    ],
                    "provisioning_timeout_seconds": normalized[
                        "provisioning_timeout_seconds"
                    ],
                    "connect_abandon_timeout_seconds": normalized[
                        "connect_abandon_timeout_seconds"
                    ],
                    "schedule": normalized["schedule"],
                    "launch_spec": launch_spec,
                    **({"spec_input_hash": _spec_hash} if _spec_hash else {}),
                    "apply_status": "PENDING_APPLY",
                    "updated_by": updated_by or "unknown",
                    "updated_at": _now,
                }
            )
            # One item per instance-type entry.
            for _entry in normalized["entries"]:
                batch.put_item(
                    Item={
                        "pk": _pk_val,
                        "sk": f"{_TYPE_SK_PREFIX}{_entry['instance_type']}",
                        **_entry,
                    }
                )
            # Remove entries that are no longer in the config.
            for _sk in _stale_sks:
                batch.delete_item(Key={"pk": _pk_val, "sk": _sk})

        logger.info(
            f"vdi_pool_store.put stack={stack_id} entries={len(_new_type_sks)} "
            f"pruned={len(_stale_sks)} by={updated_by}"
        )
        return SocaResponse(
            success=True,
            message={
                "stack_id": stack_id,
                "apply_status": "PENDING_APPLY",
                "entries": len(_new_type_sks),
            },
        )
    except Exception as err:
        logger.warning(f"vdi_pool_store.put stack={stack_id} failed: {err}")
        return SocaResponse(success=False, message=str(err))

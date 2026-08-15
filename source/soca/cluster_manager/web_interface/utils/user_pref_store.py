# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
DynamoDB-backed user-preferences store + resolver.

Table:  ``{EDH_CLUSTER_ID}-user-preferences``   PK = ``username``

Each preference is stored as a TOP-LEVEL attribute on the user's item
(variant-2)::

    { "username": "jsmith", "language": "fr", "vdi_tile_masking": true }

Rows are SPARSE -- an attribute exists only when the user has explicitly set
that pref. Absence => resolve through the fallback chain. ``reset`` = delete the
attribute (no sentinel value; absence IS the reset). A top-level ``SET`` on a
non-existent item auto-creates the item with its key, so there is no
parent-map existence gotcha.

Resolution (resolve-at-read, 3 tiers -- see docs/UserPreferences-Design.md):
    1. user value   -- the stored attribute, IF present AND still valid
    2. admin default -- the catalog spec's ``default_ssm`` org default (if any)
    3. code default  -- the catalog spec's static ``default``
No clamp in v1.

Read-path self-healing: a stored value that no longer passes catalog validation
(an enum value retired, a range tightened, a type changed) is treated as ABSENT
-- it falls through to the default and is logged at WARN. It is NOT auto-pruned
on read (a GET stays a GET; cleanup is the reconciliation sweep's job).

Observability: every set / clear / clear_all emits one structured INFO log line
(user, key, action, new_value). No audit table, no old-value capture (the write
stays a single blind UpdateItem / REMOVE).
"""

import logging
import os
from typing import Any, Optional

from utils.aws import boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.error import SocaError
from utils.response import SocaResponse
from utils.datamodels.soca_user_preferences import ResolvedPrefMeta
from utils import user_pref_catalog as catalog

logger = logging.getLogger("soca_logger")

_CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")
_TABLE = f"{_CLUSTER_ID}-user-preferences"
_PK = "username"


def _ddb():
    """Low-level DynamoDB client (mirrors utils.dcv_event_store._ddb)."""
    _resp = utils_boto3.get_boto(service_name="dynamodb")
    if _resp.get("success") is False:
        SocaError.AWS_API_ERROR(
            service_name="dynamodb",
            helper=f"Failed to get dynamodb client: {_resp.get('message')}",
        )
        return None
    return _resp.get("message")


def _read_ssm(key: str) -> Optional[str]:
    """
    Read a single SSM config value (tier-2 org default), or None if unset /
    unreadable. SocaConfig is imported lazily (the async_placement pattern) so
    this module stays importable off-cluster for unit tests, and so a single
    seam can be monkeypatched in tests.
    """
    from utils.config import SocaConfig

    _resp = SocaConfig(key=key).get_value(
        return_as=str, default=None, allow_unknown_key=True
    )
    if not _resp.success:
        return None
    return _resp.message


# ---------------------------------------------------------------------------
# DDB scalar <-> attribute-map helpers (driven by the catalog's declared type)
# ---------------------------------------------------------------------------
def _to_ddb_value(ptype: str, value: Any) -> dict:
    if ptype == "bool":
        _cast = SocaCastEngine(value).cast_as(expected_type=bool)
        if not _cast.get("success"):
            # Reached only on an internal inconsistency (set_pref validates the
            # value first). Log loudly via SocaError rather than silently
            # persisting a wrong default -- a silent bad write is hard to trace.
            SocaError.GENERIC_ERROR(
                helper=f"_to_ddb_value: unexpected bool cast failure for {value!r}"
            )
            return {"BOOL": False}
        return {"BOOL": _cast.get("message")}
    if ptype == "int":
        _cast = SocaCastEngine(value).cast_as(expected_type=int)
        if not _cast.get("success"):
            SocaError.GENERIC_ERROR(
                helper=f"_to_ddb_value: unexpected int cast failure for {value!r}"
            )
            return {"N": "0"}
        _str_cast = SocaCastEngine(_cast.get("message")).cast_as(expected_type=str)
        return {"N": _str_cast.get("message") if _str_cast.get("success") else "0"}
    # string / enum
    _cast = SocaCastEngine(value).cast_as(expected_type=str)
    return {"S": _cast.get("message") if _cast.get("success") else ""}


def _from_ddb_value(attr: dict) -> Any:
    if "BOOL" in attr:
        return attr["BOOL"]
    if "N" in attr:
        # v1 numeric prefs are ints only
        _cast = SocaCastEngine(attr["N"]).cast_as(expected_type=int)
        return _cast.get("message") if _cast.get("success") else None
    if "S" in attr:
        return attr["S"]
    return None


# ---------------------------------------------------------------------------
# Raw read
# ---------------------------------------------------------------------------
def _get_raw_row(username: str) -> dict:
    """
    Return the user's stored preference attributes as a decoded python dict
    (only catalog keys; metadata/PK filtered out). Empty dict if the user has
    no row. Does NOT apply defaults or validation -- this is the raw tier-1
    material the resolver consumes. Internal helper (``_`` prefixed); the public
    SocaResponse-returning entrypoints are ``resolve_pref`` / ``resolve_all``.
    """
    # One-shot recovery bypass (decision #9 / §9): when the request carries
    # ?noprefs -- or immediately after a ?resetprefs wipe -- app.before_request
    # sets g._skip_user_prefs, so this render ignores stored values entirely and
    # resolves through admin/code defaults. Optional flask import + request-context
    # guard keep the store unit-testable off-cluster (no context -> never bypass).
    try:
        from flask import g as _g, has_request_context as _has_ctx

        if _has_ctx() and getattr(_g, "_skip_user_prefs", False):
            return {}
    except Exception:
        pass

    _client = _ddb()
    if _client is None:
        return {}
    _resp = _client.get_item(
        TableName=_TABLE,
        Key={_PK: {"S": username}},
        ConsistentRead=False,
    )
    _item = _resp.get("Item", {})
    _out = {}
    for _key in catalog._all_keys():
        if _key in _item:
            _out[_key] = _from_ddb_value(_item[_key])
    return _out


# ---------------------------------------------------------------------------
# Resolver (Option-B metadata payload)
# ---------------------------------------------------------------------------
def _with_meta(
    key: str, value: Any, *, is_set: bool, source: str, spec: dict
) -> ResolvedPrefMeta:
    """
    Build the ResolvedPrefMeta payload: resolved ``value`` plus the metadata the
    UI needs (``is_set`` for a reset affordance, ``source`` tier, and for
    constrained types the ``allowed`` set / ``min``/``max`` bounds).
    """
    _ptype = spec.get("type")
    return ResolvedPrefMeta(
        value=value,
        is_set=is_set,
        source=source,
        allowed=catalog._allowed_values(key) if _ptype == "enum" else None,
        min=spec.get("min") if _ptype == "int" else None,
        max=spec.get("max") if _ptype == "int" else None,
    )


def _admin_default(key: str):
    """
    Tier 2: the admin-configured org default from SSM, if the catalog declares
    ``default_ssm`` for this key. Returns ``(value, found)``. A missing key,
    unreadable SSM, or a value that fails catalog validation all yield
    ``(None, False)`` so the resolver falls through to the code default rather
    than serving a poisoned org default.
    """
    _spec = catalog._spec(key)
    _ssm_key = _spec.get("default_ssm")
    if not _ssm_key:
        return None, False

    _raw = _read_ssm(_ssm_key)
    if _raw is None:
        return None, False

    _v = catalog.validate(key, _raw)
    if not _v.success:
        logger.warning(
            f"user_prefs: admin default for '{key}' at {_ssm_key} failed "
            f"validation ({_raw!r}); ignoring -> code default"
        )
        return None, False

    # An org default that equals the shipped code default carries no admin
    # intent -- it's the install-time seed, untouched. Treat it as absent so
    # the value resolves with source="default" rather than "admin". source
    # "admin" is reserved for an org default that DIFFERS from what we shipped
    # (i.e. an admin deliberately changed the org-wide default).
    if _v.message == _spec.get("default"):
        return None, False
    return _v.message, True


def _resolve_pref_dict(
    username: str, key: str, raw_row: Optional[dict] = None
) -> ResolvedPrefMeta:
    """
    Internal: resolve one preference through the 3-tier chain and return the
    ResolvedPrefMeta payload. ``raw_row`` may be supplied to avoid a per-key
    GetItem when resolving many keys. The public ``resolve_pref`` serializes
    this to a dict in its SocaResponse.
    """
    _spec = catalog._spec(key)
    if _spec is None:
        return ResolvedPrefMeta(value=None, is_set=False, source=None)

    _row = raw_row if raw_row is not None else _get_raw_row(username)

    # Tier 1: user's explicit value -- with read-path self-healing.
    if key in _row:
        _stored = _row[key]
        _v = catalog.validate(key, _stored)
        if _v.success:
            return _with_meta(key, _v.message, is_set=True, source="user", spec=_spec)
        logger.warning(
            f"user_prefs: stored value for user={username} key={key} is invalid "
            f"({_stored!r}); self-healing -> default (not pruned)"
        )
        # fall through: treat as absent

    # Tier 2: admin org default (SSM).
    _admin_val, _found = _admin_default(key)
    if _found:
        return _with_meta(key, _admin_val, is_set=False, source="admin", spec=_spec)

    # Tier 3: code static default.
    return _with_meta(
        key, _spec.get("default"), is_set=False, source="default", spec=_spec
    )


def resolve_pref(username: str, key: str, raw_row: Optional[dict] = None) -> SocaResponse:
    """
    Resolve one preference for ``username`` through the 3-tier chain. Returns a
    SocaResponse whose ``message`` is the Option-B metadata payload
    (``{"value", "is_set", "source", ...}``). ``raw_row`` may be supplied to
    avoid a per-key GetItem when resolving many keys (see ``resolve_all``).
    """
    return SocaResponse(
        success=True,
        message=_resolve_pref_dict(username, key, raw_row=raw_row).model_dump(),
    )


def resolve_all(username: str) -> SocaResponse:
    """
    Resolve EVERY catalog preference for ``username`` in a single GetItem.
    Returns a SocaResponse whose ``message`` is ``{key: option_b_payload}`` for
    all known keys -- a brand-new user with no row resolves every key straight
    through admin/code defaults.
    """
    _row = _get_raw_row(username)
    _resolved = {
        _key: _resolve_pref_dict(username, _key, raw_row=_row).model_dump()
        for _key in catalog._all_keys()
    }
    return SocaResponse(success=True, message=_resolved)


# ---------------------------------------------------------------------------
# Writes (caller-scoped: the caller passes their own session-derived username;
# this layer never sources the target user from request data)
# ---------------------------------------------------------------------------
def set_pref(username: str, key: str, value: Any) -> SocaResponse:
    """
    Validate + persist one preference. Returns the failed validation
    SocaResponse (status 400) on bad key/type/range, else success with the
    coerced value. The write is a single blind ``SET`` of a top-level attribute.
    """
    _v = catalog.validate(key, value)
    if not _v.success:
        return _v
    _coerced = _v.message
    _spec = catalog._spec(key)

    _client = _ddb()
    if _client is None:
        return SocaResponse(
            success=False,
            message="Failed to get dynamodb client",
            status_code=500,
        )
    _client.update_item(
        TableName=_TABLE,
        Key={_PK: {"S": username}},
        UpdateExpression="SET #k = :v",
        ExpressionAttributeNames={"#k": key},
        ExpressionAttributeValues={":v": _to_ddb_value(_spec["type"], _coerced)},
    )
    logger.info(
        f"user_prefs action=set user={username} key={key} new_value={_coerced!r}"
    )
    return SocaResponse(success=True, message=_coerced)


def clear_pref(username: str, key: str) -> SocaResponse:
    """
    Reset one preference: REMOVE the attribute so it falls back through the
    resolver chain. Unknown key => 400. Removing an absent attribute is a no-op.
    """
    if not catalog._is_known(key):
        return SocaResponse(
            success=False, message=f"unknown preference key '{key}'", status_code=400
        )
    _client = _ddb()
    if _client is None:
        return SocaResponse(
            success=False,
            message="Failed to get dynamodb client",
            status_code=500,
        )
    _client.update_item(
        TableName=_TABLE,
        Key={_PK: {"S": username}},
        UpdateExpression="REMOVE #k",
        ExpressionAttributeNames={"#k": key},
    )
    logger.info(f"user_prefs action=clear user={username} key={key}")
    return SocaResponse(success=True, message=key)


def clear_all(username: str) -> SocaResponse:
    """
    Reset ALL preferences: delete the user's row entirely. The next resolve
    falls straight through admin/code defaults. Used by ``?resetprefs`` recovery
    and the user-delete cleanup hook.
    """
    _client = _ddb()
    if _client is None:
        return SocaResponse(
            success=False,
            message="Failed to get dynamodb client",
            status_code=500,
        )
    _client.delete_item(TableName=_TABLE, Key={_PK: {"S": username}})
    logger.info(f"user_prefs action=clear_all user={username}")
    return SocaResponse(success=True, message=username)


# ---------------------------------------------------------------------------
# Maintenance (used by the Phase-8 cleanup hook + reconciliation sweep)
# ---------------------------------------------------------------------------
def all_usernames() -> SocaResponse:
    """
    Paginated Scan of every username with a stored preferences row. Pagination
    is mandatory -- an un-paginated Scan silently stops at the first 1 MB page
    and misses rows. Returns a SocaResponse whose ``message`` is the list of
    usernames (the table is small: one row per user who has ever changed a pref).
    """
    _client = _ddb()
    if _client is None:
        return SocaResponse(
            success=False,
            message="Failed to get dynamodb client",
            status_code=500,
        )
    _names = []
    _kwargs = {
        "TableName": _TABLE,
        "ProjectionExpression": "#u",
        "ExpressionAttributeNames": {"#u": _PK},
    }
    while True:
        _resp = _client.scan(**_kwargs)
        for _item in _resp.get("Items", []):
            if _PK in _item and "S" in _item[_PK]:
                _names.append(_item[_PK]["S"])
        _last = _resp.get("LastEvaluatedKey")
        if not _last:
            break
        _kwargs["ExclusiveStartKey"] = _last
    return SocaResponse(success=True, message=_names)

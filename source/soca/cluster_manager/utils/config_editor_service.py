# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
config_editor_service -- read/browse/search over the cluster's SSM config
parameters for the Admin Configuration Editor.

Reads for the editor go straight to SSM get_parameters_by_path so we get raw
values + Version + LastModifiedDate (metadata the Valkey hot-read path does not
carry). The Valkey-backed runtime hot path (SocaConfig.get_value used by the
rest of the app) is unchanged. Writes (a later slice) go through
SocaConfig.set_value -> validation + put_parameter + Valkey write-through.

Every function returns SocaResponse/SocaError (web-tier contract). The API
handlers add .as_flask(). `hidden` params (per config_registry) are pruned from
listings/tree and redacted from search -- both the match AND the value -- so the
editor never becomes a secret-exfiltration path.
"""

import logging
import os
from datetime import timezone

import utils.aws.boto3_wrapper as utils_boto3
from utils.response import SocaResponse
from utils.error import SocaError
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.settings.config_checks import SocaConfigKeyVerifier
from utils.validators import Validators
from utils import config_registry as registry
from helpers import config_audit_store as audit_store

logger = logging.getLogger("soca_logger")

_CLUSTER_ID = os.environ.get("EDH_CLUSTER_ID", "")
_PREFIX = f"/edh/{_CLUSTER_ID}"

_ssm_client = None


def _ssm():
    global _ssm_client
    if _ssm_client is None:
        _resp = utils_boto3.get_boto(service_name="ssm")
        if _resp.success is False:
            logger.error("config_editor: could not get ssm client: %s", _resp.message)
            return None
        _ssm_client = _resp.message
    return _ssm_client


def _rel(name):
    """Strip the /edh/<cluster_id> prefix -> editor-relative key."""
    return name[len(_PREFIX):] if name.startswith(_PREFIX) else name


def _iso(dt):
    try:
        return dt.astimezone(timezone.utc).isoformat()
    except Exception:
        return None


def _scan(rel_prefix="/"):
    """Yield every parameter under the (relative) prefix as raw dicts.

    Returns [] on error (logged). Does NOT decrypt SecureString values --
    secrets are handled by the hidden-redaction layer regardless.
    """
    full = f"{_PREFIX}{rel_prefix if rel_prefix.startswith('/') else '/' + rel_prefix}"
    rows = []
    try:
        paginator = _ssm().get_paginator("get_parameters_by_path")
        for page in paginator.paginate(Path=full, Recursive=True, WithDecryption=False):
            for p in page.get("Parameters", []):
                rows.append(
                    {
                        "key": _rel(p["Name"]),
                        "value": p.get("Value", ""),
                        "version": p.get("Version"),
                        "last_modified": _iso(p.get("LastModifiedDate")),
                        "ssm_type": p.get("Type"),
                    }
                )
    except Exception as e:
        logger.error("config_editor _scan(%s) failed: %s", full, e)
    return rows


_validator_schema = None
_validator_loaded = False
_WRITABLE_SPECIAL = (
    "/configuration/CustomTags/",
    "/configuration/HPC/schedulers/",
    "/configuration/HPC/hooks/",
)


def _load_validator_schema():
    """Load socaconfig_key_validator.yml once (the EDH write-allowlist/schema).
    Returns the dict, or None if unavailable (in which case we do NOT
    over-restrict -- SocaConfig.set_value still gates writes)."""
    global _validator_schema, _validator_loaded
    if _validator_loaded:
        return _validator_schema
    _validator_loaded = True
    try:
        import yaml
        with open(SocaConfigKeyVerifier._KEY_CONFIG_FILE, "r", encoding="utf-8") as fh:
            _validator_schema = yaml.safe_load(fh)
    except Exception as e:
        logger.warning("config_editor: validator schema unavailable (%s); not restricting on writability", e)
        _validator_schema = None
    return _validator_schema


def _writability(key):
    """Is this key writable per EDH's own rules? Returns (bool, reason).
    Mirrors SocaConfigKeyVerifier: immutable list, CustomTags/HPC specials,
    FileSystems path normalization, then schema-tree presence."""
    k = key if key.startswith("/") else "/" + key
    if k in SocaConfigKeyVerifier._IMMUTABLE_KEYS:
        return (False, "immutable")
    for s in _WRITABLE_SPECIAL:
        if s in k:
            return (True, "")
    if "/configuration/FileSystems/" in k:
        _rest = k.split("/configuration/FileSystems/")[1]
        k = "/configuration/FileSystems/" + "/".join(_rest.split("/")[1:])
    schema = _load_validator_schema()
    if not Validators.is_dict(schema):
        return (True, "")
    vt = SocaConfigKeyVerifier.get_validation_test(schema, [s for s in k.split("/") if s])
    return (True, "") if vt is not None else (False, "not writable (no config schema entry)")


def _decorate(row):
    """Attach registry policy + effective writability to a raw row.
    Returns None if hidden (caller prunes). Effective editable = registry
    editable AND EDH-writable; readonly badge carries a reason."""
    policy = registry.resolve(row["key"])
    if policy["hidden"]:
        return None
    row = dict(row)
    row["leaf"] = row["key"].rstrip("/").split("/")[-1]
    _reg_editable = policy["editable"]
    _w_editable, _w_reason = _writability(row["key"])
    editable = _reg_editable and _w_editable
    row["editable"] = editable
    row["readonly"] = not editable
    if not _reg_editable:
        row["ro_reason"] = "read-only (policy)"
    elif not _w_editable:
        row["ro_reason"] = _w_reason
    else:
        row["ro_reason"] = ""
    row["impact"] = policy["impact"]
    row["type"] = policy["type"]
    row["description"] = policy["description"]
    row["value_rules"] = policy["value_rules"]
    return row


def list_params(prefix="/", direct=False):
    """List visible params under a relative prefix, policy-decorated.

    direct=True returns only the params whose key sits *directly* under the
    prefix (no further path segment) -- i.e. the leaves at this tree level.
    Branches are navigated via the tree, not listed here.
    """
    out = [d for d in (_decorate(r) for r in _scan(prefix)) if d is not None]
    if direct:
        base = prefix if prefix.startswith("/") else "/" + prefix
        if not base.endswith("/"):
            base += "/"

        def _is_direct(k):
            rem = k[len(base):] if k.startswith(base) else k
            return rem != "" and "/" not in rem

        out = [r for r in out if _is_direct(r["key"])]
    out.sort(key=lambda r: r["key"])
    return SocaResponse(success=True, message=out)


def build_tree():
    """Nested tree of path segments over ALL visible params, with per-node
    leaf counts. Shape: {name, path, children:{...}, count}."""
    root = {"name": "", "path": "", "children": {}, "count": 0, "leaf_count": 0}
    for r in _scan("/"):
        if registry.resolve(r["key"])["hidden"]:
            continue
        segs = [s for s in r["key"].split("/") if s != ""]
        node = root
        node["count"] += 1
        acc = ""
        # all but the last segment are tree nodes; the last is the leaf param
        for seg in segs[:-1]:
            acc = f"{acc}/{seg}"
            child = node["children"].get(seg)
            if child is None:
                child = {"name": seg, "path": acc, "children": {}, "count": 0, "leaf_count": 0}
                node["children"][seg] = child
            child["count"] += 1
            node = child
        # `node` is now the branch that directly holds this leaf param
        node["leaf_count"] += 1
    return SocaResponse(success=True, message=root)


def search(q, scope="both"):
    """Search visible params by key and/or value substring (case-insensitive).

    scope: "key" | "value" | "both" (default). hidden params never match and
    their values are never returned.
    """
    q = (q or "").strip().lower()
    if not q:
        return SocaResponse(success=True, message=[])
    scope = scope if scope in ("key", "value", "both") else "both"
    hits = []
    for r in _scan("/"):
        policy = registry.resolve(r["key"])
        if policy["hidden"]:
            continue
        key_l = r["key"].lower()
        _vl = SocaCastEngine(r["value"]).cast_as(str)
        val_l = (_vl.message if _vl.success else "").lower()
        match_key = scope in ("key", "both") and q in key_l
        match_val = scope in ("value", "both") and q in val_l
        if match_key or match_val:
            d = _decorate(r)
            if d is not None:
                d["matched_on"] = "key" if match_key and not match_val else ("value" if match_val and not match_key else "both")
                hits.append(d)
    hits.sort(key=lambda r: r["key"])
    return SocaResponse(success=True, message=hits)


def get_param(key):
    """Single param detail + policy. Refuses hidden params."""
    if not key:
        return SocaError.GENERIC_ERROR(helper="key is required", status_code=400)
    policy = registry.resolve(key)
    if policy["hidden"]:
        return SocaError.GENERIC_ERROR(helper="Parameter not available", status_code=404)
    full = f"{_PREFIX}{key if key.startswith('/') else '/' + key}"
    try:
        resp = _ssm().get_parameter(Name=full, WithDecryption=False)
        p = resp["Parameter"]
        row = {
            "key": _rel(p["Name"]),
            "value": p.get("Value", ""),
            "version": p.get("Version"),
            "last_modified": _iso(p.get("LastModifiedDate")),
            "ssm_type": p.get("Type"),
        }
    except Exception as e:
        return SocaError.AWS_API_ERROR(
            service_name="ssm_parameterstore",
            helper=f"Could not read {full}: {e}",
        )
    row = _decorate(row)
    return SocaResponse(success=True, message=row)


def get_history(key):
    """SSM version history for a param (newest first). Refuses hidden params."""
    if not key:
        return SocaError.GENERIC_ERROR(helper="key is required", status_code=400)
    if registry.resolve(key)["hidden"]:
        return SocaError.GENERIC_ERROR(helper="Parameter not available", status_code=404)
    _hist = SocaConfig(key=key).get_value_history(sort="desc")
    if not _hist.success:
        return _hist
    # Normalize {version: {Version, Value, LastModifiedDate}} -> sorted list
    out = []
    for v in _hist.message.values():
        out.append(
            {
                "version": v.get("Version"),
                "value": v.get("Value", ""),
                "last_modified": _iso(v.get("LastModifiedDate")),
            }
        )
    # Merge DDB audit attribution (who/source) by ssm version. Versions with no
    # audit row (deploy-time seeds, out-of-band SSM edits) render as system.
    try:
        _aud = audit_store.history_for(key)
    except Exception:
        _aud = {}
    for row in out:
        a = _aud.get(row["version"])
        row["edh_admin"] = a.get("edh_admin") if a else None
        row["source"] = a.get("source") if a else None
    return SocaResponse(success=True, message=out)


def list_activity(days=7, limit=200):
    """Cluster-wide recent config changes (newest first) from the audit GSI."""
    try:
        return SocaResponse(success=True, message=audit_store.recent_activity(days=days, limit=limit))
    except Exception as e:
        return SocaError.GENERIC_ERROR(helper=f"activity query failed: {e}", status_code=500)


def set_param(key, value, actor="unknown-user"):
    """Write one param via SocaConfig.set_value (validation + put_parameter +
    Valkey write-through). Enforces editor policy: hidden/readonly are refused.
    Returns a plain result dict for batch aggregation (not a SocaResponse)."""
    if not key:
        return {"key": key, "success": False, "error": "missing key"}
    policy = registry.resolve(key)
    if policy["hidden"]:
        return {"key": key, "success": False, "error": "parameter not available"}
    if not policy["editable"]:
        return {"key": key, "success": False, "error": "parameter is read-only"}
    _w_editable, _w_reason = _writability(key)
    if not _w_editable:
        return {"key": key, "success": False, "error": _w_reason or "not writable"}
    _old_value = None
    try:
        _full = f"{_PREFIX}{key if key.startswith('/') else '/' + key}"
        _old_value = _ssm().get_parameter(Name=_full, WithDecryption=False)["Parameter"].get("Value")
    except Exception:
        _old_value = None
    _vc = SocaCastEngine(value).cast_as(str)
    if not _vc.success:
        return {"key": key, "success": False, "error": "could not convert value to string"}
    _value_str = _vc.message
    _res = SocaConfig(key=key).set_value(_value_str)
    if not _res.success:
        _mc = SocaCastEngine(_res.message or "").cast_as(str)
        _msg = _mc.message if _mc.success else ""
        if "already" in _msg.lower():
            # value unchanged -- treat as a no-op success, not an error
            return {"key": key, "success": True, "new_version": None, "unchanged": True}
        return {"key": key, "success": False, "error": _msg}
    new_version = None
    try:
        full = f"{_PREFIX}{key if key.startswith('/') else '/' + key}"
        new_version = _ssm().get_parameter(Name=full, WithDecryption=False)["Parameter"].get("Version")
    except Exception as e:
        logger.warning("set_param: wrote %s but could not read back version: %s", key, e)
    try:
        audit_store.record(key, _old_value, _value_str, new_version, actor, source="ui")
    except Exception as e:
        logger.warning("set_param: audit record failed for %s: %s", key, e)
    logger.info("config_editor: %s set %s (v%s)", actor, key, new_version)
    return {"key": key, "success": True, "new_version": new_version}


def batch_set(items, actor="unknown-user"):
    """Best-effort batch write. Returns {results:[{key,success,new_version?,error?}]}.
    SSM has no transactions -- each write is independent; a failure does not
    abort the rest."""
    results = []
    for it in (items or []):
        it = it or {}
        results.append(set_param(it.get("key"), it.get("value", ""), actor=actor))
    return SocaResponse(success=True, message={"results": results})

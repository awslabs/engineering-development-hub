# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
config_registry -- catalog + policy resolver for the SSM Configuration Editor.

Loads config_registry.yml (web_interface root) once and answers, for any SSM
parameter key (relative to the /edh/<cluster_id> prefix), how the editor must
treat it: editable / readonly / hidden, restart impact, value type, optional
value rules, and a human description.

Resolution order: exact `params` match -> longest-prefix `prefixes` match ->
module DEFAULTS. Unlisted params therefore need zero hand-annotation.

PyYAML is available in the web tier (utils.cast / utils.settings.config_checks
both import it). The loader is defensive: a missing/broken file degrades to
DEFAULTS-for-everything rather than 500-ing the page.
"""

import logging
import os
import threading

import yaml
from utils.cast import SocaCastEngine
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

_REGISTRY_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config_registry.yml"
)

DEFAULTS = {
    "editable": True,
    "readonly": False,
    "hidden": False,
    "impact": "hot",
    "type": "string",
    "value_rules": {},
    "description": "",
}

_ALLOWED_TYPES = {"string", "int", "bool", "json", "csv"}

_lock = threading.Lock()
_cache = None  # {"prefixes": {...}, "params": {...}}


def _load():
    """Load + normalize the registry file. Never raises."""
    global _cache
    with _lock:
        if _cache is not None:
            return _cache
        data = {"prefixes": {}, "params": {}}
        try:
            with open(_REGISTRY_FILE, "r", encoding="utf-8") as fh:
                raw = yaml.safe_load(fh) or {}
            if Validators.is_dict(raw):
                data["prefixes"] = raw.get("prefixes") or {}
                data["params"] = raw.get("params") or {}
        except FileNotFoundError:
            logger.warning("config_registry.yml not found at %s; using defaults", _REGISTRY_FILE)
        except Exception as e:  # malformed YAML etc -- degrade, do not crash the page
            logger.error("Failed to load config_registry.yml (%s); using defaults", e)
        _cache = data
        return _cache


def reload():
    """Drop the cache so the next resolve() re-reads the file (SIGHUP-friendly)."""
    global _cache
    with _lock:
        _cache = None


def _normalize(rule):
    """Merge a raw rule dict over DEFAULTS, coercing/validating fields."""
    out = dict(DEFAULTS)
    out["value_rules"] = {}  # fresh mutable copy (DEFAULTS' is shared)
    if Validators.is_dict(rule):
        for k in ("editable", "readonly", "hidden"):
            if k in rule:
                _b = SocaCastEngine(rule[k]).cast_as(bool)
                out[k] = _b.message if _b.success else False
        if rule.get("impact"):
            _i = SocaCastEngine(rule["impact"]).cast_as(str)
            if _i.success:
                out["impact"] = _i.message
        _tc = SocaCastEngine(rule.get("type") or "").cast_as(str)
        _t = (_tc.message if _tc.success else "").lower()
        if _t in _ALLOWED_TYPES:
            out["type"] = _t
        if Validators.is_dict(rule.get("value_rules")):
            out["value_rules"] = rule["value_rules"]
        if rule.get("description"):
            _d = SocaCastEngine(rule["description"]).cast_as(str)
            if _d.success:
                out["description"] = _d.message
    # readonly implies not editable
    if out["readonly"]:
        out["editable"] = False
    return out


def resolve(key):
    """Return the effective policy dict for a relative SSM key.

    key: parameter name relative to /edh/<cluster_id>, e.g.
         "/configuration/VirtualDesktops/MaxProvisioning".
    """
    reg = _load()
    if not key.startswith("/"):
        key = "/" + key

    # 1. exact param override
    if key in reg["params"]:
        return _normalize(reg["params"][key])

    # 2. longest-prefix match
    best = None
    best_len = -1
    for prefix, rule in reg["prefixes"].items():
        _p = prefix if prefix.startswith("/") else "/" + prefix
        if key.startswith(_p) and len(_p) > best_len:
            best = rule
            best_len = len(_p)
    if best is not None:
        return _normalize(best)

    # 3. defaults
    return _normalize({})


def is_restart_impact(policy):
    """True if the policy carries a restart:<service> impact tier."""
    _ic = SocaCastEngine(policy.get("impact", "")).cast_as(str)
    return (_ic.message if _ic.success else "").startswith("restart:")


def restart_service(policy):
    """The service name for a restart:<service> impact, else ''."""
    _ic = SocaCastEngine(policy.get("impact", "")).cast_as(str)
    _i = _ic.message if _ic.success else ""
    return _i.split("restart:", 1)[1] if _i.startswith("restart:") else ""

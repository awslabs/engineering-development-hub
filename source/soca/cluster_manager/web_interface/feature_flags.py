# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.cache.decorator import soca_cache
from utils.response import SocaResponse
from utils.error import SocaError
import ast
from typing import Any
import logging

logger = logging.getLogger("soca_logger")


from utils.validators import Validators

# ------------------------------------------------------------------------------
# FEATURE FLAGS
# Use enabled: False to fully disable a feature for everyone regardless of user lists.
# If enabled: True and allowed_users is empty, it implies all users are allowed unless explicitly denied.
# if enabled: True and allowed_users is not empty, it implies only those users are allowed unless explicitly denied.
#
#
# - VIRTUAL_DESKTOPS: Manage Virtual Desktops Views and APIs
# - TARGET_NODES: Manage Target Nodes Views and APIs
# - LOGIN_NODES: Manage Login Nodes Views and APIs (e.g: SSH section on the web UI)
# - WEBSHELL: Enable the in-browser terminal tab on the SSH page. This requires the edh-webshell service to be running on the Login Nodes, which is configured via the login node bootstrap script (compute_node/extra/login_node.sh.j2). The webshell service listens on a configurable TCP port (default 7681) and the WebUI ALB is configured to forward traffic to that port on the Login Nodes when this feature is enabled.
# - HPC: Manage HPC Views and APIs, including My Jobs Queue, and web based job submission
# - RUN_REMOTE_COMMAND: Allow to run Remote Command on the Controller
# - FILE_BROWSER: Manage File Browser (My Files) Views and APIs
# - FILE_LIVE_TAIL: Manage Live File Tail Views (depends on FILE_BROWSER)
# - USERS_GROUPS_MANAGEMENT: Users/Groups Management
# - CONTAINER_MANAGEMENT: Manage Containers Views and APIs
# - MY_API_KEY_MANAGEMENT: Manage API Key Views and APIs
# - MY_API_TOKENS: Manage Scoped API Token Views and APIs (create, renew, revoke, audit)
# - MY_ACCOUNT_MANAGEMENT: Manage My Account Views
# - ANALYTICS_COST_MANAGEMENT: Manage Budget/Analytics Views
# - AI_ASSISTANT: Manage AI Assistant Views and APIs (Bedrock/Anthropic)
# ------------------------------------------------------------------------------

FEATURE_FLAGS = {
    "VIRTUAL_DESKTOPS": {"enabled": True, "allowed_users": [], "denied_users": []},
    "TARGET_NODES": {"enabled": True, "allowed_users": [], "denied_users": []},
    "LOGIN_NODES": {"enabled": True, "allowed_users": [], "denied_users": []},
    "WEBSHELL": {"enabled": True, "allowed_users": [], "denied_users": []},
    # Code editor (VS Code in browser). Requires code-server installed on the
    # controller and the code-server nginx reverse proxy config under
    # /etc/nginx/conf.d/edh-code-server.conf.
    "CODE_SERVER": {"enabled": True, "allowed_users": [], "denied_users": []},
    "HPC": {"enabled": True, "allowed_users": [], "denied_users": []},
    "RUN_REMOTE_COMMAND": {
        "enabled": False,
        "allowed_users": [],
        "denied_users": [],
    },  # WARNING: this will allow user to run remote command on the scheduler
    "FILE_BROWSER": {"enabled": True, "allowed_users": [], "denied_users": []},
    "FILE_LIVE_TAIL": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
        # Live file tail requires FILE_BROWSER to be enabled; the viewer is
        # only reachable via the file explorer's per-row tail button and
        # re-uses the file_explorer encrypted UID model for authorization.
        # If FILE_BROWSER is disabled, FILE_LIVE_TAIL is automatically
        # inaccessible regardless of this flag's `enabled` value.
        #
        # `depends_on` may be a single string ("FILE_BROWSER") or a list of
        # strings (["FLAG_A", "FLAG_B"]) for multi-parent AND dependencies.
        # The list form is preferred for forward-compatibility even when
        # only one parent exists today.
        "depends_on": ["FILE_BROWSER"],
    },
    "USERS_GROUPS_MANAGEMENT": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
    "CONTAINERS_MANAGEMENT_EKS": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
    "CONTAINERS_MANAGEMENT_BATCH": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
    "MY_API_KEY_MANAGEMENT": {"enabled": True, "allowed_users": [], "denied_users": []},
    "MY_API_TOKENS": {"enabled": True, "allowed_users": [], "denied_users": []},
    "MY_ACCOUNT_MANAGEMENT": {  # WARNING: this will remove password reset ability for your users
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
    "ANALYTICS_COST_MANAGEMENT": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
    },
    # Cluster Configuration editor (SSM Parameter Store browse/edit + audit).
    # Admin-gated; DDB audit-table infra always deploys, but the WebUI page,
    # nav entry, and /api/admin/config/* endpoints only render/serve when this
    # flag is enabled. Default OFF -- opt-in.
    "CONFIG_EDITOR": {"enabled": False, "allowed_users": [], "denied_users": []},
    "AI_ASSISTANT": {"enabled": True, "allowed_users": [], "denied_users": []},
    # Golden Image Publish: self-service nomination and publish workflow for
    # software stack AMIs. You nominate a SAVED desktop, so this depends on
    # SAVED_DESKTOPS -- which itself chains VIRTUAL_DESKTOPS -- ensuring both the
    # saved-desktop capability and its infrastructure exist. Ships enabled;
    # scope per cluster via allowed_users/denied_users/allowed_groups, or set
    # enabled=False to ship it dark.
    "GOLDEN_IMAGE_PUBLISH": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
        "allowed_groups": ["sudoers"],
        "denied_groups": [],
        "depends_on": ["SAVED_DESKTOPS"],
    },
    # Saved Desktops (Save & Shut Down / resume / recycle bin / Spot ITN
    # auto-capture). This flag's `enabled` field is the cluster capability
    # switch -- it REPLACES the legacy SSM knob
    # /configuration/FeatureFlags/VirtualDesktops/AllowSavedDesktops (retired).
    # allowed_groups scopes WHO can use it (default: sudoers). Per-cluster
    # override via the /configuration/FeatureFlags/SAVED_DESKTOPS/* SSM overlay.
    "SAVED_DESKTOPS": {
        "enabled": True,
        "allowed_users": [],
        "denied_users": [],
        "allowed_groups": ["sudoers"],
        "denied_groups": [],
        "depends_on": ["VIRTUAL_DESKTOPS"],
    },
}


# ------------------------------------------------------------------------------
# Startup validation
# ------------------------------------------------------------------------------
# validate_feature_flags() is called once at Flask app startup (from app.py,
# right before register_blueprint) to surface misconfigurations early. It's
# non-fatal -- the runtime `feature_flag` decorator handles every edge case
# safely via "deny on uncertainty" -- but startup warnings make typos and
# broken config easy to spot in the server log rather than requiring an
# operator to reproduce "feature unavailable" errors in the UI.
#
# Issues reported:
#   * `depends_on` references a flag name that doesn't exist in FEATURE_FLAGS
#   * `depends_on` value is not a string, list, tuple, or None
#   * list entries that aren't strings
#   * cycles in the dependency graph (any path that loops back to itself)
#   * a flag that isn't itself a dict
# ------------------------------------------------------------------------------


def _normalize_depends_on(dep):
    """Coerce a depends_on value to a list of string parent flag names.

    Mirrors the logic in decorators.feature_flag so validation matches
    runtime semantics exactly. Silently drops non-string entries -- those
    are reported separately via _iter_flag_issues.
    """
    if dep is None:
        return []
    if Validators.is_string(dep):
        return [dep]
    if Validators.is_list(dep):
        return [d for d in dep if Validators.is_string(d)]
    return []


def _iter_flag_issues():
    """Generator of (flag_name, issue_string) tuples covering every
    misconfiguration in FEATURE_FLAGS. Does NOT raise; designed for
    log-only reporting at startup.
    """
    known_flags = set(FEATURE_FLAGS.keys())

    for flag_name, config in FEATURE_FLAGS.items():
        if not Validators.is_dict(config):
            yield flag_name, f"config is not a dict (got {type(config).__name__})"
            continue

        dep = config.get("depends_on")
        # Valid shapes: absent, None, str, list (tuples intentionally not
        # supported -- config is YAML/JSON-authored which has no tuples).
        if (
            dep is not None
            and not Validators.is_string(dep)
            and not Validators.is_list(dep)
        ):
            yield flag_name, f"depends_on has invalid type {type(dep).__name__} (expected str, list, or None)"
            continue

        # Non-string entries in the list
        if Validators.is_list(dep):
            for idx, entry in enumerate(dep):
                if not Validators.is_string(entry):
                    yield flag_name, (
                        f"depends_on[{idx}] is not a string "
                        f"(got {type(entry).__name__}: {entry!r})"
                    )

        # Unknown parent references
        for parent in _normalize_depends_on(dep):
            if parent not in known_flags:
                yield flag_name, f"depends_on references unknown flag {parent!r}"

    # Cycle detection: run an iterative DFS from each flag and check if
    # we revisit the origin.
    for origin in FEATURE_FLAGS.keys():
        origin_config = FEATURE_FLAGS.get(origin)
        if not Validators.is_dict(origin_config):
            # Not a dict -- can't have depends_on; the non-dict case was
            # already reported above. Skip to avoid AttributeError.
            continue
        visited = set()
        stack = list(_normalize_depends_on(origin_config.get("depends_on")))
        cycle_detected = False
        while stack:
            node = stack.pop()
            if node == origin:
                cycle_detected = True
                break
            if node in visited:
                continue
            visited.add(node)
            parent_config = FEATURE_FLAGS.get(node, {})
            if Validators.is_dict(parent_config):
                stack.extend(_normalize_depends_on(parent_config.get("depends_on")))
        if cycle_detected:
            yield origin, "depends_on chain contains a cycle back to this flag"


def validate_feature_flags():
    """
    Walk FEATURE_FLAGS once and log a warning for every misconfiguration.
    Returns the number of issues found (so callers / tests can assert on
    a clean dict).

    Non-fatal by design: the `feature_flag` decorator handles cycles,
    unknown parents, and malformed entries safely at runtime (via cycle-
    protected BFS and "deny on uncertainty"). This function exists purely
    to surface configuration errors to operators at startup.
    """
    issue_count = 0
    for flag_name, issue in _iter_flag_issues():
        logger.warning(f"FEATURE_FLAGS[{flag_name!r}]: {issue}")
        issue_count += 1
    if issue_count == 0:
        logger.debug(
            f"FEATURE_FLAGS: {len(FEATURE_FLAGS)} flags validated with 0 issues"
        )
    else:
        logger.warning(
            f"FEATURE_FLAGS: {issue_count} issue(s) detected across "
            f"{len(FEATURE_FLAGS)} flags -- see preceding warnings. "
            f"Runtime access checks will degrade safely (deny on uncertainty); "
            f"fix the config to silence these warnings."
        )
    return issue_count


# ------------------------------------------------------------------------------
# SSM overlay
# ------------------------------------------------------------------------------
# FEATURE_FLAGS above are CODE DEFAULTS. Per-cluster overrides live in SSM under
#   /configuration/FeatureFlags/<FLAG_NAME>/<Field>
# (Field in PascalCase: Enabled, AllowedUsers, DeniedUsers, AllowedGroups,
# DeniedGroups). Each present field is merged over the code default at read
# time, so a cluster retunes access with no redeploy (EDH walk-away principle).
# Absent keys == code default. List fields are JSON arrays (e.g. '["sudoers"]').
#
# ALL readers (feature_flag decorator, template context, views) MUST go through
# get_flag() / get_effective_flags() -- never read FEATURE_FLAGS directly -- so
# the overlay applies uniformly.

_OVERLAY_LIST_FIELDS = (
    "allowed_users",
    "denied_users",
    "allowed_groups",
    "denied_groups",
)


def _overlay_field_camel(field):
    """allowed_users -> AllowedUsers (SSM key segment)."""
    return "".join(part.capitalize() for part in field.split("_"))


def _overlay_key(flag_name, field_camel):
    return f"/configuration/FeatureFlags/{flag_name}/{field_camel}"


def _read_enabled_override(flag_name):
    """Bool override for `enabled`, or None if unset."""
    _resp = SocaConfig(
        key=_overlay_key(flag_name, "Enabled")
    ).get_value(return_as=bool, default=None, allow_unknown_key=True)
    if _resp.get("success") is True and _resp.get("message") is not None:
        return _resp.get("message") is True
    return None


def _read_list_override(flag_name, field):
    """List override for a user/group field from SSM (JSON array), or None."""
    _resp = SocaConfig(
        key=_overlay_key(flag_name, _overlay_field_camel(field))
    ).get_value(return_as=str, default=None, allow_unknown_key=True)
    if _resp.get("success") is not True:
        return None
    _raw = _resp.get("message")
    if not Validators.is_string_not_empty(_raw):
        return None
    _cast = SocaCastEngine(_raw).as_json()
    if _cast.get("success") is True and Validators.is_list(_cast.get("message")):
        _items = []
        for _v in _cast.get("message"):
            _sc = SocaCastEngine(_v).cast_as(expected_type=str)
            if _sc.get("success") is True:
                _items.append(_sc.get("message"))
        return _items
    logger.warning(
        f"FEATURE_FLAGS overlay: {flag_name}/{field} is not a JSON list "
        f"({_raw!r}); keeping code default"
    )
    return None


@soca_cache(prefix="feature_flags_overlay", ttl=60)
def get_flag(flag_name):
    """Effective flag config = code default with a per-field SSM overlay merged
    on top, returned as SocaResponse(success=True, message=<merged dict>). A
    flag that is missing or malformed returns a SocaError (the decorator denies
    safely). Fail-safe: any overlay READ error falls back to the code default.

    Programmatic dispatch: consumed in-process by the feature_flag decorator,
    the template context and views (via .get("message")), never returned as an
    HTTP response, so it is intentionally NOT wrapped with .as_flask().

    Caching: @soca_cache (SocaCacheClient / ElastiCache, shared across workers,
    60s) caches only the successful merged result, so a config flip takes effect
    within the TTL and a cache outage degrades to a live SSM read (never a
    denial).
    """
    _base = FEATURE_FLAGS.get(flag_name, {})
    if not Validators.is_dict(_base):
        return SocaError.GENERIC_ERROR(
            helper=f"Feature flag {flag_name!r} is missing or malformed"
        )

    _merged = dict(_base)
    _merged.setdefault("allowed_groups", [])
    _merged.setdefault("denied_groups", [])

    # Stage overlay overrides and apply them only if ALL reads succeed, so a
    # mid-read error truly falls back to code defaults (never a partial merge).
    _overrides = {}
    try:
        _en = _read_enabled_override(flag_name)
        if _en is not None:
            _overrides["enabled"] = _en
        for _field in _OVERLAY_LIST_FIELDS:
            _ov = _read_list_override(flag_name, _field)
            if _ov is not None:
                _overrides[_field] = _ov
    except Exception as err:
        logger.warning(
            f"FEATURE_FLAGS overlay read failed for {flag_name}: {err}; "
            f"using code defaults"
        )
        _overrides = {}

    _merged.update(_overrides)
    return SocaResponse(success=True, message=_merged)


def get_effective_flags():
    """All flags with the SSM overlay applied, as
    SocaResponse(success=True, message={flag_name: <merged dict>}). For template
    context / bulk reads; consumed in-process (via .get("message")), never an
    HTTP response, so intentionally not .as_flask()-wrapped. A flag that fails
    to resolve falls back to its code default so the map is always complete.
    """
    _flags = {}
    for _name in FEATURE_FLAGS.keys():
        _r = get_flag(_name)
        if _r.get("success") is True:
            _flags[_name] = _r.get("message")
        else:
            _flags[_name] = FEATURE_FLAGS.get(_name, {})
    return SocaResponse(success=True, message=_flags)


def is_user_allowed(flag_name, user):
    """Whether `user` passes `flag_name` (enabled + deny/allow across users AND
    groups), returned as SocaResponse(success=True, message=<bool>). Mirrors the
    API decorator so UI/template gates match it. Does not walk depends_on (UI
    gates gate the parent separately). Group refs resolve via
    utils.group_resolver (fail-closed). Consumed in-process (via .get("message")),
    never an HTTP response, so intentionally not .as_flask()-wrapped.
    """
    from utils.group_resolver import resolve_membership

    _ff = get_flag(flag_name)
    if _ff.get("success") is not True:
        return SocaResponse(success=True, message=False)
    _feature = _ff.get("message")
    if not Validators.is_dict(_feature) or _feature.get("enabled", False) is not True:
        return SocaResponse(success=True, message=False)

    _denied_users = _feature.get("denied_users", []) or []
    _allowed_users = _feature.get("allowed_users", []) or []
    _denied_groups = _feature.get("denied_groups", []) or []
    _allowed_groups = _feature.get("allowed_groups", []) or []

    if user in _denied_users:
        return SocaResponse(success=True, message=False)
    for _g in _denied_groups:
        _m = resolve_membership(user, _g)
        if _m.get("success") is True and _m.get("message") is True:
            return SocaResponse(success=True, message=False)

    if not _allowed_users and not _allowed_groups:
        return SocaResponse(success=True, message=True)
    if user in _allowed_users:
        return SocaResponse(success=True, message=True)
    for _g in _allowed_groups:
        _m = resolve_membership(user, _g)
        if _m.get("success") is True and _m.get("message") is True:
            return SocaResponse(success=True, message=True)
    return SocaResponse(success=True, message=False)

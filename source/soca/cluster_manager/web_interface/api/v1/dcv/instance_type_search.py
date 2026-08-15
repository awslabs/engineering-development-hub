# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Admin typeahead search for EC2 instance types (VDI pool config form).

Route (registered in app.py):
    GET /api/dcv/virtual_desktops/instance_types?q=<substr>&limit=<n>

Returns up to `limit` instance types whose name matches `q` (prefix matches
ranked first, then substring), each decorated with the hardware-spec hints an
admin uses to pick a size (vCPU / RAM / GPU / arch / disk / network). This is
the AJAX alternative to embedding the full ~800-type list in the page: the
catalog is loaded ONCE per worker (specs are immutable) via a paginated
describe_instance_types with no filter, and every keystroke is served from the
in-process cache (no per-keystroke AWS call).

The same cache backs submit-time validation -- `is_known_instance_type()` lets
the pool-config save path reject a non-existent instance type with a clear
message (and catches future/API callers, not just the form).

VDI software stacks / admin only.
"""

import logging
import threading

from flask import request
from flask_restful import Resource

from decorators import admin_api, feature_flag
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators
from utils.cache.decorator import soca_cache
from utils.aws.instance_type_specs import parse_instance_specs
import utils.aws.boto3_wrapper as utils_boto3
import utils.aws.ec2_helper as ec2_helper

logger = logging.getLogger("soca_logger")

# name -> spec dict. Instance-type specs are immutable -> cache the whole
# catalog for the worker lifetime; only the first request pays the describe.
_ALL_TYPES: dict = {}
_LOAD_LOCK = threading.Lock()
_LOADED = False

# A VDI software stack's AMI is a single architecture; an instance of a
# different arch can't boot it. We compare the stack's stored ami_arch against
# each type's SupportedArchitectures. EC2 uses x86_64 / arm64 in both places;
# "aarch64" only ever appears as display text, so normalize it just in case.
_ARCH_ALIASES = {"aarch64": "arm64"}


def _norm_arch(a: str) -> str:
    _a = (a or "").strip().lower()
    return _ARCH_ALIASES.get(_a, _a)


def _type_archs(spec: dict) -> set:
    """SupportedArchitectures of a catalog spec as a normalized set."""
    return {
        _norm_arch(x) for x in (spec.get("arch") or "").split(",") if x.strip()
    }


# Spec parsing lives in utils/aws/instance_type_specs.py so the admin typeahead
# and the end-user launch modal share ONE parser (and therefore one spec-line
# shape). Do not reintroduce a local parser here.
_parse = parse_instance_specs


@soca_cache(prefix="edh:webui:aws:ec2:vdi_instance_type_catalog:v8", ttl=86400)
def _fetch_catalog() -> SocaResponse:
    """Full region instance-type catalog (name -> spec) as a Valkey-cached
    SocaResponse. The expensive paginated describe runs ~once fleet-wide
    (specs are immutable; the 24h TTL covers new-type additions). Only a
    successful response is cached, so a transient failure is retried next call.
    Mirrors the @soca_cache pattern used across utils/aws/ec2_helper.py.

    NOTE: bump the cache-key version suffix (:v2, :v3, ...) whenever _parse's
    output shape changes -- otherwise the stale pre-change catalog is served
    until the TTL expires (this is why :v2 was introduced when clock_ghz added)."""
    _ec2 = getattr(utils_boto3.get_boto(service_name="ec2"), "message", None)
    if _ec2 is None:
        return SocaError.GENERIC_ERROR(helper="ec2 client unavailable")
    _catalog = {}
    try:
        _pag = _ec2.get_paginator("describe_instance_types")
        for _page in _pag.paginate():
            for _info in _page.get("InstanceTypes", []):
                _name = _info.get("InstanceType")
                if _name:
                    _catalog[_name] = _parse(_info)
    except Exception as exc:  # noqa: BLE001
        return SocaError.GENERIC_ERROR(
            helper=f"describe_instance_types (catalog) failed: {exc}"
        )
    return SocaResponse(success=True, message=_catalog)


def _ensure_loaded() -> bool:
    """Populate the per-worker in-process catalog from the Valkey-cached
    SocaResponse (fast per-keystroke filtering without a Valkey round-trip per
    request). Returns False if the catalog couldn't be loaded."""
    global _LOADED
    if _LOADED:
        return True
    with _LOAD_LOCK:
        if _LOADED:
            return True
        _resp = _fetch_catalog()
        if _resp.get("success") is not True:
            logger.warning(
                "instance_types: catalog load failed: %s", _resp.get("message")
            )
            return False
        _ALL_TYPES.clear()
        _ALL_TYPES.update(_resp.get("message") or {})
        _LOADED = True
        logger.info(
            "instance_types: cached %d types (Valkey-backed describe)",
            len(_ALL_TYPES),
        )
        return True


def is_known_instance_type(instance_type: str) -> bool:
    """Submit-time validation helper: True if `instance_type` exists in this
    region's catalog. Fails OPEN (returns True) when the catalog can't load, so
    a transient EC2/IAM hiccup never blocks a legitimate save."""
    _t = (instance_type or "").strip()
    if not _t:
        return False
    if not _ensure_loaded():
        return True  # fail-open: don't block saves on a catalog-load failure
    return _t in _ALL_TYPES


def instance_type_arch_ok(instance_type: str, ami_arch: str) -> bool:
    """Submit-time arch guard: True if `instance_type`'s SupportedArchitectures
    include the stack's `ami_arch`. A stack's AMI is one architecture and an
    instance of a different arch can't boot it, so a pool must never mix archs.
    Fails OPEN (returns True) when: the catalog can't load, the type is unknown
    (the unknown-type check handles that separately), the type carries no arch
    data, or `ami_arch` is blank -- so a data gap never blocks a legit save."""
    _t = (instance_type or "").strip()
    _a = _norm_arch(ami_arch)
    if not _t or not _a:
        return True
    if not _ensure_loaded():
        return True  # fail-open
    _spec = _ALL_TYPES.get(_t)
    if not _spec:
        return True  # unknown type -> handled by is_known_instance_type
    _archs = _type_archs(_spec)
    if not _archs:
        return True  # no arch data -> don't block
    return _a in _archs


def hibernation_ram_ceiling_mib(base_os: str):
    """Return (ceiling_mib, os_label) for the hibernation RAM limit that applies
    to `base_os`. AWS enforces an upper RAM bound for EC2 hibernation that is far
    lower on Windows than on Linux; both limits are admin-tunable via config
    (SSM-overridable) so they can be raised between releases as AWS lifts them,
    without a code change (V1587014009)."""
    import config
    from utils.datamodels.constants import SocaWindowsBaseOS

    _is_windows = (base_os or "").strip().lower() in [
        _o.value for _o in SocaWindowsBaseOS
    ]
    if _is_windows:
        return config.Config.DCV_HIBERNATE_MAX_RAM_MIB_WINDOWS, "Windows"
    return config.Config.DCV_HIBERNATE_MAX_RAM_MIB_LINUX, "Linux"


def hibernation_ram_ok(mem_mib, base_os):
    """(ok, reason): True when an instance with `mem_mib` RAM is within the
    hibernation RAM ceiling for `base_os`. Fails OPEN (ok=True) when `mem_mib`
    is unknown/falsy so a data gap never blocks a launch. `reason` is a
    user-facing string only when ok is False."""
    if not mem_mib:
        return True, None
    _ceiling, _label = hibernation_ram_ceiling_mib(base_os)
    if _ceiling and mem_mib > _ceiling:
        return (
            False,
            f"{round(mem_mib / 1024)} GiB RAM exceeds the "
            f"{round(_ceiling / 1024)} GiB hibernation limit for {_label} "
            f"instances. Disable hibernation or pick a smaller instance type.",
        )
    return True, None


def instance_type_hibernation_ok(instance_type: str, base_os: str):
    """(ok, reason): catalog-backed hibernation gate for `instance_type` on a
    given `base_os` -- rejects types that don't support hibernation AND types
    whose RAM exceeds the OS ceiling. Fails OPEN (ok=True) on catalog-load
    failure, unknown type, or missing spec data so a transient hiccup / data gap
    never blocks a save (unknown types are reported by is_known_instance_type)."""
    _t = (instance_type or "").strip()
    if not _t:
        return True, None
    if not _ensure_loaded():
        return True, None  # fail-open
    _spec = _ALL_TYPES.get(_t)
    if not _spec:
        return True, None  # unknown type -> handled by is_known_instance_type
    if _spec.get("hibernation_supported") is False:
        return False, f"{_t} does not support hibernation"
    return hibernation_ram_ok(_spec.get("mem_mib"), base_os)


def search_instance_types(q: str, limit: int = 25, arch: str = None) -> list:
    """Return up to `limit` instance-type spec dicts whose name matches `q`
    (prefix matches first, then substring). When `arch` is given, the result is
    HARD-FILTERED to types whose SupportedArchitectures include it -- this is
    the typeahead arch guard: a stack is locked to its AMI's architecture, so
    wrong-arch types must never appear as selectable. Empty list if the catalog
    can't load. Shared by the session-authed admin view route (browser
    typeahead) and the header-authed Resource below."""
    _q = (q or "").strip().lower()
    try:
        _limit = int(limit)
    except (TypeError, ValueError):
        _limit = 25
    _limit = max(1, min(_limit, 50))
    if not _ensure_loaded():
        return []

    _arch = _norm_arch(arch)

    def _key(_n):
        # Size-ascending within a family: vCPU, then RAM, then name (so the
        # dropdown reads small -> large instead of lexicographic 12xl/16xl/2xl).
        _s = _ALL_TYPES[_n]
        return ((_s.get("vcpu") or 0), (_s.get("mem_gib") or 0), _n)

    _names = list(_ALL_TYPES.keys())
    if _arch:
        # Hard-filter to the stack's AMI arch. Types with no arch data are kept
        # (can't prove a mismatch; the server guard fails open on them too).
        _names = [
            n
            for n in _names
            if (not _type_archs(_ALL_TYPES[n])) or _arch in _type_archs(_ALL_TYPES[n])
        ]
    if _q:
        _prefix = sorted((n for n in _names if n.lower().startswith(_q)), key=_key)
        _sub = sorted(
            (n for n in _names if _q in n.lower() and not n.lower().startswith(_q)),
            key=_key,
        )
        _ranked = _prefix + _sub
    else:
        _ranked = sorted(_names, key=_key)
    return [_ALL_TYPES[n] for n in _ranked[:_limit]]


def catalog_spec(instance_type: str) -> dict:
    """Public accessor: cached catalog spec for a type ({} if unknown or the
    catalog can't load). Ensures the Valkey-backed catalog is loaded first."""
    _t = (instance_type or "").strip()
    if not _t or not _ensure_loaded():
        return {}
    return _ALL_TYPES.get(_t) or {}


def compatible_resume_types(origin_instance_type: str, pattern_allowed_instance_types) -> list:
    """Instance types a Saved Desktop may resume onto.

    Boundary (order matters):
      1. Admin allowlist -- the profile's `pattern_allowed_instance_types` glob
         list, resolved LIVE against the current EC2 catalog (picks up admin
         edits + newly-released matching types with no session re-mint).
      2. Same GPU manufacturer as the origin type (NVIDIA->NVIDIA ok, NVIDIA->AMD
         blocked). GPU version/driver compat within a manufacturer is the user's
         risk. Architecture is naturally AMI-enforced; filtered defensively.

    Returns sorted list[dict]: {type, gpu, gpu_name, gpu_manufacturer, vcpu,
    mem_gib, is_origin}. The origin type is always present (so the modal default
    exists even if the pattern/catalog momentarily excludes it).
    """
    _origin = (origin_instance_type or "").strip()
    _origin_spec = catalog_spec(_origin)
    _origin_mfr = (_origin_spec.get("gpu_manufacturer") or "").strip()
    _origin_archs = _type_archs(_origin_spec) if _origin_spec else set()

    _patterns = [p for p in (pattern_allowed_instance_types or []) if p and str(p).strip()]
    _resolved = ec2_helper.get_instance_types_by_architecture(
        instance_type_pattern=_patterns
    )
    if _resolved.get("success") is True:
        _msg = _resolved.get("message") or {}
        # get_instance_types_by_architecture returns {arch: [type_names]} -> flatten
        # to a single list of names. (Defensive: also accept a plain list.)
        _allowed = (
            [t for _lst in _msg.values() for t in (_lst or [])]
            if Validators.is_dict(_msg)
            else list(_msg or [])
        )
    else:
        logger.warning(
            "compatible_resume_types: pattern resolve failed (%s); "
            "falling back to origin only", _resolved.get("message")
        )
        _allowed = [_origin] if _origin else []

    def _mk(_t: str, _spec: dict) -> dict:
        return {
            "type": _t,
            "gpu": _spec.get("gpu") or 0,
            "gpu_name": _spec.get("gpu_name") or "",
            "gpu_manufacturer": (_spec.get("gpu_manufacturer") or "").strip(),
            "vcpu": _spec.get("vcpu"),
            "mem_gib": _spec.get("mem_gib"),
            "is_origin": _t == _origin,
        }

    _out, _seen = [], set()
    for _t in _allowed:
        if _t in _seen:
            continue
        _spec = catalog_spec(_t)
        if not _spec:
            continue
        # Same GPU manufacturer (both "" for non-GPU -> non-GPU peers).
        if (_spec.get("gpu_manufacturer") or "").strip() != _origin_mfr:
            continue
        # Arch guard: require an overlap when both sides declare archs.
        _archs = _type_archs(_spec)
        if _origin_archs and _archs and not (_origin_archs & _archs):
            continue
        _seen.add(_t)
        _out.append(_mk(_t, _spec))

    _out.sort(key=lambda d: (d.get("vcpu") or 0, d.get("mem_gib") or 0, d["type"]))

    # Guarantee the origin is present (default selection), first in the list.
    if _origin and _origin not in _seen and _origin_spec:
        _out.insert(0, _mk(_origin, _origin_spec))
    return _out


class VdiInstanceTypeSearch(Resource):
    """Header-authed (@admin_api) typeahead, for programmatic/API callers:
    ?q=<substr>&limit=<n> -> [{type, vcpu, mem_mib, mem_gib, hibernation_supported,
    gpu, gpu_name, gpu_mem_gib, gpu_frac, arch, clock_ghz, cpu_mfr, disk}].
    The browser uses the session-authed admin view route instead."""

    @admin_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def get(self):
        r"""
        Search EC2 instance types by name substring for the VDI pool config typeahead
        ---
        openapi: 3.1.0
        operationId: searchVdiInstanceTypes
        tags:
          - Virtual Desktops
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
          - name: q
            in: query
            schema:
              type: string
            required: false
            description: Substring to match against instance type names (prefix matches ranked first)
          - name: limit
            in: query
            schema:
              type: integer
              minimum: 1
              maximum: 50
              default: 25
            required: false
            description: Maximum number of results to return
          - name: arch
            in: query
            schema:
              type: string
              enum:
                - x86_64
                - arm64
            required: false
            description: Filter results to instance types supporting this CPU architecture
        responses:
          '200':
            description: Success
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: array
                      items:
                        type: object
                        properties:
                          type:
                            type: string
                          vcpu:
                            type: integer
                          mem_mib:
                            type: integer
                          mem_gib:
                            type: integer
                          hibernation_supported:
                            type: boolean
                            nullable: true
                          gpu:
                            type: integer
                          gpu_name:
                            type: string
                            nullable: true
                          gpu_mem_gib:
                            type: integer
                            nullable: true
                          gpu_frac:
                            type: string
                            nullable: true
                          arch:
                            type: string
                          clock_ghz:
                            type: number
                            nullable: true
                          cpu_mfr:
                            type: string
                          disk:
                            type: string
          '401':
            description: Authentication required
          '403':
            description: Admin privileges required
          '500':
            description: Server error
        """
        _out = search_instance_types(
            request.args.get("q") or "",
            request.args.get("limit") or 25,
            request.args.get("arch") or None,
        )
        return SocaResponse(success=True, message=_out).as_flask()

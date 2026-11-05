# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Shared validation + normalization for VDI pool per-(stack, instance_type)
configuration.

This is the SINGLE validation home used by BOTH the admin API endpoint and the
WebUI view (the WebUI is a thin client of the API). Per the web-interface
conventions, the functions here return PLAIN DATA -- never SocaResponse /
SocaError. The calling endpoint constructs SocaError(...).as_flask() from any
returned error list.

Phase 1: core field validation only. The admin API (GET/PUT), DDB persistence,
and the PoolController reconcile are wired in later phases.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")

# EC2 Capacity Reservation id. Same {8,17} hex convention the rest of the tree
# uses for EC2 resource ids (session_event.INSTANCE_ID_RE, the ami- patterns in
# software_stacks), covering both the legacy 8-char and current 17-char forms.
_CR_ID_RE = re.compile(r"^cr-[0-9a-f]{8,17}$")


def _as_int(value: Any) -> Optional[int]:
    """Cast to int via SocaCastEngine (error-first); None on failure."""
    _cast = SocaCastEngine(value).cast_as(expected_type=int)
    if _cast.get("success") is not True:
        return None
    return _cast.get("message")


def validate_pool_type_config(
    entry: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Validate + normalize a single per-(stack, instance_type) pool entry.

    Returns (normalized_dict, []) on success or (None, [errors]) on failure.
    Never raises; never returns a SocaResponse/SocaError.

    Expected keys in `entry`:
        instance_type                     (str, required, non-empty)
        label                             (str, optional, <= 24 chars,
                                           [A-Za-z0-9 ._-]; admin display tag)
        hot_count                         (int >= 0)
        warm_count                        (int >= 0)
        on_demand_base_count              (int >= 0, <= hot_count)
        on_demand_percentage_above_base   (int 0..100)
    """
    errors: List[str] = []

    _instance_type = (entry.get("instance_type") or "").strip()
    if not _instance_type:
        errors.append("instance_type is required")

    # Optional admin display label (e.g. "PROD", "EMERGENCY-ONLY"). Grounds
    # the user-facing pill alongside the instance type -- never replaces it.
    # Constrained charset + length so it renders cleanly and can't smuggle
    # markup (the template autoescapes too -- defense in depth).
    _label = (entry.get("label") or "").strip()
    if _label:
        if len(_label) > 24:
            errors.append("label must be <= 24 characters")
        elif not _is_label(_label):
            errors.append(
                "label must not contain < > & \" ' or control characters"
            )

    _hot = _as_int(entry.get("hot_count", 0))
    if _hot is None or _hot < 0:
        errors.append("hot_count must be an integer >= 0")

    _warm = _as_int(entry.get("warm_count", 0))
    if _warm is None or _warm < 0:
        errors.append("warm_count must be an integer >= 0")

    _od_base = _as_int(entry.get("on_demand_base_count", 0))
    if _od_base is None or _od_base < 0:
        errors.append("on_demand_base_count must be an integer >= 0")
    elif _hot is not None and _od_base > _hot:
        errors.append("on_demand_base_count must be <= hot_count")

    _od_pct = _as_int(entry.get("on_demand_percentage_above_base", 100))
    if _od_pct is None or not (0 <= _od_pct <= 100):
        errors.append("on_demand_percentage_above_base must be an integer 0..100")

    # Per-entry enable switch. A disabled entry stays in the config and keeps
    # its ASG alive PARKED at 0/0/0 (no compute) so re-enabling is instant and
    # never collides with a still-deleting same-named ASG.
    _entry_enabled = _as_bool(entry.get("enabled"), default=True)
    if _entry_enabled is None:
        errors.append("enabled must be a boolean")

    # ODCR reserved-capacity tier (Phase 1). All optional; absent => this type
    # is not backed by a reservation. A per-entry capacity_reservation_id is an
    # OPTIONAL OVERRIDE that targets one specific reservation (deterministic at
    # launch); otherwise the type targets the stack-level CR-Group ARN (if set).
    #
    # Shape only -- existence / AZ-match / type-match need AWS calls and are
    # checked by validate_capacity_reservation_exists(), which the endpoint
    # calls. The previous check here was `startswith("cr-")`, which accepted
    # anything after the prefix: "cr-123" was stored and rendered into a live
    # launch template's CapacityReservationTarget. Matched to the repo's EC2
    # id convention (session_event.INSTANCE_ID_RE, the ami- patterns in
    # software_stacks) so a typo is refused at save time rather than at launch.
    _cr_id = (entry.get("capacity_reservation_id") or "").strip()
    if _cr_id and not _CR_ID_RE.match(_cr_id):
        errors.append(
            "capacity_reservation_id must be a Capacity Reservation id of the "
            "form cr-<8 to 17 hex chars>"
        )

    _follow_odcr = _as_bool(entry.get("follow_odcr_capacity"), default=True)
    if _follow_odcr is None:
        errors.append("follow_odcr_capacity must be a boolean")

    _odcr_fallback = _as_bool(
        entry.get("odcr_fallback_to_od_when_full"), default=True
    )
    if _odcr_fallback is None:
        errors.append("odcr_fallback_to_od_when_full must be a boolean")

    if errors:
        return None, errors

    return (
        {
            "instance_type": _instance_type,
            "label": _label,
            "enabled": _entry_enabled,
            "hot_count": _hot,
            "warm_count": _warm,
            "on_demand_base_count": _od_base,
            "on_demand_percentage_above_base": _od_pct,
            "capacity_reservation_id": _cr_id or None,
            "follow_odcr_capacity": _follow_odcr,
            "odcr_fallback_to_od_when_full": _odcr_fallback,
        },
        [],
    )


_VALID_POOL_STATES = ("Stopped", "Hibernated")


def validate_capacity_reservation_ids(entries: Any) -> List[str]:
    """Confirm every per-entry capacity_reservation_id EXISTS and matches its
    instance type. Returns a list of error strings (empty when all are fine).

    Shape alone is not enough. validate_pool_type_config previously accepted
    anything starting with "cr-", so "cr-123" was stored and rendered into a
    live launch template's CapacityReservationTarget; nothing downstream ever
    checked it, and the failure surfaced only when a member tried to launch.
    The ODCR docstring in validate_pool_type_config claimed existence was
    "validated in the endpoint via odcr_helper" -- it was not: the pool
    endpoint makes no odcr_helper call at all (grep: zero references in
    api/v1/dcv/pool.py).

    Needs ec2:DescribeCapacityReservations, which the controller role already
    holds (simulate-principal-policy: allowed), so this adds no IAM and needs
    no stack update.

    FAIL-OPEN on an API error: an unreachable or throttled EC2 must not block
    an admin save. Only a definitive "this reservation does not exist" or a
    definitive type mismatch produces an error. A reservation is also rejected
    when it is not usable (cancelled / expired), because targeting one fails
    at launch exactly like a nonexistent id.
    """
    _errors: List[str] = []
    _wanted: Dict[str, str] = {}  # cr id -> instance_type that referenced it
    for _e in entries or []:
        _cr = ((_e or {}).get("capacity_reservation_id") or "").strip()
        if _cr:
            _wanted[_cr] = ((_e or {}).get("instance_type") or "").strip()
    if not _wanted:
        return _errors

    try:
        import utils.aws.boto3_wrapper as utils_boto3

        _resp = utils_boto3.get_boto(service_name="ec2")
        if _resp.get("success") is False:
            logger.warning(
                "ODCR validation: no EC2 client; admitting %d reservation id(s) "
                "unchecked",
                len(_wanted),
            )
            return _errors
        _ec2 = _resp.get("message")
        _found = {}
        _page = _ec2.get_paginator("describe_capacity_reservations")
        for _p in _page.paginate(CapacityReservationIds=sorted(_wanted)):
            for _cr in _p.get("CapacityReservations", []) or []:
                _found[_cr.get("CapacityReservationId")] = _cr
    except Exception as err:
        # Includes InvalidCapacityReservationId.NotFound, which EC2 raises for
        # the WHOLE call rather than omitting the row -- so we cannot tell
        # which id was bad from here. Re-check them one at a time so a real
        # typo is named, and so one bad id does not hide the others.
        logger.info(
            "ODCR validation: batch describe failed (%s); re-checking "
            "individually",
            err,
        )
        return _validate_capacity_reservations_individually(_wanted)

    for _cr_id, _itype in sorted(_wanted.items()):
        _cr = _found.get(_cr_id)
        if _cr is None:
            _errors.append(
                f"capacity_reservation_id {_cr_id} does not exist in this "
                f"account and region"
            )
            continue
        _errors.extend(_capacity_reservation_mismatches(_cr_id, _itype, _cr))
    return _errors


def _validate_capacity_reservations_individually(wanted: Dict[str, str]) -> List[str]:
    """Per-id fallback for validate_capacity_reservation_ids.

    describe_capacity_reservations raises InvalidCapacityReservationId.NotFound
    for the entire request when ANY requested id is unknown, so a single typo
    in a batch tells us nothing about which id it was. Checking one at a time
    names the offender. Still fail-open per id on a non-NotFound error.
    """
    _errors: List[str] = []
    try:
        import utils.aws.boto3_wrapper as utils_boto3

        _resp = utils_boto3.get_boto(service_name="ec2")
        if _resp.get("success") is False:
            return _errors
        _ec2 = _resp.get("message")
    except Exception:
        return _errors

    for _cr_id, _itype in sorted(wanted.items()):
        try:
            _r = _ec2.describe_capacity_reservations(
                CapacityReservationIds=[_cr_id]
            )
            _rows = _r.get("CapacityReservations", []) or []
            if not _rows:
                _errors.append(
                    f"capacity_reservation_id {_cr_id} does not exist in this "
                    f"account and region"
                )
                continue
            _errors.extend(
                _capacity_reservation_mismatches(_cr_id, _itype, _rows[0])
            )
        except Exception as err:
            if "InvalidCapacityReservationId" in str(err) or "NotFound" in str(err):
                _errors.append(
                    f"capacity_reservation_id {_cr_id} does not exist in this "
                    f"account and region"
                )
            else:
                logger.warning(
                    "ODCR validation: %s could not be checked (%s); admitting "
                    "it unchecked",
                    _cr_id,
                    err,
                )
    return _errors


def _capacity_reservation_mismatches(cr_id: str, instance_type: str, cr: Dict[str, Any]) -> List[str]:
    """Usability + instance-type agreement for one described reservation.

    A Capacity Reservation is pinned to one instance type (and one AZ and
    platform), so a per-entry override that names a reservation for a
    DIFFERENT type can never place that entry's members.
    """
    _errors: List[str] = []
    _state = str(cr.get("State") or "").lower()
    # 'active' and 'pending' are both targetable; 'payment-pending' is in-flight
    # and resolves on its own. Anything else is terminal for this reservation.
    if _state not in ("active", "pending", "payment-pending"):
        _errors.append(
            f"capacity_reservation_id {cr_id} is in state '{cr.get('State')}' "
            f"and cannot be targeted"
        )
    _cr_type = (cr.get("InstanceType") or "").strip()
    if instance_type and _cr_type and _cr_type != instance_type:
        _errors.append(
            f"capacity_reservation_id {cr_id} is reserved for {_cr_type}, not "
            f"{instance_type}"
        )
    return _errors


def _as_bool(value: Any, default: bool) -> Optional[bool]:
    """Cast to bool via SocaCastEngine (error-first). Returns default when
    the value is None/missing; None only on an explicit bad cast."""
    if value is None:
        return default
    _cast = SocaCastEngine(value).cast_as(expected_type=bool)
    if _cast.get("success") is not True:
        return None
    return _cast.get("message")


def _validate_schedule(schedule: Any, errors: List[str]) -> Optional[Dict[str, Any]]:
    """Validate the optional active-hours schedule. None/empty -> None (no
    schedule). Shape: {timezone: str, windows: [{days, start, end}]}."""
    if not schedule:
        return None
    if not isinstance(schedule, dict):
        errors.append("schedule must be an object")
        return None
    _tz = (schedule.get("timezone") or "").strip()
    if not _tz:
        errors.append("schedule.timezone is required when a schedule is set")
    _windows_in = schedule.get("windows") or []
    if not isinstance(_windows_in, list):
        errors.append("schedule.windows must be a list")
        _windows_in = []
    _windows: List[Dict[str, str]] = []
    for _i, _w in enumerate(_windows_in):
        if not isinstance(_w, dict):
            errors.append(f"schedule.windows[{_i}] must be an object")
            continue
        _days = (_w.get("days") or "").strip()
        _start = (_w.get("start") or "").strip()
        _end = (_w.get("end") or "").strip()
        if not _days:
            errors.append(f"schedule.windows[{_i}].days is required")
        if not _is_hhmm(_start):
            errors.append(f"schedule.windows[{_i}].start must be HH:MM")
        if not _is_hhmm(_end):
            errors.append(f"schedule.windows[{_i}].end must be HH:MM")
        _windows.append({"days": _days, "start": _start, "end": _end})
    return {"timezone": _tz, "windows": _windows}


_LABEL_BLOCKED = ("<", ">", "&", '"', "'")


def _is_label(value: str) -> bool:
    """True if value is display-safe: no HTML-sensitive chars (< > & " ') and
    no control characters. Emoji and other printable punctuation ARE allowed --
    the label is always Jinja-autoescaped on render, so the denylist only needs
    to bar the characters that could break out of HTML text/attribute context.
    (Relaxed from the prior strict [A-Za-z0-9 ._-] allowlist 2026-06-15.)"""
    return all(
        ord(c) >= 0x20 and c != "\x7f" and c not in _LABEL_BLOCKED for c in value
    )


def _is_hhmm(value: str) -> bool:
    """True if value is a 24h HH:MM time string."""
    parts = value.split(":")
    if len(parts) != 2:
        return False
    h, m = (_as_int(parts[0]), _as_int(parts[1]))
    return h is not None and m is not None and 0 <= h <= 23 and 0 <= m <= 59


def validate_pool_config(
    payload: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """Validate + normalize a full per-stack pool config payload (the body
    of PUT .../software_stacks/<id>/pool).

    Single validation home shared by the admin API and the WebUI. Returns
    (normalized_dict, []) or (None, [errors]). Never raises; never returns
    SocaResponse/SocaError -- the endpoint wraps errors via as_flask().

    Payload shape:
        enabled                          (bool, default False)
        pool_state                       ("Stopped" | "Hibernated")
        allow_recycle                    (bool, default False)
        backfill_on_claim                (bool, default True)
        show_interruptible_hint          (bool, default True)
        provisioning_timeout_seconds     (optional int > 0; override)
        connect_abandon_timeout_seconds  (optional int > 0; override)
        schedule                         (optional {timezone, windows[]})
        entries                          (list of per-(instance_type) dicts)
    """
    if not isinstance(payload, dict):
        return None, ["request body must be a JSON object"]

    errors: List[str] = []

    _enabled = _as_bool(payload.get("enabled"), default=False)
    if _enabled is None:
        errors.append("enabled must be a boolean")

    _pool_state = (payload.get("pool_state") or "Stopped").strip()
    if _pool_state not in _VALID_POOL_STATES:
        errors.append(f"pool_state must be one of {list(_VALID_POOL_STATES)}")

    _allow_recycle = _as_bool(payload.get("allow_recycle"), default=False)
    if _allow_recycle is None:
        errors.append("allow_recycle must be a boolean")

    _backfill = _as_bool(payload.get("backfill_on_claim"), default=True)
    if _backfill is None:
        errors.append("backfill_on_claim must be a boolean")

    # ON -> reconciler burns down + relaunches this stack's members on any LT
    # change (uniform fleet). OFF -> roll forward only on natural churn/claim.
    _recycle_on_lt = _as_bool(payload.get("recycle_on_lt_change"), default=False)
    if _recycle_on_lt is None:
        errors.append("recycle_on_lt_change must be a boolean")

    _hint = _as_bool(payload.get("show_interruptible_hint"), default=True)
    if _hint is None:
        errors.append("show_interruptible_hint must be a boolean")

    # ODCR reserved-capacity tier (Phase 1): optional stack-level Capacity
    # Reservation *group* ARN. A single CR id is intentionally NOT supported
    # at this scope -- a CR is pinned to one instance type + AZ + platform,
    # so a stack-level bare CR id would be wrong for any pool with more than
    # one instance-type entry. Single-CR targeting belongs on the per-entry
    # capacity_reservation_id (validate_pool_type_config), which already
    # exists. A group ARN is fine here since AWS resolves per-launch which
    # member CR matches the requested instance type. Every pool type targets
    # this group (open-within-target, self-healing) unless the type carries
    # its own capacity_reservation_id override. Absent => no reserved tier
    # for this stack. Shape-only check here; existence is validated in the
    # endpoint via odcr_helper.
    _cr_group_arn = (payload.get("capacity_reservation_group_arn") or "").strip()
    if _cr_group_arn and not (
        _cr_group_arn.startswith("arn:")
        and ":resource-groups:" in _cr_group_arn
        and ":group/" in _cr_group_arn
    ):
        errors.append(
            "capacity_reservation_group_arn must be a resource-groups group ARN "
            "(arn:<partition>:resource-groups:<region>:<account>:group/<name>)"
        )

    _cr_od_fallback = _as_bool(
        payload.get("capacity_reservation_fallback_to_od"), default=True
    )
    if _cr_od_fallback is None:
        errors.append("capacity_reservation_fallback_to_od must be a boolean")

    # Optional per-stack timeout overrides (fall back to cluster defaults
    # when absent -> stored as None).
    _prov_to = None
    if payload.get("provisioning_timeout_seconds") not in (None, ""):
        _prov_to = _as_int(payload.get("provisioning_timeout_seconds"))
        if _prov_to is None or _prov_to <= 0:
            errors.append("provisioning_timeout_seconds must be an integer > 0")
    _conn_to = None
    if payload.get("connect_abandon_timeout_seconds") not in (None, ""):
        _conn_to = _as_int(payload.get("connect_abandon_timeout_seconds"))
        if _conn_to is None or _conn_to <= 0:
            errors.append("connect_abandon_timeout_seconds must be an integer > 0")

    _schedule = _validate_schedule(payload.get("schedule"), errors)

    # Per-instance-type entries.
    _entries_in = payload.get("entries") or []
    if not isinstance(_entries_in, list):
        errors.append("entries must be a list")
        _entries_in = []
    _entries: List[Dict[str, Any]] = []
    _seen_types = set()
    for _i, _entry in enumerate(_entries_in):
        if not isinstance(_entry, dict):
            errors.append(f"entries[{_i}] must be an object")
            continue
        _norm, _entry_errors = validate_pool_type_config(_entry)
        if _entry_errors:
            errors.extend(f"entries[{_i}]: {_e}" for _e in _entry_errors)
            continue
        if _norm["instance_type"] in _seen_types:
            errors.append(
                f"entries[{_i}]: duplicate instance_type "
                f"{_norm['instance_type']!r}"
            )
            continue
        _seen_types.add(_norm["instance_type"])
        _entries.append(_norm)

    # An enabled pool with no instance-type entries serves nothing.
    if _enabled and not _entries and not errors:
        errors.append("an enabled pool requires at least one instance-type entry")

    if errors:
        return None, errors

    return (
        {
            "enabled": _enabled,
            "pool_state": _pool_state,
            "allow_recycle": _allow_recycle,
            "backfill_on_claim": _backfill,
            "recycle_on_lt_change": _recycle_on_lt,
            "show_interruptible_hint": _hint,
            "capacity_reservation_group_arn": _cr_group_arn or None,
            "capacity_reservation_fallback_to_od": _cr_od_fallback,
            "provisioning_timeout_seconds": _prov_to,
            "connect_abandon_timeout_seconds": _conn_to,
            "schedule": _schedule,
            "entries": _entries,
        },
        [],
    )

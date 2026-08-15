# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
UsbProfileService -- CRUD + validation for USB device allowlists.

A UsbProfile is a reusable, named allowlist of DCV usb-devices.conf filter
entries (8 fields each). Referenced by HardwareProfiles; rendered to
usb-devices.conf at VDI boot by the resolver Lambda.

Public functions return SocaResponse/SocaError and are consumed internally by
the API handlers and the edhctl CLI (which add .as_flask() at the web tier).
Per the web_interface/helpers precedent (vdi_pool_store.py, vdi_eta.py), these
service functions intentionally return WITHOUT .as_flask() -- they are not
Flask request handlers.

The 8-field DCV filter string is:
    Name, BaseClass, SubClass, Protocol, VID, PID, SupportAutoshare, SkipReset
BaseClass/SubClass/Protocol accept an integer 0-255 or the literal "*".
VID/PID accept an integer 0-65535 or "*". The flags are 0/1. This is a device
compatibility filter, NOT a security boundary (AWS documents this).
"""

import logging
import re
from datetime import datetime, timezone

from models import db, UsbProfiles, UsbProfileEntries
from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

_WILDCARD = "*"
# ARCC BSC1 Input Validation: use an ALLOWLIST, not a denylist. Device labels
# are human device names -- permit letters, digits, space, and a small safe
# punctuation set only. This structurally excludes the field delimiter (comma),
# newlines/control chars (cannot break the line format or inject a filter line),
# and the HTML-sink chars < > " ' & (defense-in-depth alongside output-encoding
# at the render sink).
_MAX_LABEL = 255
_LABEL_ALLOWED_RE = re.compile(r"^[A-Za-z0-9 ._()+/#:\-]{1,255}$")
# admin_comment is a free-form internal operator note (never user-facing, never
# rendered to usb-devices.conf). Allowlist to printable ASCII, cap length, and
# reject angle brackets (never needed; keeps the HTML sink safe pre-encoding).
_MAX_COMMENT = 512
_COMMENT_PRINTABLE_RE = re.compile(r"^[\x20-\x7E]{0,512}$")


def _valid_bounded_int(value: str, lo: int, hi: int) -> bool:
    """True if value is the wildcard or an integer within [lo, hi]."""
    if value == _WILDCARD:
        return True
    _cast = SocaCastEngine(value).cast_as(int)
    if not _cast.success:
        return False
    return lo <= _cast.message <= hi


def _normalize_numeric(value) -> tuple:
    """Normalize a class/vid/pid field to a canonical DECIMAL string.

    DCV usb-devices.conf stores these fields in decimal. Accepts the wildcard
    '*', a decimal integer, or a 0x-prefixed hex value (convenience for admins
    reading a hex USB ID) and returns the decimal string DCV expects.
    Returns (ok: bool, normalized: str).
    """
    s = str(value).strip()
    if s == _WILDCARD:
        return True, _WILDCARD
    try:
        n = int(s, 16) if s.lower().startswith("0x") else int(s, 10)
    except (ValueError, TypeError):
        return False, s
    return True, str(n)


def validate_entry_fields(
    device_label: str,
    base_class: str,
    sub_class: str,
    protocol: str,
    vid: str,
    pid: str,
    support_autoshare,
    skip_reset,
    enabled=True,
    admin_comment=None,
) -> SocaResponse:
    """Validate the 8 filter-string fields + enabled/admin_comment.

    message=normalized dict on success. All user-entered strings are validated
    with an allowlist (ARCC BSC1) so nothing dangerous is ever persisted.
    """
    if not Validators.is_string(device_label) or not device_label.strip():
        return SocaError.GENERIC_ERROR(
            helper="device_label is required", status_code=400
        )
    _label = device_label.strip()
    if Validators.is_string_length_greater_than(_label, _MAX_LABEL) or not _LABEL_ALLOWED_RE.match(_label):
        return SocaError.GENERIC_ERROR(
            helper=(
                "device_label must be 1-255 chars using only letters, digits, "
                "space, and . _ - ( ) + / # : (no commas, angle brackets, or quotes)"
            ),
            status_code=400,
        )
    _norm = {}
    for _name, _val, _hi in (
        ("base_class", base_class, 255),
        ("sub_class", sub_class, 255),
        ("protocol", protocol, 255),
        ("vid", vid, 65535),
        ("pid", pid, 65535),
    ):
        _ok, _nv = _normalize_numeric(_val)
        if not _ok:
            return SocaError.GENERIC_ERROR(
                helper=f"{_name} must be an integer, 0x-hex, or '*'", status_code=400
            )
        if _nv != _WILDCARD and not (0 <= int(_nv) <= _hi):
            return SocaError.GENERIC_ERROR(
                helper=f"{_name} must be 0-{_hi} or '*'", status_code=400
            )
        _norm[_name] = _nv
    _auto = _coerce_flag(support_autoshare)
    if not _auto.success:
        return _auto
    _reset = _coerce_flag(skip_reset)
    if not _reset.success:
        return _reset
    _enabled = _coerce_flag(enabled)
    if not _enabled.success:
        return _enabled

    _comment = None
    if admin_comment is not None and str(admin_comment).strip() != "":
        if not Validators.is_string(admin_comment):
            return SocaError.GENERIC_ERROR(
                helper="admin_comment must be a string", status_code=400
            )
        if (
            Validators.is_string_length_greater_than(admin_comment, _MAX_COMMENT)
            or not _COMMENT_PRINTABLE_RE.match(admin_comment)
            or "<" in admin_comment
            or ">" in admin_comment
        ):
            return SocaError.GENERIC_ERROR(
                helper="admin_comment must be <=512 printable ASCII chars with no angle brackets",
                status_code=400,
            )
        _comment = admin_comment.strip()

    return SocaResponse(
        success=True,
        message={
            "device_label": _label,
            "base_class": _norm["base_class"],
            "sub_class": _norm["sub_class"],
            "protocol": _norm["protocol"],
            "vid": _norm["vid"],
            "pid": _norm["pid"],
            "support_autoshare": _auto.message,
            "skip_reset": _reset.message,
            "enabled": _enabled.message,
            "admin_comment": _comment,
        },
    )


def _coerce_flag(value) -> SocaResponse:
    """Coerce 0/1/true/false into a bool. message=bool on success."""
    if Validators.is_bool(value):
        return SocaResponse(success=True, message=value)
    _s = str(value).strip().lower()
    if _s in ("1", "true", "yes"):
        return SocaResponse(success=True, message=True)
    if _s in ("0", "false", "no"):
        return SocaResponse(success=True, message=False)
    return SocaError.GENERIC_ERROR(
        helper="flag must be 0/1 or true/false", status_code=400
    )


def parse_filter_string(filter_string: str) -> SocaResponse:
    """Paste-to-parse a raw DCV filter string into validated fields.

    Accepts the 8-field comma form copied from dcvusblist.exe, e.g.
        "YubiKey 5,3,0,0,4176,1031,1,0"
    message=normalized dict on success (same shape as validate_entry_fields).
    """
    if not Validators.is_string(filter_string):
        return SocaError.GENERIC_ERROR(
            helper="filter_string must be a string", status_code=400
        )
    parts = [p.strip() for p in filter_string.split(",")]
    if Validators.is_list_length_not_equal_of(parts, 8):
        return SocaError.GENERIC_ERROR(
            helper="filter_string must have exactly 8 comma-separated fields",
            status_code=400,
        )
    return validate_entry_fields(
        device_label=parts[0],
        base_class=parts[1],
        sub_class=parts[2],
        protocol=parts[3],
        vid=parts[4],
        pid=parts[5],
        support_autoshare=parts[6],
        skip_reset=parts[7],
    )


def _profile_as_dict(profile: UsbProfiles, include_entries: bool = True) -> dict:
    result = profile.as_dict()
    if include_entries:
        result["entries"] = [e.as_dict() for e in profile.entries]
    return result


def list_usb_profiles(include_inactive: bool = False) -> SocaResponse:
    """List USB profiles. message=list of dicts (with entries)."""
    _query = UsbProfiles.query
    if not include_inactive:
        _query = _query.filter_by(is_active=True)
    profiles = _query.all()
    return SocaResponse(
        success=True, message=[_profile_as_dict(p) for p in profiles]
    )


def get_usb_profile(profile_id: int) -> SocaResponse:
    """Get one USB profile by id (active or disabled). message=dict; 404 if absent."""
    profile = db.session.get(UsbProfiles, profile_id)
    if profile is None:
        return SocaError.GENERIC_ERROR(
            helper=f"UsbProfile {profile_id} not found", status_code=404
        )
    return SocaResponse(success=True, message=_profile_as_dict(profile))


def _usb_name_taken(name, exclude_id=None) -> bool:
    """True if another UsbProfile already uses this name (case-insensitive,
    across ALL rows regardless of is_active, so a disabled profile's name stays
    reserved and can be re-enabled without a collision). exclude_id skips the
    row being updated."""
    _q = UsbProfiles.query.filter(
        db.func.lower(UsbProfiles.profile_name) == name.strip().lower()
    )
    if exclude_id is not None:
        _q = _q.filter(UsbProfiles.id != exclude_id)
    return _q.first() is not None


def create_usb_profile(
    profile_name: str, description: str, created_by: str
) -> SocaResponse:
    """Create a USB profile. message=created dict."""
    if not Validators.is_string(profile_name) or not profile_name.strip():
        return SocaError.GENERIC_ERROR(
            helper="profile_name is required", status_code=400
        )
    if _usb_name_taken(profile_name):
        return SocaError.GENERIC_ERROR(
            helper=f"A USB allowlist named '{profile_name.strip()}' already exists",
            status_code=400,
        )
    now = datetime.now(timezone.utc)
    profile = UsbProfiles(
        profile_name=profile_name.strip(),
        description=description,
        is_active=True,
        created_on=now,
        created_by=created_by,
    )
    try:
        db.session.add(profile)
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to create UsbProfile due to {err}"
        )
    return SocaResponse(success=True, message=_profile_as_dict(profile))


def update_usb_profile(profile_id: int, updated_by: str, **fields) -> SocaResponse:
    """Update mutable profile fields (profile_name, description) and the
    is_active enable/disable flag. Works on disabled rows too (so they can be
    re-enabled). message=dict."""
    profile = db.session.get(UsbProfiles, profile_id)
    if profile is None:
        return SocaError.GENERIC_ERROR(
            helper=f"UsbProfile {profile_id} not found", status_code=404
        )
    if "profile_name" in fields:
        _name = fields["profile_name"]
        if not Validators.is_string(_name) or not _name.strip():
            return SocaError.GENERIC_ERROR(
                helper="profile_name cannot be empty", status_code=400
            )
        if _usb_name_taken(_name, exclude_id=profile_id):
            return SocaError.GENERIC_ERROR(
                helper=f"A USB allowlist named '{_name.strip()}' already exists",
                status_code=400,
            )
        profile.profile_name = _name.strip()
    if "description" in fields:
        profile.description = fields["description"]
    if "is_active" in fields:
        _new = bool(fields["is_active"])
        if _new and not profile.is_active:
            profile.is_active = True
            profile.deactivated_on = None
            profile.deactivated_by = None
        elif not _new and profile.is_active:
            profile.is_active = False
            profile.deactivated_on = datetime.now(timezone.utc)
            profile.deactivated_by = updated_by
    profile.updated_by = updated_by
    try:
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to update UsbProfile {profile_id} due to {err}"
        )
    return SocaResponse(success=True, message=_profile_as_dict(profile))


def deactivate_usb_profile(profile_id: int, deactivated_by: str) -> SocaResponse:
    """Soft-delete a USB profile (is_active=False). message='Deactivated'."""
    profile = db.session.get(UsbProfiles, profile_id)
    if profile is None or not profile.is_active:
        return SocaError.GENERIC_ERROR(
            helper=f"UsbProfile {profile_id} not found", status_code=404
        )
    profile.is_active = False
    profile.deactivated_on = datetime.now(timezone.utc)
    profile.deactivated_by = deactivated_by
    try:
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to deactivate UsbProfile {profile_id} due to {err}"
        )
    return SocaResponse(success=True, message="Deactivated")


def add_entry(profile_id: int, created_by: str, **fields) -> SocaResponse:
    """Add a validated filter entry to a profile. message=entry dict."""
    profile = db.session.get(UsbProfiles, profile_id)
    if profile is None or not profile.is_active:
        return SocaError.GENERIC_ERROR(
            helper=f"UsbProfile {profile_id} not found", status_code=404
        )
    _valid = validate_entry_fields(
        device_label=fields.get("device_label"),
        base_class=fields.get("base_class"),
        sub_class=fields.get("sub_class"),
        protocol=fields.get("protocol"),
        vid=fields.get("vid"),
        pid=fields.get("pid"),
        support_autoshare=fields.get("support_autoshare"),
        skip_reset=fields.get("skip_reset"),
        enabled=fields.get("enabled", True),
        admin_comment=fields.get("admin_comment"),
    )
    if not _valid.success:
        return _valid
    v = _valid.message
    entry = UsbProfileEntries(
        usb_profile_id=profile_id,
        device_label=v["device_label"],
        base_class=v["base_class"],
        sub_class=v["sub_class"],
        protocol=v["protocol"],
        vid=v["vid"],
        pid=v["pid"],
        support_autoshare=v["support_autoshare"],
        skip_reset=v["skip_reset"],
        enabled=v["enabled"],
        admin_comment=v["admin_comment"],
        created_on=datetime.now(timezone.utc),
        created_by=created_by,
    )
    try:
        db.session.add(entry)
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to add entry to UsbProfile {profile_id} due to {err}"
        )
    return SocaResponse(success=True, message=entry.as_dict())


def remove_entry(entry_id: int) -> SocaResponse:
    """Delete a filter entry by id. message='Deleted'; 404 if absent."""
    entry = db.session.get(UsbProfileEntries, entry_id)
    if entry is None:
        return SocaError.GENERIC_ERROR(
            helper=f"UsbProfileEntry {entry_id} not found", status_code=404
        )
    try:
        db.session.delete(entry)
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to remove entry {entry_id} due to {err}"
        )
    return SocaResponse(success=True, message="Deleted")


def set_entries(profile_id: int, actor: str, desired) -> SocaResponse:
    """Reconcile a profile's entries to the desired set in ONE transaction.

    desired: list of dicts, each optionally carrying an existing integer "id".
    Semantics (the WebUI "Apply updates" action):
      - every desired row is validated up-front; ANY invalid row fails the whole
        apply (atomic -- nothing is written on validation error);
      - rows with an id matching an existing entry are updated in place;
      - rows without a (known) id are inserted;
      - existing entries absent from the desired set are deleted.
    A single commit applies all add/update/delete/toggle changes together.
    message=refreshed profile dict.
    """
    profile = db.session.get(UsbProfiles, profile_id)
    if profile is None or not profile.is_active:
        return SocaError.GENERIC_ERROR(
            helper=f"UsbProfile {profile_id} not found", status_code=404
        )
    if not Validators.is_list(desired):
        return SocaError.GENERIC_ERROR(
            helper="entries must be a list", status_code=400
        )

    # Validate every desired row first (atomic apply -- fail before any write).
    normalized = []
    for idx, row in enumerate(desired):
        if not Validators.is_dict(row):
            return SocaError.GENERIC_ERROR(
                helper=f"entry {idx} must be an object", status_code=400
            )
        _valid = validate_entry_fields(
            device_label=row.get("device_label"),
            base_class=row.get("base_class"),
            sub_class=row.get("sub_class"),
            protocol=row.get("protocol"),
            vid=row.get("vid"),
            pid=row.get("pid"),
            support_autoshare=row.get("support_autoshare"),
            skip_reset=row.get("skip_reset"),
            enabled=row.get("enabled", True),
            admin_comment=row.get("admin_comment"),
        )
        if not _valid.success:
            return _valid
        v = _valid.message
        _raw_id = row.get("id")
        if _raw_id in (None, "", "null"):
            v["_id"] = None
        else:
            _cast = SocaCastEngine(_raw_id).cast_as(int)
            v["_id"] = _cast.message if _cast.success else None
        normalized.append(v)

    existing = {e.id: e for e in profile.entries}
    keep_ids = set()
    now = datetime.now(timezone.utc)
    try:
        for v in normalized:
            eid = v["_id"]
            if eid is not None and eid in existing:
                e = existing[eid]
                e.device_label = v["device_label"]
                e.base_class = v["base_class"]
                e.sub_class = v["sub_class"]
                e.protocol = v["protocol"]
                e.vid = v["vid"]
                e.pid = v["pid"]
                e.support_autoshare = v["support_autoshare"]
                e.skip_reset = v["skip_reset"]
                e.enabled = v["enabled"]
                e.admin_comment = v["admin_comment"]
                keep_ids.add(eid)
            else:
                db.session.add(
                    UsbProfileEntries(
                        usb_profile_id=profile_id,
                        device_label=v["device_label"],
                        base_class=v["base_class"],
                        sub_class=v["sub_class"],
                        protocol=v["protocol"],
                        vid=v["vid"],
                        pid=v["pid"],
                        support_autoshare=v["support_autoshare"],
                        skip_reset=v["skip_reset"],
                        enabled=v["enabled"],
                        admin_comment=v["admin_comment"],
                        created_on=now,
                        created_by=actor,
                    )
                )
        for eid, e in existing.items():
            if eid not in keep_ids:
                db.session.delete(e)
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to apply entries to UsbProfile {profile_id} due to {err}"
        )
    db.session.refresh(profile)
    return SocaResponse(success=True, message=_profile_as_dict(profile))

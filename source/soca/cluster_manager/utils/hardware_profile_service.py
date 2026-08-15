# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
HardwareProfileService -- CRUD + binding + resolution for Hardware Profiles.

A HardwareProfile is the admin container that bundles capability sub-profiles.
Phase 1 links a single sub-profile type -- usb (a UsbProfile). It binds to a
Software Stack and/or a Project; exactly one HardwareProfile is effective per
VDI launch, resolved Project-over-Stack.

Public functions return SocaResponse/SocaError and are consumed by the API
handlers and edhctl CLI (which add .as_flask() at the web tier). Per the
web_interface/helpers precedent they intentionally return WITHOUT .as_flask()
(this is a service layer, not a Flask request handler).

The render/preview helpers resolve the effective profile and render its USB
sub-profile entries to usb-devices.conf filter lines -- the same lines the
boot-time resolver Lambda produces, used here for admin API/CLI preview.
"""

import logging
from datetime import datetime, timezone

from models import db, HardwareProfiles, UsbProfiles, SoftwareStacks, Projects
from utils.response import SocaResponse
from utils.error import SocaError
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


# Sub-profile type registry. Each Hardware Profile is a container that composes
# one or more sub-profile types. Adding a new type (disk, cpu, ...) is additive:
# append an entry here (and enable it once its UI renderer + data model exist).
# The admin detail pane renders one section per enabled type, in `order`.
#  - phase: when the sub-profile takes effect (boot-time vs provision-time).
#  - fk_field: the hardware_profiles column linking to the reusable library row.
#  - library_endpoint/library_label: the reusable library this type links to.
SUB_PROFILE_TYPES = [
    {
        "id": "usb",
        "label": "USB Devices",
        "phase": "boot-time",
        "order": 1,
        "enabled": True,
        "fk_field": "usb_profile_id",
        "library_endpoint": "/usb_profiles",
        "library_label": "USB Allowlists",
    },
]


def list_sub_profile_types() -> SocaResponse:
    """List enabled sub-profile types (ordered). message=list of dicts. Drives
    the registry-based detail-pane section rendering in the admin UI."""
    _types = sorted(
        [t for t in SUB_PROFILE_TYPES if t.get("enabled")],
        key=lambda t: t.get("order", 0),
    )
    return SocaResponse(success=True, message=_types)


def _hp_as_dict(hp: HardwareProfiles) -> dict:
    result = hp.as_dict()
    if hp.usb_profile is not None and hp.usb_profile.is_active:
        result["usb_profile"] = {
            "id": hp.usb_profile.id,
            "profile_name": hp.usb_profile.profile_name,
            "entry_count": len(hp.usb_profile.entries),
        }
    else:
        result["usb_profile"] = None
    return result


def list_hardware_profiles(include_inactive: bool = False) -> SocaResponse:
    """List Hardware Profiles. message=list of dicts."""
    _query = HardwareProfiles.query
    if not include_inactive:
        _query = _query.filter_by(is_active=True)
    return SocaResponse(
        success=True, message=[_hp_as_dict(hp) for hp in _query.all()]
    )


def get_hardware_profile(hp_id: int) -> SocaResponse:
    """Get one Hardware Profile. message=dict; SocaError 404 if absent."""
    hp = db.session.get(HardwareProfiles, hp_id)
    if hp is None or not hp.is_active:
        return SocaError.GENERIC_ERROR(
            helper=f"HardwareProfile {hp_id} not found", status_code=404
        )
    return SocaResponse(success=True, message=_hp_as_dict(hp))


def _validate_usb_profile_ref(usb_profile_id) -> SocaResponse:
    """Validate an optional usb_profile_id references an active UsbProfile.

    message=the normalized id (int) or None on success.
    """
    if usb_profile_id is None:
        return SocaResponse(success=True, message=None)
    usb = db.session.get(UsbProfiles, usb_profile_id)
    if usb is None or not usb.is_active:
        return SocaError.GENERIC_ERROR(
            helper=f"UsbProfile {usb_profile_id} not found", status_code=400
        )
    return SocaResponse(success=True, message=usb.id)


def _hp_name_taken(name, exclude_id=None) -> bool:
    """True if another HardwareProfile already uses this name (case-insensitive,
    across ALL rows regardless of is_active, so a disabled profile's name stays
    reserved and can be re-enabled without a collision). exclude_id skips the
    row being updated."""
    _q = HardwareProfiles.query.filter(
        db.func.lower(HardwareProfiles.profile_name) == name.strip().lower()
    )
    if exclude_id is not None:
        _q = _q.filter(HardwareProfiles.id != exclude_id)
    return _q.first() is not None


def create_hardware_profile(
    profile_name: str,
    description: str,
    created_by: str,
    usb_profile_id=None,
) -> SocaResponse:
    """Create a Hardware Profile, optionally linking a UsbProfile. message=dict."""
    if not Validators.is_string(profile_name) or not profile_name.strip():
        return SocaError.GENERIC_ERROR(
            helper="profile_name is required", status_code=400
        )
    if _hp_name_taken(profile_name):
        return SocaError.GENERIC_ERROR(
            helper=f"A Hardware Profile named '{profile_name.strip()}' already exists",
            status_code=400,
        )
    _usb = _validate_usb_profile_ref(usb_profile_id)
    if not _usb.success:
        return _usb
    now = datetime.now(timezone.utc)
    hp = HardwareProfiles(
        profile_name=profile_name.strip(),
        description=description,
        usb_profile_id=_usb.message,
        is_active=True,
        created_on=now,
        created_by=created_by,
    )
    try:
        db.session.add(hp)
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to create HardwareProfile due to {err}"
        )
    return SocaResponse(success=True, message=_hp_as_dict(hp))


def update_hardware_profile(hp_id: int, updated_by: str, **fields) -> SocaResponse:
    """Update profile_name / description / usb_profile_id and the is_active
    enable/disable flag. Works on disabled rows too (so they can be re-enabled).
    Disabling clears any stack/project bindings. message=dict."""
    hp = db.session.get(HardwareProfiles, hp_id)
    if hp is None:
        return SocaError.GENERIC_ERROR(
            helper=f"HardwareProfile {hp_id} not found", status_code=404
        )
    if "profile_name" in fields:
        _name = fields["profile_name"]
        if not Validators.is_string(_name) or not _name.strip():
            return SocaError.GENERIC_ERROR(
                helper="profile_name cannot be empty", status_code=400
            )
        if _hp_name_taken(_name, exclude_id=hp_id):
            return SocaError.GENERIC_ERROR(
                helper=f"A Hardware Profile named '{_name.strip()}' already exists",
                status_code=400,
            )
        hp.profile_name = _name.strip()
    if "description" in fields:
        hp.description = fields["description"]
    if "usb_profile_id" in fields:
        _usb = _validate_usb_profile_ref(fields["usb_profile_id"])
        if not _usb.success:
            return _usb
        hp.usb_profile_id = _usb.message
    if "is_active" in fields:
        _new = bool(fields["is_active"])
        if _new and not hp.is_active:
            hp.is_active = True
            hp.deactivated_on = None
            hp.deactivated_by = None
        elif not _new and hp.is_active:
            hp.is_active = False
            hp.deactivated_on = datetime.now(timezone.utc)
            hp.deactivated_by = updated_by
            # Disabling unbinds any stack/project so no launch resolves to it.
            for _stack in hp.software_stacks:
                _stack.hardware_profile_id = None
            for _project in hp.projects:
                _project.hardware_profile_id = None
    hp.updated_by = updated_by
    try:
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to update HardwareProfile {hp_id} due to {err}"
        )
    return SocaResponse(success=True, message=_hp_as_dict(hp))


def deactivate_hardware_profile(hp_id: int, deactivated_by: str) -> SocaResponse:
    """Soft-delete a Hardware Profile. Also clears any stack/project bindings
    to it so no launch resolves to an inactive profile. message='Deactivated'."""
    hp = db.session.get(HardwareProfiles, hp_id)
    if hp is None or not hp.is_active:
        return SocaError.GENERIC_ERROR(
            helper=f"HardwareProfile {hp_id} not found", status_code=404
        )
    hp.is_active = False
    hp.deactivated_on = datetime.now(timezone.utc)
    hp.deactivated_by = deactivated_by
    for _stack in hp.software_stacks:
        _stack.hardware_profile_id = None
    for _project in hp.projects:
        _project.hardware_profile_id = None
    try:
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to deactivate HardwareProfile {hp_id} due to {err}"
        )
    return SocaResponse(success=True, message="Deactivated")


def _bind(model, obj_id: int, hp_id, updated_by: str, label: str) -> SocaResponse:
    """Set (or clear when hp_id is None) the hardware_profile_id on a bound row."""
    obj = db.session.get(model, obj_id)
    if obj is None:
        return SocaError.GENERIC_ERROR(
            helper=f"{label} {obj_id} not found", status_code=404
        )
    if hp_id is not None:
        hp = db.session.get(HardwareProfiles, hp_id)
        if hp is None or not hp.is_active:
            return SocaError.GENERIC_ERROR(
                helper=f"HardwareProfile {hp_id} not found", status_code=400
            )
    obj.hardware_profile_id = hp_id
    obj.updated_by = updated_by
    try:
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            helper=f"Failed to bind HardwareProfile to {label} {obj_id} due to {err}"
        )
    return SocaResponse(success=True, message=f"{label} binding updated")


def bind_to_stack(software_stack_id: int, hp_id, updated_by: str) -> SocaResponse:
    """Bind (hp_id) or clear (None) a Hardware Profile on a Software Stack."""
    return _bind(SoftwareStacks, software_stack_id, hp_id, updated_by, "SoftwareStack")


def bind_to_project(project_id: int, hp_id, updated_by: str) -> SocaResponse:
    """Bind (hp_id) or clear (None) a Hardware Profile on a Project."""
    return _bind(Projects, project_id, hp_id, updated_by, "Project")


def list_all_bindings() -> SocaResponse:
    """List every active Stack/Project that currently binds a Hardware Profile.

    message=list of dicts: target_type (stack|project), target_id, target_name,
    hardware_profile_id, hardware_profile_name, hardware_profile_active. Used by
    the admin read-only "Current bindings" rollup. Setting/clearing a binding is
    done on the Software Stack / Project edit page, not here.
    """
    _bindings = []
    for _stack in (
        SoftwareStacks.query.filter_by(is_active=True)
        .filter(SoftwareStacks.hardware_profile_id.isnot(None))
        .all()
    ):
        _hp = _stack.hardware_profile
        _bindings.append(
            {
                "target_type": "stack",
                "target_id": _stack.id,
                "target_name": _stack.stack_name,
                "hardware_profile_id": _stack.hardware_profile_id,
                "hardware_profile_name": _hp.profile_name if _hp else None,
                "hardware_profile_active": bool(_hp and _hp.is_active),
            }
        )
    for _project in (
        Projects.query.filter_by(is_active=True)
        .filter(Projects.hardware_profile_id.isnot(None))
        .all()
    ):
        _hp = _project.hardware_profile
        _bindings.append(
            {
                "target_type": "project",
                "target_id": _project.id,
                "target_name": _project.project_name,
                "hardware_profile_id": _project.hardware_profile_id,
                "hardware_profile_name": _hp.profile_name if _hp else None,
                "hardware_profile_active": bool(_hp and _hp.is_active),
            }
        )
    return SocaResponse(success=True, message=_bindings)


def resolve_effective_profile(software_stack_id: int, project_id=None) -> SocaResponse:
    """Resolve the single effective Hardware Profile (Project overrides Stack).

    message=HardwareProfile dict, or None if neither binds a profile.
    """
    _effective_id = None
    if project_id is not None:
        project = db.session.get(Projects, project_id)
        if project is not None and project.hardware_profile_id is not None:
            _effective_id = project.hardware_profile_id
    if _effective_id is None:
        stack = db.session.get(SoftwareStacks, software_stack_id)
        if stack is None:
            return SocaError.GENERIC_ERROR(
                helper=f"SoftwareStack {software_stack_id} not found", status_code=404
            )
        _effective_id = stack.hardware_profile_id
    if _effective_id is None:
        return SocaResponse(success=True, message=None)
    hp = db.session.get(HardwareProfiles, _effective_id)
    if hp is None or not hp.is_active:
        return SocaResponse(success=True, message=None)
    return SocaResponse(success=True, message=_hp_as_dict(hp))


def render_allowlist(hp_id: int) -> SocaResponse:
    """Render a Hardware Profile's USB sub-profile to usb-devices.conf lines.

    message=list of filter-string lines (empty if no active USB sub-profile).
    """
    hp = db.session.get(HardwareProfiles, hp_id)
    if hp is None or not hp.is_active:
        return SocaError.GENERIC_ERROR(
            helper=f"HardwareProfile {hp_id} not found", status_code=404
        )
    usb = hp.usb_profile
    if usb is None or not usb.is_active:
        return SocaResponse(success=True, message=[])
    # Only enabled entries are delivered; disabled rows are retained for
    # documentation but never rendered to usb-devices.conf.
    return SocaResponse(
        success=True,
        message=[e.render_filter_line() for e in usb.entries if e.enabled],
    )


def preview_allowlist_for_stack_project(
    software_stack_id: int, project_id=None
) -> SocaResponse:
    """Admin preview: resolve effective profile for a stack/project and render.

    message={"hardware_profile": dict|None, "lines": [str, ...]}
    """
    _resolved = resolve_effective_profile(software_stack_id, project_id)
    if not _resolved.success:
        return _resolved
    profile = _resolved.message
    if profile is None:
        return SocaResponse(
            success=True, message={"hardware_profile": None, "lines": []}
        )
    _lines = render_allowlist(profile["id"])
    if not _lines.success:
        return _lines
    return SocaResponse(
        success=True,
        message={"hardware_profile": profile, "lines": _lines.message},
    )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import time
import logging
import config
from flask import (
    render_template,
    Blueprint,
    request,
    redirect,
    session,
    flash,
    Response,
)
from flask_babel import gettext as _
from requests import get, post, put, delete
from decorators import login_required, feature_flag
import feature_flags
from models import db, VirtualDesktopSessions, SoftwareStacks, VdiSavedImages
from datetime import datetime, timezone
from utils.config import SocaConfig
from utils.http_client import SocaHttpClient
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.aws.boto3_wrapper import get_boto
from models import SoftwareStacks, VirtualDesktopProfiles
import boto3
import botocore
import fnmatch
import pytz
import json

virtual_desktops = Blueprint("virtual_desktops", __name__, template_folder="templates")
logger = logging.getLogger("soca_logger")


# SocaConfig caching that used to live here was deleted alongside the
# SSM ElastiCache ConfigSync feature ship. Path queries now route through
# HGETALL on the cluster config hash; single-key reads through HGET.
# Both are sub-millisecond, so an in-process workaround cache adds
# nothing but moving parts. See utils/config.py for the new code path
# and docs/SsmConfigSync.md for the design.


@virtual_desktops.route("/virtual_desktops", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def index():
    _get_all_sessions = SocaHttpClient(
        endpoint=f"/api/dcv/virtual_desktops/list",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get(params={"user": session["user"], "is_active": "true"})

    logger.debug(f"get_all_desktops {_get_all_sessions}")
    if _get_all_sessions.get("success") is False:
        return SocaError.GENERIC_ERROR(
            helper=f"Unable to list desktops because of {_get_all_sessions.get('message')}"
        ).as_flask()

    try:
        tz = pytz.timezone(config.Config.TIMEZONE)
    except pytz.exceptions.UnknownTimeZoneError:
        flash(
            _(
                "Timezone {config.Config.TIMEZONE} configured by the admin does not exist. Defaulting to UTC. Refer to https://en.wikipedia.org/wiki/List_of_tz_database_time_zones for a full list of supported timezones"
            )
        )
        tz = pytz.timezone("UTC")

    server_time = (
        (datetime.now(timezone.utc)).astimezone(tz).strftime("%Y-%m-%d (%A) %H:%M")
    )

    # List all VDI stack this user is authorized to launch
    _get_vdi_software_stacks_for_user = SocaHttpClient(
        endpoint=f"/api/user/resources_permissions",
        headers={
            "X-EDH-USER": session["user"],
            "X-EDH-TOKEN": session["api_key"],
        },
    ).get(params={"virtual_desktops": "all"})

    if _get_vdi_software_stacks_for_user.get("success") is False:
        flash(
            _(
                f"Unable to list software stack for this user because of {_get_vdi_software_stacks_for_user.get('message')}"
            ),
            "error",
        )
        _software_stacks = {}
    else:
        _software_stacks = _get_vdi_software_stacks_for_user.get("message").get(
            "software_stacks"
        )

    logger.debug(f"Authorized Software Stack: {_software_stacks}")

    # Friendly subnet metadata (Name tag + AZ + AZ-ID) for the launch modal
    # subnet dropdown. Keyed by subnet id; the template falls back to the raw
    # id for any subnet missing here, so this is strictly best-effort.
    _subnet_info = {}
    try:
        from utils.cast import SocaCastEngine
        from utils.aws.ec2_helper import describe_subnets

        _private_subnets = (
            SocaCastEngine(
                SocaConfig(key="/configuration/PrivateSubnets").get_value().get("message")
            )
            .cast_as(list)
            .get("message")
            or []
        )
        if _private_subnets:
            _describe = describe_subnets(subnet_ids=_private_subnets)
            if _describe.get("success") is True:
                for _sn in _describe.get("message", {}).get("Subnets", []):
                    _name = next(
                        (
                            t.get("Value")
                            for t in _sn.get("Tags", [])
                            if t.get("Key") == "Name"
                        ),
                        "",
                    )
                    _subnet_info[_sn.get("SubnetId")] = {
                        "name": _name,
                        "az": _sn.get("AvailabilityZone", ""),
                        "az_id": _sn.get("AvailabilityZoneId", ""),
                    }
    except Exception as _subnet_err:
        logger.warning(f"Unable to build subnet_info for launch modal: {_subnet_err}")

    # Initial VDI-tile blur state = the user's resolved vdi_tile_masking
    # preference (user choice -> admin org default -> built-in false).
    # Best-effort: any preference-store error degrades to unblurred.
    try:
        from utils import user_pref_store as _user_prefs
        from utils.cast import SocaCastEngine

        _mask_resp = _user_prefs.resolve_pref(session["user"], "vdi_tile_masking")
        _mask_cast = SocaCastEngine(
            _mask_resp.message.get("value") if _mask_resp.success else False
        ).cast_as(expected_type=bool)
        _masking_default = (
            _mask_cast.get("message") if _mask_cast.get("success") else False
        )

        _cards_resp = _user_prefs.resolve_pref(session["user"], "vdi_cards_per_row")
        _cards_cast = SocaCastEngine(
            _cards_resp.message.get("value") if _cards_resp.success else 3
        ).cast_as(expected_type=int)
        _cards_per_row = (
            _cards_cast.get("message") if _cards_cast.get("success") else 3
        )

        _uuid_resp = _user_prefs.resolve_pref(session["user"], "show_session_uuid_tile")
        _uuid_cast = SocaCastEngine(
            _uuid_resp.message.get("value") if _uuid_resp.success else False
        ).cast_as(expected_type=bool)
        _show_session_uuid_tile = (
            _uuid_cast.get("message") if _uuid_cast.get("success") else False
        )
    except Exception as _mask_err:
        logger.warning(f"user preference resolve failed: {_mask_err}")
        _masking_default = False
        _cards_per_row = 3
        _show_session_uuid_tile = False

    _allow_spot = (
        SocaConfig(key="/configuration/FeatureFlags/VirtualDesktops/AllowSpot")
        .get_value(return_as=bool)
        .get("message")
        is True
    )

    from utils.resume_orchestration import saved_desktops_enabled as _sd_enabled
    _allow_saved_desktops = _sd_enabled()

    _saved_rows = (
        VdiSavedImages.query.filter_by(owner=session["user"], is_active=True)
        .filter(VdiSavedImages.state.notin_(["consumed", "error", "recycled"]))
        .order_by(VdiSavedImages.created_on.desc())
        .all()
    )
    def _capture_duration_str(r):
        if r.capture_completed_at and r.created_on:
            _secs = int((r.capture_completed_at - r.created_on).total_seconds())
            if _secs < 0:
                return ""
            _m, _s = divmod(_secs, 60)
            return f"{_m}m {_s}s" if _m else f"{_s}s"
        return ""
    _saved_desktops = [
        {
            "id": r.id,
            "name": r.session_name,
            "os": r.os_family,
            "instance_type": r.instance_type,
            "size_gib": int((r.root_bytes or 0) / 1073741824),
            "stack": r.software_stack_label or "",
            "captured": r.created_on.strftime("%Y-%m-%d %H:%M") if r.created_on else "",
            "capture_duration": _capture_duration_str(r),
            "source": r.source,
            "state": r.state,
            "pinned": r.pinned,
        }
        for r in _saved_rows
    ]

    # Recycle bin (D9): recently-deleted saved desktops still inside the recovery
    # window, offered for one-click recover before the reaper hard-deletes them.
    from utils.resume_orchestration import recycle_ttl_days as _recycle_ttl_days
    from datetime import datetime as _dt, timezone as _tz
    _ttl_days = _recycle_ttl_days()

    _recycled_rows = (
        VdiSavedImages.query.filter_by(
            owner=session["user"], is_active=True, state="recycled"
        )
        .order_by(VdiSavedImages.deleted_on.desc())
        .all()
    )
    _recycled_desktops = []
    for r in _recycled_rows:
        _days_left = None
        if r.deleted_on:
            _del = (
                r.deleted_on
                if r.deleted_on.tzinfo
                else r.deleted_on.replace(tzinfo=_tz.utc)
            )
            _days_left = max(_ttl_days - (_dt.now(_tz.utc) - _del).days, 0)
        _recycled_desktops.append(
            {
                "id": r.id,
                "name": r.session_name,
                "os": r.os_family,
                "instance_type": r.instance_type,
                "size_gib": int((r.root_bytes or 0) / 1073741824),
                "deleted": r.deleted_on.strftime("%Y-%m-%d %H:%M") if r.deleted_on else "",
                "days_left": _days_left,
            }
        )

    # Quota usage feedback for the Saved Desktops section. EBS storage is the
    # meaningful capture-limit axis; count is secondary. Limits are config-backed
    # with defaults until the D7 policy/reaper lands.
    from utils.cast import SocaCastEngine as _SCE
    def _cfg_int(_key, _default):
        _r = SocaConfig(key=_key).get_value(default=str(_default), allow_unknown_key=True)
        _c = _SCE(_r.get("message", _default)).cast_as(expected_type=int)
        return _c.get("message") if _c.get("success") else _default
    _quota_states = {"available", "capturing", "resuming", "pending_capture"}
    _active_saved = [r for r in _saved_rows if r.state in _quota_states]
    _max_count = _cfg_int("/configuration/FeatureFlags/VirtualDesktops/MaxSavedImagesPerUser", 5)
    _max_gib = _cfg_int("/configuration/FeatureFlags/VirtualDesktops/MaxSavedImagesTotalGiB", 500)
    _used_count = len(_active_saved)
    _used_gib = round(sum((r.root_bytes or 0) for r in _active_saved) / 1073741824, 1)
    _quota = {
        "count_used": _used_count,
        "count_max": _max_count,
        "gib_used": _used_gib,
        "gib_max": _max_gib,
        "pct_count": min(100, round(_used_count / _max_count * 100)) if _max_count else 0,
        "pct_bytes": min(100, round(_used_gib / _max_gib * 100)) if _max_gib else 0,
    }

    # Interrupted-card hand-off: attach the linked interrupt saved-image state so
    # the tile can render success (saved) vs failure (auto-save did not complete),
    # derived from VdiSavedImages.origin_session_uuid. Best-effort.
    try:
        _us = _get_all_sessions.get("message")
        _sess_iter = (
            list(_us.values()) if Validators.is_dict(_us)
            else (_us if Validators.is_list(_us) else [])
        )
        _interrupted_uuids = [
            s.get("session_uuid") for s in _sess_iter
            if Validators.is_dict(s) and s.get("session_state") == "interrupted"
        ]
        if _interrupted_uuids:
            _imgs = (
                VdiSavedImages.query.filter(
                    VdiSavedImages.origin_session_uuid.in_(_interrupted_uuids),
                    VdiSavedImages.source == "interrupt",
                )
                .order_by(VdiSavedImages.id.desc())
                .all()
            )
            _state_by_uuid = {}
            for _im in _imgs:
                _state_by_uuid.setdefault(_im.origin_session_uuid, _im.state)
            for s in _sess_iter:
                if Validators.is_dict(s) and s.get("session_state") == "interrupted":
                    s["interrupt_image_state"] = _state_by_uuid.get(s.get("session_uuid"))
    except Exception as _int_err:
        logger.warning(f"interrupted-card image-state enrichment failed: {_int_err}")

    # Golden Image Publish FF check for template context. Mirror the full gate
    # used in vertical_menu_bar.html (enabled + allowed/denied) so the UI matches
    # what the API's @feature_flag decorator will actually authorize.
    _allow_golden_image_publish = False
    try:
        _allow_golden_image_publish = feature_flags.is_user_allowed(
            "GOLDEN_IMAGE_PUBLISH", session.get("user")
        ).get("message") is True
    except Exception:
        pass

    return render_template(
        "virtual_desktops.html",
        allow_spot=_allow_spot,
        allow_saved_desktops=_allow_saved_desktops,
        allow_golden_image_publish=_allow_golden_image_publish,
        saved_desktops=_saved_desktops,
        recycled_desktops=_recycled_desktops,
        recycle_ttl_days=_ttl_days,
        quota=_quota,
        allowed_dcv_session_types=config.Config.DCV_ALLOWED_SESSION_TYPES,
        software_stacks=_software_stacks,
        subnet_info=_subnet_info,
        base_os_labels=config.Config.DCV_BASE_OS,
        user_sessions=_get_all_sessions.get("message"),
        linux_stop_idle_session=config.Config.DCV_LINUX_STOP_IDLE_SESSION,
        linux_terminate_stopped_session=config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION,
        linux_terminate_session=config.Config.DCV_LINUX_TERMINATE_STOPPED_SESSION,
        windows_stop_idle_session=config.Config.DCV_WINDOWS_STOP_IDLE_SESSION,
        windows_terminate_stopped_session=config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION,
        windows_terminate_session=config.Config.DCV_WINDOWS_TERMINATE_STOPPED_SESSION,
        allow_instance_change=config.Config.DCV_LINUX_ALLOW_INSTANCE_CHANGE,
        page="virtual_desktops",
        server_time=server_time,
        server_timezone_human=config.Config.TIMEZONE,
        screenshot_privacy_default=_masking_default,
        vdi_cards_per_row=_cards_per_row,
        show_session_uuid_tile=_show_session_uuid_tile,
        # Browser refresh interval for the screenshot thumbnail. Match the
        # broker-side Lambda polling cadence so we never refresh the URL
        # faster than the Lambda actually puts a new image -- otherwise
        # we'd waste presigned URL generation calls and serve the same
        # bytes back. Sourced from SSM
        # (Config.dcv.screenshot.refresh_seconds in default_config.yml).
        config_screenshot_refresh_seconds=int(
            SocaConfig(key="/dcv/screenshot/refresh_seconds")
            .get_value()
            .get("message", "120")
            or 120
        ),
    )


@virtual_desktops.route("/virtual_desktops/get_session_state", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def get_session_state():
    logger.info(
        f"Received following parameters {request.args} for new virtual desktops"
    )
    _get_all_state = SocaHttpClient(
        endpoint=f"/api/dcv/virtual_desktops/session_state",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get(params={"session_uuid": request.args.get("session_uuid")})

    return _get_all_state.get("message"), 200


@virtual_desktops.route("/virtual_desktops/create", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def create():
    logger.info(
        f"Received following parameters {request.form} for new virtual desktops"
    )
    # configure large timeout in case of capacity probing in multiple subnets
    _create_desktop = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/create",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
        timeout=60,
    ).post(data=request.form.to_dict())

    if _create_desktop.get("success") is True:
        flash(
            _(
                "Your Virtual Desktop session has been initiated. It will be ready within 20 minutes."
            ),
            "success",
        )
    else:
        flash(
            _(f"{_create_desktop.get('message')} "),
            "error",
        )

    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/delete", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def delete():
    _session_uuid = request.form.get("session_uuid", None)
    logger.info(f"Received following parameters {request.form} to delete DCV Session")

    # Delete a desktop
    _delete_desktop_request = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/delete",
        headers={
            "X-EDH-USER": session["user"],
            "X-EDH-TOKEN": session["api_key"],
        },
    ).delete(data={"session_uuid": _session_uuid})

    if _delete_desktop_request.get("success") is True:
        flash(_(f"Your desktop is about to be terminated as requested"), "success")
    else:
        flash(
            _(f"Unable to delete desktop: {_delete_desktop_request.get('message')} "),
            "error",
        )

    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/stop", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def stop():
    _session_uuid = request.form.get("session_uuid", None)
    logger.info(f"Received following parameters {request.form} to stop DCV Session")

    # Delete a desktop
    _stop_desktop_request = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/stop",
        headers={
            "X-EDH-USER": session["user"],
            "X-EDH-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid})

    if _stop_desktop_request.get("success") is True:
        flash(_(f"Your desktop is about to be stopped as requested"), "success")
    else:
        flash(
            _(f"Unable to stop desktop: {_stop_desktop_request.get('message')} "),
            "error",
        )

    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/recycle", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def recycle_saved_desktop_view():
    _saved_image_id = request.form.get("saved_image_id", None)
    _req = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/recycle_saved_desktop",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).post(data={"saved_image_id": _saved_image_id})
    if _req.get("success") is True:
        from utils.resume_orchestration import recycle_ttl_days as _rttl
        flash(_("Saved desktop moved to the recycle bin. You can recover it within {n} days.").format(n=_rttl()), "success")
    else:
        flash(_(f"Unable to delete saved desktop: {_req.get('message')}"), "error")
    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/recover", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def recover_saved_desktop_view():
    _saved_image_id = request.form.get("saved_image_id", None)
    _req = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/recover_saved_desktop",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).post(data={"saved_image_id": _saved_image_id})
    if _req.get("success") is True:
        flash(_("Saved desktop recovered."), "success")
    else:
        flash(_(f"Unable to recover saved desktop: {_req.get('message')}"), "error")
    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/save_and_shutdown", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def save_and_shutdown():
    _session_uuid = request.form.get("session_uuid", None)
    _resp = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/save_and_shutdown",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).put(data={"session_uuid": _session_uuid})
    if _resp.get("success") is True:
        flash(_("Your desktop is being saved & shut down - a resumable image is being captured, then it will terminate."), "success")
    else:
        flash(_(f"Unable to save & shut down: {_resp.get('message')}"), "error")
    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/resume", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def resume_saved_desktop():
    _saved_image_id = request.form.get("saved_image_id", None)
    _spot = request.form.get("spot", "false")
    _instance_type = request.form.get("instance_type", "")
    _resp = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/resume_saved_desktop",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).post(data={"saved_image_id": _saved_image_id, "spot": _spot, "instance_type": _instance_type})
    if _resp.get("success") is True:
        flash(_("Resuming your saved desktop - it will appear shortly as it boots and re-registers with the broker."), "success")
    else:
        flash(_(f"Unable to resume: {_resp.get('message')}"), "error")
    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/resume_options", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def resume_options():
    """Session-authed (browser) JSON for the resume modal: compatible alternate
    instance types (admin allowlist ∩ GPU manufacturer) for a saved desktop,
    computed server-side. Mirrors the header-authed VdiResumeOptions Resource, for
    cookie-authed fetch() from the page (same dual-route pattern as the admin
    instance-type typeahead)."""
    from flask import jsonify
    from api.v1.dcv.instance_type_search import (
        compatible_resume_types,
    )
    from api.v1.dcv.resume_saved_desktop import _profile_pattern_for_saved_image

    _sid = request.args.get("saved_image_id", type=int)
    if not _sid:
        return SocaError.CLIENT_MISSING_PARAMETER(parameter="saved_image_id").as_flask()
    _row = VdiSavedImages.query.filter_by(
        id=_sid, is_active=True, owner=session["user"]
    ).first()
    if not _row:
        return SocaError.GENERIC_ERROR(helper="Saved desktop not found").as_flask()

    _pattern = _profile_pattern_for_saved_image(_row)
    _types = compatible_resume_types(_row.instance_type, _pattern)
    _out = {"origin": _row.instance_type, "types": _types}
    return SocaResponse(success=True, message=_out).as_flask()


@virtual_desktops.route("/virtual_desktops/saved_images_progress", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def saved_images_progress():
    from flask import jsonify
    _rows = (
        VdiSavedImages.query.filter_by(owner=session["user"], is_active=True)
        .filter(VdiSavedImages.state.in_(["capturing", "pending_capture"]))
        .all()
    )
    if not _rows:
        return jsonify(success=True, message=[])
    _ec2 = get_boto(service_name="ec2").get("message")
    _results = []
    for _r in _rows:
        _pct = 0
        _state = "capturing"
        # pending_capture: the box is still stopping for a clean snapshot; no AMI
        # exists yet, so report an indeterminate "working" bar without an AWS call.
        if _r.state == "pending_capture" or not _r.image_id:
            _results.append({"id": _r.id, "pct": 0, "state": "capturing"})
            continue
        try:
            _img = _ec2.describe_images(ImageIds=[_r.image_id])
            _images = _img.get("Images", [])
            if _images and _images[0].get("State") == "available":
                _bytes = sum(
                    int(bdm.get("Ebs", {}).get("VolumeSize", 0))
                    for bdm in _images[0].get("BlockDeviceMappings", [])
                ) * 1073741824
                _r.state = "available"
                if _bytes:
                    _r.root_bytes = _bytes
                if _r.capture_completed_at is None:
                    _r.capture_completed_at = datetime.now(timezone.utc)
                db.session.commit()
                _state = "available"
                _pct = 100
            else:
                _snap_ids = [
                    bdm["Ebs"]["SnapshotId"]
                    for i in _images
                    for bdm in i.get("BlockDeviceMappings", [])
                    if bdm.get("Ebs", {}).get("SnapshotId")
                ]
                if _snap_ids:
                    _snaps = _ec2.describe_snapshots(SnapshotIds=_snap_ids)
                    _progs = []
                    for _s in _snaps.get("Snapshots", []):
                        _p = _s.get("Progress", "0%").rstrip("%")
                        try:
                            _progs.append(int(_p))
                        except ValueError:
                            _progs.append(0)
                    _pct = round(sum(_progs) / len(_progs)) if _progs else 0
        except Exception:
            pass
        _results.append({"id": _r.id, "pct": _pct, "state": _state})
    return jsonify(success=True, message=_results)


@virtual_desktops.route("/virtual_desktops/start", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def start():
    _session_uuid = request.args.get("session_uuid", None)
    logger.info(f"Received following parameters {request.args} to start DCV Session")

    # Delete a desktop
    _start_desktop_request = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/start",
        headers={
            "X-EDH-USER": session["user"],
            "X-EDH-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid})

    if _start_desktop_request.get("success") is True:
        flash(_(f"Your desktop is starting"), "success")
    else:
        flash(
            _(f"Unable to start desktop: {_start_desktop_request.get('message')} "),
            "error",
        )

    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/schedule", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def schedule():
    _session_uuid = request.form.get("session_uuid", None)
    _schedule = request.form.get("schedule", None)
    logger.info(
        f"Received following parameters {request.form} to update schedule DCV Session"
    )

    # Update Schedule
    _update_desktop_schedule_request = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/schedule",
        headers={
            "X-EDH-USER": session["user"],
            "X-EDH-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid, "schedule": _schedule})

    if _update_desktop_schedule_request.get("success") is True:
        flash(_(f"Your schedule has been updated successfully"), "success")
    else:
        flash(
            _(
                f"Unable to update schedule: {_update_desktop_schedule_request.get('message')} "
            ),
            "error",
        )

    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/resize", methods=["POST"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def resize():
    _session_uuid = request.form.get("session_uuid", None)
    _instance_type = request.form.get("instance_type", None)

    logger.info(f"Received following parameters {request.form} to modify DCV instance")

    # Resize VDI instance
    _resize_desktop_request = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/resize",
        headers={
            "X-EDH-USER": session["user"],
            "X-EDH-TOKEN": session["api_key"],
        },
    ).put(data={"session_uuid": _session_uuid, "instance_type": _instance_type})

    if _resize_desktop_request.get("success") is True:
        flash(_(f"Your virtual desktop is now using {_instance_type}"), "success")
    else:
        flash(
            _(f"{_resize_desktop_request.get('message')} "),
            "error",
        )

    return redirect("/virtual_desktops")


@virtual_desktops.route("/virtual_desktops/client", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def generate_client():
    _session_uuid = request.args.get("session_uuid", None)
    if _session_uuid is None:
        flash(_("Invalid graphical sessions"), "error")
        return redirect("/virtual_desktop")

    _result = build_dcv_session_file(
        owner=session["user"],
        session_uuid=_session_uuid,
    )
    if not _result["success"]:
        # Preserve existing UX: redirect to the listing page on failure.
        flash(_result["message"], "error")
        return redirect("/virtual_desktops")

    return Response(
        _result["body"],
        mimetype="text/txt",
        headers={
            "Content-disposition": f"attachment; filename={_result['filename']}"
        },
    )


def build_dcv_session_file(owner: str, session_uuid: str) -> dict:
    """Build the .dcv connection file payload for a given session.

    Pure function -- no Flask session or request access. Callable from both
    the WebUI route (`/virtual_desktops/client`) and the API resource
    (`/api/dcv/virtual_desktops/connection_file`). Returns a dict:

        success=True   -> {"success": True, "body": <text>, "filename": <name>}
        success=False  -> {"success": False, "message": <reason>, "status": <http>}

    The status code is advisory; the WebUI route ignores it and renders a flash,
    while the API resource maps it directly to the HTTP response.
    """
    _check_session = VirtualDesktopSessions.query.filter_by(
        session_owner=owner, session_uuid=session_uuid, is_active=True
    ).first()

    if not _check_session:
        # Click-time repoint: the requested session_uuid may be stale -- a
        # Save->Resume supersedes a desktop's session with a NEW uuid for the
        # SAME stable identity (session_name + owner). A tile that hasn't
        # repointed yet (poll not fired) would otherwise build a connection file
        # for the dead session -> DCV-branded connect error. Resolve the
        # desktop's current live session so Connect always lands on the live one.
        # Belt-and-suspenders with the 30s poll repoint (current_session_uuid).
        # Owner scoping is preserved throughout (no cross-user resolution).
        _stale = VirtualDesktopSessions.query.filter_by(
            session_owner=owner, session_uuid=session_uuid
        ).first()
        if _stale:
            _check_session = (
                VirtualDesktopSessions.query.filter_by(
                    session_owner=owner,
                    session_name=_stale.session_name,
                    is_active=True,
                )
                .order_by(VirtualDesktopSessions.created_on.desc())
                .first()
            )
            if _check_session:
                logger.info(
                    f"build_dcv_session_file: requested session {session_uuid} is "
                    f"stale/inactive; resolved live successor "
                    f"{_check_session.session_uuid} for desktop "
                    f"'{_stale.session_name}' (owner {owner})"
                )

    if not _check_session:
        return {
            "success": False,
            "message": _("Session not found or not owned by user"),
            "status": 404,
        }

    if SocaConfig("/configuration/UserDirectory/provider").get_value().get(
        "message"
    ) in [
        "aws_ds_managed_activedirectory",
        "existing_active_directory",
    ]:
        logger.info(
            "Building DCV Client, AD is enabled, checking if it's a windows session"
        )
        if _check_session.os_family == "windows":
            logger.info("Windows session detected, using DOMAIN\\user format")
            _user = (
                f"{SocaConfig('/configuration/UserDirectory/short_name').get_value().get('message')}"
                f"\\{_check_session.session_owner}"
            )
        else:
            _user = _check_session.session_owner
    else:
        _user = _check_session.session_owner

    _session_type = _check_session.session_type
    _is_high_scale = (
        str(SocaConfig(key="/dcv/high_scale_enabled").get_value().get("message", "false")).lower()
        == "true"
    )

    if _is_high_scale:
        _dcv_host = (
            SocaConfig(key="/dcv/frontend_nlb_dns").get_value().get("message", "")
        )
        # In high-scale mode, _check_session.authentication_token is the broker
        # session id (opaque UUID), not a token. The native DCV client connects
        # with sessionid=<broker session id> and a fresh JWT fetched on demand.
        _broker_session_id = _check_session.authentication_token or ""
        _auth_token = ""
        if _broker_session_id:
            try:
                from utils.dcv_broker_client import DcvBrokerClient
                _broker = DcvBrokerClient()
                _conn_resp = _broker.get_session_connection_data(
                    session_id=_broker_session_id,
                    user=_check_session.session_owner,
                )
                if _conn_resp.success:
                    _auth_token = (_conn_resp.message or {}).get("ConnectionToken", "")
                else:
                    logger.warning(
                        f"broker.get_session_connection_data failed for "
                        f"{_check_session.session_uuid} ({_broker_session_id}): "
                        f"{_conn_resp.message}"
                    )
            except Exception as _err:
                logger.error(
                    f"DcvBrokerClient.get_session_connection_data raised: {_err}"
                )
        _body = (
            "[version]\nformat=1.0\n[connect]\n"
            f"user={_user}\n"
            f"sessionid={_broker_session_id}\n"
            f"host={_dcv_host}\n"
            "port=443\n"
            "webport=443\n"
            "quicport=443\n"
            "certificatevalidationpolicy=accept-untrusted\n"
            f"authtoken={_auth_token}\n"
        )
    else:
        _body = (
            "\n[version]\nformat=1.0\n[connect]\n"
            f"host={SocaConfig(key='/configuration/DCVEntryPointDNSName').get_value().get('message')}\n"
            "port=443\n"
            f"sessionid={_check_session.session_id}\n"
            f"user={_user}\n"
            + (
                f"authToken={_check_session.authentication_token}\n"
                if _session_type == "virtual"
                else ""
            )
            + f"weburlpath=/{_check_session.instance_private_dns}"
        )

    return {
        "success": True,
        "body": _body,
        "filename": f"{owner}_soca_{session_uuid}.dcv",
        "status": 200,
    }



@virtual_desktops.route("/virtual_desktops/<string:session_uuid>/timeline", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def timeline_detail(session_uuid: str):
    """
    Detail-page route showing the full event log for a single DCV session.

    Renders virtual_desktops_timeline.html with the historical events
    fetched from DcvSessionEventLog. The page also opens an SSE stream on
    /api/dcv/events/stream/<session_uuid> for live updates.

    Authorization: same model as the list page -- session_owner must
    match the caller. The DB query enforces that filter so a user cannot
    GET another user's timeline by guessing the UUID.
    """
    # UUID format gate matches the controller-side regex; keeps malformed
    # paths from reaching the DB.
    import re
    if not re.match(r"^[0-9a-fA-F-]{36}$", session_uuid):
        return SocaError.GENERIC_ERROR(
            helper=f"Invalid session_uuid format"
        ).as_flask()

    # Ownership check: the session must belong to the caller
    _session_row = (
        VirtualDesktopSessions.query
        .filter_by(session_uuid=session_uuid, session_owner=session["user"], is_active=True)
        .first()
    )
    if _session_row is None:
        return SocaError.GENERIC_ERROR(
            helper=f"Virtual desktop {session_uuid} not found or not accessible"
        ).as_flask()

    # Pull historical events from the DDB notification store -- the SAME
    # source the SSE stream replays from -- so server-rendered rows and live
    # SSE rows share one id space (ULID) and the JS dedup (keyed on the row
    # id) matches across them. Reading the ORM DcvSessionEventLog here instead
    # gave server rows integer PK ids that the ULID-keyed SSE replay could not
    # match, rendering every dual-written event twice. Capped at 200.
    from utils.dcv_event_store import recent_events, normalize_ts
    try:
        _envelopes = recent_events(f"dcv#{session_uuid}", limit=200)
    except Exception as _ev_err:
        logger.warning(f"timeline DDB event read failed for {session_uuid}: {_ev_err}")
        _envelopes = []

    # Simple shape for template: lists of dicts. id is the envelope ULID
    # (matches the SSE stream); ts is normalized to ISO so the legacy
    # epoch-format control-plane "placed" event parses + sorts correctly.
    _event_rows = []
    for _env in _envelopes:
        _payload = _env.get("payload") or {}
        _ts_resp = normalize_ts(_env.get("ts"))
        _iso = _ts_resp.message if _ts_resp.success else ""
        _event_rows.append({
            "id": _env.get("id"),
            "event_type": _payload.get("event_type") or "",
            "checkpoint": _payload.get("checkpoint") or "",
            "sub_status": _payload.get("sub_status") or "",
            "event_timestamp": _iso,
            "received_at": _iso,
        })

    # Per-checkpoint historical ETA bands for this stack+instance, so
    # the detail page can tint each gate vs its typical timing. Best-
    # effort: None when history is too thin. JSON-serialized into the
    # page; JS compares each row's actual T+ against p75/p95.
    _eta = None
    try:
        from helpers.vdi_eta import get_eta
        _eta = get_eta(
            stack_id=_session_row.software_stack_id,
            instance_type=_session_row.instance_type,
        )
    except Exception as _err:
        logger.warning(f"timeline eta lookup failed for {session_uuid}: {_err}")

    return render_template(
        "virtual_desktops_timeline.html",
        page="virtual_desktops",
        user=session["user"],
        session_uuid=session_uuid,
        session_name=_session_row.session_name,
        session_state=_session_row.session_state,
        session_owner=_session_row.session_owner,
        session_created_on=_session_row.created_on.isoformat() + "Z" if _session_row.created_on else "",
        instance_id=_session_row.instance_id or "",
        instance_base_os=getattr(_session_row, "session_instance_base_os", ""),
        events=_event_rows,
        eta=_eta,
    )


# ---------------------------------------------------------------------------
# WebUI (cookie-auth) SSE entry points.
#
# Browser EventSource cannot send custom HTTP headers (W3C limitation), so
# the API routes under /api/dcv/events/stream (which require X-EDH-USER +
# X-EDH-TOKEN via @private_api) cannot be reached from the WebUI directly.
# These view routes are session-cookie authenticated via @login_required
# and delegate to the same generator the API routes use, keeping the
# streaming + ownership-filter logic in one place.
#
# API surface (header-auth) lives at:
#   /api/dcv/events/stream
#   /api/dcv/events/stream/<session_uuid>
# WebUI surface (cookie-auth) lives at:
#   /virtual_desktops/events/stream
#   /virtual_desktops/events/stream/<session_uuid>
# ---------------------------------------------------------------------------


@virtual_desktops.route("/virtual_desktops/events/stream", methods=["GET"])
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def events_stream():
    """
    Multiplexed SSE stream for the WebUI grid view.

    Authentication: Flask session cookie (set by /auth login).
    Authorization: enforced inside build_grid_stream_response via
    session_owner == user.
    """
    from api.v1.dcv.event_stream import build_grid_stream_response
    return build_grid_stream_response(session["user"])


@virtual_desktops.route(
    "/virtual_desktops/events/stream/<string:session_uuid>", methods=["GET"]
)
@login_required
@feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="view")
def events_stream_session(session_uuid: str):
    """
    Focused SSE stream for the WebUI detail page.

    Authentication: Flask session cookie. Authorization (the session must
    be owned by the caller) is enforced inside
    build_session_stream_response.
    """
    from api.v1.dcv.event_stream import build_session_stream_response
    return build_session_stream_response(session["user"], session_uuid)

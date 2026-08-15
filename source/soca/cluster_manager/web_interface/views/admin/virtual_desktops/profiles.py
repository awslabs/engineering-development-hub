######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

import logging
import config
from flask import render_template, Blueprint, request, redirect, session, flash
from flask_babel import gettext as _
from decorators import login_required, admin_only
from utils.config import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse
from utils.http_client import SocaHttpClient

logger = logging.getLogger("soca_logger")
admin_virtual_desktops_profiles = Blueprint(
    "admin_virtual_desktops_profiles", __name__, template_folder="templates"
)


def _describe_subnet_hints(subnet_ids: list) -> list:
    """
    Ordered list of subnet rows (id, name, az, az_id, cidr, free) for the
    admin profile picker, sorted by AZ-ID then subnet id.

    Returns a LIST, not a dict: Flask's tojson sorts dict keys, which would
    clobber this AZ ordering in the template. A JSON array preserves order.
    Best-effort: any failure yields [].
    """
    _rows = []
    try:
        from utils.aws.ec2_helper import describe_subnets

        if subnet_ids:
            _desc = describe_subnets(subnet_ids=subnet_ids)
            if _desc.get("success") is True:
                for _sn in _desc.get("message", {}).get("Subnets", []):
                    _name = next(
                        (
                            t.get("Value")
                            for t in _sn.get("Tags", [])
                            if t.get("Key") == "Name"
                        ),
                        "",
                    )
                    _ipv6 = ""
                    for _a in _sn.get("Ipv6CidrBlockAssociationSet", []) or []:
                        if _a.get("Ipv6CidrBlock") and (
                            _a.get("Ipv6CidrBlockState", {}) or {}
                        ).get("State", "associated") == "associated":
                            _ipv6 = _a.get("Ipv6CidrBlock")
                            break
                    _rows.append(
                        {
                            "id": _sn.get("SubnetId"),
                            "name": _name,
                            "az": _sn.get("AvailabilityZone", ""),
                            "az_id": _sn.get("AvailabilityZoneId", ""),
                            "cidr": _sn.get("CidrBlock", ""),
                            "ipv6": _ipv6,
                            "free": _sn.get("AvailableIpAddressCount"),
                        }
                    )
    except Exception as _err:
        logger.warning(f"Unable to build subnet hints for admin profiles: {_err}")
    # Order by AZ-ID (then subnet id) so the table groups by AZ logically.
    _rows.sort(key=lambda _r: (_r.get("az_id") or "\uffff", _r.get("id") or ""))
    return _rows


@admin_virtual_desktops_profiles.route(
    "/admin/virtual_desktops/profiles", methods=["GET"]
)
@login_required
@admin_only
def index():
    logger.info(f"Get all profiles")
    _all_profiles = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/profiles",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    if _all_profiles.get("success") is False:
        flash(_(
            f"Unable to list Virtual Desktop profiles because of {_all_profiles.get('message')}"),
            "error",
        )
        _vdi_profiles = {}
    else:
        _vdi_profiles = _all_profiles.get("message")

    _soca_private_subnets = (
        SocaConfig(key="/configuration/PrivateSubnets")
        .get_value(return_as=list)
        .get("message")
    )

    _default_instance_type_pattern = ", ".join(
        config.Config.DCV_DEFAULT_AMI_INSTANCE_TYPES
    )

    return render_template(
        "admin/virtual_desktops/profiles.html",
        subnet_rows=_describe_subnet_hints(_soca_private_subnets),
        preselected_subnets=_soca_private_subnets,
        default_instance_type_pattern=_default_instance_type_pattern,
        vdi_profiles=_vdi_profiles,
        page="admin_profiles",
    )


@admin_virtual_desktops_profiles.route(
    "/admin/virtual_desktops/profiles/create", methods=["POST"]
)
@login_required
@admin_only
def create_new_profile():
    logger.info(f"Creating new VDI profile")
    _create_new_profile = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/profiles",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).post(request.form.to_dict())

    if _create_new_profile.get("success") is False:
        flash(_(
            f"{_create_new_profile.get('message')}"),
            "error",
        )
    else:
        flash(_(f"Your profile has been created successfully"), "success")

    return redirect("/admin/virtual_desktops/profiles")


@admin_virtual_desktops_profiles.route(
    "/admin/virtual_desktops/profiles/delete", methods=["POST"]
)
@login_required
@admin_only
def delete_profile():
    logger.info(f"Deleting VDI profile")
    _delete_new_profile = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/profiles",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).delete(request.form.to_dict())

    if _delete_new_profile.get("success") is False:
        flash(_(
            f"{_delete_new_profile.get('message')}"),
            "error",
        )
    else:
        flash(_(f"Your profile has been deleted successfully"), "success")

    return redirect("/admin/virtual_desktops/profiles")


@admin_virtual_desktops_profiles.route(
    "/admin/virtual_desktops/profiles/edit", methods=["POST", "GET"]
)
@login_required
@admin_only
def profile_edit():
    if request.method == "GET":
        return redirect("/admin/virtual_desktops/profiles")

    logger.info(f"Received following parameters {request.form} to edit profile")
    _profile_to_modify = request.form.get("profile_id", None)
    if _profile_to_modify is None:
        flash(_("Missing profile_id"), "error")
        return redirect("/admin/virtual_desktops/profiles")

    _get_profile_info = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/profiles",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get(params={"profile_id": request.form.get("profile_id")})

    _list_profiles = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/profiles",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    if _get_profile_info.get("success") is True:
        _profile_info = _get_profile_info.get("message").get(_profile_to_modify)
        _current_subnets = [
            _s.strip()
            for _s in str(_profile_info.get("allowed_subnet_ids", "") or "").split(",")
            if _s.strip()
        ]
        return render_template(
            "admin/virtual_desktops/profiles_edit.html",
            user=session["user"],
            subnet_rows=_describe_subnet_hints(
                SocaConfig(key="/configuration/PrivateSubnets")
                .get_value(return_as=list)
                .get("message")
                or []
            ),
            preselected_subnets=_current_subnets,
            profiles=_list_profiles.get("message"),
            supported_base_os=config.Config.DCV_BASE_OS.keys(),
            profile_info=_profile_info,
            page="admin_profiles",
        )
    else:
        flash(_(
            f"Unable to list Virtual Desktop Profile because of {_get_profile_info.get('message')}"),
            "error",
        )
        return redirect("/admin/virtual_desktops/profiles")


@admin_virtual_desktops_profiles.route(
    "/admin/virtual_desktops/profiles/edit/update", methods=["POST"]
)
@login_required
@admin_only
def profile_update():
    logger.info(f"Received following parameters {request.form} to edit profile ")

    _profile_to_modify = request.form.get("profile_id", None)
    if _profile_to_modify is None:
        flash(_("Missing profile_id"), "error")
        return redirect("/admin/virtual_desktops/profiles")

    _modify_profile = SocaHttpClient(
        endpoint="/api/dcv/virtual_desktops/profiles",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).put(data=request.form.to_dict())

    if _modify_profile.get("success") is True:
        flash(_(
            f"Your Virtual Desktop Profile has been updated successfully"),
            "success",
        )
    else:
        flash(_(
            f"{_modify_profile.get('message')}"),
            "error",
        )
    return redirect("/admin/virtual_desktops/profiles")

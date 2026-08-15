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
import boto3
from flask import render_template, Blueprint, request, redirect, session, flash
from flask_babel import gettext as _
from decorators import login_required, admin_only
from utils.http_client import SocaHttpClient
from collections import defaultdict

logger = logging.getLogger("soca_logger")
admin_target_nodes_user_data = Blueprint(
    "admin_target_nodes_user_data", __name__, template_folder="templates"
)


def get_region():
    session = boto3.session.Session()
    aws_region = session.region_name
    return aws_region


@admin_target_nodes_user_data.route("/admin/target_nodes/user_data", methods=["GET"])
@login_required
@admin_only
def index():
    logger.info(f"List all User Data Templates")
    _list_user_data_templates = SocaHttpClient(
        endpoint="/api/target_nodes/user_data",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get()

    if _list_user_data_templates.get("success") is False:
        flash(_(
            f"Unable to list User Data Template  because of {_list_user_data_templates.get('message')}"),
            "error",
        )
        _user_data_templates = {}
    else:
        _user_data_templates = _list_user_data_templates.get("message")

    return render_template(
        "admin/target_nodes/user_data.html",
        user_data_templates=_user_data_templates,
        page="admin_target_nodes_user_data",
    )


@admin_target_nodes_user_data.route(
    "/admin/target_nodes/user_data/create", methods=["POST"]
)
@login_required
@admin_only
def user_data_template_create():
    logger.info(
        f"Received following parameters {request.form} to create target node user template projects"
    )

    _create_user_data = SocaHttpClient(
        endpoint="/api/target_nodes/user_data",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).post(data=request.form.to_dict())

    if _create_user_data.get("success") is True:
        flash(_(
            f"Your user data template has been created successfully"),
            "success",
        )
    else:
        flash(_(
            f"Unable to create your user data template because of {_create_user_data.get('message')}"),
            "error",
        )

    return redirect("/admin/target_nodes/user_data")


@admin_target_nodes_user_data.route(
    "/admin/target_nodes/user_data/delete", methods=["POST"]
)
@login_required
@admin_only
def user_data_template_delete():
    logger.info(
        f"Received following parameters {request.form} to delete target node user template projects"
    )

    _delete_user_data_template = SocaHttpClient(
        endpoint="/api/target_nodes/user_data",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).delete(data=request.form.to_dict())

    if _delete_user_data_template.get("success") is True:
        flash(_(
            f"Your User Data Template has been removed  successfully"),
            "success",
        )
    else:
        flash(_(
            f"Unable to remove your User Data Template because of {_delete_user_data_template.get('message')}"),
            "error",
        )

    return redirect("/admin/target_nodes/user_data")


@admin_target_nodes_user_data.route(
    "/admin/target_nodes/user_data/edit", methods=["POST", "GET"]
)
@login_required
@admin_only
def user_data_template_edit():
    if request.method == "GET":
        return redirect("/admin/target_nodes/user_data")

    logger.info(
        f"Received following parameters {request.form} to edit user data template"
    )
    _template_to_modify = request.form.get("template_id", None)
    if _template_to_modify is None:
        flash(_("Missing template_id"), "error")
        return redirect("/admin/target_nodes/user_data")

    _get_template_info = SocaHttpClient(
        endpoint="/api/target_nodes/user_data",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).get(params={"template_id": request.form.get("template_id")})

    if _get_template_info.get("success") is True:
        return render_template(
            "admin/target_nodes/user_data_edit.html",
            user=session["user"],
            template_info=_get_template_info.get("message").get(_template_to_modify),
            page="admin_target_nodes_user_data",
        )
    else:
        flash(_(
            f"Unable to list SOCA User Data Template because of {_get_template_info.get('message')}"),
            "error",
        )
        return redirect("/admin/target_nodes/user_data")


@admin_target_nodes_user_data.route(
    "/admin/target_nodes/user_data/edit/update", methods=["POST"]
)
@login_required
@admin_only
def user_data_template_update():
    logger.info(f"Received following parameters {request.form} to update projects ")

    _template_to_modify = request.form.get("template_id", None)
    if _template_to_modify is None:
        flash(_("Missing template_id"), "error")
        return redirect("/admin/target_nodes/user_data")

    _modify_user_data_template = SocaHttpClient(
        endpoint="/api/target_nodes/user_data",
        headers={"X-EDH-USER": session["user"], "X-EDH-TOKEN": session["api_key"]},
    ).put(data=request.form.to_dict())

    if _modify_user_data_template.get("success") is True:
        flash(_(
            f"Your user data template has been updated successfully"),
            "success",
        )
    else:
        flash(_(
            f"{_modify_user_data_template.get('message')}"),
            "error",
        )
    return redirect("/admin/target_nodes/user_data")

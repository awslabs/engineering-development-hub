# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from flask import render_template, Blueprint, session
from decorators import login_required, admin_only

logger = logging.getLogger("soca_logger")
admin_virtual_desktops_hardware_profiles = Blueprint(
    "admin_virtual_desktops_hardware_profiles", __name__, template_folder="templates"
)


@admin_virtual_desktops_hardware_profiles.route(
    "/admin/virtual_desktops/hardware_profiles", methods=["GET"]
)
@login_required
@admin_only
def index():
    return render_template(
        "admin/virtual_desktops/hardware_profiles.html",
        user=session["user"],
        page="hardware_profiles",
    )

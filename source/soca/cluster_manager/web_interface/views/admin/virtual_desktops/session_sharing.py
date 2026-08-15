# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from flask import render_template, Blueprint, session
from decorators import login_required, admin_only

logger = logging.getLogger("soca_logger")
admin_virtual_desktops_session_sharing = Blueprint(
    "admin_virtual_desktops_session_sharing", __name__, template_folder="templates"
)


@admin_virtual_desktops_session_sharing.route(
    "/admin/virtual_desktops/session_sharing", methods=["GET"]
)
@login_required
@admin_only
def index():
    return render_template(
        "admin/virtual_desktops/session_sharing.html",
        user=session["user"],
        page="session_sharing",
    )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from flask import render_template, Blueprint, session
from decorators import login_required, admin_only, feature_flag

logger = logging.getLogger("soca_logger")
admin_config_editor = Blueprint(
    "admin_config_editor", __name__, template_folder="templates"
)


@admin_config_editor.route("/admin/config/editor", methods=["GET"])
@login_required
@admin_only
@feature_flag(flag_name="CONFIG_EDITOR", mode="view")
def index():
    return render_template(
        "admin/config/config_editor.html",
        user=session.get("user", "unknown-user"),
        page="config_editor",
    )

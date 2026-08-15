# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from flask import render_template, Blueprint, session
from decorators import login_required, admin_only, feature_flag

logger = logging.getLogger("soca_logger")
admin_token_audit = Blueprint("admin_token_audit", __name__, template_folder="templates")


@admin_token_audit.route("/admin/tokens/audit", methods=["GET"])
@login_required
@admin_only
@feature_flag(flag_name="MY_API_TOKENS", mode="view")
def index():
    return render_template(
        "admin/token_audit.html",
        user=session.get("user", ""),
        page="admin_token_audit",
    )

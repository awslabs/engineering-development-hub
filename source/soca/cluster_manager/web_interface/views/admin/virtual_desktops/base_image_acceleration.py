# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Admin 'Local Acceleration Mirror' page -- owned-base AMI acceleration status.

Renders the cluster-level status panel and serves a session-authed JSON feed the page
fetches client-side (mirrors the software_stacks admin typeahead pattern). The header-authed
/api/dcv/base_image_acceleration/status Resource remains for API callers.
"""

import logging

from flask import Blueprint, render_template, request

from decorators import admin_only, login_required
from helpers.base_image_registry import list_status

logger = logging.getLogger("soca_logger")

admin_base_image_acceleration = Blueprint(
    "base_image_acceleration", __name__, template_folder="templates"
)


@admin_base_image_acceleration.route(
    "/admin/virtual_desktops/base_image_acceleration", methods=["GET"]
)
@login_required
@admin_only
def base_image_acceleration_page():
    return render_template("admin/virtual_desktops/base_image_acceleration.html")


@admin_base_image_acceleration.route(
    "/admin/virtual_desktops/base_image_acceleration/data", methods=["GET"]
)
@login_required
@admin_only
def base_image_acceleration_data():
    """Session-authed JSON feed for the page (browser fetch)."""
    return list_status(region=request.args.get("region")).as_flask()

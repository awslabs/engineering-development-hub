# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from flask import render_template, Blueprint, request, session
from decorators import login_required, admin_only, feature_flag
from models import (
    db,
    GoldenImageNomination,
    SoftwareStackVersion,
    SoftwareStacks,
)

logger = logging.getLogger("soca_logger")
admin_golden_images = Blueprint(
    "golden_images", __name__, template_folder="templates"
)


@admin_golden_images.route("/admin/virtual_desktops/golden_images", methods=["GET"])
@login_required
@admin_only
@feature_flag(flag_name="GOLDEN_IMAGE_PUBLISH", mode="view")
def index():
    # Pending nominations
    _pending = GoldenImageNomination.query.filter_by(
        status="pending"
    ).order_by(GoldenImageNomination.nominated_at.desc()).all()

    # Recent non-pending (last 50)
    _recent = GoldenImageNomination.query.filter(
        GoldenImageNomination.status != "pending"
    ).order_by(GoldenImageNomination.reviewed_at.desc()).limit(50).all()

    # Active software stacks (for the publish target dropdown)
    _stacks = SoftwareStacks.query.filter_by(is_active=True).order_by(
        SoftwareStacks.stack_name
    ).all()

    # Stacks that have version history
    _versioned_stacks = []
    for s in _stacks:
        _versions = SoftwareStackVersion.query.filter_by(
            stack_id=s.id
        ).order_by(SoftwareStackVersion.version.desc()).all()
        if _versions:
            _versioned_stacks.append({
                "stack": s.as_dict(),
                "versions": [v.as_dict() for v in _versions],
            })

    return render_template(
        "admin/virtual_desktops/golden_images.html",
        pending_nominations=_pending,
        recent_nominations=_recent,
        stacks=_stacks,
        versioned_stacks=_versioned_stacks,
        page="golden_images",
    )

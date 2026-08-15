# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Saved Desktop lifecycle -- Recycle bin (D9).

Soft-delete an available saved desktop (available->recycled, AMI + snapshots
kept for a recovery window) and recover it (recycled->available) before the
reaper hard-deregisters it. The state transitions live in
utils.resume_orchestration; the TTL reaper (reap_recycled_images) runs on the
session_state_watcher cycle. Owner-only (admin purge is the D8 admin console).
"""

import logging

from flask_restful import Resource, reqparse
from flask import request

from decorators import private_api, feature_flag
from models import VdiSavedImages
from utils.resume_orchestration import recycle_saved_image, recover_saved_image, saved_desktops_enabled
from utils.error import SocaError

logger = logging.getLogger("soca_logger")


def _saved_desktops_gate():
    """Return a SocaError.as_flask() response when Saved Desktops is disabled,
    else None. Admin gate: FeatureFlags/VirtualDesktops/AllowSavedDesktops."""
    if saved_desktops_enabled().get("message") is not True:
        return SocaError.GENERIC_ERROR(
            helper="Saved Desktops is not enabled on this EDH cluster."
        ).as_flask()
    return None


def _owned_row_or_error(saved_image_id, user):
    """Resolve an active saved-image row owned by the caller, else a SocaError."""
    if not user:
        return None, SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER")
    if not saved_image_id:
        return None, SocaError.CLIENT_MISSING_PARAMETER(parameter="saved_image_id")
    _row = VdiSavedImages.query.filter_by(id=saved_image_id, is_active=True).first()
    if not _row:
        return None, SocaError.GENERIC_ERROR(helper="Saved desktop not found.")
    if _row.owner != user:
        return None, SocaError.GENERIC_ERROR(
            helper="You are not the owner of this saved desktop."
        )
    return _row, None


class RecycleSavedDesktop(Resource):
    """POST -> move an available saved desktop to the recycle bin (soft-delete)."""

    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    @feature_flag(flag_name="SAVED_DESKTOPS", mode="api")
    def post(self):
        _gate = _saved_desktops_gate()
        if _gate:
            return _gate
        parser = reqparse.RequestParser()
        parser.add_argument("saved_image_id", type=int, location="form")
        args = parser.parse_args()
        _user = request.headers.get("X-EDH-USER")
        _row, _err = _owned_row_or_error(args["saved_image_id"], _user)
        if _err:
            return _err.as_flask()
        logger.info(f"Recycle saved desktop id={args['saved_image_id']} by {_user}")
        return recycle_saved_image(args["saved_image_id"]).as_flask()


class RecoverSavedDesktop(Resource):
    """POST -> recover a recycled saved desktop back to available."""

    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    @feature_flag(flag_name="SAVED_DESKTOPS", mode="api")
    def post(self):
        _gate = _saved_desktops_gate()
        if _gate:
            return _gate
        parser = reqparse.RequestParser()
        parser.add_argument("saved_image_id", type=int, location="form")
        args = parser.parse_args()
        _user = request.headers.get("X-EDH-USER")
        _row, _err = _owned_row_or_error(args["saved_image_id"], _user)
        if _err:
            return _err.as_flask()
        logger.info(f"Recover saved desktop id={args['saved_image_id']} by {_user}")
        return recover_saved_image(args["saved_image_id"]).as_flask()

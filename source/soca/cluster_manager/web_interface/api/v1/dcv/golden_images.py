# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
from flask import request, g, session, current_app
import logging
from datetime import datetime, timezone
from decorators import admin_api, private_api, feature_flag
from models import (
    db,
    GoldenImageNomination,
    SoftwareStackVersion,
    SoftwareStacks,
    VdiSavedImages,
)
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.error import SocaError
from utils.validators import Validators
from helpers.golden_image_publish import run_publish_async

logger = logging.getLogger("soca_logger")


def _ff_gate(func):
    """Stack both required feature flags for golden image publish."""

    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    @feature_flag(flag_name="GOLDEN_IMAGE_PUBLISH", mode="api")
    def wrapper(*args, **kwargs):
        return func(*args, **kwargs)

    wrapper.__name__ = func.__name__
    return wrapper


class GoldenImageNominate(Resource):
    """POST /api/dcv/golden-images/nominate — user nominates a saved VDI."""

    @private_api
    @_ff_gate
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("saved_image_id", type=int, location="form", required=True)
        parser.add_argument("label", type=str, location="form", required=True)
        args = parser.parse_args()

        _user = getattr(g, "authenticated_user", None) or session.get("user", "unknown-user")

        _saved_image_id = args["saved_image_id"]
        _label = args["label"]

        if not Validators.is_string_not_empty(_label.strip()):
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="label").as_flask()

        if not Validators.is_string_length_lower_equal_than(_label, 500):
            return SocaError.GENERIC_ERROR(
                helper="Label must be 500 characters or fewer"
            ).as_flask()

        # Verify saved image exists and belongs to the user (or user is admin)
        _saved_image = VdiSavedImages.query.filter_by(
            id=_saved_image_id, is_active=True, state="available"
        ).first()

        if not _saved_image:
            return SocaError.GENERIC_ERROR(
                helper=f"Saved image {_saved_image_id} not found or not available"
            ).as_flask()

        if _saved_image.owner != _user:
            return SocaError.GENERIC_ERROR(
                helper="You can only nominate your own saved desktops"
            ).as_flask()

        # Check for existing pending nomination for this image
        _existing = GoldenImageNomination.query.filter_by(
            saved_image_id=_saved_image_id, status="pending"
        ).first()
        if _existing:
            return SocaError.GENERIC_ERROR(
                helper="This saved image already has a pending nomination"
            ).as_flask()

        _nomination = GoldenImageNomination(
            saved_image_id=_saved_image_id,
            ami_id=_saved_image.image_id,
            nominated_by=_user,
            nominated_at=datetime.now(timezone.utc),
            label=_label.strip(),
            os_family=_saved_image.os_family,
            base_os=_saved_image.base_os,
            arch=None,
            status="pending",
        )

        try:
            db.session.add(_nomination)
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_nomination,
                helper=f"Failed to create nomination: {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=f"Nomination created successfully (id={_nomination.id})",
        ).as_flask()


class GoldenImageNominations(Resource):
    """GET /api/dcv/golden-images/nominations — admin lists nominations."""

    @admin_api
    @_ff_gate
    def get(self):
        parser = reqparse.RequestParser()
        parser.add_argument("status", type=str, location="args")
        args = parser.parse_args()

        _status = args.get("status") or "pending"
        if _status not in ("pending", "approved", "rejected", "published", "all"):
            return SocaError.GENERIC_ERROR(
                helper=f"Invalid status filter: {_status}"
            ).as_flask()

        if _status == "all":
            _nominations = GoldenImageNomination.query.order_by(
                GoldenImageNomination.nominated_at.desc()
            ).all()
        else:
            _nominations = GoldenImageNomination.query.filter_by(
                status=_status
            ).order_by(GoldenImageNomination.nominated_at.desc()).all()

        _result = {}
        for _nom in _nominations:
            _result[_nom.id] = _nom.as_dict()

        return SocaResponse(success=True, message=_result).as_flask()


class GoldenImageApprove(Resource):
    """POST /api/dcv/golden-images/approve — admin approves a nomination."""

    @admin_api
    @_ff_gate
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("nomination_id", type=int, location="form", required=True)
        parser.add_argument("target_stack_id", type=int, location="form")
        parser.add_argument("description", type=str, location="form")
        args = parser.parse_args()

        _user = getattr(g, "authenticated_user", None) or session.get("user", "unknown-user")

        _nomination_id = args["nomination_id"]
        _target_stack_id = args.get("target_stack_id")
        _description = args.get("description") or ""

        _nomination = GoldenImageNomination.query.filter_by(
            id=_nomination_id, status="pending"
        ).first()

        if not _nomination:
            return SocaError.GENERIC_ERROR(
                helper=f"Nomination {_nomination_id} not found or not pending"
            ).as_flask()

        # Publish only targets an existing stack (there is no create-stack-from-name
        # path), so approval requires an existing target_stack_id.
        if not _target_stack_id:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="target_stack_id"
            ).as_flask()

        _stack = SoftwareStacks.query.filter_by(
            id=_target_stack_id, is_active=True
        ).first()
        if not _stack:
            return SocaError.GENERIC_ERROR(
                helper=f"Stack {_target_stack_id} not found or inactive"
            ).as_flask()

        # Mark nomination as approved
        _nomination.status = "approved"
        _nomination.reviewed_by = _user
        _nomination.reviewed_at = datetime.now(timezone.utc)
        _nomination.target_stack_id = _target_stack_id
        _nomination.target_stack_name = _stack.stack_name

        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_nomination,
                helper=f"Failed to approve nomination: {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=f"Nomination {_nomination_id} approved. Ready for publish.",
        ).as_flask()


class GoldenImageReject(Resource):
    """POST /api/dcv/golden-images/reject — admin rejects a nomination."""

    @admin_api
    @_ff_gate
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("nomination_id", type=int, location="form", required=True)
        parser.add_argument("rejection_note", type=str, location="form")
        args = parser.parse_args()

        _user = getattr(g, "authenticated_user", None) or session.get("user", "unknown-user")

        _nomination_id = args["nomination_id"]
        _rejection_note = args.get("rejection_note") or ""

        _nomination = GoldenImageNomination.query.filter_by(
            id=_nomination_id, status="pending"
        ).first()

        if not _nomination:
            return SocaError.GENERIC_ERROR(
                helper=f"Nomination {_nomination_id} not found or not pending"
            ).as_flask()

        _nomination.status = "rejected"
        _nomination.reviewed_by = _user
        _nomination.reviewed_at = datetime.now(timezone.utc)
        _nomination.rejection_note = _rejection_note[:500] if _rejection_note else ""

        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_nomination,
                helper=f"Failed to reject nomination: {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=f"Nomination {_nomination_id} rejected.",
        ).as_flask()


class GoldenImagePublish(Resource):
    """POST /api/dcv/golden-images/publish — admin publishes (direct or from nomination)."""

    @admin_api
    @_ff_gate
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument("nomination_id", type=int, location="form")
        parser.add_argument("saved_image_id", type=int, location="form")
        parser.add_argument("target_stack_id", type=int, location="form", required=True)
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("skip_sysprep", type=str, location="form")
        args = parser.parse_args()

        _user = getattr(g, "authenticated_user", None) or session.get("user", "unknown-user")

        _nomination_id = args.get("nomination_id")
        _saved_image_id = args.get("saved_image_id")
        _target_stack_id = args["target_stack_id"]
        _description = args.get("description") or ""
        _skip_sysprep = (args.get("skip_sysprep") or "").lower() == "true"

        # Must specify either nomination_id or saved_image_id
        if not _nomination_id and not _saved_image_id:
            return SocaError.GENERIC_ERROR(
                helper="Must specify nomination_id or saved_image_id"
            ).as_flask()

        # Resolve the AMI
        if _nomination_id:
            _nomination = GoldenImageNomination.query.filter_by(
                id=_nomination_id, status="approved"
            ).first()
            if not _nomination:
                return SocaError.GENERIC_ERROR(
                    helper=f"Nomination {_nomination_id} not found or not approved"
                ).as_flask()
            _ami_id = _nomination.ami_id
            _os_family = _nomination.os_family
        else:
            _saved_image = VdiSavedImages.query.filter_by(
                id=_saved_image_id, is_active=True, state="available"
            ).first()
            if not _saved_image:
                return SocaError.GENERIC_ERROR(
                    helper=f"Saved image {_saved_image_id} not found or not available"
                ).as_flask()
            _ami_id = _saved_image.image_id
            _os_family = _saved_image.os_family
            _nomination = None

        # Verify target stack
        _stack = SoftwareStacks.query.filter_by(
            id=_target_stack_id, is_active=True
        ).first()
        if not _stack:
            return SocaError.GENERIC_ERROR(
                helper=f"Stack {_target_stack_id} not found or inactive"
            ).as_flask()

        # Determine next version number
        _latest_version = SoftwareStackVersion.query.filter_by(
            stack_id=_target_stack_id
        ).order_by(SoftwareStackVersion.version.desc()).first()
        _next_version = (_latest_version.version + 1) if _latest_version else 1

        # Record prior AMI
        _prior_ami_id = _stack.ami_id

        # Mark nomination as publishing (in-progress) so the queue reflects state
        if _nomination:
            _nomination.status = "publishing"
            _nomination.reviewed_by = _user
            _nomination.reviewed_at = datetime.now(timezone.utc)
            _nomination.target_stack_id = _target_stack_id

        # Create a PENDING version row synchronously (not active; stack NOT
        # flipped yet). The slow sysprep flow + activation runs in a background
        # worker so the HTTP request returns immediately (no ALB 504).
        _version_record = SoftwareStackVersion(
            stack_id=_target_stack_id,
            version=_next_version,
            ami_id=_ami_id,
            source_ami_id=_ami_id,
            published_by=_user,
            published_at=datetime.now(timezone.utc),
            description=_description[:500] if _description else "",
            nomination_id=_nomination_id,
            sysprep_status="pending",
            lineage_status="not_needed",
            validation_status="skipped",
            is_active=False,
            prior_ami_id=_prior_ami_id,
        )

        try:
            db.session.add(_version_record)
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_version_record,
                helper=f"Failed to create publish version: {err}",
            ).as_flask()

        # Kick off the background publish worker (sysprep -> activate -> lineage
        # -> validation). Capture the real app object for the thread's context.
        _app = current_app._get_current_object()
        run_publish_async(
            app=_app,
            stack_id=_target_stack_id,
            version_id=_version_record.id,
            nomination_id=_nomination_id,
            source_ami_id=_ami_id,
            os_family=_os_family,
            skip_sysprep=_skip_sysprep,
            user=_user,
        )

        return SocaResponse(
            success=True,
            message=(
                f"Publish started for '{_stack.stack_name}' as v{_next_version}. "
                f"Sysprep is running in the background; the version becomes active "
                f"when it completes. Track status on the Published Stacks tab."
            ),
        ).as_flask()


class GoldenImageRollback(Resource):
    """POST /api/dcv/golden-images/<stack_id>/rollback — admin reverts to a prior version."""

    @admin_api
    @_ff_gate
    def post(self, stack_id):
        parser = reqparse.RequestParser()
        parser.add_argument("target_version", type=int, location="form", required=True)
        args = parser.parse_args()

        _user = getattr(g, "authenticated_user", None) or session.get("user", "unknown-user")

        _target_version = args["target_version"]

        _stack = SoftwareStacks.query.filter_by(
            id=stack_id, is_active=True
        ).first()
        if not _stack:
            return SocaError.GENERIC_ERROR(
                helper=f"Stack {stack_id} not found or inactive"
            ).as_flask()

        _version_record = SoftwareStackVersion.query.filter_by(
            stack_id=stack_id, version=_target_version
        ).first()
        if not _version_record:
            return SocaError.GENERIC_ERROR(
                helper=f"Version {_target_version} not found for stack {stack_id}"
            ).as_flask()

        # Only roll back to a version that completed a successful publish. A row is
        # created PENDING/inactive (ami_id=source, un-sysprepped) and activated by
        # the background worker; rolling back to a pending/failed one would point the
        # stack at a broken or non-sysprepped AMI.
        if (
            _version_record.sysprep_status in ("pending", "failed")
            or _version_record.validation_status in ("pending", "failed")
            or _version_record.lineage_status in ("copying", "copy_failed")
            or _version_record.failure_reason
        ):
            return SocaError.GENERIC_ERROR(
                helper=(
                    f"Version {_target_version} did not complete a successful publish "
                    f"(sysprep={_version_record.sysprep_status}, "
                    f"validation={_version_record.validation_status}, "
                    f"lineage={_version_record.lineage_status}); cannot roll back to it"
                )
            ).as_flask()

        # Update the stack's active AMI to the rollback target
        _stack.ami_id = _version_record.ami_id
        _stack.last_updated_on = datetime.now(timezone.utc)
        _stack.last_updated_by = _user

        # Mark the rollback version as the new active
        # (deactivate the current active, activate the target)
        SoftwareStackVersion.query.filter_by(
            stack_id=stack_id, is_active=True
        ).update({"is_active": False})
        _version_record.is_active = True

        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_version_record,
                helper=f"Failed to rollback: {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=f"Stack '{_stack.stack_name}' rolled back to v{_target_version}",
        ).as_flask()


class GoldenImageVersions(Resource):
    """GET /api/dcv/golden-images/<stack_id>/versions — version history."""

    @admin_api
    @_ff_gate
    def get(self, stack_id):
        _stack = SoftwareStacks.query.filter_by(
            id=stack_id, is_active=True
        ).first()
        if not _stack:
            return SocaError.GENERIC_ERROR(
                helper=f"Stack {stack_id} not found or inactive"
            ).as_flask()

        _versions = SoftwareStackVersion.query.filter_by(
            stack_id=stack_id
        ).order_by(SoftwareStackVersion.version.desc()).all()

        _result = {}
        for _v in _versions:
            _result[_v.version] = _v.as_dict()

        return SocaResponse(success=True, message=_result).as_flask()

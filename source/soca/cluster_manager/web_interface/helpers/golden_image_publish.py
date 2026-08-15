# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Golden Image Publish — async orchestrator.

The publish endpoint creates a PENDING SoftwareStackVersion row synchronously
and returns immediately. This module runs the slow work (sysprep verify/auto-
sysprep, then stack activation, lineage copy, and validation) in a background
daemon thread so the HTTP request never blocks on the multi-minute sysprep
flow (which would otherwise 504 at the ALB).

State model on the version row (no schema migration needed -- all free strings):
  sysprep_status: pending -> verified_clean | auto_sysprepped | skipped_linux
                  | skipped_dedicated | failed
  is_active: False while pending; flipped True only on success (which also
             deactivates the prior active version and repoints the stack).
Nomination status: publishing (set by endpoint) -> published (success) or
                   back to approved (failure, so an admin can retry).
"""

import logging
import threading
from datetime import datetime, timezone

from models import db, SoftwareStackVersion, SoftwareStacks, GoldenImageNomination
from utils.response import SocaResponse
from helpers.golden_image_sysprep import verify_and_sysprep
from helpers.golden_image_lineage import trigger_lineage_copy
from helpers.golden_image_validation import trigger_validation

logger = logging.getLogger("soca_logger")


def run_publish_async(
    app,
    stack_id: int,
    version_id: int,
    nomination_id,
    source_ami_id: str,
    os_family: str,
    skip_sysprep: bool,
    user: str,
) -> SocaResponse:
    """Spawn the background publish worker. `app` is the real Flask app object
    captured in the request context so the thread can push its own app_context."""
    _thread = threading.Thread(
        target=_publish_worker,
        args=(app, stack_id, version_id, nomination_id, source_ami_id, os_family, skip_sysprep, user),
        daemon=True,
        name=f"golden-publish-{stack_id}-v{version_id}",
    )
    _thread.start()
    logger.info(
        f"Golden publish: background worker started for stack {stack_id} "
        f"version_id {version_id} (source_ami={source_ami_id})"
    )
    # Programmatic dispatch ack -- consumed in-process, never an HTTP response (no .as_flask()).
    return SocaResponse(
        success=True,
        message=f"Golden publish worker started for stack {stack_id} version {version_id}",
    )


def _publish_worker(app, stack_id, version_id, nomination_id, source_ami_id,
                    os_family, skip_sysprep, user) -> None:
    with app.app_context():
        try:
            # 1. Sysprep (slow for Windows auto-sysprep)
            if os_family == "linux":
                _status, _publish_ami = "skipped_linux", source_ami_id
            elif skip_sysprep:
                _status, _publish_ami = "skipped_dedicated", source_ami_id
            else:
                _res = verify_and_sysprep(source_ami_id, os_family)
                if not _res.get("success"):
                    _detail = (_res.get("message") or {}).get("detail", "sysprep failed")
                    _mark_failed(stack_id, version_id, nomination_id, _detail)
                    return
                _sysprep = _res.get("message") or {}
                _status, _publish_ami = _sysprep.get("status"), _sysprep.get("ami_id")

            # 2. Activate: update version, flip stack, retire prior active version
            _version = SoftwareStackVersion.query.filter_by(id=version_id).first()
            _stack = SoftwareStacks.query.filter_by(id=stack_id, is_active=True).first()
            if not _version or not _stack:
                logger.error(
                    f"Golden publish: version {version_id} or stack {stack_id} vanished"
                )
                return

            SoftwareStackVersion.query.filter_by(
                stack_id=stack_id, is_active=True
            ).update({"is_active": False})

            _version.ami_id = _publish_ami
            _version.sysprep_status = _status
            _version.is_active = True

            _stack.ami_id = _publish_ami
            _stack.last_updated_on = datetime.now(timezone.utc)
            _stack.last_updated_by = user

            if nomination_id:
                _nom = GoldenImageNomination.query.filter_by(id=nomination_id).first()
                if _nom:
                    _nom.status = "published"
                    _nom.target_stack_id = stack_id

            db.session.commit()
            logger.info(
                f"Golden publish: stack {stack_id} activated version {version_id} "
                f"(ami={_publish_ami}, sysprep={_status})"
            )

            # 3. Background lineage copy + optional validation (own threads)
            try:
                trigger_lineage_copy(app, stack_id, version_id, _publish_ami, source_ami_id)
            except Exception as _le:
                logger.warning(f"Golden publish: lineage trigger failed (non-fatal): {_le}")
            try:
                trigger_validation(app, stack_id, version_id, _publish_ami, os_family)
            except Exception as _ve:
                logger.warning(f"Golden publish: validation trigger failed (non-fatal): {_ve}")

        except Exception as err:
            db.session.rollback()
            logger.error(f"Golden publish: worker failed for version {version_id}: {err}")
            _mark_failed(stack_id, version_id, nomination_id, str(err))


def _mark_failed(stack_id, version_id, nomination_id, message) -> None:
    """Stamp the version failed and revert the nomination to approved for retry.
    Leaves the stack's active AMI untouched (never activated on failure)."""
    try:
        _version = SoftwareStackVersion.query.filter_by(id=version_id).first()
        if _version:
            _version.sysprep_status = "failed"
            _version.is_active = False
            _version.failure_reason = str(message)[:1000]
        if nomination_id:
            _nom = GoldenImageNomination.query.filter_by(id=nomination_id).first()
            if _nom:
                _nom.status = "approved"
        db.session.commit()
        logger.error(
            f"Golden publish: version {version_id} marked failed for stack {stack_id}: {message}"
        )
    except Exception as err:
        db.session.rollback()
        logger.error(f"Golden publish: failed to mark version {version_id} failed: {err}")

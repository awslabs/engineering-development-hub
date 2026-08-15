# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resume-From (Saved Desktops) orchestration -- single-use invariant.

A saved image carries a UNIQUE specialized AD identity (computer name + SID +
machine secret), so it must be resumed AT MOST ONCE and exist in at most one
live form at any moment. Resume is therefore a MOVE, not a COPY:

    capturing -> available -> resuming -> consumed

- acquire_resume_lease: atomic compare-and-set available->resuming. Exactly one
  caller wins; a concurrent or repeat resume of the same image loses and is
  rejected. This is the enforcement point for the single-use invariant.
- revert_resume_lease: resuming->available on launch failure, so the image is
  not lost and the user can retry.
- consume_on_success: on a CONFIRMED-HEALTHY resume, deregister the source AMI
  immediately (the un-relaunchable guard; the running instance is already
  decoupled from the AMI) and set state=consumed. Snapshot deletion is DEFERRED
  to the reaper (P5) for EBS lazy-load safety, so the backing snapshot ids are
  returned for the caller/reaper to reclaim later.
"""

import logging
from datetime import datetime, timezone, timedelta

import utils.aws.boto3_wrapper as utils_boto3
from models import db, VdiSavedImages
from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.validators import Validators

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def acquire_resume_lease(saved_image_id: int) -> SocaResponse:
    """
    Atomically transition a saved image available->resuming. Returns
    SocaResponse(success=True) to the single winner; SocaError otherwise
    (already resuming/consumed/absent, or a concurrent resume lost the race).
    """
    try:
        _updated = (
            VdiSavedImages.query.filter_by(
                id=saved_image_id, state="available", is_active=True
            ).update({"state": "resuming"}, synchronize_session=False)
        )
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            query="vdi_saved_images CAS available->resuming", helper=f"{err}"
        )

    if _updated == 1:
        logger.info(f"Resume lease acquired for saved image id={saved_image_id}")
        return SocaResponse(success=True, message=saved_image_id)

    logger.warning(
        f"Resume lease DENIED for saved image id={saved_image_id} "
        f"(not in 'available' state -- already resuming/consumed, or concurrent resume won)"
    )
    return SocaError.GENERIC_ERROR(
        helper="This saved desktop is not available to resume (it may already be resuming or was consumed)."
    )


def revert_resume_lease(saved_image_id: int) -> SocaResponse:
    """resuming->available, so a failed launch does not lose the image."""
    try:
        VdiSavedImages.query.filter_by(
            id=saved_image_id, state="resuming"
        ).update({"state": "available"}, synchronize_session=False)
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            query="vdi_saved_images revert resuming->available", helper=f"{err}"
        )
    logger.info(f"Resume lease reverted to available for saved image id={saved_image_id}")
    return SocaResponse(success=True, message=saved_image_id)


def promote_ready_captures() -> SocaResponse:
    """
    Flip saved-image rows from 'capturing' to 'available' once their AMI reaches
    the 'available' state (and record the root size). Marks 'error' on a failed
    AMI. Called each watcher cycle so the Resume button appears when a capture
    finishes. Idempotent (only touches 'capturing' rows).
    """
    _rows = VdiSavedImages.query.filter_by(state="capturing", is_active=True).all()
    if not _rows:
        return SocaResponse(success=True, message=0)
    _changed = 0
    for _r in _rows:
        try:
            _imgs = client_ec2.describe_images(ImageIds=[_r.image_id]).get("Images", [])
        except Exception as err:
            logger.warning(f"promote_ready_captures: describe {_r.image_id} failed: {err}")
            continue
        if not _imgs:
            continue
        _state = _imgs[0].get("State")
        if _state == "available":
            _bytes = 0
            for _bdm in _imgs[0].get("BlockDeviceMappings", []):
                _ebs = _bdm.get("Ebs") or {}
                _vs = SocaCastEngine(_ebs.get("VolumeSize", 0)).cast_as(expected_type=int)
                if _vs.get("success") and _vs.get("message"):
                    _bytes += _vs.get("message") * 1073741824
            _r.state = "available"
            if _bytes:
                _r.root_bytes = _bytes
            _changed += 1
        elif _state in ("failed", "error", "invalid"):
            _r.state = "error"
            _changed += 1
    if _changed:
        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(query="vdi_saved_images promote captures", helper=f"{err}")
    return SocaResponse(success=True, message=_changed)


# Stop-then-image capture: how long a 'pending_capture' row may wait for its
# instance to reach 'stopped' before we give up and surface the tile as failed.
# A clean Windows stop is normally 1-3 min; this is a generous backstop so a box
# that never stops (hung shutdown) does not leave the tile "working" forever.
PENDING_CAPTURE_STOP_TIMEOUT_MIN = 20


def _saved_image_capture_tags(row) -> list:
    """Cluster + owner + custom tags for a saved-image CreateImage, applied AT
    CREATE TIME to the image AND its backing snapshots so tag-on-create SCPs
    (e.g. a required edh:ClusterId) are satisfied and the resources are
    attributable/cleanable. Mirrors the tag set the request handler used before
    the capture was deferred to this reconciler."""
    from utils.config import SocaConfig

    _cid = SocaConfig(key="/configuration/ClusterId").get_value()
    _cluster_id = _cid.get("message") if _cid.get("success") is True else ""
    _tags = [
        {"Key": "Name", "Value": (row.image_id or f"edh-savedvdi-{row.origin_session_uuid}")},
        {"Key": "edh:ClusterId", "Value": _cluster_id},
        {"Key": "edh:SavedVdiOwner", "Value": row.owner},
        {"Key": "edh:OriginSessionUuid", "Value": row.origin_session_uuid},
        {"Key": "edh:SavedVdiName", "Value": row.session_name},
    ]
    _tags_allowed = SocaConfig(
        key="/configuration/FeatureFlags/VirtualDesktops/AllowCustomTags"
    ).get_value(return_as=bool)
    if _tags_allowed.get("success") is True and _tags_allowed.get("message") is True:
        _get_tags = SocaConfig(key="/configuration/CustomTags/").get_value(allow_unknown_key=True)
        if _get_tags.get("success") is True:
            _cast = SocaCastEngine(data=_get_tags.get("message")).autocast(preserve_key_name=True)
            if _cast.get("success") is True:
                _existing = {t["Key"] for t in _tags}
                for _ct in (_cast.get("message") or {}).values():
                    if _ct.get("Enabled", "") and _ct.get("Key") and _ct["Key"] not in _existing:
                        _tags.append({"Key": _ct["Key"], "Value": _ct.get("Value", "")})
                        _existing.add(_ct["Key"])
    return _tags


def create_images_for_stopped_captures() -> SocaResponse:
    """
    Deferred half of the stop-then-image Save & Shut Down capture.

    The request handler gracefully STOPS the origin instance and inserts a
    'pending_capture' row (no AMI yet). This reconciler -- run each watcher
    cycle, so it is SIGHUP-safe (unlike an in-worker thread) -- watches those
    rows and, once EC2 reports the box 'stopped', runs CreateImage on the
    STOPPED instance (a clean, consistent snapshot), stamps image_id, flips the
    row to 'capturing' (promote_ready_captures then drives capturing->available),
    and terminates the now-imaged instance.

    Per-row outcomes by instance state:
      stopped                 -> CreateImage -> state='capturing' -> terminate
      pending/running/stopping-> wait (until PENDING_CAPTURE_STOP_TIMEOUT_MIN)
      terminated / gone       -> state='error' (box died before it could be imaged)
      timed out (never stops) -> state='error'

    Idempotent (only touches 'pending_capture' rows); best-effort per row.

    Returns a SocaResponse consumed programmatically by the session-state
    watcher (a scheduled task), not returned as an HTTP response -- so the
    SocaResponse/SocaError returns here are intentionally NOT wrapped with
    .as_flask().
    """
    from botocore.exceptions import ClientError

    _rows = VdiSavedImages.query.filter_by(state="pending_capture", is_active=True).all()
    if not _rows:
        return SocaResponse(success=True, message=0)

    _now = datetime.now(timezone.utc)
    _changed = 0
    for _r in _rows:
        _iid = _r.capture_instance_id
        if not _iid:
            logger.warning(
                f"create_images_for_stopped_captures: row id={_r.id} has no "
                f"capture_instance_id; marking error"
            )
            _r.state = "error"
            _changed += 1
            continue

        # Resolve the instance's current run state.
        _state = None
        try:
            _resv = client_ec2.describe_instances(InstanceIds=[_iid]).get("Reservations", [])
            for _res in _resv:
                for _inst in _res.get("Instances", []):
                    _state = (_inst.get("State") or {}).get("Name")
        except ClientError as err:
            if err.response.get("Error", {}).get("Code") == "InvalidInstanceID.NotFound":
                logger.warning(
                    f"create_images_for_stopped_captures: instance {_iid} gone before "
                    f"capture (row id={_r.id}); marking error"
                )
                _r.state = "error"
                _changed += 1
                continue
            logger.warning(
                f"create_images_for_stopped_captures: describe {_iid} failed: {err}"
            )
            continue
        except Exception as err:
            logger.warning(
                f"create_images_for_stopped_captures: describe {_iid} failed: {err}"
            )
            continue

        if _state is None or _state == "terminated":
            logger.warning(
                f"create_images_for_stopped_captures: instance {_iid} is {_state!r} "
                f"(row id={_r.id}); marking error"
            )
            _r.state = "error"
            _changed += 1
            continue

        if _state != "stopped":
            # Still stopping/running/pending: wait, unless we have blown the backstop.
            _created = _r.created_on
            if _created is not None and _created.tzinfo is None:
                _created = _created.replace(tzinfo=timezone.utc)
            if _created is not None and (_now - _created) > timedelta(
                minutes=PENDING_CAPTURE_STOP_TIMEOUT_MIN
            ):
                logger.warning(
                    f"create_images_for_stopped_captures: instance {_iid} still {_state!r} "
                    f">{PENDING_CAPTURE_STOP_TIMEOUT_MIN}min after Save (row id={_r.id}); "
                    f"marking error (hung shutdown)"
                )
                _r.state = "error"
                _changed += 1
            continue

        # Instance is 'stopped' -> clean CreateImage on the stopped box.
        _ts_cast = SocaCastEngine(_now.timestamp()).cast_as(expected_type=int)
        _epoch = _ts_cast.get("message") if _ts_cast.get("success") is True else 0
        _name = f"edh-savedvdi-{_r.origin_session_uuid}-{_epoch}"
        try:
            _tags = _saved_image_capture_tags(_r)
            # Ensure the Name tag reflects the image name (not the null image_id).
            for _t in _tags:
                if _t.get("Key") == "Name":
                    _t["Value"] = _name
            _img = client_ec2.create_image(
                InstanceId=_iid,
                Name=_name,
                NoReboot=True,  # box is already stopped; never touch its power state
                Description=f"EDH Save & Shut Down of {_r.session_name} ({_r.owner})",
                TagSpecifications=[
                    {"ResourceType": "image", "Tags": _tags},
                    {"ResourceType": "snapshot", "Tags": _tags},
                ],
            )
            _r.image_id = _img["ImageId"]
            _r.state = "capturing"
            _changed += 1
            logger.info(
                f"create_images_for_stopped_captures: imaged stopped instance {_iid} "
                f"-> {_r.image_id} (row id={_r.id}); state pending_capture->capturing"
            )
        except Exception as err:
            logger.warning(
                f"create_images_for_stopped_captures: CreateImage failed for {_iid} "
                f"(row id={_r.id}): {err}; will retry next cycle"
            )
            continue

        # Durably record the image_id/capturing transition BEFORE terminating the
        # box. If we terminate first and the process dies before the end-of-loop
        # commit, the freshly-created AMI is orphaned (never referenced/reaped) and
        # the row is wrongly marked 'error' on the next cycle.
        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            logger.warning(
                f"create_images_for_stopped_captures: commit of image_id for "
                f"{_iid} (row id={_r.id}) failed: {err}; will retry next cycle"
            )
            continue

        # Image is registering; the box is no longer needed. Terminate it (its CFN
        # stack is now unprotected -- state left pending_capture -- and the orphan-
        # stack reaper cleans the stack).
        try:
            client_ec2.terminate_instances(InstanceIds=[_iid])
        except Exception as err:
            logger.warning(
                f"create_images_for_stopped_captures: terminate {_iid} failed after "
                f"imaging (row id={_r.id}): {err}; orphan-stack reaper will reclaim it"
            )

    if _changed:
        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query="vdi_saved_images stopped-capture reconcile", helper=f"{err}"
            )
    return SocaResponse(success=True, message=_changed)


def consume_on_success(saved_image_id: int) -> SocaResponse:
    """
    Consume a saved image after a confirmed-healthy resume: capture backing
    snapshot ids, deregister the AMI (single-use guard -- running instance is
    unaffected), set state=consumed. Snapshot deletion is DEFERRED to the reaper
    (P5); the snapshot ids are returned in the response message for reclamation.
    """
    _row = VdiSavedImages.query.filter_by(id=saved_image_id).first()
    if not _row:
        return SocaError.GENERIC_ERROR(helper=f"Saved image id={saved_image_id} not found")

    _snapshot_ids = []
    try:
        _desc = client_ec2.describe_images(ImageIds=[_row.image_id])
        for _img in _desc.get("Images", []):
            for _bdm in _img.get("BlockDeviceMappings", []):
                _ebs = _bdm.get("Ebs") or {}
                if _ebs.get("SnapshotId"):
                    _snapshot_ids.append(_ebs["SnapshotId"])
    except Exception as err:
        # Non-fatal: without snapshot ids the reaper can still reclaim by AMI-less
        # orphan sweep later; proceed to deregister so the single-use guard holds.
        logger.warning(
            f"consume_on_success: could not enumerate snapshots for {_row.image_id}: {err}"
        )

    try:
        client_ec2.deregister_image(ImageId=_row.image_id)
    except Exception as err:
        # Best-effort: a failed deregister (missing ec2:DeregisterImage,
        # already-deregistered, etc.) must NOT strand the saved image in
        # 'resuming' forever. Log and proceed to consumed; the recycle bin /
        # reaper reclaims the AMI + snapshots later. Mirrors the non-fatal
        # snapshot-enumeration handling above.
        logger.warning(
            f"consume_on_success: deregister_image failed for {_row.image_id} "
            f"(proceeding to consumed anyway): {err}"
        )

    try:
        _row.state = "consumed"
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            query="vdi_saved_images set consumed", helper=f"{err}"
        )

    logger.info(
        f"Consumed saved image id={saved_image_id} ({_row.image_id}); "
        f"deregistered AMI; deferred snapshots for reaper: {_snapshot_ids}"
    )
    return SocaResponse(success=True, message={"image_id": _row.image_id, "snapshot_ids": _snapshot_ids})


# ---------------------------------------------------------------------------
# Recycle bin (D9): soft-delete with a recovery window.
#
# A delete (manual OR auto-clean) flips available->recycled and keeps the AMI +
# snapshots. The reaper hard-deregisters only after RECYCLE_TTL_DAYS; recover
# flips recycled->available inside the window. An AMI is irreplaceable once
# deregistered (the source instance is gone), so the window makes deletes
# reversible and lets aggressive auto-clean be safe.
# ---------------------------------------------------------------------------
RECYCLE_TTL_CONFIG_KEY = "/configuration/FeatureFlags/VirtualDesktops/SavedImageRecycleTTLDays"
DEFAULT_RECYCLE_TTL_DAYS = 14


def recycle_ttl_days() -> int:
    """Admin-configurable recovery window (days) before a recycled saved image
    is hard-deleted. Reads the config key with a default; unknown-key safe."""
    from utils.config import SocaConfig
    from utils.cast import SocaCastEngine
    _r = SocaConfig(key=RECYCLE_TTL_CONFIG_KEY).get_value(
        default=str(DEFAULT_RECYCLE_TTL_DAYS), allow_unknown_key=True
    )
    _c = SocaCastEngine(_r.get("message", DEFAULT_RECYCLE_TTL_DAYS)).cast_as(expected_type=int)
    return _c.get("message") if _c.get("success") else DEFAULT_RECYCLE_TTL_DAYS


def saved_desktops_enabled() -> SocaResponse:
    """Capability gate for the entire Saved Desktops feature (Save & Shut Down,
    resume, recycle bin, Spot ITN auto-capture), returned as
    SocaResponse(success=True, message=<bool>). Backed by the SAVED_DESKTOPS
    feature flag's `enabled` field (code default True, per-cluster overridable
    via the /configuration/FeatureFlags/SAVED_DESKTOPS/Enabled SSM overlay).

    This retires the legacy /configuration/FeatureFlags/VirtualDesktops/
    AllowSavedDesktops knob: SAVED_DESKTOPS.enabled is now the single source of
    truth for the capability. WHO may use it (allowed_groups) is enforced
    separately by the @feature_flag('SAVED_DESKTOPS') decorator on the
    user-facing endpoints. Consumed in-process (callers unwrap .get("message")),
    never returned as an HTTP response."""
    import feature_flags
    _ff = feature_flags.get_flag("SAVED_DESKTOPS")
    if _ff.get("success") is not True:
        return SocaResponse(success=True, message=False)
    _flag = _ff.get("message")
    if not Validators.is_dict(_flag):
        return SocaResponse(success=True, message=False)
    return SocaResponse(success=True, message=_flag.get("enabled", False) is True)


def recycle_saved_image(saved_image_id: int) -> SocaResponse:
    """Soft-delete: CAS available->recycled, stamp deleted_on. Only an
    'available' image can be recycled (never capturing/resuming/consumed)."""
    try:
        _updated = VdiSavedImages.query.filter_by(
            id=saved_image_id, state="available", is_active=True
        ).update(
            {"state": "recycled", "deleted_on": datetime.now(timezone.utc)},
            synchronize_session=False,
        )
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            query="vdi_saved_images available->recycled", helper=f"{err}"
        )
    if _updated == 1:
        logger.info(f"Saved image id={saved_image_id} recycled (soft-delete)")
        return SocaResponse(success=True, message=saved_image_id)
    return SocaError.GENERIC_ERROR(
        helper="This saved desktop cannot be deleted right now (only an available desktop can be moved to the recycle bin)."
    )


def recover_saved_image(saved_image_id: int) -> SocaResponse:
    """Recover a recycled image back to available, if still inside the recovery
    window (the reaper has not hard-deregistered it yet)."""
    _row = VdiSavedImages.query.filter_by(
        id=saved_image_id, state="recycled", is_active=True
    ).first()
    if not _row:
        return SocaError.GENERIC_ERROR(
            helper="This saved desktop is not in the recycle bin (it may have been permanently removed)."
        )
    try:
        _row.state = "available"
        _row.deleted_on = None
        db.session.commit()
    except Exception as err:
        db.session.rollback()
        return SocaError.DB_ERROR(
            query="vdi_saved_images recycled->available", helper=f"{err}"
        )
    logger.info(f"Saved image id={saved_image_id} recovered from recycle bin")
    return SocaResponse(success=True, message=saved_image_id)


def reap_recycled_images() -> SocaResponse:
    """Hard-delete recycled images past the recovery TTL: deregister the AMI +
    delete backing snapshots, then set is_active=False so the row drops out.
    Best-effort per row; called each watcher cycle; idempotent (an already
    deactivated row is not re-selected)."""
    _ttl = recycle_ttl_days()
    _cutoff = datetime.now(timezone.utc) - timedelta(days=_ttl)
    _rows = VdiSavedImages.query.filter_by(state="recycled", is_active=True).all()
    _reaped = 0
    for _r in _rows:
        _del = _r.deleted_on
        if _del is None:
            continue
        if _del.tzinfo is None:  # DB timestamps come back naive; treat as UTC
            _del = _del.replace(tzinfo=timezone.utc)
        if _del > _cutoff:
            continue  # still inside the recovery window

        _snap_ids = []
        try:
            for _img in client_ec2.describe_images(ImageIds=[_r.image_id]).get("Images", []):
                for _bdm in _img.get("BlockDeviceMappings", []):
                    _ebs = _bdm.get("Ebs") or {}
                    if _ebs.get("SnapshotId"):
                        _snap_ids.append(_ebs["SnapshotId"])
            client_ec2.deregister_image(ImageId=_r.image_id)
        except Exception as err:
            logger.warning(
                f"reap_recycled_images: deregister {_r.image_id} failed (may already be gone): {err}"
            )
        for _sid in _snap_ids:
            try:
                client_ec2.delete_snapshot(SnapshotId=_sid)
            except Exception as err:
                logger.warning(f"reap_recycled_images: delete snapshot {_sid} failed: {err}")
        try:
            _r.is_active = False
            db.session.commit()
            _reaped += 1
            logger.info(
                f"reap_recycled_images: hard-deleted saved image id={_r.id} ({_r.image_id}) past {_ttl}d TTL"
            )
        except Exception as err:
            db.session.rollback()
            logger.warning(f"reap_recycled_images: row deactivate failed for id={_r.id}: {err}")
    return SocaResponse(success=True, message=_reaped)

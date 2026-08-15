# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
from flask import request
import logging
import time
from datetime import datetime, timezone
from decorators import private_api, feature_flag
from models import db, VirtualDesktopSessions, VdiSavedImages
import utils.aws.boto3_wrapper as utils_boto3
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.error import SocaError
from utils.resume_orchestration import saved_desktops_enabled

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class SaveAndShutdown(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    @feature_flag(flag_name="SAVED_DESKTOPS", mode="api")
    def put(self):
        if saved_desktops_enabled().get("message") is not True:
            return SocaError.GENERIC_ERROR(
                helper="Saved Desktops is not enabled on this EDH cluster."
            ).as_flask()
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="form")
        args = parser.parse_args()

        _user = request.headers.get("X-EDH-USER")
        _session_uuid = args["session_uuid"]
        if not _user:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()
        if not _session_uuid:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="session_uuid").as_flask()

        _sess = VirtualDesktopSessions.query.filter_by(
            session_owner=_user, session_uuid=_session_uuid, is_active=True
        ).first()
        if not _sess:
            return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                session_number=_session_uuid, session_owner=_user,
                helper="Unable to find this desktop.",
            ).as_flask()

        _iid = _sess.instance_id
        if not _iid:
            return SocaError.GENERIC_ERROR(
                helper="This desktop has no instance to capture yet."
            ).as_flask()

        # Root storage footprint (all attached EBS volumes) for the tile + storage quota.
        _root_bytes = 0
        try:
            _vols = client_ec2.describe_volumes(
                Filters=[{"Name": "attachment.instance-id", "Values": [_iid]}]
            )
            _root_gib = 0
            for v in _vols.get("Volumes", []):
                _sz = SocaCastEngine(v.get("Size", 0)).cast_as(expected_type=int)
                if _sz.get("success"):
                    _root_gib += _sz.get("message")
            _root_bytes = _root_gib * 1073741824
        except Exception as err:
            logger.warning(f"Save & Shut Down: could not size volumes for {_iid}: {err}")

        # Preserve the AD computer object through the later termination so the resumed
        # clone can heal via a light secure-channel reset instead of a full re-provision.
        # Tag BEFORE the stop so it is durably present when the reconciler terminates the
        # (imaged) instance. Read-back-confirm visibility (CreateTags->describe is
        # eventually consistent).
        try:
            client_ec2.create_tags(
                Resources=[_iid],
                Tags=[{"Key": "edh:PreserveAdObject", "Value": "true"}],
            )
            _tag_seen = False
            for _ in range(10):  # up to ~5s; CreateTags->describe is normally sub-second
                _desc = client_ec2.describe_instances(InstanceIds=[_iid])
                _live_tags = {
                    t["Key"]: t["Value"]
                    for r in _desc.get("Reservations", [])
                    for i in r.get("Instances", [])
                    for t in (i.get("Tags") or [])
                }
                if _live_tags.get("edh:PreserveAdObject") == "true":
                    _tag_seen = True
                    break
                time.sleep(0.5)
            if not _tag_seen:
                logger.warning(
                    f"Save & Shut Down: edh:PreserveAdObject not confirmed visible on {_iid} "
                    f"after read-back; proceeding (resume heal re-provisions if AD object is purged)."
                )
        except Exception as err:
            logger.warning(
                f"Save & Shut Down: could not set/confirm edh:PreserveAdObject on {_iid}: {err}; "
                f"proceeding (resume heal re-provisions if needed)."
            )

        # Stop-then-image: gracefully STOP the instance first so the capture is a clean,
        # consistent snapshot (an orderly OS shutdown flushes the disk and commits the
        # registry) rather than a crash-consistent NoReboot image of a live box. The
        # button is literally "Save & Shut Down" -- a clean stop is exactly what the user
        # expects, and a consistent resumable image outweighs the extra minute or two.
        # The actual CreateImage (on the STOPPED box) + terminate is deferred to the
        # session_state_watcher reconciler (create_images_for_stopped_captures) once EC2
        # reports 'stopped', so this request returns immediately -- the multi-minute stop
        # wait never blocks a uwsgi worker and survives a controller reload (a background
        # thread would be orphaned by a SIGHUP).
        try:
            client_ec2.stop_instances(InstanceIds=[_iid])
        except Exception as err:
            return SocaError.AWS_API_ERROR(
                service_name="ec2", helper=f"stop-instances failed: {err}"
            ).as_flask()

        try:
            _row = VdiSavedImages(
                image_id=None,  # stamped by the reconciler after CreateImage on the stopped box
                capture_instance_id=_iid,
                capture_stack_name=_sess.stack_name,
                origin_session_uuid=_session_uuid,
                session_name=_sess.session_name,
                os_family=str(_sess.os_family),
                base_os=_sess.instance_base_os,
                software_stack_id=_sess.software_stack_id,
                instance_type=_sess.instance_type,
                root_bytes=_root_bytes,
                software_stack_label="",
                created_by=_user,
                owner=_user,
                source="save",
                state="pending_capture",
                pinned=False,
                is_active=True,
            )
            db.session.add(_row)
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query="vdi_saved_images insert", helper=f"{err}"
            ).as_flask()

        # Park the origin session: it is being captured then destroyed (single-use
        # invariant -- the image is the sole continuation until resumed). The instance
        # itself is terminated by the reconciler after it is imaged; its CFN stack is
        # protected from the orphan-stack reaper (via capture_stack_name) until then.
        try:
            _sess.is_active = False
            _sess.deactivated_on = datetime.now(timezone.utc)
            _sess.session_state = "stopping"
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            logger.error(
                f"Save & Shut Down: capture row created for {_iid} but session "
                f"deactivation failed: {err}"
            )
            return SocaError.GENERIC_ERROR(
                helper=f"Capture queued but parking the desktop failed: {err}"
            ).as_flask()

        return SocaResponse(
            success=True,
            message="Desktop is shutting down cleanly; capture begins once it has stopped.",
        ).as_flask()

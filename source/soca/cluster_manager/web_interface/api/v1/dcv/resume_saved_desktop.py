# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Resume a Saved Desktop (Resume-From) -- launch a NEW VDI from a saved specialized
AMI, reusing the EDH-native async-placement path so the resumed desktop behaves
exactly like a normal VDI (broker session, watchers, connection file).

Single-use invariant: acquire an atomic available->resuming lease BEFORE launch
(resume_orchestration.acquire_resume_lease). On any launch failure, revert the
lease so the image is not lost. The image is consumed (AMI deregistered) later by
the session_state_watcher once the resumed session is confirmed running -- the
running instance is decoupled from the AMI, so it can never be resumed twice.

The resumed session row carries resume_saved_image_id so the watcher knows which
saved image to consume.
"""

import base64
import json
import logging
import os
import re
import uuid
from datetime import datetime, timezone

from flask_restful import Resource, reqparse
from flask import request

import config
import dcv_cloudformation_builder
from decorators import private_api, feature_flag
from models import db, VirtualDesktopSessions, VdiSavedImages, SoftwareStacks
import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.cast import SocaCastEngine
from utils.stack_naming import generate_stack_name
from utils.jinjanizer import SocaJinja2Generator
from utils.async_placement import enqueue_placement
from utils.resume_orchestration import acquire_resume_lease, revert_resume_lease, saved_desktops_enabled
from api.v1.dcv.instance_type_search import compatible_resume_types, catalog_spec
from utils.response import SocaResponse
from utils.error import SocaError

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def _profile_pattern_for_saved_image(row) -> list:
    """Admin instance-type allowlist glob patterns governing this saved image's
    profile, via its software stack (VirtualDesktopProfiles.pattern_allowed_
    instance_types). Empty list when unresolved -> compatible_resume_types then
    falls back to origin-only."""
    _ss = (
        SoftwareStacks.query.filter_by(id=row.software_stack_id).first()
        if row.software_stack_id
        else None
    )
    _prof = getattr(_ss, "profile", None) if _ss else None
    _pat = getattr(_prof, "pattern_allowed_instance_types", "") if _prof else ""
    return [p.strip() for p in (_pat or "").split(",") if p.strip()]


class ResumeSavedDesktop(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    @feature_flag(flag_name="SAVED_DESKTOPS", mode="api")
    def post(self):
        if saved_desktops_enabled().get("message") is not True:
            return SocaError.GENERIC_ERROR(
                helper="Saved Desktops is not enabled on this EDH cluster."
            ).as_flask()
        parser = reqparse.RequestParser()
        parser.add_argument("saved_image_id", type=int, location="form")
        parser.add_argument("spot", type=str, location="form", default="false")
        parser.add_argument("instance_type", type=str, location="form", default="")
        args = parser.parse_args()

        _user = request.headers.get("X-EDH-USER")
        _saved_image_id = args["saved_image_id"]
        if not _user:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()
        if not _saved_image_id:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="saved_image_id").as_flask()

        _row = VdiSavedImages.query.filter_by(id=_saved_image_id, is_active=True).first()
        if not _row:
            return SocaError.GENERIC_ERROR(helper="Saved desktop not found.").as_flask()
        # Ownership: only the current owner may resume (transfer reassigns owner; admin later).
        if _row.owner != _user:
            return SocaError.GENERIC_ERROR(
                helper="You are not the owner of this saved desktop."
            ).as_flask()
        if str(_row.os_family).lower() != "windows":
            return SocaError.GENERIC_ERROR(
                helper="Resume currently supports Windows saved desktops only."
            ).as_flask()

        # Interrupt-captured images may lack software_stack_id; resolve it from the
        # origin session and backfill, since it is NOT NULL on the session row.
        if _row.software_stack_id is None:
            _origin = (
                VirtualDesktopSessions.query.filter_by(
                    session_uuid=_row.origin_session_uuid
                )
                .order_by(VirtualDesktopSessions.created_on.desc())
                .first()
            )
            if _origin and _origin.software_stack_id is not None:
                _row.software_stack_id = _origin.software_stack_id
                db.session.commit()
            else:
                return SocaError.GENERIC_ERROR(
                    helper="This saved desktop is missing its software stack reference and cannot be resumed. Please contact your administrator."
                ).as_flask()

        # Alternate instance type (optional). Empty or the origin type keeps the
        # origin. Any other value MUST be in the server-computed compatible set
        # (admin allowlist ∩ GPU manufacturer) -- never trust the client type.
        _chosen_type = (args.get("instance_type") or "").strip() or _row.instance_type
        if _chosen_type != _row.instance_type:
            _pattern = _profile_pattern_for_saved_image(_row)
            _compatible = {
                t["type"] for t in compatible_resume_types(_row.instance_type, _pattern)
            }
            if _chosen_type not in _compatible:
                return SocaError.GENERIC_ERROR(
                    helper=f"Instance type {_chosen_type} is not a permitted, "
                    f"compatible resume target for this saved desktop."
                ).as_flask()

        # --- Single-use lease: atomic available->resuming (single winner) ---
        _lease = acquire_resume_lease(_saved_image_id)
        if _lease.get("success") is not True:
            return _lease.as_flask()

        # From here on, any failure MUST revert the lease so the image is not stranded.
        try:
            _spot_requested = False
            if SocaCastEngine(args.get("spot")).cast_as(expected_type=bool).get("message") is True:
                _spot_allowed = SocaConfig(
                    key="/configuration/FeatureFlags/VirtualDesktops/AllowSpot"
                ).get_value(return_as=bool)
                if _spot_allowed.get("success") is True and _spot_allowed.get("message") is True:
                    _spot_requested = True

            _soca = SocaConfig(key="/").get_value(return_as=dict).get("message")
            if not _soca:
                raise RuntimeError("Unable to query SSM for this SOCA environment")

            _session_uuid = str(uuid.uuid4())
            _session_name = _row.session_name
            _cluster_id = _soca.get("/configuration/ClusterId")
            _stack_name = generate_stack_name(
                cluster_id=_cluster_id, owner=_user, session_uuid=_session_uuid
            )
            _cfn_stack_name = re.sub(r"[^a-zA-Z0-9\-]", "", _stack_name)

            # Root disk size + platform from the AMI itself (never shrink below the captured root).
            _disk_size = 50
            _instance_platform = ""
            try:
                _img = client_ec2.describe_images(ImageIds=[_row.image_id])
                for _i in _img.get("Images", []):
                    if not _instance_platform:
                        _instance_platform = _i.get("PlatformDetails", "")
                    for _bdm in _i.get("BlockDeviceMappings", []):
                        _ebs = _bdm.get("Ebs") or {}
                        if _ebs.get("VolumeSize"):
                            _disk_size = int(_ebs["VolumeSize"])
                            break
            except Exception as _derr:
                raise RuntimeError(f"Unable to describe saved AMI {_row.image_id}: {_derr}")
            if not _instance_platform:
                raise RuntimeError(f"Unable to determine InstancePlatform for AMI {_row.image_id}")

            # Render the warm-resume user_data (skips provisioning; heals AD; re-registers DCV).
            _soca["/dcv/SessionOwner"] = _user
            _soca["/dcv/SessionId"] = _session_uuid
            # Offload the large AD-heal script to S3 so the rendered userData stays
            # under EC2's 16 KB cap. Windows EC2Launch v2 cannot gunzip, so userData
            # MUST be plain base64 (see the encode below); inlining the ~7 KB AD-heal
            # would push it over the cap. The resume stub downloads + dot-sources it.
            # to_s3() renders + uploads in one sanctioned call (handles the S3 client
            # and put_object internally, returning SocaResponse/SocaError).
            _heal_bucket = _soca.get("/configuration/S3Bucket")
            _heal_key = (
                f"{_cluster_id}/config/do_not_delete/bootstrap/dcv_node/resume/"
                f"{_session_uuid}/resume_ad_heal.ps1"
            )
            _heal_upload = SocaJinja2Generator(
                get_template="templates/windows/resume_ad_heal.ps.j2",
                template_dirs=[
                    f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID')}/cluster_node_bootstrap/"
                ],
                variables=_soca,
            ).to_s3(bucket_name=_heal_bucket, key=_heal_key, autocast_values=True)
            if _heal_upload.get("success") is not True:
                raise RuntimeError(
                    f"resume ad-heal S3 offload failed: {_heal_upload.get('message')}"
                )
            _soca["/job/ResumeAdHealS3"] = f"s3://{_heal_bucket}/{_heal_key}"
            _gen = SocaJinja2Generator(
                get_template="windows_virtual_desktop/01_user_data_resume.ps1.j2",
                template_dirs=[
                    f"/opt/edh/{os.environ.get('EDH_CLUSTER_ID')}/cluster_node_bootstrap/"
                ],
                variables=_soca,
            ).to_stdout(autocast_values=True)
            if _gen.get("success") is False:
                raise RuntimeError(f"resume user_data render failed: {_gen.get('message')}")
            # Plain base64 -- NOT gzip: Windows EC2Launch v2 cannot auto-gunzip
            # userData (only Linux cloud-init can). The AD-heal offload above keeps
            # this under the 16 KB cap without compression.
            _encoded_user_data = base64.b64encode(
                _gen.get("message").encode("utf-8")
            ).decode("utf-8")

            # Per-stack PRVI override (NULL => inherit fleet default in the builder).
            _stk = SoftwareStacks.query.filter_by(id=_row.software_stack_id).first()
            _stack_accel = _stk.volume_acceleration if _stk is not None else None

            _launch_parameters = {
                "security_group_id": _soca.get("/configuration/VdiNodeSecurityGroup"),
                "instance_profile": _soca.get("/configuration/VdiNodeInstanceProfileArn"),
                "instance_type": _chosen_type,
                "subnet_id": None,  # async placement injects SubnetId at stack-create
                "tenancy": "default",
                "project": "desktop",
                "image_id": _row.image_id,
                "session_name": _session_name,
                "session_uuid": _session_uuid,
                "base_os": _row.base_os,
                "disk_size": _disk_size,
                "volume_type": _soca.get("/configuration/DefaultVolumeType"),
                "volume_acceleration": _stack_accel,
                "cluster_id": _cluster_id,
                "metadata_http_tokens": _soca.get("/configuration/MetadataHttpTokens"),
                "hibernate": False,
                "user": _user,
                "Version": _soca.get("/configuration/Version"),
                "Region": _soca.get("/configuration/Region"),
                "DefaultMetricCollection": SocaCastEngine(
                    _soca.get("/configuration/DefaultMetricCollection")
                ).cast_as(expected_type=bool).get("message"),
                "SolutionMetricsLambda": _soca.get("/configuration/SolutionMetricsLambda"),
                "NestedVirtLauncherLambda": _soca.get("/configuration/NestedVirtLauncherLambda"),
                "VdiNodeInstanceProfileArn": _soca.get("/configuration/VdiNodeInstanceProfileArn"),
                "user_data": _encoded_user_data,
                "custom_tags": {},
                "capacity_reservation_id": "",
                "nested_virtualization": False,
                "spot": _spot_requested,
                "async_placement": True,
            }

            _launch_template = dcv_cloudformation_builder.main(**_launch_parameters)
            if _launch_template.get("success") is not True:
                raise RuntimeError(f"Template build failed: {_launch_template.get('message')}")

            _cfn_stack_tags = [
                {"Key": "edh:JobName", "Value": str(_session_name)},
                {"Key": "edh:JobOwner", "Value": _user},
                {"Key": "edh:ClusterId", "Value": str(_cluster_id)},
                {"Key": "edh:JobProject", "Value": "desktop"},
                {"Key": "edh:NodeType", "Value": "dcv_node"},
                {"Key": "edh:BaseOS", "Value": _row.base_os},
                {"Key": "edh:SessionUuid", "Value": str(_session_uuid)},
                {"Key": "edh:DCVResume", "Value": "true"},
            ]

            _cfn_notification_arns = []
            _topic = SocaConfig(key="/configuration/CfnEventsTopicArn").get_value(
                default="", allow_unknown_key=True
            )
            if _topic.success and _topic.message:
                _cfn_notification_arns = [_topic.message]

            _private_subnets = (
                SocaCastEngine(_soca.get("/configuration/PrivateSubnets"))
                .cast_as(expected_type=list)
                .get("message")
            )

            _enqueue = enqueue_placement(
                session_uuid=_session_uuid,
                stack_name=_cfn_stack_name,
                template_body=_launch_template.get("message"),
                cfn_tags=_cfn_stack_tags,
                cfn_notification_arns=_cfn_notification_arns,
                instance_type=_chosen_type,
                ami_id=_row.image_id,
                capacity_reservation_id="",
                spot=_spot_requested,
                subnet_ids=_private_subnets,
                tenancy="default",
                instance_platform=_instance_platform,
                session_row=VirtualDesktopSessions(
                    is_active=True,
                    created_on=datetime.now(timezone.utc),
                    deactivated_on=None,
                    session_owner=_user,
                    session_uuid=_session_uuid,
                    session_project="desktop",
                    session_id=_soca.get("/dcv/SessionId"),
                    session_name=_session_name,
                    stack_name=_cfn_stack_name,
                    session_local_admin_password=None,
                    authentication_token=None,
                    session_token=str(uuid.uuid4()),
                    session_thumbnail=_stk.thumbnail if _stk else None,
                    schedule=json.dumps(config.Config.DCV_DEFAULT_SCHEDULE),
                    session_state="placing",
                    session_state_latest_change_time=datetime.now(timezone.utc),
                    instance_private_dns=None,
                    instance_private_ip=None,
                    instance_id=None,
                    instance_type=_chosen_type,
                    instance_base_os=_row.base_os,
                    os_family=_row.os_family,
                    support_hibernation=False,
                    is_spot=_spot_requested,
                    software_stack_id=_row.software_stack_id,
                    session_type="console",
                    resume_saved_image_id=_saved_image_id,
                ),
            )
            if _enqueue.get("success"):
                # User-facing provenance: record the origin vs. resumed hardware on
                # the session timeline so the end user can see what the saved desktop
                # was captured on and what it's now running on (esp. cross-GPU-model
                # resume). Informational only ('bootstrap-checkpoint' does NOT drive
                # session state -- unlike 'session-resumed', which signals readiness).
                try:
                    from utils.dcv_event_store import append_event, build_envelope, new_event_id
                    _og = (catalog_spec(_row.instance_type).get("gpu_name") or "").strip()
                    _cg = (catalog_spec(_chosen_type).get("gpu_name") or "").strip()
                    if _chosen_type != _row.instance_type:
                        _msg = (
                            f"Resumed from a saved desktop captured on {_row.instance_type}"
                            + (f" ({_og})" if _og else "")
                            + f" \u2192 launching on {_chosen_type}"
                            + (f" ({_cg})" if _cg else "") + "."
                        )
                    else:
                        _msg = (
                            f"Resumed on {_chosen_type}"
                            + (f" ({_cg})" if _cg else "") + "."
                        )
                    _eid = new_event_id()
                    _env = build_envelope(
                        _eid, "bootstrap-checkpoint", _session_uuid,
                        "resume-hardware", _msg, owner=_user,
                    )
                    append_event(f"dcv#{_session_uuid}", _eid, _env)
                except Exception as _prov_err:
                    logger.warning(
                        f"resume provenance event failed (non-fatal) for "
                        f"{_session_uuid}: {_prov_err}"
                    )
                return SocaResponse(
                    success=True,
                    message=f"Resume queued for {_session_name} (session {_session_uuid})",
                ).as_flask()
            raise RuntimeError(f"Async placement failed: {_enqueue.get('message')}")

        except Exception as err:
            logger.error(f"Resume failed for saved image {_saved_image_id}: {err}")
            revert_resume_lease(_saved_image_id)
            return SocaError.GENERIC_ERROR(
                helper=f"Resume failed (saved desktop returned to available): {err}"
            ).as_flask()


class VdiResumeOptions(Resource):
    """Modal support for Resume-on-alternate-type. GET returns the compatible
    instance types for a saved desktop (admin allowlist ∩ GPU manufacturer),
    computed server-side so the client cannot widen the set."""

    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    @feature_flag(flag_name="SAVED_DESKTOPS", mode="api")
    def get(self):
        if saved_desktops_enabled().get("message") is not True:
            return SocaError.GENERIC_ERROR(
                helper="Saved Desktops is not enabled on this EDH cluster."
            ).as_flask()
        parser = reqparse.RequestParser()
        parser.add_argument("saved_image_id", type=int, location="args")
        args = parser.parse_args()

        _user = request.headers.get("X-EDH-USER")
        if not _user:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()
        _sid = args["saved_image_id"]
        if not _sid:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="saved_image_id").as_flask()

        _row = VdiSavedImages.query.filter_by(id=_sid, is_active=True).first()
        if not _row:
            return SocaError.GENERIC_ERROR(helper="Saved desktop not found.").as_flask()
        if _row.owner != _user:
            return SocaError.GENERIC_ERROR(
                helper="You are not the owner of this saved desktop."
            ).as_flask()

        _pattern = _profile_pattern_for_saved_image(_row)
        _types = compatible_resume_types(_row.instance_type, _pattern)
        _out = {"origin": _row.instance_type, "types": _types}
        return SocaResponse(success=True, message=_out).as_flask()

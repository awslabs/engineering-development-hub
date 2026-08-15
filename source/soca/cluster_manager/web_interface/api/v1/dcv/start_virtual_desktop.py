######################################################################################################################
#  Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.                                                #
#                                                                                                                    #
#  Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance    #
#  with the License. A copy of the License is located at                                                             #
#                                                                                                                    #
#      http://www.apache.org/licenses/LICENSE-2.0                                                                    #
#                                                                                                                    #
#  or in the 'license' file accompanying this file. This file is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES #
#  OR CONDITIONS OF ANY KIND, express or implied. See the License for the specific language governing permissions    #
#  and limitations under the License.                                                                                #
######################################################################################################################

from flask_restful import Resource, reqparse
from flask import request
from flask_babel import gettext as _
import logging
from decorators import private_api, feature_flag
from botocore.exceptions import ClientError
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from datetime import datetime, timezone
import utils.aws.odcr_helper as odcr_helper
from utils.config import SocaConfig
from utils.cast import SocaCastEngine

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class StartVirtualDesktop(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def put(self):
        """
        Start a DCV desktop session
        ---
        openapi: 3.1.0
        operationId: startVirtualDesktop
        tags:
          - Virtual Desktops
        summary: Start virtual desktop
        description: Start a stopped DCV virtual desktop session with automatic ODCR (On-Demand Capacity Reservation) management
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              example: "john.doe"
            description: SOCA username for authentication
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
            description: SOCA authentication token
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - session_uuid
                properties:
                  session_uuid:
                    type: string
                    format: uuid
                    description: UUID of the virtual desktop session to start
                    example: "12345678-1234-1234-1234-123456789012"
        responses:
          '200':
            description: Desktop start initiated successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "Your virtual desktop is starting"
          '400':
            description: Missing parameter or invalid session state
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "This virtual desktop seems to be already running."
          '401':
            description: Session not found or unauthorized
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to find this session"
          '500':
            description: Failed to start desktop or capacity reservation error
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to create capacity reservation"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="form")

        args = parser.parse_args()
        _session_uuid = args["session_uuid"]
        logger.info(f"Received parameter for restarting DCV desktop: {args}")

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="_session_uuid"
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _check_session = VirtualDesktopSessions.query.filter_by(
            session_owner=_user, session_uuid=_session_uuid, is_active=True
        ).first()

        if _check_session:
            _instance_id = _check_session.instance_id
            _session_state = _check_session.session_state

            if _session_state == "pending":
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="This DCV desktop is still being started. Please wait a little bit before restarting this session.",
                ).as_flask()

            if _session_state != "stopped":
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="This virtual desktop seems to be already running.",
                ).as_flask()

            try:
                # --- ODCR resume handling -------------------------------------
                # An instance copies its launch-time CapacityReservationSpecification
                # for life. Per-session "auto" ODCRs are short-lived (minutes) and
                # are long gone by resume, leaving the instance pinned to a dead CR
                # with capacity-reservations-only (no On-Demand fallback) -> start
                # fails with ReservationCapacityExceeded. For auto instances we
                # re-secure capacity exactly like launch: reserve a fresh short-
                # window ODCR in the instance's own AZ, then retarget the stopped
                # instance to it. Admin-supplied CRs are left untouched -- they may
                # be a large shared reservation the operator manages.
                try:
                    _describe_instance = client_ec2.describe_instances(
                        InstanceIds=[_instance_id]
                    )
                    _instance_info = _describe_instance["Reservations"][0][
                        "Instances"
                    ][0]
                except Exception as err:
                    logger.error(
                        f"Unable to describe {_instance_id} for ODCR resume handling: {err}"
                    )
                    _instance_info = None

                if _instance_info is not None:
                    _cr_spec = (
                        _instance_info.get("CapacityReservationSpecification") or {}
                    )
                    _targeted_cr = (
                        _cr_spec.get("CapacityReservationTarget") or {}
                    ).get("CapacityReservationId")
                    _tags = {
                        t.get("Key"): t.get("Value")
                        for t in _instance_info.get("Tags", [])
                    }
                    # Provenance: prefer the launch-time tag; for legacy (pre-tag)
                    # instances fall back to inspecting the targeted CR -- a live,
                    # EDH-untagged reservation is treated as admin-owned (durable
                    # shared pool); a gone/expired CR can only be a disposable auto.
                    _cr_source = _tags.get("edh:CapacityReservationSource")
                    if _cr_source is None and _targeted_cr:
                        try:
                            _cr_info = odcr_helper.get_reservation_info_soca_capacity_reservation(
                                capacity_reservation_id=_targeted_cr
                            )
                            _cr_source = (
                                "admin"
                                if (
                                    _cr_info.reservation_exist
                                    and _cr_info.state == "active"
                                )
                                else "auto"
                            )
                        except Exception:
                            _cr_source = "auto"

                    if _cr_source == "admin":
                        logger.info(
                            f"Resume: {_instance_id} uses an admin-supplied capacity "
                            f"reservation ({_targeted_cr}); leaving its spec untouched"
                        )
                    elif _cr_source == "auto":
                        logger.info(
                            f"Resume re-secure for {_instance_id} (old_cr={_targeted_cr}): "
                            f"reserving a fresh ODCR in {_instance_info.get('SubnetId')}"
                        )
                        _fresh = odcr_helper.create_capacity_reservation(
                            probe_capacity_only=False,
                            instance_type=_instance_info.get("InstanceType"),
                            capacity_reservation_name=_check_session.stack_name,
                            desired_capacity=1,
                            subnet_id=_instance_info.get("SubnetId"),
                            instance_ami=_instance_info.get("ImageId"),
                            tenancy=_instance_info.get("Placement", {}).get("Tenancy"),
                        )
                        if _fresh.get("success") is True and getattr(
                            _fresh.message, "reservation_exist", False
                        ):
                            _new_cr_id = _fresh.message.reservation_id
                            logger.info(
                                f"Fresh ODCR {_new_cr_id} reserved; retargeting {_instance_id}"
                            )
                            # Target-only form (no capacity-reservations-only):
                            # the modify API takes a target OR an open/none
                            # preference, not the launch-template combo.
                            try:
                                client_ec2.modify_instance_capacity_reservation_attributes(
                                    InstanceId=_instance_id,
                                    CapacityReservationSpecification={
                                        "CapacityReservationTarget": {
                                            "CapacityReservationId": _new_cr_id
                                        }
                                    },
                                )
                            except ClientError as _mod_err:
                                return SocaError.AWS_API_ERROR(
                                    service_name="ec2",
                                    helper=(
                                        f"Failed to retarget {_instance_id} to "
                                        f"{_new_cr_id}: {_mod_err}"
                                    ),
                                ).as_flask()
                        else:
                            # No reserved capacity in the instance's AZ. Honor the
                            # resume On-Demand fallback (default ON): detach the dead
                            # CR (preference=open) so the instance starts On-Demand
                            # instead of ICE-ing on the dead reservation.
                            _od_fallback_val = (
                                SocaConfig(
                                    key="/configuration/FeatureFlags/VirtualDesktops/ResumeODCRFallback"
                                )
                                .get_value(default="true", allow_unknown_key=True)
                                .get("message", "true")
                            )
                            _od_fallback_cast = SocaCastEngine(_od_fallback_val).cast_as(
                                bool
                            )
                            _od_fallback = (
                                _od_fallback_cast.message
                                if _od_fallback_cast.success
                                else True
                            )
                            if _od_fallback:
                                logger.warning(
                                    f"No reserved capacity for "
                                    f"{_instance_info.get('InstanceType')} in "
                                    f"{_instance_info.get('SubnetId')}; detaching "
                                    f"{_targeted_cr} and resuming {_instance_id} On-Demand"
                                )
                                try:
                                    client_ec2.modify_instance_capacity_reservation_attributes(
                                        InstanceId=_instance_id,
                                        CapacityReservationSpecification={
                                            "CapacityReservationPreference": "open"
                                        },
                                    )
                                except ClientError as _mod_err:
                                    logger.error(
                                        f"On-Demand fallback modify failed for "
                                        f"{_instance_id}: {_mod_err}"
                                    )
                                    return SocaError.AWS_API_ERROR(
                                        service_name="ec2",
                                        helper=(
                                            f"Failed to detach dead capacity "
                                            f"reservation from {_instance_id}: "
                                            f"{_mod_err}"
                                        ),
                                    ).as_flask()
                            else:
                                return SocaError.GENERIC_ERROR(
                                    helper=(
                                        f"No reserved capacity available for "
                                        f"{_instance_info.get('InstanceType')} in "
                                        f"{_instance_info.get('SubnetId')} right now, and "
                                        f"On-Demand fallback is disabled. Please try again later."
                                    )
                                ).as_flask()
                        
                client_ec2.start_instances(InstanceIds=[_instance_id])

                # --- High-scale broker re-registration on resume --------------
                # The broker tears down its Session object when a VDI is
                # stopped (SM agent goes offline). On resume, update_ec2_info()
                # in session_state_watcher.py -- the only place that calls
                # broker.create_session() -- is gated on the session having
                # *no* EC2 instance info in the DB yet, which is only true on
                # a brand-new launch. A resumed session already has
                # instance_id/private_ip/private_dns persisted from its
                # original launch, so update_ec2_info() skips it forever and
                # the broker never gets a Session for this UUID again --
                # _validate_dcv_sessions_via_broker() then has nothing to
                # promote and the WebUI never leaves "pending".
                #
                # Clear authentication_token (the column doubles as the
                # broker session Id handle -- see update_ec2_info) so the
                # next session_state_watcher cycle's update_ec2_info() sees
                # this as needing re-registration and retries
                # broker.create_session() on its own schedule until the
                # resumed instance's DCV server registers with the broker
                # (mirrors the exact retry-until-ready behavior it already
                # uses for a first launch -- no separate one-shot call here).
                _is_high_scale_cast = SocaCastEngine(
                    SocaConfig(key="/dcv/high_scale_enabled")
                    .get_value(default="false", allow_unknown_key=True)
                    .get("message", "false")
                ).cast_as(bool)
                _is_high_scale = (
                    _is_high_scale_cast.message
                    if _is_high_scale_cast.success
                    else False
                )
                if _is_high_scale:
                    logger.info(
                        f"Resume: clearing stale broker session handle for "
                        f"{_check_session.session_uuid} so session_state_watcher "
                        f"re-registers it with the broker"
                    )
                    _check_session.authentication_token = None

                try:
                    _check_session.session_state = "pending"
                    _check_session.session_state_latest_change_time = datetime.now(
                        timezone.utc
                    )
                    db.session.commit()
                except Exception as err:
                    return SocaError.DB_ERROR(
                        query=_check_session,
                        helper=f"Unable to update session state to 'pending' due to {err}",
                    ).as_flask()
            except ClientError as err:
                if "IncorrectInstanceState" in str(err):
                    return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                        session_number=_session_uuid,
                        session_owner=_user,
                        helper=f"Your current desktop is not yet stopped. Please wait a little longer if you just tried to stop your desktop.",
                    ).as_flask()
                else:
                    return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                        session_number=_session_uuid,
                        session_owner=_user,
                        helper=f"Unable to start instance due to {err}",
                    ).as_flask()
            except Exception as err:
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to start instance due to {err}",
                ).as_flask()

            return SocaResponse(
                success=True,
                message=_(f"Your virtual desktop is starting"),
            ).as_flask()
        else:
            return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper="Unable to find this session. Please refresh your browser and try again.",
            ).as_flask()

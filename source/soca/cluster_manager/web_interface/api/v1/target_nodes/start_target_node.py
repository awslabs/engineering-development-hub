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
from models import db, TargetNodeSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
from datetime import datetime, timezone
import utils.aws.odcr_helper as odcr_helper
from utils.config import SocaConfig

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class StartTargetNode(Resource):
    @private_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def put(self):
        """
        Start target node
        ---
        openapi: 3.1.0
        operationId: startTargetNode
        tags:
          - Target Nodes
        summary: Start a stopped target node session
        description: Restart a previously stopped target node session by session UUID
        security:
          - socaAuth: []
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
              example: "john.doe"
            description: SOCA username for authentication
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              minLength: 1
              example: "abc123def456"
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
                    description: UUID of the target node session to start
                    example: "12345678-1234-1234-1234-123456789abc"
        responses:
          '200':
            description: Target node start initiated successfully
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: string
                      example: "Your target node is starting"
          '400':
            description: Missing required parameter or invalid session state
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      enum:
                        - "Missing required parameter: session_uuid"
                        - "This target node is still being started. Please wait a little bit before restarting this session."
                        - "This target node seems to be already running."
                      example: "Missing required parameter: session_uuid"
          '401':
            description: Missing authentication header
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing X-EDH-USER header"
          '404':
            description: Session not found
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to find this session. Please refresh your browser and try again."
          '500':
            description: AWS API error or internal server error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      enum:
                        - "Unable to create capacity reservation"
                        - "Unable to start instance due to AWS error"
                        - "Your current target node is not yet stopped. Please wait a little longer"
                      example: "Unable to start instance due to AWS error"
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-EDH-USER
              description: SOCA authentication using username and token headers
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="form")

        args = parser.parse_args()
        _session_uuid = args["session_uuid"]
        logger.info(f"Received parameter for restarting target node: {args}")

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _check_session = TargetNodeSessions.query.filter_by(
            session_owner=_user, session_uuid=_session_uuid, is_active=True
        ).first()

        if _check_session:
            _instance_id = _check_session.instance_id
            _session_state = _check_session.session_state

            if _session_state == "pending":
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="This target node is still being started. Please wait a little bit before restarting this session.",
                ).as_flask()

            if _session_state != "stopped":
                return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="This target node seems to be already running.",
                ).as_flask()

            try:
                if (
                    SocaConfig(key="/configuration/FeatureFlags/EnableCapacityReservation")
                    .get_value(return_as=bool)
                    .get("message")
                    is True
                ):
                    logging.info("Retrieving instance information for new ODCR")
                    _describe_instance = client_ec2.describe_instances(
                        InstanceIds=[_instance_id]
                    )
                    _instance_info = _describe_instance["Reservations"][0]["Instances"][
                        0
                    ]
                    logging.info("Requesting new ODCR for this EC2 instance")
                    _request_on_demand_capacity_reservation = (
                        odcr_helper.create_capacity_reservation(
                            probe_capacity_only=True,
                            instance_type=_instance_info.get("InstanceType"),
                            desired_capacity=1,
                            capacity_reservation_name=_check_session.stack_name,
                            subnet_id=_instance_info.get("SubnetId"),
                            instance_ami=_instance_info.get("ImageId"),
                            tenancy=_instance_info.get("Placement").get("Tenancy"),
                        )
                    )
                    if _request_on_demand_capacity_reservation.get("success") is False:
                        return SocaError.GENERIC_ERROR(
                            helper=f"Unable to create capacity reservation due to {_request_on_demand_capacity_reservation.message}. Please try again later."
                        ).as_flask()
                    else:
                        logger.info(
                            f"Capacity reservation successfully validated {_request_on_demand_capacity_reservation.get('message')}"
                        )
                        
                client_ec2.start_instances(InstanceIds=[_instance_id])
                try:
                    _check_session.session_state = "pending"
                    _check_session.session_state_latest_change_time = datetime.now(
                        timezone.utc
                    )
                    db.session.commit()
                except Exception as err:
                    db.session.rollback()
                    return SocaError.DB_ERROR(
                        query=_check_session,
                        helper=f"Unable to update session state to 'pending' due to {err}",
                    ).as_flask()
            except ClientError as err:
                if "IncorrectInstanceState" in str(err):
                    return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                        session_number=_session_uuid,
                        session_owner=_user,
                        helper=f"Your current target node is not yet stopped. Please wait a little longer if you just tried to stop your target node.",
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
                message=_(f"Your target node is starting"),
            ).as_flask()
        else:
            return SocaError.VIRTUAL_DESKTOP_RESTART_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper="Unable to find this session. Please refresh your browser and try again.",
            ).as_flask()

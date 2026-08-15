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
from datetime import datetime, timezone
from decorators import private_api, feature_flag
from models import db, TargetNodeSessions
import utils.aws.boto3_wrapper as utils_boto3
import utils.aws.odcr_helper as odcr_helper
from utils.response import SocaResponse
from utils.error import SocaError
from utils.config import SocaConfig


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message


class StopTargetNode(Resource):
    @private_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def put(self):
        """
        Stop target node
        ---
        openapi: 3.1.0
        operationId: stopTargetNode
        tags:
          - Target Nodes
        summary: Stop a running target node session
        description: Stop or hibernate a running target node session by session UUID
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
                    description: UUID of the target node session to stop
                    example: "12345678-1234-1234-1234-123456789abc"
        responses:
          '200':
            description: Target node stop initiated successfully
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
                      example: "Your target node will be stopped soon."
          '400':
            description: Missing required parameter or session already stopped
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
                        - "Your target node is already stopped."
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
            description: AWS API error or database error
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
                        - "Unable to stop/hibernate instance due to AWS error"
                        - "Unable to set session_state to stopped due to database error"
                      example: "Unable to stop/hibernate instance due to AWS error"
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
        _user = request.headers.get("X-EDH-USER")
        _session_uuid = args.get("session_uuid", None)
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        logger.debug(
            f"Received stop target node request for {_session_uuid}, user {_user}"
        )

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()

        _check_session = TargetNodeSessions.query.filter_by(
            session_owner=_user,
            session_uuid=_session_uuid,
            is_active=True,
        ).first()

        if _check_session:
            _instance_id = _check_session.instance_id
            if _check_session == "stopped":
                return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper="Your target node is already stopped.",
                ).as_flask()

            # Check hibernate
            _hibernate_enabled = False
            try:
                _describe_instance = client_ec2.describe_instances(
                    InstanceIds=[_instance_id]
                )
                _response = _describe_instance["Reservations"][0]["Instances"]
                if _response:
                    _hibernate_enabled = (
                        _response[0]
                        .get("HibernationOptions", {})
                        .get("Configured", False)
                    )
            except Exception as err:
                logger.error(
                    f"Unable to check HibernationOptions for {_instance_id} due to {err}. Desktop will be stopped"
                )

            logger.info(
                f"About to stop/hibernate the instance. _hibernate_enabled flag {_hibernate_enabled}"
            )
            
            try:
                client_ec2.stop_instances(
                    InstanceIds=[_instance_id], Hibernate=_hibernate_enabled
                )
            except Exception as err:
                return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to stop/hibernate instance due to {err}",
                ).as_flask()

            try:
                _check_session.session_state = "stopping"
                _check_session.session_state_latest_change_time = datetime.now(
                    timezone.utc
                )
                db.session.commit()
            except Exception as err:
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query=_check_session,
                    helper=f"Unable to set session_state to stopping due to {err}",
                ).as_flask()

            return SocaResponse(
                success=True, message=_(f"Your target node will be stopped soon.")
            ).as_flask()
        else:
            return SocaError.VIRTUAL_DESKTOP_STOP_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper="Unable to find this session. Please refresh your browser and try again.",
            ).as_flask()

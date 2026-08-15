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
from models import db, TargetNodeSessions, TargetNodeProfiles, TargetNodeSoftwareStacks
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.response import SocaResponse
import json

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class ResizeTargetNode(Resource):
    @private_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def put(self):
        r"""
        Resize target node instance type
        ---
        openapi: 3.1.0
        operationId: resizeTargetNode
        tags:
          - Target Nodes
        summary: Resize target node instance type
        description: Modify the instance type of a target node session. The session must be in stopped state.
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
                  - instance_type
                properties:
                  session_uuid:
                    type: string
                    format: uuid
                    description: UUID of the target node session to resize
                    example: "12345678-1234-1234-1234-123456789abc"
                  instance_type:
                    type: string
                    pattern: '^[a-z0-9]+\.[a-z0-9]+$'
                    description: New EC2 instance type for the target node (must be allowed by the associated software stack profile)
                    example: "m5.large"
        responses:
          '200':
            description: Target node successfully resized
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
                      example: "Your virtual desktop has been updated"
          '400':
            description: Bad request - missing parameters or invalid instance type
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: string
                      example: "CLIENT_MISSING_PARAMETER"
                    message:
                      type: string
                      example: "Missing required parameter: session_uuid"
          '401':
            description: Unauthorized - invalid or missing authentication headers
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: string
                      example: "CLIENT_MISSING_HEADER"
                    message:
                      type: string
                      example: "Missing required header: X-EDH-USER"
          '403':
            description: Forbidden - session not owned by user or session not in stopped state
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: string
                      example: "VIRTUAL_DESKTOP_MODIFY_ERROR"
                    message:
                      type: string
                      example: "This target node is not stopped. You can only modify a stopped target node."
          '500':
            description: Internal server error - AWS API or database error
            content:
              application/json:
                schema:
                  type: object
                  required:
                    - success
                    - error_code
                    - message
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: string
                      example: "VIRTUAL_DESKTOP_MODIFY_ERROR"
                    message:
                      type: string
                      example: "Unable to modify this target node because of AWS error"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="form")
        parser.add_argument("instance_type", type=str, location="form")
        args = parser.parse_args()
        logger.info(f"Received parameter for resizing target node: {args}")

        _session_uuid = args["session_uuid"]
        _instance_type = args["instance_type"]

        if _session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="_session_uuid"
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        if _instance_type is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="instance_type"
            ).as_flask()

        _check_session = (
            TargetNodeSessions.query.join(
                TargetNodeSoftwareStacks,
                TargetNodeSoftwareStacks.id
                == TargetNodeSessions.target_node_software_stack_id,
            )
            .join(
                TargetNodeProfiles,
                TargetNodeProfiles.id
                == TargetNodeSoftwareStacks.target_node_profile_id,
            )
            .filter(
                TargetNodeSessions.session_owner == _user,
                TargetNodeSessions.is_active == True,
                TargetNodeSessions.session_uuid == _session_uuid,
            )
            .add_columns(
                TargetNodeSoftwareStacks.ami_arch,
                TargetNodeProfiles.allowed_instance_types,
            )
        ).first()

        if _check_session:
            session_info = _check_session[0]  # TargetNodeSessions
            _ami_arch = _check_session[1]
            allowed_instance_types = json.loads(_check_session[2]).get(
                _ami_arch
            )  # TargetNodeProfiles
            if _instance_type not in allowed_instance_types:
                return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Instance type {_instance_type} is not allowed by the software stack. Allowed instance types are: {allowed_instance_types}",
                ).as_flask()

            _instance_id = session_info.instance_id
            _session_state = session_info.session_state
            _software_stack = session_info.software_stack_id
            # Validate instance type provided is allowed by the software stack

            if _session_state != "stopped":
                return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"This Virtual Desktop is not stopped. You can only modify a stopped desktop.",
                ).as_flask()
            try:
                client_ec2.modify_instance_attribute(
                    InstanceId=_instance_id,
                    InstanceType={"Value": args["instance_type"].lower()},
                )

                try:
                    session_info.instance_type = args["instance_type"].lower()
                    db.session.commit()
                except Exception as err:
                    db.session.rollback()
                    return SocaError.DB_ERROR(
                        query=session_info,
                        helper=f"Unable to update instance type on database due to {err}",
                    ).as_flask()

            except Exception as err:
                return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                    session_number=_session_uuid,
                    session_owner=_user,
                    helper=f"Unable to modify this desktop because of {err}.",
                ).as_flask()

            return SocaResponse(
                success=True,
                message=_(f"Your virtual desktop has been updated"),
            ).as_flask()

        else:
            return SocaError.VIRTUAL_DESKTOP_MODIFY_ERROR(
                session_number=_session_uuid,
                session_owner=_user,
                helper=f"Unable to retrieve this session. It's possible your session has been deleted.",
            ).as_flask()

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
import logging
import json
from decorators import private_api, feature_flag
import os
import sys
from models import (
    db,
    TargetNodeSessions,
    TargetNodeSoftwareStacks,
    TargetNodeProfiles,
    TargetNodeUserData,
    SessionState,
)
import utils.aws.boto3_wrapper as utils_boto3
from utils.config import SocaConfig
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.jinjanizer import SocaJinja2Renderer

logger = logging.getLogger("soca_logger")

client_ec2 = utils_boto3.get_boto(service_name="ec2").message
client_cfn = utils_boto3.get_boto(service_name="cloudformation").message
client_ssm = utils_boto3.get_boto(service_name="ssm").message


class ListTargetNode(Resource):
    @private_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def get(self):
        """
        List target node sessions
        ---
        openapi: 3.1.0
        operationId: listTargetNodeSessions
        tags:
          - Target Nodes
        summary: Retrieve target node sessions for the authenticated user
        description: Returns a list of target node sessions with detailed information including connection strings and instance details
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: john.doe
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: Authentication token for the SOCA user
            example: abc123token
          - name: is_active
            in: query
            schema:
              type: string
              enum: ["true", "false"]
            required: true
            description: Filter by active status (true/false)
            example: "true"
          - name: session_uuid
            in: query
            schema:
              type: string
              format: uuid
              pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
            required: false
            description: Filter by specific session UUID
            example: 550e8400-e29b-41d4-a716-446655440000
          - name: state
            in: query
            schema:
              type: string
              enum: [pending, running, stopped, terminated, error]
            required: false
            description: Filter by session state
            example: running
        responses:
          '200':
            description: Target node sessions retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: object
                      description: Dictionary of session UUIDs mapped to session details
                      additionalProperties:
                        type: object
                        properties:
                          session_uuid:
                            type: string
                            format: uuid
                          session_name:
                            type: string
                          session_owner:
                            type: string
                          session_state:
                            type: string
                            enum: [pending, running, stopped, terminated, error]
                          instance_type:
                            type: string
                          connection_string:
                            type: string
          '400':
            description: Bad request - missing or invalid parameters
          '401':
            description: Authentication required
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("is_active", type=str, location="args")
        parser.add_argument("session_uuid", type=str, location="args")
        parser.add_argument("state", type=str, location="args")
        args = parser.parse_args()

        user = request.headers.get("X-EDH-USER")
        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        logger.info(
            f"Received parameter for listing target nodes: {args} for user {user}"
        )

        if args["is_active"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="is_active").as_flask()

        _check_active = SocaCastEngine(args["is_active"]).cast_as(expected_type=bool)
        if not _check_active.success:
            return SocaError.CLIENT_INVALID_PARAMETER(
                parameter="is_active", helper="is_active must be true or false"
            ).as_flask()
        else:
            _is_active = _check_active.message

        # Retrieve sessions
        logger.info(f"Retrieving target node sessions for {user}")
        _user_target_nodes_sessions = (
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
                TargetNodeSessions.session_owner == f"{user}",
                TargetNodeSessions.is_active == _is_active,
            )
            .add_columns(
                TargetNodeSoftwareStacks.target_node_profile_id,
                TargetNodeSoftwareStacks.ami_arch,
                TargetNodeSoftwareStacks.ami_connection_string,
                TargetNodeProfiles.allowed_instance_types,
            )
        )

        if args.get("state", ""):
            if args["state"] not in SessionState.enums:
                return SocaError.CLIENT_INVALID_PARAMETER(
                    parameter="state",
                    helper=f"state must be one of {SessionState.enums}",
                ).as_flask()
            logger.debug(f"Adding filter for session_state to {args['state']}")
            _all_dcv_sessions = _user_target_nodes_sessions.filter(
                TargetNodeSessions.session_state == args["state"]
            )

        if args.get("session_uuid", ""):
            logger.debug(f"Adding filter for session_uuid to {args['session_uuid']}")
            _all_dcv_sessions = _user_target_nodes_sessions.filter(
                TargetNodeSessions.session_uuid == args["session_uuid"]
            )

        logger.debug(
            f"Found all target nodes for {user=} {_user_target_nodes_sessions.all()}"
        )

        user_sessions = {}
        logger.info("Getting Session information for all session")

        _get_soca_parameters = SocaConfig(key="/").get_value(return_as=dict)
        if _get_soca_parameters.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve SOCA Parameters: {_get_soca_parameters.get('message')}"
            ).as_flask()
        else:
            _soca_parameters = _get_soca_parameters.get("message")

        for (
            session_info,
            target_node_profile_id,
            ami_arch,
            ami_connection_string,
            allowed_instance_types,
        ) in _user_target_nodes_sessions.all():
            try:

                # Render ami_connection_string if needed
                _ami_connection_string_variables = {
                    "EDH_USER": session_info.session_owner,
                    "EDH_NODE_INSTANCE_TYPE": session_info.instance_type,
                    "EDH_NODE_INSTANCE_PRIVATE_IP": session_info.instance_private_ip,
                    "EDH_NODE_INSTANCE_PRIVATE_DNS": session_info.instance_private_dns,
                    "EDH_NODE_INSTANCE_ID": session_info.instance_id,
                    "EDH_NODE_INSTANCE_ARCH": ami_arch,
                    "AWS_REGION": _soca_parameters.get("/configuration/Region"),
                }

                _generate_connection_string = SocaJinja2Renderer.from_string(
                    data=ami_connection_string,
                    variables=_ami_connection_string_variables,
                )
                if _generate_connection_string.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to generate connection string for {session_info.session_uuid} due to {_generate_connection_string.get('message')}"
                    ).as_flask()
                else:
                    _connection_string = _generate_connection_string.get("message")

                _session_data = {
                    "session_uuid": session_info.session_uuid,
                    "session_name": session_info.session_name,
                    "session_owner": session_info.session_owner,
                    "session_project": session_info.session_project,
                    "session_state": session_info.session_state,
                    "session_state_latest_change_time": session_info.session_state_latest_change_time.isoformat() + "Z" if session_info.session_state_latest_change_time else None,
                    "schedule": session_info.schedule,
                    "session_thumbnail": session_info.session_thumbnail,
                    "instance_private_dns": session_info.instance_private_dns,
                    "instance_private_ip": session_info.instance_private_ip,
                    "instance_id": session_info.instance_id,
                    "instance_type": session_info.instance_type,
                    "stack_name": session_info.stack_name,
                    "target_node_software_stack_id": session_info.target_node_software_stack_id,
                    "ami_arch": ami_arch,  # joined
                    "target_node_profile_id": target_node_profile_id,  # joined
                    "allowed_instance_types": sorted(
                        json.loads(allowed_instance_types).get(ami_arch)
                    ),  # joined
                    "connection_string": _connection_string,  # joined
                    "os_family": session_info.os_family,
                }

                user_sessions[session_info.session_uuid] = _session_data
                logger.debug(f"Session Info {user_sessions[session_info.session_uuid]}")

            except Exception as err:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                return SocaError.GENERIC_ERROR(
                    helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                ).as_flask()

        logger.debug(f"Complete User Sessions details to return: {user_sessions}")
        return SocaResponse(success=True, message=user_sessions).as_flask()

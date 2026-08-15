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
from utils.response import SocaResponse
from decorators import private_api, feature_flag
from utils.error import SocaError
from models import db, TargetNodeSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.cloudformation_client import SocaCfnClient

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


class DeleteTargetNode(Resource):
    @private_api
    @feature_flag(flag_name="TARGET_NODES", mode="api")
    def delete(self):
        """
        Delete a target node session
        ---
        openapi: 3.1.0
        operationId: deleteTargetNodeSession
        tags:
          - Target Nodes
        summary: Delete an existing target node session
        description: Terminates and removes a target node session including associated AWS resources
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
                    pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                    description: UUID of the target node session to delete
                    example: 550e8400-e29b-41d4-a716-446655440000
        responses:
          '200':
            description: Target node session deleted successfully
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
                      example: Your Target Node is about to be terminated
          '400':
            description: Bad request - missing or invalid parameters
          '401':
            description: Authentication required
          '404':
            description: Session not found or not active
          '500':
            description: Internal server error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="form")

        args = parser.parse_args()
        user = request.headers.get("X-EDH-USER")
        session_uuid = args["session_uuid"]
        logger.info(f"Receive Delete Target Node {args} session number {session_uuid}")

        if session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()

        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _check_session = TargetNodeSessions.query.filter_by(
            session_owner=user, session_uuid=session_uuid, is_active=True
        ).first()
        if _check_session:
            _stack_name = _check_session.stack_name
            # Terminate instance
            logger.debug(
                f"Found session {_check_session} about to delete {_check_session.session_name} and associated CloudFormation {_check_session.stack_name}"
            )

            logger.info(f"Deleting Target Node CloudFormation Stack {_stack_name}")
            _delete_stack = SocaCfnClient(stack_name=_stack_name).delete_stack()
            if _delete_stack.get("success") is False:
                return SocaError.AWS_API_ERROR(
                    service_name="cloudformation",
                    helper=f"Unable to delete cloudformation stack ({_stack_name}) due to {_delete_stack.get('message')}",
                ).as_flask()

            logger.debug("Stack deleted successfully, updating database")
            try:
                _check_session.is_active = False
                _check_session.deactivated_on = datetime.now(timezone.utc)
                _check_session.deactivated_by = user
                _check_session.session_state_latest_change_time = datetime.now(
                    timezone.utc
                )
                db.session.commit()
            
            except Exception as e:
                db.session.rollback()
                return SocaError.DB_ERROR(
                    helper=f"Unable to deactivate target node session due to {e}",
                    query=_check_session,
                ).as_flask()

            return SocaResponse(
                success=True,
                message=_(f"Your Target Node is about to be terminated"),
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"This session does not exist or is not active"
            ).as_flask()

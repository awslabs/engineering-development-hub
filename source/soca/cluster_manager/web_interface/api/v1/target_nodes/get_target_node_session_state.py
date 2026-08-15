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
import logging
from models import db, TargetNodeSessions
from utils.response import SocaResponse
from utils.error import SocaError
from decorators import private_api

logger = logging.getLogger("soca_logger")


class GetTargetNodeSessionState(Resource):
    @private_api
    def get(self):
        """
        Get target node session states
        ---
        openapi: 3.1.0
        operationId: getTargetNodeSessionStates
        tags:
          - Target Nodes
        summary: Retrieve the current state of target node sessions
        description: Returns the current state (pending, running, stopped, etc.) for one or more target node sessions
        parameters:
          - name: session_uuid
            in: query
            schema:
              type: string
              pattern: '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(,[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})*$'
              minLength: 1
            required: true
            description: Comma-separated list of session UUIDs to check
            example: 550e8400-e29b-41d4-a716-446655440000,660e8400-e29b-41d4-a716-446655440001
        responses:
          '200':
            description: Session states retrieved successfully
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
                      description: Dictionary mapping session UUIDs to their current states
                      additionalProperties:
                        type: string
                        enum: [pending, running, stopped, terminated, error]
                      example:
                        550e8400-e29b-41d4-a716-446655440000: running
                        660e8400-e29b-41d4-a716-446655440001: stopped
          '400':
            description: Bad request - missing or invalid parameters
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="args")
        args = parser.parse_args()
        logger.debug(
            f"Received parameter for listing target node session state: {args}"
        )

        if not args.get("session_uuid"):
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()
        
        _sessions_uuid = args["session_uuid"].split(",")
        _session_results = {}
        for _session in _sessions_uuid:
            _check_session = TargetNodeSessions.query.filter(
                TargetNodeSessions.session_uuid == _session,
                TargetNodeSessions.is_active == True,
            ).first()
            if _check_session:
                _session_results[_check_session.session_uuid] = (
                    _check_session.session_state
                )

        logger.debug(
            f"Complete User Sessions Check Session State details to return: {_session_results}"
        )
        return SocaResponse(success=True, message=_session_results).as_flask()

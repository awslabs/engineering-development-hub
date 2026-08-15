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
from models import db, VirtualDesktopSessions
from utils.response import SocaResponse
from utils.error import SocaError
from decorators import private_api

logger = logging.getLogger("soca_logger")


class GetVirtualDesktopsSessionState(Resource):
    @private_api
    def get(self):
        """
        Get virtual desktop session states
        ---
        openapi: 3.1.0
        operationId: getVirtualDesktopSessionStates
        tags:
          - Virtual Desktops
        summary: Get session states for virtual desktops
        description: Retrieves the current state of one or more DCV virtual desktop sessions
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication
            example: "john.doe"
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 256
            description: SOCA authentication token
            example: "abc123token456"
          - name: session_uuid
            in: query
            required: true
            schema:
              type: string
              pattern: '^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}(,[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})*$'
            description: Comma-separated list of session UUIDs to check
            example: "12345678-1234-1234-1234-123456789abc,87654321-4321-4321-4321-cba987654321"
        responses:
          '200':
            description: Session states retrieved successfully
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
                      type: object
                      additionalProperties:
                        type: object
                        properties:
                          state:
                            type: string
                            enum: ["pending", "running", "stopped", "stopping", "terminated"]
                            description: Current session state
                          ssm_ping:
                            type: string
                            description: SSM ping status (e.g. Online, Unknown)
                          instance_id:
                            type: string
                            nullable: true
                            description: EC2 instance ID (null if not yet provisioned)
                          instance_private_ip:
                            type: string
                            nullable: true
                            description: Instance private IP address
                          instance_private_dns:
                            type: string
                            nullable: true
                            description: Instance private DNS name
                      description: Dictionary mapping session UUIDs to their state objects
                      example:
                        "12345678-1234-1234-1234-123456789abc":
                          state: "running"
                          ssm_ping: "Online"
                          instance_id: "i-0abc123def456"
                          instance_private_ip: "10.0.1.100"
                          instance_private_dns: "ip-10-0-1-100.ec2.internal"
          '400':
            description: Missing required parameters
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
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "Missing required parameter: session_uuid"
          '401':
            description: Authentication failed
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
                      type: integer
                      example: 401
                    message:
                      type: string
                      example: "Invalid authentication credentials"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="args")
        args = parser.parse_args()
        logger.debug(
            f"Received parameter for listing DCV desktop session state: {args}"
        )

        if not args.get("session_uuid"):
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()
        
        _sessions_uuid = args["session_uuid"].split(",")
        _session_results = {}
        for _session in _sessions_uuid:
            _check_session = VirtualDesktopSessions.query.filter(
                VirtualDesktopSessions.session_uuid == _session,
                VirtualDesktopSessions.is_active == True,
            ).first()
            if _check_session:
                _session_results[_check_session.session_uuid] = {
                    "state": _check_session.session_state,
                    "ssm_ping": _check_session.ssm_ping_status or "Unknown",
                    # Volatile EC2 identity fields. These are stamped during
                    # provisioning (ec2-running event / watcher) while the
                    # session_state stays 'pending', so the page-load render of
                    # the card + View Details modal can be stale. Return them on
                    # every poll so the client can refresh them live (card IP
                    # badge) and fetch-on-open (View Details) without a full
                    # page reload.
                    "instance_id": _check_session.instance_id,
                    "instance_private_ip": _check_session.instance_private_ip,
                    "instance_private_dns": _check_session.instance_private_dns,
                }
            else:
                # The polled session_uuid has no active row. This is the
                # Save->Resume (or relaunch) case: the desktop was superseded by
                # a NEW session_uuid while keeping the SAME stable identity
                # (session_name + session_owner). The client's tile + Connect
                # link are still bound to the now-dead uuid, so resolve the
                # desktop's CURRENT live session and hand its uuid back as
                # `current_session_uuid`. The client repoints to the live session
                # instead of connecting to the dead one -- deterministic (driven
                # by the DB row, not a timer) and gated to the desktop's owner.
                _old = VirtualDesktopSessions.query.filter(
                    VirtualDesktopSessions.session_uuid == _session,
                ).first()
                if _old:
                    _successor = (
                        VirtualDesktopSessions.query.filter(
                            VirtualDesktopSessions.session_name == _old.session_name,
                            VirtualDesktopSessions.session_owner == _old.session_owner,
                            VirtualDesktopSessions.is_active == True,
                        )
                        .order_by(VirtualDesktopSessions.created_on.desc())
                        .first()
                    )
                    if _successor and _successor.session_uuid != _session:
                        _session_results[_session] = {
                            "state": _successor.session_state,
                            "ssm_ping": _successor.ssm_ping_status or "Unknown",
                            "instance_id": _successor.instance_id,
                            "instance_private_ip": _successor.instance_private_ip,
                            "instance_private_dns": _successor.instance_private_dns,
                            # Repoint signal: the tile bound to `_session` should
                            # rebind/Connect to this live uuid.
                            "current_session_uuid": _successor.session_uuid,
                        }

        logger.debug(
            f"Complete User Sessions Check Session State details to return: {_session_results}"
        )
        return SocaResponse(success=True, message=_session_results).as_flask()

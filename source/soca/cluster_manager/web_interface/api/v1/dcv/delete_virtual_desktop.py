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
from flask import request, session
from flask_babel import gettext as _
import logging
from datetime import datetime, timezone
from utils.response import SocaResponse
from decorators import private_api, feature_flag
from utils.error import SocaError
from models import db, VirtualDesktopSessions
import utils.aws.boto3_wrapper as utils_boto3
from utils.aws.cloudformation_client import SocaCfnClient
from helpers import vdi_pool_allocator


logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def _cfn_stack_exists(stack_name):
    """True if a CloudFormation stack with this name exists. Pool-served
    desktops have NO stack (the instance was claimed from a pool ASG, not
    launched via CFN), so this is how we route their deletion to a direct
    instance terminate instead of delete_stack."""
    if not stack_name:
        return False
    try:
        _cfn = utils_boto3.get_boto(service_name="cloudformation").message
        return bool(_cfn.describe_stacks(StackName=stack_name).get("Stacks"))
    except Exception:
        return False


class DeleteVirtualDesktop(Resource):
    @private_api
    @feature_flag(flag_name="VIRTUAL_DESKTOPS", mode="api")
    def delete(self):
        """
        Delete a DCV virtual desktop session
        ---
        openapi: 3.1.0
        operationId: deleteVirtualDesktop
        tags:
          - Virtual Desktops
        summary: Delete virtual desktop session
        description: Terminates an active DCV virtual desktop session and cleans up associated resources
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
                    description: UUID of the DCV session to delete
                    example: "12345678-1234-1234-1234-123456789abc"
        responses:
          '200':
            description: Virtual desktop session deletion initiated successfully
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
                      example: "Your Virtual Desktop is about to be terminated"
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
                      example: "Missing required header: X-EDH-USER"
          '403':
            description: Feature not enabled or insufficient permissions
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
                      example: 403
                    message:
                      type: string
                      example: "Virtual desktops feature is not enabled"
          '404':
            description: Session not found or not active
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
                      example: 404
                    message:
                      type: string
                      example: "This session does not exist or is not active"
          '500':
            description: Internal server error during deletion
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
                      example: 500
                    message:
                      type: string
                      example: "Unable to delete cloudformation stack"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("session_uuid", type=str, location="form")

        args = parser.parse_args()
        user = request.headers.get("X-EDH-USER")
        session_uuid = args["session_uuid"]
        logger.info(f"Receive Delete Desktop for {args} session number {session_uuid}")

        if session_uuid is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="session_uuid"
            ).as_flask()

        if user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        # Admin can delete any user's session. Admin is either the programmatic
        # root key (API_ROOT_KEY) or a sudoers user in the web session.
        # Regular users can only delete their own.
        import config
        token = request.headers.get("X-EDH-TOKEN", "")
        is_admin = token == config.Config.API_ROOT_KEY or session.get("sudoers", False) is True
        if is_admin:
            logger.info(f"Admin delete: actor={user!r} session_uuid={session_uuid}")
            _check_session = VirtualDesktopSessions.query.filter_by(
                session_uuid=session_uuid, is_active=True
            ).first()
        else:
            _check_session = VirtualDesktopSessions.query.filter_by(
                session_owner=user, session_uuid=session_uuid, is_active=True
            ).first()
        if _check_session:
            _stack_name = _check_session.stack_name
            # Terminate instance
            logger.debug(
                f"Found session {_check_session} about to delete {_check_session.session_name} and associated CloudFormation {_check_session.stack_name}"
            )

            # Best-effort broker closeSession BEFORE terminating the instance,
            # while the agent is still alive so the broker can close cleanly.
            # Non-fatal: a broker hiccup must never block the user's delete.
            # If this is skipped/fails, the broker's unreachable-session reaper
            # (seconds-before-deleting-sessions-unreachable-server) is the net.
            try:
                from utils.dcv_broker_client import DcvBrokerClient
                _broker = DcvBrokerClient()
                # Broker keys deleteSessions on its OWN session Id, not the
                # SOCA uuid (the uuid is the broker session Name). Resolve it
                # while the agent is still alive (describeSessions still lists it).
                _sess = _broker.find_session_by_name(session_uuid)
                if _sess:
                    _close = _broker.delete_session(
                        session_id=_sess["Id"],
                        owner=_sess.get("Owner", _check_session.session_owner),
                    )
                    if _close.success:
                        logger.info(f"Broker closeSession ok for {session_uuid}")
                    else:
                        logger.warning(
                            f"Broker closeSession failed for {session_uuid} (reaper will reclaim): {_close.message}"
                        )
                else:
                    logger.info(
                        f"Broker has no session matching {session_uuid}; nothing to close"
                    )
            except Exception as e:
                logger.warning(
                    f"Broker closeSession raised for {session_uuid} (reaper will reclaim): {e}"
                )

            # Session sharing: revoke any active grants on this session so guest
            # access does not outlive the desktop. Best-effort, non-fatal.
            try:
                from helpers import dcv_session_sharing_store
                _grant_svc = dcv_session_sharing_store.get_grant_service()
                if _grant_svc and _check_session.authentication_token:
                    _n = _grant_svc.revoke_all_for_session(
                        _check_session.authentication_token, revoked_by="system"
                    )
                    if _n:
                        logger.info(
                            f"Revoked {_n} session-sharing grant(s) on deleted session {session_uuid}"
                        )
            except Exception as e:
                logger.warning(
                    f"Session-sharing grant revoke raised for {session_uuid} (non-fatal): {e}"
                )

            # Pool-served desktops have no CloudFormation stack -- the instance
            # was claimed from a pool ASG and detached. Terminate it directly.
            # Regular VDIs are torn down via their CFN stack as before.
            if _check_session.instance_id and not _cfn_stack_exists(_stack_name):
                logger.info(
                    f"Pool-served desktop (no CFN stack); terminating instance "
                    f"{_check_session.instance_id} directly"
                )
                try:
                    client_ec2.terminate_instances(
                        InstanceIds=[_check_session.instance_id]
                    )
                except Exception as e:
                    return SocaError.AWS_API_ERROR(
                        service_name="ec2",
                        helper=f"Unable to terminate pool desktop instance "
                        f"{_check_session.instance_id}: {e}",
                    ).as_flask()
                # Free the ledger row now (don't wait for the reaper sweep).
                # Best-effort: the reaper is the backstop if this no-ops.
                vdi_pool_allocator.release_claim(
                    _check_session.software_stack_id,
                    _check_session.instance_type,
                    _check_session.instance_id,
                )
            else:
                logger.info(f"Deleting DCV CloudFormation Stack {_stack_name}")
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
                    helper=f"Unable to deactivate DCV desktop session due to {e}",
                    query=_check_session,
                ).as_flask()

            return SocaResponse(
                success=True,
                message=_(f"Your Virtual Desktop is about to be terminated"),
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper=f"This session does not exist or is not active"
            ).as_flask()

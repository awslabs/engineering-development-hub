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
from decorators import admin_api, restricted_api, private_api
from models import (
    VirtualDesktopProfiles,
    SoftwareStacks,
    TargetNodeSoftwareStacks,
    Projects,
    ProjectMemberships,
    ApplicationProfiles,
)
from extensions import db
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.http_client import SocaHttpClient
from flask import request
import os
import grp
import pwd

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def _validate_stack_ids(csv_str: str):
    # Stack ids can be:
    # - Empty -> won't check
    # - "all" -> returns all matching stacks
    # - 1,2,3 -> validate list of stack ids
    logger.info(f"Validating {csv_str}")
    if not csv_str:
        return True
    if csv_str.strip().lower() == "all":
        return True
    try:
        items = csv_str.split(",")
        _ = [int(item.strip()) for item in items]
        return True
    except ValueError:
        logger.error("specified value is not empty, all or a list of integer")
        return False


def get_authorized_target_node_software_stacks(
    allowed_project_ids: set, excluded_columns: list, stack_ids: list = None
) -> list[TargetNodeSoftwareStacks]:
    try:
        logger.debug(
            f"Retrieving associated TargetNodeSoftwareStacks for {allowed_project_ids} with {excluded_columns=}"
        )
        if stack_ids:
            _int_stack_ids = []
            for _s in stack_ids:
                _c = SocaCastEngine(data=_s).cast_as(int)
                if _c.get("success") is True:
                    _int_stack_ids.append(_c.get("message"))
            target_node_software_stacks = (
                TargetNodeSoftwareStacks.query.join(TargetNodeSoftwareStacks.projects)
                .filter(
                    Projects.id.in_(allowed_project_ids),
                    TargetNodeSoftwareStacks.id.in_(_int_stack_ids),
                    TargetNodeSoftwareStacks.is_active.is_(True),
                )
                .distinct()
            ).all()
        else:
            target_node_software_stacks = (
                TargetNodeSoftwareStacks.query.join(TargetNodeSoftwareStacks.projects)
                .filter(
                    Projects.id.in_(allowed_project_ids),
                    TargetNodeSoftwareStacks.is_active.is_(True),
                )
                .distinct()
            ).all()

        logger.debug(
            f"Found {len(target_node_software_stacks)} target node software stacks"
        )
        return [
            stack.as_dict(
                exclude_columns=excluded_columns,
                allowed_project_ids=allowed_project_ids,
            )
            for stack in target_node_software_stacks
        ]

    except Exception as err:
        logger.error(
            f"Failed to get get_authorized_target_node_software_stacks for user due to {err}"
        )
        raise ValueError()


def get_authorized_virtual_desktops_software_stacks(
    allowed_project_ids: set, excluded_columns: list, stack_ids: list = None
) -> list[SoftwareStacks]:
    try:
        logger.debug(
            f"Retrieving associated Virtual Desktop SoftwareStacks for {allowed_project_ids} with {excluded_columns=}"
        )

        if stack_ids:
            _int_stack_ids = []
            for _s in stack_ids:
                _c = SocaCastEngine(data=_s).cast_as(int)
                if _c.get("success") is True:
                    _int_stack_ids.append(_c.get("message"))
            software_stacks_report = (
                SoftwareStacks.query.join(SoftwareStacks.projects)
                .filter(
                    Projects.id.in_(allowed_project_ids),
                    SoftwareStacks.id.in_(_int_stack_ids),
                    SoftwareStacks.is_active.is_(True),
                )
                .distinct()
            ).all()

        else:
            software_stacks_report = (
                SoftwareStacks.query.join(SoftwareStacks.projects)
                .filter(
                    Projects.id.in_(allowed_project_ids),
                    SoftwareStacks.is_active.is_(True),
                )
                .distinct()
            ).all()

        logger.debug(f"{software_stacks_report=}")
        return [
            stack.as_dict(
                exclude_columns=excluded_columns,
                allowed_project_ids=allowed_project_ids,
            )
            for stack in software_stacks_report
        ]

    except Exception as err:
        logger.error(
            f"Failed to get get_authorized_virtual_desktops_software_stacks for user due to {err}"
        )
        raise ValueError()


def get_authorized_application_profiles(
    allowed_project_ids: set, excluded_columns: list, profile_ids: list = None
) -> list[ApplicationProfiles]:
    try:
        logger.debug(
            f"Retrieving associated ApplicationProfiles for {allowed_project_ids} with {excluded_columns=}"
        )
        if profile_ids:
            _application_profiles = (
                ApplicationProfiles.query.join(ApplicationProfiles.projects)
                .filter(
                    Projects.id.in_(allowed_project_ids),
                    ApplicationProfiles.id.in_(profile_ids),
                    ApplicationProfiles.deactivated_on.is_(None),
                )
                .distinct()
            ).all()
        else:
            _application_profiles = (
                ApplicationProfiles.query.join(ApplicationProfiles.projects)
                .filter(
                    Projects.id.in_(allowed_project_ids),
                    ApplicationProfiles.deactivated_on.is_(None),
                )
                .distinct()
            ).all()

        logger.debug(f"Found {len(_application_profiles)} application profiles")
        return [
            stack.as_dict(exclude_columns=excluded_columns)
            for stack in _application_profiles
        ]

    except Exception as err:
        logger.error(
            f"Failed to get get_authorized_application_profiles for user due to {err}"
        )
        raise ValueError()


class GetUserResourcesPermissions(Resource):

    @private_api
    def get(self):
        """
        Get user resource permissions
        ---
        openapi: 3.1.0
        operationId: getUserResourcePermissions
        tags:
          - User Permissions
        summary: Get current user's resource permissions
        description: Retrieves resource permissions for the authenticated user (private API)
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: user.name
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA authentication token
            example: abc123token
          - name: virtual_desktops
            in: query
            schema:
              type: string
              pattern: '^(all|[0-9]+(,[0-9]+)*)?$'
            required: false
            description: Include virtual desktop permissions ("all" or comma-separated IDs)
            example: "all"
          - name: target_nodes
            in: query
            schema:
              type: string
              pattern: '^(all|[0-9]+(,[0-9]+)*)?$'
            required: false
            description: Include target node permissions ("all" or comma-separated IDs)
            example: "1,2,3"
          - name: application_profiles
            in: query
            schema:
              type: string
              pattern: '^(all|[0-9]+(,[0-9]+)*)?$'
            required: false
            description: Include application profiles ("all" or comma-separated IDs)
            example: "all"
          - name: exclude_columns
            in: query
            schema:
              type: string
              pattern: '^[a-zA-Z0-9_,]*$'
            required: false
            description: Comma-separated list of columns to exclude from response
            example: "created_on,updated_on"
        responses:
          '200':
            description: User resource permissions retrieved successfully
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
                      properties:
                        user:
                          type: string
                          example: user.name
                        software_stacks:
                          type: array
                          items:
                            type: object
                          description: Virtual desktop software stacks (if requested)
                        target_node_software_stacks:
                          type: array
                          items:
                            type: object
                          description: Target node software stacks (if requested)
                        application_profiles:
                          type: array
                          items:
                            type: object
                          description: Application profiles (if requested)
          '401':
            description: Missing authentication header
          '500':
            description: Database error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("virtual_desktops", type=str, default="", location="args")
        parser.add_argument("target_nodes", type=str, default="", location="args")
        parser.add_argument(
            "application_profiles", type=str, default="", location="args"
        )
        parser.add_argument("exclude_columns", type=str, default="", location="args")
        args = parser.parse_args()
        logger.info(
            f"Received GetUserResourcesPermissions Get Request {request.args.to_dict()}"
        )

        _virtual_desktops = args.get("virtual_desktops")
        _target_nodes = args.get("target_nodes")
        _application_profiles = args.get("application_profiles")
        _exclude_columns = args.get("exclude_columns").split(",")

        if not _validate_stack_ids(_application_profiles):
            return SocaError.GENERIC_ERROR(
                helper=f"{_application_profiles} must be empty, 'all' or a csv of integer"
            ).as_flask()

        if not _validate_stack_ids(_virtual_desktops):
            return SocaError.GENERIC_ERROR(
                helper=f"{_virtual_desktops} must be empty, 'all' or a csv of integer"
            ).as_flask()

        if not _validate_stack_ids(_target_nodes):
            return SocaError.GENERIC_ERROR(
                helper=f"{_target_nodes} must be empty, 'all' or a csv of integer"
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")

        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()
        else:
            _get_user_info = SocaHttpClient(
                endpoint="/api/ldap/user",
                headers={
                    "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                    "X-EDH-USER": request.headers.get("X-EDH-USER"),
                },
            ).get(params={"user": _user})
            if _get_user_info.success is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to retrieve information for user {_user} due to {_get_user_info.message}"
                ).as_flask()

            else:
                if not _get_user_info.message:
                    return SocaError.GENERIC_ERROR(
                        helper="User does not seems to exist."
                    ).as_flask()
                else:
                    logger.info(f"Fetching group membership for {_user}")
                    try:
                        _group_membership = []
                        _pw_record = pwd.getpwnam(_user)
                        _user_uid = _pw_record.pw_uid
                        if _user_uid < 1000:
                            logger.error(
                                f"Unable to check user {_user} as {_user_uid} is < 1000"
                            )
                            return SocaError.GENERIC_ERROR(
                                helper="You cannot check system-level users"
                            ).as_flask()

                        _user_gid = _pw_record.pw_gid
                        _user_group_ids = os.getgrouplist(_user, _user_gid)
                        for _gid in _user_group_ids:
                            try:
                                _group_membership.append(grp.getgrgid(_gid).gr_name)
                            except Exception as err:
                                logger.error(
                                    f"Unable to fetch information for {_gid} because of {err}. Ignoring this group"
                                )
                    except Exception as err:
                        logger.error(
                            f"Failed to get group membership for {_user} due to {err}"
                        )
                        return SocaError.GENERIC_ERROR(
                            helper="Unable to get group membership for user. See log for more details"
                        ).as_flask()

        _allowed_resources = {
            "user": _user,
            "software_stacks": [],
            "target_node_software_stacks": [],
            "application_profiles": [],
        }
        try:
            logger.debug(f"Getting allowed projects for {_user}")
            allowed_project_ids = Projects.get_allowed_projects_for_user(
                db_session=db.session, user_name=_user, groups=_group_membership
            )

            logger.debug(f"{allowed_project_ids=}")

        except Exception as err:
            logger.error(
                f"Failed to get allowed_project_ids for user {_user} due to {err}"
            )
            return SocaError.DB_ERROR(
                query="allowed_project_ids",
                helper="Error occurred while fetching projects for user. See logs for details.",
            ).as_flask()

        if _virtual_desktops:
            try:
                _get_virtual_desktops_stacks = (
                    get_authorized_virtual_desktops_software_stacks(
                        allowed_project_ids=allowed_project_ids,
                        excluded_columns=_exclude_columns,
                        stack_ids=(
                            None
                            if _virtual_desktops == "all"
                            else [
                                int(item.strip())
                                for item in _virtual_desktops.split(",")
                            ]
                        ),
                    )
                )
                logger.debug(f"{_get_virtual_desktops_stacks=}")
                _allowed_resources["software_stacks"] = _get_virtual_desktops_stacks

            except ValueError:
                return SocaError.DB_ERROR(
                    query="get_authorized_virtual_desktops_software_stacks",
                    helper="Error occurred while fetching VDI Stacks for user. See logs for more details.",
                ).as_flask()

        if _target_nodes:
            try:
                _get_target_nodes = get_authorized_target_node_software_stacks(
                    allowed_project_ids=allowed_project_ids,
                    excluded_columns=_exclude_columns,
                    stack_ids=(
                        None
                        if _target_nodes == "all"
                        else [int(item.strip()) for item in _target_nodes.split(",")]
                    ),
                )
                logger.debug(f"{_get_target_nodes=}")
                _allowed_resources["target_node_software_stacks"] = _get_target_nodes
            except ValueError:
                return SocaError.DB_ERROR(
                    query="get_authorized_target_node_software_stacks",
                    helper="Error occurred while fetching Target Nodes Stacks for user. See logs for more details.",
                ).as_flask()

        if _application_profiles:
            try:
                _get_application_profiles = get_authorized_application_profiles(
                    allowed_project_ids=allowed_project_ids,
                    excluded_columns=_exclude_columns,
                    profile_ids=(
                        None
                        if _application_profiles == "all"
                        else [
                            int(item.strip())
                            for item in _application_profiles.split(",")
                        ]
                    ),
                )
                logger.debug(f"{_get_application_profiles=}")
                _allowed_resources["application_profiles"] = _get_application_profiles

            except ValueError:
                return SocaError.DB_ERROR(
                    query="get_authorized_application_profiles",
                    helper="Error occurred while fetching Application profiles. See logs for more details.",
                ).as_flask()

        logger.debug(f"Allowed Resources for {_user} = {_allowed_resources}")
        return SocaResponse(success=True, message=_allowed_resources).as_flask()

    @admin_api
    def post(self):
        """
        Get user resource permissions (admin)
        ---
        openapi: 3.1.0
        operationId: getUserResourcePermissionsAdmin
        tags:
          - User Permissions
        summary: Get resource permissions for a specific user
        description: Retrieves resource permissions for a specified user (admin access required)
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication (must be admin)
            example: admin.user
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA authentication token
            example: abc123token
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - user
                properties:
                  user:
                    type: string
                    pattern: '^[a-zA-Z0-9._-]+$'
                    minLength: 1
                    description: Username to check permissions for
                    example: target.user
                  virtual_desktops:
                    type: string
                    pattern: '^(all|[0-9]+(,[0-9]+)*)?$'
                    description: Include virtual desktop permissions ("all" or comma-separated IDs)
                    example: "all"
                  target_nodes:
                    type: string
                    pattern: '^(all|[0-9]+(,[0-9]+)*)?$'
                    description: Include target node permissions ("all" or comma-separated IDs)
                    example: "1,2,3"
                  application_profiles:
                    type: string
                    pattern: '^(all|[0-9]+(,[0-9]+)*)?$'
                    description: Include application profiles ("all" or comma-separated IDs)
                    example: "all"
                  exclude_columns:
                    type: string
                    pattern: '^[a-zA-Z0-9_,]*$'
                    description: Comma-separated list of columns to exclude from response
                    example: "created_on,updated_on"
        responses:
          '200':
            description: User resource permissions retrieved successfully
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
                      properties:
                        user:
                          type: string
                          example: target.user
                        software_stacks:
                          type: array
                          items:
                            type: object
                          description: Virtual desktop software stacks (if requested)
                        target_node_software_stacks:
                          type: array
                          items:
                            type: object
                          description: Target node software stacks (if requested)
                        application_profiles:
                          type: array
                          items:
                            type: object
                          description: Application profiles (if requested)
          '400':
            description: Missing required parameters
          '403':
            description: Insufficient permissions
          '500':
            description: Database error
        """
        parser = reqparse.RequestParser()
        parser.add_argument("virtual_desktops", type=str, location="form", default="")
        parser.add_argument("target_nodes", type=str, location="form", default="")
        parser.add_argument(
            "application_profiles", type=str, location="form", default=""
        )
        parser.add_argument("exclude_columns", type=str, location="form", default="")
        parser.add_argument("user", type=str, location="form", default="")
        args = parser.parse_args()
        logger.info(f"Received GetUserResourcesPermissions POST Request {args=}")

        _virtual_desktops = args.get("virtual_desktops")
        _target_nodes = args.get("target_nodes")
        _application_profiles = args.get("application_profiles")
        _exclude_columns = args.get("exclude_columns").split(",")
        _user = args.get("user")

        if not _validate_stack_ids(_application_profiles):
            return SocaError.GENERIC_ERROR(
                helper=f"{_application_profiles} must be empty, 'all' or a csv of integer"
            ).as_flask()

        if not _validate_stack_ids(_virtual_desktops):
            return SocaError.GENERIC_ERROR(
                helper=f"{_virtual_desktops} must be empty, 'all' or a csv of integer"
            ).as_flask()

        if not _validate_stack_ids(_target_nodes):
            return SocaError.GENERIC_ERROR(
                helper=f"{_target_nodes} must be empty, 'all' or a csv of integer"
            ).as_flask()
        logger.debug(
            f"Received GetUserStackVisibility Get Request {args=} for {_user=}"
        )

        if not _user:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        _get_user_info = SocaHttpClient(
            endpoint="/api/ldap/user",
            headers={
                "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                "X-EDH-USER": request.headers.get("X-EDH-USER"),
            },
        ).get(params={"user": _user})
        if _get_user_info.success is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to retrieve information for user {_user} due to {_get_user_info.message}"
            ).as_flask()

        else:
            if not _get_user_info.message:
                return SocaError.GENERIC_ERROR(
                    helper=f"User does not seems to exist."
                ).as_flask()
            else:
                _group_membership = []
                for _group in _get_user_info.message[0][1].get(
                    "memberOf", []
                ):  # this only work for AD for now
                    _group_membership.append(_group)

        _allowed_resources = {
            "user": _user,
            "software_stacks": [],
            "target_node_software_stacks": [],
            "application_profiles": [],
        }

        try:
            logger.debug(f"Getting allowed projects for {_user}")
            allowed_project_ids = Projects.get_allowed_projects_for_user(
                db_session=db.session, user_name=_user, groups=_group_membership
            )
            logger.debug(f"{allowed_project_ids=}")

        except Exception as err:
            logger.error(
                f"Failed to get allowed_project_ids for user {_user} due to {err}"
            )
            return SocaError.DB_ERROR(
                query="allowed_project_ids",
                helper="Error occurred while fetching projects for user. See logs for details.",
            ).as_flask()

        if _virtual_desktops:
            try:
                _get_virtual_desktops_stacks = (
                    get_authorized_virtual_desktops_software_stacks(
                        allowed_project_ids=allowed_project_ids,
                        excluded_columns=_exclude_columns,
                        stack_ids=(
                            None
                            if _virtual_desktops == "all"
                            else [
                                int(item.strip())
                                for item in _virtual_desktops.split(",")
                            ]
                        ),
                    )
                )
                logger.debug(f"{_get_virtual_desktops_stacks=}")
                _allowed_resources["software_stacks"] = _get_virtual_desktops_stacks
            except ValueError:
                return SocaError.DB_ERROR(
                    query="get_authorized_virtual_desktops_software_stacks",
                    helper="Error occurred while VDI Stacks for user. See logs for more details.",
                ).as_flask()

        if _target_nodes:
            try:
                _get_target_nodes = get_authorized_target_node_software_stacks(
                    allowed_project_ids=allowed_project_ids,
                    excluded_columns=_exclude_columns,
                    stack_ids=(
                        None
                        if _target_nodes == "all"
                        else [int(item.strip()) for item in _target_nodes.split(",")]
                    ),
                )
                logger.debug(f"{_get_target_nodes=}")
                _allowed_resources["target_node_software_stacks"] = _get_target_nodes

            except ValueError:
                return SocaError.DB_ERROR(
                    query="get_authorized_target_node_software_stacks",
                    helper="Error occurred while Target Nodes Stacks for user. See logs for more details.",
                ).as_flask()

        if _application_profiles:
            try:
                _get_application_profiles = get_authorized_application_profiles(
                    allowed_project_ids=allowed_project_ids,
                    excluded_columns=_exclude_columns,
                    profile_ids=(
                        None
                        if _application_profiles == "all"
                        else [
                            int(item.strip())
                            for item in _application_profiles.split(",")
                        ]
                    ),
                )
                logger.debug(f"{_get_application_profiles=}")
                _allowed_resources["application_profiles"] = _get_application_profiles

            except ValueError:
                return SocaError.DB_ERROR(
                    query="get_authorized_virtual_desktops_software_stacks",
                    helper="Error occurred while VDI Stacks for user. See logs for more details.",
                ).as_flask()

        logger.debug(f"Allowed Resources for {_user} = {_allowed_resources}")
        return SocaResponse(success=True, message=_allowed_resources).as_flask()

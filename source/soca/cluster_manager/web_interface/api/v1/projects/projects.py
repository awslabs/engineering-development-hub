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
from datetime import datetime, timezone
from models import (
    db,
    project_software_stack_association,
    project_application_profile_association,
    project_target_node_software_stack_association,
    VirtualDesktopProfiles,
    SoftwareStacks,
    Projects,
    ProjectMemberships,
    TargetNodeSoftwareStacks,
    ApplicationProfiles,
    HardwareProfiles,
)
import utils.aws.boto3_wrapper as utils_boto3
from utils.error import SocaError
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.http_client import SocaHttpClient
from flask import request
from flask_babel import gettext as _
from sqlalchemy.orm import joinedload
from sqlalchemy import tuple_
import re

logger = logging.getLogger("soca_logger")
client_ec2 = utils_boto3.get_boto(service_name="ec2").message


def _csv_to_int_id_list(_csv_value):
    """Parse a comma-separated id string into a list of ints via SocaCastEngine.

    Returns an (ids, invalid_token) tuple: (list[int], None) on success, or
    ([], offending_token) on a non-integer token -- the caller builds the
    SocaError(...).as_flask() response itself (web_interface returns must use
    .as_flask()). Empty/None input yields ([], None). Avoids a raw ValueError
    from bare int().
    """
    _ids = []
    if not _csv_value:
        return _ids, None
    for _item in _csv_value.split(","):
        _item = _item.strip()
        if not _item:
            continue
        _cast = SocaCastEngine(data=_item).cast_as(int)
        if _cast.get("success") is not True:
            return [], _item
        _ids.append(_cast.get("message"))
    return _ids, None


def is_valid_csv(csv_string: str):
    """
    Validate if a given string is in a proper CSV format.

    A valid CSV string:
    - Can be empty ("").
    - Can be a single "*", meaning "all".
    - Uses commas as delimiters.
    - Each value is non-empty after stripping whitespace.

    Returns:
    - True if valid, False otherwise.
    r"""
    if not isinstance(csv_string, str):
        return False

    if csv_string == "":  # Allow empty string as valid
        return True

    if csv_string.strip() == "*":  # Allow single "*"
        return True

    # Regex: Allows numbers, letters, spaces, *
    csv_pattern = r"^\s*[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*\s*$"

    return bool(re.match(csv_pattern, csv_string))


class ProjectsManager(Resource):

    @admin_api
    def get(self):
        """
        Get SOCA projects
        ---
        openapi: 3.1.0
        operationId: getProjects
        tags:
          - Projects
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA authentication token
            example: abc123token
          - name: project_id
            in: query
            schema:
              type: string
              pattern: '^[0-9]+$'
            required: false
            description: Specific project ID to retrieve
            example: "1"
        responses:
          '200':
            description: Projects retrieved successfully
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
                      example: {"1": {"id": 1, "project_name": "default", "description": "Default project"}}
          '400':
            description: Invalid project_id parameter
          '401':
            description: Authentication required
          '403':
            description: Admin access required
        """
        parser = reqparse.RequestParser()
        parser.add_argument("project_id", type=str, location="args")
        args = parser.parse_args()

        logger.debug(f"List SOCA projects with {request.args}")
        _project_info = {}
        if args["project_id"] is None:
            _list_project_profiles = Projects.query.filter_by(is_active=True).options(
                joinedload(Projects.software_stacks),
                joinedload(Projects.target_node_software_stacks),
                joinedload(Projects.application_profiles),
            )
        else:
            if (
                cast_result := SocaCastEngine(data=args["project_id"]).cast_as(int)
            ).get("success"):
                _project_id = cast_result.get("message")
                _list_project_profiles = Projects.query.filter_by(
                    id=_project_id, is_active=True
                ).options(
                    joinedload(Projects.software_stacks),
                    joinedload(Projects.target_node_software_stacks),
                    joinedload(Projects.application_profiles),
                )
            else:
                return SocaError.GENERIC_ERROR(
                    helper="profile_id does not seems to be a valid integer"
                ).as_flask()

        if _list_project_profiles.count() == 0:
            logger.warning("No Project found")
            return SocaResponse(success=True, message=_("No Project found")).as_flask()
        else:
            for _project in _list_project_profiles.all():
                project_data = _project.as_dict()
                project_data["software_stack_ids"] = [
                    stack.id for stack in getattr(_project, "software_stacks", []) or []
                ]
                project_data["target_node_software_stack_ids"] = [
                    stack.id
                    for stack in getattr(_project, "target_node_software_stacks", [])
                    or []
                ]
                project_data["allowed_users"] = ",".join(_project.allowed_users)
                project_data["denied_users"] = ",".join(_project.denied_users)
                project_data["allowed_groups"] = ",".join(_project.allowed_groups)
                project_data["denied_groups"] = ",".join(_project.denied_groups)

                project_data["application_profile_ids"] = [
                    stack.id
                    for stack in getattr(_project, "application_profiles", []) or []
                ]
                _project_info[_project.id] = project_data
            return SocaResponse(success=True, message=_project_info).as_flask()

    @admin_api
    def post(self):
        r"""
        Create a new SOCA project
        ---
        openapi: 3.1.0
        operationId: createProject
        tags:
          - Projects
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
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
                  - project_name
                  - description
                  - allowed_users
                  - denied_users
                  - allowed_groups
                  - denied_groups
                properties:
                  project_name:
                    type: string
                    minLength: 1
                    maxLength: 100
                    pattern: '^[a-zA-Z0-9_-]+$'
                    description: Name of the project
                    example: my-project
                  description:
                    type: string
                    minLength: 1
                    maxLength: 500
                    description: Project description (max 500 characters)
                    example: My custom project for CAE workloads
                  allowed_users:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of allowed users or * for all
                    example: "user1,user2,user3"
                  denied_users:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of denied users or * for all
                    example: "user4,user5"
                  allowed_groups:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of allowed groups or * for all
                    example: "group1,group2"
                  denied_groups:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of denied groups or * for all
                    example: "group3,group4"
                  software_stack_ids:
                    type: string
                    pattern: '^[0-9]+(,[0-9]+)*$'
                    description: CSV list of software stack IDs
                    example: "1,2,3"
                  target_nodes_software_stack_ids:
                    type: string
                    pattern: '^[0-9]+(,[0-9]+)*$'
                    description: CSV list of target node software stack IDs
                    example: "1,2"
                  application_profile_ids:
                    type: string
                    pattern: '^[0-9]+(,[0-9]+)*$'
                    description: CSV list of application profile IDs
                    example: "1,2"
                  aws_budget:
                    type: string
                    description: AWS budget name
                    example: my-budget
        responses:
          '200':
            description: Project created successfully
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
                      example: Project has been created successfully
          '400':
            description: Missing required parameters or validation error
          '401':
            description: Authentication required
          '403':
            description: Admin access required
          '409':
            description: Project name already exists
        """
        parser = reqparse.RequestParser()
        parser.add_argument("project_name", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("aws_budget", type=str, location="form")
        parser.add_argument("allowed_users", type=str, location="form")
        parser.add_argument("denied_users", type=str, location="form")
        parser.add_argument("allowed_groups", type=str, location="form")
        parser.add_argument("denied_groups", type=str, location="form")
        parser.add_argument("software_stack_ids", type=str, location="form")
        parser.add_argument(
            "target_nodes_software_stack_ids", type=str, location="form"
        )
        parser.add_argument("application_profile_ids", type=str, location="form")

        args = parser.parse_args()

        logger.debug(f"Received ProjectsManager Create Request args {args}")
        _project_name = args["project_name"]
        _description = args["description"]
        if not is_valid_csv(csv_string=args.get("allowed_users", "")):
            return SocaError.GENERIC_ERROR(
                helper="allowed_users must be a valid CSV string"
            ).as_flask()
        else:
            _allowed_users = args.get("allowed_users", "").split(",")

        if not is_valid_csv(csv_string=args.get("allowed_groups", "")):
            return SocaError.GENERIC_ERROR(
                helper="allowed_groups must be a valid CSV string"
            ).as_flask()
        else:
            _allowed_groups = args.get("allowed_groups", "").split(",")

        if not is_valid_csv(csv_string=args.get("denied_users", "")):
            return SocaError.GENERIC_ERROR(
                helper="denied_users must be a valid CSV string"
            ).as_flask()
        else:
            _denied_users = args.get("denied_users", "").split(",")

        if not is_valid_csv(csv_string=args.get("denied_groups", "")):
            return SocaError.GENERIC_ERROR(
                helper="denied_groups must be a valid CSV string"
            ).as_flask()
        else:
            _denied_groups = args.get("denied_groups", "").split(",")

        _software_stack_ids = args.get("software_stack_ids", "")
        _target_nodes_software_stack_ids = args.get(
            "target_nodes_software_stack_ids", ""
        )
        _application_profile_ids = args.get("application_profile_ids", "")
        _aws_budget = args.get("aws_budget", "")

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _required_input = [
            "project_name",
            "description",
            "allowed_users",
            "denied_users",
            "allowed_groups",
            "denied_groups",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        if len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helper="Description cannot be greater than 500 characters"
            ).as_flask()

        if Projects.query.filter_by(is_active=True, project_name=_project_name).first():
            return SocaError.GENERIC_ERROR(
                helper=f"Project name {_project_name} already exists, pick a different name or deactivate the existing one",
            ).as_flask()

        # Validate correct AWS budget
        if _aws_budget:
            _check_budget = SocaHttpClient(
                endpoint="/api/cost_management/budgets",
                headers={
                    "X-EDH-USER": request.headers.get("X-EDH-USER"),
                    "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                },
            ).get()
            if _check_budget.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to check budget due to {_check_budget.get('message')}"
                ).as_flask()
            else:
                _budget_lists = _check_budget.get("message")
                if _aws_budget not in _budget_lists:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to find {_aws_budget} in the list of available budgets"
                    ).as_flask()
        else:
            # No budget for this project
            _aws_budget = None

        _new_project_creation = Projects(
            project_name=_project_name,
            description=_description,
            aws_budget=_aws_budget,
            is_active=True,
            created_on=datetime.now(timezone.utc),
            created_by=_user,
        )

        _add_application_profile_ids, _bad_id = _csv_to_int_id_list(_application_profile_ids)
        if _bad_id is not None:
            return SocaError.GENERIC_ERROR(
                helper=f"application_profile_ids contains a non-integer value: '{_bad_id}'"
            ).as_flask()

        _application_profiles = ApplicationProfiles.query.filter(
            ApplicationProfiles.id.in_(_add_application_profile_ids)
        ).all()
        _new_project_creation.application_profiles.extend(_application_profiles)

        _add_software_stack_ids, _bad_id = _csv_to_int_id_list(_software_stack_ids)
        if _bad_id is not None:
            return SocaError.GENERIC_ERROR(
                helper=f"software_stack_ids contains a non-integer value: '{_bad_id}'"
            ).as_flask()

        _software_stacks = SoftwareStacks.query.filter(
            SoftwareStacks.id.in_(_add_software_stack_ids)
        ).all()
        _new_project_creation.software_stacks.extend(_software_stacks)

        add_target_node_software_stack_ids, _bad_id = _csv_to_int_id_list(_target_nodes_software_stack_ids)
        if _bad_id is not None:
            return SocaError.GENERIC_ERROR(
                helper=f"target_nodes_software_stack_ids contains a non-integer value: '{_bad_id}'"
            ).as_flask()

        _target_node_software_stacks = TargetNodeSoftwareStacks.query.filter(
            TargetNodeSoftwareStacks.id.in_(add_target_node_software_stack_ids)
        ).all()
        _new_project_creation.target_node_software_stacks.extend(_target_node_software_stacks)

        try:
            db.session.add(_new_project_creation)
            db.session.commit()

            # Populate membership table
            try:
                # Indivirual users (allow/deny)
                _list_all_users = SocaHttpClient(
                    endpoint="/api/ldap/users",
                    headers={
                        "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                        "X-EDH-USER": request.headers.get("X-EDH-USER"),
                    },
                ).get()
                logger.debug(f"List all SOCA Users {_list_all_users}")
                if _list_all_users.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper="Project created, but unable to manage group membership, unable to list SOCA users"
                    ).as_flask()
                else:
                    _valid_users = list(_list_all_users.get("message").keys())
                    _valid_users.append("*")  # add wildcard as valid option

                if _allowed_users:
                    logger.info(
                        f"Adding {_allowed_users} membership (allow) to {_new_project_creation.id}"
                    )
                    _allowed_users = [
                        user for user in _allowed_users if user in _valid_users
                    ]
                    logger.info(
                        f"List of user to add (ALLOW) to project after removing any invalid soca users: {_allowed_users}"
                    )

                    allow_memberships = [
                        ProjectMemberships(
                            project_id=_new_project_creation.id,
                            identity_name=user.strip(),
                            identity_type="user",
                            state="allow",
                        )
                        for user in _allowed_users
                    ]
                    db.session.add_all(allow_memberships)
                    db.session.commit()

                if _denied_users:
                    logger.info(
                        f"Adding {_denied_users} membership (deny) to {_new_project_creation.id}"
                    )
                    _denied_users = [
                        user for user in _denied_users if user in _valid_users
                    ]
                    logger.info(
                        f"List of user to add (DENY) to project after removing any invalid soca users: {_denied_users}"
                    )

                    deny_memberships = [
                        ProjectMemberships(
                            project_id=_new_project_creation.id,
                            identity_name=user.strip(),
                            identity_type="user",
                            state="deny",
                        )
                        for user in _denied_users
                    ]
                    db.session.add_all(deny_memberships)
                    db.session.commit()

                # Groups users (allow/deny)
                _list_all_groups = SocaHttpClient(
                    endpoint="/api/ldap/groups",
                    headers={
                        "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                        "X-EDH-USER": request.headers.get("X-EDH-USER"),
                    },
                ).get()
                logger.debug(f"List all SOCA Groups {_list_all_users}")
                if _list_all_groups.get("success") is False:
                    return SocaError.GENERIC_ERROR(
                        helper="Project created, but unable to manage group membership, unable to list SOCA groups"
                    ).as_flask()
                else:
                    _valid_groups = list(_list_all_groups.get("message").keys())

                if _allowed_groups:
                    logger.info(
                        f"Adding {_allowed_groups} membership (allow) to {_new_project_creation.id}"
                    )
                    _allowed_groups = [
                        group for group in _allowed_groups if group in _valid_groups
                    ]
                    logger.info(
                        f"List of group to add (ALLOW) to project after removing any invalid soca group: {_allowed_groups}"
                    )

                    allow_group_memberships = [
                        ProjectMemberships(
                            project_id=_new_project_creation.id,
                            identity_name=group.strip(),
                            identity_type="group",
                            state="allow",
                        )
                        for group in _allowed_groups
                    ]
                    db.session.add_all(allow_group_memberships)
                    db.session.commit()

                if _denied_groups:
                    logger.info(
                        f"Adding {_denied_groups} membership (deny) to {_new_project_creation.id}"
                    )
                    _denied_groups = [
                        group for group in _denied_groups if group in _valid_groups
                    ]
                    logger.info(
                        f"List of group to add (DENY) to project after removing any invalid soca users: {_denied_groups}"
                    )

                    deny_memberships = [
                        ProjectMemberships(
                            project_id=_new_project_creation.id,
                            identity_name=group.strip(),
                            identity_type="group",
                            state="deny",
                        )
                        for group in _denied_groups
                    ]
                    db.session.add_all(deny_memberships)
                    db.session.commit()

            except Exception as err:
                logger.error(
                    f"Project {_project_name} created but failed to manage project membership due to {err}"
                )
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query="membership",
                    helper="Project created but failed to manage group membership. See log for details",
                ).as_flask()

        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_new_project_creation,
                helper=f"Unable to add new project to DB due to {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=_("Project has been created successfully"),
        ).as_flask()

    @admin_api
    def delete(self):
        """
        Delete a SOCA project
        ---
        openapi: 3.1.0
        operationId: deleteProject
        tags:
          - Projects
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
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
                  - project_id
                properties:
                  project_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the project to delete
                    example: "2"
        responses:
          '200':
            description: Project deleted successfully
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
                      example: Project deleted successfully
          '400':
            description: Missing project_id or invalid ID
          '401':
            description: Authentication required
          '403':
            description: Admin access required or default project cannot be deleted
          '404':
            description: Project not found
          '409':
            description: Project is in use by active software stacks
        """
        parser = reqparse.RequestParser()
        parser.add_argument("project_id", type=str, location="form")

        args = parser.parse_args()
        logger.debug(f"Received Project Delete for {args}")

        if args["project_id"] is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="project_id").as_flask()

        _validate_project_id = SocaCastEngine(data=args["project_id"]).cast_as(int)

        if _validate_project_id.get("success") is True:
            _project_id = _validate_project_id.get("message")
        else:
            return SocaError.IMAGE_DEREGISTER_ERROR(
                image_label=args["project_id"],
                helper=f"profile_id does not seems to be a valid integer {args['project_id']}",
            ).as_flask()

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _check_project = Projects.query.filter_by(
            id=_project_id, is_active=True
        ).first()

        if _check_project:
            if _check_project.id == 1 or _check_project.project_name == "default":
                return SocaError.GENERIC_ERROR(
                    helper=f"Project {_check_project.project_name} is a default project and cannot be deleted"
                ).as_flask()

            _applications_using_project = (
                ApplicationProfiles.query.join(project_application_profile_association)
                .filter(
                    project_application_profile_association.c.project_id
                    == _check_project.id
                )
            )

            if _applications_using_project.count() > 0:
                return SocaError.GENERIC_ERROR(
                    helper=f"Project {_check_project.project_name} is using {_applications_using_project.count()} active Application Profiles. Update them first."
                ).as_flask()

            _software_stack_using_project = SoftwareStacks.query.join(
                project_software_stack_association
            ).filter(
                project_software_stack_association.c.project_id == _check_project.id,
                SoftwareStacks.is_active == True,
            )

            if _software_stack_using_project.count() > 0:
                return SocaError.GENERIC_ERROR(
                    helper=f"Project {_check_project.project_name} is using {_software_stack_using_project.count()} active Virtual Desktop software stacks. Update them first."
                ).as_flask()

            _target_nodes_software_stack_using_project = (
                TargetNodeSoftwareStacks.query.join(
                    project_target_node_software_stack_association
                ).filter(
                    project_target_node_software_stack_association.c.project_id
                    == _check_project.id,
                    TargetNodeSoftwareStacks.is_active == True,
                )
            )

            if _target_nodes_software_stack_using_project.count() > 0:
                return SocaError.GENERIC_ERROR(
                    helper=f"Project {_check_project.project_name} is using {_target_nodes_software_stack_using_project.count()} active Target Nodes software stacks. Update them first."
                ).as_flask()

            try:
                _check_project.is_active = False
                _check_project.deactivated_on = datetime.now(timezone.utc)
                _check_project.deactivated_by = _user
                db.session.commit()
            except Exception as err:
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query=_check_project,
                    helper=f"Unable to deactivate project {_project_id} due to {err}",
                ).as_flask()

            # delete project reference on  membership table
            try:
                db.session.query(ProjectMemberships).filter(
                    ProjectMemberships.project_id == _check_project.id
                ).delete()
                db.session.commit()
            except Exception as err:
                logger.error(
                    f"Project {_check_project} deleted but unable to delete referenced members due to {err}"
                )

            return SocaResponse(
                success=True, message=_("Project deleted successfully")
            ).as_flask()

        else:
            return SocaError.GENERIC_ERROR(
                helper="Project not found or already deactivated",
            ).as_flask()

    @admin_api
    def put(self):
        r"""
        Update an existing SOCA project
        ---
        openapi: 3.1.0
        operationId: updateProject
        tags:
          - Projects
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
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
                  - project_id
                  - description
                  - allowed_users
                  - denied_users
                  - allowed_groups
                  - denied_groups
                properties:
                  project_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the project to update
                    example: "2"
                  description:
                    type: string
                    minLength: 1
                    maxLength: 500
                    description: Updated project description (max 500 characters)
                    example: Updated project description
                  allowed_users:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of allowed users or * for all
                    example: "user1,user2,user4"
                  denied_users:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of denied users or * for all
                    example: "user5,user6"
                  allowed_groups:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of allowed groups or * for all
                    example: "group1,group2"
                  denied_groups:
                    type: string
                    pattern: '^(\*|[\w\s\.\-\'\*]+(\s*,\s*[\w\s\.\-\'\*]+)*)$'
                    description: CSV list of denied groups or * for all
                    example: "group3,group4"
                  software_stack_ids:
                    type: string
                    pattern: '^[0-9]+(,[0-9]+)*$'
                    description: CSV list of software stack IDs
                    example: "1,3,4"
                  target_nodes_software_stack_ids:
                    type: string
                    pattern: '^[0-9]+(,[0-9]+)*$'
                    description: CSV list of target node software stack IDs
                    example: "2,3"
                  application_profile_ids:
                    type: string
                    pattern: '^[0-9]+(,[0-9]+)*$'
                    description: CSV list of application profile IDs
                    example: "1,2"
                  aws_budget:
                    type: string
                    description: AWS budget name
                    example: updated-budget
                  hardware_profile_id:
                    type: string
                    pattern: '^[0-9]+$'
                    description: ID of the hardware profile to bind to this project (empty string to clear)
                    example: "5"
        responses:
          '200':
            description: Project updated successfully
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
                      example: Project has been updated successfully
          '400':
            description: Missing required parameters or validation error
          '401':
            description: Authentication required
          '403':
            description: Admin access required
          '404':
            description: Project not found
        """
        parser = reqparse.RequestParser()
        parser.add_argument("project_id", type=str, location="form")
        parser.add_argument("allowed_users", type=str, location="form")
        parser.add_argument("denied_users", type=str, location="form")
        parser.add_argument("allowed_groups", type=str, location="form")
        parser.add_argument("denied_groups", type=str, location="form")
        parser.add_argument("software_stack_ids", type=str, location="form")
        parser.add_argument(
            "target_nodes_software_stack_ids", type=str, location="form"
        )
        parser.add_argument("application_profile_ids", type=str, location="form")
        parser.add_argument("aws_budget", type=str, location="form")
        parser.add_argument("description", type=str, location="form")
        parser.add_argument("hardware_profile_id", type=str, location="form")

        args = parser.parse_args()
        if not is_valid_csv(csv_string=args.get("allowed_users", "")):
            return SocaError.GENERIC_ERROR(
                helper="allowed_users must be a valid CSV string"
            ).as_flask()
        else:
            _allowed_users = args.get("allowed_users", "").split(",")

        if not is_valid_csv(csv_string=args.get("denied_users", "")):
            return SocaError.GENERIC_ERROR(
                helper="denied_users must be a valid CSV string"
            ).as_flask()
        else:
            _denied_users = args.get("denied_users", "").split(",")

        if not is_valid_csv(csv_string=args.get("allowed_groups", "")):
            return SocaError.GENERIC_ERROR(
                helper="allowed_groups must be a valid CSV string"
            ).as_flask()
        else:
            _allowed_groups = args.get("allowed_groups", "").split(",")

        if not is_valid_csv(csv_string=args.get("denied_groups", "")):
            return SocaError.GENERIC_ERROR(
                helper="denied_groups must be a valid CSV string"
            ).as_flask()
        else:
            _denied_groups = args.get("denied_groups", "").split(",")

        _software_stack_ids = args.get("software_stack_ids", "")
        _target_nodes_software_stack_ids = args.get(
            "target_nodes_software_stack_ids", ""
        )
        _application_profile_ids = args.get("application_profile_ids", "")
        _project_id = args["project_id"]
        _description = args["description"]

        # Optional Hardware Profile binding (edit form always submits it; empty
        # clears the FK). A bound profile must be active. Project binding
        # overrides any Stack binding at resolve time.
        _hardware_profile_id = None
        _hw_raw = args.get("hardware_profile_id")
        if _hw_raw is not None and str(_hw_raw).strip() != "":
            _hw_cast = SocaCastEngine(data=_hw_raw).cast_as(int)
            if _hw_cast.get("success") is not True:
                return SocaError.GENERIC_ERROR(
                    helper=f"hardware_profile_id must be a valid integer {_hw_raw}"
                ).as_flask()
            _hardware_profile_id = _hw_cast.get("message")
            if not HardwareProfiles.query.filter_by(
                id=_hardware_profile_id, is_active=True
            ).first():
                return SocaError.GENERIC_ERROR(
                    helper=f"HardwareProfile {_hardware_profile_id} not found or inactive"
                ).as_flask()

        logger.info(f"Receive Project Update request with {args}")

        _user = request.headers.get("X-EDH-USER")
        if _user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        _required_input = [
            "description",
            "allowed_users",
            "denied_users",
            "allowed_groups",
            "denied_groups",
            "project_id",
        ]

        for _input in _required_input:
            if args[_input] is None:
                return SocaError.CLIENT_MISSING_PARAMETER(parameter=_input).as_flask()

        _pid_cast = SocaCastEngine(data=_project_id).cast_as(int)
        if _pid_cast.get("success") is True:
            _project_id = _pid_cast.get("message")
            _project_to_update = Projects.query.filter_by(
                id=_project_id, is_active=True
            ).first()
            if not _project_to_update:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to find existing project with id {_project_id}",
                ).as_flask()
        else:
            return SocaError.GENERIC_ERROR(
                helper=f"project_id does not seems to be a valid integer",
            ).as_flask()

        if len(_description) > 500:
            return SocaError.GENERIC_ERROR(
                helper="Description cannot be greater than 500 characters"
            ).as_flask()

        # Validate correct AWS budget
        _aws_budget = args.get("aws_budget", "")
        if _aws_budget:
            _check_budget = SocaHttpClient(
                endpoint=f"/api/cost_management/budgets",
                headers={
                    "X-EDH-USER": request.headers.get("X-EDH-USER"),
                    "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                },
            ).get()
            if _check_budget.get("success") is False:
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to check budget due to {_check_budget.get('message')}"
                ).as_flask()
            else:
                _budget_lists = _check_budget.get("message")
                if _aws_budget not in _budget_lists:
                    return SocaError.GENERIC_ERROR(
                        helper=f"Unable to find {_aws_budget} in the list of available budgets"
                    ).as_flask()
        else:
            # No budget for this project
            _aws_budget = None

        try:
            _project_to_update.description = _description
            _project_to_update.hardware_profile_id = _hardware_profile_id
            _project_to_update.software_stacks.clear()

            # Update VDI Software Stacks
            _add_software_stack_ids, _bad_id = _csv_to_int_id_list(_software_stack_ids)
            if _bad_id is not None:
                return SocaError.GENERIC_ERROR(
                    helper=f"software_stack_ids contains a non-integer value: '{_bad_id}'"
                ).as_flask()

            _software_stacks = SoftwareStacks.query.filter(
                SoftwareStacks.id.in_(_add_software_stack_ids)
            ).all()
            _project_to_update.software_stacks.extend(_software_stacks)

            # Update Target Node Software Stacks
            _project_to_update.target_node_software_stacks.clear()
            _add_target_node_software_stack_ids, _bad_id = _csv_to_int_id_list(_target_nodes_software_stack_ids)
            if _bad_id is not None:
                return SocaError.GENERIC_ERROR(
                    helper=f"target_nodes_software_stack_ids contains a non-integer value: '{_bad_id}'"
                ).as_flask()

            _target_node_software_stacks = TargetNodeSoftwareStacks.query.filter(
                TargetNodeSoftwareStacks.id.in_(_add_target_node_software_stack_ids)
            ).all()
            _project_to_update.target_node_software_stacks.extend(
                _target_node_software_stacks
            )

            # Update Application Profile
            _project_to_update.application_profiles.clear()
            _add_application_profile_ids, _bad_id = _csv_to_int_id_list(_application_profile_ids)
            if _bad_id is not None:
                return SocaError.GENERIC_ERROR(
                    helper=f"application_profile_ids contains a non-integer value: '{_bad_id}'"
                ).as_flask()

            _application_profiles = ApplicationProfiles.query.filter(
                ApplicationProfiles.id.in_(_add_application_profile_ids)
            ).all()
            _project_to_update.application_profiles.extend(_application_profiles)

            _project_to_update.aws_budget = _aws_budget
            db.session.commit()
            
            # Update Membership
            try:
                existing_memberships = (
                    db.session.query(
                        ProjectMemberships.identity_name,
                        ProjectMemberships.identity_type,
                        ProjectMemberships.state,
                    )
                    .filter(ProjectMemberships.project_id == _project_id)
                    .all()
                )

                logger.info(f"Existing memberships: {existing_memberships}")

                # Normalize current DB state into sets
                existing_members = {
                    (identity.strip(), identity_type, state)
                    for identity, identity_type, state in existing_memberships
                    if identity and identity.strip()
                }

                # Normalize incoming allowed/denied sets from user input
                allowed_users_set = {(user.strip(), "user", "allow") for user in _allowed_users if user and user.strip()}
                denied_users_set = {(user.strip(), "user", "deny") for user in _denied_users if user and user.strip()}
                allowed_groups_set = {(group.strip(), "group", "allow") for group in _allowed_groups if group and group.strip()}
                denied_groups_set = {(group.strip(), "group", "deny") for group in _denied_groups if group and group.strip()}

                new_members = allowed_users_set | denied_users_set | allowed_groups_set | denied_groups_set

                # Validate entries
                _list_all_users = SocaHttpClient(
                    endpoint="/api/ldap/users",
                    headers={
                        "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                        "X-EDH-USER": request.headers.get("X-EDH-USER"),
                    },
                ).get()

                if not _list_all_users.get("success"):
                    return SocaError.GENERIC_ERROR(
                        helper="Project edited, but unable to manage project membership, unable to list SOCA users"
                    ).as_flask()

                _valid_users = set(_list_all_users.get("message").keys()) | {"*"}

                _list_all_groups = SocaHttpClient(
                    endpoint="/api/ldap/groups",
                    headers={
                        "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                        "X-EDH-USER": request.headers.get("X-EDH-USER"),
                    },
                ).get()

                if not _list_all_groups.get("success"):
                    return SocaError.GENERIC_ERROR(
                        helper="Project edited, but unable to manage group membership, unable to list SOCA groups"
                    ).as_flask()

                _valid_groups = set(_list_all_groups.get("message").keys())

                # Filter out invalid identities
                new_members = {
                    (id_name, id_type, state)
                    for (id_name, id_type, state) in new_members
                    if (id_type == "user" and id_name in _valid_users)
                    or (id_type == "group" and id_name in _valid_groups)
                }

                members_to_add = new_members - existing_members
                members_to_remove = existing_members - new_members

                if members_to_remove:
                    db.session.query(ProjectMemberships).filter(
                        ProjectMemberships.project_id == _project_id,
                        tuple_(
                            ProjectMemberships.identity_name,
                            ProjectMemberships.identity_type,
                            ProjectMemberships.state,
                        ).in_(list(members_to_remove)),
                    ).delete(synchronize_session=False)
                    logger.debug(f"Removed identities: {members_to_remove}")

                memberships_to_add = [
                    ProjectMemberships(
                        project_id=_project_id,
                        identity_name=id_name,
                        identity_type=id_type,
                        state=state,
                    )
                    for (id_name, id_type, state) in members_to_add
                ]

                if memberships_to_add:
                    db.session.add_all(memberships_to_add)
                    logger.debug(f"Added identities: {memberships_to_add}")

                db.session.commit()

            except Exception as err:
                logger.error(
                    f"Project {_project_to_update} updated but failed to manage project membership due to: {err}"
                )
                db.session.rollback()
                return SocaError.DB_ERROR(
                    query="membership",
                    helper="Project updated but failed to manage project membership. See log for details",
                ).as_flask()

        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=_project_to_update,
                helper=f"Unable to edit project to DB due to {err}",
            ).as_flask()

        return SocaResponse(
            success=True,
            message=_(f"Project has been updated successfully"),
        ).as_flask()

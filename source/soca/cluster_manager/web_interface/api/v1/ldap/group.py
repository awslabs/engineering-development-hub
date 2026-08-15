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

import config
import ldap
from flask_restful import Resource, reqparse
from requests import get, put
import logging
from flask import request
from flask_babel import gettext as _
from decorators import private_api, admin_api, feature_flag
import re
import errors
import os
import sys
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.config import SocaConfig
from utils.http_client import SocaHttpClient

logger = logging.getLogger("soca_logger")


class Group(Resource):
    @admin_api
    def get(self):
        """
        Get group information
        ---
        openapi: 3.1.0
        operationId: getLdapGroup
        tags:
          - Group Management
        summary: Get group information
        description: Retrieve detailed information for a specific LDAP group including members
        security:
          - socaAuth: []
        parameters:
          - name: group
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 31
              pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
              example: "developers"
            description: Name of the group to retrieve
        responses:
          '200':
            description: Successfully retrieved group information
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
                        group_dn:
                          type: string
                          description: LDAP Distinguished Name of the group
                          example: "cn=developers,ou=group,dc=soca,dc=local"
                        members:
                          type: array
                          items:
                            type: string
                          description: List of group members
                          example: ["john.doe", "jane.smith"]
          '203':
            description: Group not found
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "LDAP group developers does not exist"
          '400':
            description: Missing required parameter
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: group"
        components:
          securitySchemes:
            socaAuth:
              type: apiKey
              in: header
              name: X-EDH-USER
              description: SOCA username for authentication
            socaToken:
              type: apiKey
              in: header
              name: X-EDH-TOKEN
              description: SOCA authentication token
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="args")
        args = parser.parse_args()
        group = args["group"]
        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter="group",
            ).as_flask()

        _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE
        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _filter = f"(&(objectClass=posixGroup)(cn={group}))"
                _attr_list = ["cn", "memberUid"]
            else:
                _filter = f"(&(objectClass=group)(cn={group}))"
                _attr_list = ["cn", "member"]

            _group = _soca_identity_client.search(
                base=_group_search_base,
                scope=ldap.SCOPE_SUBTREE,
                filter=_filter,
                attr_list=_attr_list,
            )
            if _group.success is False:
                logger.debug(f"{group} is not a valid LDAP group")
                return SocaResponse(
                    success=False, message=_(f"LDAP group {group} does not exist")
                ).as_flask()
            else:
                group_base = ""
                members = []
                for group in _group.message:
                    group_base = group[0]
                    if _attr_list[1] in group[1].keys():
                        for member in group[1][_attr_list[1]]:
                            members.append(
                                member.decode("utf-8")
                                if isinstance(member, bytes)
                                else member
                            )

                return SocaResponse(
                    success=True, message={"group_dn": group_base, "members": members}
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="api")
    def post(self):
        """
        Create new group
        ---
        openapi: 3.1.0
        operationId: createLdapGroup
        tags:
          - Group Management
        summary: Create new group
        description: Create a new LDAP group with optional initial members
        security:
          - socaAuth: []
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - group
                properties:
                  group:
                    type: string
                    description: Name of the group (alphanumeric, _, -, . allowed, max 31 chars)
                    minLength: 1
                    maxLength: 31
                    pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
                    example: "developers"
                  gid:
                    type: integer
                    description: Linux GID (auto-assigned if not provided)
                    minimum: 1000
                    maximum: 65535
                    example: 5001
                  members:
                    type: string
                    description: Comma-separated list of usernames to add to the group
                    pattern: '^[a-zA-Z0-9._-]+(,[a-zA-Z0-9._-]+)*$'
                    example: "john.doe,jane.smith"
        responses:
          '200':
            description: Group created successfully
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
                      example: "Group created successfully"
          '400':
            description: Invalid input or missing parameter
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Missing required parameter: group"
          '500':
            description: Backend error during group creation
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to create group"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="form")
        parser.add_argument("gid", type=int, location="form")
        parser.add_argument(
            "members", type=str, location="form"
        )  # comma separated list of users

        args = parser.parse_args()
        _group_regex_pattern = r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,31}$"
        if re.match(_group_regex_pattern, args["group"]):
            group = args["group"].lower()
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"group {args['group']} is not valid, must match {_group_regex_pattern} (contains -and start with- only alpha-numerical characters plus _ . - and must be 31 chars max"
            ).as_flask()

        gid = args["gid"]

        _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE
        _people_search_base = config.Config.DIRECTORY_PEOPLE_SEARCH_BASE

        if args["members"] is None:
            members = []
        else:
            members = args["members"].split(",")

        _get_gid = SocaHttpClient(
            endpoint="/api/ldap/ids",
            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
        ).get()
        if _get_gid.success:
            current_ldap_gids = _get_gid.message
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Unable to retrieve IDS due to {_get_gid.message}"
            ).as_flask()

        if gid is None:
            group_id = current_ldap_gids["proposed_gid"]
        else:
            if gid in current_ldap_gids["gid_in_use"]:
                return errors.all_errors("GID_ALREADY_IN_USE")
            group_id = gid

        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="group").as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            group_members = []
            if members is not None:
                if not isinstance(members, list):
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper="members must be a valid list"
                    ).as_flask()

                _get_all_users = SocaHttpClient(
                    endpoint="/api/ldap/users",
                    headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                ).get()
                if _get_all_users.success:
                    all_users = _get_all_users.message
                else:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Unable to retrieve the list of all SOCA users because of {_get_all_users.message}"
                    ).as_flask()

                for member in members:
                    if member not in all_users.keys():
                        return SocaError.IDENTITY_PROVIDER_ERROR(
                            helper=f"Unable to create group because supplied user {member} does not exist"
                        ).as_flask()
                    else:
                        group_members.append(member)

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                group_dn = f"cn={group},{_group_search_base}"
                attrs = [
                    (
                        "objectClass",
                        ["top".encode("utf-8"), "posixGroup".encode("utf-8")],
                    ),
                    ("gidNumber", [str(group_id).encode("utf-8")]),
                    (
                        "cn",
                        [str(group).encode("utf-8")],
                    ),
                ]
            else:
                group_dn = f"cn={group},{_group_search_base}"
                attrs = [
                    ("objectClass", ["top".encode("utf-8"), "group".encode("utf-8")]),
                    ("gidNumber", [str(group_id).encode("utf-8")]),
                    ("sAMAccountName", [f"{group}".encode("utf-8")]),
                ]

            _soca_identity_client.add(dn=group_dn, mod_list=attrs)

            users_not_added = []
            for member in group_members:
                _add_member_to_group = SocaHttpClient(
                    endpoint="/api/ldap/group",
                    headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                ).put(data={"group": group, "user": member, "action": "add"})
                if not _add_member_to_group.success:
                    users_not_added.append(member)

            if users_not_added.__len__() == 0:
                return SocaResponse(
                    success=True, message=_("Group created successfully")
                ).as_flask()
            else:
                return SocaResponse(
                    success=True,
                    message=_(f"Group created successfully but unable to add some users: {users_not_added}"),
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="api")
    def delete(self):
        """
        Delete group
        ---
        openapi: 3.1.0
        operationId: deleteLdapGroup
        tags:
          - Group Management
        summary: Delete group
        description: Delete a LDAP group from the directory
        security:
          - socaAuth: []
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - group
                properties:
                  group:
                    type: string
                    description: Name of the group to delete
                    minLength: 1
                    maxLength: 31
                    pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
                    example: "developers"
        responses:
          '200':
            description: Group deleted successfully
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
                      example: "Group deleted successfully"
          '400':
            description: Missing parameter or self-deletion attempt
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "You cannot delete your own group"
          '500':
            description: Failed to delete group
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to delete group"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="form")
        args = parser.parse_args()
        group = args["group"]

        request_user = request.headers.get("X-EDH-USER")
        if request_user is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        if request_user == group:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper="You cannot delete your own group"
            ).as_flask()

        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="group").as_flask()

        _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _dn = f"cn={group},{_group_search_base}"
            else:
                _dn = f"cn={group},{_group_search_base}"

            _delete_req = _soca_identity_client.delete(dn=_dn)
            if _delete_req.success:
                return SocaResponse(
                    success=True, message=_("Group deleted successfully")
                ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to delete group because of {_delete_req.message}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @admin_api
    @feature_flag(flag_name="USERS_GROUPS_MANAGEMENT", mode="api")
    def put(self):
        """
        Modify group membership
        ---
        openapi: 3.1.0
        operationId: modifyLdapGroupMembership
        tags:
          - Group Management
        summary: Modify group membership
        description: Add or remove a user from a LDAP group
        security:
          - socaAuth: []
        requestBody:
          required: true
          content:
            application/x-www-form-urlencoded:
              schema:
                type: object
                required:
                  - group
                  - user
                  - action
                properties:
                  group:
                    type: string
                    description: Name of the group to modify
                    minLength: 1
                    maxLength: 31
                    pattern: '^[a-zA-Z0-9][a-zA-Z0-9_.-]*$'
                    example: "developers"
                  user:
                    type: string
                    description: Username to add or remove from the group
                    minLength: 1
                    maxLength: 64
                    pattern: '^[a-zA-Z0-9._-]+$'
                    example: "john.doe"
                  action:
                    type: string
                    description: Action to perform
                    enum: ["add", "remove"]
                    example: "add"
        responses:
          '200':
            description: Group membership modified successfully
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
                      example: "Group updated successfully"
          '400':
            description: Missing parameter or invalid action
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Action invalid is not supported"
          '500':
            description: Failed to modify group membership
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    message:
                      type: string
                      example: "Unable to modify group"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("group", type=str, location="form")
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("action", type=str, location="form")
        args = parser.parse_args()
        group = args["group"]
        user = args["user"]
        action = args["action"]
        ALLOWED_ACTIONS = ["add", "remove"]

        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if group is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="group").as_flask()

        if action is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="action").as_flask()

        if action not in ALLOWED_ACTIONS:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Action {action} is not supported"
            ).as_flask()

        # Modifying resources on ActiveDirectory require to supply the full DN for the user
        if config.Config.DIRECTORY_AUTH_PROVIDER in [
            "aws_ds_managed_activedirectory",
        ]:
            if not config.Config.DIRECTORY_PEOPLE_SEARCH_BASE.lower() in user.lower():
                user_dn = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
            else:
                user_dn = user
        else:
            user_dn = user

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _group_search_base = config.Config.DIRECTORY_GROUP_SEARCH_BASE
            _people_search_base = config.Config.DIRECTORY_PEOPLE_SEARCH_BASE

            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _group_dn = f"cn={group},{_group_search_base}"
                _attr_name = "memberUid"
            else:
                _group_dn = f"cn={group},{_group_search_base}"
                _attr_name = "member"

            _is_user_exist = SocaHttpClient(
                endpoint="/api/ldap/user",
                headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
            ).get(params={"user": user})

            if _is_user_exist.success:
                if len(_is_user_exist.message) == 0:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"User {user} does not exist"
                    ).as_flask()
                else:
                    if action == "add":
                        mod_attrs = [
                            (ldap.MOD_ADD, _attr_name, [user_dn.encode("utf-8")])
                        ]
                    else:
                        mod_attrs = [
                            (ldap.MOD_DELETE, _attr_name, [user_dn.encode("utf-8")])
                        ]

                    _modify = _soca_identity_client.modify(
                        dn=_group_dn, mod_list=mod_attrs
                    )
                    if _modify.success:
                        return SocaResponse(
                            success=True, message=_("Group updated successfully")
                        ).as_flask()
                    else:
                        return SocaResponse(
                            success=False,
                            message=_(f"Unable to modify group because of {_modify.message}"),
                        ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to determine if {user} exist because of {_is_user_exist.message}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

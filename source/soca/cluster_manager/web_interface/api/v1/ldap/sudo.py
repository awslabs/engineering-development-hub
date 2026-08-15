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
from flask_babel import gettext as _
import config
import ldap
from decorators import restricted_api, private_api, admin_api, feature_flag
import errors
import logging
import os
import sys
import time
from utils.config import SocaConfig
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.error import SocaError

logger = logging.getLogger("soca_logger")

_sudo_cache = {}
_SUDO_CACHE_TTL = 60


class Sudo(Resource):
    @private_api
    def get(self):
        """
        Check user sudo permissions
        ---
        openapi: 3.1.0
        operationId: checkUserSudoPermissions
        tags:
          - User Management
        summary: Check user sudo permissions
        description: Verify if a specific user has sudo/administrator privileges in the LDAP directory
        security:
          - socaAuth: []
        parameters:
          - name: user
            in: query
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 64
              pattern: '^[a-zA-Z0-9._-]+$'
              example: "john.doe"
            description: Username to check sudo permissions for
        responses:
          '200':
            description: Successfully checked sudo permissions
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
                      example: "john.doe has SUDO permissions"
          '203':
            description: User does not have sudo permissions
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
                      example: "john.doe does not have SUDO permissions"
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
                      example: "Missing required parameter: user"
          '500':
            description: Internal server error
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
                      example: "Unable to check SUDO permissions"
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
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        cached = _sudo_cache.get(user)
        if cached and (time.time() - cached[1]) < _SUDO_CACHE_TTL:
            if cached[0]:
                return SocaResponse(success=True, message=_(f"{user} has SUDO permissions")).as_flask()
            else:
                return SocaResponse(success=False, message=_(f"{user} does not have SUDO permissions"), status_code=403).as_flask()

        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _user_filter = f"(&(objectClass=sudoRole)(sudoUser={user}))"
            _attr_list = ["cn"]
        else:
            # member on AD expects the DN of the user
            _user_filter = f"(&(objectClass=group)(member=cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}))"
            _attr_list = ["cn"]

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            _is_sudo = _soca_identity_client.search(
                base=config.Config.DIRECTORY_ADMIN_SEARCH_BASE,
                scope=ldap.SCOPE_SUBTREE,
                filter=_user_filter,
                attr_list=_attr_list,
            )
            if _is_sudo.success:
                if len(_is_sudo.message) == 1:
                    _sudo_cache[user] = (True, time.time())
                    return SocaResponse(
                        success=True, message=_(f"{user} has SUDO permissions")
                    ).as_flask()
                else:
                    _sudo_cache[user] = (False, time.time())
                    return SocaResponse(
                        success=False, message=_(f"{user} does not have SUDO permissions"), status_code=403
                    ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to check SUDO permissions because of {_is_sudo.message}"
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
        Grant sudo permissions
        ---
        openapi: 3.1.0
        operationId: grantUserSudoPermissions
        tags:
          - User Management
        summary: Grant sudo permissions
        description: Grant sudo/administrator privileges to a user and update their API key scope
        security:
          - socaAuth: []
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
                    description: Username to grant sudo permissions to
                    minLength: 1
                    maxLength: 64
                    pattern: '^[a-zA-Z0-9._-]+$'
                    example: "john.doe"
        responses:
          '200':
            description: Successfully granted sudo permissions
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
                      example: "john.doe has now SUDO permissions"
          '400':
            description: Missing required parameter or invalid request
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
                      example: "Missing required parameter: user"
          '500':
            description: Failed to grant sudo permissions
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
                      example: "Unable to grant SUDO permission to john.doe"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                _dn_user = f"cn={user},{config.Config.DIRECTORY_ADMIN_SEARCH_BASE}"
                _attrs = [
                    (
                        "objectClass",
                        ["top".encode("utf-8"), "sudoRole".encode("utf-8")],
                    ),
                    ("sudoHost", ["ALL".encode("utf-8")]),
                    ("sudoUser", [str(user).encode("utf-8")]),
                    ("sudoCommand", ["ALL".encode("utf-8")]),
                ]
                _add_sudo = _soca_identity_client.add(dn=_dn_user, mod_list=_attrs)
            else:
                # with AD, there is no concept of Sudoers OU, instead we rely on group membership
                _dn_sudoers_group = config.Config.DIRECTORY_ADMIN_SEARCH_BASE
                _dn_user = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
                _add_sudo = _soca_identity_client.modify(
                    dn=_dn_sudoers_group,
                    mod_list=[(ldap.MOD_ADD, "member", [_dn_user.encode("utf-8")])],
                )

            if _add_sudo.success:
                _sudo_cache.pop(user, None)
                return SocaResponse(
                    success=True, message=_(f"{user} has now SUDO permissions")
                ).as_flask()
            else:
                return SocaResponse(
                    success=False,
                    message=_(f"Unable to grant SUDO permission to {user} because of {_add_sudo.get('message')}"),
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
        Revoke sudo permissions
        ---
        openapi: 3.1.0
        operationId: revokeUserSudoPermissions
        tags:
          - User Management
        summary: Revoke sudo permissions
        description: Remove sudo/administrator privileges from a user and downgrade their API key scope
        security:
          - socaAuth: []
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
                    description: Username to revoke sudo permissions from
                    minLength: 1
                    maxLength: 64
                    pattern: '^[a-zA-Z0-9._-]+$'
                    example: "john.doe"
        responses:
          '200':
            description: Successfully revoked sudo permissions
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
                      example: "john.doe does not have admin permission anymore"
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
                      example: "Missing required parameter: user"
          '500':
            description: Failed to revoke sudo permissions
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
                      example: "Unable to remove admin permission for john.doe"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if config.Config.DIRECTORY_AUTH_PROVIDER in [
                "openldap",
                "existing_openldap",
            ]:
                dn_user = f"cn={user},{config.Config.DIRECTORY_ADMIN_SEARCH_BASE}"
                _delete_sudo = _soca_identity_client.delete(dn=dn_user)
            else:
                _dn_sudoers_group = config.Config.DIRECTORY_ADMIN_SEARCH_BASE
                _dn_user = f"cn={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
                _delete_sudo = _soca_identity_client.modify(
                    dn=_dn_sudoers_group,
                    mod_list=[(ldap.MOD_DELETE, "member", [_dn_user.encode("utf-8")])],
                )

            if _delete_sudo.get("success"):
                _sudo_cache.pop(user, None)
                return SocaResponse(
                    success=True,
                    message=_(f"{user} does not have admin permission anymore"),
                ).as_flask()
            else:
                return SocaResponse(
                    success=False,
                    message=_(f"Unable to remove admin permission for {user} because of {_delete_sudo.get('message')}"),
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

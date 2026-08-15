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
from flask import request
from flask_restful import Resource
import logging
from decorators import admin_api, private_api
from utils.config import SocaConfig
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.error import SocaError
from utils.validators import Validators
from utils.cast import SocaCastEngine
import os
import sys
logger = logging.getLogger("soca_logger")


class Users(Resource):
    @private_api
    def get(self):
        """
        Retrieve all LDAP users
        ---
        openapi: 3.1.0
        operationId: getAllLdapUsers
        tags:
          - User Management
        summary: Retrieve all LDAP users
        description: Returns a list of all users from the configured LDAP directory (OpenLDAP or Active Directory). Supports optional typeahead mode via the q parameter.
        security:
          - socaAuth: []
        parameters:
          - name: q
            in: query
            required: false
            schema:
              type: string
              minLength: 2
              example: "john"
            description: Typeahead filter (minimum 2 characters). When provided, returns a small filtered list with username and display_name instead of the full directory.
          - name: max_results
            in: query
            required: false
            schema:
              type: integer
              minimum: 1
              maximum: 200
              default: 50
              example: 50
            description: Maximum number of results to return in typeahead mode. Clamped to 1-200.
        responses:
          '200':
            description: Successfully retrieved all LDAP users
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
                      description: Dictionary of username to LDAP DN mappings
                      additionalProperties:
                        type: string
                        description: LDAP Distinguished Name
                      example:
                        "john.doe": "cn=john.doe,ou=people,dc=soca,dc=local"
                        "jane.smith": "cn=jane.smith,ou=people,dc=soca,dc=local"
          '203':
            description: Invalid username/token pair
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
                      example: "Invalid authentication credentials"
          '400':
            description: Malformed client input
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
                      example: "Bad request parameters"
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
                      example: "Unable to connect to LDAP server"
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
        all_ldap_users = {}
        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _filter = "(objectClass=person)"
            _attr_name = "uid"
        else:
            # (!(userAccountControl:1.2.840.113556.1.4.803:=2))) -> catch disabled users
            if config.Config.DIRECTORY_AUTH_PROVIDER == "aws_ds_managed_activedirectory":
                _filter = "(&(objectClass=user)(!(sAMAccountName=Admin))(!(sAMAccountName=krbtgt))(!(sAMAccountName=AWS_*)))"
            else:
                _filter = "(&(objectClass=user)(!(sAMAccountName=Administrator))(!(sAMAccountName=krbtgt))(!(sAMAccountName=AWS_*)))"
            _attr_name = "sAMAccountName"

        # Optional bounded typeahead mode: ?q=<2+ chars> returns a small,
        # filtered candidate list with display names (capped via max_results)
        # instead of the full directory -- used by admin user-management
        # pickers so they never render the entire (4000+) user list. Without
        # q the response is unchanged: the full {username: dn} mapping.
        _q = (request.args.get("q") or "").strip()
        _typeahead = Validators.is_string_length_greater_equal_than(_q, 2)
        if _typeahead:
            _cast = SocaCastEngine(request.args.get("max_results", 50)).cast_as(int)
            _max = _cast.message if _cast.success else 50
            _max = max(1, min(_max, 200))

            def _esc_term(_t):
                return (
                    _t.replace("\\", "\\5c").replace("*", "\\2a")
                    .replace("(", "\\28").replace(")", "\\29").replace("\x00", "\\00")
                )

            _groups = "".join(
                f"(|({_attr_name}=*{_e}*)(givenName=*{_e}*)(sn=*{_e}*)(displayName=*{_e}*))"
                for _e in (_esc_term(t) for t in _q.split() if t)
            )
            _filter = f"(&{_filter}{_groups})"

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if _typeahead:
                _res = _soca_identity_client.search(
                    base=config.Config.DIRECTORY_PEOPLE_SEARCH_BASE,
                    scope=ldap.SCOPE_SUBTREE,
                    filter=_filter,
                    attr_list=[_attr_name, "givenName", "sn"],
                    page_size=200,
                    max_results=_max,
                )
                if not _res.success:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Unable to search users because of {_res.message}"
                    ).as_flask()
                _results = []
                for _entry in (_res.message or []):
                    _attrs = _entry[1] or {}
                    _u = (_attrs.get(_attr_name) or [""])[0]
                    _u = _u.decode("utf-8") if Validators.is_bytes(_u) else _u
                    if not _u:
                        continue
                    _gn = (_attrs.get("givenName") or [""])[0]
                    _sn = (_attrs.get("sn") or [""])[0]
                    _gn = _gn.decode("utf-8") if Validators.is_bytes(_gn) else _gn
                    _sn = _sn.decode("utf-8") if Validators.is_bytes(_sn) else _sn
                    _display = f"{_gn} {_sn}".strip() or _u
                    _results.append({"username": _u, "display_name": _display})
                _results.sort(key=lambda r: r["username"].lower())
                return SocaResponse(success=True, message=_results).as_flask()

            _users = _soca_identity_client.search(base=config.Config.DIRECTORY_PEOPLE_SEARCH_BASE,
                                                  scope=ldap.SCOPE_SUBTREE,
                                                  filter=_filter,
                                                  attr_list=[_attr_name])
            if _users.success:
                for user in _users.message:
                    user_base = user[0]
                    username = user[1][_attr_name][0]
                    all_ldap_users[username.decode("utf-8") if Validators.is_bytes(username) else username] = user_base

                return SocaResponse(success=True, message=all_ldap_users).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(helper=f"Unable to list all users because of {_users.message}").as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}").as_flask()

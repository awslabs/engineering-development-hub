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
from decorators import private_api
import os
import sys
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.validators import Validators
from utils.cast import SocaCastEngine
from utils.response import SocaResponse
from utils.config import SocaConfig

logger = logging.getLogger("soca_logger")


class Groups(Resource):
    @private_api
    def get(self):
        """
        Retrieve all LDAP groups
        ---
        openapi: 3.1.0
        operationId: getAllLdapGroups
        tags:
          - Group Management
        summary: Retrieve all LDAP groups
        description: Returns a list of all groups from the configured LDAP directory with their members. Supports optional typeahead mode via the q parameter.
        security:
          - socaAuth: []
        parameters:
          - name: q
            in: query
            required: false
            schema:
              type: string
              minLength: 2
              example: "dev"
            description: Typeahead filter (minimum 2 characters). When provided, returns a small filtered list of matching group names instead of the full directory.
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
            description: Successfully retrieved all LDAP groups
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
                      description: Dictionary of group names to group information
                      additionalProperties:
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
                      example:
                        "developers":
                          group_dn: "cn=developers,ou=group,dc=soca,dc=local"
                          members: ["john.doe", "jane.smith"]
                        "admins":
                          group_dn: "cn=admins,ou=group,dc=soca,dc=local"
                          members: ["admin"]
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
            description: Unable to connect to LDAP server
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
                      example: "Unable to list all groups"
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
        # List all LDAP users
        if config.Config.DIRECTORY_AUTH_PROVIDER in ["openldap", "existing_openldap"]:
            _filter = "objectClass=posixGroup"
            _attr_list = ["cn", "memberUid"]
        else:
            _filter = "objectClass=group"
            _attr_list = ["cn", "member"]

        # Optional bounded typeahead mode: ?q=<2+ chars> returns a small, cn-only
        # filtered group list (capped via max_results) for on-demand pickers
        # instead of the full directory. SOCA creates a private group per user,
        # so the group count meets/exceeds the user count -- this keeps group
        # selectors from rendering thousands of entries. No q = unchanged full
        # {group: {group_dn, members}} mapping.
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

            _cn_clause = "".join(
                f"(cn=*{_e}*)" for _e in (_esc_term(t) for t in _q.split() if t)
            )
            _filter = f"(&({_filter}){_cn_clause})"

        all_ldap_groups = {}
        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            if _typeahead:
                _res = _soca_identity_client.search(
                    base=config.Config.DIRECTORY_GROUP_SEARCH_BASE,
                    scope=ldap.SCOPE_SUBTREE,
                    filter=_filter,
                    attr_list=["cn"],
                    page_size=200,
                    max_results=_max,
                )
                if not _res.success:
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper=f"Unable to search groups because of {_res.message}"
                    ).as_flask()
                _results = []
                for _g in (_res.message or []):
                    _cn = ((_g[1] or {}).get("cn") or [""])[0]
                    _cn = _cn.decode("utf-8") if Validators.is_bytes(_cn) else _cn
                    if _cn:
                        _results.append({"group": _cn})
                _results.sort(key=lambda r: r["group"].lower())
                return SocaResponse(success=True, message=_results).as_flask()

            _groups = _soca_identity_client.search(
                base=config.Config.DIRECTORY_GROUP_SEARCH_BASE,
                scope=ldap.SCOPE_SUBTREE,
                filter=_filter,
                attr_list=_attr_list,
            )
            if _groups.success:
                # ex: ('cn=edhadminsocagroup,ou=group,dc=soca-dev200,dc=local', {'cn': [b'edhadminsocagroup'], 'memberUid': [b'edhadmin']})
                for group in _groups.message:
                    group_base = group[0]
                    group_name = (
                        group[1]["cn"][0].decode("utf-8")
                        if isinstance(group[1]["cn"][0], bytes)
                        else group[1]["cn"][0]
                    )
                    members = []
                    if _attr_list[1] in group[1].keys():
                        for member in group[1][_attr_list[1]]:
                            members.append(
                                member.decode("utf-8")
                                if isinstance(member, bytes)
                                else member
                            )

                    all_ldap_groups[group_name] = {
                        "group_dn": group_base,
                        "members": members,
                    }
                return SocaResponse(success=True, message=all_ldap_groups).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to list all groups because of {_groups.message}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

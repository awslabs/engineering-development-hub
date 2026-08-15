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

import hashlib
import os
from base64 import b64encode as encode
from email.utils import parseaddr
import config
import ldap
from flask_restful import Resource, reqparse
from requests import get
import json
import logging
from decorators import private_api, admin_api, feature_flag
from flask import session
from flask_babel import gettext as _
import ldap.modlist as modlist
from datetime import datetime
import errors
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.error import SocaError
import os
import sys

logger = logging.getLogger("soca_logger")


class Reset(Resource):
    @admin_api
    @feature_flag(flag_name="MY_ACCOUNT_MANAGEMENT", mode="api")
    def post(self):
        """
        Reset user password
        ---
        openapi: 3.1.0
        operationId: resetLdapUserPassword
        tags:
          - User Management
        summary: Reset user password
        description: Reset the password for a specific LDAP user using SSHA encryption
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
                  - password
                properties:
                  user:
                    type: string
                    description: Username of the user whose password will be reset
                    minLength: 1
                    maxLength: 64
                    pattern: '^[a-zA-Z0-9._-]+$'
                    example: "john.doe"
                  password:
                    type: string
                    description: New password for the user
                    minLength: 1
                    format: password
                    example: "NewSecurePass123!"
        responses:
          '200':
            description: Password successfully updated
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
                      example: "Password updated correctly"
          '400':
            description: Missing required parameters
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
            description: Failed to update password
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
                      example: "Unable to reset password for john.doe"
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
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("password", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        password = args["password"]

        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()
        if password is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        dn_user = f"uid={user},{config.Config.DIRECTORY_PEOPLE_SEARCH_BASE}"
        enc_passwd = bytes(password, "utf-8")
        salt = os.urandom(16)
        sha = hashlib.sha1(enc_passwd)  # nosec
        sha.update(salt)
        digest = sha.digest()
        b64_envelop = encode(digest + salt)
        passwd = "{{SSHA}}{}".format(b64_envelop.decode("utf-8"))
        new_value = passwd
        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()
            _soca_identity_client.bind_as_service_account()
            mod_attrs = [(ldap.MOD_REPLACE, "userPassword", new_value.encode("utf-8"))]
            _update = _soca_identity_client.modify(dn=dn_user, mod_list=mod_attrs)
            if _update.success:
                return SocaResponse(
                    success=True, message=_("Password updated correctly")
                ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to reset password for {user} because {_update.message}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

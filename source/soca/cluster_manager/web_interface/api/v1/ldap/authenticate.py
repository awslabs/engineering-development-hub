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
import sys
import os
from decorators import private_api
import logging
from utils.error import SocaError
from utils.identity_provider_client import SocaIdentityProviderClient
from utils.response import SocaResponse
from utils.http_client import SocaHttpClient
import pathlib
import config
import re
from api.v1.ldap.user import create_home, check_ad_authentication_groups
from flask import request
import pwd

logger = logging.getLogger("soca_logger")


class Authenticate(Resource):
    @private_api
    def post(self):
        """
        Authenticate user credentials
        ---
        openapi: 3.1.0
        operationId: authenticateLdapUser
        tags:
          - LDAP management
        summary: Authenticate user credentials
        description: Validate LDAP user credentials and create home directory if needed
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
                    description: Username or DN to authenticate
                    minLength: 1
                    maxLength: 256
                    example: "john.doe"
                  password:
                    type: string
                    description: Password for authentication
                    minLength: 1
                    format: password
                    example: "userPassword123!"
        responses:
          '200':
            description: Authentication successful
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
                      example: "Authentication successful"
          '210':
            description: Invalid credentials
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
                      example: "Invalid username or password"
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
          '401':
            description: Unauthorized access
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
                      example: "Unauthorized"
          '500':
            description: Backend error during authentication
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
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        parser.add_argument("password", type=str, location="form")
        args = parser.parse_args()

        if args.get("user", None) is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()
        
        if re.match(config.Config.USER_REGEX_PATTERN, args["user"]):
            user = args["user"].lower()
        else:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"User {args['user']} is not valid, must match {config.Config.USER_REGEX_PATTERN} (contains -and start with- only alpha-numerical characters plus _ . - and must be 31 chars max"
            ).as_flask()

        password = args.get("password", "")
        if not password:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        try:
            _soca_identity_client = SocaIdentityProviderClient()
            _soca_identity_client.initialize()

            # note: we can pass user as just username or entire base_dn. SocaIdentityProvider will automatically update it
            _user_bind = _soca_identity_client.bind_as_user(dn=user, password=password)
            if _user_bind.success:
                logger.info(
                    f"Successful Login for {user}, validating wheter user also exist in people OU"
                )
                check_user = SocaHttpClient(
                    endpoint="/api/ldap/user",
                    headers={
                        "X-EDH-USER": request.headers.get("X-EDH-USER"),
                        "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                    },
                ).get(params={"user": user})

                if check_user.get("success") is False:
                    logger.error(
                        f"Valid credentials but {user} could not be found in the specified OU. Verify specified People Base OU (/configuration/UserDirectory/people_search_base) and update it via cluster_manager/edhctl config set --key '/configuration/UserDirectory/people_search_base' --value 'MY_NEW_OU'  if needed. error {check_user.get('message')}"
                    )
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper="User could not be found in the directory OU. See logs for more details."
                    ).as_flask()

                _check_groups = check_ad_authentication_groups(username=user)
                if not _check_groups.get("success"):
                    logger.error(
                        f"Valid credentials but {user} is not allowed to log in: {_check_groups.get('message')}. Verify group membership or update /configuration/UserDirectory/ad_authentication_groups if needed."
                    )
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper="Authentication successful, but your account does not belong to any of the groups allowed to access SOCA. Contact your administrator to be added to an authorized group."
                    ).as_flask()

                logger.info(
                    f"{user=} exist in OU, doing a final test to see if the user available on the current system via sssd"
                )

                try:
                    pwd.getpwnam(user)
                    logger.info(f"{user=} exists on this system.")
                except KeyError:
                    logger.error(
                        f"{user=} does not exist on this system as pwd.getpwnam() failed. try to run id <user> and verify sssd.conf ."
                    )
                    return SocaError.IDENTITY_PROVIDER_ERROR(
                        helper="User is valid but does not seems to be available on the SOCA Controller. See log for more details."
                    ).as_flask()

                logger.info(
                    f"Successful Login for {user} and user exist in OU, checking if user has a valid SOCA home ..."
                )
                _home_dir = pathlib.Path(f"{config.Config.USER_HOME}/{user}")
                if _home_dir.exists():
                    logger.info(f"{_home_dir} already exist.")
                else:
                    # Handle case where user login from external AD/LDAP and user was not specifically created by SOCA or if $HOME has been deleted
                    logger.info(f"{_home_dir} does not already exist, creating it ...")
                    # Search for the pattern in the provided DN
                    create_home(
                        username=user,
                        group=f"{user}{config.Config.DIRECTORY_GROUP_NAME_SUFFIX}",
                    )

            return SocaResponse(
                success=_user_bind.success, message=_user_bind.message
            ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

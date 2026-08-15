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

import re
import config
from flask_restful import Resource, reqparse
from flask_babel import gettext as _
import logging
from decorators import private_api, admin_api, feature_flag
import json
import utils.aws.boto3_wrapper as utils_boto3
import os
import sys
from utils.response import SocaResponse
from utils.error import SocaError
import json

logger = logging.getLogger("soca_logger")


class Reset(Resource):
    @admin_api
    @feature_flag(flag_name="MY_ACCOUNT_MANAGEMENT", mode="api")
    def post(self):
        """
        Reset Active Directory user password
        ---
        openapi: 3.1.0
        operationId: resetActiveDirectoryPassword
        tags:
          - User Management
        summary: Reset Active Directory user password
        description: Reset password for a user in AWS Directory Service (Active Directory) with complexity validation
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
                    description: New password (must meet AD complexity requirements - 8-64 chars with 3 of 4 character types)
                    minLength: 8
                    maxLength: 64
                    format: password
                    example: "NewSecurePass123!"
                  directory_id:
                    type: string
                    description: AWS Directory Service ID (uses default if not provided)
                    pattern: '^d-[0-9a-f]{10}$'
                    example: "d-1234567890"
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
            description: Invalid password or missing parameters
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
                      example: "Password cannot contain username"
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
                      example: "john.doe does not seem to exist in this directory"
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
        parser.add_argument("directory_id", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        password = args["password"]
        directory_id = args["directory_id"]
        if directory_id is None:
            logger.info("directory_id not set, defaulting to SOCA DS ID if known.")
            directory_id = config.Config.DIRECTORY_SERVICE_ID

        logger.info(
            f"Received AWS DS password reset request for {user} for directory service: {config.Config.DIRECTORY_SERVICE_ID}"
        )
        if user.lower() in password.lower():
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper="Password cannot contain username"
            ).as_flask()
        ds_password_complexity = r"(?=^.{8,64}$)((?=.*\d)(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[^A-Za-z0-9\s])(?=.*[a-z])|(?=.*[^A-Za-z0-9\s])(?=.*[A-Z])(?=.*[a-z])|(?=.*\d)(?=.*[A-Z])(?=.*[^A-Za-z0-9\s]))^.*"
        if not re.search(ds_password_complexity, password):
            logger.error(
                f"Password did not match complexity, regex is {ds_password_complexity}"
            )
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Password does not meet the required complexity. The password must be 8 to 64 characters long and include at least three of the following four types: uppercase letters, lowercase letters, numbers, and special characters"
            ).as_flask()

        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        if password is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="password").as_flask()

        _ds_client = utils_boto3.get_boto(service_name="ds").message

        try:
            _reset_password = _ds_client.reset_user_password(
                DirectoryId=directory_id, UserName=user, NewPassword=password
            )

            if _reset_password.get("ResponseMetadata").get("HTTPStatusCode") == 200:
                return SocaResponse(
                    success=True, message=_("Password updated correctly")
                ).as_flask()
            else:
                return SocaError.IDENTITY_PROVIDER_ERROR(
                    helper=f"Unable to reset password due to {_reset_password}"
                ).as_flask()
        except _ds_client.exceptions.InvalidPasswordException as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"Password is invalid: {err}"
            ).as_flask()
        except _ds_client.exceptions.UserDoesNotExistException as err:
            return SocaError.IDENTITY_PROVIDER_ERROR(
                helper=f"{user} does not seems to exist in this directory: {err}"
            ).as_flask()
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

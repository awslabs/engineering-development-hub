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
from models import db, ApiKeys
from datetime import datetime, timezone
import secrets
import config
from decorators import restricted_api, admin_api, retrieve_api_key, feature_flag
import logging
from utils.error import SocaError
from utils.http_client import SocaHttpClient
from utils.response import SocaResponse
import os
import sys

logger = logging.getLogger("soca_logger")


class ApiKey(Resource):
    @retrieve_api_key
    @feature_flag(flag_name="MY_API_KEY_MANAGEMENT", mode="api")
    def get(self):
        """
        Retrieve API key for a user
        ---
        openapi: 3.1.0
        operationId: getUserApiKey
        tags:
          - User
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA username for authentication
            example: admin
          - name: X-EDH-PASSWORD
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: SOCA password for the specified user
            example: mypassword
          - name: user
            in: query
            schema:
              type: string
              pattern: '^[a-zA-Z0-9._-]+$'
              minLength: 1
            required: true
            description: Username to retrieve API key for
            example: john.doe
        responses:
          '200':
            description: API key retrieved successfully
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
                      pattern: '^[a-f0-9]{32}$'
                      example: a1b2c3d4e5f6789012345678
          '400':
            description: Missing required parameter
          '401':
            description: Authentication required
          '404':
            description: User not found
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="args")
        args = parser.parse_args()
        user = args["user"]
        logger.debug(f"Retrieving HTTP API Key for user {user}")

        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        try:
            logger.info("Checking if user has active API key")
            check_existing_key = ApiKeys.query.filter_by(
                user=user, is_active=True
            ).first()
            if check_existing_key:
                logger.debug(f"API Key for {user} detected")
                return SocaResponse(
                    success=True, message=check_existing_key.token
                ).as_flask()
            else:
                logger.debug(f"No API Key for {user} detected, creating new one")
                try:
                    user_exist = SocaHttpClient(
                        endpoint="/api/ldap/user",
                        headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                    ).get(params={"user": user})
                    if user_exist.success:
                        permissions = SocaHttpClient(
                            endpoint="/api/ldap/sudo",
                            headers={"X-EDH-TOKEN": config.Config.API_ROOT_KEY},
                        ).get(params={"user": user})
                        if permissions.success:
                            logger.debug("User has SUDO permission")
                            scope = "sudo"
                        else:
                            logger.debug("User does NOT have SUDO permission")
                            scope = "user"

                        api_token = secrets.token_hex(16)
                        new_key = ApiKeys(
                            user=user,
                            token=api_token,
                            is_active=True,
                            scope=scope,
                            created_on=datetime.now(timezone.utc),
                        )
                        try:
                            db.session.add(new_key)
                            db.session.commit()
                        except Exception as err:
                            db.session.rollback()
                            return SocaError.DB_ERROR(
                                query=new_key,
                                helper=f"Unable to save new API key on DB due to {err}",
                            ).as_flask()

                        return SocaResponse(success=True, message=api_token).as_flask()
                    else:
                        return SocaError.HTTP_ERROR(
                            endpoint="/api/ldap/user",
                            method="get",
                            helper="Unable to check API key for user. Check logs",
                        ).as_flask()

                except Exception as err:
                    exc_type, exc_obj, exc_tb = sys.exc_info()
                    fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                    return SocaError.GENERIC_ERROR(
                        helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
                    ).as_flask()
        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

    @restricted_api
    @feature_flag(flag_name="MY_API_KEY_MANAGEMENT", mode="api")
    def delete(self):
        """
        Delete API key(s) for a user
        ---
        openapi: 3.1.0
        operationId: deleteUserApiKey
        tags:
          - User
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
                  - user
                properties:
                  user:
                    type: string
                    pattern: '^[a-zA-Z0-9._-]+$'
                    minLength: 1
                    description: Username to delete API key for
                    example: john.doe
        responses:
          '200':
            description: API key(s) deleted successfully
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
                      example: Successfully deactivated
          '400':
            description: Missing required parameter
          '401':
            description: Authentication required
          '404':
            description: No active API key found for user
        """
        parser = reqparse.RequestParser()
        parser.add_argument("user", type=str, location="form")
        args = parser.parse_args()
        user = args["user"]
        if user is None:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()
        logger.debug(f"Deleting API Key for {user}")
        try:
            logger.info(f"Checking if user {user} has active API key")
            check_existing_keys = ApiKeys.query.filter_by(
                user=user, is_active=True
            ).all()
            if check_existing_keys:
                logger.debug(f"API Key for {user} detected: {check_existing_keys}")
                for key in check_existing_keys:
                    key.is_active = False
                    key.deactivated_on = datetime.now(timezone.utc)
                    try:
                        db.session.commit()
                    except Exception as err:
                        db.session.rollback()
                        return SocaError.DB_ERROR(
                            query=key,
                            helper=f"Unable to deactivate key in DB due to {err}",
                        ).as_flask()
                return SocaResponse(
                    success=True, message=_("Successfully deactivated")
                ).as_flask()
            else:
                logger.info("No active token found")
                return SocaError.API_KEY_ERROR(
                    helper=f"No active token found for {user}"
                ).as_flask()

        except Exception as err:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
            return SocaError.GENERIC_ERROR(
                helper=f"{err}, {exc_type}, {fname}, {exc_tb.tb_lineno}"
            ).as_flask()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
import logging
from utils.response import SocaResponse
from flask import request
from flask_babel import gettext as _
from werkzeug.datastructures import FileStorage
import json
from utils.error import SocaError
from utils.http_client import SocaHttpClient
from decorators import admin_api, feature_flag
from models import ApplicationProfiles

logger = logging.getLogger("soca_logger")


class ImportApplication(Resource):
    @feature_flag(flag_name="HPC", mode="api")
    @admin_api
    def post(self):
        """
        Import application profile
        ---
        openapi: 3.1.0
        operationId: importApplicationProfile
        tags:
          - Applications
        summary: Import application profile
        description: Imports an application profile from a JSON file (admin access required)
        parameters:
          - in: header
            name: X-EDH-USER
            required: true
            schema:
              type: string
              minLength: 1
              maxLength: 100
              pattern: '^[a-zA-Z0-9._-]+$'
            description: SOCA username for authentication (must be admin)
            example: "admin.user"
          - in: header
            name: X-EDH-TOKEN
            required: true
            schema:
              type: string
              minLength: 10
              maxLength: 1000
            description: SOCA authentication token
            example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
        requestBody:
          required: true
          content:
            multipart/form-data:
              schema:
                type: object
                required:
                  - app_profile
                  - profile_name
                properties:
                  app_profile:
                    type: string
                    format: binary
                    description: JSON file containing application profile configuration
                  profile_name:
                    type: string
                    minLength: 1
                    maxLength: 100
                    description: Name to assign to the imported application profile
                    example: "ANSYS Fluent"
        responses:
          '200':
            description: Application profile imported successfully
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
                      example: "Application Imported successfully"
          '400':
            description: Invalid JSON file or missing parameters
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 400
                    message:
                      type: string
                      example: "This does not seem to be a valid JSON"
          '403':
            description: Insufficient permissions
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: false
                    error_code:
                      type: integer
                      example: 403
                    message:
                      type: string
                      example: "Admin access required"
          '500':
            description: Server error during import
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
                      example: "Unable to import file. See log for details"
        """
        parser = reqparse.RequestParser()
        parser.add_argument(
            "app_profile", type=FileStorage, location="files", required=True
        )
        parser.add_argument("profile_name", type=str, location="form")

        args = parser.parse_args()
        _app_profile = args.get("app_profile", "")
        _profile_name = args.get("profile_name", "")

        if not _profile_name:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="profile_name").as_flask()

        try:
            _app_profile_content = _app_profile.read()
            _app_profile_input = json.loads(_app_profile_content)
            _create_application = SocaHttpClient(
                "/api/applications/application",
                headers={
                    "X-EDH-TOKEN": request.headers.get("X-EDH-TOKEN"),
                    "X-EDH-USER": request.headers.get("X-EDH-USER"),
                },
            ).post(
                data={
                    "submit_job_script": _app_profile_input.get(
                        "profile_job", ""
                    ),
                    "submit_job_form": _app_profile_input.get("profile_form", ""),
                    "submit_job_interpreter": _app_profile_input.get(
                        "profile_interpreter", ""
                    ),
                    "profile_name": _profile_name,
                    "thumbnail_b64": _app_profile_input.get("thumbnail_b64", ""),
                }
            )
     
            if _create_application.get("success") is True:
                return SocaResponse(
                    success=True, message=_("Application Imported successfully")
                ).as_flask()
            else:
                logger.error(
                    f"Unable to import file due to {_create_application.get('message')}"
                )
                return SocaError.GENERIC_ERROR(
                    helper=f"Unable to import file due to {_create_application.get('message')}"
                ).as_flask()

        except json.JSONDecodeError as err:
            logger.error(f"Unable to read JSON due to {err}")
            return SocaError.GENERIC_ERROR(
                helper="This does not seem to be a valid JSON. See log for additional details."
            ).as_flask()
        except Exception as err:
            logger.error(f"Unable to import application due to {err}")
            return SocaError.GENERIC_ERROR(
                helper="This does not seem to be a valid JSON. See log for additional details."
            ).as_flask()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
import logging
from utils.response import SocaResponse
from utils.error import SocaError
from utils.cast import SocaCastEngine
from decorators import admin_api, feature_flag
from models import ApplicationProfiles

logger = logging.getLogger("soca_logger")


class ExportApplication(Resource):
    @feature_flag(flag_name="HPC", mode="api")
    @admin_api
    def get(self):
        """
        Export application profile
        ---
        openapi: 3.1.0
        operationId: exportApplicationProfile
        tags:
          - Applications
        summary: Export application profile
        description: Exports an application profile configuration for backup or migration (admin access required)
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
          - in: query
            name: application_id
            required: true
            schema:
              type: string
              pattern: '^[0-9]+$'
            description: ID of the application profile to export
            example: "1"
        responses:
          '200':
            description: Application profile exported successfully
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
                        "Instructions:":
                          type: string
                          example: "https://awslabs.github.io/engineering-development-hub-documentation/documentation/web-interface/import-export-application-profiles"
                        profile_form:
                          type: string
                          example: "<form><input name='cores' type='number' /></form>"
                        profile_job:
                          type: string
                          example: "#!/bin/bash\nmodule load ansys\nfluent -g"
                        profile_interpreter:
                          type: string
                          example: "bash"
                        profile_thumbnail:
                          type: string
                          example: "data:image/png;base64,..."
          '400':
            description: Missing application_id parameter
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
                      example: "Missing required parameter: application_id"
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
            description: Server error (includes application not found or invalid application_id)
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
                      example: "Application does not exist"
        """
        parser = reqparse.RequestParser()
        parser.add_argument("application_id", type=str, location="args")
        args = parser.parse_args()
        _application_id = args.get("application_id", "")
        logger.info(f"About to generate Export file for application {_application_id=}")
        if not _application_id:
            return SocaError.CLIENT_MISSING_PARAMETER(
                parameter_name="application_id"
            ).as_flask()

        _app_id_cast = SocaCastEngine(data=_application_id).cast_as(int)
        if _app_id_cast.get("success") is not True:
            return SocaError.GENERIC_ERROR(
                helper="application_id is not a valid integer"
            ).as_flask()
        _profile = ApplicationProfiles.query.filter_by(
            id=_app_id_cast.get("message")
        ).first()
        if _profile:
            output = {
                "Instructions:": "https://awslabs.github.io/engineering-development-hub-documentation/documentation/web-interface/import-export-application-profiles",
                "profile_form": _profile.profile_form,
                "profile_job": _profile.profile_job,
                "profile_interpreter": _profile.profile_interpreter,
                "profile_thumbnail": _profile.profile_thumbnail,
            }
            return SocaResponse(success=True, message=output).as_flask()
        else:
            logger.error(f"Application profile with id {_application_id} not found")
            return SocaError.GENERIC_ERROR(
                helper="Application does not exist"
            ).as_flask()

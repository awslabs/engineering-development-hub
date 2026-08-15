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

class ListApplications(Resource):
    @feature_flag(flag_name="HPC", mode="api")
    @admin_api
    def get(self):
        """
        Get application profiles
        ---
        openapi: 3.1.0
        operationId: listApplications
        tags:
          - Applications
        summary: Get application profiles
        description: Retrieves all application profiles (admin access required)
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
            required: false
            schema:
              type: string
              pattern: '^[0-9]+$'
              example: "1"
            description: Specific application ID to retrieve (returns all if not specified)
        responses:
          '200':
            description: Application profiles retrieved successfully
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                      example: true
                    message:
                      type: array
                      items:
                        type: object
                        properties:
                          id:
                            type: integer
                            example: 1
                          profile_name:
                            type: string
                            example: "ANSYS Fluent"
                          created_by:
                            type: string
                            example: "admin"
                          profile_form:
                            type: string
                            example: "<form>...</form>"
                          profile_job:
                            type: string
                            example: "#!/bin/bash\n..."
                          profile_interpreter:
                            type: string
                            example: "bash"
                          profile_thumbnail:
                            type: string
                            example: "data:image/png;base64,..."
                          acl_allowed_users:
                            type: string
                            example: "user1,user2"
                          acl_restricted_users:
                            type: string
                            example: "restricted_user"
                          created_on:
                            type: string
                            format: date-time
                            example: "2024-01-15T10:30:00Z"
                          deactivated_on:
                            type: string
                            format: date-time
                            nullable: true
                            example: null
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
            description: Server error
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
                      example: "Error retrieving applications profile list, check logs for more details."
        """
        parser = reqparse.RequestParser()
        parser.add_argument("application_id", type=str, location="args")
        args = parser.parse_args()
        _application_id = args.get("application_id", "")
        logger.debug(f"List applications received parameters: {_application_id=}")
        try:
            _application_profiles = []
            if _application_id:
                _app_id_cast = SocaCastEngine(data=_application_id).cast_as(int)
                _profile = (
                    ApplicationProfiles.query.filter_by(
                        id=_app_id_cast.get("message")
                    ).first()
                    if _app_id_cast.get("success") is True
                    else None
                )
                if _profile:
                    _application_profiles = [_profile]
                else:
                    logger.error(f"Application profile with id {_application_id} not found")
                    
            else:
                _application_profiles = ApplicationProfiles.query.all()
           
            return SocaResponse(success=True, message=[p.as_dict() for p in _application_profiles]).as_flask()

        except Exception as e:
            logger.error(f"Error retrieving application profile list: {str(e)}")
            return SocaError.GENERIC_ERROR(
                helper=f"Error retrieving applications profile list, check logs for more details."
            ).as_flask()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

from flask_restful import Resource
from flask_babel import gettext as _

from decorators import private_api, feature_flag
from utils.token_service import load_token_policy
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class UserTokenPolicy(Resource):
    @private_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def get(self):
        """
        Get current token policy
        ---
        openapi: 3.1.0
        operationId: getUserTokenPolicy
        tags:
          - Token
        summary: Get the current token policy
        description: Returns the admin-configured token policy that governs token creation, lifetime, and renewal limits. Read-only for non-admin users.
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
            description: SOCA username for authentication
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
            description: SOCA authentication token
        responses:
          '200':
            description: Token policy retrieved successfully
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
                        max_tokens_per_user:
                          type: integer
                          description: Maximum number of active tokens per user
                        max_lifetime_hours:
                          type: integer
                          description: Maximum token lifetime in hours
                        default_lifetime_hours:
                          type: integer
                          description: Default token lifetime when not specified
                        max_renewals:
                          type: integer
                          description: Maximum number of times a token can be renewed
                        renewal_allowed:
                          type: boolean
                          description: Whether token renewal is allowed globally
                        require_expiration:
                          type: boolean
                          description: Whether tokens must have an expiration
                        global_deny:
                          type: object
                          description: Paths that are denied for all scoped tokens
                          additionalProperties:
                            type: array
                            items:
                              type: string
          '401':
            description: Authentication required
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
        """
        policy = load_token_policy()
        return SocaResponse(success=True, message=policy).as_flask()

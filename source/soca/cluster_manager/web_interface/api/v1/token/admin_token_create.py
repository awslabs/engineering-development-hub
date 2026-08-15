# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

from flask import request, session
from flask_restful import Resource, reqparse
from flask_babel import gettext as _

from decorators import admin_api, feature_flag
from utils.token_service import (
    create_token,
    count_active_user_tokens,
    load_token_policy,
    validate_permissions_structure,
)
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


class AdminTokenCreate(Resource):
    @admin_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def post(self, target_user):
        """
        Create a token on behalf of a user (admin)
        ---
        openapi: 3.1.0
        operationId: adminCreateToken
        tags:
          - Token (Admin)
        summary: Create a scoped API token for a specific user
        description: |
          Allows an admin to create a scoped API token on behalf of any user. The token
          is returned in plaintext only once. Subject to the same token policy limits
          (max tokens per user, max lifetime).
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
            description: Admin username
          - name: X-EDH-TOKEN
            in: header
            required: true
            schema:
              type: string
            description: Admin authentication token
          - name: target_user
            in: path
            required: true
            schema:
              type: string
            description: Username to create the token for
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - name
                  - permissions
                properties:
                  name:
                    type: string
                    minLength: 1
                    maxLength: 100
                    description: Human-readable label for the token
                  permissions:
                    type: object
                    description: "Scoped permission map, e.g. {\"allow\": {\"/api/user/*\": [\"GET\"]}}"
                    properties:
                      allow:
                        type: object
                        additionalProperties:
                          type: array
                          items:
                            type: string
                            enum: ["GET", "POST", "PUT", "DELETE", "*"]
                  lifetime_hours:
                    type: integer
                    minimum: 1
                    description: Token lifetime in hours. Capped by admin policy.
                  renewable:
                    type: boolean
                    default: true
                    description: Whether this token can be renewed
        responses:
          '200':
            description: Token created successfully
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
                        id:
                          type: integer
                        token:
                          type: string
                          description: The plaintext token (only shown once)
                        name:
                          type: string
                        hint:
                          type: string
                        user:
                          type: string
                        permissions:
                          type: object
                        expires_at:
                          type: string
                          format: date-time
                        renewable:
                          type: boolean
                        created_by:
                          type: string
          '400':
            description: Invalid parameters
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
          '401':
            description: Not authorized (requires admin privileges)
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
          '409':
            description: Token limit reached for the target user
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
        admin_user = request.headers.get("X-EDH-USER") or session.get("user")

        parser = reqparse.RequestParser()
        parser.add_argument("name", type=str, required=True, location="json")
        parser.add_argument("permissions", type=dict, required=True, location="json")
        parser.add_argument("lifetime_hours", type=int, required=False, location="json")
        parser.add_argument("renewable", type=bool, required=False, default=True, location="json")
        args = parser.parse_args()

        token_name = args["name"]
        permissions = args["permissions"]
        renewable = args["renewable"]

        if not token_name or Validators.is_string_length_greater_than(token_name, 100):
            return {"success": False, "message": "Token name must be 1-100 characters"}, 400

        valid, err = validate_permissions_structure(permissions)
        if not valid:
            return {"success": False, "message": err}, 400

        policy = load_token_policy()

        active_count = count_active_user_tokens(target_user)
        max_tokens = policy.get("max_tokens_per_user", 5)
        if Validators.is_int_greater_or_equal(active_count, max_tokens):
            return {
                "success": False,
                "message": f"Token limit reached for user '{target_user}' ({max_tokens}).",
            }, 409

        max_lifetime = policy.get("max_lifetime_hours", 720)
        default_lifetime = policy.get("default_lifetime_hours", 24)
        requested_lifetime = args.get("lifetime_hours") or default_lifetime
        lifetime_hours = min(requested_lifetime, max_lifetime)
        if Validators.is_int_lower_than(lifetime_hours, 1):
            lifetime_hours = 1

        plaintext, record = create_token(
            user=target_user,
            name=token_name,
            permissions=permissions,
            lifetime_hours=lifetime_hours,
            created_by=admin_user or "_admin",
            renewable=renewable,
            max_renewals=policy.get("max_renewals", 10),
            token_type="user",
        )

        return SocaResponse(
            success=True,
            message={
                "id": record.id,
                "token": plaintext,
                "name": record.name,
                "hint": record.token_hint,
                "user": target_user,
                "permissions": permissions,
                "expires_at": record.expires_at.isoformat() + "Z",
                "renewable": record.renewable,
                "created_by": record.created_by,
            },
        ).as_flask()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from datetime import datetime, timezone

from flask import request
from flask_restful import Resource, reqparse
from flask_babel import gettext as _

from decorators import feature_flag, validate_password
from models import ApiTokens
from utils.token_service import (
    create_token,
    count_active_user_tokens,
    load_token_policy,
    validate_permissions_structure,
)
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


class UserTokenAuthenticate(Resource):
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def post(self):
        """
        Authenticate with username/password and create a scoped API token
        ---
        openapi: 3.1.0
        operationId: authenticateAndCreateToken
        tags:
          - Token
        summary: Create a token via password authentication
        description: |
          Entry point for programmatic callers (CI/CD, scripts) that do not have an
          existing token. Authenticates using LDAP username/password and returns a new
          scoped API token. The plaintext token is only shown once in the response.
          Subject to the admin-configured token policy.
        parameters:
          - name: X-EDH-USER
            in: header
            required: true
            schema:
              type: string
            description: SOCA username (LDAP)
          - name: X-EDH-PASSWORD
            in: header
            required: true
            schema:
              type: string
            description: User's LDAP password
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
                        permissions:
                          type: object
                        expires_at:
                          type: string
                          format: date-time
                        renewable:
                          type: boolean
          '400':
            description: Invalid parameters (bad name, invalid permissions, or expiration required)
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
            description: Invalid credentials or missing headers
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
          '403':
            description: Path blocked by admin policy
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
            description: Token limit reached for this user
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
                    existing_tokens:
                      type: array
                      items:
                        type: object
                        properties:
                          name:
                            type: string
                          hint:
                            type: string
        """
        user = request.headers.get("X-EDH-USER")
        password = request.headers.get("X-EDH-PASSWORD")

        if not user or not password:
            return {"success": False, "message": "X-EDH-USER and X-EDH-PASSWORD headers are required."}, 401

        if not validate_password(user=user, password=password):
            return {"success": False, "message": "Invalid credentials."}, 401

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

        active_count = count_active_user_tokens(user)
        max_tokens = policy.get("max_tokens_per_user", 5)
        if Validators.is_int_greater_or_equal(active_count, max_tokens):
            existing = (
                ApiTokens.query.filter_by(user=user, token_type="user")
                .filter(ApiTokens.revoked_at.is_(None))
                .filter(ApiTokens.expires_at > datetime.now(timezone.utc))
                .all()
            )
            hints = [{"name": t.name, "hint": t.token_hint} for t in existing]
            return {
                "success": False,
                "message": f"Token limit reached ({max_tokens}). Revoke an existing token first.",
                "existing_tokens": hints,
            }, 409

        max_lifetime = policy.get("max_lifetime_hours", 720)
        require_expiration = policy.get("require_expiration", True)
        requested_lifetime = args.get("lifetime_hours")

        if not requested_lifetime or Validators.is_int_lower_or_equal(requested_lifetime, 0):
            if require_expiration:
                return {"success": False, "message": "Unlimited lifetime is not allowed by policy. Specify lifetime_hours."}, 400
            lifetime_hours = max_lifetime
        else:
            lifetime_hours = min(requested_lifetime, max_lifetime)
            if Validators.is_int_lower_than(lifetime_hours, 1):
                lifetime_hours = 1

        global_deny = policy.get("global_deny", {})
        allow_paths = permissions.get("allow", {})
        for allow_path in allow_paths:
            for deny_pattern in global_deny:
                if deny_pattern.endswith("*"):
                    if allow_path.startswith(deny_pattern[:-1]):
                        return {
                            "success": False,
                            "message": f"Path '{allow_path}' is blocked by admin policy (global_deny: '{deny_pattern}')",
                        }, 403
                else:
                    if allow_path == deny_pattern:
                        return {
                            "success": False,
                            "message": f"Path '{allow_path}' is blocked by admin policy",
                        }, 403

        plaintext, record = create_token(
            user=user,
            name=token_name,
            permissions=permissions,
            lifetime_hours=lifetime_hours,
            created_by=user,
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
                "permissions": permissions,
                "expires_at": record.expires_at.isoformat() + "Z",
                "renewable": record.renewable,
            },
        ).as_flask()

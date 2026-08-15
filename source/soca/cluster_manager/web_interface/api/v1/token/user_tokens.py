# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from datetime import datetime, timezone

from flask import request, session
from flask_restful import Resource, reqparse
from flask_babel import gettext as _

from decorators import private_api, feature_flag
from extensions import db
from models import ApiTokens
from utils.token_service import (
    create_token,
    count_active_user_tokens,
    load_token_policy,
    validate_permissions_structure,
)
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


class UserTokens(Resource):
    @private_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def get(self):
        """
        List the caller's active tokens
        ---
        openapi: 3.1.0
        operationId: listUserTokens
        tags:
          - Token
        summary: List active API tokens for the authenticated user
        description: Returns all non-revoked, non-expired scoped API tokens owned by the caller. Session tokens are excluded.
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
            description: Token list retrieved successfully
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
                          name:
                            type: string
                          hint:
                            type: string
                            description: Last 8 characters of the token
                          permissions:
                            type: object
                          expires_at:
                            type: string
                            format: date-time
                            nullable: true
                          renewable:
                            type: boolean
                          renewal_count:
                            type: integer
                          max_renewals:
                            type: integer
                            nullable: true
                          last_used_at:
                            type: string
                            format: date-time
                            nullable: true
                          last_used_ip:
                            type: string
                            nullable: true
                          created_at:
                            type: string
                            format: date-time
                          created_by:
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
        user = request.headers.get("X-EDH-USER") or session.get("user")
        if not user:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

        now = datetime.now(timezone.utc)
        tokens = (
            ApiTokens.query.filter_by(user=user, token_type="user")
            .filter(ApiTokens.revoked_at.is_(None))
            .filter(ApiTokens.expires_at > now)
            .order_by(ApiTokens.created_at.desc())
            .all()
        )

        result = []
        for t in tokens:
            result.append(
                {
                    "id": t.id,
                    "name": t.name,
                    "hint": t.token_hint,
                    "permissions": json.loads(t.permissions),
                    "expires_at": None if t.expires_at.year >= 9999 else t.expires_at.isoformat() + "Z",
                    "renewable": t.renewable,
                    "renewal_count": t.renewal_count,
                    "max_renewals": t.max_renewals,
                    "last_used_at": t.last_used_at.isoformat() + "Z" if t.last_used_at else None,
                    "last_used_ip": t.last_used_ip,
                    "created_at": t.created_at.isoformat() + "Z",
                    "created_by": t.created_by,
                }
            )

        return SocaResponse(success=True, message=result).as_flask()

    @private_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def post(self):
        """
        Create a new scoped API token
        ---
        openapi: 3.1.0
        operationId: createUserToken
        tags:
          - Token
        summary: Create a scoped API token
        description: |
          Create a new scoped API token for the authenticated user. The token is returned
          in plaintext only once in the response; it cannot be retrieved again. Token
          creation is subject to the admin-configured token policy (max tokens per user,
          max lifetime, global deny paths).
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
                    description: Token lifetime in hours. Capped by admin policy max_lifetime_hours. Defaults to policy default_lifetime_hours.
                  renewable:
                    type: boolean
                    default: true
                    description: Whether this token can be renewed after creation
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
            description: Token limit reached
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
        user = request.headers.get("X-EDH-USER") or session.get("user")
        if not user:
            return SocaError.CLIENT_MISSING_PARAMETER(parameter="user").as_flask()

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
        default_lifetime = policy.get("default_lifetime_hours", 24)
        require_expiration = policy.get("require_expiration", True)
        body = request.get_json(silent=True) or {}
        requested_lifetime = body.get("lifetime_hours") if "lifetime_hours" in body else None

        if requested_lifetime is None:
            lifetime_hours = default_lifetime
        elif Validators.is_int_lower_or_equal(requested_lifetime, 0):
            if require_expiration:
                return {"success": False, "message": "Unlimited lifetime is not allowed by policy. Specify lifetime_hours."}, 400
            lifetime_hours = 0
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

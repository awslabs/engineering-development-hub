# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging

from flask import request
from flask_restful import Resource, reqparse
from flask_babel import gettext as _

from decorators import admin_api, feature_flag
from utils.token_service import load_token_policy, _policy_cache
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")

_VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "*"}


class AdminTokenPolicy(Resource):
    @admin_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def get(self):
        """
        Get current token policy (admin)
        ---
        openapi: 3.1.0
        operationId: adminGetTokenPolicy
        tags:
          - Token (Admin)
        summary: Get the current token policy
        description: Returns the full admin-configured token policy. Requires admin (sudo) privileges.
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
                        max_lifetime_hours:
                          type: integer
                        default_lifetime_hours:
                          type: integer
                        max_renewals:
                          type: integer
                        renewal_allowed:
                          type: boolean
                        require_expiration:
                          type: boolean
                        global_deny:
                          type: object
                          additionalProperties:
                            type: array
                            items:
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
        """
        policy = load_token_policy()
        return SocaResponse(success=True, message=policy).as_flask()

    @admin_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def put(self):
        """
        Update token policy (admin)
        ---
        openapi: 3.1.0
        operationId: adminUpdateTokenPolicy
        tags:
          - Token (Admin)
        summary: Update the token policy
        description: |
          Merge-updates the token policy. Only the fields provided in the request body
          are updated; unspecified fields retain their current values. Requires admin
          (sudo) privileges. Changes take effect immediately for new token operations.
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
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                properties:
                  max_tokens_per_user:
                    type: integer
                    minimum: 1
                    maximum: 50
                    description: Maximum number of active tokens per user
                  max_lifetime_hours:
                    type: integer
                    minimum: 1
                    maximum: 8760
                    description: Maximum token lifetime in hours (up to 1 year)
                  default_lifetime_hours:
                    type: integer
                    minimum: 1
                    description: Default token lifetime when not specified by user
                  max_renewals:
                    type: integer
                    minimum: 0
                    maximum: 100
                    description: Maximum number of renewals per token
                  renewal_allowed:
                    type: boolean
                    description: Whether token renewal is allowed globally
                  require_expiration:
                    type: boolean
                    description: Whether all tokens must have an expiration
                  global_deny:
                    type: object
                    description: "Paths blocked for all scoped tokens. Keys are path patterns (prefix with /api/, suffix with * for wildcard). Values are arrays of HTTP methods."
                    additionalProperties:
                      type: array
                      items:
                        type: string
                        enum: ["GET", "POST", "PUT", "DELETE", "*"]
        responses:
          '200':
            description: Policy updated successfully (returns merged policy)
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
                        max_lifetime_hours:
                          type: integer
                        default_lifetime_hours:
                          type: integer
                        max_renewals:
                          type: integer
                        renewal_allowed:
                          type: boolean
                        require_expiration:
                          type: boolean
                        global_deny:
                          type: object
          '400':
            description: Validation error in policy values
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
        """
        body = request.get_json(force=True, silent=True) or {}

        errors = []

        # --- Validate max_tokens_per_user ---
        if "max_tokens_per_user" in body:
            val = body["max_tokens_per_user"]
            if not Validators.is_int(val) or Validators.is_int_lower_than(val, 1) or Validators.is_int_greater_than(val, 50):
                errors.append("max_tokens_per_user must be an integer between 1 and 50")

        # --- Validate max_lifetime_hours ---
        if "max_lifetime_hours" in body:
            val = body["max_lifetime_hours"]
            if not Validators.is_int(val) or Validators.is_int_lower_than(val, 1) or Validators.is_int_greater_than(val, 8760):
                errors.append("max_lifetime_hours must be an integer between 1 and 8760")

        # --- Validate default_lifetime_hours ---
        if "default_lifetime_hours" in body:
            val = body["default_lifetime_hours"]
            max_lt = body.get("max_lifetime_hours") or load_token_policy().get("max_lifetime_hours", 8760)
            if not Validators.is_int(val) or Validators.is_int_lower_than(val, 1) or Validators.is_int_greater_than(val, max_lt):
                errors.append(
                    f"default_lifetime_hours must be an integer between 1 and {max_lt}"
                )

        # --- Validate max_renewals ---
        if "max_renewals" in body:
            val = body["max_renewals"]
            if not Validators.is_int(val) or Validators.is_int_lower_than(val, 0) or Validators.is_int_greater_than(val, 100):
                errors.append("max_renewals must be an integer between 0 and 100")

        # --- Validate renewal_allowed ---
        if "renewal_allowed" in body:
            val = body["renewal_allowed"]
            if not Validators.is_bool(val):
                errors.append("renewal_allowed must be a boolean")

        # --- Validate require_expiration ---
        if "require_expiration" in body:
            val = body["require_expiration"]
            if not Validators.is_bool(val):
                errors.append("require_expiration must be a boolean")

        # --- Validate global_deny ---
        if "global_deny" in body:
            val = body["global_deny"]
            if not isinstance(val, dict):
                errors.append("global_deny must be a dict")
            else:
                for path_pattern, methods in val.items():
                    if not path_pattern.startswith("/api/"):
                        errors.append(
                            f"global_deny key '{path_pattern}' must start with /api/"
                        )
                    if not isinstance(methods, list):
                        errors.append(
                            f"global_deny value for '{path_pattern}' must be a list"
                        )
                    else:
                        for m in methods:
                            if m not in _VALID_METHODS:
                                errors.append(
                                    f"global_deny method '{m}' is not valid; "
                                    f"allowed: GET, POST, PUT, DELETE, *"
                                )

        if errors:
            return SocaResponse(success=False, message="; ".join(errors)).as_flask()

        # Load current policy and merge provided fields
        current_policy = load_token_policy()
        allowed_keys = {
            "max_tokens_per_user",
            "max_lifetime_hours",
            "default_lifetime_hours",
            "max_renewals",
            "renewal_allowed",
            "require_expiration",
            "global_deny",
        }
        merged_policy = {**current_policy}
        for key in allowed_keys:
            if key in body:
                merged_policy[key] = body[key]

        # Persist via SocaConfig
        SocaConfig(key="/configuration/Security/api_token_policy").set_value(
            json.dumps(merged_policy)
        )

        # Invalidate token_service policy cache
        _policy_cache["expires"] = 0

        return SocaResponse(success=True, message=merged_policy).as_flask()

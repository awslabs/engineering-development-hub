# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging
from datetime import datetime, timezone

from flask import request
from flask_restful import Resource
from flask_babel import gettext as _

from decorators import admin_api, feature_flag
from models import ApiTokens
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class AdminTokens(Resource):
    @admin_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def get(self):
        """
        List all active tokens (admin)
        ---
        openapi: 3.1.0
        operationId: adminListTokens
        tags:
          - Token (Admin)
        summary: List all active tokens across users
        description: |
          Returns all non-revoked, non-expired user-type tokens. Optionally filter by
          a specific user via query parameter. Requires admin (sudo) privileges.
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
          - name: user
            in: query
            required: false
            schema:
              type: string
            description: Filter tokens by a specific username
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
                          user:
                            type: string
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
                          renewal_count:
                            type: integer
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
        filter_user = request.args.get("user")
        now = datetime.now(timezone.utc)

        query = (
            ApiTokens.query.filter_by(token_type="user")
            .filter(ApiTokens.revoked_at.is_(None))
            .filter(ApiTokens.expires_at > now)
        )
        if filter_user:
            query = query.filter_by(user=filter_user)

        tokens = query.order_by(ApiTokens.created_at.desc()).all()

        result = []
        for t in tokens:
            result.append(
                {
                    "id": t.id,
                    "user": t.user,
                    "name": t.name,
                    "hint": t.token_hint,
                    "permissions": json.loads(t.permissions),
                    "expires_at": t.expires_at.isoformat() + "Z",
                    "renewable": t.renewable,
                    "renewal_count": t.renewal_count,
                    "last_used_at": t.last_used_at.isoformat() + "Z" if t.last_used_at else None,
                    "last_used_ip": t.last_used_ip,
                    "created_at": t.created_at.isoformat() + "Z",
                    "created_by": t.created_by,
                }
            )

        return SocaResponse(success=True, message=result).as_flask()

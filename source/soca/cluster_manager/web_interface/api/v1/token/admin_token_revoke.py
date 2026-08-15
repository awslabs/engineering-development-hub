# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from datetime import datetime, timezone

from flask_restful import Resource
from flask_babel import gettext as _

from decorators import admin_api, feature_flag
from extensions import db
from models import ApiTokens
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


class AdminTokenRevoke(Resource):
    @admin_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def delete(self, target_user, token_id):
        """
        Force-revoke a user's token (admin)
        ---
        openapi: 3.1.0
        operationId: adminRevokeToken
        tags:
          - Token (Admin)
        summary: Force-revoke a specific user's token
        description: Allows an admin to revoke any user's token regardless of ownership. The token will immediately stop authenticating.
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
            description: Username who owns the token
          - name: token_id
            in: path
            required: true
            schema:
              type: integer
            description: ID of the token to revoke
        responses:
          '200':
            description: Token revoked successfully
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
                      example: "Token revoked"
          '400':
            description: Token already revoked
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
          '404':
            description: Token not found or does not belong to the specified user
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
        record = db.session.get(ApiTokens, token_id)
        if not record or not Validators.is_string_equal(record.user, target_user) or not Validators.is_string_equal(record.token_type, "user"):
            return {"success": False, "message": "Token not found"}, 404

        if record.revoked_at:
            return {"success": False, "message": "Token already revoked"}, 400

        record.revoked_at = datetime.now(timezone.utc)
        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=record, helper=f"Failed to revoke token: {err}"
            ).as_flask()

        return SocaResponse(success=True, message="Token revoked").as_flask()

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from datetime import datetime, timezone

from flask import request, session
from flask_restful import Resource
from flask_babel import gettext as _

from decorators import private_api, feature_flag
from extensions import db
from models import ApiTokens
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


class UserTokenDetail(Resource):
    @private_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def delete(self, token_id):
        """
        Revoke a specific token
        ---
        openapi: 3.1.0
        operationId: revokeUserToken
        tags:
          - Token
        summary: Revoke one of the caller's API tokens
        description: Permanently revokes the specified token. The token will no longer authenticate API requests.
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
          '404':
            description: Token not found or does not belong to the caller
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

        record = db.session.get(ApiTokens, token_id)
        if not record or not Validators.is_string_equal(record.user, user) or not Validators.is_string_equal(record.token_type, "user"):
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

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging
from datetime import datetime, timedelta, timezone

from flask import request, session
from flask_restful import Resource
from flask_babel import gettext as _

from decorators import private_api, feature_flag
from extensions import db
from models import ApiTokens
from utils.token_service import load_token_policy
from utils.error import SocaError
from utils.response import SocaResponse
from utils.validators import Validators

logger = logging.getLogger("soca_logger")


class UserTokenRenew(Resource):
    @private_api
    @feature_flag(flag_name="MY_API_TOKENS", mode="api")
    def post(self, token_id):
        """
        Renew a token's expiration
        ---
        openapi: 3.1.0
        operationId: renewUserToken
        tags:
          - Token
        summary: Extend a token's expiration time
        description: |
          Renew (extend) the expiration of the specified token by the policy's default
          lifetime. Renewal is subject to the token being marked renewable, admin policy
          allowing renewals, and the max_renewals limit not being reached.
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
            description: ID of the token to renew
        responses:
          '200':
            description: Token renewed successfully
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
                        name:
                          type: string
                        expires_at:
                          type: string
                          format: date-time
                        renewal_count:
                          type: integer
                        max_renewals:
                          type: integer
                          nullable: true
          '400':
            description: Token is revoked
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
            description: Token is not renewable or max renewals reached or renewal disabled by policy
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
            return {"success": False, "message": "Token is revoked"}, 400

        if not record.renewable:
            return {"success": False, "message": "Token is not renewable"}, 403

        policy = load_token_policy()
        if not policy.get("renewal_allowed", True):
            return {"success": False, "message": "Token renewal is disabled by admin policy"}, 403

        if record.max_renewals is not None and Validators.is_int_greater_or_equal(record.renewal_count, record.max_renewals):
            return {"success": False, "message": "Maximum renewals reached"}, 403

        max_lifetime = policy.get("max_lifetime_hours", 720)
        default_lifetime = policy.get("default_lifetime_hours", 24)
        extension = min(default_lifetime, max_lifetime)

        record.expires_at = datetime.now(timezone.utc) + timedelta(hours=extension)
        record.renewal_count += 1

        try:
            db.session.commit()
        except Exception as err:
            db.session.rollback()
            return SocaError.DB_ERROR(
                query=record, helper=f"Failed to renew token: {err}"
            ).as_flask()

        return SocaResponse(
            success=True,
            message={
                "id": record.id,
                "name": record.name,
                "expires_at": record.expires_at.isoformat() + "Z",
                "renewal_count": record.renewal_count,
                "max_renewals": record.max_renewals,
            },
        ).as_flask()

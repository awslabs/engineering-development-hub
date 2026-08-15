# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

from flask import request, session
from flask_restful import Resource
from decorators import private_api, feature_flag
from utils.ai_assistant.token_usage import SocaAiAssistantTokenUsage
from utils.response import SocaResponse
from utils.error import SocaError

logger = logging.getLogger("soca_logger")


class AiAssistantUsage(Resource):
    @private_api
    @feature_flag(flag_name="AI_ASSISTANT", mode="api")
    def get(self):
        r"""
        Get the current user's daily AI token usage
        ---
        openapi: 3.1.0
        operationId: getAiAssistantUsage
        tags:
          - AI Assistant
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
            required: true
            description: EDH authentication token
        responses:
          '200':
            description: Current daily token usage
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: object
                      properties:
                        used:
                          type: integer
                        limit:
                          type: integer
        """
        username = request.headers.get("X-EDH-USER") or session.get("user")
        if username is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        token_usage = SocaAiAssistantTokenUsage(username=username)

        limit_resp = token_usage.limit
        if limit_resp.get("success") is False:
            return limit_resp.as_flask()

        usage_resp = token_usage.get_current_usage()
        if usage_resp.get("success") is False:
            return usage_resp.as_flask()

        return SocaResponse(
            success=True,
            message={"used": usage_resp.message, "limit": limit_resp.message},
        ).as_flask()

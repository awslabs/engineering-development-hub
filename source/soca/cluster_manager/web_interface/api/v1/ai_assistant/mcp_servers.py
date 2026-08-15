# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

from flask import request, session
from flask_restful import Resource
from decorators import private_api, feature_flag
from utils.ai_assistant.mcp_tools import SocaAiAssistantMcpTools
from utils.response import SocaResponse
from utils.error import SocaError

logger = logging.getLogger("soca_logger")


class AiAssistantMcpServers(Resource):
    @private_api
    @feature_flag(flag_name="AI_ASSISTANT", mode="api")
    def get(self):
        r"""
        List available MCP servers configured for the AI Assistant
        ---
        openapi: 3.1.0
        operationId: listAiAssistantMcpServers
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
            description: List of configured MCP servers
            content:
              application/json:
                schema:
                  type: object
                  properties:
                    success:
                      type: boolean
                    message:
                      type: array
                      items:
                        type: object
                        properties:
                          name:
                            type: string
                            description: Server display name
                          endpoint:
                            type: string
                            description: Server endpoint URL
                          headers:
                            type: object
                            nullable: true
                            description: Optional HTTP headers for the server connection
        """
        username = request.headers.get("X-EDH-USER") or session.get("user")
        if username is None:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        tools_mgr = SocaAiAssistantMcpTools()
        resp = tools_mgr.list_servers()
        return SocaResponse(success=True, message=resp.message).as_flask()

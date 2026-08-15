# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import logging

from flask import request, Response, session, stream_with_context
from flask_restful import Resource
from decorators import private_api, feature_flag
from utils.ai_assistant.assistant import SocaAiAssistant
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")


class AiAssistantConverseStream(Resource):
    @private_api
    @feature_flag(flag_name="AI_ASSISTANT", mode="api")
    def post(self):
        r"""
        Stream AI Assistant response via Server-Sent Events
        ---
        openapi: 3.1.0
        operationId: aiAssistantConverseStream
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
        requestBody:
          required: true
          content:
            application/json:
              schema:
                type: object
                required:
                  - prompt
                properties:
                  prompt:
                    type: string
                  system_prompt:
                    type: string
                    nullable: true
                  max_tokens:
                    type: integer
                    nullable: true
                  temperature:
                    type: number
                    nullable: true
                  top_p:
                    type: number
                    nullable: true
                  inference_profile_arn:
                    type: string
                    nullable: true
                    description: Custom Bedrock inference profile ARN
                  model_id:
                    type: string
                    nullable: true
                    description: Bedrock model ID to use for inference
                  messages:
                    type: array
                    nullable: true
                    description: Conversation history for context
                    items:
                      type: object
                      properties:
                        role:
                          type: string
                          enum: [user, assistant]
                        content:
                          type: string
                  agent_runtime_id:
                    type: string
                    nullable: true
                    description: Bedrock Agent runtime ID for agent-mode invocation
                  session_id:
                    type: string
                    nullable: true
                    description: Session ID for agent-mode conversation continuity
                  conversation_id:
                    type: string
                    nullable: true
                    description: Conversation identifier used to derive the agent session ID when session_id is not provided
                  mcp_server_names:
                    type: array
                    nullable: true
                    description: List of MCP server names to enable tool use during streaming
                    items:
                      type: string
        responses:
          '200':
            description: SSE stream of text chunks
            content:
              text/event-stream:
                schema:
                  type: string
          '401':
            description: Authentication required
          '500':
            description: Streaming failed
        """
        data = request.get_json(force=True)
        prompt = data.get("prompt")
        if not prompt:
            return SocaError.GENERIC_ERROR(helper="prompt is required").as_flask()

        username = request.headers.get("X-EDH-USER") or session.get("user")
        if not username:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()
        system_prompt = SocaAiAssistant.generate_system_prompt(user_specified_system_prompt=data.get("system_prompt"))
        max_tokens = data.get("max_tokens")
        temperature = data.get("temperature")
        top_p = data.get("top_p")
        inference_profile_arn = data.get("inference_profile_arn")
        model_id = data.get("model_id")
        messages = data.get("messages")
        agent_runtime_id = data.get("agent_runtime_id")
        session_id = data.get("session_id")
        mcp_server_names = data.get("mcp_server_names")

        assistant = SocaAiAssistant(
            username=username,
            model_id=model_id,
            inference_profile_arn=inference_profile_arn,
            agent_runtime_id=agent_runtime_id,
        )
        logger.info(
            f"Invoking AI Assistant Stream with prompt from {username} with model_id={model_id}, agent_runtime_id={agent_runtime_id}, mcp_servers={mcp_server_names}"
        )

        def generate():
            try:
                if assistant.is_agent_mode:
                    _session_id = session_id or f"{username}-{data.get('conversation_id', 'default')}"
                    stream = assistant.invoke_agent_stream(
                        prompt=prompt,
                        session_id=_session_id,
                    )
                elif mcp_server_names:
                    stream = assistant.converse_stream_with_tools(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        max_tokens=max_tokens,
                        temperature=temperature,
                        top_p=top_p,
                        messages=messages,
                        mcp_server_names=mcp_server_names,
                    )
                else:
                    stream = assistant.converse_stream(
                        prompt=prompt,
                        system_prompt=system_prompt,
                        max_tokens=max_tokens,
                        temperature=temperature,
                        top_p=top_p,
                        messages=messages,
                    )

                if isinstance(stream, SocaResponse) and stream.success is False:
                    yield f"data: {json.dumps({'error': stream.message or 'Unknown error'})}\n\n"
                    return

                for chunk in stream:
                    yield f"data: {json.dumps({'text': chunk})}\n\n"

                usage = assistant.last_usage
                yield f"data: {json.dumps({'done': True, 'usage': usage})}\n\n"
            except Exception as e:
                logger.error(f"Stream error: {e}")
                yield f"data: {json.dumps({'error': str(e)})}\n\n"

        return Response(
            stream_with_context(generate()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

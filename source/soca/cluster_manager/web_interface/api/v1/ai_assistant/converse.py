# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from flask_restful import Resource, reqparse
import logging
from decorators import private_api, feature_flag
from utils.ai_assistant.assistant import SocaAiAssistant
from utils.response import SocaResponse
from utils.error import SocaError
from flask import request, session
logger = logging.getLogger("soca_logger")


class AiAssistantConverse(Resource):
    @private_api
    @feature_flag(flag_name="AI_ASSISTANT", mode="api")
    def post(self):
        r"""
        Invoke the AI Assistant via Amazon Bedrock
        ---
        openapi: 3.1.0
        operationId: aiAssistantConverse
        tags:
          - AI Assistant
        parameters:
          - name: X-EDH-USER
            in: header
            schema:
              type: string
              minLength: 1
            required: true
            description: EDH username for authentication
          - name: X-EDH-TOKEN
            in: header
            schema:
              type: string
              minLength: 1
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
                    description: The user message to send to the AI assistant
                    example: "Why is my HPC job failing with mount errors?"
                  system_prompt:
                    type: string
                    nullable: true
                    description: Optional system instruction to guide the AI response
                  max_tokens:
                    type: integer
                    nullable: true
                    description: Maximum number of tokens in the response
                    example: 4096
                  temperature:
                    type: number
                    format: float
                    nullable: true
                    description: Temperature (0.0 = deterministic, 1.0 = creative)
                    example: 0.0
                  top_p:
                    type: number
                    format: float
                    nullable: true
                    description: Top-p nucleus sampling parameter
                  knowledge_base_id:
                    type: string
                    nullable: true
                    description: Bedrock Knowledge Base ID for RAG-based responses
                  number_of_results:
                    type: integer
                    default: 5
                    description: Number of KB chunks to retrieve (only used with knowledge_base_id)
                  inference_profile_arn:
                    type: string
                    nullable: true
                    description: Custom Bedrock inference profile ARN. Defaults to cluster-configured model.
                  model_id:
                    type: string
                    nullable: true
                    description: Bedrock model ID to use for inference. Defaults to cluster-configured model.
                  messages:
                    type: array
                    nullable: true
                    description: Conversation history to provide context for the AI assistant
                    items:
                      type: object
                      properties:
                        role:
                          type: string
                          enum: [user, assistant]
                        content:
                          type: string
        responses:
          '200':
            description: AI assistant response generated successfully
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
                        message:
                          type: string
                          description: The AI-generated response text
                        usage:
                          type: object
                          nullable: true
                          properties:
                            inputTokens:
                              type: integer
                            outputTokens:
                              type: integer
                            totalTokens:
                              type: integer
          '401':
            description: Authentication required
          '500':
            description: AI assistant invocation failed
        """
        parser = reqparse.RequestParser()
        parser.add_argument(
            "prompt",
            type=str,
            required=True,
            help="The user message to send to the AI assistant",
        )
        parser.add_argument("system_prompt", type=str, required=False, default=None)
        parser.add_argument("max_tokens", type=int, required=False, default=None)
        parser.add_argument("temperature", type=float, required=False, default=None)
        parser.add_argument("top_p", type=float, required=False, default=None)
        parser.add_argument("knowledge_base_id", type=str, required=False, default=None)
        parser.add_argument("number_of_results", type=int, required=False, default=5)
        parser.add_argument(
            "inference_profile_arn", type=str, required=False, default=None
        )
        parser.add_argument("model_id", type=str, required=False, default=None)
        args = parser.parse_args()
        username = request.headers.get("X-EDH-USER") or session.get("user")
        if not username:
            return SocaError.CLIENT_MISSING_HEADER(header="X-EDH-USER").as_flask()

        data = request.get_json(force=True)
        messages = data.get("messages")

        assistant = SocaAiAssistant(
            username=username,
            model_id=args["model_id"],
            inference_profile_arn=args["inference_profile_arn"],
        )
        logger.info(
            f"Invoking AI Assistant with prompt from {username} with model_id={args['model_id']}, inference_profile_arn={args['inference_profile_arn']}"
        )
        system_prompt = SocaAiAssistant.generate_system_prompt(user_specified_system_prompt=args["system_prompt"])
        response = assistant.converse(
            prompt=args["prompt"],
            system_prompt=system_prompt,
            max_tokens=args["max_tokens"],
            temperature=args["temperature"],
            top_p=args["top_p"],
            knowledge_base_id=args["knowledge_base_id"],
            number_of_results=args["number_of_results"],
            messages=messages,
        )

        logger.info(f"AI Assistant response status: {response.get('success')}")

        if response.get("success") is True:
            return SocaResponse(
                success=True,
                message={"message": response.message, "usage": assistant.last_usage},
            ).as_flask()
        else:
            logger.error(f"AI Assistant invocation failed: {response.message}")
            return SocaError.GENERIC_ERROR(helper=response.message).as_flask()

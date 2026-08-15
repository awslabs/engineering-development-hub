# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Wrapper around Amazon Bedrock and Anthropic for AI-assisted operations.
"""

from __future__ import annotations

import json
import logging
from flask import session
from typing import Optional
from utils.error import SocaError
from utils.config import SocaConfig
from utils.response import SocaResponse
from utils.ai_assistant.token_usage import SocaAiAssistantTokenUsage
from utils.ai_assistant.agents import SocaAiAssistantAgents
from utils.validators import Validators
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")


def _aws_partition(region: str) -> str:
    """Map an AWS region to its ARN partition (GovCloud/China aware)."""
    if region.startswith("us-gov-"):
        return "aws-us-gov"
    if region.startswith("cn-"):
        return "aws-cn"
    return "aws"


class SocaAiAssistant:
    """Wrapper around Amazon Bedrock for AI-assisted operations."""

    def __init__(
        self,
        username: str,
        model_id: Optional[str] = None,
        inference_profile_arn: Optional[str] = None,
        agent_runtime_id: Optional[str] = None,
        max_tokens: int = 4096,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        guardrail_id: Optional[str] = None,
        guardrail_version: Optional[str] = None,
    ):
        self._model_id = model_id
        self._inference_profile_arn = inference_profile_arn
        self._agent_runtime_id = agent_runtime_id
        self._model_inference_arn = None
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._top_p = top_p
        self._guardrail_id = guardrail_id
        self._guardrail_version = guardrail_version
        self._token_usage = SocaAiAssistantTokenUsage(username=username)
        self._client = None
        self._last_usage = None

    @property
    def is_agent_mode(self) -> bool:
        return bool(self._agent_runtime_id)

    @staticmethod
    def generate_system_prompt(
        user_specified_system_prompt: Optional[str] = None,
    ) -> str:
        """Generate the final system prompt by appending enforced context to the admin-configured prompt.

        The enforced suffix ensures the model always has access to EDH documentation
        and source code references, regardless of what the admin/user provides.
        Links already present in the user prompt are not duplicated.
        """

        _EDH_DOC_URL = (
            "https://awslabs.github.io/engineering-development-hub-documentation/"
        )
        _EDH_SOURCE_URL = "https://github.com/awslabs/engineering-development-hub/tree/main/source/soca"

        base = (
            user_specified_system_prompt.strip() if user_specified_system_prompt else ""
        )

        _user = session.get("user") or request.headers.get("X-EDH-USER")

        missing_refs = []
        if _EDH_DOC_URL not in base:
            missing_refs.append(f"- EDH Documentation: {_EDH_DOC_URL}")
        if _EDH_SOURCE_URL not in base:
            missing_refs.append(f"- EDH Source Code: {_EDH_SOURCE_URL}")

        _enforced_context = (
            "\n\n---\n"
            "# EDH Context\n\n" + "\n".join(missing_refs) + "\n\n"
            "## What is EDH\n"
            "Engineering Development Hub (EDH) is an open-source AWS solution deployed in the customer's AWS account. "
            "It serves Computer Aided Engineering (CAE) workloads including Finite Element Analysis (FEA), "
            "Computational Fluid Dynamics (CFD), and RF/antenna simulation.\n\n"
            "## Capabilities\n"
            "- **HPC Schedulers**: OpenPBS (default and recommended), LSF, Slurm, AWS Batch, AWS Parallel Compute Service, Amazon Elastic Kubernete Services, AWS Batch — https://awslabs.github.io/engineering-development-hub-documentation/documentation/High-Performance-Computing/\n"
            "- **Job Parameters** (instance type, EBS scratch, EFA): https://awslabs.github.io/engineering-development-hub-documentation/documentation/High-Performance-Computing/integration-ec2-job-parameters/\n"
            "- **Virtual Desktops**: Amazon DCV only — https://awslabs.github.io/engineering-development-hub-documentation/documentation/virtual-desktops/\n"
            "- **Storage** (FSx Lustre, FSx ONTAP, EFS, S3, NFS, EBS, NVMe): https://awslabs.github.io/engineering-development-hub-documentation/documentation/storage/\n"
            "- **Security** (KMS CMK, SSO, Active Directory, custom domain/SSL): https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/\n"
            "- **CLI**: edhctl for configuration management — https://awslabs.github.io/engineering-development-hub-documentation/documentation/architecture/edhctl/\n"
            "- **API**: OpenAPI 3.1 spec at https://github.com/awslabs/engineering-development-hub/blob/main/source/soca/cluster_manager/web_interface/api/v1/api.json\n"
            "- **Supported Operating Systems**: https://awslabs.github.io/engineering-development-hub-documentation/#multi-operating-systems-support\n"
            "- **Backup**: Automatic native backups via AWS Backups: https://awslabs.github.io/engineering-development-hub-documentation/documentation/security/backup-restore-your-cluster/\n"
            "- **Analytics and Business Inteligence**: Create Dashboards via https://awslabs.github.io/engineering-development-hub-documentation/documentation/analytics/\n\n "
            "## Troubleshooting\n"
            f"- You are logged as user: {_user}"
            "- Bootstrap sequence: https://awslabs.github.io/engineering-development-hub-documentation/documentation/architecture/node-bootstrap/\n"
            "- DCV node logs: /apps/edh/<cluster_id>/shared/logs/dcv_node/<username>/<session_name>\n"
            "- HPC compute node logs: /apps/edh/<cluster_id>/shared/logs/compute_node/<job_id>/<host>\n"
            "- Fallback if /apps logs are missing: /root/edh_bootstrap_<instance_id> on the node itself\n\n"
            "## Rules\n"
            "- Always consult EDH documentation before answering.\n"
            "- Validate all links/references exist before sharing — never point to a 404.\n"
            "- SOCA (Scale out Computing on AWS) is the previous name of EDH (from 2019 to April 2026). Refer the user to EDH when SOCA is mentioned."
        )

        _full_system_prompt = base + _enforced_context
        logger.debug(f"Full system prompt: {_full_system_prompt}")
        return _full_system_prompt

    @staticmethod
    def list_models() -> SocaResponse:
        """List allowed Bedrock model IDs from configuration."""
        resp = SocaConfig(
            key="/configuration/AIAssistant/allowed_bedrock_model_ids"
        ).get_value(return_as=list)
        if resp.get("success") is False:
            return SocaResponse(success=True, message=[])
        return SocaResponse(success=True, message=resp.get("message") or [])

    @staticmethod
    def _get_bedrock_model_inference_profile_arn(model_id: str) -> str:
        _account_id = SocaConfig(key="/configuration/AWSAccountId").get_value().message
        _region = SocaConfig(key="/configuration/Region").get_value().message
        return f"arn:{_aws_partition(_region)}:bedrock:{_region}:{_account_id}:inference-profile/{model_id}"

    def _resolve_and_validate_model(self) -> SocaResponse:
        """Resolve the model ARN and validate it against allowed models. Called before each request."""
        if self._model_id and self._inference_profile_arn:
            return SocaError.GENERIC_ERROR(
                helper="Specify either model_id or inference_profile_arn, not both."
            )

        _allowed_resp = SocaAiAssistant.list_models()
        if _allowed_resp.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper="Failed to retrieve allowed model list"
            )
        _allowed_models = _allowed_resp.get("message")
        if not _allowed_models:
            return SocaError.GENERIC_ERROR(helper="No allowed models configured")
        logger.debug(f"Allowed Bedrock models: {_allowed_models}")

        if self._model_id:
            _resolved_model_id = self._model_id
        elif self._inference_profile_arn:
            _resolved_model_id = self._inference_profile_arn.split("/")[-1]
        else:
            _resolved_model_id = _allowed_models[0]

        logger.info(
            "Model resolution: model_id=%s, inference_profile_arn=%s, resolved_model_id=%s",
            self._model_id,
            self._inference_profile_arn,
            _resolved_model_id,
        )

        if _resolved_model_id not in _allowed_models:
            return SocaError.GENERIC_ERROR(
                helper=f"Model '{_resolved_model_id}' is not allowed. Permitted models: {', '.join(_allowed_models)}"
            )

        self._model_inference_arn = self._get_bedrock_model_inference_profile_arn(
            _resolved_model_id
        )
        logger.info(f"Resolved model inference ARN: {self._model_inference_arn}")
        return SocaResponse(success=True, message=self._model_inference_arn)

    def _get_client(self, service_name: str = "bedrock-runtime") -> SocaResponse:
        if service_name == "bedrock-runtime":
            if self._client is None:
                _region = SocaConfig(key="/configuration/Region").get_value().message
                response = utils_boto3.get_boto(
                    service_name="bedrock-runtime", region_name=_region
                )
                if response.get("success") is False:
                    return response
                self._client = response.message
            return SocaResponse(success=True, message=self._client)

        _region = SocaConfig(key="/configuration/Region").get_value().message
        response = utils_boto3.get_boto(service_name=service_name, region_name=_region)
        if response.get("success") is False:
            return response
        return SocaResponse(success=True, message=response.message)

    @property
    def last_usage(self) -> Optional[dict]:
        """Token usage from the last converse call. Keys: inputTokens, outputTokens, totalTokens."""
        return self._last_usage

    def converse(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        knowledge_base_id: Optional[str] = None,
        number_of_results: int = 5,
        messages: Optional[list] = None,
    ) -> SocaResponse:
        """Send a conversation to Bedrock and return the response text.

        Args:
            prompt: The user message (used if messages is not provided).
            system_prompt: Optional system instruction.
            max_tokens: Override max tokens for this call.
            temperature: Override temperature (0.0 = deterministic, 1.0 = creative).
            top_p: Override top_p nucleus sampling.
            knowledge_base_id: Optional Bedrock Knowledge Base ID for RAG.
            number_of_results: Number of KB chunks to retrieve (default: 5, only used with knowledge_base_id).
            messages: Full conversation history as a list of {"role": ..., "content": ...} dicts.
        """
        _model_check = self._resolve_and_validate_model()
        if _model_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_model_check.get("message"))

        _token_check = self._token_usage.verify_quota_available()
        if _token_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_token_check.get("message"))

        if knowledge_base_id:
            return self.converse_with_kb(
                prompt=prompt,
                knowledge_base_id=knowledge_base_id,
                system_prompt=system_prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                number_of_results=number_of_results,
            )

        _max_tokens = max_tokens or self._max_tokens
        _temperature = temperature if temperature is not None else self._temperature
        _top_p = top_p if top_p is not None else self._top_p
        _model = self._model_inference_arn

        inference_config = {"maxTokens": _max_tokens}
        if _temperature is not None:
            inference_config["temperature"] = _temperature
        if _top_p is not None:
            inference_config["topP"] = _top_p

        if messages:
            _bedrock_messages = [
                {"role": m["role"], "content": [{"text": m["content"]}]}
                for m in messages
            ]
        else:
            _bedrock_messages = [{"role": "user", "content": [{"text": prompt}]}]

        kwargs = {
            "modelId": _model,
            "messages": _bedrock_messages,
            "inferenceConfig": inference_config,
        }

        if system_prompt:
            kwargs["system"] = [{"text": system_prompt}]

        if self._guardrail_id and self._guardrail_version:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": self._guardrail_id,
                "guardrailVersion": self._guardrail_version,
            }

        _client_response = self._get_client()
        if _client_response.get("success") is False:
            return _client_response
        else:
            _bedrock_client = _client_response.get("message")

        logger.debug(f"Bedrock converse kwargs: {kwargs}")
        try:
            response = _bedrock_client.converse(**kwargs)
            self._last_usage = response.get("usage")
            if self._last_usage:
                total = self._last_usage.get("totalTokens") or (
                    self._last_usage.get("inputTokens", 0)
                    + self._last_usage.get("outputTokens", 0)
                )
                self._token_usage.increment(total)
            return SocaResponse(
                success=True,
                message=response["output"]["message"]["content"][0]["text"],
            )
        except Exception as e:
            logger.error(f"Bedrock converse failed: {e}")
            return SocaError.GENERIC_ERROR(helper=f"Bedrock converse failed: {e}")

    def converse_stream(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        messages: Optional[list] = None,
    ):
        """Stream a conversation response from Bedrock.

        Returns a SocaResponse on error, or a generator that yields text chunks on success.
        Caller must check isinstance(result, SocaResponse) before iterating.
        """
        _model_check = self._resolve_and_validate_model()
        if _model_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_model_check.get("message"))

        _token_check = self._token_usage.verify_quota_available()
        if _token_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_token_check.get("message"))

        _max_tokens = max_tokens or self._max_tokens
        _temperature = temperature if temperature is not None else self._temperature
        _top_p = top_p if top_p is not None else self._top_p
        _model = self._model_inference_arn

        inference_config = {"maxTokens": _max_tokens}
        if _temperature is not None:
            inference_config["temperature"] = _temperature
        if _top_p is not None:
            inference_config["topP"] = _top_p

        if messages:
            _bedrock_messages = [
                {"role": m["role"], "content": [{"text": m["content"]}]}
                for m in messages
            ]
        else:
            _bedrock_messages = [{"role": "user", "content": [{"text": prompt}]}]

        kwargs = {
            "modelId": _model,
            "messages": _bedrock_messages,
            "inferenceConfig": inference_config,
        }

        if system_prompt:
            kwargs["system"] = [{"text": system_prompt}]

        if self._guardrail_id and self._guardrail_version:
            kwargs["guardrailConfig"] = {
                "guardrailIdentifier": self._guardrail_id,
                "guardrailVersion": self._guardrail_version,
            }

        _client_response = self._get_client()
        if _client_response.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_client_response.get("message"))

        _bedrock_client = _client_response.message

        if messages:
            _estimated_input = sum(len(m["content"]) for m in messages) // 4
        else:
            _estimated_input = len(prompt) // 4
        _pre_charged = _estimated_input + _max_tokens
        self._token_usage.increment(_pre_charged)

        def _stream():
            response = _bedrock_client.converse_stream(**kwargs)

            for event in response.get("stream", []):
                if "contentBlockDelta" in event:
                    delta = event["contentBlockDelta"].get("delta", {})
                    text = delta.get("text", "")
                    if text:
                        yield text
                elif "metadata" in event:
                    self._last_usage = event["metadata"].get("usage")
                    if self._last_usage:
                        actual_total = self._last_usage.get("totalTokens") or (
                            self._last_usage.get("inputTokens", 0)
                            + self._last_usage.get("outputTokens", 0)
                        )
                        correction = actual_total - _pre_charged
                        if correction != 0:
                            self._token_usage.increment(correction)

        return _stream()

    def converse_stream_with_tools(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        top_p: Optional[float] = None,
        messages: Optional[list] = None,
        mcp_server_names: Optional[list[str]] = None,
        max_tool_rounds: int = 10,
    ):
        """Stream a conversation with MCP tool-use support.

        Returns a SocaResponse on error, or a generator that yields text chunks on success.
        Caller must check isinstance(result, SocaResponse) before iterating.
        """
        from utils.ai_assistant.mcp_tools import SocaAiAssistantMcpTools

        _model_check = self._resolve_and_validate_model()
        if _model_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_model_check.get("message"))

        _token_check = self._token_usage.verify_quota_available()
        if _token_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_token_check.get("message"))

        tools_mgr = SocaAiAssistantMcpTools()
        _connect_resp = tools_mgr.connect_servers(server_names=mcp_server_names)
        if _connect_resp.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_connect_resp.get("message"))

        if not tools_mgr.has_tools:
            return SocaError.GENERIC_ERROR(
                helper="No MCP tools available from the configured servers"
            )

        tool_config = tools_mgr.get_bedrock_tool_config()

        _max_tokens = max_tokens or self._max_tokens
        _temperature = temperature if temperature is not None else self._temperature
        _top_p = top_p if top_p is not None else self._top_p
        _model = self._model_inference_arn

        inference_config = {"maxTokens": _max_tokens}
        if _temperature is not None:
            inference_config["temperature"] = _temperature
        if _top_p is not None:
            inference_config["topP"] = _top_p

        if messages:
            _bedrock_messages = [
                {"role": m["role"], "content": [{"text": m["content"]}]}
                for m in messages
            ]
        else:
            _bedrock_messages = [{"role": "user", "content": [{"text": prompt}]}]

        _client_response = self._get_client()
        if _client_response.get("success") is False:
            tools_mgr.cleanup()
            return SocaError.GENERIC_ERROR(helper=_client_response.get("message"))

        _bedrock_client = _client_response.message

        if messages:
            _estimated_input = sum(len(m["content"]) for m in messages) // 4
        else:
            _estimated_input = len(prompt) // 4
        _pre_charged = _estimated_input + _max_tokens
        self._token_usage.increment(_pre_charged)

        def _stream():
            nonlocal _pre_charged
            try:
                for _round in range(max_tool_rounds):
                    kwargs = {
                        "modelId": _model,
                        "messages": _bedrock_messages,
                        "inferenceConfig": inference_config,
                    }
                    if system_prompt:
                        kwargs["system"] = [{"text": system_prompt}]
                    if tool_config:
                        kwargs["toolConfig"] = tool_config
                    if self._guardrail_id and self._guardrail_version:
                        kwargs["guardrailConfig"] = {
                            "guardrailIdentifier": self._guardrail_id,
                            "guardrailVersion": self._guardrail_version,
                        }

                    response = _bedrock_client.converse_stream(**kwargs)

                    _assistant_content = []
                    _tool_use_block = None
                    _tool_input_json = ""
                    _stop_reason = None

                    for event in response.get("stream", []):
                        if "contentBlockStart" in event:
                            start = event["contentBlockStart"].get("start", {})
                            if "toolUse" in start:
                                _tool_use_block = {
                                    "toolUseId": start["toolUse"]["toolUseId"],
                                    "name": start["toolUse"]["name"],
                                }
                                _tool_input_json = ""
                                yield f"\n\n__TOOL_CALL__: {_tool_use_block['name']}\n"

                        elif "contentBlockDelta" in event:
                            delta = event["contentBlockDelta"].get("delta", {})
                            if "text" in delta:
                                text = delta["text"]
                                _assistant_content.append({"text": text})
                                yield text
                            elif "toolUse" in delta:
                                _tool_input_json += delta["toolUse"].get("input", "")

                        elif "contentBlockStop" in event:
                            if _tool_use_block is not None:
                                try:
                                    tool_input = (
                                        json.loads(_tool_input_json)
                                        if _tool_input_json
                                        else {}
                                    )
                                except json.JSONDecodeError:
                                    tool_input = {}
                                _tool_use_block["input"] = tool_input
                                _assistant_content.append({"toolUse": _tool_use_block})
                                _tool_use_block = None
                                _tool_input_json = ""

                        elif "messageStop" in event:
                            _stop_reason = event["messageStop"].get("stopReason")

                        elif "metadata" in event:
                            self._last_usage = event["metadata"].get("usage")
                            if self._last_usage:
                                actual_total = self._last_usage.get("totalTokens") or (
                                    self._last_usage.get("inputTokens", 0)
                                    + self._last_usage.get("outputTokens", 0)
                                )
                                correction = actual_total - _pre_charged
                                if correction != 0:
                                    self._token_usage.increment(correction)
                                _pre_charged = actual_total

                    if _stop_reason != "tool_use":
                        break

                    _bedrock_messages.append(
                        {"role": "assistant", "content": _assistant_content}
                    )

                    tool_results = []
                    for block in _assistant_content:
                        if "toolUse" in block:
                            tool_name = block["toolUse"]["name"]
                            tool_input = block["toolUse"].get("input", {})
                            tool_use_id = block["toolUse"]["toolUseId"]

                            yield f"__TOOL_EXECUTING__: {tool_name}\n"
                            result_text = tools_mgr.execute_tool(tool_name, tool_input)
                            yield f"__TOOL_RESULT__: {tool_name}\n"

                            tool_results.append(
                                {
                                    "toolResult": {
                                        "toolUseId": tool_use_id,
                                        "content": [{"text": result_text}],
                                    }
                                }
                            )

                    _bedrock_messages.append({"role": "user", "content": tool_results})

                    _token_check = self._token_usage.verify_quota_available()
                    if _token_check.get("success") is False:
                        yield f"\n\n[Token quota exceeded, stopping tool loop]\n"
                        break

            finally:
                tools_mgr.cleanup()

        return _stream()

    def converse_with_kb(
        self,
        prompt: str,
        knowledge_base_id: str,
        system_prompt: Optional[str] = None,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        number_of_results: int = 5,
    ) -> SocaResponse:
        """Query a Bedrock Knowledge Base and generate a response using RAG.

        Args:
            prompt: The user question.
            knowledge_base_id: The Bedrock Knowledge Base ID to query.
            system_prompt: Optional system instruction.
            max_tokens: Override max tokens for the generation.
            temperature: Override temperature for the generation.
            number_of_results: Number of KB chunks to retrieve (default: 5).
        """
        _max_tokens = max_tokens or self._max_tokens
        _temperature = temperature if temperature is not None else self._temperature
        _model = self._model_inference_arn

        _client_response = self._get_client("bedrock-agent-runtime")
        if _client_response.get("success") is False:
            return _client_response
        else:
            _bedrock_client = _client_response.get("message")

        _text_inference_config = {"maxTokens": _max_tokens}
        if _temperature is not None:
            _text_inference_config["temperature"] = _temperature

        kwargs = {
            "input": {"text": prompt},
            "retrieveAndGenerateConfiguration": {
                "type": "KNOWLEDGE_BASE",
                "knowledgeBaseConfiguration": {
                    "knowledgeBaseId": knowledge_base_id,
                    "modelArn": _model,
                    "retrievalConfiguration": {
                        "vectorSearchConfiguration": {
                            "numberOfResults": number_of_results,
                        }
                    },
                    "generationConfiguration": {
                        "inferenceConfig": {
                            "textInferenceConfig": _text_inference_config,
                        }
                    },
                },
            },
        }

        if system_prompt:
            kwargs["retrieveAndGenerateConfiguration"]["knowledgeBaseConfiguration"][
                "generationConfiguration"
            ]["additionalModelRequestFields"] = {"system": system_prompt}

        if self._guardrail_id and self._guardrail_version:
            kwargs["retrieveAndGenerateConfiguration"]["knowledgeBaseConfiguration"][
                "generationConfiguration"
            ]["guardrailConfiguration"] = {
                "guardrailId": self._guardrail_id,
                "guardrailVersion": self._guardrail_version,
            }

        try:
            logger.debug(f"Calling Bedrock retrieve_and_generate with kwargs: {kwargs}")
            response = _bedrock_client.retrieve_and_generate(**kwargs)
            logger.debug(f"Bedrock response: {response}")
            return SocaResponse(
                success=True,
                message=response.get("output", {}).get("text", ""),
                trace=response.get("citations", []),
            )
        except Exception as e:
            logger.error(f"Bedrock Knowledge Base query failed: {e}")
            return SocaError.GENERIC_ERROR(
                helper=f"Bedrock Knowledge Base query failed: {e}"
            )

    def invoke_agent_stream(
        self,
        prompt: str,
        session_id: str,
    ):
        """Invoke a Bedrock AgentCore runtime and stream the response.

        Returns a SocaResponse on error, or a generator that yields text chunks on success.
        Caller must check isinstance(result, SocaResponse) before iterating.
        """
        if not self._agent_runtime_id:
            return SocaError.GENERIC_ERROR(
                helper="agent_runtime_id is required for invoke_agent_stream"
            )

        _agent_check = SocaAiAssistantAgents().validate_agent(self._agent_runtime_id)
        if _agent_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_agent_check.get("message"))

        _token_check = self._token_usage.verify_quota_available()
        if _token_check.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_token_check.get("message"))

        _client_response = self._get_client("bedrock-agentcore")
        if _client_response.get("success") is False:
            return SocaError.GENERIC_ERROR(helper=_client_response.get("message"))

        _agent_client = _client_response.message

        _estimated_input = len(prompt) // 4
        _pre_charged = _estimated_input + self._max_tokens
        self._token_usage.increment(_pre_charged)

        logger.info(
            f"Invoking AgentCore runtime {self._agent_runtime_id} with session {session_id}"
        )

        _region = SocaConfig(key="/configuration/Region").get_value().message
        _account_id = SocaConfig(key="/configuration/AWSAccountId").get_value().message
        _agent_runtime_arn = f"arn:{_aws_partition(_region)}:bedrock-agentcore:{_region}:{_account_id}:runtime/{self._agent_runtime_id}"

        import json as _json

        _payload = _json.dumps({"prompt": prompt})

        def _stream():
            try:
                response = _agent_client.invoke_agent_runtime(
                    agentRuntimeArn=_agent_runtime_arn,
                    runtimeSessionId=session_id,
                    payload=_payload,
                )

                _streaming_body = response.get("response") or response.get("body")
                if _streaming_body is None:
                    raise RuntimeError(
                        f"No response body found. Keys: {list(response.keys())}"
                    )

                _output_tokens = 0

                for line in _streaming_body.iter_lines():
                    if not line:
                        continue
                    line_str = line.decode("utf-8") if isinstance(line, bytes) else line
                    if not line_str.startswith("data: "):
                        continue

                    try:
                        event_data = _json.loads(line_str[6:])
                        event = event_data.get("event", event_data)

                        if "contentBlockDelta" in event:
                            delta = event["contentBlockDelta"].get("delta", {})
                            text = delta.get("text", "")
                            if text:
                                _output_tokens += len(text) // 4
                                yield text
                    except (_json.JSONDecodeError, ValueError):
                        continue

                actual_total = _estimated_input + _output_tokens
                correction = actual_total - _pre_charged
                if correction != 0:
                    self._token_usage.increment(correction)

                self._last_usage = {
                    "inputTokens": _estimated_input,
                    "outputTokens": _output_tokens,
                    "totalTokens": _estimated_input + _output_tokens,
                }

            except Exception as e:
                logger.error(f"Bedrock AgentCore invocation failed: {e}")
                raise

        return _stream()

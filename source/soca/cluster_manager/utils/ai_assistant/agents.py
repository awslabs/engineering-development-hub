# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
Bedrock AgentCore runtime discovery and validation.
"""

from __future__ import annotations

import logging
from typing import Optional

from utils.error import SocaError
from utils.config import SocaConfig
from utils.response import SocaResponse
import utils.aws.boto3_wrapper as utils_boto3

logger = logging.getLogger("soca_logger")


class SocaAiAssistantAgents:
    """Discover and validate Bedrock AgentCore runtimes for the cluster.

    Caches the agent list and boto3 client after first fetch.
    Filters agents by READY status and edh:visibility:<cluster_id>=true tag.
    """

    def __init__(self):
        self._client = None
        self._agents = None
        self._cluster_id = (
            SocaConfig(key="/configuration/ClusterId").get_value().message
        )
        self._region = SocaConfig(key="/configuration/Region").get_value().message
        self._visibility_tag = f"edh:visibility:{self._cluster_id}"

    def _get_client(self):
        if self._client is None:
            _resp = utils_boto3.get_boto(
                service_name="bedrock-agentcore-control", region_name=self._region
            )
            if _resp.get("success") is False:
                return None
            self._client = _resp.get("message")
        return self._client

    def list_agents(self) -> SocaResponse:
        """List all READY AgentCore runtimes visible to this cluster.

        Returns:
            SocaResponse with success=True and message as list of agent dicts:
            [{"id": ..., "name": ..., "description": ..., "arn": ...}, ...]
        """
        if self._agents is not None:
            return SocaResponse(success=True, message=self._agents)

        client = self._get_client()
        if client is None:
            return SocaError.GENERIC_ERROR(
                helper="Failed to get bedrock-agentcore-control client"
            )

        agents = []
        try:
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs["nextToken"] = next_token
                resp = client.list_agent_runtimes(**kwargs)

                for agent in resp.get("agentRuntimes", []):
                    _name = agent.get("agentRuntimeName", agent.get("agentRuntimeId"))
                    _status = agent.get("status")
                    if _status != "READY":
                        logger.info(
                            f"Skipping agent '{_name}' — status is {_status}"
                        )
                        continue

                    _arn = agent.get("agentRuntimeArn", "")
                    try:
                        tags_resp = client.list_tags_for_resource(resourceArn=_arn)
                        tags = tags_resp.get("tags", {})
                    except Exception as tag_err:
                        logger.warning(
                            f"Failed to fetch tags for agent '{_name}' ({_arn}): {tag_err}"
                        )
                        tags = {}

                    if tags.get(self._visibility_tag, "").lower() != "true":
                        logger.info(
                            f"Skipping agent '{_name}' — missing tag "
                            f"{self._visibility_tag}=true (tags: {tags})"
                        )
                        continue

                    agents.append(
                        {
                            "id": agent["agentRuntimeId"],
                            "name": _name,
                            "description": agent.get("description", ""),
                            "arn": _arn,
                        }
                    )

                next_token = resp.get("nextToken")
                if not next_token:
                    break
        except Exception as e:
            return SocaError.GENERIC_ERROR(
                helper=f"Failed to list Bedrock AgentCore runtimes: {e}"
            )

        logger.info(f"Found {len(agents)} READY AgentCore runtimes visible to cluster {self._cluster_id}")
        self._agents = agents
        return SocaResponse(success=True, message=agents)

    def get_agent(
        self,
        agent_runtime_id: Optional[str] = None,
        agent_runtime_arn: Optional[str] = None,
    ) -> SocaResponse:
        """Get information for a specific agent by ID or ARN.

        Args:
            agent_runtime_id: The AgentCore runtime ID.
            agent_runtime_arn: The AgentCore runtime ARN.
            Specify one but not both.

        Returns:
            SocaResponse with success=True and message as agent dict,
            or success=False if not found or invalid params.
        """
        logger.info(
            f"Fetching agent runtime info for ID={agent_runtime_id} ARN={agent_runtime_arn}"
        )
        if agent_runtime_id and agent_runtime_arn:
            return SocaError.GENERIC_ERROR(
                helper="Specify either agent_runtime_id or agent_runtime_arn, not both."
            )
        if not agent_runtime_id and not agent_runtime_arn:
            return SocaError.GENERIC_ERROR(
                helper="Specify either agent_runtime_id or agent_runtime_arn."
            )

        client = self._get_client()
        if client is None:
            return SocaError.GENERIC_ERROR(
                helper="Failed to get bedrock-agentcore-control client"
            )

        if agent_runtime_arn:
            agent_runtime_id = agent_runtime_arn.split("/")[-1]

        try:
            resp = client.get_agent_runtime(agentRuntimeId=agent_runtime_id)
            return SocaResponse(
                success=True,
                message={
                    "id": resp.get("agentRuntimeId", agent_runtime_id),
                    "name": resp.get("agentRuntimeName", agent_runtime_id),
                    "description": resp.get("description", ""),
                    "status": resp.get("status", ""),
                    "arn": resp.get("agentRuntimeArn", agent_runtime_arn or ""),
                },
            )
        except Exception as e:
            logger.error(f"Failed to get agent runtime {agent_runtime_id}: {e}")
            return SocaError.GENERIC_ERROR(
                helper=f"Failed to get agent runtime '{agent_runtime_id}': {e}"
            )

    def validate_agent(self, agent_runtime_id: str) -> SocaResponse:
        """Validate that the given agent runtime ID is allowed for this cluster.

        Args:
            agent_runtime_id: The AgentCore runtime ID to validate.

        Returns:
            SocaResponse with success=True if allowed, success=False if not.
        """
        _list_resp = self.list_agents()
        if _list_resp.get("success") is False:
            return _list_resp

        _allowed_ids = [a["id"] for a in _list_resp.get("message")]

        if agent_runtime_id not in _allowed_ids:
            _allowed_names = [a["name"] for a in _list_resp.get("message")]
            return SocaError.GENERIC_ERROR(
                helper=f"Agent '{agent_runtime_id}' is not allowed. Permitted agents: {', '.join(_allowed_names)}"
            )

        return SocaResponse(success=True, message=agent_runtime_id)

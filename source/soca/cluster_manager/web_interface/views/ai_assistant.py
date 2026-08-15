# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

from decorators import login_required, feature_flag
from flask import Blueprint, render_template, request, session, flash
from utils.config import SocaConfig
from utils.ai_assistant.assistant import SocaAiAssistant
from utils.ai_assistant.agents import SocaAiAssistantAgents
from utils.ai_assistant.mcp_tools import SocaAiAssistantMcpTools

logger = logging.getLogger("soca_logger")
ai_assistant = Blueprint("ai_assistant", __name__, template_folder="templates")


@ai_assistant.route("/ai_assistant", methods=["GET"])
@login_required
@feature_flag(flag_name="AI_ASSISTANT", mode="view")
def index():
    file_path = request.args.get("file", "")
    logger.info(
        f"Rendering AI Assistant page for user {session['user']} with file_path={file_path}"
    )

    # Fetch allowed models
    _models_resp = SocaAiAssistant.list_models()
    if _models_resp.get("success") is False:
        logger.error(
            f"Failed to list Bedrock allowed models due to {_models_resp.get('message')}"
        )
        flash(f"Failed to list Bedrock models. Check logs for details", "error")
        allowed_models = []
    else:
        allowed_models = _models_resp.get("message")

    # Fetch Agents
    _agents_resp = SocaAiAssistantAgents().list_agents()
    if _agents_resp.get("success") is False:
        logger.error(f"Failed to list Bedrock agents: {_agents_resp.get('message')}")
        flash(f"Failed to list Bedrock agents. Check logs for details", "error")
        agents = []
    else:
        agents = _agents_resp.get("message")

    # Fetch MCP Servers
    _mcp_resp = SocaAiAssistantMcpTools().list_servers()
    if _mcp_resp.get("success") is False:
        logger.error(f"Failed to list MCP Servers: {_mcp_resp.get('message')}")
        flash(f"Failed to list MCP Servers. Check logs for details", "error")
        mcp_servers = []
    else:
        mcp_servers = _mcp_resp.get("message")

    _cluster_id = SocaConfig(key="/configuration/ClusterId").get_value().message

    template = "ai_assistant_file_context.html" if file_path else "ai_assistant.html"

    return render_template(
        template,
        file_path=file_path,
        page="ai_assistant",
        allowed_models=allowed_models,
        agents=agents,
        mcp_servers=mcp_servers,
        cluster_id=_cluster_id,
        user=session.get("user", "unknown-user"),
    )

# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""
MCP (Model Context Protocol) tool integration for the AI Assistant.

Connects to already-running MCP servers via Streamable HTTP transport.
MCP servers are configured in SSM Parameter Store under:
    /configuration/AIAssistant/allowed_mcp_servers

Expected format (JSON list):
[
    {
        "name": "my-server",
        "endpoint": "http://mcp-server-host:8080/mcp",
        "headers": {"Authorization": "Bearer ..."}
    }
]

Tools discovered from allowed servers are converted to Bedrock toolConfig format
and passed to the Converse API for tool-use loops.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from typing import Optional

from utils.config import SocaConfig
from utils.error import SocaError
from utils.response import SocaResponse

logger = logging.getLogger("soca_logger")

_MCP_PROTOCOL_VERSION = "2024-11-05"
_REQUEST_TIMEOUT = 30


class McpServerConnection:
    """Client for a single MCP server via Streamable HTTP transport."""

    def __init__(
        self,
        name: str,
        endpoint: str,
        headers: Optional[dict] = None,
    ):
        self.name = name
        self._endpoint = endpoint
        self._headers = headers or {}
        self._request_id = 0
        self._tools: list[dict] = []
        self._session_id: Optional[str] = None

    @property
    def tools(self) -> list[dict]:
        return self._tools

    def _send_jsonrpc(self, method: str, params: Optional[dict] = None) -> dict:
        self._request_id += 1
        request_body = {
            "jsonrpc": "2.0",
            "id": self._request_id,
            "method": method,
        }
        if params is not None:
            request_body["params"] = params

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
            **self._headers,
        }
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id

        payload = json.dumps(request_body).encode()
        req = urllib.request.Request(
            self._endpoint,
            data=payload,
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                if resp.headers.get("Mcp-Session-Id"):
                    self._session_id = resp.headers.get("Mcp-Session-Id")

                response_data = resp.read().decode()
                if not response_data:
                    return {}

                response = json.loads(response_data)
                if "error" in response:
                    err = response["error"]
                    raise RuntimeError(
                        f"MCP server '{self.name}' error [{err.get('code')}]: {err.get('message')}"
                    )
                return response.get("result", {})

        except urllib.error.HTTPError as e:
            raise RuntimeError(
                f"MCP server '{self.name}' HTTP {e.code}: {e.reason}"
            )
        except urllib.error.URLError as e:
            raise RuntimeError(
                f"MCP server '{self.name}' unreachable: {e.reason}"
            )

    def initialize(self):
        """Perform the MCP handshake."""
        self._send_jsonrpc(
            "initialize",
            {
                "protocolVersion": _MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "edh-ai-assistant", "version": "1.0.0"},
            },
        )
        self._send_jsonrpc("notifications/initialized")

    def discover_tools(self) -> list[dict]:
        """Fetch tools from the server. Stores them internally and returns the list."""
        result = self._send_jsonrpc("tools/list")
        self._tools = result.get("tools", [])
        return self._tools

    def call_tool(self, tool_name: str, arguments: dict) -> str:
        """Execute a tool and return the text result."""
        result = self._send_jsonrpc(
            "tools/call",
            {"name": tool_name, "arguments": arguments},
        )
        content = result.get("content", [])
        text_parts = [c.get("text", "") for c in content if c.get("type") == "text"]
        if text_parts:
            return "\n".join(text_parts)
        return json.dumps(result)


class SocaAiAssistantMcpTools:
    """Connects to allowed MCP servers and provides Bedrock-compatible tool definitions.

    Usage:
        tools_mgr = SocaAiAssistantMcpTools()
        tools_mgr.connect_servers(server_names=["my-server"])
        tool_config = tools_mgr.get_bedrock_tool_config()
        # ... pass tool_config to Bedrock Converse API ...
        # When model returns a toolUse block:
        result = tools_mgr.execute_tool(tool_name, tool_input)
    """

    def __init__(self):
        self._servers: list[McpServerConnection] = []
        self._tool_to_server: dict[str, McpServerConnection] = {}

    @property
    def has_tools(self) -> bool:
        return len(self._tool_to_server) > 0

    def list_servers(self) -> SocaResponse:
        """List configured MCP servers (metadata only, does not connect).

        Returns:
            SocaResponse with message as list of server info dicts.
        """
        config_resp = SocaConfig(
            key="/configuration/AIAssistant/allowed_mcp_servers"
        ).get_value()

        if config_resp.get("success") is False:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to fetch allowed MCP servers due to {config_resp}"
            )

        try:
            servers_config = (
                json.loads(config_resp.message)
                if isinstance(config_resp.message, str)
                else config_resp.message
            )
        except (json.JSONDecodeError, TypeError):
            return SocaError.GENERIC_ERROR(
                helper=f"{config_resp} does not seem to be a valid JSON object"
            )
        except Exception as err:
            return SocaError.GENERIC_ERROR(
                helper=f"Unable to parse {config_resp} because of {err}"
            )

        servers = []
        for srv in servers_config:
            if srv.get("name") and srv.get("endpoint"):
                servers.append({
                    "name": srv["name"],
                    "endpoint": srv["endpoint"],
                    "headers": srv.get("headers"),
                })
        return SocaResponse(success=True, message=servers)

    def connect_servers(self, server_names: Optional[list[str]] = None) -> SocaResponse:
        """Connect to MCP servers, perform handshake, and discover tools.

        Args:
            server_names: Optional list of server names to connect to. If None, connects to all configured servers.

        Returns:
            SocaResponse with success=True and message as count of tools discovered.
        """
        list_resp = self.list_servers()
        if list_resp.get("success") is False:
            return list_resp

        servers_config = list_resp.get("message") or []
        active_names = {s.name for s in self._servers}

        total_tools = 0
        for srv_config in servers_config:
            name = srv_config.get("name")
            endpoint = srv_config.get("endpoint")
            if not name or not endpoint:
                continue

            if server_names and name not in server_names:
                continue

            if name in active_names:
                logger.debug(f"MCP server '{name}' already connected, skipping")
                continue

            server = McpServerConnection(
                name=name,
                endpoint=endpoint,
                headers=srv_config.get("headers"),
            )
            try:
                server.initialize()
                tools = server.discover_tools()
                for tool in tools:
                    self._tool_to_server[tool["name"]] = server
                self._servers.append(server)
                total_tools += len(tools)
                logger.info(f"MCP server '{name}' connected with {len(tools)} tools")
            except Exception as e:
                logger.error(f"Failed to connect to MCP server '{name}': {e}")

        return SocaResponse(success=True, message=total_tools)

    def get_bedrock_tool_config(self) -> Optional[dict]:
        """Convert discovered MCP tools to Bedrock Converse API toolConfig format.

        Returns:
            A dict with "tools" key suitable for Bedrock converse kwargs, or None if no tools.
        """
        if not self._tool_to_server:
            return None

        tools = []
        for server in self._servers:
            for mcp_tool in server.tools:
                input_schema = mcp_tool.get(
                    "inputSchema", {"type": "object", "properties": {}}
                )
                tool_spec = {
                    "toolSpec": {
                        "name": mcp_tool["name"],
                        "description": mcp_tool.get(
                            "description",
                            f"Tool from MCP server '{server.name}'",
                        ),
                        "inputSchema": {"json": input_schema},
                    }
                }
                tools.append(tool_spec)

        if not tools:
            return None

        return {"tools": tools}

    def execute_tool(self, tool_name: str, tool_input: dict) -> str:
        """Execute a tool call via the appropriate MCP server.

        Args:
            tool_name: The tool name as returned by the model.
            tool_input: The input arguments dict.

        Returns:
            The tool result as a string.
        """
        server = self._tool_to_server.get(tool_name)
        if not server:
            return json.dumps({"error": f"Unknown tool '{tool_name}'"})

        try:
            result = server.call_tool(tool_name, tool_input)
            logger.info(
                f"MCP tool '{tool_name}' executed successfully on server '{server.name}'"
            )
            return result
        except Exception as e:
            logger.error(f"MCP tool execution failed for '{tool_name}': {e}")
            return json.dumps({"error": f"Tool execution failed: {e}"})

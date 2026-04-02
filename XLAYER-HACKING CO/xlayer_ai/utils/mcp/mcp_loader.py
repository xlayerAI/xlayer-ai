"""
MCP (Model Context Protocol) tool loader.

Loads external tools from MCP servers for each agent based on mcp_config.json.
Each agent gets only the tools it needs (browser, file system, etc.).
"""

import json
import os
from langchain_mcp_adapters.client import MultiServerMCPClient
import asyncio

_CONFIG_NAME = "mcp_config.json"


def _find_mcp_config() -> str:
    """Resolve mcp_config.json path: env MCP_CONFIG, then project root, then cwd."""
    path = os.environ.get("MCP_CONFIG")
    if path and os.path.isfile(path):
        return path
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    candidate = os.path.join(root, _CONFIG_NAME)
    if os.path.isfile(candidate):
        return candidate
    if os.path.isfile(_CONFIG_NAME):
        return os.path.abspath(_CONFIG_NAME)
    return os.path.join(root, _CONFIG_NAME)


async def load_mcp_tools(agent_name=None):
    """
    Load MCP tools for specified agent(s) from mcp_config.json.

    Args:
        agent_name: List of agent names to load tools for.
                    If None, loads tools for all agents.
                    Example: ["initial_access"], ["reconnaissance"], ["planner"]

    Returns:
        List of tool objects from MCP servers.
    """
    config_path = _find_mcp_config()
    with open(config_path, "r", encoding="utf-8") as f:
        config = json.load(f)

    if agent_name:
        selected_agents = {
            agent: config[agent]
            for agent in agent_name
            if agent in config
        }
    else:
        selected_agents = config

    tools = []

    for name, servers in selected_agents.items():
        if not servers:
            continue

        for server_name, server_config in servers.items():
            if "transport" not in server_config:
                server_config["transport"] = (
                    "streamable_http" if "url" in server_config else "stdio"
                )

            client = MultiServerMCPClient({server_name: server_config})
            current_tools = await client.get_tools() if client else []

            if current_tools:
                tools.extend(current_tools)

    return tools if tools else []

"""
Re-exports MCP loader from the core utils module.

Swarm agents import from here:
    from src.utils.mcp.mcp_loader import load_mcp_tools
"""

from xlayer_ai.utils.mcp.mcp_loader import load_mcp_tools

__all__ = ["load_mcp_tools"]

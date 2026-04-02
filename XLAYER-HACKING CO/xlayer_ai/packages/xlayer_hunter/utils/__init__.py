"""
XLayer AI Utilities - Helper modules for the vulnerability hunter

Modules:
- agent_manager: Centralized agent configuration and routing
- logger: Logging utilities
- validators: Input validation helpers
"""

from xlayer_hunter.utils.agent_manager import (
    AgentManager,
    get_agent_color,
    get_agent_avatar,
    normalize_agent
)

__all__ = [
    "AgentManager",
    "get_agent_color",
    "get_agent_avatar",
    "normalize_agent",
]

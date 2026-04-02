"""
XLayer AI Prompts - System prompts for all agents

This module contains carefully crafted prompts for each agent in the system.
Prompts define agent behavior, capabilities, and constraints.

Usage:
    from xlayer_hunter.prompts import get_prompt, PLANNER_PROMPT, SQLI_HUNTER_PROMPT
    
    # Get prompt by agent name
    prompt = get_prompt("sqli")
    
    # Use directly
    from xlayer_hunter.prompts import SQLI_HUNTER_PROMPT
"""

from xlayer_hunter.prompts.core_agents import (
    PLANNER_PROMPT,
    RECON_PROMPT,
    EXPLOIT_PROMPT,
    REPORTER_PROMPT,
)
from xlayer_hunter.prompts.hunters.sqli import SQLI_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.xss import XSS_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.auth import AUTH_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.ssrf import SSRF_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.lfi import LFI_HUNTER_PROMPT
from xlayer_hunter.prompts.system import (
    SYSTEM_IDENTITY,
    CORE_PHILOSOPHY,
    OPERATIONAL_CONSTRAINTS,
)

# Prompt registry
PROMPTS = {
    # Core agents
    "planner": PLANNER_PROMPT,
    "recon": RECON_PROMPT,
    "exploit": EXPLOIT_PROMPT,
    "reporter": REPORTER_PROMPT,
    
    # Hunters
    "sqli": SQLI_HUNTER_PROMPT,
    "xss": XSS_HUNTER_PROMPT,
    "auth": AUTH_HUNTER_PROMPT,
    "ssrf": SSRF_HUNTER_PROMPT,
    "lfi": LFI_HUNTER_PROMPT,
}


def get_prompt(agent_name: str) -> str:
    """Get prompt for an agent by name"""
    return PROMPTS.get(agent_name.lower(), "")


def get_full_prompt(agent_name: str) -> str:
    """Get full prompt with system identity prepended"""
    agent_prompt = get_prompt(agent_name)
    if agent_prompt:
        return f"{SYSTEM_IDENTITY}\n\n{CORE_PHILOSOPHY}\n\n{agent_prompt}"
    return ""


__all__ = [
    # Functions
    "get_prompt",
    "get_full_prompt",
    "PROMPTS",
    
    # System
    "SYSTEM_IDENTITY",
    "CORE_PHILOSOPHY",
    "OPERATIONAL_CONSTRAINTS",
    
    # Core agents
    "PLANNER_PROMPT",
    "RECON_PROMPT",
    "EXPLOIT_PROMPT",
    "REPORTER_PROMPT",
    
    # Hunters
    "SQLI_HUNTER_PROMPT",
    "XSS_HUNTER_PROMPT",
    "AUTH_HUNTER_PROMPT",
    "SSRF_HUNTER_PROMPT",
    "LFI_HUNTER_PROMPT",
]

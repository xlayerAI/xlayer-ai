"""
Base prompts for XLayer AI agents.

Shared base prompts used across personas and modes.
Import these to build or extend agent prompts.
"""

from .initial_access_persona import BASE_INITACCESS_PROMPT
from .planner import BASE_PLANNER_PROMPT
from .recon import BASE_RECON_PROMPT
from .supervisor import BASE_SUPERVISOR_PROMPT
from .summary import BASE_SUMMARY_PROMPT
from .terminal import BASE_TERMINAL_PROMPT

__all__ = [
    "BASE_INITACCESS_PROMPT",
    "BASE_PLANNER_PROMPT",
    "BASE_RECON_PROMPT",
    "BASE_SUPERVISOR_PROMPT",
    "BASE_SUMMARY_PROMPT",
    "BASE_TERMINAL_PROMPT",
]

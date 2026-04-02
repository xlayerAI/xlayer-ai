"""
XLayer AI Hunter Prompts

Prompts for vulnerability-specific hunter agents.
"""

from xlayer_hunter.prompts.hunters.sqli import SQLI_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.xss import XSS_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.auth import AUTH_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.ssrf import SSRF_HUNTER_PROMPT
from xlayer_hunter.prompts.hunters.lfi import LFI_HUNTER_PROMPT

__all__ = [
    "SQLI_HUNTER_PROMPT",
    "XSS_HUNTER_PROMPT",
    "AUTH_HUNTER_PROMPT",
    "SSRF_HUNTER_PROMPT",
    "LFI_HUNTER_PROMPT",
]

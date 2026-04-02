"""
XLayer AI Vulnerability Hunters - Specialized agents for each vulnerability class

XLayer AI Compatible Scope:
1. Broken Authentication & Authorization (AuthHunter)
2. Injection - SQL, NoSQL, Command (SQLiHunter)
3. Cross-Site Scripting - XSS (XSSHunter)
4. Server-Side Request Forgery - SSRF (SSRFHunter)
5. File Inclusion - LFI/RFI (LFIHunter)
"""

from xlayer_hunter.core.vuln_hunters.base import BaseHunter, HunterResult, run_hunters_parallel
from xlayer_hunter.core.vuln_hunters.sqli import SQLiHunter
from xlayer_hunter.core.vuln_hunters.xss import XSSHunter
from xlayer_hunter.core.vuln_hunters.auth import AuthHunter
from xlayer_hunter.core.vuln_hunters.ssrf import SSRFHunter
from xlayer_hunter.core.vuln_hunters.lfi import LFIHunter

# Hunter registry for easy access
HUNTERS = {
    "sqli": SQLiHunter,
    "xss": XSSHunter,
    "auth": AuthHunter,
    "ssrf": SSRFHunter,
    "lfi": LFIHunter,
}

# XLayer AI compatible categories
SHANNON_LITE_CATEGORIES = {
    "broken_auth": ["auth"],
    "injection": ["sqli"],
    "xss": ["xss"],
    "ssrf": ["ssrf"],
}

__all__ = [
    "BaseHunter",
    "HunterResult",
    "run_hunters_parallel",
    "SQLiHunter",
    "XSSHunter",
    "AuthHunter",
    "SSRFHunter",
    "LFIHunter",
    "HUNTERS",
    "SHANNON_LITE_CATEGORIES",
]

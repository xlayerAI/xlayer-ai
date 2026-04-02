"""
XLayer Hunter - Autonomous Web Vulnerability Hunter

"Hack before hackers hack — Prove before you report"

This package contains:
- Planner Agent (Mission orchestration)
- Recon Agent (Attack surface mapping)
- Vulnerability Hunters (SQLi, XSS, Auth, SSRF, LFI)
- Exploit Agent (Proof validation)
- Reporter (Professional reports)

Usage:
    from xlayer_hunter import PlannerAgent
    
    async with PlannerAgent() as planner:
        report = await planner.start_mission("https://target.com")
"""

__version__ = "1.0.0"
__package_name__ = "xlayer_hunter"

from xlayer_hunter.core.planner import PlannerAgent, MissionState
from xlayer_hunter.core.recon import ReconAgent
from xlayer_hunter.core.exploit import ExploitAgent
from xlayer_hunter.core.reporter import Reporter

__all__ = [
    "PlannerAgent",
    "MissionState",
    "ReconAgent",
    "ExploitAgent",
    "Reporter",
]

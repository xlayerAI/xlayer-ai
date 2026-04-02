"""
XLayer AI Vulnerability Hunters - Specialized agents for each vulnerability class
"""

# Original 5 hunters
from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.core.vuln_hunters.sqli import SQLiHunter
from xlayer_ai.core.vuln_hunters.xss import XSSHunter
from xlayer_ai.core.vuln_hunters.auth import AuthHunter
from xlayer_ai.core.vuln_hunters.ssrf import SSRFHunter
from xlayer_ai.core.vuln_hunters.lfi import LFIHunter

# Agentic path — additional hunters
from xlayer_ai.core.vuln_hunters.ssti import SSTIHunter
from xlayer_ai.core.vuln_hunters.rce import RCEHunter
from xlayer_ai.core.vuln_hunters.xxe import XXEHunter
from xlayer_ai.core.vuln_hunters.open_redirect import OpenRedirectHunter
from xlayer_ai.core.vuln_hunters.cors import CORSHunter
from xlayer_ai.core.vuln_hunters.csrf import CSRFHunter
from xlayer_ai.core.vuln_hunters.subdomain_takeover import SubdomainTakeoverHunter
from xlayer_ai.core.vuln_hunters.graphql import GraphQLHunter
from xlayer_ai.core.vuln_hunters.race_condition import RaceConditionHunter
from xlayer_ai.core.vuln_hunters.deserialization import DeserializationHunter
from xlayer_ai.core.vuln_hunters.http_smuggling import HTTPSmugglingHunter

# Registry: name → class
HUNTER_REGISTRY = {
    "sqli":                SQLiHunter,
    "xss":                 XSSHunter,
    "auth":                AuthHunter,
    "ssrf":                SSRFHunter,
    "lfi":                 LFIHunter,
    "ssti":                SSTIHunter,
    "rce":                 RCEHunter,
    "xxe":                 XXEHunter,
    "open_redirect":       OpenRedirectHunter,
    "cors":                CORSHunter,
    "csrf":                CSRFHunter,
    "subdomain_takeover":  SubdomainTakeoverHunter,
    "graphql":             GraphQLHunter,
    "race_condition":      RaceConditionHunter,
    "deserialization":     DeserializationHunter,
    "http_smuggling":      HTTPSmugglingHunter,
}

ALL_HUNTERS = list(HUNTER_REGISTRY.values())

__all__ = [
    "BaseHunter",
    "HunterResult",
    "HUNTER_REGISTRY",
    "ALL_HUNTERS",
    # Original
    "SQLiHunter", "XSSHunter", "AuthHunter", "SSRFHunter", "LFIHunter",
    # New
    "SSTIHunter", "RCEHunter", "XXEHunter", "OpenRedirectHunter",
    "CORSHunter", "CSRFHunter", "SubdomainTakeoverHunter",
    "GraphQLHunter", "RaceConditionHunter", "DeserializationHunter",
    "HTTPSmugglingHunter",
]

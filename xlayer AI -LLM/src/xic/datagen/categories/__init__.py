"""
Registry of all category generators.
"""

from .exploit_chain import ExploitChainGenerator
from .code_audit import CodeAuditGenerator
from .vulnerability_analysis import VulnerabilityAnalysisGenerator
from .web_app_security import WebAppSecurityGenerator
from .secure_coding import SecureCodingGenerator
from .incident_response import IncidentResponseGenerator
from .cloud_security import CloudSecurityGenerator
from .api_security import APISecurityGenerator
from .network_security import NetworkSecurityGenerator
from .malware_analysis import MalwareAnalysisGenerator
from .log_analysis import LogAnalysisGenerator
from .threat_modeling import ThreatModelingGenerator
from .supply_chain import SupplyChainGenerator
from .cryptography import CryptographyGenerator
from .reverse_engineering import ReverseEngineeringGenerator

CATEGORY_REGISTRY = {
    "exploit_chain": ExploitChainGenerator(),
    "code_audit": CodeAuditGenerator(),
    "vulnerability_analysis": VulnerabilityAnalysisGenerator(),
    "web_app_security": WebAppSecurityGenerator(),
    "secure_coding": SecureCodingGenerator(),
    "incident_response": IncidentResponseGenerator(),
    "cloud_security": CloudSecurityGenerator(),
    "api_security": APISecurityGenerator(),
    "network_security": NetworkSecurityGenerator(),
    "malware_analysis": MalwareAnalysisGenerator(),
    "log_analysis": LogAnalysisGenerator(),
    "threat_modeling": ThreatModelingGenerator(),
    "supply_chain": SupplyChainGenerator(),
    "cryptography": CryptographyGenerator(),
    "reverse_engineering": ReverseEngineeringGenerator(),
}

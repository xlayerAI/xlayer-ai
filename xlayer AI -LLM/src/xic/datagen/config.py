"""
Configuration for the cybersecurity training data generator.
"""

from dataclasses import dataclass, field
from typing import Dict, List


@dataclass
class DataGenConfig:
    seed: int = 42
    total_entries: int = 100_000
    output_dir: str = "data/generated"
    combined_output: str = "data/generated/xlayer_cybersec_100k.jsonl"
    stats_output: str = "data/generated/gen_stats.json"

    complexity_weights: Dict[str, float] = field(default_factory=lambda: {
        "beginner": 0.20,
        "intermediate": 0.35,
        "advanced": 0.30,
        "expert": 0.15,
    })

    distribution: Dict[str, int] = field(default_factory=lambda: {
        "exploit_chain": 12_000,
        "code_audit": 11_000,
        "vulnerability_analysis": 12_000,
        "web_app_security": 9_000,
        "secure_coding": 9_000,
        "incident_response": 8_000,
        "cloud_security": 9_000,
        "api_security": 8_000,
        "network_security": 7_000,
        "malware_analysis": 6_000,
        "log_analysis": 6_000,
        "threat_modeling": 6_000,
        "supply_chain": 5_000,
        "cryptography": 5_000,
        "reverse_engineering": 5_000,
    })

    deny_keywords: List[str] = field(default_factory=lambda: [
        "ransomware-as-a-service", "botnet-for-hire", "ddos-for-hire",
    ])
    defensive_only: bool = True

    id_prefixes: Dict[str, str] = field(default_factory=lambda: {
        "exploit_chain": "xld-chain",
        "code_audit": "xld-audit",
        "vulnerability_analysis": "xld-vuln",
        "web_app_security": "xld-web",
        "secure_coding": "xld-secure",
        "incident_response": "xld-ir",
        "cloud_security": "xld-cloud",
        "api_security": "xld-api",
        "network_security": "xld-net",
        "malware_analysis": "xld-malware",
        "log_analysis": "xld-log",
        "threat_modeling": "xld-threat",
        "supply_chain": "xld-supply",
        "cryptography": "xld-crypto",
        "reverse_engineering": "xld-re",
    })

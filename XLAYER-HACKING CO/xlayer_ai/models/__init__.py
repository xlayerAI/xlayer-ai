"""
XLayer AI Models - Data structures for targets, vulnerabilities, and reports
"""

from xlayer_ai.models.target import Target, Endpoint, AttackSurface
from xlayer_ai.models.vulnerability import (
    Vulnerability,
    VulnHypothesis,
    ValidatedVuln,
    Severity,
    Confidence,
)
from xlayer_ai.models.report import Report, Finding, Evidence

__all__ = [
    "Target",
    "Endpoint",
    "AttackSurface",
    "Vulnerability",
    "VulnHypothesis",
    "ValidatedVuln",
    "Severity",
    "Confidence",
    "Report",
    "Finding",
    "Evidence",
]

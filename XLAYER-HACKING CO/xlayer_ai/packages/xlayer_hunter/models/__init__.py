"""
XLayer AI Models - Data structures for targets, vulnerabilities, and reports

XLayer AI Compatible Vulnerability Categories:
1. Broken Authentication & Authorization
2. Injection (SQL, Command, NoSQL)
3. Cross-Site Scripting (XSS)
4. Server-Side Request Forgery (SSRF)
"""

from xlayer_hunter.models.target import Target, Endpoint, AttackSurface
from xlayer_hunter.models.vulnerability import (
    Vulnerability,
    VulnHypothesis,
    ValidatedVuln,
    Severity,
    Confidence,
    VulnType,
    VulnCategory,
    VULN_CATEGORY_MAP,
    OWASP_MAPPING,
    CWE_MAPPING,
)
from xlayer_hunter.models.report import Report, Finding, Evidence

__all__ = [
    # Target models
    "Target",
    "Endpoint",
    "AttackSurface",
    # Vulnerability models
    "Vulnerability",
    "VulnHypothesis",
    "ValidatedVuln",
    "Severity",
    "Confidence",
    "VulnType",
    "VulnCategory",
    # Mappings
    "VULN_CATEGORY_MAP",
    "OWASP_MAPPING",
    "CWE_MAPPING",
    # Report models
    "Report",
    "Finding",
    "Evidence",
]

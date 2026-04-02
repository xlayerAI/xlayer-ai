"""
engine/logical_surface_map/supply_chain.py — Supply Chain Mapper

Scans JS files + HTML for:
  - Third-party API keys embedded in client-side code (Stripe, AWS, Firebase, etc.)
  - Third-party service dependencies (which external APIs the app relies on)
  - Subdomain references that might be exploitable (SSRF targets, takeover candidates)
  - Known-vulnerable tech stack hints matched against a static CVE hint table

Results stored in LogicalSurface.supply_chain_findings.
Used by:
  - ChainPlanner: token extraction (stripe_key_leaked, aws_key_leaked, etc.)
  - Reporter: supply chain risk section
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


# ── API key patterns (regex → (service_name, description, severity)) ─────────

_API_KEY_PATTERNS: List[tuple] = [
    # (name, regex, severity, description)
    ("stripe_publishable",  r"pk_(test|live)_[a-zA-Z0-9]{20,}",
     "high",     "Stripe publishable key — exposed to users, but reveals account + test/live mode"),
    ("stripe_secret",       r"sk_(test|live)_[a-zA-Z0-9]{20,}",
     "critical",  "Stripe SECRET API key — full billing/charge access"),
    ("aws_access_key",      r"AKIA[0-9A-Z]{16}",
     "critical",  "AWS Access Key ID — likely paired with a secret key"),
    ("firebase_api_key",    r"AIzaSy[a-zA-Z0-9_\-]{33}",
     "high",     "Firebase API key — access to Firebase project services"),
    ("google_api_key",      r"AIza[0-9A-Za-z\-_]{35}",
     "high",     "Google API key — Maps, Vision, Sheets, etc."),
    ("sendgrid_key",        r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}",
     "critical",  "SendGrid API key — send email as the application"),
    ("github_pat",          r"ghp_[a-zA-Z0-9]{36}",
     "critical",  "GitHub Personal Access Token"),
    ("github_oauth",        r"gho_[a-zA-Z0-9]{36}",
     "critical",  "GitHub OAuth Token"),
    ("slack_token",         r"xox[baprs]-[a-zA-Z0-9\-]+",
     "high",     "Slack API Token"),
    ("twilio_sid",          r"AC[a-f0-9]{32}",
     "high",     "Twilio Account SID"),
    ("mapbox_token",        r"pk\.eyJ1IjoiW",
     "medium",   "Mapbox public access token"),
    ("openai_key",          r"sk-[a-zA-Z0-9]{48}",
     "critical",  "OpenAI API key — LLM API access + billing"),
    ("anthropic_key",       r"sk-ant-[a-zA-Z0-9\-_]{90,}",
     "critical",  "Anthropic API key — Claude API access"),
    ("jwt_secret_hint",     r"secret\s*[:=]\s*['\"][a-zA-Z0-9!@#$%^&*]{8,}['\"]",
     "high",     "Potential JWT/session secret value hardcoded"),
]


# ── Third-party service domain patterns ───────────────────────────────────────

_THIRD_PARTY_SERVICES: Dict[str, List[str]] = {
    "stripe":          ["api.stripe.com", "js.stripe.com", "checkout.stripe.com"],
    "aws_s3":          ["s3.amazonaws.com", ".s3.", "cloudfront.net", "amazonaws.com"],
    "firebase":        ["firebaseapp.com", "firebase.google.com", "firestore.googleapis.com"],
    "twilio":          ["api.twilio.com", "twilio.com"],
    "sendgrid":        ["api.sendgrid.com", "sendgrid.net"],
    "google_oauth":    ["accounts.google.com", "oauth2.googleapis.com"],
    "github":          ["api.github.com"],
    "cloudinary":      ["cloudinary.com", "res.cloudinary.com"],
    "intercom":        ["widget.intercom.io", "api.intercom.io"],
    "sentry":          ["sentry.io", "o\\d+\\.ingest\\.sentry\\.io"],
    "datadog":         ["datadoghq.com", "browser-intake-datadoghq.com"],
    "segment":         ["api.segment.io", "cdn.segment.com"],
    "mixpanel":        ["api.mixpanel.com", "cdn.mxpnl.com"],
    "paypal":          ["paypal.com", "paypalobjects.com"],
    "braintree":       ["braintreegateway.com", "paypal.com/sdk"],
    "shopify":         ["cdn.shopify.com", "shopify.com"],
}


# ── CVE hint table (framework → known critical CVEs) ─────────────────────────
# Compact — just enough to prompt the AI to check further.
# Format: {framework_hint: [(cve_id, description, affected_versions)]}

_CVE_HINTS: Dict[str, List[Dict]] = {
    "django": [
        {"cve": "CVE-2023-23969", "desc": "Potential DoS via multipart form parsing", "versions": "< 4.1.6"},
        {"cve": "CVE-2022-34265", "desc": "SQL injection via Trunc/Extract", "versions": "< 4.0.6"},
    ],
    "laravel": [
        {"cve": "CVE-2021-3129", "desc": "RCE via Ignition debug mode + PHAR deserialization", "versions": "< 8.4.3"},
        {"cve": "CVE-2022-40482", "desc": "Auth bypass via remember_me cookie", "versions": "< 9.x"},
    ],
    "spring": [
        {"cve": "CVE-2022-22965", "desc": "Spring4Shell — RCE via DataBinder (Spring MVC)", "versions": "5.3.x < 5.3.18"},
        {"cve": "CVE-2022-22963", "desc": "RCE via Spring Cloud Function SPEL injection", "versions": "< 3.1.7"},
        {"cve": "CVE-2021-22053", "desc": "SSRF via Spring Actuator", "versions": "various"},
    ],
    "express": [
        {"cve": "CVE-2022-24999", "desc": "Express ReDoS via qs prototype pollution", "versions": "< 4.17.3"},
    ],
    "rails": [
        {"cve": "CVE-2023-22795", "desc": "ReDoS in Action Dispatch header parsing", "versions": "< 7.0.4.1"},
        {"cve": "CVE-2022-32224", "desc": "RCE via YAML deserialization in ActiveRecord", "versions": "< 6.1.7.1"},
    ],
    "flask": [
        {"cve": "CVE-2023-30861", "desc": "Session cookie vulnerability", "versions": "< 2.3.2"},
    ],
    "asp_net": [
        {"cve": "CVE-2023-21538", "desc": "DoS in .NET 6 HTTP/2 parsing", "versions": "various"},
    ],
}


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class SupplyChainFinding:
    """One supply chain finding — API key leak, third-party service, or CVE hint."""
    finding_type: str          # "api_key", "third_party_service", "cve_hint", "subdomain_dep"
    service: str               # e.g., "stripe", "aws_s3", "django"
    severity: str              # "critical", "high", "medium", "low"
    description: str
    evidence: str = ""         # matched string or context (truncated)
    source_file: str = ""      # JS file or URL where found
    cve: str = ""              # for cve_hint findings
    token: str = ""            # ChainPlanner token to emit

    def to_dict(self) -> dict:
        return {
            "type":        self.finding_type,
            "service":     self.service,
            "severity":    self.severity,
            "description": self.description,
            "evidence":    self.evidence[:200],
            "source_file": self.source_file,
            "cve":         self.cve,
            "token":       self.token,
        }


# ── Mapper ────────────────────────────────────────────────────────────────────

class SupplyChainMapper:
    """
    Scans JS/HTML content for supply chain risks.

    Usage:
        mapper = SupplyChainMapper()
        findings = mapper.scan(content, source_file="main.js")
        # Also scan tech_stack from LogicalSurface:
        findings += mapper.scan_tech_stack({"django": "header", "react": "js_deep"})
    """

    def __init__(self) -> None:
        self._seen_keys: Set[str] = set()   # deduplicate by (name + first 20 chars of evidence)

    def scan(self, content: str, source_file: str = "") -> List[SupplyChainFinding]:
        """
        Scan text content (JS file, HTML page) for API keys and service references.
        Returns list of findings.
        """
        findings: List[SupplyChainFinding] = []

        # 1. API key patterns
        for name, pattern, severity, desc in _API_KEY_PATTERNS:
            for m in re.finditer(pattern, content):
                evidence  = m.group(0)[:80]
                dedup_key = f"{name}:{evidence[:20]}"
                if dedup_key in self._seen_keys:
                    continue
                self._seen_keys.add(dedup_key)
                findings.append(SupplyChainFinding(
                    finding_type="api_key",
                    service=name,
                    severity=severity,
                    description=desc,
                    evidence=evidence,
                    source_file=source_file,
                    token=f"{name}_leaked",
                ))

        # 2. Third-party service references
        for service, domains in _THIRD_PARTY_SERVICES.items():
            for domain_pat in domains:
                if re.search(re.escape(domain_pat).replace(r"\\", "\\") if "." in domain_pat else domain_pat,
                             content, re.IGNORECASE):
                    dedup_key = f"svc:{service}"
                    if dedup_key in self._seen_keys:
                        continue
                    self._seen_keys.add(dedup_key)
                    findings.append(SupplyChainFinding(
                        finding_type="third_party_service",
                        service=service,
                        severity="medium",
                        description=f"App communicates with {service} — potential SSRF target or key leak surface",
                        source_file=source_file,
                        token=f"third_party_{service}",
                    ))
                    break   # one finding per service

        return findings

    def scan_tech_stack(self, tech_stack: Dict[str, str]) -> List[SupplyChainFinding]:
        """Check detected tech stack against CVE hint table."""
        findings: List[SupplyChainFinding] = []
        for tech, source in tech_stack.items():
            tech_lower = tech.lower()
            for framework, cves in _CVE_HINTS.items():
                if framework in tech_lower:
                    for cve_info in cves:
                        dedup_key = f"cve:{cve_info['cve']}"
                        if dedup_key in self._seen_keys:
                            continue
                        self._seen_keys.add(dedup_key)
                        findings.append(SupplyChainFinding(
                            finding_type="cve_hint",
                            service=framework,
                            severity="high",
                            description=(
                                f"{cve_info['cve']}: {cve_info['desc']} "
                                f"(affected: {cve_info.get('versions', 'unknown')})"
                            ),
                            cve=cve_info["cve"],
                            token=f"cve_{framework}",
                        ))
        return findings

    def scan_subdomains(self, content: str, base_domain: str) -> List[SupplyChainFinding]:
        """
        Extract subdomain references from content.
        Flags subdomains not belonging to the base domain as dependency targets.
        """
        findings: List[SupplyChainFinding] = []
        subdomain_re = re.compile(
            r'https?://([a-zA-Z0-9_\-]+\.' + re.escape(base_domain) + r')',
            re.IGNORECASE,
        )
        for m in subdomain_re.finditer(content):
            sub = m.group(1)
            dedup_key = f"sub:{sub}"
            if dedup_key in self._seen_keys:
                continue
            self._seen_keys.add(dedup_key)
            findings.append(SupplyChainFinding(
                finding_type="subdomain_dep",
                service=sub,
                severity="low",
                description=f"Subdomain dependency: {sub} — check for takeover if CNAME dangling",
                evidence=sub,
                token="subdomain_dependency",
            ))
        return findings

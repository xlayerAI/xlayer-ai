"""
engine/domain_scorer.py — Domain Scoring System

Evaluates each endpoint/subdomain for attack potential using deterministic
scoring. Higher score = more likely to yield vulnerabilities = solver priority.

Evaluates: WAF presence, HTTP status, redirects, auth forms,
endpoint count, technologies.

Called by Coordinator after LSM + dedup, before AgentSpawner.
Scores are injected into SpawnSpec priority for solver dispatch ordering.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

from loguru import logger


@dataclass
class DomainScore:
    """Score breakdown for a single domain/subdomain."""
    domain: str
    total_score: float = 0.0

    # Component scores (0-10 each)
    waf_score: float = 0.0          # No WAF = higher score (easier target)
    status_score: float = 0.0       # 200 = good, 403 = interesting, 404 = skip
    auth_score: float = 0.0         # Auth forms = juicy targets
    tech_score: float = 0.0         # Vuln-prone tech = higher score
    endpoint_density: float = 0.0   # More endpoints = bigger surface
    redirect_score: float = 0.0     # Redirect behavior (open redirect potential)
    param_score: float = 0.0        # Parameterized endpoints = injectable
    secret_score: float = 0.0       # Secrets found = high value

    details: Dict[str, Any] = field(default_factory=dict)

    def compute_total(self) -> float:
        """Weighted total for attack potential."""
        self.total_score = (
            self.waf_score * 1.5          # WAF absence is huge advantage
            + self.status_score * 1.0
            + self.auth_score * 2.0       # Auth = highest value targets
            + self.tech_score * 1.5       # Known-vuln tech = easy wins
            + self.endpoint_density * 1.0
            + self.redirect_score * 0.5
            + self.param_score * 2.0      # Params = direct injection points
            + self.secret_score * 3.0     # Secrets = instant wins
        )
        return self.total_score


@dataclass
class ScoringResult:
    """Output of domain scoring phase. endpoint_entity for report."""
    domain_scores: Dict[str, DomainScore]        # domain → score
    endpoint_scores: Dict[str, float]             # endpoint_url → score
    sorted_endpoints: List[Tuple[str, float]]     # [(url, score)] highest first
    total_domains: int = 0
    avg_score: float = 0.0
    endpoint_entity: Dict[str, str] = field(default_factory=dict)  # endpoint_url → "Admin"|"User"|"Invoice"|""


# Tech stacks known to have frequent vulns (HackerOne etc.)
_VULN_PRONE_TECH = {
    # High score (frequently vulnerable)
    "php": 8, "wordpress": 9, "joomla": 8, "drupal": 7,
    "laravel": 6, "codeigniter": 7, "cakephp": 7,
    "asp.net": 6, "iis": 5, "coldfusion": 9,
    "struts": 9, "spring": 5, "tomcat": 5,
    "rails": 5, "django": 4, "flask": 5,
    "express": 4, "node.js": 4, "nodejs": 4,

    # Medium score
    "nginx": 3, "apache": 4, "graphql": 6,
    "jquery": 3, "angular": 3, "react": 2, "vue": 2,

    # Low score (generally hardened)
    "cloudflare": 1, "akamai": 1, "fastly": 1,
    "next.js": 2, "nuxt": 2, "gatsby": 1,
}

# Path segment → entity hint for scoring and report
_ENTITY_PATH_HINTS = [
    ("/admin", "Admin"), ("/administrator", "Admin"), ("/dashboard", "Admin"),
    ("/user", "User"), ("/users", "User"), ("/profile", "User"), ("/account", "User"),
    ("/invoice", "Invoice"), ("/invoices", "Invoice"), ("/order", "Order"), ("/orders", "Order"),
    ("/api/", "API"), ("/internal", "Internal"), ("/manage", "Admin"),
]


def _entity_from_path(url: str) -> str:
    """Return entity hint from URL path (e.g. /admin → Admin)."""
    path = (urlparse(url).path or "").lower()
    for segment, entity in _ENTITY_PATH_HINTS:
        if segment.rstrip("/") in path or path.startswith(segment.strip("/")):
            return entity
    return ""


# WAFs that make exploitation harder
_KNOWN_WAFS = {
    "cloudflare", "akamai", "imperva", "incapsula", "sucuri",
    "f5", "bigip", "barracuda", "fortinet", "fortigate",
    "modsecurity", "aws waf", "azure waf", "gcp armor",
    "wordfence", "comodo", "stackpath", "reblaze",
}


class DomainScorer:
    """
    Domain/endpoint scoring system.

    Evaluates attack potential of each discovered endpoint using
    deterministic scoring. No LLM calls — pure heuristics.
    """

    def score(self, surface) -> ScoringResult:
        """
        Score all endpoints in a LogicalSurface.

        Args:
            surface: LogicalSurface object from ScoutLoop

        Returns:
            ScoringResult with per-domain and per-endpoint scores
        """
        domain_scores: Dict[str, DomainScore] = {}
        endpoint_scores: Dict[str, float] = {}
        endpoint_entity: Dict[str, str] = {}

        # Group endpoints by domain
        domain_endpoints: Dict[str, List[str]] = {}
        for url in surface.endpoints:
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.hostname or "unknown"
            if domain not in domain_endpoints:
                domain_endpoints[domain] = []
            domain_endpoints[domain].append(url)

        # Score each domain
        for domain, endpoints in domain_endpoints.items():
            ds = DomainScore(domain=domain)

            # 1. WAF Score — no WAF = 10, known WAF = 2
            ds.waf_score = self._score_waf(surface, endpoints)

            # 2. Status Score — reachable 200s are better than 404s
            ds.status_score = self._score_status(surface, endpoints)

            # 3. Auth Score — auth forms = high-value targets
            ds.auth_score = self._score_auth(surface, endpoints)

            # 4. Tech Score — vuln-prone tech = higher score
            ds.tech_score = self._score_tech(surface)

            # 5. Endpoint Density — more endpoints = bigger attack surface
            ds.endpoint_density = min(10.0, len(endpoints) * 0.5)

            # 6. Redirect Score — endpoints with redirect params
            ds.redirect_score = self._score_redirects(surface, endpoints)

            # 7. Param Score — parameterized endpoints
            ds.param_score = self._score_params(surface, endpoints)

            # 8. Secret Score — any secrets found on this domain
            ds.secret_score = self._score_secrets(surface, domain)

            ds.compute_total()
            domain_scores[domain] = ds

            # Per-endpoint scoring (domain score + endpoint-specific bonuses) — entity hint
            for ep_url in endpoints:
                ep_bonus = self._endpoint_bonus(surface, ep_url)
                entity = _entity_from_path(ep_url)
                if entity:
                    if entity == "Admin":
                        ep_bonus += 2.0  # Admin endpoints = higher priority
                    elif entity in ("User", "API"):
                        ep_bonus += 0.5
                    endpoint_entity[ep_url] = entity
                endpoint_scores[ep_url] = ds.total_score + ep_bonus

        # Sort endpoints by score (highest first)
        sorted_endpoints = sorted(
            endpoint_scores.items(),
            key=lambda x: x[1],
            reverse=True,
        )

        avg = (
            sum(endpoint_scores.values()) / len(endpoint_scores)
            if endpoint_scores else 0.0
        )

        result = ScoringResult(
            domain_scores=domain_scores,
            endpoint_scores=endpoint_scores,
            sorted_endpoints=sorted_endpoints,
            total_domains=len(domain_scores),
            avg_score=round(avg, 2),
            endpoint_entity=endpoint_entity,
        )

        # Log summary
        if domain_scores:
            top = sorted(
                domain_scores.values(),
                key=lambda d: d.total_score,
                reverse=True,
            )[:3]
            top_str = ", ".join(
                f"{d.domain}={d.total_score:.1f}" for d in top
            )
            logger.info(
                f"[DomainScorer] {len(domain_scores)} domains scored, "
                f"avg={avg:.1f}, top: {top_str}"
            )

        return result

    def _score_waf(self, surface, endpoints: List[str]) -> float:
        """No WAF = 10, detected WAF = 2-4."""
        profiles = getattr(surface, "behavior_profiles", {})

        waf_detected = False
        waf_name = ""
        for ep in endpoints:
            bp = profiles.get(ep, {})
            if isinstance(bp, dict):
                if bp.get("waf_detected"):
                    waf_detected = True
                    waf_name = bp.get("waf_name", "").lower()
                    break
            elif hasattr(bp, "waf_detected") and bp.waf_detected:
                waf_detected = True
                waf_name = getattr(bp, "waf_name", "").lower()
                break

        if not waf_detected:
            return 10.0  # No WAF = easy target

        # Known WAFs have different bypass difficulty
        if any(w in waf_name for w in ("cloudflare", "akamai", "imperva")):
            return 2.0  # Hard WAFs
        if any(w in waf_name for w in ("modsecurity", "wordfence")):
            return 4.0  # Bypassable WAFs
        return 3.0  # Unknown WAF

    def _score_status(self, surface, endpoints: List[str]) -> float:
        """Reachable endpoints (200) score highest, 403 = interesting, 404 = low."""
        nodes = surface.endpoints
        status_200 = 0
        status_403 = 0
        total = len(endpoints)

        for ep in endpoints:
            node = nodes.get(ep)
            if not node:
                continue
            # 403 endpoints are interesting (auth bypass potential)
            if node.auth_required:
                status_403 += 1
            else:
                status_200 += 1

        if total == 0:
            return 0.0

        # Mix of 200 and 403 is ideal (both accessible and protected targets)
        ratio_200 = status_200 / total
        ratio_403 = status_403 / total
        return min(10.0, ratio_200 * 6 + ratio_403 * 8)

    def _score_auth(self, surface, endpoints: List[str]) -> float:
        """Auth forms and protected endpoints = high value."""
        nodes = surface.endpoints
        auth_eps = sum(1 for ep in endpoints if nodes.get(ep, EndpointNodeStub()).auth_required)
        jwt_bonus = min(3.0, len(getattr(surface, "jwt_issues", [])) * 1.5)

        if auth_eps == 0 and jwt_bonus == 0:
            return 0.0

        return min(10.0, auth_eps * 2.0 + jwt_bonus)

    def _score_tech(self, surface) -> float:
        """Score based on known vuln-prone technologies."""
        tech = getattr(surface, "tech_stack", {})
        if not tech:
            return 5.0  # Unknown = assume medium

        max_score = 0
        for tech_name in tech:
            normalized = tech_name.lower().strip()
            for key, score in _VULN_PRONE_TECH.items():
                if key in normalized:
                    max_score = max(max_score, score)

        return float(max_score) if max_score else 5.0

    def _score_redirects(self, surface, endpoints: List[str]) -> float:
        """Endpoints with redirect-related params."""
        redirect_keywords = {"redirect", "return", "next", "goto", "url", "callback", "continue"}
        count = 0
        for ep in endpoints:
            node = surface.endpoints.get(ep)
            if not node:
                continue
            for param in node.parameters:
                if param.lower() in redirect_keywords:
                    count += 1
                    break
            if any(k in ep.lower() for k in redirect_keywords):
                count += 1

        return min(10.0, count * 3.0)

    def _score_params(self, surface, endpoints: List[str]) -> float:
        """Parameterized endpoints = injection targets."""
        total_params = 0
        param_eps = 0
        for ep in endpoints:
            node = surface.endpoints.get(ep)
            if not node:
                continue
            n_params = len(node.parameters)
            if n_params > 0:
                param_eps += 1
                total_params += n_params

        if param_eps == 0:
            return 0.0

        # More params = more injection points
        return min(10.0, param_eps * 1.5 + total_params * 0.3)

    def _score_secrets(self, surface, domain: str) -> float:
        """Secrets found on this domain."""
        secrets = getattr(surface, "secrets", [])
        if not secrets:
            return 0.0
        # Any secret found = high value
        return min(10.0, len(secrets) * 5.0)

    def _endpoint_bonus(self, surface, ep_url: str) -> float:
        """Per-endpoint bonus on top of domain score."""
        bonus = 0.0
        node = surface.endpoints.get(ep_url)
        if not node:
            return 0.0

        # Taint hints pointing to this endpoint
        taint_hints = getattr(surface, "taint_hints", [])
        for hint in taint_hints:
            if hint.js_file and ep_url in str(hint.js_file):
                bonus += 5.0

        # Behavioral profile with SQL error = SQLi likely
        profiles = getattr(surface, "behavior_profiles", {})
        bp = profiles.get(ep_url, {})
        if isinstance(bp, dict):
            if bp.get("sql_error_on_quote"):
                bonus += 10.0
            if bp.get("reflects_input"):
                bonus += 5.0
        elif hasattr(bp, "sql_error_on_quote"):
            if bp.sql_error_on_quote:
                bonus += 10.0
            if getattr(bp, "reflects_input", False):
                bonus += 5.0

        # Auth-protected with params = auth bypass + injection
        if node.auth_required and len(node.parameters) > 0:
            bonus += 3.0

        # Admin endpoints
        if any(k in ep_url.lower() for k in ("admin", "manage", "internal", "debug")):
            bonus += 4.0

        # GraphQL = deep injection surface
        if "graphql" in ep_url.lower():
            bonus += 3.0

        # Supply chain findings referencing this endpoint
        sc_findings = getattr(surface, "supply_chain_findings", [])
        for f in sc_findings:
            if f.get("severity") in ("critical", "high"):
                bonus += 2.0

        return bonus


class EndpointNodeStub:
    """Minimal stub for type safety when endpoint not found."""
    auth_required = False
    parameters: set = set()

"""
engine/logical_surface_map/graph.py — XLayer Entity-State Graph (Memory for LSM)
The logical "Blueprint" of the target application.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Any


@dataclass
class EndpointNode:
    url: str
    method: str = "GET"                                        # primary method (backward compat)
    methods: Set[str] = field(default_factory=set)             # Fix 12: all observed methods
    parameters: Set[str] = field(default_factory=set)          # param names (backward compat)
    typed_params: Dict[str, Dict[str, str]] = field(           # Fix 13: {name: {location, type}}
        default_factory=dict
    )
    auth_required: bool = False
    role_level: str = "guest"  # guest, user, admin
    linked_entities: List[str] = field(default_factory=list)
    discovery_source: str = "spider"  # spider, js_analysis, js_deep, guessing, openapi, graphql
    tech_stack: Set[str] = field(default_factory=set)

    def add_method(self, method: str) -> None:
        """Fix 12: track every HTTP method observed for this endpoint."""
        m = method.upper()
        self.methods.add(m)
        # Keep primary method as the most privileged one seen
        _priority = {"DELETE": 0, "PUT": 1, "PATCH": 2, "POST": 3, "GET": 4, "HEAD": 5}
        if _priority.get(m, 9) < _priority.get(self.method, 9):
            self.method = m

    def add_typed_param(self, name: str, location: str = "query", ptype: str = "string") -> None:
        """Fix 13: record param with location (query/body/path/header) and type."""
        self.parameters.add(name)  # backward compat
        self.typed_params[name] = {"location": location, "type": ptype}

    @property
    def body_params(self) -> List[str]:
        """Params sent in request body (POST/PUT/PATCH)."""
        return [n for n, m in self.typed_params.items() if m.get("location") == "body"]

    @property
    def path_params(self) -> List[str]:
        """Params embedded in URL path (e.g. /users/{id})."""
        return [n for n, m in self.typed_params.items() if m.get("location") == "path"]


@dataclass
class TaintHint:
    """A potential vulnerability hint found during deep JS taint analysis."""
    source: str       # e.g. "location.search", "URLSearchParams"
    sink: str         # e.g. "innerHTML", "window.location", "fetch"
    vuln_type: str    # e.g. "xss", "open_redirect", "ssrf"
    context: str = "" # surrounding JS snippet for reference
    js_file: str = "" # which JS file it came from


@dataclass
class LogicalSurface:
    """Relational map of the target application surface."""
    base_url: str
    endpoints: Dict[str, EndpointNode] = field(default_factory=dict)
    js_files: Set[str] = field(default_factory=set)
    entities: Set[str] = field(default_factory=set)  # e.g., 'User', 'Order', 'Invoice'

    # Global discoveries
    tech_stack: Dict[str, str] = field(default_factory=dict)
    secrets: List[Dict[str, str]] = field(default_factory=list)
    taint_hints: List[TaintHint] = field(default_factory=list)
    vuln_hints: List[dict] = field(default_factory=list)
    dev_comments: List[dict] = field(default_factory=list)
    sourcemap_sources: List[str] = field(default_factory=list)

    # Behavioral fingerprints (from BehaviorProbe — Phase 0c)
    behavior_profiles: Dict[str, Any] = field(default_factory=dict)   # {url: BehaviorProfile}

    # Supply chain findings (from SupplyChainMapper — JS scan + tech stack)
    supply_chain_findings: List[dict] = field(default_factory=list)   # [SupplyChainFinding.to_dict()]

    # HTTP Probe findings (from HttpProbe)
    openapi_spec_url: str = ""                                         # e.g. "/openapi.json"
    graphql_endpoint: str = ""                                         # e.g. "/graphql"
    graphql_queries: List[str] = field(default_factory=list)           # query field names
    graphql_mutations: List[str] = field(default_factory=list)         # mutation field names
    security_header_misconfigs: List[dict] = field(default_factory=list)  # {header, value, issue}
    missing_security_headers: List[str] = field(default_factory=list)  # absent security headers
    allowed_methods: Dict[str, List[str]] = field(default_factory=dict)   # path → [GET, POST, ...]
    jwt_issues: List[dict] = field(default_factory=list)               # {source, algorithm, issues}
    cors_open: bool = False                                            # CORS: * detected

    # Domain scoring (computed by DomainScorer after LSM)
    domain_scores: Dict[str, float] = field(default_factory=dict)      # {domain: total_score}
    endpoint_scores: Dict[str, float] = field(default_factory=dict)     # {url: attack_potential_score}
    endpoint_entity: Dict[str, str] = field(default_factory=dict)       # {url: "Admin"|"User"|"Invoice"|""}

    def add_endpoint(self, url: str, method: str = "GET", params: Optional[List[str]] = None, source: str = "spider"):
        if url not in self.endpoints:
            node = EndpointNode(url=url, method=method.upper(), discovery_source=source)
            node.methods.add(method.upper())
            self.endpoints[url] = node
        else:
            # Fix 12: accumulate all methods, update primary if more privileged
            self.endpoints[url].add_method(method)
        if params:
            self.endpoints[url].parameters.update(params)

    def set_endpoint_auth(self, url: str, auth_required: bool = True, role_level: str = "user") -> None:
        """Mark an endpoint as protected (for auth_scoping strategy)."""
        if url in self.endpoints:
            self.endpoints[url].auth_required = auth_required
            self.endpoints[url].role_level = role_level

    def add_params_to_endpoint(self, url: str, params: List[str], location: str = "query") -> None:
        """Attach discovered params to an endpoint.
        Fix 13: location hint (query/body/path/header) stored in typed_params.
        """
        if url in self.endpoints and params:
            for p in params:
                self.endpoints[url].add_typed_param(p, location=location)

    def add_typed_params_to_endpoint(
        self,
        url: str,
        params: List[Dict[str, str]],
    ) -> None:
        """Add params with full type metadata: [{"name": "id", "location": "path", "type": "int"}]."""
        if url not in self.endpoints or not params:
            return
        for p in params:
            name = p.get("name", "")
            if name:
                self.endpoints[url].add_typed_param(
                    name,
                    location=p.get("location", "query"),
                    ptype=p.get("type", "string"),
                )

    def to_summary(self) -> str:
        """Condensed summary for the AI Reasoning loop."""
        summary = [f"### LOGICAL SURFACE SUMMARY: {self.base_url}"]
        summary.append(f"Endpoints Mapped: {len(self.endpoints)}")
        summary.append(f"JS Files Found: {len(self.js_files)}")

        if self.entities:
            summary.append(f"Entities: {', '.join(sorted(self.entities)[:15])}")

        summary.append(f"Tech Stack: {self.tech_stack}")

        # OpenAPI spec
        if self.openapi_spec_url:
            summary.append(f"OpenAPI Spec: {self.openapi_spec_url} ({len(self.endpoints)} endpoints from spec)")

        # GraphQL
        if self.graphql_endpoint:
            summary.append(
                f"GraphQL: {self.graphql_endpoint} "
                f"({len(self.graphql_queries)} queries, {len(self.graphql_mutations)} mutations)"
            )

        # Security header misconfigs
        if self.security_header_misconfigs or self.missing_security_headers:
            summary.append(
                f"Security Headers: {len(self.missing_security_headers)} missing, "
                f"{len(self.security_header_misconfigs)} misconfigured"
                + (" | CORS:* OPEN" if self.cors_open else "")
            )

        # HTTP method audit
        if self.allowed_methods:
            writable = {
                p: methods for p, methods in self.allowed_methods.items()
                if any(m in methods for m in ("DELETE", "PUT", "PATCH"))
            }
            summary.append(
                f"HTTP Methods (OPTIONS): {len(self.allowed_methods)} probed"
                + (f", {len(writable)} with writable methods" if writable else "")
            )

        # Fix 12: endpoints with multiple methods (GET+POST+DELETE — higher attack surface)
        multi_method = [
            f"{u} [{','.join(sorted(n.methods))}]"
            for u, n in self.endpoints.items()
            if len(n.methods) > 1
        ]
        if multi_method:
            summary.append(f"Multi-Method Endpoints ({len(multi_method)}): " + ", ".join(multi_method[:5]))

        # Fix 13: endpoints with body params (POST/PUT — JSON injection targets)
        body_ep = [
            f"{u}({','.join(n.body_params[:4])})"
            for u, n in self.endpoints.items()
            if n.body_params
        ]
        if body_ep:
            summary.append(f"Body-Param Endpoints ({len(body_ep)}): " + ", ".join(body_ep[:5]))

        # Supply chain findings
        if self.supply_chain_findings:
            critical_sc = [f for f in self.supply_chain_findings if f.get("severity") == "critical"]
            key_leaks   = [f for f in self.supply_chain_findings if f.get("type") == "api_key"]
            cve_hints   = [f for f in self.supply_chain_findings if f.get("type") == "cve_hint"]
            services    = list({f["service"] for f in self.supply_chain_findings if f.get("type") == "third_party_service"})
            summary.append(
                f"Supply Chain: {len(self.supply_chain_findings)} findings"
                + (f" | CRITICAL: {len(critical_sc)}" if critical_sc else "")
                + (f" | Key leaks: {len(key_leaks)}" if key_leaks else "")
                + (f" | CVE hints: {len(cve_hints)}" if cve_hints else "")
                + (f" | Services: {', '.join(services[:6])}" if services else "")
            )

        # Behavioral fingerprints
        if self.behavior_profiles:
            waf_eps   = [u for u, p in self.behavior_profiles.items() if getattr(p, "waf_detected", False)]
            sql_eps   = [u for u, p in self.behavior_profiles.items() if getattr(p, "sql_error_on_quote", False)]
            refl_eps  = [u for u, p in self.behavior_profiles.items() if getattr(p, "reflects_input", False)]
            frameworks = list({getattr(p, "error_signature", "") for p in self.behavior_profiles.values() if getattr(p, "error_signature", "")})
            summary.append(
                f"Behavioral Fingerprint: {len(self.behavior_profiles)} profiled"
                + (f" | WAF-protected: {len(waf_eps)}" if waf_eps else "")
                + (f" | SQL-error: {len(sql_eps)}" if sql_eps else "")
                + (f" | Reflecting: {len(refl_eps)}" if refl_eps else "")
                + (f" | Frameworks: {', '.join(frameworks)}" if frameworks else "")
            )

        # JWT issues
        if self.jwt_issues:
            critical = [j for j in self.jwt_issues if any("none" in i or "critical" in i for i in j.get("issues", []))]
            summary.append(
                f"JWT: {len(self.jwt_issues)} token(s) analyzed"
                + (f" ({len(critical)} critical issues)" if critical else "")
            )

        # Taint + vuln hints
        if self.taint_hints:
            summary.append(f"Taint Hints: {len(self.taint_hints)} ({', '.join(sorted(set(h.vuln_type for h in self.taint_hints)))})")
        if self.vuln_hints:
            high = [h for h in self.vuln_hints if h.get("confidence") == "high"]
            summary.append(f"Vuln Hints: {len(self.vuln_hints)} ({len(high)} high-confidence)")
        if self.dev_comments:
            high_comments = [c for c in self.dev_comments if c.get("severity") == "high"]
            summary.append(f"Dev Comments: {len(self.dev_comments)} ({len(high_comments)} critical)")
        if self.sourcemap_sources:
            summary.append(f"Source Map: {len(self.sourcemap_sources)} original files")

        # Domain scores (attack potential)
        if self.domain_scores:
            scored = sorted(self.domain_scores.items(), key=lambda x: x[1], reverse=True)
            top_domains = ", ".join(f"{d}={s:.1f}" for d, s in scored[:5])
            summary.append(f"Domain Scores: {len(self.domain_scores)} scored | Top: {top_domains}")
        if self.endpoint_scores:
            top_eps = sorted(self.endpoint_scores.items(), key=lambda x: x[1], reverse=True)[:5]
            summary.append(
                f"Top Attack Targets: "
                + ", ".join(f"{url.split('/')[-1] or url}={score:.1f}" for url, score in top_eps)
            )

        # High-value targets — categorised so LLM gets a richer picture
        # even on large apps with 50+ endpoints.
        _hv_cats = {
            "admin":   [u for u in self.endpoints if "admin"   in u.lower()],
            "auth":    [u for u in self.endpoints if any(k in u.lower() for k in ("auth", "login", "oauth", "sso"))],
            "config":  [u for u in self.endpoints if any(k in u.lower() for k in ("config", "env", "debug", "internal"))],
            "graphql": [u for u in self.endpoints if "graphql" in u.lower()],
            "api":     [u for u in self.endpoints if "/api"    in u.lower()],
        }
        hv_parts: List[str] = []
        for cat, urls in _hv_cats.items():
            if urls:
                sample = ", ".join(urls[:6])
                hv_parts.append(f"{cat}({len(urls)}): {sample}")
        if hv_parts:
            summary.append("High-Value Endpoints | " + " | ".join(hv_parts))

        return "\n".join(summary)

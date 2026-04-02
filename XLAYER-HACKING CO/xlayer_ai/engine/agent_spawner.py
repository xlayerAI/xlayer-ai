"""
engine/agent_spawner.py — Dynamic Context-Aware Agent Spawning

Watches LogicalSurface findings → generates SpawnSpecs → NO fixed limit.
  10 findings  →  10 agents
 100 findings  → 100 agents
1000 findings  → 1000 agents

DynamicDispatch controls CONCURRENCY (not total count) via adaptive semaphore:
  ≤10 agents  → all run simultaneously
  ≤50 agents  → 20 at a time
  ≤200 agents → 35 at a time
  1000+       → 50 at a time (API rate limit safe)
"""

import asyncio
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from loguru import logger

from xlayer_ai.engine.logical_surface_map.graph import LogicalSurface


# ── SpawnSpec ─────────────────────────────────────────────────────────────────

@dataclass
class SpawnSpec:
    """
    Everything a Solver needs to start with pre-loaded evidence.
    Replaces generic (endpoint × vuln_type) matrix with context-rich specs.
    context_values = token/session_id to inject for chaining.
    """
    agent_type: str                           # "sqli", "xss", "jwt_bypass", etc.
    endpoint: str                             # primary target endpoint
    evidence: dict                            # pre-collected context from LSM
    priority: str = "medium"                  # "critical" / "high" / "medium" / "low"
    initial_confidence: float = 0.0           # pre-loaded (0.0–1.0)
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    context_values: Optional[Dict[str, str]] = None  # e.g. {"token": "eyJ...", "session_id": "abc"} for chaining


# Ephemeral specialist naming — one spec = one specialist agent (e.g. "SQLi Specialist")
def specialist_label(agent_type: str) -> str:
    """Human-readable specialist role for logging/reports. E.g. sqli -> 'SQLi Specialist'."""
    labels = {
        "sqli": "SQLi Specialist",
        "xss_reflected": "XSS Specialist",
        "xss_stored": "XSS Stored Specialist",
        "auth_bypass": "Auth Bypass Specialist",
        "jwt_bypass": "JWT Bypass Specialist",
        "ssrf": "SSRF Specialist",
        "lfi": "LFI Specialist",
        "rce": "RCE Specialist",
        "ssti": "SSTI Specialist",
        "xxe": "XXE Specialist",
        "graphql": "GraphQL Specialist",
    }
    return labels.get((agent_type or "").lower(), f"{(agent_type or 'generic').replace('_', ' ').title()} Specialist")


# ── AgentSpawner ──────────────────────────────────────────────────────────────

class AgentSpawner:
    """
    Watches LogicalSurface and generates a SpawnSpec for every actionable finding.
    No fixed limit — 1 finding = 1 agent, 1000 findings = 1000 agents.
    """

    def watch(self, surface: LogicalSurface) -> List[SpawnSpec]:
        specs: List[SpawnSpec] = []

        # ── 1. JWT issues ─────────────────────────────────────────────────────
        for jwt in surface.jwt_issues:
            issues = jwt.get("issues", [])
            if any("none" in i.lower() for i in issues):
                specs.append(SpawnSpec(
                    agent_type="jwt_bypass",
                    endpoint="/api/login",
                    evidence=jwt,
                    priority="critical",
                    initial_confidence=0.80,
                ))
            elif any("weak" in i.lower() or "hs256" in i.lower() for i in issues):
                specs.append(SpawnSpec(
                    agent_type="jwt_crack",
                    endpoint="/api/login",
                    evidence=jwt,
                    priority="high",
                    initial_confidence=0.65,
                ))

        # ── 2. Taint hints (XSS / SSRF / open_redirect) ──────────────────────
        for taint in surface.taint_hints:
            conf = 0.65 if taint.vuln_type == "xss" else 0.55
            specs.append(SpawnSpec(
                agent_type=taint.vuln_type,
                endpoint=taint.js_file or "",
                evidence={
                    "source":  taint.source,
                    "sink":    taint.sink,
                    "context": taint.context,
                    "js_file": taint.js_file,
                },
                priority="high",
                initial_confidence=conf,
            ))

        # ── 3. Source map vuln hints ──────────────────────────────────────────
        for hint in surface.vuln_hints:
            conf_label = hint.get("confidence", "low")
            if conf_label == "high":
                specs.append(SpawnSpec(
                    agent_type=hint["vuln_type"],
                    endpoint=hint.get("source_file", ""),
                    evidence=hint,
                    priority="high",
                    initial_confidence=0.70,
                ))
            elif conf_label == "medium":
                specs.append(SpawnSpec(
                    agent_type=hint["vuln_type"],
                    endpoint=hint.get("source_file", ""),
                    evidence=hint,
                    priority="medium",
                    initial_confidence=0.45,
                ))

        # ── 4. CORS open → test every auth-required endpoint ─────────────────
        if surface.cors_open:
            for ep_url, node in surface.endpoints.items():
                if node.auth_required:
                    specs.append(SpawnSpec(
                        agent_type="cors",
                        endpoint=ep_url,
                        evidence={"cors_open": True, "role_level": node.role_level},
                        priority="medium",
                        initial_confidence=0.50,
                    ))

        # ── 5. Security header misconfigs (already confirmed, high conf) ──────
        for misconfig in surface.security_header_misconfigs:
            specs.append(SpawnSpec(
                agent_type="header_misconfig",
                endpoint="/",
                evidence=misconfig,
                priority="low",
                initial_confidence=0.90,
            ))

        # ── 6. Endpoints with params → SQLi + XSS per endpoint ───────────────
        for ep_url, node in surface.endpoints.items():
            if not node.parameters:
                continue
            params = list(node.parameters)
            method = node.method

            # SQLi — every method
            specs.append(SpawnSpec(
                agent_type="sqli",
                endpoint=ep_url,
                evidence={"params": params, "method": method},
                priority="high",
                initial_confidence=0.20,
                method=method,
                params=params,
            ))

            # XSS — GET only (reflected)
            if method == "GET":
                specs.append(SpawnSpec(
                    agent_type="xss",
                    endpoint=ep_url,
                    evidence={"params": params},
                    priority="medium",
                    initial_confidence=0.20,
                    method="GET",
                    params=params,
                ))

        # ── 7. Auth-required endpoints → auth bypass ─────────────────────────
        for ep_url, node in surface.endpoints.items():
            if node.auth_required:
                specs.append(SpawnSpec(
                    agent_type="auth_bypass",
                    endpoint=ep_url,
                    evidence={"role_level": node.role_level},
                    priority="high",
                    initial_confidence=0.30,
                ))

        # ── 8. GraphQL endpoint ───────────────────────────────────────────────
        if surface.graphql_endpoint:
            specs.append(SpawnSpec(
                agent_type="graphql",
                endpoint=surface.graphql_endpoint,
                evidence={
                    "queries":   surface.graphql_queries[:10],
                    "mutations": surface.graphql_mutations[:10],
                },
                priority="high",
                initial_confidence=0.55,
            ))

        # ── 9. High-severity dev comments ────────────────────────────────────
        for comment in surface.dev_comments:
            if comment.get("severity") == "high":
                specs.append(SpawnSpec(
                    agent_type="dev_comment_lead",
                    endpoint=comment.get("source_file", ""),
                    evidence=comment,
                    priority="medium",
                    initial_confidence=0.40,
                ))

        # ── 10. Secrets found → verify if live ───────────────────────────────
        for secret in surface.secrets:
            specs.append(SpawnSpec(
                agent_type="secret_verify",
                endpoint="/",
                evidence=secret,
                priority="high",
                initial_confidence=0.60,
            ))

        # ── 11. Supply chain findings → targeted follow-up agents ─────────────
        # API key leaks → high-priority secret_verify agents
        # CVE hints → targeted RCE/SSTI agents for that framework
        # Third-party services → SSRF targets if SSRF also seen
        _ssrf_in_findings = any(
            hint.get("vuln_type") == "ssrf" for hint in surface.vuln_hints
        )
        for sc in surface.supply_chain_findings:
            sc_type     = sc.get("type", "")
            sc_service  = sc.get("service", "")
            sc_severity = sc.get("severity", "low")
            sc_token    = sc.get("token", "")

            if sc_type == "api_key" and sc_severity in ("critical", "high"):
                # Leaked API key → spawn secret_verify with the key evidence
                specs.append(SpawnSpec(
                    agent_type="secret_verify",
                    endpoint=surface.base_url,
                    evidence=sc,
                    priority="critical" if sc_severity == "critical" else "high",
                    initial_confidence=0.80,
                ))

            elif sc_type == "cve_hint":
                # CVE hint for a framework → spawn targeted vuln agent
                cve_vuln_map = {
                    "laravel": "rce",    # CVE-2021-3129 (debug mode + phar)
                    "spring":  "rce",    # Spring4Shell
                    "rails":   "rce",    # deserialization
                    "flask":   "ssti",   # Werkzeug debugger
                    "django":  "sqli",   # SQLi via Trunc
                }
                vuln_type = cve_vuln_map.get(sc_service, "rce")
                specs.append(SpawnSpec(
                    agent_type=vuln_type,
                    endpoint=surface.base_url,
                    evidence={
                        "cve_context":  sc.get("description", ""),
                        "cve_id":       sc.get("cve", ""),
                        "framework":    sc_service,
                    },
                    priority="high",
                    initial_confidence=0.45,
                ))

            elif sc_type == "third_party_service" and _ssrf_in_findings:
                # Third-party service + existing SSRF signal → SSRF chain
                if sc_service in ("aws_s3", "firebase", "stripe"):
                    specs.append(SpawnSpec(
                        agent_type="ssrf",
                        endpoint=surface.base_url,
                        evidence={
                            "ssrf_chain":   True,
                            "target_cloud": sc_service,
                            "description":  sc.get("description", ""),
                        },
                        priority="high",
                        initial_confidence=0.40,
                    ))

        # Sort: critical first, then by initial_confidence descending
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        specs.sort(key=lambda s: (_order.get(s.priority, 4), -s.initial_confidence))

        logger.info(
            f"[AgentSpawner] {len(specs)} agents from surface findings | "
            f"critical={sum(1 for s in specs if s.priority == 'critical')} "
            f"high={sum(1 for s in specs if s.priority == 'high')} "
            f"medium={sum(1 for s in specs if s.priority == 'medium')} "
            f"low={sum(1 for s in specs if s.priority == 'low')}"
        )
        return specs


# ── DynamicDispatch ───────────────────────────────────────────────────────────

class DynamicDispatch:
    """
    Run N agents in parallel — no fixed limit on total agent count.

    Concurrency adapts automatically:
      ≤10  agents → all run at once
      ≤50  agents → 20 concurrent
      ≤200 agents → 35 concurrent
      1000+       → 50 concurrent  (API rate-limit safe)

    Pass max_concurrency to override adaptive scaling.
    """

    @staticmethod
    def _adaptive_concurrency(n: int) -> int:
        if n <= 10:  return n
        if n <= 50:  return 20
        if n <= 200: return 35
        return 50

    @staticmethod
    async def run(
        fn: Callable[[SpawnSpec], Any],
        specs: List[SpawnSpec],
        max_concurrency: Optional[int] = None,
        timeout_per_agent: float = 600.0,
    ) -> List[Any]:
        """
        Execute fn(spec) for every spec in parallel.

        Args:
            fn:                 Async function — receives SpawnSpec, returns result
            specs:              All agent specs to run (no count limit)
            max_concurrency:    Override adaptive concurrency (None = auto)
            timeout_per_agent:  Per-agent timeout in seconds

        Returns:
            Results list (same order as specs). None for timed-out/failed agents.
        """
        if not specs:
            return []

        concurrency = max_concurrency or DynamicDispatch._adaptive_concurrency(len(specs))
        semaphore   = asyncio.Semaphore(concurrency)
        total       = len(specs)

        logger.info(
            f"[DynamicDispatch] Launching {total} agents "
            f"(concurrency={concurrency})"
        )

        async def _run_one(spec: SpawnSpec, idx: int) -> Any:
            async with semaphore:
                logger.debug(
                    f"[DynamicDispatch] [{idx+1}/{total}] "
                    f"{spec.agent_type} @ {spec.endpoint} "
                    f"priority={spec.priority} "
                    f"conf={spec.initial_confidence:.2f}"
                )
                try:
                    return await asyncio.wait_for(
                        fn(spec),
                        timeout=timeout_per_agent,
                    )
                except asyncio.TimeoutError:
                    logger.warning(
                        f"[DynamicDispatch] TIMEOUT [{idx+1}/{total}]: "
                        f"{spec.agent_type} @ {spec.endpoint}"
                    )
                    return None
                except Exception as e:
                    logger.error(
                        f"[DynamicDispatch] ERROR [{idx+1}/{total}]: "
                        f"{spec.agent_type} @ {spec.endpoint} — {e}"
                    )
                    return None

        results = await asyncio.gather(
            *[_run_one(s, i) for i, s in enumerate(specs)],
            return_exceptions=False,
        )

        completed = sum(1 for r in results if r is not None)
        logger.success(
            f"[DynamicDispatch] Complete: {completed}/{total} agents finished"
        )
        return list(results)

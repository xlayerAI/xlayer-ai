"""
engine/chain/planner.py — Attack Chain Planner

Two passes:
  Pass 1: Pattern matching — known chains (fast, O(n))
  Pass 2: LLM correlation  — novel chains (smart, for unmatched findings)

Pattern library grows over time via PatternDistiller.
Success rates from PatternStore guide priority.
"""

import json
from typing import Any, Dict, List, Optional, Set

from loguru import logger

from xlayer_ai.engine.agentic_loop import _extract_json_block
from xlayer_ai.engine.llm import LLMClient
from xlayer_ai.engine.logical_surface_map.graph import LogicalSurface
from .models import ChainPattern, ChainSpec, ChainStep
from .pattern_store import PatternStore


# ── Semantic aliases — solver vuln_type → chain requires tokens ───────────────

_VULN_TYPE_ALIASES: Dict[str, Set[str]] = {
    "jwt_bypass":       {"jwt_none_alg", "jwt_weak_secret"},
    "jwt_crack":        {"jwt_weak_secret"},
    "sqli":             {"sqli_confirmed"},
    "ssrf":             {"ssrf_confirmed"},
    "idor":             {"idor_confirmed"},
    "auth_bypass":      {"auth_bypass_confirmed"},
    "xss":              {"xss_confirmed"},
    "xss_reflected":    {"xss_confirmed"},
    "xss_stored":       {"xss_confirmed"},
    "cors":             {"cors_open"},
    "graphql":          {"graphql_endpoint"},
    "rce":              {"command_exec", "debug_endpoint"},
    "ssti":             {"command_exec"},
    "lfi":              {"lfi_confirmed"},
    "open_redirect":    {"open_redirect_confirmed"},
}

_LLM_CORRELATE_PROMPT = """\
You are an expert penetration tester analyzing security findings.

## Application Surface
{surface_summary}

## Confirmed Findings
{findings_summary}

## Task
Identify multi-step attack chains that connect these findings.
Each chain must:
1. Use at least 2 findings as building blocks
2. Have a clear step-by-step execution path
3. Show how the output of step N feeds into step N+1
4. Be practically exploitable (not theoretical)

For each chain, return:
- name: snake_case identifier
- description: one line
- severity: critical / high / medium
- confidence: 0.0-1.0
- steps: list of {name, description, input_keys, output_keys}
- evidence_keys: which findings this chain uses

Return JSON:
```json
{
  "chains": [
    {
      "name": "example_chain",
      "description": "...",
      "severity": "critical",
      "confidence": 0.75,
      "steps": [
        {
          "name": "step_one",
          "description": "...",
          "input_keys": ["jwt_token"],
          "output_keys": ["cracked_secret"]
        }
      ],
      "evidence_keys": ["jwt_token", "admin_endpoint"]
    }
  ]
}
```
If no chains are possible, return: {"chains": []}
"""


class ChainPlanner:
    """
    Builds ChainSpecs from LSM surface + solver findings.

    Pass 1: Fast pattern matching (built-in + learned templates)
    Pass 2: LLM-based novel chain discovery
    """

    def __init__(self, llm: LLMClient, store: Optional[PatternStore] = None) -> None:
        self.llm   = llm
        self.store = store or PatternStore()

    async def plan(
        self,
        surface: LogicalSurface,
        findings: List[Dict],
    ) -> List[ChainSpec]:
        """
        Main entry: return all chains worth attempting.
        """
        if not findings:
            return []

        found_tokens = self._extract_tokens(surface, findings)
        logger.debug(f"[ChainPlanner] Found tokens: {found_tokens}")

        # Pass 1: pattern matching (all patterns — built-in + learned)
        specs = self._match_patterns(found_tokens, findings, surface)

        # Pass 2: LLM novel correlation
        # Run when: findings exist that patterns didn't cover
        covered_vuln_types = {s.source for s in specs}
        if len(findings) > len(specs) or not specs:
            novel = await self._llm_correlate(surface, findings, specs)
            specs += novel

        # Sort: critical first, then by success_rate descending
        specs.sort(key=lambda s: (
            0 if s.severity == "critical" else
            1 if s.severity == "high" else 2,
            -self.store.get_success_rate(s.pattern_name),
        ))

        logger.info(
            f"[ChainPlanner] {len(specs)} chains planned "
            f"({sum(1 for s in specs if s.source == 'static')} static, "
            f"{sum(1 for s in specs if s.source == 'learned')} learned, "
            f"{sum(1 for s in specs if s.source == 'llm')} novel)"
        )
        return specs

    # ── Pass 1: Pattern matching ──────────────────────────────────────────────

    def _match_patterns(
        self,
        found_tokens: Set[str],
        findings: List[Dict],
        surface: LogicalSurface,
    ) -> List[ChainSpec]:
        specs = []
        seen = set()

        for pattern in self.store.all_patterns():
            if not pattern.requires.issubset(found_tokens):
                continue
            if pattern.name in seen:
                continue
            seen.add(pattern.name)

            evidence = self._collect_evidence(pattern, findings, surface)
            confidence = self._plan_confidence(pattern, found_tokens)

            specs.append(ChainSpec(
                name=pattern.name,
                steps=pattern.steps,
                severity=pattern.severity,
                confidence=confidence,
                evidence=evidence,
                source=pattern.source,
                pattern_name=pattern.name,
            ))

        return specs

    def _plan_confidence(self, pattern: ChainPattern, found_tokens: Set[str]) -> float:
        """Confidence = historical success rate + token coverage bonus."""
        base  = self.store.get_success_rate(pattern.name)  # 0.5 if unknown
        cover = len(pattern.requires & found_tokens) / max(len(pattern.requires), 1)
        return min(round(base * 0.6 + cover * 0.4, 3), 0.95)

    def _collect_evidence(
        self,
        pattern: ChainPattern,
        findings: List[Dict],
        surface: LogicalSurface,
    ) -> Dict[str, Any]:
        """Build initial context from relevant findings."""
        ev: Dict[str, Any] = {}

        # From solver findings
        for f in findings:
            if not f.get("found"):
                continue
            vt = f.get("vuln_type", "")
            if vt == "jwt_bypass":
                ev.setdefault("jwt_token", f.get("working_payload", ""))
                ev.setdefault("jwt_algo", "none")
            if vt == "jwt_crack":
                ev.setdefault("jwt_token", f.get("working_payload", ""))
                ev.setdefault("jwt_algo", "HS256")
            if vt in ("sqli",):
                ev.setdefault("sqli_endpoint", f.get("target_url", ""))
                ev.setdefault("sqli_param",    f.get("parameter", ""))
            if vt in ("ssrf",):
                ev.setdefault("ssrf_endpoint", f.get("target_url", ""))
                ev.setdefault("ssrf_param",    f.get("parameter", ""))
            if vt in ("idor",):
                ev.setdefault("idor_endpoint", f.get("target_url", ""))
                ev.setdefault("idor_param",    f.get("parameter", ""))

        # From LSM surface
        if surface.jwt_issues:
            j = surface.jwt_issues[0]
            ev.setdefault("jwt_token", j.get("token", ""))
            issues = j.get("issues", [])
            if any("none" in i.lower() for i in issues):
                ev["jwt_algo"] = "none"
            elif any("hs256" in i.lower() or "weak" in i.lower() for i in issues):
                ev["jwt_algo"] = "HS256"

        admin_eps = [u for u in surface.endpoints if "admin" in u.lower()]
        if admin_eps:
            ev.setdefault("admin_endpoint", admin_eps[0])

        auth_eps = [u for u in surface.endpoints
                    if any(k in u.lower() for k in ("login", "auth", "signin"))]
        if auth_eps:
            ev.setdefault("auth_endpoint", auth_eps[0])

        if surface.secrets:
            s = surface.secrets[0]
            ev.setdefault("secret_key",   s.get("key", ""))
            ev.setdefault("secret_value", s.get("value", ""))

        if surface.graphql_endpoint:
            ev.setdefault("graphql_endpoint", surface.graphql_endpoint)

        ev["target_url"] = surface.base_url
        return ev

    # ── Pass 2: LLM novel correlation ────────────────────────────────────────

    async def _llm_correlate(
        self,
        surface: LogicalSurface,
        findings: List[Dict],
        existing_specs: List[ChainSpec],
    ) -> List[ChainSpec]:
        """Ask LLM to find chains that pattern matching missed."""
        try:
            confirmed = [f for f in findings if f.get("found")]
            if len(confirmed) < 2:
                return []

            findings_summary = json.dumps([{
                "vuln_type":  f.get("vuln_type"),
                "target_url": f.get("target_url"),
                "parameter":  f.get("parameter"),
                "confidence": f.get("confidence"),
                "proof":      (f.get("proof_response") or "")[:100],
            } for f in confirmed], indent=2)

            prompt = _LLM_CORRELATE_PROMPT.format(
                surface_summary=surface.to_summary(),
                findings_summary=findings_summary,
            )

            ai_msg = await self.llm.call(
                messages=[{"role": "user", "content": prompt}]
            )
            data = _extract_json_block(ai_msg.content or "")
            if not data or "chains" not in data:
                return []

            existing_names = {s.name for s in existing_specs}
            novel_specs = []

            for chain_data in data.get("chains", []):
                name = chain_data.get("name", "")
                if not name or name in existing_names:
                    continue

                steps = [
                    ChainStep.from_dict(s)
                    for s in chain_data.get("steps", [])
                ]
                if not steps:
                    continue

                ev_keys = chain_data.get("evidence_keys", [])
                evidence = {
                    k: findings[0].get(k, "")
                    for k in ev_keys
                    if findings
                }
                evidence["target_url"] = surface.base_url

                novel_specs.append(ChainSpec(
                    name=name,
                    steps=steps,
                    severity=chain_data.get("severity", "high"),
                    confidence=float(chain_data.get("confidence", 0.4)),
                    evidence=evidence,
                    source="llm",
                    pattern_name=name,
                ))

            logger.info(f"[ChainPlanner] LLM found {len(novel_specs)} novel chains")
            return novel_specs

        except Exception as e:
            logger.warning(f"[ChainPlanner] LLM correlation error: {e}")
            return []

    # ── Token extraction ──────────────────────────────────────────────────────

    def _extract_tokens(self, surface: LogicalSurface, findings: List[Dict]) -> Set[str]:
        """Normalize all findings + surface observations into a flat token set."""
        tokens: Set[str] = set()

        # From confirmed solver results
        for f in findings:
            if not f.get("found"):
                continue
            vt = f.get("vuln_type", "")
            tokens.add(vt)
            for alias in _VULN_TYPE_ALIASES.get(vt, set()):
                tokens.add(alias)

        # From LSM surface
        if surface.jwt_issues:
            for j in surface.jwt_issues:
                issues = j.get("issues", [])
                if any("none" in i.lower() for i in issues):
                    tokens.add("jwt_none_alg")
                if any("weak" in i.lower() or "hs256" in i.lower() for i in issues):
                    tokens.add("jwt_weak_secret")

        if surface.secrets:
            tokens.add("secret_leaked")

        if surface.cors_open:
            tokens.add("cors_open")

        if surface.graphql_endpoint:
            tokens.add("graphql_endpoint")

        if any("admin" in u.lower() for u in surface.endpoints):
            tokens.add("admin_endpoint")

        if any(k in u.lower() for u in surface.endpoints
               for k in ("login", "auth", "signin")):
            tokens.add("auth_endpoint")

        # Role param hint (from typed_params)
        for ep in surface.endpoints.values():
            if any("role" in p.lower() for p in ep.parameters):
                tokens.add("role_param")

        # From behavioral fingerprints (Phase 0c)
        for profile in surface.behavior_profiles.values():
            for token in getattr(profile, "to_tokens", lambda: [])():
                tokens.add(token)

        # From supply chain findings (Phase 0d — API keys, CVEs, third-party services)
        for finding in surface.supply_chain_findings:
            token = finding.get("token", "")
            if token:
                tokens.add(token)

        return tokens

"""
Coordinator — Persistent Orchestration Engine

Architecture (4 components):
  1. Coordinator (this) — persistent; global view; identifies attack surface; directs testing.
  2. Autonomous Agents (Solvers) — short-lived, parallel, one task then destroyed.
  3. Attack Machine — shared execution (tools + JIT + OOB); see engine.attack_machine.
  4. Validators — deterministic replay; no finding without proof.

4 stages: Define Scope → Discover and Map → Execute Parallel Attacks → Validate & Enforce Safety.

This Coordinator:
  - Runs LSM (ScoutLoop = Discover and Map), dedup, domain scoring.
  - Builds attack matrix (endpoint × vuln_type); spawns Solvers via Attack Machine.
  - Collects results; only Validator-confirmed findings returned.

Usage:
    from xlayer_ai.engine.llm import LLMClient
    from xlayer_ai.src.agent.coordinator import Coordinator
    llm = LLMClient.from_settings()
    coordinator = Coordinator(llm=llm)
    vulns = await coordinator.run(attack_surface, hunter_hypotheses)
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from loguru import logger

# ── Custom engine ─────────────────────────────────────────────────────────
from xlayer_ai.engine.llm import LLMClient, AlloyLLM
from xlayer_ai.engine.pipeline import ParallelDispatch
from xlayer_ai.engine.tool import tool, Tool
from xlayer_ai.engine.agent_spawner import AgentSpawner, DynamicDispatch, SpawnSpec, specialist_label


# ── Attack Matrix constants ────────────────────────────────────────────────

ENDPOINT_VULN_MATRIX = {
    "search":   ["sqli", "xss_reflected", "ssti"],
    "login":    ["auth_bypass", "sqli", "csrf"],
    "upload":   ["lfi", "xss_stored", "xxe", "rce"],
    "redirect": ["ssrf", "open_redirect"],
    "file":     ["lfi", "path_traversal", "rce"],
    "api":      ["sqli", "ssrf", "auth_bypass", "cors", "graphql"],
    "template": ["ssti"],
    "xml":      ["xxe"],
    "checkout": ["race_condition", "csrf"],
    "coupon":   ["race_condition"],
    "graphql":  ["graphql"],
    "default":  [
        "sqli", "xss_reflected", "lfi", "ssrf", "auth_bypass",
        "ssti", "cors", "open_redirect", "csrf",
    ],
}

HUNTER_CONFIDENCE_THRESHOLD = 0.3   # min confidence from hunter → create solver task
SKIP_UNHINTED_ENDPOINTS = False      # False = test all endpoints even without hunter hits
MAX_PARALLEL_SOLVERS = 5


# ── Attack Matrix ──────────────────────────────────────────────────────────

@dataclass
class AttackMatrixEntry:
    """One row in the attack matrix — one Solver task."""
    endpoint_url: str
    parameter: str
    method: str
    vuln_type: str
    priority: int = 5               # 1=highest, 10=lowest
    initial_hypothesis: Optional[Dict] = None
    confidence_hint: float = 0.0


def build_attack_matrix(
    attack_surface_summary: Dict,
    hunter_hypotheses: List[Dict],
) -> List[AttackMatrixEntry]:
    """
    Build the attack matrix from recon output + hunter hypotheses.

    Priority:
      1 — Hunter HIGH confidence
      2 — Hunter MEDIUM confidence
      3 — Hunter LOW confidence
      4 — Endpoint looks interesting (no hunter hit)
      5 — Generic coverage scan

    Returns sorted list (priority ascending = highest first).
    """
    matrix: List[AttackMatrixEntry] = []
    seen: set = set()

    # Pass 1: Hunter hypotheses drive the matrix
    for h in hunter_hypotheses:
        url = h.get("endpoint", "")
        param = h.get("parameter", "")
        vuln_type = h.get("vuln_type", "sqli")
        confidence = h.get("confidence_score", 0.0)
        method = h.get("method", "GET")

        if not url or not param:
            continue
        if confidence < HUNTER_CONFIDENCE_THRESHOLD:
            continue

        key = (url, param, vuln_type)
        if key in seen:
            continue
        seen.add(key)

        conf_str = h.get("confidence", "low")
        priority_map = {"high": 1, "medium": 2, "low": 3}
        priority = priority_map.get(conf_str, 3)

        matrix.append(AttackMatrixEntry(
            endpoint_url=url,
            parameter=param,
            method=method,
            vuln_type=vuln_type,
            priority=priority,
            initial_hypothesis=h,
            confidence_hint=confidence,
        ))

    # Pass 2: Coverage scan — all endpoints not already covered
    if not SKIP_UNHINTED_ENDPOINTS:
        for ep in attack_surface_summary.get("endpoints", []):
            url = ep.get("url", "")
            method = ep.get("method", "GET")
            params = ep.get("parameters", [])

            for param_info in params:
                param = param_info.get("name", "") if isinstance(param_info, dict) else str(param_info)

                ep_type = _classify_endpoint(url)
                vuln_types = ENDPOINT_VULN_MATRIX.get(ep_type, ENDPOINT_VULN_MATRIX["default"])

                for vuln_type in vuln_types:
                    key = (url, param, vuln_type)
                    if key in seen:
                        continue
                    seen.add(key)
                    matrix.append(AttackMatrixEntry(
                        endpoint_url=url,
                        parameter=param,
                        method=method,
                        vuln_type=vuln_type,
                        priority=4,
                        confidence_hint=0.0,
                    ))

    matrix.sort(key=lambda e: e.priority)
    logger.info(
        f"[Coordinator] Attack matrix: {len(matrix)} tasks "
        f"from {len(hunter_hypotheses)} hypotheses"
    )
    return matrix


def _classify_endpoint(url: str) -> str:
    """Classify endpoint type from URL path."""
    u = url.lower()
    if any(k in u for k in ["login", "auth", "signin", "session"]):
        return "login"
    if any(k in u for k in ["search", "query", "find", "filter"]):
        return "search"
    if any(k in u for k in ["upload", "file", "attachment", "import"]):
        return "upload"
    if any(k in u for k in ["redirect", "return", "next", "goto", "url"]):
        return "redirect"
    if any(k in u for k in ["include", "path", "page", "doc", "read"]):
        return "file"
    if any(k in u for k in ["graphql", "/graph", "/gql"]):
        return "graphql"
    if any(k in u for k in ["template", "render", "tpl", "theme"]):
        return "template"
    if any(k in u for k in ["xml", "soap", "wsdl"]):
        return "xml"
    if any(k in u for k in ["checkout", "payment", "order", "purchase"]):
        return "checkout"
    if any(k in u for k in ["coupon", "voucher", "promo", "redeem", "discount"]):
        return "coupon"
    if any(k in u for k in ["api", "/v1/", "/v2/", "/v3/"]):
        return "api"
    return "default"


# ── JIT Tool ─────────────────────────────────────────────────────────────

def make_jit_tool(jit_engine) -> Tool:
    """Create a custom Tool wrapping the JIT sandbox engine."""

    @tool
    def run_jit_code(code: str, target_url: str = "", parameter: str = "") -> str:
        """
        Execute custom Python exploit code in a sandboxed subprocess.
        Use when built-in hunter tools are not flexible enough.
        Code has access to httpx, json, base64, re, urllib.parse.

        Args:
            code: Python code to execute in the sandbox
            target_url: Target URL injected as variable target_url
            parameter: Parameter name injected as variable parameter
        """
        import asyncio
        import json as _json

        async def _run():
            ctx = {"target_url": target_url, "parameter": parameter}
            result = await jit_engine.run(code, context=ctx)
            return _json.dumps({
                "success": result.success,
                "output": result.output,
                "exit_code": result.exit_code,
                "timed_out": result.timed_out,
                "blocked": result.blocked,
                "block_reason": result.block_reason,
                "duration_ms": round(result.duration_ms, 1),
            })

        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                import concurrent.futures
                with concurrent.futures.ThreadPoolExecutor() as pool:
                    future = pool.submit(asyncio.run, _run())
                    return future.result(timeout=30)
            return loop.run_until_complete(_run())
        except Exception as e:
            import json as _j
            return _j.dumps({"error": str(e)})

    return run_jit_code


# ── Kill-and-Respawn helpers ───────────────────────────────────────────────

def _extract_confirmed_facts(result) -> str:
    """
    Extract only confirmed observations from a solver's journal.
    Used for kill-and-respawn: fresh solver starts with clean context
    but carries forward confirmed evidence from the prior attempt.
    """
    facts = []
    journal = getattr(result, "_journal", None)
    if journal is None:
        # Fallback: use proof_response and techniques
        if result.proof_response:
            facts.append(f"Prior proof signal: {result.proof_response[:300]}")
        for tech in result.techniques_tried[:5]:
            facts.append(f"Tried strategy: {tech}")
        return "\n".join(facts) or "No confirmed facts from prior attempt."

    # Extract from ObservationJournal
    for entry in journal.all():
        action = getattr(entry, "action", "")
        # Keep only high-signal observations
        if action in ("OOB_HIT", "CONFIDENCE_UPDATE", "TOOL_RESULT"):
            detail = getattr(entry, "detail", "")
            conf = getattr(entry, "confidence", None)
            if conf and conf >= 0.3:
                facts.append(f"[{action}] conf={conf:.2f}: {str(detail)[:200]}")
        elif action == "PIVOT":
            facts.append(f"[PIVOT] {getattr(entry, 'detail', '')[:150]}")

    if not facts:
        facts.append(f"Prior confidence: {result.confidence:.2f}")
        facts.append(f"Iterations used: {result.iterations_used}")
        for tech in result.techniques_tried[:5]:
            facts.append(f"Tried: {tech}")

    return "\n".join(facts)


# ── Coordinator ────────────────────────────────────────────────────────────

class Coordinator:
    """
    Standalone Coordinator.

    Orchestrates the full Coordinator + Solver (agentic exploit) pipeline:
      Recon output → Attack Matrix → Parallel Solvers → ValidatedVulns

    Uses engine.pipeline.ParallelDispatch for parallel solver execution.
    """

    def __init__(
        self,
        llm: LLMClient,
        settings=None,
        max_parallel: int = MAX_PARALLEL_SOLVERS,
    ) -> None:
        self.llm = llm
        self.settings = settings
        self.max_parallel = max_parallel
        # Model alloy for solvers — alternates primary + Gemini
        # Different model biases catch different vuln patterns (+11% solve rate)
        self.solver_llm = AlloyLLM.from_settings()

    async def run(
        self,
        attack_surface,
        hunter_hypotheses: Optional[List[Dict]] = None,
    ) -> List[Dict]:
        """
        Run the full Coordinator pipeline with Logical Surface Mapping.

        Args:
            attack_surface: AttackSurface object from Recon phase
            hunter_hypotheses: Pre-computed hunter results (optional)

        Returns:
            List of validated vuln dicts ready for Reporter
        """
        from xlayer_ai.src.tools.hunter_tools import ALL_HUNTER_TOOLS
        from xlayer_ai.src.tools.jit_engine import JITEngine
        from xlayer_ai.src.tools.oob_server import OOBServer
        from xlayer_ai.src.agent.solver import SolverAgent, SolverTask
        from xlayer_ai.engine.logical_surface_map.scout import ScoutLoop

        start_time = time.monotonic()

        # ═══════════════════════════════════════════════════════════════════
        # Phase 1: BUILD (map first, no attacks yet)
        # Coordinator builds: LSM → dedup → domain scoring → attack matrix.
        # Only after the surface is ready do we spawn ephemeral Solvers.
        # ═══════════════════════════════════════════════════════════════════
        # Step 0: Logical Surface Mapping (LSM) — The "Discovery" Phase
        logger.info("[Coordinator] Phase 1 (Build): Logical Surface Mapping")
        from xlayer_ai.src.tools.jit_engine import JITEngine
        from xlayer_ai.src.tools.hunter_tools import ALL_HUNTER_TOOLS
        from xlayer_ai.engine.logical_surface_map.scout import ScoutLoop
        
        jit_engine = JITEngine(timeout=60)
        # Alloy LLM for ScoutLoop — alternates primary + Gemini for broader coverage
        scout_llm = AlloyLLM.from_settings()
        lsm_scout = ScoutLoop(llm=scout_llm, tools=ALL_HUNTER_TOOLS, jit_engine=jit_engine)
        
        target_url = getattr(getattr(attack_surface, "target", None), "url", str(attack_surface))
        lsm_state = await lsm_scout.run(target_url)
        
        # Build Logical Blueprint for Knowledge Injection
        # Note: lsm_state is the surface object returned by ScoutLoop.run()
        lsm_blueprint = lsm_state.to_summary()
        logger.info(f"[Coordinator] LSM Complete: {len(lsm_state.endpoints)} endpoints discovered.")

        # Step 0b: SimHash deduplication — remove near-identical endpoints
        # Avoids wasting solver budget on /product/1, /product/2, etc.
        try:
            from xlayer_ai.engine.dedup import TargetDeduplicator
            deduper = TargetDeduplicator(
                proxy=getattr(self.settings, "proxy", None) if self.settings else None,
            )
            dedup_result = await deduper.deduplicate(lsm_state.endpoints)
            if dedup_result.duplicates_removed:
                for dup_url in dedup_result.duplicates_removed:
                    lsm_state.endpoints.pop(dup_url, None)
                logger.info(
                    f"[Coordinator] Dedup: {dedup_result.total_before} → "
                    f"{dedup_result.total_after} endpoints "
                    f"({len(dedup_result.duplicates_removed)} duplicates removed)"
                )
        except Exception as e:
            logger.debug(f"[Coordinator] Dedup skipped: {e}")

        # Step 0c: Domain Scoring (attack potential ranking)
        # Evaluates each endpoint/subdomain with numeric score based on:
        # WAF presence, status codes, auth forms, tech stack, params, secrets
        # Scores feed into solver dispatch priority — highest-scored endpoints first
        try:
            from xlayer_ai.engine.domain_scorer import DomainScorer
            _scorer = DomainScorer()
            scoring_result = _scorer.score(lsm_state)
            # Inject scores into LogicalSurface for downstream use
            lsm_state.domain_scores = {
                d: ds.total_score for d, ds in scoring_result.domain_scores.items()
            }
            lsm_state.endpoint_scores = scoring_result.endpoint_scores
            lsm_state.endpoint_entity = getattr(scoring_result, "endpoint_entity", {}) or {}
            logger.info(
                f"[Coordinator] Domain Scoring: {scoring_result.total_domains} domains, "
                f"avg={scoring_result.avg_score:.1f}"
            )
        except Exception as e:
            logger.debug(f"[Coordinator] Domain scoring skipped: {e}")
            scoring_result = None

        # Step 1: Context-aware agent spawning from LSM findings
        # AgentSpawner replaces the generic attack matrix:
        #   - Reads LogicalSurface findings (JWT issues, taint hints, vuln hints, etc.)
        #   - Spawns one SpawnSpec per finding — no fixed cap
        #   - Each spec carries pre-loaded evidence + initial confidence
        spawner = AgentSpawner()
        specs   = spawner.watch(lsm_state)

        # Fallback: if LSM found nothing actionable, use old matrix
        if not specs:
            logger.warning("[Coordinator] AgentSpawner found no specs — falling back to attack matrix")
            surface_summary = self._serialize_attack_surface(attack_surface)
            for endpoint_url, node in lsm_state.endpoints.items():
                if not any(e["url"] == endpoint_url for e in surface_summary["endpoints"]):
                    surface_summary["endpoints"].append({
                        "url": endpoint_url,
                        "method": node.method,
                        "parameters": [{"name": p, "location": "query"} for p in node.parameters],
                    })
            hypotheses = hunter_hypotheses or []
            matrix = build_attack_matrix(surface_summary, hypotheses)[:50]
            specs = [
                SpawnSpec(
                    agent_type=e.vuln_type,
                    endpoint=e.endpoint_url,
                    evidence=e.initial_hypothesis or {},
                    priority="medium",
                    initial_confidence=e.confidence_hint,
                    method=e.method,
                    params=[e.parameter] if e.parameter else [],
                )
                for e in matrix
            ]

        if not specs:
            logger.warning("[Coordinator] No specs after fallback — nothing to solve")
            return []

        # Sort specs by domain score (highest attack potential first)
        # This ensures solvers hit the juiciest targets before budget runs out
        if scoring_result and scoring_result.endpoint_scores:
            _ep_scores = scoring_result.endpoint_scores
            specs.sort(
                key=lambda s: _ep_scores.get(s.endpoint, 0.0),
                reverse=True,
            )
            top3 = [(s.endpoint.split("/")[-1] or s.endpoint, _ep_scores.get(s.endpoint, 0))
                    for s in specs[:3]]
            logger.info(
                f"[Coordinator] Specs sorted by domain score. "
                f"Top 3: {top3}"
            )

        # ═══════════════════════════════════════════════════════════════════
        # Phase 2: ATTACK via Dynamic Agent Swarm
        # SwarmCoordinator handles ALL agent lifecycle:
        #   - Spawning ephemeral SolverAgents (fresh context each)
        #   - 80-iter OODA loop per agent
        #   - Kill-and-respawn (partial progress → clean context + facts)
        #   - Knowledge harvesting (tokens/IDs → Knowledge Store)
        #   - Wave 2/3 auto-spawning (chaining from Knowledge Store)
        #   - Adaptive concurrency (10 agents → all, 1000 → 50 at a time)
        # ═══════════════════════════════════════════════════════════════════
        logger.info(f"[Coordinator] Phase 2 (Attack): Deploying Swarm — {len(specs)} agents")

        async with OOBServer() as oob:
            from xlayer_ai.engine.attack_machine import AttackMachine
            attack_machine = AttackMachine(
                base_tools=ALL_HUNTER_TOOLS,
                jit_engine=jit_engine,
                oob_server=oob if oob.available else None,
            )

            # Shared knowledge store for chaining (tokens, session_id, user_id)
            from xlayer_ai.engine.knowledge_store import KnowledgeStore
            knowledge_store = KnowledgeStore()

            # Discovery Monitor — polls auth-gated endpoints for 403→200 transitions
            from xlayer_ai.engine.discovery_monitor import DiscoveryMonitor
            _monitor = DiscoveryMonitor(
                surface=lsm_state,
                proxy=getattr(self.settings, "proxy", None) if self.settings else None,
                poll_interval=30.0,
            )
            await _monitor.start()

            # ── SWARM: Dynamic Agent Spawning ────────────────────────────
            from xlayer_ai.coordinator.swarm import SwarmCoordinator
            swarm = SwarmCoordinator.from_attack_machine(
                attack_machine=attack_machine,
                solver_llm=self.solver_llm,
                knowledge_store=knowledge_store,
                lsm_blueprint=lsm_blueprint,
                max_concurrency=self.max_parallel,
            )

            # Swarm handles: spawn → OODA → kill → respawn → chain → wave 2/3
            swarm_result = await swarm.attack(
                specs=specs,
                lsm_state=lsm_state,
            )
            all_results = swarm_result.all_results

            logger.info(
                f"[Coordinator] Swarm complete: "
                f"{swarm_result.total_spawned} spawned, "
                f"{swarm_result.total_killed} killed, "
                f"{swarm_result.total_respawned} respawned, "
                f"{swarm_result.total_found} found across "
                f"{swarm_result.waves_executed} waves"
            )

            # Discovery Monitor — check for newly unblocked endpoints
            monitor_changes = await _monitor.drain()
            await _monitor.stop()

            # Wave N+1: monitor-discovered endpoints
            unblocked = [c for c in (monitor_changes or []) if c.is_opportunity]
            if unblocked:
                logger.info(
                    f"[Coordinator] Discovery Monitor: "
                    f"{len(unblocked)} newly accessible endpoint(s) → extra wave"
                )
                monitor_specs = []
                for change in unblocked:
                    ep_url = change.url
                    ep_node = lsm_state.endpoints.get(ep_url)
                    ep_type = _classify_endpoint(ep_url)
                    vuln_types = ENDPOINT_VULN_MATRIX.get(ep_type, ENDPOINT_VULN_MATRIX["default"])
                    method = ep_node.method if ep_node else "GET"
                    params = list(ep_node.parameters)[:3] if ep_node and ep_node.parameters else ["id", "token", "q"]
                    for vt in vuln_types[:3]:
                        monitor_specs.append(SpawnSpec(
                            agent_type=vt,
                            endpoint=ep_url,
                            evidence={
                                "monitor_event": change.change_type,
                                "prev_status": change.old_status,
                                "new_status": change.new_status,
                            },
                            priority="high",
                            initial_confidence=0.4,
                            method=method,
                            params=params,
                        ))
                if monitor_specs:
                    monitor_result = await swarm.attack(specs=monitor_specs, lsm_state=lsm_state)
                    all_results.extend(monitor_result.all_results)

            # Step 5: Filter confirmed vulns
            candidates = []
            for r in all_results:
                if isinstance(r, Exception):
                    logger.error(f"[Coordinator] Solver exception: {r}")
                    continue
                if r.get("found") and r.get("confidence", 0) >= 0.72:
                    candidates.append(r)

            # Step 5a: Validator — replay-based false positive elimination
            validated = []
            if candidates:
                from xlayer_ai.src.agent.validator import (
                    ValidatorAgent, ValidationTask,
                )
                _validator = ValidatorAgent(
                    oob_server=oob if oob.available else None,
                    jit_engine=jit_engine,
                )
                logger.info(
                    f"[Coordinator] Validating {len(candidates)} confirmed findings"
                )
                for cand in candidates:
                    v_task = ValidationTask(
                        task_id=cand.get("task_id", ""),
                        target_url=cand.get("target_url", ""),
                        parameter=cand.get("parameter", ""),
                        vuln_type=cand.get("vuln_type", ""),
                        method="GET",
                        working_payload=cand.get("working_payload", ""),
                        proof_response=cand.get("proof_response", ""),
                        injection_type=cand.get("injection_type", ""),
                        confidence=cand.get("confidence", 0),
                        raw_result=cand,
                    )
                    v_result = await _validator.validate(v_task)
                    if v_result.validated:
                        cand["validation_method"] = v_result.validation_method
                        cand["validation_evidence"] = v_result.evidence
                        validated.append(cand)
                    else:
                        logger.warning(
                            f"[Coordinator] FALSE POSITIVE rejected: "
                            f"{cand.get('vuln_type')} @ {cand.get('target_url')} "
                            f"({v_result.validation_method})"
                        )
                logger.info(
                    f"[Coordinator] Validation: {len(validated)}/{len(candidates)} "
                    f"confirmed, {len(candidates) - len(validated)} false positives rejected"
                )

            # Step 5b: Cross-finding Synthesis
            # Correlates confirmed + partial findings to detect chained vulnerabilities.
            # Also generates follow-up solver specs for chain verification.
            synthesis_findings = []
            wave3_specs = []
            try:
                from xlayer_ai.engine.cross_synthesis import CrossFindingSynthesizer
                _synthesizer = CrossFindingSynthesizer()
                # Include partial findings (confidence ≥ 0.2) for synthesis input
                _all_for_synth = [
                    r for r in all_results
                    if not isinstance(r, Exception) and r is not None
                    and (r.get("found") or r.get("confidence", 0) >= 0.2)
                ]
                synthesis_findings, wave3_specs = _synthesizer.synthesize(
                    _all_for_synth, lsm_state
                )
                if synthesis_findings:
                    logger.info(
                        f"[Coordinator] Cross-synthesis: "
                        f"{len(synthesis_findings)} chained finding(s)"
                    )
            except Exception as e:
                logger.warning(f"[Coordinator] Cross-synthesis error: {e}")

            # Wave-3: run follow-up solvers to verify synthesized chains
            if wave3_specs:
                logger.info(
                    f"[Coordinator] Wave-3 (chain verification): "
                    f"{len(wave3_specs)} solver(s)"
                )
                wave3_results = await DynamicDispatch.run(
                    solve_one,
                    wave3_specs,
                    max_concurrency=self.max_parallel,
                )
                for r in wave3_results:
                    if r and not isinstance(r, Exception) and r.get("found"):
                        validated.append(r)

            # Step 6: Attack Chain Planning + Execution
            chain_findings = []
            if validated or lsm_state.jwt_issues or lsm_state.secrets:
                try:
                    from xlayer_ai.engine.chain import (
                        ChainPlanner, ChainExecutor, PatternDistiller
                    )
                    logger.info(
                        f"[Coordinator] Step 6: Chain Planning "
                        f"({len(validated)} findings → chains)"
                    )
                    planner  = ChainPlanner(llm=self.llm)
                    executor = ChainExecutor(
                        llm=self.llm,
                        tools=all_tools,
                        jit_engine=jit_engine,
                        oob=oob if oob.available else None,
                    )
                    distiller = PatternDistiller(llm=self.llm)

                    chain_specs = await planner.plan(lsm_state, validated)

                    if chain_specs:
                        logger.info(
                            f"[Coordinator] Executing {len(chain_specs)} chains"
                        )
                        chain_results = await asyncio.gather(
                            *[executor.execute(spec) for spec in chain_specs[:10]],
                            return_exceptions=True,
                        )
                        for cr in chain_results:
                            if isinstance(cr, Exception):
                                logger.error(f"[Coordinator] Chain error: {cr}")
                                continue
                            await distiller.distill(cr)
                            if cr.completed:
                                chain_findings.append(cr.to_dict())

                        logger.success(
                            f"[Coordinator] Chains: "
                            f"{len(chain_findings)}/{len(chain_specs)} confirmed"
                        )
                except Exception as e:
                    logger.warning(f"[Coordinator] Chain phase error: {e}")

        duration = time.monotonic() - start_time
        all_findings = validated + chain_findings + synthesis_findings
        logger.success(
            f"[Coordinator] Done: {len(validated)} isolated + "
            f"{len(chain_findings)} chains + "
            f"{len(synthesis_findings)} synthesized = {len(all_findings)} total "
            f"in {duration:.1f}s"
        )
        return all_findings

    def _serialize_attack_surface(self, attack_surface) -> Dict:
        """Convert AttackSurface to JSON-friendly dict."""
        try:
            endpoints = []
            for ep in getattr(attack_surface, "endpoints", []):
                params = []
                for p in getattr(ep, "parameters", []):
                    name = getattr(p, "name", str(p))
                    params.append({
                        "name": name,
                        "location": getattr(getattr(p, "input_type", None), "value", "query"),
                    })
                endpoints.append({
                    "url": getattr(ep, "url", ""),
                    "method": getattr(getattr(ep, "method", None), "value", str(getattr(ep, "method", "GET"))),
                    "parameters": params,
                })
            return {
                "base_url": getattr(getattr(attack_surface, "target", None), "url", ""),
                "endpoints": endpoints,
            }
        except Exception as e:
            logger.warning(f"[Coordinator] Serialize error: {e}")
            return {"base_url": "", "endpoints": []}

    def _result_to_dict(self, result) -> Dict:
        """Convert SolverResult to dict."""
        return {
            "task_id": result.task_id,
            "target_url": result.target_url,
            "parameter": result.parameter,
            "vuln_type": result.vuln_type,
            "found": result.found,
            "confidence": round(result.confidence, 3),
            "working_payload": result.working_payload,
            "proof_response": (result.proof_response or "")[:500],
            "injection_type": result.injection_type,
            "poc_script": result.poc_script,
            "oob_confirmed": result.oob_confirmed,
            "iterations_used": result.iterations_used,
            "total_payloads_sent": result.total_payloads_sent,
            "techniques_tried": result.techniques_tried,
            "duration_seconds": round(result.duration_seconds, 2),
        }

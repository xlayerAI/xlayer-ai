"""
Dynamic Agent Swarm — Ephemeral Multi-Agent System

Integrated with XLayer's existing SolverAgent + AgentLoop + AttackMachine.

This system:
  1. OBSERVES the target surface (LSM endpoints, tech, auth, JS intel)
  2. DECIDES how many agents and what type based on context (Attack Matrix)
  3. SPAWNS them in parallel via asyncio semaphore (adaptive concurrency)
  4. COORDINATES via shared KnowledgeStore
  5. KILLS each agent the moment its task completes (ephemeral — no reuse)
  6. RESPAWNS if partial progress detected (0.35–0.72 conf after 60+ iters)
  7. TRIGGERS Wave-2/3 agents when new intel appears from Knowledge Store

Architecture:
    ┌──────────────────────────────────┐
    │  SwarmCoordinator (persistent)    │
    │  - Decides agent count from       │
    │    surface context                │
    │  - Spawns SolverAgent instances   │
    │  - Watches KnowledgeStore for     │
    │    chaining opportunities         │
    │  - Kill-and-respawn logic         │
    └───────────────┬──────────────────┘
                    │ spawns/kills
    ┌───────────────▼──────────────────┐
    │  SolverAgent (ephemeral)          │
    │  - 80-iter AgentLoop (OODA)       │
    │  - Uses AttackMachine tools       │
    │  - Born → Work → Die              │
    └──────────────────────────────────┘

Usage:
    from xlayer_ai.coordinator.swarm import SwarmCoordinator
    swarm = SwarmCoordinator.from_settings()
    results = await swarm.attack(specs, surface, lsm_state)
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set

from loguru import logger


# ═══════════════════════════════════════════════════════════════════════════
# Agent Lifecycle
# ═══════════════════════════════════════════════════════════════════════════

class AgentState(str, Enum):
    """Lifecycle of an ephemeral agent."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    KILLED = "killed"
    RESPAWNED = "respawned"


@dataclass
class SwarmResult:
    """Result from the entire swarm attack."""
    all_results: List[Dict] = field(default_factory=list)
    total_spawned: int = 0
    total_killed: int = 0
    total_found: int = 0
    total_respawned: int = 0
    waves_executed: int = 0
    duration_seconds: float = 0.0


# ═══════════════════════════════════════════════════════════════════════════
# The Swarm Coordinator
# ═══════════════════════════════════════════════════════════════════════════

class SwarmCoordinator:
    """
    Dynamic Agent Swarm — context-aware, self-organizing.

    Agents are NOT predefined — the system creates them based on what it discovers.
    Each agent lives only for its task. When one agent finds something useful,
    new agents are spawned automatically to exploit that knowledge.

    Integrates with:
      - SolverAgent (src/agent/solver.py) — the ephemeral OODA loop
      - AgentLoop (engine/agent.py) — 80-iteration reasoning loop
      - AttackMachine (engine/attack_machine.py) — shared tools
      - KnowledgeStore (engine/knowledge_store.py) — chaining data
      - AlloyLLM (engine/llm.py) — multi-model rotation
    """

    # Adaptive concurrency
    MIN_CONCURRENCY = 3
    MAX_CONCURRENCY = 50
    DEFAULT_CONCURRENCY = 10

    # Respawn thresholds
    RESPAWN_CONF_MIN = 0.35
    RESPAWN_CONF_MAX = 0.72
    RESPAWN_MIN_ITERS = 60

    # Validation
    VALIDATION_THRESHOLD = 0.72

    def __init__(
        self,
        solver_llm=None,
        tools: List = None,
        oob_server=None,
        jit_engine=None,
        knowledge_store=None,
        lsm_blueprint: str = "",
        max_concurrency: int = DEFAULT_CONCURRENCY,
    ):
        self._solver_llm = solver_llm
        self._tools = tools or []
        self._oob = oob_server
        self._jit = jit_engine
        self._knowledge = knowledge_store
        self._lsm_blueprint = lsm_blueprint
        self._max_concurrency = max_concurrency

        # Live tracking
        self._active: Dict[str, AgentState] = {}
        self._total_spawned = 0
        self._total_killed = 0
        self._total_respawned = 0

    @classmethod
    def from_attack_machine(
        cls,
        attack_machine,
        solver_llm=None,
        knowledge_store=None,
        lsm_blueprint: str = "",
        max_concurrency: int = DEFAULT_CONCURRENCY,
    ) -> "SwarmCoordinator":
        """Create SwarmCoordinator from an AttackMachine."""
        return cls(
            solver_llm=solver_llm,
            tools=attack_machine.get_tools(),
            oob_server=attack_machine.oob_server,
            jit_engine=attack_machine.jit_engine,
            knowledge_store=knowledge_store,
            lsm_blueprint=lsm_blueprint,
            max_concurrency=max_concurrency,
        )

    @property
    def active_count(self) -> int:
        """Number of currently running agents."""
        return sum(1 for s in self._active.values() if s == AgentState.RUNNING)

    # ═══════════════════════════════════════════════════════════════════
    # MAIN ENTRY POINT
    # ═══════════════════════════════════════════════════════════════════

    async def attack(
        self,
        specs: List,           # List[SpawnSpec] from AgentSpawner
        lsm_state=None,        # LogicalSurface from ScoutLoop
        surface_dict: Dict = None,  # surface dict
    ) -> SwarmResult:
        """
        Run the full multi-wave swarm attack.

        The system decides:
          - HOW MANY agents → len(specs), then auto-extends with chaining
          - WHAT TYPE → vuln_type from each spec
          - WHEN TO SPAWN → Wave 1 immediately, Wave 2/3 when intel appears
          - WHEN TO KILL → Task complete or timeout
          - WHEN TO RESPAWN → Partial progress (0.35-0.72 conf, 60+ iters)

        Args:
            specs: Initial agent specs from AgentSpawner / AttackMatrix
            lsm_state: LogicalSurface for chaining + context
            surface_dict: Alternative surface dict for chaining

        Returns:
            SwarmResult with all agent results, stats
        """
        start = time.monotonic()
        concurrency = self._calc_concurrency(len(specs))

        logger.info(
            f"[Swarm] ══════════════════════════════════════════════════"
        )
        logger.info(
            f"[Swarm] ATTACK: {len(specs)} agents, concurrency={concurrency}"
        )
        logger.info(
            f"[Swarm] ══════════════════════════════════════════════════"
        )

        all_results: List[Dict] = []

        # ── Wave 1: Primary Attack ──────────────────────────────────
        logger.info(f"[Swarm] Wave 1: {len(specs)} primary agents")
        wave1_results = await self._run_wave(specs, concurrency, wave_num=1)
        all_results.extend(wave1_results)

        # Harvest knowledge (tokens, IDs, sessions) for chaining
        new_knowledge = self._harvest_knowledge(wave1_results)

        # Identify respawn candidates
        respawn_specs = self._find_respawn_candidates(wave1_results, specs)

        # ── Wave 2: Chaining + Respawns ─────────────────────────────
        wave2_specs = []

        # Chain specs from knowledge store
        if new_knowledge and lsm_state:
            chain_specs = self._generate_chain_specs(new_knowledge, lsm_state)
            wave2_specs.extend(chain_specs)

        # Add respawn specs
        wave2_specs.extend(respawn_specs)

        if wave2_specs:
            logger.info(
                f"[Swarm] Wave 2: {len(wave2_specs)} agents "
                f"({len(wave2_specs) - len(respawn_specs)} chaining + "
                f"{len(respawn_specs)} respawns)"
            )
            wave2_results = await self._run_wave(wave2_specs, concurrency, wave_num=2)
            all_results.extend(wave2_results)

            # Wave 2 may produce more knowledge → Wave 3
            new_knowledge_2 = self._harvest_knowledge(wave2_results)
            if new_knowledge_2 and lsm_state:
                wave3_specs = self._generate_chain_specs(new_knowledge_2, lsm_state)
                if wave3_specs:
                    logger.info(f"[Swarm] Wave 3: {len(wave3_specs)} chain-verification agents")
                    wave3_results = await self._run_wave(wave3_specs, concurrency, wave_num=3)
                    all_results.extend(wave3_results)

        # Stats
        duration = time.monotonic() - start
        found = [r for r in all_results if r.get("found")]
        waves = 1 + (1 if wave2_specs else 0) + (1 if 'wave3_results' in dir() else 0)

        logger.success(
            f"[Swarm] COMPLETE: "
            f"{self._total_spawned} spawned, "
            f"{self._total_killed} killed, "
            f"{self._total_respawned} respawned, "
            f"{len(found)} found in {duration:.1f}s across {waves} waves"
        )

        return SwarmResult(
            all_results=all_results,
            total_spawned=self._total_spawned,
            total_killed=self._total_killed,
            total_found=len(found),
            total_respawned=self._total_respawned,
            waves_executed=waves,
            duration_seconds=duration,
        )

    # ═══════════════════════════════════════════════════════════════════
    # WAVE EXECUTION
    # ═══════════════════════════════════════════════════════════════════

    async def _run_wave(
        self, specs: List, concurrency: int, wave_num: int = 1
    ) -> List[Dict]:
        """Run a wave of ephemeral agents with adaptive concurrency."""
        # Sort by priority (highest first)
        try:
            specs.sort(key=lambda s: {"high": 1, "critical": 0, "medium": 3, "low": 5}.get(
                getattr(s, "priority", "medium"), 3
            ))
        except Exception:
            pass

        semaphore = asyncio.Semaphore(concurrency)
        results = []
        total = len(specs)

        async def _run_one(spec, idx: int) -> Optional[Dict]:
            async with semaphore:
                return await self._spawn_solve_kill(spec, wave_num, idx, total)

        # Launch all agents in parallel (semaphore limits concurrency)
        tasks = [
            asyncio.create_task(_run_one(spec, i))
            for i, spec in enumerate(specs)
        ]

        for coro in asyncio.as_completed(tasks):
            try:
                result = await coro
                if result:
                    results.append(result)
                    done = len(results)
                    if result.get("found"):
                        logger.success(
                            f"[Swarm] W{wave_num} [{done}/{total}] ✅ "
                            f"{result.get('vuln_type', '?')} FOUND @ "
                            f"{result.get('target_url', '?')[:60]} "
                            f"(conf={result.get('confidence', 0):.2f})"
                        )
                    elif done % 5 == 0 or done == total:
                        logger.info(f"[Swarm] W{wave_num} [{done}/{total}] agents done")
            except Exception as e:
                logger.error(f"[Swarm] Agent error: {e}")

        return results

    async def _spawn_solve_kill(
        self, spec, wave_num: int, idx: int, total: int
    ) -> Optional[Dict]:
        """
        THE CORE: Spawn → Solve → Kill

        BORN:     SolverAgent created (fresh memory, clean context)
        RUNNING:  80-iteration OODA loop
        KILLED:   Agent destroyed, memory freed, no reuse
        """
        from xlayer_ai.src.agent.solver import SolverAgent, SolverTask

        agent_type = getattr(spec, "agent_type", "unknown")
        endpoint = getattr(spec, "endpoint", "")
        agent_id = f"{agent_type}_{uuid.uuid4().hex[:8]}"

        # ── BORN ──────────────────────────────────────────────────────
        self._total_spawned += 1
        self._active[agent_id] = AgentState.RUNNING

        start = time.monotonic()
        specialist = self._specialist_label(agent_type)

        logger.debug(
            f"[Swarm] 🔄 SPAWN #{self._total_spawned}: "
            f"{specialist} → {endpoint[:50]} "
            f"(wave={wave_num})"
        )

        try:
            # Build context from LSM + evidence
            context = self._build_context(spec)

            # OOB token
            oob_token = None
            oob_url = None
            if self._oob and getattr(self._oob, "available", False):
                oob_token = self._oob.new_token()
                oob_url = self._oob.http_url(oob_token)
                register = getattr(self._oob, "register_token", None)
                if callable(register):
                    register(oob_token)

            # Build SolverTask
            params = getattr(spec, "params", []) or []
            task = SolverTask(
                task_id=agent_id,
                target_url=endpoint,
                parameter=params[0] if params else "",
                method=getattr(spec, "method", "GET"),
                vuln_type=agent_type,
                initial_hypothesis=getattr(spec, "evidence", None),
                oob_url=oob_url,
                oob_token=oob_token,
                extra_context=context,
            )

            # ── RUNNING (Create fresh SolverAgent — ephemeral) ────────
            solver = SolverAgent(
                llm=self._solver_llm,
                tools=self._tools,
                oob_server=self._oob,
                jit_engine=self._jit,
            )

            result = await solver.run(task)

            # ── CONVERT to dict ───────────────────────────────────────
            result_dict = {
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
                "wave": wave_num,
                "agent_id": agent_id,
                "specialist": specialist,
                # Internal (for respawn)
                "_raw_result": result,
            }

            return result_dict

        except Exception as e:
            logger.error(f"[Swarm] Agent {agent_id} crashed: {e}")
            return {
                "task_id": agent_id,
                "target_url": endpoint,
                "vuln_type": agent_type,
                "found": False,
                "confidence": 0.0,
                "wave": wave_num,
                "error": str(e),
            }
        finally:
            # ── KILLED ☠️ ─────────────────────────────────────────────
            # Agent goes out of scope here.
            # No reference kept. Memory is freed by GC.
            # Context window, model connection — ALL gone.
            self._active.pop(agent_id, None)
            self._total_killed += 1
            # solver = None  ← implicit when function returns

    # ═══════════════════════════════════════════════════════════════════
    # KNOWLEDGE HARVESTING (for chaining)
    # ═══════════════════════════════════════════════════════════════════

    def _harvest_knowledge(self, results: List[Dict]) -> Dict[str, str]:
        """Extract tokens/sessions/IDs from results → Knowledge Store."""
        import re
        new_intel = {}

        for r in results:
            if not r or isinstance(r, Exception):
                continue

            proof = r.get("proof_response", "") or ""

            # Auto-extract tokens from proof
            patterns = [
                (r'session[_]?id[":\s=]+["\']*([a-zA-Z0-9_-]{16,})', "session_id"),
                (r'token[":\s=]+["\']*([a-zA-Z0-9_.-]{16,})', "auth_token"),
                (r'user[_]?id[":\s=]+["\']*(\d+)', "user_id"),
                (r'(eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)', "jwt_token"),
                (r'api[_-]?key["\s:=]+["\']?([a-zA-Z0-9_-]{16,})', "api_key"),
            ]

            for pattern, key in patterns:
                match = re.search(pattern, proof, re.IGNORECASE)
                if match:
                    val = match.group(1)
                    new_intel[key] = val
                    if self._knowledge:
                        try:
                            self._knowledge.put(
                                key, val,
                                source_url=r.get("target_url", ""),
                                source_vuln_type=r.get("vuln_type", ""),
                            )
                        except Exception:
                            pass

        if new_intel:
            logger.info(f"[Swarm] 🔗 Knowledge harvested: {list(new_intel.keys())}")

        return new_intel

    def _generate_chain_specs(self, knowledge: Dict[str, str], lsm_state) -> List:
        """Generate new agent specs to exploit discovered knowledge."""
        from xlayer_ai.engine.agent_spawner import SpawnSpec

        chain_specs = []
        endpoints = getattr(lsm_state, "endpoints", {})

        CHAIN_PARAMS = {"token", "session_id", "session", "user_id", "auth",
                        "authorization", "jwt_token", "api_key"}

        for key, value in knowledge.items():
            if key not in CHAIN_PARAMS:
                continue

            for ep_url, ep_node in endpoints.items():
                params = list(ep_node.parameters) if hasattr(ep_node, "parameters") and ep_node.parameters else []

                # Match: endpoint accepts this type of parameter
                matches = any(
                    key.lower() in p.lower() or p.lower() in key.lower()
                    for p in params
                )

                if matches:
                    chain_specs.append(SpawnSpec(
                        agent_type="auth_bypass",
                        endpoint=ep_url,
                        evidence={"chaining_from_store": key, "chain_value": value[:50]},
                        priority="high",
                        initial_confidence=0.5,
                        method=getattr(ep_node, "method", "GET"),
                        params=params[:3] or ["id"],
                        context_values={key: value},
                    ))
                    break  # one spec per knowledge entry

        return chain_specs

    # ═══════════════════════════════════════════════════════════════════
    # KILL-AND-RESPAWN
    # ═══════════════════════════════════════════════════════════════════

    def _find_respawn_candidates(
        self, results: List[Dict], original_specs: List
    ) -> List:
        """Find agents with partial progress → generate respawn specs."""
        from xlayer_ai.engine.agent_spawner import SpawnSpec
        from xlayer_ai.src.agent.coordinator import _extract_confirmed_facts

        respawn_specs = []
        spec_map = {getattr(s, "endpoint", ""): s for s in original_specs}

        for r in results:
            if not r or isinstance(r, Exception):
                continue

            conf = r.get("confidence", 0)
            iters = r.get("iterations_used", 0)
            raw = r.get("_raw_result")

            if (
                self.RESPAWN_CONF_MIN <= conf < self.RESPAWN_CONF_MAX
                and iters >= self.RESPAWN_MIN_ITERS
                and raw is not None
                and getattr(raw, "_journal", None) is not None
            ):
                # Extract confirmed facts
                confirmed_facts = _extract_confirmed_facts(raw)
                endpoint = r.get("target_url", "")
                orig = spec_map.get(endpoint)

                respawn_specs.append(SpawnSpec(
                    agent_type=r.get("vuln_type", "sqli"),
                    endpoint=endpoint,
                    evidence=getattr(orig, "evidence", {}) if orig else {},
                    priority="high",
                    initial_confidence=conf,
                    method=r.get("method", "GET"),
                    params=[r.get("parameter", "id")],
                    context_values={"_prior_facts": confirmed_facts},
                ))
                self._total_respawned += 1

                logger.info(
                    f"[Swarm] 🔄 RESPAWN queued: "
                    f"{r.get('vuln_type')} @ {endpoint[:40]} "
                    f"(conf={conf:.2f}, iters={iters})"
                )

        return respawn_specs

    # ═══════════════════════════════════════════════════════════════════
    # CONTEXT BUILDING
    # ═══════════════════════════════════════════════════════════════════

    def _build_context(self, spec) -> str:
        """Build rich context for agent from LSM + evidence + chaining."""
        parts = []

        # LSM Blueprint
        if self._lsm_blueprint:
            parts.append(self._lsm_blueprint)

        # Evidence from AgentSpawner
        evidence = getattr(spec, "evidence", {})
        if evidence:
            import json
            try:
                parts.append("LSM Evidence:\n" + json.dumps(evidence, indent=2)[:800])
            except Exception:
                parts.append(f"Evidence: {str(evidence)[:800]}")

        # Chaining values (tokens/IDs from Knowledge Store)
        context_values = getattr(spec, "context_values", {})
        if context_values:
            # Prior facts from respawn
            if "_prior_facts" in context_values:
                parts.append(
                    "CONFIRMED OBSERVATIONS FROM PRIOR ATTEMPT:\n"
                    + context_values.pop("_prior_facts")
                )
            # Remaining values = chaining tokens
            if context_values:
                parts.append(
                    "[Chaining] Use these values in requests:\n"
                    + "\n".join(f"  {k}: {v}" for k, v in context_values.items())
                )

        return "\n\n".join(parts)

    # ═══════════════════════════════════════════════════════════════════
    # HELPERS
    # ═══════════════════════════════════════════════════════════════════

    def _calc_concurrency(self, total: int) -> int:
        """Adaptive concurrency: small targets = all parallel, large = throttled."""
        if total <= self.MIN_CONCURRENCY:
            return total
        elif total <= 20:
            return min(total, self.DEFAULT_CONCURRENCY)
        elif total <= 100:
            return 20
        else:
            return self.MAX_CONCURRENCY

    @staticmethod
    def _specialist_label(vuln_type: str) -> str:
        """Human-readable specialist name."""
        labels = {
            "sqli": "SQLi Specialist",
            "xss_reflected": "XSS Hunter",
            "xss_stored": "Stored XSS Hunter",
            "xss_dom": "DOM XSS Hunter",
            "ssrf": "SSRF Prober",
            "auth_bypass": "Auth Bypass Agent",
            "lfi": "LFI/Path Traversal Agent",
            "rce": "RCE Specialist",
            "ssti": "SSTI Hunter",
            "xxe": "XXE Specialist",
            "cors": "CORS Analyzer",
            "csrf": "CSRF Hunter",
            "open_redirect": "Redirect Hunter",
            "race_condition": "Race Condition Agent",
            "deserialization": "Deserialization Agent",
            "graphql": "GraphQL Specialist",
            "http_smuggling": "HTTP Smuggling Agent",
        }
        return labels.get(vuln_type, f"{vuln_type.upper()} Agent")

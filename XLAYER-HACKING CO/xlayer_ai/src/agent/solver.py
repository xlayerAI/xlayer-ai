"""
Solver — Short-Lived Exploitation Runtime (Autonomous Agent)

Autonomous agents are ephemeral; one task then destroyed. They receive
tasks from the Coordinator and execution environment (tools + JIT + OOB) from
the Attack Machine. No global state; evidence comes from LSM and Coordinator.

This Solver receives (endpoint, parameter, vuln_type) from the Coordinator,
uses tools/JIT/OOB from the Attack Machine, and runs XLayerLoop to validate
findings with proof. Output: SolverResult → Coordinator filters → Validator.
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from loguru import logger

from xlayer_ai.engine.agent import AgentLoop
from xlayer_ai.engine.llm import LLMClient
from xlayer_ai.engine.tool import Tool


def _get_solver_system_prompt() -> str:
    """
    Load solver persona prompt lazily.
    Falls back to a minimal local prompt if prompt package wiring is unavailable.
    """
    try:
        from xlayer_ai.prompts.base.initial_access_persona import BASE_INITACCESS_PROMPT
        return BASE_INITACCESS_PROMPT
    except Exception:
        return (
            "You are the XLayer exploitation solver. "
            "Use tools iteratively to validate findings with reproducible proof. "
            "Prefer tool calls over pure reasoning, and conclude only with evidence."
        )


@dataclass
class SolverTask:
    """Input task for the Solver from the Coordinator."""

    task_id: str
    target_url: str
    parameter: str
    method: str
    vuln_type: str
    initial_hypothesis: Optional[Dict[str, Any]] = None
    oob_url: Optional[str] = None
    oob_token: Optional[str] = None
    extra_context: str = ""


@dataclass
class SolverResult:
    """Output from the Solver after iteration budget is exhausted."""

    task_id: str
    target_url: str
    parameter: str
    vuln_type: str

    found: bool = False
    confidence: float = 0.0

    working_payload: str = ""
    proof_response: str = ""
    injection_type: str = ""
    poc_script: str = ""
    oob_confirmed: bool = False

    iterations_used: int = 0
    total_payloads_sent: int = 0
    techniques_tried: List[str] = field(default_factory=list)
    failure_reasons: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    # Internal: journal for kill-and-respawn (not serialized to report)
    _journal: Optional[Any] = field(default=None, repr=False)


class SolverAgent:
    """
    Autonomous agent: agentic exploitation loop (tools + JIT + OOB from Attack Machine).
    Internally powered by AgentLoop from engine/.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: List[Tool],
        oob_server=None,
        jit_engine=None,
    ) -> None:
        """
        Args:
            llm: LLMClient instance
            tools: List of engine.tool.Tool instances
            oob_server: Optional OOBServer for blind detection
            jit_engine: Optional JITEngine for code synthesis
        """
        self.llm = llm
        self.tools = tools
        self.oob_server = oob_server
        self.jit_engine = jit_engine

    async def run(self, task: SolverTask) -> SolverResult:
        """
        Run the 80-iteration AgentLoop exploitation runtime.
        Converts SolverTask -> AgentLoop task/context -> SolverResult.
        Ephemeral lifecycle: this agent is created for one task only;
        after run() returns, the Coordinator discards it (no reuse).
        """
        start_time = time.monotonic()

        logger.info(
            f"[Solver][{task.task_id}] starting: {task.vuln_type} @ "
            f"{task.target_url} param={task.parameter}"
        )

        extra = task.extra_context or ""

        # Probe-first: lightweight probe before payloads; observation used for payload choice
        try:
            from xlayer_ai.tools.probe_first import run_probe_first, format_probe_observation_for_context
            obs = await run_probe_first(
                url=task.target_url,
                param=task.parameter,
                method=task.method,
                timeout=8.0,
            )
            extra += "\n\n" + format_probe_observation_for_context(obs)
        except Exception as e:
            logger.debug(f"[Solver] probe_first failed: {e}")
            extra += "\n\nProbe observation: (probe skipped)\n"

        if task.initial_hypothesis:
            h = task.initial_hypothesis
            extra += (
                "\nInitial Hunter Hypothesis:\n"
                f"  confidence: {h.get('confidence', 'N/A')}\n"
                f"  injection_type: {h.get('injection_type', 'unknown')}\n"
                f"  trigger_payload: {h.get('trigger_payload', 'N/A')}\n"
                f"  indicators: {h.get('indicators', [])}\n"
                f"  suggested_payloads: {h.get('suggested_payloads', [])}\n"
            )

        if task.oob_url:
            extra += f"\nOOB Callback URL: {task.oob_url} (token: {task.oob_token})\n"
            if self.oob_server and task.oob_token:
                register = getattr(self.oob_server, "register_token", None)
                if callable(register):
                    register(task.oob_token)

        task_text = _build_solver_task_text(task)
        loop = AgentLoop.for_solver(
            llm=self.llm,
            tools=self.tools,
            system=_get_solver_system_prompt(),
            vuln_type=task.vuln_type,
            oob_server=self.oob_server,
            jit_engine=self.jit_engine,
        )

        try:
            final = await loop.run(task=task_text, extra_context=extra)
        except Exception as e:
            logger.error(f"[Solver][{task.task_id}] Loop crashed: {e}")
            return SolverResult(
                task_id=task.task_id,
                target_url=task.target_url,
                parameter=task.parameter,
                vuln_type=task.vuln_type,
                found=False,
                confidence=0.0,
                failure_reasons=[str(e)],
                duration_seconds=time.monotonic() - start_time,
            )

        techniques = list(final.strategies_tried)

        oob_confirmed = False
        if final.journal:
            for entry in final.journal.all():
                if entry.action == "OOB_HIT":
                    oob_confirmed = True
                    break

        stop_reason = (
            final.stop_reason.value
            if hasattr(final.stop_reason, "value")
            else str(final.stop_reason)
        )

        failure_reasons: List[str] = []
        if not final.goal_achieved:
            failure_reasons.append(f"stop_reason={stop_reason}")
        if stop_reason == "error":
            failure_reasons.append("runtime_error")
        if not failure_reasons and not final.goal_achieved:
            failure_reasons.append("no_validated_signal")

        result = SolverResult(
            task_id=task.task_id,
            target_url=task.target_url,
            parameter=task.parameter,
            vuln_type=task.vuln_type,
            found=final.goal_achieved,
            confidence=final.progress,
            working_payload="",
            proof_response=final.proof or final.final_answer or "",
            injection_type=_infer_injection_type(
                strategies_tried=final.strategies_tried,
                progress=final.progress,
                oob_confirmed=oob_confirmed,
            ),
            oob_confirmed=oob_confirmed,
            iterations_used=final.iterations_used,
            total_payloads_sent=final.tool_calls_made,
            techniques_tried=techniques,
            failure_reasons=failure_reasons,
            duration_seconds=time.monotonic() - start_time,
            _journal=final.journal,
        )

        logger.info(
            f"[Solver][{task.task_id}] done: found={result.found} "
            f"confidence={result.confidence:.2f} iters={result.iterations_used} "
            f"time={result.duration_seconds:.1f}s stop={stop_reason}"
        )

        return result


def _build_solver_task_text(task: SolverTask) -> str:
    """Build a strict, tool-oriented task prompt for solver runtime."""

    lines = [
        "Goal: Validate or refute ONE vulnerability on ONE endpoint.",
        f"Target URL: {task.target_url}",
        f"HTTP Method: {task.method}",
        f"Primary Parameter: {task.parameter}",
        f"Vulnerability Type: {task.vuln_type}",
        "",
        "Execution rules:",
        "- Always use tool calls for testing (do not answer without running tools).",
        "- Include concrete tool arguments each time.",
        "- Use target_url, parameter, and method where applicable.",
        "- If blind behavior is suspected, use OOB/JIT pathways for confirmation.",
        "- Only conclude stop_found after concrete proof.",
    ]
    if task.oob_url:
        lines.append(f"- OOB callback URL available: {task.oob_url}")
    return "\n".join(lines)


def _infer_injection_type(
    strategies_tried: List[str],
    progress: float,
    oob_confirmed: bool,
) -> str:
    """Infer injection type from strategy history and final progress."""

    joined = " ".join(strategies_tried or []).lower()

    if oob_confirmed or progress >= 0.90:
        return "oob"
    if "time_based" in joined or "time-based" in joined:
        return "time_based"
    if "boolean_blind" in joined or "boolean" in joined:
        return "boolean_blind"
    if "error_based" in joined or "error" in joined:
        return "error_based"
    if "jit" in joined or "custom_approach" in joined:
        return "jit"
    if "union" in joined:
        return "union"
    return "unknown"

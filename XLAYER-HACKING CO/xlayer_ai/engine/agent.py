"""
engine/agent.py — Universal AgentLoop

ONE loop that powers ALL agents in XLayer AI:
  - Planner agent    (strategic planning,     max 15 iterations)
  - Recon agent      (intelligence gathering, max 20 iterations)
  - Solver agent     (exploitation,           max 80 iterations)
  - Summary agent    (report writing,         max  8 iterations)

Features:
  Observation Journal      — every action+result recorded; LLM sees full history
  Progress Scoring         — 0.0-1.0 confidence tracking, monotonically increasing
  Auto-Pivot               — stuck for N iters → strategy switch (with cooldown)
  Context Compression      — every N iters → LLM summarises old messages
  Parallel Tool Execution  — asyncio.gather across all tool calls per iteration
  Dynamic System Prompt    — persona + journal + context rebuilt every iteration
  Goal Detection           — configurable threshold + optional custom checker
  Evidence Patterns        — regex auto-bumps progress on confirmed findings
  Streak-based Nudge       — N consecutive no-tool-call iters → inject nudge
  OOB Polling              — blind vuln detection; stops loop immediately on hit
  JIT Execution            — LLM-written Python executed in sandbox thread
  Explicit Stop Control    — stop_on_no_tool_call flag replaces iteration heuristic
"""

import asyncio
import functools
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from loguru import logger

from .llm import LLMClient
from .memory import ObservationEntry, ObservationJournal
from .messages import (
    AIMessage,
    HumanMessage,
    Message,
    ToolMessage,
)
from .tool import Tool, ToolRegistry


# ── Observation memo + next strategy from HTTP tool results ─────────────────

def _observation_memo_and_strategy(tool_results: List[ToolMessage]) -> Tuple[str, str]:
    """
    From http_probe-style tool results, build observation_memo (status, body len, WAF)
    and next_strategy hint (e.g. "403 → try encoding") for journal and LLM context.
    """
    memo_parts = []
    next_strategy = ""
    waf_sigs = {"cloudflare": "Cloudflare", "cf-ray": "Cloudflare", "mod_security": "ModSecurity",
                "modsecurity": "ModSecurity", "x-amzn-requestid": "AWS WAF", "x-iinfo": "Imperva"}
    for tm in tool_results:
        if tm.name != "http_probe":
            continue
        try:
            data = json.loads(tm.content)
        except (json.JSONDecodeError, TypeError):
            continue
        status = data.get("status_code")
        body = data.get("body_snippet", "") or data.get("body", "")
        headers = data.get("headers", {}) or {}
        if status is not None:
            memo_parts.append(f"status={status}")
        if body:
            memo_parts.append(f"body_len={len(body)}")
        waf = None
        for k, v in waf_sigs.items():
            if k in str(headers).lower() or k in body.lower():
                waf = v
                break
        if waf:
            memo_parts.append(f"WAF={waf}")
            if not next_strategy:
                next_strategy = "WAF detected → try hex/comment/encoding bypass"
        if status in (403, 406, 429, 503) and not next_strategy:
            next_strategy = "403/block → try encoding or comment sandwich"
        if memo_parts:
            break
    return (" ".join(memo_parts), next_strategy)


# ── Default constants ─────────────────────────────────────────────────────────

DEFAULT_MAX_ITER         = 30     # Solver=80, Planner=15, Recon=20, Summary=8
DEFAULT_GOAL_THRESHOLD   = 0.72   # progress ≥ this → goal achieved
DEFAULT_PIVOT_THRESHOLD  = 0.30   # progress < this for N iters → pivot
DEFAULT_PIVOT_AFTER      = 3      # consecutive low-progress iters before pivot
DEFAULT_PIVOT_COOLDOWN   = 3      # iters locked after pivot before next pivot allowed
DEFAULT_COMPRESS_EVERY   = 15     # compress message history every N iterations
DEFAULT_COMPRESS_KEEP    = 5      # number of recent messages kept verbatim
DEFAULT_COMPRESS_EXCERPT = 500    # max chars per message fed to compression LLM
DEFAULT_OOB_POLL_EVERY   = 5      # poll OOB server every N iterations
DEFAULT_OOB_TIMEOUT      = 10.0   # seconds before OOB poll is abandoned
DEFAULT_NUDGE_AFTER      = 3      # consecutive no-tool-call iters before first nudge


# ── Stop reasons ──────────────────────────────────────────────────────────────

class StopReason(str, Enum):
    GOAL_ACHIEVED     = "goal_achieved"      # progress ≥ threshold or custom checker
    EXPLICIT_STOP     = "explicit_stop"      # LLM emitted stop_found / done
    EXPLICIT_NOT_DONE = "explicit_not_done"  # LLM emitted stop_not_found / give_up
    MAX_ITERATIONS    = "max_iterations"     # budget exhausted
    NO_TOOL_CALLS     = "no_tool_calls"      # LLM gave final text, stop_on_no_tool_call=True
    OOB_CONFIRMED     = "oob_confirmed"      # OOB callback received → stop immediately
    ERROR             = "error"              # unrecoverable LLM error


# ── Loop state ────────────────────────────────────────────────────────────────

@dataclass
class LoopState:
    """
    Complete runtime state for one AgentLoop execution.
    Passed to all callbacks (goal_checker, prompt_builder, pivot_fn).
    """
    run_id: str
    task: str
    agent_name: str
    extra_context: str = ""

    # Progress
    progress: float = 0.0            # monotonically non-decreasing
    iteration: int = 0
    strategy: str = "initial"
    strategies_tried: List[str] = field(default_factory=list)

    # Conversation
    messages: List[Message] = field(default_factory=list)
    journal: ObservationJournal = field(default_factory=ObservationJournal)

    # Results
    goal_achieved: bool = False
    final_answer: str = ""
    proof: Optional[str] = None
    stop_reason: StopReason = StopReason.MAX_ITERATIONS
    error: Optional[str] = None

    # Stats
    tool_calls_total: int = 0
    start_time: float = field(default_factory=time.monotonic)

    # Internal counters
    iters_without_tool_call: int = 0  # streak for nudge system
    pivot_cooldown: int = 0            # iters remaining before next pivot is allowed

    @property
    def elapsed_seconds(self) -> float:
        return time.monotonic() - self.start_time

    def journal_text(self, max_entries: int = 20) -> str:
        return self.journal.as_text(max_entries)

    def is_stuck(self, window: int, threshold: float) -> bool:
        """True only if cooldown has expired AND last N entries are all low-confidence."""
        if self.pivot_cooldown > 0:
            return False
        return self.journal.is_stuck(window, threshold)

    def best_progress(self) -> float:
        return self.journal.best_confidence()


# ── Agent result ──────────────────────────────────────────────────────────────

@dataclass
class AgentResult:
    """Final output from an AgentLoop.run() call."""
    run_id: str
    agent_name: str
    task: str

    goal_achieved: bool = False
    final_answer: str = ""
    proof: Optional[str] = None
    progress: float = 0.0
    stop_reason: StopReason = StopReason.MAX_ITERATIONS

    iterations_used: int = 0
    tool_calls_made: int = 0
    strategies_tried: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0

    journal: Optional[ObservationJournal] = None
    messages: List[Message] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.goal_achieved


# ── JSON extraction ───────────────────────────────────────────────────────────

def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """
    Extract the LAST valid decision JSON block from LLM response text.

    Pass 1 — fenced ```json ... ``` blocks (most reliable).
    Pass 2 — bare {...} with up to one level of nesting (fallback).

    Returns the last matching block so that a final decision block always
    wins over any intermediate analysis blocks earlier in the response.
    """
    last: Optional[Dict[str, Any]] = None

    # Pass 1: fenced blocks
    for m in re.finditer(r"```json\s*(.*?)```", text, re.DOTALL):
        try:
            candidate = json.loads(m.group(1).strip())
            if isinstance(candidate, dict):
                last = candidate
        except json.JSONDecodeError:
            pass
    if last is not None:
        return last

    # Pass 2: bare {...} — handles one level of nesting via non-greedy pattern
    for m in re.finditer(r"\{(?:[^{}]|\{[^{}]*\})*\}", text, re.DOTALL):
        try:
            candidate = json.loads(m.group(0))
            if isinstance(candidate, dict) and any(
                k in candidate for k in ("progress", "confidence", "action", "stop")
            ):
                last = candidate
        except json.JSONDecodeError:
            pass
    return last


def _parse_progress(ai_msg: AIMessage, state: LoopState) -> Tuple[float, Optional[str]]:
    """
    Extract progress score and stop signal from an LLM response.

    Returns:
        (progress_score, stop_signal)
        stop_signal: "found" | "not_found" | None
    """
    data = _extract_json(ai_msg.content or "")
    if not data:
        return state.progress, None

    # Progress score — check multiple key aliases
    progress = float(
        data.get("progress",
        data.get("confidence",
        data.get("score", state.progress)))
    )
    progress = max(0.0, min(1.0, progress))

    # Stop signal — check action / next_action with liberal alias sets
    action = str(data.get("action", data.get("next_action", ""))).lower()
    _STOP_FOUND = {"stop_found", "found", "done", "achieved", "stop_done", "goal_achieved"}
    _STOP_FAIL  = {"stop_not_found", "not_found", "give_up", "failed", "stop_failed"}

    if action in _STOP_FOUND:
        return progress, "found"
    if action in _STOP_FAIL:
        return progress, "not_found"
    return progress, None


# ── JIT helper (module-level, runs in thread pool) ────────────────────────────

def _sync_run_jit(jit_engine: Any, code: str, ctx: Dict[str, str]) -> Dict[str, Any]:
    """
    Execute JIT engine synchronously inside a worker thread.
    Creates a fresh event loop per call — avoids nested-asyncio issues.
    All result attributes accessed via getattr for interface resilience.
    """
    loop = asyncio.new_event_loop()
    try:
        result = loop.run_until_complete(jit_engine.run(code, ctx))
        return {
            "success":    getattr(result, "success",    False),
            "output":     (getattr(result, "stdout", None) or getattr(result, "output", ""))[:1000],
            "exit_code":  getattr(result, "exit_code",  -1),
            "timed_out":  getattr(result, "timed_out",  False),
            "duration_ms": round(getattr(result, "duration_ms", 0.0), 1),
        }
    finally:
        loop.close()


# ── AgentLoop ─────────────────────────────────────────────────────────────────

class AgentLoop:
    """
    Universal agentic loop for XLayer AI.

    All agents (Planner, Recon, Solver, Summary) share this single loop.
    Behaviour is controlled by constructor parameters and factory methods.

    Quick start:
        loop   = AgentLoop.for_planner(llm, tools, system=BASE_PLANNER_PROMPT)
        result = await loop.run("Plan the assessment for https://target.com")
    """

    # Injected into every system prompt so LLM always knows the decision format.
    DECISION_SUFFIX = """
## Decision Format
End every response with a JSON block:
```json
{
  "progress": 0.0-1.0,
  "reasoning": "why this confidence level",
  "action": "tool_call | think | pivot | stop_found | stop_not_found",
  "strategy": "current strategy name"
}
```
Progress bands:
  0.00-0.30 → No signal — change approach
  0.30-0.72 → Partial signal — refine and escalate
  0.72+     → Strong signal — validate and conclude
"""

    def __init__(
        self,
        llm: LLMClient,
        tools: List[Tool],

        # Identity
        agent_name: str = "Agent",
        system: Optional[str] = None,

        # Iteration budget
        max_iterations: int = DEFAULT_MAX_ITER,

        # Progress / goal
        goal_threshold: float = DEFAULT_GOAL_THRESHOLD,
        pivot_threshold: float = DEFAULT_PIVOT_THRESHOLD,
        pivot_after: int = DEFAULT_PIVOT_AFTER,
        pivot_cooldown: int = DEFAULT_PIVOT_COOLDOWN,

        # History compression
        compress_every: int = DEFAULT_COMPRESS_EVERY,
        compress_keep_recent: int = DEFAULT_COMPRESS_KEEP,

        # OOB
        oob_server: Optional[Any] = None,
        oob_poll_every: int = DEFAULT_OOB_POLL_EVERY,
        oob_timeout: float = DEFAULT_OOB_TIMEOUT,

        # JIT
        jit_engine: Optional[Any] = None,

        # Evidence
        evidence_patterns: Optional[List[str]] = None,

        # Strategies for auto-pivot
        strategies: Optional[List[str]] = None,

        # Callbacks
        goal_checker: Optional[Callable[[LoopState], bool]] = None,
        prompt_builder: Optional[Callable[[LoopState], str]] = None,
        pivot_fn: Optional[Callable[[LoopState], str]] = None,

        # Execution
        parallel_tools: bool = True,
        stop_on_no_tool_call: bool = False,
        nudge_after: int = DEFAULT_NUDGE_AFTER,
    ) -> None:

        self.llm = llm
        self.registry = ToolRegistry(tools)
        self.agent_name = agent_name
        self.system_base = system or ""
        self.max_iterations = max_iterations
        self.goal_threshold = goal_threshold
        self.pivot_threshold = pivot_threshold
        self.pivot_after = pivot_after
        self.pivot_cooldown_iters = pivot_cooldown
        self.compress_every = compress_every
        self.compress_keep_recent = compress_keep_recent
        self.oob = oob_server
        self.oob_poll_every = oob_poll_every
        self.oob_timeout = oob_timeout
        self.jit = jit_engine
        self.evidence_patterns = [re.compile(p, re.IGNORECASE) for p in (evidence_patterns or [])]
        self.strategies = strategies or ["default_a", "default_b", "default_c"]
        self.goal_checker = goal_checker
        self.prompt_builder = prompt_builder
        self.pivot_fn = pivot_fn
        self.parallel_tools = parallel_tools
        self.stop_on_no_tool_call = stop_on_no_tool_call
        self.nudge_after = nudge_after

    # ── Main entry point ──────────────────────────────────────────────────────

    async def run(
        self,
        task: str,
        extra_context: str = "",
        initial_messages: Optional[List[Message]] = None,
    ) -> AgentResult:
        """
        Run the agent loop for a given task.

        Args:
            task:             Goal / task description.
            extra_context:    Additional context injected into every system prompt.
            initial_messages: Pre-existing conversation to continue from.

        Returns:
            AgentResult with goal_achieved, final_answer, proof, journal, etc.
        """
        state = LoopState(
            run_id=uuid.uuid4().hex[:12],
            task=task,
            agent_name=self.agent_name,
            extra_context=extra_context,
        )
        state.strategies_tried.append("initial")

        if initial_messages:
            state.messages = list(initial_messages)

        logger.info(f"[{self.agent_name}] Starting — task: {task[:80]}")

        for i in range(1, self.max_iterations + 1):
            state.iteration = i
            remaining = self.max_iterations - i

            # ── Tick down pivot cooldown ─────────────────────────────────────
            if state.pivot_cooldown > 0:
                state.pivot_cooldown -= 1

            # ── OOB poll ─────────────────────────────────────────────────────
            if self.oob and i % self.oob_poll_every == 0:
                oob_hit = await self._poll_oob(state)
                if oob_hit:
                    # Confirmed — stop without an unnecessary extra LLM call
                    state.goal_achieved = True
                    state.stop_reason = StopReason.OOB_CONFIRMED
                    for m in reversed(state.messages):
                        if isinstance(m, AIMessage) and m.content:
                            state.final_answer = m.content
                            break
                    logger.success(f"[{self.agent_name}] OOB confirmed — stopping immediately")
                    break

            # ── Build system prompt (fresh every iteration) ──────────────────
            system_prompt = self._build_system_prompt(state)

            # ── Build iteration message ──────────────────────────────────────
            iter_msg = HumanMessage(self._build_iter_message(state, remaining))

            # ── LLM call ─────────────────────────────────────────────────────
            messages_to_send = list(state.messages) + [iter_msg]
            try:
                ai_response = await self.llm.call(
                    messages=messages_to_send,
                    tools=self.registry.all(),
                    system=system_prompt,
                )
            except Exception as e:
                logger.error(f"[{self.agent_name}] LLM error iter {i}: {e}")
                state.error = str(e)
                state.stop_reason = StopReason.ERROR
                break

            state.messages.append(ai_response)

            # ── Parse progress + stop signal ─────────────────────────────────
            new_progress, stop_signal = _parse_progress(ai_response, state)
            state.progress = max(state.progress, new_progress)

            # ── Execute tool calls ────────────────────────────────────────────
            tool_result_text = ""
            obs_memo_j, next_strat_j = "", ""
            if ai_response.has_tool_calls:
                state.iters_without_tool_call = 0  # reset streak

                tool_results = await self._execute_tools(ai_response.tool_calls, state)

                # Observation memo + next strategy from HTTP results → next LLM context
                obs_memo, next_strat = _observation_memo_and_strategy(tool_results)
                obs_memo_j, next_strat_j = obs_memo, next_strat
                suffix = ""
                if obs_memo:
                    suffix += f"\n\n[Observation] {obs_memo}"
                if next_strat:
                    suffix += f"\n[Next strategy] {next_strat}"
                messages_to_append = []
                for tm in tool_results:
                    if tm.name == "http_probe" and suffix:
                        tm = ToolMessage(
                            content=(tm.content or "") + suffix,
                            tool_call_id=tm.tool_call_id,
                            name=tm.name,
                        )
                    messages_to_append.append(tm)
                for tm in messages_to_append:
                    state.messages.append(tm)

                # Evidence — one bump per iteration (deduplication across parallel results)
                max_bump = 0.0
                for tm in messages_to_append:
                    state.tool_calls_total += 1
                    max_bump = max(max_bump, self._check_evidence(tm.content))

                if max_bump > 0:
                    old = state.progress
                    state.progress = min(1.0, state.progress + max_bump)
                    logger.info(
                        f"[{self.agent_name}] Evidence match → "
                        f"progress {old:.2f}→{state.progress:.2f}"
                    )

                tool_result_text = " | ".join(
                    f"{tm.name}: {tm.content[:100]}" for tm in messages_to_append
                )

            else:
                state.iters_without_tool_call += 1
                streak = state.iters_without_tool_call
                # Nudge fires at first threshold crossing, then every nudge_after iters
                if streak >= self.nudge_after and streak % self.nudge_after == 0:
                    state.messages.append(HumanMessage(
                        f"[Nudge] {streak} consecutive iterations without a tool call. "
                        f"Iteration {i}/{self.max_iterations}. "
                        f"Progress: {state.progress:.2f}. "
                        f"Make a tool call or conclude with stop_found/stop_not_found."
                    ))

            # ── Record observation (memo + next_strategy in journal) ─────────────
            action_taken = (
                " + ".join(tc["function"]["name"] for tc in ai_response.tool_calls)
                if ai_response.has_tool_calls else "think"
            )
            state.journal.add(ObservationEntry(
                iteration=i,
                action=action_taken,
                input_summary=(ai_response.content or "")[:120],
                result_summary=tool_result_text[:200] or "(no tool result)",
                confidence=state.progress,
                observation_memo=obs_memo_j,
                next_strategy=next_strat_j,
            ))

            logger.info(
                f"[{self.agent_name}] iter={i}/{self.max_iterations} "
                f"action={action_taken} progress={state.progress:.2f}"
            )

            # ── Stop conditions (evaluated in priority order) ─────────────────

            # 1. Explicit LLM signal
            if stop_signal == "found":
                state.goal_achieved = True
                state.stop_reason = StopReason.EXPLICIT_STOP
                state.final_answer = ai_response.content or ""
                logger.success(f"[{self.agent_name}] Goal achieved (explicit stop_found)")
                break

            if stop_signal == "not_found":
                state.goal_achieved = False
                state.stop_reason = StopReason.EXPLICIT_NOT_DONE
                state.final_answer = ai_response.content or ""
                logger.info(f"[{self.agent_name}] Explicitly stopped (not found)")
                break

            # 2. Custom goal checker
            if self.goal_checker and self.goal_checker(state):
                state.goal_achieved = True
                state.stop_reason = StopReason.GOAL_ACHIEVED
                state.final_answer = ai_response.content or ""
                logger.success(f"[{self.agent_name}] Goal achieved (custom checker)")
                break

            # 3. Progress threshold
            if state.progress >= self.goal_threshold:
                state.goal_achieved = True
                state.stop_reason = StopReason.GOAL_ACHIEVED
                state.final_answer = ai_response.content or ""
                logger.success(
                    f"[{self.agent_name}] Goal achieved (progress={state.progress:.2f})"
                )
                break

            # 4. No tool calls — only if explicitly configured to stop
            if not ai_response.has_tool_calls and i > 3 and self.stop_on_no_tool_call:
                state.goal_achieved = state.progress >= 0.5
                state.stop_reason = StopReason.NO_TOOL_CALLS
                state.final_answer = ai_response.content or ""
                logger.info(f"[{self.agent_name}] Stopped: no tool calls (configured)")
                break

            # ── Auto-pivot (respects cooldown via state.is_stuck) ─────────────
            if state.is_stuck(self.pivot_after, self.pivot_threshold):
                old_strategy = state.strategy  # save before overwriting
                new_strategy = (
                    self.pivot_fn(state) if self.pivot_fn
                    else self._pick_strategy(state)
                )
                logger.warning(
                    f"[{self.agent_name}] Auto-pivot: {old_strategy} → {new_strategy}"
                )
                state.strategy = new_strategy
                state.strategies_tried.append(new_strategy)
                state.pivot_cooldown = self.pivot_cooldown_iters
                state.messages.append(HumanMessage(
                    f"[Auto-Pivot] Strategy '{old_strategy}' is not producing results. "
                    f"Switching to: '{new_strategy}'. "
                    f"All strategies tried so far: {', '.join(state.strategies_tried)}."
                ))

            # ── Compress history at interval ──────────────────────────────────
            if i % self.compress_every == 0:
                state.messages = await self._compress(state)

        else:
            # for-loop completed without break → iteration budget exhausted
            state.stop_reason = StopReason.MAX_ITERATIONS
            for m in reversed(state.messages):
                if isinstance(m, AIMessage) and m.content:
                    state.final_answer = m.content
                    break

        duration = time.monotonic() - state.start_time
        logger.info(
            f"[{self.agent_name}] Done — goal={state.goal_achieved} "
            f"progress={state.progress:.2f} iters={state.iteration} "
            f"tools={state.tool_calls_total} time={duration:.1f}s "
            f"stop={state.stop_reason}"
        )

        return AgentResult(
            run_id=state.run_id,
            agent_name=state.agent_name,
            task=state.task,
            goal_achieved=state.goal_achieved,
            final_answer=state.final_answer,
            proof=state.proof,
            progress=state.progress,
            stop_reason=state.stop_reason,
            iterations_used=state.iteration,
            tool_calls_made=state.tool_calls_total,
            strategies_tried=state.strategies_tried,
            duration_seconds=duration,
            journal=state.journal,
            messages=state.messages,
        )

    # ── System prompt ─────────────────────────────────────────────────────────

    def _build_system_prompt(self, state: LoopState) -> str:
        """
        Assemble the system prompt for this iteration.
        Injects: base persona → current run state → observation journal
                 → extra context → decision format.
        Custom prompt_builder callback fully replaces this logic.
        """
        if self.prompt_builder:
            return self.prompt_builder(state)

        parts = [self.system_base]

        parts.append(f"""
## Current Run State
Agent:            {self.agent_name}
Iteration:        {state.iteration}/{self.max_iterations}
Progress:         {state.progress:.2f}
Strategy:         {state.strategy}
Strategies tried: {', '.join(state.strategies_tried) or 'none'}
""")

        if state.journal.all():
            parts.append(f"""
## Observation Journal
{state.journal_text(max_entries=15)}
""")

        if state.extra_context:
            parts.append(f"""
## Context
{state.extra_context}
""")

        parts.append(self.DECISION_SUFFIX)
        return "\n".join(parts)

    def _build_iter_message(self, state: LoopState, remaining: int) -> str:
        return (
            f"Task: {state.task}\n\n"
            f"Remaining iterations: {remaining}\n"
            f"Current progress: {state.progress:.2f}\n"
            f"What is your next action? End with a JSON decision block."
        )

    # ── Tool execution ────────────────────────────────────────────────────────

    async def _execute_tools(
        self,
        tool_calls: List[Dict[str, Any]],
        state: LoopState,
    ) -> List[ToolMessage]:
        """
        Execute tool calls.
        Runs in parallel via asyncio.gather when parallel_tools=True.
        Individual failures are isolated — one bad tool does not abort others.
        """
        if self.parallel_tools and len(tool_calls) > 1:
            tasks = [self._execute_one_tool(tc, state) for tc in tool_calls]
            raw = await asyncio.gather(*tasks, return_exceptions=True)
            results: List[ToolMessage] = []
            for idx, r in enumerate(raw):
                if isinstance(r, Exception):
                    tc = tool_calls[idx]
                    call_id = tc.get("id", f"err_{idx}")
                    tool_name = tc.get("function", {}).get("name", "error")
                    results.append(ToolMessage(
                        content=f"Tool error: {r}",
                        tool_call_id=call_id,
                        name=tool_name,
                    ))
                else:
                    results.append(r)
            return results
        else:
            return [await self._execute_one_tool(tc, state) for tc in tool_calls]

    def _vet_tool_call(self, tc: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Vet action before execution. Only tools in the registry are allowed.
        Returns (allowed, reason); if not allowed, caller should not execute.
        """
        tool_name = tc.get("function", {}).get("name", "")
        if not tool_name:
            return False, "missing tool name"
        if self.registry.get(tool_name) is None:
            return False, f"tool '{tool_name}' not in allowed registry"
        return True, ""

    async def _execute_one_tool(
        self,
        tc: Dict[str, Any],
        state: LoopState,
    ) -> ToolMessage:
        tool_name = tc["function"]["name"]
        try:
            args = json.loads(tc["function"]["arguments"])
        except json.JSONDecodeError:
            args = {}

        call_id = tc.get("id", uuid.uuid4().hex[:8])

        # Vet before execute — only allowed tools run
        allowed, reason = self._vet_tool_call(tc)
        if not allowed:
            return ToolMessage(
                content=f"Vet rejected: {reason}",
                tool_call_id=call_id,
                name=tool_name,
            )

        if tool_name == "run_jit_code" and self.jit:
            return await self._run_jit(args, call_id)

        result = self.registry.execute(tool_name, args)
        return ToolMessage(content=result, tool_call_id=call_id, name=tool_name)

    async def _run_jit(self, args: Dict, call_id: str) -> ToolMessage:
        """Execute LLM-written Python code via JIT engine in a worker thread."""
        code = args.get("code", "")
        if not code:
            return ToolMessage(
                content=json.dumps({"error": "no code provided"}),
                tool_call_id=call_id,
                name="run_jit_code",
            )

        ctx = {
            "target_url": args.get("target_url", ""),
            "parameter":  args.get("parameter", ""),
        }

        try:
            loop = asyncio.get_running_loop()
            result_dict = await loop.run_in_executor(
                None,
                functools.partial(_sync_run_jit, self.jit, code, ctx),
            )
            output = json.dumps(result_dict)
        except Exception as e:
            output = json.dumps({"error": str(e)})

        return ToolMessage(content=output, tool_call_id=call_id, name="run_jit_code")

    # ── Evidence detection ────────────────────────────────────────────────────

    def _check_evidence(self, text: str) -> float:
        """
        Scan a tool result for evidence patterns.
        Returns 0.25 on first match, 0.0 otherwise.
        Caller deduplicates across parallel results (takes max per iteration).
        """
        for pattern in self.evidence_patterns:
            if pattern.search(text):
                return 0.25
        return 0.0

    # ── OOB polling ───────────────────────────────────────────────────────────

    async def _poll_oob(self, state: LoopState) -> bool:
        """
        Poll OOB server for blind callback hits.

        Returns True if a callback was received (loop should stop immediately).
        Applies oob_timeout — never blocks indefinitely.
        """
        if not self.oob:
            return False
        try:
            get_recent = getattr(self.oob, "get_recent_hits", None)
            if not get_recent:
                return False

            if asyncio.iscoroutinefunction(get_recent):
                hits = await asyncio.wait_for(get_recent(), timeout=self.oob_timeout)
            else:
                loop = asyncio.get_running_loop()
                hits = await asyncio.wait_for(
                    loop.run_in_executor(None, get_recent),
                    timeout=self.oob_timeout,
                )

            if hits:
                logger.success(f"[{self.agent_name}] OOB callback! hits={len(hits)}")
                old_progress = state.progress
                state.progress = max(state.progress, 0.90)
                state.proof = f"OOB callback: {hits[0]}"
                state.journal.add(ObservationEntry(
                    iteration=state.iteration,
                    action="OOB_HIT",
                    input_summary="OOB server polled",
                    result_summary=f"{len(hits)} callback(s) — blind vuln confirmed",
                    confidence=state.progress,
                ))
                state.messages.append(HumanMessage(
                    f"[OOB CALLBACK RECEIVED] {len(hits)} hit(s) from OOB server. "
                    f"Progress: {old_progress:.2f} → {state.progress:.2f}. "
                    f"Blind vulnerability confirmed."
                ))
                return True
        except asyncio.TimeoutError:
            logger.debug(f"[{self.agent_name}] OOB poll timed out ({self.oob_timeout}s)")
        except Exception as e:
            logger.debug(f"[{self.agent_name}] OOB poll error: {e}")
        return False

    # ── Context compression ───────────────────────────────────────────────────

    async def _compress(self, state: LoopState) -> List[Message]:
        """
        Compress old message history to manage token budget.

        Keeps the most recent compress_keep_recent messages verbatim.
        Summarises everything older via a secondary LLM call.
        Compressed summary stored as HumanMessage (API-compatible mid-array placement).

        Falls back to recent-only on compression failure.
        """
        keep = self.compress_keep_recent
        if len(state.messages) <= keep:
            return state.messages

        old_msgs = state.messages[:-keep]
        recent_msgs = state.messages[-keep:]

        old_text = "\n".join(
            f"[{m.__class__.__name__}]: {(getattr(m, 'content', '') or '')[:DEFAULT_COMPRESS_EXCERPT]}"
            for m in old_msgs
        )

        try:
            summary_resp = await self.llm.call(
                messages=[HumanMessage(
                    "Summarise this agent action history in 5 bullet points. "
                    "Preserve: what was tried, what worked, what failed, "
                    "any confirmed findings, and current progress.\n\n"
                    f"{old_text}"
                )],
                system="You are a concise summariser. Output bullet points only.",
            )
            compressed = HumanMessage(
                f"[Compressed History — iterations 1-{state.iteration - keep}]\n"
                f"{summary_resp.content}"
            )
            logger.debug(f"[{self.agent_name}] History compressed at iter {state.iteration}")
            return [compressed] + list(recent_msgs)
        except Exception as e:
            logger.warning(f"[{self.agent_name}] Compression failed: {e} — keeping recent only")
            return list(recent_msgs)

    # ── Strategy picker ───────────────────────────────────────────────────────

    def _pick_strategy(self, state: LoopState) -> str:
        """Return the next untried strategy. Generates a unique fallback when all are exhausted."""
        for s in self.strategies:
            if s not in state.strategies_tried:
                return s
        return f"custom_approach_{len(state.strategies_tried)}"

    # ── Factory methods ───────────────────────────────────────────────────────

    @classmethod
    def for_planner(cls, llm: LLMClient, tools: List[Tool], system: str = "") -> "AgentLoop":
        """Pre-configured AgentLoop for the Planner agent."""
        return cls(
            llm=llm, tools=tools, agent_name="Planner",
            system=system, max_iterations=15,
            goal_threshold=0.80,
            parallel_tools=False,
            stop_on_no_tool_call=True,
        )

    @classmethod
    def for_recon(cls, llm: LLMClient, tools: List[Tool], system: str = "") -> "AgentLoop":
        """Pre-configured AgentLoop for the Reconnaissance agent."""
        return cls(
            llm=llm, tools=tools, agent_name="Recon",
            system=system, max_iterations=20,
            goal_threshold=0.75,
            parallel_tools=True,
            stop_on_no_tool_call=True,
        )

    @classmethod
    def for_solver(
        cls,
        llm: LLMClient,
        tools: List[Tool],
        system: str = "",
        vuln_type: str = "generic",
        oob_server: Optional[Any] = None,
        jit_engine: Optional[Any] = None,
        evidence_patterns: Optional[List[str]] = None,
        strategies: Optional[List[str]] = None,
    ) -> "AgentLoop":
        """Pre-configured AgentLoop for the Solver/Exploitation agent."""
        _default_evidence = [
            r"root:.*:0:0",          # /etc/passwd line
            r"uid=\d+\(",            # id command output
            r"SQL\s+syntax",         # MySQL syntax error
            r"ORA-\d+",              # Oracle error
            r"Warning.*mysql",       # PHP MySQL warning
            r"<script[\s>]",         # XSS reflection
            r"\{\{7\*7\}\}.*49",     # SSTI math eval confirmed
            r"Exception in thread",  # Java deserialization trace
            r"Traceback \(most",     # Python exception (SSTI/RCE)
        ]
        _default_strategies: Dict[str, List[str]] = {
            "sqli":              ["error_based", "boolean_blind", "time_based", "union", "oob"],
            "xss":               ["reflected", "stored", "dom_based", "csp_bypass", "polyglot"],
            "ssti":              ["jinja2", "twig", "freemarker", "velocity", "erb"],
            "ssrf":              ["cloud_metadata", "internal_network", "oob_dns", "file_scheme"],
            "rce":               ["cmd_injection", "time_based", "output_based", "oob"],
            "lfi":               ["path_traversal", "null_byte", "php_wrappers", "log_poisoning"],
            "auth":              ["default_creds", "jwt_none_alg", "idor_enum", "brute_force"],
            "cors":              ["origin_reflection", "null_origin", "subdomain_trust", "wildcard"],
            "csrf":              ["token_absent", "token_bypass", "samesite_none", "referer_bypass"],
            "xxe":               ["file_read", "ssrf_via_xxe", "oob_dtd", "php_expect"],
            "open_redirect":     ["param_injection", "double_slash", "protocol_bypass", "host_header"],
            "graphql":           ["introspection", "field_suggestion", "batch_query", "auth_bypass"],
            "race_condition":    ["limit_check", "coupon_reuse", "concurrent_write", "toctou"],
            "deserialization":   ["java_gadget", "pickle_rce", "yaml_load", "php_unserialize"],
            "http_smuggling":    ["cl_te", "te_cl", "te_te", "cl_cl"],
            "subdomain_takeover":["dangling_cname", "unclaimed_service", "wildcard_dns", "ns_takeover"],
        }
        _generic_fallback = ["payload_fuzzing", "encoding_bypass", "oob_detection"]

        return cls(
            llm=llm, tools=tools,
            agent_name=f"Solver[{vuln_type}]",
            system=system,
            max_iterations=80,
            goal_threshold=0.72,
            pivot_threshold=0.30,
            pivot_after=3,
            pivot_cooldown=3,
            compress_every=15,
            compress_keep_recent=8,
            oob_server=oob_server,
            oob_poll_every=5,
            oob_timeout=10.0,
            jit_engine=jit_engine,
            evidence_patterns=evidence_patterns or _default_evidence,
            strategies=strategies or _default_strategies.get(vuln_type, _generic_fallback),
            parallel_tools=True,
            stop_on_no_tool_call=False,
            nudge_after=3,
        )

    @classmethod
    def for_summary(cls, llm: LLMClient, tools: List[Tool], system: str = "") -> "AgentLoop":
        """Pre-configured AgentLoop for the Summary/Reporter agent."""
        return cls(
            llm=llm, tools=tools, agent_name="Summary",
            system=system, max_iterations=8,
            goal_threshold=0.90,
            parallel_tools=False,
            stop_on_no_tool_call=True,
        )

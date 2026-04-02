"""
engine/agentic_loop.py — XLayer Reasoning Loop
The core "brain" of XLayer agentic Solver (reasoning loop).

This is NOT a fixed graph. Each iteration the LLM:
  1. Reads the full observation journal (all prior results)
  2. Decides WHAT to do next (tool call / JIT code / pivot / conclude)
  3. Executes the action
  4. Updates confidence score
  5. Checks if we found the vuln (confidence ≥ FOUND_THRESHOLD)
  6. Checks if we should pivot (stuck for N iterations)
  7. Compresses history every 15 iterations to save tokens

Key differences from basic AgentLoop:
  - Observation Journal: structured record of ALL past actions + results
  - Confidence Scoring: explicit 0.0–1.0 confidence tracking
  - Auto-Pivot: after CONSECUTIVE_FAIL_PIVOT low-conf iterations → new strategy
  - JIT Synthesis: LLM can write + run Python code in a sandbox
  - OOB Polling: blind detection (SQLi/SSRF/XSS) via InteractSH
  - Context Compression: every 15 iterations, old turns summarized
"""

import asyncio
import json
import re
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from loguru import logger

from .llm import LLMClient
from .memory import ObservationEntry, ObservationJournal
from .messages import AIMessage, HumanMessage, Message, SystemMessage, ToolMessage
from .tool import Tool, ToolRegistry


# ── Constants ────────────────────────────────────────────────────────────────

MAX_ITERATIONS = 80
FOUND_THRESHOLD = 0.72           # confidence ≥ this → vulnerability confirmed
REFINE_THRESHOLD = 0.35          # confidence ≥ this → refine current approach
CONSECUTIVE_FAIL_PIVOT = 3       # stuck for this many iters → auto-pivot
COMPRESS_EVERY = 15              # compress history every N iterations
OOB_POLL_EVERY = 5               # check OOB callbacks every N iterations

# Mutation injection points — iterations where MutationEngine is triggered on auto-pivot
MUTATION_INJECT_ITERS = {15, 30, 45, 60}


# ── Enums ────────────────────────────────────────────────────────────────────

class ActionType(str, Enum):
    TOOL_CALL  = "tool_call"   # call a hunter tool or http_probe
    JIT_CODE   = "jit_code"    # write + execute Python in sandbox
    THINK      = "think"       # pure reasoning, no external call
    PIVOT      = "pivot"       # switch strategy
    CONCLUDE   = "conclude"    # stop — found or not found


# ── State ────────────────────────────────────────────────────────────────────

@dataclass
class SolverState:
    """Full exploitation context for one (endpoint × vuln_type) task."""
    run_id: str
    target_url: str
    parameter: str
    vuln_type: str                              # e.g. "sqli", "xss", "ssti"
    method: str = "GET"
    extra_context: str = ""                     # recon findings, tech stack, etc.

    # Accumulated state
    confidence: float = 0.0
    iteration: int = 0
    journal: ObservationJournal = field(default_factory=ObservationJournal)
    messages: List[Message] = field(default_factory=list)
    proof: Optional[str] = None                 # confirmed exploit proof
    proof_payload: Optional[str] = None
    strategy: str = "initial"                   # current attack strategy name
    strategies_tried: List[str] = field(default_factory=list)

    # Results
    found: bool = False
    not_found: bool = False
    error: Optional[str] = None

    def full_context(self) -> str:
        """
        Build context-rich prompt section for the LLM.
        This is injected at each iteration so the LLM always has full picture.
        """
        lines = [
            f"## Target",
            f"URL: {self.target_url}",
            f"Parameter: {self.parameter}",
            f"Method: {self.method}",
            f"Vuln Type: {self.vuln_type}",
        ]
        if self.extra_context:
            lines += ["", "## Recon Context", self.extra_context]

        lines += [
            "",
            f"## Progress",
            f"Iteration: {self.iteration}/{MAX_ITERATIONS}",
            f"Confidence: {self.confidence:.2f}",
            f"Strategy: {self.strategy}",
            f"Strategies tried: {', '.join(self.strategies_tried) or 'none'}",
        ]

        lines += [
            "",
            "## Observation Journal (all past actions + results)",
            self.journal.as_text(max_entries=20),
        ]

        if self.proof:
            lines += ["", f"## Current Best Proof", self.proof]

        return "\n".join(lines)


# ── Decision parsing ──────────────────────────────────────────────────────────

@dataclass
class Decision:
    """Parsed LLM decision from a single iteration."""
    action: ActionType
    tool_name: Optional[str] = None
    tool_args: Dict[str, Any] = field(default_factory=dict)
    jit_code: Optional[str] = None
    register_tool_name: Optional[str] = None  # NEW: for persistent JIT tools
    tool_description: Optional[str] = None   # NEW: for persistent JIT tools
    reasoning: str = ""
    new_confidence: float = 0.0
    new_strategy: Optional[str] = None
    conclusion: Optional[str] = None   # "found" or "not_found"
    proof: Optional[str] = None


def _extract_json_block(text: str) -> Optional[Dict[str, Any]]:
    """Extract the last JSON block from LLM response."""
    # Try ```json ... ``` first
    matches = re.findall(r"```json\s*(.*?)```", text, re.DOTALL)
    if matches:
        try:
            return json.loads(matches[-1].strip())
        except json.JSONDecodeError:
            pass

    # Try bare { ... } block
    matches = re.findall(r"\{[^{}]*\}", text, re.DOTALL)
    for m in reversed(matches):
        try:
            return json.loads(m)
        except json.JSONDecodeError:
            continue
    return None


def _extract_think_block(text: str) -> str:
    """Extract content between <think>...</think> tags (Chain of Thought reasoning)."""
    match = re.search(r"<think>(.*?)</think>", text, re.DOTALL)
    return match.group(1).strip() if match else ""


def _parse_decision(ai_msg: AIMessage, state: SolverState) -> Decision:
    """
    Parse LLM response into a structured Decision.

    The LLM is instructed to always end with a JSON block like:
    {
      "action": "tool_call",
      "tool": "run_sqli_hunter",
      "args": {"url": "...", "parameter": "id"},
      "confidence": 0.45,
      "reasoning": "..."
    }
    """
    # First check for tool_calls (OpenAI/Anthropic native function calling)
    if ai_msg.has_tool_calls:
        tc = ai_msg.tool_calls[0]
        tool_name = tc["function"]["name"]
        try:
            args = json.loads(tc["function"]["arguments"])
        except Exception:
            args = {}
        return Decision(
            action=ActionType.TOOL_CALL,
            tool_name=tool_name,
            tool_args=args,
            reasoning=ai_msg.content or "",
            new_confidence=state.confidence,  # unchanged until result known
        )

    # Fall back to JSON block in text
    data = _extract_json_block(ai_msg.content or "")
    if not data:
        # No parseable JSON — treat as THINK action
        return Decision(
            action=ActionType.THINK,
            reasoning=ai_msg.content or "",
            new_confidence=state.confidence,
        )

    action_str = data.get("action", "think").lower()

    # Map string to ActionType
    action_map = {
        "tool_call": ActionType.TOOL_CALL,
        "tool": ActionType.TOOL_CALL,
        "jit_code": ActionType.JIT_CODE,
        "jit": ActionType.JIT_CODE,
        "think": ActionType.THINK,
        "pivot": ActionType.PIVOT,
        "conclude": ActionType.CONCLUDE,
        "stop_found": ActionType.CONCLUDE,
        "stop_not_found": ActionType.CONCLUDE,
        "found": ActionType.CONCLUDE,
        "not_found": ActionType.CONCLUDE,
    }
    action = action_map.get(action_str, ActionType.THINK)

    # Determine conclusion
    conclusion = None
    if action == ActionType.CONCLUDE:
        if action_str in ("stop_found", "found"):
            conclusion = "found"
        elif action_str in ("stop_not_found", "not_found"):
            conclusion = "not_found"
        else:
            conclusion = data.get("conclusion", "not_found")

    return Decision(
        action=action,
        tool_name=data.get("tool") or data.get("tool_name"),
        tool_args=data.get("args", {}),
        jit_code=data.get("code") or data.get("jit_code"),
        register_tool_name=data.get("register_tool_name"),
        tool_description=data.get("tool_description"),
        reasoning=data.get("reasoning", ai_msg.content or ""),
        new_confidence=float(data.get("confidence", state.confidence)),
        new_strategy=data.get("new_strategy"),
        conclusion=conclusion,
        proof=data.get("proof"),
    )


# ── Deep Think Prompt (used before auto-pivot) ────────────────────────────────

_DEEP_THINK_PROMPT = """\
You are analyzing a stalled penetration test. Think carefully and be concrete.

Target: {target_url}
Vulnerability type: {vuln_type}
Iterations used: {iteration}/{max_iter}
Confidence so far: {confidence}
Strategies tried: {strategies}

Last observations:
{recent_journal}

Analyze step by step:
1. Why has exploitation stalled? (root cause — WAF? wrong param? wrong vuln type?)
2. What assumptions might be wrong about this target?
3. What completely different technique could bypass current blockers?
4. List 3 specific payloads or approaches to try next.

Be concrete. No generic advice.
"""


# ── XLayer Loop ──────────────────────────────────────────────────────────────

class XLayerLoop:
    """
    The core agentic reasoning loop.

    Each iteration:
      1. Build prompt with full context + observation journal
      2. Call LLM → get Decision
      3. Execute action (tool / JIT / pivot / conclude)
      4. Record observation in journal
      5. Update confidence
      6. Check: found? stuck? → auto-pivot or conclude
      7. Every COMPRESS_EVERY iters: compress old messages to save tokens
      8. Every OOB_POLL_EVERY iters: check OOB callbacks

    Usage:
        loop = XLayerLoop(llm=client, tools=tool_list)
        state = SolverState(
            run_id="scan_001",
            target_url="https://target.com/search",
            parameter="q",
            vuln_type="sqli",
        )
        result = await loop.run(state)
        if result.found:
            print("VULN CONFIRMED:", result.proof)
    """

    SYSTEM_PROMPT = """\
You are an expert penetration tester running an autonomous exploitation loop.

Your task: Prove OR definitively rule out a vulnerability at the given target.

## Reasoning Protocol
Before your JSON decision block, write your step-by-step reasoning inside <think> tags:
<think>
Current state: [what the evidence shows so far]
What failed: [past approaches and why they didn't work]
Best next move: [chosen approach and concrete reasoning]
</think>

This reasoning improves your decisions. Always include it.

## Decision Format
After your <think> block, end with a JSON block:

For tool calls:
```json
{"action": "tool_call", "tool": "<tool_name>", "args": {}, "confidence": 0.45, "reasoning": "..."}
```

For JIT Python code:
```json
{"action": "jit_code", "code": "...", "register_tool_name": "custom_parser", "tool_description": "Parses custom crypto", "confidence": 0.5, "reasoning": "..."}
```
Use `register_tool_name` ONLY if you want to create a persistent tool that you can call later in this session.

For pivoting strategy:
```json
{"action": "pivot", "new_strategy": "<strategy_name>", "confidence": 0.2, "reasoning": "..."}
```

For conclusion:
```json
{"action": "stop_found", "proof": "<what proved it>", "confidence": 0.85, "reasoning": "..."}
{"action": "stop_not_found", "confidence": 0.05, "reasoning": "..."}
```

## Confidence Bands
- 0.00–0.35: No signal — try completely different approach
- 0.35–0.72: Partial signal — refine and escalate
- 0.72+:     Strong signal — validate and collect proof

## Iteration Budget Strategy
- Iteration 0:      Auto-fingerprint — WAF, filtered chars, boolean/time feasibility (done for you)
- Iterations 1-10:  Recon — understand target, identify injection points
- Iterations 11-40: Exploitation — escalating payload complexity
- Iterations 41-65: Novel approaches — JIT scripts, chained exploits, OOB
- Iterations 66-80: Validation — confirm finding, collect clean proof

## Mutation Engine (automatic)
When you get stuck and auto-pivot triggers, the system automatically injects
WAF bypass mutations (100+ techniques) at iterations 15, 30, 45, 60.
Use the suggested mutations in your next tool calls.

## Key Rules
1. If confidence < 0.35 for 3+ iterations → PIVOT immediately
2. If OOB callback received → confidence = 0.9, collect proof
3. Always escalate: if simple payload failed, try encoded/obfuscated version
4. Chain vulns: SQLi → file read → RCE is valid chain
5. Never repeat a payload that already failed
"""

    def __init__(
        self,
        llm: LLMClient,
        tools: List[Tool],
        oob_server: Optional[Any] = None,   # OOBServer instance (optional)
        jit_engine: Optional[Any] = None,   # JITEngine instance (optional)
    ) -> None:
        self.llm = llm
        self.registry = ToolRegistry(tools)
        self.oob = oob_server
        self.jit = jit_engine

        # ── Unified Engine Components ─────────────────────────────────────
        # MutationEngine: 100+ WAF bypass mutations, injected on auto-pivot
        try:
            from xlayer_ai.tools.mutation_engine import MutationEngine
            self._mutation_engine = MutationEngine()
        except Exception:
            self._mutation_engine = None

        # ProbeEngine fingerprint context (populated in run() iter 1)
        self._probe_ctx = None

    async def run(self, state: SolverState) -> SolverState:
        """
        Run the XLayer loop until found, not_found, or max iterations.
        Returns updated SolverState.
        """
        state.strategies_tried.append(state.strategy)

        # ── Iteration 0: Target Fingerprint (ProbeEngine) ────────────────
        # Populates WAF, filtered chars, boolean/time injection feasibility
        # so the LLM starts with real intelligence instead of guessing.
        probe_summary = await self._fingerprint_target(state)
        if probe_summary:
            state.extra_context += f"\n\n## Probe Fingerprint\n{probe_summary}"
            state.journal.add(ObservationEntry(
                iteration=0,
                action="fingerprint",
                input_summary="ProbeEngine target fingerprint",
                result_summary=probe_summary[:200],
                confidence=state.confidence,
            ))

        for i in range(1, MAX_ITERATIONS + 1):
            state.iteration = i
            remaining = MAX_ITERATIONS - i

            # ── Poll OOB every N iterations ──────────────────────────────
            if self.oob and i % OOB_POLL_EVERY == 0:
                await self._poll_oob(state)

            # ── Build context prompt ──────────────────────────────────────
            context = state.full_context()
            user_msg = HumanMessage(
                f"{context}\n\n"
                f"Remaining iterations: {remaining}\n"
                f"What is your next action? Respond with reasoning and a JSON decision block."
            )

            # Use compressed messages + fresh user message
            msgs_to_send = list(state.messages) + [user_msg]

            # ── Call LLM ──────────────────────────────────────────────────
            ai_response = await self.llm.call(
                messages=msgs_to_send,
                tools=self.registry.all(),
                system=self.SYSTEM_PROMPT,
            )

            # Store only AI response (user msg already in context string)
            state.messages.append(ai_response)

            # ── Extract CoT reasoning ─────────────────────────────────────
            think_content = _extract_think_block(ai_response.content or "")
            if think_content:
                logger.debug(
                    f"[XLayerLoop][CoT] iter={i} "
                    f"think={think_content[:120].replace(chr(10), ' ')}"
                )
                state.journal.add(ObservationEntry(
                    iteration=i,
                    action="think",
                    input_summary="CoT reasoning",
                    result_summary=think_content[:200],
                    confidence=state.confidence,
                ))

            # ── Parse decision ────────────────────────────────────────────
            decision = _parse_decision(ai_response, state)

            # ── Execute action ────────────────────────────────────────────
            obs_result = await self._execute(decision, state)

            # ── Update confidence ─────────────────────────────────────────
            if decision.new_confidence > 0:
                # Take the higher of LLM estimate vs current
                state.confidence = max(state.confidence, decision.new_confidence)

            # ── Record observation ────────────────────────────────────────
            obs = ObservationEntry(
                iteration=i,
                action=decision.action.value,
                input_summary=_summarize_input(decision),
                result_summary=obs_result[:200] if obs_result else "no result",
                confidence=state.confidence,
            )
            state.journal.add(obs)

            logger.info(
                f"[XLayerLoop][{state.vuln_type}] iter={i} "
                f"action={decision.action.value} conf={state.confidence:.2f}"
            )

            # ── Check conclusion ──────────────────────────────────────────
            if decision.action == ActionType.CONCLUDE:
                if decision.conclusion == "found":
                    state.found = True
                    state.proof = decision.proof or obs_result
                    logger.success(
                        f"[XLayerLoop] VULN CONFIRMED: {state.vuln_type} at {state.target_url}"
                    )
                else:
                    state.not_found = True
                    logger.info(
                        f"[XLayerLoop] Not found: {state.vuln_type} at {state.target_url}"
                    )
                break

            # ── Check confidence threshold ────────────────────────────────
            if state.confidence >= FOUND_THRESHOLD:
                state.found = True
                state.proof = decision.proof or obs_result
                logger.success(
                    f"[XLayerLoop] FOUND (conf={state.confidence:.2f}): "
                    f"{state.vuln_type} at {state.target_url}"
                )
                break

            # ── Auto-pivot if stuck ───────────────────────────────────────
            if state.journal.is_stuck(CONSECUTIVE_FAIL_PIVOT, REFINE_THRESHOLD):
                # Deep CoT reasoning call before committing to new strategy.
                # Gives LLM a chance to diagnose the root cause before pivoting.
                deep_reasoning = await self._deep_think(state)
                new_strategy = self._pick_new_strategy(state)
                logger.warning(
                    f"[XLayerLoop] Auto-pivot: {state.strategy} → {new_strategy}"
                )
                state.strategy = new_strategy
                state.strategies_tried.append(new_strategy)
                pivot_msg = (
                    f"[SYSTEM] Auto-pivot triggered. "
                    f"New strategy: {new_strategy}. "
                    f"Previous approaches failed. Try a completely different angle."
                )
                if deep_reasoning:
                    pivot_msg += f"\n\n[Analysis]\n{deep_reasoning[:600]}"

                # ── MutationEngine injection on pivot iterations ──────────
                # At key iteration milestones, generate WAF bypass mutations
                # from failed payloads and inject them as LLM suggestions.
                if i in MUTATION_INJECT_ITERS and self._mutation_engine:
                    mutation_suggestions = self._generate_mutation_suggestions(state)
                    if mutation_suggestions:
                        pivot_msg += f"\n\n[MutationEngine Suggestions]\n{mutation_suggestions}"
                        logger.info(
                            f"[XLayerLoop] MutationEngine injected at iter {i}"
                        )

                state.messages.append(HumanMessage(pivot_msg))

            # ── Compress history every N iterations ───────────────────────
            if i % COMPRESS_EVERY == 0 and len(state.messages) > COMPRESS_EVERY:
                state.messages = await self._compress_history(state)

        return state

    # ── Action execution ─────────────────────────────────────────────────────

    async def _execute(self, decision: Decision, state: SolverState) -> str:
        """Execute one decision and return result string."""

        if decision.action == ActionType.TOOL_CALL:
            return await self._execute_tool(decision, state)

        elif decision.action == ActionType.JIT_CODE:
            return await self._execute_jit(decision, state)

        elif decision.action == ActionType.PIVOT:
            if decision.new_strategy:
                state.strategy = decision.new_strategy
                if decision.new_strategy not in state.strategies_tried:
                    state.strategies_tried.append(decision.new_strategy)
            return f"Pivoted to strategy: {state.strategy}"

        elif decision.action == ActionType.THINK:
            return decision.reasoning or "Thinking..."

        elif decision.action == ActionType.CONCLUDE:
            return f"Concluded: {decision.conclusion} | {decision.proof or ''}"

        return "Unknown action"

    async def _execute_tool(self, decision: Decision, state: SolverState) -> str:
        """Execute a tool call with universal pacing (anti-WAF jitter)."""
        if not decision.tool_name:
            return "Error: no tool name in decision"

        # ── Universal Pacing — random delay before every HTTP tool call ──
        try:
            from xlayer_ai.tools.pacing import apply_pacing
            await apply_pacing()
        except Exception:
            pass

        # Add target context to args if not present
        args = dict(decision.tool_args)
        if "url" not in args:
            args["url"] = state.target_url
        if "parameter" not in args and state.parameter:
            args["parameter"] = state.parameter
        if "method" not in args:
            args["method"] = state.method

        result = self.registry.execute(decision.tool_name, args)
        return result

    async def _execute_jit(self, decision: Decision, state: SolverState) -> str:
        """Execute JIT Python code in sandbox."""
        if not self.jit:
            return "JIT engine not available — skipping code execution"

        code = decision.jit_code
        if not code:
            return "No code provided"

        try:
            # JITEngine.run is synchronous (subprocess-based)
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.jit.run(code, {
                    "url": state.target_url,
                    "param": state.parameter,
                    "vuln": state.vuln_type,
                })
            )

            execution_output = ""
            if result.success:
                # Check if output implies vuln found
                output = result.stdout[:500]
                self._check_jit_output_for_evidence(output, state)
                execution_output = f"JIT Success:\n{output}"
            else:
                execution_output = f"JIT Failed: {result.stderr[:300]}"

            # ── Dynamic Tool Registration (Self-Evolving Tooling) ──────
            if decision.register_tool_name and result.success:
                tool_name = decision.register_tool_name
                desc = decision.tool_description or f"JIT tool generated for {state.vuln_type}"
                
                # Create a wrapper that calls the JIT engine with this specific code
                # We use a closure to capture the code
                def jit_tool_wrapper(**kwargs) -> str:
                    # Merge static context with runtime kwargs
                    combined_ctx = {
                        "url": state.target_url,
                        "param": state.parameter,
                        "vuln": state.vuln_type,
                        **kwargs
                    }
                    # Synchronous call to JIT engine (wrapped in the registry.execute)
                    res = self.jit.run(code, combined_ctx)
                    return res.stdout if res.success else f"JIT Tool Error: {res.stderr}"

                # Wrap as a Tool object
                from .tool import Tool
                import inspect

                # Simple schema generation for JIT tools (accepts anything in kwargs)
                new_tool = Tool(
                    name=tool_name,
                    description=desc,
                    parameters={"type": "object", "properties": {}, "additionalProperties": True},
                    func=jit_tool_wrapper
                )
                
                self.registry.register(new_tool)
                logger.success(f"[XLayerLoop] NEW JIT TOOL REGISTERED: {tool_name}")
                execution_output += f"\n\n[SYSTEM] Persistent tool '{tool_name}' has been registered and is now available for use."

            return execution_output

        except Exception as e:
            return f"JIT Error: {e}"

    def _check_jit_output_for_evidence(self, output: str, state: SolverState) -> None:
        """Bump confidence if JIT output shows exploit evidence."""
        evidence_patterns = [
            r"root:.*:0:0",           # /etc/passwd
            r"uid=\d+\(",             # id command output
            r"sleep\s+\d+.*done",     # sleep command confirmed
            r"SQL\s+syntax",          # SQL error
            r"ORA-\d+",               # Oracle error
            r"<script.*?>",           # XSS payload reflected
            r"\{\{.*?\}\}",           # template injection
            r"Exception in thread",   # Java deserialization
        ]
        for pat in evidence_patterns:
            if re.search(pat, output, re.IGNORECASE):
                old_conf = state.confidence
                state.confidence = min(1.0, state.confidence + 0.25)
                logger.info(
                    f"[XLayerLoop] JIT output pattern match → conf {old_conf:.2f} → {state.confidence:.2f}"
                )
                break

    # ── OOB polling ──────────────────────────────────────────────────────────

    async def _poll_oob(self, state: SolverState) -> None:
        """Check OOB server for blind vuln callbacks."""
        if not self.oob:
            return
        try:
            # OOBServer.get_recent_hits() returns list of OOBHit
            hits = await asyncio.get_event_loop().run_in_executor(
                None, self.oob.get_recent_hits
            )
            if hits:
                logger.success(f"[XLayerLoop] OOB callback received! hits={len(hits)}")
                state.confidence = max(state.confidence, 0.90)
                state.proof = f"OOB callback received: {hits[0]}"
                state.journal.add(ObservationEntry(
                    iteration=state.iteration,
                    action="OOB_HIT",
                    input_summary="OOB server polled",
                    result_summary=f"{len(hits)} callback(s) received",
                    confidence=state.confidence,
                ))
        except Exception as e:
            logger.debug(f"[XLayerLoop] OOB poll error: {e}")

    # ── History compression ───────────────────────────────────────────────────

    async def _compress_history(self, state: SolverState) -> List[Message]:
        """
        Ask LLM to summarize old messages to reduce token usage.
        Keeps last 5 messages verbatim, compresses the rest.
        """
        if len(state.messages) <= 5:
            return state.messages

        old_msgs = state.messages[:-5]
        recent_msgs = state.messages[-5:]

        old_text = "\n".join(
            f"[{m.__class__.__name__}]: {getattr(m, 'content', '')[:200]}"
            for m in old_msgs
        )

        summary_prompt = [
            HumanMessage(
                f"Summarize the following exploitation attempt history in 3-5 bullet points. "
                f"Focus on: what was tried, what worked, what failed, current confidence level.\n\n"
                f"{old_text}"
            )
        ]

        try:
            summary_resp = await self.llm.call(summary_prompt)
            summary_msg = SystemMessage(
                f"[Compressed History — iterations 1-{state.iteration - 5}]\n"
                f"{summary_resp.content}"
            )
            return [summary_msg] + list(recent_msgs)
        except Exception as e:
            logger.warning(f"[XLayerLoop] History compression failed: {e}")
            return recent_msgs  # fallback: just keep recent

    # ── Chain of Thought: deep reasoning ─────────────────────────────────────

    async def _deep_think(self, state: SolverState) -> str:
        """
        Dedicated reasoning call used before auto-pivot decisions.

        Separate from the main loop call — no tools, no JSON required.
        Returns raw reasoning text to inject into pivot context.
        """
        try:
            prompt = _DEEP_THINK_PROMPT.format(
                target_url=state.target_url,
                vuln_type=state.vuln_type,
                iteration=state.iteration,
                max_iter=MAX_ITERATIONS,
                confidence=f"{state.confidence:.2f}",
                strategies=", ".join(state.strategies_tried) or "none",
                recent_journal=state.journal.as_text(max_entries=5),
            )
            resp = await self.llm.call(
                messages=[{"role": "user", "content": prompt}]
            )
            reasoning = resp.content or ""
            logger.debug(
                f"[XLayerLoop][DeepThink] iter={state.iteration} "
                f"reasoning={reasoning[:120].replace(chr(10), ' ')}"
            )
            return reasoning
        except Exception as e:
            logger.debug(f"[XLayerLoop][DeepThink] failed: {e}")
            return ""

    # ── Strategy selection ────────────────────────────────────────────────────

    STRATEGIES: Dict[str, List[str]] = {
        "sqli": ["error_based", "boolean_blind", "time_based", "union", "oob_dns", "stacked_queries"],
        "xss":  ["reflected", "stored", "dom_based", "csp_bypass", "mutation", "polyglot"],
        "ssrf": ["cloud_metadata", "internal_network", "protocol_bypass", "oob_dns", "file_scheme"],
        "ssti": ["jinja2", "twig", "freemarker", "velocity", "erb", "smarty", "mako"],
        "rce":  ["cmd_injection", "time_based", "output_based", "oob_dns", "polyglot_chain"],
        "lfi":  ["path_traversal", "php_wrappers", "log_poisoning", "null_byte", "zip_wrapper"],
        "xxe":  ["file_read", "ssrf", "oob_dns", "error_based", "php_expect"],
    }

    def _pick_new_strategy(self, state: SolverState) -> str:
        """Choose the next untried strategy for the current vuln type."""
        options = self.STRATEGIES.get(state.vuln_type, ["generic_a", "generic_b", "oob"])
        for s in options:
            if s not in state.strategies_tried:
                return s
        # All specific strategies exhausted — try JIT custom approach
        return f"jit_custom_{len(state.strategies_tried)}"

    # ── Target Fingerprint (ProbeEngine integration) ─────────────────────

    async def _fingerprint_target(self, state: SolverState) -> str:
        """
        Run lightweight target fingerprinting before the main loop.
        Uses ProbeEngine to detect WAF, filtered chars, boolean/time injection.
        Returns a summary string for the LLM context.
        """
        try:
            from xlayer_ai.tools.adaptive_engine import ProbeEngine, SendResult
            from xlayer_ai.llm.payload_generator import AttackContext
            from xlayer_ai.models.target import Endpoint, HTTPMethod, EndpointType

            ctx = AttackContext(vuln_type=state.vuln_type)

            # Build a minimal send_fn using http_probe tool
            async def _send_fn(endpoint, param, payload):
                try:
                    import httpx
                    url = state.target_url
                    params = {param: payload} if param else {}
                    async with httpx.AsyncClient(
                        timeout=8, verify=False, follow_redirects=True
                    ) as client:
                        import time
                        start = time.monotonic()
                        if state.method.upper() in ("POST", "PUT", "PATCH"):
                            r = await client.post(url, data=params)
                        else:
                            r = await client.get(url, params=params)
                        elapsed = (time.monotonic() - start) * 1000
                        return SendResult(
                            payload=payload,
                            status_code=r.status_code,
                            body=r.text[:5000],
                            elapsed_ms=elapsed,
                            success=True,
                            headers=dict(r.headers),
                        )
                except Exception:
                    return None

            method_upper = state.method.upper()
            method_enum = (
                HTTPMethod(method_upper)
                if method_upper in HTTPMethod._value2member_map_
                else HTTPMethod.GET
            )
            endpoint = Endpoint(
                url=state.target_url,
                method=method_enum,
                endpoint_type=EndpointType.API,
                parameters=[],
            )

            probe = ProbeEngine(_send_fn)
            await probe.probe(endpoint, state.parameter, ctx)

            # Store probe context for MutationEngine later
            self._probe_ctx = ctx

            # Build summary
            parts = []
            if ctx.waf:
                parts.append(f"WAF: {ctx.waf}")
            if ctx.filtered_chars:
                parts.append(f"Filtered chars: {ctx.filtered_chars}")
            if ctx.keywords_filtered:
                parts.append(f"Filtered keywords: {ctx.keywords_filtered}")
            if ctx.quotes_filtered:
                parts.append("Quotes filtered: YES")
            if ctx.time_delay_works:
                parts.append("Time-based injection: POSSIBLE")
            if ctx.boolean_diff_works:
                parts.append("Boolean-blind injection: POSSIBLE")
            if ctx.baseline_length:
                parts.append(f"Baseline response: {ctx.baseline_length} bytes")

            summary = " | ".join(parts) if parts else "No WAF, no filtering detected"
            logger.info(f"[XLayerLoop] Fingerprint: {summary}")
            return summary

        except Exception as e:
            logger.debug(f"[XLayerLoop] Fingerprint failed (non-fatal): {e}")
            return ""

    # ── MutationEngine integration ───────────────────────────────────────

    def _generate_mutation_suggestions(self, state: SolverState) -> str:
        """
        Extract failed payloads from journal, run through MutationEngine,
        return top suggestions as text for LLM context injection.
        """
        if not self._mutation_engine:
            return ""

        # Extract payloads from recent journal entries
        failed_payloads = []
        for entry in state.journal.entries[-20:]:
            # Look for payload patterns in input_summary
            inp = entry.input_summary or ""
            if "payload" in inp.lower() or "http_probe" in inp.lower():
                # Extract payload from tool args if present
                import re as _re
                payload_match = _re.search(r"payload['\"]?\s*[:=]\s*['\"](.+?)['\"]", inp)
                if payload_match:
                    failed_payloads.append(payload_match.group(1))

        if not failed_payloads:
            # Fallback: use standard test payloads for the vuln type
            _default_payloads = {
                "sqli": ["' OR 1=1--", "' UNION SELECT NULL--"],
                "xss": ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"],
                "lfi": ["../../../etc/passwd", "....//....//etc/passwd"],
                "ssrf": ["http://127.0.0.1", "http://169.254.169.254/latest/meta-data/"],
                "ssti": ["{{7*7}}", "${7*7}"],
                "rce": ["; id", "| whoami"],
                "xxe": ['<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>'],
            }
            failed_payloads = _default_payloads.get(state.vuln_type, ["test"])

        # Generate mutations with WAF context from probe
        mutations = self._mutation_engine.mutate_to_strings(
            vuln_type=state.vuln_type,
            payloads=failed_payloads[:5],
            ctx=self._probe_ctx,
            limit=10,
        )

        if not mutations:
            return ""

        lines = [f"Try these WAF-bypass mutations ({state.vuln_type}):"]
        for j, m in enumerate(mutations, 1):
            lines.append(f"  {j}. {m[:120]}")
        return "\n".join(lines)


# ── Helper ────────────────────────────────────────────────────────────────────

def _summarize_input(decision: Decision) -> str:
    """Short description of what the decision attempted."""
    if decision.action == ActionType.TOOL_CALL:
        args_preview = str(decision.tool_args)[:80]
        return f"{decision.tool_name}({args_preview})"
    elif decision.action == ActionType.JIT_CODE:
        code_preview = (decision.jit_code or "")[:80].replace("\n", " ")
        return f"JIT: {code_preview}"
    elif decision.action == ActionType.PIVOT:
        return f"pivot → {decision.new_strategy}"
    elif decision.action == ActionType.CONCLUDE:
        return f"conclude({decision.conclusion})"
    return decision.reasoning[:80] if decision.reasoning else "think"

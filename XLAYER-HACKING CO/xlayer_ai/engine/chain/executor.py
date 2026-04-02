"""
engine/chain/executor.py — Attack Chain Executor

Executes a ChainSpec step by step.
Each step's outputs automatically become the next step's inputs via shared context.
LLM generates JIT Python code for each step — no hardcoded exploit logic.
"""

import asyncio
import json
import time
from typing import Any, Dict, List, Optional

from loguru import logger

from xlayer_ai.engine.agentic_loop import _extract_json_block
from xlayer_ai.engine.llm import LLMClient
from xlayer_ai.engine.tool import Tool
from .models import ChainSpec, ChainResult, ChainStep, StepResult


_STEP_PLAN_PROMPT = """\
You are executing step {step_num}/{total_steps} of an attack chain.

## Chain: {chain_name}
## Current Step: {step_name}
## Goal: {step_description}

## Available Context (outputs from previous steps)
{context_json}

## Task
Write Python code to execute this step.
The code has access to: httpx, json, base64, re, urllib.parse, jwt (PyJWT), hmac, hashlib
Context variables are injected as globals.

The code MUST:
1. Use context variables as inputs (they are available as globals)
2. Print results as JSON: print(json.dumps({"key": "value", ...}))
3. Print a "proof" field with evidence of success/failure
4. Be self-contained (no external imports except the listed ones)

Return JSON:
```json
{
  "code": "import json\\n...\\nprint(json.dumps({...}))",
  "expected_outputs": ["output_key_1", "output_key_2"],
  "reasoning": "one line explaining approach"
}
```
"""

_POC_PROMPT = """\
Generate a clean, runnable proof-of-concept script for this confirmed attack chain.

Chain: {chain_name}
Description: {chain_description}
Steps executed:
{steps_summary}

Context collected:
{context_json}

Target: {target_url}

Write a single Python script using httpx that reproduces the full attack chain.
Include comments explaining each step.
The script should be copy-pasteable and runnable.

Return only the Python code, no JSON wrapper.
"""


class ChainExecutor:
    """
    Executes a ChainSpec step by step.

    Each step:
      1. LLM generates Python code for the step
      2. JITEngine runs the code in sandbox
      3. Output parsed → injected into shared context
      4. Next step reads from updated context

    If a step fails, execution stops and partial result returned.
    """

    def __init__(
        self,
        llm: LLMClient,
        tools: Optional[List[Tool]] = None,
        jit_engine: Any = None,
        oob: Any = None,
        step_timeout: float = 60.0,
    ) -> None:
        self.llm          = llm
        self.tools        = tools or []
        self.jit          = jit_engine
        self.oob          = oob
        self.step_timeout = step_timeout

    async def execute(self, spec: ChainSpec) -> ChainResult:
        """Execute all steps of the chain. Returns ChainResult."""
        t0 = time.monotonic()
        context: Dict[str, Any] = dict(spec.evidence)  # seed with pre-loaded evidence

        step_results: List[StepResult] = []

        logger.info(
            f"[ChainExecutor] Starting chain: {spec.name} "
            f"({len(spec.steps)} steps)"
        )

        for idx, step in enumerate(spec.steps):
            logger.debug(
                f"[ChainExecutor] Step {idx+1}/{len(spec.steps)}: {step.name}"
            )
            try:
                sr = await asyncio.wait_for(
                    self._execute_step(step, context, idx + 1, len(spec.steps), spec.name),
                    timeout=self.step_timeout,
                )
            except asyncio.TimeoutError:
                sr = StepResult(
                    step_name=step.name,
                    success=False,
                    error=f"Step timed out after {self.step_timeout}s",
                )
            except Exception as e:
                sr = StepResult(
                    step_name=step.name,
                    success=False,
                    error=str(e),
                )

            step_results.append(sr)
            context.update(sr.outputs)

            if not sr.success:
                logger.warning(
                    f"[ChainExecutor] Chain {spec.name} failed at step: {step.name} "
                    f"— {sr.error}"
                )
                return ChainResult(
                    spec=spec,
                    completed=False,
                    step_results=step_results,
                    context=context,
                    failed_at=step.name,
                    duration_seconds=time.monotonic() - t0,
                )

            logger.debug(f"[ChainExecutor] Step {step.name} ✓ outputs: {list(sr.outputs.keys())}")

        # All steps succeeded — generate PoC
        poc = await self._generate_poc(spec, step_results, context)
        duration = time.monotonic() - t0

        logger.success(
            f"[ChainExecutor] Chain CONFIRMED: {spec.name} "
            f"in {duration:.1f}s"
        )

        return ChainResult(
            spec=spec,
            completed=True,
            step_results=step_results,
            context=context,
            poc_script=poc,
            duration_seconds=duration,
        )

    # ── Step execution ────────────────────────────────────────────────────────

    async def _execute_step(
        self,
        step: ChainStep,
        context: Dict[str, Any],
        step_num: int,
        total: int,
        chain_name: str,
    ) -> StepResult:
        t0 = time.monotonic()

        # Build context subset for this step
        step_context = {k: context[k] for k in step.input_keys if k in context}
        # Also pass all context in case step needs more
        step_context.update(context)

        # Ask LLM to write code for this step
        code, reasoning = await self._plan_step_code(
            step, step_context, step_num, total, chain_name
        )

        if not code:
            return StepResult(
                step_name=step.name,
                success=False,
                error="LLM failed to generate step code",
                duration_ms=(time.monotonic() - t0) * 1000,
            )

        # Execute code in JIT sandbox
        outputs, proof, error = await self._run_code(code, step_context)
        success = bool(outputs) and not error

        return StepResult(
            step_name=step.name,
            success=success,
            outputs=outputs,
            proof=proof,
            error=error,
            duration_ms=round((time.monotonic() - t0) * 1000, 1),
        )

    async def _plan_step_code(
        self,
        step: ChainStep,
        context: Dict[str, Any],
        step_num: int,
        total: int,
        chain_name: str,
    ) -> tuple:
        """Ask LLM to generate Python code for this step."""
        try:
            # Sanitize context for prompt (no huge blobs)
            safe_ctx = {
                k: str(v)[:200] for k, v in context.items()
                if v and k not in ("admin_response",)
            }
            prompt = _STEP_PLAN_PROMPT.format(
                step_num=step_num,
                total_steps=total,
                chain_name=chain_name,
                step_name=step.name,
                step_description=step.description,
                context_json=json.dumps(safe_ctx, indent=2)[:800],
            )
            ai_msg = await self.llm.call(
                messages=[{"role": "user", "content": prompt}]
            )
            data = _extract_json_block(ai_msg.content or "")
            if not data:
                return None, ""
            return data.get("code", ""), data.get("reasoning", "")
        except Exception as e:
            logger.debug(f"[ChainExecutor] Step code gen error: {e}")
            return None, ""

    async def _run_code(
        self,
        code: str,
        context: Dict[str, Any],
    ) -> tuple:
        """Run generated code in JIT sandbox. Returns (outputs, proof, error)."""
        if not self.jit:
            # No JIT engine — dry run, return mock success
            logger.debug("[ChainExecutor] No JIT engine — dry run")
            return {"dry_run": True}, "dry_run (no JIT engine)", ""

        try:
            result = await self.jit.run(code, context=context)

            if result.timed_out:
                return {}, "", "JIT timeout"
            if result.blocked:
                return {}, "", f"JIT blocked: {result.block_reason}"

            stdout = (result.output or "").strip()
            if not stdout:
                return {}, "", "No output from code"

            # Parse JSON output
            outputs = {}
            proof   = stdout[:300]
            try:
                parsed = json.loads(stdout)
                if isinstance(parsed, dict):
                    outputs = parsed
                    proof   = parsed.get("proof", stdout[:300])
            except json.JSONDecodeError:
                # Non-JSON output — treat as proof text
                outputs = {"raw_output": stdout[:500]}
                proof   = stdout[:300]

            # Check for explicit failure signal
            if outputs.get("success") is False or outputs.get("error"):
                return {}, proof, outputs.get("error", "Step reported failure")

            return outputs, proof, ""

        except Exception as e:
            return {}, "", str(e)

    # ── PoC generation ────────────────────────────────────────────────────────

    async def _generate_poc(
        self,
        spec: ChainSpec,
        step_results: List[StepResult],
        context: Dict[str, Any],
    ) -> str:
        """Generate a clean, runnable PoC script for the confirmed chain."""
        try:
            steps_summary = "\n".join(
                f"Step {i+1} ({sr.step_name}): {sr.proof[:150]}"
                for i, sr in enumerate(step_results)
            )
            safe_ctx = {
                k: str(v)[:200] for k, v in context.items()
                if v and k not in ("admin_response", "raw_output")
            }
            prompt = _POC_PROMPT.format(
                chain_name=spec.name,
                chain_description=spec.steps[0].description if spec.steps else "",
                steps_summary=steps_summary,
                context_json=json.dumps(safe_ctx, indent=2)[:600],
                target_url=context.get("target_url", "https://target.com"),
            )
            ai_msg = await self.llm.call(
                messages=[{"role": "user", "content": prompt}]
            )
            content = ai_msg.content or ""
            # Extract code block if present
            import re
            match = re.search(r'```python\s*(.*?)```', content, re.DOTALL)
            if match:
                return match.group(1).strip()
            return content.strip()[:2000]
        except Exception as e:
            logger.debug(f"[ChainExecutor] PoC gen error: {e}")
            return f"# PoC generation failed: {e}\n# Chain: {spec.name}"

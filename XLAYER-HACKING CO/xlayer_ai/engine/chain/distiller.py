"""
engine/chain/distiller.py — Pattern Distiller

Learns from successful chain executions.

  Novel chain succeeded → distill → generalizable pattern → PatternStore
  Built-in chain succeeded → update stats only

Over time:
  Pattern library grows (more coverage)
  Success rates refine (better prioritization)
  LLM correlation needed less (known patterns cover more)
"""

import json
from typing import Optional

from loguru import logger

from xlayer_ai.engine.agentic_loop import _extract_json_block
from xlayer_ai.engine.llm import LLMClient
from .models import ChainPattern, ChainResult, ChainStep
from .pattern_store import PatternStore


_DISTILL_PROMPT = """\
A novel attack chain just succeeded in a penetration test.
Extract a GENERAL, REUSABLE pattern from this specific execution.

## Specific execution details
Chain name: {chain_name}
Target: {target_url}

Steps that succeeded:
{steps_detail}

Context values collected:
{context_json}

## Task
Create a generalized ChainPattern that would work on OTHER targets with similar characteristics.

Rules:
- Remove target-specific values (replace with generic placeholders / input_keys)
- Keep the logical structure and step order
- Define 'requires' as the MINIMUM conditions to attempt this chain
- Each step must have clear input_keys and output_keys
- Name should be descriptive and snake_case

Return JSON:
```json
{{
  "name": "descriptive_pattern_name",
  "description": "One line: what this chain does",
  "severity": "critical",
  "requires": ["token_1", "token_2"],
  "steps": [
    {{
      "name": "step_name",
      "description": "what this step does",
      "input_keys": ["context_key_needed"],
      "output_keys": ["context_key_produced"]
    }}
  ],
  "target_characteristics": {{
    "framework_hints": [],
    "auth_type": "",
    "notes": ""
  }}
}}
```
"""


class PatternDistiller:
    """
    Learns from successful chain executions.

    Built-in pattern succeeded → stats updated
    Novel (LLM-discovered) chain succeeded → new pattern saved to store
    """

    def __init__(self, llm: LLMClient, store: Optional[PatternStore] = None) -> None:
        self.llm   = llm
        self.store = store or PatternStore()

    async def distill(self, result: ChainResult) -> Optional[ChainPattern]:
        """
        Process a completed chain result.
        Returns new ChainPattern if a new pattern was learned, else None.
        """
        if not result.completed:
            # Failed execution — record failure stats only
            self.store.record_execution(
                pattern_name=result.spec.pattern_name or result.spec.name,
                success=False,
                duration_ms=result.duration_seconds * 1000,
                target_fingerprint=self._fingerprint(result),
            )
            return None

        pattern_name = result.spec.pattern_name or result.spec.name

        # Always record execution stats
        self.store.record_execution(
            pattern_name=pattern_name,
            success=True,
            duration_ms=result.duration_seconds * 1000,
            target_fingerprint=self._fingerprint(result),
        )

        # If this was a known (static/learned) pattern — stats update is enough
        if result.spec.source in ("static", "learned"):
            logger.debug(
                f"[Distiller] Known pattern '{pattern_name}' success recorded. "
                f"Rate: {self.store.get_success_rate(pattern_name):.0%}"
            )
            return None

        # Novel (LLM-discovered) chain → try to generalize it
        if self.store.pattern_exists(pattern_name):
            logger.debug(f"[Distiller] Pattern '{pattern_name}' already in store")
            return None

        return await self._generalize(result)

    # ── Generalization ────────────────────────────────────────────────────────

    async def _generalize(self, result: ChainResult) -> Optional[ChainPattern]:
        """Ask LLM to extract a general pattern from this specific success."""
        try:
            steps_detail = "\n".join(
                f"  {i+1}. {sr.step_name}: {sr.proof[:200]}"
                for i, sr in enumerate(result.step_results)
                if sr.success
            )
            safe_ctx = {
                k: str(v)[:150]
                for k, v in result.context.items()
                if v and k not in ("admin_response", "raw_output")
            }

            prompt = _DISTILL_PROMPT.format(
                chain_name=result.spec.name,
                target_url=result.context.get("target_url", ""),
                steps_detail=steps_detail,
                context_json=json.dumps(safe_ctx, indent=2)[:600],
            )

            ai_msg = await self.llm.call(
                messages=[{"role": "user", "content": prompt}]
            )
            data = _extract_json_block(ai_msg.content or "")
            if not data or not data.get("name"):
                logger.debug("[Distiller] LLM failed to produce pattern")
                return None

            steps = [
                ChainStep.from_dict(s)
                for s in data.get("steps", [])
            ]
            if not steps:
                return None

            new_pattern = ChainPattern(
                name=data["name"],
                description=data.get("description", ""),
                requires=set(data.get("requires", [])),
                steps=steps,
                severity=data.get("severity", "high"),
                source="learned",
                success_count=1,
                fail_count=0,
            )

            self.store.save_pattern(new_pattern)
            # Record the first success
            self.store.record_execution(
                pattern_name=new_pattern.name,
                success=True,
                duration_ms=result.duration_seconds * 1000,
                target_fingerprint=self._fingerprint(result),
            )

            logger.success(
                f"[Distiller] New pattern learned: '{new_pattern.name}' "
                f"(severity={new_pattern.severity})"
            )
            return new_pattern

        except Exception as e:
            logger.warning(f"[Distiller] Generalization error: {e}")
            return None

    def _fingerprint(self, result: ChainResult) -> dict:
        """Target characteristics — helps identify when this pattern applies."""
        ctx = result.context
        return {
            "target_url":    ctx.get("target_url", ""),
            "tech_stack":    ctx.get("tech_stack", []),
            "auth_type":     ctx.get("jwt_algo", ctx.get("auth_type", "")),
            "chain_name":    result.spec.name,
        }

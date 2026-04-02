"""
engine/chain/models.py — Attack Chain Data Structures
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


# ── Chain building blocks ─────────────────────────────────────────────────────

@dataclass
class ChainStep:
    """
    One step in an attack chain.

    input_keys:  keys the step reads from shared context
    output_keys: keys the step writes back to shared context
    """
    name: str                               # "crack_jwt", "forge_token", "access_admin"
    description: str                        # human-readable intent
    input_keys: List[str] = field(default_factory=list)
    output_keys: List[str] = field(default_factory=list)
    tool: Optional[str] = None             # hunter tool name (optional)
    jit_template: Optional[str] = None    # Python code template (optional)

    def to_dict(self) -> Dict:
        return {
            "name":         self.name,
            "description":  self.description,
            "input_keys":   self.input_keys,
            "output_keys":  self.output_keys,
            "tool":         self.tool,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "ChainStep":
        return cls(
            name=d.get("name", ""),
            description=d.get("description", ""),
            input_keys=d.get("input_keys", []),
            output_keys=d.get("output_keys", []),
            tool=d.get("tool"),
        )


# ── Pattern template ──────────────────────────────────────────────────────────

@dataclass
class ChainPattern:
    """
    Reusable attack chain template.
    Can be manually written or learned from a successful execution.
    """
    name: str
    description: str
    requires: set                          # finding types needed to attempt
    steps: List[ChainStep]
    severity: str = "high"                 # critical / high / medium
    source: str = "static"                 # static / learned
    success_count: int = 0
    fail_count: int = 0
    created_at: float = field(default_factory=time.time)

    @property
    def success_rate(self) -> float:
        total = self.success_count + self.fail_count
        return self.success_count / total if total > 0 else 0.5

    def to_dict(self) -> Dict:
        return {
            "name":          self.name,
            "description":   self.description,
            "requires":      list(self.requires),
            "steps":         [s.to_dict() for s in self.steps],
            "severity":      self.severity,
            "source":        self.source,
            "success_count": self.success_count,
            "fail_count":    self.fail_count,
            "created_at":    self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict) -> "ChainPattern":
        return cls(
            name=d.get("name", ""),
            description=d.get("description", ""),
            requires=set(d.get("requires", [])),
            steps=[ChainStep.from_dict(s) for s in d.get("steps", [])],
            severity=d.get("severity", "high"),
            source=d.get("source", "static"),
            success_count=d.get("success_count", 0),
            fail_count=d.get("fail_count", 0),
            created_at=d.get("created_at", time.time()),
        )


# ── Execution spec + result ───────────────────────────────────────────────────

@dataclass
class ChainSpec:
    """
    One chain scheduled for execution.
    Built by ChainPlanner from a ChainPattern + matching evidence.
    """
    name: str
    steps: List[ChainStep]
    severity: str
    confidence: float                      # plan-time confidence
    evidence: Dict[str, Any]              # findings that triggered this chain
    source: str = "static"                # static / learned / llm
    pattern_name: str = ""                # original pattern name (for stats)


@dataclass
class StepResult:
    """Result of executing a single ChainStep."""
    step_name: str
    success: bool
    outputs: Dict[str, Any] = field(default_factory=dict)
    proof: str = ""                        # response snippet / evidence
    error: str = ""
    duration_ms: float = 0.0


@dataclass
class ChainResult:
    """Full result of executing a ChainSpec."""
    spec: ChainSpec
    completed: bool
    step_results: List[StepResult] = field(default_factory=list)
    context: Dict[str, Any] = field(default_factory=dict)
    failed_at: Optional[str] = None
    poc_script: str = ""
    duration_seconds: float = 0.0

    @property
    def severity(self) -> str:
        return self.spec.severity

    @property
    def name(self) -> str:
        return self.spec.name

    def to_dict(self) -> Dict:
        return {
            "chain_name":       self.spec.name,
            "found":            self.completed,
            "severity":         self.severity,
            "confidence":       self.spec.confidence if self.completed else 0.0,
            "vuln_type":        f"chain:{self.spec.name}",
            "target_url":       self.context.get("target_url", ""),
            "parameter":        "",
            "working_payload":  self._working_payload(),
            "proof_response":   self._proof_summary(),
            "poc_script":       self.poc_script,
            "oob_confirmed":    False,
            "duration_seconds": round(self.duration_seconds, 2),
            "chain_steps":      [
                {
                    "step":    sr.step_name,
                    "success": sr.success,
                    "proof":   sr.proof[:200],
                }
                for sr in self.step_results
            ],
        }

    def _working_payload(self) -> str:
        for sr in reversed(self.step_results):
            if sr.success and sr.proof:
                return sr.proof[:300]
        return ""

    def _proof_summary(self) -> str:
        lines = []
        for sr in self.step_results:
            status = "✓" if sr.success else "✗"
            lines.append(f"{status} {sr.step_name}: {sr.proof[:150]}")
        return "\n".join(lines)

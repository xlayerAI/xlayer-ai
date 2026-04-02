"""
Attack Machine — Shared Execution Environment

Real-world offensive security toolkit providing agents access to
industry-standard and custom-built security tools, a steerable headless browser,
and collaboration services for safe exploit validation."

In XLayer, the Attack Machine is the bundle of:
  - base_tools: hunter tools (HTTP, browser, etc.)
  - jit_engine: JITEngine for agent-generated Python scripts
  - oob_server: OOBServer for out-of-band validation (SSRF, RCE, etc.)

Coordinator creates one AttackMachine per run; each Solver (Autonomous Agent)
receives tools + JIT + OOB from it. No LLM — pure execution environment.
"""

from dataclasses import dataclass, field
from typing import Any, List, Optional


@dataclass
class AttackMachine:
    """
    Attack Machine: shared execution environment for Solvers.

    Attributes:
        base_tools: List of Tool (e.g. ALL_HUNTER_TOOLS).
        jit_engine: JITEngine for run_jit_code.
        oob_server: Optional OOBServer for OOB callbacks.
    """

    base_tools: List[Any] = field(default_factory=list)
    jit_engine: Optional[Any] = None
    oob_server: Optional[Any] = None

    def get_tools(self, jit_tool: Optional[Any] = None) -> List[Any]:
        """Return base_tools + JIT tool (for Solver use)."""
        if jit_tool is not None:
            return list(self.base_tools) + [jit_tool]
        if self.jit_engine is not None:
            from xlayer_ai.src.agent.coordinator import make_jit_tool
            jit_tool = make_jit_tool(self.jit_engine)
            return list(self.base_tools) + [jit_tool]
        return list(self.base_tools)

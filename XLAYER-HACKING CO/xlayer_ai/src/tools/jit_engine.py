"""
JIT Execution Engine — runs agent-generated Python exploit scripts in a sandboxed subprocess.

The agent writes a Python script, we execute it with a timeout and resource limits,
and return stdout/stderr. This enables the agentic Solver to run novel attack patterns the agent discovers.

Safety: runs in subprocess (not exec()), 60s hard timeout.
Subprocess access allowed for multi-payload scripts.
"""

import asyncio
import sys
import tempfile
import os
import textwrap
from dataclasses import dataclass, field
from typing import Optional


# Imports the agent's script is always allowed to use
# socket: for outbound TCP only (e.g. port scan); socket.bind is blocked below
SAFE_PRELUDE = """\
import sys, os, re, json, base64, hashlib, urllib.parse, time, random, string
import asyncio
import socket
import subprocess
import httpx

# Convenience: pre-imported for exploit scripts
requests_like = httpx  # use httpx.get/post etc.
# socket: use socket.create_connection((host, port)) for port scan; do NOT use socket.bind
# subprocess: use subprocess.run() for curl, sqlmap, ffuf, etc.
"""

# Imports that signal dangerous operations — blocked before exec
BLOCKED_PATTERNS = [
    "import os.system",
    "__import__",
    "open('/etc/passwd'",
    "open('/etc/shadow'",
    "os.remove",
    "os.rmdir",
    "shutil.rmtree",
    "socket.bind",          # no local server binding
    # subprocess, 127.0.0.1, 0.0.0.0 — ALLOWED for multi-payload scripts
]


@dataclass
class JITResult:
    """Result from a JIT script execution."""
    success: bool
    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool = False
    blocked: bool = False
    block_reason: str = ""
    duration_ms: float = 0.0

    @property
    def output(self) -> str:
        """Combined stdout + stderr for LLM consumption."""
        parts = []
        if self.stdout.strip():
            parts.append(self.stdout.strip())
        if self.stderr.strip():
            parts.append(f"[stderr] {self.stderr.strip()}")
        if self.timed_out:
            parts.append("[TIMEOUT: script exceeded time limit]")
        if self.blocked:
            parts.append(f"[BLOCKED: {self.block_reason}]")
        return "\n".join(parts) or "(no output)"

    @property
    def short_summary(self) -> str:
        """One-line summary for logging."""
        if self.blocked:
            return f"BLOCKED({self.block_reason})"
        if self.timed_out:
            return "TIMEOUT"
        status = "OK" if self.success else f"EXIT({self.exit_code})"
        preview = self.stdout[:80].replace("\n", " ") if self.stdout else ""
        return f"{status} | {preview}"


class JITEngine:
    """
    Sandboxed JIT Python executor.

    Usage:
        engine = JITEngine(timeout=20)
        result = await engine.run(script_code, context={"target_url": "http://..."})
        print(result.output)
    """

    def __init__(self, timeout: int = 60, max_output_bytes: int = 64_000):
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def _check_blocked(self, code: str) -> Optional[str]:
        """Return block reason if code contains dangerous patterns."""
        for pattern in BLOCKED_PATTERNS:
            if pattern in code:
                return f"contains '{pattern}'"
        return None

    def _wrap_script(self, code: str, context: dict) -> str:
        """
        Wrap the agent's code with:
        - safe prelude imports
        - context variables injected as Python literals
        - async entry point if code uses 'await'
        """
        ctx_lines = []
        for k, v in context.items():
            # Only inject simple types
            if isinstance(v, (str, int, float, bool, list, dict)) or v is None:
                ctx_lines.append(f"{k} = {repr(v)}")

        ctx_block = "\n".join(ctx_lines)
        needs_async = "await " in code or "async def" in code

        if needs_async:
            # Wrap in async main() and run
            indented = textwrap.indent(code, "    ")
            return f"""{SAFE_PRELUDE}
{ctx_block}

async def main():
{indented}

asyncio.run(main())
"""
        else:
            return f"""{SAFE_PRELUDE}
{ctx_block}

{code}
"""

    async def run(self, code: str, context: Optional[dict] = None) -> JITResult:
        """
        Execute agent-generated Python code in a subprocess.

        Args:
            code: Python source code written by the agent
            context: Dict of variables to inject into the script namespace

        Returns:
            JITResult with stdout, stderr, exit code, timing
        """
        import time
        context = context or {}
        start = time.monotonic()

        # Security check
        block_reason = self._check_blocked(code)
        if block_reason:
            return JITResult(
                success=False, stdout="", stderr="",
                exit_code=-1, blocked=True, block_reason=block_reason
            )

        full_script = self._wrap_script(code, context)

        # Write to temp file
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False, encoding="utf-8"
        ) as f:
            f.write(full_script)
            script_path = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                sys.executable, script_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                # Limit environment (no inherited secrets)
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "HOME": os.environ.get("HOME", ""),
                    "PYTHONPATH": os.environ.get("PYTHONPATH", ""),
                }
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
                timed_out = False
            except asyncio.TimeoutError:
                proc.kill()
                stdout_bytes, stderr_bytes = b"", b"[killed: timeout]"
                timed_out = True

            stdout = stdout_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
            stderr = stderr_bytes[: self.max_output_bytes].decode("utf-8", errors="replace")
            exit_code = proc.returncode if not timed_out else -9

            duration_ms = (time.monotonic() - start) * 1000

            return JITResult(
                success=(exit_code == 0 and not timed_out),
                stdout=stdout,
                stderr=stderr,
                exit_code=exit_code or 0,
                timed_out=timed_out,
                duration_ms=duration_ms,
            )

        finally:
            try:
                os.unlink(script_path)
            except OSError:
                pass

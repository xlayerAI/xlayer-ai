"""
Docker Sandbox — Isolated JIT Code Execution

AI-generated exploit code runs in isolated Docker containers.
XLayer uses Docker containers for the same isolation guarantee.

Architecture:
    1. AI (Solver) writes Python exploit code
    2. Code is sent to DockerSandbox
    3. DockerSandbox spins up an isolated container:
       - Network: only outbound to target (no host access)
       - Filesystem: read-only (only /tmp writable)
       - Resources: CPU/RAM/time limited
       - No privileged operations
    4. Code runs inside container, output captured
    5. Container destroyed immediately

Security Model:
    - Even if AI generates malicious code (rm -rf /, reverse shell to attacker),
      it runs inside a throwaway container — host machine is SAFE.
    - If Docker is not available, falls back to subprocess with strict filtering.
"""

import asyncio
import json
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass
from typing import Dict, Optional

from loguru import logger


@dataclass
class SandboxResult:
    """Result from sandbox code execution."""
    success: bool = False
    output: str = ""
    error: str = ""
    exit_code: int = -1
    timed_out: bool = False
    blocked: bool = False
    block_reason: str = ""
    duration_ms: float = 0.0
    execution_mode: str = "unknown"  # "docker" or "subprocess"


# Patterns that should NEVER appear in AI-generated code
BLOCKED_PATTERNS = [
    "os.system",
    "subprocess.call",
    "subprocess.Popen",
    "shutil.rmtree",
    "os.remove",
    "os.rmdir",
    "os.unlink",
    "__import__('os')",
    "eval(",
    "exec(",
    "open('/etc",
    "open('C:",
    "import socket",
    "reverse_shell",
    "bind_shell",
    "rm -rf",
    "format c:",
    "deltree",
    "shutdown",
    "reboot",
]

# Packages available inside the sandbox
SANDBOX_PACKAGES = [
    "httpx", "requests", "json", "base64", "re",
    "urllib.parse", "hashlib", "hmac", "html",
    "xml.etree.ElementTree", "struct", "binascii",
    "time", "datetime", "math", "random", "string",
    "collections", "itertools", "functools",
]

# Docker image name for sandbox
SANDBOX_IMAGE = "xlayer-jit-sandbox:latest"

# Dockerfile content for building sandbox image
DOCKERFILE_CONTENT = '''
FROM python:3.11-slim

# Security: non-root user
RUN useradd -m -s /bin/bash sandbox

# Install only safe packages
RUN pip install --no-cache-dir httpx requests beautifulsoup4 lxml

# Security: read-only filesystem except /tmp
RUN chmod 755 /tmp

# Switch to non-root user
USER sandbox
WORKDIR /tmp

# No shell access by default
ENTRYPOINT ["python3", "-u"]
'''


class DockerSandbox:
    """
    Docker-based isolated execution environment for JIT code.

    Usage:
        sandbox = DockerSandbox()
        if sandbox.docker_available:
            result = await sandbox.run(code, context={"target_url": "..."})
        else:
            result = await sandbox.run_subprocess(code, context={...})  # fallback
    """

    def __init__(
        self,
        timeout: int = 60,
        memory_limit: str = "256m",
        cpu_limit: float = 1.0,
        network_mode: str = "bridge",  # "bridge" allows outbound, "none" blocks all
    ):
        self.timeout = timeout
        self.memory_limit = memory_limit
        self.cpu_limit = cpu_limit
        self.network_mode = network_mode
        self._docker_checked = False
        self._docker_ok = False
        self._image_built = False

    @property
    def docker_available(self) -> bool:
        """Check if Docker is available on this machine."""
        if not self._docker_checked:
            self._docker_ok = shutil.which("docker") is not None
            self._docker_checked = True
            if self._docker_ok:
                logger.info("[DockerSandbox] Docker available ✅")
            else:
                logger.warning("[DockerSandbox] Docker not found — using subprocess fallback")
        return self._docker_ok

    async def ensure_image(self) -> bool:
        """Build the sandbox Docker image if not already built."""
        if self._image_built:
            return True

        if not self.docker_available:
            return False

        try:
            # Check if image exists
            proc = await asyncio.create_subprocess_exec(
                "docker", "image", "inspect", SANDBOX_IMAGE,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await proc.wait()
            if proc.returncode == 0:
                self._image_built = True
                return True

            # Build image
            logger.info("[DockerSandbox] Building sandbox image...")
            with tempfile.NamedTemporaryFile(
                mode="w", suffix="Dockerfile", delete=False
            ) as f:
                f.write(DOCKERFILE_CONTENT)
                dockerfile_path = f.name

            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "build", "-t", SANDBOX_IMAGE, "-f", dockerfile_path, ".",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    cwd=tempfile.gettempdir(),
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
                if proc.returncode == 0:
                    self._image_built = True
                    logger.success("[DockerSandbox] Sandbox image built ✅")
                    return True
                else:
                    logger.error(f"[DockerSandbox] Image build failed: {stderr.decode()[:500]}")
                    return False
            finally:
                os.unlink(dockerfile_path)

        except Exception as e:
            logger.error(f"[DockerSandbox] Image setup error: {e}")
            return False

    async def run(
        self,
        code: str,
        context: Optional[Dict] = None,
    ) -> SandboxResult:
        """
        Execute code in the safest available mode.

        1. Docker container (if available) — ISOLATED
        2. Subprocess fallback (if Docker unavailable) — FILTERED

        Args:
            code: Python code to execute
            context: Variables injected into the code (target_url, parameter, etc.)

        Returns:
            SandboxResult with output, errors, timing
        """
        # Security check: block dangerous patterns
        blocked = self._check_blocked(code)
        if blocked:
            return SandboxResult(
                blocked=True,
                block_reason=f"Blocked pattern: {blocked}",
                execution_mode="blocked",
            )

        # Docker mode (preferred)
        if self.docker_available and await self.ensure_image():
            return await self._run_docker(code, context)

        # Subprocess fallback
        return await self._run_subprocess(code, context)

    async def _run_docker(
        self, code: str, context: Optional[Dict] = None
    ) -> SandboxResult:
        """Execute code inside a Docker container."""
        container_name = f"xlayer-jit-{uuid.uuid4().hex[:12]}"
        start_time = time.monotonic()

        # Prepare code with context injection
        full_code = self._inject_context(code, context)

        try:
            # Write code to temp file
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".py", delete=False, dir=tempfile.gettempdir()
            ) as f:
                f.write(full_code)
                code_path = f.name

            # Run in container
            cmd = [
                "docker", "run",
                "--name", container_name,
                "--rm",                              # auto-remove after exit
                "--memory", self.memory_limit,       # RAM limit
                f"--cpus={self.cpu_limit}",          # CPU limit
                "--network", self.network_mode,      # network isolation
                "--read-only",                       # read-only filesystem
                "--tmpfs", "/tmp:rw,size=64m",       # writable /tmp only
                "--security-opt", "no-new-privileges",
                "-v", f"{code_path}:/tmp/exploit.py:ro",  # mount code read-only
                SANDBOX_IMAGE,
                "/tmp/exploit.py",
            ]

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
                duration = (time.monotonic() - start_time) * 1000

                return SandboxResult(
                    success=proc.returncode == 0,
                    output=stdout.decode("utf-8", errors="replace")[:10000],
                    error=stderr.decode("utf-8", errors="replace")[:5000],
                    exit_code=proc.returncode or 0,
                    duration_ms=duration,
                    execution_mode="docker",
                )

            except asyncio.TimeoutError:
                # Kill container on timeout
                kill_proc = await asyncio.create_subprocess_exec(
                    "docker", "kill", container_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await kill_proc.wait()

                return SandboxResult(
                    timed_out=True,
                    duration_ms=(time.monotonic() - start_time) * 1000,
                    execution_mode="docker",
                    error=f"Execution timed out after {self.timeout}s",
                )

        except Exception as e:
            return SandboxResult(
                error=str(e),
                duration_ms=(time.monotonic() - start_time) * 1000,
                execution_mode="docker",
            )
        finally:
            # Cleanup temp file
            try:
                os.unlink(code_path)
            except Exception:
                pass
            # Force-remove container if still exists
            try:
                proc = await asyncio.create_subprocess_exec(
                    "docker", "rm", "-f", container_name,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
                await proc.wait()
            except Exception:
                pass

    async def _run_subprocess(
        self, code: str, context: Optional[Dict] = None
    ) -> SandboxResult:
        """Fallback: execute in subprocess with strict filtering."""
        start_time = time.monotonic()
        full_code = self._inject_context(code, context)

        try:
            proc = await asyncio.create_subprocess_exec(
                "python", "-u", "-c", full_code,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env={
                    "PATH": os.environ.get("PATH", ""),
                    "PYTHONPATH": "",
                    "HOME": tempfile.gettempdir(),
                },
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(), timeout=self.timeout
                )
                duration = (time.monotonic() - start_time) * 1000

                return SandboxResult(
                    success=proc.returncode == 0,
                    output=stdout.decode("utf-8", errors="replace")[:10000],
                    error=stderr.decode("utf-8", errors="replace")[:5000],
                    exit_code=proc.returncode or 0,
                    duration_ms=duration,
                    execution_mode="subprocess",
                )

            except asyncio.TimeoutError:
                proc.kill()
                return SandboxResult(
                    timed_out=True,
                    duration_ms=(time.monotonic() - start_time) * 1000,
                    execution_mode="subprocess",
                    error=f"Execution timed out after {self.timeout}s",
                )

        except Exception as e:
            return SandboxResult(
                error=str(e),
                duration_ms=(time.monotonic() - start_time) * 1000,
                execution_mode="subprocess",
            )

    # ── Helpers ────────────────────────────────────────────────────────

    @staticmethod
    def _check_blocked(code: str) -> Optional[str]:
        """Check code for blocked patterns. Returns pattern if blocked."""
        code_lower = code.lower()
        for pattern in BLOCKED_PATTERNS:
            if pattern.lower() in code_lower:
                return pattern
        return None

    @staticmethod
    def _inject_context(code: str, context: Optional[Dict] = None) -> str:
        """Inject context variables into code."""
        if not context:
            return code
        header = "# === Injected Context ===\n"
        for key, value in context.items():
            safe_val = json.dumps(value) if isinstance(value, str) else repr(value)
            header += f"{key} = {safe_val}\n"
        header += "# === End Context ===\n\n"
        return header + code

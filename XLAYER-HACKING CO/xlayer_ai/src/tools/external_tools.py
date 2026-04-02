"""
External / binary tools — run allowlisted hacking tools (nmap, etc.) from the agent.

These run in the MAIN process via subprocess (not inside JIT sandbox).
Only allowlisted binaries and fixed argument shapes are allowed; no arbitrary shell.

- nmap: port scan, service detection
- (Future: nikto, ffuf, Burp API, etc.)
"""

import re
import shutil
import subprocess
import json
from typing import Optional, List, Any

from xlayer_ai.engine.tool import tool
from loguru import logger


# ── Allowlist: only these binaries can be run ─────────────────────────────

ALLOWED_BINARIES = {
    "nmap",
}

DEFAULT_TIMEOUT = 120


def _find_binary(name: str) -> Optional[str]:
    if name not in ALLOWED_BINARIES:
        return None
    return shutil.which(name)


def _validate_host(host: str) -> bool:
    if not host or len(host) > 253:
        return False
    if re.match(r"^[\w.\-]+$", host):
        return True
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", host):
        return True
    return False


def _validate_ports(ports: str) -> bool:
    if not ports or len(ports) > 200:
        return False
    return bool(re.match(r"^[\d\-\s,]+$", ports))


@tool
def run_nmap(
    target_host: str,
    ports: str = "80,443,8080",
    scan_type: str = "connect",
    timeout_seconds: int = 60,
) -> str:
    """
    Run nmap port scan on a target host (allowlisted binary).
    Use for recon: discover open ports and services.

    Args:
        target_host: Hostname or IP to scan
        ports: Ports to scan: comma list (80,443) or range (1-1000). Default 80,443,8080
        scan_type: connect (TCP connect) or syn (requires root). Default connect
        timeout_seconds: Max run time in seconds. Default 60
    """
    if not _validate_host(target_host):
        return json.dumps({"error": "Invalid target_host", "allowed": "hostname or IPv4"})
    if not _validate_ports(ports):
        return json.dumps({"error": "Invalid ports", "allowed": "e.g. 80,443 or 1-1000"})

    nmap_path = _find_binary("nmap")
    if not nmap_path:
        return json.dumps({
            "error": "nmap not available",
            "hint": "Install nmap and ensure it is in PATH, or use JIT port-scan script (pure Python)",
        })

    args = [nmap_path, "-p", ports.replace(" ", "")]
    if scan_type == "syn":
        args.extend(["-sS", "-T4"])
    else:
        args.extend(["-sT", "-T4"])
    args.append(target_host)

    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=min(timeout_seconds, DEFAULT_TIMEOUT),
        )
        out = (result.stdout or "") + (result.stderr or "")
        return json.dumps({
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout or "",
            "stderr": result.stderr or "",
            "output_preview": out[:4000],
        }, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "nmap timed out", "timeout_seconds": timeout_seconds})
    except FileNotFoundError:
        return json.dumps({"error": "nmap binary not found"})
    except Exception as e:
        logger.exception("nmap run failed")
        return json.dumps({"error": str(e)})


@tool
def run_allowlisted_tool(
    tool_name: str,
    args_json: str,
    timeout_seconds: int = 60,
) -> str:
    """
    Run an allowlisted external tool by name with fixed arguments (JSON).
    Only binaries in the allowlist can be run; args are passed as list, no shell.

    Args:
        tool_name: One of: nmap (for now only nmap is allowlisted)
        args_json: JSON array of string arguments, e.g. ["-p", "80,443", "example.com"]
        timeout_seconds: Max run time. Default 60
    """
    bin_path = _find_binary(tool_name)
    if not bin_path:
        return json.dumps({
            "error": f"Tool '{tool_name}' not allowlisted or not in PATH",
            "allowlisted": list(ALLOWED_BINARIES),
        })

    try:
        args_list = json.loads(args_json)
        if not isinstance(args_list, list) or not all(isinstance(a, str) for a in args_list):
            return json.dumps({"error": "args_json must be a JSON array of strings"})
        if len(args_list) > 50:
            return json.dumps({"error": "Too many arguments"})
    except json.JSONDecodeError as e:
        return json.dumps({"error": f"Invalid args_json: {e}"})

    full_args = [bin_path] + args_list
    try:
        result = subprocess.run(
            full_args,
            capture_output=True,
            text=True,
            timeout=min(timeout_seconds, DEFAULT_TIMEOUT),
        )
        return json.dumps({
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": (result.stdout or "")[:8000],
            "stderr": (result.stderr or "")[:2000],
        }, indent=2)
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "Tool timed out", "timeout_seconds": timeout_seconds})
    except Exception as e:
        return json.dumps({"error": str(e)})


EXTERNAL_TOOLS: List[Any] = [
    run_nmap,
    run_allowlisted_tool,
]

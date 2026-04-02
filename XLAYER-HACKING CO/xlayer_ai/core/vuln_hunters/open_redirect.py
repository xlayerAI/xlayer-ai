"""
XLayer AI Open Redirect Hunter
Detects unvalidated redirects that can be abused for phishing and OAuth token theft.
Tests common bypass techniques: protocol-relative, Unicode, encoded characters, @ trick.
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


# External domain to redirect to (benign probe)
PROBE_DOMAIN = "xlayer-redirect-test.example.com"
PROBE_URL = f"https://{PROBE_DOMAIN}"

REDIRECT_PAYLOADS = [
    # Direct
    PROBE_URL,
    f"http://{PROBE_DOMAIN}",
    # Protocol-relative
    f"//{PROBE_DOMAIN}",
    f"\/\/{PROBE_DOMAIN}",
    # @ trick (browser goes to domain after @)
    f"https://target.com@{PROBE_DOMAIN}",
    f"@{PROBE_DOMAIN}",
    # Encoded
    f"https://{PROBE_DOMAIN}%09",             # tab
    f"https://{PROBE_DOMAIN}%0a",             # newline
    f"https://{PROBE_DOMAIN}%23",             # fragment #
    f"https://{PROBE_DOMAIN}%3f",             # ?
    f"https://{PROBE_DOMAIN}%2f%2f",          # //
    # Backslash (IIS)
    f"https:\\\\{PROBE_DOMAIN}",
    f"\\\\{PROBE_DOMAIN}",
    # Unicode
    f"https://{PROBE_DOMAIN}\u2044",           # fraction slash
    # Double encoding
    f"https://{PROBE_DOMAIN}%252f",
    # Whitespace prefix
    f" https://{PROBE_DOMAIN}",
    f"\thttps://{PROBE_DOMAIN}",
    # Relative with traversal
    f"////{PROBE_DOMAIN}",
    f"/%09/{PROBE_DOMAIN}",
    # Data URI (for XSS via redirect)
    "data:text/html,<script>alert(1)</script>",
    # JavaScript URI
    "javascript:alert(1)",
]

# Parameters commonly used for redirects
REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri", "return",
    "return_url", "returnurl", "next", "next_url", "goto", "destination",
    "dest", "target", "rurl", "ref", "referer", "referrer", "forward",
    "location", "continue", "back", "link", "page", "path", "callback",
    "oauth_callback", "success_url", "cancel_url", "from", "to",
    "out", "view", "window", "resume", "service", "q",
]


class OpenRedirectHunter(BaseHunter):
    """
    Open Redirect Hunter.

    Detection strategy:
    1. Identify redirect parameters by name heuristic
    2. Inject attacker domain as redirect target
    3. Detect: Location header → probe domain, or 3xx response with probe in header
    4. Test bypass techniques if direct is blocked
    """

    name = "open_redirect"
    vuln_types = [VulnType.OPEN_REDIRECT]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"Open Redirect Hunter starting")

        for endpoint in attack_surface.testable_endpoints:
            for param in endpoint.parameters:
                if self._is_redirect_param(param.name):
                    await self._test_redirect(endpoint, param.name, attack_surface)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"Open Redirect Hunter complete: {result.findings_count} hypotheses")
        return result

    def _is_redirect_param(self, param_name: str) -> bool:
        return param_name.lower() in REDIRECT_PARAMS

    async def _test_redirect(
        self, endpoint: Endpoint, parameter: str, attack_surface: AttackSurface
    ):
        self._endpoints_tested += 1

        ctx = self._build_attack_context(endpoint, parameter, "open_redirect", attack_surface)

        def redirect_success(send_result, attack_ctx):
            # Location header redirect to probe domain
            location = send_result.headers.get("location", send_result.headers.get("Location", ""))
            if PROBE_DOMAIN in location:
                return True
            body = send_result.body
            # Meta-refresh
            if re.search(
                rf'<meta[^>]+refresh[^>]+url=["\']?{re.escape(PROBE_DOMAIN)}',
                body, re.IGNORECASE
            ):
                return True
            # JavaScript redirect
            if PROBE_DOMAIN in body and re.search(
                r"(window\.location|document\.location|location\.href)", body
            ):
                return True
            return False

        attempts = await self._adaptive_test(
            endpoint, parameter, list(REDIRECT_PAYLOADS), ctx, redirect_success,
        )

        for attempt in attempts:
            if not attempt.success:
                continue

            # Re-derive redirect location from response body (stored in response_body)
            location = ""
            body = attempt.response_body

            # Determine redirect type from evidence
            if re.search(
                rf'<meta[^>]+refresh[^>]+url=["\']?{re.escape(PROBE_DOMAIN)}',
                body, re.IGNORECASE
            ):
                indicator_type = "meta_refresh"
                detail = "Meta-refresh redirect to attacker domain"
                confidence = Confidence.MEDIUM
                boost = 0.25
            elif PROBE_DOMAIN in body and re.search(
                r"(window\.location|document\.location|location\.href)", body
            ):
                indicator_type = "js_redirect"
                detail = "JavaScript redirect to attacker domain in response"
                confidence = Confidence.MEDIUM
                boost = 0.2
            else:
                indicator_type = "location_header"
                detail = f"Redirect to attacker domain: payload='{attempt.payload[:60]}'"
                confidence = Confidence.HIGH
                boost = 0.4

            h = self._create_hypothesis(
                vuln_type=VulnType.OPEN_REDIRECT,
                endpoint=endpoint,
                parameter=parameter,
                confidence=confidence,
                indicators=[
                    VulnIndicator(
                        indicator_type=indicator_type,
                        detail=detail,
                        confidence_boost=boost,
                    ),
                ],
                suggested_payloads=[
                    attempt.payload,
                    f"//{PROBE_DOMAIN}",
                    f"https://{PROBE_DOMAIN}",
                ],
                context={
                    "injection_type": indicator_type,
                    "trigger_payload": attempt.payload,
                    "waf_bypassed": ctx.waf,
                    "status_code": attempt.status_code,
                },
            )
            self._hypotheses.append(h)
            return

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None

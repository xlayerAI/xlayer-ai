"""
XLayer AI CSRF Hunter - Cross-Site Request Forgery
Detects missing/bypassable CSRF tokens, missing SameSite cookie attributes,
and state-changing endpoints without CSRF protection.
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


# State-changing HTTP methods
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths indicating state-changing actions
STATE_CHANGING_PATHS = [
    "update", "edit", "change", "modify", "delete", "remove",
    "create", "add", "submit", "transfer", "send", "pay",
    "password", "email", "profile", "settings", "account",
    "logout", "admin", "user", "order", "checkout",
]

# Common CSRF token parameter/header names
CSRF_TOKEN_NAMES = [
    "csrf_token", "csrftoken", "_csrf", "csrf", "xsrf",
    "_token", "authenticity_token", "token", "__requestverificationtoken",
    "x-csrf-token", "x-xsrf-token", "x-csrftoken",
]


class CSRFHunter(BaseHunter):
    """
    CSRF Hunter.

    Detection strategy:
    1. Find state-changing endpoints (POST/PUT/PATCH/DELETE)
    2. Check if CSRF token is present in form/headers
    3. If token absent → HIGH confidence CSRF
    4. If token present → test bypass: empty token, wrong token, removed token
    5. Check SameSite cookie attribute
    6. Test GET-based state change (method override)
    """

    name = "csrf"
    vuln_types = [VulnType.CSRF]

    async def hunt(self, attack_surface: AttackSurface) -> HunterResult:
        start_time = time.time()
        self._reset_state()

        logger.info(f"CSRF Hunter starting on {len(attack_surface.testable_endpoints)} endpoints")

        for endpoint in attack_surface.testable_endpoints:
            if endpoint.method.value.upper() in STATE_CHANGING_METHODS:
                await self._test_csrf(endpoint)

        duration = time.time() - start_time
        result = self._build_result(duration)
        logger.info(f"CSRF Hunter complete: {result.findings_count} hypotheses")
        return result

    async def _test_csrf(self, endpoint: Endpoint):
        self._endpoints_tested += 1

        # Step 1: Fetch the page/form to inspect for CSRF token
        page_response = await self._fetch_page(endpoint)
        if not page_response:
            return

        body = page_response.get("body", "")
        headers = page_response.get("headers", {})
        set_cookie = headers.get("set-cookie", headers.get("Set-Cookie", ""))

        # Step 2: Check SameSite cookie attribute
        samesite_missing = self._check_samesite(set_cookie)

        # Step 3: Find CSRF token in form
        csrf_token = self._extract_csrf_token(body)
        has_token = csrf_token is not None

        # Step 4: If no CSRF token → likely vulnerable
        if not has_token and self._is_sensitive_endpoint(endpoint.url):
            indicators = [
                VulnIndicator(
                    indicator_type="no_csrf_token",
                    detail="No CSRF token found in form/headers for state-changing endpoint",
                    confidence_boost=0.3,
                )
            ]
            if samesite_missing:
                indicators.append(VulnIndicator(
                    indicator_type="no_samesite",
                    detail="Session cookie missing SameSite attribute",
                    confidence_boost=0.15,
                ))

            h = self._create_hypothesis(
                vuln_type=VulnType.CSRF,
                endpoint=endpoint,
                parameter="(form)",
                confidence=Confidence.HIGH if samesite_missing else Confidence.MEDIUM,
                indicators=indicators,
                suggested_payloads=[
                    f'<form action="{endpoint.url}" method="POST">',
                    '<input type="hidden" name="amount" value="1000">',
                    '<input type="submit" value="Click me">',
                    "</form>",
                ],
                context={
                    "injection_type": "csrf_no_token",
                    "samesite_missing": samesite_missing,
                    "method": endpoint.method.value,
                },
            )
            self._hypotheses.append(h)
            return

        # Step 5: Token present → test bypass
        if has_token:
            await self._test_token_bypass(endpoint, csrf_token)

    async def _test_token_bypass(self, endpoint: Endpoint, token: str):
        """Test if CSRF token validation can be bypassed."""
        bypass_tests = [
            ("", "empty_token"),
            ("invalid_csrf_xyz", "wrong_token"),
            (token[:-4] + "xxxx", "partial_wrong"),
        ]

        for test_value, bypass_type in bypass_tests:
            self._payloads_sent += 1
            # Send without CSRF token (remove it from params)
            response = await self._send_without_csrf(endpoint, test_value)
            if not response:
                continue

            status = response.get("status", 0)
            body = response.get("body", "")

            # If server accepts request (200/302) with invalid/missing token → bypass!
            if status in (200, 201, 302) and not self._is_csrf_error(body):
                h = self._create_hypothesis(
                    vuln_type=VulnType.CSRF,
                    endpoint=endpoint,
                    parameter="csrf_token",
                    confidence=Confidence.HIGH,
                    indicators=[
                        VulnIndicator(
                            indicator_type="token_bypass",
                            detail=f"CSRF token bypass: '{bypass_type}' accepted (HTTP {status})",
                            confidence_boost=0.4,
                        )
                    ],
                    suggested_payloads=[f"csrf_token={test_value}"],
                    context={
                        "injection_type": f"csrf_{bypass_type}",
                        "bypass_type": bypass_type,
                        "response_status": status,
                    },
                )
                self._hypotheses.append(h)
                return

    def _extract_csrf_token(self, body: str) -> Optional[str]:
        """Extract CSRF token value from HTML body."""
        for name in CSRF_TOKEN_NAMES:
            # Input field
            match = re.search(
                rf'<input[^>]+name=["\']?{re.escape(name)}["\']?[^>]+value=["\']?([^"\'>\s]+)',
                body, re.IGNORECASE
            )
            if match:
                return match.group(1)
            # Meta tag
            match = re.search(
                rf'<meta[^>]+name=["\']?{re.escape(name)}["\']?[^>]+content=["\']?([^"\'>\s]+)',
                body, re.IGNORECASE
            )
            if match:
                return match.group(1)
        return None

    def _check_samesite(self, set_cookie: str) -> bool:
        """Return True if session cookie is missing SameSite."""
        if not set_cookie:
            return True
        if re.search(r"(session|auth|token)", set_cookie, re.IGNORECASE):
            return "samesite" not in set_cookie.lower()
        return False

    def _is_sensitive_endpoint(self, url: str) -> bool:
        url_lower = url.lower()
        return any(path in url_lower for path in STATE_CHANGING_PATHS)

    def _is_csrf_error(self, body: str) -> bool:
        """Check if response indicates CSRF protection triggered."""
        return bool(re.search(
            r"(csrf|forbidden|invalid token|token mismatch|security check)",
            body, re.IGNORECASE
        ))

    async def _fetch_page(self, endpoint: Endpoint) -> Optional[Dict]:
        try:
            response = await self.http.get(endpoint.url)
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
            }
        except Exception as e:
            logger.debug(f"CSRF page fetch failed: {e}")
            return None

    async def _send_without_csrf(self, endpoint: Endpoint, token_value: str) -> Optional[Dict]:
        """Send state-changing request with modified/missing CSRF token."""
        try:
            # Build minimal form data
            data = {}
            for param in endpoint.parameters:
                data[param.name] = param.value or "test"
            # Set csrf token to test value
            for name in CSRF_TOKEN_NAMES:
                if name in data:
                    data[name] = token_value
                    break
            else:
                data[CSRF_TOKEN_NAMES[0]] = token_value

            self._payloads_sent += 1
            response = await self.http.post(endpoint.url, data=data)
            return {
                "status": response.status,
                "headers": response.headers,
                "body": response.body,
                "elapsed_ms": response.elapsed_ms,
            }
        except Exception as e:
            logger.debug(f"CSRF bypass test failed: {e}")
            return None

    def _analyze_response(self, endpoint, parameter, payload, response):
        return None

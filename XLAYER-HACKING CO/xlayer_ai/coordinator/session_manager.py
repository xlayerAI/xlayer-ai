"""
Session Manager — Shared Auth Persistence

Manages authentication state across all Solver agents:
  - Shared Cookie Jar across all HTTP requests
  - Auto-detect session expiry (401/403 → re-auth)
  - Browser-based login flow → cookie harvest → inject into HTTP client
  - Logout detection: tracks which payload killed the session

Architecture:
  Coordinator owns one SessionManager.
  All Solvers share it via the Attack Machine.
  When a 401/403 is detected, SessionManager re-authenticates automatically.
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from loguru import logger


@dataclass
class SessionState:
    """Current session state."""
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    bearer_token: Optional[str] = None
    last_auth_time: float = 0.0
    auth_failures: int = 0
    is_valid: bool = False
    logout_payloads: Set[str] = field(default_factory=set)  # payloads that killed session


@dataclass
class AuthConfig:
    """Authentication configuration."""
    # Form-based login
    login_url: Optional[str] = None
    username: Optional[str] = None
    password: Optional[str] = None
    username_field: str = "username"
    password_field: str = "password"
    success_indicator: Optional[str] = None  # URL pattern or body text after success

    # Token-based
    bearer_token: Optional[str] = None
    api_key: Optional[str] = None
    api_key_header: str = "X-API-Key"

    # Raw cookie
    session_cookie: Optional[str] = None


class SessionManager:
    """
    Shared Session Manager for all Solver agents.

    Features:
      1. Shared Cookie Jar — all solvers use the same session
      2. Auto Re-auth — detects 401/403 and re-authenticates
      3. Logout Detection — tracks which payloads destroy the session
      4. Browser Login — uses headless browser for complex login flows
    """

    MAX_AUTH_RETRIES = 3
    SESSION_CHECK_INTERVAL = 60  # seconds between session validity checks
    AUTH_COOLDOWN = 10  # seconds between re-auth attempts

    def __init__(self, auth_config: Optional[AuthConfig] = None):
        self._config = auth_config
        self._state = SessionState()
        self._lock = asyncio.Lock()
        self._auth_in_progress = False

    @classmethod
    def from_settings(cls, settings=None) -> "SessionManager":
        """Create SessionManager from application settings."""
        if settings is None:
            return cls()
        auth = getattr(settings, "auth", None)
        if not auth or not auth.enabled:
            return cls()
        config = AuthConfig(
            login_url=auth.login_url,
            username=auth.username,
            password=auth.password,
            username_field=getattr(auth, "username_field", "username"),
            password_field=getattr(auth, "password_field", "password"),
            bearer_token=auth.bearer_token,
            api_key=auth.api_key,
            api_key_header=getattr(auth, "api_key_header", "X-API-Key"),
            session_cookie=auth.session_cookie,
        )
        return cls(auth_config=config)

    @property
    def is_configured(self) -> bool:
        """Check if any auth is configured."""
        if not self._config:
            return False
        return bool(
            self._config.login_url
            or self._config.bearer_token
            or self._config.api_key
            or self._config.session_cookie
        )

    # ── Public API for Solvers ───────────────────────────────────────────

    def get_auth_headers(self) -> Dict[str, str]:
        """Get current auth headers for HTTP requests."""
        headers = dict(self._state.headers)
        if self._state.bearer_token:
            headers["Authorization"] = f"Bearer {self._state.bearer_token}"
        if self._config and self._config.api_key:
            headers[self._config.api_key_header] = self._config.api_key
        return headers

    def get_cookies(self) -> Dict[str, str]:
        """Get current session cookies."""
        return dict(self._state.cookies)

    async def ensure_session(self) -> bool:
        """Ensure we have a valid session. Re-auth if needed."""
        if not self.is_configured:
            return True  # No auth required

        if self._state.is_valid:
            return True

        return await self._authenticate()

    async def handle_auth_failure(self, status_code: int, payload: str = "") -> bool:
        """
        Handle 401/403 response from target.

        Args:
            status_code: HTTP status code
            payload: The payload that caused the response

        Returns:
            True if re-auth succeeded, False otherwise
        """
        if status_code not in (401, 403):
            return True

        # Track which payload might have killed the session
        if payload:
            self._state.logout_payloads.add(payload[:200])

        logger.warning(f"[SessionManager] Auth failure (HTTP {status_code}), attempting re-auth")
        self._state.is_valid = False

        return await self._authenticate()

    def is_logout_payload(self, payload: str) -> bool:
        """Check if a payload previously caused session logout."""
        return payload[:200] in self._state.logout_payloads

    # ── Authentication Methods ───────────────────────────────────────────

    async def _authenticate(self) -> bool:
        """Perform authentication (thread-safe)."""
        async with self._lock:
            # Double-check after acquiring lock
            if self._state.is_valid:
                return True

            if self._auth_in_progress:
                return False

            # Cooldown check
            elapsed = time.monotonic() - self._state.last_auth_time
            if elapsed < self.AUTH_COOLDOWN:
                return False

            if self._state.auth_failures >= self.MAX_AUTH_RETRIES:
                logger.error("[SessionManager] Max auth retries exceeded")
                return False

            self._auth_in_progress = True
            try:
                success = False

                # Method 1: Static token/cookie (fastest)
                if self._config.bearer_token:
                    self._state.bearer_token = self._config.bearer_token
                    self._state.is_valid = True
                    success = True
                    logger.info("[SessionManager] Auth via bearer token")

                elif self._config.session_cookie:
                    self._parse_cookie_string(self._config.session_cookie)
                    self._state.is_valid = True
                    success = True
                    logger.info("[SessionManager] Auth via session cookie")

                # Method 2: Form-based login (HTTP)
                elif self._config.login_url and self._config.username:
                    success = await self._form_login()

                # Method 3: Browser-based login (complex flows)
                if not success and self._config.login_url:
                    success = await self._browser_login()

                self._state.last_auth_time = time.monotonic()
                if not success:
                    self._state.auth_failures += 1
                else:
                    self._state.auth_failures = 0

                return success

            finally:
                self._auth_in_progress = False

    async def _form_login(self) -> bool:
        """Perform form-based HTTP login."""
        try:
            import httpx
            login_data = {
                self._config.username_field: self._config.username,
                self._config.password_field: self._config.password,
            }

            async with httpx.AsyncClient(
                follow_redirects=True, timeout=20, verify=False
            ) as client:
                resp = await client.post(self._config.login_url, data=login_data)

                if resp.status_code < 400:
                    # Harvest cookies
                    for name, value in resp.cookies.items():
                        self._state.cookies[name] = value

                    # Check for auth cookies
                    session_indicators = ("session", "token", "auth", "jwt", "sid", "phpsessid")
                    has_session = any(
                        any(ind in name.lower() for ind in session_indicators)
                        for name in self._state.cookies.keys()
                    )

                    if has_session:
                        self._state.is_valid = True
                        logger.success(f"[SessionManager] Form login success: {len(self._state.cookies)} cookies")
                        return True

                logger.warning(f"[SessionManager] Form login failed: HTTP {resp.status_code}")
                return False

        except Exception as e:
            logger.error(f"[SessionManager] Form login error: {e}")
            return False

    async def _browser_login(self) -> bool:
        """Perform browser-based login (for complex JS flows)."""
        try:
            from xlayer_ai.tools.browser import HeadlessBrowser

            async with HeadlessBrowser() as browser:
                page = await browser.new_page()
                await page.goto(self._config.login_url)

                # Fill login form
                if self._config.username:
                    await page.fill(
                        f'input[name="{self._config.username_field}"]',
                        self._config.username
                    )
                if self._config.password:
                    await page.fill(
                        f'input[name="{self._config.password_field}"]',
                        self._config.password
                    )

                # Submit
                await page.click('button[type="submit"], input[type="submit"]')
                await page.wait_for_load_state("networkidle")

                # Harvest cookies from browser context
                cookies = await page.context.cookies()
                for cookie in cookies:
                    self._state.cookies[cookie["name"]] = cookie["value"]

                if self._state.cookies:
                    self._state.is_valid = True
                    logger.success(
                        f"[SessionManager] Browser login success: "
                        f"{len(cookies)} cookies harvested"
                    )
                    return True

                return False

        except Exception as e:
            logger.debug(f"[SessionManager] Browser login failed: {e}")
            return False

    def _parse_cookie_string(self, cookie_str: str):
        """Parse cookie string like 'name=value; name2=value2'."""
        for part in cookie_str.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                self._state.cookies[name.strip()] = value.strip()

"""
XLayer AI - OpenAI OAuth PKCE Provider

Connects to OpenAI using browser-based OAuth (no API key needed).
Compatible with ChatGPT Max / Codex subscription plans.

Flow:
  1. Generate PKCE code_verifier + code_challenge
  2. Open browser → user logs in to OpenAI (Google/Apple/email)
  3. Local HTTP server captures the OAuth callback code
  4. Exchange code + verifier for access_token + refresh_token
  5. Tokens saved at ~/.xlayer/auth/openai_token.json
  6. Auto-refresh when expired

Requirements:
  - XLAYER_LLM__OPENAI_CLIENT_ID in .env  (OAuth app client ID)
  - ChatGPT Max or Codex subscription plan

Setup:
  python -m xlayer_ai auth login openai
  → browser opens → sign in with your OpenAI account
"""

import asyncio
import base64
import hashlib
import json
import os
import secrets
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from threading import Thread
from typing import Dict, Optional
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from loguru import logger


# ─── OAuth Endpoints ──────────────────────────────────────────────────────────
OPENAI_AUTHORIZE_URL = "https://auth.openai.com/authorize"
OPENAI_TOKEN_URL     = "https://auth.openai.com/oauth/token"
OPENAI_REDIRECT_URI  = "http://localhost:21337/callback"
OPENAI_SCOPES        = "openid email profile"

# Token storage
TOKEN_PATH = Path.home() / ".xlayer" / "auth" / "openai_token.json"


# ─── Callback Handler ─────────────────────────────────────────────────────────

class _CallbackHandler(BaseHTTPRequestHandler):
    """Local HTTP handler that captures the OAuth redirect code."""

    auth_code: Optional[str] = None
    error: Optional[str] = None

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        _CallbackHandler.auth_code = params.get("code", [None])[0]
        _CallbackHandler.error     = params.get("error", [None])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

        if _CallbackHandler.auth_code:
            body = (
                "<h2 style='font-family:sans-serif;color:#22c55e'>XLayer AI</h2>"
                "<p>Authentication successful. You can close this tab.</p>"
            )
        else:
            body = (
                f"<h2 style='font-family:sans-serif;color:#ef4444'>Auth failed</h2>"
                f"<p>{_CallbackHandler.error}</p>"
            )
        self.wfile.write(body.encode())

    def log_message(self, *_):
        pass  # suppress access log noise


# ─── PKCE Helpers ─────────────────────────────────────────────────────────────

def _generate_pkce() -> tuple[str, str]:
    verifier  = secrets.token_urlsafe(43)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge


def _build_auth_url(client_id: str, challenge: str) -> str:
    params = {
        "response_type":         "code",
        "client_id":             client_id,
        "redirect_uri":          OPENAI_REDIRECT_URI,
        "scope":                 OPENAI_SCOPES,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    return f"{OPENAI_AUTHORIZE_URL}?{urlencode(params)}"


# ─── Token I/O ────────────────────────────────────────────────────────────────

def _save(tokens: Dict) -> None:
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(json.dumps(tokens, indent=2))
    logger.debug(f"OpenAI tokens saved → {TOKEN_PATH}")


def _load() -> Optional[Dict]:
    if TOKEN_PATH.exists():
        try:
            return json.loads(TOKEN_PATH.read_text())
        except Exception:
            return None
    return None


# ─── Token Exchange / Refresh ─────────────────────────────────────────────────

async def _exchange_code(client_id: str, code: str, verifier: str) -> Dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            OPENAI_TOKEN_URL,
            data={
                "grant_type":    "authorization_code",
                "client_id":     client_id,
                "code":          code,
                "redirect_uri":  OPENAI_REDIRECT_URI,
                "code_verifier": verifier,
            },
        )
        r.raise_for_status()
        data = r.json()
        data["expires_at"] = time.time() + data.get("expires_in", 3600)
        return data


async def _do_refresh(client_id: str, refresh_token: str) -> Dict:
    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(
            OPENAI_TOKEN_URL,
            data={
                "grant_type":    "refresh_token",
                "client_id":     client_id,
                "refresh_token": refresh_token,
            },
        )
        r.raise_for_status()
        data = r.json()
        data["expires_at"] = time.time() + data.get("expires_in", 3600)
        return data


# ─── Main Provider ────────────────────────────────────────────────────────────

class OpenAIOAuthProvider:
    """
    OpenAI provider using PKCE OAuth browser login.

    Usage:
      provider = OpenAIOAuthProvider(client_id="...", model="gpt-4o-mini")
      await provider.initialize()   # opens browser on first run
      text = await provider.complete("your prompt", "system prompt")
    """

    def __init__(
        self,
        model:       str = "gpt-4o-mini",
        temperature: float = 0.1,
        max_tokens:  int = 4096,
        client_id:   Optional[str] = None,
    ):
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.client_id   = (
            client_id
            or os.getenv("XLAYER_LLM__OPENAI_CLIENT_ID", "")
            or os.getenv("OPENAI_CLIENT_ID", "")
        )
        self._tokens: Optional[Dict] = None
        self._http:   Optional[httpx.AsyncClient] = None

    async def initialize(self) -> bool:
        if not self.client_id:
            logger.warning(
                "OpenAI OAuth: client_id not configured.\n"
                "  Add XLAYER_LLM__OPENAI_CLIENT_ID=<client_id> to .env\n"
                "  OR use XLAYER_LLM__PROVIDER=openai with XLAYER_LLM__API_KEY"
            )
            return False

        # Try loading existing tokens
        tokens = _load()
        if tokens:
            # Valid → use directly
            if time.time() < tokens.get("expires_at", 0) - 60:
                self._tokens = tokens
                self._http   = httpx.AsyncClient(timeout=60)
                logger.info("OpenAI OAuth: loaded cached tokens")
                return True
            # Expired → refresh
            try:
                tokens = await _do_refresh(self.client_id, tokens["refresh_token"])
                _save(tokens)
                self._tokens = tokens
                self._http   = httpx.AsyncClient(timeout=60)
                logger.info("OpenAI OAuth: tokens refreshed")
                return True
            except Exception as e:
                logger.warning(f"Token refresh failed ({e}) — re-authenticating")

        return await self._pkce_flow()

    async def _pkce_flow(self) -> bool:
        """Open browser, capture callback, exchange for tokens."""
        verifier, challenge = _generate_pkce()
        auth_url = _build_auth_url(self.client_id, challenge)

        # Reset callback state
        _CallbackHandler.auth_code = None
        _CallbackHandler.error     = None

        # Start local callback server on port 21337
        server = HTTPServer(("localhost", 21337), _CallbackHandler)
        Thread(target=server.serve_forever, daemon=True).start()

        logger.info("Opening browser for OpenAI login...")
        webbrowser.open(auth_url)
        print(f"\n  If the browser did not open, visit:\n  {auth_url}\n")

        # Wait for callback (max 2 minutes)
        deadline = time.time() + 120
        while time.time() < deadline:
            await asyncio.sleep(0.5)
            if _CallbackHandler.auth_code or _CallbackHandler.error:
                break

        server.shutdown()

        if _CallbackHandler.error:
            logger.error(f"OpenAI OAuth error: {_CallbackHandler.error}")
            return False

        if not _CallbackHandler.auth_code:
            logger.error("OpenAI OAuth timed out — no callback received")
            return False

        try:
            tokens = await _exchange_code(
                self.client_id, _CallbackHandler.auth_code, verifier
            )
            _save(tokens)
            self._tokens = tokens
            self._http   = httpx.AsyncClient(timeout=60)
            logger.info("OpenAI OAuth: login successful")
            return True
        except Exception as e:
            logger.error(f"OpenAI OAuth token exchange failed: {e}")
            return False

    async def complete(
        self,
        prompt:        str,
        system_prompt: Optional[str] = None,
        json_mode:     bool = False,
    ) -> str:
        if not self._tokens or not self._http:
            raise RuntimeError("OpenAIOAuthProvider not initialized")

        # Auto-refresh if near expiry
        if time.time() >= self._tokens.get("expires_at", 0) - 60:
            tokens = await _do_refresh(self.client_id, self._tokens["refresh_token"])
            _save(tokens)
            self._tokens = tokens

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        body: Dict = {
            "model":       self.model,
            "messages":    messages,
            "temperature": self.temperature,
            "max_tokens":  self.max_tokens,
        }
        if json_mode:
            body["response_format"] = {"type": "json_object"}

        r = await self._http.post(
            "https://api.openai.com/v1/chat/completions",
            headers={"Authorization": f"Bearer {self._tokens['access_token']}"},
            json=body,
        )
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    @property
    def is_ready(self) -> bool:
        return self._tokens is not None

    async def close(self) -> None:
        if self._http:
            await self._http.aclose()


# ─── CLI Helper ───────────────────────────────────────────────────────────────

async def login_cli(client_id: str, model: str = "gpt-4o-mini") -> bool:
    """
    Standalone login helper — call from CLI:
      python -c "from xlayer_ai.llm.openai_oauth import login_cli; import asyncio; asyncio.run(login_cli('YOUR_CLIENT_ID'))"
    """
    provider = OpenAIOAuthProvider(client_id=client_id, model=model)
    ok = await provider._pkce_flow()
    if ok:
        print(f"[OK] Logged in. Tokens saved to {TOKEN_PATH}")
    else:
        print("[FAIL] Login failed")
    return ok

"""
engine/logical_surface_map/behavior_probe.py — Behavioral Fingerprinting

Pre-classifies endpoints through differential response analysis:
  - WAF detection (Cloudflare, AWS WAF, ModSecurity, Akamai, F5, Imperva)
  - Error signature mapping (Django, Laravel, Spring, Flask, Express, Rails)
  - Input reflection check (canary token echo)
  - SQL error surface (single-quote probe → error in response)

Results stored in LogicalSurface.behavior_profiles and used by:
  - ChainPlanner: token extraction (waf_detected, sql_error_reflected, input_reflected)
  - XLayerLoop: initial strategy hints per endpoint
  - Coordinator: prioritize high-signal endpoints
"""

import asyncio
import re
import time
import uuid
import urllib.parse
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import httpx
from loguru import logger


# ── Signatures ────────────────────────────────────────────────────────────────

_WAF_SIGNATURES = [
    ("cloudflare",  [r"cloudflare", r"CF-RAY", r"Sorry, you have been blocked"]),
    ("aws_waf",     [r"x-amzn-RequestId", r"aws-waf", r"Request blocked"]),
    ("modsecurity", [r"ModSecurity", r"mod_security", r"NOYB"]),
    ("akamai",      [r"AkamaiGHost", r"Reference\s*#", r"Access Denied.*Akamai"]),
    ("f5",          [r"The requested URL was rejected", r"F5 Networks"]),
    ("imperva",     [r"incapsula", r"Imperva", r"Request Denied"]),
]

_ERROR_SIGNATURES = [
    ("django",   [r"Django Version:", r"Page not found \(404\)", r"Traceback \(most recent call last\)"]),
    ("laravel",  [r"Illuminate\\\\", r"Whoops!", r"laravel", r"symfony/debug"]),
    ("spring",   [r"Whitelabel Error Page", r"Spring Boot", r"org\.springframework"]),
    ("flask",    [r"Werkzeug Debugger", r"werkzeug", r"Flask \(2\."]),
    ("express",  [r"Cannot GET /", r"Express", r"node_modules"]),
    ("rails",    [r"ActionController", r"ActiveRecord", r"Ruby on Rails"]),
    ("asp_net",  [r"ASP\.NET", r"__VIEWSTATE", r"System\.Web"]),
]

_WAF_TEST_PAYLOADS = [
    "' OR 1=1 --",
    "<script>alert(1)</script>",
    "../../etc/passwd",
]

_SQL_TEST_PAYLOAD = "'"

_SQL_ERROR_RE = re.compile(
    r"(SQL syntax|syntax error|ORA-\d+|SQLSTATE|mysql_fetch|"
    r"PostgreSQL.*ERROR|SQLite.*error|Unclosed quotation mark|"
    r"quoted string not properly terminated)",
    re.IGNORECASE,
)


# ── Data model ────────────────────────────────────────────────────────────────

@dataclass
class BehaviorProfile:
    """Behavioral characteristics of a single endpoint."""
    url: str

    # WAF
    waf_detected: bool = False
    waf_name: str = ""           # "cloudflare", "aws_waf", "modsecurity", etc.

    # Framework error signature
    error_signature: str = ""    # "django", "laravel", "spring", "flask", etc.

    # Reflection — canary token echoed back in response
    reflects_input: bool = False

    # SQL error surface — single-quote triggers error
    sql_error_on_quote: bool = False

    # Baseline timing
    avg_response_ms: float = 0.0
    baseline_status: int = 0

    def to_tokens(self) -> List[str]:
        """Convert profile to token set for ChainPlanner._extract_tokens()."""
        tokens: List[str] = []
        if self.waf_detected:
            tokens.append("waf_detected")
            if self.waf_name:
                tokens.append(f"waf_{self.waf_name}")
        if self.reflects_input:
            tokens.append("input_reflected")
        if self.sql_error_on_quote:
            tokens.append("sql_error_reflected")
        if self.error_signature:
            tokens.append(f"framework_{self.error_signature}")
        return tokens

    def to_hint(self) -> str:
        """One-line human-readable summary for the surface summary."""
        parts = []
        if self.waf_detected:
            parts.append(f"WAF:{self.waf_name or 'unknown'}")
        if self.error_signature:
            parts.append(f"framework:{self.error_signature}")
        if self.sql_error_on_quote:
            parts.append("sql_errors")
        if self.reflects_input:
            parts.append("reflects_input")
        return ", ".join(parts) if parts else "clean"


# ── Probe engine ──────────────────────────────────────────────────────────────

class BehaviorProbe:
    """
    Profiles endpoints through differential HTTP analysis.

    Per endpoint, runs 4 lightweight probes concurrently:
      1. Baseline  — normal GET, measure status + timing
      2. WAF test  — inject known WAF-triggering strings, detect block signatures
      3. SQL quote — inject single-quote, detect SQL error in response
      4. Reflection — inject canary token, check if it echoes back

    Capped at max_endpoints (default 15) to stay within scan budget.
    Results used to pre-classify endpoints before exploitation begins.
    """

    def __init__(
        self,
        timeout: float = 8.0,
        proxy: Optional[str] = None,
        max_endpoints: int = 15,
    ) -> None:
        self.timeout       = timeout
        self.proxy         = proxy
        self.max_endpoints = max_endpoints

    async def probe_endpoints(
        self,
        endpoints: List[str],
        cookies: Optional[List[dict]] = None,
    ) -> Dict[str, BehaviorProfile]:
        """
        Probe up to max_endpoints and return {url: BehaviorProfile}.
        Prioritizes endpoints with query params and high-value paths.
        """
        def _priority(url: str) -> int:
            lower = url.lower()
            if "?" in lower:
                return 0   # has params — highest attack surface
            if any(k in lower for k in ("admin", "login", "search", "api", "user")):
                return 1
            return 2

        targets = sorted(endpoints, key=_priority)[: self.max_endpoints]

        cookie_jar: dict = {}
        if cookies:
            for c in cookies:
                name  = c.get("name") or c.get("key", "")
                value = c.get("value", "")
                if name and value:
                    cookie_jar[name] = value

        profiles: Dict[str, BehaviorProfile] = {}

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            proxies=self.proxy or None,
            cookies=cookie_jar,
            verify=False,
        ) as client:
            tasks   = [self._probe_one(client, url) for url in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, result in zip(targets, results):
            if isinstance(result, Exception):
                logger.debug(f"[BehaviorProbe] {url}: {type(result).__name__}: {result}")
                continue
            profiles[url] = result

        # Summary log
        waf_n     = sum(1 for p in profiles.values() if p.waf_detected)
        sql_n     = sum(1 for p in profiles.values() if p.sql_error_on_quote)
        reflect_n = sum(1 for p in profiles.values() if p.reflects_input)
        logger.info(
            f"[BehaviorProbe] {len(profiles)}/{len(targets)} profiled | "
            f"WAF: {waf_n}  SQL-err: {sql_n}  Reflecting: {reflect_n}"
        )
        return profiles

    async def _probe_one(
        self, client: httpx.AsyncClient, url: str
    ) -> BehaviorProfile:
        profile = BehaviorProfile(url=url)

        # 1. Baseline
        base_status, base_body, base_headers, base_ms = await self._get(client, url)
        profile.baseline_status = base_status
        profile.avg_response_ms = base_ms

        # Detect framework from baseline response (error page / headers)
        profile.error_signature = _detect_error_signature(base_body, base_headers)
        if not profile.error_signature:
            # Try 404 response for framework hints
            _, err_body, err_headers, _ = await self._get(
                client, _inject_param(url, "__xlayer_notfound__")
            )
            profile.error_signature = _detect_error_signature(err_body, err_headers)

        # 2. WAF probe — try each payload, stop on first block
        if base_status not in (0, 404):   # skip WAF probe for inaccessible endpoints
            for waf_payload in _WAF_TEST_PAYLOADS:
                probe_url = _inject_param(url, waf_payload)
                waf_status, waf_body, waf_headers, _ = await self._get(client, probe_url)
                detected, name = _detect_waf(waf_status, waf_body, waf_headers)
                if detected:
                    profile.waf_detected = True
                    profile.waf_name     = name
                    break

        # 3. SQL error probe (skip if WAF present — would just return block page)
        if not profile.waf_detected:
            sql_url = _inject_param(url, _SQL_TEST_PAYLOAD)
            _, sql_body, _, _ = await self._get(client, sql_url)
            profile.sql_error_on_quote = bool(_SQL_ERROR_RE.search(sql_body))

        # 4. Reflection probe — canary token
        canary     = f"xlayerprobe{uuid.uuid4().hex[:8]}"
        canary_url = _inject_param(url, canary)
        _, canary_body, _, _ = await self._get(client, canary_url)
        profile.reflects_input = canary in canary_body

        return profile

    async def _get(
        self,
        client: httpx.AsyncClient,
        url: str,
    ) -> Tuple[int, str, dict, float]:
        """GET request, returns (status, body, headers, elapsed_ms)."""
        try:
            t0   = time.monotonic()
            resp = await client.get(url)
            ms   = (time.monotonic() - t0) * 1000
            return resp.status_code, resp.text[:4000], dict(resp.headers), ms
        except Exception:
            return 0, "", {}, 0.0


# ── Helpers ───────────────────────────────────────────────────────────────────

def _inject_param(url: str, value: str) -> str:
    """Inject value into the first query param, or append ?q=<value>."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    if params:
        first_key       = next(iter(params))
        params[first_key] = [value]
    else:
        params["q"] = [value]
    new_query = urllib.parse.urlencode(params, doseq=True)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))


def _detect_waf(status: int, body: str, headers: dict) -> Tuple[bool, str]:
    """Check response for WAF block signatures."""
    headers_str = " ".join(f"{k}:{v}" for k, v in headers.items())
    combined    = f"{body[:2000]} {headers_str}".lower()

    # Status-based + body/header pattern
    if status in (403, 406, 429, 503):
        for waf_name, patterns in _WAF_SIGNATURES:
            for pat in patterns:
                if re.search(pat, combined, re.IGNORECASE):
                    return True, waf_name

    # Header-only check (some WAFs return 200 with added headers)
    for waf_name, patterns in _WAF_SIGNATURES:
        for pat in patterns:
            if re.search(pat, headers_str, re.IGNORECASE):
                return True, waf_name

    return False, ""


def _detect_error_signature(body: str, headers: dict) -> str:
    """Identify framework from response body and headers."""
    combined = f"{body[:3000]} " + " ".join(f"{k}:{v}" for k, v in headers.items())
    for framework, patterns in _ERROR_SIGNATURES:
        for pat in patterns:
            if re.search(pat, combined, re.IGNORECASE):
                return framework
    return ""

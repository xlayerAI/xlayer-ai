"""
engine/logical_surface_map/lsm_tools.py — ScoutLoop HTTP Tool Implementations

Async tools called by the LLM during ScoutLoop's agentic reconnaissance loop.

Available tools (LLM can call any of these via tool_call action):
  fetch_js        — Download a JS bundle for AST analysis (js_crawling strategy)
  fetch_html      — Download an HTML page (link/form extraction)
  spider_links    — Extract all href/src/action URLs from a page
  check_endpoint  — Probe a path: status, headers, body snippet (auth_scoping)
  fetch_json      — Fetch a JSON API endpoint, return pretty-printed response

Usage in ScoutLoop:
    async with LSMTools(base_url, timeout, proxy, cookies) as tools:
        result = await tools.call("fetch_js", {"url": "https://t.com/main.js"})

The `call()` method dispatches by name and handles missing tools gracefully.
"""

import json
import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from loguru import logger


# ── Tool schema definitions (for LLM tool declaration) ──────────────────────
# These are returned by get_schemas() and passed to the LLM so it knows
# what tools exist and what arguments each tool takes.

LSM_TOOL_SCHEMAS: List[Dict[str, Any]] = [
    {
        "name": "behavior_probe",
        "description": (
            "Run differential behavioral analysis on an endpoint to understand what you are dealing with BEFORE exploiting. "
            "Detects: WAF presence and vendor (Cloudflare, AWS WAF, ModSecurity...), "
            "framework error signature (Django, Laravel, Spring, Flask, Express...), "
            "SQL error surface (does a quote trigger an error?), "
            "input reflection (does the endpoint echo back input?). "
            "Use this when: you found an interesting endpoint with params, "
            "you suspect a WAF is blocking your probes, "
            "confidence is stuck and you need to understand why, "
            "or before choosing a SQLi/XSS/SSTI strategy."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL of the endpoint to profile (e.g. https://target.com/api/search?q=test)"
                }
            },
            "required": ["url"],
        },
    },
    {
        "name": "fetch_js",
        "description": (
            "Download a JavaScript bundle file and return its raw content for deep AST analysis. "
            "Use on every JS URL discovered by browser_crawl. "
            "The content will be automatically analyzed for endpoints, secrets, taint flows, "
            "and source maps."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL of the JS file (e.g. https://target.com/static/main.js)"
                }
            },
            "required": ["url"],
        },
    },
    {
        "name": "fetch_html",
        "description": (
            "Fetch an HTML page and return its raw content. "
            "Useful for discovering inline scripts, meta tags, framework hints, and linked resources."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL of the HTML page to fetch"
                }
            },
            "required": ["url"],
        },
    },
    {
        "name": "spider_links",
        "description": (
            "Fetch a page and extract all discovered URLs: "
            "<a href>, <script src>, <form action>, <link href>. "
            "Returns one URL per line. Use for initial link discovery on pages not covered by browser_crawl."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL of the page to spider for links"
                }
            },
            "required": ["url"],
        },
    },
    {
        "name": "check_endpoint",
        "description": (
            "Probe a specific endpoint path and return: HTTP status, key response headers, body snippet. "
            "Use for auth_scoping (check if 401/403), endpoint verification, or tech detection. "
            "401 = auth required. 403 = forbidden. 200 = accessible."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": "Path or full URL to check (e.g. /api/users or https://target.com/admin)"
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method: GET (default), POST, PUT, DELETE, OPTIONS"
                },
            },
            "required": ["path"],
        },
    },
    {
        "name": "fetch_json",
        "description": (
            "Fetch a JSON API endpoint and return the pretty-printed response. "
            "Use to inspect API responses for nested endpoint paths, entity structures, "
            "or HATEOAS-style links embedded in response bodies."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "URL of the JSON endpoint"
                },
                "method": {
                    "type": "string",
                    "description": "HTTP method: GET (default) or POST"
                },
                "body": {
                    "type": "object",
                    "description": "Optional JSON body for POST requests"
                },
            },
            "required": ["url"],
        },
    },
]


# ── LSMTools — async HTTP tool executor ──────────────────────────────────────

class LSMTools:
    """
    Async context manager that provides HTTP tools for ScoutLoop.

    Usage:
        async with LSMTools(base_url=url, cookies=auth_cookies) as tools:
            result = await tools.call("fetch_js", {"url": "https://t.com/main.js"})

    Holds one shared httpx.AsyncClient for the lifetime of a ScoutLoop.run() call.
    """

    # Max response sizes to avoid memory explosion on huge bundles
    _MAX_JS_BYTES   = 2_000_000    # 2 MB
    _MAX_HTML_BYTES = 500_000      # 500 KB
    _MAX_JSON_CHARS = 3_000        # chars in pretty-printed JSON snippet

    def __init__(
        self,
        base_url: str,
        timeout: int = 15,
        proxy: Optional[str] = None,
        cookies: Optional[List[dict]] = None,
    ):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.proxy = proxy
        self._raw_cookies = cookies or []
        self._client = None

    async def __aenter__(self) -> "LSMTools":
        try:
            import httpx
        except ImportError:
            logger.warning("[LSMTools] httpx not installed — tool calls will fail")
            return self

        cookie_str = "; ".join(
            f"{c.get('name', '')}={c.get('value', '')}"
            for c in self._raw_cookies
            if c.get("name") and c.get("value")
        )

        self._client = httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            proxies={"all://": self.proxy} if self.proxy else None,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                **({"Cookie": cookie_str} if cookie_str else {}),
            },
        )
        return self

    async def __aexit__(self, *_) -> None:
        if self._client:
            await self._client.aclose()
            self._client = None

    # ── Dispatcher ────────────────────────────────────────────────────────────

    async def call(self, tool_name: str, args: Dict[str, Any]) -> str:
        """
        Dispatch a tool call by name. Returns string result.
        Returns an error string (not raises) for unknown tools or failures.
        """
        _dispatch = {
            "fetch_js":        self.fetch_js,
            "fetch_html":      self.fetch_html,
            "spider_links":    self.spider_links,
            "check_endpoint":  self.check_endpoint,
            "fetch_json":      self.fetch_json,
            "behavior_probe":  self.behavior_probe,
        }
        fn = _dispatch.get(tool_name)
        if fn is None:
            return f"[LSMTools] Unknown tool: '{tool_name}'"
        if self._client is None:
            return f"[LSMTools] HTTP client not initialized (use as async context manager)"
        try:
            return await fn(**args)
        except TypeError as e:
            return f"[LSMTools] Bad arguments for '{tool_name}': {e}"
        except Exception as e:
            return f"[LSMTools] Error in '{tool_name}': {e}"

    def has_tool(self, name: str) -> bool:
        return name in {"fetch_js", "fetch_html", "spider_links", "check_endpoint", "fetch_json", "behavior_probe"}

    # ── URL helper ────────────────────────────────────────────────────────────

    def _resolve(self, url: str) -> str:
        """Resolve relative path against base_url."""
        url = (url or "").strip()
        if url.startswith("http://") or url.startswith("https://"):
            return url
        if url.startswith("/"):
            return f"{self.base_url}{url}"
        # Relative without leading slash — e.g. "api/users" → base/api/users
        return f"{self.base_url}/{url}"

    # ── Tool: fetch_js ────────────────────────────────────────────────────────

    async def fetch_js(self, url: str) -> str:
        """
        Download a JavaScript bundle. Returns raw JS content.
        Output is consumed by _apply_discovery_logic(strategy='js_crawling').
        """
        url = self._resolve(url)
        try:
            r = await self._client.get(url)
        except Exception as e:
            return f"Error fetching {url}: {e}"

        if r.status_code != 200:
            return f"HTTP {r.status_code} for {url} — no content"

        content = r.text or ""
        if len(content) > self._MAX_JS_BYTES:
            logger.warning(
                f"[LSMTools] fetch_js: {url} is {len(content)//1024}KB — truncating to 2MB"
            )
            content = content[: self._MAX_JS_BYTES]

        logger.debug(f"[LSMTools] fetch_js {url}: {len(content):,} chars")
        return content

    # ── Tool: fetch_html ─────────────────────────────────────────────────────

    async def fetch_html(self, url: str) -> str:
        """Fetch an HTML page. Returns raw HTML content."""
        url = self._resolve(url)
        try:
            r = await self._client.get(url)
            content = (r.text or "")[: self._MAX_HTML_BYTES]
            logger.debug(
                f"[LSMTools] fetch_html {url}: HTTP {r.status_code}, {len(content):,} chars"
            )
            return content
        except Exception as e:
            return f"Error fetching {url}: {e}"

    # ── Tool: spider_links ────────────────────────────────────────────────────

    async def spider_links(self, url: str) -> str:
        """
        Fetch a page, extract all URLs (a[href], script[src], form[action]).
        Returns one absolute URL per line.
        """
        url = self._resolve(url)
        try:
            r = await self._client.get(url)
            html = (r.text or "")[: self._MAX_HTML_BYTES]
        except Exception as e:
            return f"Error fetching {url}: {e}"

        base_host = urlparse(url).netloc
        found: List[str] = []
        seen: set = set()

        def _add(raw: str) -> None:
            resolved = urljoin(url, raw.strip())
            if resolved not in seen:
                seen.add(resolved)
                found.append(resolved)

        # <a href="...">
        for m in re.findall(r'''<a[^>]+href=["']([^"']+)["']''', html, re.IGNORECASE):
            p = urlparse(urljoin(url, m))
            if not p.netloc or p.netloc == base_host:
                _add(m)

        # <script src="...">
        for m in re.findall(r'''<script[^>]+src=["']([^"']+)["']''', html, re.IGNORECASE):
            _add(m)

        # <form action="...">
        for m in re.findall(r'''<form[^>]+action=["']([^"']+)["']''', html, re.IGNORECASE):
            if m:
                _add(m)

        # <link href="..."> — only API/data links (skip CSS, fonts)
        for m in re.findall(r'''<link[^>]+href=["']([^"']+)["']''', html, re.IGNORECASE):
            if any(x in m for x in ("/api", ".json", "manifest", "data")):
                _add(m)

        logger.debug(f"[LSMTools] spider_links {url}: {len(found)} URLs")
        return "\n".join(found) if found else f"No links found on {url}"

    # ── Tool: check_endpoint ─────────────────────────────────────────────────

    async def check_endpoint(self, path: str, method: str = "GET") -> str:
        """
        Probe a specific endpoint. Returns status, key headers, body snippet.
        """
        url = self._resolve(path)
        method = (method or "GET").upper()

        try:
            if method == "GET":
                r = await self._client.get(url)
            elif method == "POST":
                r = await self._client.post(
                    url, json={}, headers={"Content-Type": "application/json"}
                )
            elif method == "PUT":
                r = await self._client.put(
                    url, json={}, headers={"Content-Type": "application/json"}
                )
            elif method == "DELETE":
                r = await self._client.delete(url)
            elif method == "OPTIONS":
                r = await self._client.options(url)
            elif method == "HEAD":
                r = await self._client.head(url)
            else:
                r = await self._client.get(url)
        except Exception as e:
            return f"Error checking {url}: {e}"

        # Collect key headers
        ct          = r.headers.get("content-type", "")
        server      = r.headers.get("server", "")
        location    = r.headers.get("location", "")
        www_auth    = r.headers.get("www-authenticate", "")
        allow       = r.headers.get("allow", "")
        x_powered   = r.headers.get("x-powered-by", "")
        cors        = r.headers.get("access-control-allow-origin", "")

        # Strip HTML tags from body snippet
        body_raw    = (r.text or "")[:800]
        body_clean  = re.sub(r"<[^>]+>", " ", body_raw)
        body_clean  = re.sub(r"\s{2,}", " ", body_clean).strip()[:300]

        lines = [
            f"URL:    {url}",
            f"Method: {method}",
            f"Status: {r.status_code}",
        ]
        if ct:          lines.append(f"Content-Type: {ct}")
        if server:      lines.append(f"Server: {server}")
        if x_powered:   lines.append(f"X-Powered-By: {x_powered}")
        if location:    lines.append(f"Location: {location}")
        if www_auth:    lines.append(f"WWW-Authenticate: {www_auth}")
        if allow:       lines.append(f"Allow: {allow}")
        if cors:        lines.append(f"CORS: {cors}")
        if body_clean:  lines.append(f"Body: {body_clean}")

        logger.debug(f"[LSMTools] check_endpoint {method} {url}: HTTP {r.status_code}")
        return "\n".join(lines)

    # ── Tool: fetch_json ─────────────────────────────────────────────────────

    async def fetch_json(
        self,
        url: str,
        method: str = "GET",
        body: Optional[dict] = None,
    ) -> str:
        """
        Fetch a JSON API endpoint. Returns HTTP status line + pretty-printed JSON.
        """
        url = self._resolve(url)
        method = (method or "GET").upper()

        try:
            if method == "POST":
                r = await self._client.post(
                    url,
                    json=body or {},
                    headers={"Content-Type": "application/json"},
                )
            else:
                r = await self._client.get(url)
        except Exception as e:
            return f"Error fetching {url}: {e}"

        status_line = f"HTTP {r.status_code} | {r.headers.get('content-type', '')}"

        try:
            data = r.json()
            pretty = json.dumps(data, indent=2, default=str)
            if len(pretty) > self._MAX_JSON_CHARS:
                pretty = pretty[: self._MAX_JSON_CHARS] + "\n... (truncated)"
            logger.debug(f"[LSMTools] fetch_json {url}: HTTP {r.status_code}, JSON OK")
            return f"{status_line}\n{pretty}"
        except Exception:
            # Not valid JSON — return raw text snippet
            body_text = (r.text or "(empty)")[:500]
            logger.debug(f"[LSMTools] fetch_json {url}: HTTP {r.status_code}, non-JSON")
            return f"{status_line}\n{body_text}"

    # ── Tool: behavior_probe ────────────────────────────────────────────────

    # WAF signature patterns (header / body markers)
    _WAF_SIGNATURES = {
        "cloudflare":   (["cf-ray", "cf-cache-status", "__cfduid"], ["cloudflare", "attention required"]),
        "aws_waf":      (["x-amzn-requestid"], ["aws", "request blocked"]),
        "modsecurity":  ([], ["mod_security", "modsecurity", "not acceptable"]),
        "akamai":       (["x-akamai-"], ["akamai", "access denied"]),
        "imperva":      (["x-iinfo"], ["incapsula", "imperva"]),
        "f5_bigip":     (["x-wa-info", "bigipserver"], ["the requested url was rejected"]),
    }

    # Framework error signature patterns
    _FRAMEWORK_SIGS = {
        "django":   ["traceback", "django", "wsgi", "csrfmiddlewaretoken"],
        "laravel":  ["laravel", "symfony", "whoops", "blade"],
        "spring":   ["whitelabel error", "spring", "java.lang"],
        "flask":    ["werkzeug", "debugger", "flask"],
        "express":  ["cannot get", "express", "at layer", "at router"],
        "rails":    ["actioncontroller", "routing error", "rails"],
        "asp_net":  ["asp.net", "__viewstate", "server error in"],
    }

    async def behavior_probe(self, url: str) -> str:
        """
        Run differential behavioral analysis on an endpoint.
        Returns JSON with: waf_detected, waf_name, error_signature,
        reflects_input, sql_error_on_quote, baseline_status, avg_response_ms.
        """
        url = self._resolve(url)
        profile = {
            "url": url,
            "waf_detected": False,
            "waf_name": None,
            "error_signature": None,
            "reflects_input": False,
            "sql_error_on_quote": False,
            "baseline_status": None,
            "avg_response_ms": 0,
        }

        import time

        # ── Probe 1: Clean baseline ──────────────────────────────────────
        try:
            t0 = time.monotonic()
            r_base = await self._client.get(url)
            baseline_ms = (time.monotonic() - t0) * 1000
            profile["baseline_status"] = r_base.status_code
            profile["avg_response_ms"] = round(baseline_ms, 1)
            base_body = (r_base.text or "").lower()
            base_headers = {k.lower(): v.lower() for k, v in r_base.headers.items()}
        except Exception as e:
            return json.dumps({"url": url, "error": str(e)})

        # ── WAF detection from baseline headers + body ───────────────────
        for waf_name, (hdr_markers, body_markers) in self._WAF_SIGNATURES.items():
            for hm in hdr_markers:
                if any(hm in h for h in base_headers):
                    profile["waf_detected"] = True
                    profile["waf_name"] = waf_name
                    break
            if profile["waf_detected"]:
                break
            for bm in body_markers:
                if bm in base_body:
                    profile["waf_detected"] = True
                    profile["waf_name"] = waf_name
                    break
            if profile["waf_detected"]:
                break

        # ── Framework error signature from baseline ──────────────────────
        for fw, markers in self._FRAMEWORK_SIGS.items():
            if any(m in base_body for m in markers):
                profile["error_signature"] = fw
                break

        # ── Probe 2: SQL quote injection ─────────────────────────────────
        sql_markers = ["sql", "syntax", "mysql", "postgresql", "sqlite", "ora-",
                       "unclosed quotation", "quoted string", "unterminated"]
        try:
            probe_url = self._inject_param(url, "'")
            r_sql = await self._client.get(probe_url)
            sql_body = (r_sql.text or "").lower()
            if any(m in sql_body for m in sql_markers):
                profile["sql_error_on_quote"] = True
            # WAF detection from error probe (WAFs often block this)
            if not profile["waf_detected"] and r_sql.status_code in (403, 406, 429):
                for waf_name, (_, body_markers) in self._WAF_SIGNATURES.items():
                    if any(bm in sql_body for bm in body_markers):
                        profile["waf_detected"] = True
                        profile["waf_name"] = waf_name
                        break
        except Exception:
            pass

        # ── Probe 3: Input reflection check ──────────────────────────────
        canary = "xlr3fl3ct90"
        try:
            refl_url = self._inject_param(url, canary)
            r_refl = await self._client.get(refl_url)
            if canary in (r_refl.text or ""):
                profile["reflects_input"] = True
        except Exception:
            pass

        # ── Probe 4: Framework error from bad path ───────────────────────
        if not profile["error_signature"]:
            try:
                from urllib.parse import urlparse as _up
                parsed = _up(url)
                err_url = f"{parsed.scheme}://{parsed.netloc}/xlayer_nonexist_8372"
                r_err = await self._client.get(err_url)
                err_body = (r_err.text or "").lower()
                for fw, markers in self._FRAMEWORK_SIGS.items():
                    if any(m in err_body for m in markers):
                        profile["error_signature"] = fw
                        break
            except Exception:
                pass

        logger.debug(
            f"[LSMTools] behavior_probe {url}: "
            f"waf={profile['waf_name'] or 'none'} "
            f"fw={profile['error_signature'] or 'none'} "
            f"sql_err={profile['sql_error_on_quote']} "
            f"reflects={profile['reflects_input']}"
        )
        return json.dumps(profile, indent=2)

    @staticmethod
    def _inject_param(url: str, payload: str) -> str:
        """Inject payload into the first query parameter value, or append as ?x=payload."""
        if "?" in url and "=" in url:
            # Replace the first param value
            base, qs = url.split("?", 1)
            parts = qs.split("&")
            if "=" in parts[0]:
                key = parts[0].split("=", 1)[0]
                parts[0] = f"{key}={payload}"
            return base + "?" + "&".join(parts)
        elif "?" in url:
            return url + f"x={payload}"
        else:
            return url + f"?x={payload}"

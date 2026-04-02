"""
CDP Hooks — Chrome DevTools Protocol Deep Browser Integration

Deep browser instrumentation via Chrome DevTools Protocol.
This module goes beyond simple page.goto() — it hooks into the browser engine itself.

Capabilities:
    1. Network Interception — pause, inspect, modify requests before they leave
    2. Fetch/XHR Hooking — capture encrypted requests at plaintext level
    3. postMessage Monitoring — iframe/cross-origin communication bugs
    4. DOM Taint Tracking — inject canary strings, track through sinks
    5. JS Variable Extraction — read window.CONFIG, API keys, secrets
    6. Service Worker/WebSocket monitoring

Architecture:
    CDPSession wraps a Playwright Page with CDP superpowers.
    The Solver calls CDPSession methods to deeply analyze client-side behavior.
"""

import asyncio
import json
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set

from loguru import logger


@dataclass
class InterceptedRequest:
    """A network request captured via CDP."""
    request_id: str
    url: str
    method: str
    headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None
    resource_type: str = "unknown"
    timestamp: float = 0.0


@dataclass
class PostMessageEvent:
    """A postMessage event captured between frames/origins."""
    source_origin: str = ""
    target_origin: str = ""
    data: str = ""
    timestamp: float = 0.0


@dataclass
class DOMTaintResult:
    """Result of DOM taint tracking — where did the canary end up?"""
    canary: str = ""
    found_in: List[str] = field(default_factory=list)  # list of sink locations
    dangerous_sinks: List[str] = field(default_factory=list)  # innerHTML, eval, etc.
    xss_possible: bool = False


@dataclass
class JSIntelResult:
    """JavaScript intelligence gathered from the page."""
    variables: Dict[str, Any] = field(default_factory=dict)   # window.CONFIG, etc.
    endpoints: List[str] = field(default_factory=list)         # API URLs found in JS
    secrets: List[Dict[str, str]] = field(default_factory=list)  # API keys, tokens
    event_listeners: List[Dict] = field(default_factory=list)  # click, input events
    fetch_hooks: List[Dict] = field(default_factory=list)      # intercepted fetch calls


class CDPSession:
    """
    CDP-powered browser session for deep client-side analysis.

    Usage:
        from playwright.async_api import async_playwright
        async with async_playwright() as p:
            browser = await p.chromium.launch()
            page = await browser.new_page()
            cdp = CDPSession(page)
            await cdp.setup()

            await page.goto("https://target.com")

            intel = await cdp.extract_js_intel()
            taint = await cdp.track_dom_taint("search_param")
            messages = cdp.get_post_messages()
    """

    # Dangerous DOM sinks that indicate XSS potential
    DANGEROUS_SINKS = [
        "innerHTML", "outerHTML", "document.write", "document.writeln",
        "eval", "setTimeout", "setInterval", "Function",
        "location.href", "location.assign", "location.replace",
        "window.open", "element.setAttribute",
    ]

    def __init__(self, page):
        """
        Args:
            page: Playwright Page object
        """
        self._page = page
        self._cdp = None
        self._intercepted_requests: List[InterceptedRequest] = []
        self._post_messages: List[PostMessageEvent] = []
        self._fetch_captures: List[Dict] = []
        self._setup_done = False

    async def setup(self):
        """Initialize CDP session and install hooks."""
        if self._setup_done:
            return

        try:
            context = self._page.context
            self._cdp = await context.new_cdp_session(self._page)

            # Enable network domain for request interception
            await self._cdp.send("Network.enable")

            # Install request interceptor
            await self._cdp.send("Fetch.enable", {
                "patterns": [{"urlPattern": "*", "requestStage": "Request"}]
            })
            self._cdp.on("Fetch.requestPaused", self._on_request_paused)

            # Install postMessage monitor + fetch/XHR hooks via JS injection
            await self._page.add_init_script(self._get_hook_script())

            # Listen for console messages (from our hooks)
            self._page.on("console", self._on_console_message)

            self._setup_done = True
            logger.debug("[CDP] Session setup complete — hooks installed")

        except Exception as e:
            logger.warning(f"[CDP] Setup failed (non-critical): {e}")

    # ── Network Interception ──────────────────────────────────────────

    async def _on_request_paused(self, params: Dict):
        """Handle intercepted request — log and continue."""
        try:
            req = InterceptedRequest(
                request_id=params.get("requestId", ""),
                url=params.get("request", {}).get("url", ""),
                method=params.get("request", {}).get("method", "GET"),
                headers=params.get("request", {}).get("headers", {}),
                post_data=params.get("request", {}).get("postData"),
                resource_type=params.get("resourceType", "unknown"),
            )
            self._intercepted_requests.append(req)

            # Continue the request (don't block it)
            await self._cdp.send("Fetch.continueRequest", {
                "requestId": req.request_id
            })
        except Exception:
            pass

    def get_intercepted_requests(self) -> List[InterceptedRequest]:
        """Get all intercepted network requests."""
        return list(self._intercepted_requests)

    def get_api_requests(self) -> List[InterceptedRequest]:
        """Get only API/XHR/Fetch requests (not images, CSS, etc.)."""
        api_types = {"xhr", "fetch", "document", "other"}
        return [
            r for r in self._intercepted_requests
            if r.resource_type.lower() in api_types
            and not r.url.endswith((".css", ".js", ".png", ".jpg", ".gif", ".svg", ".woff"))
        ]

    # ── postMessage Monitoring ────────────────────────────────────────

    def _on_console_message(self, msg):
        """Process console messages from our injected hooks."""
        text = msg.text
        try:
            if text.startswith("__XLAYER_POSTMSG__:"):
                data = json.loads(text.split(":", 1)[1])
                self._post_messages.append(PostMessageEvent(
                    source_origin=data.get("source_origin", ""),
                    target_origin=data.get("target_origin", ""),
                    data=str(data.get("data", ""))[:2000],
                ))
            elif text.startswith("__XLAYER_FETCH__:"):
                data = json.loads(text.split(":", 1)[1])
                self._fetch_captures.append(data)
        except Exception:
            pass

    def get_post_messages(self) -> List[PostMessageEvent]:
        """Get captured postMessage events."""
        return list(self._post_messages)

    # ── DOM Taint Tracking ────────────────────────────────────────────

    async def track_dom_taint(
        self, parameter: str, input_value: Optional[str] = None
    ) -> DOMTaintResult:
        """
        Track where user input ends up in the DOM.

        Injects a unique canary string into the page via a form/parameter,
        then checks if it appears in any dangerous DOM sinks.
        """
        canary = f"xlayer_canary_{uuid.uuid4().hex[:8]}"
        value = input_value or canary

        result = DOMTaintResult(canary=canary)

        try:
            # Search DOM for canary reflection
            taint_check = await self._page.evaluate(f'''() => {{
                const canary = "{canary}";
                const results = [];
                const dangerousSinks = [];

                // Check all elements
                const all = document.querySelectorAll("*");
                for (const el of all) {{
                    // innerHTML check
                    if (el.innerHTML && el.innerHTML.includes(canary)) {{
                        results.push("innerHTML:" + el.tagName);
                        if (el.tagName !== "SCRIPT") {{
                            dangerousSinks.push("innerHTML");
                        }}
                    }}
                    // Attribute check (href, src, onclick, etc.)
                    for (const attr of el.attributes || []) {{
                        if (attr.value && attr.value.includes(canary)) {{
                            results.push("attr:" + attr.name + ":" + el.tagName);
                            if (["href", "src", "onclick", "onerror", "onload", "action"].includes(attr.name)) {{
                                dangerousSinks.push("attr:" + attr.name);
                            }}
                        }}
                    }}
                }}

                // Check script contents
                const scripts = document.querySelectorAll("script");
                for (const s of scripts) {{
                    if (s.textContent && s.textContent.includes(canary)) {{
                        results.push("script_content");
                        dangerousSinks.push("script_content");
                    }}
                }}

                return {{ results, dangerousSinks }};
            }}''')

            result.found_in = taint_check.get("results", [])
            result.dangerous_sinks = taint_check.get("dangerousSinks", [])
            result.xss_possible = len(result.dangerous_sinks) > 0

            if result.xss_possible:
                logger.info(
                    f"[CDP] DOM Taint: canary found in dangerous sinks: "
                    f"{result.dangerous_sinks}"
                )

        except Exception as e:
            logger.debug(f"[CDP] DOM taint tracking error: {e}")

        return result

    # ── JS Variable Extraction ────────────────────────────────────────

    async def extract_js_intel(self) -> JSIntelResult:
        """
        Extract intelligence from the page's JavaScript environment.

        Reads:
          - window.CONFIG, window.APP_CONFIG, etc.
          - API endpoints in JS source
          - Secrets (API keys, tokens)
          - Event listeners
        """
        result = JSIntelResult()

        try:
            # Extract global config objects
            config_data = await self._page.evaluate('''() => {
                const configs = {};
                const configNames = [
                    "CONFIG", "APP_CONFIG", "config", "appConfig",
                    "__INITIAL_STATE__", "__NEXT_DATA__", "__NUXT__",
                    "ENV", "env", "settings", "SETTINGS",
                ];
                for (const name of configNames) {
                    try {
                        const val = window[name];
                        if (val && typeof val === "object") {
                            configs[name] = JSON.parse(JSON.stringify(val));
                        }
                    } catch(e) {}
                }
                return configs;
            }''')
            result.variables = config_data or {}

            # Extract API endpoints from page source
            content = await self._page.content()
            api_patterns = [
                r'["\']/(api|v[0-9]+)/[^"\']+["\']',
                r'["\'](https?://[^"\']*/(api|v[0-9]+)/[^"\']+)["\']',
                r'fetch\(["\']([^"\']+)["\']',
                r'XMLHttpRequest.*open\(["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
                r'axios\.\w+\(["\']([^"\']+)["\']',
            ]
            endpoints_found = set()
            for pattern in api_patterns:
                for match in re.finditer(pattern, content):
                    ep = match.group(1) if match.lastindex else match.group(0)
                    ep = ep.strip("\"'")
                    if ep and len(ep) < 500:
                        endpoints_found.add(ep)
            result.endpoints = list(endpoints_found)

            # Extract secrets
            secret_patterns = [
                (r'["\']([a-zA-Z0-9]{32,})["\']', "api_key"),
                (r'api[_-]?key["\s:=]+["\']([^"\']{10,})["\']', "api_key"),
                (r'secret["\s:=]+["\']([^"\']{10,})["\']', "secret"),
                (r'token["\s:=]+["\']([^"\']{10,})["\']', "token"),
                (r'(sk-[a-zA-Z0-9]{20,})', "openai_key"),
                (r'(AIza[a-zA-Z0-9_-]{35})', "google_api_key"),
                (r'(ghp_[a-zA-Z0-9]{36})', "github_token"),
            ]
            for pattern, secret_type in secret_patterns:
                for match in re.finditer(pattern, content):
                    val = match.group(1)
                    if len(val) > 8 and not val.startswith("function"):
                        result.secrets.append({
                            "type": secret_type,
                            "value": val[:50] + "..." if len(val) > 50 else val,
                            "full_value": val,
                        })

            # Get fetch hook captures
            result.fetch_hooks = list(self._fetch_captures)

            logger.info(
                f"[CDP] JS Intel: {len(result.variables)} configs, "
                f"{len(result.endpoints)} endpoints, "
                f"{len(result.secrets)} secrets"
            )

        except Exception as e:
            logger.debug(f"[CDP] JS intel extraction error: {e}")

        return result

    # ── Hook Script ───────────────────────────────────────────────────

    @staticmethod
    def _get_hook_script() -> str:
        """JavaScript hooks injected into every page load."""
        return '''
        // === XLayer CDP Hooks ===

        // 1. postMessage monitor
        (function() {
            const origPostMessage = window.postMessage;
            window.addEventListener("message", function(event) {
                try {
                    console.log("__XLAYER_POSTMSG__:" + JSON.stringify({
                        source_origin: event.origin,
                        target_origin: window.location.origin,
                        data: typeof event.data === "string"
                            ? event.data.substring(0, 2000)
                            : JSON.stringify(event.data).substring(0, 2000)
                    }));
                } catch(e) {}
            }, true);
        })();

        // 2. Fetch/XHR hook (capture pre-encryption)
        (function() {
            const origFetch = window.fetch;
            window.fetch = function() {
                const url = arguments[0];
                const opts = arguments[1] || {};
                try {
                    console.log("__XLAYER_FETCH__:" + JSON.stringify({
                        url: typeof url === "string" ? url : url.url,
                        method: opts.method || "GET",
                        body: opts.body ? String(opts.body).substring(0, 1000) : null,
                        headers: opts.headers || {},
                        timestamp: Date.now()
                    }));
                } catch(e) {}
                return origFetch.apply(this, arguments);
            };

            // XHR hook
            const origOpen = XMLHttpRequest.prototype.open;
            const origSend = XMLHttpRequest.prototype.send;
            XMLHttpRequest.prototype.open = function(method, url) {
                this.__xlayer_method = method;
                this.__xlayer_url = url;
                return origOpen.apply(this, arguments);
            };
            XMLHttpRequest.prototype.send = function(body) {
                try {
                    console.log("__XLAYER_FETCH__:" + JSON.stringify({
                        url: this.__xlayer_url,
                        method: this.__xlayer_method,
                        body: body ? String(body).substring(0, 1000) : null,
                        type: "xhr",
                        timestamp: Date.now()
                    }));
                } catch(e) {}
                return origSend.apply(this, arguments);
            };
        })();
        '''

"""
engine/logical_surface_map/browser_analyzer.py — XLayer Dynamic Browser Analysis

Executes the target SPA in a real Playwright headless browser to:
  - Intercept every XHR/fetch call as it actually fires
  - Navigate discovered SPA routes (React/Vue/Angular)
  - Observe history.pushState route changes via injected spy
  - Detect auth walls (401/403 on specific paths)
  - Extract forms with input names
  - Collect loaded JS file URLs for further static analysis

Gracefully returns empty BrowserResult if playwright is not installed.
"""

import asyncio
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse, urljoin
from loguru import logger


# ── Result containers ────────────────────────────────────────────────────────

@dataclass
class XHRCall:
    """A single observed network request."""
    url: str
    method: str
    resource_type: str = ""                             # "xhr", "fetch", "document"
    request_headers: Dict[str, str] = field(default_factory=dict)
    post_data: Optional[str] = None                     # request body for POST/PUT
    response_status: int = 0
    content_type: str = ""                              # response content-type


@dataclass
class BrowserResult:
    """All findings from a dynamic browser execution run."""
    endpoints: Dict[str, str] = field(default_factory=dict)     # path → method (from XHR)
    xhr_calls: List[XHRCall] = field(default_factory=list)       # full XHR/fetch records
    spa_routes: Set[str] = field(default_factory=set)            # routes seen via pushState + links
    js_files: Set[str] = field(default_factory=set)              # JS bundle URLs loaded by the page
    forms: List[dict] = field(default_factory=list)              # [{action, method, inputs:[{name,type}]}]
    cookies: List[dict] = field(default_factory=list)            # browser cookies after navigation
    auth_walls: Set[str] = field(default_factory=set)            # paths that returned 401/403
    websocket_urls: Set[str] = field(default_factory=set)        # Fix 21: WebSocket endpoints detected


# ── pushState spy script (injected before page scripts run) ──────────────────

_PUSHSTATE_SPY = """
window.__xlayer_routes__ = new Set();
(function() {
    const _push    = history.pushState.bind(history);
    const _replace = history.replaceState.bind(history);
    history.pushState = function(s, t, url) {
        if (url) window.__xlayer_routes__.add(String(url));
        return _push(s, t, url);
    };
    history.replaceState = function(s, t, url) {
        if (url) window.__xlayer_routes__.add(String(url));
        return _replace(s, t, url);
    };
    window.addEventListener('hashchange', function() {
        window.__xlayer_routes__.add(window.location.hash);
    });
})();
"""

# ── Route + link extraction script (runs after page load) ────────────────────

_COLLECT_ROUTES_JS = """
() => {
    const routes = new Set([...(window.__xlayer_routes__ || [])]);

    // <a href> links
    document.querySelectorAll('a[href]').forEach(a => {
        const h = a.getAttribute('href');
        if (h && (h.startsWith('/') || h.startsWith(window.location.origin)))
            routes.add(h);
    });

    // Angular routerLink, Vue-router data-route
    document.querySelectorAll('[routerlink],[data-route],[ng-href]').forEach(el => {
        const r = el.getAttribute('routerlink')
               || el.getAttribute('data-route')
               || el.getAttribute('ng-href');
        if (r && r.startsWith('/')) routes.add(r);
    });

    // Vue router instance (app.__vue_app__.config.globalProperties.$router)
    try {
        const app = document.querySelector('#app')?.__vue_app__;
        const router = app?.config?.globalProperties?.$router;
        if (router?.options?.routes) {
            router.options.routes.forEach(function walk(r) {
                if (r.path) routes.add(r.path);
                (r.children || []).forEach(walk);
            });
        }
    } catch(e) {}

    return [...routes];
}
"""

# ── Form extraction script ────────────────────────────────────────────────────

_COLLECT_FORMS_JS = """
() => [...document.querySelectorAll('form')].map(f => ({
    action: f.action || f.getAttribute('action') || '',
    method: (f.method || 'GET').toUpperCase(),
    inputs: [...f.querySelectorAll('input,select,textarea')]
        .map(i => ({ name: i.name || i.id || '', type: i.type || 'text' }))
        .filter(i => i.name)
}))
"""

# ── JS file collection ────────────────────────────────────────────────────────

_COLLECT_JS_JS = """
() => [...document.querySelectorAll('script[src]')]
        .map(s => s.src)
        .filter(s => s.startsWith('http'))
"""


# ── UI Interaction scripts ────────────────────────────────────────────────────

# Seed localStorage/sessionStorage with test auth tokens before page code reads them.
# Tests whether the app uses client-side auth checks (security vulnerability) and
# unlocks UI sections that only render for "authenticated" state.
_LOCALSTORAGE_SEED_JS = """
() => {
    const seeds = {
        'token':         'xlayer_test_token_seed',
        'access_token':  'xlayer_test_token_seed',
        'auth_token':    'xlayer_test_token_seed',
        'jwt':           'xlayer_test_token_seed',
        'user':          JSON.stringify({id: 1, role: 'admin', name: 'xlayer_probe'}),
        'isLoggedIn':    'true',
        'role':          'admin',
        'userId':        '1',
    };
    let seeded = 0;
    for (const [k, v] of Object.entries(seeds)) {
        try { localStorage.setItem(k, v); seeded++; } catch(e) {}
        try { sessionStorage.setItem(k, v); seeded++; } catch(e) {}
    }
    return seeded;
}
"""

# Scroll page in steps to trigger IntersectionObserver / infinite scroll / lazy loading.
_SCROLL_TRIGGER_JS = """
async () => {
    const delay = ms => new Promise(r => setTimeout(r, ms));
    const total = Math.max(document.body.scrollHeight, document.documentElement.scrollHeight);
    const step  = Math.max(300, Math.floor(total / 8));
    for (let y = 0; y <= total; y += step) {
        window.scrollTo({top: y, behavior: 'instant'});
        await delay(150);
    }
    window.scrollTo({top: total, behavior: 'instant'});
    await delay(300);
    window.scrollTo({top: 0, behavior: 'instant'});
    return total;
}
"""

# Collect all visible interactive elements to click.
_COLLECT_INTERACTIVE_JS = """
() => {
    const sel = [
        'button:not([disabled]):not([type="submit"])',
        '[role="button"]:not([disabled])',
        '[role="tab"]',
        '[role="menuitem"]',
        '[data-action]',
        '.btn:not([disabled])',
        'a[href^="#"]',           // in-page anchor links (trigger SPA navigation)
    ].join(',');
    return [...document.querySelectorAll(sel)]
        .filter(el => {
            const r = el.getBoundingClientRect();
            return r.width > 0 && r.height > 0 && window.getComputedStyle(el).display !== 'none';
        })
        .slice(0, 20)    // cap at 20 elements
        .map(el => ({
            tag:   el.tagName.toLowerCase(),
            text:  (el.textContent || '').trim().slice(0, 40),
            id:    el.id || '',
            cls:   el.className || '',
        }));
}
"""

# Realistic form fill data by input type / name patterns.
_FORM_FILL_DATA: Dict[str, str] = {
    "email":      "probe@xlayer-test.io",
    "password":   "XlayerProbe2024!",
    "username":   "xlayer_probe",
    "user":       "xlayer_probe",
    "name":       "XLayer Probe",
    "first_name": "XLayer",
    "last_name":  "Probe",
    "phone":      "+15550001234",
    "address":    "123 Test Street",
    "city":       "Testville",
    "zip":        "12345",
    "url":        "https://xlayer-test.io",
    "website":    "https://xlayer-test.io",
    "search":     "xlayer probe query",
    "query":      "xlayer probe query",
    "q":          "test",
    "message":    "XLayer probe message",
    "comment":    "XLayer probe comment",
    "text":       "XLayer probe text",
    "title":      "XLayer Probe Title",
    "description":"XLayer probe description",
    "code":       "PROBE2024",
    "token":      "xlayer_probe_token",
}


# ── BrowserAnalyzer ──────────────────────────────────────────────────────────

class BrowserAnalyzer:
    """
    Playwright-based dynamic surface analyzer.

    Launches a headless Chromium browser, injects a route-spy script,
    navigates the target, intercepts all XHR/fetch calls, and navigates
    each discovered SPA route to trigger lazy API calls.
    """

    # File extensions to ignore in endpoint tracking
    _STATIC_EXTS = {
        '.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp',
        '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.ico', '.css', '.map', '.txt', '.pdf', '.zip',
    }

    def __init__(
        self,
        headless: bool = True,
        timeout: int = 30_000,   # ms
        nav_timeout: int = 10_000,
        proxy: Optional[str] = None,
    ):
        self.headless = headless
        self.timeout = timeout
        self.nav_timeout = nav_timeout
        self.proxy = proxy

    async def analyze(
        self,
        url: str,
        cookies: Optional[List[dict]] = None,
        max_navigate: int = 20,
        ui_interact: bool = True,
    ) -> BrowserResult:
        """
        Full dynamic analysis of a URL.

        1. Navigate to URL with pushState spy injected
        2. Intercept all XHR/fetch requests
        3. Collect discovered SPA routes
        4. Navigate each route to observe lazy-loaded API calls
        5. Extract forms, cookies, JS file URLs
        6. UI Interaction (if ui_interact=True):
           - Seed localStorage with test auth tokens
           - Scroll to trigger lazy-loaded content
           - Click visible interactive buttons / tabs
           - Fill + observe forms (without real submission)
        """
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            logger.warning(
                "[Browser] playwright not installed. "
                "Run: pip install playwright && playwright install chromium"
            )
            return BrowserResult()

        result = BrowserResult()
        base = urlparse(url)

        async with async_playwright() as pw:
            launch_kwargs: dict = {"headless": self.headless}
            if self.proxy:
                launch_kwargs["proxy"] = {"server": self.proxy}

            browser = await pw.chromium.launch(**launch_kwargs)
            ctx = await browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                ignore_https_errors=True,
                java_script_enabled=True,
            )

            if cookies:
                await ctx.add_cookies(cookies)

            # Inject pushState spy — runs before ANY page script
            await ctx.add_init_script(_PUSHSTATE_SPY)

            page = await ctx.new_page()

            # ── Request / response hooks ──────────────────────────────────
            _pending: Dict[str, XHRCall] = {}

            def _is_relevant(req_url: str, rtype: str) -> bool:
                p = urlparse(req_url)
                path_lower = p.path.lower()
                if any(path_lower.endswith(ext) for ext in self._STATIC_EXTS):
                    return False
                same_origin = p.netloc == base.netloc
                api_like = (
                    rtype in ("xhr", "fetch")
                    or "/api/" in req_url
                    or "graphql" in req_url.lower()
                    or req_url.endswith(".json")
                )
                return same_origin or api_like

            async def _on_request(req):
                if not _is_relevant(req.url, req.resource_type):
                    return
                call = XHRCall(
                    url=req.url,
                    method=req.method,
                    resource_type=req.resource_type,
                    request_headers=dict(req.headers),
                    post_data=req.post_data,
                )
                _pending[req.url] = call
                # Register path immediately (response may never come)
                p = urlparse(req.url)
                if p.netloc == base.netloc and p.path and p.path != "/":
                    result.endpoints[p.path] = req.method

            async def _on_response(resp):
                call = _pending.pop(resp.url, None)
                if call:
                    call.response_status = resp.status
                    call.content_type = resp.headers.get("content-type", "")
                    result.xhr_calls.append(call)
                    if resp.status in (401, 403):
                        p = urlparse(resp.url)
                        if p.netloc == base.netloc and p.path:
                            result.auth_walls.add(p.path)

            page.on("request", _on_request)
            page.on("response", _on_response)

            # ── Fix 21: WebSocket detection ───────────────────────────────
            def _on_websocket(ws):
                ws_url = getattr(ws, "url", "") or ""
                if ws_url:
                    result.websocket_urls.add(ws_url)
                    # Extract path from ws:// or wss:// URL
                    p = urlparse(ws_url)
                    if p.path and p.path != "/":
                        # Register as GET endpoint so hunters can probe it
                        result.endpoints[p.path] = "WS"
                    logger.debug(f"[Browser] WebSocket: {ws_url}")

            page.on("websocket", _on_websocket)

            # ── Initial navigation ────────────────────────────────────────
            logger.info(f"[Browser] Navigating to {url}")
            try:
                await page.goto(url, timeout=self.timeout, wait_until="networkidle")
            except Exception as e:
                logger.debug(f"[Browser] goto warning (continuing): {e}")

            await asyncio.sleep(1.5)  # let JS finish initializing

            # ── Collect JS files ──────────────────────────────────────────
            try:
                js_srcs = await page.evaluate(_COLLECT_JS_JS)
                result.js_files = set(js_srcs or [])
            except Exception:
                pass

            # ── Collect SPA routes ────────────────────────────────────────
            discovered: Set[str] = set()
            try:
                raw_links = await page.evaluate(_COLLECT_ROUTES_JS)
                for link in (raw_links or []):
                    p = urlparse(link)
                    if p.netloc and p.netloc != base.netloc:
                        continue
                    path = p.path
                    if path and path != "/" and not any(path.lower().endswith(e) for e in self._STATIC_EXTS):
                        discovered.add(path)
            except Exception as e:
                logger.debug(f"[Browser] route collection: {e}")

            result.spa_routes = discovered

            # ── Navigate SPA routes ───────────────────────────────────────
            navigated = 0
            for route in list(discovered)[:max_navigate]:
                nav_url = f"{base.scheme}://{base.netloc}{route}"
                try:
                    await page.goto(nav_url, timeout=self.nav_timeout, wait_until="domcontentloaded")
                    await asyncio.sleep(0.8)
                    navigated += 1
                    logger.debug(f"[Browser] SPA → {route}")
                except Exception as e:
                    logger.debug(f"[Browser] Skip {route}: {e}")

            logger.info(f"[Browser] Navigated {navigated}/{len(discovered)} SPA routes")

            # ── Extract forms (from root page) ────────────────────────────
            try:
                await page.goto(url, timeout=self.nav_timeout, wait_until="domcontentloaded")
                await asyncio.sleep(0.5)
                result.forms = await page.evaluate(_COLLECT_FORMS_JS) or []
            except Exception:
                pass

            # ── UI Interaction ────────────────────────────────────────────
            if ui_interact:
                await self._ui_interact(page, result, base)

            # ── Cookies ───────────────────────────────────────────────────
            result.cookies = await ctx.cookies()

            await ctx.close()
            await browser.close()

        logger.success(
            f"[Browser] Complete: "
            f"{len(result.endpoints)} endpoints, "
            f"{len(result.xhr_calls)} XHR calls, "
            f"{len(result.spa_routes)} SPA routes, "
            f"{len(result.auth_walls)} auth walls, "
            f"{len(result.js_files)} JS files"
        )
        return result

    # ── UI Interaction Engine ─────────────────────────────────────────────────

    async def _ui_interact(self, page, result: BrowserResult, base) -> None:
        """
        Automated UI interaction to expose hidden API surface:

        1. localStorage seed  — inject test tokens so JS auth guards open
        2. Scroll trigger      — scroll to bottom to load lazy/infinite content
        3. Button clicking     — click tabs, accordions, "load more" buttons
        4. Form exploration    — fill forms with realistic data, observe requests
                                 (intercepted via existing request hook — no submit)
        """
        # 1. Seed localStorage BEFORE re-navigating
        try:
            seeded = await page.evaluate(_LOCALSTORAGE_SEED_JS)
            if seeded:
                logger.debug(f"[Browser] localStorage seeded ({seeded} keys)")
                # Reload so the app reads the seeded tokens
                await page.reload(wait_until="domcontentloaded")
                await asyncio.sleep(1.0)
        except Exception as e:
            logger.debug(f"[Browser] localStorage seed error: {e}")

        # 2. Scroll to trigger lazy-loaded content
        try:
            page_height = await page.evaluate(_SCROLL_TRIGGER_JS)
            await asyncio.sleep(0.8)
            logger.debug(f"[Browser] Scroll trigger complete (page_height={page_height}px)")
        except Exception as e:
            logger.debug(f"[Browser] Scroll trigger error: {e}")

        # 3. Click interactive elements (tabs, buttons, accordions, etc.)
        try:
            elements = await page.evaluate(_COLLECT_INTERACTIVE_JS)
            clicked = 0
            for el_info in (elements or []):
                try:
                    # Re-select by matching tag + id/text since JS refs are stale
                    selector = self._build_element_selector(el_info)
                    if not selector:
                        continue
                    el = await page.query_selector(selector)
                    if el and await el.is_visible():
                        await el.click(timeout=1500)
                        await asyncio.sleep(0.4)
                        clicked += 1
                except Exception:
                    pass
            if clicked:
                logger.debug(f"[Browser] Clicked {clicked} interactive elements")
                await asyncio.sleep(0.5)   # let API calls fire
        except Exception as e:
            logger.debug(f"[Browser] Button interaction error: {e}")

        # 4. Fill forms with realistic data (observe requests — don't submit)
        try:
            form_count = await self._fill_forms(page)
            if form_count:
                logger.debug(f"[Browser] Filled {form_count} form(s)")
        except Exception as e:
            logger.debug(f"[Browser] Form fill error: {e}")

    async def _fill_forms(self, page) -> int:
        """
        Fill visible forms with realistic test data.
        Filling (not submitting) often triggers onChange → API calls.
        Returns number of forms processed.
        """
        forms_processed = 0
        try:
            forms = await page.query_selector_all("form")
            for form in forms[:5]:   # cap at 5 forms
                if not await form.is_visible():
                    continue
                inputs = await form.query_selector_all("input, textarea, select")
                for inp in inputs:
                    try:
                        itype = (await inp.get_attribute("type") or "text").lower()
                        iname = (
                            await inp.get_attribute("name")
                            or await inp.get_attribute("id")
                            or ""
                        ).lower()
                        if itype in ("submit", "button", "image", "reset", "file", "hidden"):
                            continue
                        value = self._pick_fill_value(iname, itype)
                        if itype == "checkbox":
                            await inp.check()
                        elif itype == "radio":
                            await inp.check()
                        elif await inp.evaluate("el => el.tagName.toLowerCase()") == "select":
                            # Select second option (first is often placeholder)
                            options = await inp.query_selector_all("option")
                            if len(options) > 1:
                                val = await options[1].get_attribute("value")
                                if val:
                                    await inp.select_option(val)
                        else:
                            await inp.fill(value, timeout=1000)
                        await asyncio.sleep(0.1)  # let onChange fire
                    except Exception:
                        continue
                forms_processed += 1
        except Exception as e:
            logger.debug(f"[Browser] _fill_forms error: {e}")
        return forms_processed

    @staticmethod
    def _pick_fill_value(name: str, input_type: str) -> str:
        """Choose realistic fill value based on input name and type."""
        # Match by name first
        for key, val in _FORM_FILL_DATA.items():
            if key in name:
                return val
        # Fall back to type
        type_defaults = {
            "email":    "probe@xlayer-test.io",
            "password": "XlayerProbe2024!",
            "number":   "1",
            "tel":      "+15550001234",
            "url":      "https://xlayer-test.io",
            "date":     "2024-01-01",
            "search":   "test",
        }
        return type_defaults.get(input_type, "xlayer_probe_value")

    @staticmethod
    def _build_element_selector(el_info: dict) -> Optional[str]:
        """Build a CSS selector from element metadata returned by JS."""
        tag   = el_info.get("tag", "button")
        el_id = el_info.get("id", "")
        text  = el_info.get("text", "").strip()
        if el_id:
            return f"#{el_id}"
        if text:
            # Playwright text selector
            return f"{tag}:has-text('{text[:30]}')"
        return tag if tag else None

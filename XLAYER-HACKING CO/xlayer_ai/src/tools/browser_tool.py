"""
Browser Tools — Steerable Browser for Solver Agents

Two tools:
1. browser_interact — navigate, execute JS, get cookies/DOM, intercept requests
2. victim_browser  — simulate victim visiting attacker URL (XSS proof validation)

Uses Playwright (same dependency as BrowserAnalyzer in LSM).
Lazy-init module-level browser instance, reused across calls.
"""

import asyncio
import json
from typing import Optional

from loguru import logger

from xlayer_ai.engine.tool import tool, Tool


# ── Lazy browser singleton ────────────────────────────────────────────────

_BROWSER = None
_PLAYWRIGHT = None


async def _get_browser():
    """Lazy-init Playwright Chromium browser, reuse across calls."""
    global _BROWSER, _PLAYWRIGHT

    if _BROWSER and _BROWSER.is_connected():
        return _BROWSER

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        logger.warning(
            "[BrowserTool] playwright not installed. "
            "Run: pip install playwright && playwright install chromium"
        )
        return None

    _PLAYWRIGHT = await async_playwright().__aenter__()
    _BROWSER = await _PLAYWRIGHT.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    logger.info("[BrowserTool] Chromium browser launched (headless)")
    return _BROWSER


# ── browser_interact Tool ─────────────────────────────────────────────────

@tool
def browser_interact(
    url: str,
    action: str = "navigate",
    js_code: str = "",
    wait_for: str = "",
    timeout: str = "15",
) -> str:
    """
    Interact with a headless Chromium browser. Use for DOM XSS testing,
    JavaScript execution, cookie extraction, and request interception.

    Args:
        url: URL to navigate to (required for navigate action)
        action: Action to perform: navigate, execute_js, get_cookies, get_dom, intercept_requests
        js_code: JavaScript code to execute (for execute_js action)
        wait_for: CSS selector to wait for after navigation
        timeout: Page load timeout in seconds
    """

    async def _run():
        browser = await _get_browser()
        if not browser:
            return {"error": "playwright not available"}

        req_timeout = int(timeout) if timeout else 15
        page = await browser.new_page()

        try:
            if action == "navigate":
                response = await page.goto(
                    url, timeout=req_timeout * 1000, wait_until="domcontentloaded"
                )
                if wait_for:
                    await page.wait_for_selector(wait_for, timeout=5000)

                return {
                    "action": "navigate",
                    "url": str(page.url),
                    "status": response.status if response else 0,
                    "title": await page.title(),
                    "body_snippet": (await page.content())[:3000],
                    "cookies": await page.context.cookies(),
                }

            elif action == "execute_js":
                if not js_code:
                    return {"error": "js_code required for execute_js action"}

                # Navigate first if URL provided
                await page.goto(
                    url, timeout=req_timeout * 1000, wait_until="domcontentloaded"
                )

                result = await page.evaluate(js_code)
                return {
                    "action": "execute_js",
                    "url": str(page.url),
                    "js_result": str(result)[:3000] if result else None,
                }

            elif action == "get_cookies":
                await page.goto(
                    url, timeout=req_timeout * 1000, wait_until="domcontentloaded"
                )
                cookies = await page.context.cookies()
                return {
                    "action": "get_cookies",
                    "url": str(page.url),
                    "cookies": cookies,
                }

            elif action == "get_dom":
                await page.goto(
                    url, timeout=req_timeout * 1000, wait_until="domcontentloaded"
                )
                dom = await page.content()
                return {
                    "action": "get_dom",
                    "url": str(page.url),
                    "dom": dom[:5000],
                    "dom_length": len(dom),
                }

            elif action == "intercept_requests":
                captured = []

                async def _on_request(request):
                    captured.append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    })

                page.on("request", _on_request)
                await page.goto(
                    url, timeout=req_timeout * 1000, wait_until="networkidle"
                )
                # Wait a bit for async requests
                await asyncio.sleep(2)

                return {
                    "action": "intercept_requests",
                    "url": str(page.url),
                    "requests_captured": len(captured),
                    "requests": captured[:50],
                }

            else:
                return {"error": f"unknown action: {action}"}

        except Exception as e:
            return {"error": str(e), "action": action, "url": url}
        finally:
            await page.close()

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _run())
                result = future.result(timeout=30)
        else:
            result = loop.run_until_complete(_run())
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "action": action})


# ── victim_browser Tool ───────────────────────────────────────────────────

@tool
def victim_browser(
    attacker_url: str,
    victim_cookies: str = "",
    origin_url: str = "",
    timeout: str = "15",
) -> str:
    """
    Simulate a victim visiting an attacker-controlled URL (XSS proof).
    Opens a fresh isolated browser context with victim cookies set,
    navigates to the attacker URL, and monitors for JS execution,
    external requests, cookie exfiltration, and DOM mutations.

    Args:
        attacker_url: The attacker's URL the victim visits
        victim_cookies: JSON string of victim cookies like {"session": "abc123"}
        origin_url: Origin URL to set cookies on (e.g. https://target.com)
        timeout: How long to wait for attack to trigger in seconds
    """

    async def _run():
        browser = await _get_browser()
        if not browser:
            return {"error": "playwright not available"}

        req_timeout = int(timeout) if timeout else 15

        # Fresh isolated context (separate from browser_interact)
        context = await browser.new_context()

        # Set victim cookies if provided
        if victim_cookies:
            try:
                cookies_dict = json.loads(victim_cookies)
                cookie_url = origin_url or attacker_url
                cookie_list = []
                for name, value in cookies_dict.items():
                    cookie_list.append({
                        "name": name,
                        "value": str(value),
                        "url": cookie_url,
                    })
                if cookie_list:
                    await context.add_cookies(cookie_list)
            except (json.JSONDecodeError, TypeError):
                pass

        page = await context.new_page()

        # Monitor signals
        console_logs = []
        external_requests = []
        cookie_changes = []
        js_errors = []

        page.on("console", lambda msg: console_logs.append({
            "type": msg.type, "text": msg.text[:500],
        }))

        page.on("pageerror", lambda err: js_errors.append(str(err)[:500]))

        async def _on_request(request):
            # Track external requests (different origin)
            from urllib.parse import urlparse
            req_host = urlparse(request.url).hostname
            attacker_host = urlparse(attacker_url).hostname
            if req_host and req_host != attacker_host:
                external_requests.append({
                    "url": request.url[:500],
                    "method": request.method,
                })

        page.on("request", _on_request)

        try:
            await page.goto(
                attacker_url,
                timeout=req_timeout * 1000,
                wait_until="domcontentloaded",
            )

            # Wait for attack payloads to trigger
            await asyncio.sleep(min(req_timeout, 5))

            # Check cookies after visit
            post_cookies = await context.cookies()
            initial_cookies = json.loads(victim_cookies) if victim_cookies else {}
            for c in post_cookies:
                if c["name"] not in initial_cookies:
                    cookie_changes.append({
                        "name": c["name"],
                        "value": c["value"][:100],
                        "domain": c.get("domain", ""),
                        "change": "added",
                    })

            dom_snippet = (await page.content())[:2000]

            return {
                "attacker_url": attacker_url,
                "js_executed": len(console_logs) > 0 or len(js_errors) > 0,
                "console_logs": console_logs[:20],
                "js_errors": js_errors[:10],
                "external_requests": external_requests[:20],
                "cookies_sent": len(external_requests) > 0,
                "cookie_changes": cookie_changes,
                "dom_snippet": dom_snippet,
                "page_title": await page.title(),
            }

        except Exception as e:
            return {"error": str(e), "attacker_url": attacker_url}
        finally:
            await page.close()
            await context.close()

    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, _run())
                result = future.result(timeout=30)
        else:
            result = loop.run_until_complete(_run())
        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e), "attacker_url": attacker_url})


# ── Export ─────────────────────────────────────────────────────────────────

BROWSER_TOOLS: list[Tool] = [
    browser_interact,
    victim_browser,
]

"""
XLayer AI Headless Browser - Playwright-based browser automation for exploitation
"""

import asyncio
import base64
import json
from typing import Optional, Dict, Any, List, Callable
from dataclasses import dataclass, field
from datetime import datetime

from loguru import logger

try:
    from playwright.async_api import async_playwright, Browser, Page, BrowserContext
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    logger.warning("Playwright not installed. Browser exploitation will be disabled.")


@dataclass
class BrowserResult:
    """Result of browser-based exploitation"""
    success: bool
    url: str
    payload: str
    
    screenshot_base64: Optional[str] = None
    console_logs: List[str] = field(default_factory=list)
    network_requests: List[Dict[str, Any]] = field(default_factory=list)
    
    js_result: Optional[Any] = None
    alert_triggered: bool = False
    cookies_accessed: bool = False
    dom_modified: bool = False
    
    error: Optional[str] = None
    execution_time_ms: float = 0.0


@dataclass
class ExploitConfig:
    """Configuration for exploit execution"""
    timeout: int = 30000
    wait_for_network: bool = True
    capture_screenshot: bool = True
    capture_console: bool = True
    capture_network: bool = True
    headless: bool = True


class HeadlessBrowser:
    """
    Headless browser for real exploit verification
    
    Uses Playwright (Chromium) for actual JavaScript execution
    and DOM manipulation verification.
    """
    
    def __init__(self, config: Optional[ExploitConfig] = None):
        if not PLAYWRIGHT_AVAILABLE:
            raise RuntimeError("Playwright is required for browser exploitation")
        
        self.config = config or ExploitConfig()
        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
    
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def start(self):
        """Initialize the browser"""
        if self._browser is not None:
            return

        self._playwright = await async_playwright().start()

        try:
            self._browser = await self._playwright.chromium.launch(
                headless=self.config.headless
            )
        except Exception as e:
            error_msg = str(e)
            if "Executable doesn't exist" in error_msg or "browserType.launch" in error_msg:
                logger.error(
                    "Playwright browsers not installed. "
                    "Run 'python -m playwright install chromium' to install."
                )
                await self._playwright.stop()
                self._playwright = None
                raise RuntimeError(
                    "Playwright Chromium not installed. "
                    "Run: python -m playwright install chromium"
                ) from e
            raise

        self._context = await self._browser.new_context(
            ignore_https_errors=True,
            java_script_enabled=True
        )
        logger.debug("Headless browser started")
    
    async def close(self):
        """Close the browser"""
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None
        logger.debug("Headless browser closed")
    
    async def execute_xss(
        self,
        url: str,
        payload: str,
        parameter: Optional[str] = None
    ) -> BrowserResult:
        """
        Execute XSS payload and verify JavaScript execution
        
        Args:
            url: Target URL (with payload already injected or to inject)
            payload: XSS payload
            parameter: Parameter name if payload needs injection
            
        Returns:
            BrowserResult with exploitation details
        """
        import time
        start_time = time.time()
        
        if self._context is None:
            await self.start()
        
        page = await self._context.new_page()
        
        console_logs = []
        network_requests = []
        alert_triggered = False
        
        if self.config.capture_console:
            page.on("console", lambda msg: console_logs.append(f"{msg.type}: {msg.text}"))
        
        if self.config.capture_network:
            page.on("request", lambda req: network_requests.append({
                "url": req.url,
                "method": req.method
            }))
        
        async def handle_dialog(dialog):
            nonlocal alert_triggered
            alert_triggered = True
            console_logs.append(f"ALERT: {dialog.message}")
            await dialog.dismiss()
        
        page.on("dialog", handle_dialog)
        
        try:
            if parameter:
                if "?" in url:
                    target_url = f"{url}&{parameter}={payload}"
                else:
                    target_url = f"{url}?{parameter}={payload}"
            else:
                target_url = url
            
            await page.goto(target_url, timeout=self.config.timeout)
            
            if self.config.wait_for_network:
                await page.wait_for_load_state("networkidle", timeout=5000)
            
            await asyncio.sleep(1)
            
            js_result = None
            try:
                js_result = await page.evaluate("() => window.__xlayer_xss_triggered || false")
            except Exception:
                pass
            
            screenshot_base64 = None
            if self.config.capture_screenshot:
                screenshot = await page.screenshot(full_page=True)
                screenshot_base64 = base64.b64encode(screenshot).decode()
            
            execution_time = (time.time() - start_time) * 1000
            
            success = alert_triggered or any("xlayer" in log.lower() for log in console_logs)
            
            return BrowserResult(
                success=success,
                url=target_url,
                payload=payload,
                screenshot_base64=screenshot_base64,
                console_logs=console_logs,
                network_requests=network_requests,
                js_result=js_result,
                alert_triggered=alert_triggered,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return BrowserResult(
                success=False,
                url=url,
                payload=payload,
                error=str(e),
                execution_time_ms=execution_time
            )
        finally:
            await page.close()
    
    async def execute_sqli(
        self,
        url: str,
        payload: str,
        parameter: str,
        method: str = "GET",
        expected_patterns: Optional[List[str]] = None
    ) -> BrowserResult:
        """
        Execute SQL injection payload and analyze response
        
        Args:
            url: Target URL
            payload: SQLi payload
            parameter: Vulnerable parameter
            method: HTTP method
            expected_patterns: Patterns indicating successful injection
            
        Returns:
            BrowserResult with exploitation details
        """
        import time
        start_time = time.time()
        
        if self._context is None:
            await self.start()
        
        page = await self._context.new_page()
        
        network_requests = []
        responses = []
        
        async def capture_response(response):
            try:
                body = await response.text()
                responses.append({
                    "url": response.url,
                    "status": response.status,
                    "body_preview": body[:500]
                })
            except Exception:
                pass
        
        page.on("response", capture_response)
        
        try:
            if method.upper() == "GET":
                if "?" in url:
                    target_url = f"{url}&{parameter}={payload}"
                else:
                    target_url = f"{url}?{parameter}={payload}"
                await page.goto(target_url, timeout=self.config.timeout)
            else:
                await page.goto(url, timeout=self.config.timeout)
            
            await asyncio.sleep(2)
            
            page_content = await page.content()
            
            success = False
            if expected_patterns:
                for pattern in expected_patterns:
                    if pattern.lower() in page_content.lower():
                        success = True
                        break
            
            sql_error_patterns = [
                "sql syntax",
                "mysql_fetch",
                "ora-",
                "postgresql",
                "sqlite",
                "syntax error",
                "unclosed quotation",
                "quoted string not properly terminated"
            ]
            
            for pattern in sql_error_patterns:
                if pattern in page_content.lower():
                    success = True
                    break
            
            screenshot_base64 = None
            if self.config.capture_screenshot:
                screenshot = await page.screenshot(full_page=True)
                screenshot_base64 = base64.b64encode(screenshot).decode()
            
            execution_time = (time.time() - start_time) * 1000
            
            return BrowserResult(
                success=success,
                url=target_url if method.upper() == "GET" else url,
                payload=payload,
                screenshot_base64=screenshot_base64,
                network_requests=network_requests,
                js_result={"responses": responses, "content_length": len(page_content)},
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return BrowserResult(
                success=False,
                url=url,
                payload=payload,
                error=str(e),
                execution_time_ms=execution_time
            )
        finally:
            await page.close()
    
    async def capture_evidence(
        self,
        url: str,
        actions: Optional[List[Callable]] = None
    ) -> Dict[str, Any]:
        """
        Capture evidence of exploitation
        
        Args:
            url: URL to capture
            actions: Optional list of actions to perform before capture
            
        Returns:
            Dictionary with evidence data
        """
        if self._context is None:
            await self.start()
        
        page = await self._context.new_page()
        
        try:
            await page.goto(url, timeout=self.config.timeout)
            
            if actions:
                for action in actions:
                    await action(page)
            
            screenshot = await page.screenshot(full_page=True)
            content = await page.content()
            cookies = await self._context.cookies()
            
            return {
                "screenshot_base64": base64.b64encode(screenshot).decode(),
                "html_content": content[:10000],
                "cookies": cookies,
                "url": page.url,
                "timestamp": datetime.utcnow().isoformat()
            }
            
        finally:
            await page.close()
    
    async def test_auth_bypass(
        self,
        login_url: str,
        protected_url: str,
        bypass_payload: Dict[str, str]
    ) -> BrowserResult:
        """
        Test authentication bypass
        
        Args:
            login_url: Login page URL
            protected_url: URL that should require auth
            bypass_payload: Payload to attempt bypass
            
        Returns:
            BrowserResult indicating if bypass was successful
        """
        import time
        start_time = time.time()
        
        if self._context is None:
            await self.start()
        
        page = await self._context.new_page()
        
        try:
            await page.goto(protected_url, timeout=self.config.timeout)
            
            initial_url = page.url
            initial_content = await page.content()
            
            if login_url not in initial_url and "login" not in initial_url.lower():
                success = True
            else:
                success = False
            
            screenshot_base64 = None
            if self.config.capture_screenshot:
                screenshot = await page.screenshot(full_page=True)
                screenshot_base64 = base64.b64encode(screenshot).decode()
            
            execution_time = (time.time() - start_time) * 1000
            
            return BrowserResult(
                success=success,
                url=protected_url,
                payload=json.dumps(bypass_payload),
                screenshot_base64=screenshot_base64,
                js_result={"final_url": page.url, "redirected": initial_url != page.url},
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            return BrowserResult(
                success=False,
                url=protected_url,
                payload=json.dumps(bypass_payload),
                error=str(e),
                execution_time_ms=execution_time
            )
        finally:
            await page.close()

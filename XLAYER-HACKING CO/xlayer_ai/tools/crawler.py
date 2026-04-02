"""
XLayer AI Web Crawler - Recursive web crawler for endpoint discovery
Supports both static HTML and JavaScript-rendered pages (SPA support)
"""

import asyncio
import re
import json
from typing import Set, List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, parse_qsl, urlencode, urlunparse
from dataclasses import dataclass, field

from bs4 import BeautifulSoup
from loguru import logger

from xlayer_ai.tools.http_client import HTTPClient, HTTPResponse
from xlayer_ai.models.target import Endpoint, InputParameter, EndpointType, HTTPMethod, InputType

try:
    from playwright.async_api import async_playwright, Browser, BrowserContext, Page
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False


@dataclass
class CrawlResult:
    """Result of web crawling"""
    pages_crawled: int
    endpoints: List[Endpoint]
    forms: List[Endpoint]
    api_endpoints: List[Endpoint]
    external_links: Set[str]
    errors: List[str]
    crawl_time_seconds: float
    js_rendered: bool = False


class WebCrawler:
    """
    Web crawler for discovering endpoints and input vectors

    Features:
    - BFS crawling with depth limit
    - Form extraction
    - API endpoint detection
    - Parameter discovery
    - JavaScript rendering for SPA sites (React/Vue/Angular)
    - Network request interception for hidden API discovery
    """

    def __init__(
        self,
        http_client: HTTPClient,
        max_depth: int = 3,
        max_pages: int = 100,
        respect_robots: bool = True,
        js_rendering: bool = True,
        session_cookies: Optional[Dict[str, str]] = None
    ):
        self.http = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        self.js_rendering = js_rendering and PLAYWRIGHT_AVAILABLE
        self.session_cookies = session_cookies or {}

        self._visited: Set[str] = set()
        self._endpoints: List[Endpoint] = []
        self._forms: List[Endpoint] = []
        self._api_endpoints: List[Endpoint] = []
        self._external: Set[str] = set()
        self._errors: List[str] = []
        self._disallowed: Set[str] = set()
        self._intercepted_apis: Set[str] = set()

        self._playwright = None
        self._browser: Optional[Browser] = None
        self._context: Optional[BrowserContext] = None
    
    async def _start_browser(self):
        """Initialize Playwright browser for JS rendering"""
        if not PLAYWRIGHT_AVAILABLE:
            return
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(headless=True)
        ctx_opts = {"ignore_https_errors": True, "java_script_enabled": True}
        if self.session_cookies:
            self._context = await self._browser.new_context(**ctx_opts)
            cookie_list = [
                {"name": k, "value": v, "domain": self._base_host, "path": "/"}
                for k, v in self.session_cookies.items()
            ]
            await self._context.add_cookies(cookie_list)
        else:
            self._context = await self._browser.new_context(**ctx_opts)
        logger.debug("JS rendering browser started")

    async def _close_browser(self):
        """Close Playwright browser"""
        if self._context:
            await self._context.close()
            self._context = None
        if self._browser:
            await self._browser.close()
            self._browser = None
        if self._playwright:
            await self._playwright.stop()
            self._playwright = None

    async def _render_page(self, url: str) -> Tuple[str, List[str]]:
        """
        Render page with JavaScript and intercept network requests.
        Returns (rendered_html, intercepted_api_urls)
        """
        if self._context is None:
            await self._start_browser()

        page: Page = await self._context.new_page()
        intercepted: List[str] = []

        def on_request(request):
            req_url = request.url
            if any(p in req_url for p in ["/api/", "/v1/", "/v2/", "/graphql", "/rest/"]):
                if self._is_same_domain(req_url):
                    intercepted.append(req_url)

        page.on("request", on_request)

        try:
            await page.goto(url, wait_until="networkidle", timeout=20000)
            await asyncio.sleep(1)
            html = await page.content()
            return html, intercepted
        except Exception as e:
            logger.debug(f"JS render failed for {url}: {e}")
            return "", intercepted
        finally:
            await page.close()

    async def crawl(
        self,
        start_url: str,
        seed_urls: Optional[List[str]] = None
    ) -> CrawlResult:
        """
        Crawl a website starting from the given URL.
        Uses JS rendering if enabled to support SPAs (React/Vue/Angular).

        Args:
            start_url: Starting URL for crawling
            seed_urls: Additional URLs (e.g., sitemap) to seed the queue

        Returns:
            CrawlResult with all discovered endpoints
        """
        import time
        start_time = time.time()

        self._visited.clear()
        self._endpoints.clear()
        self._forms.clear()
        self._api_endpoints.clear()
        self._external.clear()
        self._errors.clear()
        self._intercepted_apis.clear()

        parsed = urlparse(start_url)
        self._base_domain = parsed.netloc
        self._base_host = parsed.hostname or parsed.netloc.split(":")[0]
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"

        if self.respect_robots:
            await self._parse_robots(self._base_url)

        # Detect if site is a SPA on first load
        is_spa = False
        if self.js_rendering:
            try:
                await self._start_browser()
                probe_html, _ = await self._render_page(start_url)
                is_spa = self._detect_spa(probe_html)
                if is_spa:
                    logger.info("SPA detected - using JS rendering for all pages")
                else:
                    logger.info("Static site detected - JS rendering available as fallback")
            except Exception as e:
                logger.warning(f"Could not start JS rendering: {e}")
                self.js_rendering = False

        queue: List[Tuple[str, int]] = [(start_url, 0)]
        for seed in (seed_urls or [])[:200]:
            if not seed:
                continue
            full_seed = urljoin(self._base_url, seed)
            if self._is_same_domain(full_seed):
                queue.append((full_seed, 0))

        try:
            while queue and len(self._visited) < self.max_pages:
                url, depth = queue.pop(0)
                canonical_url = self._canonicalize_url(url)

                if canonical_url in self._visited:
                    continue
                if depth > self.max_depth:
                    continue
                if self._is_disallowed(canonical_url):
                    continue

                self._visited.add(canonical_url)
                logger.debug(f"Crawling: {url} (depth={depth}, js={self.js_rendering})")

                # JS rendering path
                if self.js_rendering:
                    html, intercepted = await self._render_page(url)
                    for api_url in intercepted:
                        api_key = self._canonicalize_url(api_url)
                        if api_key not in self._intercepted_apis:
                            self._intercepted_apis.add(api_key)
                            self._api_endpoints.append(Endpoint(
                                url=api_url.split("?")[0],
                                endpoint_type=EndpointType.API,
                                parameters=self._extract_url_params(api_url)
                            ))

                    if html:
                        fake_response = HTTPResponse(
                            url=url, status=200, headers={"content-type": "text/html"},
                            body=html, cookies={}, elapsed_ms=0
                        )
                        new_urls = await self._process_page(url, fake_response, depth)
                        for new_url in new_urls:
                            if self._canonicalize_url(new_url) not in self._visited:
                                queue.append((new_url, depth + 1))
                        continue

                # Static fallback path
                response = await self.http.get(url)
                if response.error:
                    self._errors.append(f"{url}: {response.error}")
                    continue
                if not response.is_success:
                    continue
                content_type = response.content_type
                if content_type and "html" not in content_type:
                    continue

                new_urls = await self._process_page(url, response, depth)
                for new_url in new_urls:
                    if self._canonicalize_url(new_url) not in self._visited:
                        queue.append((new_url, depth + 1))
        finally:
            if self.js_rendering:
                await self._close_browser()

        self._endpoints = self._deduplicate_endpoints(self._endpoints)
        self._forms = self._deduplicate_endpoints(self._forms)
        self._api_endpoints = self._deduplicate_endpoints(self._api_endpoints)

        crawl_time = time.time() - start_time

        logger.info(
            f"Crawl complete: {len(self._visited)} pages, "
            f"{len(self._endpoints)} endpoints, "
            f"{len(self._forms)} forms, "
            f"{len(self._api_endpoints)} API endpoints in {crawl_time:.2f}s"
        )

        return CrawlResult(
            pages_crawled=len(self._visited),
            endpoints=self._endpoints,
            forms=self._forms,
            api_endpoints=self._api_endpoints,
            external_links=self._external,
            errors=self._errors,
            crawl_time_seconds=crawl_time,
            js_rendered=self.js_rendering
        )

    def _detect_spa(self, html: str) -> bool:
        """Detect if page is a Single Page Application"""
        spa_indicators = [
            'id="root"', "id='root'",
            'id="app"', "id='app'",
            "__next_data__",
            "ng-version",
            "data-reactroot",
            "__vue__",
            "nuxt",
        ]
        html_lower = html.lower()
        matches = sum(1 for indicator in spa_indicators if indicator.lower() in html_lower)
        # Also check if body has very little static content
        soup = BeautifulSoup(html, "html.parser")
        text_content = soup.get_text(strip=True)
        is_empty_body = len(text_content) < 200
        return matches >= 1 or is_empty_body
    
    async def _process_page(
        self,
        url: str,
        response: HTTPResponse,
        depth: int
    ) -> List[str]:
        """Process a single page and extract links/forms"""
        new_urls = []
        
        try:
            soup = BeautifulSoup(response.body, "lxml")
        except Exception:
            soup = BeautifulSoup(response.body, "html.parser")
        
        parsed_url = urlparse(url)
        url_params = self._extract_url_params(url)
        
        if url_params:
            endpoint = Endpoint(
                url=url.split("?")[0],
                method=HTTPMethod.GET,
                endpoint_type=EndpointType.PAGE,
                parameters=url_params
            )
            self._endpoints.append(endpoint)
        
        for link in soup.find_all("a", href=True):
            href = link["href"]
            full_url = urljoin(url, href)
            
            if self._is_same_domain(full_url):
                new_urls.append(full_url)
            else:
                self._external.add(full_url)
        
        for form in soup.find_all("form"):
            form_endpoint = self._extract_form(url, form)
            if form_endpoint:
                self._forms.append(form_endpoint)
        
        for script in soup.find_all("script", src=True):
            src = script["src"]
            if "api" in src.lower() or ".json" in src.lower():
                full_url = urljoin(url, src)
                if self._is_same_domain(full_url):
                    self._api_endpoints.append(Endpoint(
                        url=full_url,
                        endpoint_type=EndpointType.API
                    ))
        
        api_patterns = [
            r'/api/[^\s"\'<>]+',
            r'/v\d+/[^\s"\'<>]+',
            r'/graphql[^\s"\'<>]*',
            r'/rest/[^\s"\'<>]+'
        ]
        
        for pattern in api_patterns:
            matches = re.findall(pattern, response.body)
            for match in matches:
                full_url = urljoin(url, match)
                if self._is_same_domain(full_url):
                    self._api_endpoints.append(Endpoint(
                        url=full_url,
                        endpoint_type=EndpointType.API
                    ))
        
        return new_urls
    
    def _extract_form(self, page_url: str, form) -> Optional[Endpoint]:
        """Extract form as endpoint with parameters"""
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        
        form_url = urljoin(page_url, action) if action else page_url
        
        parameters = []
        
        for input_elem in form.find_all(["input", "textarea", "select"]):
            name = input_elem.get("name")
            if not name:
                continue
            
            input_type = input_elem.get("type", "text")
            value = input_elem.get("value", "")
            required = input_elem.has_attr("required")
            
            validation_hints = []
            if input_elem.get("pattern"):
                validation_hints.append(f"pattern:{input_elem['pattern']}")
            if input_elem.get("maxlength"):
                validation_hints.append(f"maxlength:{input_elem['maxlength']}")
            if input_elem.get("minlength"):
                validation_hints.append(f"minlength:{input_elem['minlength']}")
            
            param = InputParameter(
                name=name,
                input_type=InputType.FORM_FIELD,
                sample_value=value,
                required=required,
                validation_hints=validation_hints
            )
            parameters.append(param)
        
        if not parameters:
            return None
        
        endpoint_type = EndpointType.FORM
        if any(n in form_url.lower() for n in ["login", "signin", "auth"]):
            endpoint_type = EndpointType.AUTH
        
        return Endpoint(
            url=form_url,
            method=HTTPMethod(method) if method in ["GET", "POST"] else HTTPMethod.POST,
            endpoint_type=endpoint_type,
            parameters=parameters
        )
    
    def _extract_url_params(self, url: str) -> List[InputParameter]:
        """Extract URL parameters as input parameters"""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        result = []
        for name, values in params.items():
            param = InputParameter(
                name=name,
                input_type=InputType.URL_PARAM,
                sample_value=values[0] if values else None
            )
            result.append(param)
        
        return result

    def _canonicalize_url(self, url: str) -> str:
        """Canonical URL form for deduplication (keeps semantic query values)."""
        parsed = urlparse(url)
        path = parsed.path or "/"
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
        normalized_query = urlencode(sorted(query_pairs))
        return urlunparse((
            parsed.scheme.lower(),
            parsed.netloc.lower(),
            path,
            "",
            normalized_query,
            ""
        ))

    def _endpoint_key(self, endpoint: Endpoint) -> str:
        """Stable dedup key for discovered endpoints."""
        method = endpoint.method.value if hasattr(endpoint.method, "value") else str(endpoint.method)
        endpoint_type = (
            endpoint.endpoint_type.value
            if hasattr(endpoint.endpoint_type, "value")
            else str(endpoint.endpoint_type)
        )
        param_names = ",".join(sorted(p.name for p in endpoint.parameters))
        return f"{method}:{self._canonicalize_url(endpoint.url)}:{endpoint_type}:{param_names}"

    def _deduplicate_endpoints(self, endpoints: List[Endpoint]) -> List[Endpoint]:
        """Remove duplicate endpoint records while preserving insertion order."""
        seen: Set[str] = set()
        unique: List[Endpoint] = []
        for endpoint in endpoints:
            key = self._endpoint_key(endpoint)
            if key in seen:
                continue
            seen.add(key)
            unique.append(endpoint)
        return unique
    
    def _is_same_domain(self, url: str) -> bool:
        """Check if URL is on the same domain"""
        try:
            parsed = urlparse(url)
            return parsed.netloc == self._base_domain
        except Exception:
            return False
    
    def _is_disallowed(self, url: str) -> bool:
        """Check if URL is disallowed by robots.txt"""
        if not self._disallowed:
            return False
        
        parsed = urlparse(url)
        path = parsed.path
        
        for pattern in self._disallowed:
            if path.startswith(pattern):
                return True
        
        return False
    
    async def _parse_robots(self, base_url: str):
        """Parse robots.txt for disallowed paths"""
        robots_url = f"{base_url}/robots.txt"
        
        try:
            response = await self.http.get(robots_url)
            if response.is_success:
                lines = response.body.split("\n")
                user_agent_match = False
                
                for line in lines:
                    line = line.strip().lower()
                    
                    if line.startswith("user-agent:"):
                        agent = line.split(":", 1)[1].strip()
                        user_agent_match = agent == "*" or "xlayer" in agent
                    
                    elif user_agent_match and line.startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            self._disallowed.add(path)
                
                logger.debug(f"Loaded {len(self._disallowed)} disallowed paths from robots.txt")
        except Exception as e:
            logger.debug(f"Could not parse robots.txt: {e}")

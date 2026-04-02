"""
XLayer AI Web Crawler - Recursive web crawler for endpoint discovery
"""

import asyncio
import re
from typing import Set, List, Dict, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs
from dataclasses import dataclass, field

from bs4 import BeautifulSoup
from loguru import logger

from xlayer_hunter.tools.http_client import HTTPClient, HTTPResponse
from xlayer_hunter.models.target import Endpoint, InputParameter, EndpointType, HTTPMethod, InputType


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


class WebCrawler:
    """
    Web crawler for discovering endpoints and input vectors
    
    Features:
    - BFS crawling with depth limit
    - Form extraction
    - API endpoint detection
    - Parameter discovery
    """
    
    def __init__(
        self,
        http_client: HTTPClient,
        max_depth: int = 3,
        max_pages: int = 100,
        respect_robots: bool = True
    ):
        self.http = http_client
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.respect_robots = respect_robots
        
        self._visited: Set[str] = set()
        self._endpoints: List[Endpoint] = []
        self._forms: List[Endpoint] = []
        self._api_endpoints: List[Endpoint] = []
        self._external: Set[str] = set()
        self._errors: List[str] = []
        self._disallowed: Set[str] = set()
    
    async def crawl(self, start_url: str) -> CrawlResult:
        """
        Crawl a website starting from the given URL
        
        Args:
            start_url: Starting URL for crawling
            
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
        
        parsed = urlparse(start_url)
        self._base_domain = parsed.netloc
        self._base_url = f"{parsed.scheme}://{parsed.netloc}"
        
        if self.respect_robots:
            await self._parse_robots(self._base_url)
        
        queue: List[Tuple[str, int]] = [(start_url, 0)]
        
        while queue and len(self._visited) < self.max_pages:
            url, depth = queue.pop(0)
            
            if url in self._visited:
                continue
            
            if depth > self.max_depth:
                continue
            
            if self._is_disallowed(url):
                continue
            
            self._visited.add(url)
            logger.debug(f"Crawling: {url} (depth={depth})")
            
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
                if new_url not in self._visited:
                    queue.append((new_url, depth + 1))
        
        crawl_time = time.time() - start_time
        
        logger.info(
            f"Crawl complete: {len(self._visited)} pages, "
            f"{len(self._endpoints)} endpoints, "
            f"{len(self._forms)} forms in {crawl_time:.2f}s"
        )
        
        return CrawlResult(
            pages_crawled=len(self._visited),
            endpoints=self._endpoints,
            forms=self._forms,
            api_endpoints=self._api_endpoints,
            external_links=self._external,
            errors=self._errors,
            crawl_time_seconds=crawl_time
        )
    
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

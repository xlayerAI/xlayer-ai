"""
XLayer AI HTTP Client - Async HTTP client with logging and interception
"""

import asyncio
import time
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from loguru import logger


@dataclass
class HTTPResponse:
    """HTTP response wrapper"""
    url: str
    status: int
    headers: Dict[str, str]
    body: str
    cookies: Dict[str, str]
    elapsed_ms: float
    redirects: List[str] = field(default_factory=list)
    error: Optional[str] = None
    
    @property
    def is_success(self) -> bool:
        return 200 <= self.status < 300
    
    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status < 400
    
    @property
    def content_type(self) -> Optional[str]:
        return self.headers.get("content-type", "").split(";")[0].strip()


@dataclass
class HTTPRequest:
    """HTTP request record for HAR generation"""
    method: str
    url: str
    headers: Dict[str, str]
    body: Optional[str]
    timestamp: float


class HTTPClient:
    """
    Async HTTP client for XLayer AI
    
    Features:
    - Connection pooling
    - Request/response logging
    - Cookie management
    - Rate limiting
    - HAR generation
    """
    
    def __init__(
        self,
        timeout: int = 30,
        rate_limit: float = 0.5,
        user_agent: str = "XLayer-AI/1.0 (Security Scanner)",
        verify_ssl: bool = True,
        follow_redirects: bool = True,
        max_redirects: int = 10
    ):
        self.timeout = ClientTimeout(total=timeout)
        self.rate_limit = rate_limit
        self.user_agent = user_agent
        self.verify_ssl = verify_ssl
        self.follow_redirects = follow_redirects
        self.max_redirects = max_redirects
        
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request_time: float = 0
        self._request_count: int = 0
        self._request_log: List[Dict[str, Any]] = []
        
    async def __aenter__(self):
        await self.start()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.close()
    
    async def start(self):
        """Initialize the HTTP session"""
        if self._session is None:
            connector = TCPConnector(
                limit=100,
                limit_per_host=10,
                ssl=self.verify_ssl if self.verify_ssl else False
            )
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=self.timeout,
                headers={"User-Agent": self.user_agent}
            )
    
    async def close(self):
        """Close the HTTP session"""
        if self._session:
            await self._session.close()
            self._session = None
    
    async def _rate_limit_wait(self):
        """Enforce rate limiting between requests"""
        if self.rate_limit > 0:
            elapsed = time.time() - self._last_request_time
            if elapsed < self.rate_limit:
                await asyncio.sleep(self.rate_limit - elapsed)
        self._last_request_time = time.time()
    
    async def request(
        self,
        method: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        params: Optional[Dict[str, str]] = None,
        data: Optional[Any] = None,
        json: Optional[Dict] = None,
        cookies: Optional[Dict[str, str]] = None,
        allow_redirects: Optional[bool] = None
    ) -> HTTPResponse:
        """
        Make an HTTP request
        
        Args:
            method: HTTP method (GET, POST, etc.)
            url: Target URL
            headers: Additional headers
            params: URL parameters
            data: Form data
            json: JSON body
            cookies: Cookies to send
            allow_redirects: Override redirect behavior
            
        Returns:
            HTTPResponse object
        """
        if self._session is None:
            await self.start()
        
        await self._rate_limit_wait()
        
        start_time = time.time()
        redirects = []
        
        req_headers = dict(headers) if headers else {}
        
        request_record = HTTPRequest(
            method=method,
            url=url,
            headers=req_headers,
            body=str(data or json or ""),
            timestamp=start_time
        )
        
        try:
            allow_redir = allow_redirects if allow_redirects is not None else self.follow_redirects
            
            async with self._session.request(
                method=method,
                url=url,
                headers=req_headers,
                params=params,
                data=data,
                json=json,
                cookies=cookies,
                allow_redirects=allow_redir,
                max_redirects=self.max_redirects
            ) as resp:
                body = await resp.text()
                elapsed_ms = (time.time() - start_time) * 1000
                
                if resp.history:
                    redirects = [str(r.url) for r in resp.history]
                
                response = HTTPResponse(
                    url=str(resp.url),
                    status=resp.status,
                    headers=dict(resp.headers),
                    body=body,
                    cookies={k: v.value for k, v in resp.cookies.items()},
                    elapsed_ms=elapsed_ms,
                    redirects=redirects
                )
                
                self._request_count += 1
                self._log_request(request_record, response)
                
                logger.debug(f"{method} {url} -> {resp.status} ({elapsed_ms:.0f}ms)")
                
                return response
                
        except asyncio.TimeoutError:
            elapsed_ms = (time.time() - start_time) * 1000
            return HTTPResponse(
                url=url,
                status=0,
                headers={},
                body="",
                cookies={},
                elapsed_ms=elapsed_ms,
                error="Request timeout"
            )
        except aiohttp.ClientError as e:
            elapsed_ms = (time.time() - start_time) * 1000
            return HTTPResponse(
                url=url,
                status=0,
                headers={},
                body="",
                cookies={},
                elapsed_ms=elapsed_ms,
                error=str(e)
            )
    
    async def get(self, url: str, **kwargs) -> HTTPResponse:
        """Make a GET request"""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> HTTPResponse:
        """Make a POST request"""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> HTTPResponse:
        """Make a PUT request"""
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> HTTPResponse:
        """Make a DELETE request"""
        return await self.request("DELETE", url, **kwargs)
    
    async def head(self, url: str, **kwargs) -> HTTPResponse:
        """Make a HEAD request"""
        return await self.request("HEAD", url, **kwargs)
    
    def _log_request(self, request: HTTPRequest, response: HTTPResponse):
        """Log request/response for HAR generation"""
        self._request_log.append({
            "request": {
                "method": request.method,
                "url": request.url,
                "headers": request.headers,
                "body": request.body,
                "timestamp": request.timestamp
            },
            "response": {
                "status": response.status,
                "headers": response.headers,
                "body_length": len(response.body),
                "elapsed_ms": response.elapsed_ms,
                "error": response.error
            }
        })
    
    def get_har(self) -> Dict[str, Any]:
        """Generate HAR (HTTP Archive) from request log"""
        entries = []
        for log in self._request_log:
            entries.append({
                "startedDateTime": log["request"]["timestamp"],
                "request": {
                    "method": log["request"]["method"],
                    "url": log["request"]["url"],
                    "headers": [{"name": k, "value": v} for k, v in log["request"]["headers"].items()]
                },
                "response": {
                    "status": log["response"]["status"],
                    "headers": [{"name": k, "value": v} for k, v in log["response"]["headers"].items()]
                },
                "time": log["response"]["elapsed_ms"]
            })
        
        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "XLayer-AI", "version": "1.0"},
                "entries": entries
            }
        }
    
    @property
    def request_count(self) -> int:
        """Get total request count"""
        return self._request_count
    
    def clear_log(self):
        """Clear request log"""
        self._request_log.clear()

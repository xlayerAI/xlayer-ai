"""
MITM Proxy Capture — Request History & Body Inspection

XLayer AI routes ALL solver HTTP traffic through a transparent MITM proxy.
This allows:
  1. Full request/response logging (even for libraries that don't support hooks)
  2. Encrypted traffic inspection (SSL bump)
  3. Request replay for validation
  4. Request history database for analysis
  5. Auto-correlation of OOB callbacks with outbound requests

Architecture:
    Solver → [MITM Proxy] → Target
                  ↓
            RequestHistory DB (in-memory, queryable)

This module provides a lightweight proxy capture layer using httpx hooks.
For full MITM (SSL bump), configure mitmproxy separately.
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from loguru import logger


@dataclass
class CapturedRequest:
    """One captured HTTP request + response pair."""
    request_id: str = ""
    timestamp: float = 0.0

    # Request
    method: str = "GET"
    url: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    content_type: str = ""

    # Response
    status_code: int = 0
    response_headers: Dict[str, str] = field(default_factory=dict)
    response_body: str = ""
    response_size: int = 0
    response_time_ms: float = 0.0

    # Metadata
    agent_id: str = ""          # which solver sent this
    vuln_type: str = ""         # what was being tested
    payload: str = ""           # the attack payload used
    is_oob_callback: bool = False
    tags: List[str] = field(default_factory=list)


@dataclass
class RequestStats:
    """Aggregate stats for request history."""
    total_requests: int = 0
    total_by_method: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    total_by_status: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    total_by_agent: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    unique_endpoints: int = 0
    avg_response_time_ms: float = 0.0
    total_bytes_sent: int = 0
    total_bytes_received: int = 0
    waf_blocks: int = 0
    errors: int = 0


class RequestHistory:
    """
    In-memory request history database.

    All solver HTTP traffic is logged here. Supports querying by:
      - Agent ID
      - Target URL
      - Status code
      - Vuln type
      - Time range
    """

    MAX_ENTRIES = 50000  # 50K max to prevent OOM

    def __init__(self):
        self._requests: List[CapturedRequest] = []
        self._by_agent: Dict[str, List[int]] = defaultdict(list)
        self._by_url: Dict[str, List[int]] = defaultdict(list)
        self._by_status: Dict[int, List[int]] = defaultdict(list)
        self._unique_urls: Set[str] = set()
        self._lock = asyncio.Lock()

    async def add(self, req: CapturedRequest):
        """Add a captured request to history."""
        async with self._lock:
            if len(self._requests) >= self.MAX_ENTRIES:
                # Evict oldest 10%
                evict = self.MAX_ENTRIES // 10
                self._requests = self._requests[evict:]
                self._rebuild_indices()

            idx = len(self._requests)
            self._requests.append(req)
            self._by_agent[req.agent_id].append(idx)
            self._by_url[req.url].append(idx)
            self._by_status[req.status_code].append(idx)
            self._unique_urls.add(req.url)

    def get_by_agent(self, agent_id: str) -> List[CapturedRequest]:
        """Get all requests from a specific agent."""
        indices = self._by_agent.get(agent_id, [])
        return [self._requests[i] for i in indices if i < len(self._requests)]

    def get_by_url(self, url: str) -> List[CapturedRequest]:
        """Get all requests to a specific URL."""
        indices = self._by_url.get(url, [])
        return [self._requests[i] for i in indices if i < len(self._requests)]

    def get_by_status(self, status: int) -> List[CapturedRequest]:
        """Get all requests with a specific status code."""
        indices = self._by_status.get(status, [])
        return [self._requests[i] for i in indices if i < len(self._requests)]

    def get_waf_blocks(self) -> List[CapturedRequest]:
        """Get all requests that were blocked by WAF (403, 406, 429)."""
        blocked = []
        for status in (403, 406, 429, 503):
            blocked.extend(self.get_by_status(status))
        return blocked

    def get_successful_payloads(self) -> List[CapturedRequest]:
        """Get all requests where the payload successfully triggered a vuln."""
        return [
            r for r in self._requests
            if r.payload and r.status_code == 200
            and any(tag in r.tags for tag in ["xss_triggered", "sqli_triggered", "oob_hit"])
        ]

    def get_stats(self) -> RequestStats:
        """Get aggregate stats for the entire history."""
        stats = RequestStats()
        stats.total_requests = len(self._requests)
        stats.unique_endpoints = len(self._unique_urls)

        total_response_time = 0.0
        for req in self._requests:
            stats.total_by_method[req.method] += 1
            stats.total_by_status[req.status_code] += 1
            stats.total_by_agent[req.agent_id] += 1
            total_response_time += req.response_time_ms
            stats.total_bytes_sent += len(req.body)
            stats.total_bytes_received += req.response_size
            if req.status_code in (403, 406, 429):
                stats.waf_blocks += 1
            if req.status_code >= 500:
                stats.errors += 1

        if self._requests:
            stats.avg_response_time_ms = total_response_time / len(self._requests)

        return stats

    def search(
        self,
        url_contains: str = "",
        body_contains: str = "",
        status: int = 0,
        agent_id: str = "",
        limit: int = 100,
    ) -> List[CapturedRequest]:
        """Search request history with filters."""
        results = []
        for req in reversed(self._requests):  # newest first
            if url_contains and url_contains not in req.url:
                continue
            if body_contains and body_contains not in req.response_body:
                continue
            if status and req.status_code != status:
                continue
            if agent_id and req.agent_id != agent_id:
                continue
            results.append(req)
            if len(results) >= limit:
                break
        return results

    def _rebuild_indices(self):
        """Rebuild indices after eviction."""
        self._by_agent.clear()
        self._by_url.clear()
        self._by_status.clear()
        self._unique_urls.clear()
        for i, req in enumerate(self._requests):
            self._by_agent[req.agent_id].append(i)
            self._by_url[req.url].append(i)
            self._by_status[req.status_code].append(i)
            self._unique_urls.add(req.url)


class ProxyCapture:
    """
    Transparent proxy capture layer.

    Wraps httpx event hooks to log all solver traffic.
    Can be injected into AttackMachine's HTTP client.

    Usage:
        proxy = ProxyCapture()
        # All requests through the attack machine are logged
        proxy.install(attack_machine)
        
        # After scan:
        stats = proxy.history.get_stats()
        waf_blocks = proxy.history.get_waf_blocks()
    """

    def __init__(self):
        self.history = RequestHistory()
        self._agent_context: Dict[str, str] = {}  # thread-local agent ID tracking

    def set_agent_context(self, agent_id: str, vuln_type: str = ""):
        """Set current agent context for request tagging."""
        self._agent_context["agent_id"] = agent_id
        self._agent_context["vuln_type"] = vuln_type

    def clear_agent_context(self):
        """Clear agent context."""
        self._agent_context.clear()

    async def capture(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        body: str = "",
        status_code: int = 0,
        response_headers: Dict[str, str] = None,
        response_body: str = "",
        response_time_ms: float = 0.0,
        payload: str = "",
        tags: List[str] = None,
    ):
        """Manually capture a request/response pair."""
        import uuid
        req = CapturedRequest(
            request_id=uuid.uuid4().hex[:12],
            timestamp=time.time(),
            method=method,
            url=url,
            headers=headers,
            body=body,
            content_type=headers.get("Content-Type", ""),
            status_code=status_code,
            response_headers=response_headers or {},
            response_body=response_body[:5000],
            response_size=len(response_body),
            response_time_ms=response_time_ms,
            agent_id=self._agent_context.get("agent_id", ""),
            vuln_type=self._agent_context.get("vuln_type", ""),
            payload=payload,
            tags=tags or [],
        )
        await self.history.add(req)

    def get_replay_data(self, request_id: str) -> Optional[Dict]:
        """Get request data for replay (Validator use)."""
        for req in self.history._requests:
            if req.request_id == request_id:
                return {
                    "method": req.method,
                    "url": req.url,
                    "headers": req.headers,
                    "body": req.body,
                    "payload": req.payload,
                }
        return None

    def get_all_for_replay(self, agent_id: str) -> List[Dict]:
        """Get all requests from an agent for replay-based validation."""
        reqs = self.history.get_by_agent(agent_id)
        return [
            {
                "method": r.method,
                "url": r.url,
                "headers": r.headers,
                "body": r.body,
                "payload": r.payload,
                "status_code": r.status_code,
            }
            for r in reqs
        ]

    def summary(self) -> str:
        """Get a human-readable summary of captured traffic."""
        stats = self.history.get_stats()
        lines = [
            f"Total requests: {stats.total_requests}",
            f"Unique endpoints: {stats.unique_endpoints}",
            f"Avg response time: {stats.avg_response_time_ms:.1f}ms",
            f"WAF blocks: {stats.waf_blocks}",
            f"Errors (5xx): {stats.errors}",
            f"Methods: {dict(stats.total_by_method)}",
        ]
        return "\n".join(lines)

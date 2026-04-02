"""
engine/discovery_monitor.py — Continuous Discovery Monitor

Runs as a background task alongside the solver phase.
Polls auth-gated endpoints for status changes while exploitation is in progress.

Key event: 403→200 transition — indicates:
  - Time-based authorization bypass
  - Race condition in auth middleware
  - Auth state changed by another solver's exploitation

On change detection:
  - Endpoint queued in `changes` asyncio.Queue
  - Coordinator picks up the event and spawns a high-priority solver
"""

import asyncio
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import httpx
from loguru import logger

from xlayer_ai.engine.logical_surface_map.graph import LogicalSurface


# ── Data models ───────────────────────────────────────────────────────────────

@dataclass
class AccessChange:
    """A meaningful status change detected on a monitored endpoint."""
    url: str
    old_status: int
    new_status: int
    change_type: str    # "unblocked" | "blocked" | "method_exposed" | "appeared"
    timestamp: float = field(default_factory=time.time)

    @property
    def is_opportunity(self) -> bool:
        """True if this change represents a new attack opportunity."""
        return self.change_type in ("unblocked", "appeared")

    def __str__(self) -> str:
        return (
            f"AccessChange({self.change_type}: {self.url} "
            f"{self.old_status}→{self.new_status})"
        )


# ── Monitor ───────────────────────────────────────────────────────────────────

class DiscoveryMonitor:
    """
    Background poller that watches auth-gated endpoints for status changes.

    Lifecycle:
        monitor = DiscoveryMonitor(surface, proxy=proxy, cookies=cookies)
        await monitor.start()
        # ... exploitation runs ...
        changes = await monitor.drain()   # collect all changes found
        await monitor.stop()

    Changes are also available via:
        change = await monitor.get_change(timeout=0.1)  # non-blocking

    Design:
      - Polls auth_required endpoints every poll_interval seconds
      - Also tracks newly-added endpoints (surface grows during scan)
      - Compares status against last known baseline
      - 403/401 → 200: "unblocked" (highest priority — auth bypass)
      - 404 → 200/201: "appeared" (new endpoint became active)
      - Max poll_targets per cycle: 20 (keep HTTP overhead low)
    """

    def __init__(
        self,
        surface: LogicalSurface,
        proxy: Optional[str] = None,
        cookies: Optional[List[dict]] = None,
        poll_interval: float = 30.0,
        http_timeout: float = 6.0,
        max_poll_targets: int = 20,
    ) -> None:
        self.surface          = surface
        self.proxy            = proxy
        self.poll_interval    = poll_interval
        self.http_timeout     = http_timeout
        self.max_poll_targets = max_poll_targets

        self._cookie_jar: dict = {}
        if cookies:
            for c in cookies:
                name  = c.get("name") or c.get("key", "")
                value = c.get("value", "")
                if name and value:
                    self._cookie_jar[name] = value

        # Baseline: {url: last_known_status}
        self._baseline: Dict[str, int] = {}
        self._changes: asyncio.Queue = asyncio.Queue()
        self._task: Optional[asyncio.Task] = None
        self._running = False

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    async def start(self) -> None:
        """Start background polling task."""
        if self._running:
            return
        # Seed baseline from current surface state (no HTTP calls yet)
        self._seed_baseline()
        self._running = True
        self._task = asyncio.create_task(self._monitor_loop(), name="discovery_monitor")
        logger.info(
            f"[DiscoveryMonitor] Started — polling {len(self._baseline)} "
            f"endpoints every {self.poll_interval:.0f}s"
        )

    async def stop(self) -> None:
        """Stop polling gracefully."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.debug("[DiscoveryMonitor] Stopped")

    # ── Change retrieval ──────────────────────────────────────────────────────

    async def get_change(self, timeout: float = 0.1) -> Optional[AccessChange]:
        """
        Non-blocking poll for a single change event.
        Returns None if no change is available within timeout.
        """
        try:
            return await asyncio.wait_for(self._changes.get(), timeout=timeout)
        except asyncio.TimeoutError:
            return None

    async def drain(self) -> List[AccessChange]:
        """Collect all pending changes (non-blocking)."""
        changes: List[AccessChange] = []
        while not self._changes.empty():
            try:
                changes.append(self._changes.get_nowait())
            except asyncio.QueueEmpty:
                break
        return changes

    @property
    def pending_count(self) -> int:
        return self._changes.qsize()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _seed_baseline(self) -> None:
        """Build initial baseline from LSM surface — no HTTP calls."""
        for url, node in self.surface.endpoints.items():
            if not url.startswith("http"):
                continue
            # Auth-required → baseline 401/403 (optimistic guess)
            if node.auth_required:
                self._baseline[url] = 403
            else:
                # Not marked auth-required — we'll discover the real status
                # Only seed the ones with actual signals (params, high-value paths)
                if node.parameters or any(k in url.lower() for k in ("admin", "api", "config")):
                    self._baseline[url] = 200

    def _pick_poll_targets(self) -> List[str]:
        """
        Select up to max_poll_targets endpoints to check this cycle.
        Prioritizes:
          1. Auth-gated (most likely to show auth bypass)
          2. High-value paths (admin, config, debug)
          3. Newly added endpoints (not yet in baseline)
        """
        auth_gated = [
            url for url, node in self.surface.endpoints.items()
            if node.auth_required and url.startswith("http")
        ]
        high_value = [
            url for url in self.surface.endpoints
            if url.startswith("http") and any(
                k in url.lower() for k in ("admin", "config", "debug", "internal", "secret")
            ) and url not in auth_gated
        ]
        new_endpoints = [
            url for url in self.surface.endpoints
            if url.startswith("http") and url not in self._baseline
        ]

        targets: List[str] = []
        # Fill: auth-gated first, then new, then high-value
        for pool in (auth_gated, new_endpoints, high_value):
            for url in pool:
                if len(targets) >= self.max_poll_targets:
                    break
                if url not in targets:
                    targets.append(url)
            if len(targets) >= self.max_poll_targets:
                break

        return targets

    async def _monitor_loop(self) -> None:
        """Background loop: sleep → poll → emit changes → repeat."""
        while self._running:
            try:
                await asyncio.sleep(self.poll_interval)
                if not self._running:
                    break
                await self._poll_cycle()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.debug(f"[DiscoveryMonitor] Loop error: {e}")

    async def _poll_cycle(self) -> None:
        """One complete polling cycle."""
        targets = self._pick_poll_targets()
        if not targets:
            return

        logger.debug(f"[DiscoveryMonitor] Polling {len(targets)} endpoints")

        async with httpx.AsyncClient(
            timeout=self.http_timeout,
            follow_redirects=False,   # don't follow — we want the raw redirect status
            proxies=self.proxy or None,
            cookies=self._cookie_jar,
            verify=False,
        ) as client:
            tasks   = [self._probe(client, url) for url in targets]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for url, result in zip(targets, results):
            if isinstance(result, Exception):
                continue
            new_status = result
            old_status = self._baseline.get(url, -1)

            change = self._classify_change(url, old_status, new_status)
            if change:
                logger.info(f"[DiscoveryMonitor] {change}")
                await self._changes.put(change)

            # Update baseline
            self._baseline[url] = new_status

            # Register newly-found endpoint in surface if missing
            if url not in self.surface.endpoints:
                self.surface.add_endpoint(url, source="discovery_monitor")

    async def _probe(self, client: httpx.AsyncClient, url: str) -> int:
        """HEAD request (fast). Falls back to GET if HEAD not allowed."""
        try:
            resp = await client.head(url)
            if resp.status_code == 405:
                resp = await client.get(url)
            return resp.status_code
        except Exception:
            return 0

    @staticmethod
    def _classify_change(url: str, old: int, new: int) -> Optional[AccessChange]:
        """
        Return an AccessChange if the transition is meaningful, else None.

        Interesting transitions:
          403/401 → 200/201/204: unblocked (auth bypass / timing bypass)
          404     → 200/201:     appeared  (new endpoint became active)
          200     → 403/401:     blocked   (access revoked — defensive side)
        """
        if old == new or old == -1:
            return None   # no change or no baseline yet

        if old in (401, 403) and new in (200, 201, 204):
            return AccessChange(url=url, old_status=old, new_status=new, change_type="unblocked")

        if old == 404 and new in (200, 201):
            return AccessChange(url=url, old_status=old, new_status=new, change_type="appeared")

        if old == 200 and new in (401, 403):
            return AccessChange(url=url, old_status=old, new_status=new, change_type="blocked")

        return None

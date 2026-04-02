"""
engine/logical_surface_map/path_fuzzer.py — XLayer Wordlist-Based Path Discovery

Fills the gap between logic-based guessing and wordlist fuzzing.

Two-phase approach:
  Phase 1 — CORE wordlist: ~300 high-value paths (admin, auth, api, debug, config, backup)
  Phase 2 — SMART expansion: combine discovered path prefixes with wordlist suffixes
             e.g. /api/v1 discovered + "users" → try /api/v1/users

Returns only real hits (200, 201, 204, 301, 302, 401, 403) with status codes.
Concurrent requests throttled by semaphore to avoid hammering the target.
"""

import asyncio
import secrets
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from loguru import logger


# ── Hit container ────────────────────────────────────────────────────────────

@dataclass
class FuzzHit:
    path: str
    status: int
    content_type: str = ""
    content_length: int = 0
    redirect_to: str = ""


@dataclass
class FuzzResult:
    hits: List[FuzzHit] = field(default_factory=list)
    paths_tested: int = 0
    auth_walls: Set[str] = field(default_factory=set)   # 401/403 paths
    redirects: Dict[str, str] = field(default_factory=dict)  # path → Location


# ── Core wordlist ────────────────────────────────────────────────────────────
# High-value paths ordered by discovery priority.
# NOT a 100k dirbuster list — focused on security-relevant endpoints.

WORDLIST_CORE: List[str] = [
    # ── Authentication / Session ──────────────────────────────────────────
    "/login", "/logout", "/signin", "/signout", "/signup", "/register",
    "/auth", "/auth/login", "/auth/logout", "/auth/token", "/auth/refresh",
    "/auth/callback", "/auth/verify", "/auth/reset", "/auth/forgot",
    "/oauth", "/oauth/token", "/oauth/authorize", "/oauth/callback",
    "/token", "/refresh", "/reset-password", "/forgot-password",
    "/verify-email", "/confirm", "/2fa", "/mfa",
    "/api/auth", "/api/login", "/api/logout", "/api/register",
    "/api/token", "/api/refresh", "/api/reset-password",
    "/sso", "/saml", "/saml/acs", "/saml/metadata",

    # ── Admin ─────────────────────────────────────────────────────────────
    "/admin", "/admin/", "/administrator",
    "/admin/login", "/admin/logout", "/admin/dashboard",
    "/admin/users", "/admin/user", "/admin/settings",
    "/admin/config", "/admin/system", "/admin/logs",
    "/admin/api", "/admin/panel", "/admin/console",
    "/dashboard", "/panel", "/control", "/manage", "/management",
    "/staff", "/superadmin", "/root",
    "/wp-admin", "/wp-login.php", "/wp-json",
    "/administrator/index.php",

    # ── API base paths ────────────────────────────────────────────────────
    "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
    "/api/v1/", "/api/v2/", "/api/v3/",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/", "/rest/v1", "/rest/v2",
    "/graphql", "/gql", "/graph",
    "/api/graphql",

    # ── Common REST resources ─────────────────────────────────────────────
    "/api/users", "/api/user", "/api/users/me", "/api/profile",
    "/api/accounts", "/api/account", "/api/account/me",
    "/api/orders", "/api/order",
    "/api/products", "/api/product",
    "/api/settings", "/api/config",
    "/api/admin", "/api/admin/users",
    "/api/roles", "/api/permissions",
    "/api/files", "/api/upload", "/api/uploads",
    "/api/search",
    "/api/export", "/api/import",
    "/api/logs", "/api/audit",
    "/api/health", "/api/status", "/api/version", "/api/ping",
    "/api/internal", "/api/private", "/api/debug",

    # ── Health / Status / Info ────────────────────────────────────────────
    "/health", "/healthz", "/health/live", "/health/ready",
    "/status", "/ping", "/version",
    "/info", "/about", "/metrics",
    "/actuator", "/actuator/health", "/actuator/info",
    "/actuator/env", "/actuator/beans", "/actuator/mappings",
    "/actuator/shutdown",    # RCE if enabled
    "/__admin", "/_debug", "/_status",

    # ── Configuration / Debug / Dev ───────────────────────────────────────
    "/config", "/configuration", "/settings",
    "/debug", "/dev", "/development", "/test", "/testing",
    "/internal", "/private", "/secret",
    "/console", "/shell",
    "/phpinfo.php", "/info.php", "/test.php",
    "/env", "/.env", "/.env.local", "/.env.production",
    "/config.json", "/config.yml", "/config.yaml",
    "/settings.json", "/application.json",

    # ── Sensitive files ───────────────────────────────────────────────────
    "/.git", "/.git/HEAD", "/.git/config",
    "/.svn", "/.svn/entries",
    "/.DS_Store",
    "/robots.txt", "/sitemap.xml",
    "/crossdomain.xml", "/clientaccesspolicy.xml",
    "/package.json", "/composer.json", "/Gemfile",
    "/webpack.config.js", "/vite.config.js",
    "/app.js", "/main.js", "/index.js",
    "/server.js", "/app.py", "/main.py",
    "/database.yml", "/database.json",
    "/backup.sql", "/dump.sql", "/db.sql",
    "/backup.zip", "/backup.tar.gz",
    "/web.config", "/nginx.conf", "/apache.conf",
    "/.htaccess", "/.htpasswd",

    # ── Documentation ─────────────────────────────────────────────────────
    "/docs", "/documentation", "/api-docs",
    "/swagger", "/swagger-ui", "/swagger-ui.html",
    "/openapi.json", "/openapi.yaml",
    "/redoc", "/api/docs",

    # ── User-facing sensitive ─────────────────────────────────────────────
    "/profile", "/account", "/account/settings",
    "/user", "/users", "/me",
    "/billing", "/payment", "/payments",
    "/invoice", "/invoices",
    "/report", "/reports", "/export",
    "/download", "/downloads",
    "/upload", "/uploads", "/files",
    "/media", "/assets",

    # ── SSRF / Internal service candidates ───────────────────────────────
    "/proxy", "/fetch", "/redirect",
    "/webhook", "/webhooks", "/callback",
    "/ping", "/request", "/load",
    "/forward", "/gateway",

    # ── Password reset / account takeover ────────────────────────────────
    "/reset", "/password-reset", "/forgot", "/recover",
    "/unlock", "/activate", "/deactivate",
    "/invite", "/invitations",

    # ── Common CMS / framework paths ─────────────────────────────────────
    "/wp-json/wp/v2/users",
    "/wp-content/debug.log",
    "/xmlrpc.php",
    "/phpmyadmin", "/adminer.php", "/adminer",
    "/rails/info", "/rails/info/routes",
    "/_next/static", "/_nuxt",
    "/static/admin",

    # ── GraphQL specific ──────────────────────────────────────────────────
    "/api/graphql/console",
    "/graphiql",
    "/playground",

    # ── Misc high-value ───────────────────────────────────────────────────
    "/cron", "/jobs", "/tasks", "/queues",
    "/cache", "/flush", "/clear",
    "/token/verify", "/token/decode",
    "/sessions", "/session",
    "/keys", "/secrets", "/vault",
]

# ── Wordlist suffix expansion (appended to discovered path prefixes) ─────────
# Shorter list — only used in Phase 2 smart expansion

WORDLIST_SUFFIXES: List[str] = [
    "users", "user", "admin", "me", "profile", "account",
    "login", "logout", "register", "auth", "token", "refresh",
    "settings", "config", "health", "status", "ping",
    "list", "create", "update", "delete", "edit", "remove",
    "export", "import", "upload", "download", "search",
    "all", "bulk", "batch",
    "logs", "audit", "debug", "test",
    "roles", "permissions", "access",
    "password", "reset", "verify",
    "invite", "activate", "deactivate",
    "{id}", "{id}/edit", "{id}/delete", "{id}/update",
    "1", "1/edit", "0", "me/settings",
]

# ── Backup file extensions (Phase 3 — tried on every real hit) ───────────────
# Developers leave backup copies on servers: config.bak, db.sql.old, etc.
# These often contain plaintext credentials or source code.

BACKUP_EXTS: List[str] = [
    ".bak", ".old", ".orig", ".backup", ".copy",
    "~", ".swp", ".tmp", ".1", ".save",
]


# ── WordlistFuzzer ────────────────────────────────────────────────────────────

class WordlistFuzzer:
    """
    Concurrent wordlist-based path discovery.

    Two phases:
      1. Core wordlist probing (always runs)
      2. Smart expansion — discovered prefixes × suffix wordlist (optional)

    Hits = responses with status 200, 201, 204, 301, 302, 401, 403.
    404 and 5xx are ignored (unless consistent pattern detected).
    """

    # Status codes considered a "hit" (path exists in some form)
    HIT_CODES = {200, 201, 204, 206, 301, 302, 307, 308, 401, 403}

    # Static file extensions to skip (never a real endpoint)
    _SKIP_EXTS = {
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
        ".woff", ".woff2", ".ttf", ".eot",
        ".css", ".map",
    }

    def __init__(
        self,
        concurrency: int = 20,
        timeout: int = 8,
        proxy: Optional[str] = None,
    ):
        self.concurrency = concurrency
        self.timeout = timeout
        self.proxy = proxy

    async def fuzz(
        self,
        base_url: str,
        cookies: Optional[List[dict]] = None,
        known_prefixes: Optional[List[str]] = None,
        extra_paths: Optional[List[str]] = None,
        smart_expand: bool = True,
        wordlist: Optional[List[str]] = None,
    ) -> FuzzResult:
        """
        Fuzz a target with the core wordlist + optional smart expansion.

        Args:
            base_url:        Target origin (scheme + host)
            cookies:         Auth cookies for authenticated scanning
            known_prefixes:  Discovered path prefixes for smart expansion
                             e.g. ["/api/v1", "/admin"] → tries /api/v1/users etc.
            extra_paths:     Additional custom paths to probe
            smart_expand:    Whether to run Phase 2 prefix×suffix expansion
            wordlist:        Override default WORDLIST_CORE (pass custom list)
        """
        result = FuzzResult()
        base = base_url.rstrip("/")

        try:
            import httpx
        except ImportError:
            logger.warning("[Fuzzer] httpx not installed")
            return result

        # Build cookie header
        cookie_str = "; ".join(
            f"{c.get('name', '')}={c.get('value', '')}"
            for c in (cookies or []) if c.get("name") and c.get("value")
        )

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,    # track redirects manually
            verify=False,
            proxies={"all://": self.proxy} if self.proxy else None,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                **({"Cookie": cookie_str} if cookie_str else {}),
            },
        ) as client:
            sem = asyncio.Semaphore(self.concurrency)

            # ── Soft 404 detection ─────────────────────────────────────────
            # Some apps return HTTP 200 for ALL paths (custom 404 page).
            # Without this check, the entire 300-path wordlist appears as hits.
            # Strategy: probe a cryptographically random junk path first →
            # if 200, record its body fingerprint → filter same-fingerprint hits.
            soft404_baseline = await self._detect_soft_404(client, base)
            if soft404_baseline:
                logger.warning(
                    f"[Fuzzer] Soft 404 detected (server returns HTTP 200 for random paths). "
                    f"Filtering by baseline body fingerprint."
                )

            # ── Phase 1: Core wordlist ─────────────────────────────────────
            # Note: `wordlist is not None` allows passing wordlist=[] to skip
            # Phase 1 entirely (used by re-run logic in ScoutLoop).
            core = list(wordlist) if wordlist is not None else list(WORDLIST_CORE)
            if extra_paths:
                core += [p for p in extra_paths if p not in core]

            if core:
                logger.info(
                    f"[Fuzzer] Phase 1: {len(core)} core paths against {base}"
                )
                phase1_hits = await self._probe_batch(
                    client, base, core, sem, result, soft404_baseline
                )
                logger.info(f"[Fuzzer] Phase 1 complete: {len(phase1_hits)} hits")
            else:
                phase1_hits = []

            # ── Phase 2: Smart expansion ───────────────────────────────────
            if smart_expand and known_prefixes:
                expanded = self._build_smart_paths(known_prefixes, phase1_hits)
                if expanded:
                    logger.info(
                        f"[Fuzzer] Phase 2: {len(expanded)} smart paths "
                        f"({len(known_prefixes)} prefixes × suffixes)"
                    )
                    phase2_hits = await self._probe_batch(
                        client, base, expanded, sem, result, soft404_baseline
                    )
                    logger.info(
                        f"[Fuzzer] Phase 2 complete: {len(phase2_hits)} hits"
                    )

            # ── Phase 3: Backup file extension probing ─────────────────────
            # For every real hit (200/401/403), try common backup extensions.
            # /admin/config → /admin/config.bak, /admin/config.old, etc.
            backup_paths = self._build_backup_paths(result.hits)
            if backup_paths:
                logger.info(
                    f"[Fuzzer] Phase 3: {len(backup_paths)} backup variants "
                    f"from {len(result.hits)} hit(s)"
                )
                phase3_hits = await self._probe_batch(
                    client, base, backup_paths, sem, result, soft404_baseline
                )
                logger.info(
                    f"[Fuzzer] Phase 3 complete: {len(phase3_hits)} backup hit(s)"
                )

        logger.success(
            f"[Fuzzer] Done: {result.paths_tested} tested, "
            f"{len(result.hits)} hits, "
            f"{len(result.auth_walls)} auth walls"
        )
        return result

    async def _detect_soft_404(
        self,
        client,
        base: str,
    ) -> Optional[Tuple[int, int, int]]:
        """
        Probe a random junk path to detect soft 404 behaviour.

        Returns (status, body_len, body_hash) if the server returns a hit-code
        (e.g. HTTP 200) for a path that cannot possibly exist, signalling that
        every wordlist response at that status needs body-fingerprint filtering.
        Returns None if the server returns a proper 404/4xx for unknown paths.
        """
        junk_path = f"/{secrets.token_hex(10)}_xlayer_probe"
        try:
            r = await client.get(f"{base}{junk_path}")
            if r.status_code in self.HIT_CODES:
                body = r.text or ""
                return (r.status_code, len(body), hash(body[:500]))
        except Exception:
            pass
        return None

    async def _probe_batch(
        self,
        client,
        base: str,
        paths: List[str],
        sem: asyncio.Semaphore,
        result: FuzzResult,
        soft404_baseline: Optional[Tuple[int, int, int]] = None,
    ) -> List[FuzzHit]:
        """Probe a batch of paths concurrently. Returns new hits from this batch."""
        new_hits: List[FuzzHit] = []

        async def _probe_one(path: str) -> None:
            # Skip static files
            path_lower = path.split("?")[0].lower()
            if any(path_lower.endswith(ext) for ext in self._SKIP_EXTS):
                return

            url = f"{base}{path}" if path.startswith("/") else f"{base}/{path}"
            async with sem:
                try:
                    r = await client.get(url)
                    result.paths_tested += 1

                    if r.status_code not in self.HIT_CODES:
                        return

                    # ── Soft 404 filter ───────────────────────────────────
                    # Baseline: (status, body_len, body_hash) from a junk path.
                    # Skip this hit if it looks identical to the baseline 404.
                    # Uses exact hash match OR ±15% body length similarity.
                    if soft404_baseline and r.status_code == soft404_baseline[0]:
                        body = r.text or ""
                        b_hash = hash(body[:500])
                        b_len  = len(body)
                        base_len = soft404_baseline[1]
                        if b_hash == soft404_baseline[2] or (
                            base_len > 0
                            and abs(b_len - base_len) / max(base_len, 1) < 0.15
                        ):
                            return  # soft 404 — same fingerprint as junk path

                    ct = r.headers.get("content-type", "")
                    cl = len(r.content)   # actual bytes (chunked-transfer safe)
                    redirect_to = r.headers.get("location", "")

                    hit = FuzzHit(
                        path=path,
                        status=r.status_code,
                        content_type=ct,
                        content_length=cl,
                        redirect_to=redirect_to,
                    )
                    result.hits.append(hit)
                    new_hits.append(hit)

                    if r.status_code in (401, 403):
                        result.auth_walls.add(path)
                    if redirect_to:
                        result.redirects[path] = redirect_to

                    _emoji = {200: "✓", 201: "✓", 301: "→", 302: "→", 401: "🔒", 403: "🔒"}
                    logger.debug(
                        f"[Fuzzer] {_emoji.get(r.status_code, '?')} "
                        f"HTTP {r.status_code} {path}"
                    )
                except Exception:
                    pass

        await asyncio.gather(*[_probe_one(p) for p in paths], return_exceptions=True)
        return new_hits

    def _build_smart_paths(
        self,
        known_prefixes: List[str],
        phase1_hits: List[FuzzHit],
    ) -> List[str]:
        """
        Build smart expanded paths:
        1. known_prefixes × WORDLIST_SUFFIXES
        2. existing hit paths + IDOR variants (/{id}, /1, /0)
        3. version variants (v1 → v2, v0)

        Deduplicates and excludes any path already tested.
        """
        already_hit = {h.path for h in phase1_hits}
        # Also exclude paths from the core wordlist
        exclude = set(WORDLIST_CORE) | already_hit

        paths: Set[str] = set()

        # Prefix × suffix
        for prefix in known_prefixes:
            prefix = prefix.rstrip("/")
            if not prefix or prefix == "/":
                continue
            for suffix in WORDLIST_SUFFIXES:
                candidate = f"{prefix}/{suffix}"
                if candidate not in exclude:
                    paths.add(candidate)

        # IDOR / ID variants on existing hits
        for hit in phase1_hits:
            if hit.status in (200, 401, 403):
                base_path = hit.path.rstrip("/")
                for variant in ("/1", "/0", "/me", "/2", "/admin"):
                    candidate = base_path + variant
                    if candidate not in exclude:
                        paths.add(candidate)

        # Version pivots on core hits
        for hit in phase1_hits:
            for m in re.finditer(r'/v(\d+)', hit.path):
                n = int(m.group(1))
                for alt in (n - 1, n + 1):
                    if alt >= 0:
                        candidate = hit.path.replace(f"/v{n}", f"/v{alt}", 1)
                        if candidate not in exclude:
                            paths.add(candidate)

        return sorted(paths)

    def _build_backup_paths(self, hits: List[FuzzHit]) -> List[str]:
        """
        For every real hit (200/401/403), generate backup file variants.

        Example:
            /admin/config      → /admin/config.bak, /admin/config.old, …
            /api/v1/users      → /api/v1/users.bak, /api/v1/users~, …

        Skips paths that already have static file extensions (.js, .css, etc.)
        because backup variants of those are almost never interesting.
        """
        # Extensions that indicate the path is already a static file
        _SKIP_BASE_EXTS = {
            ".js", ".css", ".png", ".jpg", ".jpeg", ".gif",
            ".svg", ".ico", ".woff", ".woff2", ".ttf", ".pdf",
            ".xml", ".txt", ".map",
        }
        already_tested = {h.path for h in hits}
        paths: Set[str] = set()

        for hit in hits:
            if hit.status not in (200, 401, 403):
                continue
            base_path = hit.path.rstrip("/")
            p_lower = base_path.lower()
            if any(p_lower.endswith(ext) for ext in _SKIP_BASE_EXTS):
                continue
            for ext in BACKUP_EXTS:
                candidate = f"{base_path}{ext}"
                if candidate not in already_tested:
                    paths.add(candidate)

        return sorted(paths)

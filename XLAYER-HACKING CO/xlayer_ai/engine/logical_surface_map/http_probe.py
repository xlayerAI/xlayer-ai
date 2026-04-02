"""
engine/logical_surface_map/http_probe.py — XLayer Passive HTTP Intelligence

Fills the gaps left by browser + JS analysis with direct HTTP probing.
Runs once at the start of ScoutLoop to give the LLM maximum prior context.

Capabilities:
  1. robots.txt / sitemap.xml  — hidden paths the app explicitly lists
  2. OpenAPI / Swagger spec    — full endpoint map with params, auth, body fields
  3. GraphQL introspection     — full schema (queries, mutations, subscriptions)
  4. Response header analysis  — tech stack + security misconfigs (CSP, CORS, HSTS)
  5. HTTP OPTIONS enumeration  — actual allowed methods per endpoint
  6. Error fingerprinting      — stack traces, internal paths from 4xx/5xx
  7. JWT / cookie analysis     — alg:none, sensitive payload fields, no expiry
"""

import asyncio
import base64
import json
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse
from loguru import logger


# ── Result containers ────────────────────────────────────────────────────────

@dataclass
class SecurityHeaderResult:
    """HTTP security header audit findings."""
    missing_headers: List[str] = field(default_factory=list)   # headers absent entirely
    misconfigs: List[dict] = field(default_factory=list)        # {header, value, issue}
    tech_hints: List[str] = field(default_factory=list)         # from X-Powered-By, Server, etc.
    cors_open: bool = False                                      # Access-Control-Allow-Origin: *
    cors_allowed_origin: str = ""


@dataclass
class GraphQLField:
    name: str
    type_name: str
    args: List[str] = field(default_factory=list)


@dataclass
class GraphQLSchema:
    """Extracted GraphQL schema via introspection."""
    endpoint: str = ""
    queries: List[GraphQLField] = field(default_factory=list)
    mutations: List[GraphQLField] = field(default_factory=list)
    subscriptions: List[GraphQLField] = field(default_factory=list)


@dataclass
class OpenAPIEndpoint:
    """A single endpoint extracted from an OpenAPI/Swagger spec."""
    path: str
    method: str
    params: List[str] = field(default_factory=list)        # query + path params
    body_fields: List[str] = field(default_factory=list)   # request body field names
    auth_required: bool = False
    summary: str = ""


@dataclass
class JWTAnalysis:
    """Decoded + audited JWT token."""
    raw: str                                               # first 40 chars + "..."
    source: str = ""                                       # cookie name or header
    algorithm: str = ""
    header: dict = field(default_factory=dict)
    payload: dict = field(default_factory=dict)
    issues: List[str] = field(default_factory=list)        # "alg:none", "no_exp", etc.
    sensitive_fields: List[str] = field(default_factory=list)


@dataclass
class ProbeResult:
    """Aggregated findings from one HttpProbe.probe() call."""
    discovered_paths: Set[str] = field(default_factory=set)
    openapi_endpoints: List[OpenAPIEndpoint] = field(default_factory=list)
    openapi_spec_url: str = ""
    graphql_schema: Optional[GraphQLSchema] = None
    security_headers: Optional[SecurityHeaderResult] = None
    allowed_methods: Dict[str, List[str]] = field(default_factory=dict)   # path → [GET, POST, ...]
    error_fingerprints: List[dict] = field(default_factory=list)           # {path, status, tech, paths}
    jwt_findings: List[JWTAnalysis] = field(default_factory=list)
    tech_hints: List[str] = field(default_factory=list)


# ── Constants ────────────────────────────────────────────────────────────────

# GraphQL full introspection query
_GQL_INTROSPECTION_QUERY = {
    "query": """
    query IntrospectionQuery {
      __schema {
        queryType {
          fields {
            name
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind } }
          }
        }
        mutationType {
          fields {
            name
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind } }
          }
        }
        subscriptionType {
          fields {
            name
            args { name type { name kind ofType { name kind } } }
            type { name kind ofType { name kind } }
          }
        }
      }
    }
    """
}

# Common OpenAPI / Swagger spec paths to probe
_SPEC_PATHS = [
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs.json", "/api-docs/swagger.json",
    "/swagger.json", "/swagger.yaml",
    "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/swagger-ui.html",
    "/docs", "/redoc",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/api/openapi.json", "/api/swagger.json", "/api/docs",
    "/.well-known/openapi.json",
]

# Well-known discovery endpoints
_WELL_KNOWN_PATHS = [
    "/.well-known/openid-configuration",       # OIDC discovery — exposes all OAuth endpoints
    "/.well-known/oauth-authorization-server", # OAuth 2.0 server metadata (RFC 8414)
    "/.well-known/jwks.json",                  # JWT public key set (key exposure risk)
    "/.well-known/security.txt",               # Security disclosure / bug bounty scope
    "/.well-known/webfinger",                  # User discovery endpoint
]

# OIDC/OAuth metadata keys that contain endpoint URLs
_OIDC_ENDPOINT_KEYS = {
    "authorization_endpoint", "token_endpoint", "userinfo_endpoint",
    "revocation_endpoint", "introspection_endpoint", "end_session_endpoint",
    "registration_endpoint", "device_authorization_endpoint",
}

# Common GraphQL endpoint paths
_GQL_PATHS = [
    "/graphql", "/gql", "/graph",
    "/api/graphql", "/api/gql",
    "/graphql/v1", "/graphql/v2",
    "/query", "/graphiql",
]

# Security headers that MUST be present
_REQUIRED_SECURITY_HEADERS = [
    "x-frame-options",
    "x-content-type-options",
    "content-security-policy",
    "strict-transport-security",
    "referrer-policy",
    "permissions-policy",
]

# Headers that reveal tech stack
_TECH_REVEAL_HEADERS = [
    "x-powered-by",
    "server",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "x-drupal-cache",
    "x-wordpress-cache",
    "x-runtime",         # Rails
    "x-rack-cache",      # Rails/Rack
]

# JWT payload fields considered sensitive
_JWT_SENSITIVE_FIELDS = {
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "access_key",
    "ssn", "credit_card", "cc", "phone", "dob",
    "email",
    "admin", "is_admin", "role", "roles", "permissions", "scope",
    "private_key", "session", "pin",
}

# Error response body patterns → (regex, label)
_ERROR_FINGERPRINT_PATTERNS: List[Tuple[str, str]] = [
    (r'at\s+\w+\s+\(([^)]+\.(?:js|ts):\d+:\d+)\)',         "js_stack_trace"),
    (r'(?:File|in)\s+"([^"]+\.py)",\s+line\s+\d+',          "python_stack_trace"),
    (r'at\s+[\w.$]+\(([^)]+\.java:\d+)\)',                   "java_stack_trace"),
    (r'/(?:home|var|srv|app|usr|opt)/[^\s"\'<>,]+',         "internal_path"),
    (r'(?:django|flask|fastapi|tornado)\b',                  "python_framework"),
    (r'(?:rails|sinatra|rack)\b',                            "ruby_framework"),
    (r'(?:laravel|symfony|codeigniter|slim)\b',              "php_framework"),
    (r'(?:spring|tomcat|jersey|quarkus)\b',                  "java_framework"),
    (r'(?:mysql|postgres|postgresql|sqlite|mongodb|redis):',  "database"),
    (r'(?:PHP (?:Warning|Fatal|Notice|Error):)',              "php_error"),
    (r'(?:SyntaxError|TypeError|ValueError|AttributeError):\s*[^\n]{0,100}', "python_error"),
    (r'java\.(?:lang|io|util|sql)\.\w+(?:Exception|Error)',  "java_exception"),
    (r'Traceback \(most recent call last\)',                   "python_traceback"),
]


# ── HttpProbe ─────────────────────────────────────────────────────────────────

class HttpProbe:
    """
    Passive HTTP intelligence engine.

    Runs once at the START of ScoutLoop (before the LLM agentic loop)
    to give the AI maximum prior knowledge about the target's surface,
    spec, security posture, and API structure.
    """

    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self.timeout = timeout
        self.proxy = proxy

    async def probe(
        self,
        base_url: str,
        cookies: Optional[List[dict]] = None,
        endpoints_to_probe: Optional[List[str]] = None,
    ) -> ProbeResult:
        """
        Full passive probe. Runs all 7 intelligence gathering modules.

        Args:
            base_url:             Target origin (scheme + host, no trailing slash)
            cookies:              Auth cookies [{name, value, domain, ...}]
            endpoints_to_probe:   Known endpoint paths for OPTIONS + error probing
        """
        result = ProbeResult()
        base = base_url.rstrip("/")

        # JWT analysis from cookies — pure crypto, no network needed
        if cookies:
            result.jwt_findings = self._analyze_jwt_cookies(cookies)

        try:
            import httpx
        except ImportError:
            logger.warning("[HttpProbe] httpx not installed — skipping HTTP probing")
            return result

        # Build cookie header
        cookie_str = "; ".join(
            f"{c.get('name', '')}={c.get('value', '')}"
            for c in (cookies or []) if c.get("name") and c.get("value")
        )
        extra_headers = {"Cookie": cookie_str} if cookie_str else {}

        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=True,
            verify=False,
            proxies={"all://": self.proxy} if self.proxy else None,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                **extra_headers,
            },
        ) as client:
            # Phase 1 — Run passive scans concurrently (no write ops)
            await asyncio.gather(
                self._probe_robots_sitemap(client, base, result),
                self._probe_spec_endpoints(client, base, result),
                self._analyze_root_headers(client, base, result),
                self._probe_well_known(client, base, result),
                return_exceptions=True,
            )

            # Phase 2 — Active probing on discovered + known endpoints
            # Fallback paths ensure OPTIONS/error probing ALWAYS runs,
            # even on a cold start where robots.txt found nothing.
            _DEFAULT_PROBE_PATHS = [
                "/", "/api", "/api/v1", "/admin", "/auth", "/login",
            ]
            all_paths = list(result.discovered_paths) + (endpoints_to_probe or [])
            if not all_paths:
                all_paths = _DEFAULT_PROBE_PATHS
            sample = list(dict.fromkeys(all_paths))[:12]  # deduplicate, cap at 12

            await asyncio.gather(
                self._enumerate_options(client, base, sample, result),
                self._fingerprint_errors(client, base, sample[:6], result),
                return_exceptions=True,
            )

        self._log_summary(result)
        return result

    # ── 1. robots.txt + sitemap.xml ──────────────────────────────────────────

    async def _probe_robots_sitemap(
        self, client, base: str, result: ProbeResult
    ) -> None:
        """Fetch robots.txt — Disallow/Allow/Sitemap lines → discovered paths."""
        # robots.txt
        try:
            r = await client.get(f"{base}/robots.txt", timeout=6)
            if r.status_code == 200 and "text" in r.headers.get("content-type", "text"):
                sitemap_refs: List[str] = []
                for line in r.text.splitlines():
                    line = line.strip()
                    upper = line.upper()
                    if upper.startswith("DISALLOW:") or upper.startswith("ALLOW:"):
                        val = line.split(":", 1)[1].strip()
                        if val and val != "/" and val.startswith("/"):
                            # Strip wildcards: /admin* → /admin
                            path = val.split("*")[0].split("?")[0]
                            if path and path != "/":
                                result.discovered_paths.add(path)
                    elif upper.startswith("SITEMAP:"):
                        ref = line.split(":", 1)[1].strip()
                        if ref.startswith("http"):
                            sitemap_refs.append(ref)

                logger.debug(
                    f"[HttpProbe] robots.txt: {len(result.discovered_paths)} paths, "
                    f"{len(sitemap_refs)} sitemaps"
                )
                for ref in sitemap_refs:
                    await self._fetch_parse_sitemap(client, ref, base, result)
        except Exception as e:
            logger.debug(f"[HttpProbe] robots.txt: {e}")

        # sitemap.xml (try common paths)
        for sitemap_path in ("/sitemap.xml", "/sitemap_index.xml", "/sitemap.txt"):
            try:
                r = await client.get(f"{base}{sitemap_path}", timeout=6)
                if r.status_code == 200:
                    ct = r.headers.get("content-type", "")
                    sub_sitemaps = self._parse_sitemap_body(r.text, ct, base, result)
                    for sub_url in sub_sitemaps:
                        await self._fetch_parse_sitemap(client, sub_url, base, result)
                    break
            except Exception as e:
                logger.debug(f"[HttpProbe] {sitemap_path}: {e}")

    async def _fetch_parse_sitemap(
        self, client, url: str, base: str, result: ProbeResult,
        _depth: int = 0,
    ) -> None:
        """Fetch and parse a sitemap URL, recursively following sub-sitemaps (Fix 24)."""
        if _depth > 2:  # guard against infinite sub-sitemap loops
            return
        try:
            r = await client.get(url, timeout=6)
            if r.status_code == 200:
                sub_sitemaps = self._parse_sitemap_body(
                    r.text, r.headers.get("content-type", ""), base, result
                )
                for sub_url in sub_sitemaps:
                    await self._fetch_parse_sitemap(client, sub_url, base, result, _depth + 1)
        except Exception:
            pass

    def _parse_sitemap_body(
        self, content: str, content_type: str, base: str, result: ProbeResult
    ) -> List[str]:
        """Parse sitemap body and return list of sub-sitemap URLs to follow (Fix 24)."""
        base_host = urlparse(base).netloc
        stripped = content.strip()
        sub_sitemaps: List[str] = []

        if "xml" in content_type or stripped.startswith("<"):
            try:
                root = ET.fromstring(stripped)
                ns = "http://www.sitemaps.org/schemas/sitemap/0.9"

                # Fix 24: detect sitemapindex — collect child <sitemap><loc> refs
                for sitemap_el in root.iter(f"{{{ns}}}sitemap"):
                    loc_el = sitemap_el.find(f"{{{ns}}}loc")
                    if loc_el is not None:
                        sub_url = (loc_el.text or "").strip()
                        if sub_url.startswith("http"):
                            sub_sitemaps.append(sub_url)

                # Regular <url><loc> entries
                for loc in root.iter(f"{{{ns}}}loc"):
                    url = (loc.text or "").strip()
                    parsed = urlparse(url)
                    if parsed.netloc == base_host and parsed.path and parsed.path != "/":
                        result.discovered_paths.add(parsed.path)
            except ET.ParseError:
                # Fallback: regex
                for m in re.findall(r'<loc>([^<]+)</loc>', content):
                    parsed = urlparse(m.strip())
                    if parsed.netloc == base_host and parsed.path:
                        result.discovered_paths.add(parsed.path)
        else:
            # Plain-text sitemap
            for line in content.splitlines():
                url = line.strip()
                if url.startswith("http"):
                    parsed = urlparse(url)
                    if parsed.netloc == base_host and parsed.path:
                        result.discovered_paths.add(parsed.path)

        return sub_sitemaps

    # ── 2. OpenAPI / Swagger + GraphQL spec discovery ────────────────────────

    async def _probe_spec_endpoints(
        self, client, base: str, result: ProbeResult
    ) -> None:
        """Probe common spec paths. Parse whatever spec is found first."""
        # OpenAPI / Swagger
        for path in _SPEC_PATHS:
            try:
                r = await client.get(f"{base}{path}", timeout=6)

                # Auth-protected spec — note it so hunters know it exists
                # even though we cannot parse it without valid credentials.
                if r.status_code in (401, 403):
                    result.discovered_paths.add(path)
                    result.tech_hints.append(
                        f"OpenAPI spec found but auth-protected at {path} "
                        f"(HTTP {r.status_code}) — retry with valid auth cookies"
                    )
                    logger.warning(
                        f"[HttpProbe] OpenAPI spec at {path}: "
                        f"HTTP {r.status_code} (auth required)"
                    )
                    continue

                if r.status_code != 200:
                    continue
                ct = r.headers.get("content-type", "")
                body = r.text.lstrip()
                if "json" in ct or "yaml" in ct or body.startswith(("{", "openapi", "swagger")):
                    parsed = self._parse_openapi_spec(r.text)
                    if parsed:
                        result.openapi_endpoints = parsed
                        result.openapi_spec_url = f"{base}{path}"
                        logger.success(
                            f"[HttpProbe] OpenAPI spec at {path}: "
                            f"{len(parsed)} endpoints"
                        )
                        break
            except Exception as e:
                logger.debug(f"[HttpProbe] spec {path}: {e}")

        # GraphQL — try introspection on common paths
        for path in _GQL_PATHS:
            try:
                r = await client.post(
                    f"{base}{path}",
                    json=_GQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                    timeout=8,
                )
                if r.status_code == 200:
                    try:
                        data = r.json()
                    except Exception:
                        continue
                    schema = self._parse_graphql_introspection(data, f"{base}{path}")
                    if schema and (schema.queries or schema.mutations):
                        result.graphql_schema = schema
                        logger.success(
                            f"[HttpProbe] GraphQL introspection at {path}: "
                            f"{len(schema.queries)} queries, "
                            f"{len(schema.mutations)} mutations, "
                            f"{len(schema.subscriptions)} subscriptions"
                        )
                        break
            except Exception as e:
                logger.debug(f"[HttpProbe] graphql {path}: {e}")

    def _parse_openapi_spec(self, text: str) -> List[OpenAPIEndpoint]:
        """Parse OpenAPI 2.0 (Swagger) or OpenAPI 3.0 JSON or YAML."""
        endpoints: List[OpenAPIEndpoint] = []
        try:
            if text.lstrip().startswith("{"):
                spec = json.loads(text)
            else:
                try:
                    import yaml  # type: ignore
                    spec = yaml.safe_load(text)
                except ImportError:
                    # No yaml installed — try json anyway
                    spec = json.loads(text)
        except Exception as e:
            logger.debug(f"[HttpProbe] OpenAPI parse error: {e}")
            return endpoints

        if not isinstance(spec, dict):
            return endpoints

        # Global auth flag (Swagger 2 / OpenAPI 3)
        global_security = bool(
            spec.get("security")
            or spec.get("securityDefinitions")
            or (spec.get("components") or {}).get("securitySchemes")
        )

        for ep_path, methods in (spec.get("paths") or {}).items():
            if not isinstance(methods, dict):
                continue
            for method, op in methods.items():
                method = method.upper()
                if method not in {"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}:
                    continue
                if not isinstance(op, dict):
                    continue

                params: List[str] = []
                body_fields: List[str] = []
                auth_required = global_security or bool(op.get("security"))

                # Query / path parameters
                for param in (op.get("parameters") or []):
                    if isinstance(param, dict) and param.get("name"):
                        params.append(param["name"])

                # OpenAPI 3 requestBody
                req_body = op.get("requestBody") or {}
                if isinstance(req_body, dict):
                    for _, media_val in (req_body.get("content") or {}).items():
                        schema = (media_val or {}).get("schema") or {}
                        body_fields.extend((schema.get("properties") or {}).keys())

                # Swagger 2 body parameter
                for param in (op.get("parameters") or []):
                    if isinstance(param, dict) and param.get("in") == "body":
                        schema = param.get("schema") or {}
                        body_fields.extend((schema.get("properties") or {}).keys())

                endpoints.append(OpenAPIEndpoint(
                    path=ep_path,
                    method=method,
                    params=params,
                    body_fields=body_fields,
                    auth_required=auth_required,
                    summary=(op.get("summary") or op.get("description") or "")[:120],
                ))

        return endpoints

    def _parse_graphql_introspection(
        self, data: dict, endpoint: str
    ) -> Optional[GraphQLSchema]:
        """Extract queries/mutations/subscriptions from a GraphQL introspection response."""
        try:
            schema_data = (data.get("data") or {}).get("__schema") or {}
            if not schema_data:
                return None

            def _unwrap_type(type_node: Optional[dict]) -> str:
                """Fix 23: recursively unwrap NonNull/List wrappers to get base type name."""
                if not type_node:
                    return ""
                name = type_node.get("name")
                if name:
                    return name
                of_type = type_node.get("ofType")
                if of_type:
                    return _unwrap_type(of_type)
                return type_node.get("kind", "")

            def _extract_fields(type_info: Optional[dict]) -> List[GraphQLField]:
                if not type_info:
                    return []
                out: List[GraphQLField] = []
                for f in (type_info.get("fields") or []):
                    if not isinstance(f, dict) or not f.get("name"):
                        continue
                    args = [
                        a.get("name", "")
                        for a in (f.get("args") or [])
                        if isinstance(a, dict)
                    ]
                    # Fix 23: use recursive unwrap instead of single-level ofType check
                    type_name = _unwrap_type(f.get("type") or {})
                    out.append(GraphQLField(
                        name=f["name"],
                        type_name=type_name,
                        args=[a for a in args if a],
                    ))
                return out

            schema = GraphQLSchema(endpoint=endpoint)
            schema.queries = _extract_fields(schema_data.get("queryType"))
            schema.mutations = _extract_fields(schema_data.get("mutationType"))
            schema.subscriptions = _extract_fields(schema_data.get("subscriptionType"))
            return schema
        except Exception as e:
            logger.debug(f"[HttpProbe] GraphQL schema parse: {e}")
            return None

    # ── 3. Response header analysis ──────────────────────────────────────────

    async def _analyze_root_headers(
        self, client, base: str, result: ProbeResult
    ) -> None:
        """GET / and audit security headers + tech stack reveals."""
        try:
            r = await client.get(base, timeout=8)
        except Exception as e:
            logger.debug(f"[HttpProbe] root header fetch: {e}")
            return

        headers = {k.lower(): v for k, v in r.headers.items()}
        sec = SecurityHeaderResult()

        # Missing security headers
        for h in _REQUIRED_SECURITY_HEADERS:
            if h not in headers:
                sec.missing_headers.append(h)

        # Tech stack leakage
        for th in _TECH_REVEAL_HEADERS:
            if th in headers:
                val = headers[th]
                hint = f"{th}: {val}"
                sec.tech_hints.append(hint)
                result.tech_hints.append(hint)

        # CORS misconfiguration
        acao = headers.get("access-control-allow-origin", "")
        if acao:
            sec.cors_allowed_origin = acao
            if acao == "*":
                sec.cors_open = True
                sec.misconfigs.append({
                    "header": "Access-Control-Allow-Origin",
                    "value": "*",
                    "issue": "Wildcard CORS — any origin can read responses (CORS bypass risk)",
                })
            elif acao not in ("null", ""):
                # Non-wildcard CORS — just note it (may be misconfigured reflection)
                acac = headers.get("access-control-allow-credentials", "")
                if acac.lower() == "true":
                    sec.misconfigs.append({
                        "header": "Access-Control-Allow-Credentials",
                        "value": f"true (origin: {acao})",
                        "issue": "Credentialed CORS with specific origin — check if origin is reflected",
                    })

        # CSP issues
        csp = headers.get("content-security-policy", "")
        if csp:
            if "unsafe-inline" in csp:
                sec.misconfigs.append({
                    "header": "Content-Security-Policy",
                    "value": csp[:120],
                    "issue": "unsafe-inline allows inline <script> execution (XSS bypass)",
                })
            if "unsafe-eval" in csp:
                sec.misconfigs.append({
                    "header": "Content-Security-Policy",
                    "value": csp[:120],
                    "issue": "unsafe-eval allows eval() / Function() (XSS bypass)",
                })

        # HSTS: max-age=0 is effectively disabled
        hsts = headers.get("strict-transport-security", "")
        if hsts and "max-age=0" in hsts:
            sec.misconfigs.append({
                "header": "Strict-Transport-Security",
                "value": hsts,
                "issue": "max-age=0 disables HSTS — MITM downgrade attack possible",
            })

        # X-Frame-Options permissive
        xfo = headers.get("x-frame-options", "")
        if xfo and xfo.strip().upper() in ("ALLOWALL", "ALLOW-FROM *"):
            sec.misconfigs.append({
                "header": "X-Frame-Options",
                "value": xfo,
                "issue": "Permissive X-Frame-Options — Clickjacking risk",
            })

        # ── JWT in Set-Cookie response headers ───────────────────────────────
        # Previous code only decoded JWTs from REQUEST cookies passed in.
        # This catches tokens the server sets in the response itself.
        _jwt_re = re.compile(r'(ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)')
        for sc_val in r.headers.get_list("set-cookie"):
            for jwt_raw in _jwt_re.findall(sc_val):
                cookie_name = sc_val.split("=")[0].strip()
                analysis = self._decode_jwt(
                    jwt_raw, source=f"set-cookie:{cookie_name}"
                )
                if analysis:
                    result.jwt_findings.append(analysis)

        result.security_headers = sec

        if sec.missing_headers:
            logger.info(
                f"[HttpProbe] Missing security headers: {', '.join(sec.missing_headers)}"
            )
        if sec.misconfigs:
            logger.warning(
                f"[HttpProbe] {len(sec.misconfigs)} header misconfig(s): "
                + ", ".join(m["header"] for m in sec.misconfigs)
            )

    # ── 3b. .well-known/ discovery ───────────────────────────────────────────

    async def _probe_well_known(
        self, client, base: str, result: ProbeResult
    ) -> None:
        """
        Probe /.well-known/ discovery endpoints.

        OIDC configuration documents expose all OAuth auth/token/userinfo
        endpoints for free — better than guessing. JWKS endpoint signals
        that JWT public keys are accessible (useful for algorithm confusion
        attacks). security.txt reveals bug bounty scope and disclosure info.
        """
        for path in _WELL_KNOWN_PATHS:
            try:
                r = await client.get(f"{base}{path}", timeout=6)
                if r.status_code != 200:
                    continue

                result.discovered_paths.add(path)
                ct = r.headers.get("content-type", "")

                # Parse OIDC / OAuth metadata JSON for auth endpoint URLs
                if "json" in ct or "openid" in path or "oauth" in path or "jwks" in path:
                    try:
                        data = r.json()
                        if isinstance(data, dict):
                            found_eps: List[str] = []
                            for key in _OIDC_ENDPOINT_KEYS:
                                ep_url = data.get(key, "")
                                if ep_url and isinstance(ep_url, str):
                                    parsed = urlparse(ep_url)
                                    if parsed.path and parsed.path != "/":
                                        result.discovered_paths.add(parsed.path)
                                        found_eps.append(parsed.path)

                            issuer = data.get("issuer", "")
                            if issuer:
                                result.tech_hints.append(
                                    f"OIDC issuer: {issuer[:100]}"
                                )

                            if found_eps:
                                logger.success(
                                    f"[HttpProbe] .well-known {path}: "
                                    f"{len(found_eps)} OAuth endpoints found"
                                )
                    except Exception:
                        pass

                # JWKS — note that public key endpoint is exposed
                if "jwks" in path:
                    result.tech_hints.append(
                        f"JWKS public-key endpoint exposed: {path} "
                        "(algorithm confusion / key confusion attacks possible)"
                    )
                    logger.info(f"[HttpProbe] JWKS endpoint found: {path}")

                # security.txt — just note its presence
                if "security.txt" in path:
                    result.tech_hints.append(f"security.txt found at {path}")
                    logger.debug(f"[HttpProbe] security.txt found")

            except Exception as e:
                logger.debug(f"[HttpProbe] well-known {path}: {e}")

    # ── 4. HTTP OPTIONS enumeration ──────────────────────────────────────────

    async def _enumerate_options(
        self, client, base: str, paths: List[str], result: ProbeResult
    ) -> None:
        """
        Send OPTIONS request to each endpoint path.
        The Allow: header reveals which HTTP methods the server actually accepts.
        """
        async def _check_one(path: str) -> None:
            url = f"{base}{path}" if path.startswith("/") else path
            try:
                r = await client.options(url, timeout=5)
                allow = (
                    r.headers.get("allow")
                    or r.headers.get("access-control-allow-methods")
                    or ""
                )
                if allow:
                    methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
                    if methods:
                        result.allowed_methods[path] = methods
                        if any(m in methods for m in ("DELETE", "PUT", "PATCH")):
                            logger.debug(
                                f"[HttpProbe] OPTIONS {path}: {methods} "
                                f"(writable methods exposed)"
                            )
            except Exception:
                pass

        await asyncio.gather(
            *[_check_one(p) for p in paths[:15]],
            return_exceptions=True,
        )

    # ── 5. Error fingerprinting ──────────────────────────────────────────────

    async def _fingerprint_errors(
        self, client, base: str, paths: List[str], result: ProbeResult
    ) -> None:
        """
        Send intentionally malformed POST requests to trigger 4xx/5xx errors.
        Parse response bodies for stack traces, internal paths, framework names.
        """
        async def _probe_one(path: str) -> None:
            url = f"{base}{path}" if path.startswith("/") else path
            fingerprint: dict = {"path": path, "status": 0, "tech": [], "paths": []}
            try:
                r = await client.post(
                    url,
                    content=b'{"__xlayer_probe": true, "id": "\' OR 1=1--"}',
                    headers={"Content-Type": "application/json"},
                    timeout=6,
                )
                fingerprint["status"] = r.status_code
                if r.status_code in (400, 422, 500, 501, 502, 503):
                    body = r.text[:4000]
                    for pattern, label in _ERROR_FINGERPRINT_PATTERNS:
                        for m in re.finditer(pattern, body, re.IGNORECASE):
                            val = m.group(0)[:150]
                            if "path" in label:
                                fingerprint["paths"].append(val)
                            else:
                                fingerprint["tech"].append(f"{label}: {val}")
                    if fingerprint["tech"] or fingerprint["paths"]:
                        result.error_fingerprints.append(fingerprint)
                        logger.debug(
                            f"[HttpProbe] Error fingerprint {path} "
                            f"(HTTP {r.status_code}): "
                            f"{fingerprint['tech'][:2]}"
                        )
            except Exception:
                pass

        await asyncio.gather(
            *[_probe_one(p) for p in paths[:8]],
            return_exceptions=True,
        )

    # ── 6. JWT / cookie analysis ─────────────────────────────────────────────

    def _analyze_jwt_cookies(self, cookies: List[dict]) -> List[JWTAnalysis]:
        """
        Scan all cookie values for JWT tokens (ey... pattern).
        Decode header + payload (no signature needed) and audit for issues.
        """
        findings: List[JWTAnalysis] = []
        for cookie in cookies:
            value = cookie.get("value") or ""
            name = cookie.get("name") or ""
            # JWT: three base64url parts, header always starts with "ey"
            candidates = re.findall(
                r'(ey[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*)',
                value,
            )
            for jwt_raw in candidates:
                analysis = self._decode_jwt(jwt_raw, source=name)
                if analysis:
                    findings.append(analysis)
        return findings

    def _decode_jwt(self, token: str, source: str = "") -> Optional[JWTAnalysis]:
        """Decode JWT without verifying signature. Audit for common issues."""
        parts = token.split(".")
        if len(parts) != 3:
            return None

        def _b64decode(s: str) -> Optional[dict]:
            try:
                s += "=" * (4 - len(s) % 4)  # re-pad
                return json.loads(base64.urlsafe_b64decode(s).decode("utf-8", errors="replace"))
            except Exception:
                return None

        header = _b64decode(parts[0])
        payload = _b64decode(parts[1])
        if not header or not payload:
            return None

        analysis = JWTAnalysis(
            raw=token[:40] + "...",
            source=source,
            header=header,
            payload=payload,
            algorithm=header.get("alg", "unknown"),
        )

        # alg: none — no signature verification (critical)
        if analysis.algorithm.lower() in ("none", ""):
            analysis.issues.append("alg:none — server may accept unsigned tokens (critical)")

        # Weak algorithm — symmetric, brute-forceable
        if analysis.algorithm.upper() in ("HS256", "HS384", "HS512"):
            analysis.issues.append(
                f"weak_alg:{analysis.algorithm} — symmetric HMAC, "
                "susceptible to secret brute-force"
            )

        # No expiry
        if "exp" not in payload:
            analysis.issues.append("no_exp — token never expires")

        # Sensitive fields in payload
        for key in payload:
            if key.lower() in _JWT_SENSITIVE_FIELDS:
                analysis.sensitive_fields.append(key)
        if analysis.sensitive_fields:
            analysis.issues.append(
                f"sensitive_payload: {', '.join(analysis.sensitive_fields)}"
            )

        if analysis.issues:
            logger.warning(
                f"[HttpProbe] JWT in '{source}': "
                + " | ".join(analysis.issues)
            )

        return analysis

    # ── Summary logging ──────────────────────────────────────────────────────

    def _log_summary(self, result: ProbeResult) -> None:
        parts: List[str] = []
        if result.discovered_paths:
            parts.append(f"{len(result.discovered_paths)} robot/sitemap paths")
        if result.openapi_endpoints:
            parts.append(f"{len(result.openapi_endpoints)} OpenAPI endpoints")
        if result.graphql_schema:
            q = len(result.graphql_schema.queries)
            m = len(result.graphql_schema.mutations)
            s = len(result.graphql_schema.subscriptions)
            parts.append(f"GraphQL ({q}Q / {m}M / {s}Sub)")
        if result.security_headers:
            sec = result.security_headers
            parts.append(
                f"headers: {len(sec.missing_headers)} missing, "
                f"{len(sec.misconfigs)} misconfigs"
                + (" | CORS:*" if sec.cors_open else "")
            )
        if result.allowed_methods:
            parts.append(f"{len(result.allowed_methods)} OPTIONS mapped")
        if result.error_fingerprints:
            parts.append(f"{len(result.error_fingerprints)} error fingerprints")
        if result.jwt_findings:
            issues = sum(1 for j in result.jwt_findings if j.issues)
            parts.append(f"{len(result.jwt_findings)} JWT(s) decoded ({issues} with issues)")

        logger.success(f"[HttpProbe] Complete: {' | '.join(parts) or 'no findings'}")

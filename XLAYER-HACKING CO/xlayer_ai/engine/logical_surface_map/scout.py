"""
engine/logical_surface_map/scout.py — XLayer Agentic Logical Surface Mapper (LSM)
The "Strategic Scouting" phase kernel.

Integrated Discovery Strategies:
  - browser_crawl: Playwright headless browser — intercepts real XHR/fetch, navigates SPA routes.
  - js_crawling:   AST deep analysis of JS files — routes, secrets, taint, source maps.
  - api_guessing:  Reason-based route guessing.
  - param_mining:  Finding hidden logical parameters.
  - auth_scoping:  Mapping auth boundaries (Guest vs Protected).
"""

import asyncio
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse
from loguru import logger

# Internal imports
from xlayer_ai.engine.agentic_loop import _extract_json_block, _extract_think_block
from xlayer_ai.engine.llm import LLMClient
from xlayer_ai.engine.tool import Tool, ToolRegistry
from xlayer_ai.engine.logical_surface_map.graph import LogicalSurface, EndpointNode, TaintHint
from xlayer_ai.engine.logical_surface_map.js_analyzer import JSAnalyzer, VulnHint
from xlayer_ai.engine.logical_surface_map.browser_analyzer import BrowserAnalyzer, BrowserResult
from xlayer_ai.engine.logical_surface_map.http_probe import HttpProbe, ProbeResult
from xlayer_ai.engine.logical_surface_map.path_fuzzer import WordlistFuzzer, FuzzResult
from xlayer_ai.engine.logical_surface_map.lsm_tools import LSMTools, LSM_TOOL_SCHEMAS
from xlayer_ai.engine.logical_surface_map.supply_chain import SupplyChainMapper


# ── Scout State ──────────────────────────────────────────────────────────────

@dataclass
class ScoutState:
    """Unified memory structure for strategic discovery."""
    target_url: str
    iteration: int = 0
    surface: Optional[LogicalSurface] = field(default=None)
    current_strategy: str = "initial_recon"
    strategies_tried: Set[str] = field(default_factory=set)
    journal: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.surface is None:
            self.surface = LogicalSurface(base_url=self.target_url)

    def as_prompt(self) -> str:
        """Condensed context for the Reasoning Loop."""
        summary = self.surface.to_summary()
        return f"""
{summary}
Iteration: {self.iteration}/50 (Budget)
Current Strategy: {self.current_strategy}
Strategies Tried: {list(self.strategies_tried)}
Secrets: {len(self.surface.secrets)}
"""


# High-value param names to mine (security/recon relevance)
_PARAM_MINING_KEYS = frozenset({
    "id", "role", "debug", "admin", "test", "callback", "redirect", "token",
    "key", "session", "user", "auth", "secret", "file", "path", "cmd", "exec",
})

# Auth-related response hints
_AUTH_HINT_KEYS = ("login", "unauthorized", "sign-in", "sign_in", "forbidden", "401", "403", "authenticate")

# Tech stack hints (lowercase substrings to detect in response text)
_TECH_STACK_PATTERNS = (
    ("react", "React"), ("vue", "Vue"), ("angular", "Angular"), ("next", "Next.js"),
    ("jquery", "jQuery"), ("webpack", "Webpack"), ("vite", "Vite"), ("express", "Express"),
    ("django", "Django"), ("flask", "Flask"), ("laravel", "Laravel"), ("rails", "Rails"),
    ("graphql", "GraphQL"), ("rest", "REST"), ("grpc", "gRPC"),
)


# ── External Recon Helpers ────────────────────────────────────────────────

async def _run_subfinder(domain: str) -> List[str]:
    """
    Run subfinder for subdomain discovery. Returns list of subdomains.
    Silently returns [] if subfinder is not installed.
    """
    import shutil
    if not shutil.which("subfinder"):
        return []

    try:
        proc = await asyncio.create_subprocess_exec(
            "subfinder", "-d", domain, "-silent", "-timeout", "30",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=45)
        subs = [
            line.strip()
            for line in stdout.decode("utf-8", errors="replace").splitlines()
            if line.strip()
        ]
        return subs
    except Exception as e:
        logger.debug(f"[subfinder] error: {e}")
        return []


async def _run_httpx_fingerprint(urls: List[str]) -> List[Dict]:
    """
    Run httpx for live host detection + tech fingerprinting.
    Silently returns [] if httpx CLI is not installed.
    """
    import shutil
    if not shutil.which("httpx"):
        return []

    if not urls:
        return []

    try:
        input_data = "\n".join(urls).encode("utf-8")
        proc = await asyncio.create_subprocess_exec(
            "httpx", "-silent", "-json", "-tech-detect", "-timeout", "10",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(
            proc.communicate(input=input_data), timeout=60
        )
        results = []
        for line in stdout.decode("utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                results.append({
                    "url": data.get("url", ""),
                    "status": data.get("status_code", 0),
                    "tech": data.get("tech", []),
                    "title": data.get("title", ""),
                    "content_length": data.get("content_length", 0),
                })
            except json.JSONDecodeError:
                continue
        return results
    except Exception as e:
        logger.debug(f"[httpx] error: {e}")
        return []


def _normalize_url(base_url: str, url: str) -> str:
    """Resolve relative paths against base_url so endpoint keys are consistent."""
    url = (url or "").strip()
    if not url or url.startswith("http://") or url.startswith("https://"):
        return url
    base = base_url.rstrip("/")
    return f"{base}{url}" if url.startswith("/") else url


# ── Browser result merger ────────────────────────────────────────────────────

def _apply_browser_result(state: ScoutState, br: BrowserResult) -> None:
    """Merge BrowserResult findings into the LogicalSurface graph."""
    norm = lambda u: _normalize_url(state.surface.base_url, u)
    i = state.iteration

    # XHR-observed endpoints — highest confidence (actually called by the app)
    for path, method in br.endpoints.items():
        state.surface.add_endpoint(norm(path), method=method, source="browser_xhr")

    # SPA routes discovered via pushState / links / routerLink
    for route in br.spa_routes:
        full = norm(route)
        if full not in state.surface.endpoints:
            state.surface.add_endpoint(full, source="browser_spa")

    # JS files discovered → queue for static analysis
    state.surface.js_files.update(br.js_files)

    # Fix 21: WebSocket endpoints — register as endpoints for hunter analysis
    for ws_url in br.websocket_urls:
        state.surface.add_endpoint(ws_url, method="WS", source="browser_ws")
        state.journal.append(f"[{i}] WebSocket detected: {ws_url}")

    # Auth walls — paths that returned 401/403
    for path in br.auth_walls:
        full = norm(path)
        state.surface.add_endpoint(full, source="browser_xhr")
        state.surface.set_endpoint_auth(full, auth_required=True, role_level="user")
        state.journal.append(f"[{i}] AUTH WALL: {path} (browser 401/403)")

    # Forms → endpoints with discovered parameter names
    for form in br.forms:
        action = form.get("action", "")
        if not action:
            continue
        method = form.get("method", "POST")
        full_action = norm(action)
        state.surface.add_endpoint(full_action, method=method, source="browser_form")
        params = [inp["name"] for inp in form.get("inputs", []) if inp.get("name")]
        if params:
            state.surface.add_params_to_endpoint(full_action, params)

    # XHR POST body params — extract field names from observed request bodies.
    # browser_crawl captures post_data on every intercepted request, but the
    # original merger never used it. Now we parse JSON bodies and attach the
    # top-level field names as parameters to the matching endpoint.
    base_netloc = urlparse(state.surface.base_url).netloc
    for call in br.xhr_calls:
        if not call.post_data or call.method not in ("POST", "PUT", "PATCH"):
            continue
        parsed_url = urlparse(call.url)
        if parsed_url.netloc != base_netloc:
            continue
        try:
            body_data = json.loads(call.post_data)
        except Exception:
            continue
        if not isinstance(body_data, dict) or not body_data:
            continue
        params = [k for k in body_data if isinstance(k, str)]
        if params:
            full_path = norm(parsed_url.path)
            state.surface.add_params_to_endpoint(full_path, params)
            state.journal.append(
                f"[{i}] XHR POST PARAMS: {parsed_url.path} → {params[:6]}"
            )

    logger.success(
        f"[Browser] Merged: "
        f"{len(br.endpoints)} XHR endpoints, "
        f"{len(br.spa_routes)} SPA routes, "
        f"{len(br.auth_walls)} auth walls, "
        f"{len(br.forms)} forms, "
        f"{len(br.js_files)} JS files queued"
    )


def _apply_probe_result(state: ScoutState, pr: ProbeResult) -> None:
    """Merge HttpProbe findings into the LogicalSurface graph."""
    norm = lambda u: _normalize_url(state.surface.base_url, u)
    surface = state.surface

    # robots.txt / sitemap paths
    for path in pr.discovered_paths:
        full = norm(path)
        if full not in surface.endpoints:
            surface.add_endpoint(full, source="robots_sitemap")

    # OpenAPI endpoints — highest-fidelity source (method + params + auth)
    if pr.openapi_endpoints:
        surface.openapi_spec_url = pr.openapi_spec_url
        for ep in pr.openapi_endpoints:
            full = norm(ep.path)
            surface.add_endpoint(full, method=ep.method, source="openapi")
            if ep.params or ep.body_fields:
                surface.add_params_to_endpoint(full, ep.params + ep.body_fields)
            if ep.auth_required:
                surface.set_endpoint_auth(full, auth_required=True, role_level="user")

    # GraphQL schema — each query/mutation becomes a logical endpoint
    if pr.graphql_schema:
        gql = pr.graphql_schema
        surface.graphql_endpoint = gql.endpoint
        surface.graphql_queries = [f.name for f in gql.queries]
        surface.graphql_mutations = [f.name for f in gql.mutations]
        # Register the GraphQL endpoint itself
        surface.add_endpoint(gql.endpoint, method="POST", source="graphql")
        # Log each operation as an entity-level hint
        for q in gql.queries:
            args_str = f"({', '.join(q.args)})" if q.args else ""
            state.journal.append(
                f"[0] GQL QUERY: {q.name}{args_str} → {q.type_name}"
            )
        for m in gql.mutations:
            args_str = f"({', '.join(m.args)})" if m.args else ""
            state.journal.append(
                f"[0] GQL MUTATION: {m.name}{args_str} → {m.type_name}"
            )

    # Security header findings
    if pr.security_headers:
        sec = pr.security_headers
        surface.missing_security_headers = sec.missing_headers
        surface.security_header_misconfigs = sec.misconfigs
        surface.cors_open = sec.cors_open
        for hint in sec.tech_hints:
            surface.tech_stack[hint] = "header"

    # OPTIONS enumeration — actual allowed methods
    if pr.allowed_methods:
        surface.allowed_methods.update(pr.allowed_methods)
        # Upgrade method in endpoint graph if OPTIONS revealed non-GET
        for path, methods in pr.allowed_methods.items():
            full = norm(path)
            for m in methods:
                if m != "GET" and full in surface.endpoints:
                    # Don't downgrade — only upgrade
                    pass
            if full not in surface.endpoints and methods:
                surface.add_endpoint(full, method=methods[0], source="options_enum")

    # Error fingerprints — tech hints
    for fp in pr.error_fingerprints:
        for tech_str in fp.get("tech", []):
            surface.tech_stack[tech_str[:60]] = "error_fingerprint"
        for internal_path in fp.get("paths", []):
            state.journal.append(
                f"[0] ERROR FINGERPRINT: internal path leaked: {internal_path[:80]}"
            )

    # JWT issues
    for jwt in pr.jwt_findings:
        if jwt.issues:
            surface.jwt_issues.append({
                "source": jwt.source,
                "algorithm": jwt.algorithm,
                "issues": jwt.issues,
                "sensitive_fields": jwt.sensitive_fields,
            })
            state.journal.append(
                f"[0] JWT '{jwt.source}' (alg={jwt.algorithm}): "
                + " | ".join(jwt.issues)
            )

    # Tech hints
    for hint in pr.tech_hints:
        surface.tech_stack[hint[:60]] = "http_probe"

    logger.success(
        f"[HttpProbe] Merged: "
        f"{len(pr.discovered_paths)} robot/sitemap paths, "
        f"{len(pr.openapi_endpoints)} OpenAPI endpoints, "
        f"GraphQL={'yes' if pr.graphql_schema else 'no'}, "
        f"{len(pr.jwt_findings)} JWT(s)"
    )


def _apply_fuzz_result(state: ScoutState, fr: FuzzResult) -> None:
    """Merge WordlistFuzzer hits into the LogicalSurface graph."""
    norm = lambda u: _normalize_url(state.surface.base_url, u)
    i = state.iteration

    added = 0
    for hit in fr.hits:
        full = norm(hit.path)
        if full not in state.surface.endpoints:
            state.surface.add_endpoint(full, source="wordlist_fuzz")
            added += 1
        # 401/403 → mark as auth-required
        if hit.status in (401, 403):
            state.surface.add_endpoint(full, source="wordlist_fuzz")
            state.surface.set_endpoint_auth(full, auth_required=True, role_level="user")
            state.journal.append(f"[{i}] FUZZ AUTH WALL: {hit.path} (HTTP {hit.status})")
        # Redirects → note destination
        if hit.redirect_to:
            state.journal.append(
                f"[{i}] FUZZ REDIRECT: {hit.path} → {hit.redirect_to}"
            )

    logger.success(
        f"[Fuzzer] Merged: {len(fr.hits)} hits ({added} new), "
        f"{len(fr.auth_walls)} auth walls, "
        f"{fr.paths_tested} paths tested"
    )


# ── Strategy dispatch ────────────────────────────────────────────────────────

def _looks_like_js_or_bundle(text: str) -> bool:
    """Heuristic: content is JS source (or minified bundle), not JSON/HTML response."""
    if not text or len(text) < 200:
        return False
    head = text[:4000].lower()
    return (
        "function " in head or "=>" in head or "const " in head or "let " in head
        or "var " in head or "__webpack" in head or "esprima" in head
    )


async def _apply_discovery_logic(
    state: ScoutState,
    result_text: str,
    strategy: str,
    context_url: Optional[str] = None,
) -> None:
    """Updates the surface graph based on specific discovery strategy outcomes."""
    if not result_text:
        return

    # Skip general URL/tech extraction for JS bundle content — it pollutes the graph
    # with hundreds of false endpoints (URLs inside strings) and noisy tech_stack.
    # JSAnalyzer.analyze (js_crawling branch) is the single source of truth for JS.
    skip_general = strategy == "js_crawling" or _looks_like_js_or_bundle(result_text)
    if not skip_general:
        _extract_general_assets(state, result_text)

        # HATEOAS link extraction — find embedded URLs in JSON API responses.
        # Only run on JSON-like responses; parsing JS as JSON yields garbage.
        base_netloc = urlparse(state.surface.base_url).netloc
        hateoas_links = _extract_hateoas_links(result_text)
        for link in hateoas_links:
            parsed_link = urlparse(link)
            if parsed_link.netloc and parsed_link.netloc != base_netloc:
                continue
            path = parsed_link.path or link
            if path and path not in ("/", ""):
                state.surface.add_endpoint(
                    _normalize_url(state.surface.base_url, path),
                    source="hateoas",
                )
        if hateoas_links:
            logger.debug(f"[LSM] HATEOAS: {len(hateoas_links)} embedded link(s) extracted")

    base = state.surface.base_url
    norm = lambda u: _normalize_url(base, u)

    if strategy == "js_crawling":
        js_file_hint = context_url or ""

        # Single unified call — AST + secrets + source map all handled internally
        deep = await JSAnalyzer.analyze(result_text, url=js_file_hint)

        # Endpoints with method info
        for ep, method in deep.endpoints_with_method.items():
            state.surface.add_endpoint(norm(ep), method=method, source="js_deep")

        # Endpoints without method info (regex fallback or route config)
        for ep in deep.endpoints - set(deep.endpoints_with_method):
            state.surface.add_endpoint(norm(ep), source="js_crawling")

        # Secrets
        for s in deep.secrets:
            if s not in state.surface.secrets:
                state.surface.secrets.append(s)

        # Taint hints (XSS / Open Redirect / SSRF signals)
        for hint in deep.taint_hints:
            th = TaintHint(
                source=hint["source"],
                sink=hint["sink"],
                vuln_type=hint["vuln_type"],
                context=hint.get("context", ""),
                js_file=hint.get("js_file", js_file_hint),
            )
            state.surface.taint_hints.append(th)
            state.journal.append(
                f"[{state.iteration}] TAINT {hint['vuln_type'].upper()}: "
                f"{hint['source']} → {hint['sink']}"
            )

        # Framework detection → tech stack
        if deep.framework_detected:
            state.surface.tech_stack[deep.framework_detected] = "js_deep"

        # Route config auth metadata → graph (Vue/Angular/React Router)
        for route_url, auth_meta in deep.route_auth.items():
            full_route = norm(route_url)
            state.surface.add_endpoint(full_route, source="route_config")
            if auth_meta.get("auth_required"):
                state.surface.set_endpoint_auth(
                    full_route,
                    auth_required=True,
                    role_level=auth_meta.get("role_level", "user"),
                )
            if auth_meta.get("redirect_to"):
                state.journal.append(
                    f"[{state.iteration}] ROUTE {full_route} → "
                    f"redirectTo={auth_meta['redirect_to']} (public)"
                )
        if deep.route_auth:
            protected = [u for u, a in deep.route_auth.items() if a.get("auth_required")]
            logger.info(
                f"[LSM] route_config: {len(deep.route_auth)} routes, "
                f"{len(protected)} protected "
                f"({', '.join(protected[:5])})"
            )

        if deep.taint_hints:
            logger.warning(
                f"[LSM] {len(deep.taint_hints)} taint hint(s) in {js_file_hint}: "
                + ", ".join(f"{h['vuln_type']}({h['source']}→{h['sink']})" for h in deep.taint_hints)
            )

        # Source map findings (merged into deep result by analyze())
        state.surface.vuln_hints.extend([
            {"vuln_type": h.vuln_type, "evidence": h.evidence,
             "confidence": h.confidence, "source_file": h.source_file,
             "context": h.context}
            for h in deep.vuln_hints
        ])
        state.surface.dev_comments.extend(deep.dev_comments)
        state.surface.sourcemap_sources.extend(deep.sourcemap_sources)

        for h in deep.vuln_hints:
            if h.confidence == "high":
                state.journal.append(
                    f"[{state.iteration}] SOURCEMAP VULN HINT [{h.vuln_type.upper()}]: "
                    f"{h.evidence}() in {h.source_file}"
                )
        for c in deep.dev_comments:
            if c["severity"] == "high":
                state.journal.append(
                    f"[{state.iteration}] SOURCEMAP COMMENT [{c['keyword'].upper()}]: "
                    f"{c['text'][:80]} in {c['source_file']}"
                )

        if deep.sourcemap_sources:
            logger.success(
                f"[SourceMap] {len(deep.sourcemap_sources)} files → "
                f"{len(deep.endpoints)} endpoints, "
                f"{len(deep.vuln_hints)} vuln hints, "
                f"{len(deep.secrets)} secrets"
            )

        # Supply chain scan — run on every JS bundle analyzed
        try:
            from urllib.parse import urlparse as _up
            _base_domain = _up(state.surface.base_url).netloc
            _sc_mapper = SupplyChainMapper()
            _sc_findings = _sc_mapper.scan(result_text, source_file=js_file_hint)
            _sc_findings += _sc_mapper.scan_subdomains(result_text, _base_domain)
            for f in _sc_findings:
                state.surface.supply_chain_findings.append(f.to_dict())
                if f.severity in ("critical", "high"):
                    state.journal.append(
                        f"[{state.iteration}] SUPPLY_CHAIN [{f.severity.upper()}] "
                        f"{f.service}: {f.description[:80]}"
                    )
            if _sc_findings:
                logger.info(
                    f"[SupplyChain] {len(_sc_findings)} finding(s) in {js_file_hint}"
                )
        except Exception as _sc_e:
            logger.debug(f"[SupplyChain] scan error: {_sc_e}")

    elif strategy == "api_guessing":
        existing = {url for url in state.surface.endpoints.keys()}
        guesses = JSAnalyzer.generate_guessing_logic(existing)
        for g in guesses:
            state.surface.add_endpoint(norm(g), source="api_guessing")

    elif strategy == "param_mining":
        param_patterns = [
            r"(?<![a-zA-Z0-9_])([a-zA-Z0-9_\-]+)\s*=",
            r'["\']([a-zA-Z0-9_\-]+)["\']\s*[:=]',
        ]
        found: Set[str] = set()
        for pat in param_patterns:
            for m in re.findall(pat, result_text):
                name = (m if isinstance(m, str) else m[0]).lower()
                if name in _PARAM_MINING_KEYS:
                    found.add(name)
        # Only attach params to the specific probed endpoint.
        # Previously the else-branch broadcast params to ALL api/admin endpoints —
        # one response could incorrectly annotate dozens of unrelated endpoints.
        if found and context_url:
            ctx = norm(context_url)
            if ctx in state.surface.endpoints:
                state.surface.add_params_to_endpoint(ctx, list(found))

    elif strategy == "auth_scoping":
        if any(k in result_text.lower() for k in _AUTH_HINT_KEYS):
            # Only mark the specific probed endpoint as auth-required.
            # Previously the else-branch marked ALL api/admin/auth endpoints when
            # context_url was missing — a single 401 response polluted the whole graph.
            if context_url:
                ctx = norm(context_url)
                if ctx in state.surface.endpoints:
                    state.surface.set_endpoint_auth(
                        ctx, auth_required=True, role_level="user"
                    )


_HATEOAS_LINK_KEYS = frozenset({
    "href", "url", "uri", "link", "self", "next", "prev", "previous",
    "first", "last", "related", "alternate", "location", "canonical",
})


def _extract_hateoas_links(text: str) -> List[str]:
    """
    Parse JSON from tool result text and recursively extract URLs embedded
    in HATEOAS-style keys (href, url, _links, links, self, next, etc.).

    Handles both flat dicts and nested HAL+JSON structures:
      {"_links": {"self": {"href": "/api/users/1"}, "next": {"href": "..."}}}
      {"items": [{"url": "/api/item/1"}, ...]}
    """
    # Find the start of JSON object or array
    json_start = text.find("{")
    if json_start < 0:
        json_start = text.find("[")
    if json_start < 0:
        return []
    try:
        data = json.loads(text[json_start:])
    except Exception:
        return []

    found: List[str] = []

    def _walk(obj, depth: int = 0) -> None:
        if depth > 8:      # cap recursion depth
            return
        if isinstance(obj, dict):
            for k, v in obj.items():
                k_lower = k.lower().lstrip("_")
                if k_lower in _HATEOAS_LINK_KEYS and isinstance(v, str):
                    if v.startswith("/") or v.startswith("http"):
                        found.append(v)
                elif k_lower in ("links", "embedded", "_embedded") and isinstance(v, dict):
                    # HAL+JSON: {"_links": {"users": {"href": "..."}, ...}}
                    for link_val in v.values():
                        if isinstance(link_val, dict):
                            href = link_val.get("href") or link_val.get("url") or ""
                            if href and (href.startswith("/") or href.startswith("http")):
                                found.append(href)
                        elif isinstance(link_val, str) and (
                            link_val.startswith("/") or link_val.startswith("http")
                        ):
                            found.append(link_val)
                elif isinstance(v, (dict, list)):
                    _walk(v, depth + 1)
        elif isinstance(obj, list):
            for item in obj[:30]:   # cap list iteration
                _walk(item, depth + 1)

    _walk(data)
    return list(set(found))


async def _generate_tech_paths(llm: LLMClient, tech_stack: dict) -> List[str]:
    """
    Change 1: LLM knowledge-based path generation.

    Instead of a static wordlist, ask the LLM to generate framework-specific
    high-value paths based on the detected tech stack. LLM training data already
    knows common admin panels, debug endpoints, API docs, and health checks for
    every major framework — no wordlist needed for these.
    """
    # Bug 2 fix: if tech_stack is empty (no headers detected), still run —
    # pass base_url so LLM can infer framework from domain/path hints.
    if tech_stack:
        tech_list = ", ".join(list(tech_stack.keys())[:8])
        tech_context = f"Detected tech stack: {tech_list}"
    else:
        tech_list = "unknown"
        tech_context = "Tech stack unknown — use common web framework defaults"

    try:
        msg = await llm.call(messages=[
            {"role": "system", "content": (
                "You are a senior pentester. Given a tech stack (or best guess), "
                "output ONLY a JSON array of high-value paths to probe. Include: "
                "admin panels, debug endpoints, API docs, health checks, "
                "framework-specific hidden routes, config/env endpoints, backup files. "
                "No explanation. JSON array only."
            )},
            {"role": "user", "content": (
                f"{tech_context}\n"
                "Output 20-40 high-value paths specific to this stack. JSON array only."
            )},
        ])
        content = msg.content or ""
        start = content.find("[")
        end   = content.rfind("]") + 1
        if start >= 0 and end > start:
            paths = json.loads(content[start:end])
            valid = [p for p in paths if isinstance(p, str) and p.startswith("/")]
            logger.info(f"[LSM] LLM tech-paths: {len(valid)} paths for [{tech_list}]")
            return valid
    except Exception as e:
        logger.debug(f"[LSM] tech path generation failed: {e}")
    return []


async def _quick_probe_new_endpoints(
    state: ScoutState,
    lsm_tools,
    new_endpoints: Set[str],
) -> None:
    """
    Change 2: Continuous recon-exploit loop.

    When new endpoints are discovered, immediately probe them instead of
    waiting for the Hunt phase. Catches auth walls, parameter reflection,
    and tech hints in the same iteration — feeds results back into surface.

    Capped at 5 per call to avoid slowing the main loop.
    """
    if not new_endpoints:
        return

    targets = list(new_endpoints)[:5]
    logger.debug(f"[LSM] Quick probe: {len(targets)} new endpoint(s)")

    base_netloc = urlparse(state.surface.base_url).netloc

    for ep_url in targets:
        try:
            # Bug 1 fix: check_endpoint expects a path (/api/users), not a full URL.
            # ep_url may be full (https://target.com/api/users) — extract path only.
            parsed = urlparse(ep_url)
            if parsed.netloc and parsed.netloc != base_netloc:
                continue  # cross-origin — skip
            path = parsed.path or ep_url
            if not path or path == "/":
                continue

            # Use check_endpoint — returns status + headers + body snippet
            result = await lsm_tools.call("check_endpoint", {"path": path})
            if not result:
                continue

            result_lower = result.lower()

            # Auth wall detection
            if any(k in result_lower for k in _AUTH_HINT_KEYS):
                state.surface.set_endpoint_auth(ep_url, auth_required=True, role_level="user")
                state.journal.append(f"[quick_probe] AUTH WALL: {ep_url}")

            # Param mining on response body
            await _apply_discovery_logic(
                state, result, "param_mining", context_url=ep_url
            )

            # Tech stack hints from response
            _extract_general_assets(state, result)

            logger.debug(f"[LSM] Quick probe done: {ep_url}")
        except Exception as e:
            logger.debug(f"[LSM] Quick probe failed {ep_url}: {e}")


def _prioritize_js_files(js_files: Set[str], max_files: int = 15) -> List[str]:
    """
    Bug 3 fix: smart JS file prioritization instead of arbitrary [:10] slice.

    Priority order:
      1. main / app / index bundles  (most likely to have routes + secrets)
      2. chunk files with low numeric hash  (early chunks = core logic)
      3. vendor / lib / runtime bundles  (framework code — lower value)
      4. everything else

    Caps at max_files (default 15) after sorting.
    """
    def _score(url: str) -> int:
        name = url.rsplit("/", 1)[-1].lower()
        if any(k in name for k in ("main.", "app.", "index.", "bundle.")):
            return 0
        if any(k in name for k in ("chunk.", "page.", "route.", "module.")):
            return 1
        if any(k in name for k in ("vendor.", "lib.", "runtime.", "polyfill.")):
            return 3
        return 2

    sorted_files = sorted(js_files, key=_score)
    return sorted_files[:max_files]


async def _auto_analyze_js_files(
    state: ScoutState,
    lsm_tools,
    js_files: Set[str],
    max_files: int = 15,
) -> None:
    """
    Automatically fetch + JSAnalyzer every JS bundle discovered by BrowserAnalyzer.

    Called immediately after browser_crawl — no LLM iteration wasted.
    Prioritizes main/app bundles first, caps at max_files (default 15).
    """
    if not js_files:
        return

    candidates = _prioritize_js_files(js_files, max_files)
    logger.info(f"[LSM] Auto JS analysis: {len(candidates)}/{len(js_files)} bundle(s)")

    for js_url in candidates:
        try:
            content = await lsm_tools.call("fetch_js", {"url": js_url})
            if not content:
                logger.debug(f"[LSM] Auto JS: empty response for {js_url}")
                continue
            await _apply_discovery_logic(
                state, content, "js_crawling", context_url=js_url
            )
            state.journal.append(f"[{state.iteration}] AUTO JS: {js_url}")
        except Exception as e:
            logger.debug(f"[LSM] Auto JS failed {js_url}: {e}")


def _extract_general_assets(state: ScoutState, text: str) -> None:
    """Utility to extract URLs and tech stack from any result."""
    url_pattern = re.compile(r'https?://[^\s\'"<>)(,\]]+')
    static_exts = {'.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.css', '.ico'}
    base_netloc = urlparse(state.surface.base_url).netloc

    for match in url_pattern.finditer(text):
        url = match.group(0).rstrip('.,;)/\\')
        if any(ext in url.lower() for ext in static_exts):
            continue
        # Same-origin filter — skip CDN / third-party URLs (Google, Cloudflare,
        # jQuery, FontAwesome, etc.) that will never be target endpoints.
        parsed_u = urlparse(url)
        if parsed_u.netloc and parsed_u.netloc != base_netloc:
            # Fix 25: cross-origin JS files are still worth analyzing
            # (app bundles often served from CDN sub-domains like assets.example.com)
            if url.endswith('.js'):
                state.surface.js_files.add(url)
            continue
        if url.endswith('.js'):
            state.surface.js_files.add(url)
        else:
            state.surface.add_endpoint(url, source="spider")

    low = text.lower()
    for key, label in _TECH_STACK_PATTERNS:
        if key in low and label not in state.surface.tech_stack:
            state.surface.tech_stack[label] = "detected"


# ── Scout Loop (Discovery Architecture) ────────────────────────────────────

class ScoutLoop:
    """
    Discovery Architecture.

    Two-phase design:
      Phase 1 (Parallel Agents): All discovery agents run simultaneously
        - HttpProbeAgent: robots, sitemap, OpenAPI, GraphQL, headers, JWT
        - BrowserCrawlAgent: Playwright crawl + auto JS analysis
        - SubdomainAgent: subfinder + httpx fingerprint
        - WordlistFuzzAgent: 300-path wordlist + smart expansion
        - TechFuzzAgent: LLM tech-aware path generation (after Phase A)
        - SupplyChainAgent: CVE hints from detected tech stack

      Phase 2 (Gap-Fill Loop): Reduced LLM loop (10 iters max)
        - Only runs if parallel agents missed gaps
        - Focuses on: param_mining, auth_scoping, behavior_probe, IDOR
        - Much faster than the old 50-iteration sequential loop

    Architecture: Coordinator → ScoutLoop (parallel agents + gap-fill) → DomainScoring → Solvers
    """

    GAP_FILL_PROMPT = """
You are the 'Gap Filler' — the final pass of agentic reconnaissance.
Parallel discovery agents have ALREADY completed. The surface below reflects
ALL findings from: HTTP probe, browser crawl, subdomain discovery, JS analysis,
wordlist fuzzing, tech-path fuzzing, and supply chain scanning.

Your job: fill remaining gaps that automated agents missed.

## What's Already Done (DO NOT repeat these):
- HTTP Probe: robots.txt, sitemap, OpenAPI, GraphQL, security headers, JWT
- Browser Crawl: XHR endpoints, SPA routes, forms, auth walls, JS bundles
- JS Analysis: AST deep analysis of all JS bundles (endpoints, secrets, taint)
- Subdomain Discovery: subfinder + httpx fingerprint
- Wordlist Fuzz: 300+ paths tested with smart expansion
- Tech Fuzz: LLM-generated framework-specific paths tested

## What You Should Focus On:
1. 'param_mining': Discover hidden params on interesting endpoints
2. 'auth_scoping': Map auth boundaries on new endpoints
3. 'behavior_probe': Profile high-value endpoints (WAF, SQL error, reflection)
4. 'jit_code': Custom recon scripts for edge cases (IDOR checks, JWT decode)
5. 'js_crawling': Only if specific JS files were missed by auto-analysis

## Reasoning Protocol
<think>
What parallel agents found: [summary of current surface]
What's missing: [specific gaps — params unmined, auth unclear, behavior unknown]
Next action: [why this fills the most critical gap]
</think>

## Decision Format:
```json
{
  "action": "tool_call",
  "tool": "behavior_probe",
  "args": {"url": "https://target.com/api/search?q=test"},
  "strategy": "param_mining",
  "reasoning": "..."
}
```
Or to finish:
```json
{
  "action": "conclude",
  "reasoning": "All gaps filled."
}
```
"""

    def __init__(
        self,
        llm: LLMClient,
        tools: List[Tool],
        jit_engine: Any,
        browser: bool = True,
        browser_headless: bool = True,
        browser_proxy: Optional[str] = None,
        http_probe: bool = True,
        probe_timeout: int = 10,
        gap_fill_iters: int = 10,
    ):
        self.llm = llm
        self._proxy = browser_proxy
        self._browser = browser
        self._browser_headless = browser_headless
        self._probe_timeout = probe_timeout
        self._gap_fill_iters = gap_fill_iters

        # Build schema-only Tool wrappers so the LLM knows about LSM tools.
        # Actual execution is handled by LSMTools (async), not ToolRegistry.
        _dummy_fn = lambda **kw: ""
        _lsm_schema_tools = [
            Tool(
                name=s["name"],
                description=s["description"],
                parameters=s["parameters"],
                func=_dummy_fn,
            )
            for s in LSM_TOOL_SCHEMAS
        ]
        self.registry = ToolRegistry(tools + _lsm_schema_tools)

        self.jit = jit_engine

    async def run(self, url: str, auth_cookies: Optional[List[dict]] = None) -> LogicalSurface:
        import time as _time
        start = _time.monotonic()

        # ══════════════════════════════════════════════════════════════════
        # PHASE 1: Parallel Discovery Agents
        # All agents run simultaneously — no sequential phases
        # ══════════════════════════════════════════════════════════════════
        from xlayer_ai.engine.logical_surface_map.discovery_agents import DiscoveryOrchestrator

        orchestrator = DiscoveryOrchestrator(
            llm=self.llm,
            proxy=self._proxy,
            browser=self._browser,
            browser_headless=self._browser_headless,
            probe_timeout=self._probe_timeout,
        )
        surface = await orchestrator.run(url, cookies=auth_cookies)

        phase1_time = _time.monotonic() - start
        phase1_eps = len(surface.endpoints)
        logger.info(
            f"[ScoutLoop] Phase 1 (Parallel Agents) complete: "
            f"{phase1_eps} endpoints in {phase1_time:.1f}s"
        )

        # ══════════════════════════════════════════════════════════════════
        # PHASE 2: LLM Gap-Fill Loop (reduced — 10 iters max)
        # Only fills gaps that parallel agents missed:
        # param mining, auth scoping, behavior profiling, edge cases
        # ══════════════════════════════════════════════════════════════════
        state = ScoutState(target_url=url, surface=surface)

        _lsm_tools = LSMTools(
            base_url=url,
            timeout=15,
            proxy=self._proxy,
            cookies=auth_cookies,
        )

        logger.info(
            f"[ScoutLoop] Phase 2 (Gap-Fill): up to {self._gap_fill_iters} "
            f"iterations for param/auth/behavior gaps"
        )

        async with _lsm_tools as lsm_tools:
            for i in range(1, self._gap_fill_iters + 1):
                state.iteration = i
                context = state.as_prompt()

                # 1. Ask LLM for next gap-fill action
                try:
                    ai_msg = await self.llm.call(
                        messages=[
                            {"role": "system", "content": self.GAP_FILL_PROMPT},
                            {"role": "user",   "content": f"{context}\n\nDecision?"},
                        ],
                        tools=self.registry.all(),
                    )
                except Exception as e:
                    logger.error(f"[GapFill] LLM Error: {e}")
                    continue

                # 2a. Extract CoT reasoning
                think_content = _extract_think_block(ai_msg.content or "")
                if think_content:
                    state.journal.append(
                        f"[GF-{i}] <think> {think_content[:200].replace(chr(10), ' ')}"
                    )

                # 2b. Parse action
                data = _extract_json_block(ai_msg.content or "")
                if not data:
                    try:
                        retry_msg = await self.llm.call(
                            messages=[
                                {"role": "system",    "content": self.GAP_FILL_PROMPT},
                                {"role": "user",      "content": f"{context}\n\nDecision?"},
                                {"role": "assistant", "content": ai_msg.content or ""},
                                {"role": "user",      "content": (
                                    "Your response must be a JSON block. No prose. Respond now."
                                )},
                            ],
                            tools=self.registry.all(),
                        )
                        data = _extract_json_block(retry_msg.content or "")
                    except Exception:
                        pass
                    if not data:
                        continue

                action   = data.get("action", "think")
                strategy = data.get("strategy", state.current_strategy)
                args     = data.get("args") or {}
                state.current_strategy = strategy
                state.strategies_tried.add(strategy)

                if action == "conclude":
                    logger.success(
                        f"[GapFill] Complete at iteration {i}/{self._gap_fill_iters}"
                    )
                    break

                # 3. Execute action
                tool_result = ""
                if action in ("tool_call", "tool"):
                    tool_name = data.get("tool", "")
                    if lsm_tools.has_tool(tool_name):
                        logger.info(f"[GapFill] {tool_name}({args})")
                        tool_result = await lsm_tools.call(tool_name, args)

                        # behavior_probe → store in surface
                        if tool_name == "behavior_probe" and tool_result:
                            try:
                                bp_data = json.loads(tool_result)
                                bp_url = bp_data.get("url", args.get("url", ""))
                                if bp_url and "error" not in bp_data:
                                    state.surface.behavior_profiles[bp_url] = bp_data
                                    hints = []
                                    if bp_data.get("waf_detected"):
                                        hints.append(f"WAF:{bp_data.get('waf_name', '?')}")
                                    if bp_data.get("error_signature"):
                                        hints.append(f"FW:{bp_data['error_signature']}")
                                    if bp_data.get("sql_error_on_quote"):
                                        hints.append("SQL_ERROR")
                                    if bp_data.get("reflects_input"):
                                        hints.append("REFLECTS")
                                    if hints:
                                        state.journal.append(
                                            f"[GF-{i}] BEHAVIOR {bp_url}: {' | '.join(hints)}"
                                        )
                            except (json.JSONDecodeError, TypeError):
                                pass
                    else:
                        tool_result = self.registry.execute(tool_name, args)

                elif action in ("jit_code", "jit"):
                    if self.jit:
                        loop = asyncio.get_running_loop()
                        res = await loop.run_in_executor(
                            None,
                            lambda: self.jit.run(data.get("code", ""), {"url": url}),
                        )
                        tool_result = res.stdout if res.success else res.stderr

                # 4. Apply discovery logic to tool output
                context_url: Optional[str] = None
                if isinstance(args, dict):
                    context_url = args.get("url") or args.get("path")
                if tool_result:
                    _eps_before = set(state.surface.endpoints.keys())
                    await _apply_discovery_logic(
                        state, tool_result, strategy, context_url=context_url
                    )
                    state.journal.append(f"[GF-{i}] {strategy} → processed")

                    # Quick-probe newly discovered endpoints
                    _new_eps = set(state.surface.endpoints.keys()) - _eps_before
                    if _new_eps:
                        await _quick_probe_new_endpoints(state, lsm_tools, _new_eps)

        total_time = _time.monotonic() - start
        logger.success(
            f"[ScoutLoop] Done: {len(state.surface.endpoints)} endpoints total "
            f"({phase1_eps} from agents, "
            f"{len(state.surface.endpoints) - phase1_eps} from gap-fill) "
            f"in {total_time:.1f}s"
        )

        return state.surface

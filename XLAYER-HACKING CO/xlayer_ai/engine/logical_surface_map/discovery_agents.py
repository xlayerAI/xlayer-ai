"""
engine/logical_surface_map/discovery_agents.py — Parallel Discovery Agents

Independent Discovery Agents run in PARALLEL before any solver.
Each agent focuses on one reconnaissance domain, returns findings, and exits.
Results merge into a unified LogicalSurface.

Architecture:
    DiscoveryOrchestrator
        ├── HttpProbeAgent      (parallel) — robots, sitemap, OpenAPI, GraphQL, headers, JWT
        ├── BrowserCrawlAgent   (parallel) — Playwright headless + auto JS analysis
        ├── SubdomainAgent      (parallel) — subfinder + httpx fingerprint
        ├── TechFuzzAgent       (parallel) — LLM tech-aware path fuzzing
        ├── SupplyChainAgent    (parallel) — CVE hints from tech stack + JS bundles
        └── WordlistFuzzAgent   (parallel) — 300-path wordlist + smart expansion

All agents run simultaneously via asyncio.gather().
After all agents complete, results merge → domain scoring → solver dispatch.
"""

import asyncio
import json
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from loguru import logger


@dataclass
class DiscoveryResult:
    """Unified output from any discovery agent."""
    agent_name: str
    endpoints: Dict[str, Dict[str, Any]] = field(default_factory=dict)  # {url: {method, source, params}}
    js_files: Set[str] = field(default_factory=set)
    tech_stack: Dict[str, str] = field(default_factory=dict)            # {tech: source}
    secrets: List[Dict[str, str]] = field(default_factory=list)
    auth_walls: Set[str] = field(default_factory=set)                   # URLs with 401/403
    forms: List[dict] = field(default_factory=list)
    jwt_findings: List[dict] = field(default_factory=list)
    taint_hints: List[dict] = field(default_factory=list)
    supply_chain: List[dict] = field(default_factory=list)
    vuln_hints: List[dict] = field(default_factory=list)
    dev_comments: List[dict] = field(default_factory=list)
    sourcemap_sources: List[str] = field(default_factory=list)
    behavior_profiles: Dict[str, Any] = field(default_factory=dict)
    journal_entries: List[str] = field(default_factory=list)

    # HTTP Probe specific
    openapi_spec_url: str = ""
    graphql_endpoint: str = ""
    graphql_queries: List[str] = field(default_factory=list)
    graphql_mutations: List[str] = field(default_factory=list)
    security_header_misconfigs: List[dict] = field(default_factory=list)
    missing_security_headers: List[str] = field(default_factory=list)
    allowed_methods: Dict[str, List[str]] = field(default_factory=dict)
    cors_open: bool = False

    # Timing
    duration_seconds: float = 0.0
    error: str = ""


class BaseDiscoveryAgent(ABC):
    """Base class for all discovery agents. Each agent runs independently."""

    name: str = "base"

    @abstractmethod
    async def discover(
        self,
        target_url: str,
        cookies: Optional[List[dict]] = None,
        shared_context: Optional[Dict[str, Any]] = None,
    ) -> DiscoveryResult:
        """Run discovery and return findings."""
        ...


class HttpProbeAgent(BaseDiscoveryAgent):
    """
    Agent 1: Passive HTTP Intelligence.
    robots.txt, sitemap, OpenAPI/Swagger, GraphQL introspection,
    security headers, OPTIONS enumeration, error fingerprinting, JWT analysis.
    """
    name = "http_probe"

    def __init__(self, timeout: int = 10, proxy: Optional[str] = None):
        self._timeout = timeout
        self._proxy = proxy

    async def discover(self, target_url, cookies=None, shared_context=None):
        start = time.monotonic()
        result = DiscoveryResult(agent_name=self.name)

        try:
            from xlayer_ai.engine.logical_surface_map.http_probe import HttpProbe
            probe = HttpProbe(timeout=self._timeout, proxy=self._proxy)
            pr = await probe.probe(base_url=target_url, cookies=cookies, endpoints_to_probe=None)

            # robots.txt / sitemap paths
            for path in pr.discovered_paths:
                result.endpoints[_normalize(target_url, path)] = {
                    "method": "GET", "source": "robots_sitemap",
                }

            # OpenAPI endpoints
            if pr.openapi_endpoints:
                result.openapi_spec_url = pr.openapi_spec_url
                for ep in pr.openapi_endpoints:
                    full = _normalize(target_url, ep.path)
                    result.endpoints[full] = {
                        "method": ep.method, "source": "openapi",
                        "params": ep.params + ep.body_fields,
                        "auth_required": ep.auth_required,
                    }

            # GraphQL
            if pr.graphql_schema:
                gql = pr.graphql_schema
                result.graphql_endpoint = gql.endpoint
                result.graphql_queries = [f.name for f in gql.queries]
                result.graphql_mutations = [f.name for f in gql.mutations]
                result.endpoints[gql.endpoint] = {"method": "POST", "source": "graphql"}

            # Security headers
            if pr.security_headers:
                sec = pr.security_headers
                result.missing_security_headers = sec.missing_headers
                result.security_header_misconfigs = sec.misconfigs
                result.cors_open = sec.cors_open
                for hint in sec.tech_hints:
                    result.tech_stack[hint] = "header"

            # OPTIONS enumeration
            if pr.allowed_methods:
                result.allowed_methods = pr.allowed_methods

            # Error fingerprints
            for fp in pr.error_fingerprints:
                for tech_str in fp.get("tech", []):
                    result.tech_stack[tech_str[:60]] = "error_fingerprint"

            # JWT
            for jwt in pr.jwt_findings:
                if jwt.issues:
                    result.jwt_findings.append({
                        "source": jwt.source,
                        "algorithm": jwt.algorithm,
                        "issues": jwt.issues,
                        "sensitive_fields": jwt.sensitive_fields,
                    })

            # Tech hints
            for hint in pr.tech_hints:
                result.tech_stack[hint[:60]] = "http_probe"

            result.journal_entries.append(
                f"[HttpProbe] {len(pr.discovered_paths)} paths, "
                f"{len(pr.openapi_endpoints)} OpenAPI, "
                f"GraphQL={'yes' if pr.graphql_schema else 'no'}, "
                f"{len(pr.jwt_findings)} JWT(s)"
            )
            logger.success(f"[HttpProbeAgent] Done: {len(result.endpoints)} endpoints")

        except Exception as e:
            result.error = str(e)
            logger.error(f"[HttpProbeAgent] Failed: {e}")

        result.duration_seconds = time.monotonic() - start
        return result


class BrowserCrawlAgent(BaseDiscoveryAgent):
    """
    Agent 2: Dynamic Browser Crawl.
    Playwright headless browser — intercepts XHR/fetch, navigates SPA routes,
    discovers forms, auth walls, WebSockets. Auto-analyzes all JS bundles.
    """
    name = "browser_crawl"

    def __init__(
        self,
        headless: bool = True,
        proxy: Optional[str] = None,
        analyze_js: bool = True,
    ):
        self._headless = headless
        self._proxy = proxy
        self._analyze_js = analyze_js

    async def discover(self, target_url, cookies=None, shared_context=None):
        start = time.monotonic()
        result = DiscoveryResult(agent_name=self.name)

        try:
            from xlayer_ai.engine.logical_surface_map.browser_analyzer import (
                BrowserAnalyzer, BrowserResult,
            )
            browser = BrowserAnalyzer(headless=self._headless, proxy=self._proxy)
            br = await browser.analyze(target_url, cookies=cookies)

            # XHR-observed endpoints
            for path, method in br.endpoints.items():
                result.endpoints[_normalize(target_url, path)] = {
                    "method": method, "source": "browser_xhr",
                }

            # SPA routes
            for route in br.spa_routes:
                full = _normalize(target_url, route)
                if full not in result.endpoints:
                    result.endpoints[full] = {"method": "GET", "source": "browser_spa"}

            # JS files
            result.js_files.update(br.js_files)

            # WebSockets
            for ws_url in br.websocket_urls:
                result.endpoints[ws_url] = {"method": "WS", "source": "browser_ws"}

            # Auth walls
            for path in br.auth_walls:
                full = _normalize(target_url, path)
                result.auth_walls.add(full)
                result.endpoints[full] = {"method": "GET", "source": "browser_xhr", "auth_required": True}

            # Forms
            for form in br.forms:
                action = form.get("action", "")
                if action:
                    full = _normalize(target_url, action)
                    method = form.get("method", "POST")
                    params = [inp["name"] for inp in form.get("inputs", []) if inp.get("name")]
                    result.endpoints[full] = {
                        "method": method, "source": "browser_form", "params": params,
                    }
                result.forms.append(form)

            # XHR POST body params
            base_netloc = urlparse(target_url).netloc
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
                if isinstance(body_data, dict) and body_data:
                    params = [k for k in body_data if isinstance(k, str)]
                    if params:
                        full = _normalize(target_url, parsed_url.path)
                        existing = result.endpoints.get(full, {})
                        existing_params = existing.get("params", [])
                        result.endpoints[full] = {
                            **existing,
                            "method": call.method,
                            "source": "browser_xhr",
                            "params": list(set(existing_params + params)),
                        }

            result.journal_entries.append(
                f"[BrowserCrawl] {len(br.endpoints)} XHR, "
                f"{len(br.spa_routes)} SPA, "
                f"{len(br.auth_walls)} auth walls, "
                f"{len(br.forms)} forms, "
                f"{len(br.js_files)} JS files"
            )

            # Auto-analyze JS bundles (browser finds JS → immediate analysis)
            if self._analyze_js and br.js_files:
                await self._analyze_js_bundles(result, target_url, br.js_files)

            logger.success(
                f"[BrowserCrawlAgent] Done: {len(result.endpoints)} endpoints, "
                f"{len(result.js_files)} JS files"
            )

        except ImportError:
            result.error = "playwright not installed"
            logger.warning("[BrowserCrawlAgent] Skipped: playwright not installed")
        except Exception as e:
            result.error = str(e)
            logger.error(f"[BrowserCrawlAgent] Failed: {e}")

        result.duration_seconds = time.monotonic() - start
        return result

    async def _analyze_js_bundles(
        self, result: DiscoveryResult, target_url: str, js_files: Set[str]
    ):
        """Auto-analyze JS bundles found by browser (immediate analysis)."""
        from xlayer_ai.engine.logical_surface_map.js_analyzer import JSAnalyzer

        # Prioritize main/app bundles
        def _score(url: str) -> int:
            name = url.rsplit("/", 1)[-1].lower()
            if any(k in name for k in ("main.", "app.", "index.", "bundle.")):
                return 0
            if any(k in name for k in ("chunk.", "page.", "route.")):
                return 1
            if any(k in name for k in ("vendor.", "lib.", "runtime.")):
                return 3
            return 2

        candidates = sorted(js_files, key=_score)[:15]
        logger.info(f"[BrowserCrawlAgent] Auto JS analysis: {len(candidates)}/{len(js_files)} bundles")

        try:
            import httpx
        except ImportError:
            return

        async with httpx.AsyncClient(
            follow_redirects=True, timeout=15, verify=False
        ) as client:
            for js_url in candidates:
                try:
                    resp = await client.get(js_url)
                    if resp.status_code >= 400 or not resp.text:
                        continue
                    content = resp.text

                    deep = await JSAnalyzer.analyze(content, url=js_url)

                    # Endpoints
                    for ep, method in deep.endpoints_with_method.items():
                        result.endpoints[_normalize(target_url, ep)] = {
                            "method": method, "source": "js_deep",
                        }
                    for ep in deep.endpoints - set(deep.endpoints_with_method):
                        result.endpoints[_normalize(target_url, ep)] = {
                            "method": "GET", "source": "js_crawling",
                        }

                    # Secrets
                    result.secrets.extend(deep.secrets)

                    # Taint hints
                    for hint in deep.taint_hints:
                        result.taint_hints.append({
                            "source": hint["source"],
                            "sink": hint["sink"],
                            "vuln_type": hint["vuln_type"],
                            "context": hint.get("context", ""),
                            "js_file": js_url,
                        })

                    # Framework
                    if deep.framework_detected:
                        result.tech_stack[deep.framework_detected] = "js_deep"

                    # Route auth metadata
                    for route_url, auth_meta in deep.route_auth.items():
                        full = _normalize(target_url, route_url)
                        ep_data = {"method": "GET", "source": "route_config"}
                        if auth_meta.get("auth_required"):
                            ep_data["auth_required"] = True
                            result.auth_walls.add(full)
                        result.endpoints[full] = ep_data

                    # Vuln hints + dev comments + sourcemap
                    result.vuln_hints.extend([
                        {"vuln_type": h.vuln_type, "evidence": h.evidence,
                         "confidence": h.confidence, "source_file": h.source_file,
                         "context": h.context}
                        for h in deep.vuln_hints
                    ])
                    result.dev_comments.extend(deep.dev_comments)
                    result.sourcemap_sources.extend(deep.sourcemap_sources)

                    # Supply chain scan on each JS bundle
                    try:
                        from xlayer_ai.engine.logical_surface_map.supply_chain import SupplyChainMapper
                        base_domain = urlparse(target_url).netloc
                        sc_mapper = SupplyChainMapper()
                        sc_findings = sc_mapper.scan(content, source_file=js_url)
                        sc_findings += sc_mapper.scan_subdomains(content, base_domain)
                        for f in sc_findings:
                            result.supply_chain.append(f.to_dict())
                    except Exception:
                        pass

                except Exception as e:
                    logger.debug(f"[BrowserCrawlAgent] JS analysis failed {js_url}: {e}")


class SubdomainAgent(BaseDiscoveryAgent):
    """
    Agent 3: Subdomain Discovery + Live Host Fingerprinting.
    subfinder for enumeration, httpx for live detection + tech fingerprint.
    Silently skips if tools not installed.
    """
    name = "subdomain"

    async def discover(self, target_url, cookies=None, shared_context=None):
        start = time.monotonic()
        result = DiscoveryResult(agent_name=self.name)

        try:
            parsed = urlparse(target_url)
            domain = parsed.hostname or parsed.netloc
            scheme = parsed.scheme or "https"

            # Step 1: subfinder
            import shutil
            if shutil.which("subfinder"):
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

                    for sub in subs[:50]:
                        sub_url = f"{scheme}://{sub}"
                        result.endpoints[sub_url] = {"method": "GET", "source": "subfinder"}

                    result.journal_entries.append(
                        f"[Subfinder] {len(subs)} subdomains for {domain}"
                    )
                    logger.info(f"[SubdomainAgent] Subfinder: {len(subs)} subdomains")

                    # Step 2: httpx fingerprint on discovered subdomains
                    if subs and shutil.which("httpx"):
                        all_urls = [f"{scheme}://{s}" for s in subs[:50]]
                        input_data = "\n".join(all_urls).encode("utf-8")
                        proc2 = await asyncio.create_subprocess_exec(
                            "httpx", "-silent", "-json", "-tech-detect", "-timeout", "10",
                            stdin=asyncio.subprocess.PIPE,
                            stdout=asyncio.subprocess.PIPE,
                            stderr=asyncio.subprocess.PIPE,
                        )
                        stdout2, _ = await asyncio.wait_for(
                            proc2.communicate(input=input_data), timeout=60
                        )
                        for line in stdout2.decode("utf-8", errors="replace").splitlines():
                            if not line.strip():
                                continue
                            try:
                                data = json.loads(line.strip())
                                hr_url = data.get("url", "")
                                if hr_url:
                                    result.endpoints[hr_url] = {"method": "GET", "source": "httpx"}
                                for t in data.get("tech", []):
                                    result.tech_stack[t.lower()] = "httpx"
                            except json.JSONDecodeError:
                                continue

                        result.journal_entries.append(
                            f"[httpx] live host fingerprinting complete"
                        )
                except Exception as e:
                    logger.debug(f"[SubdomainAgent] error: {e}")
            else:
                result.journal_entries.append("[Subfinder] not installed — skipped")
                logger.debug("[SubdomainAgent] subfinder not installed, skipping")

        except Exception as e:
            result.error = str(e)
            logger.error(f"[SubdomainAgent] Failed: {e}")

        result.duration_seconds = time.monotonic() - start
        return result


class TechFuzzAgent(BaseDiscoveryAgent):
    """
    Agent 4: LLM Tech-Aware Path Fuzzing.
    Uses LLM knowledge of framework-specific paths (admin panels, debug endpoints,
    API docs, config files) based on detected tech stack.
    """
    name = "tech_fuzz"

    def __init__(self, llm=None, proxy: Optional[str] = None):
        self._llm = llm
        self._proxy = proxy

    async def discover(self, target_url, cookies=None, shared_context=None):
        start = time.monotonic()
        result = DiscoveryResult(agent_name=self.name)

        if not self._llm:
            result.error = "no LLM provided"
            return result

        # Get tech stack from shared_context (populated by HttpProbeAgent if it finishes first)
        tech_stack = (shared_context or {}).get("tech_stack", {})

        try:
            # Step 1: Ask LLM for framework-specific paths
            if tech_stack:
                tech_list = ", ".join(list(tech_stack.keys())[:8])
                tech_context = f"Detected tech stack: {tech_list}"
            else:
                tech_list = "unknown"
                tech_context = "Tech stack unknown — use common web framework defaults"

            msg = await self._llm.call(messages=[
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
            start_idx = content.find("[")
            end_idx = content.rfind("]") + 1
            if start_idx >= 0 and end_idx > start_idx:
                paths = json.loads(content[start_idx:end_idx])
                valid_paths = [p for p in paths if isinstance(p, str) and p.startswith("/")]
            else:
                valid_paths = []

            if not valid_paths:
                result.journal_entries.append("[TechFuzz] LLM returned no valid paths")
                result.duration_seconds = time.monotonic() - start
                return result

            # Step 2: Fuzz these paths
            from xlayer_ai.engine.logical_surface_map.path_fuzzer import WordlistFuzzer
            fuzzer = WordlistFuzzer(concurrency=20, timeout=8, proxy=self._proxy)
            fuzz_result = await fuzzer.fuzz(
                base_url=target_url,
                cookies=cookies,
                wordlist=valid_paths,
                smart_expand=False,
            )

            for hit in fuzz_result.hits:
                full = _normalize(target_url, hit.path)
                ep_data = {"method": "GET", "source": "tech_fuzz"}
                if hit.status in (401, 403):
                    ep_data["auth_required"] = True
                    result.auth_walls.add(full)
                result.endpoints[full] = ep_data

            result.journal_entries.append(
                f"[TechFuzz] {fuzz_result.paths_tested} paths tested → "
                f"{len(fuzz_result.hits)} hits for [{tech_list}]"
            )
            logger.success(
                f"[TechFuzzAgent] Done: {len(fuzz_result.hits)} hits from "
                f"{fuzz_result.paths_tested} paths"
            )

        except Exception as e:
            result.error = str(e)
            logger.error(f"[TechFuzzAgent] Failed: {e}")

        result.duration_seconds = time.monotonic() - start
        return result


class WordlistFuzzAgent(BaseDiscoveryAgent):
    """
    Agent 5: Standard Wordlist Fuzzer.
    300-path wordlist of common admin/debug/API paths + smart prefix expansion.
    Runs independently of tech detection.
    """
    name = "wordlist_fuzz"

    def __init__(self, proxy: Optional[str] = None):
        self._proxy = proxy

    async def discover(self, target_url, cookies=None, shared_context=None):
        start = time.monotonic()
        result = DiscoveryResult(agent_name=self.name)

        try:
            from xlayer_ai.engine.logical_surface_map.path_fuzzer import WordlistFuzzer
            fuzzer = WordlistFuzzer(concurrency=20, timeout=8, proxy=self._proxy)
            fuzz_result = await fuzzer.fuzz(
                base_url=target_url,
                cookies=cookies,
                wordlist=None,       # default 300-path wordlist
                smart_expand=True,   # expand discovered prefixes
            )

            for hit in fuzz_result.hits:
                full = _normalize(target_url, hit.path)
                ep_data = {"method": "GET", "source": "wordlist_fuzz"}
                if hit.status in (401, 403):
                    ep_data["auth_required"] = True
                    result.auth_walls.add(full)
                if hit.redirect_to:
                    result.journal_entries.append(
                        f"[Fuzz] redirect: {hit.path} → {hit.redirect_to}"
                    )
                result.endpoints[full] = ep_data

            result.journal_entries.append(
                f"[WordlistFuzz] {fuzz_result.paths_tested} paths → "
                f"{len(fuzz_result.hits)} hits, "
                f"{len(fuzz_result.auth_walls)} auth walls"
            )
            logger.success(
                f"[WordlistFuzzAgent] Done: {len(fuzz_result.hits)} hits "
                f"from {fuzz_result.paths_tested} paths"
            )

        except Exception as e:
            result.error = str(e)
            logger.error(f"[WordlistFuzzAgent] Failed: {e}")

        result.duration_seconds = time.monotonic() - start
        return result


class SupplyChainAgent(BaseDiscoveryAgent):
    """
    Agent 6: Supply Chain CVE Hints.
    Scans tech stack for known CVEs. Runs after tech is detected.
    """
    name = "supply_chain"

    async def discover(self, target_url, cookies=None, shared_context=None):
        start = time.monotonic()
        result = DiscoveryResult(agent_name=self.name)

        tech_stack = (shared_context or {}).get("tech_stack", {})

        try:
            from xlayer_ai.engine.logical_surface_map.supply_chain import SupplyChainMapper
            mapper = SupplyChainMapper()

            if tech_stack:
                cve_findings = mapper.scan_tech_stack(tech_stack)
                for f in cve_findings:
                    result.supply_chain.append(f.to_dict())
                    result.journal_entries.append(
                        f"[SupplyChain] CVE: {f.cve}: {f.description[:80]}"
                    )
                if cve_findings:
                    logger.info(
                        f"[SupplyChainAgent] {len(cve_findings)} CVE hints from "
                        f"{list(tech_stack.keys())[:5]}"
                    )
            else:
                result.journal_entries.append("[SupplyChain] no tech stack detected yet")

        except Exception as e:
            result.error = str(e)
            logger.debug(f"[SupplyChainAgent] Failed: {e}")

        result.duration_seconds = time.monotonic() - start
        return result


# ── Orchestrator ────────────────────────────────────────────────────────────

class DiscoveryOrchestrator:
    """
    Discovery Orchestrator.

    Spawns all discovery agents in parallel, waits for completion,
    merges results into a unified LogicalSurface.

    Flow:
        1. Phase A (parallel): HttpProbe + BrowserCrawl + Subdomain + WordlistFuzz
        2. Phase B (parallel, depends on A): TechFuzz + SupplyChain (need tech_stack from A)
        3. Merge all results → LogicalSurface
    """

    def __init__(
        self,
        llm=None,
        proxy: Optional[str] = None,
        browser: bool = True,
        browser_headless: bool = True,
        probe_timeout: int = 10,
    ):
        self._llm = llm
        self._proxy = proxy
        self._browser = browser
        self._browser_headless = browser_headless
        self._probe_timeout = probe_timeout

    async def run(
        self,
        target_url: str,
        cookies: Optional[List[dict]] = None,
    ) -> "LogicalSurface":
        """
        Run all discovery agents and return unified LogicalSurface.
        """
        from xlayer_ai.engine.logical_surface_map.graph import (
            LogicalSurface, EndpointNode, TaintHint,
        )

        start = time.monotonic()
        surface = LogicalSurface(base_url=target_url)
        surface.add_endpoint(target_url, source="initial")

        logger.info(f"[Discovery] Starting parallel discovery for: {target_url}")

        # ── Phase A: Independent agents (no cross-dependencies) ──────────
        phase_a_agents: List[BaseDiscoveryAgent] = [
            HttpProbeAgent(timeout=self._probe_timeout, proxy=self._proxy),
            WordlistFuzzAgent(proxy=self._proxy),
            SubdomainAgent(),
        ]
        if self._browser:
            phase_a_agents.append(
                BrowserCrawlAgent(
                    headless=self._browser_headless,
                    proxy=self._proxy,
                    analyze_js=True,
                )
            )

        logger.info(
            f"[Discovery] Phase A: launching {len(phase_a_agents)} agents in parallel "
            f"({', '.join(a.name for a in phase_a_agents)})"
        )

        phase_a_tasks = [
            agent.discover(target_url, cookies=cookies)
            for agent in phase_a_agents
        ]
        phase_a_results = await asyncio.gather(*phase_a_tasks, return_exceptions=True)

        # Merge Phase A results
        all_results: List[DiscoveryResult] = []
        merged_tech: Dict[str, str] = {}
        for r in phase_a_results:
            if isinstance(r, Exception):
                logger.error(f"[Discovery] Phase A agent crashed: {r}")
                continue
            all_results.append(r)
            merged_tech.update(r.tech_stack)

        # ── Phase B: Tech-dependent agents (need tech_stack from Phase A) ──
        shared_context = {"tech_stack": merged_tech}

        phase_b_agents: List[BaseDiscoveryAgent] = [
            SupplyChainAgent(),
        ]
        if self._llm:
            phase_b_agents.append(TechFuzzAgent(llm=self._llm, proxy=self._proxy))

        logger.info(
            f"[Discovery] Phase B: launching {len(phase_b_agents)} agents "
            f"({', '.join(a.name for a in phase_b_agents)}) "
            f"with {len(merged_tech)} tech hints"
        )

        phase_b_tasks = [
            agent.discover(target_url, cookies=cookies, shared_context=shared_context)
            for agent in phase_b_agents
        ]
        phase_b_results = await asyncio.gather(*phase_b_tasks, return_exceptions=True)

        for r in phase_b_results:
            if isinstance(r, Exception):
                logger.error(f"[Discovery] Phase B agent crashed: {r}")
                continue
            all_results.append(r)

        # ── Merge all results into LogicalSurface ────────────────────────
        journal: List[str] = []
        for dr in all_results:
            _merge_into_surface(surface, dr)
            journal.extend(dr.journal_entries)

        duration = time.monotonic() - start
        agent_times = {
            r.agent_name: f"{r.duration_seconds:.1f}s"
            for r in all_results
        }

        logger.success(
            f"[Discovery] Complete: {len(surface.endpoints)} endpoints, "
            f"{len(surface.tech_stack)} tech, {len(surface.secrets)} secrets, "
            f"{len(surface.taint_hints)} taint hints | "
            f"Total: {duration:.1f}s | Agents: {agent_times}"
        )

        return surface


def _merge_into_surface(surface, dr: DiscoveryResult) -> None:
    """Merge a DiscoveryResult into a LogicalSurface."""
    from xlayer_ai.engine.logical_surface_map.graph import TaintHint

    # Endpoints
    for url, meta in dr.endpoints.items():
        method = meta.get("method", "GET")
        source = meta.get("source", dr.agent_name)
        surface.add_endpoint(url, method=method, source=source)
        params = meta.get("params", [])
        if params:
            surface.add_params_to_endpoint(url, params)
        if meta.get("auth_required"):
            surface.set_endpoint_auth(url, auth_required=True, role_level="user")

    # JS files
    surface.js_files.update(dr.js_files)

    # Tech stack
    for tech, src in dr.tech_stack.items():
        surface.tech_stack[tech] = src

    # Secrets
    for s in dr.secrets:
        if s not in surface.secrets:
            surface.secrets.append(s)

    # Taint hints
    for hint in dr.taint_hints:
        th = TaintHint(
            source=hint.get("source", ""),
            sink=hint.get("sink", ""),
            vuln_type=hint.get("vuln_type", ""),
            context=hint.get("context", ""),
            js_file=hint.get("js_file", ""),
        )
        surface.taint_hints.append(th)

    # Supply chain
    surface.supply_chain_findings.extend(dr.supply_chain)

    # Vuln hints + dev comments + sourcemap
    surface.vuln_hints.extend(dr.vuln_hints)
    surface.dev_comments.extend(dr.dev_comments)
    surface.sourcemap_sources.extend(dr.sourcemap_sources)

    # Behavioral profiles
    surface.behavior_profiles.update(dr.behavior_profiles)

    # JWT
    surface.jwt_issues.extend(dr.jwt_findings)

    # HTTP Probe specifics
    if dr.openapi_spec_url:
        surface.openapi_spec_url = dr.openapi_spec_url
    if dr.graphql_endpoint:
        surface.graphql_endpoint = dr.graphql_endpoint
        surface.graphql_queries = dr.graphql_queries
        surface.graphql_mutations = dr.graphql_mutations
    if dr.security_header_misconfigs:
        surface.security_header_misconfigs = dr.security_header_misconfigs
    if dr.missing_security_headers:
        surface.missing_security_headers = dr.missing_security_headers
    if dr.allowed_methods:
        surface.allowed_methods.update(dr.allowed_methods)
    if dr.cors_open:
        surface.cors_open = True

    # Auth walls
    for wall in dr.auth_walls:
        surface.set_endpoint_auth(wall, auth_required=True, role_level="user")


def _normalize(base_url: str, url: str) -> str:
    """Resolve relative paths against base_url."""
    url = (url or "").strip()
    if not url or url.startswith("http://") or url.startswith("https://"):
        return url
    base = base_url.rstrip("/")
    return f"{base}{url}" if url.startswith("/") else url

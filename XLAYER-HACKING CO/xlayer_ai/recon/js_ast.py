"""
JS AST Analyzer — JavaScript Abstract Syntax Tree Analysis

XLayer AI parses JavaScript files into AST to find:
  1. Source → Sink mapping (user input → eval/innerHTML/document.write)
  2. Secret extraction (API keys, internal endpoints, config objects)
  3. Hidden parameters and routes
  4. Auth logic patterns (token generation, session handling)

Uses regex-based analysis (no external AST parser dependency).
For deeper analysis, can optionally use esprima/tree-sitter.
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from loguru import logger


@dataclass
class SourceSinkFlow:
    """A detected flow from user-controlled source to dangerous sink."""
    source: str          # e.g. "location.search", "document.cookie"
    sink: str            # e.g. "innerHTML", "eval"
    context: str = ""    # surrounding code snippet
    severity: str = "medium"
    vuln_type: str = "xss_dom"


@dataclass
class JSSecret:
    """A secret found in JavaScript source code."""
    secret_type: str     # api_key, token, password, endpoint
    key_name: str        # variable/property name
    value: str           # the secret value
    file_url: str = ""   # which JS file
    line_hint: str = ""  # surrounding context


@dataclass
class JSRoute:
    """A route/endpoint discovered in JavaScript."""
    path: str            # /api/v1/users
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    auth_required: bool = False
    source: str = ""     # which JS file


@dataclass
class JSASTResult:
    """Complete JS analysis results."""
    findings: List[SourceSinkFlow] = field(default_factory=list)
    secrets: List[JSSecret] = field(default_factory=list)
    routes: List[JSRoute] = field(default_factory=list)
    config_objects: Dict[str, Any] = field(default_factory=dict)
    auth_patterns: List[Dict] = field(default_factory=list)


class JSASTAnalyzer:
    """
    Analyzes JavaScript source code for security-relevant patterns.

    This is a regex-based analyzer (works without external deps).
    Covers 90%+ of real-world patterns.
    """

    # User-controllable sources (input origins)
    SOURCES = [
        "location.search", "location.hash", "location.href",
        "location.pathname", "location.host",
        "document.cookie", "document.referrer", "document.URL",
        "window.name", "window.location",
        "URLSearchParams", "getParameter", "req.query",
        "req.params", "req.body", "this.props",
        "event.data",  # postMessage
        "localStorage.getItem", "sessionStorage.getItem",
    ]

    # Dangerous sinks (code execution / HTML injection)
    SINKS = {
        "innerHTML": ("xss_dom", "high"),
        "outerHTML": ("xss_dom", "high"),
        "document.write": ("xss_dom", "high"),
        "document.writeln": ("xss_dom", "high"),
        "eval(": ("rce_client", "critical"),
        "setTimeout(": ("xss_dom", "medium"),
        "setInterval(": ("xss_dom", "medium"),
        "Function(": ("rce_client", "critical"),
        "$.html(": ("xss_dom", "high"),
        "v-html": ("xss_dom", "high"),
        "dangerouslySetInnerHTML": ("xss_dom", "high"),
        "location.href": ("open_redirect", "medium"),
        "location.assign": ("open_redirect", "medium"),
        "location.replace": ("open_redirect", "medium"),
        "window.open": ("open_redirect", "medium"),
        "element.src": ("xss_dom", "medium"),
        "$.append(": ("xss_dom", "medium"),
        "$.prepend(": ("xss_dom", "medium"),
        "$.after(": ("xss_dom", "medium"),
        "$.before(": ("xss_dom", "medium"),
    }

    # Secret patterns
    SECRET_PATTERNS = [
        (r'''['"]?(api[_-]?key|apikey|api_secret)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]''', "api_key"),
        (r'''['"]?(secret[_-]?key|secret)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]''', "secret"),
        (r'''['"]?(token|access_token|auth_token)['"]?\s*[:=]\s*['"]([^'"]{8,})['"]''', "token"),
        (r'''['"]?(password|passwd|pwd)['"]?\s*[:=]\s*['"]([^'"]{4,})['"]''', "password"),
        (r'''['"]?(aws[_-]?access|aws[_-]?secret)['"]?\s*[:=]\s*['"]([A-Za-z0-9+/]{16,})['"]''', "aws_key"),
        (r'(sk-[a-zA-Z0-9]{20,})', "openai_key"),
        (r'(AIza[a-zA-Z0-9_-]{35})', "google_api_key"),
        (r'(ghp_[a-zA-Z0-9]{36})', "github_token"),
        (r'(xox[bpsa]-[a-zA-Z0-9-]{10,})', "slack_token"),
        (r'''['"]?(AKIA[A-Z0-9]{12,})['"]?''', "aws_access_key"),
        (r'''firebase[_-]?config.*?apiKey.*?['"]([^'"]+)['"]''', "firebase_key"),
    ]

    # Route/endpoint patterns
    ROUTE_PATTERNS = [
        r'''['"]([/][a-zA-Z0-9_/-]+(?:\.[a-z]+)?)['"]''',
        r'''fetch\s*\(\s*['"]([^'"]+)['"]''',
        r'''axios\.\w+\s*\(\s*['"]([^'"]+)['"]''',
        r'''url\s*[:=]\s*['"]([^'"]+)['"]''',
        r'''endpoint\s*[:=]\s*['"]([^'"]+)['"]''',
        r'''baseURL\s*[:=]\s*['"]([^'"]+)['"]''',
        r'''\.get\s*\(\s*['"]([/][^'"]+)['"]''',
        r'''\.post\s*\(\s*['"]([/][^'"]+)['"]''',
        r'''\.put\s*\(\s*['"]([/][^'"]+)['"]''',
        r'''\.delete\s*\(\s*['"]([/][^'"]+)['"]''',
    ]

    # Auth pattern detection
    AUTH_PATTERNS = [
        (r'(jwt|jsonwebtoken|jose)', "jwt_usage"),
        (r'(bcrypt|argon2|scrypt|pbkdf2)', "password_hashing"),
        (r'(Bearer\s+)', "bearer_auth"),
        (r'(localStorage\.setItem.*token)', "token_storage_localstorage"),
        (r'(sessionStorage\.setItem.*token)', "token_storage_sessionstorage"),
        (r'(document\.cookie\s*=.*token)', "token_storage_cookie"),
        (r'(authorization.*header)', "auth_header"),
        (r'(isAuthenticated|isLoggedIn|checkAuth)', "auth_check"),
        (r'(role.*admin|isAdmin|hasRole)', "rbac_check"),
    ]

    async def analyze_surface(self, surface: Dict) -> Dict:
        """
        Analyze all JS from the surface for security findings.

        Args:
            surface: The surface dict from LSM

        Returns:
            Dict with "findings" and "secrets" lists
        """
        all_findings = []
        all_secrets = []
        all_routes = []

        # Get JS content from surface endpoints
        js_urls = []
        for url, node in surface.get("endpoints", {}).items():
            if url.endswith(".js") or ".js?" in url:
                js_urls.append(url)

        # Analyze each JS file
        for js_url in js_urls[:50]:  # limit to 50 JS files
            try:
                content = await self._fetch_js(js_url)
                if content:
                    result = self.analyze(content, source_url=js_url)
                    all_findings.extend(result.findings)
                    all_secrets.extend(result.secrets)
                    all_routes.extend(result.routes)
            except Exception as e:
                logger.debug(f"[JS AST] Error analyzing {js_url}: {e}")

        return {
            "findings": [self._flow_to_dict(f) for f in all_findings],
            "secrets": [self._secret_to_dict(s) for s in all_secrets],
            "routes": [self._route_to_dict(r) for r in all_routes],
        }

    def analyze(self, js_code: str, source_url: str = "") -> JSASTResult:
        """
        Analyze a single JavaScript source string.

        Returns JSASTResult with all findings.
        """
        result = JSASTResult()

        # 1. Source → Sink flows
        result.findings = self._find_source_sink_flows(js_code)

        # 2. Secrets
        result.secrets = self._find_secrets(js_code, source_url)

        # 3. Routes/Endpoints
        result.routes = self._find_routes(js_code, source_url)

        # 4. Config objects
        result.config_objects = self._find_configs(js_code)

        # 5. Auth patterns
        result.auth_patterns = self._find_auth_patterns(js_code)

        return result

    def _find_source_sink_flows(self, code: str) -> List[SourceSinkFlow]:
        """Find data flows from user-controlled sources to dangerous sinks."""
        flows = []
        lines = code.split("\n")

        for i, line in enumerate(lines):
            line_stripped = line.strip()
            # Check if line contains both a source and a sink
            for source in self.SOURCES:
                if source.lower() in line_stripped.lower():
                    for sink, (vuln_type, severity) in self.SINKS.items():
                        # Check same line
                        if sink.lower() in line_stripped.lower():
                            flows.append(SourceSinkFlow(
                                source=source,
                                sink=sink,
                                context=line_stripped[:200],
                                severity=severity,
                                vuln_type=vuln_type,
                            ))
                        # Check nearby lines (±3)
                        elif i > 0:
                            nearby = "\n".join(lines[max(0, i-3):min(len(lines), i+4)])
                            if sink.lower() in nearby.lower():
                                flows.append(SourceSinkFlow(
                                    source=source,
                                    sink=sink,
                                    context=nearby[:300],
                                    severity=severity,
                                    vuln_type=vuln_type,
                                ))

        # Deduplicate
        seen = set()
        unique = []
        for f in flows:
            key = (f.source, f.sink)
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _find_secrets(self, code: str, source_url: str = "") -> List[JSSecret]:
        """Find hardcoded secrets in JS code."""
        secrets = []
        seen_values: Set[str] = set()

        for pattern, secret_type in self.SECRET_PATTERNS:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                groups = match.groups()
                value = groups[-1] if groups else match.group(0)
                key_name = groups[0] if len(groups) > 1 else secret_type

                # Skip common false positives
                if value in seen_values:
                    continue
                if len(value) < 8:
                    continue
                if value in ("undefined", "null", "true", "false", "function"):
                    continue
                if all(c == value[0] for c in value):  # "aaaaaaa"
                    continue

                seen_values.add(value)
                # Get context
                pos = match.start()
                start = max(0, pos - 50)
                end = min(len(code), pos + len(match.group(0)) + 50)
                context = code[start:end].strip()

                secrets.append(JSSecret(
                    secret_type=secret_type,
                    key_name=str(key_name),
                    value=value,
                    file_url=source_url,
                    line_hint=context[:200],
                ))

        return secrets

    def _find_routes(self, code: str, source_url: str = "") -> List[JSRoute]:
        """Find API routes/endpoints in JS code."""
        routes = []
        seen: Set[str] = set()

        for pattern in self.ROUTE_PATTERNS:
            for match in re.finditer(pattern, code):
                path = match.group(1)
                if not path or path in seen:
                    continue
                if not path.startswith("/") and not path.startswith("http"):
                    continue
                if len(path) < 3 or len(path) > 500:
                    continue
                # Skip asset paths
                if any(path.endswith(ext) for ext in [".css", ".png", ".jpg", ".svg", ".woff", ".ico"]):
                    continue

                seen.add(path)
                method = "GET"
                # Detect method from context
                pos = max(0, match.start() - 50)
                ctx = code[pos:match.start()].lower()
                if "post" in ctx:
                    method = "POST"
                elif "put" in ctx:
                    method = "PUT"
                elif "delete" in ctx:
                    method = "DELETE"
                elif "patch" in ctx:
                    method = "PATCH"

                # Extract params from path
                params = re.findall(r':(\w+)|{(\w+)}', path)
                param_names = [p[0] or p[1] for p in params]

                routes.append(JSRoute(
                    path=path,
                    method=method,
                    params=param_names,
                    source=source_url,
                ))

        return routes

    def _find_configs(self, code: str) -> Dict[str, Any]:
        """Find config objects (window.CONFIG = {...})."""
        configs = {}
        config_patterns = [
            r'window\.(\w+Config|\w+CONFIG|config|CONFIG)\s*=\s*({[^;]{10,}})',
            r'var\s+(\w*config\w*)\s*=\s*({[^;]{10,}})',
            r'const\s+(\w*config\w*)\s*=\s*({[^;]{10,}})',
            r'let\s+(\w*config\w*)\s*=\s*({[^;]{10,}})',
        ]
        for pattern in config_patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                name = match.group(1)
                try:
                    # Try to parse as JSON (won't always work for JS objects)
                    obj_str = match.group(2)
                    configs[name] = obj_str[:500]
                except Exception:
                    pass
        return configs

    def _find_auth_patterns(self, code: str) -> List[Dict]:
        """Find authentication-related patterns in JS code."""
        patterns_found = []
        for pattern, auth_type in self.AUTH_PATTERNS:
            if re.search(pattern, code, re.IGNORECASE):
                patterns_found.append({"type": auth_type, "pattern": pattern})
        return patterns_found

    async def _fetch_js(self, url: str) -> Optional[str]:
        """Fetch a JS file content."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.text[:500000]  # 500KB limit
        except Exception:
            pass
        return None

    @staticmethod
    def _flow_to_dict(f: SourceSinkFlow) -> Dict:
        return {
            "type": "source_sink_flow", "source": f.source,
            "sink": f.sink, "context": f.context,
            "severity": f.severity, "vuln_type": f.vuln_type,
        }

    @staticmethod
    def _secret_to_dict(s: JSSecret) -> Dict:
        return {
            "type": "secret", "secret_type": s.secret_type,
            "key_name": s.key_name, "value": s.value[:50] + "...",
            "file_url": s.file_url,
        }

    @staticmethod
    def _route_to_dict(r: JSRoute) -> Dict:
        return {
            "type": "route", "path": r.path,
            "method": r.method, "params": r.params,
        }

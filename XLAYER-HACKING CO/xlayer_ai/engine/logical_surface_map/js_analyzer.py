"""
engine/logical_surface_map/js_analyzer.py — XLayer JS Intelligence Engine

Single entry point: await JSAnalyzer.analyze(content, url) → DeepJSResult

Extraction pipeline (runs internally in one call):
  - AST (esprima): variable resolution, HTTP calls, framework routes, taint tracking
  - Secret regex: camelCase + SCREAMING_SNAKE_CASE patterns
  - Source map: if sourceMappingURL found, analyzes original source files

Regex endpoint fallback activates only when AST fails entirely.
"""

import base64
import json
import math
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from loguru import logger


# ── Result container ────────────────────────────────────────────────────────

@dataclass
class VulnHint:
    """Vulnerability hint derived from function name / comment semantics."""
    vuln_type: str        # "sqli", "rce", "idor", "ssti", "open_redirect", etc.
    evidence: str         # function name or comment text that triggered
    confidence: str       # "high" / "medium" / "low"
    source_file: str = "" # original source file (from source map)
    context: str = ""     # surrounding code snippet


@dataclass
class DeepJSResult:
    endpoints: Set[str] = field(default_factory=set)
    endpoints_with_method: Dict[str, str] = field(default_factory=dict)    # url → method
    route_auth: Dict[str, dict] = field(default_factory=dict)              # url → {auth_required, role_level, redirect_to}
    params_per_endpoint: Dict[str, Set[str]] = field(default_factory=dict)
    user_controlled_params: List[str] = field(default_factory=list)
    taint_hints: List[dict] = field(default_factory=list)                  # {source, sink, vuln_type, context}
    secrets: List[Dict[str, str]] = field(default_factory=list)
    vuln_hints: List[VulnHint] = field(default_factory=list)               # from source map analysis
    dev_comments: List[dict] = field(default_factory=list)                 # {text, keyword, source_file}
    sourcemap_sources: List[str] = field(default_factory=list)             # original file names
    framework_detected: Optional[str] = None                               # "react", "express", "vue", "angular"


# ── TypeScript annotation stripper ──────────────────────────────────────────

def _strip_typescript(content: str) -> str:
    """
    Remove TypeScript-specific syntax that breaks esprima JS parsing.
    Handles primitive type annotations, interfaces, type aliases, enums.
    """
    # Param annotations: (x: string, n: number) — remove the ": type" part
    content = re.sub(
        r':\s*(?:string|number|boolean|any|void|never|unknown|object|null|undefined)'
        r'(?=\s*[,)=])',
        '', content,
    )
    # Return type annotations: ): void { → ) {
    content = re.sub(r'\)\s*:\s*[A-Za-z<>\[\]|& ]+?(\s*\{)', r')\1', content)
    # Type assertions: foo as Bar
    content = re.sub(r'\s+as\s+[A-Za-z][A-Za-z0-9<>\[\]]*', '', content)
    # interface / enum blocks
    content = re.sub(r'\b(?:interface|enum)\s+\w+\s*\{[^}]*\}', '', content, flags=re.DOTALL)
    # type alias: type Foo = ...;
    content = re.sub(r'\btype\s+\w+\s*=\s*[^;{]+?;', '', content)
    return content


# ── Obfuscation pre-scanner ──────────────────────────────────────────────────

def _prescan_obfuscation(content: str) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
    """
    Regex pre-scan for JavaScript Obfuscator string arrays — runs BEFORE AST parse.

    Detects two patterns:
      1. var _0xABCD = ['str1', 'str2', ...]
         → array_vars: {'_0xABCD': ['/api/users', 'POST', ...]}

      2. function _0x1234(n) { return _0xABCD[n] }
         → array_funcs: {'_0x1234': '_0xABCD'}

    These are fed into _ASTWalker so _resolve_string() can resolve
    _0x1234(0x3) and _0xABCD[0x3] lookups at walk time.
    """
    array_vars: Dict[str, List[str]] = {}
    array_funcs: Dict[str, str] = {}

    # Pattern 1: var/let/const _0xABCD = ['...', '...']
    arr_re = re.compile(
        r'(?:var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*\[([^\]]{5,})\]'
    )
    str_re = re.compile(r'"((?:[^"\\]|\\.)*)"|\'((?:[^\'\\]|\\.)*)\'' )
    for m in arr_re.finditer(content):
        var_name = m.group(1)
        raw = m.group(2)
        vals = [a or b for a, b in str_re.findall(raw)]
        if vals:
            array_vars[var_name] = vals

    if not array_vars:
        return array_vars, array_funcs

    # Pattern 2: function _0x1234(...) { return _0xABCD[...] }
    func_re = re.compile(
        r'function\s+(_0x[a-fA-F0-9]+)\s*\([^)]*\)\s*\{\s*return\s+(_0x[a-fA-F0-9]+)\['
    )
    for m in func_re.finditer(content):
        fn, arr = m.group(1), m.group(2)
        if arr in array_vars:
            array_funcs[fn] = arr

    # Pattern 2b: var/const _0x1234 = function(...) { return _0xABCD[...] }
    var_func_re = re.compile(
        r'(?:var|let|const)\s+(_0x[a-fA-F0-9]+)\s*=\s*function\s*\([^)]*\)\s*\{\s*return\s+(_0x[a-fA-F0-9]+)\['
    )
    for m in var_func_re.finditer(content):
        fn, arr = m.group(1), m.group(2)
        if arr in array_vars:
            array_funcs[fn] = arr

    if array_vars:
        logger.debug(
            f"[Deobfuscate] {len(array_vars)} string arrays, "
            f"{len(array_funcs)} wrapper functions"
        )

    return array_vars, array_funcs


# ── AST Walker ───────────────────────────────────────────────────────────────

class _ASTWalker:
    """
    Walks an esprima AST to extract:
      - Variable string values (const base = '/api/v1')
      - Concatenated strings (base + '/users')
      - Template literals (`/api/${id}`)
      - HTTP call arguments (fetch, axios, XHR, $.ajax)
      - Framework routes (React Router <Route>, Express app.get)
      - Taint sources → sinks (location.search → innerHTML)
    """

    # HTTP call patterns: function name → default method
    HTTP_CALLEE_MAP = {
        "fetch": "GET",
        "axios": "GET",
        "axios.get": "GET",
        "axios.post": "POST",
        "axios.put": "PUT",
        "axios.delete": "DELETE",
        "axios.patch": "PATCH",
        "$.get": "GET",
        "$.post": "POST",
        "$.ajax": "GET",
        "jQuery.get": "GET",
        "jQuery.post": "POST",
        "request": "GET",
        "superagent.get": "GET",
        "superagent.post": "POST",
        "ky.get": "GET",
        "ky.post": "POST",
    }

    # Express-style route methods
    EXPRESS_METHODS = {"get", "post", "put", "delete", "patch", "all", "use", "route"}

    # Taint sources: user-controlled inputs
    TAINT_SOURCES = {
        "location.search", "location.hash", "location.href",
        "document.URL", "document.referrer",
        "URLSearchParams", "searchParams.get",
        "window.name", "document.cookie",
    }

    # Fix 5: max hops for multi-hop taint chain
    MAX_TAINT_HOPS = 5

    # Dangerous sinks mapped to vuln type
    TAINT_SINKS = {
        "innerHTML": "xss",
        "outerHTML": "xss",
        "document.write": "xss",
        "document.writeln": "xss",
        "eval": "xss",
        "setTimeout": "xss",
        "setInterval": "xss",
        "window.location": "open_redirect",
        "location.href": "open_redirect",
        "location.replace": "open_redirect",
        "location.assign": "open_redirect",
        "fetch": "ssrf",
        "XMLHttpRequest": "ssrf",
        "src": "xss",
        "href": "open_redirect",
    }

    # Route config variable name hints (common naming conventions)
    _ROUTE_VAR_NAMES = {
        "routes", "routeConfig", "appRoutes", "ROUTES", "routerConfig",
        "routeDefinitions", "routeList", "pageRoutes", "router",
    }

    # canActivate guard names → role level
    _ADMIN_GUARDS = {
        "AdminGuard", "RoleGuard", "SuperUserGuard", "ManagerGuard",
        "SuperAdminGuard", "StaffGuard", "PrivilegeGuard",
    }
    _AUTH_GUARDS = {
        "AuthGuard", "LoginGuard", "AuthenticatedGuard", "IsAuthGuard",
        "IsLoggedIn", "AuthRequired", "JwtAuthGuard", "TokenGuard",
    }

    def __init__(
        self,
        array_vars: Optional[Dict[str, List[str]]] = None,
        array_funcs: Optional[Dict[str, str]] = None,
    ):
        self.string_vars: Dict[str, str] = {}               # varName → resolved string value
        self.object_vars: Dict[str, Dict[str, str]] = {}    # varName → {prop: value} for flat objects
        self.tainted_vars: Dict[str, str] = {}              # varName → taint source
        self.tainted_funcs: Dict[str, str] = {}             # Fix 5: funcName → taint source (return val)
        self.taint_hops: Dict[str, int] = {}                # Fix 5: varName → hop count
        self.endpoints: Dict[str, str] = {}                 # url → http method
        self.route_auth: Dict[str, dict] = {}               # url → {auth_required, role_level}
        self.params_per_endpoint: Dict[str, Set[str]] = {}
        self.taint_hints: List[dict] = []
        self.framework: Optional[str] = None
        self._active_sources: Set[str] = set()
        # Obfuscation: pre-scanned string arrays + wrapper functions
        self.array_vars: Dict[str, List[str]] = array_vars or {}   # _0xABCD → ['str1', 'str2', ...]
        self.array_funcs: Dict[str, str] = array_funcs or {}        # _0x1234 → '_0xABCD'

    # ── Public entry ──────────────────────────────────────────────────────

    def walk(self, node) -> None:
        if node is None:
            return
        node_type = getattr(node, "type", None)
        if node_type is None:
            return

        handler = getattr(self, f"_visit_{node_type}", self._visit_generic)
        handler(node)

    # ── Node visitors ─────────────────────────────────────────────────────

    def _visit_generic(self, node) -> None:
        """Recurse into all child nodes."""
        for key in vars(node):
            child = getattr(node, key)
            if hasattr(child, "type"):
                self.walk(child)
            elif isinstance(child, list):
                for item in child:
                    if hasattr(item, "type"):
                        self.walk(item)

    def _visit_Program(self, node) -> None:
        for stmt in node.body:
            self.walk(stmt)

    def _visit_VariableDeclaration(self, node) -> None:
        for decl in node.declarations:
            self.walk(decl)

    def _visit_VariableDeclarator(self, node) -> None:
        if node.init is None:
            return
        name = getattr(node.id, "name", None)

        # String value resolution
        value = self._resolve_string(node.init)
        if name and value:
            self.string_vars[name] = value

        # Object literal tracking: const API = {users: '/api/users', admin: '/api/admin'}
        if name and getattr(node.init, "type", "") == "ObjectExpression":
            props: Dict[str, str] = {}
            for prop in getattr(node.init, "properties", []):
                key = (
                    getattr(getattr(prop, "key", None), "name", None)
                    or getattr(getattr(prop, "key", None), "value", None)
                )
                val = self._resolve_string(prop.value)
                if key and val:
                    props[key] = val
            if props:
                self.object_vars[name] = props

        # Route config array: const routes = [{path: '/admin', ...}, ...]
        if name and getattr(node.init, "type", "") == "ArrayExpression":
            is_route_var = name in self._ROUTE_VAR_NAMES or "route" in name.lower()
            if is_route_var:
                elements = getattr(node.init, "elements", []) or []
                if elements and getattr(elements[0], "type", "") == "ObjectExpression":
                    # Looks like a route config array — check first element has 'path'
                    first_keys = {
                        getattr(getattr(p, "key", None), "name", "")
                        for p in getattr(elements[0], "properties", [])
                    }
                    if "path" in first_keys or "component" in first_keys:
                        self._parse_route_array(elements, parent_path="")

        # Taint propagation: const redir = location.search → redir is tainted
        if name:
            rhs_str = self._member_to_str(node.init) or ""
            for src in self.TAINT_SOURCES:
                if src == rhs_str or src.split(".")[-1] in rhs_str:
                    self.tainted_vars[name] = src
                    self.taint_hops[name] = 1
                    self._active_sources.add(src)
                    break
            # Propagate taint through variables: const x = redir (redir already tainted)
            rhs_name = getattr(node.init, "name", None)
            if rhs_name and rhs_name in self.tainted_vars:
                hops = self.taint_hops.get(rhs_name, 1) + 1
                if hops <= self.MAX_TAINT_HOPS:
                    self.tainted_vars[name] = self.tainted_vars[rhs_name]
                    self.taint_hops[name] = hops

            # Fix 5: multi-hop — const result = sanitize(taintedVar)
            # If a called function's return value is stored, and the argument was tainted,
            # mark result as tainted too (function may not sanitize properly).
            if getattr(node.init, "type", "") == "CallExpression":
                args = getattr(node.init, "arguments", []) or []
                for arg in args:
                    arg_name = getattr(arg, "name", "")
                    if arg_name and arg_name in self.tainted_vars:
                        hops = self.taint_hops.get(arg_name, 1) + 1
                        if hops <= self.MAX_TAINT_HOPS:
                            self.tainted_vars[name] = self.tainted_vars[arg_name]
                            self.taint_hops[name] = hops
                            # Track the function as taint-propagating
                            callee = self._member_to_str(getattr(node.init, "callee", None)) or ""
                            if callee:
                                self.tainted_funcs[callee] = self.tainted_vars[arg_name]
                        break

        # Still recurse to catch nested calls
        self.walk(node.init)

    def _visit_ExpressionStatement(self, node) -> None:
        self.walk(node.expression)

    def _visit_AssignmentExpression(self, node) -> None:
        # Track variable assignments: a = '/api/v1'
        name = self._member_to_str(node.left)
        value = self._resolve_string(node.right)
        if name and value:
            self.string_vars[name] = value

        # Taint propagation through assignment: tainted = rhs (already tainted var)
        lhs_name = getattr(node.left, "name", None)
        if lhs_name:
            rhs_name = getattr(node.right, "name", None)
            if rhs_name and rhs_name in self.tainted_vars:
                self.tainted_vars[lhs_name] = self.tainted_vars[rhs_name]
            else:
                rhs_str = self._member_to_str(node.right) or ""
                for src in self.TAINT_SOURCES:
                    if src == rhs_str or src.split(".")[-1] in rhs_str:
                        self.tainted_vars[lhs_name] = src
                        self._active_sources.add(src)

        # Detect taint sink assignments: element.innerHTML = userInput / taintedVar
        # Also handle complex LHS like: document.getElementById('x').innerHTML = val
        sink_name = self._member_to_str(node.left)
        if not sink_name:
            # Try extracting just the property name from MemberExpression
            prop = getattr(getattr(node.left, "property", None), "name", None)
            if prop:
                sink_name = prop
        for sink, vuln in self.TAINT_SINKS.items():
            if sink in (sink_name or "") or sink_name == sink:
                rhs = self._member_to_str(node.right) or ""
                rhs_var = getattr(node.right, "name", "")

                # Direct source (e.g. window.location = location.search)
                taint_src = None
                for src in self.TAINT_SOURCES:
                    if src == rhs or src.split(".")[-1] in rhs:
                        taint_src = src
                        break

                # Propagated taint through variable (e.g. window.location = redir)
                if taint_src is None and rhs_var in self.tainted_vars:
                    taint_src = self.tainted_vars[rhs_var]

                if taint_src:
                    self._active_sources.add(taint_src)
                    self.taint_hints.append({
                        "source": taint_src,
                        "sink": sink_name,
                        "vuln_type": vuln,
                        "context": f"{sink_name} = {rhs or rhs_var}",
                    })
                    break  # one hint per assignment is enough
        self.walk(node.right)

    def _visit_CallExpression(self, node) -> None:
        callee_str = self._member_to_str(node.callee)

        # ── HTTP calls ────────────────────────────────────────────────────
        method = self.HTTP_CALLEE_MAP.get(callee_str)
        if method is not None and node.arguments:
            url = self._resolve_string(node.arguments[0])
            if url and url.startswith("/"):
                # fetch(url, {method:'POST'}) — check arguments[1] for options object
                if len(node.arguments) > 1:
                    _, obj_method = self._extract_options_object(node.arguments[1])
                    if obj_method:
                        method = obj_method
                self.endpoints[url] = method
            # axios({method: 'POST', url: ...}) single-object form
            elif not url and callee_str in ("fetch", "axios") and node.arguments:
                obj_url, obj_method = self._extract_options_object(node.arguments[0])
                if obj_url:
                    self.endpoints[obj_url] = obj_method or method

        # ── $.ajax / jQuery.ajax ──────────────────────────────────────────
        if callee_str in ("$.ajax", "jQuery.ajax") and node.arguments:
            obj_url, obj_method = self._extract_options_object(node.arguments[0])
            if obj_url:
                self.endpoints[obj_url] = obj_method or "GET"

        # ── Express routes: app.get('/path', handler) ─────────────────────
        if node.arguments and len(node.arguments) >= 1:
            callee_parts = callee_str.split(".") if callee_str else []
            if len(callee_parts) == 2 and callee_parts[1].lower() in self.EXPRESS_METHODS:
                route_method = callee_parts[1].upper()
                url = self._resolve_string(node.arguments[0])
                if url and url.startswith("/"):
                    self.endpoints[url] = route_method
                    self.framework = "express"

        # ── React Router v6: createBrowserRouter([...]) ──────────────────
        _ROUTER_CREATORS = {
            "createBrowserRouter", "createHashRouter", "createMemoryRouter",
            "createStaticRouter", "RouterModule.forRoot", "RouterModule.forChild",
        }
        if callee_str in _ROUTER_CREATORS and node.arguments:
            arg = node.arguments[0]
            if getattr(arg, "type", "") == "ArrayExpression":
                elements = getattr(arg, "elements", []) or []
                if elements:
                    self._parse_route_array(elements, parent_path="")
                    self.framework = "react"

        # ── Fix 10: React Router lazy chunks — import('/pages/Admin') ─────
        # Dynamic import() calls in route config reveal lazy-loaded route paths.
        # e.g. { path: '/admin', component: lazy(() => import('./pages/Admin')) }
        # The import path gives us a strong hint about the route even without
        # the parent route config being fully resolved.
        if callee_str == "import" and node.arguments:
            import_path = self._resolve_string(node.arguments[0]) or ""
            if import_path:
                # Convert module path to URL hint: './pages/AdminDashboard' → '/admin-dashboard'
                chunk_hint = self._import_path_to_route(import_path)
                if chunk_hint:
                    self.endpoints[chunk_hint] = "GET"
                    if self.framework is None:
                        self.framework = "react"

        # ── XHR: xhr.open('GET', '/api') ─────────────────────────────────
        if callee_str and callee_str.endswith(".open") and len(node.arguments) >= 2:
            method_arg = self._resolve_string(node.arguments[0]) or "GET"
            url = self._resolve_string(node.arguments[1])
            if url and url.startswith("/"):
                self.endpoints[url] = method_arg.upper()

        # ── Taint: call-based sinks (document.write, eval, fetch with tainted arg) ──
        if callee_str and node.arguments:
            arg0 = node.arguments[0]
            arg_var = getattr(arg0, "name", "")
            arg_str = self._member_to_str(arg0) or ""

            # Find taint source from arg — either direct or via tainted variable
            taint_src = None
            for src in self.TAINT_SOURCES:
                if src == arg_str or src.split(".")[-1] in arg_str:
                    taint_src = src
                    break
            if taint_src is None and arg_var in self.tainted_vars:
                taint_src = self.tainted_vars[arg_var]

            if taint_src:
                # Check if this callee is a sink
                for sink, vuln in self.TAINT_SINKS.items():
                    if callee_str == sink or callee_str.endswith(f".{sink.split('.')[-1]}"):
                        self._active_sources.add(taint_src)
                        self.taint_hints.append({
                            "source": taint_src,
                            "sink": callee_str,
                            "vuln_type": vuln,
                            "context": f"{callee_str}({arg_str or arg_var})",
                        })
                        break

        # Recurse into arguments
        for arg in node.arguments:
            self.walk(arg)
        self.walk(node.callee)

    def _visit_JSXOpeningElement(self, node) -> None:
        """React JSX: <Route path="/admin" /> detection."""
        name = getattr(getattr(node, "name", None), "name", "")
        if name == "Route":
            for attr in getattr(node, "attributes", []):
                attr_name = getattr(getattr(attr, "name", None), "name", "")
                if attr_name == "path":
                    val = attr.value
                    path = self._resolve_string(val) if hasattr(val, "type") else getattr(val, "value", None)
                    if path and path.startswith("/"):
                        self.endpoints[path] = "GET"
                        self.framework = "react"
        self._visit_generic(node)

    def _visit_ImportDeclaration(self, node) -> None:
        """Detect framework from imports."""
        src = getattr(node.source, "value", "")
        if "react-router" in src:
            self.framework = "react"
        elif "vue-router" in src:
            self.framework = "vue"
        elif "express" in src:
            self.framework = "express"
        elif "@angular/router" in src:
            self.framework = "angular"

    # ── String resolution ─────────────────────────────────────────────────

    def _resolve_string(self, node) -> Optional[str]:
        """Recursively resolve a node to a string value if possible."""
        if node is None:
            return None
        t = getattr(node, "type", None)

        if t == "Literal":
            v = getattr(node, "value", None)
            return str(v) if isinstance(v, str) else None

        if t == "Identifier":
            name = getattr(node, "name", "")
            return self.string_vars.get(name)

        if t == "BinaryExpression" and getattr(node, "operator", "") == "+":
            left = self._resolve_string(node.left)
            right = self._resolve_string(node.right)
            if left is not None and right is not None:
                return left + right
            if left is not None:
                return left  # partial — keep prefix
            return None

        if t == "TemplateLiteral":
            parts = []
            quasis = getattr(node, "quasis", [])
            exprs = getattr(node, "expressions", [])
            for i, quasi in enumerate(quasis):
                parts.append(getattr(getattr(quasi, "value", None), "cooked", "") or "")
                if i < len(exprs):
                    resolved = self._resolve_string(exprs[i])
                    parts.append(resolved if resolved is not None else "{param}")
            result = "".join(parts)
            return result if result.startswith("/") else None

        if t == "CallExpression":
            callee = self._member_to_str(getattr(node, "callee", None)) or ""
            args = getattr(node, "arguments", []) or []

            # String.fromCharCode(47, 97, 112, 105) → '/api'
            if callee == "String.fromCharCode" and args:
                chars = []
                for arg in args:
                    v = getattr(arg, "value", None)
                    if isinstance(v, (int, float)) and 32 <= int(v) <= 126:
                        chars.append(chr(int(v)))
                if chars:
                    return "".join(chars)

            # Obfuscator array wrapper: _0x1234(0x3) → array_vars['_0xABCD'][3]
            callee_name = getattr(getattr(node, "callee", None), "name", "")
            if callee_name in self.array_funcs and args:
                arr_name = self.array_funcs[callee_name]
                idx = getattr(args[0], "value", None)
                if isinstance(idx, (int, float)):
                    arr = self.array_vars.get(arr_name, [])
                    n = int(idx)
                    if 0 <= n < len(arr):
                        return arr[n]

            return None

        if t == "MemberExpression":
            # Computed index: _0xABCD[0x3] → array_vars lookup
            if getattr(node, "computed", False):
                obj_name = getattr(getattr(node, "object", None), "name", "")
                if obj_name in self.array_vars:
                    idx = getattr(node.property, "value", None)
                    if isinstance(idx, (int, float)):
                        arr = self.array_vars[obj_name]
                        n = int(idx)
                        if 0 <= n < len(arr):
                            return arr[n]

            # Check flat string_vars first (e.g. "API.admin" stored directly)
            full_key = self._member_to_str(node) or ""
            if full_key in self.string_vars:
                return self.string_vars[full_key]
            # Check object_vars: API.admin → object_vars["API"]["admin"]
            obj_name = self._member_to_str(node.object) or ""
            prop_name = (
                getattr(node.property, "name", None)
                or getattr(node.property, "value", None)
            )
            if obj_name in self.object_vars and prop_name:
                return self.object_vars[obj_name].get(prop_name)
            return None

        return None

    def _member_to_str(self, node) -> Optional[str]:
        """Convert MemberExpression/Identifier to dotted string."""
        if node is None:
            return None
        t = getattr(node, "type", None)
        if t == "Identifier":
            return node.name
        if t == "MemberExpression":
            obj = self._member_to_str(node.object)
            prop = getattr(node.property, "name", None) or getattr(node.property, "value", None)
            if obj and prop:
                return f"{obj}.{prop}"
        if t == "Literal":
            return str(getattr(node, "value", ""))
        return None

    # ── Route Config Parsing ──────────────────────────────────────────────

    def _parse_route_array(self, elements: list, parent_path: str = "", parent_auth: Optional[dict] = None) -> None:
        """
        Parse an array of route config objects recursively.
        Handles Vue Router, Angular Router, and React Router v6 array syntax.

        Each element shape:
          { path, component, canActivate, meta, data, children, redirectTo, loadChildren }
        """
        for elem in elements:
            if not elem or getattr(elem, "type", "") != "ObjectExpression":
                continue
            self._parse_route_object(elem, parent_path=parent_path, parent_auth=parent_auth)

    def _parse_route_object(self, node, parent_path: str = "", parent_auth: Optional[dict] = None) -> None:
        """
        Extract route info from a single route config object node.
        Inherits auth from parent for nested children.
        """
        props = getattr(node, "properties", [])
        prop_map: Dict[str, object] = {}  # key → AST node (value)

        for prop in props:
            key = (
                getattr(getattr(prop, "key", None), "name", None)
                or getattr(getattr(prop, "key", None), "value", None)
            )
            if key:
                prop_map[key] = prop.value

        # ── path ─────────────────────────────────────────────────────────
        path_node = prop_map.get("path")
        raw_path = self._resolve_string(path_node) if path_node else None

        # Wildcard / catch-all — skip
        if raw_path in ("**", "*", ""):
            return

        # Build full path
        if raw_path is None:
            full_path = parent_path or None
        elif raw_path.startswith("/"):
            full_path = raw_path
        else:
            full_path = (parent_path.rstrip("/") + "/" + raw_path) if parent_path else ("/" + raw_path)

        # ── redirectTo — mark as public redirect endpoint ─────────────────
        redirect_node = prop_map.get("redirectTo")
        redirect_to = self._resolve_string(redirect_node) if redirect_node else None

        # ── auth detection ────────────────────────────────────────────────
        auth_info = dict(parent_auth) if parent_auth else {"auth_required": False, "role_level": "guest"}

        # canActivate: [AuthGuard, AdminGuard]
        can_activate = prop_map.get("canActivate")
        if can_activate and getattr(can_activate, "type", "") == "ArrayExpression":
            for guard_node in getattr(can_activate, "elements", []):
                guard_name = getattr(guard_node, "name", "") or self._resolve_string(guard_node) or ""
                if guard_name in self._ADMIN_GUARDS:
                    auth_info["auth_required"] = True
                    auth_info["role_level"] = "admin"
                elif guard_name in self._AUTH_GUARDS or guard_name:
                    # Any guard implies auth required
                    auth_info["auth_required"] = True
                    if auth_info.get("role_level") == "guest":
                        auth_info["role_level"] = "user"

        # meta: { requiresAuth: true } — Vue Router convention
        meta_node = prop_map.get("meta")
        if meta_node and getattr(meta_node, "type", "") == "ObjectExpression":
            for mp in getattr(meta_node, "properties", []):
                mk = getattr(getattr(mp, "key", None), "name", "")
                mv = getattr(mp.value, "value", None)
                if mk in ("requiresAuth", "auth", "authenticated") and mv:
                    auth_info["auth_required"] = True
                    if auth_info.get("role_level") == "guest":
                        auth_info["role_level"] = "user"

        # data: { roles: ['admin'] } — Angular convention
        data_node = prop_map.get("data")
        if data_node and getattr(data_node, "type", "") == "ObjectExpression":
            for dp in getattr(data_node, "properties", []):
                dk = getattr(getattr(dp, "key", None), "name", "")
                if dk in ("roles", "role", "permissions"):
                    roles_node = dp.value
                    if getattr(roles_node, "type", "") == "ArrayExpression":
                        for r in getattr(roles_node, "elements", []):
                            role_val = (self._resolve_string(r) or "").lower()
                            if role_val in ("admin", "superadmin", "manager", "staff"):
                                auth_info["auth_required"] = True
                                auth_info["role_level"] = role_val

        # loader / beforeEnter — React Router v6 / Vue Navigation Guard
        if "loader" in prop_map or "beforeEnter" in prop_map:
            loader_name = self._member_to_str(prop_map.get("loader")) or ""
            guard_name = self._member_to_str(prop_map.get("beforeEnter")) or ""
            hint = (loader_name + guard_name).lower()
            if any(k in hint for k in (
                "auth", "login", "guard", "require", "protect",
                "admin", "role", "only", "private", "permission",
            )):
                auth_info["auth_required"] = True
                if auth_info.get("role_level") == "guest":
                    auth_info["role_level"] = "user"

        # ── Store endpoint ────────────────────────────────────────────────
        if full_path:
            self.endpoints[full_path] = "GET"
            self.route_auth[full_path] = {
                "auth_required": auth_info["auth_required"],
                "role_level": auth_info["role_level"],
                "redirect_to": redirect_to,
                "source": "route_config",
            }
            if self.framework is None:
                self.framework = "vue_or_angular"

        # ── Recurse into children ─────────────────────────────────────────
        children_node = prop_map.get("children")
        if children_node and getattr(children_node, "type", "") == "ArrayExpression":
            self._parse_route_array(
                getattr(children_node, "elements", []),
                parent_path=full_path or parent_path,
                parent_auth=auth_info,  # pass auth down to children
            )

    def _import_path_to_route(self, import_path: str) -> Optional[str]:
        """
        Fix 10: Convert a JS dynamic import path to a likely URL route hint.

        './pages/AdminDashboard'  → '/admin-dashboard'
        '../views/UserProfile'    → '/user-profile'
        './components/auth/Login' → '/auth/login'

        Returns None if the path looks like a utility (not a page/route).
        """
        # Strip leading ./ ../
        clean = import_path.lstrip("./").lstrip("../")
        # Only treat as route if under pages/ views/ routes/ screens/
        _ROUTE_DIRS = ("pages/", "views/", "routes/", "screens/", "containers/")
        for prefix in _ROUTE_DIRS:
            if clean.lower().startswith(prefix):
                clean = clean[len(prefix):]
                break
        else:
            return None  # not a route module

        # Remove file extension
        clean = re.sub(r'\.(jsx?|tsx?)$', '', clean)

        # Convert CamelCase / PascalCase → kebab-case
        clean = re.sub(r'([A-Z])', lambda m: '-' + m.group(1).lower(), clean).lstrip('-')

        # Forward slashes for nested paths
        route = "/" + clean.replace("\\", "/")
        return route if len(route) > 1 else None

    def _extract_options_object(self, node) -> tuple:
        """Extract url and method from {url: '...', method: 'POST'} object."""
        if not node or getattr(node, "type", "") != "ObjectExpression":
            return None, None
        url, method = None, None
        for prop in getattr(node, "properties", []):
            key = getattr(getattr(prop, "key", None), "name", "") or \
                  getattr(getattr(prop, "key", None), "value", "")
            val = self._resolve_string(prop.value)
            if key == "url" and val:
                url = val
            elif key == "method" and val:
                method = val.upper()
        return url, method


# ── JSAnalyzer public class ──────────────────────────────────────────────────

class JSAnalyzer:
    """
    XLayer JS Intelligence Engine.

    Use await JSAnalyzer.analyze(content, url) as the single entry point.
    Returns a DeepJSResult with all findings (endpoints, secrets, taint, routes, source map).
    """

    # Regex for endpoint literals — used as fallback when AST fails
    _ENDPOINT_REGEX = r'["\'](\/(?:api\/)?[a-zA-Z0-9_\-\.\/]+)["\']'

    # Secret patterns (case-insensitive camelCase / lowercase variable names)
    _SECRET_REGEX = re.compile(
        r'(?i)(?:api[-_]?key|(?:auth|access|refresh)[-_]?token|(?:jwt|app|api)[-_]?secret'
        r'|secret[-_]?key|(?:db|database)[-_]?(?:pass(?:word)?|secret)'
        r'|(?:private|public)[-_]?key|password|passphrase|credential)'
        r'["\']?\s*[:=]\s*["\']([^"\']{6,})["\']'
    )

    # SCREAMING_SNAKE_CASE env-var style secrets: SECRET_KEY, API_KEY, JWT_TOKEN, etc.
    _SECRET_REGEX_SCREAMING = re.compile(
        r'\b([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|CREDENTIAL)[A-Z0-9_]*)'
        r'\s*[:=]\s*["\']([^"\']{6,})["\']'
    )

    _STATIC_EXTS = {".jpg", ".png", ".css", ".woff", ".svg", ".gif", ".ico", ".webp", ".ttf"}

    # ── Primary entry point ──────────────────────────────────────────────

    @staticmethod
    async def analyze(
        content: str,
        url: str = "",
        http_client=None,
    ) -> DeepJSResult:
        """
        Full JS analysis. Single entry point.

        Runs internally:
          1. AST extraction — endpoints, routes, taint, framework detection
          2. Secret extraction — regex (camelCase + SCREAMING_SNAKE_CASE)
          3. Source map pipeline — if sourceMappingURL found, analyzes original sources

        Falls back to regex-only endpoint extraction if AST fails.
        Returns DeepJSResult with all findings merged.
        """
        logger.debug(
            f"[JSAnalyzer.analyze] entry url={url!r} content_len={len(content)}"
        )
        result = JSAnalyzer._extract_sync(content, url)
        logger.debug(
            f"[JSAnalyzer.analyze] after _extract_sync: endpoints={len(result.endpoints)} "
            f"taint_hints={len(result.taint_hints)} secrets={len(result.secrets)} "
            f"framework={result.framework_detected}"
        )

        smap = await JSAnalyzer._sourcemap_pipeline(content, url, http_client)
        if smap:
            result.endpoints |= smap.endpoints
            result.endpoints_with_method.update(smap.endpoints_with_method)
            result.route_auth.update(smap.route_auth)
            result.taint_hints.extend(smap.taint_hints)
            result.secrets.extend(smap.secrets)
            result.user_controlled_params.extend(smap.user_controlled_params)
            result.vuln_hints.extend(smap.vuln_hints)
            result.dev_comments.extend(smap.dev_comments)
            result.sourcemap_sources.extend(smap.sourcemap_sources)
            if smap.framework_detected and not result.framework_detected:
                result.framework_detected = smap.framework_detected
            result.secrets = JSAnalyzer._dedup_secrets(result.secrets)
            logger.debug(
                f"[JSAnalyzer.analyze] after sourcemap merge: endpoints={len(result.endpoints)} "
                f"vuln_hints={len(result.vuln_hints)} dev_comments={len(result.dev_comments)}"
            )

        return result

    # ── Internal: sync extraction (AST + secrets) ────────────────────────

    @staticmethod
    def _extract_sync(content: str, url: str = "") -> DeepJSResult:
        """
        AST-based endpoint/route/taint analysis + secret regex.
        Falls back to regex endpoint extraction if AST fails.
        """
        result = DeepJSResult()
        logger.debug(
            f"[JSAnalyzer._extract_sync] start url={url!r} content_len={len(content)}"
        )

        # Secret extraction always runs — works on minified JS too
        result.secrets = JSAnalyzer._extract_secrets(content)
        logger.debug(f"[JSAnalyzer._extract_sync] secrets extracted: {len(result.secrets)}")

        # Webpack detection (quick text scan)
        _is_webpack = (
            "__webpack_require__" in content
            or "webpackChunk" in content
            or "webpackJsonp" in content
        )
        if _is_webpack:
            logger.debug("[JSAnalyzer._extract_sync] webpack bundle detected")

        # Obfuscation pre-scan — detect _0x string arrays before AST parse
        array_vars, array_funcs = _prescan_obfuscation(content)

        try:
            import esprima  # type: ignore
        except ImportError:
            logger.debug("[JSAnalyzer] esprima not installed — regex endpoint fallback")
            result.endpoints = JSAnalyzer._extract_endpoints_regex(content)
            logger.debug(f"[JSAnalyzer._extract_sync] regex fallback endpoints: {len(result.endpoints)}")
            return result

        # Try AST parse: strict → tolerant → TypeScript-stripped + tolerant
        tree = None
        parse_strategy = None
        for js_src, tolerant, label in (
            (content, False, "strict"),
            (content, True, "tolerant"),
            (_strip_typescript(content), True, "typescript_stripped+tolerant"),
        ):
            try:
                tree = esprima.parseScript(js_src, tolerant=tolerant, jsx=True)
                parse_strategy = label
                break
            except Exception as parse_err:
                logger.debug(
                    f"[JSAnalyzer._extract_sync] parse attempt '{label}' failed: {type(parse_err).__name__}: {parse_err}"
                )
                continue

        if tree is None:
            logger.debug(f"[JSAnalyzer] AST parse failed for {url or 'inline JS'} — regex fallback")
            result.endpoints = JSAnalyzer._extract_endpoints_regex(content)
            logger.debug(f"[JSAnalyzer._extract_sync] regex fallback endpoints: {len(result.endpoints)}")
            return result

        logger.debug(f"[JSAnalyzer._extract_sync] AST parse ok (strategy={parse_strategy})")

        walker = _ASTWalker(array_vars=array_vars, array_funcs=array_funcs)
        try:
            walker.walk(tree)
        except Exception as e:
            logger.debug(f"[JSAnalyzer] AST walk error: {e}")
            result.endpoints = JSAnalyzer._extract_endpoints_regex(content)
            logger.debug(f"[JSAnalyzer._extract_sync] regex fallback after walk error, endpoints: {len(result.endpoints)}")
            return result

        logger.debug(
            f"[JSAnalyzer._extract_sync] AST walk done: string_vars={len(walker.string_vars)} "
            f"endpoints={len(walker.endpoints)} taint_hints={len(walker.taint_hints)} "
            f"route_auth={len(walker.route_auth)} framework={walker.framework}"
        )

        if _is_webpack and not walker.framework:
            walker.framework = "webpack"

        # Merge AST results — no regex baseline (avoids false positives from partial strings)
        for ep_url, method in walker.endpoints.items():
            if ep_url.startswith("/") and not any(ep_url.lower().endswith(ext) for ext in JSAnalyzer._STATIC_EXTS):
                result.endpoints.add(ep_url)
                result.endpoints_with_method[ep_url] = method

        for hint in walker.taint_hints:
            hint["js_file"] = url
            result.taint_hints.append(hint)

        result.framework_detected = walker.framework
        result.route_auth = walker.route_auth

        for src in walker._active_sources:
            result.user_controlled_params.append(src)

        sample_eps = list(result.endpoints)[:5] if result.endpoints else []
        logger.debug(
            f"[JSAnalyzer] {url or 'inline'}: "
            f"{len(result.endpoints)} endpoints, "
            f"{len(result.taint_hints)} taint hints, "
            f"framework={result.framework_detected} "
            f"(sample endpoints: {sample_eps})"
        )
        return result

    @staticmethod
    def _extract_endpoints_regex(content: str) -> Set[str]:
        """Regex fallback: literal endpoint strings. Used only when AST fails."""
        matches = re.findall(JSAnalyzer._ENDPOINT_REGEX, content)
        out = {
            m for m in matches
            if not any(m.lower().endswith(ext) for ext in JSAnalyzer._STATIC_EXTS)
            and len(m) >= 4
        }
        logger.debug(
            f"[JSAnalyzer._extract_endpoints_regex] raw_matches={len(matches)} "
            f"after_filter={len(out)}"
        )
        return out

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """
        Shannon entropy of a string (bits per character).

        Real secrets (API keys, tokens, passwords) have high character variety
        and typically score > 3.5. Low-entropy values like "idle", "loading",
        "development", "default" score below 3.0 and are almost certainly
        not secrets — filtering them removes false positives from SCREAMING_SNAKE_CASE
        matches like LOADING_STATE = 'idle' or ENV_MODE = 'development'.
        """
        if not s:
            return 0.0
        freq: Dict[str, int] = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((v / n) * math.log2(v / n) for v in freq.values())

    @staticmethod
    def _extract_secrets(content: str) -> List[Dict[str, str]]:
        """Regex-based secret extraction (camelCase + SCREAMING_SNAKE_CASE).

        Entropy filter (>= 3.0 bits/char) removes false positives like
        LOADING_STATE = 'idle' or ENV_MODE = 'development'.
        Applied only to values longer than 7 chars (short values may be
        genuine secrets like 'abc123' even at lower entropy).
        """
        results: List[Dict[str, str]] = []
        seen: Set[str] = set()

        for m in JSAnalyzer._SECRET_REGEX.finditer(content):
            value = m.group(1)
            # Entropy filter: skip obvious non-secrets in longer values
            if len(value) > 7 and JSAnalyzer._shannon_entropy(value) < 3.0:
                continue
            sig = f"ci:{value}"
            if sig not in seen:
                seen.add(sig)
                # Reconstruct the key name from the match start
                key_end = m.start(1) - 1
                raw = content[max(0, m.start()):key_end].strip().rstrip("'\"").rstrip()
                results.append({"key": raw or "secret", "value": value})

        for m in JSAnalyzer._SECRET_REGEX_SCREAMING.finditer(content):
            key_name, value = m.group(1), m.group(2)
            # Entropy filter: SCREAMING_SNAKE_CASE has more FP risk
            if len(value) > 7 and JSAnalyzer._shannon_entropy(value) < 3.0:
                continue
            sig = f"scream:{key_name}:{value}"
            if sig not in seen:
                seen.add(sig)
                results.append({"key": key_name, "value": value})

        # Fix 22: localStorage JWT scan — detect tokens stored in browser storage
        # Pattern: localStorage.setItem('token', 'eyJ...') or sessionStorage.setItem
        _storage_jwt_re = re.compile(
            r'(?:localStorage|sessionStorage)\.setItem\s*\(\s*["\']'
            r'(?P<key>[^"\']{1,40})["\']'
            r'\s*,\s*(?:["\'](?P<literal_val>[^"\']{8,})["\']|(?P<var_name>[a-zA-Z_$][a-zA-Z0-9_$]*))',
            re.IGNORECASE,
        )
        for m in _storage_jwt_re.finditer(content):
            key_name = m.group("key") or ""
            literal_val = m.group("literal_val") or ""
            var_name    = m.group("var_name") or ""
            # Only interested if key hints at auth material
            if not any(k in key_name.lower() for k in (
                "token", "jwt", "auth", "session", "access", "refresh", "bearer"
            )):
                continue
            # Record as a secret (literal value) or as an exposure hint (variable)
            sig = f"storage:{key_name}:{literal_val or var_name}"
            if sig not in seen:
                seen.add(sig)
                entry = {
                    "key": f"localStorage[{key_name}]",
                    "value": literal_val or f"<var:{var_name}>",
                    "source": "localStorage",
                }
                if literal_val and literal_val.startswith("eyJ"):
                    entry["is_jwt"] = "true"
                results.append(entry)

        sample_keys = [r.get("key", "?") for r in results[:5]]
        logger.debug(
            f"[JSAnalyzer._extract_secrets] found {len(results)} (sample keys: {sample_keys})"
        )
        return results

    @staticmethod
    def _dedup_secrets(secrets: List[Dict[str, str]]) -> List[Dict[str, str]]:
        seen: Set[str] = set()
        out: List[Dict[str, str]] = []
        for s in secrets:
            k = f"{s.get('key')}:{s.get('value')}"
            if k not in seen:
                seen.add(k)
                out.append(s)
        return out

    # ── Route guessing ───────────────────────────────────────────────────

    @staticmethod
    def generate_guessing_logic(endpoints: Set[str]) -> List[str]:
        """Logical route guessing from known endpoints."""
        guesses = set()
        verb_swaps = {
            "get": ["delete", "update", "edit", "add", "create", "remove", "list"],
            "view": ["edit", "remove", "delete", "update"],
            "read": ["write", "delete", "update"],
            "list": ["create", "add", "delete", "export"],
            "create": ["delete", "list", "update"],
            "show": ["edit", "delete", "update"],
        }
        for ep in endpoints:
            ep_lower = ep.lower()

            # Verb swap
            for verb, replacements in verb_swaps.items():
                if verb in ep_lower:
                    for r in replacements:
                        guesses.add(ep_lower.replace(verb, r, 1))

            # Version pivot: /v1/ → /v2/, /v0/
            for match in re.finditer(r'/v(\d+)/', ep_lower):
                n = int(match.group(1))
                for alt in [n - 1, n + 1]:
                    if alt >= 0:
                        guesses.add(ep_lower.replace(f"/v{n}/", f"/v{alt}/", 1))

            # Role prefix injection
            if "/user/" in ep_lower and "/admin/" not in ep_lower:
                guesses.add(ep_lower.replace("/user/", "/admin/", 1))
            if "/api/" in ep_lower and "/api/internal/" not in ep_lower:
                guesses.add(ep_lower.replace("/api/", "/api/internal/", 1))

            # IDOR: add numeric ID
            if not ep_lower.rstrip("/").split("/")[-1].isdigit():
                guesses.add(ep_lower.rstrip("/") + "/1")
                guesses.add(ep_lower.rstrip("/") + "/0")

        return [g for g in guesses if g not in {e.lower() for e in endpoints}]

    # ── Source map analysis helpers ──────────────────────────────────────

    # Function name → vulnerability type + confidence
    _FUNC_VULN_MAP: List[Tuple[List[str], str, str]] = [
        (["executeQuery","runQuery","rawQuery",
          "buildQuery","sqlQuery"],               "sqli",           "high"),
        (["executeShell","runCommand","execCmd",
          "shellExec","runProcess","spawnProcess"],"rce",           "high"),
        (["deserialize","unserialize",
          "fromJson","objectFromBytes"],           "deserialization","high"),
        (["renderTemplate","renderView",
          "evalTemplate","processTemplate"],       "ssti",           "high"),
        (["parseXml","loadXml",
          "fromXml","xmlParse"],                  "xxe",            "high"),
        (["deleteUser","removeUser","deleteById",
          "removeById","deleteRecord"],            "idor",           "medium"),
        (["redirect","redirectTo",
          "navigateTo","forwardTo"],               "open_redirect",  "medium"),
        (["fetchUrl","proxyRequest",
          "httpRequest","loadUrl"],                "ssrf",           "medium"),
        (["uploadFile","saveFile",
          "writeFile","storeFile"],                "lfi",            "medium"),
        (["setHeader","setCookie",
          "writeResponse","renderHtml"],           "xss",            "low"),
    ]

    # Developer comment keywords → suspicious level
    _COMMENT_KEYWORDS: List[Tuple[str, str]] = [
        ("bypass",      "high"),
        ("backdoor",    "high"),
        ("debug",       "medium"),
        ("todo",        "low"),
        ("fixme",       "medium"),
        ("hack",        "medium"),
        ("temporary",   "medium"),
        ("remove",      "low"),
        ("disable",     "medium"),
        ("skip auth",   "high"),
        ("no auth",     "high"),
        ("insecure",    "high"),
        ("unsafe",      "high"),
        ("hardcoded",   "high"),
        ("secret",      "high"),
        ("password",    "high"),
        ("not sanitized","high"),
        ("sql",         "medium"),
        ("injection",   "high"),
    ]

    @staticmethod
    def analyze_function_names(source_content: str, source_file: str = "") -> List[VulnHint]:
        """Scan source code for function names that indicate vulnerability patterns."""
        hints: List[VulnHint] = []
        func_pattern = re.compile(
            r'(?:function\s+|async\s+function\s+|(?:const|let|var)\s+)'
            r'([a-zA-Z_][a-zA-Z0-9_]+)\s*[=:(]|'
            r'([a-zA-Z_][a-zA-Z0-9_]+)\s*\([^)]*\)\s*\{'
        )
        found_funcs: Set[str] = set()
        for m in func_pattern.finditer(source_content):
            name = m.group(1) or m.group(2) or ""
            if name and len(name) > 3:
                found_funcs.add(name)

        for func_name in found_funcs:
            fn_lower = func_name.lower()
            for keywords, vuln_type, confidence in JSAnalyzer._FUNC_VULN_MAP:
                for kw in keywords:
                    if kw.lower() in fn_lower or fn_lower in kw.lower():
                        idx = source_content.find(func_name)
                        if idx < 0:
                            ctx = func_name  # fallback: just the name
                        else:
                            ctx_start = max(0, idx - 60)
                            ctx_end = min(len(source_content), idx + 120)
                            ctx = source_content[ctx_start:ctx_end].strip().replace("\n", " ")
                        hints.append(VulnHint(
                            vuln_type=vuln_type,
                            evidence=func_name,
                            confidence=confidence,
                            source_file=source_file,
                            context=ctx[:200],
                        ))
                        break

        return hints

    @staticmethod
    def extract_dev_comments(source_content: str, source_file: str = "") -> List[dict]:
        """Extract developer comments with suspicious keywords (TODO, BYPASS, HACK, etc.)."""
        findings: List[dict] = []
        comment_pattern = re.compile(
            r'(?://\s*(.+?)$|/\*+\s*([\s\S]+?)\s*\*+/)',
            re.MULTILINE
        )
        for m in comment_pattern.finditer(source_content):
            comment_text = (m.group(1) or m.group(2) or "").strip()
            if not comment_text or len(comment_text) < 5:
                continue
            lower = comment_text.lower()
            for keyword, severity in JSAnalyzer._COMMENT_KEYWORDS:
                if keyword in lower:
                    findings.append({
                        "text": comment_text[:300],
                        "keyword": keyword,
                        "severity": severity,
                        "source_file": source_file,
                    })
                    break
        return findings

    # ── Source map pipeline (internal) ───────────────────────────────────

    @staticmethod
    def _detect_sourcemap_url(js_content: str, js_url: str = "") -> Optional[str]:
        """Detect source map URL from JS content (external or inline base64)."""
        tail = "\n".join(js_content.splitlines()[-5:])
        m = re.search(r'//[#@]\s*sourceMappingURL=(.+)', tail)
        if not m:
            return None
        ref = m.group(1).strip()
        if ref.startswith("data:application/json"):
            return ref
        if ref.startswith("http://") or ref.startswith("https://"):
            return ref
        if js_url:
            base = js_url.rsplit("/", 1)[0]
            return f"{base}/{ref}"
        return ref

    @staticmethod
    def _parse_sourcemap(map_content: str) -> Tuple[List[str], List[str]]:
        """Parse source map JSON → (source_file_names, source_contents)."""
        try:
            data = json.loads(map_content)
        except json.JSONDecodeError as e:
            logger.debug(f"[SourceMap] JSON parse failed: {e}")
            return [], []
        return data.get("sources", []), data.get("sourcesContent", [])

    @staticmethod
    def _decode_inline_map(data_uri: str) -> Optional[str]:
        """Decode inline base64 source map data URI."""
        try:
            _, encoded = data_uri.split(",", 1)
            return base64.b64decode(encoded).decode("utf-8")
        except Exception as e:
            logger.debug(f"[SourceMap] inline decode failed: {e}")
            return None

    @staticmethod
    async def _sourcemap_pipeline(
        js_content: str,
        js_url: str = "",
        http_client=None,
    ) -> Optional[DeepJSResult]:
        """
        Internal: detect → fetch/decode → parse → analyze each original source file.
        Returns merged DeepJSResult or None if no source map found.
        """
        map_url = JSAnalyzer._detect_sourcemap_url(js_content, js_url)
        if not map_url:
            logger.debug("[SourceMap] no sourceMappingURL found — skip")
            return None

        logger.debug(
            f"[SourceMap] pipeline start js_url={js_url!r} map_ref={map_url[:80] + '...' if len(map_url) > 80 else map_url!r}"
        )
        map_content: Optional[str] = None

        if map_url.startswith("data:"):
            map_content = JSAnalyzer._decode_inline_map(map_url)
            logger.debug("[SourceMap] inline base64 map decoded")
        else:
            try:
                import httpx
                own_client = http_client is None
                client = http_client or httpx.AsyncClient(
                    timeout=15,
                    verify=False,
                    follow_redirects=True,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                try:
                    resp = await client.get(map_url)
                    if resp.status_code == 200:
                        map_content = resp.text
                        logger.info(f"[SourceMap] fetched {map_url} ({len(map_content)} bytes)")
                    else:
                        logger.debug(f"[SourceMap] {map_url} → HTTP {resp.status_code}")
                finally:
                    if own_client:
                        await client.aclose()
            except Exception as e:
                logger.debug(f"[SourceMap] fetch error: {e}")

        if not map_content:
            logger.debug("[SourceMap] no map content (fetch/decode failed) — skip")
            return None

        sources, contents = JSAnalyzer._parse_sourcemap(map_content)
        if not sources:
            logger.debug("[SourceMap] parse ok but sources list empty — skip")
            return None

        logger.info(f"[SourceMap] {len(sources)} source files: {sources[:5]}")

        merged = DeepJSResult()
        merged.sourcemap_sources = sources
        with_content = sum(1 for i in range(len(sources)) if i < len(contents) and contents[i])
        logger.debug(f"[SourceMap] analyzing {with_content}/{len(sources)} sources with content")

        for i, src_file in enumerate(sources):
            src_content = contents[i] if i < len(contents) else None
            if not src_content:
                continue

            result = JSAnalyzer._extract_sync(src_content, url=src_file)
            merged.endpoints |= result.endpoints
            merged.endpoints_with_method.update(result.endpoints_with_method)
            merged.route_auth.update(result.route_auth)
            merged.taint_hints.extend(result.taint_hints)
            merged.secrets.extend(result.secrets)
            merged.user_controlled_params.extend(result.user_controlled_params)
            if result.framework_detected and not merged.framework_detected:
                merged.framework_detected = result.framework_detected

            merged.vuln_hints.extend(JSAnalyzer.analyze_function_names(src_content, src_file))
            merged.dev_comments.extend(JSAnalyzer.extract_dev_comments(src_content, src_file))

        merged.secrets = JSAnalyzer._dedup_secrets(merged.secrets)

        logger.success(
            f"[SourceMap] merged: {len(merged.endpoints)} endpoints, "
            f"{len(merged.secrets)} secrets, "
            f"{len(merged.vuln_hints)} vuln hints, "
            f"{len(merged.dev_comments)} dev comments"
        )
        return merged

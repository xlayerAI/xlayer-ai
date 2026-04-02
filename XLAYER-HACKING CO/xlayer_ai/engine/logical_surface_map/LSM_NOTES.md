# XLayer LSM — Logical Surface Mapping System
# Complete Development Notes

**Location:** `xlayer_ai/engine/logical_surface_map/`
**Total:** 5 files, 3,565 lines
**Purpose:** Phase 1 of XLayer pipeline — target surface ko complete blueprint banaucha hunting phase start hunu agadi

---

## Files Overview

| File | Lines | Role |
|------|-------|------|
| `js_analyzer.py` | 1205 | JS intelligence engine — AST, secrets, taint, source map |
| `http_probe.py` | 818 | Passive HTTP probe — robots, OpenAPI, GraphQL, headers, JWT |
| `scout.py` | 652 | Agentic orchestrator — LLM loop, strategy dispatch |
| `path_fuzzer.py` | 418 | Wordlist + smart path discovery |
| `browser_analyzer.py` | 324 | Playwright dynamic browser execution |
| `graph.py` | 148 | Data structures — LogicalSurface, EndpointNode, TaintHint |

---

## Full Execution Flow

```
ScoutLoop.run(url, auth_cookies)
│
├─ Phase 0: HttpProbe.probe()              ← PASSIVE, runs ALWAYS before LLM
│     ├─ robots.txt + sitemap.xml
│     ├─ /openapi.json + /swagger.json      ← full endpoint map if found
│     ├─ /graphql introspection             ← full schema if found
│     ├─ GET / → response headers           ← security audit
│     ├─ OPTIONS per endpoint               ← real allowed HTTP methods
│     ├─ POST malformed body                ← error fingerprinting
│     └─ JWT decode from cookies            ← alg:none, sensitive fields
│
├─ Phase 1-50: LLM agentic loop            ← 50 iterations max
│     │
│     ├─ LLM reads surface summary → decides strategy
│     │
│     ├─ "browser_crawl"
│     │     └─ BrowserAnalyzer.analyze()
│     │           ├─ Playwright headless Chromium
│     │           ├─ history.pushState spy → SPA routes
│     │           ├─ page.on('request/response') → real XHR/fetch
│     │           ├─ form extraction (action/method/inputs)
│     │           ├─ 401/403 response → auth walls
│     │           └─ JS bundle URLs → queued for js_crawling
│     │
│     ├─ "js_crawling"
│     │     └─ JSAnalyzer.analyze(js_content, url)
│     │           ├─ _prescan_obfuscation() → _0x string arrays
│     │           ├─ esprima AST parse (strict → tolerant → TS-stripped)
│     │           ├─ _ASTWalker.walk() → endpoints, routes, taint
│     │           ├─ _extract_secrets() → camelCase + SCREAMING_SNAKE_CASE
│     │           └─ _sourcemap_pipeline() → original source analysis
│     │
│     ├─ "api_guessing" (1st time)
│     │     └─ WordlistFuzzer.fuzz()
│     │           ├─ Phase 1: 300-path core wordlist
│     │           └─ Phase 2: prefix × suffix smart expansion
│     │
│     ├─ "api_guessing" (2nd+ time)
│     │     └─ JSAnalyzer.generate_guessing_logic()
│     │           ├─ verb swaps (get→delete, view→edit)
│     │           ├─ version pivots (/v1/ → /v0/, /v2/)
│     │           ├─ role prefixes (/user/ → /admin/)
│     │           └─ IDOR (/endpoint/1, /endpoint/0)
│     │
│     ├─ "param_mining" → hidden params (debug, admin, token, ...)
│     ├─ "auth_scoping" → public vs protected boundary mapping
│     └─ "conclude" → LLM satisfied, return LogicalSurface
│
└─ Returns: LogicalSurface (complete blueprint)
```

---

## File 1: `js_analyzer.py` — JS Intelligence Engine

### Kina banayo?
JavaScript files ma application ko sabai logic hunch — API endpoints, routes, secrets, vulnerability patterns. Static HTML ma kei hudaina modern SPAs ma. Yo file chai JS bata intelligence extract garcha.

### K garcha?

#### Entry Point
```python
await JSAnalyzer.analyze(content, url, http_client) → DeepJSResult
```
Ek call ma sab kaam garcha (pehle 2 alag calls thiyo — merge garyo).

#### A. Obfuscation Pre-Scanner — `_prescan_obfuscation()`
**Kina:** JavaScript Obfuscator tool le code lai unreadable banaucha. Real targets (especially paid apps) ma common xa.

Detect garcha:
```javascript
// Pattern 1: string array
var _0xABCD = ['/api/users', 'POST', 'Authorization']

// Pattern 2: wrapper function
function _0x1234(n) { return _0xABCD[n] }
```
Yo AST parse hunu AGADI regex le catch garcha. Ani AST walk ma `_resolve_string()` le yinlai use garcha.

#### B. TypeScript Stripper — `_strip_typescript()`
**Kina:** esprima pure JS parser ho — TypeScript annotations `(x: string)`, `interface Foo {}`, `type Bar = ...` dekheyo bhane crash garcha. Real targets ma `.ts` files source map bata aaucha.

Strips:
- `: string`, `: number`, `: boolean` param annotations
- `): void {` return type annotations
- `foo as Bar` type assertions
- `interface Foo {}` blocks
- `type Foo = ...;` aliases

#### C. AST Walker — `_ASTWalker`
**Kina:** Regex le `"/api/users"` ta catch garcha tara:
- `const BASE = '/api'; fetch(BASE + '/users')` — regex le miss garcha
- `axios.post('/api/login', {method: 'POST'})` — regex le method miss garcha
- `router.get('/admin', adminGuard, handler)` — regex le auth miss garcha

AST le actual program structure bujhcha.

Extracts:
- **Variable string resolution:** `const base = '/api/v1'; fetch(base + '/users')` → `/api/v1/users`
- **Template literals:** `` fetch(`/api/${version}/users`) `` → `/api/{param}/users`
- **HTTP calls:** fetch, axios, $.ajax, XMLHttpRequest, superagent, ky
- **Framework routes:** React Router `<Route path>`, Express `app.get()`, Vue/Angular route config arrays
- **Route auth guards:** `canActivate: [AdminGuard]` → `auth_required=True, role_level="admin"`
- **Taint tracking:** `location.search → innerHTML` = XSS hint

#### D. `_resolve_string()` — 3 new obfuscation cases
**Kina:** Obfuscated code ma URLs direct string ma haudaina, indirect xa.

```python
String.fromCharCode(47, 97, 112, 105)  →  "/api"
_0x1234(0x3)                           →  array_vars['_0xABCD'][3]
_0xABCD[0x3]                           →  array_vars['_0xABCD'][3]
```

#### E. `fetch(url, {method:'POST'})` Bug Fix
**Kina:** `fetch('/api/login', {method: 'POST'})` — HTTP_CALLEE_MAP ma fetch → "GET" default. Arguments[1] check nathiyo. Sabai POST requests "GET" store hunchyo.

Fix:
```python
if len(node.arguments) > 1:
    _, obj_method = self._extract_options_object(node.arguments[1])
    if obj_method:
        method = obj_method   # override GET with POST/PUT/DELETE
```

#### F. Secret Detection — Dual Regex
**Kina:** Pehle `apiKey = '...'` catch hunchyo tara `SECRET_KEY = '...'` miss hunchyo.

```python
# camelCase/lowercase
apiKey, authToken, dbPassword, jwtSecret ...

# SCREAMING_SNAKE_CASE (env vars style)
SECRET_KEY, API_KEY, JWT_TOKEN, DB_PASSWORD ...
```

#### G. Source Map Pipeline
**Kina:** Production JS minified hunch — original source files access garna source map chahincha. Source map ma original TypeScript/JSX files hunchaN jaha developer comments, function names, file paths visible hunchaN.

Pipeline:
1. `sourceMappingURL=` detect (file tail ma hunch)
2. Fetch map file (external URL) ya decode inline base64
3. Parse `sources[]` + `sourcesContent[]`
4. Each original source file ma:
   - `analyze_function_names()` → `executeQuery()` = SQLi hint, `renderTemplate()` = SSTI hint
   - `extract_dev_comments()` → `// bypass auth`, `// TODO: remove hardcoded key`

#### H. Route Guessing — `generate_guessing_logic()`
**Kina:** Discovered endpoints bata logically related routes predict garcha.

```python
/api/getUser  →  /api/deleteUser, /api/updateUser, /api/createUser
/api/v1/      →  /api/v0/, /api/v2/
/api/user/    →  /api/admin/
/api/orders   →  /api/orders/1, /api/orders/0
```

---

## File 2: `browser_analyzer.py` — Dynamic Browser Execution

### Kina banayo?
Modern SPAs (React, Vue, Angular) ma HTML ma kei hudaina — JavaScript run bhaepachi matra API calls hunchaN. Static analysis le yinlai dekhdaina. Real browser chahincha.

### K garcha?

#### pushState Spy Injection
```javascript
// Page scripts run hunu AGADI inject hunch
history.pushState = function(s, t, url) {
    window.__xlayer_routes__.add(String(url));
    return _push(s, t, url);
};
```
**Kina:** React Router, Vue Router le `history.pushState()` call garcha route change garda. Yo intercept nabhayi SPA routes miss hunchaN.

#### XHR/Fetch Interception
```python
page.on('request', _on_request)    # method, URL, headers, body capture
page.on('response', _on_response)  # status code, content-type capture
```
**Kina:** Real browser le actual API calls garchon — developer tools ma dekhine jasto. Network intercept = ground truth.

#### Auth Wall Detection
```python
if resp.status in (401, 403):
    result.auth_walls.add(p.path)
```
**Kina:** Kुन paths authenticated xa thaha paucha without manually testing. Auth scoping automatic hunch.

#### SPA Route Navigation
Browser le discover gareko har route navigate garcha (max 20) → lazy-loaded APIs trigger hunchaN.

#### Vue Router Schema Extraction
```javascript
const router = app.__vue_app__.config.globalProperties.$router;
router.options.routes.forEach(r => routes.add(r.path));
```
**Kina:** Vue Router ko route config runtime ma JS memory ma hunch — DOM ma visible hudaina. JS execution bata matra access hunch.

---

## File 3: `http_probe.py` — Passive HTTP Intelligence

### Kina banayo?
Reference comparison garda yo 7 capabilities miss thiyo. Static JS analysis ra browser execution ले HTTP-level intelligence miss garcha:
- Response headers (CSP, CORS, HSTS) — vulnerability configuration info
- Swagger spec — FREE endpoint map
- robots.txt — admin le nai hidden paths list gareka hunchaN
- JWT tokens — auth bypass opportunities

### K garcha?

#### 1. robots.txt + sitemap.xml
**Kina:** `Disallow: /admin/backup` — admin le nai accidentally expose gareko. Common discovery step jo every pentester garchaN.

```
Disallow: /admin          →  discovered_paths.add("/admin")
Disallow: /internal/api   →  discovered_paths.add("/internal/api")
Sitemap: https://x.com/sitemap.xml  →  recursively parse
```

#### 2. OpenAPI / Swagger Spec
**Kina:** Agar `/openapi.json` xa bhane — sab endpoints, methods, params, body fields, auth requirements FREE ma milcha. api_guessing ra js_crawling skip garna milcha.

Probes 15 common paths: `/openapi.json`, `/swagger.json`, `/api-docs`, `/docs`, etc.

Extracts per endpoint:
- Path + HTTP method
- Query/path parameters (exact names)
- Request body fields (JSON schema properties)
- Auth required (global security scheme ya per-operation)
- Summary/description

#### 3. GraphQL Introspection
**Kina:** GraphQL le `__schema` query accept garchon by default — entire API schema expose hunch. Queries, mutations, subscriptions, field types, argument names.

```graphql
query IntrospectionQuery {
  __schema {
    queryType { fields { name args { name } type { name } } }
    mutationType { fields { name args { name } type { name } } }
    subscriptionType { fields { name args { name } type { name } } }
  }
}
```

Mutations = data modify garcha = high-value attack targets.

#### 4. Security Header Audit
**Kina:** Misconfigured headers directly = vulnerabilities (CORS bypass, XSS, Clickjacking).

Checks:
| Header | Issue |
|--------|-------|
| Missing CSP | XSS easier |
| `unsafe-inline` in CSP | XSS bypass |
| `Access-Control-Allow-Origin: *` | CORS bypass — any site can read responses |
| `ACAO: * + ACAC: true` | Credentialed CORS = session steal |
| HSTS `max-age=0` | MITM downgrade possible |
| Missing `X-Frame-Options` | Clickjacking |
| `X-Powered-By: Express 4.18` | Tech stack leak |

#### 5. HTTP OPTIONS Enumeration
**Kina:** Hamle assume garcha `/api/users` GET ho — tara OPTIONS le `DELETE` ni allowed cha bhanyo bhane IDOR + delete possible xa.

```
OPTIONS /api/users → Allow: GET, POST, DELETE, PUT
```
DELETE, PUT, PATCH visible = writable endpoint = high priority for IDOR testing.

#### 6. Error Fingerprinting
**Kina:** Malformed request pathaucha → server error message bata internal paths, stack traces, framework versions leak hunchaN.

```
POST /api/users  body: {"id": "' OR 1=1--"}
→ HTTP 500: "at executeQuery (src/db/users.ts:142:5)"
→ internal path: /app/src/db/users.ts
→ tech: Node.js + TypeScript
```

#### 7. JWT Cookie Analysis
**Kina:** Browser cookies ma JWT tokens hunchaN. Decode bhaepachi:
- `alg: none` → signature verification skip, token forge possible (CRITICAL)
- `alg: HS256` → symmetric secret, brute-forceable
- `exp` absent → token never expires
- payload ma `password`, `is_admin`, `role` → sensitive data exposure

No network needed — pure base64 decode.

---

## File 4: `path_fuzzer.py` — Wordlist-Based Discovery

### Kina banayo?
XLayer ma logic-based guessing thiyo (verb swaps etc.) — tara blank target ma kaam gardaina. Wordlist-based discovery: target ma kei known endpoint nabhaye ni `/admin`, `/.env`, `/actuator/shutdown` try garcha. Yo gap fill garyo.

### K garcha?

#### WORDLIST_CORE — 300 high-value paths
Logic-based nai, pre-researched paths:
```
/.env, /.env.local, /.env.production     ← exposed secrets
/.git/HEAD, /.git/config                 ← source code leak
/actuator/shutdown                       ← Spring Boot RCE
/admin, /administrator                   ← admin panels
/phpmyadmin, /adminer                    ← DB admin UI
/api/internal, /api/private              ← hidden APIs
/backup.sql, /dump.sql                   ← database dumps
/wp-json/wp/v2/users                     ← WordPress user enum
/debug, /console, /shell                 ← dev tools left exposed
```

Categories:
- Auth endpoints
- Admin panels
- API base paths + common resources
- Health/Status/Actuator
- Config/Debug/Dev
- Sensitive files (git, env, backup)
- Documentation/Swagger
- CMS-specific (WordPress, Drupal, Laravel)
- SSRF candidates

#### Phase 2: Smart Expansion
**Kina:** `/api/v1` discovered xa bhane `/api/v1/users`, `/api/v1/admin` etc. try garnu parcha. Static wordlist le context-awareness hudaina.

```python
# Known prefix: /api/v1
# + suffix: users, admin, settings, export ...
→ /api/v1/users, /api/v1/admin, /api/v1/settings ...

# Existing hit: /api/users (200)
# + IDOR: /1, /0, /me
→ /api/users/1, /api/users/0, /api/users/me

# Existing hit: /api/v1/data (200)
# + version pivot
→ /api/v0/data, /api/v2/data
```

#### Concurrent Execution
`asyncio.Semaphore(20)` — 20 concurrent requests, target hammering nagarna.

#### Hit Codes
`200, 201, 204, 301, 302, 401, 403` = "hit" (path exists)
- 200/201/204 = accessible
- 301/302 = redirect (note destination)
- 401/403 = exists but auth-required → mark as auth wall

---

## File 5: `scout.py` — Agentic Orchestrator

### Kina banayo?
Strategy decision machine. LLM le surface summary hercha ani "aile kha garnu parcha?" decide garcha. Fixed sequence (always browser → always js → always guess) bhandaa LLM-driven adaptive xa — target ko nature hेrera strategy choose garcha.

### K garcha?

#### ScoutState
50 iterations ko memory:
- `surface: LogicalSurface` — accumulated findings
- `strategies_tried: Set[str]` — loop avoid garna
- `journal: List[str]` — chronological discovery log

#### Strategy Selection Logic (LLM prompt)
```
OpenAPI spec found → skip api_guessing, focus js_crawling + auth_scoping
GraphQL found → focus auth_scoping on mutations
No spec/GraphQL → browser_crawl first, then js_crawling
CORS: * detected → note as CORS bypass target
```

#### `_apply_probe_result()` — Probe merger
HttpProbe findings lai graph ma merge garcha:
- robots paths → `add_endpoint(..., source="robots_sitemap")`
- OpenAPI endpoints → `add_endpoint + add_params + set_endpoint_auth`
- GraphQL queries/mutations → journal entries + endpoint registration
- Security misconfigs → `surface.security_header_misconfigs`
- JWT issues → `surface.jwt_issues`

#### `_apply_fuzz_result()` — Fuzz merger
WordlistFuzzer hits lai graph ma merge garcha:
- 200/301/302 hits → `add_endpoint(..., source="wordlist_fuzz")`
- 401/403 hits → `set_endpoint_auth(auth_required=True)`
- Redirects → journal entry

---

## File 6: `graph.py` — Data Structures

### LogicalSurface — Application Blueprint

```python
@dataclass
class LogicalSurface:
    base_url: str

    # Core discovery
    endpoints: Dict[str, EndpointNode]    # url → EndpointNode
    js_files: Set[str]                    # JS bundle URLs
    entities: Set[str]                    # User, Order, Invoice
    tech_stack: Dict[str, str]            # React: "js_deep", Express: "import"

    # JS analysis findings
    secrets: List[Dict]                   # {key, value}
    taint_hints: List[TaintHint]         # source → sink chains
    vuln_hints: List[dict]               # function name → vuln type
    dev_comments: List[dict]             # bypass, backdoor, hardcoded
    sourcemap_sources: List[str]         # original .ts/.jsx file names

    # HTTP Probe findings (NEW)
    openapi_spec_url: str               # "/openapi.json" if found
    graphql_endpoint: str               # "/graphql" if found
    graphql_queries: List[str]          # ["getUser", "listOrders"]
    graphql_mutations: List[str]        # ["createUser", "deleteOrder"]
    security_header_misconfigs: List[dict]  # {header, value, issue}
    missing_security_headers: List[str]     # ["content-security-policy"]
    allowed_methods: Dict[str, List[str]]   # {"/api/users": ["GET","DELETE"]}
    jwt_issues: List[dict]              # {algorithm, issues, sensitive_fields}
    cors_open: bool                     # True if CORS: * detected
```

### EndpointNode — Per-Endpoint Data
```python
@dataclass
class EndpointNode:
    url: str
    method: str = "GET"
    parameters: Set[str]        # query params + body fields
    auth_required: bool = False
    role_level: str = "guest"   # guest, user, admin
    discovery_source: str       # spider/js_deep/openapi/graphql/wordlist_fuzz/browser_xhr
```

### TaintHint — XSS/SSRF/Redirect Evidence
```python
@dataclass
class TaintHint:
    source: str    # "location.search", "URLSearchParams"
    sink: str      # "innerHTML", "window.location", "fetch"
    vuln_type: str # "xss", "open_redirect", "ssrf"
    context: str   # JS code snippet
    js_file: str   # which bundle file
```

---

## Bugs Fixed

| Bug | Effect | Fix |
|-----|--------|-----|
| `await` in sync `def _apply_discovery_logic` | SyntaxError crash on js_crawling | `async def` |
| TypeScript esprima crash | All .ts source map files fail | `_strip_typescript()` before parse |
| `SECRET_KEY` miss | Env-style secrets not detected | `_SECRET_REGEX_SCREAMING` added |
| `fetch(url, {method:'POST'})` stored as GET | Wrong HTTP method in endpoint graph | Check `arguments[1]` for options object |
| `_prescan_obfuscation` empty strings | `a if a is not None else b` on regex groups | Changed to `a or b` |

---

## Reference Comparison — Final State

| Capability | XLayer | Reference | Notes |
|---|---|---|---|
| Browser XHR interception | ✅ | ✅ | Playwright |
| SPA route tracking | ✅ | ✅ | pushState spy |
| JS AST analysis | ✅ | ✅ | esprima |
| Taint tracking | ✅ | ✅ | source→sink |
| Source map analysis | ✅ | ✅ | |
| Obfuscation deobfuscation | ✅ **better** | partial | _0x full deobfuscation |
| robots.txt / sitemap | ✅ | ✅ | |
| OpenAPI/Swagger parsing | ✅ | ✅ | v2 + v3 |
| GraphQL introspection | ✅ | ✅ | queries+mutations+subscriptions |
| Security header audit | ✅ | ✅ | CSP, CORS, HSTS, XFO |
| HTTP OPTIONS enumeration | ✅ | ✅ | actual methods |
| Error fingerprinting | ✅ | ✅ | stack traces, internal paths |
| JWT cookie analysis | ✅ | ✅ | alg:none, no_exp, sensitive fields |
| Route guessing — wordlist | ✅ | ✅ | 300-path focused wordlist |
| Route guessing — logic | ✅ **better** | ❌ | verb swaps, version pivots, IDOR |

**XLayer has parity on all 15 points. 2 areas ma better.**

---

## Dependencies Required

```
httpx          — HTTP client (probe + fuzz)
playwright     — browser execution (install: playwright install chromium)
esprima        — JS AST parser
loguru         — logging
pyyaml         — YAML OpenAPI spec parsing (optional, fallback to JSON)
```

---

## File 7: `lsm_tools.py` — Async HTTP Tools (NEW)

### Kina banayo?
`ToolRegistry.execute()` sync xa. HTTP fetch async chaincha. Previous state ma LLM le "tool_call: fetch_js" decide garyo bhane `tool_result = ""` (empty string) — kei kaam garydainathiyo. JS analysis hune nai thiyena.

### Architecture
```
ToolRegistry (schema declaration — LLM lai dekhaucha)
    → schema-only Tool objects (dummy func)
    → LLM: "I can call fetch_js, fetch_html, spider_links, check_endpoint, fetch_json"

LSMTools (actual execution — async HTTP)
    → async with LSMTools(...) as lsm_tools:  ← opened once per run()
    → lsm_tools.call("fetch_js", {"url": "..."})  ← real HTTP request

ScoutLoop.run() dispatch:
    if lsm_tools.has_tool(tool_name):
        result = await lsm_tools.call(...)   ← ASYNC path
    else:
        result = self.registry.execute(...)  ← SYNC fallback (hunter tools, JIT)
```

### 5 Tools

| Tool | Input | Output | Strategy |
|------|-------|--------|----------|
| `fetch_js` | url | Raw JS content (2MB cap) | js_crawling |
| `fetch_html` | url | Raw HTML (500KB cap) | any |
| `spider_links` | url | One URL per line (a[href], script[src], form[action]) | js_crawling, auth_scoping |
| `check_endpoint` | path, method | Status + headers + body snippet | auth_scoping, param_mining |
| `fetch_json` | url, method, body | HTTP status + pretty JSON (3000 char cap) | api_guessing, param_mining |

### `check_endpoint` output example
```
URL:    https://target.com/api/admin
Method: GET
Status: 403
Content-Type: application/json
Server: nginx/1.24.0
WWW-Authenticate: Bearer realm="api"
Body: {"error": "Forbidden", "message": "Admin access required"}
```
→ `_apply_discovery_logic(strategy="auth_scoping")` picks this up and marks endpoint as `auth_required=True`

## TODO / Remaining Work

- [ ] `ScoutLoop` tool registry — ✅ DONE (lsm_tools.py)
- [ ] `ReconAgent` (src/agent/swarm/Recon.py) → ScoutLoop connection missing
- [ ] `main.py` still uses old PlannerAgent (Coordinator connection pending)
- [ ] Phase 2 fuzz runs `smart_expand=True` only when `known_prefixes` exist — first scan (no prior endpoints) Phase 2 skips
- [ ] Wordlist can be extended — current 300 paths is focused (not exhaustive like dirbuster's 200k)

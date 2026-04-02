# XLayer Logical Surface Map (LSM) — गहिरो विवरण रिपोर्ट

यो रिपोर्टमा **target URL** दिएपछि LSM engine कसरी काम गर्छ, प्रत्येक मोड्युलको भूमिका, र एकअर्कासँग कसरी जोडिन्छ भन्ने सबै विवरण समेटिएको छ।

---

## १. समग्र ढाँचा (Overall Flow)

```
TARGET URL दिइन्छ
       │
       ▼
┌──────────────────────────────────────────────────────────────────┐
│  SCOUT.run(url)  — मुख्य नियन्त्रक (scout.py)                     │
└──────────────────────────────────────────────────────────────────┘
       │
       ├─► Phase 0: HttpProbe.probe()     (http_probe.py)
       │        → robots.txt, OpenAPI, GraphQL, headers, JWT, OPTIONS...
       │
       ├─► Phase 0b: Tech-aware path fuzz (path_fuzzer + LLM)
       │        → tech stack अनुसार path generate → WordlistFuzzer
       │
       └─► Phase 1–50: LLM Agentic Loop
                │
                ├─► LLM ले decision दिन्छ (browser_crawl / tool_call / api_guessing / conclude...)
                │
                ├─► browser_crawl → BrowserAnalyzer.analyze()  (browser_analyzer.py)
                │        → XHR intercept, SPA routes, forms, JS files
                │        → नतिजा LogicalSurface मा merge
                │        → auto: JS files → JSAnalyzer.analyze() (js_analyzer.py)
                │
                ├─► api_guessing → WordlistFuzzer.fuzz()  (path_fuzzer.py)
                │        → core wordlist + smart expansion → hits merge
                │
                ├─► tool_call → LSMTools.call()  (lsm_tools.py)
                │        → fetch_js / fetch_html / spider_links / check_endpoint / fetch_json
                │        → output → _apply_discovery_logic(strategy, ...)
                │        → js_crawling को लागि JSAnalyzer.analyze() बाट endpoints, secrets, taint...
                │
                └─► नयाँ endpoints आएमा → _quick_probe_new_endpoints() (check_endpoint)
                         → auth_scoping, param_mining फेरि apply
       │
       ▼
  LogicalSurface (graph.py) — अन्तिम “blueprint”
       │
       ▼
  Agentic Loop (exploitation) — agentic_loop.py
       → यो surface प्रयोग गरेर vulnerability hunt (SQLi, XSS, SSRF...) गर्ने loop
```

---

## २. प्रत्येक मोड्युलको काम र कसरी काम गर्छ

### २.१ `scout.py` — ScoutLoop (Strategic Scouting Kernel)

**काम के हो:**  
Target URL लिएर **सम्पूर्ण application को logical surface (blueprint)** बनाउने। यो LSM को **मुख्य नियन्त्रक** हो। LLM सँग बातचीत गरेर strategy छान्छ र बाँकी सबै मोड्युलहरू यहींबाट चलाइन्छ।

**कसरी काम गर्छ:**
1. **ScoutState** बनाउँछ: `target_url`, `surface` (LogicalSurface), `iteration`, `current_strategy`, `journal`.
2. **Phase 0:** सुरुमै `HttpProbe.probe(base_url)` चलाउँछ → robots.txt, OpenAPI, GraphQL, security headers, JWT, OPTIONS, error fingerprint सबै एकै पटक।
3. **Phase 0b:** यदि tech stack पत्ता लाग्यो भने LLM लाई framework-specific path generate गर्न लगाउँछ → त्यो path list लाई `WordlistFuzzer.fuzz(wordlist=tech_paths)` मा दिन्छ।
4. **Phase 1–50:** हरेक iteration मा:
   - `state.as_prompt()` बाट context (surface summary, iteration, strategies) LLM लाई पठाउँछ।
   - LLM को JSON decision parse गर्छ: `action`, `strategy`, `args`.
   - **browser_crawl** भए → `BrowserAnalyzer.analyze()` चलाउँछ, नतिजा `_apply_browser_result()` ले surface मा merge गर्छ; JS files लाई `_auto_analyze_js_files()` ले fetch + JSAnalyzer चलाउँछ।
   - **api_guessing** भए → `WordlistFuzzer.fuzz()` (पहिलो पटक Phase 1+2, पछि Phase 2 मात्र), नतिजा `_apply_fuzz_result()` ले surface मा merge।
   - **tool_call** भए → `LSMTools.call(tool_name, args)` वा registry को अर्को tool; output आएपछि `_apply_discovery_logic(state, result_text, strategy, context_url)` चलाउँछ (js_crawling / api_guessing / param_mining / auth_scoping अनुसार surface update).
   - **conclude** भए → कम्तीमा 3 endpoints र 2 strategies भएमात्र loop बन्द गर्छ।
5. नयाँ endpoints आएको हरेक iteration मा `_quick_probe_new_endpoints()` ले ती path हरूमा `check_endpoint` गरेर auth wall र param mining फेरि apply गर्छ।

**कसरी जोडिन्छ:**
- `HttpProbe`, `BrowserAnalyzer`, `WordlistFuzzer`, `LSMTools`, `JSAnalyzer` सबै ScoutLoop ले नै चलाउछ।
- सबै नतिजा **LogicalSurface** (graph.py) मा merge हुन्छ।
- अन्त्यमा `state.surface` (LogicalSurface) return गर्छ — यही blueprint पछि exploitation (agentic_loop) ले प्रयोग गर्छ।

---

### २.२ `http_probe.py` — HttpProbe (Passive HTTP Intelligence)

**काम के हो:**  
Browser वा JS बिनै **direct HTTP** बाट सबै “prior intelligence” एकै चोटि लिने: robots/sitemap, OpenAPI/Swagger, GraphQL introspection, security headers, OPTIONS, error fingerprint, JWT analysis। ScoutLoop को **Phase 0** मा एक पटक मात्र चल्छ।

**कसरी काम गर्छ:**
1. **robots.txt + sitemap:** `GET /robots.txt` → Disallow/Allow/Sitemap parse → sitemap URL लिएर fetch → XML/plain parse गरेर path निकाल्छ।
2. **OpenAPI/Swagger:** `/openapi.json`, `/swagger.json`, `/api-docs` जस्ता path हरू probe गर्छ → 200 आएमा JSON/YAML parse → `paths` बाट endpoint, method, params, body_fields, auth_required निकाल्छ।
3. **GraphQL:** `/graphql`, `/gql` आदि मा introspection query POST गर्छ → response बाट queries, mutations, subscriptions निकाल्छ।
4. **Security headers:** `GET /` को response headers मा required headers (X-Frame-Options, CSP, HSTS…) check गर्छ, tech-reveal headers (X-Powered-By, Server…) र CORS misconfig लगाउँछ।
5. **.well-known:** OIDC, OAuth, JWKS, security.txt probe गरेर auth endpoints र tech hints निकाल्छ।
6. **OPTIONS enumeration:** दिएको path list मा OPTIONS request → `Allow` / `Access-Control-Allow-Methods` बाट actual allowed methods लिन्छ।
7. **Error fingerprinting:** केही path मा जान्दै malformed POST (e.g. JSON with `' OR 1=1--`) पठाएर 4xx/5xx को body मा stack trace, internal path, framework name pattern match गर्छ।
8. **JWT:** cookies (र Set-Cookie response) मा `ey...` pattern खोजी decode गर्छ (signature verify गर्दैन), alg:none, no_exp, sensitive payload जस्ता issues लगाउँछ।

**कसरी जोडिन्छ:**
- ScoutLoop को `run()` को सुरुमा `await self.http_probe.probe(base_url=url, cookies=auth_cookies)`।
- नतिजा `_apply_probe_result(state, probe_result)` ले **LogicalSurface** मा: `discovered_paths`, `openapi_endpoints`, `graphql_schema`, `security_headers`, `allowed_methods`, `error_fingerprints`, `jwt_findings`, `tech_hints` सबै merge गर्छ।

---

### २.३ `browser_analyzer.py` — BrowserAnalyzer (Dynamic Browser Analysis)

**काम के हो:**  
Target लाई **वास्तविक browser** (Playwright headless Chromium) मा खोलेर SPA को वास्तविक व्यवहार देख्ने: कुन XHR/fetch फायर भयो, कुन SPA route छ, form कस्तो छ, कुन JS file load भयो, कुन path ले 401/403 दियो।

**कसरी काम गर्छ:**
1. Playwright सँग browser launch गर्छ, context मा **pushState spy** (`_PUSHSTATE_SPY`) add_init_script गर्छ → `history.pushState`/`replaceState` र `hashchange` intercept गरेर route Set मा राख्छ।
2. Page मा request/response listener लगाउँछ: XHR/fetch/document (static file exclude) लाई track गर्छ, URL + method + headers + post_data + response status राख्छ; 401/403 आए path लाई `auth_walls` मा राख्छ।
3. Target URL मा `goto` गर्छ, केही सेकेन्ड पछि:
   - `_COLLECT_JS_JS`: `<script src>` सबै निकालेर `js_files` मा राख्छ।
   - `_COLLECT_ROUTES_JS`: `__xlayer_routes__` + `<a href>`, `routerLink`, Vue router config बाट SPA routes निकाल्छ।
4. Discovered SPA routes मध्ये (max_navigate सम्म) प्रत्येक route मा फेरि `goto` गर्छ ताकि lazy API call हरू intercept हुन।
5. Form extract: `_COLLECT_FORMS_JS` ले form action, method, input names निकाल्छ।
6. Cookies context बाट लिइन्छ।

**कसरी जोडिन्छ:**
- ScoutLoop मा action `browser_crawl` भएमा `br = await self.browser.analyze(crawl_url, cookies=auth_cookies)` चल्छ।
- नतिजा `_apply_browser_result(state, br)` ले surface मा: **endpoints** (XHR path+method), **spa_routes**, **js_files**, **auth_walls**, **forms** (action + params), र XHR POST body बाट params merge गर्छ।
- `br.js_files` लाई `_auto_analyze_js_files(state, lsm_tools, br.js_files)` ले fetch + JSAnalyzer चलाउँछ।

---

### २.४ `js_analyzer.py` — JSAnalyzer (JS Intelligence Engine)

**काम के हो:**  
JavaScript (र source map बाट आएको original source) को **AST + regex + source map** बाट endpoints, routes, secrets, taint flow (XSS/SSRF/open_redirect), route auth, vuln/dev hints निकाल्ने। Single entry: `await JSAnalyzer.analyze(content, url)`।

**कसरी काम गर्छ:**
1. **Obfuscation pre-scan:** पहिले string array `_0xABCD = ['...']` र wrapper function `_0x1234(n) => _0xABCD[n]` regex ले पत्ता लगाउँछ, AST walk समयमा resolve गर्न दिन्छ।
2. **TypeScript strip:** type annotation हटाउँछ ताकि esprima parse सक्छ।
3. **AST (esprima):** `_ASTWalker` ले:
   - variable assignment (string, template literal, concatenation) resolve गर्छ।
   - `fetch`, `axios`, `$.ajax`, XHR आदि call बाट URL + method निकाल्छ।
   - Express-style `app.get(path, ...)` जस्ता route निकाल्छ।
   - React Router / Vue / Angular route config बाट path + auth guard (AuthGuard, AdminGuard) निकाल्छ।
   - Taint: source (location.search, URLSearchParams…) → sink (innerHTML, fetch, location.href…) map गरेर XSS / open_redirect / SSRF hint दिन्छ।
4. **Secrets:** regex (api_key, auth_token, password, secret…) ले variable name/value scan गर्छ।
5. **Regex fallback:** AST fail भए endpoint literal `/api/...` regex ले निकाल्छ।
6. **Source map:** `//# sourceMappingURL=...` भए fetch/decode गरेर original source files parse गर्छ, प्रत्येक file मा फेरि AST + function name vuln hints + dev comments निकाल्छ र सबै merge गर्छ।

**कसरी जोडिन्छ:**
- ScoutLoop को **js_crawling** strategy: tool `fetch_js` को output (raw JS string) आएपछि `_apply_discovery_logic(state, result_text, "js_crawling", context_url=js_url)` चल्छ। त्यहाँ भित्र `deep = await JSAnalyzer.analyze(result_text, url=js_file_hint)` बोलाइन्छ।
- नतिजा: endpoints (र method), route_auth, secrets, taint_hints, vuln_hints, dev_comments, sourcemap_sources सबै **LogicalSurface** मा merge (scout को `_apply_discovery_logic` ले गर्छ).
- Browser को JS files पनि `_auto_analyze_js_files` ले fetch गरेर यही `JSAnalyzer.analyze` मा पठाउँछ।

---

### २.५ `path_fuzzer.py` — WordlistFuzzer (Path Discovery)

**काम के हो:**  
Logic/OpenAPI बाहेक **wordlist-based path discovery**: admin, auth, api, debug, config, backup जस्ता high-value path हरू probe गर्छ; साथमा “smart expansion” (discovered prefix + suffix) र hit path को backup variant (.bak, .old…) पनि try गर्छ।

**कसरी काम गर्छ:**
1. **Soft 404 detection:** एउटा random junk path probe गर्छ; यदि server ले 200 दिन्छ भने body fingerprint (hash/length) baseline बनाउँछ र बाँकी 200 response यही fingerprint जस्तै भए filter गर्छ।
2. **Phase 1 — Core wordlist:** `WORDLIST_CORE` (~300 path) मा GET request; 200/201/204/301/302/401/403 लाई “hit” मान्छ, 401/403 लाई auth_walls मा राख्छ।
3. **Phase 2 — Smart expansion:** `known_prefixes` (e.g. `/api/v1`, `/admin`) × `WORDLIST_SUFFIXES` (users, login, config…) र hit path + `/1`, `/0`, `/me` जस्ता IDOR variant; version pivot (v1→v2) पनि।
4. **Phase 3 — Backup extensions:** प्रत्येक hit path को लागि `.bak`, `.old`, `.orig` आदि try गर्छ।

**कसरी जोडिन्छ:**
- ScoutLoop को **api_guessing** strategy: पहिलो पटक `WordlistFuzzer.fuzz(base_url, known_prefixes=..., wordlist=None)` → Phase 1+2; पछि पटकहरूमा `wordlist=[]` दिएर Phase 2 मात्र (नयाँ prefix मात्र)।
- Tech path fuzz (Phase 0b): LLM को path list लाई `wordlist=tech_paths` दिएर fuzz।
- नतिजा `_apply_fuzz_result(state, fuzz_result)` ले surface मा hit path र auth_walls merge गर्छ।

---

### २.६ `lsm_tools.py` — LSMTools (ScoutLoop HTTP Tools)

**काम के हो:**  
LLM ले ScoutLoop मा **tool_call** गर्दा चल्ने async HTTP tools को implementation: fetch_js, fetch_html, spider_links, check_endpoint, fetch_json। एउटै httpx client सँग base_url, cookies, proxy use गर्छ।

**कसरी काम गर्छ:**
1. **fetch_js(url):** GET → raw JS content (max 2MB); बाँकी pipeline ले यही content JSAnalyzer मा पठाउँछ।
2. **fetch_html(url):** GET → raw HTML (max 500KB); inline script, meta, link discovery को लागि।
3. **spider_links(url):** GET → regex बाट `<a href>`, `<script src>`, `<form action>`, `<link href>` (api/json/manifest) निकाल्छ, absolute URL एक पंक्तिमा एक।
4. **check_endpoint(path, method):** GET/POST/PUT/DELETE/OPTIONS/HEAD → status, Server, X-Powered-By, Location, WWW-Authenticate, Allow, CORS, body snippet (tag strip) return गर्छ; auth_scoping र param_mining को लागि प्रयोग।
5. **fetch_json(url, method, body):** GET वा POST JSON → status + content-type र pretty JSON (वा non-JSON snippet); HATEOAS link extraction को लागि।

**कसरी जोडिन्छ:**
- ScoutLoop को `run()` भित्र `async with LSMTools(...) as lsm_tools` ले एक पटक client खोल्छ।
- LLM ले `tool_call` + `fetch_js`/`fetch_html`/… दिएमा `tool_result = await lsm_tools.call(tool_name, args)` चल्छ।
- यो `tool_result` नै `_apply_discovery_logic(state, tool_result, strategy, context_url)` मा जान्छ; strategy **js_crawling** भए JSAnalyzer.analyze यहींबाट trigger हुन्छ।

---

### २.७ `graph.py` — LogicalSurface + EndpointNode (Memory / Blueprint)

**काम के हो:**  
सम्पूर्ण recon को **एक ठाउँको memory**: endpoints (path → EndpointNode), js_files, entities, tech_stack, secrets, taint_hints, vuln_hints, dev_comments, sourcemap_sources; साथै HttpProbe बाट openapi_spec_url, graphql_endpoint, security_header_misconfigs, allowed_methods, jwt_issues, cors_open। यही “blueprint” पछि exploitation phase ले प्रयोग गर्छ।

**कसरी काम गर्छ:**
- **EndpointNode:** url, method, parameters, auth_required, role_level, discovery_source (spider, js_analysis, openapi, browser_xhr…), tech_stack।
- **add_endpoint / set_endpoint_auth / add_params_to_endpoint** ले scout र probe को नतिजा merge गर्छ।
- **to_summary()** ले LLM को लागि short text summary बनाउँछ: endpoint count, JS files, entities, OpenAPI/GraphQL, security headers, OPTIONS, JWT, taint/vuln hints, high-value categories (admin, auth, config, graphql, api).

**कसरी जोडिन्छ:**
- ScoutState को `state.surface` नै LogicalSurface हो।
- HttpProbe, BrowserAnalyzer, WordlistFuzzer, _apply_discovery_logic सबैले यही `state.surface` लाई update गर्छ।
- ScoutLoop को return value `state.surface` हो; यही चाहिँ agentic_loop (exploitation) लाई context को रूपमा दिइन्छ।

---

### २.८ `agentic_loop.py` — XLayerLoop (Exploitation Reasoning Loop)

**काम के हो:**  
LSM को **blueprint (LogicalSurface)** र target (URL, parameter, vuln_type) लिएर **vulnerability exploitation** को agentic loop: LLM ले observation journal र context हेरेर tool_call / jit_code / pivot / conclude गर्छ, confidence update र OOB poll गर्छ।

**कसरी काम गर्छ:**
1. **SolverState:** target_url, parameter, vuln_type, method, extra_context (recon/surface), confidence, iteration, journal, messages, strategy।
2. हरेक iteration: `state.full_context()` (target + recon context + journal) + remaining iterations LLM लाई पठाइन्छ।
3. LLM को response parse गरेर **Decision** (tool_call / jit_code / pivot / conclude) निकाल्छ।
4. **tool_call** → ToolRegistry.execute(tool_name, args); **jit_code** → JITEngine.run(code); **pivot** → strategy change; **conclude** → found/not_found।
5. Observation journal मा entry add, confidence update; OOB poll (हरेक 5 iteration); confidence ≥ threshold भए वा conclude भए loop बन्द।
6. Stuck (निम्न confidence लगातार 3+) भए auto-pivot (नयाँ strategy); हरेक 15 iteration मा history compress।

**कसरी जोडिन्छ:**
- LSM **पहिले** चल्छ र **LogicalSurface** बनाउँछ।
- Exploitation phase (XLayerLoop) ले यही surface को summary वा relevant part लाई `SolverState.extra_context` मा राखेर target endpoint र parameter मा vulnerability prove गर्ने प्रयास गर्छ।
- टुटी फाइलहरू: scout → surface; surface + target → agentic_loop।

---

## ३. Target दिएपछि क्रम (Step-by-Step Connection)

1. **User ले target URL दिन्छ** (र optional auth cookies).
2. **ScoutLoop.run(url)** सुरु हुन्छ।
3. **Phase 0 — HttpProbe:** url मा passive probe → robots, OpenAPI, GraphQL, headers, JWT, OPTIONS, errors → नतिजा सबै **LogicalSurface** मा।
4. **Phase 0b:** Tech stack भए LLM path suggest गर्छ → WordlistFuzzer त्यो path लाई probe गर्छ → फेरि surface मा merge।
5. **Loop (1–50):**  
   - LLM ले surface summary र strategy देख्छ।  
   - **browser_crawl** छान्यो भने → BrowserAnalyzer चल्छ → XHR, SPA routes, forms, JS files surface मा; JS files लाई auto fetch + **JSAnalyzer** चलाउँछ → फेरि surface update।  
   - **api_guessing** छान्यो भने → WordlistFuzzer (Phase 1 वा Phase 2) चल्छ → hits surface मा।  
   - **tool_call** (fetch_js/fetch_html/…) छान्यो भने → **LSMTools** चल्छ → output आएपछि **strategy** अनुसार **_apply_discovery_logic** (जसमा **js_crawling** भए **JSAnalyzer.analyze**) चल्छ → surface update।  
   - नयाँ endpoints आएमा **quick_probe** (check_endpoint) चल्छ → auth र param फेरि surface मा।  
   - **conclude** (र न्यूनतम coverage पुगेपछि) भए loop बन्द।
6. **Return:** `state.surface` (LogicalSurface) — यही blueprint।
7. यो blueprint + concrete target (endpoint, param, vuln_type) लिएर **XLayerLoop** (agentic_loop) exploitation चल्छ।

---

## ४. संक्षेप तालिका (Module ↔ Responsibility)

| मोड्युल           | मुख्य काम                                      | कसरी trigger / connect                          |
|-------------------|-----------------------------------------------|-------------------------------------------------|
| **scout.py**      | Strategy नियन्त्रण, Phase 0/0b/1–50, surface merge | Entry: `ScoutLoop.run(url)`                      |
| **http_probe.py** | Passive HTTP intel (robots, OpenAPI, GQL, headers, JWT, OPTIONS) | Phase 0 मा scout ले बोलाउँछ → _apply_probe_result |
| **browser_analyzer.py** | Headless browser, XHR/SPA/forms/JS files | action=browser_crawl → _apply_browser_result + auto JS analyze |
| **js_analyzer.py** | JS AST + secrets + taint + source map        | browser को JS files र fetch_js output → _apply_discovery_logic(js_crawling) |
| **path_fuzzer.py** | Wordlist + smart expansion + backup paths   | api_guessing र tech-path fuzz → _apply_fuzz_result |
| **lsm_tools.py**  | fetch_js/html, spider_links, check_endpoint, fetch_json | tool_call मा scout ले LSMTools.call() गर्छ       |
| **graph.py**      | LogicalSurface / EndpointNode — सबैको नतिजा एक ठाउँ | सबै merger function ले state.surface update गर्छ |
| **agentic_loop.py** | Exploitation loop (tool/jit/pivot/conclude) | LSM पछि surface + target ले run(state)          |

---

यो रिपोर्टले LSM को प्रत्येक भागको काम, कसरी चल्छ, र target दिएपछि कसरी एक-अर्कासँग जोडिन्छ भन्ने **सम्पूर्ण विवरण** समेटिएको छ।


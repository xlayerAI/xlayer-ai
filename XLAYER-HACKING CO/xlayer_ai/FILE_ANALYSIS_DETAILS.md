# XLayer AI — Complete File Analysis & Change Log
# हरेक file को role, के गर्छ, कसरी connect छ — सबै details

---

## SECTION 1 — Complete Project Structure

```
xlayer_ai/                                   ROOT
│
├── main.py                                  CLI entry point
├── README.md                                Project overview
├── FILE_ANALYSIS_DETAILS.md                 This file
├── CHANGELOG.md                             Session-by-session changes
├── requirements.txt                         Python dependencies
├── .env.example                             Environment template
├── mcp_config.json                          MCP config (currently empty — not used)
│
├── config/
│   ├── __init__.py
│   └── settings.py                          ← MODIFIED (session 2)
│
├── core/
│   ├── __init__.py
│   ├── planner.py                           Original 4-phase pipeline orchestrator
│   ├── recon.py                             DNS + ports + tech + crawl
│   ├── exploit.py                           Basic exploit validation (pre-Level4)
│   ├── reporter.py                          JSON/HTML/PDF report
│   └── vuln_hunters/
│       ├── __init__.py                      ← MODIFIED (session 2)
│       ├── base.py                          Abstract BaseHunter
│       ├── sqli.py                          Original
│       ├── xss.py                           Original
│       ├── auth.py                          Original
│       ├── ssrf.py                          Original
│       ├── lfi.py                           Original
│       ├── ssti.py                          ← NEW (session 2)
│       ├── rce.py                           ← NEW (session 2)
│       ├── xxe.py                           ← NEW (session 2)
│       ├── open_redirect.py                 ← NEW (session 2)
│       ├── cors.py                          ← NEW (session 2)
│       ├── csrf.py                          ← NEW (session 2)
│       ├── subdomain_takeover.py            ← NEW (session 2)
│       ├── graphql.py                       ← NEW (session 2)
│       ├── race_condition.py                ← NEW (session 2)
│       ├── deserialization.py               ← NEW (session 2)
│       └── http_smuggling.py               ← NEW (session 2)
│
├── src/
│   ├── __init__.py
│   ├── agent/
│   │   ├── __init__.py                      ← MODIFIED (session 1)
│   │   ├── coordinator.py                   ← NEW (session 1)
│   │   ├── solver.py                        ← NEW (session 1)
│   │   └── swarm/
│   │       ├── __init__.py
│   │       ├── Planner.py                   Swarm agent
│   │       ├── Recon.py                     Swarm agent
│   │       ├── InitAccess.py                Swarm agent
│   │       └── Summary.py                   Swarm agent
│   ├── graph/
│   │   ├── __init__.py
│   │   └── swarm.py                         Swarm graph compiler
│   ├── tools/
│   │   ├── __init__.py                      ← MODIFIED (session 1)
│   │   ├── handoff.py                       Handoff tools
│   │   ├── hunter_tools.py                  ← NEW (session 1)
│   │   ├── jit_engine.py                    ← NEW (session 1)
│   │   └── oob_server.py                    ← NEW (session 1)
│   ├── prompts/
│   │   ├── __init__.py
│   │   └── prompt_loader.py                 Agent prompt loader
│   └── utils/
│       ├── __init__.py
│       ├── memory.py                        InMemoryStore (swarm)
│       ├── llm/
│       │   ├── __init__.py
│       │   └── config_manager.py            re-exports llm/config_manager
│       ├── mcp/
│       │   ├── __init__.py
│       │   └── mcp_loader.py                MCP tool loader
│       └── swarm/
│           ├── __init__.py
│           └── swarm.py                     re-exports swarm utilities
│
├── tools/                                   Core tool layer
│   ├── __init__.py
│   ├── http_client.py                       AsyncHTTPClient + AuthConfig
│   ├── crawler.py                           WebCrawler + Playwright JS
│   ├── payload_manager.py                   YAML payloads + WAF detect
│   ├── adaptive_engine.py                   ← NEW (session 1 prev)
│   ├── mutation_engine.py                   ← NEW (session 1 prev)
│   ├── browser.py                           Playwright headless
│   └── scanner.py                           Async port scanner
│
├── llm/
│   ├── __init__.py
│   ├── engine.py                            OpenAI/Ollama/Anthropic
│   ├── payload_generator.py                 AIPayloadGenerator + AttackContext
│   ├── models.py                            LLM model definitions
│   ├── config_manager.py                    LLM config management
│   ├── selection.py                         Model selection logic
│   ├── openrouter.py                        OpenRouter integration
│   └── README.md
│
├── models/
│   ├── __init__.py
│   ├── target.py                            AttackSurface, Endpoint, Parameter
│   ├── vulnerability.py                     ← MODIFIED (session 2)
│   └── report.py                            Report, Finding
│
├── utils/
│   ├── __init__.py
│   ├── logger.py
│   └── validators.py
│
├── prompts/                                 System + agent prompts
│   ├── __init__.py
│   ├── core_agents.py
│   ├── system.py
│   └── pipeline-testing/
│       └── *.txt                            Prompt text files
│
└── packages/
    ├── __init__.py
    └── xlayer_hunter/
        ├── README.md
        ├── requirements.txt
        ├── tools/
        │   ├── kali_executor.py             Docker Kali (optional, not default)
        │   └── mcp/
        │       └── Initial_Access.py        Empty — not used
        └── utils/
            └── swarm/
                ├── swarm.py                 create_swarm, SwarmState
                └── handoff.py               create_handoff_tool
```

---

## SECTION 2 — Changed/New Files: Exact Details

---

### 2.1 `models/vulnerability.py` — MODIFIED

**के change भयो:**
`VulnType` enum मा 7 नया vulnerability types थपियो:

```python
# थपिएका:
SSTI = "ssti"
SUBDOMAIN_TAKEOVER = "subdomain_takeover"
RACE_CONDITION = "race_condition"
DESERIALIZATION = "deserialization"
GRAPHQL_INJECTION = "graphql_injection"
CORS_MISCONFIGURATION = "cors_misconfiguration"
HTTP_REQUEST_SMUGGLING = "http_request_smuggling"
```

**अघि थिए:** 16 types (sqli, xss_*, auth_bypass, idor, ssrf, lfi, rfi, path_traversal,
command_injection, xxe, csrf, open_redirect, info_disclosure)

**अहिले छन्:** 23 types

---

### 2.2 `config/settings.py` — MODIFIED

**के change भयो:**
`hunters` field को default list update भयो — 5 → 16 hunters:

```python
# अघि:
hunters: List[str] = Field(default=["sqli", "xss", "auth", "ssrf", "lfi"])

# अहिले:
hunters: List[str] = Field(default=[
    "sqli", "xss", "auth", "ssrf", "lfi",          # original 5
    "ssti", "rce", "xxe", "open_redirect", "cors",  # new batch 1
    "csrf", "subdomain_takeover", "graphql",         # new batch 2
    "race_condition", "deserialization", "http_smuggling",  # new batch 3
])
```

---

### 2.3 `core/vuln_hunters/__init__.py` — MODIFIED

**के change भयो:**
- 11 नया hunter classes import थपियो
- `HUNTER_REGISTRY` dict बनाइयो (name → class)
- `ALL_HUNTERS` list बनाइयो

```python
HUNTER_REGISTRY = {
    "sqli": SQLiHunter,
    "xss": XSSHunter,
    "auth": AuthHunter,
    "ssrf": SSRFHunter,
    "lfi": LFIHunter,
    "ssti": SSTIHunter,
    "rce": RCEHunter,
    "xxe": XXEHunter,
    "open_redirect": OpenRedirectHunter,
    "cors": CORSHunter,
    "csrf": CSRFHunter,
    "subdomain_takeover": SubdomainTakeoverHunter,
    "graphql": GraphQLHunter,
    "race_condition": RaceConditionHunter,
    "deserialization": DeserializationHunter,
    "http_smuggling": HTTPSmugglingHunter,
}
```

---

### 2.4 `src/agent/coordinator.py` — NEW

**के हो:**
Attack Matrix builder + parallel Solver dispatcher।
XLayer AI Coordinator→Solvers pattern।

**Key components:**

| Component | काम |
|-----------|-----|
| `CoordinatorState` | TypedDict state |
| `ENDPOINT_VULN_MATRIX` | Endpoint type → vuln types mapping |
| `AttackMatrixEntry` | एक task (endpoint + param + vuln_type + priority) |
| `build_attack_matrix()` | Hunter hypotheses + coverage scan → sorted matrix |
| `_classify_endpoint()` | URL path → endpoint category (login/search/upload/graphql...) |
| `Coordinator.run()` | Standalone: OOB + JIT + parallel solvers |
| `coordinator_node()` | Node: matrix → Send() dispatch |
| `solver_node()` | Node: runs one SolverAgent |
| `collect_node()` | Node: aggregate results, filter confidence ≥ 0.72 |
| `build_coordinator_graph()` | StateGraph builder |

**ENDPOINT_VULN_MATRIX (updated):**
```python
"search":   ["sqli", "xss_reflected", "ssti"]
"login":    ["auth_bypass", "sqli", "csrf"]
"upload":   ["lfi", "xss_stored", "xxe", "rce"]
"redirect": ["ssrf", "open_redirect"]
"file":     ["lfi", "path_traversal", "rce"]
"api":      ["sqli", "ssrf", "auth_bypass", "cors", "graphql"]
"template": ["ssti"]
"xml":      ["xxe"]
"checkout": ["race_condition", "csrf"]
"coupon":   ["race_condition"]
"graphql":  ["graphql"]
"default":  ["sqli", "xss_reflected", "lfi", "ssrf", "auth_bypass",
             "ssti", "cors", "open_redirect", "csrf"]
```

---

### 2.5 `src/agent/solver.py` — NEW

**के हो:**
Framework-less 80-iteration agentic exploitation loop।

**Key components:**

| Component | काम |
|-----------|-----|
| `SolverTask` | Input: task_id, target_url, parameter, method, vuln_type, hypothesis, oob_url/token |
| `SolverResult` | Output: found, confidence, working_payload, proof_response, injection_type, poc_script, oob_confirmed, iterations/payloads/techniques/duration |
| `SOLVER_SYSTEM_PROMPT` | Iteration budget guide, confidence bands, JSON decision format, pivot strategies |
| `SolverAgent.run()` | Core 80-iter loop: LLM → parse → tool_calls → OOB poll (every 5 iter) → stop |
| `_parse_decision()` | JSON block extract: confidence + next_action |
| `_execute_tool()` | Async tool call wrapper |

**Confidence thresholds:**
- `CONFIDENCE_REPORT_THRESHOLD = 0.72` → found!
- `CONFIDENCE_EXPAND_THRESHOLD = 0.35` → pivot approach

**Stop conditions:**
- `stop_found` + confidence ≥ 0.72 → ValidatedVuln
- `stop_not_found` → agent gave up
- `iteration >= 80` → budget exhausted

---

### 2.6 `src/tools/jit_engine.py` — NEW

**के हो:**
Agent-generated Python code को sandboxed subprocess मा execute गर्ने।

**Key components:**

| Component | काम |
|-----------|-----|
| `SAFE_PRELUDE` | Pre-imported: sys, os, re, json, base64, httpx, urllib.parse, time |
| `BLOCKED_PATTERNS` | Blocked: subprocess, os.remove, socket.bind, 127.0.0.1 etc. |
| `JITEngine.run(code, context)` | Security check → wrap script → tempfile → subprocess exec → stdout/stderr |
| `JITResult` | success, stdout, stderr, exit_code, timed_out, blocked, duration_ms |
| `JITResult.output` | LLM-friendly combined stdout+stderr |

**Context injection:**
```python
# Agent को code मा automatically inject हुन्छ:
target_url = "https://example.com/search"
parameter = "q"
```

**Timeout:** 20 seconds (configurable)
**Max output:** 64KB

---

### 2.7 `src/tools/oob_server.py` — NEW

**के हो:**
Blind vulnerability detection — DNS/HTTP callback via InteractSH।

**Key components:**

| Component | काम |
|-----------|-----|
| `InteractSHClient` | Public interactsh API (no binary needed): register → unique subdomain → poll |
| `LocalOOBServer` | asyncio TCP server fallback (when InteractSH unavailable) |
| `OOBServer` | Unified wrapper: tries InteractSH first, falls back to local |
| `OOBHit` | protocol, remote_address, raw_request, timestamp |
| `OOBServer.wait_for_hit(token, timeout=15)` | Poll until hit or timeout |
| `make_sqli_payloads(token)` | DB-specific blind SQLi payloads (LOAD_FILE, xp_cmdshell, UTL_HTTP) |
| `make_ssrf_payloads(token)` | SSRF callback URLs |
| `make_xss_payloads(token)` | Blind XSS with script src/fetch |

**Usage:**
```python
async with OOBServer() as oob:
    url = oob.http_url(token)      # http://abc123.oast.fun
    dns = oob.dns_domain(token)    # abc123.oast.fun
    hits = await oob.wait_for_hit(token, timeout=15)
```

---

### 2.8 `src/tools/hunter_tools.py` — NEW

**के हो:**
`@tool` wrappers — Solver agent ले hunters सीधै call गर्न।

**Tools:**

| Tool | Parameters | Returns |
|------|-----------|---------|
| `run_sqli_hunter` | target_url, parameter, method, db_hint | hunter result JSON |
| `run_xss_hunter` | target_url, parameter, method | hunter result JSON |
| `run_auth_hunter` | target_url, parameter, method | hunter result JSON |
| `run_ssrf_hunter` | target_url, parameter, method, oob_url | hunter result JSON |
| `run_lfi_hunter` | target_url, parameter, method | hunter result JSON |
| `http_probe` | url, method, params, body, headers, payload_in_param, payload | response JSON |

**Output format (same for all):**
```json
{
    "hunter": "sqli",
    "endpoints_tested": 1,
    "payloads_sent": 12,
    "hypotheses_count": 1,
    "high_confidence_count": 1,
    "hypotheses": [
        {
            "vuln_type": "sql_injection",
            "endpoint": "https://target.com/search",
            "parameter": "q",
            "confidence": "high",
            "confidence_score": 0.9,
            "injection_type": "error_based",
            "trigger_payload": "'",
            "suggested_payloads": [...]
        }
    ]
}
```

---

## SECTION 2.5 — Anya Files (अन्य फाइलहरू): Full Analysis

यो section मा बाँकी सबै important फाइलहरूको role र details छ।

---

### Core Pipeline (core/)

| File | Role | Key contents |
|------|------|--------------|
| **planner.py** | 4-phase pipeline को master orchestrator। main.py scan यहीबाट चल्छ। | `MissionState` (IDLE→RECON→VULN_HUNT→EXPLOIT→REPORT→COMPLETE), `MissionContext`, `PlannerAgent`. Phase 1: ReconAgent.execute() → AttackSurface. Phase 2: `run_hunters_parallel()` (HUNTER_MAP: sqli, xss, auth, ssrf, lfi — हाल 5 मात्र direct; नया 11 hunters __init__ बाट registry). Phase 3: ExploitAgent. Phase 4: Reporter. |
| **exploit.py** | Hunter hypotheses लाई real exploitation बाट validate गर्छ। NO EXPLOIT = NO REPORT। | `CVSS_SCORES`, `SEVERITY_MAP`, `REMEDIATION_GUIDANCE`. ExploitAgent: HTTP + HeadlessBrowser + PayloadManager. Per vuln type: replay request, check response/error/screenshot, build ValidatedVuln/FailedExploit. |
| **reporter.py** | JSON / HTML / PDF report generate गर्छ। | `Report`, `Finding`, `Evidence`, `ScanMetadata`, `ExecutiveSummary`. HTML_TEMPLATE (dark theme, severity colors). `generate_report(validated_vulns, attack_surface, metadata)` → output_dir मा json, html, (optional) pdf। |

---

### Models (models/)

| File | Role | Key contents |
|------|------|--------------|
| **target.py** | Target र attack surface को data structures। | `HTTPMethod`, `EndpointType`, `InputType`, `InputParameter`, `Endpoint` (url, method, parameters, has_inputs), `ServiceInfo`, `TechnologyStack`, `Target` (url, scope, is_in_scope), `AttackSurface` (endpoints, forms, api_endpoints, auth_endpoints, technology, open_ports, all_endpoints, testable_endpoints, attack_surface_score, to_summary()). |
| **report.py** | Report output structures। | `ReportFormat` (json/html/pdf/markdown), `RiskRating`, `Evidence`, `Finding` (finding_id, title, vulnerability, description, technical_details, evidence), `ExecutiveSummary`, `ScanMetadata`, `Report` (findings, metadata, executive_summary, vulnerability_stats). |

---

### Tools (tools/)

| File | Role | Key contents |
|------|------|--------------|
| **http_client.py** | Async HTTP client — recon, hunters, exploit सबैले use गर्छ। | `HTTPResponse`, `HTTPRequest`, `AuthConfig` (login form, bearer, cookies). `HTTPClient`: aiohttp, connection pool, rate_limit, follow_redirects, verify_ssl, cookie jar, HAR-style logging. `get()`, `post()`, `request()`. |
| **crawler.py** | Endpoint discovery — BFS crawl + form/API extraction। | `CrawlResult` (pages_crawled, endpoints, forms, api_endpoints). `WebCrawler`: max_depth, max_pages, respect_robots, js_rendering (Playwright). BeautifulSoup + optional Playwright for SPA; network interception for hidden APIs. |
| **payload_manager.py** | Payload database + context-aware selection। | `PayloadCategory`, `DatabaseType`, `XSSContext`, `Payload` (value, category, tags, bypass_waf). `PayloadManager`: _load_builtin_payloads (SQLi error/union/boolean/time, XSS, auth, SSRF, LFI…), get_payloads(category, context), WAF detection support। |
| **scanner.py** | Port scan — nmap बाहेक native socket। | `TOP_PORTS`, `TOP_100_PORTS`, `SERVICE_BANNERS`. `PortScanner`: timeout, concurrent, grab_banner. `scan_ports(host, top_n)` → `ScanResult` (open_ports, services). `resolve_hostname()`, `get_dns_records()` (A, AAAA, etc.). |
| **browser.py** | Playwright headless — XSS/auth exploit verification। | `BrowserResult`, `ExploitConfig`. `HeadlessBrowser`: navigate, inject payload, capture screenshot, console, network; detect alert/cookies/DOM change। ExploitAgent ले use गर्छ। |

---

### Config & Utils

| File | Role | Key contents |
|------|------|--------------|
| **config/settings.py** | Pydantic settings — env prefix `XLAYER_`, `.env`। | `LLMSettings` (provider, api_key, model, base_url, temperature, is_enabled, validate_config). `AuthSettings`, `ScanSettings`, `PortScanSettings`, `ExploitSettings`, `ReportSettings`. `Settings`: llm, scan, auth, port_scan, exploit, report, **hunters** (16 default). `get_settings()` cached। |
| **utils/logger.py** | Loguru setup। | `setup_logger(level, log_file, rotation, retention)`, `get_logger(name)`, scan_logger, exploit_logger, report_logger। |
| **utils/validators.py** | URL/scope validation। | `validate_url(url)` → (bool, error); scheme http/https, no private IP/localhost. `validate_scope(target_url, test_url)`, `sanitize_filename()`, `extract_domain()`, `is_same_origin()`। |

---

### LLM (llm/)

| File | Role | Key contents |
|------|------|--------------|
| **llm/config_manager.py** | In-memory LLM config (swarm agents को लागि)। | `LLMConfig` (model_name, provider, display_name, temperature). `MemoryConfigManager` singleton: config, llm_instance, update_config(), get_current_llm(). load_llm_model() from .models। |
| **llm/engine.py** | OpenAI / Ollama / Anthropic / OpenRouter — Planner & Solver को LLM। | Provider bind, get_llm() for Coordinator/Solver. |
| **llm/payload_generator.py** | AI-generated payloads + blind extraction। | `AttackContext`, `AttemptResult`, `FailureReason`, `AIPayloadGenerator`, `BinarySearchExtractor`. |

---

### Swarm (multi-agent)

| File | Role | Key contents |
|------|------|--------------|
| **src/agent/swarm/Planner.py** | Planner agent factory। | `make_planner_agent()`: get_current_llm(), get_store(), load_mcp_tools(planner), handoff_to_recon/initaccess/summary, manage/search memory. create_react_agent(llm, tools, store, name="Planner", prompt=load_prompt("planner","swarm")). |
| **src/agent/swarm/Recon.py** | Recon agent factory। | `make_recon_agent()`: MCP tools (reconnaissance), handoff_to_planner/initaccess/summary, memory tools. create_react_agent(name="Reconnaissance", prompt=load_prompt("reconnaissance","swarm")). |
| **src/agent/swarm/InitAccess.py** | Initial Access agent factory। | `make_initaccess_agent()`: MCP (initial_access), handoffs, memory. create_react_agent(name="Initial_Access"). |
| **src/agent/swarm/Summary.py** | Summary agent factory। | `make_summary_agent()`: MCP (summary), handoffs, memory. create_react_agent(name="Summary"). |
| **src/graph/swarm.py** | Swarm graph compiler। | `create_agents()` → recon, initaccess, planner, summary. `create_dynamic_swarm()`: create_swarm(agents, default_active_agent="Planner"). compile(checkpointer=InMemorySaver()). |
| **packages/xlayer_hunter/utils/swarm/swarm.py** | Swarm graph builder। | `SwarmState` (MessagesState + active_agent). `add_active_agent_router()`, `create_swarm(agents, default_active_agent)` — agents लाई node बनाएर handoff tools बाट route। |
| **packages/xlayer_hunter/utils/swarm/handoff.py** | Agent-to-agent handoff। | `create_handoff_tool(agent_name)` → tool that returns Command(goto=agent_name, update=messages+active_agent). `get_handoff_destinations()`, `get_handoff_tools_for()`. SWARM_AGENTS list. handoff_to_planner, handoff_to_reconnaissance, handoff_to_initial_access, handoff_to_summary. |
| **src/tools/handoff.py** | Re-export। | xlayer_ai.packages.xlayer_hunter.utils.swarm.handoff बाट सबै handoff tools export। |

---

### Utils & Prompts (src/)

| File | Role | Key contents |
|------|------|--------------|
| **src/utils/memory.py** | Shared store for swarm। | `InMemoryStore` singleton (dims=1536, embed=openai:text-embedding-3-small). `get_store()`, `reset_store()`. Store tools use गर्छ। |
| **src/utils/mcp/mcp_loader.py** | Re-export। | xlayer_ai.utils.mcp.mcp_loader.load_mcp_tools. |
| **utils/mcp/mcp_loader.py** | MCP tool loader। | `mcp_config.json` (env MCP_CONFIG वा project root). load_mcp_tools(agent_name=["planner"] etc.) → per-agent server config → MultiServerMCPClient → get_tools(). |
| **src/prompts/prompt_loader.py** | Swarm agent prompts। | BASE_PROMPTS (initial_access, planner, reconnaissance, summary), SWARM_PROMPTS. load_prompt(agent_name, mode="swarm") → base + swarm coordination prompt. prompts/base/* र prompts/swarm/* use। |

---

### Config Files (non-Python)

| File | Role |
|------|------|
| **mcp_config.json** | MCP servers per agent (planner, reconnaissance, initial_access, summary). हाल empty/not used भए पनि loader यही file खोज्छ। |
| **llm/local_config.json** | Local LLM config (optional). |
| **llm/cloud_config.json** | Cloud LLM config (optional). |

---

### Connection Summary (अन्य फाइलहरू कसरी जोडिन्छ)

- **main.py** → `PlannerAgent` (core/planner) → ReconAgent, run_hunters_parallel, ExploitAgent, Reporter.
- **ReconAgent** → HTTPClient, PortScanner, get_dns_records, WebCrawler → AttackSurface (models/target).
- **PlannerAgent** हाल 5 hunters मात्र direct import गर्छ (sqli,xss,auth,ssrf,lfi); बाँकी 11 hunters `core/vuln_hunters/__init__.py` को HUNTER_REGISTRY बाट name ले instantiate गर्न सक्छ (अहिले planner को HUNTER_MAP मा थप्नु पर्छ).
- **ExploitAgent** → HTTPClient, HeadlessBrowser, PayloadManager; ValidatedVuln → Reporter.
- **Swarm flow** (alternative): src/graph/swarm.py → create_agents() → create_swarm() with handoff; प्रत्येक agent को MCP tools mcp_config.json बाट।
- **Agentic path**: Coordinator (attack matrix) → SolverAgent (hunter_tools + jit_engine + oob_server) → validated_vulns; main.py मा हाल Coordinator path optional/alternate बनाउन बाँकी छ।

---

## SECTION 3 — New Hunters: Detection Details

### 3.1 `core/vuln_hunters/ssti.py` — NEW

**Detection:** Math expression evaluation across 8 template engines

**Probe payloads:**
```
{{7*7}}       → 49    (Jinja2, Twig)
${7*7}        → 49    (Freemarker, Velocity, EL)
#{7*7}        → 49    (Spring SpEL, Ruby ERB)
<%= 7*7 %>   → 49    (ERB, EJS)
*{7*7}        → 49    (Spring SpEL)
{7*7}         → 49    (Smarty)
```

**Engine differentiator:**
```
{{7*'7'}} → 7777777  = Jinja2
{{7*'7'}} → 49       = Twig
```

**RCE payloads per engine:** Jinja2, Twig, Freemarker, Velocity, Spring SpEL, ERB, Smarty, Mako

---

### 3.2 `core/vuln_hunters/rce.py` — NEW

**Detection:** 3 methods in priority order:

1. **Time-based (most reliable):** `; sleep 5` → measure delay → double-confirm with `sleep 2`
2. **Output-based:** `; id` → uid=0(root) pattern match
3. **Echo reflection:** `; echo xlayer_rce_test` → marker in response

**Payload categories:** Unix semicolon/pipe/backtick/subshell/newline, Windows timeout/ping, IFS bypass, quote bypass, URL encoding

**Suspicious params:** cmd, exec, command, ping, host, ip, convert, resize, format

---

### 3.3 `core/vuln_hunters/xxe.py` — NEW

**Detection:** XML body injection + parameter probe

**Payloads:**
- File read: `file:///etc/passwd`, `file:///c:/windows/win.ini`
- PHP wrapper: `php://filter/convert.base64-encode/resource=/etc/passwd`
- SSRF: `http://169.254.169.254/latest/meta-data/`
- Blind OOB: external DTD via InteractSH

**Success patterns:** `root:x:0:0`, `[boot loader]`, `ami-id`

**Detection targets:** XML Content-Type endpoints, file upload (SVG/DOCX/XLSX), SOAP

---

### 3.4 `core/vuln_hunters/open_redirect.py` — NEW

**Detection:** Location header contains probe domain

**18 bypass payloads:** direct, protocol-relative `//evil.com`, `@evil.com`, tab/newline encoded, backslash, Unicode fraction slash, double encoding, whitespace prefix, `////evil.com`

**Detects:** Location header redirect, meta-refresh, JavaScript `window.location`

**Params tested:** url, redirect, return, next, goto, destination, callback, oauth_callback, etc. (25 names)

---

### 3.5 `core/vuln_hunters/cors.py` — NEW

**Detection:** Origin header manipulation + ACAO response check

**Test origins:** `https://evil.com`, `null`, `https://evil.{target}`, subdomain confusion

**Vulnerability types:**
- Origin reflection (ACAO = our evil origin) → HIGH if `ACAC: true`
- Null origin + credentials → HIGH
- Subdomain trust → MEDIUM
- Wildcard + credentials → MEDIUM

**Only tests interesting endpoints** (API, /user, /account, /admin, /auth paths)

---

### 3.6 `core/vuln_hunters/csrf.py` — NEW

**Detection:** State-changing endpoints (POST/PUT/PATCH/DELETE)

**Tests:**
1. CSRF token absent in form → HIGH (if SameSite also missing)
2. Token bypass: empty token, wrong token, partial wrong token
3. SameSite cookie attribute check

**Token detection:** 10 common names (csrf_token, _csrf, authenticity_token, x-csrf-token...)

---

### 3.7 `core/vuln_hunters/subdomain_takeover.py` — NEW

**Detection:** DNS CNAME → HTTP fingerprint

**20+ service fingerprints:**
- GitHub Pages: `There isn't a GitHub Pages site here`
- AWS S3: `NoSuchBucket`
- Heroku: `No such app`
- Azure: `404 Web Site not found`
- Netlify: `Not found - Request ID`
- Fastly: `unknown domain`
- Shopify: `shop is currently unavailable`
- Pantheon, WordPress.com, Ghost, Tumblr, Unbounce, HubSpot, Surge.sh, Firebase, ReadTheDocs, Zendesk

**Parallel DNS resolution:** asyncio Semaphore(10) for speed

---

### 3.8 `core/vuln_hunters/graphql.py` — NEW

**Detection:** Auto-discovers GraphQL endpoints, then tests:

1. **Introspection:** `__schema` → type count exposure
2. **Batch queries:** array `[{query:...}, ...]` → rate limit bypass
3. **Depth limit:** 9-level nested query → DoS potential
4. **Argument injection:** SQL patterns in GraphQL arguments

**Auto-discovery paths:** `/graphql`, `/api/graphql`, `/v1/graphql`, `/graphiql`, `/gql`, etc.

---

### 3.9 `core/vuln_hunters/race_condition.py` — NEW

**Detection:** N=15 parallel requests → anomaly analysis

**Anomaly 1 (HIGH):** Multiple 200 OK responses → double-spend possible
**Anomaly 2 (MEDIUM):** Response length varies significantly → non-atomic state

**Targets:** redeem, coupon, transfer, withdraw, verify, otp, checkout paths (POST/PUT/PATCH only)

---

### 3.10 `core/vuln_hunters/deserialization.py` — NEW

**Detection:** 4 strategies:

1. **Passive:** Parameter value starts with `rO0AB` (Java) or `O:\d+:` (PHP) or pickle magic bytes
2. **Error-based:** Send malformed serialized payload → check Java/PHP/Python error patterns
3. **Time-based:** Python pickle sleep payload → `elapsed_ms > 4500`
4. **Content-Type:** `application/x-java-serialized-object` POST body

**Languages:** Java (`\xac\xed\x00\x05`), PHP (`O:...`), Python pickle (`\x80\x02/\x80\x04`), .NET, Ruby

---

### 3.11 `core/vuln_hunters/http_smuggling.py` — NEW

**Detection:** Raw TCP socket timing probes

**Variants tested:**
1. **CL.TE:** Content-Length frontend, Transfer-Encoding backend → hang test (>8s)
2. **TE.CL:** Transfer-Encoding frontend, Content-Length backend → hang test
3. **TE.TE:** Obfuscated Transfer-Encoding (`xchunked`, `chunked\r\n`, whitespace chars)

**Raw socket:** asyncio `open_connection()` → custom HTTP bytes → measure response time vs baseline

---

## SECTION 4 — Data Flow (Full Agentic Path)

```
main.py
  ↓ scan(target_url)
core/planner.py
  ↓ execute()
  │
  ├─[Phase 1] core/recon.py
  │             ↓
  │           AttackSurface {
  │             base_url, endpoints[], forms[], api_endpoints[],
  │             auth_endpoints[], technology{server,language,framework,db,waf},
  │             open_ports[], subdomains[], robots_txt, sitemap_urls
  │           }
  │
  ├─[Phase 2] 16 hunters in parallel (asyncio.gather)
  │             ↓ each returns HunterResult
  │           hunter_hypotheses[] = [
  │             {endpoint, parameter, vuln_type, confidence, indicators,
  │              suggested_payloads, context{injection_type, trigger_payload...}}
  │           ]
  │
  ├─[Phase 3] src/agent/coordinator.py
  │             ↓ build_attack_matrix(surface, hypotheses)
  │           attack_matrix[] = [
  │             priority=1: HIGH confidence hunter hits
  │             priority=2: MEDIUM confidence hunter hits
  │             priority=3: LOW confidence hunter hits
  │             priority=4: Unhinted but interesting endpoints
  │             priority=5: Generic coverage
  │           ]
  │             ↓ async gather with semaphore(5)
  │           solver_results[] = await [SolverAgent.run(task) for task in matrix]
  │
  │           Each SolverAgent:
  │             src/agent/solver.py
  │               loop (max 80 iter):
  │                 LLM(messages) → tool_call / jit_code / stop
  │                 ├─ hunter_tools.py → run specific hunter
  │                 ├─ http_probe → custom request
  │                 ├─ jit_engine.py → subprocess Python
  │                 └─ oob_server.py → check blind callbacks (every 5 iter)
  │               confidence ≥ 0.72 → found=True
  │
  ├─[Filter] confidence ≥ 0.72 → validated_vulns[]
  │
  └─[Phase 4] core/reporter.py
                ↓
              reports/ {
                report.json
                report.html
                report.pdf (optional)
              }
```

---

## SECTION 5 — Key Constants & Tuning

| Constant | Location | Default | Purpose |
|----------|----------|---------|---------|
| `MAX_ITERATIONS` | solver.py | 80 | Max iterations per solver task |
| `CONFIDENCE_REPORT_THRESHOLD` | solver.py | 0.72 | Min confidence to report |
| `CONFIDENCE_EXPAND_THRESHOLD` | solver.py | 0.35 | Below this → pivot |
| `MAX_PARALLEL_SOLVERS` | coordinator.py | 5 | Concurrent solver limit |
| `RACE_WINDOW_COUNT` | race_condition.py | 15 | Parallel requests per race test |
| `HUNTER_CONFIDENCE_THRESHOLD` | coordinator.py | 0.3 | Min hunter confidence for solver task |
| `JITEngine.timeout` | jit_engine.py | 20s | JIT script max execution time |
| `OOBServer.wait_for_hit timeout` | oob_server.py | 15s | OOB callback wait time |

---

## SECTION 6 — WAF Support

Automatic WAF detection + bypass mutations:

| WAF | Detection Method |
|-----|----------------|
| Cloudflare | `__cf_bm` cookie, `cf-ray` header, response body |
| AWS WAF | `awsalb` cookie, `x-amzn-requestid` header |
| Akamai | `akamai-*` headers, response patterns |
| Imperva | `visid_incap` cookie, `incap_ses` |
| ModSecurity | `mod_security`, `NOYB` patterns |
| Sucuri | `sucuri` in response headers |
| F5 BIG-IP | `TS01` cookie, `bigipserver` header |

---

## SECTION 7 — Mutation Engine Summary

`tools/mutation_engine.py` — 100+ mutations per vuln type:

| Vuln Type | Mutation Count | Key Techniques |
|-----------|---------------|----------------|
| SQLi | 14 | URL encode, Unicode, case variation, comment inject, whitespace |
| XSS | 15 | Tag case, attribute encoding, event handler variations, SVG |
| LFI | 14 | Double encode, null byte, semicolon, Windows paths, PHP wrappers |
| SSRF | 12 | IPv6, decimal IP, hex IP, redirect chain, DNS rebind |
| Auth | 12 | JWT none alg, header injection, case variation, null byte |

---

## SECTION 8 — LLM Integration

`llm/engine.py` + `llm/payload_generator.py`:

```
AttackContext {
    url, parameter, method, vuln_type,
    server, language, framework, database,
    waf (detected WAF),
    baseline_length,
    failure_history []
}
    ↓
AIPayloadGenerator.generate(context)
    ↓
BinarySearchExtractor (for blind SQLi data extraction)
```

**Providers:** OpenAI, Ollama (local), Anthropic, OpenRouter

---

## SECTION 9 — Session Change Summary

### Session 1 (Agentic Foundation)
| File | Change |
|------|--------|
| src/tools/jit_engine.py | NEW — sandboxed Python executor |
| src/tools/oob_server.py | NEW — InteractSH + local HTTP OOB |
| src/tools/hunter_tools.py | NEW — @tool wrappers |
| src/agent/solver.py | NEW — 80-iter framework-less loop |
| src/agent/coordinator.py | NEW — attack matrix + Send API |
| src/tools/__init__.py | MODIFIED — exports Coordinator/Solver tools |
| src/agent/__init__.py | MODIFIED — exports Coordinator/Solver agents |

### Session 2 (11 New Hunters)
| File | Change |
|------|--------|
| models/vulnerability.py | MODIFIED — 7 new VulnType enums |
| config/settings.py | MODIFIED — 16 hunters in default list |
| core/vuln_hunters/__init__.py | MODIFIED — HUNTER_REGISTRY, ALL_HUNTERS |
| core/vuln_hunters/ssti.py | NEW — SSTI (8 engines) |
| core/vuln_hunters/rce.py | NEW — Command Injection |
| core/vuln_hunters/xxe.py | NEW — XML External Entity |
| core/vuln_hunters/open_redirect.py | NEW — Open Redirect (18 bypasses) |
| core/vuln_hunters/cors.py | NEW — CORS Misconfiguration |
| core/vuln_hunters/csrf.py | NEW — CSRF |
| core/vuln_hunters/subdomain_takeover.py | NEW — 20+ service fingerprints |
| core/vuln_hunters/graphql.py | NEW — GraphQL Issues |
| core/vuln_hunters/race_condition.py | NEW — Race Condition |
| core/vuln_hunters/deserialization.py | NEW — Insecure Deserialization |
| core/vuln_hunters/http_smuggling.py | NEW — HTTP Request Smuggling |
| src/agent/coordinator.py | MODIFIED — expanded ENDPOINT_VULN_MATRIX + _classify_endpoint |
| README.md | UPDATED — full rewrite |
| FILE_ANALYSIS_DETAILS.md | UPDATED — this file |

---

## SECTION 10 — TODO / Next Steps

```
□ main.py → Coordinator pipeline connect गर्ने
  (हाल PlannerAgent use गर्छ — Coordinator/Solver path थप्ने)

□ core/recon.py → TECH_SIGNATURES update
  (ssti for template frameworks, xxe for XML/SOAP, graphql for GraphQL)

□ core/exploit.py → ValidatedVuln format standardize
  (Coordinator output र ExploitAgent output match गर्नु पर्छ)

□ src/tools/hunter_tools.py → नया 11 hunters को @tool wrappers थप्ने
  (हाल only 5 original hunters छन् — ssti, rce, xxe etc. थप्ने)

□ SqliteSaver replace InMemorySaver
  (checkpoint/resume for long scans)

□ Business Logic hunter (advanced)
  (LLM-driven, app-specific — hardest to automate)

□ SSTI fingerprint async fix
  (ssti.py _fingerprint_engine() हाल sync — async send थप्ने)
```

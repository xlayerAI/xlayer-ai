# XLayer AI — CHANGELOG
# के कहिले थपियो, के बदलियो — complete history

---

## Session 3 — Custom Engine
Date: 2026-02-24

### New Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `engine/__init__.py` | ~50 | Clean exports for entire engine/ package |
| `engine/messages.py` | ~110 | SystemMessage, HumanMessage, AIMessage, ToolMessage + API converters |
| `engine/tool.py` | ~160 | @tool decorator + Tool dataclass + ToolRegistry |
| `engine/llm.py` | ~210 | LLMClient — direct Anthropic + OpenAI + Ollama API calls |
| `engine/agent.py` | ~130 | AgentLoop — simple ReAct loop (replaces create_react_agent) |
| `engine/pipeline.py` | ~160 | Pipeline + ParallelDispatch (replaces external graph + Send) |
| `engine/memory.py` | ~220 | CheckpointStore (SQLite) + KVStore + ObservationJournal |
| `engine/agentic_loop.py` | ~310 | XLayerLoop — full XLayer reasoning with confidence + auto-pivot |

### Modified Files

**`src/agent/solver.py`**
- Removed: `from langchain_core.messages import ...`, `from langchain_core.tools import BaseTool`
- Added: `from engine.agentic_loop import SolverState, XLayerLoop`
- Added: `from engine.llm import LLMClient`
- SolverAgent now wraps XLayerLoop internally
- Public interface (SolverTask, SolverResult) unchanged

**`src/agent/coordinator.py`**
- Removed: `from langchain_core.tools import tool`, `from langgraph.graph import StateGraph`, `from langgraph.types import Send`
- Removed: `build_coordinator_graph()`, `coordinator_node()`, `solver_node()`, `collect_node()` (graph nodes)
- Added: `from engine.pipeline import ParallelDispatch`
- Added: `from engine.tool import tool, Tool`
- Added: `make_jit_tool()` using custom @tool
- `Coordinator.run()` now uses `ParallelDispatch.run()` instead of asyncio.Semaphore manually

**`src/tools/hunter_tools.py`**
- Removed: `from langchain_core.tools import tool` + all `Annotated[...]` types
- Added: `from engine.tool import tool, Tool`
- Added: 8 new @tool wrappers (ssti, rce, xxe, open_redirect, cors, csrf, graphql, race_condition)
- `ALL_HUNTER_TOOLS` now has 14 tools (was 6)
- `VULN_TOOL_MAP` expanded with all new vuln types

**`src/agent/__init__.py`**
- Removed: `build_coordinator_graph` (graph-specific)
- Updated comment: "custom engine only"

**`src/tools/__init__.py`**
- Comment updated

### What This Enables

| Before | After (Custom Engine) |
|---|---|
| `bind_tools(tools)` → fixed format | `LLMClient.call(messages, tools)` → direct API |
| StateGraph nodes | `Pipeline.add_stage(...)` simple stages |
| Send API | `ParallelDispatch.run(fn, tasks)` |
| langmem InMemoryStore | `KVStore` (SQLite-backed) |
| SqliteSaver | `CheckpointStore` (SQLite) |
| Basic iteration loop | `XLayerLoop` — observation journal + confidence + auto-pivot |

### Dependencies to Remove from requirements.txt
```
langchain
langchain-core
langchain-openai
langchain-anthropic
langgraph
langmem
langchain-mcp-adapters
```

---

## Session 2 — 11 New Hunters + VulnType Update
Date: 2026-02-24

### New Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `core/vuln_hunters/ssti.py` | ~160 | Server-Side Template Injection — 8 engines |
| `core/vuln_hunters/rce.py` | ~170 | Remote Code Execution — time/output/echo |
| `core/vuln_hunters/xxe.py` | ~200 | XML External Entity — file read, SSRF, OOB |
| `core/vuln_hunters/open_redirect.py` | ~160 | Open Redirect — 18 bypass techniques |
| `core/vuln_hunters/cors.py` | ~175 | CORS Misconfiguration — origin reflection |
| `core/vuln_hunters/csrf.py` | ~185 | CSRF — token absent + bypass tests |
| `core/vuln_hunters/subdomain_takeover.py` | ~190 | Takeover — 20+ cloud fingerprints |
| `core/vuln_hunters/graphql.py` | ~210 | GraphQL — introspection/batch/depth/injection |
| `core/vuln_hunters/race_condition.py` | ~155 | Race Condition — parallel request analysis |
| `core/vuln_hunters/deserialization.py` | ~240 | Deserialization — Java/PHP/Python |
| `core/vuln_hunters/http_smuggling.py` | ~215 | HTTP Smuggling — CL.TE/TE.CL/TE.TE |

### Modified Files

**`models/vulnerability.py`**
- Added 7 new VulnType enum values:
  `SSTI`, `SUBDOMAIN_TAKEOVER`, `RACE_CONDITION`, `DESERIALIZATION`,
  `GRAPHQL_INJECTION`, `CORS_MISCONFIGURATION`, `HTTP_REQUEST_SMUGGLING`

**`config/settings.py`**
- Updated `hunters` default from 5 to 16 hunters

**`core/vuln_hunters/__init__.py`**
- Added all 11 new hunter imports
- Added `HUNTER_REGISTRY = {name: class}` dict
- Added `ALL_HUNTERS` list

**`src/agent/coordinator.py`**
- Expanded `ENDPOINT_VULN_MATRIX` with new endpoint types:
  `template`, `xml`, `checkout`, `coupon`, `graphql`
- Updated existing categories with new vuln types
- Expanded `_classify_endpoint()` with 5 new categories

**`README.md`** — Full rewrite
**`FILE_ANALYSIS_DETAILS.md`** — Full rewrite with all details
**`CHANGELOG.md`** — This file (new)

---

## Session 1 — Agentic Foundation (JIT + Solver + Coordinator + OOB)
Date: 2026-02-24

### New Files Created

| File | Lines | Purpose |
|------|-------|---------|
| `src/tools/jit_engine.py` | ~175 | Sandboxed Python JIT executor |
| `src/tools/oob_server.py` | ~310 | InteractSH + local HTTP OOB server |
| `src/tools/hunter_tools.py` | ~220 | @tool wrappers for 5 hunters |
| `src/agent/solver.py` | ~340 | 80-iter framework-less exploit loop |
| `src/agent/coordinator.py` | ~400 | Attack matrix + parallel Send API |

### Modified Files

**`src/tools/__init__.py`**
- Added exports: `ALL_HUNTER_TOOLS`, `VULN_TOOL_MAP`, `JITEngine`, `JITResult`, `OOBServer`, `OOBHit`

**`src/agent/__init__.py`**
- Added exports: `SolverAgent`, `SolverTask`, `SolverResult`, `Coordinator`, `build_coordinator_graph`, `build_attack_matrix`

---

## Session 0 — Original Build (Previous Sessions)

### Files built before this changelog

**Core pipeline:**
- `core/planner.py` — 4-phase master orchestrator
- `core/recon.py` — DNS + ports + tech + crawl (1000+ tech signatures)
- `core/exploit.py` — Basic exploit validation
- `core/reporter.py` — JSON/HTML/PDF reports

**Original 5 hunters:**
- `core/vuln_hunters/base.py` — BaseHunter + adaptive_test + build_context
- `core/vuln_hunters/sqli.py` — SQLi (4 methods, 6 DB types)
- `core/vuln_hunters/xss.py` — XSS (reflected, stored, DOM)
- `core/vuln_hunters/auth.py` — Auth bypass, IDOR, session
- `core/vuln_hunters/ssrf.py` — SSRF (cloud metadata, 6 providers)
- `core/vuln_hunters/lfi.py` — LFI + path traversal

**Tools layer:**
- `tools/http_client.py` — AsyncHTTPClient + AuthConfig (form/bearer/apikey/cookie)
- `tools/crawler.py` — WebCrawler + JS rendering (Playwright)
- `tools/payload_manager.py` — YAML payload DB + WAF detection (7 WAFs)
- `tools/adaptive_engine.py` — ProbeEngine + AdaptiveEngine (4-phase feedback)
- `tools/mutation_engine.py` — MutationEngine (100+ mutations, priority-sorted)
- `tools/browser.py` — Playwright headless browser
- `tools/scanner.py` — Async port scanner

**LLM layer:**
- `llm/engine.py` — OpenAI/Ollama/Anthropic interface
- `llm/payload_generator.py` — AIPayloadGenerator + AttackContext + BinarySearchExtractor
- `llm/models.py`, `config_manager.py`, `selection.py`, `openrouter.py`

**Swarm:**
- `src/graph/swarm.py` — Swarm graph (Planner, Recon, InitAccess, Summary)
- `src/agent/swarm/Planner.py`, `Recon.py`, `InitAccess.py`, `Summary.py`

**Models:**
- `models/target.py` — AttackSurface, Endpoint, Parameter, Technology
- `models/vulnerability.py` — VulnType, VulnHypothesis, ValidatedVuln, etc.
- `models/report.py` — Report, Finding

---

## Vulnerability Coverage Tracker

| Hunter | Status | Method | Severity |
|--------|--------|--------|---------|
| SQLi | ✅ Active | Error/Boolean/Time/Union | Critical |
| XSS | ✅ Active | Reflected/Stored/DOM | High |
| Auth Bypass | ✅ Active | Default creds/JWT/IDOR | High |
| SSRF | ✅ Active | Cloud meta/Internal | High |
| LFI | ✅ Active | Traversal/Wrappers/Log | High |
| SSTI | ✅ Active | Math eval / 8 engines | Critical |
| RCE | ✅ Active | Time/Output/Echo | Critical |
| XXE | ✅ Active | File/SSRF/Error/OOB | High |
| Open Redirect | ✅ Active | Location header / 18 bypass | Medium |
| CORS | ✅ Active | Origin reflection | High |
| CSRF | ✅ Active | Token absent/bypass | Medium |
| Subdomain Takeover | ✅ Active | DNS CNAME + fingerprint | High |
| GraphQL | ✅ Active | Introspection/batch/depth | Medium |
| Race Condition | ✅ Active | Parallel request anomaly | High |
| Deserialization | ✅ Active | Magic bytes/error/timing | Critical |
| HTTP Smuggling | ✅ Active | CL.TE/TE.CL/TE.TE timing | Critical |
| Business Logic | ❌ TODO | LLM-driven (complex) | Varies |
| SSTI Async Fingerprint | ⚠️ Partial | Sync fingerprint (fix needed) | — |
| Hunter tools (11 new) | ⚠️ TODO | @tool wrappers for new hunters | — |
| main.py → Coordinator | ⚠️ TODO | Connect CLI to Coordinator/Solver path | — |

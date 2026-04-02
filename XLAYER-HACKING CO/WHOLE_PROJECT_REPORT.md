# XLAYER-HACKING CO — पूरा प्रोजेक्ट रिपोर्ट (Whole Project Report)

**शुरु देखि अहिले सम्म — Philosophy, Mission, Vision, Architecture, Components, Recon→Vuln→Exploit→Report, Agentic Workflow, File-by-File Role — सबै विस्तारमा।**

---

## सूची (Table of Contents)

1. [दर्शन, मिशन, विजन](#1-दर्शन-मिशन-विजन)
2. [आर्किटेक्चर — सिस्टम कसरी काम गर्छ](#2-आर्किटेक्चर--सिस्टम-कसरी-काम-गर्छ)
3. [नया कम्पोनेन्टहरू र उनीहरूको भूमिका](#3-नया-कम्पोनेन्टहरू-र-उनीहरूको-भूमिका)
4. [Vulnerability Hunting — कसरी काम गर्छ](#4-vulnerability-hunting--कसरी-काम-गर्छ)
5. [Agentic Workflow — Coordinator, Solver, XLayerLoop](#5-agentic-workflow--coordinator-solver-xlayerloop)
6. [कुन फाइल को काम, एजेन्ट को भूमिका](#6-कुन-फाइल-को-काम-एजेन्ट-को-भूमिका)
7. [Recon → Vuln → Exploit → Report — प्रत्येक चरण विस्तारमा](#7-recon--vuln--exploit--report--प्रत्येक-चरण-विस्तारमा)
8. [सबै मिलेर कसरी काम गर्छन्](#8-सबै-मिलेर-कसरी-काम-गर्छन्)
9. [डाटा फ्लो र मोडल](#9-डाटा-फ्लो-र-मोडल)
10. [सारांश र सन्दर्भ](#10-सारांश-र-सन्दर्भ)

---

## 1. दर्शन, मिशन, विजन

### 1.1 कोर दर्शन (Core Philosophy)

```
NO EXPLOIT = NO REPORT
```

**अर्थ:** XLayer AI ले **अनुमान** मात्र रिपोर्ट गर्दैन। जुन vulnerability को **वास्तविक exploit** गरेर **proof** लिएको छ, त्यही मात्र रिपोर्टमा जान्छ।

- **False positive नै हटाउँछ** — guess मात्रले report मा आउँदैन।
- हरेक finding को:
  - काम गरेको exact payload
  - server response (proof)
  - reproduce गर्न curl command
  - (optional) screenshot / HAR evidence

**नारा:** *"Hack before hackers hack — Prove before you report"*

---

### 1.2 मिशन (Mission)

- **Target:** कुनै पनि web application / URL लिएर autonomous रूपमा vulnerability hunt गर्ने।
- **Goal:** Recon → Hunt → Exploit → Report को एकै pipeline मा सबै phase समन्वय गरेर **validated vulnerabilities** (proof सहित) निकाल्ने।
- **Scope:** 16 प्रकारका vulnerabilities (SQLi, XSS, Auth, SSRF, LFI, SSTI, RCE, XXE, Open Redirect, CORS, CSRF, Subdomain Takeover, GraphQL, Race Condition, Deserialization, HTTP Smuggling)।

---

### 1.3 विजन (Vision)

- **Framework-less agentic exploit:** Fixed script को सट्टा LLM ले step-by-step decide गर्छ — 80 iterations, JIT code, OOB callback, hunter tools।
- **Proof-first reporting:** Client/team लाई झूटा अलर्ट नदिई, exploit proof सहित professional report (JSON, HTML, PDF)।
- **Scalable hunt:** 16 hunters parallel; Coordinator ले attack matrix बनाएर parallel Solver agents चलाउँछ।

---

## 2. आर्किटेक्चर — सिस्टम कसरी काम गर्छ

### 2.1 High-Level Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     XLayer AI — Agentic Solver                           │
├─────────────────────────────────────────────────────────────────────────┤
│  User: python -m xlayer_ai scan https://target.com                      │
│                    │                                                     │
│                    ▼                                                     │
│  main.py (CLI) → PlannerAgent.start_mission()                            │
│                    │                                                     │
│  ┌─────────────────▼─────────────────────────────────────────────────┐  │
│  │  Phase 1: RECON (core/recon.py)                                   │  │
│  │  DNS, port scan, tech fingerprint, crawl (static+JS)              │  │
│  │  → AttackSurface (endpoints, forms, APIs, tech stack)              │  │
│  └─────────────────┬─────────────────────────────────────────────────┘  │
│                    │                                                     │
│  ┌─────────────────▼─────────────────────────────────────────────────┐  │
│  │  Phase 2: VULN HUNT (core/vuln_hunters/)                           │  │
│  │  16 hunters parallel: sqli, xss, auth, ssrf, lfi, ssti, rce, ...   │  │
│  │  → VulnHypothesis[] (confidence: HIGH/MEDIUM/LOW)                   │  │
│  └─────────────────┬─────────────────────────────────────────────────┘  │
│                    │                                                     │
│  ┌─────────────────▼─────────────────────────────────────────────────┐  │
│  │  Phase 3: EXPLOIT                                                  │  │
│  │  (a) Traditional: ExploitAgent — browser + HTTP proof                │  │
│  │  (b) Agentic:     Coordinator → Attack Matrix → Parallel Solvers    │  │
│  │                   (80 iter, JIT + OOB + hunter_tools)              │  │
│  │  → ValidatedVuln[] (proof सहित मात्र)                              │  │
│  └─────────────────┬─────────────────────────────────────────────────┘  │
│                    │                                                     │
│  ┌─────────────────▼─────────────────────────────────────────────────┐  │
│  │  Phase 4: REPORT (core/reporter.py)                               │  │
│  │  JSON / HTML / PDF — CVSS, PoC, remediation                        │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 चार Phase को संक्षिप्त भूमिका

| Phase   | फाइल/मोड्युल           | इनपुट              | आउटपुट           |
|--------|-------------------------|---------------------|-------------------|
| **Recon**  | `core/recon.py`         | Target URL          | `AttackSurface`   |
| **Hunt**   | `core/vuln_hunters/*`   | `AttackSurface`     | `VulnHypothesis[]`|
| **Exploit**| `core/exploit.py` + (optional) Coordinator/Solver | Hypotheses + Surface | `ValidatedVuln[]` |
| **Report** | `core/reporter.py`      | ValidatedVulns + metadata | report.json/html/pdf |

---

## 3. नया कम्पोनेन्टहरू र उनीहरूको भूमिका

### 3.1 Coordinator (`src/agent/coordinator.py`)

- **काम:** Attack matrix बनाउँछ र parallel Solver agents लाई task दिन्छ।
- **इनपुट:** AttackSurface (summary), Hunter hypotheses (list of dicts)。
- **प्रक्रिया:**
  1. `build_attack_matrix()` — hypotheses बाट (endpoint, parameter, vuln_type) tasks; coverage को लागि unhinted endpoints पनि matrix मा थप्छ।
  2. URL path बाट endpoint classify गर्छ: login, search, upload, api, graphql, file, redirect, checkout, coupon, default।
  3. `ENDPOINT_VULN_MATRIX` अनुसार प्रत्येक endpoint type को लागि relevant vuln types।
  4. Priority: Hunter HIGH=1, MEDIUM=2, LOW=3, coverage=4।
  5. `ParallelDispatch` बाट max 5 Solver एकै पटक चलाउँछ।
- **आउटपुट:** List[Dict] — प्रत्येक dict मा found, confidence, working_payload, proof_response, etc.। यसलाई `core/coordinator_result.py` ले `ValidatedVuln[]` मा convert गर्छ।

### 3.2 Solver Agent (`src/agent/solver.py`)

- **काम:** एक (endpoint, parameter, vuln_type) task लिएर 80-iteration agentic loop चलाउँछ।
- **इनपुट:** `SolverTask` — task_id, target_url, parameter, method, vuln_type, initial_hypothesis, oob_url/token।
- **प्रक्रिया:** `AgentLoop.for_solver()` (वा XLayerLoop) बाट iteration; हरेक iteration मा LLM decide गर्छ — tool call, JIT code, pivot, वा conclude।
- **आउटपुट:** `SolverResult` — found, confidence, working_payload, proof_response, iterations_used, techniques_tried। confidence ≥ 0.72 र found=True भए मात्र ValidatedVuln बन्छ।

### 3.3 XLayerLoop / Agentic Loop (`engine/agentic_loop.py`)

- **काम:** Reasoning loop — LLM ले हरेक iteration मा के गर्ने decide गर्छ।
- **Constants:**
  - `MAX_ITERATIONS = 80`
  - `FOUND_THRESHOLD = 0.72` → यो भन्दा माथि = vuln confirmed
  - `REFINE_THRESHOLD = 0.35` → यो भन्दा तल = pivot
  - `CONSECUTIVE_FAIL_PIVOT = 3` → 3 iteration सम्म confidence नबढे = auto-pivot
  - `COMPRESS_EVERY = 15` → token बचाउन history compress
  - `OOB_POLL_EVERY = 5` → OOB callback check
- **हरेक iteration:**
  1. Context + Observation Journal LLM लाई दिन्छ
  2. LLM JSON decision फर्काउँछ: action = tool_call | jit_code | pivot | conclude
  3. Action execute (tool / JIT / pivot)
  4. Confidence update, journal मा observation थप्छ
  5. Found / not_found / pivot / compress check

### 3.4 JIT Engine (`src/tools/jit_engine.py`)

- **काम:** Agent ले लेखेको Python code लाई sandboxed subprocess मा run गर्ने।
- **Safe prelude:** sys, os, re, json, base64, httpx, urllib.parse, time।
- **Blocked:** subprocess, socket.bind, 127.0.0.1, etc.।
- **Context inject:** target_url, parameter agent को code मा दिइन्छ।
- **Timeout:** 20s; max output 64KB।

### 3.5 OOB Server (`src/tools/oob_server.py`)

- **काम:** Blind vulnerability (SQLi, SSRF, XSS) को लागि DNS/HTTP callback — InteractSH (cloud) वा local TCP fallback।
- **InteractSHClient:** register → unique subdomain → poll for hits।
- **OOBHit:** protocol, remote_address, raw_request, timestamp।
- **Helpers:** `make_sqli_payloads(token)`, `make_ssrf_payloads(token)`, `make_xss_payloads(token)` — blind detection payloads।

### 3.6 Hunter Tools (`src/tools/hunter_tools.py`)

- **काम:** सबै 16 hunters लाई `@tool` wrapper — Solver/LLM ले सीधै `run_sqli_hunter`, `run_xss_hunter`, ... call गर्न सक्छ।
- **प्रत्येक tool:** target_url, parameter, method (र type-specific args) लिन्छ र HunterResult जस्तो dict JSON string फर्काउँछ।
- **Use:** Agentic loop भित्र LLM ले "run_sqli_hunter" call गरेर फेरि payload try गर्न सक्छ।

### 3.7 Coordinator Result (`core/coordinator_result.py`)

- **काम:** Coordinator को dict list लाई `List[ValidatedVuln]` मा convert; र धेरै list लाई merge/dedupe गर्ने।
- **Functions:**
  - `coordinator_results_to_validated_vulns(raw_list)` — found=True, confidence≥0.72 मात्र लिन्छ।
  - `coordinator_result_to_validated_vuln(raw)` — एक dict → एक ValidatedVuln।
  - `merge_validated_vulns(*lists, prefer="first"|"last")` — (endpoint, parameter, vuln_type) अनुसार dedupe।

### 3.8 11 नया Hunters (core/vuln_hunters/)

| Hunter | फाइल | के detect गर्छ |
|--------|------|-----------------|
| SSTI | ssti.py | Template injection ({{7*7}}→49, 8 engines) |
| RCE | rce.py | Command injection (sleep, echo, output) |
| XXE | xxe.py | XML External Entity (file read, SSRF, OOB) |
| Open Redirect | open_redirect.py | Unvalidated redirect (18 bypass) |
| CORS | cors.py | CORS misconfiguration (origin reflection, null, creds) |
| CSRF | csrf.py | CSRF (token absent/bypass) |
| Subdomain Takeover | subdomain_takeover.py | Dangling DNS (20+ cloud fingerprints) |
| GraphQL | graphql.py | Introspection, batch, depth, injection |
| Race Condition | race_condition.py | TOCTOU (N parallel requests) |
| Deserialization | deserialization.py | Magic bytes, error patterns, pickle timing |
| HTTP Smuggling | http_smuggling.py | CL.TE, TE.CL, TE.TE timing |

---

## 4. Vulnerability Hunting — कसरी काम गर्छ

### 4.1 BaseHunter Flow (`core/vuln_hunters/base.py`)

1. **हरेक hunter** ले `hunt(attack_surface)` implement गर्छ।
2. AttackSurface बाट relevant endpoints र parameters छान्छ (e.g. SQLi = सबै params, LFI = file/path params)।
3. **Static payloads** पहिले (YAML/DB बाट) — fast, no LLM cost।
4. Response analyze: error patterns, content change, timing।
5. **यदि केही नमिले:** AdaptiveEngine — ProbeEngine (fingerprint: WAF, filtered chars, time-based) + MutationEngine (100+ mutations) + AI round (AIPayloadGenerator with AttackContext)। Failure memory ले LLM लाई "यो try गरिसक्यौ, यो block भयो" दिन्छ।
6. **HunterResult** फर्काउँछ: hypotheses (VulnHypothesis[]), endpoints_tested, payloads_sent।

### 4.2 VulnHypothesis vs ValidatedVuln

- **VulnHypothesis:** Hunt phase को आउटपुट — "यहाँ vulnerability हुन सक्छ", confidence HIGH/MEDIUM/LOW। अझै proof छैन।
- **ValidatedVuln:** Exploit phase पछि — proof (response, payload, optional screenshot), CVSS, PoC। Report मा यही जान्छ।

### 4.3 Parallel Hunt

- `run_hunters_parallel(hunters, attack_surface)` — सबै hunters एकै पटक asyncio मा चल्छन्।
- Planner ले `_create_hunters()` बाट settings अनुसार hunter instances बनाउँछ र सबैको result एकै ठाउँमा hypotheses list मा जोड्छ।

---

## 5. Agentic Workflow — Coordinator, Solver, XLayerLoop

### 5.1 Agentic Path (optional — अहिले main pipeline मा default integrate छैन)

1. **Coordinator.run(attack_surface, hypotheses_as_dicts):**
   - Attack surface को summary (endpoints list) + hypotheses लिएर `build_attack_matrix()`।
   - OOB server start (InteractSH)।
   - Matrix को प्रत्येक task लाई SolverTask बनाएर `ParallelDispatch` मा पठाउँछ (max 5 parallel)।
   - Solver हरेक task को लागि SolverAgent.run(task) call गर्छ।

2. **SolverAgent.run(task):**
   - `AgentLoop.for_solver()` वा XLayerLoop with tools (hunter_tools + http_probe + JIT + OOB).
   - 80 iterations: LLM → decision → execute → journal → confidence check → pivot/conclude।
   - confidence ≥ 0.72 र proof भए → SolverResult(found=True, ...).

3. **Collect:**
   - Coordinator सबै SolverResult एकत्रित गर्छ।
   - found=True, confidence≥0.72 लाई `coordinator_results_to_validated_vulns()` ले ValidatedVuln मा convert गर्छ।

### 5.2 XLayerLoop एक iteration को विस्तार

```
1. state.full_context() → Target, Progress, Observation Journal (पछिल्ला 20 entries)
2. HumanMessage: context + "Remaining iterations: N. What is your next action?"
3. LLM.call(messages, tools, system_prompt) → AI response
4. _parse_decision(ai_response) → Decision(action, tool_name, tool_args, jit_code, new_confidence, conclusion)
5. _execute(decision):
   - TOOL_CALL → registry.run(tool_name, tool_args) → hunter वा http_probe
   - JIT_CODE → jit_engine.run(code) (sandbox)
   - PIVOT → state.strategy = new_strategy
   - CONCLUDE → state.found / state.not_found
6. Journal मा ObservationEntry थप्ने
7. confidence >= 0.72 → break (found)
8. journal.is_stuck(3, 0.35) → auto-pivot
9. i % 15 == 0 → _compress_history (token save)
10. i % 5 == 0 → _poll_oob (blind callback check)
```

---

## 6. कुन फाइल को काम, एजेन्ट को भूमिका

### 6.1 Entry र Orchestration

| फाइल | भूमिका |
|------|--------|
| **main.py** | CLI (Click): scan, config, version, hunters। URL validate, settings load, PlannerAgent.start_mission() call। |
| **core/planner.py** | PlannerAgent: 4 phase क्रममा चलाउँछ। MissionContext (target_url, attack_surface, hypotheses, validated_vulns, report)। _phase_recon, _phase_vuln_hunt, _phase_exploit, _phase_report। |

### 6.2 Phase 1 — Recon

| फाइल | भूमिका |
|------|--------|
| **core/recon.py** | ReconAgent: execute(target_url) → AttackSurface। DNS resolve, port scan (scanner), tech fingerprint (TECH_SIGNATURES), robots.txt, sitemap, WebCrawler (static + JS)। Endpoints, forms, api_endpoints, auth_endpoints। |
| **tools/crawler.py** | WebCrawler: BFS crawl, js_rendering (Playwright), XHR/fetch intercept → hidden API discovery। |
| **tools/scanner.py** | PortScanner: async port scan, DNS (get_dns_records)। |
| **tools/http_client.py** | AsyncHTTPClient: auth (AuthConfig), rate limit, SSL। |

### 6.3 Phase 2 — Vuln Hunt

| फाइल | भूमिका |
|------|--------|
| **core/vuln_hunters/base.py** | BaseHunter, HunterResult; test_endpoint, _send_payload, _analyze_response; AdaptiveEngine, AIPayloadGenerator integrate। |
| **core/vuln_hunters/__init__.py** | HUNTER_REGISTRY (name→class), ALL_HUNTERS। |
| **core/vuln_hunters/sqli.py … http_smuggling.py** | प्रत्येक vuln type को लागि hunt(), payloads, response analysis। |
| **tools/adaptive_engine.py** | ProbeEngine (fingerprint), AdaptiveEngine (4-phase: static → mutation → AI round 1 → AI round 2)। |
| **tools/mutation_engine.py** | 100+ mutations (SQLi, XSS, LFI, SSRF, Auth); priority-sorted। |
| **tools/payload_manager.py** | YAML payload DB, WAF detect, get_adaptive_payloads। |
| **llm/payload_generator.py** | AIPayloadGenerator, AttackContext, BinarySearchExtractor। |

### 6.4 Phase 3 — Exploit

| फाइल | भूमिका |
|------|--------|
| **core/exploit.py** | ExploitAgent: verify_all(hypotheses) → ValidatedVuln[]। HIGH/MEDIUM hypotheses लिन्छ, HeadlessBrowser + HTTP बाट proof, CVSS, remediation। |
| **src/agent/coordinator.py** | build_attack_matrix, _classify_endpoint; Coordinator.run() → parallel Solver; JIT/OOB tools। |
| **src/agent/solver.py** | SolverAgent: run(SolverTask) → SolverResult; AgentLoop.for_solver, 80 iter। |
| **engine/agentic_loop.py** | XLayerLoop: run(state) — decision parse, tool/JIT execute, journal, pivot, OOB poll। |
| **engine/agent.py** | AgentLoop (Solver को लागि wrapper)। |
| **core/coordinator_result.py** | coordinator_results_to_validated_vulns, merge_validated_vulns। |

### 6.5 Phase 4 — Report

| फाइल | भूमिका |
|------|--------|
| **core/reporter.py** | Reporter: generate(metadata, attack_surface, validated_vulns) → Report। JSON, HTML (template), PDF (optional)। CVSS, PoC, remediation। |

### 6.6 Tools (Agentic / Shared)

| फाइल | भूमिका |
|------|--------|
| **src/tools/hunter_tools.py** | run_sqli_hunter, run_xss_hunter, … (सबै 16) — @tool wrappers। |
| **src/tools/jit_engine.py** | JITEngine: run(code, context) — sandboxed Python। |
| **src/tools/oob_server.py** | OOBServer, InteractSHClient, make_sqli_payloads, make_ssrf_payloads, make_xss_payloads। |

### 6.7 Models

| फाइल | भूमिका |
|------|--------|
| **models/target.py** | Target, AttackSurface, Endpoint, Parameter, TechnologyStack। |
| **models/vulnerability.py** | VulnType, VulnHypothesis, ValidatedVuln, Confidence, Severity, ExploitEvidence, ProofOfConcept। |
| **models/report.py** | Report, Finding, Evidence, ScanMetadata। |

### 6.8 Config / LLM

| फाइल | भूमिका |
|------|--------|
| **config/settings.py** | Pydantic Settings: llm, scan, auth, port_scan, exploit, report, hunters (16 default)। |
| **engine/llm.py** | LLMClient (Coordinator/Solver को लागि — OpenAI/Anthropic direct)। |
| **llm/engine.py** | LLMEngine (Planner/pipeline को लागि — config, personas)। |

---

## 7. Recon → Vuln → Exploit → Report — प्रत्येक चरण विस्तारमा

### 7.1 RECON (Phase 1) — Step by Step

1. **Input:** `target_url` (e.g. https://example.com)。
2. **ReconAgent.execute():**
   - **DNS:** `_resolve_dns(hostname)` → A (र अरू) records; attack_surface.ip_addresses।
   - **Port scan:** (if enabled) PortScanner.scan_ports(ip, top_n) → open_ports, services (banner)。
   - **Initial GET:** target_url मा GET → headers + body।
   - **Tech stack:** _detect_technology() — TECH_SIGNATURES (server, language, framework, database, frontend, waf, cdn) headers/body मा match।
   - **robots.txt:** fetch, attack_surface.robots_txt।
   - **Sitemap:** sitemap.xml / sitemap_index.xml parse → seed URLs।
   - **Crawl:** WebCrawler.crawl(target_url, seed_urls) — max_depth, max_pages, js_rendering (Playwright), session_cookies (auth)। Static links + JS-rendered XHR/fetch → endpoints, forms, api_endpoints।
   - **Auth endpoints:** forms with AUTH type वा URL मा login/signin/auth — auth_endpoints list।
3. **Output:** AttackSurface — all_endpoints, testable_endpoints, technology, open_ports, attack_surface_score।

### 7.2 VULN HUNT (Phase 2) — Step by Step

1. **Input:** AttackSurface; settings.hunters (वा CLI --hunters)।
2. **Planner:** _create_hunters() — HUNTER_REGISTRY बाट instances (http_client, payload_manager, settings, llm_engine)。
3. **run_hunters_parallel(hunters, attack_surface):** सबै hunters लाई asyncio.gather जस्तै parallel चलाउँछ।
4. **प्रत्येक hunter.hunt(attack_surface):**
   - Relevant endpoints/params छान्छ।
   - Static payloads पठाउँछ → _analyze_response।
   - No hit भए: AdaptiveEngine (ProbeEngine + MutationEngine + AI rounds)।
   - VulnHypothesis बनाउँछ: endpoint, parameter, vuln_type, confidence (HIGH/MEDIUM/LOW), indicators, suggested_payloads।
5. **Output:** सबै HunterResult को hypotheses एकै list मा — context.hypotheses।

### 7.3 EXPLOIT (Phase 3) — Step by Step

**Current default (ExploitAgent only):**

1. **Input:** hypotheses (HIGH + MEDIUM मात्र)।
2. **ExploitAgent.verify_all(hypotheses):**
   - प्रत्येक hypothesis को लागि real exploit payload चलाउँछ (HTTP + optional HeadlessBrowser)。
   - Evidence: response snippet, extracted data, curl, screenshot।
   - CVSS, severity, remediation।
   - Success भए मात्र ValidatedVuln बनाउँछ।
3. **Output:** context.validated_vulns = List[ValidatedVuln]。

**Agentic path (अहिले optional — Planner को _phase_exploit मा integrate गर्न बाकी):**

1. Attack surface summary + hypotheses as dicts → Coordinator.run()।
2. build_attack_matrix() → List[AttackMatrixEntry] (sorted by priority)。
3. OOB server start; JIT tool, hunter_tools, http_probe ready।
4. ParallelDispatch: प्रत्येक entry → SolverTask → SolverAgent.run(task) → 80 iter XLayerLoop।
5. SolverResult (found, confidence, working_payload, proof) → coordinator_results_to_validated_vulns() → List[ValidatedVuln]।
6. Optional: ExploitAgent result सँग merge_validated_vulns(exploit_list, agentic_list, prefer="first")।

### 7.4 REPORT (Phase 4) — Step by Step

1. **Input:** context.to_metadata(), attack_surface, validated_vulns, hypotheses_count।
2. **Reporter.generate():**
   - ScanMetadata: scan_id, target_url, duration, hunters_used, endpoints_scanned, requests_made।
   - प्रत्येक ValidatedVuln → Finding (title, severity, description, evidence, poc, remediation)。
   - Report: overall_risk, stats (critical/high/medium/low), findings list।
3. **Output files:** settings.report.output_dir मा report.json, report.html; optional report.pdf।
4. **context.report** set हुन्छ; mission complete।

---

## 8. सबै मिलेर कसरी काम गर्छन्

- **User** एक पटक `python -m xlayer_ai scan https://target.com` चलाउँछ।
- **main.py** ले settings load गर्छ, PlannerAgent context manager मा चलाउँछ।
- **Planner** ले क्रममा:
  - ReconAgent बाट AttackSurface लिन्छ → hunters लाई दिन्छ;
  - 16 hunters parallel चलाएर VulnHypothesis[] बनाउँछ;
  - ExploitAgent (र optional Coordinator) ले hypothesis लाई proof सहित ValidatedVuln मा बदल्छ;
  - Reporter ले ValidatedVuln + metadata बाट report generate गर्छ।
- **Hunters** आ-आफ्नो vuln type को लागि PayloadManager, AdaptiveEngine, MutationEngine, (optional) LLM use गर्छन्।
- **ExploitAgent** HeadlessBrowser र HTTP बाट evidence लिन्छ; **Coordinator/Solver** भए JIT, OOB, hunter_tools बाट पनि proof लिन सक्छ।
- **Report** मा जाने केवल validated findings (NO EXPLOIT = NO REPORT)।

---

## 9. डाटा फ्लो र मोडल

```
Target URL
    → AttackSurface (endpoints, tech, params)
    → VulnHypothesis[] (per hunter)
    → (HIGH/MEDIUM) → ExploitAgent / Coordinator
    → ValidatedVuln[] (proof, CVSS, PoC)
    → Report (JSON/HTML/PDF)
```

**Key types:**  
AttackSurface, Endpoint, VulnHypothesis, ValidatedVuln, Report, Finding, ScanMetadata (models/target.py, vulnerability.py, report.py मा)।

---

## 10. सारांश र सन्दर्भ

### 10.1 सार

- **Philosophy:** NO EXPLOIT = NO REPORT; proof-based reporting।
- **Architecture:** 4-phase pipeline (Recon → Hunt → Exploit → Report); 16 hunters parallel; optional agentic path (Coordinator + Solver + XLayerLoop)।
- **Recon:** DNS, ports, tech, crawl (static+JS) → AttackSurface।
- **Vuln Hunt:** Static → Mutation → Adaptive (Probe + AI) → VulnHypothesis[]।
- **Exploit:** ExploitAgent (browser+HTTP); optional Coordinator → Attack Matrix → Parallel Solvers (80 iter, JIT, OOB, hunter_tools) → ValidatedVuln।
- **Report:** JSON/HTML/PDF, CVSS, PoC, remediation।
- **नया components:** Coordinator, Solver, XLayerLoop, JITEngine, OOBServer, hunter_tools, coordinator_result, 11 new hunters।

### 10.2 अरू दस्तावेज

| दस्तावेज | विषय |
|----------|------|
| **README.md** (xlayer_ai) | Package overview, usage, config |
| **PROJECT_WHOLE_OVERVIEW.md** | Structure, flow, components short |
| **XLAYER_REPORT.md** | Architecture, AI/mutation deep dive, file map |
| **FILE_ANALYSIS_DETAILS.md** | File-by-file role, changes |
| **COORDINATOR_INTEGRATION_WHAT_HAPPENS.md** | Coordinator + pipeline integrate कसरी गर्ने |
| **ANALYSIS_STRENGTH_WEAKNESS_IMPROVEMENT.md** | Strength, weakness, improvement priority |

---

*यो रिपोर्ट XLAYER-HACKING CO प्रोजेक्ट को सम्पूर्ण picture — philosophy देखि recon–vuln–exploit–report सम्म — विस्तारमा समेट्छ।*

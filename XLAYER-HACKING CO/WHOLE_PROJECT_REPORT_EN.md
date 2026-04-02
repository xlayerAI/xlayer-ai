# XLAYER-HACKING CO — Whole Project Report (English)

**From start to present: Philosophy, Mission, Vision, Architecture, All Components, Recon→Vuln→Exploit→Report, Agentic Workflow, File-by-File Roles, and Full Mutation Engine Details.**

---

## Table of Contents

1. [Philosophy, Mission, Vision](#1-philosophy-mission-vision)
2. [Architecture — How the System Works](#2-architecture--how-the-system-works)
3. [All Components and Their Roles](#3-all-components-and-their-roles)
4. [All 16 Vulnerability Hunters](#4-all-16-vulnerability-hunters)
5. [Mutation Engine — Complete Detail](#5-mutation-engine--complete-detail)
6. [Adaptive Engine and AI Payload Generator](#6-adaptive-engine-and-ai-payload-generator)
7. [Vulnerability Hunting — How It Works](#7-vulnerability-hunting--how-it-works)
8. [Agentic Workflow — Coordinator, Solver, XLayerLoop](#8-agentic-workflow--coordinator-solver-xlayerloop)
9. [File Map — Which File Does What](#9-file-map--which-file-does-what)
10. [Recon → Vuln → Exploit → Report — Each Phase in Detail](#10-recon--vuln--exploit--report--each-phase-in-detail)
11. [Data Flow and Models](#11-data-flow-and-models)
12. [WAF Support and Tech Fingerprinting](#12-waf-support-and-tech-fingerprinting)
13. [CLI, Config, and Report Output](#13-cli-config-and-report-output)
14. [AI + Mutation Decision Flow (Deep Dive)](#14-ai--mutation-decision-flow-deep-dive)
15. [How Everything Works Together (End-to-End)](#15-how-everything-works-together-end-to-end)
16. [Summary and References](#16-summary-and-references)
17. [Quick Reference](#17-quick-reference)
18. [Glossary and Terms](#18-glossary-and-terms)
19. [Legal and Intended Use](#19-legal-and-intended-use)
20. [Planned / Known Limitations](#20-planned--known-limitations)

---

## 1. Philosophy, Mission, Vision

### 1.1 Core Philosophy

```
NO EXPLOIT = NO REPORT
```

XLayer AI does **not** report what it only **guesses** is vulnerable. It reports only what it **proves** by running a real exploit and capturing evidence.

- **Eliminates false positives** — guesses never appear in the report.
- Every finding includes:
  - The exact payload that worked
  - Server response (proof)
  - Curl command to reproduce
  - (Optional) screenshot / HAR evidence

**Tagline:** *"Hack before hackers hack — Prove before you report"*

---

### 1.2 Mission

- **Target:** Run autonomous vulnerability hunting on any web application or URL.
- **Goal:** Orchestrate Recon → Hunt → Exploit → Report in one pipeline to produce **validated vulnerabilities** (with proof).
- **Scope:** 16 vulnerability types: SQLi, XSS, Auth, SSRF, LFI, SSTI, RCE, XXE, Open Redirect, CORS, CSRF, Subdomain Takeover, GraphQL, Race Condition, Deserialization, HTTP Smuggling.

---

### 1.3 Vision

- **Framework-less agentic exploit:** The LLM decides each step (up to 80 iterations), including JIT code, OOB callbacks, and hunter tools — no fixed script.
- **Proof-first reporting:** Deliver professional reports (JSON, HTML, PDF) with exploit proof, not noisy alerts.
- **Scalable hunt:** 16 hunters run in parallel; the Coordinator builds an attack matrix and runs parallel Solver agents.

---

## 2. Architecture — How the System Works

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
│  │  Phase 1: RECON (core/recon.py)                                     │  │
│  │  DNS, port scan, tech fingerprint, crawl (static+JS)                │  │
│  │  → AttackSurface (endpoints, forms, APIs, tech stack)               │  │
│  └─────────────────┬─────────────────────────────────────────────────┘  │
│                    │                                                     │
│  ┌─────────────────▼─────────────────────────────────────────────────┐  │
│  │  Phase 2: VULN HUNT (core/vuln_hunters/)                            │  │
│  │  16 hunters parallel: sqli, xss, auth, ssrf, lfi, ssti, rce, ...    │  │
│  │  → VulnHypothesis[] (confidence: HIGH/MEDIUM/LOW)                    │  │
│  └─────────────────┬─────────────────────────────────────────────────┘  │
│                    │                                                     │
│  ┌─────────────────▼─────────────────────────────────────────────────┐  │
│  │  Phase 3: EXPLOIT                                                  │  │
│  │  (a) Traditional: ExploitAgent — browser + HTTP proof              │  │
│  │  (b) Agentic:     Coordinator → Attack Matrix → Parallel Solvers    │  │
│  │                   (80 iter, JIT + OOB + hunter_tools)               │  │
│  │  → ValidatedVuln[] (only with proof)                                │  │
│  └─────────────────┬─────────────────────────────────────────────────┘  │
│                    │                                                     │
│  ┌─────────────────▼─────────────────────────────────────────────────┐  │
│  │  Phase 4: REPORT (core/reporter.py)                                 │  │
│  │  JSON / HTML / PDF — CVSS, PoC, remediation                        │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Four Phases at a Glance

| Phase     | File/Module              | Input                    | Output            |
|----------|---------------------------|---------------------------|-------------------|
| **Recon**   | `core/recon.py`          | Target URL                | `AttackSurface`   |
| **Hunt**    | `core/vuln_hunters/*`    | `AttackSurface`           | `VulnHypothesis[]`|
| **Exploit** | `core/exploit.py` + (optional) Coordinator/Solver | Hypotheses + Surface | `ValidatedVuln[]` |
| **Report**  | `core/reporter.py`       | ValidatedVulns + metadata | report.json/html/pdf |

---

## 3. All Components and Their Roles

### 3.1 Coordinator (`src/agent/coordinator.py`)

- **Role:** Builds the attack matrix and dispatches parallel Solver agents.
- **Input:** AttackSurface (summary), hunter hypotheses (list of dicts).
- **Process:**
  1. `build_attack_matrix()` — builds (endpoint, parameter, vuln_type) tasks from hypotheses; adds unhinted endpoints for coverage.
  2. Classifies endpoint by URL path: login, search, upload, api, graphql, file, redirect, checkout, coupon, default.
  3. Uses `ENDPOINT_VULN_MATRIX` to pick relevant vuln types per endpoint type.
  4. Priority: Hunter HIGH=1, MEDIUM=2, LOW=3, coverage=4.
  5. Runs up to 5 Solvers in parallel via `ParallelDispatch`.
- **Output:** List[Dict] (found, confidence, working_payload, proof_response, etc.). Converted to `ValidatedVuln[]` by `core/coordinator_result.py`.

### 3.2 Solver Agent (`src/agent/solver.py`)

- **Role:** Runs an 80-iteration agentic loop for one (endpoint, parameter, vuln_type) task.
- **Input:** `SolverTask` — task_id, target_url, parameter, method, vuln_type, initial_hypothesis, oob_url/token.
- **Process:** Uses `AgentLoop.for_solver()` or XLayerLoop; each iteration the LLM decides: tool call, JIT code, pivot, or conclude.
- **Output:** `SolverResult` — found, confidence, working_payload, proof_response, iterations_used, techniques_tried. Only results with confidence ≥ 0.72 and found=True become ValidatedVuln.

### 3.3 XLayerLoop / Agentic Loop (`engine/agentic_loop.py`)

- **Role:** Core reasoning loop — LLM decides the next action every iteration.
- **Constants:**
  - `MAX_ITERATIONS = 80`
  - `FOUND_THRESHOLD = 0.72` — above this = vulnerability confirmed
  - `REFINE_THRESHOLD = 0.35` — below this = pivot strategy
  - `CONSECUTIVE_FAIL_PIVOT = 3` — after 3 iterations with no confidence gain = auto-pivot
  - `COMPRESS_EVERY = 15` — compress history to save tokens
  - `OOB_POLL_EVERY = 5` — check OOB callbacks
- **Each iteration:** Build context + Observation Journal → LLM → parse decision → execute (tool/JIT/pivot/conclude) → update confidence and journal → check found/pivot/compress/OOB.

### 3.4 JIT Engine (`src/tools/jit_engine.py`)

- **Role:** Runs agent-written Python code in a sandboxed subprocess.
- **Safe prelude:** sys, os, re, json, base64, httpx, urllib.parse, time.
- **Blocked:** subprocess, socket.bind, 127.0.0.1, etc.
- **Context injection:** target_url, parameter are injected into the agent’s code.
- **Timeout:** 20s; max output 64KB.

### 3.5 OOB Server (`src/tools/oob_server.py`)

- **Role:** Blind vulnerability detection via DNS/HTTP callback (InteractSH cloud or local TCP fallback).
- **InteractSHClient:** register → unique subdomain → poll for hits.
- **OOBHit:** protocol, remote_address, raw_request, timestamp.
- **Helpers:** `make_sqli_payloads(token)`, `make_ssrf_payloads(token)`, `make_xss_payloads(token)` for blind detection payloads.

### 3.6 Hunter Tools (`src/tools/hunter_tools.py`)

- **Role:** `@tool` wrappers for all 16 hunters so the Solver/LLM can call e.g. `run_sqli_hunter`, `run_xss_hunter`, etc.
- **Each tool:** Takes target_url, parameter, method (and type-specific args) and returns a JSON string (HunterResult-like dict).
- **Use:** Inside the agentic loop the LLM can re-run hunters or try payloads via these tools.

### 3.7 Coordinator Result (`core/coordinator_result.py`)

- **Role:** Converts Coordinator dict list to `List[ValidatedVuln]` and merges/dedupes multiple lists.
- **Functions:**
  - `coordinator_results_to_validated_vulns(raw_list)` — only entries with found=True and confidence ≥ 0.72.
  - `coordinator_result_to_validated_vuln(raw)` — one dict → one ValidatedVuln.
  - `merge_validated_vulns(*lists, prefer="first"|"last")` — dedupe by (endpoint, parameter, vuln_type).

---

## 4. All 16 Vulnerability Hunters

### 4.1 Original 5 Hunters

| Hunter | File | What It Detects |
|--------|------|------------------|
| **SQLi** | sqli.py | Error-based, Boolean blind, Time-based, Union-based SQL injection |
| **XSS** | xss.py | Reflected, DOM-based, context-aware XSS |
| **Auth** | auth.py | Auth bypass, IDOR, session issues, default creds, JWT none, session fixation |
| **SSRF** | ssrf.py | Cloud metadata, internal network, protocol bypass |
| **LFI** | lfi.py | Path traversal, PHP wrappers, log poisoning |

### 4.2 Additional 11 Hunters

| Hunter | File | What It Detects |
|--------|------|------------------|
| **SSTI** | ssti.py | Template injection — e.g. `{{7*7}}`→49 across 8 engines |
| **RCE** | rce.py | Command injection — time-based sleep, echo reflection, output |
| **XXE** | xxe.py | XML External Entity — file read, SSRF, error patterns, OOB |
| **Open Redirect** | open_redirect.py | Unvalidated redirect — Location header, 18 bypass techniques |
| **CORS** | cors.py | CORS misconfiguration — origin reflection, null, wildcard+creds |
| **CSRF** | csrf.py | Cross-Site Request Forgery — token absent, token bypass tests |
| **Subdomain Takeover** | subdomain_takeover.py | Dangling DNS — 20+ cloud service fingerprints |
| **GraphQL** | graphql.py | Introspection, batch, depth, injection |
| **Race Condition** | race_condition.py | TOCTOU — N parallel requests, multiple success detection |
| **Deserialization** | deserialization.py | Insecure deserialization — magic bytes, error patterns, pickle timing |
| **HTTP Smuggling** | http_smuggling.py | Request smuggling — CL.TE, TE.CL, TE.TE timing probes |

### 4.3 Hunter Registry

- **core/vuln_hunters/__init__.py:** `HUNTER_REGISTRY` (name → class), `ALL_HUNTERS` list. All 16 hunters are registered and can be run in parallel via `run_hunters_parallel()`.

### 4.4 Detection Methods per Hunter (Summary)

| Hunter | Primary Detection Methods |
|--------|----------------------------|
| SQLi | Error messages, boolean true/false response diff, time delay (SLEEP/BENCHMARK), UNION-based data echo |
| XSS | Reflected canary, DOM sink detection, context (HTML/attribute/JS/URL) and encoding variants |
| Auth | Default creds, SQLi in login, NoSQL `$ne`/`$gt`, LDAP injection, JWT alg:none, session fixation, ID enumeration |
| SSRF | Internal IP response, cloud metadata endpoint hit (AWS/GCP/Azure), protocol smuggling (gopher/file) |
| LFI | File content in response (/etc/passwd, PHP source), PHP wrapper output, path traversal response diff |
| SSTI | Math expression `{{7*7}}`/`${7*7}` etc. → 49 in response across Jinja2, Twig, Freemarker, Velocity, Smarty, Mako, Tornado, ERB |
| RCE | Time-based sleep, echo/print of payload in response, command output in body |
| XXE | File content in response, SSRF callback, OOB callback, parser error patterns |
| Open Redirect | Location header points to attacker domain; 18 bypasses (double encode, subdomain, @, etc.) |
| CORS | Origin reflected in Access-Control-Allow-Origin, null origin accepted, wildcard + credentials |
| CSRF | Missing or weak token; token bypass (same-origin, header injection, token in GET) |
| Subdomain Takeover | CNAME to non-existent cloud service; 20+ fingerprints (GitHub, Heroku, S3, etc.) |
| GraphQL | Introspection enabled, batch/depth DoS, injection in query variables |
| Race Condition | N parallel requests; multiple success responses or state inconsistency |
| Deserialization | Magic bytes (Java/Python/PHP), error messages, timing (pickle/gadget) |
| HTTP Smuggling | CL.TE / TE.CL / TE.TE timing and response ordering anomalies |

---

## 5. Mutation Engine — Complete Detail

The Mutation Engine (`tools/mutation_engine.py`) is a centralized, context-aware engine that produces WAF-bypass and encoding variants. It supports **SQLi, XSS, LFI, SSRF, Auth**, and (in code) **SSTI, RCE, XXE**. Mutations are **priority-sorted** (1 = highest) and **deduplicated**; optional `ctx.get_failed_payloads()` excludes already-tried payloads.

### 5.1 SQLi Mutations (14+ techniques)

| Technique | Example / Description |
|-----------|------------------------|
| **hex_strings** | `'admin'` → `0x61646d696e` — highest priority when quotes are filtered |
| **char_encoding** | `'admin'` → `CHAR(97,100,109,105,110)` |
| **versioned_comment** | `UNION` → `/*!50000UNION*/` (MySQL versioned comment) |
| **inline_comment_split** | `UNION` → `UN/**/ION` |
| **double_char** | `UNION` → `UUNNIION` — bypasses single-strip WAFs |
| **case_toggle** | `SELECT` → `SeLeCt` |
| **scientific_notation** | `1` → `1e0` |
| **comment_sandwich** | `OR 1=1` → `OR/*!*/1=1` |
| **space_sub** (6 variants) | Space → `/**/`, `%09`, `%0a`, `%0d%0a`, `%0b`, `+` |
| **extractvalue_bypass** | Alternative extraction when UNION is blocked |
| **unicode_whitespace** | Space → `\u00a0` |
| **null_byte_suffix** | `payload%00` |
| **url_encoded** | URL-encoded payload variant |
| **versioned_mixed_case** | Versioned comment + case mix |

### 5.2 XSS Mutations (15+ techniques)

| Technique | Example / Description |
|-----------|------------------------|
| **tag_mutation** | `<script>` → `<ScRiPt>`, `<SCRIPT>` |
| **event_handler** | 18+ event handler vectors (onclick, onerror, etc.) |
| **base64_eval** | `<script>eval(atob("YWxlcnQoMSk="))</script>` |
| **template_injection** | `{{7*7}}`, `${7*7}`, `#{7*7}` |
| **svg_vector** | 10 SVG-based payloads |
| **js_uri** | 11 `javascript:` variants with encoding |
| **null_byte_tag** | `<scri\x00pt>` |
| **html_entity** | `&#60;script&#62;` — high priority when angle brackets filtered |
| **double_url_encode** | `%253Cscript%253E` |
| **css_expression** | IE-era CSS expression injection |
| **iframe_srcdoc** | `<iframe srcdoc='<script>alert(1)</script>'>` |
| **unicode_escape** | `alert` → `\u0061\u006c\u0065\u0072\u0074` |
| **event_handler_variation** | 17 event handler variants |
| **polyglot** | Universal multi-context payloads |
| **backtick_call** | `alert(1)` → `alert\`1\`` |

### 5.3 LFI Mutations (14+ techniques)

| Technique | Example / Description |
|-----------|------------------------|
| **double_dot** | `../` → `....//` |
| **url_encode** | `../` → `%2e%2e%2f` |
| **double_url_encode** | `../` → `%252e%252e%252f` |
| **triple_url_encode** | `../` → `%25252e%25252e%25252f` |
| **null_byte** | `passwd%00`, `passwd%00.jpg` |
| **php_wrapper** | 15+ PHP filter/data/expect wrappers |
| **absolute_path** | OS-specific paths (16 Linux, 8 Windows) |
| **utf8_overlong** | `../` → `%c0%ae%c0%ae%c0%af` |
| **backslash** | `/` → `\` |
| **mixed_slash** | Alternating `/` and `\` |
| **wrapper_chain** | `php://filter/zlib.deflate|base64-encode/...` |
| **path_normalization** | `/./././etc/passwd` |
| **semicolon_suffix** | `passwd;` |
| **strip_extension** | Bypass appending `.php` |

### 5.4 SSRF Mutations (12+ techniques)

| Technique | Example / Description |
|-----------|------------------------|
| **ipv6_localhost** | 10 IPv6 variants of 127.0.0.1 |
| **decimal_ip** | `127.0.0.1` → `2130706433` |
| **octal_ip** | `127.0.0.1` → `0177.0.0.1` |
| **hex_ip** | `127.0.0.1` → `0x7f000001` |
| **cloud_metadata** | 14 endpoints (AWS/GCP/Azure/DO/Oracle/K8s) |
| **dns_rebind** | localtest.me, nip.io, xip.io |
| **protocol_smuggle** | gopher, dict, ldap, file, sftp, ftp + 15 services |
| **loopback_variants** | 17 port variants of localhost |
| **ipv4_mapped** | `[::ffff:127.0.0.1]` |
| **at_sign_bypass** | `http://attacker@127.0.0.1` |
| **scheme_case** | `HTTP://`, `Http://` |
| **redirect_bypass** | Open redirect chaining |
| **ipv6_encoded** | Encoded IPv6 forms |

### 5.5 Auth Mutations (12+ techniques)

| Technique | Example / Description |
|-----------|------------------------|
| **sqli_no_quote** | 17 SQL injection bypass payloads (no quotes) |
| **sqli_hex** | Hex-encoded SQL conditions |
| **nosql_operator** | 15 MongoDB `$ne`, `$gt`, `$regex` variants |
| **ldap_injection** | 12 LDAP injection patterns |
| **type_juggling** | PHP `0e123`, `true`, `[]`, `{}` |
| **parameter_pollution** | Send same param twice with different values |
| **case_variation** | `ADMIN`, `Admin`, `aDmIn` |
| **unicode_bypass** | Full-width Unicode, Cyrillic lookalikes |
| **null_byte_truncation** | `admin%00` |
| **double_url_encode** | Double-encoded credentials |
| **jwt_hints** | `alg:none` token structure |
| **comment_bypass** | 14 SQL comment-based bypasses |

### 5.6 MutationEngine API

- **`mutate(vuln_type, payloads, ctx=None)`** — returns `List[MutationResult]` (payload, technique, vuln_type, priority), deduplicated and sorted by priority. If `ctx` has `get_failed_payloads()`, those are excluded.
- **`mutate_to_strings(vuln_type, payloads, ctx=None, limit=30)`** — same but returns plain strings, optionally capped.
- **Supported vuln_type:** `sqli`, `xss`, `lfi`, `ssrf`, `auth`, `ssti`, `rce`, `xxe` (SSTI/RCE/XXE may have lighter mutation sets).

### 5.7 Priority System (summary)

- **Priority 1:** Hex encoding (when quotes filtered), some HTML entity (XSS when angle filtered).
- **Priority 2:** CHAR encoding, versioned comment, extractvalue bypass, tag/event handler (XSS), url_encode (LFI), php_wrapper, absolute_path, IPv6/decimal/octal (SSRF).
- **Priority 3–6:** Space sub, inline comment, double char, comment sandwich, base64/template/svg/js_uri (XSS), path tricks (LFI), cloud metadata, protocol smuggle, auth variants, etc.

---

## 6. Adaptive Engine and AI Payload Generator

### 6.1 ProbeEngine (`tools/adaptive_engine.py`)

Fingerprints the target **before** heavy attacking:

- Sends test characters → learns what is filtered.
- Sends SQL keywords → learns what is blocked.
- Sends WAF trigger payloads → identifies WAF type.
- Sends time-based payloads → confirms time-based injection.
- Sends boolean pairs → confirms boolean-blind injection.

Results are stored in `AttackContext` for the AI and MutationEngine.

### 6.2 AdaptiveEngine — 4-Phase Feedback Loop

1. **Phase 1:** Static payloads (fast, no LLM).
2. **Phase 2:** ProbeEngine fingerprints + MutationEngine bypasses.
3. **Phase 3:** AI generates novel payloads from `AttackContext` (failure history, WAF, filtered chars).
4. **Phase 4:** AI learns from Phase 3 failures and generates improved payloads.

Loop continues until success or max rounds.

### 6.3 AIPayloadGenerator (`llm/payload_generator.py`)

- **AttackContext:** url, parameter, vuln_type, database, waf, quotes_filtered, keywords_filtered, time_delay_works, attempts (failure history).
- **Per-vuln-type prompts:** sqli, xss, ssrf, lfi, auth.
- **Output:** 6 novel payloads per round; `_validate()` removes duplicates and already-tried; `_add_mutations()` applies MutationEngine to AI output.
- **BinarySearchExtractor:** Efficient boolean-blind SQLi data extraction (binary search, ~5–7 requests per character).

### 6.4 Integration in Hunters

Original 5 hunters (and others where applicable) use:

- `_build_attack_context(endpoint, param, vuln_type, attack_surface)`.
- `_adaptive_test(endpoint, param, static_payloads, ctx, success_callback)` — which runs static → mutation → AI rounds via AdaptiveEngine.

---

## 7. Vulnerability Hunting — How It Works

### 7.1 BaseHunter Flow (`core/vuln_hunters/base.py`)

1. Each hunter implements `hunt(attack_surface)`.
2. From AttackSurface it selects relevant endpoints and parameters (e.g. SQLi = all params, LFI = file/path params).
3. **Static payloads** first (from YAML/DB) — fast, no LLM cost.
4. Response analysis: error patterns, content change, timing.
5. **If nothing found:** AdaptiveEngine — ProbeEngine (fingerprint) + MutationEngine (100+ mutations) + AI rounds (AIPayloadGenerator with AttackContext and failure memory).
6. Returns **HunterResult:** hypotheses (VulnHypothesis[]), endpoints_tested, payloads_sent.

### 7.2 VulnHypothesis vs ValidatedVuln

- **VulnHypothesis:** Output of Hunt phase — “this might be vulnerable”, confidence HIGH/MEDIUM/LOW. No proof yet.
- **ValidatedVuln:** After Exploit phase — proof (response, payload, optional screenshot), CVSS, PoC. Only these go into the report.

### 7.3 Parallel Hunt

- `run_hunters_parallel(hunters, attack_surface)` runs all hunters concurrently (e.g. asyncio.gather).
- Planner builds hunter instances from `_create_hunters()` (from settings / CLI) and aggregates all HunterResult hypotheses into one list.

---

## 8. Agentic Workflow — Coordinator, Solver, XLayerLoop

### 8.1 Agentic Path (Optional — Not Yet Default in Planner)

1. **Coordinator.run(attack_surface, hypotheses_as_dicts):**
   - Builds attack matrix from surface summary + hypotheses.
   - Starts OOB server (InteractSH).
   - Each matrix task becomes a SolverTask; up to 5 Solvers run in parallel via ParallelDispatch.
   - Each Solver runs `SolverAgent.run(task)`.

2. **SolverAgent.run(task):**
   - Uses AgentLoop.for_solver() or XLayerLoop with tools (hunter_tools, http_probe, JIT, OOB).
   - Up to 80 iterations: LLM → decision → execute → journal → confidence check → pivot/conclude.
   - If confidence ≥ 0.72 and proof → SolverResult(found=True, ...).

3. **Collect:**
   - Coordinator gathers all SolverResults.
   - `coordinator_results_to_validated_vulns()` converts found=True, confidence≥0.72 to ValidatedVuln[].

### 8.2 XLayerLoop — One Iteration in Detail

1. `state.full_context()` — Target, Progress, Observation Journal (last 20 entries).
2. HumanMessage: context + “Remaining iterations: N. What is your next action?”
3. `LLM.call(messages, tools, system_prompt)` → AI response.
4. `_parse_decision(ai_response)` → Decision(action, tool_name, tool_args, jit_code, new_confidence, conclusion).
5. `_execute(decision)`:
   - TOOL_CALL → registry.run(tool_name, tool_args) → hunter or http_probe.
   - JIT_CODE → jit_engine.run(code) in sandbox.
   - PIVOT → state.strategy = new_strategy.
   - CONCLUDE → state.found / state.not_found.
6. Add ObservationEntry to journal; update confidence.
7. If confidence ≥ 0.72 → break (found).
8. If journal is “stuck” (e.g. 3 iters below REFINE_THRESHOLD) → auto-pivot.
9. Every 15 iterations → _compress_history (token save).
10. Every 5 iterations → _poll_oob (blind callback check).

---

## 9. File Map — Which File Does What

### 9.1 Entry and Orchestration

| File | Role |
|------|------|
| **main.py** | CLI (Click): scan, config, version, hunters. URL validation, settings load, calls PlannerAgent.start_mission(). |
| **core/planner.py** | PlannerAgent: runs 4 phases in order. MissionContext (target_url, attack_surface, hypotheses, validated_vulns, report). _phase_recon, _phase_vuln_hunt, _phase_exploit, _phase_report. |

### 9.2 Phase 1 — Recon

| File | Role |
|------|------|
| **core/recon.py** | ReconAgent: execute(target_url) → AttackSurface. DNS resolve, port scan (scanner), tech fingerprint (TECH_SIGNATURES), robots.txt, sitemap, WebCrawler (static + JS). Populates endpoints, forms, api_endpoints, auth_endpoints. |
| **tools/crawler.py** | WebCrawler: BFS crawl, js_rendering (Playwright), XHR/fetch intercept for hidden API discovery. |
| **tools/scanner.py** | PortScanner: async port scan; get_dns_records for DNS. |
| **tools/http_client.py** | AsyncHTTPClient: auth (AuthConfig), rate limit, SSL. |

### 9.3 Phase 2 — Vuln Hunt

| File | Role |
|------|------|
| **core/vuln_hunters/base.py** | BaseHunter, HunterResult; test_endpoint, _send_payload, _analyze_response; integrates AdaptiveEngine, AIPayloadGenerator. |
| **core/vuln_hunters/__init__.py** | HUNTER_REGISTRY (name→class), ALL_HUNTERS. |
| **core/vuln_hunters/sqli.py … http_smuggling.py** | Per-vuln-type hunt(), payloads, response analysis. |
| **tools/adaptive_engine.py** | ProbeEngine (fingerprint), AdaptiveEngine (4-phase loop). |
| **tools/mutation_engine.py** | 100+ mutations (SQLi, XSS, LFI, SSRF, Auth, plus ssti/rce/xxe); priority-sorted. |
| **tools/payload_manager.py** | YAML payload DB, WAF detection, get_adaptive_payloads. |
| **llm/payload_generator.py** | AIPayloadGenerator, AttackContext, BinarySearchExtractor. |

### 9.4 Phase 3 — Exploit

| File | Role |
|------|------|
| **core/exploit.py** | ExploitAgent: verify_all(hypotheses) → ValidatedVuln[]. Uses HIGH/MEDIUM hypotheses, HeadlessBrowser + HTTP for proof, CVSS, remediation. |
| **src/agent/coordinator.py** | build_attack_matrix, _classify_endpoint; Coordinator.run() → parallel Solvers; JIT/OOB tools. |
| **src/agent/solver.py** | SolverAgent: run(SolverTask) → SolverResult; AgentLoop.for_solver, 80 iterations. |
| **engine/agentic_loop.py** | XLayerLoop: run(state) — decision parse, tool/JIT execute, journal, pivot, OOB poll. |
| **engine/agent.py** | AgentLoop (wrapper for Solver). |
| **core/coordinator_result.py** | coordinator_results_to_validated_vulns, merge_validated_vulns. |

### 9.5 Phase 4 — Report

| File | Role |
|------|------|
| **core/reporter.py** | Reporter: generate(metadata, attack_surface, validated_vulns) → Report. JSON, HTML (template), optional PDF. CVSS, PoC, remediation. |

### 9.6 Agentic / Shared Tools

| File | Role |
|------|------|
| **src/tools/hunter_tools.py** | run_sqli_hunter, run_xss_hunter, … (all 16) — @tool wrappers. |
| **src/tools/jit_engine.py** | JITEngine: run(code, context) — sandboxed Python. |
| **src/tools/oob_server.py** | OOBServer, InteractSHClient, make_sqli_payloads, make_ssrf_payloads, make_xss_payloads. |

### 9.7 Models

| File | Role |
|------|------|
| **models/target.py** | Target, AttackSurface, Endpoint, Parameter, TechnologyStack. |
| **models/vulnerability.py** | VulnType, VulnHypothesis, ValidatedVuln, Confidence, Severity, ExploitEvidence, ProofOfConcept. |
| **models/report.py** | Report, Finding, Evidence, ScanMetadata. |

### 9.8 Config and LLM

| File | Role |
|------|------|
| **config/settings.py** | Pydantic Settings: llm, scan, auth, port_scan, exploit, report, hunters (16 by default). |
| **engine/llm.py** | LLMClient for Coordinator/Solver (OpenAI/Anthropic direct). |
| **llm/engine.py** | LLMEngine for Planner/pipeline (config, personas). |

### 9.9 Hunter Tool Names (src/tools/hunter_tools.py)

All 16 hunters are exposed as tools the Solver can call by name:

- `run_sqli_hunter` (target_url, parameter, method, db_hint)
- `run_xss_hunter` (target_url, parameter, method)
- `run_auth_hunter` (target_url, parameter, method)
- `run_ssrf_hunter` (target_url, parameter, method)
- `run_lfi_hunter` (target_url, parameter, method)
- `run_ssti_hunter` (target_url, parameter, method)
- `run_rce_hunter` (target_url, parameter, method)
- `run_xxe_hunter` (target_url, parameter, method)
- `run_open_redirect_hunter` (target_url, parameter, method)
- `run_cors_hunter` (target_url, parameter, method)
- `run_csrf_hunter` (target_url, parameter, method)
- `run_subdomain_takeover_hunter` (target_url, parameter, method)
- `run_graphql_hunter` (target_url, parameter, method)
- `run_race_condition_hunter` (target_url, parameter, method)
- `run_deserialization_hunter` (target_url, parameter, method)
- `run_http_smuggling_hunter` (target_url, parameter, method)

Plus shared helpers: `http_probe` (custom HTTP request with payload) for use when hunters are not enough. JIT and OOB are wired separately in the Coordinator/Solver tool list.

### 9.10 Project Directory Structure (Simplified)

```
XLAYER-HACKING CO/
├── xlayer_ai/
│   ├── main.py
│   ├── config/settings.py
│   ├── core/
│   │   ├── planner.py, recon.py, exploit.py, reporter.py
│   │   ├── coordinator_result.py
│   │   └── vuln_hunters/ (base, sqli, xss, auth, ssrf, lfi, ssti, rce, xxe,
│   │       open_redirect, cors, csrf, subdomain_takeover, graphql,
│   │       race_condition, deserialization, http_smuggling)
│   ├── src/
│   │   ├── agent/ (coordinator.py, solver.py, swarm/)
│   │   ├── tools/ (hunter_tools.py, jit_engine.py, oob_server.py, handoff.py)
│   │   ├── graph/, prompts/, utils/
│   ├── engine/ (agentic_loop.py, agent.py, llm.py, pipeline.py, tool.py, memory.py, messages.py)
│   ├── tools/ (http_client.py, crawler.py, payload_manager.py, scanner.py,
│   │   adaptive_engine.py, mutation_engine.py, browser.py)
│   ├── llm/ (engine.py, payload_generator.py, models.py, config_manager.py)
│   ├── models/ (target.py, vulnerability.py, report.py)
│   └── prompts/, utils/, packages/xlayer_hunter/
├── WHOLE_PROJECT_REPORT_EN.md
├── WHOLE_PROJECT_REPORT.md
├── XLAYER_REPORT.md
├── PROJECT_WHOLE_OVERVIEW.md
├── FILE_ANALYSIS_DETAILS.md
├── COORDINATOR_INTEGRATION_WHAT_HAPPENS.md
└── ANALYSIS_STRENGTH_WEAKNESS_IMPROVEMENT.md
```

---

## 10. Recon → Vuln → Exploit → Report — Each Phase in Detail

### 10.1 RECON (Phase 1) — Step by Step

1. **Input:** `target_url` (e.g. https://example.com).
2. **ReconAgent.execute():**
   - **DNS:** _resolve_dns(hostname) → A (and other) records → attack_surface.ip_addresses.
   - **Port scan:** (if enabled) PortScanner.scan_ports(ip, top_n) → open_ports, services (banner).
   - **Initial GET:** target_url → headers + body.
   - **Tech stack:** _detect_technology() — TECH_SIGNATURES (server, language, framework, database, frontend, waf, cdn) matched against headers/body.
   - **robots.txt:** fetch → attack_surface.robots_txt.
   - **Sitemap:** sitemap.xml / sitemap_index.xml parsed → seed URLs.
   - **Crawl:** WebCrawler.crawl(target_url, seed_urls) — max_depth, max_pages, js_rendering (Playwright), session_cookies for auth. Static links + JS-rendered XHR/fetch → endpoints, forms, api_endpoints.
   - **Auth endpoints:** forms with AUTH type or URL containing login/signin/auth → auth_endpoints list.
3. **Output:** AttackSurface — all_endpoints, testable_endpoints, technology, open_ports, attack_surface_score.

### 10.2 VULN HUNT (Phase 2) — Step by Step

1. **Input:** AttackSurface; settings.hunters (or CLI --hunters).
2. **Planner:** _create_hunters() — builds instances from HUNTER_REGISTRY (http_client, payload_manager, settings, llm_engine).
3. **run_hunters_parallel(hunters, attack_surface):** runs all hunters in parallel (e.g. asyncio.gather).
4. **Each hunter.hunt(attack_surface):**
   - Selects relevant endpoints/parameters.
   - Sends static payloads → _analyze_response.
   - If no hit: AdaptiveEngine (ProbeEngine + MutationEngine + AI rounds).
   - Builds VulnHypothesis: endpoint, parameter, vuln_type, confidence (HIGH/MEDIUM/LOW), indicators, suggested_payloads.
5. **Output:** All HunterResult hypotheses combined → context.hypotheses.

### 10.3 EXPLOIT (Phase 3) — Step by Step

**Current default (ExploitAgent only):**

1. **Input:** Hypotheses with confidence HIGH or MEDIUM.
2. **ExploitAgent.verify_all(hypotheses):**
   - For each hypothesis runs real exploit payloads (HTTP + optional HeadlessBrowser).
   - Evidence: response snippet, extracted data, curl, screenshot.
   - CVSS, severity, remediation.
   - Only successful exploits become ValidatedVuln.
3. **Output:** context.validated_vulns = List[ValidatedVuln].

**Agentic path (optional, not yet wired in Planner’s _phase_exploit):**

1. Attack surface summary + hypotheses as dicts → Coordinator.run().
2. build_attack_matrix() → List[AttackMatrixEntry] (sorted by priority), e.g. max 50 tasks.
3. OOB server start; JIT tool, hunter_tools, http_probe ready.
4. ParallelDispatch: each entry → SolverTask → SolverAgent.run(task) → 80-iter XLayerLoop.
5. SolverResult (found, confidence, working_payload, proof) → coordinator_results_to_validated_vulns() → List[ValidatedVuln].
6. Optional: merge with ExploitAgent results via merge_validated_vulns(exploit_list, agentic_list, prefer="first").

### 10.4 REPORT (Phase 4) — Step by Step

1. **Input:** context.to_metadata(), attack_surface, validated_vulns, hypotheses_count.
2. **Reporter.generate():**
   - ScanMetadata: scan_id, target_url, duration, hunters_used, endpoints_scanned, requests_made.
   - Each ValidatedVuln → Finding (title, severity, description, evidence, poc, remediation).
   - Report: overall_risk, stats (critical/high/medium/low), findings list.
3. **Output files:** report.json, report.html in settings.report.output_dir; optional report.pdf.
4. context.report set; mission complete.

---

## 11. Data Flow and Models

```
Target URL
    → AttackSurface (endpoints, tech, params)
    → VulnHypothesis[] (per hunter)
    → (HIGH/MEDIUM) → ExploitAgent / Coordinator
    → ValidatedVuln[] (proof, CVSS, PoC)
    → Report (JSON/HTML/PDF)
```

**Key types:** AttackSurface, Endpoint, VulnHypothesis, ValidatedVuln, Report, Finding, ScanMetadata — defined in models/target.py, models/vulnerability.py, models/report.py.

### 11.1 CVSS and Severity Mapping

Used in `core/coordinator_result.py` (CVSS_BY_TYPE) and `core/exploit.py` (CVSS_SCORES / SEVERITY_MAP):

| VulnType | Typical CVSS | Severity Band (9.0–10=Critical, 7–8.9=High, 4–6.9=Medium, 0.1–3.9=Low, 0=Info) |
|----------|--------------|----------------------------------------------------------------------------------|
| SQLi, Auth Bypass, Command Injection, Deserialization | 9.1–9.8 | Critical |
| SSRF, LFI, RFI, XSS Stored, Subdomain Takeover | 7.2–8.6 | High |
| IDOR, Session Fixation, Path Traversal, XXE, Race Condition | 5.3–7.5 | Medium–High |
| XSS Reflected, XSS DOM | 6.1 | Medium |
| CSRF, Open Redirect, CORS, GraphQL | 4.3–6.5 | Medium–Low |
| Info Disclosure | 5.3 | Medium |

Severity is computed from CVSS score so that report findings get a consistent risk label (Critical/High/Medium/Low/Info).

---

## 12. WAF Support and Tech Fingerprinting

### 12.1 WAF Detection (`tools/payload_manager.py`)

- **detect_waf()** identifies WAF from response headers/body: Cloudflare, AWS WAF, Akamai, Imperva, ModSecurity, Sucuri, F5.
- **get_waf_bypass_variants()** — 20+ bypass techniques (space substitution, case mutations, Unicode, URL encoding layers).
- **get_adaptive_payloads()** — WAF-aware payload selection.

### 12.2 Tech Signatures (`core/recon.py` — TECH_SIGNATURES)

- **server:** nginx, apache, iis, cloudflare, gunicorn, uvicorn.
- **language:** php, python, node, java, ruby, asp.net.
- **framework:** django, flask, laravel, rails, express, spring, wordpress, drupal, joomla.
- **database:** mysql, postgresql, mongodb, redis, sqlite.
- **frontend:** react, vue, angular, jquery, bootstrap.
- **waf:** cloudflare, akamai, aws_waf, imperva, sucuri, modsecurity.
- **cdn:** cloudflare, akamai, fastly, cloudfront.

### 12.3 ENDPOINT_VULN_MATRIX (`src/agent/coordinator.py`)

Maps endpoint type (from URL path) to vuln types the Coordinator will consider:

| Endpoint Type | Vuln Types |
|---------------|------------|
| search | sqli, xss_reflected, ssti |
| login | auth_bypass, sqli, csrf |
| upload | lfi, xss_stored, xxe, rce |
| redirect | ssrf, open_redirect |
| file | lfi, path_traversal, rce |
| api | sqli, ssrf, auth_bypass, cors, graphql |
| template | ssti |
| xml | xxe |
| checkout | race_condition, csrf |
| coupon | race_condition |
| graphql | graphql |
| default | sqli, xss_reflected, lfi, ssrf, auth_bypass, ssti, cors, open_redirect, csrf |

---

## 13. CLI, Config, and Report Output

### 13.1 CLI Commands (`main.py`)

| Command | Description |
|---------|-------------|
| `python -m xlayer_ai scan <url>` | Run full scan on target URL. |
| `--hunters sqli,xss,auth` | Comma-separated hunters; use `all` for all 16. |
| `--depth 3` | Max crawl depth (default 3). |
| `--output ./reports` | Output directory for reports. |
| `--format json,html` | Report formats: json, html, pdf. |
| `--no-exploit` | Skip exploit phase (hypotheses only). |
| `--no-port-scan` | Skip port scanning. |
| `--timeout 30` | Request timeout (seconds). |
| `--rate-limit 0.5` | Delay between requests (seconds). |
| `--llm-provider openai` | Override LLM provider. |
| `--llm-model gpt-4o-mini` | Override LLM model. |
| `config --show` | Show current configuration. |
| `hunters` | List available hunters. |
| `version` | Show version and components. |

### 13.2 Configuration (Pydantic Settings / .env)

- **LLM:** provider (openai, ollama, anthropic), api_key, model, persona_enabled, persona_profile.
- **Scan:** max_depth, max_pages, timeout, rate_limit, user_agent, verify_ssl, js_rendering.
- **Port scan:** enabled, top_ports, timeout, concurrent.
- **Auth:** enabled, login_url, username, password, bearer_token, api_key, session_cookie, success_url_contains, failure_text.
- **Exploit:** enabled, screenshot.
- **Report:** output_dir, formats (json, html, pdf).
- **Hunters:** list of 16 names (sqli, xss, auth, ssrf, lfi, ssti, rce, xxe, open_redirect, cors, csrf, subdomain_takeover, graphql, race_condition, deserialization, http_smuggling).

### 13.3 Report Output Structure

- **report.json:** Machine-readable; ScanMetadata, attack_surface summary, list of Finding (severity, title, description, evidence, poc, remediation, cvss).
- **report.html:** Styled dashboard; stats grid (critical/high/medium/low counts); per-finding cards with severity badge, code blocks for PoC/curl.
- **report.pdf:** Optional; client-ready (when enabled).

### 13.4 Remediation Guidance (core/exploit.py — REMEDIATION_GUIDANCE)

Per vuln type the report can include guidance such as:

- **SQLi:** Parameterized queries, input allowlists, least privilege for DB, WAF as defense in depth.
- **XSS (Reflected/Stored):** Context-aware output encoding, CSP, HTTPOnly/Secure cookies, input validation/sanitization.
- **Auth Bypass:** Strong authentication, parameterized login queries, account lockout, MFA.
- **IDOR:** Authorization checks on all endpoints, indirect references (e.g. UUIDs), permission checks, logging.
- **SSRF:** URL/domain allowlist, disable dangerous schemes (file, gopher), network segmentation, input validation.
- **LFI:** Avoid user input in file paths, allowlist permitted files, chroot/containers, disable dangerous PHP functions.

Additional vuln types (SSTI, RCE, XXE, CORS, CSRF, etc.) can have remediation text added in reporter or exploit modules.

---

## 14. AI + Mutation Decision Flow (Deep Dive)

### 14.1 How the AI Decides What to Do (from XLAYER_REPORT)

- **Status 403/406/429** → WAF_BLOCK → ctx.waf set → MutationEngine.mutate with WAF-aware strategy (versioned comments, inline split, space sub, etc.).
- **Status 200 + payload stripped** → FILTERED → ctx.filtered_chars updated; if quotes filtered → hex/CHAR encoding (priority 1–2); if keywords filtered → versioned comments, inline splits.
- **Status 200 + body unchanged** → NO_DIFFERENCE → AI round: ctx.failure_summary() sent to LLM for novel payloads.
- **Timeout** → try time-based or other technique.

### 14.2 Failure Memory Loop (Example)

- Attempt 1: `' OR 1=1--` → FAIL (WAF_BLOCK); ctx.attempts.append(attempt_1).
- Attempt 2: `/*!50000OR*/ 1=1--` → FAIL (WAF_BLOCK); ctx.attempts.append(attempt_2).
- Attempt 3: hex or variant → FAIL (FILTERED); ctx.quotes_filtered = True.
- AI round: ctx.failure_summary() → LLM sees “WAF block, filtered chars; time_delay_works: True” → LLM generates time-based payload → Attempt 4 → 5s delay → SUCCESS.

### 14.3 XSS Static Canary Fix

- **Problem:** Static canary `"xlayer7x7"` could be fingerprinted by WAFs.
- **Fix:** `_fresh_canary()` generates a random suffix per scan (e.g. `xlayerx7k2m`, `xlayer3rqp1`) so each run uses a different canary.

---

## 15. How Everything Works Together (End-to-End)

### 15.1 Single-Run Narrative

1. **User** runs `python -m xlayer_ai scan https://target.com` (optionally with --hunters, --depth, --output, etc.).
2. **main.py** loads settings (Pydantic from env/.env), validates URL, and calls `PlannerAgent(settings).start_mission(target_url, hunters)` inside an async context manager.
3. **Planner** runs in order:
   - **_phase_recon:** ReconAgent.execute(target_url) → AttackSurface (DNS, ports, tech, crawl with optional JS rendering and auth cookies). Recon duration and endpoint count stored in context.
   - **_phase_vuln_hunt:** _create_hunters() builds hunter instances from HUNTER_REGISTRY; run_hunters_parallel(hunters, attack_surface) runs all 16 (or selected) in parallel. Each hunter uses PayloadManager, optional AdaptiveEngine/MutationEngine/LLM. All hypotheses are merged into context.hypotheses.
   - **_phase_exploit:** HIGH and MEDIUM hypotheses are passed to ExploitAgent.verify_all(). ExploitAgent uses HTTP client and optional HeadlessBrowser to run real exploits and capture evidence. Only confirmed findings become ValidatedVuln. (If Coordinator is integrated: attack matrix → parallel Solvers → coordinator_results_to_validated_vulns; optional merge with ExploitAgent results.)
   - **_phase_report:** Reporter.generate(metadata, attack_surface, validated_vulns, hypotheses_count) produces Report and writes report.json, report.html, and optionally report.pdf to output_dir.
4. **Hunters** share: HTTP client (with auth if configured), PayloadManager (YAML + WAF detection), optional LLM for AI payload rounds. BaseHunter provides _adaptive_test and _build_attack_context so each hunter can use ProbeEngine + MutationEngine + AIPayloadGenerator when static payloads fail.
5. **ExploitAgent** produces proof via raw requests and optional browser (screenshot, HAR). **Coordinator/Solver** (when used) add proof via JIT scripts, OOB callbacks, and re-invoking hunter tools in the agentic loop.
6. **Report** contains only validated findings (NO EXPLOIT = NO REPORT). Each finding has severity, CVSS, PoC (curl/Python), and remediation guidance.

### 15.2 Example Run (Concrete Flow)

- **Command:** `python -m xlayer_ai scan https://vulnerable-app.example.com --hunters sqli,xss,auth --depth 2 --output ./my-reports`
- **Step 1 — Recon:** ReconAgent resolves DNS for vulnerable-app.example.com, optionally scans top ports (e.g. 80, 443, 8080), GETs the homepage, and runs TECH_SIGNATURES over headers/body (e.g. detects nginx, PHP, MySQL, Cloudflare). It fetches robots.txt and sitemap.xml for seed URLs, then runs WebCrawler with depth=2 and optional JS rendering. Result: AttackSurface with e.g. 25 endpoints (forms, links, API routes), 3 auth endpoints, tech = {server: nginx, language: php, database: mysql, waf: cloudflare}.
- **Step 2 — Hunt:** Planner creates SQLiHunter, XSSHunter, AuthHunter. run_hunters_parallel runs them. SQLiHunter picks all parameters from testable endpoints, sends static payloads from YAML; some get 403 (WAF). ProbeEngine detects Cloudflare; MutationEngine produces versioned comments and hex-encoded variants. One payload triggers a 5s delay → time-based SQLi hypothesis (HIGH). XSSHunter and AuthHunter run similarly; XSS finds a reflected canary on /search?q=; Auth finds no bypass. Result: context.hypotheses = [VulnHypothesis(sqli, /search, param q, HIGH), ...].
- **Step 3 — Exploit:** ExploitAgent.verify_all([HIGH, MEDIUM hypotheses]). For the SQLi hypothesis it sends a real time-based payload, measures delay, then may run UNION/EXTRACTVALUE to extract DB version and stores response as evidence. Builds ValidatedVuln with payload_used, evidence, CVSS 9.1, severity Critical, PoC curl. No proof for others → not in validated_vulns.
- **Step 4 — Report:** Reporter.generate() builds Report with overall_risk from worst finding (e.g. Critical), stats (e.g. 1 critical, 0 high, 0 medium, 0 low), and one Finding. Writes report.json and report.html to ./my-reports. CLI prints "SCAN COMPLETE", "Overall Risk: CRITICAL", "Total Findings: 1", "Reports saved to: ./my-reports".

---

## 16. Summary and References

### 16.1 Summary

- **Philosophy:** NO EXPLOIT = NO REPORT; proof-based reporting only.
- **Architecture:** 4-phase pipeline (Recon → Hunt → Exploit → Report); 16 hunters in parallel; optional agentic path (Coordinator + Solver + XLayerLoop).
- **Recon:** DNS, ports, tech fingerprint (TECH_SIGNATURES), crawl (static + JS) → AttackSurface.
- **Vuln Hunt:** Static → Mutation (100+ techniques) → Adaptive (Probe + AI) → VulnHypothesis[].
- **Exploit:** ExploitAgent (browser + HTTP); optionally Coordinator → Attack Matrix → Parallel Solvers (80 iter, JIT, OOB, hunter_tools) → ValidatedVuln.
- **Report:** JSON/HTML/PDF with CVSS, PoC, remediation.
- **New components:** Coordinator, Solver, XLayerLoop, JITEngine, OOBServer, hunter_tools, coordinator_result, 11 new hunters.
- **Mutation Engine:** 100+ techniques across SQLi, XSS, LFI, SSRF, Auth (and ssti/rce/xxe), priority-sorted and context-aware. Every mutation type added in the project is documented in Section 5.

### 16.2 Other Documents

| Document | Content |
|----------|---------|
| **README.md** (xlayer_ai) | Package overview, usage, config |
| **PROJECT_WHOLE_OVERVIEW.md** | Structure, flow, components (short) |
| **XLAYER_REPORT.md** | Architecture, AI/mutation deep dive, file map |
| **FILE_ANALYSIS_DETAILS.md** | File-by-file role, changes |
| **COORDINATOR_INTEGRATION_WHAT_HAPPENS.md** | How to integrate Coordinator into the main pipeline |
| **ANALYSIS_STRENGTH_WEAKNESS_IMPROVEMENT.md** | Strengths, weaknesses, improvement priorities |

---

*This report is the full English picture of the XLAYER-HACKING CO project — from philosophy through recon–vuln–exploit–report, including all mutation types and components. All mutations (SQLi, XSS, LFI, SSRF, Auth, and related) that have been added are covered in Section 5.*

---

## 17. Quick Reference

| What | Where |
|------|--------|
| Entry point | `main.py` → scan → PlannerAgent.start_mission() |
| 4 phases | planner.py: _phase_recon, _phase_vuln_hunt, _phase_exploit, _phase_report |
| Attack surface | core/recon.py → AttackSurface (models/target.py) |
| 16 hunters | core/vuln_hunters/* + HUNTER_REGISTRY in __init__.py |
| Mutations | tools/mutation_engine.py — mutate(vuln_type, payloads, ctx) |
| Adaptive loop | tools/adaptive_engine.py — ProbeEngine + AdaptiveEngine 4-phase |
| AI payloads | llm/payload_generator.py — AIPayloadGenerator, AttackContext |
| Agentic exploit | src/agent/coordinator.py + solver.py, engine/agentic_loop.py |
| Coordinator result → ValidatedVuln | core/coordinator_result.py — coordinator_results_to_validated_vulns |
| Report output | core/reporter.py → report.json, report.html, report.pdf |
| Config | config/settings.py + .env (XLAYER_* prefix) |

---

## 18. Glossary and Terms

| Term | Meaning |
|------|--------|
| **AttackSurface** | Data structure (models/target.py) holding all discovered endpoints, forms, API routes, tech stack, open ports, auth endpoints. Output of Recon phase. |
| **VulnHypothesis** | A suspected vulnerability (endpoint, parameter, vuln_type, confidence HIGH/MEDIUM/LOW). Output of Hunt phase; not yet proven. |
| **ValidatedVuln** | A confirmed vulnerability with proof (payload, response, CVSS, PoC). Output of Exploit phase; only these go to the report. |
| **HunterResult** | Return type of BaseHunter.hunt(): hypotheses list, endpoints_tested, payloads_sent, errors. |
| **AttackMatrixEntry** | One task for the Coordinator: endpoint_url, parameter, method, vuln_type, priority, initial_hypothesis. |
| **SolverTask** | Input to SolverAgent: task_id, target_url, parameter, method, vuln_type, initial_hypothesis, oob_url/token. |
| **SolverResult** | Output of SolverAgent: found, confidence, working_payload, proof_response, iterations_used, techniques_tried. |
| **AttackContext** | Context for AI payload generation: url, parameter, vuln_type, database, waf, filtered chars/keywords, time_delay_works, attempts (failure history). |
| **MutationResult** | Single mutated payload with technique name, vuln_type, priority (mutation_engine.py). |
| **ObservationJournal** | In XLayerLoop: log of all past actions and results (iteration, action, input summary, result summary, confidence). |
| **JIT** | “Just-in-time” — agent-written Python code executed in a sandbox (jit_engine.py). |
| **OOB** | Out-of-band — DNS/HTTP callback (e.g. InteractSH) for blind SQLi/SSRF/XSS confirmation. |
| **WAF** | Web Application Firewall. Detected and bypassed via MutationEngine and adaptive payloads. |
| **ProbeEngine** | Fingerprints target before attacking (filtered chars, WAF type, time-based/boolean-blind signals). |
| **AdaptiveEngine** | 4-phase feedback: static → mutation → AI round 1 → AI round 2. |
| **ENDPOINT_VULN_MATRIX** | Mapping from endpoint type (login, search, api, etc.) to list of vuln types to test (coordinator.py). |
| **FOUND_THRESHOLD** | 0.72 — confidence ≥ this in XLayerLoop means vulnerability confirmed. |
| **REFINE_THRESHOLD** | 0.35 — below this for several iterations triggers auto-pivot. |

---

## 19. Legal and Intended Use

XLayer AI is intended for **authorized security testing only**. Always obtain proper written authorization before scanning any target. Unauthorized access to computer systems is illegal. The tool should be used only in environments where you have permission to perform vulnerability assessment and penetration testing.

---

## 20. Planned / Known Limitations (from codebase and analysis docs)

- **Coordinator + XLayerLoop** are not yet integrated into the default Planner _phase_exploit; they are optional/standalone. Integration steps are documented in COORDINATOR_INTEGRATION_WHAT_HAPPENS.md.
- **Mutation engine:** Some vuln types (SSTI, RCE, XXE) have lighter mutation coverage than SQLi/XSS/LFI/SSRF/Auth. PostgreSQL/MSSQL/Oracle-specific SQLi and Java/.NET LFI wrappers are limited or planned.
- **Two LLM layers:** engine/llm.LLMClient (Coordinator/Solver) vs llm.engine.LLMEngine (Planner); unification is a suggested improvement.
- **Test coverage:** Unit/integration tests for core pipeline, engine, and mutation are minimal; adding tests is a high-priority improvement.
- **JIT/OOB:** Sandbox and network restrictions for JIT, and use of default InteractSH URL, should be reviewed for safety and configurability.

### 13.1 Summary

- **Philosophy:** NO EXPLOIT = NO REPORT; proof-based reporting only.
- **Architecture:** 4-phase pipeline (Recon → Hunt → Exploit → Report); 16 hunters in parallel; optional agentic path (Coordinator + Solver + XLayerLoop).
- **Recon:** DNS, ports, tech fingerprint, crawl (static + JS) → AttackSurface.
- **Vuln Hunt:** Static → Mutation → Adaptive (Probe + AI) → VulnHypothesis[].
- **Exploit:** ExploitAgent (browser + HTTP); optionally Coordinator → Attack Matrix → Parallel Solvers (80 iter, JIT, OOB, hunter_tools) → ValidatedVuln.
- **Report:** JSON/HTML/PDF with CVSS, PoC, remediation.
- **New components:** Coordinator, Solver, XLayerLoop, JITEngine, OOBServer, hunter_tools, coordinator_result, 11 new hunters.
- **Mutation Engine:** 100+ techniques across SQLi, XSS, LFI, SSRF, Auth (and ssti/rce/xxe), priority-sorted and context-aware.

### 13.2 Other Documents

| Document | Content |
|----------|---------|
| **README.md** (xlayer_ai) | Package overview, usage, config |
| **PROJECT_WHOLE_OVERVIEW.md** | Structure, flow, components (short) |
| **XLAYER_REPORT.md** | Architecture, AI/mutation deep dive, file map |
| **FILE_ANALYSIS_DETAILS.md** | File-by-file role, changes |
| **COORDINATOR_INTEGRATION_WHAT_HAPPENS.md** | How to integrate Coordinator into the main pipeline |
| **ANALYSIS_STRENGTH_WEAKNESS_IMPROVEMENT.md** | Strengths, weaknesses, improvement priorities |

---

*This report is the full English picture of the XLAYER-HACKING CO project — from philosophy through recon–vuln–exploit–report, including all mutation types and components.*

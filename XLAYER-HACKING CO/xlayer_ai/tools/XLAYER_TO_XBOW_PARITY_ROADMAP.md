# XLayer → reference Parity Roadmap (XLayer लाई reference जस्तै बनाउने योजना)

**Goal:** XLayer लाई reference जस्तै (वा भन्दा बढी) enterprise-grade autonomous pentesting agent बनाउने — phase-by-phase, specific files र tasks सहित।

---

## 1. अहिलेको State (के पहिले नै छ)

| reference Capability | XLayer मा के छ | File / Component |
|-----------------|----------------|-------------------|
| Coordinator + Global State | ✅ Coordinator; LSM state | `src/agent/coordinator.py` |
| Parallel Discovery Agents | ✅ HttpProbe, BrowserCrawl, Subdomain, WordlistFuzz, TechFuzz, SupplyChain | `engine/logical_surface_map/discovery_agents.py` |
| Surface Mapping (LSM) | ✅ ScoutLoop, graph, endpoints, JS/HTTP intel | `engine/logical_surface_map/scout.py`, `graph.py` |
| Domain Scoring | ✅ DomainScorer (WAF, auth, tech, params) | `engine/domain_scorer.py` |
| Dedup (SimHash) | ✅ TargetDeduplicator | `engine/dedup.py` |
| Parallel Solvers | ✅ DynamicDispatch, SpawnSpec, kill-and-respawn | `coordinator.py`, `engine/pipeline.py` |
| Model Alloy | ✅ AlloyLLM (alternate primary + Gemini) | `engine/llm.py` |
| JIT Code Execution | ✅ JITEngine, run_jit_code tool | `src/tools/jit_engine.py`, coordinator |
| OOB Validation | ✅ OOBServer, token per task | `src/tools/oob_server.py` |
| Deterministic Validators | ✅ XSS, SQLi, SSRF, RCE, SSTI, LFI replay | `src/agent/validator.py` |
| Attack Matrix (endpoint × vuln) | ✅ AgentSpawner, build_attack_matrix fallback | `coordinator.py` |
| Payload + Mutation | ✅ PayloadManager, mutation_engine, adaptive_engine | `tools/payload_manager.py`, `mutation_engine.py`, `adaptive_engine.py` |

**Default scan path:** `main.py` → `Coordinator.run(target)` → LSM (ScoutLoop) → dedup → domain scoring → spawn specs → parallel solvers → validation → report। यो नै reference-style flow।

---

## 2. Gap (के कमजोर वा छैन)

| Gap | reference के गर्छ | XLayer मा के गर्नुपर्छ |
|-----|----------------|-------------------------|
| **Reasoning loop (payload fail → next)** | Observation (status, body, WAF) हेरेर smart mutation; probe first | exploit/hunter path मा fail पछि response-based next payload; probe-first option |
| **Context-aware payload** | Param name (`id`→SQLi, `name`→XSS), tech stack | Payload choice मा param + tech stack use (hunters/exploit) |
| **Adaptive Matrix (live update)** | नयाँ link भेटिएमा तुरुन्तै global matrix मा थपिन्छ | DiscoveryMonitor छ तर new endpoints → re-spawn specs / re-prioritize नगर्ने |
| **Global Knowledge Graph (chaining)** | Tokens/IDs एक endpoint बाट अर्कोमा attack param | Shared state (tokens, IDs) solver बीच share; coordinator ले chain specs बनाउने |
| **WAF evasion (pacing, fragmentation)** | Adaptive pacing, request fragmentation | mutation_engine मा WAF strategy; optional request fragmentation (HTTP) |
| **Ephemeral spawn by task type** | login.php → SQLi specialist; upload.php → Upload specialist | AgentSpawner already spec by vuln_type; naming/template clearer गर्न सकिन्छ |
| **RCE probes (timing, OOB, reflection)** | Non-destructive probes first | validator + hunter मा RCE probe sequence (timing/OOB/echo) |
| **Vuln feed / CVE ingest** | Daily CVE, PoC → attack template | नयाँ module: CVE ingest + template generator (optional) |
| **Remediation code gen** | Report मा fix code (e.g. parameterized query) | Report phase मा LLM बाट remediation snippet (optional) |

---

## 3. Phased Implementation (कहिले के गर्ने)

### Phase 1 — Quick Wins (१–२ हप्ता)

**Goal:** Exploit path मा “observe response → next payload” र context-aware payload।

| # | Task | File(s) | के गर्ने |
|---|------|--------|----------|
| 1.1 | **Probe-first + observation** | `core/exploit.py` वा hunter call sites | पहिलो request सानो probe (`'`, `<`); response (status, body snippet, WAF header) log; अर्को payload choice मा use। |
| 1.2 | **Context-aware payload choice** | `tools/payload_manager.py` वा hunter config | Param name र tech stack (LSM बाट) pass गर्ने; `id`→SQLi-first, `search`/`name`→XSS-first। |
| 1.3 | **Mutation: failed payloads फेरि mutate** | `tools/adaptive_engine.py` | B1 from ADAPTIVE_AND_MUTATION_STRENGTHEN_PLAN: failed payloads लाई mutation मा feed। |
| 1.4 | **Mutation: WAF in context** | `tools/mutation_engine.py` | ctx.waf use (A3); Cloudflare/ModSecurity अनुसार technique priority। |

**Result:** Payload loop अलिकति reference जस्तो — probe, observe, context-aware mutate।

---

### Phase 2 — Reasoning Loop & Validation (२–३ हप्ता)

**Goal:** Payload fail पछि structured “observation → reasoning → next action” र validation मा RCE probes।

| # | Task | File(s) | के गर्ने |
|---|------|--------|----------|
| 2.1 | **Observation memo (solver)** | `src/agent/solver.py` वा agent loop | प्रत्येक response बाट: status, body diff hint, “WAF detected” flag; अर्को LLM call मा यो context दिने। |
| 2.2 | **Structured reasoning step** | `src/agent/solver.py` | Tool result पछि short “observation” + “next strategy” (e.g. “403 → try encoding”) prompt वा structured output। |
| 2.3 | **RCE probe sequence** | `src/agent/validator.py` + hunter | RCE को लागि: पहिले timing (sleep), then OOB, then echo reflection; validator मा replay order match। |
| 2.4 | **SQLi/XSS validator strengthen** | `src/agent/validator.py` | Timing threshold configurable; XSS को लागि headless “victim” visit (अहिलेको http_probe मा जोड्न सकिन्छ)। |

**Result:** Solver ले “किन फेल भयो” use गरेर अर्को step लिन्छ; RCE र SQLi/XSS validation अझ strict।

---

### Phase 3 — Chaining & Adaptive Matrix (२–३ हप्ता)

**Goal:** एक endpoint को output (tokens, IDs) अर्कोमा use; नयाँ findings तुरुन्तै matrix मा।

| # | Task | File(s) | के गर्ने |
|---|------|--------|----------|
| 3.1 | **Shared knowledge store** | नयाँ `engine/knowledge_store.py` वा coordinator state | Solver findings (tokens, session IDs, user IDs) key-value store; coordinator र अर्को solver ले read गर्छ। |
| 3.2 | **Chaining specs** | `src/agent/coordinator.py`, AgentSpawner | जब कुनै finding मा “token” वा “id” छ, अर्को SpawnSpec बनाउने जसमा त्यो token/ID param को रूपमा हालिन्छ। |
| 3.3 | **DiscoveryMonitor → Matrix update** | `engine/discovery_monitor.py`, `coordinator.py` | 403→200 वा नयाँ endpoint भेटिएमा LSM/coordinator लाई signal; नयाँ specs थप्ने वा re-score गर्ने (optional re-run LSM light)। |
| 3.4 | **Entity context (User/Admin/Invoice)** | `engine/domain_scorer.py` वा graph | Endpoint मा entity hint (e.g. /admin → Admin); scoring र report मा use। |

**Result:** Multi-step chains (e.g. token from A → use in B); adaptive matrix जस्तो behavior।

---

### Phase 4 — WAF Evasion & Polish (१–२ हप्ता)

**Goal:** Pacing र fragmentation (optional); report मा remediation; ephemeral naming clear।

| # | Task | File(s) | के गर्ने |
|---|------|--------|----------|
| 4.1 | **Request pacing (jitter)** | `tools/http_client.py` वा scan config | Consecutive requests बीच random delay (configurable); WAF को लागि “human-like”। |
| 4.2 | **Remediation in report** | `core/report` वा report generator | Confirmed vuln को लागि LLM बाट short safe-code snippet (e.g. parameterized query, encode output)। |
| 4.3 | **Optional CVE ingest** | नयाँ script वा config | Daily CVE list (e.g. NVD API) + PoC parse → attack template (stretch goal)। |

**Result:** Stealth र report quality निकट reference; CVE optional।

---

## 4. File Map (कुन file मा के छ र के थप्ने)

| File | अहिले के छ | Phase मा के थप्ने |
|------|------------|-------------------|
| `src/agent/coordinator.py` | LSM, dedup, scoring, spawn, solvers, OOB, JIT, validator | Phase 3: knowledge store, chaining specs, monitor → matrix |
| `src/agent/solver.py` | Task, tools, JIT, loop | Phase 2: observation memo, reasoning step |
| `src/agent/validator.py` | XSS, SQLi, SSRF, RCE, SSTI, LFI replay | Phase 2: RCE probe order, timing config; Phase 4: XSS headless optional |
| `engine/logical_surface_map/scout.py` | ScoutLoop, LSM | Phase 3: monitor integration (already DiscoveryMonitor exists) |
| `engine/domain_scorer.py` | WAF, auth, tech, params score | Phase 3: entity hint |
| `tools/mutation_engine.py` | Per-vuln mutations | Phase 1: WAF context (ctx.waf); already in ADAPTIVE plan |
| `tools/adaptive_engine.py` | Static + mutation rounds | Phase 1: failed payloads feed |
| `tools/payload_manager.py` | Payload selection | Phase 1: param name + tech stack input |
| `core/exploit.py` | Exploit validation flow | Phase 1: probe-first, response observation |
| `tools/http_client.py` | HTTP requests | Phase 4: pacing/jitter |
| नयाँ `engine/knowledge_store.py` | — | Phase 3: shared tokens/IDs for chaining |

---

## 5. Summary: XLayer लाई reference जस्तै बनाउन के गर्ने

1. **Phase 1:** Probe-first + observation; context-aware payload (param + tech); failed payloads → mutation; WAF in mutation context।  
2. **Phase 2:** Solver मा observation memo र reasoning step; RCE probe order; validator strengthen।  
3. **Phase 3:** Shared knowledge store; chaining specs (token/ID from one to other); DiscoveryMonitor → matrix update; entity context।  
4. **Phase 4:** Pacing/jitter; remediation in report; optional CVE ingest।

यो roadmap follow गरेपछि XLayer को behavior reference को नजिक हुन्छ: reasoning-based payload, validation discipline, chaining, र adaptive matrix। सबै काम तपाईंको existing codebase मा (coordinator, solver, validator, LSM, mutation, adaptive) मा थप्ने हुन्छ; नयाँ “product” भन्दा **extension** जस्तै लाग्नेछ।

तपाईं चाहनुहुन्छ भने Phase 1 बाट कुन एक task (e.g. 1.1 probe-first वा 1.2 context-aware payload) लाई पहिलो लिएर मैले concrete code change (patch) लेखिदिन्छु।

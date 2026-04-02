# XLAYER-HACKING CO — पूरा प्रोजेक्ट ओभरभ्यू (Whole Project Overview)

**यो फाइलमा यस प्रोजेक्टको सबै कुरा — structure, philosophy, components, flow, files — एकै ठाउँमा छ।**

---

## 1. प्रोजेक्ट के हो? (What Is This Project?)

**XLAYER-HACKING CO** एउटा **folder/project name** हो। भित्रको मुख्य चीज:

| Item | विवरण |
|------|--------|
| **xlayer_ai/** | मुख्य Python package — Autonomous Web Vulnerability Hunter। सबै code यहीँ छ। |
| **XLAYER_REPORT.md** | System report — architecture, 4-phase pipeline, components, data flow, AI/mutation deep dive, file map। |
| **PROJECT_WHOLE_OVERVIEW.md** | यही फाइल — पूरा प्रोजेक्टको सबै सार। |

**xlayer_ai** नै हो जसले:
- Target URL लिएर **recon** गर्छ (crawl, tech detect, port scan)
- **16 vulnerability hunters** parallel चलाउँछ (SQLi, XSS, Auth, SSRF, LFI, SSTI, RCE, XXE, CORS, CSRF, GraphQL, Race, Deserialization, HTTP Smuggling, Subdomain Takeover, Open Redirect)
- **Agentic path** मा Coordinator → Attack Matrix → Parallel Solvers (80-iteration agentic loop, JIT + OOB)
- **Exploit** phase मा proof लिएर validate गर्छ
- **Report** (JSON / HTML / PDF) generate गर्छ

**मूल सिद्धान्त:** **NO EXPLOIT = NO REPORT** — guess गर्दैन, prove गरेको मात्र report गर्छ।

---

## 2. प्रोजेक्ट संरचना (Project Structure)

```
XLAYER-HACKING CO/
│
├── XLAYER_REPORT.md              ← Full system report (architecture, pipeline, components)
├── PROJECT_WHOLE_OVERVIEW.md     ← This file — whole project सबै
│
└── xlayer_ai/                    ← MAIN PACKAGE (all code lives here)
    │
    ├── main.py                   ← CLI: scan, config (entry point)
    ├── README.md                  ← Package readme
    ├── requirements.txt           ← Python deps
    ├── .env.example               ← Env template
    ├── mcp_config.json            ← MCP servers per agent (swarm)
    ├── FILE_ANALYSIS_DETAILS.md   ← File-by-file analysis
    ├── CHANGELOG.md               ← Session changes
    ├── CODING_SUMMARY.md          ← Lines/files summary
    │
    ├── config/
    │   └── settings.py            ← Pydantic settings (LLM, scan, auth, report, hunters)
    │
    ├── core/                      ← 4-phase pipeline core
    │   ├── planner.py             ← Master orchestrator (Recon → Hunt → Exploit → Report)
    │   ├── recon.py               ← ReconAgent (DNS, ports, tech, crawl → AttackSurface)
    │   ├── exploit.py             ← ExploitAgent (validate with proof)
    │   ├── reporter.py            ← JSON/HTML/PDF report
    │   └── vuln_hunters/          ← 16 hunters
    │       ├── base.py            ← BaseHunter, HunterResult
    │       ├── sqli.py, xss.py, auth.py, ssrf.py, lfi.py
    │       ├── ssti.py, rce.py, xxe.py, open_redirect.py, cors.py, csrf.py
    │       ├── subdomain_takeover.py, graphql.py, race_condition.py
    │       ├── deserialization.py, http_smuggling.py
    │       └── __init__.py        ← HUNTER_REGISTRY, ALL_HUNTERS
    │
    ├── src/                       ← Coordinator/Solver + Swarm
    │   ├── agent/
    │   │   ├── coordinator.py     ← Attack matrix, parallel Solvers
    │   │   ├── solver.py          ← 80-iter framework-less SolverAgent
    │   │   └── swarm/             ← Planner, Recon, InitAccess, Summary (swarm agents)
    │   ├── graph/
    │   │   └── swarm.py           ← create_dynamic_swarm(), compile graph
    │   ├── tools/
    │   │   ├── hunter_tools.py    ← @tool wrappers (run_sqli_hunter, run_xss_hunter, ...)
    │   │   ├── jit_engine.py      ← Sandboxed Python executor for agent
    │   │   ├── oob_server.py      ← InteractSH/OOB for blind vuln
    │   │   └── handoff.py         ← Re-export handoff (swarm)
    │   ├── prompts/
    │   │   └── prompt_loader.py   ← load_prompt(agent_name, mode)
    │   └── utils/
    │       ├── memory.py          ← Shared InMemoryStore (swarm)
    │       ├── mcp/               ← Re-export MCP loader
    │       └── swarm/             ← Re-export swarm
    │
    ├── tools/                     ← HTTP, crawl, payloads, browser, scan, mutation
    │   ├── http_client.py         ← Async HTTP + AuthConfig
    │   ├── crawler.py             ← BFS crawl + Playwright JS
    │   ├── payload_manager.py     ← Payload DB + WAF bypass
    │   ├── scanner.py             ← Port scan, DNS
    │   ├── browser.py             ← Playwright headless (exploit PoC)
    │   ├── mutation_engine.py      ← 100+ mutations (SQLi, XSS, LFI, SSRF, Auth)
    │   └── adaptive_engine.py     ← ProbeEngine + AdaptiveEngine (feedback loop)
    │
    ├── llm/                       ← LLM integration
    │   ├── engine.py              ← OpenAI / Ollama / Anthropic / OpenRouter
    │   ├── payload_generator.py   ← AIPayloadGenerator, BinarySearchExtractor
    │   ├── config_manager.py      ← MemoryConfigManager (swarm)
    │   ├── models.py, selection.py, openrouter.py
    │   └── local_config.json, cloud_config.json
    │
    ├── models/                    ← Data structures
    │   ├── target.py              ← Target, AttackSurface, Endpoint, TechnologyStack
    │   ├── vulnerability.py       ← VulnType, VulnHypothesis, ValidatedVuln
    │   └── report.py              ← Report, Finding, Evidence, ScanMetadata
    │
    ├── utils/                    ← Logger, validators, MCP loader
    │   ├── logger.py, validators.py
    │   └── mcp/mcp_loader.py      ← load_mcp_tools(agent_name)
    │
    ├── prompts/                   ← System prompts, personas, swarm, hunters
    │   ├── system.py, core_agents.py
    │   ├── base/, swarm/, personas/, hunters/, shared/
    │   └── pipeline-testing/
    │
    ├── engine/                    ← Optional (tool, messages)
    │
    └── packages/
        └── xlayer_hunter/         ← Sub-package (swarm utils, handoff, optional Kali/tools)
            ├── utils/swarm/       ← swarm.py, handoff.py (create_swarm, create_handoff_tool)
            ├── core/, models/, tools/, llm/, config/
            └── README.md
```

---

## 3. पूरा फ्लो — के कसरी चल्छ (End-to-End Flow)

1. **User:** `python -m xlayer_ai scan https://target.com` (वा `--hunters sqli,xss`, `--depth 3`, `--output ./reports`)
2. **main.py** → Click CLI → **PlannerAgent** (core/planner.py) लाई बोलाउँछ।
3. **Phase 1 — Recon:** ReconAgent (core/recon.py) → DNS, port scan, tech fingerprint, WebCrawler (static + JS) → **AttackSurface** (endpoints, forms, API, auth, technology).
4. **Phase 2 — Hunt:** settings को 16 hunters (वा selected) parallel चल्छ। प्रत्येक hunter AttackSurface लिएर आ-आफ्नो vuln type को लागि payloads पठाउँछ, response analyze गर्छ, AdaptiveEngine/MutationEngine/AI use गर्छ → **VulnHypothesis[]**।
5. **Phase 3 — Exploit (दुई तरिका):**
   - **Traditional:** ExploitAgent (core/exploit.py) — HIGH confidence hypotheses लाई real exploit + browser evidence → **ValidatedVuln[]**।
   - **Agentic path:** Coordinator (src/agent/coordinator.py) → attack matrix build → parallel SolverAgent (src/agent/solver.py) — 80 iterations, hunter_tools + JIT + OOB → confidence ≥ 0.72 लाई **ValidatedVuln[]**।
6. **Phase 4 — Report:** Reporter (core/reporter.py) → **report.json**, **report.html**, (optional) **report.pdf** — findings, CVSS, PoC, remediation।

**Alternative flow (Swarm):** main बाट swarm पनि चलाउन सकिन्छ — Planner, Recon, InitAccess, Summary agents; handoff tools; MCP tools; shared memory। यो flow अलग entry point वा integration मा use हुन सक्छ।

---

## 4. मुख्य Components को सूची (Quick Reference)

| Category | Components |
|----------|------------|
| **Agents** | PlannerAgent, ReconAgent, ExploitAgent, Coordinator, SolverAgent; Swarm: Planner, Recon, InitAccess, Summary |
| **Hunters** | sqli, xss, auth, ssrf, lfi, ssti, rce, xxe, open_redirect, cors, csrf, subdomain_takeover, graphql, race_condition, deserialization, http_smuggling |
| **Tools** | HTTPClient, WebCrawler, PayloadManager, PortScanner, HeadlessBrowser, MutationEngine, AdaptiveEngine, JITEngine, OOBServer, hunter_tools |
| **LLM** | LLMEngine, AIPayloadGenerator, MemoryConfigManager |
| **Models** | Target, AttackSurface, Endpoint, VulnHypothesis, ValidatedVuln, Report, Finding |
| **Config** | Settings (Pydantic), mcp_config.json, .env |

---

## 5. कुन फाइल कहाँ पढ्ने (Where to Read What)

| के जान्न चाहन्छ | फाइल |
|------------------|------|
| पूरा प्रोजेक्ट एकै ठाउँमा | **PROJECT_WHOLE_OVERVIEW.md** (यही फाइल) |
| Architecture, pipeline, AI/mutation detail | **XLAYER_REPORT.md** |
| हरेक फाइल को role र details | **xlayer_ai/FILE_ANALYSIS_DETAILS.md** |
| कति लाइन/फाइल कोड छ | **xlayer_ai/CODING_SUMMARY.md** |
| Package use कसरी गर्ने | **xlayer_ai/README.md** |
| Session-by-session changes | **xlayer_ai/CHANGELOG.md** |

---

## 6. चलाउने तरिका (How to Run)

```bash
cd "XLAYER-HACKING CO/xlayer_ai"
pip install -r requirements.txt
# .env मा XLAYER_* set गर्नुहोस् (वा .env.example copy)

# Scan
python -m xlayer_ai scan https://example.com
python -m xlayer_ai scan https://example.com --hunters sqli,xss,auth --depth 3 --output ./reports

# Config
python -m xlayer_ai config --show
```

---

## 7. सार (Summary)

- **XLAYER-HACKING CO** = project folder; **xlayer_ai** = main package।
- **4-phase pipeline:** Recon → Hunt (16 hunters) → Exploit (traditional वा Coordinator→Solvers agentic path) → Report।
- **Agentic path:** Coordinator (attack matrix) + SolverAgent (80-iter, JIT + OOB + hunter tools); confidence ≥ 0.72 = validated।
- **Swarm:** Multi-agent (Planner, Recon, InitAccess, Summary) + handoff + MCP + memory।
- **Philosophy:** NO EXPLOIT = NO REPORT; सबै finding को proof छ।
- **Docs:** XLAYER_REPORT.md (system), FILE_ANALYSIS_DETAILS.md (files), CODING_SUMMARY.md (stats), README.md (usage)।

यही सबै मिलेर **XLAYER-HACKING CO** प्रोजेक्टको पूरा picture बन्छ।

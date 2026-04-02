# XLayer AI — Autonomous Web Vulnerability Hunter

> "Hack before hackers hack — Prove before you report"

XLayer AI is an autonomous web vulnerability hunting platform.
It identifies, validates, and exploits security vulnerabilities using a
**4-Phase Pipeline + Framework-less Agentic Solver** architecture.

---

## Core Philosophy

**NO EXPLOIT = NO REPORT**

XLayer AI only reports vulnerabilities that have been successfully exploited.
This eliminates false positives and provides proof-of-concept for every finding.

---

## Architecture — Full System

```
┌──────────────────────────────────────────────────────────────────────┐
│                        XLayer AI — Agentic Solver                      │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  User Input: URL ──► main.py (CLI)                                   │
│                            │                                         │
│                            ▼                                         │
│          ┌─────────────────────────────────┐                         │
│          │   Phase 1: Recon                │                         │
│          │   core/recon.py                 │                         │
│          │   - DNS resolve + subdomains    │                         │
│          │   - Port scan (asyncio)         │                         │
│          │   - Tech stack fingerprint      │  → AttackSurface        │
│          │   - Web crawl + JS rendering    │                         │
│          │   - Forms, APIs, auth endpoints │                         │
│          └──────────────┬──────────────────┘                         │
│                         │                                            │
│                         ▼                                            │
│          ┌─────────────────────────────────┐                         │
│          │   Phase 2: Vuln Hunt (Parallel) │                         │
│          │   core/vuln_hunters/            │                         │
│          │                                 │  → VulnHypothesis[]     │
│          │   16 Hunters running parallel   │                         │
│          └──────────────┬──────────────────┘                         │
│                         │                                            │
│                         ▼                                            │
│          ┌─────────────────────────────────┐                         │
│          │   Phase 3: Agentic Exploit       │                         │
│          │                                 │                         │
│          │   Coordinator (coordinator.py)  │                         │
│          │   - Build attack matrix         │                         │
│          │   - Priority sort               │                         │
│          │   - Parallel dispatch           │                         │
│          │        │                        │                         │
│          │        ├── Solver #1 (sqli)     │                         │
│          │        ├── Solver #2 (xss)      │  80 iterations each     │
│          │        ├── Solver #3 (ssti)     │  JIT + OOB + hunters    │
│          │        ├── Solver #4 (ssrf)     │  confidence scoring     │
│          │        └── Solver #5 (rce) ...  │                         │
│          │                                 │  → ValidatedVuln[]      │
│          └──────────────┬──────────────────┘                         │
│                         │                                            │
│                         ▼                                            │
│          ┌─────────────────────────────────┐                         │
│          │   Phase 4: Report               │                         │
│          │   core/reporter.py              │                         │
│          │   - JSON / HTML / PDF           │                         │
│          │   - CVSS scores                 │                         │
│          │   - PoC (curl, Python script)   │                         │
│          │   - Remediation guidance        │                         │
│          └─────────────────────────────────┘                         │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

---

## Agentic Solver — Framework-less Exploit Loop

Each Solver is an **80-iteration agentic loop** — no fixed path, LLM decides each step:

```
SolverTask (endpoint, vuln_type)
    │
    ▼
[Iteration 1..80]
    LLM sees: target + all previous results
    LLM decides:
        ├─ call hunter tool   (run_sqli_hunter, run_xss_hunter ...)
        ├─ call http_probe    (custom request with specific payload)
        ├─ run JIT code       (write Python → execute in sandbox)
        ├─ check OOB callback (blind SQLi/SSRF/XSS via InteractSH)
        └─ stop_found / stop_not_found
    │
    Confidence score updated each iteration:
        < 0.35  → pivot strategy (new approach)
        0.35–0.72 → refine (escalate payloads)
        ≥ 0.72  → FOUND → report
```

---

## Vulnerability Coverage — 16 Hunters

### Original 5 Hunters
| Hunter | Detects | Detection Method |
|--------|---------|-----------------|
| **sqli** | SQL Injection | Error-based, Boolean blind, Time-based, Union |
| **xss** | Cross-Site Scripting | Reflected, Stored, DOM |
| **auth** | Auth Bypass, IDOR, Session | Default creds, JWT none, session fixation |
| **ssrf** | Server-Side Request Forgery | Cloud metadata, internal network, protocol bypass |
| **lfi** | Local File Inclusion | Path traversal, PHP wrappers, log poisoning |

### Additional 11 Hunters
| Hunter | Detects | Detection Method |
|--------|---------|-----------------|
| **ssti** | Template Injection | `{{7*7}}→49` math eval across 8 engines |
| **rce** | Command Injection | Time-based sleep, echo reflection, output |
| **xxe** | XML External Entity | File read, SSRF, error patterns, OOB |
| **open_redirect** | Unvalidated Redirect | Location header, 18 bypass techniques |
| **cors** | CORS Misconfiguration | Origin reflection, null, wildcard+creds |
| **csrf** | Cross-Site Request Forgery | Token absent, token bypass tests |
| **subdomain_takeover** | Dangling DNS | 20+ cloud service fingerprints |
| **graphql** | GraphQL Issues | Introspection, batch, depth, injection |
| **race_condition** | TOCTOU Races | N parallel requests, multiple success detect |
| **deserialization** | Insecure Deser. | Magic bytes, error patterns, pickle timing |
| **http_smuggling** | Request Smuggling | CL.TE, TE.CL, TE.TE timing probes |

---

## Tools Layer

| Tool | Purpose |
|------|---------|
| `src/tools/jit_engine.py` | Sandbox Python executor — agent writes + runs custom exploit code |
| `src/tools/oob_server.py` | Blind detection — InteractSH cloud + local HTTP fallback |
| `src/tools/hunter_tools.py` | `@tool` wrappers for all hunters |
| `tools/adaptive_engine.py` | 4-phase feedback: static→WAF mutations→AI round 1→AI round 2 |
| `tools/mutation_engine.py` | 100+ mutations across 5 vuln types, priority-sorted |
| `tools/payload_manager.py` | YAML payload DB + WAF detection (7 WAFs) |
| `tools/crawler.py` | Web crawler + JS rendering (Playwright) |
| `tools/http_client.py` | Async HTTP client + auth support |
| `tools/scanner.py` | Async port scanner (10-20x faster than nmap) |
| `tools/browser.py` | Playwright headless browser |

---

## Installation

```bash
# Clone and enter project
cd "xlayer-ai/XLAYER-HACKING CO/xlayer_ai"

# Create virtual environment
python -m venv venv
source venv/bin/activate       # Linux/Mac
.\venv\Scripts\activate        # Windows

# Install dependencies
pip install -r requirements.txt

# Install Playwright browsers (for JS rendering)
playwright install chromium

# Configure environment
cp .env.example .env
# Edit .env with your API keys and settings
```

---

## Usage

### Basic Scan
```bash
python -m xlayer_ai scan https://target.com
```

### With Options
```bash
# Specific hunters only
python -m xlayer_ai scan https://target.com --hunters sqli,xss,ssti

# Custom depth and output
python -m xlayer_ai scan https://target.com --depth 2 --output ./my-reports

# Skip exploitation (hypothesis only — faster)
python -m xlayer_ai scan https://target.com --no-exploit

# Adjust rate limiting
python -m xlayer_ai scan https://target.com --rate-limit 1.0

# All 16 hunters (default)
python -m xlayer_ai scan https://target.com --hunters all
```

### View Config
```bash
python -m xlayer_ai config --show
python -m xlayer_ai hunters
```

---

## Configuration (.env)

```bash
# LLM Provider
XLAYER_LLM__PROVIDER=openai          # openai | ollama | anthropic
XLAYER_LLM__API_KEY=your-key
XLAYER_LLM__MODEL=gpt-4o-mini

# Scan Settings
XLAYER_SCAN__MAX_DEPTH=3
XLAYER_SCAN__MAX_PAGES=100
XLAYER_SCAN__RATE_LIMIT=0.5
XLAYER_SCAN__JS_RENDERING=true       # Enable Playwright

# Enabled Hunters (all 16)
XLAYER_HUNTERS=sqli,xss,auth,ssrf,lfi,ssti,rce,xxe,open_redirect,cors,csrf,subdomain_takeover,graphql,race_condition,deserialization,http_smuggling

# Exploitation
XLAYER_EXPLOIT__MAX_ATTEMPTS=3
XLAYER_EXPLOIT__SCREENSHOT=true

# Authentication (for protected targets)
XLAYER_AUTH__ENABLED=false
XLAYER_AUTH__LOGIN_URL=https://target.com/login
XLAYER_AUTH__USERNAME=testuser
XLAYER_AUTH__PASSWORD=testpass
```

---

## Project Structure

```
xlayer_ai/
│
├── main.py                          # CLI entry point (Click)
├── README.md                        # This file
├── FILE_ANALYSIS_DETAILS.md         # Full file-by-file analysis
├── CHANGELOG.md                     # All changes by session
├── requirements.txt
├── .env.example
│
├── config/
│   ├── settings.py                  # Pydantic settings (all config)
│   └── payloads/                    # YAML payload files
│       ├── sqli.yaml
│       ├── xss.yaml
│       └── ...
│
├── core/                            # Original pipeline
│   ├── planner.py                   # Master orchestrator (4-phase)
│   ├── recon.py                     # ReconAgent — DNS, ports, tech, crawl
│   ├── exploit.py                   # ExploitAgent — basic validation
│   ├── reporter.py                  # JSON/HTML/PDF report generation
│   └── vuln_hunters/                # All 16 hunters
│       ├── base.py                  # BaseHunter + HunterResult
│       ├── __init__.py              # HUNTER_REGISTRY (all 16)
│       ├── sqli.py                  # SQL Injection
│       ├── xss.py                   # Cross-Site Scripting
│       ├── auth.py                  # Auth Bypass / IDOR
│       ├── ssrf.py                  # Server-Side Request Forgery
│       ├── lfi.py                   # Local File Inclusion
│       ├── ssti.py          [NEW]   # Server-Side Template Injection
│       ├── rce.py           [NEW]   # Remote Code Execution
│       ├── xxe.py           [NEW]   # XML External Entity
│       ├── open_redirect.py [NEW]   # Open Redirect
│       ├── cors.py          [NEW]   # CORS Misconfiguration
│       ├── csrf.py          [NEW]   # CSRF
│       ├── subdomain_takeover.py [NEW] # Subdomain Takeover
│       ├── graphql.py       [NEW]   # GraphQL Injection
│       ├── race_condition.py [NEW]  # Race Condition
│       ├── deserialization.py [NEW] # Insecure Deserialization
│       └── http_smuggling.py [NEW]  # HTTP Request Smuggling
│
├── src/                             # Coordinator/Solver + Swarm
│   ├── agent/
│   │   ├── __init__.py
│   │   ├── coordinator.py   [NEW]   # Attack matrix + parallel dispatch
│   │   ├── solver.py        [NEW]   # 80-iter framework-less exploit loop
│   │   └── swarm/
│   │       ├── Planner.py           # Planner agent
│   │       ├── Recon.py             # Recon agent
│   │       ├── InitAccess.py        # InitAccess agent
│   │       └── Summary.py           # Summary agent
│   ├── tools/
│   │   ├── __init__.py
│   │   ├── handoff.py               # Handoff tools
│   │   ├── hunter_tools.py  [NEW]   # @tool wrappers for all hunters
│   │   ├── jit_engine.py    [NEW]   # Sandboxed Python JIT executor
│   │   └── oob_server.py    [NEW]   # InteractSH OOB blind detection
│   ├── graph/
│   │   └── swarm.py                 # Swarm graph builder
│   ├── prompts/
│   │   └── prompt_loader.py         # Agent prompt loading
│   └── utils/
│       ├── memory.py                # InMemoryStore (swarm)
│       ├── llm/
│       │   └── config_manager.py
│       ├── mcp/
│       │   └── mcp_loader.py
│       └── swarm/
│           └── swarm.py
│
├── tools/                           # Core tools layer
│   ├── http_client.py               # AsyncHTTPClient + AuthConfig
│   ├── crawler.py                   # WebCrawler + JS rendering
│   ├── payload_manager.py           # YAML payload DB + WAF detection
│   ├── adaptive_engine.py           # AdaptiveEngine + ProbeEngine
│   ├── mutation_engine.py           # 100+ mutations (5 vuln types)
│   ├── browser.py                   # Playwright headless
│   └── scanner.py                   # Async port scanner
│
├── llm/                             # LLM layer
│   ├── engine.py                    # OpenAI/Ollama/Anthropic interface
│   ├── payload_generator.py         # AIPayloadGenerator + AttackContext
│   ├── models.py
│   ├── config_manager.py
│   ├── selection.py
│   └── openrouter.py
│
├── models/                          # Data models
│   ├── target.py                    # AttackSurface, Endpoint, Parameter
│   ├── vulnerability.py             # VulnType(16), VulnHypothesis, ValidatedVuln
│   └── report.py                    # Report, Finding
│
├── utils/
│   ├── logger.py
│   └── validators.py
│
└── packages/
    └── xlayer_hunter/
        ├── tools/
        │   └── kali_executor.py     # Docker Kali tools (optional)
        └── utils/
            └── swarm/
                ├── swarm.py         # create_swarm, SwarmState
                └── handoff.py       # create_handoff_tool
```

---

## Output Formats

XLayer AI generates professional reports:

| Format | Contents |
|--------|---------|
| **JSON** | Machine-readable, all findings + evidence |
| **HTML** | Interactive dashboard, screenshots, CVSS |
| **PDF** | Client-ready presentation (optional) |

Each finding includes:
- CVSS 3.1 score + vector
- Proof-of-concept (curl command + Python script)
- Screenshots (if exploit used browser)
- Remediation guidance
- OWASP category reference

---

## WAF Support

Automatic detection and bypass for:
`Cloudflare` `AWS WAF` `Akamai` `Imperva` `ModSecurity` `Sucuri` `F5`

---

## Legal Disclaimer

XLayer AI is intended for **authorized security testing only**.
Always obtain proper written authorization before scanning any target.
Unauthorized access to computer systems is illegal.

---

## License

MIT License — See LICENSE file for details.

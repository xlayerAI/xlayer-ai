# XLayer AI — Target (जस्तै xyc.com) दिँदा पूरा प्रक्रिया र क्षमता विश्लेषण

यो दस्तावेजमा **एउटा target (जस्तै xyc.com वा https://xyc.com)** दिँदा सिस्टमले **के–के गर्छ**, **कस्तो level** मा काम गर्छ, र **कति सक्षम** छ भन्ने **गहिरो विश्लेषण** राखिएको छ।

---

## १. टार्गेट कसरी दिने र के हुन्छ (Entry Point)

### कमान्ड

```bash
xlayer-ai scan https://xyc.com
# वा
python -m xlayer_ai scan https://xyc.com
```

### Optional flags

- `--hunters sqli,xss,lfi` — केवल यी hunters चलाउने (नभए सबै)
- `--depth 3` — क्रॉल गहिराइ (default 3)
- `--no-exploit` — exploit/verify चलाउँदैन, hunt मात्र
- `--no-port-scan` — port scan बन्द
- `--timeout 30`, `--rate-limit 0.5` — HTTP behaviour

### पहिलो चरण (main.py)

1. **URL validate** — `validate_url(target_url)` ले सही URL हो कि जाँच्छ।
2. **Settings load** — `get_settings()` बाट config (scan, report, LLM, port_scan, exploit, ...)。
3. **PlannerAgent** context manager सँग start:
   - HTTP client (timeout, rate_limit, user_agent, SSL)
   - PayloadManager load
   - LLM enable भए: LLMEngine init (optional)
4. **`planner.start_mission(target, hunters=hunters)`** एकै ठूलो async call — यही भित्र **चार phase** चल्छ।

त्यसैले **xyc.com (वा कुनै पनि target)** दिँदा सुरु भनेको:  
**validate → settings → PlannerAgent → start_mission(target)**।  
यसपछि सबै process **Planner** भित्रै Phase 1 → 2 → 3 → 4 मा handle हुन्छ।

---

## २. Phase-by-Phase — के–के हुन्छ (Step by step)

### Phase 1: RECON (Reconnaissance)

**Goal:** Target को attack surface map गर्नु (URL, endpoints, tech, ports)。

| Step | के हुन्छ | कसरी handle गर्छ |
|------|----------|-------------------|
| 1 | **Target parse** | `urlparse(target_url)` → hostname, scheme |
| 2 | **DNS resolve** | `get_dns_records(hostname)` → A (र अरू records) |
| 3 | **Port scan** (optional) | `PortScanner.scan_ports(ip, top_n=100)` — open ports र services |
| 4 | **Initial HTTP GET** | Target URL मा request — status, headers, body |
| 5 | **Technology detection** | Headers, cookies, body मा regex (TECH_SIGNATURES) — server, language, framework, WAF, CDN |
| 6 | **robots.txt** | Fetch र store |
| 7 | **Sitemap** | Fetch sitemap, URLs extract |
| 8 | **Web crawl** | `WebCrawler.crawl()` — links, forms, API-like URLs; max_depth, max_pages अनुसार |
| 9 | **Auth endpoints** | login/signin/auth जस्ता path भएका endpoints list |
| 10 | **AttackSurface build** | सबै endpoints, forms, tech_stack, open_ports, testable_endpoints र score |

**Output:** `AttackSurface` — target, endpoints, technology, open_ports, testable_endpoints, attack_surface_score।  
यो **Phase 2 र 3** को input बन्छ।

---

### Phase 2: VULN_HUNT (Vulnerability Hunting)

**Goal:** Attack surface मा प्रत्येक configured hunter ले vulnerability **hypotheses** (HIGH/MEDIUM/LOW) बनाउनु।

| Step | के हुन्छ | कसरी handle गर्छ |
|------|----------|-------------------|
| 1 | **Hunters select** | Settings र recon अनुसार (e.g. auth endpoint नभए auth hunter skip) |
| 2 | **Hunter instances** | `HUNTER_REGISTRY` बाट (sqli, xss, auth, ssrf, lfi, ssti, rce, xxe, open_redirect, cors, csrf, graphql, race_condition, deserialization, http_smuggling, subdomain_takeover) |
| 3 | **Parallel run** | `run_hunters_parallel(hunters, attack_surface)` — सबै hunters एकै पटक attack_surface मा |
| 4 | **Hypotheses collect** | प्रत्येक hunter को `HunterResult.hypotheses` — endpoint, parameter, vuln_type, confidence (HIGH/MEDIUM/LOW) |
| 5 | **Context update** | `context.hypotheses`, `context.requests_made` |

**Output:** `context.hypotheses` — list of `VulnHypothesis` (endpoint, param, vuln_type, confidence)।  
**Phase 3** ले केवल **HIGH र MEDIUM** लाई verify गर्छ।

---

### Phase 3: EXPLOIT (Validation — NO EXPLOIT = NO REPORT)

**Goal:** Hypothesis लाई **real exploit** गरेर **proof** लिनु। Proof नभएको finding report मा आउँदैन।

| Step | के हुन्छ | कसरी handle गर्छ |
|------|----------|-------------------|
| 1 | **Filter** | HIGH + MEDIUM confidence hypotheses मात्र |
| 2 | **ExploitAgent** | HTTP + HeadlessBrowser सँग प्रत्येक hypothesis को लागि payload try |
| 3 | **Verify** | `exploit.verify_all(hypotheses)` — actual request गरेर response मा vulnerability confirm (e.g. SQL error, XSS reflection, redirect) |
| 4 | **ValidatedVuln** | Proof भएको मात्र `ValidatedVuln` (severity, payload_used, evidence) |
| 5 | **False positive reduce** | Verify fail भएको hypothesis report मा जाँदैन |

**नोट:** अहिले **main pipeline** मा **Coordinator + Solver (agentic/JIT path)** integrate भएको छैन। तैपनि code मा Coordinator, SolverAgent, JIT, OOB server सबै छ — integrate गर्दा Phase 3 मा attack matrix → parallel Solver (LLM + tools + JIT) चलेर पनि validated vulns बन्छ। (See `COORDINATOR_INTEGRATION_WHAT_HAPPENS.md`.)

**Output:** `context.validated_vulns` — list of `ValidatedVuln` (proven vulnerabilities only)。

---

### Phase 4: REPORT

**Goal:** Scan metadata + attack surface + validated vulns बाट **report** generate गर्नु।

| Step | के हुन्छ | कसरी handle गर्छ |
|------|----------|-------------------|
| 1 | **Reporter** | `Reporter.generate(metadata, attack_surface, validated_vulns, hypotheses_count)` |
| 2 | **Report object** | overall_risk, findings (severity, title, endpoint, evidence), stats |
| 3 | **Export** | settings अनुसार JSON/HTML file (e.g. `./reports`) |

**Output:** `Report` — overall_risk, findings, stats। यही **main.py** ले table मा display गर्छ र file लेख्छ।

---

## ३. कुन Level मा काम गर्छ (Level of Operation)

| Level | के हो | XLayer AI मा |
|-------|--------|--------------|
| **Network** | DNS, ports, services | Recon: DNS resolve, port scan (top N ports), service detection |
| **Application (HTTP)** | URLs, forms, APIs, headers | Recon: crawl, forms, api_endpoints; Hunt: सबै hunters HTTP through; Exploit: HTTP + browser |
| **Input/Parameter** | Query, body, headers, cookies | Hunters: प्रत्येक endpoint/parameter मा vuln-type अनुसार payload; Exploit: same params मा proof |
| **Vulnerability class** | SQLi, XSS, Auth, SSRF, LFI, ... | 16 hunters + exploit verification per type |
| **Proof** | Real request/response | ExploitAgent: real HTTP + headless browser; (optional path) Solver + JIT + OOB for blind/novel |

सारांश:  
- **Recon** = network + app mapping (DNS, ports, tech, crawl).  
- **Hunt** = application-level, parameter-level, multi-vuln-type (16 classes).  
- **Exploit** = same level मा proof until “NO EXPLOIT = NO REPORT”.  
- **Orchestration** = single mission (one target), sequential phases; hunt parallel, exploit sequential per hypothesis.

---

## ४. System कसरी Handle गर्छ (Handling Summary)

- **Target string (xyc.com):**  
  URL normalize/validate → Recon को input; सबै phases ले same target/attack_surface use गर्छ।

- **Errors:**  
  MissionContext.errors मा collect; phase fail भए exception raise (mission fail); hunter/recon error ले बाँकी phase continue गर्न सक्छ (design अनुसार)。

- **Scale:**  
  Endpoints धेरै भए: hunt parallel (sabai hunters), exploit एकै पटक मा multiple hypotheses तर agent एक; Coordinator integrate भए: matrix cap (e.g. 50 tasks), max parallel solvers (e.g. 5)。

- **Config:**  
  Settings (scan depth, timeout, rate_limit, hunters, report path, LLM, port_scan, exploit on/off) सबै single target scan लाई control गर्छ।

---

## ५. क्षमता विश्लेषण (Capability Assessment)

### के–के मजबुत छ

| क्षमता | विवरण |
|--------|--------|
| **Recon** | DNS, port scan, tech detection, crawl, forms, auth endpoints — attack surface राम्ररी map हुन्छ। |
| **Hunter coverage** | 16 vuln types (SQLi, XSS, Auth, SSRF, LFI, SSTI, RCE, XXE, open redirect, CORS, CSRF, GraphQL, race, deserialization, HTTP smuggling, subdomain takeover)। |
| **Proof-based report** | NO EXPLOIT = NO REPORT — false positive कम। |
| **Exploit path** | HTTP + headless browser ले real verification। |
| **Agentic path (code ready)** | Coordinator + Solver + JIT + OOB — blind/novel exploit र parallel solver; pipeline मा wire गर्न सकिन्छ। |
| **Adaptive engine** | ProbeEngine (WAF, filters, time/boolean) र AI payload generator — context-aware payload। |

### के–के सीमित छ

| सीमितता | विवरण |
|---------|--------|
| **Orchestrator (engine/orchestrator.py)** | अलग “consciousness loop” — placeholder actions (discover_endpoints_and_tech, test_auth_bypass, …) mock data; **main scan flow सँग integrate छैन**। |
| **Coordinator in main flow** | Phase 3 मा अहिले **ExploitAgent मात्र**; Coordinator optional (integration doc अनुसार)। |
| **Single target** | एकै पटक एक target (xyc.com); multi-target queue/parallel project-level छैन। |
| **Depth/limits** | Crawl depth, max_pages, matrix cap (50), max_parallel_solvers (5) — ठूलो site मा partial coverage। |
| **LLM dependency** | Exploit/agentic path र payload generation को लागि LLM optional तर enable भएमा capability बढ्छ। |

### Overall capability (१–१० scale मा सोच्ने हो भने)

- **Recon:** ८ — DNS, ports, tech, crawl, forms सबै छ; subdomain enum / custom script जस्ता advanced recon limited।
- **Hunt:** ८ — 16 hunters, parallel, parameter-level; tuning र target-specific strategy को लागि LLM/strategy थप सकिन्छ।
- **Exploit (current):** ७ — HTTP + browser proof; JIT/OOB path add भए ८+।
- **Automation level:** ८ — एक कमान्ड मा recon → hunt → exploit → report; human only target input र config।
- **Scalability:** ६ — एक target, bounded endpoints/matrix; distributed/multi-target नभएको।

---

## ६. xyc.com दिँदा Short Flow (एक नजर मा)

```
User: xlayer-ai scan https://xyc.com
  → validate URL
  → PlannerAgent.start_mission("https://xyc.com")

  Phase 1 RECON
    → DNS(xyc.com), port scan (if IP), GET homepage, tech detect, robots, sitemap, crawl
    → AttackSurface(endpoints, forms, tech, testable_endpoints)

  Phase 2 VULN_HUNT
    → 16 hunters parallel on AttackSurface
    → hypotheses (HIGH/MEDIUM/LOW) per endpoint/param/vuln_type

  Phase 3 EXPLOIT
    → HIGH/MEDIUM hypotheses → ExploitAgent.verify_all (HTTP + browser)
    → validated_vulns (proof भएको मात्र)

  Phase 4 REPORT
    → Report(metadata, findings, risk) → JSON/HTML

  → Display results table + save reports
```

---

## ७. निष्कर्ष

- **xyc.com (वा कुनै पनि URL)** दिँदा: **validate → Recon → Hunt (parallel) → Exploit (verify) → Report** — यही पूरा process एक mission भित्र चल्छ।
- **Handle:** एक target, sequential phases, recon/hunt output लाई अर्को phase को input को रूप मा use गर्छ; error context मा collect वा raise।
- **Level:** Network (DNS, ports), Application (HTTP, params), 16 vuln types, proof-based reporting।
- **Capable:** Recon र Hunt धेरै सक्षम; Exploit पनि proof-based; Coordinator/Solver/JIT code ready तर main pipeline मा optional। Integrate गरेर agentic path on गर्दा blind/novel exploit र parallel validation बढी सक्षम हुन्छ।

यो दस्तावेज सिस्टमको **deep analysis** को लागि हो; implementation detail को लागि `COORDINATOR_INTEGRATION_WHAT_HAPPENS.md` र `XLAYER_REPORT.md` पनि हेर्नुहोस्।

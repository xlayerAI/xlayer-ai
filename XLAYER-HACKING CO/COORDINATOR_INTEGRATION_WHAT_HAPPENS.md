# Coordinator + XLayerLoop लाई main pipeline मा integrate गर्दा के हुन्छ?

यो दस्तावेजमा **integrate गर्दा flow के हुन्छ**, **फाइदा/नोट**, र **implementation को मुख्य कुरा** लेखिएको छ।

---

## 1. अहिले के हुन्छ (Current flow)

```
User: python -m xlayer_ai scan https://target.com
         │
         ▼
   Planner.start_mission()
         │
         ├─ Phase 1: Recon        → AttackSurface
         ├─ Phase 2: Hunt         → VulnHypothesis[] (16 hunters parallel)
         ├─ Phase 3: Exploit     → केवल ExploitAgent
         │                            │
         │                            ├─ HIGH/MEDIUM hypotheses लिन्छ
         │                            ├─ HeadlessBrowser + HTTP बाट proof लिन्छ
         │                            └─ ValidatedVuln[] फर्काउँछ
         │
         └─ Phase 4: Report       → report.json / report.html
```

- **Phase 3** मा **Coordinator र XLayerLoop** कहीं पनि use हुँदैन। केवल **ExploitAgent** (browser + HTTP) ले verify गर्छ।

---

## 2. Integrate गर्दा के हुन्छ (After integration)

### Option A: Agentic path ON (use_agentic_exploit = True)

Phase 3 मा **पहिले Coordinator + XLayerLoop** चल्छ, त्यसपछि (optional) ExploitAgent पनि चलाउन सकिन्छ।

```
Phase 3: Exploit
    │
    ├─ 1) Attack matrix बन्छ
    │      • AttackSurface (endpoints) + Hunter hypotheses बाट
    │      • (endpoint_url, parameter, method, vuln_type) को list — max 50 tasks
    │
    ├─ 2) OOB server start हुन्छ (InteractSH) — blind vuln को लागि
    │
    ├─ 3) प्रत्येक task को लागि एक SolverAgent (XLayerLoop) चल्छ:
    │      • 80 iterations सम्म
    │      • Tools: run_sqli_hunter, run_xss_hunter, ... (hunter_tools) + JIT + http_probe
    │      • LLM हरेक iteration मा decide गर्छ: कुन tool call गर्ने, के JIT code लेख्ने, OOB check गर्ने, वा conclude
    │      • Confidence ≥ 0.72 भए → FOUND → proof + working_payload
    │
    ├─ 4) Parallel: 5 वा configurable ओटा Solver एकै पटक चल्छन् (MAX_PARALLEL_SOLVERS)
    │
    ├─ 5) Coordinator को result (dict list) लाई ValidatedVuln मा convert गरिन्छ
    │
    └─ 6) self._context.validated_vulns = यही list → Phase 4 Report मा जान्छ
```

**नतिजा:**

- **JIT**: LLM ले आफैँ Python exploit script लेखेर sandbox मा run गर्छ — novel payload वा multi-step attack।
- **OOB**: Blind SQLi/SSRF/XSS को लागि InteractSH callback; confirmation बिना guess मात्र रिपोर्ट गर्दैन।
- **Hunter tools**: Solver ले सीधा run_sqli_hunter, run_xss_hunter आदि call गर्छ — फेरि payload try गर्न सक्छ।
- **Auto-pivot**: 3 iteration को लागि confidence नबढेमा strategy बदलिन्छ।
- **Proof**: confidence ≥ 0.72 र proof/working_payload भएको मात्र ValidatedVuln बन्छ; बाँकी report मा आउँदैन (NO EXPLOIT = NO REPORT)।

---

## 3. फाइदा (Benefits)

| कुरा | अहिले (ExploitAgent only) | Integrate पछि |
|------|----------------------------|----------------|
| Proof | Browser + HTTP मात्र | Browser/HTTP + **JIT + OOB + hunter re-run** |
| Blind vuln | सीमित | OOB बाट confirm गर्न सकिन्छ |
| Novel payload | Fixed payloads / AI generator | **LLM ले JIT code लेखेर** नयाँ pattern try गर्छ |
| Coverage | HIGH/MEDIUM hypotheses मात्र | Attack matrix बाट **बढी (endpoint × vuln_type)** tasks; hunter hit नभएको endpoint पनि test हुन सक्छ |
| False positive | कम | **Confidence threshold (0.72)** र proof बाट फेरि कम |

---

## 4. ध्यान दिने कुरा (Considerations)

- **समय**: प्रति task 80 iterations + LLM call; parallel 5 भए पनि ठूलो target मा Phase 3 लामो हुन सक्छ। Matrix cap (50) ले limit छ।
- **LLM**: Coordinator/Solver ले **engine.llm.LLMClient** (OpenAI/Anthropic direct) use गर्छ। Planner ले **llm.engine.LLMEngine** use गर्छ। Integrate गर्दा Planner बाट **LLMClient** बनाएर Coordinator लाई दिनुपर्छ (वा एउटा shared LLM adapter)。
- **Output format**: Coordinator को `run()` ले **List[Dict]** फर्काउँछ; Reporter लाई **List[ValidatedVuln]** चाहिन्छ। त्यसैले **dict → ValidatedVuln** convert (minimal VulnHypothesis, VulnType, severity, payload_used, evidence) गर्ने helper चाहिन्छ।
- **ExploitAgent सँग merge**: Optional — HIGH confidence को लागि browser proof पनि लिन चाहन्छ भने पहिले Coordinator चलाएर validated list बनाउने, त्यसपछि केही को लागि ExploitAgent पनि चलाएर दुवैको result merge गर्न सकिन्छ।

---

## 5. Merge कसरी गर्ने (How to merge)

दुई कुरा छन्: **(१) Coordinator को dict list लाई ValidatedVuln मा convert**, **(२) ExploitAgent को list सँग merge (dedupe)**।

### 5.1 Coordinator result → ValidatedVuln

**Module:** `xlayer_ai.core.coordinator_result`

- **`coordinator_results_to_validated_vulns(raw_list)`**  
  Coordinator.run() को return (List[Dict]) लाई List[ValidatedVuln] मा बदल्छ।  
  केवल `found=True` र `confidence >= 0.72` भएको entry लिन्छ।  
  प्रत्येक dict बाट VulnHypothesis (minimal) र ValidatedVuln (severity, cvss_score, payload_used, evidence, execution_method="agentic_solver") बनाउँछ।

- **`coordinator_result_to_validated_vuln(raw)`**  
  एउटा dict लाई एउटा ValidatedVuln मा convert गर्छ (single result को लागि)।

**उदाहरण (Planner._phase_exploit मा):**

```python
from xlayer_ai.core.coordinator_result import coordinator_results_to_validated_vulns

# Coordinator चलाएपछि
raw_validated = await coordinator.run(attack_surface, hypotheses_as_dicts)
agentic_vulns = coordinator_results_to_validated_vulns(raw_validated)
```

### 5.2 ExploitAgent सँग merge (dedupe)

दुवै चलाएपछि — Coordinator को validated र ExploitAgent को validated — एउटै list मा राख्न र **एकै (endpoint, parameter, vuln_type)** दोहोरिएको भए एकचोटि मात्र राख्न।

**Module:** `xlayer_ai.core.coordinator_result`

- **`merge_validated_vulns(*lists, prefer="first")`**  
  धेरै List[ValidatedVuln] लाई एकै list मा जोड्छ र **(endpoint, parameter, vuln_type)** अनुसार dedupe गर्छ।  
  - **prefer="first"**: पहिलो list को entry राख्छ (जस्तै पहिले ExploitAgent, पछि Coordinator — browser proof प्राथमिकता)।  
  - **prefer="last"**: अन्तिम entry राख्छ (Coordinator को agentic result ले override गर्छ)।

**उदाहरण (Phase 3 मा दुवै चलाएर merge):**

```python
from xlayer_ai.core.coordinator_result import (
    coordinator_results_to_validated_vulns,
    merge_validated_vulns,
)

# 1) Coordinator (agentic) चलाउने
raw_from_coordinator = await coordinator.run(...)
agentic_list = coordinator_results_to_validated_vulns(raw_from_coordinator)

# 2) ExploitAgent (browser) चलाउने (optional)
async with ExploitAgent(...) as exploit:
    exploit_list = await exploit.verify_all(hypotheses_to_verify)

# 3) Merge — same (endpoint, param, vuln_type) को लागि एकचोटि मात्र; ExploitAgent को राख्न "first"
self._context.validated_vulns = merge_validated_vulns(
    exploit_list,
    agentic_list,
    prefer="first",
)
```

**केवल Coordinator (ExploitAgent बिना):**

```python
raw_from_coordinator = await coordinator.run(...)
self._context.validated_vulns = coordinator_results_to_validated_vulns(raw_from_coordinator)
```

**केवल ExploitAgent (अहिले जस्तै):**  
`self._context.validated_vulns = await exploit.verify_all(...)` — merge को आवश्यकता छैन।

---

## 6. Implementation को मुख्य कदम (Summary)

1. **Settings** मा `use_agentic_exploit: bool = True` (वा `XLAYER_USE_AGENTIC_EXPLOIT`) थप्ने।
2. **Planner._phase_exploit()** मा:
   - यदि `use_agentic_exploit`:
     - `engine.llm.LLMClient.from_settings()` (वा सम equivalent) बाट LLM client बनाउने।
     - `Coordinator(llm=client).run(attack_surface, hypotheses_as_dicts)` call गर्ने।
   - Coordinator को return (list of dicts) लाई **ValidatedVuln** मा convert गर्ने: `coordinator_results_to_validated_vulns(raw_list)` (core.coordinator_result).
   - `self._context.validated_vulns = converted_list` वा ExploitAgent को result सँग `merge_validated_vulns(exploit_list, agentic_list, prefer="first")`।
   - यदि `use_agentic_exploit` False: अहिले जस्तै केवल ExploitAgent।
3. **Helper**: `core/coordinator_result.py` मा `coordinator_results_to_validated_vulns(raw_list)` र `merge_validated_vulns(*lists, prefer="first")` use गर्ने। Coordinator dict बाट VulnHypothesis + ValidatedVuln construct यही module मा छ।

यो गर्दा **Coordinator + XLayerLoop** main pipeline मा integrate भई, हरेक scan मा agentic exploit path पनि चल्ने र report मा त्यसको validated findings आउने हुन्छ। Merge गर्दा **coordinator_result** module को function हरू नै use गर्ने।

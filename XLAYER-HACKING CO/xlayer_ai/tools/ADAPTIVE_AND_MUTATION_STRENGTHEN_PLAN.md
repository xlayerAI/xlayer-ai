# Adaptive + Mutation Engine — Stronger बनाउन के गर्नुपर्छ

दुवै engines लाई अलि अलि stronger बनाउनको लागि concrete action plan (priority order मा).

---

## Part A: Mutation Engine (`mutation_engine.py`)

### A1. Bug fix — LFI double-dot ले `payload` use गर्ने (Must)
- **समस्या:** `_lfi_double_dot_variants(payload)` मा `payload` use हुँदैन; सधैं same fixed path list return हुन्छ।
- **गर्ने:**  
  - यदि `payload` मा path जस्तो कुरा छ (e.g. `../index.php`, `file=config`) भने त्यसलाई base बनाएर double-dot variants generate गर्ने।  
  - वा कम्तीमा `payload` लाई prefix/suffix को रूपमा use गर्ने ताकि user दिएको path include हुन्छ।

### A2. Context safe — crash नआउन (Must)
- **समस्या:** `ctx.filtered_chars`, `ctx.keywords_filtered` etc. direct access; ctx मा field नभए AttributeError।
- **गर्ने:**  
  - `mutate()` को शुरुमा वा प्रत्येक `_*_mutations()` मा:  
    `filtered_chars = getattr(ctx, "filtered_chars", []) or []` जस्तो safe access।  
  - वा एक `_safe_ctx(ctx)` helper ले default values दिएर dict-like/object return गर्ने।

### A3. `ctx.waf` use — WAF-specific strategy (Should)
- **समस्या:** `ctx.waf` कहीं पनि use भएको छैन।
- **गर्ने:**  
  - जब `ctx.waf` set छ (e.g. `Cloudflare`, `ModSecurity`):  
    - Cloudflare: hex, unicode, double-encode जस्ता technique को priority बढाउने वा अरू कम गर्ने।  
    - ModSecurity: comment sandwich, space substitution, versioned comment priority बढाउने।  
  - एक `_priority_for_waf(technique, waf)` वा per-technique priority override (e.g. +1/-1) लागू गर्ने।

### A4. Limit र OOB configurable (Should)
- **समस्या:** `mutate_to_strings(..., limit=30)` hardcoded; बाहिरी domain (e.g. burpcollaborator) पनि hardcoded।
- **गर्ने:**  
  - Limit: settings/config वा env बाट `MUTATION_PAYLOAD_LIMIT` (default 50) पढ्ने।  
  - OOB domain: `ctx.oob_domain` वा config बाट placeholder replace गर्ने।

### A5. Open Redirect mutations (Should — hunters match)
- **समस्या:** Open Redirect को लागि dispatch र mutations छैनन्।
- **गर्ने:**  
  - `dispatch` मा `"open_redirect": self._open_redirect_mutations` थप्ने।  
  - `_open_redirect_mutations`: URL लाई double encode, `//evil.com`, `\/\/`, `https:evil.com`, subdomain trick, null byte, `@evil.com`, `?url=...` जस्ता variants।

### A6. EXTRACTVALUE मा original payload use (Nice)
- **समस्या:** `_extractvalue_variants(original)` ले `original` use गर्दैन।
- **गर्ने:** Original को quote style वा comment style match गरेर EXTRACTVALUE payloads generate गर्ने (e.g. `'` vs `"`, `--` vs `#`)。

---

## Part B: Adaptive Engine (`adaptive_engine.py`)

### B1. Mutation input — failed payloads पनि mutate गर्ने (Must)
- **समस्या:** WAF mutations को लागि **मात्र** `static_payloads[:5]` use हुन्छ; already failed (static + AI) payloads फेरि mutate गर्दैन।
- **गर्ने:**  
  - Phase 2 (mutations): input = `static_payloads[:5]` + (optional) **last N failed payloads** from `ctx.get_failed_payloads()` (e.g. last 10), dedupe।  
  - वा Phase 3 पछि एक "Phase 2b again": यदि कुनै success भएन भने, **failed payloads** लाई mutation engine मा पठाएर फेरि एक round mutations try गर्ने।  
  - यसले mutation engine को `get_failed_payloads()` को फाइदा पनि पूरा use गर्ने (already-tried skip हुन्छ engine भित्रै)।

### B2. `max_rounds` वास्तवमा use गर्ने वा हटाउने (Should)
- **समस्या:** `max_rounds=4` constructor मा छ तर `run()` मा use भएको छैन; total attempt cap छैन।
- **गर्ने:**  
  - Option A: Total attempts `max_rounds * (static + mutation_batch_size)` जस्तो cap लगाउने (वा max_rounds = max phases वा max retry rounds)।  
  - Option B: यदि design अनुसार चाहिँदैन भने parameter हटाउने वा comment मा "reserved" लेख्ने।

### B3. Vuln-type specific probes (Should)
- **समस्या:** Probe सधैं SQL/XSS oriented chars/keywords (e.g. `'`, `"`, UNION, script); LFI/SSRF/Auth को लागि अलग probe छैन।
- **गर्ने:**  
  - `ctx.vuln_type` अनुसार probe extend गर्ने:  
    - **LFI:** `../`, `..\\`, `file://`, `php://` जस्ता path chars/keywords।  
    - **SSRF:** URL scheme, `localhost`, `127.0.0.1` reflect/block check।  
    - **Auth:** `'`, `"`, `#`, `--`, `OR`, `AND` (already धेरै छ), optional JSON/LDAP chars।  
  - `_probe_chars` / `_probe_keywords` मा vuln_type switch वा extra list from config।

### B4. Phase 4 — time-based blind पनि (Nice)
- **समस्या:** Phase 4 मा boolean-blind मात्र (BinarySearchExtractor); time-based blind को लागि extractor छैन।
- **गर्ने:**  
  - यदि `ctx.time_delay_works` True र `ctx.boolean_diff_works` False (वा दुवै True):  
    - Time-based extraction (SLEEP + substring comparison) को लागि साधारण extractor थप्ने वा existing LLM/binary-search जस्तो logic reuse गर्ने।

### B5. Mutation limit config (Nice)
- **समस्या:** `_generate_waf_mutations` भित्र `limit=40` hardcoded।
- **गर्ने:**  
  - Constructor मा `mutation_limit: int = 40` वा config/settings बाट पढ्ने र `mutate_to_strings(..., limit=self.mutation_limit)`।

### B6. Second mutation round after AI (Nice)
- **समस्या:** AI round(s) पछि सबै fail भए पनि फेरि mutation engine लाई AI को failed payloads दिई नयाँ bypass try गर्दैन।
- **गर्ने:**  
  - Phase 3 पछि (सबै AI rounds exhausted):  
    - `recent_failed = [r.payload for r in ctx.last_n_failures(15)]`  
    - यदि non-empty भए, `_generate_waf_mutations(recent_failed, ctx, vuln_type)` गरी एक अर्को mutation round run गर्ने (र success भए return)।  
  - यसले "AI ले दिएको तर WAF ले काटेको" payload लाई mutate गरेर फेरि chance दिन्छ।

---

## Part C: दुवै को साथमा (Integration)

### C1. ctx पूरा भर्ने
- **Adaptive:** Probe ले जति सक्दो ctx भर्ने (waf, filtered_chars, keywords_filtered, time_delay_works, boolean_diff_works)।  
- **Mutation:** यही ctx लाई WAF-based priority (A3) र safe access (A2) सँग use गर्ने।  
- **Result:** Mutation engine ले "कुन WAF छ, के filter भयो" अनुसार सही techniques prioritize गर्ने।

### C2. Failed payloads flow
- **Adaptive:** हर `_try` पछि `ctx.add_attempt(result)` (already छ)।  
- **Mutation:** `ctx.get_failed_payloads()` बाट already-tried skip (already छ)।  
- **Strengthen:** Adaptive बाट mutation लाई input मा **failed payloads पनि दिने** (B1, B6) ताकि "फेरि त्यही payload मात्र होइन, failed लाई पनि mutate गर्छ"।

### C3. Config single place
- **गर्ने:**  
  - `settings` वा env मा: `MUTATION_PAYLOAD_LIMIT`, `ADAPTIVE_MUTATION_LIMIT`, `ADAPTIVE_MAX_AI_ROUNDS`, (optional) `OOB_DOMAIN`।  
  - Mutation: limit र OOB यहीं बाट।  
  - Adaptive: mutation_limit र max_ai_rounds यहीं बाट।  
  - यसले दुवै engine एकै config सँग align हुन्छ।

---

## Priority Summary (के पहिले गर्ने)

| Priority | Item | Engine | Effort |
|----------|------|--------|--------|
| 1 | A2 — ctx safe (getattr/defaults) | Mutation | S |
| 2 | A1 — LFI double-dot use payload | Mutation | S |
| 3 | B1 — Mutate failed payloads (not only static[:5]) | Adaptive | M |
| 4 | A3 — ctx.waf strategy | Mutation | M |
| 5 | B6 — Second mutation round after AI | Adaptive | S |
| 6 | B2 — max_rounds use or remove | Adaptive | S |
| 7 | A4 — Limit/OOB configurable | Mutation | S |
| 8 | B5 — mutation_limit config in Adaptive | Adaptive | S |
| 9 | A5 — Open Redirect mutations | Mutation | M |
| 10 | B3 — Vuln-type specific probes | Adaptive | M |
| 11 | B4 — Time-based blind extractor | Adaptive | L |
| 12 | A6 — EXTRACTVALUE use original | Mutation | S |

**S=Small, M=Medium, L=Large**

यो order अनुसार गर्दा दुवै engine अलि अलि stronger र एक अर्कासँग better integrate हुनेछ।

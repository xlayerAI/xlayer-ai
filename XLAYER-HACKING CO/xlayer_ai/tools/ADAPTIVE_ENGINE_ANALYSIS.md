# adaptive_engine.py — Code Analysis & Improvements

## 1. Imports (Lines 8–20)

| Line | Issue | Severity |
|------|--------|----------|
| 9 | `time` imported but never used | Low |
| 14–16 | `to_hex_string`, `hex_encode_string_literals` imported from payload_generator but never used in this file | Low |

**Improvement:** Remove unused imports to avoid confusion and keep dependencies clear.

---

## 2. SendResult (Lines 25–34)

- **OK:** Dataclass is clear; `payload` is redundant with `AttemptResult.payload` but used by callers for consistency.
- **Minor:** `headers: Dict[str, str]` — if server sends duplicate header names, only one value is kept. Acceptable for WAF detection.

---

## 3. ProbeEngine

### 3.1 Baseline (Lines 70–75)

- **Bug risk:** If `self.send()` returns `None` (timeout/error), `ctx.baseline_length` and `ctx.baseline_time_ms` are never set (remain 0).
- **Impact:** `_probe_time` uses `ctx.baseline_time_ms + 2000` → threshold 2000 ms (still OK). `_probe_boolean` uses `ctx.baseline_length * 0.05` → 0, so `threshold = max(30, 0) = 30`. Other probes don’t depend on baseline. So no crash, but baseline=0 can make NO_DIFFERENCE classification in `_classify_failure` fragile (compare with 0).

**Improvement:** If baseline fails, set safe defaults (e.g. baseline_length=0, baseline_time_ms=0) and optionally skip or weaken probes that depend on it, or retry baseline once.

### 3.2 Parallel probes (Lines 56–64)

- **Issue:** `asyncio.gather(..., return_exceptions=True)` — if any probe raises, the exception is returned in the result list and never checked or logged. Failures are silent.

**Improvement:** After `gather`, iterate results and log any exception so probe failures are visible.

### 3.3 _probe_chars (Lines 76–84)

- **OK:** Logic is clear. `"--"` and `"/*"` are two-char; checking `char not in r.body` is substring check — correct.

### 3.4 _probe_keywords (Lines 86–94)

- **OK:** Case-insensitive check is correct. Could add more keywords (e.g. `INSERT`, `UPDATE`) for broader recon — optional.

### 3.5 _probe_time (Lines 95–108)

- **OK:** Threshold and payloads are reasonable. Only MySQL/pg style; could add MSSQL `WAITFOR DELAY` later.

### 3.6 _probe_boolean (Lines 110–119)

- **OK:** Threshold `max(30, 5% baseline)` is reasonable. Two requests in sequence — could run in parallel with `gather` for speed.

### 3.7 _detect_waf (Lines 121–171)

- **Duplication:** WAF body/header signatures are duplicated in `AdaptiveEngine._detect_waf_in_response` (lines 382–410). Different structure (dict vs list) and slight differences. Changes must be done in two places.

**Improvement:** Extract WAF signatures to a single shared constant or small module and use it in both ProbeEngine and AdaptiveEngine.

---

## 4. AdaptiveEngine

### 4.1 __init__ (Lines 188–203)

- **Dead parameter:** `max_rounds: int = 4` is stored but never used in `run()`. The loop is driven by `max_ai_rounds` and phase logic only.

**Improvement:** Either use `max_rounds` (e.g. cap total attempts or phases) or remove it to avoid confusion.

### 4.2 run() — Phase numbering (Lines 223–225)

- **Confusion:** Log says "AdaptiveEngine Phase 1" for static payloads, but probe is not numbered. So "Phase 1" is actually the second phase (after probe).

**Improvement:** Use consistent labels, e.g. "Phase 0: Probe", "Phase 1: Static", "Phase 2: Mutations", "Phase 3: AI", "Phase 4: BinarySearch".

### 4.3 run() — Mutation phase (Lines 243–249)

- **OK:** `static_payloads[:5]` limits input to mutation engine; if list is empty, `mutate_to_strings` returns [] — no crash.

### 4.4 run() — Binary search (Lines 284–318)

- **OK:** Only runs when `vuln_type == "sqli"` and `boolean_diff_works`. Tries `db_user` then `db_version`; returns on first successful extraction. If both fail, falls through and returns `all_results` with no new success — correct.
- **Minor:** On first success we `return all_results` without trying the second label; could optionally try both and append all proofs before returning. Current behavior is acceptable.

### 4.5 _try() (Lines 324–358)

- **OK:** None check, success/failure classification, and AttemptResult construction are correct.
- **Truncation:** `response_body=send_result.body[:500]` — 500 is a magic number. Consider a named constant.

### 4.6 _classify_failure() (Lines 360–368)

- **Edge case:** `payload_stripped = payload.replace("'", "").replace('"', "")...` then `payload_stripped[:10].lower() not in r.body.lower()`. If payload is very short (e.g. `"1"`), `payload_stripped` is `"1"` and `"1"` is often in body → not FILTERED. If payload is empty after strip (e.g. `"'\"<>"`), `payload_stripped` is `""`, and `"".lower() not in r.body` is False (empty string is substring of any string), so we don’t classify as FILTERED. So we fall through to UNKNOWN. That’s acceptable.
- **Real bug:** If `payload_stripped` is non-empty but shorter than 10 chars (e.g. `"1"`), then `payload_stripped[:10]` is `"1"`. If response echoes "1", we get UNKNOWN instead of FILTERED when we might want FILTERED. So the logic is “first 10 chars of stripped payload must appear in body”; for very short payloads we’re only checking that short prefix. Reasonable.
- **Defensive:** When `ctx.baseline_length` is 0 (baseline failed), `abs(len(r.body) - 0) < 10` can mark many responses as NO_DIFFERENCE. Consider skipping NO_DIFFERENCE when baseline_length is 0 or using a different threshold.

**Improvement:** When `ctx.baseline_length == 0`, avoid or relax NO_DIFFERENCE (e.g. don’t set it, or require a minimum baseline_length).

### 4.7 _detect_filtered_chars() (Lines 370–375)

- **OK:** Simple and correct. List is fixed; could be shared with ProbeEngine chars_to_test for consistency.

### 4.8 _detect_waf_in_response() (Lines 377–410)

- **Duplication:** Same WAF list as ProbeEngine with different structure. Header check uses `"server:cloudflare"` and split — value might have leading space; in practice we lowercased so " cloudflare" still contains "cloudflare". OK.
- **Improvement:** Use shared WAF constants.

### 4.9 _generate_waf_mutations() (Lines 412–429)

- **OK:** Delegates to MutationEngine with limit=40. No change needed.

---

## 5. Magic numbers (summary)

| Value | Location | Suggestion |
|-------|----------|------------|
| 10 | NO_DIFFERENCE threshold | `DIFF_THRESHOLD_BYTES = 10` |
| 500 | response_body truncation | `RESPONSE_BODY_TRUNCATE = 500` |
| 50, 60 | log payload truncation | Optional constant |
| 5 | static_payloads[:5] for mutations | `MAX_PAYLOADS_FOR_MUTATION = 5` |
| 40 | mutate_to_strings limit | Already parameter; 40 is OK |
| 2000.0 | time probe threshold ms | `TIME_DELAY_THRESHOLD_MS = 2000` |
| 30 | boolean diff min bytes | `BOOLEAN_DIFF_MIN_BYTES = 30` |
| 0.05 | boolean 5% baseline | `BOOLEAN_DIFF_BASELINE_RATIO = 0.05` |

---

## 6. Priority improvements

1. **High:** Baseline failure handling — set defaults and/or log; optionally relax NO_DIFFERENCE when baseline_length is 0.
2. **High:** ProbeEngine — log exceptions from `gather(..., return_exceptions=True)`.
3. **Medium:** Remove unused imports (`time`, `to_hex_string`, `hex_encode_string_literals`).
4. **Medium:** Remove or use `max_rounds` in `AdaptiveEngine.__init__`.
5. **Medium:** Extract WAF signatures to a single shared place (both ProbeEngine and AdaptiveEngine).
6. **Low:** Consistent phase labels in logs.
7. **Low:** Named constants for magic numbers (optional).

---

## 7. Summary

- **Yes, improvement parna sakxa:** Unused imports, baseline/probe robustness, dead parameter, WAF duplication, and logging clarity.
- **Critical bugs:** None; edge cases (baseline=0, probe exceptions) are the main robustness improvements.
- **Design:** Phases and feedback loop are clear; small fixes will make the module easier to maintain and debug.

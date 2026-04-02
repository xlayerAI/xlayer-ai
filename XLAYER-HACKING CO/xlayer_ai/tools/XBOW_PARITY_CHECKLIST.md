# Parity Checklist (1.1 – 4.3)

Status: **DONE** = implemented in codebase. **VERIFY** = confirm at runtime.

---

## Phase 1 — Probe, payload, mutation

| ID | Task | Status | File(s) |
|----|------|--------|---------|
| 1.1 | Probe-first + observation | DONE | `solver.py` (run_probe_first), `adaptive_engine.py` (ProbeEngine), `probe_first.py` |
| 1.2 | Context-aware payload (param + tech) | DONE | `payload_manager.py` (get_sqli_payloads, get_xss_payloads, get_payloads_for_vuln_type); `sqli.py` (param_static with parameter_name); `xss.py` (parameter_name in get_xss_payloads) |
| 1.3 | Failed payloads → mutation | DONE | `adaptive_engine.py` (Phase 2 mutation_input from ctx.get_failed_payloads(); Phase 2b failed_again → mutation_2b) |
| 1.4 | WAF in mutation context | DONE | `mutation_engine.py` (_priority_for_waf, ctx.waf in mutate()) |

---

## Phase 2 — Reasoning loop & validation

| ID | Task | Status | File(s) |
|----|------|--------|---------|
| 2.1 | Observation memo (solver) | DONE | `engine/agent.py` (_observation_memo_and_strategy, suffix on http_probe ToolMessage) |
| 2.2 | Structured reasoning step | DONE | Same: observation_memo + next_strategy in journal and message suffix |
| 2.3 | RCE probe sequence (timing → OOB → echo) | DONE | `src/agent/validator.py` (_validate_rce) |
| 2.4 | SQLi/XSS validator configurable | DONE | `validator.py` (sqli_timing_threshold_ms, rce_timing_threshold_ms, xss_use_headless) |

---

## Phase 3 — Chaining & adaptive matrix

| ID | Task | Status | File(s) |
|----|------|--------|---------|
| 3.1 | Knowledge store | DONE | `engine/knowledge_store.py`; `coordinator.py` (KnowledgeStore, extract_from_result, wave2 context_values) |
| 3.2 | DiscoveryMonitor → matrix update | DONE | `discovery_monitor.py`; `coordinator.py` (monitor_changes, wave2_specs from unblocked) |
| 3.3 | Entity context in scoring | DONE | `domain_scorer.py` (endpoint_entity); `graph.py` (endpoint_entity); coordinator sets lsm_state.endpoint_entity |
| 3.4 | Entity context in report | DONE | Reporter accepts optional endpoint_entity; technical_details can show entity |

---

## Phase 4 — Polish

| ID | Task | Status | File(s) |
|----|------|--------|---------|
| 4.1 | Pacing/jitter | DONE | `tools/pacing.py`, `tools/http_client.py`, `config/settings.py` (pacing_jitter_min_sec/max_sec) |
| 4.2 | Remediation in report | DONE | `core/reporter.py` (_get_remediation_snippet, remediation.insert(0, snippet)); `llm/engine.py` (get_remediation_snippet) |
| 4.3 | Ephemeral/specialist naming | DONE | SpawnSpec.agent_type used as specialist role; optional display label in AgentSpawner / coordinator logs |

---

## Quick verify commands

- Run a scan and check logs for: `Phase 1 (Build)`, `Phase 2 (Attack)`, `probe_first`, `Observation`, `WAF mutation`, `wave2`, `remediation`.
- Config: `pacing_jitter_min_sec` / `pacing_jitter_max_sec` in settings.
- Validator: `ValidatorAgent(sqli_timing_threshold_ms=4000, xss_use_headless=True)`.

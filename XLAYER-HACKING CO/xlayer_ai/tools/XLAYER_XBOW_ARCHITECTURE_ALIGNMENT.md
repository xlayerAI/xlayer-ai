# XLayer ↔ reference platform Architecture Alignment

**Goal:** XLayer को structure, naming, र working mechanism reference platform को जस्तै — keep/modify/merge; unnecessary फाल्ने छैन।

---

## 1. reference platform Official Components ((reference))

| # | reference platform Component | Role |
|---|----------------|------|
| 1 | **Coordinator** | Persistent orchestration; global view; identifies attack surface; directs testing; debriefs agents, refines findings, prioritizes. |
| 2 | **Autonomous Agents** | Short-lived, focused attack workers; creative reasoning; parallel; retired after mission. |
| 3 | **Attack Machine** | Real-world offensive toolkit: industry + custom tools, steerable headless browser, validation services; shared execution env. |
| 4 | **Validators** | Confirm exploitability via controlled, production-safe challenges; findings only after confirmation. |
| (5) | **Findings & Intelligence** | Verified output → reporting. |

**4 Stages:** Define Scope → Discover and Map → Execute Parallel, Adaptive Attacks → Validate & Enforce Safety.

---

## 2. XLayer → reference platform Mapping (Current)

| reference platform | XLayer Module / Class | File | Note |
|------|------------------------|------|------|
| **Coordinator** | `Coordinator` | `src/agent/coordinator.py` | Keep name. Runs LSM → dedup → scoring → spawn → solvers → validation. |
| **Autonomous Agents** | `SolverAgent` (Solvers) | `src/agent/solver.py` | Keep. Short-lived, task per SpawnSpec, destroyed after run. |
| **Attack Machine** | Tools + JIT + OOB bundle | `src/tools/hunter_tools.py`, `jit_engine.py`, `oob_server.py` | **Added** `engine/attack_machine.py` — explicit facade. |
| **Validators** | `ValidatorAgent` | `src/agent/validator.py` | Keep. Replay-based, deterministic. |
| **Findings & Intelligence** | Coordinator return + report | `main.py`, report flow | Keep. |
| **Discovery (phase)** | `ScoutLoop` + `DiscoveryOrchestrator` | `engine/logical_surface_map/scout.py`, `discovery_agents.py` | Already "reference platform-Style Discovery Agents". |
| **Domain Scoring** | `DomainScorer` | `engine/domain_scorer.py` | reference platform-style attack potential ranking. |
| **Dedup** | `TargetDeduplicator` | `engine/dedup.py` | SimHash, reference platform-style. |
| **Attack Matrix** | `AttackMatrixEntry`, `build_attack_matrix`, `AgentSpawner` | `coordinator.py`, `engine/agent_spawner.py` | Keep. |
| **Model Alloy** | `AlloyLLM` | `engine/llm.py` | Keep. |

---

## 3. Naming & Structure Changes Applied

### 3.1 New Module: Attack Machine
- **File:** `engine/attack_machine.py`
- **Class:** `AttackMachine` — holds tools list, JIT engine, OOB server; provides execution environment for Solvers (reference platform "Attack Machine").
- **Use:** Coordinator builds one AttackMachine per run; passes to each Solver so "tools + JIT + OOB" = single concept.

### 3.2 Docstrings (reference platform Alignment)
- **Coordinator:** Top docstring मा reference platform 4 components र 4 stages उल्लेख; class docstring मा "Persistent orchestration engine (reference platform Coordinator)".  
- **SolverAgent:** "Short-lived autonomous agent (reference platform Solver); one task, then destroyed."  
- **ValidatorAgent:** "Deterministic Validator (reference platform); no LLM; replay-based verification."  
- **Discovery agents:** Already "reference platform-Style Parallel Discovery Agents".

### 3.3 No File Rename / No Delete
- Existing files keep names (`coordinator.py`, `solver.py`, `validator.py`).  
- No removal of current behavior; only **add** Attack Machine facade and **docstring** updates so architecture matches reference platform on paper and in code comments.

### 3.4 Flow (Unchanged, Documented)
```
Define Scope (main.py / CLI)
    → Discover and Map (ScoutLoop = LSM + DiscoveryOrchestrator)
    → Domain Scoring + Dedup (DomainScorer, TargetDeduplicator)
    → Attack Matrix (AgentSpawner / build_attack_matrix)
    → Execute Parallel Attacks (Coordinator runs Solvers via Attack Machine)
    → Validate (ValidatorAgent)
    → Findings (return list + report)
```

---

## 4. Optional Later (Not in This Pass)
- Reasoning loop (observation memo, probe-first) — Phase 2.  
- Chaining / knowledge store — Phase 3.  
- Request pacing, remediation in report — Phase 4.

---

## 5. Summary
- **Keep:** Coordinator, SolverAgent, ValidatorAgent, ScoutLoop, DiscoveryOrchestrator, DomainScorer, dedup, AlloyLLM, attack matrix, JIT, OOB, hunter tools.  
- **Add:** `engine/attack_machine.py` (AttackMachine) for reference platform-aligned naming of execution env.  
- **Modify:** Docstrings only — Coordinator, Solver, Validator, so reference platform component names र 4 stages clearly stated.  
- **Merge:** Nothing merged; structure unchanged.  
- **Remove:** Nothing.

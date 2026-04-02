# XLayer AI Full File Audit Report

- Date: 2026-03-02
- Scope: 187 Python files (excluding __pycache__)
- Risk summary: high=11, medium=21, low=51, none=104

## Validated Critical Findings

1. `shell_exec` allows arbitrary shell command execution via `shell=True` and is exposed in tool registry.
   - refs: `xlayer_ai/src/tools/hunter_tools.py:638`, `:672`, `:674`, `:718`
2. JIT sandbox still executes arbitrary Python with `subprocess` available in prelude; blocklist is string-based and bypass-prone.
   - refs: `xlayer_ai/src/tools/jit_engine.py:22`, `:26`, `:36`, `:103`, `:175`
3. OPTIONS-discovered methods are not applied to endpoint method upgrades (`pass` placeholder).
   - refs: `xlayer_ai/engine/logical_surface_map/scout.py:297`, `:302`
4. Full scan path ignores `hunters` and does not pass `settings` into `Coordinator`; runtime controls (timeouts/proxy/verify choices) are partially bypassed.
   - refs: `xlayer_ai/main.py:758`, `:782`, `:783`
5. Validator can mark SSRF (and other fallback cases) as valid on any non-500 replay when OOB is unavailable, increasing false-positive risk.
   - refs: `xlayer_ai/src/agent/validator.py:249`, `:250`, `:424`, `:428`
6. InteractSH polling uses `_secret`, but code never sets it after registration (likely blind callback miss / false negatives).
   - refs: `xlayer_ai/src/tools/oob_server.py:75`, `:95`, `:121`
7. TLS verification disabled (`verify=False`) in multiple recon/probe paths despite config having `verify_ssl=True`.
   - refs: `xlayer_ai/config/settings.py:104`, `xlayer_ai/engine/logical_surface_map/http_probe.py:266`, `xlayer_ai/engine/logical_surface_map/discovery_agents.py:320`, `xlayer_ai/src/tools/hunter_tools.py:590`, `xlayer_ai/src/agent/validator.py:460`

## Per-File Inventory (Each Python File)

| File | LOC | Risk | Key Flags | Purpose/First line |
|---|---:|---|---|---|
| `src/__init__.py` | 13 | NONE | - | Compatibility package for legacy `src.*` imports. |
| `xlayer_ai/__init__.py` | 20 | NONE | - | XLayer AI - Autonomous Web Vulnerability Hunter |
| `xlayer_ai/config/__init__.py` | 7 | NONE | - | XLayer AI Configuration - Settings and payload management |
| `xlayer_ai/config/settings.py` | 195 | NONE | - | XLayer AI Settings - Configuration management using Pydantic |
| `xlayer_ai/core/__init__.py` | 16 | NONE | - | XLayer AI Core - Agent implementations |
| `xlayer_ai/core/coordinator_result.py` | 192 | LOW | except Exception:1 | Coordinator result → ValidatedVuln conversion and merge helpers. |
| `xlayer_ai/core/exploit.py` | 1032 | HIGH | except Exception:13 | XLayer AI Exploit Agent - Validates vulnerabilities through real exploitation |
| `xlayer_ai/core/planner.py` | 492 | LOW | except Exception:2 | XLayer AI Planner Agent - Master orchestrator for the vulnerability hunting pipeline |
| `xlayer_ai/core/recon.py` | 377 | LOW | except Exception:4 | XLayer AI Recon Agent - Attack surface reconnaissance and mapping |
| `xlayer_ai/core/reporter.py` | 551 | LOW | except Exception:2 | XLayer AI Reporter - Professional vulnerability assessment report generator |
| `xlayer_ai/core/vuln_hunters/__init__.py` | 60 | NONE | - | XLayer AI Vulnerability Hunters - Specialized agents for each vulnerability class |
| `xlayer_ai/core/vuln_hunters/auth.py` | 350 | LOW | except Exception:1 | XLayer AI Auth Hunter - Detects authentication and authorization vulnerabilities |
| `xlayer_ai/core/vuln_hunters/base.py` | 385 | LOW | except Exception:3 | XLayer AI Base Hunter - Abstract base class for vulnerability hunters |
| `xlayer_ai/core/vuln_hunters/cors.py` | 218 | LOW | except Exception:1 | XLayer AI CORS Hunter - Cross-Origin Resource Sharing Misconfiguration |
| `xlayer_ai/core/vuln_hunters/csrf.py` | 249 | LOW | except Exception:2 | XLayer AI CSRF Hunter - Cross-Site Request Forgery |
| `xlayer_ai/core/vuln_hunters/deserialization.py` | 401 | MED | os.system:1, except Exception:2 | XLayer AI Deserialization Hunter |
| `xlayer_ai/core/vuln_hunters/graphql.py` | 287 | LOW | except Exception:2 | XLayer AI GraphQL Hunter - GraphQL-specific vulnerabilities |
| `xlayer_ai/core/vuln_hunters/http_smuggling.py` | 313 | LOW | except Exception:3 | XLayer AI HTTP Request Smuggling Hunter |
| `xlayer_ai/core/vuln_hunters/lfi.py` | 366 | NONE | - | XLayer AI LFI Hunter - Detects Local/Remote File Inclusion vulnerabilities |
| `xlayer_ai/core/vuln_hunters/open_redirect.py` | 190 | NONE | - | XLayer AI Open Redirect Hunter |
| `xlayer_ai/core/vuln_hunters/race_condition.py` | 197 | LOW | except Exception:1 | XLayer AI Race Condition Hunter |
| `xlayer_ai/core/vuln_hunters/rce.py` | 321 | NONE | - | XLayer AI RCE Hunter - Remote Code Execution / Command Injection |
| `xlayer_ai/core/vuln_hunters/sqli.py` | 466 | NONE | - | XLayer AI SQL Injection Hunter - Detects SQL injection vulnerabilities |
| `xlayer_ai/core/vuln_hunters/ssrf.py` | 313 | NONE | - | XLayer AI SSRF Hunter - Detects Server-Side Request Forgery vulnerabilities |
| `xlayer_ai/core/vuln_hunters/ssti.py` | 233 | HIGH | eval/exec:3 | XLayer AI SSTI Hunter - Server-Side Template Injection |
| `xlayer_ai/core/vuln_hunters/subdomain_takeover.py` | 214 | LOW | except Exception:4 | XLayer AI Subdomain Takeover Hunter |
| `xlayer_ai/core/vuln_hunters/xss.py` | 322 | NONE | - | XLayer AI XSS Hunter - Detects Cross-Site Scripting vulnerabilities |
| `xlayer_ai/core/vuln_hunters/xxe.py` | 329 | LOW | except Exception:3 | XLayer AI XXE Hunter - XML External Entity Injection |
| `xlayer_ai/engine/__init__.py` | 83 | NONE | - | engine/ — XLayer Custom Agentic Framework |
| `xlayer_ai/engine/agent.py` | 1010 | LOW | except Exception:4 | engine/agent.py — Universal AgentLoop |
| `xlayer_ai/engine/agent_spawner.py` | 370 | LOW | except Exception:1 | engine/agent_spawner.py — Dynamic Context-Aware Agent Spawning |
| `xlayer_ai/engine/agentic_loop.py` | 764 | MED | except Exception:5 | engine/agentic_loop.py — XLayer Reasoning Loop |
| `xlayer_ai/engine/attack_machine.py` | 44 | NONE | - | Attack Machine — XBOW-Style Shared Execution Environment |
| `xlayer_ai/engine/chain/__init__.py` | 38 | NONE | - | engine/chain/ — Attack Chain Engine |
| `xlayer_ai/engine/chain/distiller.py` | 203 | LOW | except Exception:1 | engine/chain/distiller.py — Pattern Distiller |
| `xlayer_ai/engine/chain/executor.py` | 331 | LOW | except Exception:4 | engine/chain/executor.py — Attack Chain Executor |
| `xlayer_ai/engine/chain/models.py` | 182 | NONE | - | engine/chain/models.py — Attack Chain Data Structures |
| `xlayer_ai/engine/chain/pattern_store.py` | 152 | LOW | except Exception:1 | engine/chain/pattern_store.py — Persistent Pattern Library |
| `xlayer_ai/engine/chain/patterns.py` | 260 | NONE | - | engine/chain/patterns.py — Built-in Attack Chain Templates |
| `xlayer_ai/engine/chain/planner.py` | 375 | LOW | except Exception:1 | engine/chain/planner.py — Attack Chain Planner |
| `xlayer_ai/engine/cross_synthesis.py` | 326 | NONE | - | engine/cross_synthesis.py — Cross-finding Synthesis |
| `xlayer_ai/engine/dedup.py` | 228 | LOW | except Exception:1 | engine/dedup.py — SimHash Target Deduplication (XBOW-style) |
| `xlayer_ai/engine/discovery_monitor.py` | 290 | LOW | verify=False:1, except Exception:2 | engine/discovery_monitor.py — Continuous Discovery Monitor |
| `xlayer_ai/engine/domain_scorer.py` | 397 | NONE | - | engine/domain_scorer.py — XBOW-Style Domain Scoring System |
| `xlayer_ai/engine/knowledge_store.py` | 103 | NONE | - | engine/knowledge_store.py — XBOW-Style Shared Knowledge for Chaining (Phase 3.1) |
| `xlayer_ai/engine/llm.py` | 388 | LOW | except Exception:4 | engine/llm.py — Direct LLM API client |
| `xlayer_ai/engine/logical_surface_map/behavior_probe.py` | 301 | LOW | verify=False:1, except Exception:1 | engine/logical_surface_map/behavior_probe.py — Behavioral Fingerprinting |
| `xlayer_ai/engine/logical_surface_map/browser_analyzer.py` | 586 | HIGH | except Exception:12 | engine/logical_surface_map/browser_analyzer.py — XLayer Dynamic Browser Analysis |
| `xlayer_ai/engine/logical_surface_map/discovery_agents.py` | 878 | HIGH | verify=False:1, except Exception:10 | engine/logical_surface_map/discovery_agents.py — XBOW-Style Parallel Discovery Agents |
| `xlayer_ai/engine/logical_surface_map/graph.py` | 276 | NONE | - | engine/logical_surface_map/graph.py — XLayer Entity-State Graph (Memory for LSM) |
| `xlayer_ai/engine/logical_surface_map/http_probe.py` | 967 | HIGH | eval/exec:1, verify=False:1, except Exception:14 | engine/logical_surface_map/http_probe.py — XLayer Passive HTTP Intelligence |
| `xlayer_ai/engine/logical_surface_map/js_analyzer.py` | 1400 | MED | verify=False:1, except Exception:4 | engine/logical_surface_map/js_analyzer.py — XLayer JS Intelligence Engine |
| `xlayer_ai/engine/logical_surface_map/lsm_tools.py` | 604 | HIGH | verify=False:1, except Exception:11 | engine/logical_surface_map/lsm_tools.py — ScoutLoop HTTP Tool Implementations |
| `xlayer_ai/engine/logical_surface_map/path_fuzzer.py` | 535 | LOW | verify=False:1, except Exception:2 | engine/logical_surface_map/path_fuzzer.py — XLayer Wordlist-Based Path Discovery |
| `xlayer_ai/engine/logical_surface_map/scout.py` | 1105 | MED | except Exception:10 | engine/logical_surface_map/scout.py — XLayer Agentic Logical Surface Mapper (LSM) |
| `xlayer_ai/engine/logical_surface_map/supply_chain.py` | 250 | NONE | - | engine/logical_surface_map/supply_chain.py — Supply Chain Mapper |
| `xlayer_ai/engine/memory.py` | 298 | LOW | except Exception:4 | engine/memory.py — SQLite-based checkpoint + key-value store |
| `xlayer_ai/engine/messages.py` | 144 | LOW | except Exception:1 | engine/messages.py — Custom message types |
| `xlayer_ai/engine/pipeline.py` | 209 | LOW | except Exception:4 | engine/pipeline.py — Sequential Pipeline + Parallel Dispatcher |
| `xlayer_ai/engine/tool.py` | 202 | LOW | except Exception:1 | engine/tool.py — Custom @tool decorator |
| `xlayer_ai/llm/__init__.py` | 56 | NONE | - | XLayer AI LLM - Unified language model integration. |
| `xlayer_ai/llm/config_manager.py` | 132 | LOW | except Exception:2 | Memory-based configuration manager - manages LLM settings in memory without file persistence. |
| `xlayer_ai/llm/engine.py` | 493 | MED | except Exception:7 | XLayer AI LLM Engine - Language model integration for intelligent analysis |
| `xlayer_ai/llm/gemini_provider.py` | 139 | LOW | except Exception:2 | XLayer AI - Google Gemini Provider |
| `xlayer_ai/llm/models.py` | 283 | LOW | except Exception:2 | LLM Model loading and provider management. |
| `xlayer_ai/llm/openai_oauth.py` | 327 | LOW | except Exception:3 | XLayer AI - OpenAI OAuth PKCE Provider |
| `xlayer_ai/llm/openrouter.py` | 55 | NONE | - | OpenRouter API integration module. |
| `xlayer_ai/llm/payload_generator.py` | 839 | MED | eval/exec:1, except Exception:4 | XLayer AI - AI-Powered Adaptive Payload Generator |
| `xlayer_ai/llm/selection.py` | 355 | LOW | except Exception:1 | LLM Selection utilities for CLI and frontend. |
| `xlayer_ai/llm/test_llm.py` | 266 | MED | except Exception:5 | """ |
| `xlayer_ai/main.py` | 1410 | MED | except Exception:9 | XLayer AI - Autonomous Web Vulnerability Hunter |
| `xlayer_ai/models/__init__.py` | 27 | NONE | - | XLayer AI Models - Data structures for targets, vulnerabilities, and reports |
| `xlayer_ai/models/report.py` | 213 | NONE | - | XLayer AI Report Models - Data structures for reports and findings |
| `xlayer_ai/models/target.py` | 169 | NONE | - | XLayer AI Target Models - Data structures for targets and attack surface |
| `xlayer_ai/models/vulnerability.py` | 205 | NONE | - | XLayer AI Vulnerability Models - Data structures for vulnerabilities |
| `xlayer_ai/packages/__init__.py` | 9 | NONE | - | XLayer AI - Unified Security Intelligence Platform |
| `xlayer_ai/packages/xlayer_hunter/__init__.py` | 34 | NONE | - | XLayer Hunter - Autonomous Web Vulnerability Hunter |
| `xlayer_ai/packages/xlayer_hunter/config/__init__.py` | 7 | NONE | - | XLayer AI Configuration - Settings and payload management |
| `xlayer_ai/packages/xlayer_hunter/config/settings.py` | 100 | NONE | - | XLayer AI Settings - Configuration management using Pydantic |
| `xlayer_ai/packages/xlayer_hunter/core/__init__.py` | 63 | NONE | - | XLayer AI Core - Agent implementations and execution engine |
| `xlayer_ai/packages/xlayer_hunter/core/agent_coordinator.py` | 440 | LOW | except Exception:1 | XLayer AI Agent Coordinator - Multi-Agent Orchestration System |
| `xlayer_ai/packages/xlayer_hunter/core/agents/__init__.py` | 328 | NONE | - | XLayer AI Agents - All Agent Definitions |
| `xlayer_ai/packages/xlayer_hunter/core/executor.py` | 548 | LOW | except Exception:2 | XLayer AI Executor - Multi-Agent Workflow Execution Engine |
| `xlayer_ai/packages/xlayer_hunter/core/exploit.py` | 739 | MED | except Exception:7 | XLayer AI Exploit Agent - Validates vulnerabilities through real exploitation |
| `xlayer_ai/packages/xlayer_hunter/core/planner.py` | 344 | LOW | except Exception:1 | XLayer AI Planner Agent - Master orchestrator for the vulnerability hunting pipeline |
| `xlayer_ai/packages/xlayer_hunter/core/recon.py` | 382 | MED | except Exception:5 | XLayer AI Recon Agent - Attack surface reconnaissance and mapping |
| `xlayer_ai/packages/xlayer_hunter/core/reporter.py` | 506 | NONE | - | XLayer AI Reporter - Professional vulnerability assessment report generator |
| `xlayer_ai/packages/xlayer_hunter/core/vuln_hunters/__init__.py` | 47 | NONE | - | XLayer AI Vulnerability Hunters - Specialized agents for each vulnerability class |
| `xlayer_ai/packages/xlayer_hunter/core/vuln_hunters/auth.py` | 740 | MED | except Exception:5 | XLayer AI Auth Hunter - Detects authentication and authorization vulnerabilities |
| `xlayer_ai/packages/xlayer_hunter/core/vuln_hunters/base.py` | 246 | LOW | except Exception:2 | XLayer AI Base Hunter - Abstract base class for vulnerability hunters |
| `xlayer_ai/packages/xlayer_hunter/core/vuln_hunters/lfi.py` | 323 | NONE | - | XLayer AI LFI Hunter - Detects Local/Remote File Inclusion vulnerabilities |
| `xlayer_ai/packages/xlayer_hunter/core/vuln_hunters/sqli.py` | 420 | NONE | - | XLayer AI SQL Injection Hunter - Detects SQL injection vulnerabilities |
| `xlayer_ai/packages/xlayer_hunter/core/vuln_hunters/ssrf.py` | 591 | NONE | - | XLayer AI SSRF Hunter - Detects Server-Side Request Forgery vulnerabilities |
| `xlayer_ai/packages/xlayer_hunter/core/vuln_hunters/xss.py` | 281 | NONE | - | XLayer AI XSS Hunter - Detects Cross-Site Scripting vulnerabilities |
| `xlayer_ai/packages/xlayer_hunter/llm/__init__.py` | 7 | NONE | - | XLayer AI LLM - Language model integration for intelligent analysis |
| `xlayer_ai/packages/xlayer_hunter/llm/engine.py` | 438 | MED | except Exception:5 | XLayer AI LLM Engine - Language model integration for intelligent analysis |
| `xlayer_ai/packages/xlayer_hunter/main.py` | 313 | LOW | except Exception:1 | XLayer AI - Autonomous Web Vulnerability Hunter |
| `xlayer_ai/packages/xlayer_hunter/models/__init__.py` | 47 | NONE | - | XLayer AI Models - Data structures for targets, vulnerabilities, and reports |
| `xlayer_ai/packages/xlayer_hunter/models/report.py` | 213 | NONE | - | XLayer AI Report Models - Data structures for reports and findings |
| `xlayer_ai/packages/xlayer_hunter/models/target.py` | 169 | NONE | - | XLayer AI Target Models - Data structures for targets and attack surface |
| `xlayer_ai/packages/xlayer_hunter/models/vulnerability.py` | 399 | NONE | - | XLayer AI Vulnerability Models - Data structures for vulnerabilities |
| `xlayer_ai/packages/xlayer_hunter/tools/__init__.py` | 19 | NONE | - | XLayer AI Tools - Low-level utilities for scanning and exploitation |
| `xlayer_ai/packages/xlayer_hunter/tools/browser.py` | 421 | MED | except Exception:5 | XLayer AI Headless Browser - Playwright-based browser automation for exploitation |
| `xlayer_ai/packages/xlayer_hunter/tools/crawler.py` | 322 | LOW | except Exception:3 | XLayer AI Web Crawler - Recursive web crawler for endpoint discovery |
| `xlayer_ai/packages/xlayer_hunter/tools/http_client.py` | 296 | NONE | - | XLayer AI HTTP Client - Async HTTP client with logging and interception |
| `xlayer_ai/packages/xlayer_hunter/tools/kali_executor.py` | 167 | HIGH | subprocess:5, except Exception:1 | XLayer AI Kali Executor - Run commands and offensive tools inside a Kali Docker container. |
| `xlayer_ai/packages/xlayer_hunter/tools/mcp/Initial_Access.py` | 0 | NONE | - |  |
| `xlayer_ai/packages/xlayer_hunter/tools/payload_manager.py` | 327 | MED | eval/exec:1 | XLayer AI Payload Manager - Payload database and context-aware selection |
| `xlayer_ai/packages/xlayer_hunter/tools/scanner.py` | 256 | LOW | except Exception:1 | XLayer AI Port Scanner - Async port scanner using native sockets |
| `xlayer_ai/packages/xlayer_hunter/utils/__init__.py` | 22 | NONE | - | XLayer AI Utilities - Helper modules for the vulnerability hunter |
| `xlayer_ai/packages/xlayer_hunter/utils/agent_manager.py` | 540 | LOW | except Exception:1 | XLayer AI Agent Manager - Centralized Agent Information Management |
| `xlayer_ai/packages/xlayer_hunter/utils/logger.py` | 59 | NONE | - | XLayer AI Logger - Logging configuration using Loguru |
| `xlayer_ai/packages/xlayer_hunter/utils/swarm/handoff.py` | 133 | NONE | - | Agent handoff utilities for the swarm multi-agent system. |
| `xlayer_ai/packages/xlayer_hunter/utils/swarm/swarm.py` | 222 | NONE | - | from langgraph.graph import START, MessagesState, StateGraph |
| `xlayer_ai/packages/xlayer_hunter/utils/validators.py` | 106 | LOW | except Exception:4 | XLayer AI Validators - Input validation utilities |
| `xlayer_ai/prompts/__init__.py` | 87 | NONE | - | XLayer AI Prompts - System prompts for all agents |
| `xlayer_ai/prompts/base/__init__.py` | 22 | NONE | - | Base prompts for XLayer AI agents. |
| `xlayer_ai/prompts/base/initial_access_persona.py` | 68 | MED | eval/exec:1 | Base Initial Access / Exploitation agent prompt. |
| `xlayer_ai/prompts/base/planner.py` | 48 | NONE | - | Base Planner agent prompt. |
| `xlayer_ai/prompts/base/recon.py` | 56 | NONE | - | Base Reconnaissance agent prompt. |
| `xlayer_ai/prompts/base/summary.py` | 57 | NONE | - | Base Summary agent prompt. |
| `xlayer_ai/prompts/base/supervisor.py` | 51 | NONE | - | Base Supervisor prompt. |
| `xlayer_ai/prompts/base/terminal.py` | 165 | NONE | - | Base Terminal Management prompt. |
| `xlayer_ai/prompts/core_agents.py` | 369 | NONE | - | XLayer AI Core Agent Prompts |
| `xlayer_ai/prompts/hunters/__init__.py` | 19 | NONE | - | XLayer AI Hunter Prompts |
| `xlayer_ai/prompts/hunters/auth.py` | 90 | NONE | - | Auth Hunter Prompt |
| `xlayer_ai/prompts/hunters/lfi.py` | 98 | NONE | - | LFI Hunter Prompt |
| `xlayer_ai/prompts/hunters/sqli.py` | 81 | NONE | - | SQL Injection Hunter Prompt |
| `xlayer_ai/prompts/hunters/ssrf.py` | 98 | NONE | - | SSRF Hunter Prompt |
| `xlayer_ai/prompts/hunters/xss.py` | 80 | NONE | - | XSS Hunter Prompt |
| `xlayer_ai/prompts/personas/__init__.py` | 20 | NONE | - | Personas package for xlayer ai red team agent personalities. |
| `xlayer_ai/prompts/personas/initial_access_persona.py` | 102 | NONE | - | Initial Access Persona — exploitation specialist. |
| `xlayer_ai/prompts/personas/planner_persona.py` | 83 | NONE | - | Planner Persona — strategic planning specialist. |
| `xlayer_ai/prompts/personas/reconnaissance_persona.py` | 92 | NONE | - | Reconnaissance Persona — intelligence gathering specialist. |
| `xlayer_ai/prompts/personas/summary_persona.py` | 105 | NONE | - | Summary Persona — security analysis and reporting specialist. |
| `xlayer_ai/prompts/personas/supervisor_persona.py` | 101 | NONE | - | Supervisor Persona — multi-agent orchestration specialist. |
| `xlayer_ai/prompts/swarm/__init__.py` | 18 | NONE | - | Swarm prompts for XLayer AI multi-agent coordination. |
| `xlayer_ai/prompts/swarm/initaccess.py` | 40 | NONE | - | Swarm architecture prompt for Initial Access agent (XLayer AI). |
| `xlayer_ai/prompts/swarm/planner.py` | 40 | NONE | - | Swarm architecture prompt for Planner agent (XLayer AI). |
| `xlayer_ai/prompts/swarm/recon.py` | 39 | NONE | - | Swarm architecture prompt for Reconnaissance agent (XLayer AI). |
| `xlayer_ai/prompts/swarm/summary.py` | 29 | NONE | - | Swarm architecture prompt for Summary agent (XLayer AI). |
| `xlayer_ai/prompts/system.py` | 99 | NONE | - | XLayer AI System Prompts - Core identity and philosophy |
| `xlayer_ai/src/__init__.py` | 6 | NONE | - | XLayer AI Source - New swarm-based multi-agent architecture. |
| `xlayer_ai/src/agent/__init__.py` | 14 | NONE | - | XLayer AI Agents — custom engine. |
| `xlayer_ai/src/agent/coordinator.py` | 834 | MED | except Exception:7 | Coordinator — XBOW-Style Persistent Orchestration Engine |
| `xlayer_ai/src/agent/solver.py` | 279 | LOW | except Exception:3 | Solver (XBOW: Autonomous Agent) — Short-Lived Exploitation Runtime |
| `xlayer_ai/src/agent/swarm/InitAccess.py` | 31 | NONE | - | Initial Access swarm agent — vulnerability exploitation specialist. |
| `xlayer_ai/src/agent/swarm/Planner.py` | 25 | NONE | - | Planner swarm agent — strategic planning specialist. |
| `xlayer_ai/src/agent/swarm/Recon.py` | 25 | NONE | - | Reconnaissance swarm agent — intelligence gathering specialist. |
| `xlayer_ai/src/agent/swarm/Summary.py` | 25 | NONE | - | Summary swarm agent — security report generation specialist. |
| `xlayer_ai/src/agent/swarm/Supervisor.py` | 32 | NONE | - | Supervisor swarm agent — multi-agent orchestration specialist. |
| `xlayer_ai/src/agent/swarm/__init__.py` | 33 | NONE | - | XLayer AI Swarm Agents — specialist agents for multi-agent orchestration. |
| `xlayer_ai/src/agent/validator.py` | 479 | MED | verify=False:1, except Exception:3 | Validator (XBOW: Validators) — Zero-False-Positive Replay Validation |
| `xlayer_ai/src/graph/__init__.py` | 10 | NONE | - | XLayer AI Graph - Swarm graph definitions and compilation. |
| `xlayer_ai/src/graph/swarm.py` | 30 | NONE | - | from xlayer_ai.src.agent.swarm.Recon import make_recon_agent |
| `xlayer_ai/src/prompts/__init__.py` | 3 | NONE | - | XLayer AI Prompt Loader - loads and composes agent prompts. |
| `xlayer_ai/src/prompts/prompt_loader.py` | 64 | NONE | - | Prompt loader for swarm agents. |
| `xlayer_ai/src/tools/__init__.py` | 17 | NONE | - | XLayer AI Tools — hunter tool wrappers + JIT + OOB |
| `xlayer_ai/src/tools/browser_tool.py` | 321 | LOW | except Exception:4 | Browser Tools — Steerable Browser for Solver Agents (XBOW-style) |
| `xlayer_ai/src/tools/external_tools.py` | 166 | MED | subprocess:2, except Exception:2 | External / binary tools — run allowlisted hacking tools (nmap, etc.) from the agent. |
| `xlayer_ai/src/tools/handoff.py` | 88 | NONE | - | Handoff tools for swarm agents. |
| `xlayer_ai/src/tools/hunter_tools.py` | 751 | HIGH | shell=True:1, subprocess:1, verify=False:1, except Exception:16 | Custom @tool wrappers around XLayer's 16 hunters. |
| `xlayer_ai/src/tools/jit_engine.py` | 216 | HIGH | subprocess:1, os.system:1, eval/exec:1 | JIT Execution Engine — runs agent-generated Python exploit scripts in a sandboxed subprocess. |
| `xlayer_ai/src/tools/oob_server.py` | 427 | MED | except Exception:5 | OOB (Out-of-Band) Callback Server — detects blind vulnerabilities. |
| `xlayer_ai/src/utils/__init__.py` | 3 | NONE | - | XLayer AI Source Utilities - LLM management, memory, MCP, and swarm helpers. |
| `xlayer_ai/src/utils/llm/__init__.py` | 3 | NONE | - | LLM utilities bridge - re-exports from xlayer_ai.llm. |
| `xlayer_ai/src/utils/llm/config_manager.py` | 26 | NONE | - | Re-exports LLM config manager from the core llm module. |
| `xlayer_ai/src/utils/mcp/__init__.py` | 3 | NONE | - | MCP utilities bridge. |
| `xlayer_ai/src/utils/mcp/mcp_loader.py` | 10 | NONE | - | Re-exports MCP loader from the core utils module. |
| `xlayer_ai/src/utils/memory.py` | 33 | NONE | - | Shared memory store for the swarm agent system. |
| `xlayer_ai/src/utils/swarm/__init__.py` | 3 | NONE | - | Swarm utilities bridge. |
| `xlayer_ai/src/utils/swarm/swarm.py` | 14 | NONE | - | Re-exports the swarm creation utility from the core package. |
| `xlayer_ai/tools/__init__.py` | 17 | NONE | - | XLayer AI Tools - Low-level utilities for scanning and exploitation |
| `xlayer_ai/tools/adaptive_engine.py` | 476 | LOW | except Exception:2 | XLayer AI - Adaptive Engine |
| `xlayer_ai/tools/browser.py` | 438 | MED | except Exception:6 | XLayer AI Headless Browser - Playwright-based browser automation for exploitation |
| `xlayer_ai/tools/crawler.py` | 520 | MED | except Exception:5 | XLayer AI Web Crawler - Recursive web crawler for endpoint discovery |
| `xlayer_ai/tools/cve_ingest.py` | 106 | LOW | except Exception:1 | XBOW 4.3 (optional): CVE ingest — fetch recent CVEs from NVD and expose for attack templates. |
| `xlayer_ai/tools/http_client.py` | 404 | LOW | except Exception:2 | XLayer AI HTTP Client - Async HTTP client with logging and interception |
| `xlayer_ai/tools/mutation_engine.py` | 1637 | HIGH | eval/exec:4, except Exception:3 | XLayer AI - Mutation Engine |
| `xlayer_ai/tools/pacing.py` | 29 | LOW | except Exception:1 | XBOW 4.1: Request pacing (jitter) — configurable random delay between requests. |
| `xlayer_ai/tools/payload_manager.py` | 563 | HIGH | eval/exec:2 | XLayer AI Payload Manager - Payload database and context-aware selection |
| `xlayer_ai/tools/probe_first.py` | 176 | LOW | except Exception:2 | Probe-first (XBOW-style): lightweight probe before full payloads. |
| `xlayer_ai/tools/scanner.py` | 256 | LOW | except Exception:1 | XLayer AI Port Scanner - Async port scanner using native sockets |
| `xlayer_ai/utils/__init__.py` | 13 | NONE | - | XLayer AI Utilities - Logging, validation, and helper functions |
| `xlayer_ai/utils/logger.py` | 59 | NONE | - | XLayer AI Logger - Logging configuration using Loguru |
| `xlayer_ai/utils/mcp/mcp_loader.py` | 73 | NONE | - | MCP (Model Context Protocol) tool loader. |
| `xlayer_ai/utils/validators.py` | 106 | LOW | except Exception:4 | XLayer AI Validators - Input validation utilities |

## Notes

- `packages/xlayer_hunter/*` appears to be packaged/duplicate implementation; audited but should be confirmed whether active in runtime.
- Risk scoring is static heuristic; manual validation was applied to critical findings above.
- `eval/exec` and `os.system` flags can be false positives when they appear inside exploit payload strings (for example SSTI/XSS payload libraries), not as executed Python calls.

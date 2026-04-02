"""
XLayer AI Core - Agent implementations and execution engine

Components:
- Agents: Planner, Recon, Exploit, Reporter
- Hunters: SQLi, XSS, Auth, SSRF, LFI
- Executor: Workflow execution engine
- Coordinator: Multi-agent orchestration
"""

from xlayer_hunter.core.planner import PlannerAgent, MissionState
from xlayer_hunter.core.recon import ReconAgent
from xlayer_hunter.core.exploit import ExploitAgent
from xlayer_hunter.core.reporter import Reporter
from xlayer_hunter.core.executor import (
    XLayerExecutor,
    ExecutionPhase,
    ExecutionEvent,
    EventType,
    MissionConfig,
    get_executor,
    run_scan
)
from xlayer_hunter.core.agent_coordinator import AgentCoordinator
from xlayer_hunter.core.agents import (
    AgentRegistry,
    AgentCategory,
    get_agent,
    get_agent_info,
    list_agents,
    get_hunters,
    get_core_agents
)

__all__ = [
    # Core Agents
    "PlannerAgent",
    "MissionState",
    "ReconAgent",
    "ExploitAgent",
    "Reporter",
    
    # Executor
    "XLayerExecutor",
    "ExecutionPhase",
    "ExecutionEvent",
    "EventType",
    "MissionConfig",
    "get_executor",
    "run_scan",
    
    # Coordinator
    "AgentCoordinator",
    
    # Agent Registry
    "AgentRegistry",
    "AgentCategory",
    "get_agent",
    "get_agent_info",
    "list_agents",
    "get_hunters",
    "get_core_agents",
]

"""
XLayer AI Agents - All Agent Definitions

This module provides a central registry for all XLayer AI agents.
Each agent is a specialized component in the vulnerability hunting pipeline.

Agent Categories:
1. Core Agents - Main workflow orchestrators
2. Hunter Agents - Vulnerability-specific scanners
3. Tool Agents - Utility agents for specific tasks

Usage:
    from xlayer_hunter.core.agents import get_agent, list_agents, AgentRegistry
    
    # Get a specific agent
    sqli_hunter = get_agent("sqli")
    
    # List all available agents
    agents = list_agents()
    
    # Get agents by category
    hunters = AgentRegistry.get_by_category("hunters")
"""

from typing import Dict, List, Any, Optional, Type
from dataclasses import dataclass
from enum import Enum

from xlayer_hunter.utils.agent_manager import AgentManager


class AgentCategory(str, Enum):
    """Agent categories"""
    CORE = "core"
    HUNTER = "hunter"
    TOOL = "tool"
    LLM = "llm"


@dataclass
class AgentDefinition:
    """Definition of an agent"""
    name: str
    category: AgentCategory
    description: str
    capabilities: List[str]
    module_path: str
    class_name: str
    
    @property
    def display_name(self) -> str:
        return AgentManager.get_display_name(self.name)
    
    @property
    def avatar(self) -> str:
        return AgentManager.get_avatar(self.name)
    
    @property
    def color(self) -> str:
        return AgentManager.get_frontend_color(self.name)


class AgentRegistry:
    """
    Central registry for all XLayer AI agents
    
    This registry provides:
    - Agent discovery and lookup
    - Lazy loading of agent classes
    - Category-based filtering
    - Capability-based search
    """
    
    _agents: Dict[str, AgentDefinition] = {}
    _instances: Dict[str, Any] = {}
    
    # Agent definitions
    AGENT_DEFINITIONS = {
        # Core Agents
        "planner": AgentDefinition(
            name="planner",
            category=AgentCategory.CORE,
            description="Mission orchestrator - coordinates all phases",
            capabilities=["orchestration", "task_routing", "state_management"],
            module_path="xlayer_hunter.core.planner",
            class_name="PlannerAgent"
        ),
        "recon": AgentDefinition(
            name="recon",
            category=AgentCategory.CORE,
            description="Reconnaissance agent - maps attack surface",
            capabilities=["dns_resolution", "port_scanning", "tech_detection", "crawling"],
            module_path="xlayer_hunter.core.recon",
            class_name="ReconAgent"
        ),
        "exploit": AgentDefinition(
            name="exploit",
            category=AgentCategory.CORE,
            description="Exploitation agent - verifies vulnerabilities",
            capabilities=["payload_execution", "browser_automation", "evidence_capture"],
            module_path="xlayer_hunter.core.exploit",
            class_name="ExploitAgent"
        ),
        "reporter": AgentDefinition(
            name="reporter",
            category=AgentCategory.CORE,
            description="Report agent - generates findings documentation",
            capabilities=["report_generation", "cvss_calculation", "remediation"],
            module_path="xlayer_hunter.core.reporter",
            class_name="ReportAgent"
        ),
        
        # Hunter Agents
        "sqli": AgentDefinition(
            name="sqli",
            category=AgentCategory.HUNTER,
            description="SQL Injection hunter - detects SQLi vulnerabilities",
            capabilities=["error_based", "boolean_blind", "time_blind", "union_based"],
            module_path="xlayer_hunter.core.vuln_hunters.sqli",
            class_name="SQLiHunter"
        ),
        "xss": AgentDefinition(
            name="xss",
            category=AgentCategory.HUNTER,
            description="XSS hunter - detects cross-site scripting",
            capabilities=["reflected", "stored", "dom_based"],
            module_path="xlayer_hunter.core.vuln_hunters.xss",
            class_name="XSSHunter"
        ),
        "auth": AgentDefinition(
            name="auth",
            category=AgentCategory.HUNTER,
            description="Auth hunter - detects authentication flaws",
            capabilities=["bypass", "idor", "session", "jwt", "privilege_escalation"],
            module_path="xlayer_hunter.core.vuln_hunters.auth",
            class_name="AuthHunter"
        ),
        "ssrf": AgentDefinition(
            name="ssrf",
            category=AgentCategory.HUNTER,
            description="SSRF hunter - detects server-side request forgery",
            capabilities=["internal_access", "cloud_metadata", "file_read"],
            module_path="xlayer_hunter.core.vuln_hunters.ssrf",
            class_name="SSRFHunter"
        ),
        "lfi": AgentDefinition(
            name="lfi",
            category=AgentCategory.HUNTER,
            description="LFI hunter - detects file inclusion vulnerabilities",
            capabilities=["path_traversal", "file_inclusion", "log_poisoning"],
            module_path="xlayer_hunter.core.vuln_hunters.lfi",
            class_name="LFIHunter"
        ),
        
        # Tool Agents
        "browser": AgentDefinition(
            name="browser",
            category=AgentCategory.TOOL,
            description="Browser tool - headless browser automation",
            capabilities=["page_navigation", "screenshot", "js_execution"],
            module_path="xlayer_hunter.tools.browser",
            class_name="HeadlessBrowser"
        ),
        "scanner": AgentDefinition(
            name="scanner",
            category=AgentCategory.TOOL,
            description="Port scanner - network reconnaissance",
            capabilities=["port_scan", "service_detection", "banner_grab"],
            module_path="xlayer_hunter.tools.scanner",
            class_name="PortScanner"
        ),
        "crawler": AgentDefinition(
            name="crawler",
            category=AgentCategory.TOOL,
            description="Web crawler - endpoint discovery",
            capabilities=["link_extraction", "form_discovery", "api_detection"],
            module_path="xlayer_hunter.tools.crawler",
            class_name="WebCrawler"
        ),
    }
    
    @classmethod
    def register(cls, definition: AgentDefinition) -> None:
        """Register an agent definition"""
        cls._agents[definition.name] = definition
    
    @classmethod
    def get_definition(cls, name: str) -> Optional[AgentDefinition]:
        """Get agent definition by name"""
        # First check custom registrations
        if name in cls._agents:
            return cls._agents[name]
        # Then check built-in definitions
        return cls.AGENT_DEFINITIONS.get(name)
    
    @classmethod
    def get_instance(cls, name: str, **kwargs) -> Optional[Any]:
        """
        Get or create an agent instance
        
        Args:
            name: Agent name
            **kwargs: Arguments to pass to agent constructor
            
        Returns:
            Agent instance or None if not found
        """
        # Return cached instance if exists
        if name in cls._instances:
            return cls._instances[name]
        
        # Get definition
        definition = cls.get_definition(name)
        if not definition:
            return None
        
        # Lazy load the agent class
        try:
            import importlib
            module = importlib.import_module(definition.module_path)
            agent_class = getattr(module, definition.class_name)
            
            # Create instance
            instance = agent_class(**kwargs)
            cls._instances[name] = instance
            
            return instance
            
        except (ImportError, AttributeError) as e:
            # Log error but don't crash
            return None
    
    @classmethod
    def get_by_category(cls, category: AgentCategory) -> List[AgentDefinition]:
        """Get all agents in a category"""
        return [
            defn for defn in cls.AGENT_DEFINITIONS.values()
            if defn.category == category
        ]
    
    @classmethod
    def get_by_capability(cls, capability: str) -> List[AgentDefinition]:
        """Get all agents with a specific capability"""
        return [
            defn for defn in cls.AGENT_DEFINITIONS.values()
            if capability in defn.capabilities
        ]
    
    @classmethod
    def list_all(cls) -> List[AgentDefinition]:
        """List all registered agents"""
        # Combine built-in and custom registrations
        all_agents = dict(cls.AGENT_DEFINITIONS)
        all_agents.update(cls._agents)
        return list(all_agents.values())
    
    @classmethod
    def clear_instances(cls) -> None:
        """Clear all cached instances"""
        cls._instances.clear()


# Convenience functions
def get_agent(name: str, **kwargs) -> Optional[Any]:
    """Get an agent instance by name"""
    return AgentRegistry.get_instance(name, **kwargs)


def get_agent_info(name: str) -> Optional[Dict[str, Any]]:
    """Get agent information"""
    definition = AgentRegistry.get_definition(name)
    if definition:
        return {
            "name": definition.name,
            "display_name": definition.display_name,
            "avatar": definition.avatar,
            "color": definition.color,
            "category": definition.category.value,
            "description": definition.description,
            "capabilities": definition.capabilities
        }
    return None


def list_agents(category: Optional[str] = None) -> List[Dict[str, Any]]:
    """List all agents, optionally filtered by category"""
    if category:
        try:
            cat = AgentCategory(category)
            definitions = AgentRegistry.get_by_category(cat)
        except ValueError:
            definitions = []
    else:
        definitions = AgentRegistry.list_all()
    
    return [
        {
            "name": d.name,
            "display_name": d.display_name,
            "avatar": d.avatar,
            "category": d.category.value,
            "description": d.description
        }
        for d in definitions
    ]


def get_hunters() -> List[str]:
    """Get list of hunter agent names"""
    return [d.name for d in AgentRegistry.get_by_category(AgentCategory.HUNTER)]


def get_core_agents() -> List[str]:
    """Get list of core agent names"""
    return [d.name for d in AgentRegistry.get_by_category(AgentCategory.CORE)]


# Export all
__all__ = [
    "AgentCategory",
    "AgentDefinition", 
    "AgentRegistry",
    "get_agent",
    "get_agent_info",
    "list_agents",
    "get_hunters",
    "get_core_agents",
]

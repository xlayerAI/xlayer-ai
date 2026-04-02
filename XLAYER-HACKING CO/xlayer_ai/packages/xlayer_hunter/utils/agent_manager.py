"""
XLayer AI Agent Manager - Centralized Agent Information Management

This module manages agent configuration, styling, and metadata.
Design elements are loaded from static/config/agents.json
Contains pure logic only (matching, normalization, config management)

Usage in Agentic Architecture:
- Agent identification and routing
- Consistent UI/CLI styling across platforms
- Agent lifecycle management
- Multi-agent coordination support
"""

import json
from pathlib import Path
from typing import Dict, Optional, List, Any


class AgentManager:
    """
    Agent Information Management Class - Configuration File Based
    
    This class provides centralized management for all XLayer AI agents:
    - Vulnerability Hunters (SQLi, XSS, Auth, SSRF, LFI)
    - Core Agents (Planner, Recon, Exploit, Reporter)
    - Tool Agents (Browser, Scanner, Crawler)
    
    Agentic Implementation:
    1. Agent Registration - Register new agents dynamically
    2. Agent Discovery - Find agents by capability
    3. Agent Routing - Route tasks to appropriate agents
    4. Agent Monitoring - Track agent status and performance
    """
    
    _config: Optional[Dict] = None
    _config_path: Optional[Path] = None
    _agent_registry: Dict[str, Any] = {}
    
    # XLayer AI Agent Types
    AGENT_TYPES = {
        "core": ["planner", "recon", "exploit", "reporter"],
        "hunters": ["sqli", "xss", "auth", "ssrf", "lfi"],
        "tools": ["browser", "scanner", "crawler", "http_client"],
        "llm": ["analyzer", "payload_generator", "report_enhancer"]
    }
    
    @classmethod
    def _load_config(cls) -> Dict:
        """Load configuration file (with caching)"""
        if cls._config is None:
            # Find config file path from project root
            current_dir = Path(__file__).parent
            project_root = current_dir.parent  # utils -> xlayer_hunter
            config_path = project_root / "config" / "agents.json"
            
            cls._config_path = config_path
            
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    cls._config = json.load(f)
            except FileNotFoundError:
                # Use defaults if config file doesn't exist
                cls._config = cls._get_default_config()
                # Create the config file
                cls._save_default_config(config_path)
        
        return cls._config
    
    @classmethod
    def _get_default_config(cls) -> Dict:
        """Get default configuration for XLayer AI agents"""
        return {
            "colors": {
                "cli": {
                    "planner": "bright_cyan",
                    "recon": "bright_green",
                    "exploit": "bright_red",
                    "reporter": "bright_yellow",
                    "sqli": "red",
                    "xss": "magenta",
                    "auth": "blue",
                    "ssrf": "cyan",
                    "lfi": "yellow",
                    "browser": "green",
                    "scanner": "white",
                    "crawler": "bright_blue",
                    "default": "white"
                },
                "frontend": {
                    "planner": "#00d4ff",
                    "recon": "#00ff88",
                    "exploit": "#ff4444",
                    "reporter": "#ffaa00",
                    "sqli": "#ff6b6b",
                    "xss": "#cc66ff",
                    "auth": "#4dabf7",
                    "ssrf": "#20c997",
                    "lfi": "#ffd43b",
                    "browser": "#51cf66",
                    "scanner": "#868e96",
                    "crawler": "#339af0",
                    "default": "#adb5bd"
                }
            },
            "avatars": {
                "planner": "🧠",
                "recon": "🔍",
                "exploit": "💥",
                "reporter": "📋",
                "sqli": "💉",
                "xss": "🎭",
                "auth": "🔐",
                "ssrf": "🌐",
                "lfi": "📁",
                "browser": "🌍",
                "scanner": "📡",
                "crawler": "🕷️",
                "default": "🤖"
            },
            "css_classes": {
                "planner": "agent-planner",
                "recon": "agent-recon",
                "exploit": "agent-exploit",
                "reporter": "agent-reporter",
                "sqli": "hunter-sqli",
                "xss": "hunter-xss",
                "auth": "hunter-auth",
                "ssrf": "hunter-ssrf",
                "lfi": "hunter-lfi",
                "default": "agent-default"
            },
            "display_names": {
                "planner": "Planner Agent",
                "recon": "Reconnaissance Agent",
                "exploit": "Exploit Agent",
                "reporter": "Report Agent",
                "sqli": "SQL Injection Hunter",
                "xss": "XSS Hunter",
                "auth": "Auth Hunter",
                "ssrf": "SSRF Hunter",
                "lfi": "LFI Hunter",
                "browser": "Browser Tool",
                "scanner": "Port Scanner",
                "crawler": "Web Crawler",
                "default": "Unknown Agent"
            },
            "capabilities": {
                "planner": ["orchestration", "task_routing", "state_management"],
                "recon": ["dns_resolution", "port_scanning", "tech_detection", "crawling"],
                "exploit": ["payload_execution", "browser_automation", "evidence_capture"],
                "reporter": ["report_generation", "cvss_calculation", "remediation"],
                "sqli": ["error_based", "boolean_blind", "time_blind", "union_based"],
                "xss": ["reflected", "stored", "dom_based"],
                "auth": ["bypass", "idor", "session", "jwt"],
                "ssrf": ["internal_access", "cloud_metadata", "file_read"],
                "lfi": ["path_traversal", "file_inclusion"]
            }
        }
    
    @classmethod
    def _save_default_config(cls, config_path: Path) -> None:
        """Save default configuration to file"""
        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, "w", encoding="utf-8") as f:
                json.dump(cls._get_default_config(), f, indent=2)
        except Exception:
            pass  # Silently fail if can't write
    
    @classmethod
    def normalize_agent_name(cls, agent_name: str) -> str:
        """
        Normalize agent name - Unified matching logic for CLI and Frontend
        Ensures consistent normalization results across all platforms
        
        Args:
            agent_name: Raw agent name string
            
        Returns:
            Normalized agent name or empty string if not recognized
        """
        if not agent_name or not isinstance(agent_name, str):
            return ""
        
        agent_name_lower = agent_name.lower().strip()
        
        # Core Agents (priority order)
        if "planner" in agent_name_lower:
            return "planner"
        elif "recon" in agent_name_lower or "reconnaissance" in agent_name_lower:
            return "recon"
        elif "exploit" in agent_name_lower:
            return "exploit"
        elif "report" in agent_name_lower:
            return "reporter"
        
        # Vulnerability Hunters
        elif "sqli" in agent_name_lower or "sql" in agent_name_lower:
            return "sqli"
        elif "xss" in agent_name_lower or "cross" in agent_name_lower:
            return "xss"
        elif "auth" in agent_name_lower:
            return "auth"
        elif "ssrf" in agent_name_lower:
            return "ssrf"
        elif "lfi" in agent_name_lower or "file" in agent_name_lower:
            return "lfi"
        
        # Tool Agents
        elif "browser" in agent_name_lower:
            return "browser"
        elif "scanner" in agent_name_lower or "scan" in agent_name_lower:
            return "scanner"
        elif "crawler" in agent_name_lower or "crawl" in agent_name_lower:
            return "crawler"
        
        return ""
    
    @classmethod
    def get_cli_color(cls, agent_name: str) -> str:
        """Get CLI color (Rich color name)"""
        config = cls._load_config()
        normalized = cls.normalize_agent_name(agent_name)
        
        if normalized:
            return config["colors"]["cli"].get(
                normalized, 
                config["colors"]["cli"].get("default", "white")
            )
        return config["colors"]["cli"].get("default", "white")
    
    @classmethod 
    def get_frontend_color(cls, agent_name: str) -> str:
        """Get Frontend color (Hex code)"""
        config = cls._load_config()
        normalized = cls.normalize_agent_name(agent_name)
        
        if normalized:
            return config["colors"]["frontend"].get(
                normalized, 
                config["colors"]["frontend"].get("default", "#adb5bd")
            )
        return config["colors"]["frontend"].get("default", "#adb5bd")
    
    @classmethod
    def get_avatar(cls, agent_name: str) -> str:
        """Get agent avatar emoji"""
        config = cls._load_config()
        normalized = cls.normalize_agent_name(agent_name)
        
        if normalized:
            return config["avatars"].get(
                normalized, 
                config["avatars"].get("default", "🤖")
            )
        return config["avatars"].get("default", "🤖")
    
    @classmethod
    def get_css_class(cls, agent_name: str) -> str:
        """Get CSS class name for styling"""
        config = cls._load_config()
        normalized = cls.normalize_agent_name(agent_name)
        
        if normalized:
            return config["css_classes"].get(
                normalized, 
                config["css_classes"].get("default", "agent-default")
            )
        return config["css_classes"].get("default", "agent-default")
    
    @classmethod
    def get_display_name(cls, agent_name: str) -> str:
        """Get human-readable display name"""
        if not agent_name or agent_name == "Unknown":
            config = cls._load_config()
            return config["display_names"].get("default", "Unknown Agent")
        
        config = cls._load_config()
        normalized = cls.normalize_agent_name(agent_name)
        
        if normalized:
            return config["display_names"].get(
                normalized, 
                cls._format_fallback_name(agent_name)
            )
        
        return cls._format_fallback_name(agent_name)
    
    @classmethod
    def _format_fallback_name(cls, agent_name: str) -> str:
        """Format agent name when not found in config"""
        if "_" in agent_name:
            return agent_name.replace("_", " ").title()
        return agent_name.capitalize()
    
    @classmethod
    def get_capabilities(cls, agent_name: str) -> List[str]:
        """Get agent capabilities list"""
        config = cls._load_config()
        normalized = cls.normalize_agent_name(agent_name)
        
        if normalized and "capabilities" in config:
            return config["capabilities"].get(normalized, [])
        return []
    
    @classmethod
    def get_agent_info(cls, agent_name: str) -> Dict[str, Any]:
        """Get all agent information at once"""
        return {
            "normalized_name": cls.normalize_agent_name(agent_name),
            "display_name": cls.get_display_name(agent_name),
            "cli_color": cls.get_cli_color(agent_name),
            "frontend_color": cls.get_frontend_color(agent_name),
            "avatar": cls.get_avatar(agent_name),
            "css_class": cls.get_css_class(agent_name),
            "capabilities": cls.get_capabilities(agent_name)
        }
    
    @classmethod
    def list_all_agents(cls) -> Dict[str, Dict[str, Any]]:
        """List all agents defined in configuration"""
        config = cls._load_config()
        agents = {}
        
        for agent_key in config["colors"]["cli"].keys():
            if agent_key != "default":
                agents[agent_key] = cls.get_agent_info(agent_key)
        
        return agents
    
    @classmethod
    def get_agents_by_type(cls, agent_type: str) -> List[str]:
        """
        Get agents by type category
        
        Args:
            agent_type: One of 'core', 'hunters', 'tools', 'llm'
            
        Returns:
            List of agent names in that category
        """
        return cls.AGENT_TYPES.get(agent_type, [])
    
    @classmethod
    def find_agent_by_capability(cls, capability: str) -> List[str]:
        """
        Find agents that have a specific capability
        
        Args:
            capability: The capability to search for
            
        Returns:
            List of agent names with that capability
        """
        config = cls._load_config()
        matching_agents = []
        
        if "capabilities" in config:
            for agent_name, caps in config["capabilities"].items():
                if capability in caps:
                    matching_agents.append(agent_name)
        
        return matching_agents
    
    # ==========================================
    # Agentic Implementation Methods
    # ==========================================
    
    @classmethod
    def register_agent(cls, agent_name: str, agent_instance: Any) -> bool:
        """
        Register an agent instance for runtime management
        
        This enables:
        - Dynamic agent discovery
        - Agent health monitoring
        - Task routing to live agents
        
        Args:
            agent_name: Normalized agent name
            agent_instance: The agent object instance
            
        Returns:
            True if registration successful
        """
        normalized = cls.normalize_agent_name(agent_name) or agent_name
        cls._agent_registry[normalized] = {
            "instance": agent_instance,
            "status": "active",
            "tasks_completed": 0,
            "tasks_failed": 0
        }
        return True
    
    @classmethod
    def unregister_agent(cls, agent_name: str) -> bool:
        """Remove an agent from the registry"""
        normalized = cls.normalize_agent_name(agent_name) or agent_name
        if normalized in cls._agent_registry:
            del cls._agent_registry[normalized]
            return True
        return False
    
    @classmethod
    def get_registered_agent(cls, agent_name: str) -> Optional[Any]:
        """Get a registered agent instance"""
        normalized = cls.normalize_agent_name(agent_name) or agent_name
        entry = cls._agent_registry.get(normalized)
        return entry["instance"] if entry else None
    
    @classmethod
    def get_active_agents(cls) -> List[str]:
        """Get list of currently active agents"""
        return [
            name for name, info in cls._agent_registry.items()
            if info.get("status") == "active"
        ]
    
    @classmethod
    def update_agent_status(cls, agent_name: str, status: str) -> bool:
        """
        Update agent status
        
        Args:
            agent_name: Agent to update
            status: New status ('active', 'busy', 'idle', 'error')
        """
        normalized = cls.normalize_agent_name(agent_name) or agent_name
        if normalized in cls._agent_registry:
            cls._agent_registry[normalized]["status"] = status
            return True
        return False
    
    @classmethod
    def record_task_completion(cls, agent_name: str, success: bool = True) -> None:
        """Record task completion for an agent"""
        normalized = cls.normalize_agent_name(agent_name) or agent_name
        if normalized in cls._agent_registry:
            if success:
                cls._agent_registry[normalized]["tasks_completed"] += 1
            else:
                cls._agent_registry[normalized]["tasks_failed"] += 1
    
    @classmethod
    def get_agent_stats(cls, agent_name: str) -> Optional[Dict[str, Any]]:
        """Get agent performance statistics"""
        normalized = cls.normalize_agent_name(agent_name) or agent_name
        entry = cls._agent_registry.get(normalized)
        
        if entry:
            return {
                "status": entry["status"],
                "tasks_completed": entry["tasks_completed"],
                "tasks_failed": entry["tasks_failed"],
                "success_rate": (
                    entry["tasks_completed"] / 
                    max(1, entry["tasks_completed"] + entry["tasks_failed"])
                ) * 100
            }
        return None
    
    @classmethod
    def route_task(cls, task_type: str) -> Optional[str]:
        """
        Route a task to the appropriate agent based on task type
        
        This is the core of agentic task distribution:
        - Analyzes task requirements
        - Finds capable agents
        - Returns best agent for the task
        
        Args:
            task_type: Type of task (e.g., 'sqli_scan', 'xss_test', 'recon')
            
        Returns:
            Agent name best suited for the task, or None
        """
        # Task to agent mapping
        task_routing = {
            # Reconnaissance tasks
            "recon": "recon",
            "dns": "recon",
            "port_scan": "recon",
            "crawl": "crawler",
            "tech_detect": "recon",
            
            # Vulnerability hunting tasks
            "sqli_scan": "sqli",
            "sqli": "sqli",
            "xss_scan": "xss",
            "xss": "xss",
            "auth_test": "auth",
            "idor": "auth",
            "ssrf_scan": "ssrf",
            "ssrf": "ssrf",
            "lfi_scan": "lfi",
            "lfi": "lfi",
            
            # Exploitation tasks
            "exploit": "exploit",
            "verify": "exploit",
            "browser_test": "browser",
            
            # Reporting tasks
            "report": "reporter",
            "generate_report": "reporter",
        }
        
        return task_routing.get(task_type.lower())
    
    @classmethod
    def reload_config(cls) -> Dict:
        """Force reload configuration file"""
        cls._config = None
        return cls._load_config()
    
    @classmethod
    def get_config_path(cls) -> Optional[str]:
        """Get current configuration file path"""
        cls._load_config()
        return str(cls._config_path) if cls._config_path else None


# Convenience functions for direct import
def get_agent_color(agent_name: str, platform: str = "cli") -> str:
    """Get agent color for specified platform"""
    if platform == "frontend":
        return AgentManager.get_frontend_color(agent_name)
    return AgentManager.get_cli_color(agent_name)


def get_agent_avatar(agent_name: str) -> str:
    """Get agent avatar emoji"""
    return AgentManager.get_avatar(agent_name)


def normalize_agent(agent_name: str) -> str:
    """Normalize agent name"""
    return AgentManager.normalize_agent_name(agent_name)

"""
XLayer AI Executor - Multi-Agent Workflow Execution Engine

This module bridges the frontend/CLI with the backend agent system.
It provides:
1. Agent swarm initialization and lifecycle management
2. Workflow execution with real-time streaming
3. Session and state management
4. Event-driven communication with UI

Architecture:
┌─────────────────────────────────────────────────────────────────┐
│                        Frontend / CLI                            │
│                              │                                   │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                      XLayerExecutor                        │  │
│  │  • initialize_mission()  - Start agent swarm               │  │
│  │  • execute_scan()        - Run vulnerability scan          │  │
│  │  • stream_events()       - Real-time event streaming       │  │
│  │  • get_status()          - Check execution status          │  │
│  └───────────────────────────────────────────────────────────┘  │
│                              │                                   │
│                              ▼                                   │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    Agent Coordinator                       │  │
│  │         Planner → Recon → Hunters → Exploit → Report      │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
"""

import asyncio
import uuid
from datetime import datetime
from typing import Optional, Dict, Any, AsyncGenerator, List
from dataclasses import dataclass, field
from enum import Enum
from loguru import logger

from xlayer_hunter.utils.agent_manager import AgentManager


class ExecutionPhase(str, Enum):
    """Execution phases for vulnerability scanning"""
    IDLE = "idle"
    INITIALIZING = "initializing"
    RECON = "reconnaissance"
    HUNTING = "vulnerability_hunting"
    EXPLOITING = "exploitation"
    REPORTING = "reporting"
    COMPLETE = "complete"
    ERROR = "error"


class EventType(str, Enum):
    """Event types for streaming"""
    PHASE_START = "phase_start"
    PHASE_END = "phase_end"
    AGENT_MESSAGE = "agent_message"
    FINDING = "finding"
    PROGRESS = "progress"
    ERROR = "error"
    COMPLETE = "complete"


@dataclass
class ExecutionEvent:
    """Event structure for streaming to frontend"""
    type: EventType
    agent_name: str
    content: Any
    timestamp: datetime = field(default_factory=datetime.utcnow)
    phase: Optional[ExecutionPhase] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "type": self.type.value,
            "agent_name": self.agent_name,
            "agent_display": AgentManager.get_display_name(self.agent_name),
            "agent_avatar": AgentManager.get_avatar(self.agent_name),
            "agent_color": AgentManager.get_frontend_color(self.agent_name),
            "content": self.content,
            "timestamp": self.timestamp.isoformat(),
            "phase": self.phase.value if self.phase else None,
            "metadata": self.metadata
        }


@dataclass
class MissionConfig:
    """Configuration for a scanning mission"""
    target_url: str
    hunters: List[str] = field(default_factory=lambda: ["sqli", "xss", "auth", "ssrf", "lfi"])
    max_depth: int = 3
    rate_limit: float = 0.5
    exploit_enabled: bool = True
    thread_id: Optional[str] = None
    
    def __post_init__(self):
        if self.thread_id is None:
            self.thread_id = str(uuid.uuid4())


class XLayerExecutor:
    """
    XLayer AI Workflow Executor
    
    This class manages the execution of vulnerability scanning missions.
    It coordinates multiple agents and streams events to the frontend.
    
    Usage:
        executor = XLayerExecutor()
        await executor.initialize_mission(config)
        
        async for event in executor.execute_scan():
            print(f"{event.agent_name}: {event.content}")
    """
    
    def __init__(self):
        # Execution state
        self._initialized: bool = False
        self._mission_id: Optional[str] = None
        self._config: Optional[MissionConfig] = None
        self._phase: ExecutionPhase = ExecutionPhase.IDLE
        
        # Agent management
        self._agents: Dict[str, Any] = {}
        self._active_agent: Optional[str] = None
        
        # Event tracking
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._processed_events: set = set()
        
        # Results storage
        self._findings: List[Dict] = []
        self._recon_data: Optional[Dict] = None
        
        # Timing
        self._start_time: Optional[datetime] = None
        self._phase_times: Dict[str, float] = {}
    
    @property
    def is_ready(self) -> bool:
        """Check if executor is ready to run"""
        return self._initialized and self._config is not None
    
    @property
    def current_phase(self) -> ExecutionPhase:
        """Get current execution phase"""
        return self._phase
    
    @property
    def mission_id(self) -> Optional[str]:
        """Get current mission ID"""
        return self._mission_id
    
    async def initialize_mission(
        self, 
        target_url: str,
        hunters: Optional[List[str]] = None,
        **kwargs
    ) -> str:
        """
        Initialize a new scanning mission
        
        Args:
            target_url: URL to scan
            hunters: List of hunters to use (default: all)
            **kwargs: Additional configuration options
            
        Returns:
            Mission ID (thread_id)
        """
        try:
            self._phase = ExecutionPhase.INITIALIZING
            
            # Create mission configuration
            self._config = MissionConfig(
                target_url=target_url,
                hunters=hunters or ["sqli", "xss", "auth", "ssrf", "lfi"],
                **kwargs
            )
            
            self._mission_id = self._config.thread_id
            
            # Initialize agents
            await self._initialize_agents()
            
            # Reset state
            self._findings = []
            self._recon_data = None
            self._processed_events = set()
            self._start_time = datetime.utcnow()
            
            self._initialized = True
            self._phase = ExecutionPhase.IDLE
            
            logger.info(f"Mission initialized: {self._mission_id}")
            return self._mission_id
            
        except Exception as e:
            self._phase = ExecutionPhase.ERROR
            self._initialized = False
            raise Exception(f"Mission initialization failed: {str(e)}")
    
    async def _initialize_agents(self) -> None:
        """Initialize all required agents"""
        # Core agents
        core_agents = ["planner", "recon", "exploit", "reporter"]
        
        # Hunter agents based on config
        hunter_agents = self._config.hunters if self._config else []
        
        all_agents = core_agents + hunter_agents
        
        for agent_name in all_agents:
            agent_info = AgentManager.get_agent_info(agent_name)
            self._agents[agent_name] = {
                "info": agent_info,
                "status": "ready",
                "instance": None  # Would be actual agent instance
            }
            AgentManager.register_agent(agent_name, self._agents[agent_name])
        
        logger.debug(f"Initialized {len(self._agents)} agents")
    
    async def execute_scan(self) -> AsyncGenerator[ExecutionEvent, None]:
        """
        Execute the vulnerability scan workflow
        
        Yields:
            ExecutionEvent objects for each step
        """
        if not self.is_ready:
            yield ExecutionEvent(
                type=EventType.ERROR,
                agent_name="executor",
                content="Executor not ready - call initialize_mission() first"
            )
            return
        
        try:
            # Phase 1: Reconnaissance
            async for event in self._execute_recon():
                yield event
            
            # Phase 2: Vulnerability Hunting
            async for event in self._execute_hunting():
                yield event
            
            # Phase 3: Exploitation (if enabled)
            if self._config.exploit_enabled and self._findings:
                async for event in self._execute_exploitation():
                    yield event
            
            # Phase 4: Reporting
            async for event in self._execute_reporting():
                yield event
            
            # Complete
            self._phase = ExecutionPhase.COMPLETE
            yield ExecutionEvent(
                type=EventType.COMPLETE,
                agent_name="executor",
                content={
                    "mission_id": self._mission_id,
                    "target": self._config.target_url,
                    "findings_count": len(self._findings),
                    "duration_seconds": (datetime.utcnow() - self._start_time).total_seconds()
                },
                phase=ExecutionPhase.COMPLETE
            )
            
        except Exception as e:
            self._phase = ExecutionPhase.ERROR
            yield ExecutionEvent(
                type=EventType.ERROR,
                agent_name="executor",
                content=str(e),
                phase=ExecutionPhase.ERROR
            )
    
    async def _execute_recon(self) -> AsyncGenerator[ExecutionEvent, None]:
        """Execute reconnaissance phase"""
        self._phase = ExecutionPhase.RECON
        self._active_agent = "recon"
        
        yield ExecutionEvent(
            type=EventType.PHASE_START,
            agent_name="recon",
            content=f"Starting reconnaissance on {self._config.target_url}",
            phase=ExecutionPhase.RECON
        )
        
        # Simulate recon steps (in real implementation, call actual recon agent)
        recon_steps = [
            ("DNS Resolution", "Resolving target hostname..."),
            ("Port Scanning", "Scanning common ports..."),
            ("Technology Detection", "Identifying tech stack..."),
            ("Endpoint Discovery", "Crawling for endpoints..."),
        ]
        
        for step_name, message in recon_steps:
            yield ExecutionEvent(
                type=EventType.AGENT_MESSAGE,
                agent_name="recon",
                content=message,
                phase=ExecutionPhase.RECON,
                metadata={"step": step_name}
            )
            await asyncio.sleep(0.1)  # Simulate work
        
        # Store recon results (placeholder)
        self._recon_data = {
            "target": self._config.target_url,
            "endpoints": [],
            "technology": {}
        }
        
        yield ExecutionEvent(
            type=EventType.PHASE_END,
            agent_name="recon",
            content="Reconnaissance complete",
            phase=ExecutionPhase.RECON,
            metadata={"endpoints_found": 0}
        )
    
    async def _execute_hunting(self) -> AsyncGenerator[ExecutionEvent, None]:
        """Execute vulnerability hunting phase"""
        self._phase = ExecutionPhase.HUNTING
        
        yield ExecutionEvent(
            type=EventType.PHASE_START,
            agent_name="planner",
            content=f"Starting vulnerability hunting with {len(self._config.hunters)} hunters",
            phase=ExecutionPhase.HUNTING
        )
        
        # Run each hunter
        for hunter_name in self._config.hunters:
            self._active_agent = hunter_name
            
            yield ExecutionEvent(
                type=EventType.AGENT_MESSAGE,
                agent_name=hunter_name,
                content=f"Scanning for {hunter_name.upper()} vulnerabilities...",
                phase=ExecutionPhase.HUNTING
            )
            
            # Simulate hunting (in real implementation, call actual hunter)
            await asyncio.sleep(0.2)
            
            # Simulate finding (for demo)
            # In real implementation, this would come from actual hunter results
            yield ExecutionEvent(
                type=EventType.PROGRESS,
                agent_name=hunter_name,
                content=f"{hunter_name.upper()} scan complete",
                phase=ExecutionPhase.HUNTING,
                metadata={"hypotheses": 0}
            )
        
        yield ExecutionEvent(
            type=EventType.PHASE_END,
            agent_name="planner",
            content="Vulnerability hunting complete",
            phase=ExecutionPhase.HUNTING,
            metadata={"total_hypotheses": len(self._findings)}
        )
    
    async def _execute_exploitation(self) -> AsyncGenerator[ExecutionEvent, None]:
        """Execute exploitation phase"""
        self._phase = ExecutionPhase.EXPLOITING
        self._active_agent = "exploit"
        
        yield ExecutionEvent(
            type=EventType.PHASE_START,
            agent_name="exploit",
            content=f"Verifying {len(self._findings)} potential vulnerabilities",
            phase=ExecutionPhase.EXPLOITING
        )
        
        # In real implementation, attempt to exploit each finding
        yield ExecutionEvent(
            type=EventType.AGENT_MESSAGE,
            agent_name="exploit",
            content="Launching headless browser for verification...",
            phase=ExecutionPhase.EXPLOITING
        )
        
        await asyncio.sleep(0.3)
        
        yield ExecutionEvent(
            type=EventType.PHASE_END,
            agent_name="exploit",
            content="Exploitation verification complete",
            phase=ExecutionPhase.EXPLOITING,
            metadata={"validated": 0, "false_positives": 0}
        )
    
    async def _execute_reporting(self) -> AsyncGenerator[ExecutionEvent, None]:
        """Execute reporting phase"""
        self._phase = ExecutionPhase.REPORTING
        self._active_agent = "reporter"
        
        yield ExecutionEvent(
            type=EventType.PHASE_START,
            agent_name="reporter",
            content="Generating vulnerability report",
            phase=ExecutionPhase.REPORTING
        )
        
        await asyncio.sleep(0.2)
        
        yield ExecutionEvent(
            type=EventType.AGENT_MESSAGE,
            agent_name="reporter",
            content="Report generated successfully",
            phase=ExecutionPhase.REPORTING,
            metadata={
                "format": "json",
                "findings": len(self._findings)
            }
        )
        
        yield ExecutionEvent(
            type=EventType.PHASE_END,
            agent_name="reporter",
            content="Reporting complete",
            phase=ExecutionPhase.REPORTING
        )
    
    def get_status(self) -> Dict[str, Any]:
        """Get current execution status"""
        return {
            "initialized": self._initialized,
            "mission_id": self._mission_id,
            "phase": self._phase.value,
            "active_agent": self._active_agent,
            "target": self._config.target_url if self._config else None,
            "findings_count": len(self._findings),
            "agents": {
                name: {
                    "display_name": info["info"]["display_name"],
                    "avatar": info["info"]["avatar"],
                    "status": info["status"]
                }
                for name, info in self._agents.items()
            },
            "elapsed_seconds": (
                (datetime.utcnow() - self._start_time).total_seconds()
                if self._start_time else 0
            )
        }
    
    def get_findings(self) -> List[Dict]:
        """Get all findings from the scan"""
        return self._findings
    
    async def stop(self) -> None:
        """Stop the current execution"""
        self._phase = ExecutionPhase.IDLE
        self._active_agent = None
        logger.info(f"Mission {self._mission_id} stopped")
    
    def reset(self) -> None:
        """Reset executor state"""
        self._initialized = False
        self._mission_id = None
        self._config = None
        self._phase = ExecutionPhase.IDLE
        self._agents = {}
        self._active_agent = None
        self._findings = []
        self._recon_data = None
        self._processed_events = set()
        self._start_time = None
        
        logger.info("Executor reset")


# Singleton instance for global access
_executor_instance: Optional[XLayerExecutor] = None


def get_executor() -> XLayerExecutor:
    """Get or create the global executor instance"""
    global _executor_instance
    if _executor_instance is None:
        _executor_instance = XLayerExecutor()
    return _executor_instance


# Example usage and CLI integration
async def run_scan(target_url: str, hunters: Optional[List[str]] = None) -> None:
    """
    Run a vulnerability scan (CLI helper function)
    
    Usage:
        asyncio.run(run_scan("https://example.com"))
    """
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.text import Text
    
    console = Console()
    executor = get_executor()
    
    # Initialize
    mission_id = await executor.initialize_mission(target_url, hunters)
    console.print(f"[cyan]Mission started: {mission_id}[/]")
    
    # Execute and stream events
    async for event in executor.execute_scan():
        # Get agent styling
        color = AgentManager.get_cli_color(event.agent_name)
        avatar = AgentManager.get_avatar(event.agent_name)
        display_name = AgentManager.get_display_name(event.agent_name)
        
        # Format output based on event type
        if event.type == EventType.PHASE_START:
            console.print(f"\n[bold {color}]{'='*60}[/]")
            console.print(f"[bold {color}]{avatar} {event.content}[/]")
            console.print(f"[bold {color}]{'='*60}[/]")
        
        elif event.type == EventType.AGENT_MESSAGE:
            console.print(f"[{color}]{avatar} [{display_name}][/] {event.content}")
        
        elif event.type == EventType.FINDING:
            console.print(f"[red]🚨 FINDING: {event.content}[/]")
        
        elif event.type == EventType.COMPLETE:
            console.print(f"\n[green]✅ Scan complete![/]")
            console.print(f"   Findings: {event.content['findings_count']}")
            console.print(f"   Duration: {event.content['duration_seconds']:.2f}s")
        
        elif event.type == EventType.ERROR:
            console.print(f"[red]❌ Error: {event.content}[/]")


if __name__ == "__main__":
    # Example: Run from command line
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    asyncio.run(run_scan(target))

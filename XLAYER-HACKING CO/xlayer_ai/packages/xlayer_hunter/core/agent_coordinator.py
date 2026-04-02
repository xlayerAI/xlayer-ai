"""
XLayer AI Agent Coordinator - Multi-Agent Orchestration System

This module demonstrates how AgentManager integrates with the agentic architecture.
It provides:
1. Agent lifecycle management (start, stop, monitor)
2. Task distribution and routing
3. Inter-agent communication
4. Parallel agent execution
5. Agent health monitoring

Usage:
    coordinator = AgentCoordinator()
    await coordinator.initialize_agents()
    results = await coordinator.execute_mission("https://target.com")
"""

import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from loguru import logger

from xlayer_hunter.utils.agent_manager import AgentManager


class AgentStatus(str, Enum):
    """Agent status states"""
    IDLE = "idle"
    ACTIVE = "active"
    BUSY = "busy"
    ERROR = "error"
    STOPPED = "stopped"


@dataclass
class AgentMessage:
    """Message passed between agents"""
    sender: str
    receiver: str
    message_type: str  # 'task', 'result', 'status', 'error'
    payload: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            "sender": self.sender,
            "receiver": self.receiver,
            "type": self.message_type,
            "payload": self.payload,
            "timestamp": self.timestamp.isoformat()
        }


@dataclass
class TaskResult:
    """Result from an agent task"""
    agent_name: str
    task_type: str
    success: bool
    data: Any = None
    error: Optional[str] = None
    duration_ms: float = 0.0


class AgentCoordinator:
    """
    Multi-Agent Coordinator for XLayer AI
    
    This is the central orchestration system that:
    1. Manages agent lifecycle
    2. Routes tasks to appropriate agents
    3. Handles inter-agent communication
    4. Monitors agent health and performance
    
    Agentic Architecture:
    
    ┌─────────────────────────────────────────────────────────────┐
    │                    Agent Coordinator                         │
    │  ┌─────────────────────────────────────────────────────┐   │
    │  │              Message Bus / Event Queue               │   │
    │  └─────────────────────────────────────────────────────┘   │
    │           │              │              │                   │
    │     ┌─────▼─────┐  ┌─────▼─────┐  ┌─────▼─────┐           │
    │     │  Planner  │  │   Recon   │  │  Exploit  │           │
    │     │   Agent   │  │   Agent   │  │   Agent   │           │
    │     └───────────┘  └───────────┘  └───────────┘           │
    │           │              │              │                   │
    │     ┌─────▼─────────────▼──────────────▼─────┐            │
    │     │           Vulnerability Hunters         │            │
    │     │  ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌───┐│            │
    │     │  │SQLi │ │ XSS │ │Auth │ │SSRF │ │LFI││            │
    │     │  └─────┘ └─────┘ └─────┘ └─────┘ └───┘│            │
    │     └────────────────────────────────────────┘            │
    └─────────────────────────────────────────────────────────────┘
    """
    
    def __init__(self):
        self.agents: Dict[str, Any] = {}
        self.message_queue: asyncio.Queue = asyncio.Queue()
        self.results: List[TaskResult] = []
        self.is_running: bool = False
        self._message_handlers: Dict[str, callable] = {}
    
    async def initialize_agents(self, agent_types: Optional[List[str]] = None) -> None:
        """
        Initialize and register agents
        
        Args:
            agent_types: List of agent types to initialize. 
                        If None, initializes all core agents and hunters.
        """
        if agent_types is None:
            agent_types = (
                AgentManager.get_agents_by_type("core") +
                AgentManager.get_agents_by_type("hunters")
            )
        
        for agent_name in agent_types:
            await self._initialize_agent(agent_name)
        
        self.is_running = True
        logger.info(f"Initialized {len(self.agents)} agents")
    
    async def _initialize_agent(self, agent_name: str) -> None:
        """Initialize a single agent"""
        agent_info = AgentManager.get_agent_info(agent_name)
        
        # Create agent placeholder (in real implementation, instantiate actual agent)
        self.agents[agent_name] = {
            "info": agent_info,
            "status": AgentStatus.IDLE,
            "instance": None,  # Would be actual agent instance
            "last_activity": datetime.utcnow()
        }
        
        # Register with AgentManager
        AgentManager.register_agent(agent_name, self.agents[agent_name])
        
        logger.debug(
            f"Initialized agent: {agent_info['display_name']} "
            f"{agent_info['avatar']}"
        )
    
    async def dispatch_task(
        self, 
        task_type: str, 
        payload: Dict[str, Any],
        target_agent: Optional[str] = None
    ) -> TaskResult:
        """
        Dispatch a task to an appropriate agent
        
        Args:
            task_type: Type of task to perform
            payload: Task data/parameters
            target_agent: Specific agent to use (optional, auto-routes if None)
            
        Returns:
            TaskResult with outcome
        """
        # Route to appropriate agent
        if target_agent is None:
            target_agent = AgentManager.route_task(task_type)
        
        if target_agent is None:
            return TaskResult(
                agent_name="coordinator",
                task_type=task_type,
                success=False,
                error=f"No agent found for task type: {task_type}"
            )
        
        # Check agent availability
        if target_agent not in self.agents:
            return TaskResult(
                agent_name=target_agent,
                task_type=task_type,
                success=False,
                error=f"Agent not initialized: {target_agent}"
            )
        
        agent_entry = self.agents[target_agent]
        
        if agent_entry["status"] == AgentStatus.BUSY:
            # Queue the task
            await self.message_queue.put(AgentMessage(
                sender="coordinator",
                receiver=target_agent,
                message_type="task",
                payload={"task_type": task_type, **payload}
            ))
            logger.debug(f"Task queued for busy agent: {target_agent}")
        
        # Update agent status
        agent_entry["status"] = AgentStatus.BUSY
        AgentManager.update_agent_status(target_agent, "busy")
        
        start_time = datetime.utcnow()
        
        try:
            # Execute task (placeholder - would call actual agent method)
            result_data = await self._execute_agent_task(
                target_agent, task_type, payload
            )
            
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            # Record completion
            AgentManager.record_task_completion(target_agent, success=True)
            
            result = TaskResult(
                agent_name=target_agent,
                task_type=task_type,
                success=True,
                data=result_data,
                duration_ms=duration
            )
            
        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds() * 1000
            AgentManager.record_task_completion(target_agent, success=False)
            
            result = TaskResult(
                agent_name=target_agent,
                task_type=task_type,
                success=False,
                error=str(e),
                duration_ms=duration
            )
        
        finally:
            # Reset agent status
            agent_entry["status"] = AgentStatus.IDLE
            agent_entry["last_activity"] = datetime.utcnow()
            AgentManager.update_agent_status(target_agent, "active")
        
        self.results.append(result)
        return result
    
    async def _execute_agent_task(
        self, 
        agent_name: str, 
        task_type: str, 
        payload: Dict
    ) -> Any:
        """
        Execute task on agent (placeholder for actual implementation)
        
        In real implementation, this would:
        1. Get agent instance
        2. Call appropriate method based on task_type
        3. Return results
        """
        # Simulate task execution
        await asyncio.sleep(0.1)
        
        return {
            "agent": agent_name,
            "task": task_type,
            "status": "completed",
            "payload_received": payload
        }
    
    async def broadcast_message(
        self, 
        sender: str, 
        message_type: str, 
        payload: Dict
    ) -> None:
        """Broadcast message to all agents"""
        for agent_name in self.agents:
            await self.message_queue.put(AgentMessage(
                sender=sender,
                receiver=agent_name,
                message_type=message_type,
                payload=payload
            ))
    
    async def send_message(
        self, 
        sender: str, 
        receiver: str, 
        message_type: str, 
        payload: Dict
    ) -> None:
        """Send message to specific agent"""
        await self.message_queue.put(AgentMessage(
            sender=sender,
            receiver=receiver,
            message_type=message_type,
            payload=payload
        ))
    
    async def run_parallel_hunters(
        self, 
        target_url: str, 
        hunters: Optional[List[str]] = None
    ) -> List[TaskResult]:
        """
        Run multiple vulnerability hunters in parallel
        
        Args:
            target_url: Target to scan
            hunters: List of hunters to run (default: all)
            
        Returns:
            List of results from all hunters
        """
        if hunters is None:
            hunters = AgentManager.get_agents_by_type("hunters")
        
        tasks = []
        for hunter in hunters:
            task = self.dispatch_task(
                task_type=f"{hunter}_scan",
                payload={"target": target_url},
                target_agent=hunter
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions and convert to TaskResult
        valid_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                valid_results.append(TaskResult(
                    agent_name=hunters[i],
                    task_type=f"{hunters[i]}_scan",
                    success=False,
                    error=str(result)
                ))
            else:
                valid_results.append(result)
        
        return valid_results
    
    def get_agent_status(self, agent_name: str) -> Optional[Dict]:
        """Get status of a specific agent"""
        if agent_name in self.agents:
            agent = self.agents[agent_name]
            stats = AgentManager.get_agent_stats(agent_name)
            
            return {
                "name": agent_name,
                "display_name": agent["info"]["display_name"],
                "avatar": agent["info"]["avatar"],
                "status": agent["status"].value,
                "last_activity": agent["last_activity"].isoformat(),
                "stats": stats
            }
        return None
    
    def get_all_agent_statuses(self) -> Dict[str, Dict]:
        """Get status of all agents"""
        return {
            name: self.get_agent_status(name)
            for name in self.agents
        }
    
    async def shutdown(self) -> None:
        """Gracefully shutdown all agents"""
        self.is_running = False
        
        for agent_name in self.agents:
            AgentManager.unregister_agent(agent_name)
            self.agents[agent_name]["status"] = AgentStatus.STOPPED
        
        logger.info("All agents shut down")
    
    def print_agent_summary(self) -> None:
        """Print summary of all agents (for CLI)"""
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        table = Table(title="XLayer AI Agents")
        
        table.add_column("Agent", style="cyan")
        table.add_column("Status", style="green")
        table.add_column("Tasks", justify="right")
        table.add_column("Success Rate", justify="right")
        
        for name, agent in self.agents.items():
            stats = AgentManager.get_agent_stats(name) or {}
            
            status_color = {
                AgentStatus.ACTIVE: "green",
                AgentStatus.IDLE: "yellow",
                AgentStatus.BUSY: "blue",
                AgentStatus.ERROR: "red",
                AgentStatus.STOPPED: "dim"
            }.get(agent["status"], "white")
            
            table.add_row(
                f"{agent['info']['avatar']} {agent['info']['display_name']}",
                f"[{status_color}]{agent['status'].value}[/]",
                str(stats.get("tasks_completed", 0)),
                f"{stats.get('success_rate', 0):.1f}%"
            )
        
        console.print(table)


# Example usage
async def example_usage():
    """Example of how to use the Agent Coordinator"""
    
    # Initialize coordinator
    coordinator = AgentCoordinator()
    
    # Initialize all agents
    await coordinator.initialize_agents()
    
    # Dispatch a single task
    result = await coordinator.dispatch_task(
        task_type="sqli_scan",
        payload={"target": "https://example.com", "depth": 2}
    )
    print(f"Task result: {result}")
    
    # Run all hunters in parallel
    results = await coordinator.run_parallel_hunters(
        target_url="https://example.com"
    )
    print(f"Hunter results: {len(results)} completed")
    
    # Check agent statuses
    statuses = coordinator.get_all_agent_statuses()
    for name, status in statuses.items():
        print(f"{status['avatar']} {name}: {status['status']}")
    
    # Shutdown
    await coordinator.shutdown()


if __name__ == "__main__":
    asyncio.run(example_usage())

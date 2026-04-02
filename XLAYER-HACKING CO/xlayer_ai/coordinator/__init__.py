"""
XLayer AI — Coordinator Package

Architecture:
  - Coordinator (src/agent/coordinator.py) = THE persistent brain
  - SwarmCoordinator (coordinator/swarm.py) = Dynamic agent spawning engine
  - SessionManager (coordinator/session_manager.py) = Shared auth persistence

Pipeline: Target → LSM → Dedup → Score → Matrix → Swarm → Validate → Chain → Report
"""

from xlayer_ai.coordinator.swarm import SwarmCoordinator
from xlayer_ai.coordinator.session_manager import SessionManager

__all__ = ["SwarmCoordinator", "SessionManager"]

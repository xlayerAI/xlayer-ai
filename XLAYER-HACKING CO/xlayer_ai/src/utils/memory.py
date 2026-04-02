"""
Shared memory store for the swarm agent system.

Provides a centralized InMemoryStore that all agents share
for cross-agent memory.

Swarm agents import from here:
    from src.utils.memory import get_store
"""

from typing import Optional
from langgraph.store.memory import InMemoryStore

_store: Optional[InMemoryStore] = None


def get_store() -> InMemoryStore:
    """Return the singleton shared memory store for all swarm agents."""
    global _store
    if _store is None:
        _store = InMemoryStore(
            index={
                "dims": 1536,
                "embed": "openai:text-embedding-3-small",
            }
        )
    return _store


def reset_store() -> None:
    """Reset the shared memory store."""
    global _store
    _store = None

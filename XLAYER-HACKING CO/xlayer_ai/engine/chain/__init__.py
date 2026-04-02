"""
engine/chain/ — Attack Chain Engine

Correlates isolated findings into multi-step exploit chains.
Learns from successful chains across sessions.

Usage:
    from xlayer_ai.engine.chain import ChainPlanner, ChainExecutor, PatternDistiller

    planner   = ChainPlanner(llm=llm)
    executor  = ChainExecutor(llm=llm, tools=tools)
    distiller = PatternDistiller(llm=llm)

    chains  = await planner.plan(surface, findings)
    results = await asyncio.gather(*[executor.execute(c) for c in chains])
    for r in results:
        if r.completed:
            await distiller.distill(r)
"""

from .models import ChainSpec, ChainStep, ChainResult, ChainPattern
from .patterns import CHAIN_PATTERNS
from .pattern_store import PatternStore
from .planner import ChainPlanner
from .executor import ChainExecutor
from .distiller import PatternDistiller

__all__ = [
    "ChainSpec",
    "ChainStep",
    "ChainResult",
    "ChainPattern",
    "CHAIN_PATTERNS",
    "PatternStore",
    "ChainPlanner",
    "ChainExecutor",
    "PatternDistiller",
]

"""
engine/ — XLayer Custom Agentic Framework

Import map:
  HumanMessage                from .messages import HumanMessage
  AIMessage                   from .messages import AIMessage
  ToolMessage                 from .messages import ToolMessage
  SystemMessage               from .messages import SystemMessage
  @tool decorator             from .tool import tool
  BaseTool                    from .tool import Tool
  ToolRegistry                from .tool import ToolRegistry
  LLM client                  from .llm import LLMClient
  Agent loop                  from .agent import AgentLoop
  Pipeline / parallel         from .pipeline import Pipeline, ParallelDispatch
  Checkpoint / store          from .memory import CheckpointStore, KVStore
  Solver loop                 from .agentic_loop import XLayerLoop, SolverState
"""

# Messages
from .messages import (
    AIMessage,
    HumanMessage,
    Message,
    SystemMessage,
    ToolMessage,
    messages_to_anthropic,
    messages_to_openai,
)

# Tool system
from .tool import (
    Tool,
    ToolRegistry,
    tool,
)

# LLM client
from .llm import LLMClient

# Agent loop (universal next-level loop)
from .agent import AgentLoop, AgentResult, LoopState, StopReason

# Pipeline
from .pipeline import ParallelDispatch, Pipeline

# Memory / checkpointing
from .memory import (
    CheckpointStore,
    KVStore,
    ObservationEntry,
    ObservationJournal,
)

# XLayer reasoning loop (the brain)
from .agentic_loop import (
    ActionType,
    Decision,
    SolverState,
    XLayerLoop,
)

# Attack Machine (shared execution: tools + JIT + OOB)
from .attack_machine import AttackMachine

__all__ = [
    # messages
    "SystemMessage", "HumanMessage", "AIMessage", "ToolMessage", "Message",
    "messages_to_openai", "messages_to_anthropic",
    # tools
    "tool", "Tool", "ToolRegistry",
    # llm
    "LLMClient",
    # agent
    "AgentLoop", "AgentResult", "LoopState", "StopReason",
    # pipeline
    "Pipeline", "ParallelDispatch",
    # memory
    "CheckpointStore", "KVStore", "ObservationEntry", "ObservationJournal",
    # agentic loop
    "XLayerLoop", "SolverState", "Decision", "ActionType",
    # attack machine
    "AttackMachine",
]

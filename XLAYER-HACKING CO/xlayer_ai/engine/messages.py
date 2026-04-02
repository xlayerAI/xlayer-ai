"""
engine/messages.py — Custom message types

Use:
  from engine.messages import HumanMessage, AIMessage, ToolMessage, SystemMessage
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class SystemMessage:
    """System-level instruction to the LLM."""
    content: str
    role: str = "system"

    def to_dict(self) -> Dict[str, Any]:
        return {"role": "system", "content": self.content}


@dataclass
class HumanMessage:
    """User / human turn message."""
    content: str
    role: str = "user"

    def to_dict(self) -> Dict[str, Any]:
        return {"role": "user", "content": self.content}


@dataclass
class AIMessage:
    """LLM assistant turn message."""
    content: str
    role: str = "assistant"
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    # Raw API response — stored so callers can inspect finish_reason, usage, etc.
    raw: Optional[Dict[str, Any]] = field(default=None, repr=False)

    def to_dict(self) -> Dict[str, Any]:
        msg: Dict[str, Any] = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = self.tool_calls
        return msg

    @property
    def has_tool_calls(self) -> bool:
        return bool(self.tool_calls)


@dataclass
class ToolMessage:
    """Result returned after executing a tool call."""
    content: str
    tool_call_id: str
    role: str = "tool"
    name: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role": "tool",
            "tool_call_id": self.tool_call_id,
            "name": self.name,
            "content": self.content,
        }


# ── Conversion helpers ─────────────────────────────────────────────────────────

Message = SystemMessage | HumanMessage | AIMessage | ToolMessage


def messages_to_openai(messages: List[Message]) -> List[Dict[str, Any]]:
    """Convert our message types to OpenAI chat format."""
    result = []
    for m in messages:
        if isinstance(m, SystemMessage):
            result.append({"role": "system", "content": m.content})
        elif isinstance(m, HumanMessage):
            result.append({"role": "user", "content": m.content})
        elif isinstance(m, AIMessage):
            msg: Dict[str, Any] = {"role": "assistant", "content": m.content or ""}
            if m.tool_calls:
                msg["tool_calls"] = m.tool_calls
            result.append(msg)
        elif isinstance(m, ToolMessage):
            result.append({
                "role": "tool",
                "tool_call_id": m.tool_call_id,
                "content": m.content,
            })
    return result


def messages_to_anthropic(messages: List[Message]) -> List[Dict[str, Any]]:
    """
    Convert our message types to Anthropic Messages API format.
    System messages are returned separately (caller handles them).
    """
    result = []
    for m in messages:
        if isinstance(m, SystemMessage):
            continue  # caller handles system separately
        elif isinstance(m, HumanMessage):
            result.append({"role": "user", "content": m.content})
        elif isinstance(m, AIMessage):
            if m.tool_calls:
                # Anthropic expects tool_use content blocks
                content_blocks = []
                if m.content:
                    content_blocks.append({"type": "text", "text": m.content})
                for tc in m.tool_calls:
                    content_blocks.append({
                        "type": "tool_use",
                        "id": tc["id"],
                        "name": tc["function"]["name"],
                        "input": _safe_json(tc["function"].get("arguments", "{}")),
                    })
                result.append({"role": "assistant", "content": content_blocks})
            else:
                result.append({"role": "assistant", "content": m.content or ""})
        elif isinstance(m, ToolMessage):
            # Anthropic expects tool_result as a user turn
            result.append({
                "role": "user",
                "content": [{
                    "type": "tool_result",
                    "tool_use_id": m.tool_call_id,
                    "content": m.content,
                }]
            })
    return result


def _safe_json(s: str) -> Any:
    """Parse JSON string, return dict on failure."""
    try:
        return json.loads(s)
    except Exception:
        return {}


import json  # noqa: E402 — keep at bottom to avoid circular import issues

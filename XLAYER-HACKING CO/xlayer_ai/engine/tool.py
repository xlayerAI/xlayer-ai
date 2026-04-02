"""
engine/tool.py — Custom @tool decorator

Use:
  from engine.tool import tool, Tool

Usage:
  @tool
  def run_sqli_hunter(url: str, parameter: str) -> str:
      \"\"\"Run SQL injection hunter on a single endpoint.\"\"\"
      ...

The decorator auto-generates JSON Schema for use in OpenAI / Anthropic API calls.
"""

import inspect
import json
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, get_type_hints


# ── Type → JSON Schema mapping ──────────────────────────────────────────────

_TYPE_MAP = {
    str: "string",
    int: "integer",
    float: "number",
    bool: "boolean",
    list: "array",
    dict: "object",
    List: "array",
    Dict: "object",
}


def _python_type_to_json(t: Any) -> str:
    """Convert Python type annotation to JSON Schema type string."""
    origin = getattr(t, "__origin__", None)
    if origin in (list, List):
        return "array"
    if origin in (dict, Dict):
        return "object"
    return _TYPE_MAP.get(t, "string")


def _build_schema(func: Callable) -> Dict[str, Any]:
    """Auto-generate JSON Schema from a function's type hints + docstring."""
    hints = get_type_hints(func)
    sig = inspect.signature(func)
    doc = func.__doc__ or ""

    # Parse param descriptions from docstring (Google style)
    # Looks for lines like "    param_name: Description here"
    param_docs: Dict[str, str] = {}
    in_args = False
    for line in doc.splitlines():
        stripped = line.strip()
        if stripped.lower() in ("args:", "arguments:", "parameters:"):
            in_args = True
            continue
        if in_args:
            if stripped and not stripped.endswith(":") and ":" in stripped:
                name, _, desc = stripped.partition(":")
                param_docs[name.strip()] = desc.strip()
            elif stripped and stripped.endswith(":"):
                break  # another section started

    properties: Dict[str, Any] = {}
    required: List[str] = []

    for param_name, param in sig.parameters.items():
        if param_name in ("self", "cls"):
            continue
        ptype = hints.get(param_name, str)
        json_type = _python_type_to_json(ptype)

        prop: Dict[str, Any] = {"type": json_type}
        if param_name in param_docs:
            prop["description"] = param_docs[param_name]

        properties[param_name] = prop

        if param.default is inspect.Parameter.empty:
            required.append(param_name)

    return {
        "type": "object",
        "properties": properties,
        "required": required,
    }


# ── Tool dataclass ───────────────────────────────────────────────────────────

@dataclass
class Tool:
    """A callable tool with auto-generated JSON Schema."""
    name: str
    description: str
    parameters: Dict[str, Any]  # JSON Schema
    func: Callable = field(repr=False)

    def __call__(self, **kwargs: Any) -> Any:
        return self.func(**kwargs)

    # ── API format helpers ─────────────────────────────────────────────────

    def to_openai_schema(self) -> Dict[str, Any]:
        """Format for OpenAI `tools` array."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            }
        }

    def to_anthropic_schema(self) -> Dict[str, Any]:
        """Format for Anthropic `tools` array."""
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.parameters,
        }


# ── @tool decorator ──────────────────────────────────────────────────────────

def tool(func: Optional[Callable] = None, *, name: Optional[str] = None, description: Optional[str] = None):
    """
    Decorator to turn a plain function into a Tool instance.

    Usage:
        @tool
        def my_tool(x: str, y: int) -> str:
            \"\"\"Does something useful.\"\"\"
            ...

        @tool(name="custom_name", description="Override description")
        def my_tool(x: str) -> str:
            ...
    """
    def decorator(f: Callable) -> Tool:
        tool_name = name or f.__name__
        tool_desc = description or (f.__doc__ or "").strip().split("\n")[0]
        schema = _build_schema(f)
        return Tool(
            name=tool_name,
            description=tool_desc,
            parameters=schema,
            func=f,
        )

    if func is not None:
        # Called as @tool (no parentheses)
        return decorator(func)
    else:
        # Called as @tool(...) with arguments
        return decorator


# ── Tool registry helpers ────────────────────────────────────────────────────

class ToolRegistry:
    """
    Simple dict-like registry mapping tool name → Tool.
    Lets the engine look up tools by name when the LLM calls them.
    """

    def __init__(self, tools: Optional[List[Tool]] = None) -> None:
        self._tools: Dict[str, Tool] = {}
        for t in (tools or []):
            self.register(t)

    def register(self, t: Tool) -> None:
        self._tools[t.name] = t

    def get(self, name: str) -> Optional[Tool]:
        return self._tools.get(name)

    def all(self) -> List[Tool]:
        return list(self._tools.values())

    def to_openai_schemas(self) -> List[Dict[str, Any]]:
        return [t.to_openai_schema() for t in self._tools.values()]

    def to_anthropic_schemas(self) -> List[Dict[str, Any]]:
        return [t.to_anthropic_schema() for t in self._tools.values()]

    def execute(self, name: str, arguments: Dict[str, Any]) -> str:
        """Execute a tool by name and return string result."""
        t = self.get(name)
        if t is None:
            return f"Error: tool '{name}' not found in registry"
        try:
            result = t(**arguments)
            if isinstance(result, str):
                return result
            return json.dumps(result, default=str)
        except Exception as e:
            return f"Error executing {name}: {e}"

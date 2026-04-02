"""
engine/llm.py — Direct LLM API client

Pure httpx calls to:
  - https://api.openai.com/v1/chat/completions
  - https://api.anthropic.com/v1/messages

Use:
  from engine.llm import LLMClient
"""

import json
import os
from typing import Any, Dict, List, Optional

import httpx
from loguru import logger

from .messages import (
    AIMessage,
    Message,
    SystemMessage,
    messages_to_anthropic,
    messages_to_openai,
)
from .tool import Tool


# ── Constants ────────────────────────────────────────────────────────────────

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"
ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"

DEFAULT_TIMEOUT = 120  # seconds


class LLMClient:
    """
    Unified LLM client — supports OpenAI and Anthropic with identical interface.

    Usage:
        client = LLMClient(provider="openai", model="gpt-4o-mini", api_key="sk-...")
        response = await client.call(messages=[HumanMessage("Hello")])
        print(response.content)
    """

    def __init__(
        self,
        provider: str = "openai",
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.provider = provider.lower()
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout

        # Resolve model
        if model:
            self.model = model
        elif self.provider == "anthropic":
            self.model = "claude-sonnet-4-6"
        elif self.provider in ("google", "gemini"):
            self.model = "gemini-2.0-flash"
        elif self.provider == "ollama":
            self.model = "llama3"
        else:
            self.model = "gpt-4o-mini"

        # Resolve API key
        if api_key:
            self.api_key = api_key
        elif self.provider == "openai":
            self.api_key = os.getenv("OPENAI_API_KEY", "")
        elif self.provider == "anthropic":
            self.api_key = os.getenv("ANTHROPIC_API_KEY", "")
        elif self.provider in ("google", "gemini"):
            self.api_key = os.getenv("GOOGLE_API_KEY", os.getenv("GEMINI_API_KEY", ""))
        else:
            self.api_key = ""

        # Base URL (for Ollama or proxies)
        if base_url:
            self.base_url = base_url.rstrip("/")
        elif self.provider in ("google", "gemini"):
            self.base_url = "https://generativelanguage.googleapis.com/v1beta/openai"
        elif self.provider == "ollama":
            self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        else:
            self.base_url = None

    # ── Main call interface ──────────────────────────────────────────────────

    async def call(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]] = None,
        system: Optional[str] = None,
    ) -> AIMessage:
        """
        Send messages to the LLM and return an AIMessage.

        Args:
            messages: Conversation history
            tools: Optional list of Tool objects to bind
            system: Optional system prompt override
        """
        if self.provider == "anthropic":
            return await self._call_anthropic(messages, tools, system)
        elif self.provider == "ollama":
            return await self._call_ollama(messages, tools, system)
        elif self.provider in ("google", "gemini"):
            # Gemini exposes an OpenAI-compatible endpoint — reuse _call_openai
            return await self._call_openai(messages, tools, system)
        else:
            return await self._call_openai(messages, tools, system)

    # ── OpenAI ───────────────────────────────────────────────────────────────

    async def _call_openai(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]],
        system: Optional[str],
    ) -> AIMessage:
        """POST to OpenAI chat completions API."""
        msg_list = messages_to_openai(messages)

        # Inject system prompt at front if provided and not already there
        if system and (not msg_list or msg_list[0].get("role") != "system"):
            msg_list.insert(0, {"role": "system", "content": system})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": msg_list,
            "temperature": self.temperature,
            "max_tokens": self.max_tokens,
        }

        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]
            payload["tool_choice"] = "auto"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(OPENAI_API_URL, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"OpenAI API error {e.response.status_code}: {e.response.text}")
            return AIMessage(content=f"[LLM Error: {e.response.status_code}]", raw={})
        except Exception as e:
            logger.error(f"OpenAI request failed: {e}")
            return AIMessage(content=f"[LLM Error: {e}]", raw={})

        choice = data["choices"][0]
        msg = choice["message"]
        content = msg.get("content") or ""
        tool_calls = msg.get("tool_calls") or []

        # Normalize tool_calls to our format
        normalized: List[Dict[str, Any]] = []
        for tc in tool_calls:
            normalized.append({
                "id": tc["id"],
                "type": "function",
                "function": {
                    "name": tc["function"]["name"],
                    "arguments": tc["function"]["arguments"],
                }
            })

        return AIMessage(content=content, tool_calls=normalized, raw=data)

    # ── Anthropic ────────────────────────────────────────────────────────────

    async def _call_anthropic(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]],
        system: Optional[str],
    ) -> AIMessage:
        """POST to Anthropic Messages API."""
        # Extract system message from messages list if present
        sys_content = system or ""
        for m in messages:
            if isinstance(m, SystemMessage):
                sys_content = m.content
                break

        msg_list = messages_to_anthropic(messages)

        payload: Dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": msg_list,
            "temperature": self.temperature,
        }

        if sys_content:
            payload["system"] = sys_content

        if tools:
            payload["tools"] = [t.to_anthropic_schema() for t in tools]

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(ANTHROPIC_API_URL, headers=headers, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"Anthropic API error {e.response.status_code}: {e.response.text}")
            return AIMessage(content=f"[LLM Error: {e.response.status_code}]", raw={})
        except Exception as e:
            logger.error(f"Anthropic request failed: {e}")
            return AIMessage(content=f"[LLM Error: {e}]", raw={})

        # Parse Anthropic response content blocks
        content_text = ""
        tool_calls: List[Dict[str, Any]] = []

        for block in data.get("content", []):
            if block["type"] == "text":
                content_text += block["text"]
            elif block["type"] == "tool_use":
                # Convert to OpenAI-style tool_call format (our internal standard)
                tool_calls.append({
                    "id": block["id"],
                    "type": "function",
                    "function": {
                        "name": block["name"],
                        "arguments": json.dumps(block.get("input", {})),
                    }
                })

        return AIMessage(content=content_text, tool_calls=tool_calls, raw=data)

    # ── Ollama ───────────────────────────────────────────────────────────────

    async def _call_ollama(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]],
        system: Optional[str],
    ) -> AIMessage:
        """POST to Ollama OpenAI-compatible API."""
        url = f"{self.base_url}/v1/chat/completions"
        msg_list = messages_to_openai(messages)

        if system and (not msg_list or msg_list[0].get("role") != "system"):
            msg_list.insert(0, {"role": "system", "content": system})

        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": msg_list,
            "temperature": self.temperature,
            "stream": False,
        }

        if tools:
            payload["tools"] = [t.to_openai_schema() for t in tools]

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(url, json=payload)
                resp.raise_for_status()
                data = resp.json()
        except Exception as e:
            logger.error(f"Ollama request failed: {e}")
            return AIMessage(content=f"[LLM Error: {e}]", raw={})

        choice = data["choices"][0]
        msg = choice["message"]
        content = msg.get("content") or ""
        tool_calls_raw = msg.get("tool_calls") or []

        normalized = []
        for tc in tool_calls_raw:
            normalized.append({
                "id": tc.get("id", "tc_0"),
                "type": "function",
                "function": {
                    "name": tc["function"]["name"],
                    "arguments": tc["function"]["arguments"],
                }
            })

        return AIMessage(content=content, tool_calls=normalized, raw=data)

    # ── Factory ──────────────────────────────────────────────────────────────

    @classmethod
    def from_settings(cls) -> "LLMClient":
        """Create LLMClient from XLayer settings (config/settings.py)."""
        try:
            from xlayer_ai.config.settings import get_settings
            s = get_settings()
            return cls(
                provider=s.llm.provider,
                model=s.llm.model,
                api_key=s.llm.api_key,
                base_url=s.llm.base_url,
                temperature=s.llm.temperature,
                max_tokens=s.llm.max_tokens,
            )
        except Exception as e:
            logger.warning(f"Could not load settings, using env vars: {e}")
            provider = os.getenv("XLAYER_LLM__PROVIDER", "openai")
            return cls(provider=provider)


# ── AlloyLLM ─────────────────────────────────────────────────────────────────


class AlloyLLM:
    """
    Alloy: alternates between two LLM clients on every call.

    Alternating primary + Gemini lifts success rate
    from 57.5% → 68.8% — different model biases catch different patterns.

    Usage:
        alloy = AlloyLLM.from_settings()
        response = await alloy.call(messages)   # Sonnet
        response = await alloy.call(messages)   # Gemini
        response = await alloy.call(messages)   # Sonnet  (repeats)
    """

    def __init__(self, primary: LLMClient, secondary: LLMClient) -> None:
        self._clients = [primary, secondary]
        self._turn = 0

    async def call(
        self,
        messages: List[Message],
        tools: Optional[List[Tool]] = None,
        system: Optional[str] = None,
    ) -> AIMessage:
        client = self._clients[self._turn % 2]
        self._turn += 1
        logger.debug(
            f"[AlloyLLM] turn={self._turn} → {client.provider}/{client.model}"
        )
        return await client.call(messages, tools=tools, system=system)

    @classmethod
    def from_settings(cls) -> "AlloyLLM":
        """
        Build AlloyLLM from settings + env vars.

        If GOOGLE_API_KEY / GEMINI_API_KEY is set → true alloy (primary + Gemini).
        Otherwise → single-model mode (primary only, both slots use same client).
        """
        primary = LLMClient.from_settings()
        gemini_key = os.getenv("GOOGLE_API_KEY", os.getenv("GEMINI_API_KEY", ""))
        if gemini_key:
            secondary = LLMClient(
                provider="google",
                model=os.getenv("XLAYER_ALLOY_MODEL", "gemini-2.0-flash"),
                api_key=gemini_key,
            )
            logger.info(
                f"[AlloyLLM] Alloy ON: {primary.provider}/{primary.model} "
                f"↔ {secondary.provider}/{secondary.model}"
            )
        else:
            secondary = primary
            logger.info(
                f"[AlloyLLM] Alloy OFF (no GOOGLE_API_KEY) — "
                f"single model: {primary.provider}/{primary.model}"
            )
        return cls(primary, secondary)

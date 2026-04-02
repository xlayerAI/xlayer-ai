"""
LLM Model loading and provider management.

Core module that handles loading models from any supported provider
via chat model loader. Used by config_manager.py and selection.py.
"""

import os
import json
from enum import Enum
from typing import Optional, List, Dict, Any
from dataclasses import dataclass, field
from pathlib import Path


class ModelProvider(str, Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    GOOGLE = "google_genai"
    GROQ = "groq"
    MISTRAL = "mistralai"
    XAI = "xai"
    PERPLEXITY = "perplexity"
    DEEPSEEK = "deepseek"
    AZURE_OPENAI = "azure_openai"
    OLLAMA = "ollama"


ENV_KEY_MAP = {
    ModelProvider.OPENAI: "OPENAI_API_KEY",
    ModelProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
    ModelProvider.GOOGLE: "GOOGLE_API_KEY",
    ModelProvider.GROQ: "GROQ_API_KEY",
    ModelProvider.MISTRAL: "MISTRAL_API_KEY",
    ModelProvider.XAI: "XAI_API_KEY",
    ModelProvider.PERPLEXITY: "PPLX_API_KEY",
    ModelProvider.DEEPSEEK: "DEEPSEEK_API_KEY",
    ModelProvider.AZURE_OPENAI: "AZURE_OPENAI_API_KEY",
}


@dataclass
class LLMModelConfig:
    """Configuration for a single LLM model."""
    display_name: str
    model_name: str
    provider: ModelProvider
    description: str = ""
    context_length: int = 128000
    supports_tools: bool = True
    supports_streaming: bool = True


class LLMModelManager:
    """Manages the registry of available LLM models."""

    def __init__(self):
        self._models: List[LLMModelConfig] = []
        self._custom_models: List[LLMModelConfig] = []
        self._load_configs()

    def _load_configs(self):
        """Load models from cloud_config.json and local_config.json."""
        base_dir = Path(__file__).parent

        for config_file in ["cloud_config.json", "local_config.json"]:
            config_path = base_dir / config_file
            if config_path.exists():
                with open(config_path, "r", encoding="utf-8") as f:
                    entries = json.load(f)
                for entry in entries:
                    try:
                        provider = ModelProvider(entry["provider"])
                    except ValueError:
                        continue
                    self._models.append(LLMModelConfig(
                        display_name=entry["display_name"],
                        model_name=entry["model_name"],
                        provider=provider,
                    ))

    def get_all_models(self) -> List[LLMModelConfig]:
        """Return all registered models."""
        return self._models + self._custom_models

    def get_models_by_provider(self, provider: ModelProvider) -> List[LLMModelConfig]:
        """Return models filtered by provider."""
        return [m for m in self.get_all_models() if m.provider == provider]

    def get_model_config(
        self, model_name: str, provider: Optional[str] = None
    ) -> Optional[LLMModelConfig]:
        """Find a model by name and optionally provider."""
        for model in self.get_all_models():
            if model.model_name == model_name:
                if provider is None or model.provider.value == provider:
                    return model
        return None

    def add_custom_model(self, config: LLMModelConfig) -> None:
        """Register a custom model at runtime."""
        self._custom_models.append(config)


def validate_api_key(provider: ModelProvider) -> bool:
    """Check whether the API key for a provider is available."""
    if provider == ModelProvider.OLLAMA:
        info = check_ollama_connection()
        return info["connected"]

    env_var = ENV_KEY_MAP.get(provider)
    if env_var is None:
        return False
    return bool(os.getenv(env_var))


def check_ollama_connection() -> Dict[str, Any]:
    """Check if Ollama is running and accessible."""
    import urllib.request
    import urllib.error

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            return {"connected": True, "url": base_url}
    except Exception as e:
        return {"connected": False, "url": base_url, "error": str(e)}


def get_installed_ollama_models() -> List[str]:
    """Return list of model names installed in Ollama."""
    import urllib.request
    import urllib.error

    base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
    try:
        req = urllib.request.Request(f"{base_url}/api/tags", method="GET")
        with urllib.request.urlopen(req, timeout=3) as resp:
            data = json.loads(resp.read().decode())
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        return []


def load_llm_model(
    model_name: str,
    provider: str,
    temperature: float = 0.0,
    **kwargs,
):
    """
    Load an LLM model instance via init_chat_model.

    Args:
        model_name: The model identifier (e.g., "claude-sonnet-4-6").
        provider: The provider name (e.g., "anthropic", "openai", "ollama").
        temperature: Sampling temperature.
        **kwargs: Additional arguments forwarded to init_chat_model.

    Returns:
        A LangChain chat model instance.
    """
    from langchain.chat_models import init_chat_model

    filtered_kwargs = {k: v for k, v in kwargs.items() if v is not None}

    return init_chat_model(
        model=model_name,
        model_provider=provider,
        temperature=temperature,
        **filtered_kwargs,
    )


def load_llm(
    model_name: Optional[str] = None,
    provider: Optional[str] = None,
    temperature: float = 0.0,
    configurable_fields: Optional[tuple] = None,
    **kwargs,
):
    """
    High-level model loader. If model_name/provider are omitted and
    configurable_fields is set, returns a runtime-configurable model.

    Args:
        model_name: Model identifier. If None, returns configurable model.
        provider: Provider name. If None with model_name, attempts auto-detect.
        temperature: Sampling temperature.
        configurable_fields: Tuple of fields that can be changed at runtime.
        **kwargs: Extra arguments forwarded to init_chat_model.

    Returns:
        A chat model (possibly configurable).
    """
    from langchain.chat_models import init_chat_model

    filtered_kwargs = {k: v for k, v in kwargs.items() if v is not None}

    if model_name is None and configurable_fields:
        return init_chat_model(
            temperature=temperature,
            configurable_fields=configurable_fields,
            **filtered_kwargs,
        )

    return init_chat_model(
        model=model_name,
        model_provider=provider,
        temperature=temperature,
        **filtered_kwargs,
    )


def list_available_models(provider: Optional[str] = None) -> List[Dict[str, Any]]:
    """Return a list of all available models with their status."""
    manager = LLMModelManager()
    models = manager.get_all_models()

    if provider:
        try:
            provider_enum = ModelProvider(provider)
            models = [m for m in models if m.provider == provider_enum]
        except ValueError:
            models = []

    result = []
    for model in models:
        result.append({
            "display_name": model.display_name,
            "model_name": model.model_name,
            "provider": model.provider.value,
            "description": model.description,
            "context_length": model.context_length,
            "supports_tools": model.supports_tools,
            "supports_streaming": model.supports_streaming,
            "api_key_available": validate_api_key(model.provider),
        })

    return result


def list_available_providers() -> List[Dict[str, Any]]:
    """Return a list of all providers with model counts and key status."""
    manager = LLMModelManager()
    all_models = manager.get_all_models()

    providers_seen = {}
    for model in all_models:
        pv = model.provider.value
        if pv not in providers_seen:
            providers_seen[pv] = {
                "name": pv,
                "display_name": pv.replace("_", " ").title(),
                "model_count": 0,
                "api_key_available": validate_api_key(model.provider),
            }
        providers_seen[pv]["model_count"] += 1

    return list(providers_seen.values())


def print_model_selection_help():
    """Print a formatted overview of available models (delegates to selection module)."""
    from .selection import print_model_selection_help as _print_help
    _print_help()


__all__ = [
    "ModelProvider",
    "LLMModelConfig",
    "LLMModelManager",
    "validate_api_key",
    "check_ollama_connection",
    "get_installed_ollama_models",
    "load_llm_model",
    "load_llm",
    "list_available_models",
    "list_available_providers",
    "print_model_selection_help",
]

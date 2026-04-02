"""
XLayer AI LLM - Unified language model integration.

Provides model loading, selection, configuration management,
and multi-provider support for the XLayer AI agent pipeline.
"""

from xlayer_ai.llm.engine import LLMEngine
from xlayer_ai.llm.models import (
    ModelProvider,
    LLMModelConfig,
    LLMModelManager,
    load_llm,
    load_llm_model,
    list_available_models,
    list_available_providers,
    validate_api_key,
    check_ollama_connection,
    get_installed_ollama_models,
    print_model_selection_help,
)
from xlayer_ai.llm.config_manager import (
    get_current_llm,
    update_llm_config,
    get_current_llm_config,
    reset_config,
)
try:
    from xlayer_ai.llm.openrouter import (
        create_openrouter_model,
        is_openrouter_available,
    )
except ImportError:
    create_openrouter_model = None  # type: ignore[misc, assignment]
    is_openrouter_available = lambda: False  # type: ignore[misc]

__all__ = [
    "LLMEngine",
    "ModelProvider",
    "LLMModelConfig",
    "LLMModelManager",
    "load_llm",
    "load_llm_model",
    "list_available_models",
    "list_available_providers",
    "validate_api_key",
    "check_ollama_connection",
    "get_installed_ollama_models",
    "print_model_selection_help",
    "get_current_llm",
    "update_llm_config",
    "get_current_llm_config",
    "reset_config",
    "create_openrouter_model",
    "is_openrouter_available",
]

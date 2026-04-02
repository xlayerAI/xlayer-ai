"""
Memory-based configuration manager - manages LLM settings in memory without file persistence.
"""

from dataclasses import dataclass
from typing import Optional, Any
from .models import load_llm_model, ModelProvider


@dataclass
class LLMConfig:
    """LLM configuration."""
    model_name: str = "claude-3-5-sonnet-latest"
    provider: str = "anthropic"
    display_name: str = "Claude 3.5 Sonnet"
    temperature: float = 0.0


class MemoryConfigManager:
    """Memory-based configuration manager (singleton) - no file persistence."""
    
    _instance: Optional['MemoryConfigManager'] = None
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if not getattr(self, '_initialized', False):
            self._config: Optional[LLMConfig] = None
            self._llm_instance: Optional[Any] = None
            self._initialized = True
    
    @property
    def config(self) -> LLMConfig:
        """Return current config, falling back to defaults."""
        if self._config is None:
            self._config = LLMConfig()
        return self._config
    
    @property
    def llm_instance(self) -> Optional[Any]:
        """Return current LLM instance."""
        return self._llm_instance
    
    def update_config(self, model_name: str, provider: str, display_name: str) -> None:
        """Update LLM configuration in memory and recreate the instance."""
        self._config = LLMConfig(
            model_name=model_name,
            provider=provider,
            display_name=display_name,
            temperature=0.0
        )
        
        try:
            self._llm_instance = load_llm_model(
                model_name=model_name,
                provider=provider,
                temperature=0.0
            )
        except Exception as e:
            print(f"Warning: Failed to load LLM model: {e}")
            self._llm_instance = None
    
    def get_current_llm(self) -> Optional[Any]:
        """Return current LLM instance, creating one from config if needed."""
        if self._llm_instance is None and self._config is not None:
            try:
                self._llm_instance = load_llm_model(
                    model_name=self._config.model_name,
                    provider=self._config.provider,
                    temperature=0.0
                )
            except Exception as e:
                print(f"Warning: Failed to load LLM model: {e}")
                return None
        
        return self._llm_instance
    
    def reset(self) -> None:
        """Reset configuration and instance to initial state."""
        self._config = None
        self._llm_instance = None


_memory_config_manager: Optional[MemoryConfigManager] = None


def get_memory_config_manager() -> MemoryConfigManager:
    """Return the global singleton config manager instance."""
    global _memory_config_manager
    if _memory_config_manager is None:
        _memory_config_manager = MemoryConfigManager()
    return _memory_config_manager


def get_current_llm_config() -> LLMConfig:
    """Return the current LLM configuration from memory."""
    return get_memory_config_manager().config


def update_llm_config(model_name: str, provider: str, display_name: str, 
                     temperature: float = 0.0) -> None:
    """Update LLM configuration in memory."""
    get_memory_config_manager().update_config(
        model_name=model_name,
        provider=provider,
        display_name=display_name
    )


def get_current_llm():
    """Return the current LLM instance."""
    return get_memory_config_manager().get_current_llm()


def reset_config() -> None:
    """Reset all configuration to initial state."""
    get_memory_config_manager().reset()


__all__ = [
    "LLMConfig",
    "MemoryConfigManager",
    "get_memory_config_manager",
    "get_current_llm_config",
    "update_llm_config",
    "get_current_llm",
    "reset_config",
]

"""
OpenRouter API integration module.

OpenRouter provides a unified API gateway to access 200+ models from multiple
providers (OpenAI, Anthropic, Google, Meta, etc.) through a single API key.
"""

from langchain_openai import ChatOpenAI
import os


def create_openrouter_model(model_name: str, temperature: float = 0.0):
    """
    Create an LLM instance via OpenRouter's unified API gateway.

    Args:
        model_name: OpenRouter model identifier
                    (e.g., "deepseek/deepseek-chat-v3-0324:free")
        temperature: Sampling temperature (default 0.0 for deterministic output).

    Returns:
        ChatOpenAI instance configured for OpenRouter.

    Raises:
        ValueError: If OPENROUTER_API_KEY is not set.
    """
    api_key = os.getenv("OPENROUTER_API_KEY")
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY environment variable is not set. "
            "Add OPENROUTER_API_KEY=your-key to your .env file."
        )

    return ChatOpenAI(
        model=model_name,
        api_key=api_key,
        base_url="https://openrouter.ai/api/v1",
        temperature=temperature,
        model_kwargs={
            "extra_headers": {
                "HTTP-Referer": "https://xlayer.ai",
                "X-Title": "XLayer AI",
            }
        }
    )


def get_openrouter_api_key() -> str:
    """Return the OpenRouter API key from environment, or empty string."""
    return os.getenv("OPENROUTER_API_KEY", "")


def is_openrouter_available() -> bool:
    """Check whether an OpenRouter API key is configured."""
    return bool(get_openrouter_api_key())

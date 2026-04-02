"""
XIC (XLayer Intelligence Core) for XLayer AI

This package exposes the core modules used to build, train, evaluate,
and serve XLayer AI's custom cybersecurity LLM.

Public submodules:
- model_llm   : Model architecture and utilities
- preprocess  : Dataset cleaning, tokenization, and shard writers
- train_llm   : Training loop, schedulers, checkpointing
- inference   : Text generation helpers and streaming APIs
- evaluate    : Perplexity and task-level metrics
- utils       : Logging, metrics, checkpoints, randomness
"""

from __future__ import annotations

from types import ModuleType
from typing import Optional, Dict

__version__: str = "1.0.0"

# ---- Internal: safe importer -------------------------------------------------
def _safe_import(module_name: str) -> Optional[ModuleType]:
    """
    Import a submodule of this package safely.

    Returns:
        The imported module, or None if the import fails.
    """
    try:
        # Relative import within the package (e.g., ".model_llm")
        module = __import__(f"{__name__}.{module_name}", fromlist=["*"])
        return module  # type: ignore[return-value]
    except Exception:
        return None


# ---- Import submodules (do not hard-crash if optional deps are missing) -----
model_llm: Optional[ModuleType] = _safe_import("model_llm")
preprocess: Optional[ModuleType] = _safe_import("preprocess")
train_llm: Optional[ModuleType] = _safe_import("train_llm")
inference: Optional[ModuleType] = _safe_import("inference")
evaluate: Optional[ModuleType] = _safe_import("evaluate")
utils: Optional[ModuleType] = _safe_import("utils")


# ---- Logger convenience export ----------------------------------------------
def _noop_get_logger(name: str):
    """Fallback logger factory used only if utils.logging is unavailable."""
    import logging

    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            fmt="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


try:
    # Prefer the real helper if present
    if utils is not None:
        from .utils.logging import get_logger  # type: ignore[attr-defined]
    else:
        get_logger = _noop_get_logger  # type: ignore[assignment]
except Exception:
    # Absolute safety: never let import errors bubble up from __init__.py
    get_logger = _noop_get_logger  # type: ignore[assignment]


# ---- Public API --------------------------------------------------------------
__all__ = [
    "model_llm",
    "preprocess",
    "train_llm",
    "inference",
    "evaluate",
    "utils",
    "get_logger",
    "__version__",
]


# ---- Optional: quick sanity registry (useful in REPL/tests) -----------------
def available_modules() -> Dict[str, bool]:
    """
    Returns a map of submodule availability. Useful for smoke tests.

    Example:
        >>> from xic import available_modules
        >>> available_modules()["model_llm"]
        True
    """
    return {
        "model_llm": model_llm is not None,
        "preprocess": preprocess is not None,
        "train_llm": train_llm is not None,
        "inference": inference is not None,
        "evaluate": evaluate is not None,
        "utils": utils is not None,
    }

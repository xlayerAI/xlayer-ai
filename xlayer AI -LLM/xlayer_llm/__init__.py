"""
XLayer LLM - Bug Bounty Intelligence & LLM Training

This package contains:
- LLM model architecture and training
- HackerOne data fetching and processing
- Tokenizer training
- Configuration management

Usage:
    from xlayer_llm import Config
    from xlayer_llm.hackerone_fetch import HackerOneFetcher
"""

__version__ = "1.0.0"
__package_name__ = "xlayer_llm"

from xlayer_llm.Config import (
    ModelConfig,
    TrainingConfig,
    DataConfig,
    get_config,
)

__all__ = [
    "ModelConfig",
    "TrainingConfig",
    "DataConfig",
    "get_config",
]

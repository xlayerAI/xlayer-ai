"""
XIC DataGen - Synthetic Cybersecurity Training Data Generator

Generates 100K high-quality instruction-tuning entries for the XLayer AI
cybersecurity LLM covering exploit chains, code audit, vulnerability analysis,
and 12 other security domains.
"""

from .engine import GenerationEngine
from .config import DataGenConfig

__all__ = ["GenerationEngine", "DataGenConfig"]

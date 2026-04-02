"""
Compatibility package for legacy `src.*` imports.

This shim preserves old import paths while the project converges on
`xlayer_ai.src.*` as the canonical package namespace.
"""

from xlayer_ai import src as _real_src

# Reuse the real package search path so `import src.agent...` resolves
# to modules under `xlayer_ai/src` without duplicating code.
__path__ = _real_src.__path__


"""
engine/chain/pattern_store.py — Persistent Pattern Library

Stores both static (built-in) and learned patterns.
Tracks success/failure rates per pattern per target fingerprint.
Uses existing KVStore (SQLite) — no new DB needed.
"""

import json
import time
from typing import Dict, List, Optional

from loguru import logger

from xlayer_ai.engine.memory import KVStore
from .models import ChainPattern
from .patterns import CHAIN_PATTERNS


_NS_PATTERN  = "chain_pattern"
_NS_STATS    = "chain_stats"
_NS_EXEC_LOG = "chain_exec"


class PatternStore:
    """
    Persistent pattern library — built-in + learned patterns.

    Patterns accumulate across scan sessions:
      Session 1: 10 built-in patterns
      Session 10: 10 built-in + 5 learned = 15 patterns
      Session 50: 10 built-in + 20 learned = 30 patterns

    Success rates guide planner priority.
    """

    def __init__(self, db_path: str = "./xlayer_memory.db") -> None:
        self._kv = KVStore(db_path=db_path)

    # ── Pattern CRUD ─────────────────────────────────────────────────────────

    def save_pattern(self, pattern: ChainPattern) -> None:
        """Persist a learned pattern."""
        self._kv.set(
            f"{_NS_PATTERN}:{pattern.name}",
            pattern.to_dict(),
        )
        logger.info(f"[PatternStore] Saved pattern: {pattern.name}")

    def get_learned_patterns(self) -> List[ChainPattern]:
        """Return all learned (non-static) patterns from store."""
        all_keys = self._kv.list_keys()
        prefix = f"{_NS_PATTERN}:"
        patterns = []
        for key in all_keys:
            if not key.startswith(prefix):
                continue
            raw = self._kv.get(key)
            if not raw:
                continue
            try:
                p = ChainPattern.from_dict(raw)
                if p.source == "learned":
                    patterns.append(p)
            except Exception as e:
                logger.debug(f"[PatternStore] Pattern load error {key}: {e}")
        return patterns

    def all_patterns(self) -> List[ChainPattern]:
        """Built-in + learned patterns combined."""
        return CHAIN_PATTERNS + self.get_learned_patterns()

    def pattern_exists(self, name: str) -> bool:
        if any(p.name == name for p in CHAIN_PATTERNS):
            return True
        return self._kv.get(f"{_NS_PATTERN}:{name}") is not None

    # ── Stats tracking ────────────────────────────────────────────────────────

    def record_execution(
        self,
        pattern_name: str,
        success: bool,
        duration_ms: float,
        target_fingerprint: Optional[Dict] = None,
    ) -> None:
        """Record outcome of a chain execution attempt."""
        key = f"{_NS_STATS}:{pattern_name}"
        stats = self._kv.get(key) or {
            "success": 0,
            "fail": 0,
            "durations_ms": [],
            "fingerprints": [],
        }
        if success:
            stats["success"] += 1
        else:
            stats["fail"] += 1
        stats["durations_ms"].append(round(duration_ms, 1))
        if target_fingerprint:
            stats["fingerprints"].append(target_fingerprint)
        # Keep last 100 fingerprints only
        stats["fingerprints"] = stats["fingerprints"][-100:]
        stats["durations_ms"] = stats["durations_ms"][-100:]
        self._kv.set(key, stats)

        # Also write to exec log for auditability
        log_key = f"{_NS_EXEC_LOG}:{pattern_name}:{int(time.time())}"
        self._kv.set(log_key, {
            "pattern": pattern_name,
            "success": success,
            "duration_ms": round(duration_ms, 1),
            "fingerprint": target_fingerprint or {},
            "ts": time.time(),
        })

    def get_success_rate(self, pattern_name: str) -> float:
        """Returns success rate 0.0–1.0. Defaults to 0.5 (unknown)."""
        key = f"{_NS_STATS}:{pattern_name}"
        stats = self._kv.get(key)
        if not stats:
            return 0.5
        total = stats.get("success", 0) + stats.get("fail", 0)
        if total == 0:
            return 0.5
        return stats["success"] / total

    def get_stats(self, pattern_name: str) -> Dict:
        key = f"{_NS_STATS}:{pattern_name}"
        stats = self._kv.get(key) or {"success": 0, "fail": 0}
        total = stats.get("success", 0) + stats.get("fail", 0)
        durations = stats.get("durations_ms", [])
        return {
            "pattern":      pattern_name,
            "success":      stats.get("success", 0),
            "fail":         stats.get("fail", 0),
            "total":        total,
            "success_rate": round(self.get_success_rate(pattern_name), 3),
            "avg_duration_ms": round(
                sum(durations) / len(durations), 1
            ) if durations else 0,
        }

    def all_stats(self) -> List[Dict]:
        """Stats for all patterns ever executed."""
        all_keys = self._kv.list_keys()
        prefix = f"{_NS_STATS}:"
        return [
            self.get_stats(key[len(prefix):])
            for key in all_keys
            if key.startswith(prefix)
        ]

"""
engine/memory.py — SQLite-based checkpoint + key-value store

Use:
  from engine.memory import CheckpointStore, KVStore

Two stores:
  1. CheckpointStore — save/load full agent state (for resume-after-crash)
  2. KVStore — simple key-value store for agent working memory
"""

import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── Default DB path ──────────────────────────────────────────────────────────

DEFAULT_DB_PATH = "./xlayer_memory.db"


# ── CheckpointStore ──────────────────────────────────────────────────────────

class CheckpointStore:
    """
    SQLite-backed checkpoint store.
    Saves serialized agent state so scans can resume after interruption.

    Usage:
        store = CheckpointStore()
        store.save("scan_abc123", {"url": "...", "findings": [...]})
        state = store.load("scan_abc123")
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        """Create tables if they don't exist."""
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    run_id TEXT PRIMARY KEY,
                    state_json TEXT NOT NULL,
                    updated_at REAL NOT NULL
                )
            """)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save(self, run_id: str, state: Any) -> None:
        """Serialize and save agent state."""
        try:
            state_json = json.dumps(state, default=str)
        except Exception as e:
            state_json = json.dumps({"error": str(e), "partial": repr(state)})

        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO checkpoints (run_id, state_json, updated_at)
                VALUES (?, ?, ?)
                """,
                (run_id, state_json, time.time())
            )

    def load(self, run_id: str) -> Optional[Any]:
        """Load and deserialize agent state. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT state_json FROM checkpoints WHERE run_id = ?",
                (run_id,)
            ).fetchone()
        if row is None:
            return None
        try:
            return json.loads(row["state_json"])
        except Exception:
            return None

    def delete(self, run_id: str) -> None:
        """Remove a checkpoint."""
        with self._conn() as conn:
            conn.execute("DELETE FROM checkpoints WHERE run_id = ?", (run_id,))

    def list_runs(self) -> List[Dict[str, Any]]:
        """List all saved checkpoints."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT run_id, updated_at FROM checkpoints ORDER BY updated_at DESC"
            ).fetchall()
        return [{"run_id": r["run_id"], "updated_at": r["updated_at"]} for r in rows]

    def cleanup_old(self, max_age_hours: float = 24.0) -> int:
        """Delete checkpoints older than max_age_hours. Returns count deleted."""
        cutoff = time.time() - (max_age_hours * 3600)
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM checkpoints WHERE updated_at < ?", (cutoff,)
            )
            return cur.rowcount


# ── KVStore ──────────────────────────────────────────────────────────────────

class KVStore:
    """
    Simple key-value store for agent working memory.
    Backed by SQLite for persistence, but has an in-memory cache for speed.

    Replaces langmem InMemoryStore.

    Usage:
        mem = KVStore()
        mem.set("recon:target.com", {"ports": [80, 443], "tech": ["nginx"]})
        data = mem.get("recon:target.com")
        mem.delete("recon:target.com")
    """

    def __init__(self, db_path: str = DEFAULT_DB_PATH) -> None:
        self.db_path = db_path
        self._cache: Dict[str, Any] = {}
        self._init_db()

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value_json TEXT NOT NULL,
                    namespace TEXT DEFAULT '',
                    updated_at REAL NOT NULL
                )
            """)

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def set(self, key: str, value: Any, namespace: str = "") -> None:
        """Set a key-value pair."""
        full_key = f"{namespace}:{key}" if namespace else key
        self._cache[full_key] = value
        try:
            value_json = json.dumps(value, default=str)
        except Exception:
            value_json = json.dumps(repr(value))
        with self._conn() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO kv_store (key, value_json, namespace, updated_at)
                VALUES (?, ?, ?, ?)
                """,
                (full_key, value_json, namespace, time.time())
            )

    def get(self, key: str, namespace: str = "", default: Any = None) -> Any:
        """Get a value by key."""
        full_key = f"{namespace}:{key}" if namespace else key
        if full_key in self._cache:
            return self._cache[full_key]
        with self._conn() as conn:
            row = conn.execute(
                "SELECT value_json FROM kv_store WHERE key = ?", (full_key,)
            ).fetchone()
        if row is None:
            return default
        try:
            val = json.loads(row["value_json"])
            self._cache[full_key] = val
            return val
        except Exception:
            return default

    def delete(self, key: str, namespace: str = "") -> None:
        """Delete a key."""
        full_key = f"{namespace}:{key}" if namespace else key
        self._cache.pop(full_key, None)
        with self._conn() as conn:
            conn.execute("DELETE FROM kv_store WHERE key = ?", (full_key,))

    def list_keys(self, namespace: str = "") -> List[str]:
        """List all keys, optionally filtered by namespace."""
        with self._conn() as conn:
            if namespace:
                rows = conn.execute(
                    "SELECT key FROM kv_store WHERE namespace = ?", (namespace,)
                ).fetchall()
            else:
                rows = conn.execute("SELECT key FROM kv_store").fetchall()
        return [r["key"] for r in rows]

    def clear_namespace(self, namespace: str) -> int:
        """Delete all keys in a namespace. Returns count deleted."""
        keys_to_clear = [k for k in self._cache if k.startswith(f"{namespace}:")]
        for k in keys_to_clear:
            del self._cache[k]
        with self._conn() as conn:
            cur = conn.execute(
                "DELETE FROM kv_store WHERE namespace = ?", (namespace,)
            )
            return cur.rowcount


# ── Observation Journal ──────────────────────────────────────────────────────
# Used by the XLayer agentic loop to store per-iteration observations.

@dataclass
class ObservationEntry:
    """One entry in the observation journal. observation_memo + next_strategy for next LLM context."""
    iteration: int
    action: str          # tool name or "JIT" or "THINK"
    input_summary: str   # brief summary of what was tried
    result_summary: str  # brief summary of result
    confidence: float
    timestamp: float = 0.0
    observation_memo: str = ""   # status, body_diff_hint, WAF → for next payload choice
    next_strategy: str = ""      # e.g. "403 → try encoding" (structured reasoning hint)

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()

    def to_text(self) -> str:
        base = (
            f"[iter {self.iteration:02d}] {self.action} | "
            f"conf={self.confidence:.2f} | {self.input_summary} → {self.result_summary}"
        )
        if self.observation_memo:
            base += f" | Obs: {self.observation_memo}"
        if self.next_strategy:
            base += f" | Next: {self.next_strategy}"
        return base


class ObservationJournal:
    """
    In-memory ordered log of all observations in a Solver run.
    Provides compressed summaries for LLM context.
    """

    def __init__(self) -> None:
        self._entries: List[ObservationEntry] = []

    def add(self, entry: ObservationEntry) -> None:
        self._entries.append(entry)

    def all(self) -> List[ObservationEntry]:
        return list(self._entries)

    def last_n(self, n: int) -> List[ObservationEntry]:
        return self._entries[-n:]

    def as_text(self, max_entries: int = 20) -> str:
        """Return journal as readable text for LLM context."""
        entries = self._entries[-max_entries:]
        if not entries:
            return "(No observations yet)"
        return "\n".join(e.to_text() for e in entries)

    def recent_confidence_trend(self, n: int = 5) -> List[float]:
        """Get last n confidence scores."""
        return [e.confidence for e in self._entries[-n:]]

    def is_stuck(self, window: int = 3, threshold: float = 0.30) -> bool:
        """
        Returns True if last `window` iterations all had confidence below threshold.
        Used to trigger auto-pivot.
        """
        recent = self.recent_confidence_trend(window)
        if len(recent) < window:
            return False
        return all(c < threshold for c in recent)

    def best_confidence(self) -> float:
        """Return highest confidence seen so far."""
        if not self._entries:
            return 0.0
        return max(e.confidence for e in self._entries)

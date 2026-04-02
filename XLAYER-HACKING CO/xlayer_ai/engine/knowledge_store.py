"""
engine/knowledge_store.py — Shared Knowledge for Chaining

Key-value store for tokens, session IDs, user IDs extracted from solver findings.
Coordinator and other solvers read from it to build chaining specs (e.g. use token
from endpoint A on endpoint B).
"""

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class KnowledgeEntry:
    """One stored value with optional source context."""
    value: str
    key: str           # e.g. "token", "session_id", "user_id"
    source_url: str = ""
    source_vuln_type: str = ""


class KnowledgeStore:
    """
    In-memory key-value store for chaining: tokens, session_id, user_id, etc.
    Coordinator pushes from solver results; reads when building chaining specs.
    """

    def __init__(self) -> None:
        self._store: Dict[str, List[KnowledgeEntry]] = {}
        self._max_per_key = 5

    def put(self, key: str, value: str, source_url: str = "", source_vuln_type: str = "") -> None:
        """Store a value for key. Keeps last N entries per key."""
        key = key.lower().strip()
        if not key or not value or len(value) > 2000:
            return
        if key not in self._store:
            self._store[key] = []
        entries = self._store[key]
        entry = KnowledgeEntry(value=value, key=key, source_url=source_url, source_vuln_type=source_vuln_type)
        # Dedupe by value
        if any(e.value == value for e in entries):
            return
        entries.append(entry)
        if len(entries) > self._max_per_key:
            self._store[key] = entries[-self._max_per_key:]

    def get(self, key: str) -> Optional[str]:
        """Return latest value for key, or None."""
        entries = self._store.get(key.lower(), [])
        return entries[-1].value if entries else None

    def get_all(self, key: str) -> List[str]:
        """Return all values for key (newest last)."""
        return [e.value for e in self._store.get(key.lower(), [])]

    def get_entries(self, key: str) -> List[KnowledgeEntry]:
        """Return all entries for key."""
        return list(self._store.get(key.lower(), []))

    def keys(self) -> List[str]:
        """Return all keys that have at least one value."""
        return list(self._store.keys())

    def to_dict(self) -> Dict[str, List[str]]:
        """Return {key: [values]} for serialization."""
        return {k: [e.value for e in v] for k, v in self._store.items()}

    @staticmethod
    def extract_from_result(result: Dict[str, Any]) -> List[tuple]:
        """
        Heuristically extract (key, value) from a solver result.
        Returns [(key, value), ...] for token, session_id, user_id, etc.
        """
        out: List[tuple] = []
        proof = (result.get("proof_response") or "") + " " + (result.get("working_payload") or "")
        url = result.get("target_url", "")

        # JWT / Bearer token
        jwt_match = re.search(r"(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)", proof)
        if jwt_match:
            out.append(("token", jwt_match.group(1)))
            out.append(("authorization", "Bearer " + jwt_match.group(1)))

        # session_id=... or session=... or Session=...
        for pat in [r"[Ss]ession[_\-]?[Ii]d['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{10,})", r"session=([A-Za-z0-9_-]{10,})"]:
            m = re.search(pat, proof)
            if m:
                out.append(("session_id", m.group(1)))

        # user_id=... or user=...
        m = re.search(r"user[_\-]?[Ii]d['\"]?\s*[:=]\s*['\"]?(\d+|[A-Za-z0-9_-]{8,})", proof)
        if m:
            out.append(("user_id", m.group(1)))

        # csrf_token, _token, authenticity_token
        for key in ["csrf_token", "_token", "authenticity_token"]:
            m = re.search(rf"{re.escape(key)}['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9_-]{{8,}})", proof, re.I)
            if m:
                out.append((key, m.group(1)))

        return out

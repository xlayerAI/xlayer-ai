"""
Generation engine: orchestrates all category generators, handles deduplication,
output management, statistics, and checkpoint support.
"""

import hashlib
import json
import os
import random
import time
from pathlib import Path
from typing import Dict, List, Optional

from .config import DataGenConfig
from .categories import CATEGORY_REGISTRY


class GenerationEngine:
    """Main orchestrator for synthetic cybersecurity training data generation."""

    def __init__(self, config: DataGenConfig):
        self.config = config
        self.rng = random.Random(config.seed)
        self.seen_hashes: set = set()
        self.stats: Dict[str, int] = {}
        self.total_generated = 0

    def _content_hash(self, entry: dict) -> str:
        content = (entry.get("instruction", "")[:500] +
                   entry.get("input", "")[:500])
        return hashlib.sha256(content.encode("utf-8")).hexdigest()[:16]

    def _deduplicate(self, entries: List[dict]) -> List[dict]:
        unique = []
        for entry in entries:
            h = self._content_hash(entry)
            if h not in self.seen_hashes:
                self.seen_hashes.add(h)
                unique.append(entry)
        return unique

    def _check_deny_keywords(self, entry: dict) -> bool:
        """Return True if entry is safe (no deny keywords found)."""
        text = (entry.get("instruction", "") + " " +
                entry.get("input", "") + " " +
                entry.get("output", "")).lower()
        for kw in self.config.deny_keywords:
            if kw.lower() in text:
                return False
        return True

    def _write_jsonl(self, filepath: str, entries: List[dict]):
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            for entry in entries:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _load_checkpoint(self) -> dict:
        ckpt_path = os.path.join(self.config.output_dir, "checkpoint.json")
        if os.path.exists(ckpt_path):
            with open(ckpt_path, "r") as f:
                return json.load(f)
        return {"completed_categories": [], "total": 0}

    def _save_checkpoint(self, completed: List[str], total: int):
        ckpt_path = os.path.join(self.config.output_dir, "checkpoint.json")
        os.makedirs(os.path.dirname(ckpt_path), exist_ok=True)
        with open(ckpt_path, "w") as f:
            json.dump({"completed_categories": completed, "total": total}, f)

    def generate_all(self, categories: Optional[List[str]] = None,
                     resume: bool = False) -> Dict[str, int]:
        """
        Generate all entries across categories.

        Args:
            categories: If specified, only generate these categories.
            resume: If True, skip already-completed categories from checkpoint.

        Returns:
            Dict of category -> count generated.
        """
        os.makedirs(self.config.output_dir, exist_ok=True)

        checkpoint = self._load_checkpoint() if resume else {"completed_categories": [], "total": 0}
        completed = set(checkpoint.get("completed_categories", []))

        distribution = self.config.distribution
        if categories:
            distribution = {k: v for k, v in distribution.items() if k in categories}

        print(f"[DataGen] Starting generation: {sum(distribution.values())} entries "
              f"across {len(distribution)} categories (seed={self.config.seed})")
        print(f"[DataGen] Output directory: {self.config.output_dir}")

        start_time = time.time()
        all_entries = []

        for cat_name, count in distribution.items():
            if cat_name in completed:
                print(f"  [{cat_name}] Skipped (checkpoint)")
                continue

            if cat_name not in CATEGORY_REGISTRY:
                print(f"  [{cat_name}] WARNING: No generator registered, skipping")
                continue

            generator = CATEGORY_REGISTRY[cat_name]
            # Set the id_prefix from config
            if cat_name in self.config.id_prefixes:
                generator.id_prefix = self.config.id_prefixes[cat_name]

            cat_rng = random.Random(self.rng.randint(0, 2**32))
            cat_start = time.time()

            print(f"  [{cat_name}] Generating {count} entries...", end="", flush=True)

            entries = generator.generate_entries(
                rng=cat_rng,
                count=count,
                start_id=self.total_generated,
                complexity_weights=self.config.complexity_weights,
            )

            # Deduplicate
            entries = self._deduplicate(entries)

            # Filter deny keywords
            if self.config.defensive_only:
                entries = [e for e in entries if self._check_deny_keywords(e)]

            # Write per-category JSONL
            cat_file = os.path.join(self.config.output_dir, f"{cat_name}.jsonl")
            self._write_jsonl(cat_file, entries)

            self.stats[cat_name] = len(entries)
            self.total_generated += len(entries)
            all_entries.extend(entries)

            elapsed = time.time() - cat_start
            print(f" {len(entries)} entries in {elapsed:.1f}s")

            # Save checkpoint
            completed.add(cat_name)
            self._save_checkpoint(list(completed), self.total_generated)

        # Shuffle and write combined file
        print(f"\n[DataGen] Shuffling and writing combined file...")
        self.rng.shuffle(all_entries)
        self._write_jsonl(self.config.combined_output, all_entries)

        # Write statistics
        total_time = time.time() - start_time
        stats_data = {
            "seed": self.config.seed,
            "total_entries": self.total_generated,
            "total_unique_hashes": len(self.seen_hashes),
            "generation_time_seconds": round(total_time, 2),
            "categories": self.stats,
            "output_file": self.config.combined_output,
        }
        stats_path = self.config.stats_output
        os.makedirs(os.path.dirname(stats_path), exist_ok=True)
        with open(stats_path, "w") as f:
            json.dump(stats_data, f, indent=2)

        print(f"[DataGen] Complete! {self.total_generated} entries in {total_time:.1f}s")
        print(f"[DataGen] Combined: {self.config.combined_output}")
        print(f"[DataGen] Stats: {self.config.stats_output}")

        # Clean up checkpoint on success
        ckpt_path = os.path.join(self.config.output_dir, "checkpoint.json")
        if os.path.exists(ckpt_path):
            os.remove(ckpt_path)

        return self.stats

#!/usr/bin/env python3
"""
CLI entry point for generating the 100K cybersecurity training dataset.

Usage:
    python generate_training_data.py
    python generate_training_data.py --total 1000 --categories exploit_chain,code_audit
    python generate_training_data.py --seed 123 --output data/generated
    python generate_training_data.py --dry-run
    python generate_training_data.py --resume
"""

import argparse
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.xic.datagen.config import DataGenConfig
from src.xic.datagen.engine import GenerationEngine


def main():
    parser = argparse.ArgumentParser(
        description="Generate synthetic cybersecurity training data for XLayer AI LLM"
    )
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed for reproducible generation (default: 42)")
    parser.add_argument("--total", type=int, default=None,
                        help="Override total entry count (scales distribution proportionally)")
    parser.add_argument("--categories", type=str, default=None,
                        help="Comma-separated list of categories to generate (default: all)")
    parser.add_argument("--output", type=str, default="data/generated",
                        help="Output directory (default: data/generated)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Print configuration and exit without generating")
    parser.add_argument("--resume", action="store_true",
                        help="Resume from last checkpoint")

    args = parser.parse_args()

    config = DataGenConfig(seed=args.seed, output_dir=args.output)

    if args.output:
        config.combined_output = os.path.join(args.output, "xlayer_cybersec_100k.jsonl")
        config.stats_output = os.path.join(args.output, "gen_stats.json")

    # Scale distribution if total is overridden
    if args.total is not None:
        original_total = sum(config.distribution.values())
        scale = args.total / original_total
        scaled = {}
        remaining = args.total
        keys = list(config.distribution.keys())
        for k in keys[:-1]:
            v = max(1, int(config.distribution[k] * scale))
            scaled[k] = v
            remaining -= v
        scaled[keys[-1]] = max(1, remaining)
        config.distribution = scaled

    categories = None
    if args.categories:
        categories = [c.strip() for c in args.categories.split(",")]
        invalid = [c for c in categories if c not in config.distribution]
        if invalid:
            print(f"ERROR: Unknown categories: {', '.join(invalid)}")
            print(f"Available: {', '.join(config.distribution.keys())}")
            sys.exit(1)

    # Dry run
    if args.dry_run:
        dist = config.distribution
        if categories:
            dist = {k: v for k, v in dist.items() if k in categories}
        print("=== Dry Run Configuration ===")
        print(f"Seed: {config.seed}")
        print(f"Output: {config.output_dir}")
        print(f"Total: {sum(dist.values())}")
        print(f"\nCategory Distribution:")
        for cat, count in dist.items():
            print(f"  {cat}: {count:,}")
        print(f"\nComplexity Weights:")
        for level, weight in config.complexity_weights.items():
            print(f"  {level}: {weight:.0%}")
        return

    # Generate
    engine = GenerationEngine(config)
    stats = engine.generate_all(categories=categories, resume=args.resume)

    print(f"\n=== Generation Summary ===")
    for cat, count in sorted(stats.items()):
        print(f"  {cat}: {count:,}")
    print(f"  TOTAL: {sum(stats.values()):,}")


if __name__ == "__main__":
    main()

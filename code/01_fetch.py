#!/usr/bin/env python3
"""Fetch every source and write data/raw/_fetch_manifest.json.

Equivalent to `icsprio fetch`; kept as a numbered script so the repository
matches the project's standard run-in-order layout even for someone who
hasn't installed the package as a CLI.

Usage: python code/01_fetch.py [--since-year YYYY]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from icsprio import pipeline  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--since-year", type=int, default=None)
    args = ap.parse_args()
    manifest = pipeline.run_fetch(since_year=args.since_year)
    for stage, count in manifest["stage_counts"].items():
        print(f"{stage}: {count}")


if __name__ == "__main__":
    main()

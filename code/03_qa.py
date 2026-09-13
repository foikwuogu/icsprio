#!/usr/bin/env python3
"""Generate data/processed/qa_report.txt and stats.json from the built table.

Usage: python code/03_qa.py [--final]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pandas as pd  # noqa: E402

from icsprio import io_utils, pipeline  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--final", action="store_true")
    args = ap.parse_args()

    manifest = pipeline.load_manifest()
    df = pd.read_csv("data/processed/icsprio_joined.csv")
    # list-typed columns round-trip through CSV as "a; b" strings; restore lists
    for col in ("vendors", "products", "cwes", "attack_technique_ids", "attack_technique_names"):
        df[col] = df[col].fillna("").apply(lambda v: [s for s in str(v).split("; ") if s])

    stats, report_text = pipeline.run_qa(df, manifest["stage_counts"], draft=not args.final)
    io_utils.write_stats_json(stats, "data/processed/stats.json")
    with open("data/processed/qa_report.txt", "w", encoding="utf-8") as f:
        f.write(report_text)
    print(report_text)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Join, score, and write data/processed/icsprio_joined.{csv,parquet}.

Usage: python code/02_build.py [--weights-file weights.yaml]
"""
import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from icsprio import io_utils, pipeline  # noqa: E402
from icsprio.cli import _load_weights  # noqa: E402


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--weights-file", default=None)
    args = ap.parse_args()

    manifest = pipeline.load_manifest()
    weights = _load_weights(args.weights_file)
    df = pipeline.run_build(manifest, weights=weights)

    io_utils.export_csv(df, "data/processed/icsprio_joined.csv")
    io_utils.export_parquet(df, "data/processed/icsprio_joined.parquet")
    print(f"Wrote {len(df)} rows to data/processed/icsprio_joined.csv")


if __name__ == "__main__":
    main()

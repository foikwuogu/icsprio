"""Export helpers: CSV/Parquet output and the stats.json the docs read from.

Per the project's build standard, no document or README should ever have a
hand-typed number — everything traces back to stats.json, written here.
"""

from __future__ import annotations

import json
import os

import pandas as pd


def export_csv(df: pd.DataFrame, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    listy_cols = [c for c in df.columns if df[c].apply(lambda v: isinstance(v, list)).any()]
    out = df.copy()
    for col in listy_cols:
        out[col] = out[col].apply(lambda v: "; ".join(v) if isinstance(v, list) else v)
    out.to_csv(path, index=False)


def export_parquet(df: pd.DataFrame, path: str) -> bool:
    """Best-effort Parquet export; returns False (without raising) if pyarrow
    isn't installed, so `icsprio build` doesn't hard-fail over an optional
    dependency."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        df.to_parquet(path, index=False)
        return True
    except ImportError:
        return False


def write_stats_json(stats: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2, sort_keys=True, default=str)

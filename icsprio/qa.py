"""QA report generation: row counts, join match rates, sanity checks, and
named spot checks, written before anything downstream is trusted.

Matches the build standard's QA pattern: this is the first file a reader —
including the author, during the verification gate — should open.
"""

from __future__ import annotations

import datetime as _dt
from typing import Dict, List

import pandas as pd

from . import join as join_mod


def sanity_checks(df: pd.DataFrame) -> List[str]:
    problems = []

    dup_key = df.dropna(subset=["cve"]).duplicated(subset=["advisory_id", "cve"])
    if dup_key.any():
        problems.append(f"{int(dup_key.sum())} duplicate (advisory_id, cve) row(s)")

    bad_score = df["priority_score"].dropna()
    bad_score = bad_score[(bad_score < 0) | (bad_score > 100)]
    if len(bad_score):
        problems.append(f"{len(bad_score)} priority_score value(s) outside [0, 100]")

    bad_pct = df["epss_percentile"].dropna()
    bad_pct = bad_pct[(bad_pct < 0) | (bad_pct > 1)]
    if len(bad_pct):
        problems.append(f"{len(bad_pct)} epss_percentile value(s) outside [0, 1]")

    missing_id = df["advisory_id"].isna() | (df["advisory_id"] == "")
    if missing_id.any():
        problems.append(f"{int(missing_id.sum())} row(s) with no advisory_id")

    return problems


def spot_check_sample(df: pd.DataFrame, seed: int = 42, n_each: int = 2) -> pd.DataFrame:
    """A deterministic, reproducible sample for the author to check by hand:
    the highest-scored rows, the lowest-scored rows (excluding all-null
    scores), and a fixed-seed random sample — together meeting the build
    standard's five-or-more-named-spot-checks minimum.
    """
    scored = df.dropna(subset=["priority_score"])
    if scored.empty:
        return df.head(0)

    top = scored.nlargest(n_each, "priority_score")
    bottom = scored.nsmallest(n_each, "priority_score")
    remaining = scored.drop(index=top.index.union(bottom.index), errors="ignore")
    random_n = min(n_each, len(remaining))
    random_sample = remaining.sample(n=random_n, random_state=seed) if random_n else remaining.head(0)

    sample = pd.concat([top, bottom, random_sample]).drop_duplicates(
        subset=["advisory_id", "cve"]
    )
    return sample[
        ["advisory_id", "cve", "in_kev", "epss_percentile", "priority_score", "priority_band"]
    ]


def build_qa_report(
    df: pd.DataFrame,
    stage_counts: Dict[str, int],
    seed: int = 42,
) -> Dict[str, object]:
    """Return a dict with everything needed for both qa_report.txt (human)
    and stats.json (machine) — one computation, two renderings, so they
    cannot drift apart.
    """
    match_rates = join_mod.join_match_rates(df)
    band_counts = df["priority_band"].value_counts().to_dict()
    spot_checks = spot_check_sample(df, seed=seed)

    return {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(),
        "stage_counts": stage_counts,
        "n_rows_total": int(len(df)),
        "n_unique_advisories": int(df["advisory_id"].nunique()),
        "n_unique_cves": int(df["cve"].dropna().nunique()),
        "join_match_rates": match_rates,
        "priority_band_counts": {str(k): int(v) for k, v in band_counts.items()},
        "sanity_check_problems": sanity_checks(df),
        "spot_check_sample": spot_checks.to_dict(orient="records"),
        "spot_check_seed": seed,
    }


def render_qa_report_text(qa: Dict[str, object], draft: bool = True) -> str:
    lines = []
    if draft:
        lines.append("=" * 70)
        lines.append("DRAFT — regenerate with --final after the verification gate passes")
        lines.append("=" * 70)
        lines.append("")

    lines.append(f"icsprio QA report — generated {qa['generated_at']}")
    lines.append("")
    lines.append("## Stage counts")
    for stage, count in qa["stage_counts"].items():
        lines.append(f"  {stage}: {count}")
    lines.append(f"  rows in joined table: {qa['n_rows_total']}")
    lines.append(f"  unique advisories: {qa['n_unique_advisories']}")
    lines.append(f"  unique CVEs: {qa['n_unique_cves']}")
    lines.append("")

    lines.append("## Join match rates (share of CVE-bearing rows matched)")
    for source, rate in qa["join_match_rates"].items():
        lines.append(f"  {source}: {rate:.1%}" if rate is not None else f"  {source}: n/a (column not present)")
    lines.append("")

    lines.append("## Priority band counts")
    for band, count in qa["priority_band_counts"].items():
        lines.append(f"  {band}: {count}")
    lines.append("")

    problems = qa["sanity_check_problems"]
    lines.append("## Sanity checks")
    if problems:
        for p in problems:
            lines.append(f"  [FAIL] {p}")
    else:
        lines.append("  [OK] no problems detected")
    lines.append("")

    lines.append(f"## Spot-check sample (seed={qa['spot_check_seed']}; verify these by hand)")
    for row in qa["spot_check_sample"]:
        lines.append(
            f"  {row['advisory_id']} / {row.get('cve')}: "
            f"in_kev={row.get('in_kev')} epss_percentile={row.get('epss_percentile')} "
            f"priority_score={row.get('priority_score')} ({row.get('priority_band')})"
        )
    lines.append("")
    lines.append(
        "[VERIFY] Confirm each spot-check row against the CISA advisory page, "
        "the KEV catalog, and the EPSS API directly before trusting this report."
    )
    return "\n".join(lines)

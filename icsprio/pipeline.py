"""Pipeline orchestration: fetch -> build/join/score -> QA.

Kept separate from cli.py so the whole pipeline is callable and testable as
plain functions, independent of the CLI framework.
"""

from __future__ import annotations

import json
import os
from typing import Optional

from . import attack_mapping, config, io_utils, join, qa, scoring
from .config import ScoringWeights
from .sources import attack_ics, cisa_ics, epss, kev, vulnrichment

MANIFEST_PATH = os.path.join(config.DEFAULT_RAW_DIR, "_fetch_manifest.json")


def run_fetch(
    since_year: Optional[int] = None,
    raw_dir: str = config.DEFAULT_RAW_DIR,
    manifest_path: Optional[str] = None,
) -> dict:
    """Fetch every source and write a consolidated manifest so `run_build`
    never needs to re-fetch or re-parse raw payloads.

    `manifest_path` defaults to `<raw_dir>/_fetch_manifest.json` — derived
    from `raw_dir` rather than a fixed global path, so pointing `raw_dir` at
    a scratch directory (as the test suite does) never touches the real
    `data/raw/`.
    """
    if manifest_path is None:
        manifest_path = os.path.join(raw_dir, "_fetch_manifest.json")

    from .http import get_session

    session = get_session()

    advisories = cisa_ics.fetch_ics_advisories(since_year=since_year, session=session, raw_dir=raw_dir)
    advisory_rows = cisa_ics.advisories_to_rows(advisories)
    cve_ids = sorted({r["cve"] for r in advisory_rows if r.get("cve")})

    kev_by_cve = kev.fetch_kev(session=session, raw_dir=raw_dir)
    epss_by_cve = epss.fetch_epss(cve_ids, session=session, raw_dir=raw_dir)
    vulnrichment_by_cve = vulnrichment.fetch_vulnrichment(cve_ids, session=session, raw_dir=raw_dir)
    attack_techniques = attack_ics.fetch_attack_ics(session=session, raw_dir=raw_dir)

    manifest = {
        "since_year": since_year,
        "advisory_rows": advisory_rows,
        "kev_by_cve": kev_by_cve,
        "epss_by_cve": epss_by_cve,
        "vulnrichment_by_cve": vulnrichment_by_cve,
        "attack_techniques": attack_techniques,
        "stage_counts": {
            "advisories_fetched": len(advisories),
            "advisory_cve_rows": len(advisory_rows),
            "unique_cves": len(cve_ids),
            "kev_entries": len(kev_by_cve),
            "epss_scored_cves": len(epss_by_cve),
            "vulnrichment_records": len(vulnrichment_by_cve),
            "attack_techniques": len(attack_techniques),
        },
    }
    os.makedirs(os.path.dirname(manifest_path) or ".", exist_ok=True)
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, default=str)
    return manifest


def load_manifest(manifest_path: str = MANIFEST_PATH) -> dict:
    with open(manifest_path, encoding="utf-8") as f:
        return json.load(f)


def run_build(
    manifest: dict,
    weights: Optional[ScoringWeights] = None,
    crosswalk_path: str = config.CWE_ATTACK_CROSSWALK,
):
    crosswalk = attack_mapping.load_crosswalk(crosswalk_path)
    df = join.build_joined_table(
        advisory_rows=manifest["advisory_rows"],
        kev_by_cve=manifest["kev_by_cve"],
        epss_by_cve=manifest["epss_by_cve"],
        vulnrichment_by_cve=manifest["vulnrichment_by_cve"],
        attack_techniques=manifest["attack_techniques"],
        crosswalk=crosswalk,
    )
    df = scoring.score_dataframe(df, weights=weights)
    return df


def run_qa(df, stage_counts: dict, seed: int = 42, draft: bool = True):
    stats = qa.build_qa_report(df, stage_counts, seed=seed)
    text = qa.render_qa_report_text(stats, draft=draft)
    return stats, text


def run_pipeline(
    since_year: Optional[int] = None,
    raw_dir: str = config.DEFAULT_RAW_DIR,
    processed_dir: str = config.DEFAULT_PROCESSED_DIR,
    weights: Optional[ScoringWeights] = None,
    draft: bool = True,
):
    """Fetch, build, score, and QA in one call — what `icsprio run` invokes,
    and what tests exercise end-to-end against fixtures."""
    manifest = run_fetch(since_year=since_year, raw_dir=raw_dir)
    df = run_build(manifest, weights=weights)
    stats, report_text = run_qa(df, manifest["stage_counts"], draft=draft)

    io_utils.export_csv(df, os.path.join(processed_dir, "icsprio_joined.csv"))
    parquet_ok = io_utils.export_parquet(df, os.path.join(processed_dir, "icsprio_joined.parquet"))
    io_utils.write_stats_json(stats, os.path.join(processed_dir, "stats.json"))
    with open(os.path.join(processed_dir, "qa_report.txt"), "w", encoding="utf-8") as f:
        f.write(report_text)

    return {"df": df, "stats": stats, "report_text": report_text, "parquet_written": parquet_ok}

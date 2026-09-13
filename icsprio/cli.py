"""icsprio command-line interface.

    icsprio fetch  [--since-year YYYY] [--raw-dir data/raw]
    icsprio build  [--raw-dir data/raw] [--processed-dir data/processed] [--weights-file weights.yaml]
    icsprio run    [--since-year YYYY] [--final]
    icsprio report [--processed-dir data/processed]

`run` does fetch + build + QA in one call and is what the README's quick
start uses; `fetch`/`build` are split out for anyone who wants to re-score
already-fetched data (e.g. after editing docs/SCORING.md's weights) without
re-hitting the network.
"""

from __future__ import annotations

import os
import sys

import click
import yaml

from . import __version__, config, pipeline
from .config import ScoringWeights


def _load_weights(weights_file: str) -> ScoringWeights:
    if not weights_file:
        return ScoringWeights()
    with open(weights_file, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    weights = ScoringWeights(**data)
    weights.validate()
    return weights


@click.group()
@click.version_option(__version__, prog_name="icsprio")
def main():
    """Fetch, join, and prioritize ICS vulnerability intelligence."""


@main.command()
@click.option("--since-year", type=int, default=None, help="Earliest advisory year to fetch (default: current year - 3).")
@click.option("--raw-dir", default=config.DEFAULT_RAW_DIR, show_default=True)
def fetch(since_year, raw_dir):
    """Fetch CISA ICS advisories, KEV, EPSS, Vulnrichment, and ATT&CK for ICS."""
    manifest = pipeline.run_fetch(since_year=since_year, raw_dir=raw_dir)
    click.echo("Fetched:")
    for stage, count in manifest["stage_counts"].items():
        click.echo(f"  {stage}: {count}")


@main.command()
@click.option("--raw-dir", default=config.DEFAULT_RAW_DIR, show_default=True)
@click.option("--processed-dir", default=config.DEFAULT_PROCESSED_DIR, show_default=True)
@click.option("--weights-file", default=None, help="YAML file overriding docs/SCORING.md's default weights.")
@click.option("--final", is_flag=True, help="Remove the DRAFT stamp from the QA report (only after the verification gate passes).")
def build(raw_dir, processed_dir, weights_file, final):
    """Join, score, and QA-report an already-fetched manifest (run `fetch` first)."""
    manifest_path = os.path.join(raw_dir, "_fetch_manifest.json")
    if not os.path.exists(manifest_path):
        click.echo(f"No fetch manifest at {manifest_path}. Run `icsprio fetch` first.", err=True)
        sys.exit(1)

    manifest = pipeline.load_manifest(manifest_path)
    weights = _load_weights(weights_file)
    df = pipeline.run_build(manifest, weights=weights)
    stats, report_text = pipeline.run_qa(df, manifest["stage_counts"], draft=not final)

    from . import io_utils

    io_utils.export_csv(df, os.path.join(processed_dir, "icsprio_joined.csv"))
    parquet_ok = io_utils.export_parquet(df, os.path.join(processed_dir, "icsprio_joined.parquet"))
    io_utils.write_stats_json(stats, os.path.join(processed_dir, "stats.json"))
    with open(os.path.join(processed_dir, "qa_report.txt"), "w", encoding="utf-8") as f:
        f.write(report_text)

    click.echo(f"Wrote {len(df)} rows to {processed_dir}/icsprio_joined.csv")
    if not parquet_ok:
        click.echo("(pyarrow not installed — skipped Parquet export; `pip install icsprio[parquet]`)")
    click.echo(f"QA report: {processed_dir}/qa_report.txt")


@main.command()
@click.option("--since-year", type=int, default=None)
@click.option("--raw-dir", default=config.DEFAULT_RAW_DIR, show_default=True)
@click.option("--processed-dir", default=config.DEFAULT_PROCESSED_DIR, show_default=True)
@click.option("--weights-file", default=None)
@click.option("--final", is_flag=True)
def run(since_year, raw_dir, processed_dir, weights_file, final):
    """Fetch + build + QA in one call."""
    weights = _load_weights(weights_file)
    result = pipeline.run_pipeline(
        since_year=since_year,
        raw_dir=raw_dir,
        processed_dir=processed_dir,
        weights=weights,
        draft=not final,
    )
    click.echo(f"Wrote {len(result['df'])} rows to {processed_dir}/icsprio_joined.csv")
    click.echo(f"QA report: {processed_dir}/qa_report.txt")


@main.command()
@click.option("--processed-dir", default=config.DEFAULT_PROCESSED_DIR, show_default=True)
def report(processed_dir):
    """Print the most recently generated QA report."""
    path = os.path.join(processed_dir, "qa_report.txt")
    if not os.path.exists(path):
        click.echo(f"No QA report at {path}. Run `icsprio run` first.", err=True)
        sys.exit(1)
    with open(path, encoding="utf-8") as f:
        click.echo(f.read())


if __name__ == "__main__":
    main()

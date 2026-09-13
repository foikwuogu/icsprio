"""End-to-end pipeline test against fixtures only — no network calls.

This is the closest thing to `icsprio run` that the test suite can exercise
offline: every source fetcher is monkeypatched to return fixture-derived
data instead of hitting the live APIs, then the real join/score/QA code
runs unmodified.
"""

import os

from icsprio import pipeline
from icsprio.sources import attack_ics, cisa_ics, epss, kev, vulnrichment


def test_run_pipeline_end_to_end(
    tmp_path, monkeypatch, csaf_advisory_fixture, kev_fixture, epss_fixture, vulnrichment_fixture, attack_ics_fixture
):
    raw_dir = str(tmp_path / "raw")
    processed_dir = str(tmp_path / "processed")

    monkeypatch.setattr(
        cisa_ics,
        "fetch_ics_advisories",
        lambda since_year=None, session=None, raw_dir=raw_dir: [
            cisa_ics.parse_csaf_advisory(csaf_advisory_fixture)
        ],
    )
    monkeypatch.setattr(kev, "fetch_kev", lambda session=None, raw_dir=raw_dir: kev.parse_kev(kev_fixture))
    monkeypatch.setattr(
        epss, "fetch_epss", lambda cve_ids, session=None, raw_dir=raw_dir: epss.parse_epss(epss_fixture)
    )
    monkeypatch.setattr(
        vulnrichment,
        "fetch_vulnrichment",
        lambda cve_ids, session=None, raw_dir=raw_dir: {
            "CVE-2099-00001": vulnrichment.parse_vulnrichment_record(vulnrichment_fixture)
        },
    )
    monkeypatch.setattr(
        attack_ics,
        "fetch_attack_ics",
        lambda session=None, raw_dir=raw_dir: attack_ics.parse_attack_bundle(attack_ics_fixture),
    )

    result = pipeline.run_pipeline(raw_dir=raw_dir, processed_dir=processed_dir)

    assert len(result["df"]) == 1
    assert result["stats"]["n_rows_total"] == 1
    assert os.path.exists(os.path.join(processed_dir, "icsprio_joined.csv"))
    assert os.path.exists(os.path.join(processed_dir, "qa_report.txt"))
    assert os.path.exists(os.path.join(processed_dir, "stats.json"))
    # Note: PROVENANCE.txt is written by the real source fetchers
    # (icsprio.provenance.log_fetch), not by these monkeypatched stand-ins —
    # see tests/test_provenance.py for that behavior in isolation.

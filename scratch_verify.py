"""Ad-hoc verification harness — NOT part of the shipped test suite.

This sandbox's network egress blocks PyPI/apt, so `pytest` cannot be
installed here to run tests/ properly. This script exercises the same
code paths using only the standard library plus the runtime deps that
happen to already be present (requests, pandas, click, yaml), so the core
logic can be checked before handing the repo to the author, who will run
the real `pytest` suite (README quick start) on a machine with normal
internet access.
"""
import json
import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(__file__))

FIX = os.path.join("tests", "fixtures")


def load(name):
    with open(os.path.join(FIX, name), encoding="utf-8") as f:
        return json.load(f)


failures = []


def check(name, fn):
    try:
        fn()
        print(f"OK   {name}")
    except Exception:
        print(f"FAIL {name}")
        traceback.print_exc()
        failures.append(name)


def test_kev():
    from icsprio.sources.kev import parse_kev

    out = parse_kev(load("kev_sample.json"))
    assert set(out) == {"CVE-2099-00001", "CVE-2099-00099"}
    assert out["CVE-2099-00001"]["in_kev"] is True


def test_epss():
    from icsprio.sources.epss import parse_epss

    out = parse_epss(load("epss_sample.json"))
    assert out["CVE-2099-00001"]["epss_percentile"] == 0.99972
    assert len(out) == 3


def test_vulnrichment():
    from icsprio.sources.vulnrichment import _bucket_path, parse_vulnrichment_record

    assert _bucket_path("CVE-2024-32830") == "2024/32xxx/CVE-2024-32830.json"
    out = parse_vulnrichment_record(load("vulnrichment_cve_sample.json"))
    assert out["ssvc_exploitation"] == "active"
    assert out["cwes"] == ["CWE-798"]


def test_attack_ics():
    from icsprio.sources.attack_ics import parse_attack_bundle

    out = parse_attack_bundle(load("attack_ics_sample.json"))
    assert set(out) == {"T0859", "T0819"}
    assert "T9999" not in out


def test_cisa_ics():
    from icsprio.sources.cisa_ics import advisories_to_rows, parse_csaf_advisory

    adv = parse_csaf_advisory(load("csaf_advisory_sample.json"))
    assert adv["advisory_id"] == "ICSA-99-999-01"
    assert adv["vendors"] == ["Fixture Vendor"]
    assert adv["cves"] == ["CVE-2099-00001"]
    rows = advisories_to_rows([adv])
    assert rows[0]["cve"] == "CVE-2099-00001"


def test_attack_mapping():
    from icsprio import attack_mapping
    from icsprio.config import CWE_ATTACK_CROSSWALK

    crosswalk = attack_mapping.load_crosswalk(CWE_ATTACK_CROSSWALK)
    assert "CWE-798" in crosswalk
    mapped = attack_mapping.map_cwes_to_techniques(["CWE-798"], crosswalk)
    ids = {m["attack_technique_id"] for m in mapped}
    assert "T0859" in ids


def test_scoring():
    from icsprio.scoring import compute_priority_score, priority_band

    full = {
        "in_kev": True,
        "epss_percentile": 0.99,
        "ssvc_exploitation": "active",
        "ssvc_automatable": "yes",
        "ssvc_technical_impact": "total",
    }
    score = compute_priority_score(full)
    assert score > 90, score
    assert priority_band(score) == "Critical"

    none_row = {"in_kev": False, "epss_percentile": None}
    assert compute_priority_score(none_row) == 0.0

    no_ssvc = compute_priority_score({"in_kev": True, "epss_percentile": 1.0})
    low_ssvc = compute_priority_score(
        {
            "in_kev": True,
            "epss_percentile": 1.0,
            "ssvc_exploitation": "none",
            "ssvc_automatable": "no",
            "ssvc_technical_impact": "partial",
        }
    )
    assert no_ssvc >= low_ssvc, (no_ssvc, low_ssvc)


def test_join_and_qa_end_to_end():
    from icsprio import attack_mapping, join, qa, scoring
    from icsprio.config import CWE_ATTACK_CROSSWALK
    from icsprio.sources.attack_ics import parse_attack_bundle
    from icsprio.sources.cisa_ics import advisories_to_rows, parse_csaf_advisory
    from icsprio.sources.epss import parse_epss
    from icsprio.sources.kev import parse_kev
    from icsprio.sources.vulnrichment import parse_vulnrichment_record

    advisory_rows = advisories_to_rows([parse_csaf_advisory(load("csaf_advisory_sample.json"))])
    kev_by_cve = parse_kev(load("kev_sample.json"))
    epss_by_cve = parse_epss(load("epss_sample.json"))
    vulnrichment_by_cve = {
        "CVE-2099-00001": parse_vulnrichment_record(load("vulnrichment_cve_sample.json"))
    }
    attack_techniques = parse_attack_bundle(load("attack_ics_sample.json"))
    crosswalk = attack_mapping.load_crosswalk(CWE_ATTACK_CROSSWALK)

    df = join.build_joined_table(
        advisory_rows, kev_by_cve, epss_by_cve, vulnrichment_by_cve, attack_techniques, crosswalk
    )
    assert len(df) == 1
    df = scoring.score_dataframe(df)
    assert df.iloc[0]["priority_band"] == "Critical"

    stats = qa.build_qa_report(df, stage_counts={"advisories_fetched": 1})
    assert stats["n_rows_total"] == 1
    assert qa.sanity_checks(df) == []
    text = qa.render_qa_report_text(stats)
    assert "DRAFT" in text


def test_pipeline_end_to_end_with_monkeypatched_fetchers(tmp_path="/tmp/icsprio_verify"):
    import shutil

    from icsprio import pipeline
    from icsprio.sources import attack_ics, cisa_ics, epss, kev, vulnrichment

    shutil.rmtree(tmp_path, ignore_errors=True)
    raw_dir = os.path.join(tmp_path, "raw")
    processed_dir = os.path.join(tmp_path, "processed")

    csaf = load("csaf_advisory_sample.json")
    kev_fx = load("kev_sample.json")
    epss_fx = load("epss_sample.json")
    vr_fx = load("vulnrichment_cve_sample.json")
    attack_fx = load("attack_ics_sample.json")

    orig = {
        "cisa": cisa_ics.fetch_ics_advisories,
        "kev": kev.fetch_kev,
        "epss": epss.fetch_epss,
        "vr": vulnrichment.fetch_vulnrichment,
        "attack": attack_ics.fetch_attack_ics,
    }
    try:
        cisa_ics.fetch_ics_advisories = lambda since_year=None, session=None, raw_dir=raw_dir: [
            cisa_ics.parse_csaf_advisory(csaf)
        ]
        kev.fetch_kev = lambda session=None, raw_dir=raw_dir: kev.parse_kev(kev_fx)
        epss.fetch_epss = lambda cve_ids, session=None, raw_dir=raw_dir: epss.parse_epss(epss_fx)
        vulnrichment.fetch_vulnrichment = lambda cve_ids, session=None, raw_dir=raw_dir: {
            "CVE-2099-00001": vulnrichment.parse_vulnrichment_record(vr_fx)
        }
        attack_ics.fetch_attack_ics = lambda session=None, raw_dir=raw_dir: attack_ics.parse_attack_bundle(
            attack_fx
        )

        result = pipeline.run_pipeline(raw_dir=raw_dir, processed_dir=processed_dir)
        assert len(result["df"]) == 1
        assert os.path.exists(os.path.join(processed_dir, "icsprio_joined.csv"))
        assert os.path.exists(os.path.join(processed_dir, "qa_report.txt"))
        # PROVENANCE.txt is written by the real fetchers, not these stand-ins.
    finally:
        cisa_ics.fetch_ics_advisories = orig["cisa"]
        kev.fetch_kev = orig["kev"]
        epss.fetch_epss = orig["epss"]
        vulnrichment.fetch_vulnrichment = orig["vr"]
        attack_ics.fetch_attack_ics = orig["attack"]


def test_provenance():
    import shutil

    from icsprio.provenance import log_fetch

    tmp = "/tmp/icsprio_verify_provenance"
    shutil.rmtree(tmp, ignore_errors=True)
    os.makedirs(tmp, exist_ok=True)
    log_path = os.path.join(tmp, "PROVENANCE.txt")
    line = log_fetch(log_path, "example.json", b'{"a": 1}', "https://example.org/example.json")
    assert os.path.exists(log_path)
    assert "example.json" in line
    assert "sha256:" in line


def test_cli_smoke():
    from click.testing import CliRunner

    from icsprio.cli import main

    runner = CliRunner()
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0, result.output


if __name__ == "__main__":
    check("kev", test_kev)
    check("epss", test_epss)
    check("vulnrichment", test_vulnrichment)
    check("attack_ics", test_attack_ics)
    check("cisa_ics", test_cisa_ics)
    check("attack_mapping", test_attack_mapping)
    check("scoring", test_scoring)
    check("join_and_qa_end_to_end", test_join_and_qa_end_to_end)
    check("pipeline_end_to_end", test_pipeline_end_to_end_with_monkeypatched_fetchers)
    check("provenance", test_provenance)
    check("cli_smoke", test_cli_smoke)

    print()
    if failures:
        print(f"{len(failures)} FAILED: {failures}")
        sys.exit(1)
    print("all checks passed")

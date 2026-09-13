from icsprio import attack_mapping, join
from icsprio.config import CWE_ATTACK_CROSSWALK
from icsprio.sources.attack_ics import parse_attack_bundle
from icsprio.sources.cisa_ics import advisories_to_rows, parse_csaf_advisory
from icsprio.sources.epss import parse_epss
from icsprio.sources.kev import parse_kev
from icsprio.sources.vulnrichment import parse_vulnrichment_record


def _build_fixture_table(csaf_advisory_fixture, kev_fixture, epss_fixture, vulnrichment_fixture, attack_ics_fixture):
    advisory_rows = advisories_to_rows([parse_csaf_advisory(csaf_advisory_fixture)])
    kev_by_cve = parse_kev(kev_fixture)
    epss_by_cve = parse_epss(epss_fixture)
    vulnrichment_by_cve = {"CVE-2099-00001": parse_vulnrichment_record(vulnrichment_fixture)}
    attack_techniques = parse_attack_bundle(attack_ics_fixture)
    crosswalk = attack_mapping.load_crosswalk(CWE_ATTACK_CROSSWALK)
    return join.build_joined_table(
        advisory_rows, kev_by_cve, epss_by_cve, vulnrichment_by_cve, attack_techniques, crosswalk
    )


def test_build_joined_table_has_one_row_and_all_columns(
    csaf_advisory_fixture, kev_fixture, epss_fixture, vulnrichment_fixture, attack_ics_fixture
):
    df = _build_fixture_table(
        csaf_advisory_fixture, kev_fixture, epss_fixture, vulnrichment_fixture, attack_ics_fixture
    )
    assert len(df) == 1
    assert list(df.columns) == join.OUTPUT_COLUMNS
    row = df.iloc[0]
    assert row["advisory_id"] == "ICSA-99-999-01"
    assert row["cve"] == "CVE-2099-00001"
    assert row["in_kev"] is True
    assert row["epss_percentile"] == 0.99972
    assert row["ssvc_exploitation"] == "active"
    assert "T0859" in row["attack_technique_ids"]  # CWE-798 -> Valid Accounts


def test_join_match_rates(
    csaf_advisory_fixture, kev_fixture, epss_fixture, vulnrichment_fixture, attack_ics_fixture
):
    df = _build_fixture_table(
        csaf_advisory_fixture, kev_fixture, epss_fixture, vulnrichment_fixture, attack_ics_fixture
    )
    rates = join.join_match_rates(df)
    assert rates["kev_match_rate"] == 1.0
    assert rates["epss_match_rate"] == 1.0
    assert rates["vulnrichment_match_rate"] == 1.0
    assert rates["attack_mapped_rate"] == 1.0


def test_join_handles_cve_with_no_enrichment(csaf_advisory_fixture, attack_ics_fixture):
    advisory_rows = advisories_to_rows([parse_csaf_advisory(csaf_advisory_fixture)])
    attack_techniques = parse_attack_bundle(attack_ics_fixture)
    crosswalk = attack_mapping.load_crosswalk(CWE_ATTACK_CROSSWALK)
    df = join.build_joined_table(advisory_rows, {}, {}, {}, attack_techniques, crosswalk)
    row = df.iloc[0]
    assert row["in_kev"] is False
    assert row["epss_score"] is None
    assert row["attack_technique_ids"] == []

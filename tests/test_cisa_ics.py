from icsprio.sources.cisa_ics import advisories_to_rows, parse_csaf_advisory


def test_parse_csaf_advisory_extracts_fields(csaf_advisory_fixture):
    adv = parse_csaf_advisory(csaf_advisory_fixture)
    assert adv["advisory_id"] == "ICSA-99-999-01"
    assert adv["advisory_type"] == "ICSA"
    assert adv["vendors"] == ["Fixture Vendor"]
    assert adv["products"] == ["Fixture PLC Firmware"]
    assert adv["cves"] == ["CVE-2099-00001"]
    assert adv["advisory_url"] == "https://www.cisa.gov/news-events/ics-advisories/icsa-99-999-01"


def test_advisory_type_detects_icsma(csaf_advisory_fixture):
    doc = dict(csaf_advisory_fixture)
    doc["document"] = dict(doc["document"])
    doc["document"]["tracking"] = dict(doc["document"]["tracking"])
    doc["document"]["tracking"]["id"] = "ICSMA-99-999-01"
    adv = parse_csaf_advisory(doc)
    assert adv["advisory_type"] == "ICSMA"


def test_advisories_to_rows_one_row_per_cve():
    advisories = [{"advisory_id": "A", "cves": ["CVE-1", "CVE-2"]}]
    rows = advisories_to_rows(advisories)
    assert [r["cve"] for r in rows] == ["CVE-1", "CVE-2"]
    assert all(r["advisory_id"] == "A" for r in rows)


def test_advisories_to_rows_keeps_advisory_with_no_cve():
    advisories = [{"advisory_id": "A", "cves": []}]
    rows = advisories_to_rows(advisories)
    assert rows == [{"advisory_id": "A", "cve": None}]

from icsprio.sources.epss import parse_epss


def test_parse_epss_extracts_score_and_percentile(epss_fixture):
    out = parse_epss(epss_fixture)
    assert out["CVE-2099-00001"]["epss_score"] == 0.97458
    assert out["CVE-2099-00001"]["epss_percentile"] == 0.99972
    assert out["CVE-2099-00001"]["epss_date"] == "2099-01-10"
    assert len(out) == 3


def test_parse_epss_skips_malformed_rows():
    out = parse_epss({"data": [{"cve": "CVE-2099-00001", "epss": "not-a-number", "percentile": "0.5"}]})
    assert out == {}


def test_parse_epss_handles_empty_response():
    assert parse_epss({}) == {}

from icsprio.sources.kev import parse_kev


def test_parse_kev_indexes_by_cve(kev_fixture):
    out = parse_kev(kev_fixture)
    assert set(out.keys()) == {"CVE-2099-00001", "CVE-2099-00099"}
    assert out["CVE-2099-00001"]["in_kev"] is True
    assert out["CVE-2099-00001"]["kev_date_added"] == "2099-01-02"
    assert out["CVE-2099-00099"]["kev_ransomware_use"] == "Known"


def test_parse_kev_skips_entries_without_cve():
    out = parse_kev({"vulnerabilities": [{"vendorProject": "x"}]})
    assert out == {}

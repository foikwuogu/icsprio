from icsprio.sources.vulnrichment import _bucket_path, parse_vulnrichment_record


def test_bucket_path_matches_confirmed_repo_convention():
    assert _bucket_path("CVE-2024-32830") == "2024/32xxx/CVE-2024-32830.json"
    assert _bucket_path("CVE-2024-4947") == "2024/4xxx/CVE-2024-4947.json"
    assert _bucket_path("CVE-2025-21334") == "2025/21xxx/CVE-2025-21334.json"


def test_bucket_path_rejects_malformed_ids():
    assert _bucket_path("not-a-cve") is None


def test_parse_vulnrichment_record_extracts_ssvc_cvss_cwe(vulnrichment_fixture):
    out = parse_vulnrichment_record(vulnrichment_fixture)
    assert out["ssvc_exploitation"] == "active"
    assert out["ssvc_automatable"] == "yes"
    assert out["ssvc_technical_impact"] == "total"
    assert out["cvss_base_score"] == 9.8
    assert out["cwes"] == ["CWE-798"]


def test_parse_vulnrichment_record_handles_missing_cisa_adp():
    out = parse_vulnrichment_record({"containers": {"adp": [{"providerMetadata": {"shortName": "Other"}}]}})
    assert out["ssvc_exploitation"] is None
    assert out["cwes"] == []

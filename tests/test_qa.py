import pandas as pd

from icsprio import qa


def _sample_df():
    return pd.DataFrame(
        [
            {"advisory_id": "A1", "cve": "CVE-1", "in_kev": True, "epss_percentile": 0.9, "priority_score": 90.0, "priority_band": "Critical"},
            {"advisory_id": "A2", "cve": "CVE-2", "in_kev": False, "epss_percentile": 0.1, "priority_score": 10.0, "priority_band": "Low"},
            {"advisory_id": "A3", "cve": "CVE-3", "in_kev": False, "epss_percentile": 0.5, "priority_score": 40.0, "priority_band": "Medium"},
            {"advisory_id": "A4", "cve": "CVE-4", "in_kev": True, "epss_percentile": 0.6, "priority_score": 65.0, "priority_band": "High"},
        ]
    )


def test_sanity_checks_detects_duplicate_keys():
    df = pd.concat([_sample_df(), _sample_df().iloc[[0]]], ignore_index=True)
    problems = qa.sanity_checks(df)
    assert any("duplicate" in p for p in problems)


def test_sanity_checks_detects_out_of_range_score():
    df = _sample_df()
    df.loc[0, "priority_score"] = 150.0
    problems = qa.sanity_checks(df)
    assert any("priority_score" in p for p in problems)


def test_sanity_checks_clean_data_has_no_problems():
    assert qa.sanity_checks(_sample_df()) == []


def test_spot_check_sample_includes_top_and_bottom():
    sample = qa.spot_check_sample(_sample_df(), n_each=1)
    assert "CVE-1" in sample["cve"].values  # highest score
    assert "CVE-2" in sample["cve"].values  # lowest score


def test_build_qa_report_is_json_serializable_shape():
    df = _sample_df()
    stats = qa.build_qa_report(df, stage_counts={"advisories_fetched": 4})
    assert stats["n_rows_total"] == 4
    assert "join_match_rates" in stats
    text = qa.render_qa_report_text(stats, draft=True)
    assert "DRAFT" in text
    text_final = qa.render_qa_report_text(stats, draft=False)
    assert "DRAFT" not in text_final

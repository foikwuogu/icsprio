import pytest

from icsprio.config import ScoringWeights
from icsprio.scoring import compute_priority_score, priority_band


def test_full_signal_row_scores_high():
    row = {
        "in_kev": True,
        "epss_percentile": 0.99,
        "ssvc_exploitation": "active",
        "ssvc_automatable": "yes",
        "ssvc_technical_impact": "total",
    }
    score = compute_priority_score(row)
    assert score > 90
    assert priority_band(score) == "Critical"


def test_no_signal_row_scores_zero():
    row = {"in_kev": False, "epss_percentile": None}
    score = compute_priority_score(row)
    assert score == 0.0
    assert priority_band(score) == "Low"


def test_missing_vulnrichment_renormalizes_remaining_weights():
    """A CVE with no Vulnrichment record at all should be scored on
    KEV + EPSS alone, not penalized to near-zero for lacking SSVC data."""
    row_with_kev_and_epss_only = {"in_kev": True, "epss_percentile": 1.0}
    row_with_everything_but_low_ssvc = {
        "in_kev": True,
        "epss_percentile": 1.0,
        "ssvc_exploitation": "none",
        "ssvc_automatable": "no",
        "ssvc_technical_impact": "partial",
    }
    score_no_ssvc = compute_priority_score(row_with_kev_and_epss_only)
    score_low_ssvc = compute_priority_score(row_with_everything_but_low_ssvc)
    # Missing SSVC data should score AT LEAST as well as present-but-low SSVC data.
    assert score_no_ssvc >= score_low_ssvc


def test_score_is_deterministic():
    row = {"in_kev": True, "epss_percentile": 0.5, "ssvc_exploitation": "poc"}
    assert compute_priority_score(row) == compute_priority_score(row)


def test_invalid_weights_raise():
    bad = ScoringWeights(kev_weight=0.9, epss_weight=0.9)
    with pytest.raises(ValueError):
        compute_priority_score({"in_kev": True}, weights=bad)


def test_priority_band_thresholds():
    assert priority_band(80) == "Critical"
    assert priority_band(60) == "High"
    assert priority_band(30) == "Medium"
    assert priority_band(5) == "Low"

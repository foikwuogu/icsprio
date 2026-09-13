"""Deterministic OT-relevant priority scoring.

[VERIFY] The weights and banding thresholds here are icsprio's own
prioritization logic, not a value handed down by CISA, FIRST, or MITRE.
They are a documented starting point (docs/SCORING.md) that the author signs
off on before release and that any downstream user can override via
`icsprio.config.ScoringWeights` or `--weights-file` on the CLI. Given the
same inputs and the same weights, `compute_priority_score` always returns
the same output — that determinism is the point: two runs against the same
joined table never disagree.
"""

from __future__ import annotations

from typing import Optional

import pandas as pd

from .config import ScoringWeights

SSVC_EXPLOITATION_SCALE = {"none": 0.0, "poc": 0.5, "active": 1.0}
SSVC_AUTOMATABLE_SCALE = {"no": 0.0, "yes": 1.0}
SSVC_TECHNICAL_IMPACT_SCALE = {"partial": 0.5, "total": 1.0}

# priority_score (0-100) -> band. [VERIFY] thresholds before release.
BAND_THRESHOLDS = (
    (75.0, "Critical"),
    (50.0, "High"),
    (25.0, "Medium"),
    (0.0, "Low"),
)


def _scaled(value: Optional[str], scale: dict) -> Optional[float]:
    if value is None:
        return None
    return scale.get(str(value).strip().lower())


def compute_priority_score(row: dict, weights: ScoringWeights = None) -> float:
    """Compute one row's priority_score (0-100).

    KEV status is always scored (absence from KEV is itself a real, always-
    available signal: 0.0, not missing). EPSS and the three SSVC decision
    points are scored when present; when Vulnrichment has no record for a
    CVE at all, the three SSVC-derived weights are dropped from the
    denominator so an unenriched CVE isn't penalized purely for lacking
    enrichment coverage — see docs/SCORING.md, "Handling missing enrichment".
    """
    weights = weights or ScoringWeights()
    weights.validate()

    components = {}
    active_weight = 0.0

    kev_component = 1.0 if row.get("in_kev") else 0.0
    components["kev"] = (weights.kev_weight, kev_component)
    active_weight += weights.kev_weight

    epss_percentile = row.get("epss_percentile")
    if epss_percentile is not None and not pd.isna(epss_percentile):
        components["epss"] = (weights.epss_weight, float(epss_percentile))
        active_weight += weights.epss_weight

    has_vulnrichment = row.get("ssvc_exploitation") is not None or row.get(
        "ssvc_automatable"
    ) is not None or row.get("ssvc_technical_impact") is not None

    if has_vulnrichment:
        exploitation = _scaled(row.get("ssvc_exploitation"), SSVC_EXPLOITATION_SCALE) or 0.0
        components["ssvc_exploitation"] = (weights.ssvc_exploitation_weight, exploitation)
        active_weight += weights.ssvc_exploitation_weight

        automatable = _scaled(row.get("ssvc_automatable"), SSVC_AUTOMATABLE_SCALE) or 0.0
        components["ssvc_automatable"] = (weights.ssvc_automatable_weight, automatable)
        active_weight += weights.ssvc_automatable_weight

        technical_impact = (
            _scaled(row.get("ssvc_technical_impact"), SSVC_TECHNICAL_IMPACT_SCALE) or 0.0
        )
        components["ssvc_technical_impact"] = (
            weights.ssvc_technical_impact_weight,
            technical_impact,
        )
        active_weight += weights.ssvc_technical_impact_weight

    if active_weight <= 0:
        return 0.0

    weighted_sum = sum(w * v for w, v in components.values())
    return round(100.0 * weighted_sum / active_weight, 2)


def priority_band(score: float) -> str:
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return "Low"


def score_dataframe(df: pd.DataFrame, weights: ScoringWeights = None) -> pd.DataFrame:
    df = df.copy()
    df["priority_score"] = df.apply(lambda r: compute_priority_score(r.to_dict(), weights), axis=1)
    df["priority_band"] = df["priority_score"].apply(priority_band)
    return df

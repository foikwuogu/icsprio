"""Join advisories, KEV, EPSS, Vulnrichment, and the ATT&CK-for-ICS crosswalk
into icsprio's single output table — one row per (advisory, CVE) pair.

This is the only place all five sources meet, which is deliberate: every
other module can be tested against one source in isolation, and this module
is where join match rates get measured for the QA report.
"""

from __future__ import annotations

from typing import Dict, List, Optional

import pandas as pd

from . import attack_mapping

OUTPUT_COLUMNS = [
    "advisory_id",
    "advisory_type",
    "title",
    "published",
    "updated",
    "vendors",
    "products",
    "advisory_url",
    "cve",
    "in_kev",
    "kev_date_added",
    "kev_due_date",
    "kev_ransomware_use",
    "epss_score",
    "epss_percentile",
    "epss_date",
    "ssvc_exploitation",
    "ssvc_automatable",
    "ssvc_technical_impact",
    "cvss_base_score",
    "cvss_vector",
    "cwes",
    "attack_technique_ids",
    "attack_technique_names",
    "priority_score",
    "priority_band",
]


def build_joined_table(
    advisory_rows: List[dict],
    kev_by_cve: Dict[str, dict],
    epss_by_cve: Dict[str, dict],
    vulnrichment_by_cve: Dict[str, dict],
    attack_techniques: Dict[str, dict],
    crosswalk: Dict[str, List[dict]],
) -> pd.DataFrame:
    rows = []
    for base in advisory_rows:
        cve = base.get("cve")
        row = dict(base)

        kev = kev_by_cve.get(cve, {}) if cve else {}
        row["in_kev"] = kev.get("in_kev", False)
        row["kev_date_added"] = kev.get("kev_date_added")
        row["kev_due_date"] = kev.get("kev_due_date")
        row["kev_ransomware_use"] = kev.get("kev_ransomware_use")

        epss = epss_by_cve.get(cve, {}) if cve else {}
        row["epss_score"] = epss.get("epss_score")
        row["epss_percentile"] = epss.get("epss_percentile")
        row["epss_date"] = epss.get("epss_date")

        vr = vulnrichment_by_cve.get(cve, {}) if cve else {}
        row["ssvc_exploitation"] = vr.get("ssvc_exploitation")
        row["ssvc_automatable"] = vr.get("ssvc_automatable")
        row["ssvc_technical_impact"] = vr.get("ssvc_technical_impact")
        row["cvss_base_score"] = vr.get("cvss_base_score")
        row["cvss_vector"] = vr.get("cvss_vector")
        cwes = vr.get("cwes", [])
        row["cwes"] = cwes

        mapped = attack_mapping.map_cwes_to_techniques(cwes, crosswalk)
        # Keep only techniques actually present in the fetched ATT&CK catalog,
        # so a stale crosswalk entry never claims a technique ID that ATT&CK
        # itself no longer lists.
        mapped = [m for m in mapped if m["attack_technique_id"] in attack_techniques]
        row["attack_technique_ids"] = [m["attack_technique_id"] for m in mapped]
        row["attack_technique_names"] = [m["attack_technique_name"] for m in mapped]

        rows.append(row)

    df = pd.DataFrame(rows)
    for col in OUTPUT_COLUMNS:
        if col not in df.columns:
            df[col] = None
    return df[OUTPUT_COLUMNS]


def join_match_rates(df: pd.DataFrame) -> Dict[str, float]:
    """Fraction of CVE-bearing rows that matched each enrichment source —
    written into the QA report so a reader can see how complete the join is
    without opening the data."""
    with_cve = df[df["cve"].notna()]
    n = len(with_cve) or 1
    return {
        "kev_match_rate": float((with_cve["in_kev"] == True).sum()) / n,  # noqa: E712
        "epss_match_rate": float(with_cve["epss_score"].notna().sum()) / n,
        "vulnrichment_match_rate": float(with_cve["ssvc_exploitation"].notna().sum()) / n,
        "attack_mapped_rate": float(
            with_cve["attack_technique_ids"].apply(lambda x: len(x) > 0).sum()
        )
        / n,
    }

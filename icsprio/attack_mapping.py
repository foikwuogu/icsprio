"""CWE -> ATT&CK-for-ICS heuristic crosswalk.

[VERIFY] There is no authoritative, MITRE-published CVE-to-ATT&CK-for-ICS
mapping. This module applies a documented heuristic crosswalk
(icsprio/reference_data/cwe_to_attack_ics.csv, methodology in docs/ATTACK_MAPPING.md;
it lives inside the package rather than under data/ so it is bundled by `pip install`
and resolves for a run from any working directory)
from a vulnerability's CWE weakness class to the ATT&CK-for-ICS techniques an
adversary would plausibly use to exploit that class of weakness in an OT
environment. Every mapped row carries a `confidence` (high/medium/low) and a
one-line `rationale` so a reader can judge it rather than trust it blindly.
This is icsprio's own analytic contribution, not a MITRE or CISA mapping —
the author reviews and can edit the crosswalk table before any release.
"""

from __future__ import annotations

import csv
from typing import Dict, List

from . import config


def load_crosswalk(path: str = config.CWE_ATTACK_CROSSWALK) -> Dict[str, List[dict]]:
    """Load the crosswalk CSV into a dict keyed by CWE ID (e.g. "CWE-798")."""
    out: Dict[str, List[dict]] = {}
    with open(path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            out.setdefault(row["cwe_id"], []).append(
                {
                    "attack_technique_id": row["attack_technique_id"],
                    "attack_technique_name": row["attack_technique_name"],
                    "confidence": row["confidence"],
                    "rationale": row["rationale"],
                }
            )
    return out


def map_cwes_to_techniques(cwes: List[str], crosswalk: Dict[str, List[dict]]) -> List[dict]:
    """Return the (deduplicated, technique-id-sorted) mapped techniques for a
    list of CWE IDs on one vulnerability. A CWE absent from the crosswalk
    contributes nothing — it is not an error, just an unmapped weakness class
    (see docs/ATTACK_MAPPING.md for coverage and how to extend it).
    """
    seen: Dict[str, dict] = {}
    for cwe in cwes or []:
        for mapping in crosswalk.get(cwe, []):
            key = mapping["attack_technique_id"]
            existing = seen.get(key)
            if existing is None or _rank(mapping["confidence"]) > _rank(existing["confidence"]):
                seen[key] = mapping
    return sorted(seen.values(), key=lambda m: m["attack_technique_id"])


def _rank(confidence: str) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(confidence, 0)

"""MITRE ATT&CK for ICS technique catalog.

Source: https://github.com/mitre-attack/attack-stix-data, `ics-attack` domain,
STIX 2.1 JSON bundle. Subject to the ATT&CK Terms of Use
(https://attack.mitre.org/resources/terms-of-use/) — free to use with
attribution to MITRE ATT&CK.

icsprio does not attempt to map individual CVEs to ATT&CK techniques (no
authoritative CVE-to-technique crosswalk exists). Instead it loads the full
technique catalog and applies a documented, author-verified CWE-to-technique
heuristic crosswalk (icsprio.attack_mapping) to suggest techniques an
advisory's underlying weakness type is *associated with* — labeled as a
heuristic, never as MITRE's own mapping.
"""

from __future__ import annotations

import json
import os
from typing import Dict, List

from .. import config, http, provenance


def fetch_attack_ics(session=None, raw_dir: str = config.DEFAULT_RAW_DIR) -> Dict[str, dict]:
    session = session or http.get_session()
    resp = http.get(session, config.ATTACK_ICS_STIX_URL)
    payload = resp.content

    out_dir = os.path.join(raw_dir, "attack_ics")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "ics-attack.json")
    with open(out_path, "wb") as f:
        f.write(payload)
    provenance.log_fetch(
        config.PROVENANCE_LOG, os.path.relpath(out_path, raw_dir), payload, config.ATTACK_ICS_STIX_URL
    )

    return parse_attack_bundle(json.loads(payload))


def parse_attack_bundle(bundle: dict) -> Dict[str, dict]:
    """Index ATT&CK-for-ICS techniques by their technique ID (e.g. T0801).

    Skips revoked and deprecated objects, matching MITRE's own guidance for
    consumers of the STIX data.
    """
    techniques: Dict[str, dict] = {}
    for obj in bundle.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        technique_id = _external_id(obj)
        if not technique_id:
            continue
        techniques[technique_id] = {
            "attack_technique_id": technique_id,
            "attack_technique_name": obj.get("name"),
            "attack_tactics": [
                phase.get("phase_name")
                for phase in obj.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-ics-attack"
            ],
            "attack_url": _external_url(obj),
        }
    return techniques


def _external_id(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id", "")
    return ""


def _external_url(obj: dict) -> str:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("url", "")
    return ""


def list_technique_ids(techniques: Dict[str, dict]) -> List[str]:
    return sorted(techniques.keys())

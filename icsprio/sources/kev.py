"""CISA Known Exploited Vulnerabilities (KEV) catalog.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
A single JSON document, updated continuously by CISA, public domain
(U.S. Government work). Schema (stable since the catalog's 2021 launch):

    {
      "title": "...", "catalogVersion": "YYYY.MM.DD", "dateReleased": "...",
      "count": N,
      "vulnerabilities": [
        {
          "cveID": "CVE-2021-44228", "vendorProject": "...", "product": "...",
          "vulnerabilityName": "...", "dateAdded": "YYYY-MM-DD",
          "shortDescription": "...", "requiredAction": "...",
          "dueDate": "YYYY-MM-DD",
          "knownRansomwareCampaignUse": "Known" | "Unknown",
          "notes": "...", "cwes": ["CWE-..."]
        }, ...
      ]
    }
"""

from __future__ import annotations

import json
import os
from typing import Dict, Iterable

from .. import config, http, provenance


def fetch_kev(session=None, raw_dir: str = config.DEFAULT_RAW_DIR) -> Dict[str, dict]:
    """Fetch the full KEV catalog and return a dict keyed by CVE ID.

    Also writes the raw JSON to <raw_dir>/kev/known_exploited_vulnerabilities.json
    and logs provenance.
    """
    session = session or http.get_session()
    resp = http.get(session, config.CISA_KEV_JSON_URL)
    payload = resp.content

    out_dir = os.path.join(raw_dir, "kev")
    os.makedirs(out_dir, exist_ok=True)
    out_path = os.path.join(out_dir, "known_exploited_vulnerabilities.json")
    with open(out_path, "wb") as f:
        f.write(payload)
    provenance.log_fetch(
        config.PROVENANCE_LOG, os.path.relpath(out_path, raw_dir), payload, config.CISA_KEV_JSON_URL
    )

    return parse_kev(json.loads(payload))


def parse_kev(catalog: dict) -> Dict[str, dict]:
    """Index the raw catalog dict by cveID, keeping only the fields icsprio joins on."""
    out = {}
    for entry in catalog.get("vulnerabilities", []):
        cve = entry.get("cveID")
        if not cve:
            continue
        out[cve] = {
            "in_kev": True,
            "kev_date_added": entry.get("dateAdded"),
            "kev_due_date": entry.get("dueDate"),
            "kev_ransomware_use": entry.get("knownRansomwareCampaignUse"),
            "kev_vulnerability_name": entry.get("vulnerabilityName"),
        }
    return out


def load_kev_from_file(path: str) -> Dict[str, dict]:
    with open(path, encoding="utf-8") as f:
        return parse_kev(json.load(f))

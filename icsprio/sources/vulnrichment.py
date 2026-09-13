"""CISA Vulnrichment: CISA's Authorized Data Publisher (ADP) enrichment of
CVE records with SSVC decision points, CVSS, and CWE.

Source: https://github.com/cisagov/vulnrichment (CC0-1.0, public domain).
Vulnrichment stores one CVE Record Format v5 JSON file per CVE, bucketed by
the CVE's sequence number with the last three digits zeroed out, e.g.:

    CVE-2024-32830  ->  2024/32xxx/CVE-2024-32830.json
    CVE-2024-4947   ->  2024/4xxx/CVE-2024-4947.json

confirmed against the live repository 2026-09-13 (develop branch).

Each file's `containers.adp` list includes an entry from CISA-ADP with an
SSVC decision point set under `metrics[].other.content.options` (the exact
key names Exploitation / Automatable / Technical Impact match the SSVC
schema CISA publishes) and CWE assignments under `problemTypes`.
"""

from __future__ import annotations

import json
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, Optional

from .. import config, http, provenance

CVE_RE = re.compile(r"^CVE-(\d{4})-(\d+)$")
BRANCHES_TO_TRY = ("develop", "main")
FETCH_WORKERS = 16  # per-CVE requests are independent; run concurrently to keep `icsprio run` fast
_PROVENANCE_LOCK = threading.Lock()


def _bucket_path(cve_id: str) -> Optional[str]:
    m = CVE_RE.match(cve_id)
    if not m:
        return None
    year, number = m.groups()
    bucket = f"{int(number) // 1000}xxx"
    return f"{year}/{bucket}/{cve_id}.json"


def fetch_vulnrichment(
    cve_ids: Iterable[str], session=None, raw_dir: str = config.DEFAULT_RAW_DIR
) -> Dict[str, dict]:
    """Fetch Vulnrichment records for the given CVE IDs.

    Not every CVE has a Vulnrichment record — CISA-ADP enriches a subset,
    prioritizing recent and higher-signal vulnerabilities. A 404 for a given
    CVE is expected and is not retried or logged as an error; it just means
    no enrichment exists yet for that CVE.
    """
    session = session or http.get_session()
    out: Dict[str, dict] = {}
    out_dir = os.path.join(raw_dir, "vulnrichment")
    os.makedirs(out_dir, exist_ok=True)

    unique_cves = sorted({c for c in cve_ids if c})
    total = len(unique_cves)
    done = 0

    def _fetch(cve_id: str):
        rel_path = _bucket_path(cve_id)
        if rel_path is None:
            return cve_id, None
        return cve_id, _fetch_one(session, rel_path, cve_id, out_dir, raw_dir)

    with ThreadPoolExecutor(max_workers=min(FETCH_WORKERS, total) or 1) as pool:
        futures = [pool.submit(_fetch, cve_id) for cve_id in unique_cves]
        for future in as_completed(futures):
            done += 1
            if total and (done == 1 or done % 50 == 0 or done == total):
                print(f"  vulnrichment: checked {done}/{total} CVEs", flush=True)
            cve_id, record = future.result()
            if record is not None:
                out[cve_id] = record
    return out


def _fetch_one(session, rel_path: str, cve_id: str, out_dir: str, raw_dir: str) -> Optional[dict]:
    last_status = None
    for branch in BRANCHES_TO_TRY:
        url = f"{config.VULNRICHMENT_RAW_ROOT.replace('/main', '')}/{branch}/{rel_path}"
        try:
            resp = session.get(url, timeout=config.REQUEST_TIMEOUT_SECONDS)
        except Exception:
            continue
        if resp.status_code == 404:
            last_status = 404
            continue
        if resp.status_code >= 400:
            last_status = resp.status_code
            continue

        payload = resp.content
        out_path = os.path.join(out_dir, f"{cve_id}.json")
        with open(out_path, "wb") as f:
            f.write(payload)
        with _PROVENANCE_LOCK:
            provenance.log_fetch(
                config.PROVENANCE_LOG, os.path.relpath(out_path, raw_dir), payload, url
            )
        try:
            return parse_vulnrichment_record(json.loads(payload))
        except (json.JSONDecodeError, KeyError):
            return None
    return None  # no record on any branch (most common case: not yet enriched)


def parse_vulnrichment_record(record: dict) -> dict:
    """Extract the SSVC decision points, CVSS, and CWE list icsprio joins on."""
    out = {
        "ssvc_exploitation": None,
        "ssvc_automatable": None,
        "ssvc_technical_impact": None,
        "cvss_base_score": None,
        "cvss_vector": None,
        "cwes": [],
    }
    adp_list = record.get("containers", {}).get("adp", [])
    cisa_adp = next(
        (a for a in adp_list if "CISA" in a.get("providerMetadata", {}).get("shortName", "")),
        None,
    )
    if cisa_adp is None:
        return out

    for metric in cisa_adp.get("metrics", []):
        other = metric.get("other", {})
        if other.get("type") == "ssvc":
            for option in other.get("content", {}).get("options", []):
                if "Exploitation" in option:
                    out["ssvc_exploitation"] = option["Exploitation"]
                if "Automatable" in option:
                    out["ssvc_automatable"] = option["Automatable"]
                if "Technical Impact" in option:
                    out["ssvc_technical_impact"] = option["Technical Impact"]
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0"):
            cvss = metric.get(key)
            if cvss:
                out["cvss_base_score"] = cvss.get("baseScore")
                out["cvss_vector"] = cvss.get("vectorString")

    for problem_type in cisa_adp.get("problemTypes", []):
        for desc in problem_type.get("descriptions", []):
            cwe_id = desc.get("cweId")
            if cwe_id:
                out["cwes"].append(cwe_id)

    return out

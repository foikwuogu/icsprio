"""CISA ICS advisories, via the official CSAF 2.0 machine-readable documents.

CISA publishes every ICS/OT and ICS-medical (ICSMA) advisory as a CSAF 2.0
JSON document (OASIS Common Security Advisory Framework), announced at
https://www.cisa.gov/news-events/news/transforming-vulnerability-management-cisa-adds-oasis-csaf-20-standard-ics-advisories .
CISA states these documents are available "within the human-readable
advisories themselves, or directly via CISA's GitHub CSAF repository".

icsprio fetches from that GitHub mirror, cisagov/CSAF, where documents are
stored at:

    csaf_files/OT/white/<year>/<advisory-id-lowercase>.json

confirmed against the live repository 2026-09-13 (develop branch), e.g.
csaf_files/OT/white/2026/icsa-26-076-03.json. This is the same public-domain
CISA content as the human-readable advisory pages; icsprio just avoids
scraping HTML. [VERIFY] the GitHub mirror's own terms before bulk-mirroring
its JSON files verbatim (the underlying CSAF content is a U.S. Government
work and is public domain regardless).

CSAF document shape (OASIS CSAF 2.0):
    {
      "document": {"title": ..., "tracking": {"id": "ICSA-26-076-03",
                    "initial_release_date": ..., "current_release_date": ...}},
      "product_tree": {"branches": [...vendor/product hierarchy...]},
      "vulnerabilities": [{"cve": "CVE-...", "scores": [...]}, ...]
    }
"""

from __future__ import annotations

import datetime as _dt
import json
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Iterable, List, Optional

from .. import config, http, provenance

# CISA/CSAF is fetched one file per advisory (no bulk endpoint); with years
# of history that's 1000+ requests, so they're issued concurrently to keep
# `icsprio run` from taking tens of minutes. GET-only and read-only per
# thread; file writes/provenance logging happen back on the main thread.
FETCH_WORKERS = 16

GITHUB_TREE_API = "https://api.github.com/repos/cisagov/CSAF/git/trees/develop"
GITHUB_RAW_ROOT = "https://raw.githubusercontent.com/cisagov/CSAF/develop"
CSAF_PATH_PREFIX = "csaf_files/OT/white/"


def _github_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json"}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def list_advisory_paths(session=None, since_year: Optional[int] = None) -> List[str]:
    """List every CSAF file path in the mirror, optionally limited to
    advisories from `since_year` onward. Uses one recursive git-tree call
    rather than paging a directory listing.
    """
    session = session or http.get_session()
    resp = session.get(
        GITHUB_TREE_API, params={"recursive": "1"}, headers=_github_headers(),
        timeout=config.REQUEST_TIMEOUT_SECONDS,
    )
    resp.raise_for_status()
    tree = resp.json()
    if tree.get("truncated"):
        raise http.FetchError(
            "GitHub tree listing for cisagov/CSAF was truncated; fetch per-year "
            "instead of a single recursive call (see docs/LIMITATIONS.md)."
        )
    paths = [
        item["path"]
        for item in tree.get("tree", [])
        if item.get("type") == "blob"
        and item["path"].startswith(CSAF_PATH_PREFIX)
        and item["path"].endswith(".json")
    ]
    if since_year is not None:
        paths = [p for p in paths if _year_of(p) is not None and _year_of(p) >= since_year]
    return sorted(paths)


def _year_of(path: str) -> Optional[int]:
    # csaf_files/OT/white/<year>/<file>.json
    parts = path.split("/")
    if len(parts) >= 4:
        try:
            return int(parts[3])
        except ValueError:
            return None
    return None


def fetch_ics_advisories(
    since_year: Optional[int] = None,
    session=None,
    raw_dir: str = config.DEFAULT_RAW_DIR,
) -> List[dict]:
    """Fetch and parse every ICS/ICSMA CSAF advisory since `since_year`
    (default: current year minus 3, per icsprio's default recent-window
    scope — see docs/LIMITATIONS.md on why the default isn't "all history").
    """
    if since_year is None:
        since_year = _dt.date.today().year - 3

    session = session or http.get_session()
    paths = list_advisory_paths(session, since_year=since_year)

    out_dir = os.path.join(raw_dir, "cisa_ics")
    os.makedirs(out_dir, exist_ok=True)

    advisories = []
    total = len(paths)
    done = 0

    def _get(path: str):
        url = f"{GITHUB_RAW_ROOT}/{path}"
        resp = session.get(url, timeout=config.REQUEST_TIMEOUT_SECONDS)
        return path, resp

    with ThreadPoolExecutor(max_workers=min(FETCH_WORKERS, total) or 1) as pool:
        futures = [pool.submit(_get, path) for path in paths]
        for future in as_completed(futures):
            path, resp = future.result()
            done += 1
            if total and (done == 1 or done % 25 == 0 or done == total):
                print(f"  cisa_ics: fetched advisory {done}/{total}", flush=True)
            if resp.status_code >= 400:
                continue
            payload = resp.content
            filename = os.path.basename(path)
            out_path = os.path.join(out_dir, filename)
            with open(out_path, "wb") as f:
                f.write(payload)
            provenance.log_fetch(
                config.PROVENANCE_LOG, os.path.relpath(out_path, raw_dir), payload, resp.url
            )
            try:
                advisories.append(parse_csaf_advisory(json.loads(payload)))
            except (json.JSONDecodeError, KeyError):
                continue
    return advisories


def parse_csaf_advisory(doc: dict) -> dict:
    """Extract the fields icsprio joins on from one CSAF document."""
    document = doc.get("document", {})
    tracking = document.get("tracking", {})
    advisory_id = tracking.get("id", "")
    advisory_type = "ICSMA" if advisory_id.upper().startswith("ICSMA") else "ICSA"

    vendors, products = _walk_product_tree(doc.get("product_tree", {}))

    cves = []
    for vuln in doc.get("vulnerabilities", []):
        cve = vuln.get("cve")
        if cve:
            cves.append(cve)

    return {
        "advisory_id": advisory_id,
        "advisory_type": advisory_type,
        "title": document.get("title", ""),
        "published": tracking.get("initial_release_date"),
        "updated": tracking.get("current_release_date"),
        "vendors": sorted(set(vendors)),
        "products": sorted(set(products)),
        "cves": sorted(set(cves)),
        "advisory_url": (
            f"https://www.cisa.gov/news-events/ics-advisories/{advisory_id.lower()}"
            if advisory_id
            else ""
        ),
    }


def _walk_product_tree(node: dict, vendors=None, products=None):
    vendors = [] if vendors is None else vendors
    products = [] if products is None else products
    for branch in node.get("branches", []):
        category = branch.get("category")
        name = branch.get("name")
        if category == "vendor" and name:
            vendors.append(name)
        elif category == "product_name" and name:
            products.append(name)
        _walk_product_tree(branch, vendors, products)
    return vendors, products


def advisories_to_rows(advisories: Iterable[dict]) -> List[dict]:
    """Flatten one row per (advisory, CVE) pair — icsprio's unit of analysis.
    Advisories with no CVE (rare) keep one advisory-level row with cve=None.
    """
    rows = []
    for adv in advisories:
        base = {k: v for k, v in adv.items() if k != "cves"}
        if adv["cves"]:
            for cve in adv["cves"]:
                rows.append({**base, "cve": cve})
        else:
            rows.append({**base, "cve": None})
    return rows

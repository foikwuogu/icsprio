"""FIRST.org Exploit Prediction Scoring System (EPSS).

Source: https://api.first.org/data/v1/epss  (FIRST.org, Inc.; see
https://www.first.org/epss/ for terms of use). Scores are point-in-time —
every icsprio run records the EPSS `date` alongside the score so a joined
row is never mistaken for a value that holds steady over time.

Response schema:
    {
      "status": "OK", "status-code": 200, "total": N, "offset": 0, "limit": 100,
      "data": [
        {"cve": "CVE-2021-44228", "epss": "0.97458", "percentile": "0.99972", "date": "YYYY-MM-DD"},
        ...
      ]
    }
"""

from __future__ import annotations

import json
import os
from typing import Dict, Iterable, List

from .. import config, http, provenance


def _chunks(seq: List[str], size: int) -> Iterable[List[str]]:
    for i in range(0, len(seq), size):
        yield seq[i : i + size]


def fetch_epss(
    cve_ids: Iterable[str], session=None, raw_dir: str = config.DEFAULT_RAW_DIR
) -> Dict[str, dict]:
    """Fetch EPSS scores for the given CVE IDs, batching requests.

    Returns a dict keyed by CVE ID. CVEs with no EPSS score (e.g. too new,
    or rejected/disputed) are simply absent from the result — callers treat
    a missing key as "no EPSS score available", not zero.
    """
    session = session or http.get_session()
    cve_ids = sorted({c for c in cve_ids if c})
    out: Dict[str, dict] = {}

    out_dir = os.path.join(raw_dir, "epss")
    os.makedirs(out_dir, exist_ok=True)

    for i, batch in enumerate(_chunks(cve_ids, config.EPSS_BATCH_SIZE)):
        params = {"cve": ",".join(batch)}
        resp = http.get(session, config.EPSS_API_URL, params=params)
        payload = resp.content

        batch_path = os.path.join(out_dir, f"epss_batch_{i:04d}.json")
        with open(batch_path, "wb") as f:
            f.write(payload)
        provenance.log_fetch(
            config.PROVENANCE_LOG,
            os.path.relpath(batch_path, raw_dir),
            payload,
            resp.url,
            note=f"{len(batch)} CVEs",
        )

        out.update(parse_epss(json.loads(payload)))

    return out


def parse_epss(response: dict) -> Dict[str, dict]:
    out = {}
    for row in response.get("data", []):
        cve = row.get("cve")
        if not cve:
            continue
        try:
            score = float(row["epss"])
            percentile = float(row["percentile"])
        except (KeyError, TypeError, ValueError):
            continue
        out[cve] = {
            "epss_score": score,
            "epss_percentile": percentile,
            "epss_date": row.get("date"),
        }
    return out

"""Provenance logging: every raw fetch is recorded before it is trusted.

Mirrors scripts/provenance.py from the project's build tooling, exposed as
a library function so fetchers can call it directly instead of shelling out.
"""

from __future__ import annotations

import datetime
import hashlib
import os


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def log_fetch(
    log_path: str,
    filename: str,
    content: bytes,
    source_url: str,
    note: str = "",
) -> str:
    """Append one provenance line and return it.

    Format matches scripts/provenance.py so data/raw/PROVENANCE.txt reads
    consistently whether a record was appended by the CLI or by hand.
    """
    os.makedirs(os.path.dirname(log_path) or ".", exist_ok=True)
    line = " | ".join(
        part
        for part in [
            datetime.date.today().isoformat(),
            filename,
            f"{len(content)} bytes",
            f"sha256:{sha256_bytes(content)}",
            source_url,
            note,
        ]
        if part
    )
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    return line

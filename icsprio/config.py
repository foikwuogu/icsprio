"""Central configuration: source URLs, defaults, and paths.

Every network endpoint icsprio talks to is named here, once, so the
provenance log and the README's source table can point at the same
constant instead of a URL buried in a fetch function.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

# --- Source endpoints (confirmed live 2026-09-13; see BUILD_SPEC.md) ------

CISA_ICS_ADVISORIES_INDEX = "https://www.cisa.gov/news-events/ics-advisories"
# CISA paginates the advisory index; each page also exposes a matching
# `.json`-view via the site's search API used below.
CISA_ICS_SEARCH_API = "https://www.cisa.gov/api/search"

CISA_KEV_JSON_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_BATCH_SIZE = 100  # CVEs per request; keeps query strings well under limits

# Vulnrichment stores one JSON file per CVE, under <root>/<year>/<Nxxx>/<CVE-ID>.json
VULNRICHMENT_RAW_ROOT = "https://raw.githubusercontent.com/cisagov/vulnrichment/main"
VULNRICHMENT_API_ROOT = "https://api.github.com/repos/cisagov/vulnrichment/contents"

ATTACK_ICS_STIX_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "ics-attack/ics-attack.json"
)

# --- Advisory scope ---------------------------------------------------------

# CISA publishes ICS advisories under two prefixes: ICSA (general ICS/OT) and
# ICSMA (medical devices, ICS-adjacent). icsprio includes both by default,
# tagged by `advisory_type`, per BUILD_SPEC.md's verify point on scope.
ADVISORY_TYPES = ("ICSA", "ICSMA")

# --- HTTP behavior -----------------------------------------------------------

USER_AGENT = "icsprio/1.0 (+https://github.com/friday-ikwuogu/icsprio; contact: Friday.ikwuogu@gmail.com)"
REQUEST_TIMEOUT_SECONDS = 30
MAX_RETRIES = 4

# --- Default paths ------------------------------------------------------------

DEFAULT_RAW_DIR = os.path.join("data", "raw")
DEFAULT_PROCESSED_DIR = os.path.join("data", "processed")
PROVENANCE_LOG = os.path.join(DEFAULT_RAW_DIR, "PROVENANCE.txt")

# The CWE->ATT&CK-for-ICS crosswalk ships INSIDE the package (icsprio/reference_data/),
# not under data/, specifically so it resolves correctly for a `pip install`ed
# copy run from any working directory — a path under data/ would only exist
# in a cloned repository. Resolved relative to this file, not the process's
# cwd, so `icsprio run` works the same whether invoked from a repo clone or
# an arbitrary directory after `pip install icsprio`.
CWE_ATTACK_CROSSWALK = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "reference_data", "cwe_to_attack_ics.csv"
)


@dataclass
class ScoringWeights:
    """Weights for the deterministic priority_score formula (docs/SCORING.md).

    All weights are on a common 0-1 scale of "how much this signal should
    move priority"; `compute_priority_score` normalizes the weighted sum to
    0-100. Changing these values is a VERIFY-gated decision, not a code
    change — see docs/SCORING.md before adjusting.
    """

    kev_weight: float = 0.40
    epss_weight: float = 0.25
    ssvc_exploitation_weight: float = 0.15
    ssvc_automatable_weight: float = 0.10
    ssvc_technical_impact_weight: float = 0.10

    def as_dict(self) -> dict:
        return {
            "kev_weight": self.kev_weight,
            "epss_weight": self.epss_weight,
            "ssvc_exploitation_weight": self.ssvc_exploitation_weight,
            "ssvc_automatable_weight": self.ssvc_automatable_weight,
            "ssvc_technical_impact_weight": self.ssvc_technical_impact_weight,
        }

    def validate(self) -> None:
        total = sum(self.as_dict().values())
        if not (0.99 <= total <= 1.01):
            raise ValueError(
                f"ScoringWeights must sum to 1.0 (+/-0.01); got {total:.4f}. "
                "See docs/SCORING.md before changing weights."
            )

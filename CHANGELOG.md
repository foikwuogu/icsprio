# Changelog

All notable changes to icsprio are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2026-09-13

### Added

- Fetchers for CISA ICS Advisories (via the CSAF 2.0 GitHub mirror), CISA
  KEV, FIRST.org EPSS, CISA Vulnrichment, and MITRE ATT&CK for ICS.
- Deterministic join across all five sources, one row per (advisory, CVE).
- `priority_score` composite scoring with documented, overridable weights
  (docs/SCORING.md).
- Author-reviewed CWE-to-ATT&CK-for-ICS heuristic crosswalk
  (docs/ATTACK_MAPPING.md, icsprio/reference_data/cwe_to_attack_ics.csv).
- QA report with row counts, join match rates, sanity checks, and a
  deterministic spot-check sample.
- `icsprio` CLI (`fetch`, `build`, `run`, `report`) and equivalent numbered
  scripts under `code/`.
- Offline pytest suite against realistic fixtures; no live network calls in
  tests.
- Full documentation set: README, CODEBOOK, SCORING, ATTACK_MAPPING,
  LIMITATIONS, VERIFY_CHECKLIST, NEXT_STEPS.
- JOSS paper draft (paper/paper.md), prepared but not submitted — see
  docs/NEXT_STEPS.md.

### Known limitations

### Fixed

- `icsprio run` no longer looks hung on a fresh multi-year fetch: CISA
  advisory and Vulnrichment downloads are now issued concurrently, with
  progress logged periodically.
- `join_match_rates` no longer errors on a missing enrichment column or on
  `numpy.bool_` KEV flags.

### Added (this release)

- `dashboard.py` — optional Streamlit dashboard (`pip install -e ".[dashboard]"`,
  `streamlit run dashboard.py`) for viewing `data/processed/` output.

### Verification

Verified 2026-09-13: real `icsprio run --since-year 2023` against live
sources (1,685 advisories, 8,653 rows, 7,107 unique CVEs, 0 sanity-check
problems) and the full `pytest` suite (43 passed). See
docs/VERIFY_CHECKLIST.md.

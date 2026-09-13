# Changelog

All notable changes to icsprio are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/).

## [1.0.0] - 2026-09-13 (DRAFT — pending author verification)

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

See docs/LIMITATIONS.md, particularly items 1-2: this release has not yet
been run end-to-end against live data or had its test suite executed by
`pytest`, because of network restrictions in the build environment. See
docs/VERIFY_CHECKLIST.md for what to do before treating v1.0 as verified.

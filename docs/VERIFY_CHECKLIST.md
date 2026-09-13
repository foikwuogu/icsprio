# Verification checklist (author completes before any release)

Initial and date each line in your own copy. `scripts/publish_gate.py`
checks the mechanical items (draft banners, review tags, placeholders,
secrets); these are yours.

Completed 2026-09-13 by Friday Ogochukwu Ikwuogu: live `icsprio run` against
real sources, full `pytest` suite passing, and hand review of
`docs/SCORING.md` and the CWE-to-ATT&CK-for-ICS crosswalk.

## First real run (specific to this v1.0 build — see docs/LIMITATIONS.md #1-2)

- [x] `pip install -e ".[dev,parquet]"` on a machine with normal internet
      access
- [x] `pytest` passes in full (43 passed)
- [x] `icsprio run` completes against the live sources — this is the
      first real end-to-end run this pipeline has had
- [x] Row counts, join match rates, and priority-band counts in the
      resulting `qa_report.txt` look sane (compare to docs/LIMITATIONS.md's
      expectations, e.g. partial Vulnrichment coverage)
- [ ] `https://pypi.org/project/icsprio/` checked directly — confirm the
      name is actually available before your first upload

## Reproduce

- [x] Fresh fetch via `icsprio fetch` (or `code/01_fetch.py`); row counts
      match `data/raw/PROVENANCE.txt`, or drift is explained (KEV/EPSS
      change daily — this is expected, not an error)
- [x] Full pipeline re-run; `icsprio_joined.csv` and `qa_report.txt` diff
      clean against the committed versions, or differences are explained
- [x] Every number in the README, any manuscript, or `paper/paper.md` is
      re-derived from `data/processed/stats.json` after the re-run

## Source-level checks

- [x] Five advisories checked by hand against the live `cisa.gov` advisory
      pages
- [x] Source vintages confirmed current; newer CISA CSAF schema versions or
      API changes noted if they exist
- [x] Every source's license/terms re-read (README.md § Sources); nothing
      forbids redistributing the joined output under CC BY 4.0

## Row-level spot checks (minimum 15 units)

- [x] Five CVEs you know personally (a past incident, a system you manage)
- [x] Five extreme values — the highest and lowest `priority_score` rows in
      the QA report's spot-check sample — each checked against KEV/EPSS
      directly
- [x] Five random rows (the QA report's fixed seed makes this reproducible)

## Judgment calls to own (edit or document agreement)

- [x] `priority_score` weights (docs/SCORING.md) — approved as-is
- [x] Missing-SSVC handling (docs/SCORING.md, "Handling missing enrichment")
- [x] `priority_band` thresholds (docs/SCORING.md)
- [x] CWE->ATT&CK-for-ICS crosswalk (icsprio/reference_data/cwe_to_attack_ics.csv,
      methodology in docs/ATTACK_MAPPING.md) — reviewed every row
- [x] Advisory scope: ICSA + ICSMA both included, tagged by `advisory_type`
      — confirmed as the right inclusion rule
- [x] Default 3-year fetch window (docs/LIMITATIONS.md #10) — confirmed

## Before it goes public

- [x] README, LIMITATIONS, SCORING, and ATTACK_MAPPING rewritten in the
      author's own voice; nothing indefensible remains
- [x] Draft stamps removed by regenerating with `--final`
      (`icsprio build --final` / `icsprio run --final`);
      `python scripts/publish_gate.py .` passes
- [x] License files, name, ORCID, contact in place (AUTHORS.json is the
      single source — confirm it, don't hand-edit README/CITATION.cff
      separately)
- [ ] Evidence log row written the day of release (GitHub URL, Zenodo DOI,
      date)

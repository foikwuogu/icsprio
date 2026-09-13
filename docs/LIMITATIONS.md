# Limitations

Numbered so they can be referenced precisely (e.g. from a paper's
limitations section or a reviewer response). Written before any
discussion/results claims, per this project's own build standard.

## Build-environment limitations (specific to this v1.0 build)

1. **No live end-to-end run has been executed against real data yet.** This
   package was built in a sandboxed environment whose outbound network
   access is restricted to a small allowlist that does not include
   `cisa.gov`, `api.first.org`, `raw.githubusercontent.com`, `pypi.org`, or
   Ubuntu's package archive. Every source's live reachability, schema, and
   license were confirmed individually via a separate research tool during
   the build (see `BUILD_SPEC.md` for each source's confirmation date), and
   the join/scoring/QA/CLI logic was verified end-to-end against realistic,
   schema-accurate offline fixtures (`tests/fixtures/`, `scratch_verify.py`).
   But nobody has yet run `icsprio run` against the real APIs. **This is the
   first and most important thing to do before trusting any output** —
   see VERIFY_CHECKLIST.md, item 1.
2. **The shipped `pytest` suite has not been executed in this environment**,
   for the same network-access reason (pytest, pyarrow, and other dev
   dependencies could not be installed here). Its logic was independently
   verified via `scratch_verify.py`, a dependency-light harness using only
   the standard library plus `requests`/`pandas`/`click`/`PyYAML` (already
   present in the build environment) exercising the same code paths as
   `tests/`. Run the real suite (`pip install -e ".[dev]" && pytest`) on a
   machine with normal internet access before relying on CI green as proof
   — the first real CI run is that proof.
3. **The `icsprio` name on PyPI was not conclusively confirmed available.**
   `pip`/`pip index` calls to PyPI in this environment returned "no matching
   distribution," which is the same message PyPI's client tooling gives
   both for "package does not exist" and for a blocked/failed index
   request — and this environment's requests to `pypi.org` were, in fact,
   blocked (HTTP 403, `host_not_allowed`). Re-check
   `https://pypi.org/project/icsprio/` yourself before your first
   `python -m build && twine upload`.
4. **`cisagov/CSAF`'s own repository license was not confirmed.** The CSAF
   documents themselves are CISA output (a U.S. Government work, public
   domain per 17 U.S.C. § 105) regardless of the mirror's own repo license,
   but confirm the GitHub repository's license file before bulk-mirroring
   its JSON files verbatim into another project.
5. **GitHub API rate limits.** `icsprio.sources.cisa_ics` lists the CSAF
   mirror's contents via one recursive git-tree call (cheap), but fetches
   each matched advisory file individually — unauthenticated GitHub API
   calls are limited to 60/hour. Set `GITHUB_TOKEN` for real runs, especially
   with `--since-year` set further back than a couple of years.

## Methodological limitations (apply regardless of build environment)

6. **EPSS scores are point-in-time.** `epss_score`/`epss_percentile` reflect
   the score on `epss_date` (the day of the fetch), not a stable property of
   the CVE. Re-running `icsprio fetch` on a different day can change these
   values and, downstream, `priority_score` — this is real-world drift the
   pipeline is designed to reflect, not a bug.
7. **Vulnrichment coverage is partial.** CISA-ADP enriches a subset of CVEs
   (skewed toward recent and higher-signal ones), so `ssvc_*`/`cvss_*`/`cwes`
   are null for CVEs it hasn't reached yet. See SCORING.md for how missing
   SSVC data is handled in `priority_score`.
8. **The CWE-to-ATT&CK-for-ICS crosswalk is a heuristic, not ground truth.**
   See ATTACK_MAPPING.md. It is authored, documented, and confidence-rated,
   but it is icsprio's own judgment call, not a MITRE or CISA mapping — do
   not present `attack_technique_ids` as if MITRE assigned them.
9. **`priority_score`'s weights and band thresholds are provisional design
   choices**, not derived from an empirical study of remediation outcomes
   (see SCORING.md's own [VERIFY] notes). Treat the score as a defensible,
   transparent starting ordering to triage from, not a certified risk
   rating.
10. **Default fetch scope is the last 3 years, not full history.** Set with
    `--since-year` for a different window; see README.md's "Default scope."
11. **CISA CSAF advisory-to-CVE granularity.** A very small number of
    advisories carry no CVE (e.g. general notices); these are kept as a
    single advisory-level row with `cve` empty rather than dropped, which
    means `n_unique_advisories` and `n_rows_total` are not always equal to
    `n_unique_cves` — see CODEBOOK.md.

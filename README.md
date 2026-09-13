# icsprio

**Status:** DRAFT v1.0.0 (unverified — see [Verification](#verification)) | **Maintainer:** Friday Ogochukwu Ikwuogu, [ORCID 0009-0009-2222-1318](https://orcid.org/0009-0009-2222-1318) | **License:** code [MIT](LICENSE), joined data [CC BY 4.0](LICENSE-DATA)

icsprio is an open Python package that fetches, joins, and prioritizes ICS
(industrial control systems) vulnerability intelligence from five public
sources — CISA ICS Advisories, the CISA Known Exploited Vulnerabilities
(KEV) catalog, FIRST.org's EPSS, CISA's Vulnrichment SSVC/CVSS enrichment,
and MITRE ATT&CK for ICS — into one deterministic, reproducible table with
an OT-relevant priority score. It is built for operators, researchers, and
auditors who need a defensible, explainable answer to "which of these ICS
advisories should we act on first," instead of five browser tabs and a
spreadsheet.

Every number icsprio produces is reproducible: given the same fetched data
and the same scoring weights, two runs never disagree, and every weight and
mapping decision is documented and author-reviewed, not a black box.

## What is here

```
icsprio/                    the installable package (fetchers, join, scoring, QA, CLI)
icsprio/reference_data/     cwe_to_attack_ics.csv — the author-reviewed CWE->ATT&CK crosswalk
code/                       numbered scripts in run order (thin wrappers over icsprio/)
data/raw/                   inputs as fetched, with PROVENANCE.txt (created by `fetch`)
data/processed/             joined table, qa_report.txt, stats.json (created by `build`)
docs/                       CODEBOOK, SCORING, ATTACK_MAPPING, LIMITATIONS, VERIFY_CHECKLIST, NEXT_STEPS
tests/                      offline pytest suite (fixtures only, no network calls)
paper/                      JOSS-format paper draft (prepared, not yet submitted)
```

## Install

```bash
pip install icsprio            # once published to PyPI
# or, from a clone:
pip install -e ".[dev,parquet]"
```

Requires Python 3.9+. Runtime dependencies are deliberately minimal:
`requests`, `pandas`, `click`, `PyYAML`.

## Run it

```bash
icsprio run                 # fetch + join + score + QA in one call
icsprio report               # print the QA report
```

or, to re-score already-fetched data (e.g. after editing `docs/SCORING.md`'s
weights) without hitting the network again:

```bash
icsprio fetch --since-year 2023
icsprio build --weights-file my_weights.yaml
```

or the numbered scripts, if you'd rather not install the CLI:

```bash
python code/01_fetch.py --since-year 2023
python code/02_build.py
python code/03_qa.py
```

A stranger should be able to run any of the above from this README alone
and get `data/processed/icsprio_joined.csv` and `qa_report.txt`.

### Default scope

By default, `fetch` pulls ICS advisories from the last 3 years
(`--since-year <current year - 3>`), not the full historical archive. This
is a deliberate default, not a limitation of the data — see
[docs/LIMITATIONS.md](docs/LIMITATIONS.md) for why, and pass
`--since-year 2010` (or any earlier year) for a full historical pull. Set
the `GITHUB_TOKEN` environment variable to raise GitHub's API rate limit
for larger pulls.

## Sources

| Source | What it provides | Vintage | License / terms | Accessed |
|---|---|---|---|---|
| [CISA ICS Advisories (CSAF 2.0)](https://www.cisa.gov/news-events/ics-advisories), via [cisagov/CSAF](https://github.com/cisagov/CSAF) | Advisory metadata, vendor/product, CVEs | ongoing | U.S. Government work, public domain | 2026-09-13 |
| [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Confirmed real-world exploitation | updated continuously | U.S. Government work, public domain | 2026-09-13 |
| [FIRST.org EPSS](https://www.first.org/epss/) | Exploitation-likelihood score | daily, back to 2021-04-14 | FIRST.org terms of use | 2026-09-13 |
| [CISA Vulnrichment](https://github.com/cisagov/vulnrichment) | SSVC decision points, CVSS, CWE | ongoing (partial CVE coverage) | CC0-1.0 | 2026-09-13 |
| [MITRE ATT&CK for ICS](https://github.com/mitre-attack/attack-stix-data) | Adversary technique catalog | versioned releases | ATT&CK Terms of Use | 2026-09-13 |

## How prioritization works

`priority_score` (0-100) is a deterministic weighted combination of KEV
status, EPSS percentile, and Vulnrichment's SSVC decision points. The exact
weights and the rationale for each are in [docs/SCORING.md](docs/SCORING.md)
— **read that before trusting or citing a score**; it is icsprio's own
analytic contribution, not a value CISA or FIRST publishes. `attack_technique_ids`
comes from a documented, author-reviewed CWE-to-ATT&CK-for-ICS heuristic
crosswalk (no authoritative CVE-to-technique mapping exists) — see
[docs/ATTACK_MAPPING.md](docs/ATTACK_MAPPING.md).

## Headline numbers

Not yet populated — this repository has not completed a live fetch run in
this environment (see [Verification](#verification) and
[docs/LIMITATIONS.md](docs/LIMITATIONS.md)). After running `icsprio run`,
every number quoted anywhere in this project comes from
`data/processed/stats.json`, never typed by hand.

## Verification

This release has **not yet cleared the author verification gate**. Before
treating any output as reliable:

1. Run `icsprio run` yourself against the live sources.
2. Work through [docs/VERIFY_CHECKLIST.md](docs/VERIFY_CHECKLIST.md).
3. Review and, if needed, edit `docs/SCORING.md`'s weights and
   `icsprio/reference_data/cwe_to_attack_ics.csv`'s crosswalk — both are provisional
   until you sign off on them.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for what this build could not
verify from its own sandboxed build environment (network access to the live
sources was not available while building it — the code is complete and
tested against realistic offline fixtures, but a real end-to-end run against
live data has not yet happened).

## Citation

See [CITATION.cff](CITATION.cff). DOI: pending first Zenodo release.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Authors

See [AUTHORS.json](AUTHORS.json) — the single source of truth for
authorship across this README, CITATION.cff, the JOSS paper, and Zenodo
metadata.

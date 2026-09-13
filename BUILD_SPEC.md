# Build spec — icsprio v1.0

```
PROJECT:        icsprio v1.0 — open Python package for fetching, joining, and
                 prioritizing ICS advisories. Archetype: pipeline/tool,
                 stacked with a dataset output and a JOSS paper draft.

QUESTION:       Given the volume of CISA ICS advisories, how can OT
                 operators, researchers, and auditors get one deterministic,
                 reproducible, risk-prioritized view of ICS vulnerabilities
                 that joins advisory data with real-world exploitation
                 (KEV), exploitation likelihood (EPSS), CISA enrichment
                 (Vulnrichment SSVC/CVSS), and adversary technique context
                 (ATT&CK for ICS)?

SOURCES:
  - CISA ICS Advisories        https://www.cisa.gov/news-events/ics-advisories
                                 ongoing, public domain (US govt work)
  - CISA KEV catalog (JSON)     https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
                                 updated continuously, public domain
  - FIRST.org EPSS API          https://api.first.org/data/v1/epss
                                 daily scores back to 2021-04-14, FIRST.org terms
  - CISA Vulnrichment           https://github.com/cisagov/vulnrichment
                                 per-CVE JSON (SSVC, CVSS, CWE), CC0-1.0
  - MITRE ATT&CK for ICS        https://github.com/mitre-attack/attack-stix-data
                                 (ics-attack domain), STIX 2.1 JSON, ATT&CK Terms of Use
  All confirmed live and reachable 2026-09-13.

UNIT:           One row per (CVE, advisory) pair, joined across sources.
                 Advisories with no CVE (rare) kept as advisory-level rows.

MEASURES:
  - in_kev              bool, CVE present in CISA KEV catalog
  - epss_score / epss_percentile   float, from EPSS API, run-dated
  - ssvc_exploitation / ssvc_automatable / ssvc_technical_impact
                          categorical, from Vulnrichment ADP container
  - cvss_base_score / cvss_vector   from advisory or Vulnrichment, whichever
                          is more recent
  - attack_techniques    list of ATT&CK-for-ICS technique IDs mapped via a
                          documented CWE-to-technique crosswalk (heuristic;
                          author-reviewed crosswalk table, not a MITRE mapping)
  - priority_score       deterministic composite score combining in_kev,
                          epss_percentile, and the SSVC decision points into
                          one 0-100 OT-relevant priority number. Exact
                          weighting is author-reviewed and approved in
                          docs/SCORING.md.

OUTPUTS:
  - icsprio/               installable Python package (pip + PyPI)
  - icsprio CLI             `icsprio fetch`, `icsprio build`, `icsprio prioritize`
  - data/processed/icsprio_joined.csv (+ .parquet)   joined dataset export
  - data/processed/qa_report.txt
  - tests/                 pytest suite with fixtures (offline, no live calls)
  - docs/ (README, CODEBOOK, SCORING, LIMITATIONS, VERIFY_CHECKLIST, ATTACK_MAPPING)
  - CITATION.cff, CHANGELOG.md, CONTRIBUTING.md, LICENSE
  - paper/paper.md          JOSS-format paper draft (prepared, not submitted)

VENUES:
  1. GitHub repository + tagged v1.0.0 release
  2. Zenodo deposit on that release → DOI
  3. PyPI (pip install icsprio)
  4. JOSS submission kit — prepared and gate-checked, but per the author's
     own plan, submission is held pending a documented third-party user;
     not filed this session.

VERIFY POINTS (author must personally rule on these before release):
  - priority_score weighting formula (docs/SCORING.md)
  - CWE→ATT&CK-for-ICS technique crosswalk (docs/ATTACK_MAPPING.md)
  - advisory scope: ICSA + ICSMA (medical) both included, tagged by type —
    confirm this is the right inclusion rule
  - five hand-picked spot-check CVEs in the QA report

LICENSE:        Code: MIT. Derived/joined dataset: CC BY 4.0, attributed to
                 CISA, FIRST.org, MITRE, and the CVE Program.

AUTHORS (AUTHORS.json):
  - Friday Ogochukwu Ikwuogu, ORCID 0009-0009-2222-1318,
    Friday.ikwuogu@gmail.com, Independent Researcher, Odessa, Texas, USA
  - David Mike-Ewewie, Computer Science Department, University of Texas
    Permian Basin, Odessa, Texas, USA, mike_d63291@utpb.edu

ASSUMPTIONS (proceeding without further confirmation; flagged for review):
  - Package name `icsprio` — NOT conclusively confirmed on PyPI: this
    sandbox's outbound network blocks pypi.org entirely (HTTP 403,
    `host_not_allowed`), and pip's "no matching distribution" message looks
    identical whether a package name is free or the index request itself
    failed. Re-check https://pypi.org/project/icsprio/ yourself before
    first upload — see docs/LIMITATIONS.md #3.
  - Default fetch scope = last 3 years (`--since-year <current year - 3>`),
    not full history, REVISED from the original plan during implementation:
    advisories are fetched via the GitHub CSAF mirror's API, which rate-limits
    unauthenticated requests to 60/hour — a full historical pull needs a
    `GITHUB_TOKEN` and `--since-year 2010` explicitly. See
    docs/LIMITATIONS.md #5 and #10.
  - License defaults (MIT/CC BY 4.0) taken from the skill's standard
    default, not separately confirmed with the author.
  - GitHub push and Zenodo deposit require the author's tokens
    (GITHUB_TOKEN with repo scope; ZENODO_TOKEN with deposit:write +
    deposit:actions) — will ask for these at the publish step; until then
    the repository is built and committed locally.
  - This build's sandbox blocks outbound network to cisa.gov, api.first.org,
    raw.githubusercontent.com, pypi.org, and Ubuntu's package archive, so
    (a) no live end-to-end pipeline run happened, and (b) `pytest`/`pyarrow`
    could not be installed to run the shipped test suite. Both were
    mitigated as far as possible without live access — see
    docs/LIMITATIONS.md #1-2 — but remain the top items in
    docs/VERIFY_CHECKLIST.md.
```

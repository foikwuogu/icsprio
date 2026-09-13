---
title: 'icsprio: an open Python package for fetching, joining, and prioritizing ICS advisories'
tags:
  - Python
  - cybersecurity
  - industrial control systems
  - operational technology
  - vulnerability management
authors:
  - name: Friday Ogochukwu Ikwuogu
    orcid: 0009-0009-2222-1318
    affiliation: 1
  - name: David Mike-Ewewie
    affiliation: 2
affiliations:
  - name: Independent Researcher, Odessa, Texas, USA
    index: 1
  - name: Computer Science Department, University of Texas Permian Basin, Odessa, Texas, USA
    index: 2
date: 13 September 2026
bibliography: paper.bib
---

# Summary

`icsprio` is an open-source Python package that fetches, joins, and
prioritizes vulnerability intelligence for industrial control systems
(ICS) and operational technology (OT). It draws from five public sources —
CISA's ICS Advisories (published as machine-readable CSAF 2.0 documents),
CISA's Known Exploited Vulnerabilities (KEV) catalog, FIRST.org's Exploit
Prediction Scoring System (EPSS) [@jacobs2021epss], CISA's Vulnrichment enrichment (Stakeholder-
Specific Vulnerability Categorization, or SSVC [@spring2021ssvc], decision points and CVSS),
and MITRE ATT&CK for ICS [@strom2018mitre] — and joins them deterministically into a single
table, one row per (advisory, CVE) pair. From that joined table, `icsprio`
computes a documented, deterministic, and fully overridable `priority_score`
that combines real-world exploitation status, exploitation likelihood, and
SSVC's exploitation/automatability/impact decision points into one ordering
an operator can triage from. Every run is reproducible: given the same
fetched inputs and the same scoring weights, two runs of `icsprio` never
disagree, and every weighting and mapping decision the package makes is
written down and meant to be reviewed, not trusted blindly.

# Statement of need

Operators, incident responders, and researchers working in ICS/OT
cybersecurity routinely need to answer one practical question — "of the
vulnerability advisories affecting our environment, which should we act on
first" — using data that is public but scattered across five
independently-maintained sources with different formats, update cadences,
and coverage. In practice this is done by hand: opening CISA advisory pages,
cross-referencing the KEV catalog, looking up EPSS scores one CVE at a time,
and reading Vulnrichment or CVSS data separately, then applying an ad hoc,
undocumented mental model of "how bad is this." That process does not scale
past a handful of advisories, is not reproducible between two people doing
it, and leaves no audit trail for why a given vulnerability was or was not
treated as urgent — a real problem in regulated critical-infrastructure
environments where prioritization decisions must be defensible after the
fact.

General-purpose vulnerability management platforms typically prioritize by
CVSS or EPSS alone and are not built around ICS-specific advisory sources or
SSVC's OT-relevant decision points; ICS-specific advisory aggregators
(e.g., community CSV exports of CISA's advisories) provide the advisory data
itself but do not join it with exploitation, likelihood, and adversary
technique context, nor compute a prioritization score. `icsprio` fills this
specific gap: it is narrow in scope (it does not attempt asset inventory,
network scanning, or patch management) and instead focuses on making the
public-data half of ICS vulnerability triage — fetch, join, score,
document — fast, reproducible, and auditable.

# Functionality

`icsprio` exposes both a Python API and a CLI. The main operation is:

```bash
icsprio run
```

which fetches all five sources (respecting a configurable time window),
joins them into `data/processed/icsprio_joined.csv`, computes `priority_score`
for every row, and writes a QA report (`qa_report.txt`) documenting row
counts, join match rates against each source, sanity checks, and a
deterministic sample of rows for manual spot-checking. The scoring weights
are declared in a small dataclass (`icsprio.config.ScoringWeights`) and can
be overridden via a YAML file without touching code:

```bash
icsprio build --weights-file my_weights.yaml
```

Because no authoritative mapping exists from a CVE's CWE weakness class to
MITRE ATT&CK for ICS techniques, `icsprio` applies a documented,
confidence-rated heuristic crosswalk (`icsprio/reference_data/cwe_to_attack_ics.csv`)
rather than presenting the ATT&CK-for-ICS join as more certain than it is;
each mapped row carries a rationale and a confidence level, and the
crosswalk is data, not code, so it can be extended or corrected without a
release. Full documentation of the scoring formula, the crosswalk
methodology, and known limitations is in the package's `docs/` directory.

# Acknowledgements

`icsprio` builds entirely on public data provided by the Cybersecurity and
Infrastructure Security Agency (CISA), FIRST.org, and MITRE. AI assistance
(Claude, Anthropic) was used during development for code scaffolding, test
fixture generation, and documentation drafting; the prioritization logic,
the CWE-to-ATT&CK-for-ICS crosswalk, and all analytic decisions were
specified and are owned by the authors, who verified the software's
behavior before release.

# References

# CWE -> ATT&CK-for-ICS crosswalk methodology

**[VERIFY] This crosswalk is icsprio's own heuristic, authored for this
project. It is not a MITRE, CISA, or CVE Program mapping, and the author
should review every row in `icsprio/reference_data/cwe_to_attack_ics.csv` before
release.**

## Why a crosswalk is needed at all

No authoritative mapping from a CVE (or its CWE weakness class) to ATT&CK
for ICS techniques exists. ATT&CK for ICS catalogs *adversary behavior after
an initial foothold or during an intrusion* (e.g. "Modify Parameter," "Denial
of Service"); CWE catalogs *root-cause weakness types* in software (e.g.
"Out-of-bounds Write," "Missing Authentication"). They describe different
things at different points in an intrusion, so there is no clean 1:1
mapping — this crosswalk is a documented, reviewable judgment call about
which techniques an adversary would plausibly use *given* a vulnerability of
a certain weakness class, not a claim that exploiting CWE-X always produces
technique T.

## Method

1. For each CWE commonly seen in ICS advisories, ask: if an adversary
   exploited a vulnerability of this weakness class, what's the most direct
   ATT&CK-for-ICS technique describing what they could then do?
2. Assign one or more mapped techniques, each with:
   - `confidence`: `high` (the technique's own ATT&CK description names
     this weakness class or a direct synonym), `medium` (a common,
     well-established path but not a definitional match), or `low` (plausible
     but more context-dependent).
   - `rationale`: one sentence, so a reader can judge the mapping rather
     than trust it.
3. `icsprio.join` keeps only the highest-confidence mapping per technique
   when multiple CWEs on the same CVE point to the same technique, and
   drops any mapped technique that isn't in the currently-fetched ATT&CK
   catalog (so a stale crosswalk entry can never claim a retired ID).

## Coverage

The initial crosswalk (`icsprio/reference_data/cwe_to_attack_ics.csv`) covers
roughly the two dozen CWEs most frequently assigned in CISA ICS advisories
and Vulnrichment records (hard-coded/missing credentials, injection
families, memory-safety bugs, denial-of-service-prone weaknesses,
cryptographic/transport weaknesses, and access-control failures). A CWE not
in the table simply contributes no mapped technique — this is silent by
design (see NEXT_STEPS.md for surfacing "unmapped CWE" explicitly).

## Extending it

Add a row to `icsprio/reference_data/cwe_to_attack_ics.csv` with the same five
columns (`cwe_id, cwe_name, attack_technique_id, attack_technique_name,
confidence, rationale`) and re-run `icsprio build` — no code change needed.
`tests/test_attack_mapping.py` confirms the loader and dedup logic handle
new rows correctly.

## Terms of use

ATT&CK for ICS content (technique names, IDs, tactics) is used under the
[ATT&CK Terms of Use](https://attack.mitre.org/resources/terms-of-use/),
which permits use with attribution to MITRE ATT&CK.

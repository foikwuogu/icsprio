# Next steps (what v1.1+ could add)

icsprio v1.0 is a first, complete, working version — not a final word.
Candidates for a next release, roughly in order of value:

1. **Distinguish "no CWE" from "CWE not in crosswalk"** in
   `attack_technique_ids` output, so a reader can tell "this vulnerability's
   root cause isn't classified" from "icsprio's crosswalk doesn't cover this
   weakness class yet" (currently both render as an empty list —
   docs/CODEBOOK.md).
2. **Expand the CWE->ATT&CK-for-ICS crosswalk** beyond the ~25 CWEs covered
   in v1.0 (icsprio/reference_data/cwe_to_attack_ics.csv), ideally with a second
   reviewer's confidence ratings alongside the author's.
3. **Historical EPSS scores.** EPSS publishes daily bulk CSVs back to
   2021-04-14; a `--epss-date` option could score a historical advisory as
   of its publication date rather than always using today's score, useful
   for retrospective analysis.
4. **Sector tagging.** Join CISA's own sector classifications (where
   published) or the vendor/product text against a maintained
   vendor-to-sector table, so results can be filtered by critical
   infrastructure sector.
5. **A cached/incremental fetch mode**, so a daily cron run only pulls
   advisories, KEV entries, and EPSS/Vulnrichment records that changed
   since the last run, instead of the current full-window refetch.
6. **JOSS submission**, once real-world use exists (see paper/paper.md and
   BUILD_SPEC.md's venue note — held pending a documented third-party
   user, per the author's own plan for this project).
7. **A small validation study**: how well does `priority_score` correlate
   with, or predict, advisories that organizations later confirmed were
   actively exploited against their own environment? This would be a
   natural companion paper (the "validation or proxy study" archetype).

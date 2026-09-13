# Test fixtures

These files are synthetic but schema-accurate stand-ins for each live source
(CISA KEV, FIRST EPSS, CISA Vulnrichment, MITRE ATT&CK for ICS STIX, and a
CISA CSAF ICS advisory), used so the test suite runs fully offline and
reproducibly, independent of what today's real feeds contain. They mirror
the field names and structure confirmed against the live sources on
2026-09-13 (see BUILD_SPEC.md and the docstrings in icsprio/sources/*.py).

None of the identifiers here (CVE numbers, advisory IDs) should be treated
as real vulnerabilities — `CVE-2099-00001` and `ICSA-99-999-01` are
deliberately out-of-range placeholders so nobody mistakes a fixture for a
live record. Real data only ever comes from `icsprio fetch` against the
actual APIs.

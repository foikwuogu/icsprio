# Codebook — `data/processed/icsprio_joined.csv`

One row per (advisory, CVE) pair. An advisory with no listed CVE keeps one
row with `cve` empty.

| Column | Type | Source | Definition |
|---|---|---|---|
| `advisory_id` | string | CISA CSAF | Advisory tracking ID, e.g. `ICSA-26-076-03`. |
| `advisory_type` | string | derived | `ICSA` (general ICS/OT) or `ICSMA` (medical device), from the ID prefix. |
| `title` | string | CISA CSAF | Advisory document title. |
| `published` | date | CISA CSAF | `document.tracking.initial_release_date`. |
| `updated` | date | CISA CSAF | `document.tracking.current_release_date`. |
| `vendors` | list[string] | CISA CSAF | Vendor name(s) from the advisory's product tree. |
| `products` | list[string] | CISA CSAF | Affected product name(s). |
| `advisory_url` | string | derived | Human-readable advisory page. |
| `cve` | string | CISA CSAF | The CVE ID this row is about. |
| `in_kev` | bool | CISA KEV | Whether `cve` appears in the KEV catalog at fetch time. |
| `kev_date_added` | date | CISA KEV | Date CISA added this CVE to KEV, if applicable. |
| `kev_due_date` | date | CISA KEV | Federal remediation due date (Binding Operational Directive scope), if applicable. |
| `kev_ransomware_use` | string | CISA KEV | `Known` or `Unknown` — known use in ransomware campaigns. |
| `epss_score` | float [0,1] | FIRST EPSS | Estimated 30-day exploitation probability, at fetch time. |
| `epss_percentile` | float [0,1] | FIRST EPSS | This CVE's percentile rank among all scored CVEs, at fetch time. |
| `epss_date` | date | FIRST EPSS | The date EPSS scored this CVE (EPSS is point-in-time — see LIMITATIONS). |
| `ssvc_exploitation` | categorical | Vulnrichment | CISA-ADP's SSVC Exploitation decision point: `none` / `poc` / `active`. |
| `ssvc_automatable` | categorical | Vulnrichment | SSVC Automatable decision point: `no` / `yes`. |
| `ssvc_technical_impact` | categorical | Vulnrichment | SSVC Technical Impact decision point: `partial` / `total`. |
| `cvss_base_score` | float [0,10] | Vulnrichment | CVSS base score from the CISA-ADP container, when present. |
| `cvss_vector` | string | Vulnrichment | CVSS vector string. |
| `cwes` | list[string] | Vulnrichment | CWE weakness ID(s) CISA-ADP assigned to this CVE. |
| `attack_technique_ids` | list[string] | derived | ATT&CK-for-ICS technique IDs mapped from `cwes` via the heuristic crosswalk — see ATTACK_MAPPING.md. **Not** a MITRE or CISA mapping. |
| `attack_technique_names` | list[string] | derived | Names matching `attack_technique_ids`. |
| `priority_score` | float [0,100] | derived | icsprio's own OT-relevant priority score — see SCORING.md. |
| `priority_band` | categorical | derived | `Critical` / `High` / `Medium` / `Low`, from `priority_score` thresholds in SCORING.md. |

## Missing values

- `epss_score`/`epss_percentile`/`epss_date` are null when a CVE is too new
  or otherwise unscored by EPSS at fetch time — not zero.
- `ssvc_*`, `cvss_*`, and `cwes` are null/empty when Vulnrichment has not
  yet enriched that CVE — CISA-ADP enriches a subset of CVEs, prioritizing
  recent and higher-signal ones, not every CVE ever published.
- `attack_technique_ids` is empty both when a CVE has no CWE assignment and
  when its CWE(s) aren't yet in the crosswalk table — these two cases are
  not currently distinguished in the output; see NEXT_STEPS.md.

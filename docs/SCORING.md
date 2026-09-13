# `priority_score` — icsprio's OT-relevant prioritization logic

**Author-reviewed design:** This entire document was reviewed and signed off
on by the author before the v1.0 release. These weights and thresholds
are icsprio's own analytic contribution — nothing here is a value CISA,
FIRST, or MITRE publishes.

## Why a composite score at all

Each individual source answers a narrower question than "should I act on
this now":

- KEV answers "has this been exploited in the wild, ever" — binary, and
  necessarily lags real-world exploitation by however long it takes CISA to
  confirm and publish.
- EPSS answers "how likely is exploitation in the next 30 days" —
  continuous, but a general-internet model not tuned for OT/ICS
  deployment realities (e.g. many ICS devices are not internet-reachable,
  which EPSS's training data doesn't know).
- SSVC (via Vulnrichment) answers a decision-tree question about
  exploitation state, automatability, and technical impact — closer to
  "how bad and how easy," but only computed for a subset of CVEs.

An operator triaging a stack of advisories needs one ordering, not three
partially-overlapping signals to reconcile by eye every time. `priority_score`
is that ordering — explicit and overridable, not a replacement for reading
the advisory.

## The formula

```
priority_score = 100 * (sum of weight_i * component_i for each AVAILABLE signal i)
                        / (sum of weight_i for each AVAILABLE signal i)
```

| Signal | Component (0-1) | Default weight |
|---|---|---|
| KEV | `1.0` if in KEV else `0.0` (always available) | 0.40 |
| EPSS | `epss_percentile` | 0.25 |
| SSVC Exploitation | `none`→0.0, `poc`→0.5, `active`→1.0 | 0.15 |
| SSVC Automatable | `no`→0.0, `yes`→1.0 | 0.10 |
| SSVC Technical Impact | `partial`→0.5, `total`→1.0 | 0.10 |

Weights sum to 1.0 and live in `icsprio.config.ScoringWeights` — override
via `--weights-file weights.yaml` (any subset of the five `*_weight` keys)
on `icsprio build`/`run`.

## Handling missing enrichment

**Author-reviewed:** KEV absence is always scored (a CVE simply not in KEV is a real
signal: 0.0). EPSS is scored when present, dropped from the denominator when
not. The three SSVC-derived weights are dropped from the denominator
*together*, as a group, when Vulnrichment has no record at all for a CVE —
so an unenriched CVE is scored purely on KEV + EPSS and isn't punished for
lacking coverage it was never going to get. The alternative — treating
missing SSVC as the worst case (`none`/`no`/`partial`) — was considered and
rejected because Vulnrichment's coverage skews toward newer and
higher-profile CVEs, which would make "unenriched" partially confounded
with "less scrutinized" rather than "less severe." This tradeoff has been
reviewed and approved by the author.

## Bands

| `priority_score` | Band |
|---|---|
| ≥ 75 | Critical |
| 50–74.99 | High |
| 25–49.99 | Medium |
| < 25 | Low |

**Author-reviewed:** These cut points are round numbers chosen for legibility, not
derived from an operational study of remediation outcomes. If your
organization has its own SLA tiers, override `icsprio.scoring.BAND_THRESHOLDS`
or post-process `priority_score` directly.

## Determinism

Given the same joined table and the same `ScoringWeights`, `compute_priority_score`
returns the same output every time — there is no randomness, model
inference, or wall-clock dependency in the formula itself. Re-running
`icsprio build` without re-fetching reproduces `priority_score` exactly;
re-running `icsprio fetch` can change it, because KEV/EPSS/Vulnrichment
content changes over time — that's real-world drift, not nondeterminism.

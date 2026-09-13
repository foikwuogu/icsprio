# Contributing to icsprio

Issues and pull requests are welcome.

## Development setup

```bash
git clone https://github.com/friday-ikwuogu/icsprio.git
cd icsprio
pip install -e ".[dev,parquet]"
pytest
```

## Guidelines

- **Tests are offline.** Every test in `tests/` runs against the fixtures in
  `tests/fixtures/` and must not make live network calls — mock or
  monkeypatch the relevant `fetch_*` function instead. This keeps CI fast
  and reproducible regardless of upstream API availability.
- **The stats-file rule.** Any document that quotes a number (README,
  paper, a report) must interpolate it from `data/processed/stats.json`,
  never a hand-typed value.
- **Changing `priority_score`'s weights or the ATT&CK crosswalk** is a
  documented decision, not just a code change — update docs/SCORING.md or
  docs/ATTACK_MAPPING.md in the same pull request, and add a rationale for
  crosswalk rows.
- **Provenance.** Any new fetcher must log to `data/raw/PROVENANCE.txt` via
  `icsprio.provenance.log_fetch`, matching the existing fetchers in
  `icsprio/sources/`.
- Run `ruff check .` before submitting, if you have it installed.

## Reporting a security issue

icsprio processes public vulnerability data but is not itself
security-critical infrastructure. For a bug that could cause icsprio to
mis-prioritize or drop real vulnerability data, please open a regular GitHub
issue — there's no separate private disclosure process for this project at
this size.

## Code of conduct

Be respectful and assume good faith. This project follows the spirit of the
[Contributor Covenant](https://www.contributor-covenant.org/).

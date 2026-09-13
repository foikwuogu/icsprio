# Publish guide — icsprio v1.0.0

The repository is verified and pushed to GitHub at
`github.com/foikwuogu/icsprio`. This guide gets you from the `v1.0.0` GitHub
release to a Zenodo DOI and a PyPI package — **after** you've been through
[the verification checklist](VERIFY_CHECKLIST.md) and the pipeline has had a real
run against live data (see [LIMITATIONS.md](LIMITATIONS.md) #1-2).

Do these in order — GitHub first, since Zenodo's easiest path archives a
GitHub release, and PyPI's release notes reference the GitHub tag.

## 0. Before you push anything

```bash
python scripts/publish_gate.py .
```

(`scripts/` ships in this repository — `publish_gate.py`, `publish_github.py`,
`zenodo_deposit.py`, and `provenance.py`.) Before the verification pass, this
will report draft banners and review tags throughout `docs/`
and the source — that's expected and correct until you've done the
verification pass. Once you have:

```bash
icsprio run --final          # regenerates qa_report.txt without the draft banner
```

and rewritten anything in `docs/LIMITATIONS.md`, `docs/SCORING.md`, and
`docs/ATTACK_MAPPING.md` that no longer reads as provisional, re-run the
gate. It should report clear.

## 1. GitHub

**Option A — command line, using a personal access token:**

```bash
export GITHUB_TOKEN=ghp_...                 # fine-grained: Administration:write, Contents:write
python scripts/publish_github.py . --repo icsprio \
    --description "Fetch, join, and prioritize ICS vulnerability intelligence" \
    --release v1.0.0 \
    --release-notes "$(cat CHANGELOG.md)"
```

This creates `github.com/<your-username>/icsprio`, pushes the existing
commit, and tags `v1.0.0`. Revoke the token afterward.

**Option B — by hand:**

1. github.com/new → name it `icsprio`, leave it empty (no README/license —
   this repo already has both).
2. In the project folder: `git remote add origin https://github.com/<you>/icsprio.git`
   then `git push -u origin main`.
3. Releases → "Draft a new release" → tag `v1.0.0`, title `v1.0.0`, paste
   the "1.0.0" section of `CHANGELOG.md` into the notes → Publish.

Either way, update `README.md`'s `repository-code` links and
`pyproject.toml`'s `[project.urls]` if you use a different GitHub username
than `friday-ikwuogu` (used as a placeholder throughout this build).

## 2. Zenodo (DOI)

**Easiest: GitHub-Zenodo integration (no token needed)**

1. Log in at zenodo.org with your ORCID (0009-0009-2222-1318).
2. Account → GitHub → flip the switch for `icsprio`.
3. Create another GitHub release (or edit the `v1.0.0` one) — Zenodo
   archives it automatically and mints a DOI within minutes.
4. Copy the DOI into `CITATION.cff`'s `doi:` field, `README.md`'s Citation
   section, and `zenodo_metadata.json` isn't needed on this path.

**Manual / scripted path, if you'd rather not link GitHub:**

```bash
export ZENODO_SANDBOX_TOKEN=...     # test first — mints a fake DOI, same UI
python scripts/zenodo_deposit.py --sandbox \
    --files README.md CHANGELOG.md LICENSE LICENSE-DATA \
    --metadata zenodo_metadata.json
# review the sandbox record, then for real:
export ZENODO_TOKEN=...
python scripts/zenodo_deposit.py --publish \
    --files README.md CHANGELOG.md LICENSE LICENSE-DATA \
    --metadata zenodo_metadata.json
```

`zenodo_metadata.json` (in the repository root) is pre-filled from
`AUTHORS.json` — check it once before running. Consider attaching a
zipped source archive (`git archive -o icsprio-1.0.0.zip HEAD`) as one of
the `--files` too, so the Zenodo record has the exact released code, not
just docs.

After publishing: copy the DOI into `CITATION.cff`, the README status
line, and the evidence log the same day.

## 3. PyPI

**First, actually confirm the name is free** — this build's sandbox
couldn't reach pypi.org to check (see LIMITATIONS.md #3):
`https://pypi.org/project/icsprio/` should 404. If it's taken, rename the
package (`pyproject.toml`'s `[project].name`, and `pip install <new-name>`
in README.md) before proceeding.

```bash
python -m pip install --upgrade build twine
python -m build
python -m twine upload dist/*
# username: __token__
# password: <your PyPI API token, scoped to this project after the first upload>
```

Then tag the same version (`v1.0.0`) consistently across GitHub, Zenodo,
and PyPI — a user should be able to go from any one to the others without
version drift.

## 4. JOSS — held, per the project plan

The author's own plan for this project holds the JOSS submission
"contingent on a documented third-party user." `paper/paper.md` and
`paper/paper.bib` are prepared and gate-clean, but **do not submit to
joss.theoj.org yet**. When that condition is met:

1. Confirm `paper/paper.md` still matches the released software (functionality
   section, statement of need).
2. Submit at joss.theoj.org/papers/new with the GitHub repository URL and
   the `v1.0.0` tag or the Zenodo DOI.
3. Review happens as a public GitHub issue on the JOSS reviews repo —
   respond to each item with a commit to `icsprio` and a reply on the
   issue.

## After every step

Log it the day it happens: date, venue, URL/DOI/tracking number, and what
you saved. A simple row in a personal log or spreadsheet is enough — the
important thing is doing it same-day, before it's easy to forget which
release matches which citation.

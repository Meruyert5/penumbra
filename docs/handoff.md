# Handoff

This file is the fast path for a new session or a new maintainer. It records the
current state, the commands that reproduce it, and the tasks that require a human
account.

## Current state

| Item | Value |
|---|---|
| Author | Meruyert Oshayeva |
| Branch | `main` |
| Latest commit | use `git log -1 --oneline`; the repository is clean after each handoff |
| Repository | <https://github.com/Meruyert5/penumbra> (public) |
| Local repo | the repository checkout |
| Built dashboard | `docs/index.html` |
| Evidence sections | Response in Instruments, hunting in Umbra, validation in Corona, IR in Eclipses, roadmap in After |
| Public site | `site/` (generated, gitignored) |
| Public surface | `index.html`, `assets/`, `cases/`, `.nojekyll`; optionally `CNAME` |
| Public host | <https://meruyert5.github.io/penumbra/> |
| Permanent target | `https://penumbra.is-a.dev` (domain still available; registration pending) |
| Tests | 79 passing |
| Apsis | Complete |
| Real validation | 1,381 events across five indices and 16 labelled windows; 6 TP / 0 FP / 1 FN; 0 not evaluable; 89,704-event benign baseline |
| Lighthouse | 100 accessibility / 100 best practices / 100 SEO |

The local server can serve `site/` for review. GitHub Pages is the only public
host; the Cloudflare Quick Tunnel has been removed. `design.md`, `runbook.md`, and `tuning.md` are public in the repository
but are not part of the published site.

## Cross-project handoff

Apsis delivered the observed-path case as data in
[`integrations/apsis/`](../integrations/apsis/): a `penumbra.alert/v1` alert, its
`penumbra.evidence/v1` manifest, the case narrative, the guardrails and the
before/after route snapshots. Both payloads validate against the copied schemas.
Penumbra reads the alert and cites the evidence; it does not import Apsis code.
Apsis is complete at functional source `fae1f74`; its 89 Python tests, 5 logic
tests, console build, and both contracts pass.

## Rebuild and verify

```powershell
node --check dashboard\app.js
.\.venv\Scripts\python.exe -m pipeline.report
.\.venv\Scripts\python.exe -m pipeline.publish
.\.venv\Scripts\python.exe -m pipeline.lint
.\.venv\Scripts\python.exe -m pipeline.compile --check
.\.venv\Scripts\python.exe -m pipeline.coverage --check
.\.venv\Scripts\python.exe -m pipeline.heatmap
.\.venv\Scripts\python.exe -m pipeline.validation
.\.venv\Scripts\python.exe -m pipeline.validation_results --write-results
.\.venv\Scripts\python.exe -m pipeline.benchmark --labels docs\validation\labels.json
.\.venv\Scripts\python.exe -m pipeline.hunts
.\.venv\Scripts\python.exe -m pipeline.cloud_pack
.\.venv\Scripts\python.exe -m pipeline.triage
.\.venv\Scripts\python.exe -m pipeline.casebook
.\.venv\Scripts\python.exe -m pytest -q
```

The optional replay path is:

```powershell
python -m pipeline.replay --source path\to\otrf.json --file windows --label malicious
python -m pipeline.ingest --reset
python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z
python -m pipeline.validation
```

`pipeline.publish` copies only the public surface into `site/`. It deletes and
recreates `site/`, so never put source files there.

## Serve the public site locally

```powershell
.\.venv\Scripts\python.exe -m http.server 8765 --bind 127.0.0.1 --directory site
```

For internal design work, `--directory docs` is acceptable, but it exposes the
design notes, runbook, and tuning log. Do not point a public tunnel at `docs/`.

## Public hosting

GitHub Pages is the public host at <https://meruyert5.github.io/penumbra/>.
The workflow uploads `site/`, never `docs/`. The Cloudflare Quick Tunnel is not
used for this project. If you need a temporary preview, serve `site/` on
localhost; do not publish a tunnel that exposes the working tree.

## Repository

The repository is public at
[github.com/Meruyert5/penumbra](https://github.com/Meruyert5/penumbra).
`origin` is configured, `main` is the deployment branch, and the Pages workflow
runs on every push.

```powershell
git push origin main
```

| Workflow | Purpose |
|---|---|
| `penumbra-ci` | Tests and rule checks |
| `penumbra-quality` | Documentation links and Lighthouse |
| `penumbra-pages` | Builds `site/` and deploys Pages |

## GitHub Pages

Pages is enabled with **Source: GitHub Actions** and deploys on every push to
`main`. Redeploy by running `penumbra-pages` or pushing to `main`.

1. Open <https://meruyert5.github.io/penumbra/>.
2. Confirm `/design.md`, `/runbook.md`, and `/tuning.md` return 404.
3. Confirm the live URL is in the README reviewer path and the repository About panel.

The workflow uploads `site/`, never `docs/`.

## Custom domain

Read [`docs/custom-domain.md`](custom-domain.md). The short version:

- `penumbra.is-a.dev` appears unregistered as of 16 November 2026.
- A CNAME to `<github-username>.github.io` is the permanent path.
- The is-a.dev pull request must be created and submitted by the human owner.
  is-a.dev explicitly prohibits AI-generated pull requests; do not automate it.
- After the PR is merged, add `penumbra.is-a.dev` in GitHub Pages → Custom
  domain and enable HTTPS. Add `docs/CNAME` with the domain so `pipeline.publish`
  carries it into `site/`.

## Author and licence

- Author: **Meruyert Oshayeva**.
- README, `pyproject.toml`, `LICENSE`, the page `<meta name="author">`, and the
  footer colophon carry the name.
- The root licence is MIT. The README reserves the Penumbra name and visual
  identity as brand identifiers; it does not grant trademark rights.

## Open decisions

1. **Design privacy (decided).** The repository is public under MIT, so the
   design source is public. `pipeline.publish` keeps it off the website, not out
   of the repository. See [`docs/publishing.md`](publishing.md) for the
   split-repository options if that changes.
2. **Name.** Penumbra collides with Penumbra Security, Inc. and other products.
   Keep it for a portfolio with the disclaimer, or choose a more distinctive name
   before a commercial launch.
3. **Validation.** The small-sample benchmark is real but narrow: 16 labelled
   windows, 6 TP, 0 FP, 1 FN. Extend the corpus before treating precision and
   recall as stable. See [`docs/validation/benchmark.md`](validation/benchmark.md).

## Do not

- Do not commit `site/`; it is generated.
- Do not point the public tunnel at `docs/`.
- Do not submit an AI-generated is-a.dev pull request.
- Do not claim production precision, recall, or coverage completeness.
- Do not rename Umbra back to Totality; Umbra is the theme, Totality is the phase.
- Do not add real telemetry, credentials, or personal data to the repository.

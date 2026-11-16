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
| Local repo | the repository checkout |
| Built dashboard | `docs/index.html` |
| Public site | `site/` (generated, gitignored) |
| Public surface | `index.html`, `assets/`, `cases/`, `.nojekyll`; optionally `CNAME` |
| Public host | GitHub Pages (after the first upload) |
| Permanent target | `https://penumbra.is-a.dev` (pending registration and Pages setup) |
| Tests | 54 passing |
| Real validation | 2 OTRF samples: 228 events, 2 rules, 4 real matches; 89,704-event benign baseline |
| Lighthouse | 100 accessibility / 100 best practices / 100 SEO |

The local server can serve `site/` for review. GitHub Pages is the only public
host; the Cloudflare Quick Tunnel has been removed. `design.md`,
`design-research.md`, `runbook.md`, and `tuning.md` are not part of the public
surface.

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
.\.venv\Scripts\python.exe -m pipeline.benchmark --labels docs\validation\labels.example.json
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

GitHub Pages is the public host. The workflow uploads `site/`, never `docs/`.
The Cloudflare Quick Tunnel is not used for this project. If you need a temporary
preview, serve `site/` on localhost and keep it private; do not publish a tunnel
that exposes the working tree.

## Upload to GitHub

GitHub CLI is not installed in the current environment, and no remote or SSH key
is configured. Install the CLI, authenticate with the device flow, then create
and push:

```powershell
winget install --id GitHub.cli -e
gh auth login --hostname github.com --git-protocol https --web
cd <repo>
gh repo create penumbra --public --source=. --remote=origin --push
```

The `--web` flow prints a one-time code. The human enters it at
<https://github.com/login/device>. Never ask for or store a password or personal
access token.

Without GitHub CLI, the equivalent is:

```powershell
git remote add origin https://github.com/<owner>/penumbra.git
git push -u origin main
```

The prepared artifacts are:

- `%USERPROFILE%\Documents\penumbra-upload.zip` — tracked-file snapshot;
- `%USERPROFILE%\Documents\penumbra.bundle` — full Git history.

## GitHub Pages

1. Push `main`.
2. **Settings → Pages → Source: GitHub Actions**.
3. Run `penumbra-pages` or push to `main`.
4. Open the Pages URL and confirm `/design.md` returns 404.
5. Add the live URL to the README reviewer path and the repository About panel.

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

1. **Design privacy.** The design source is public. `pipeline.publish` keeps it
   off the website, not out of the repository. See
   [`docs/publishing.md`](publishing.md) for the split-repository options.
2. **Name.** Penumbra collides with Penumbra Security, Inc. and other products.
   Keep it for a portfolio with the disclaimer, or choose a more distinctive name
   before a commercial launch.
3. **Validation.** The current evidence is structural, not statistical. The next
   substantive change is a real-telemetry replay harness; see
   [`docs/evaluation.md`](evaluation.md).

## Do not

- Do not commit `site/`; it is generated.
- Do not point the public tunnel at `docs/`.
- Do not submit an AI-generated is-a.dev pull request.
- Do not claim production precision, recall, or coverage completeness.
- Do not rename Umbra back to Totality; Umbra is the theme, Totality is the phase.
- Do not add real telemetry, credentials, or personal data to the repository.

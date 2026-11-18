# Publishing checklist

**Current status:** the repository is public and GitHub Pages is live at
<https://meruyert5.github.io/penumbra/>. The rest of this file is the checklist
for forks and future releases.

This is the release checklist for the public repository and the public dashboard.
It separates what is safe to publish from what should stay in the working tree.

## Before the first push

1. Confirm the repository visibility. A public repository exposes every committed
   file, including `dashboard/` and `docs/design.md`.
   `pipeline.publish` keeps those files off the website, not out of the repository.
2. Decide the design licence. The current root [LICENSE](../LICENSE) is MIT and
   covers the whole repository. If the visual design should not be reusable,
   split the design source into a private repository and publish only the built
   site and screenshots. See [Design privacy](#design-privacy).
3. Set the Git identity that should appear on the commits:

   ```powershell
   git config user.name "Your Name"
   git config user.email "you@users.noreply.github.com"
   ```

4. Rebuild and verify:

   ```powershell
   python -m pipeline.report
   python -m pipeline.publish
   python -m pipeline.lint
   python -m pipeline.compile --check
   python -m pipeline.coverage --check
   python -m pytest -q
   ```

## Create the repository

With GitHub CLI:

```powershell
gh auth login --hostname github.com --git-protocol https --web
gh repo create penumbra --public --source=. --remote=origin --push
```

Without GitHub CLI:

1. Create an empty repository on GitHub.
2. Add the remote and push:

   ```powershell
   git remote add origin https://github.com/<owner>/penumbra.git
   git push -u origin main
   ```

The repository description and topics recommended for the GitHub About panel:

> A reproducible detection-as-code lab: 50 Sigma rules, Elasticsearch EQL/KQL,
> correlation, ATT&CK coverage, an interactive triage dashboard, and three
> analyst case reports.

Topics: `detection-engineering`, `detection-as-code`, `sigma`, `elasticsearch`,
`eql`, `kql`, `mitre-attack`, `blue-team`, `threat-detection`, `security-lab`,
`portfolio`.

## Configure Pages

1. Open **Settings → Pages**.
2. Set **Source** to **GitHub Actions**.
3. Run the `penumbra-pages` workflow or push to `main`.
4. Open the published URL and confirm that `/design.md` and `/runbook.md` return
   404. The workflow uploads `site/`, not `docs/`.

## After the first deploy

- Add the live URL to the README reviewer path and the repository About panel.
- Replace the relative `og:image` with an absolute URL if a custom domain is used.
- Run Lighthouse on the published URL and record the accessibility, best
  practices, and SEO scores.
- Open one case link, one ATT&CK tile, the command palette, the theme toggle, and
  the Totality sequence at 390px and 1440px.
- Confirm the Cloudflare tunnel process is stopped; GitHub Pages is the only
  public host.

## Public hosting

GitHub Pages is the durable public home. The workflow uploads `site/`, never
`docs/`. The Cloudflare Quick Tunnel has been removed from this project. If you
need a temporary preview, serve `site/` on localhost and keep it private; do not
point a public tunnel at the working tree.

## Sponsorship

The repository includes a `.github/FUNDING.yml` and is ready for a Sponsor button.
GitHub Sponsors payouts require residence in a supported region; Kazakhstan is
not on the current list. Two paths are available:

1. Apply for GitHub Sponsors and join the waitlist if GitHub offers one for the
   region. Once approved, replace the `github:` handle in `.github/FUNDING.yml`
   with the exact username and enable **Settings → General → Features →
   Sponsorships**.
2. Use a custom funding page (Ko-fi, Patreon, Open Collective) and add it as
   `custom: ["https://..."]`. The Sponsor button will show the custom link even
   without a GitHub Sponsors profile.

Do not add payment details or a tax form until the account is ready. A public
repository can show the sponsorship entry without collecting anything.

## Design privacy

A public repository cannot contain private folders. GitHub's terms also allow
visitors to view and fork a public repository. The practical options are:

| Option | Public logic | Design source | Public demo | Trade-off |
|---|---|---|---|---|
| Portfolio default | Yes | Yes, MIT | Yes | Reviewers can inspect the design; copying is possible |
| Split repositories | Yes | Private | Built `site/` only | Compiled CSS/JS is still copyable; more CI setup |
| Private demo | Yes | Private | Screenshots or authenticated URL | Best protection, weakest public portfolio |
| Commercial split | Core public | Proprietary | Authenticated or limited | Requires a design licence, deploy key, and legal review |

For personal accounts, a GitHub Pages site built from a private repository is
still publicly reachable. Access-controlled Pages requires GitHub Enterprise
Cloud. If the design must stay private, use a private host with authentication
(for example Cloudflare Access) rather than a private GitHub repository alone.

For the permanent simple link, see [Custom domain](custom-domain.md).

The current repository keeps the design public. If that changes, move
`dashboard/`, `docs/design.md`, and the dashboard
screenshots into a private repository, keep the compiled `site/` in the public
repository, and update the root licence to carve out the design assets explicitly.

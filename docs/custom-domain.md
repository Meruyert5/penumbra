# Custom domain

The public host is GitHub Pages. A permanent, memorable link is:

1. publish the dashboard on GitHub Pages;
2. register `penumbra.is-a.dev` (or a fallback) and point its CNAME at the Pages
   host;
3. add the domain in GitHub Pages and enable HTTPS.

## Is `penumbra.is-a.dev` available?

Checked on 16 November 2026:

- `https://raw.githubusercontent.com/is-a-dev/register/main/domains/penumbra.json`
  returns 404;
- `penumbra` is not in `util/reserved.json`;
- the name returns only the is-a.dev wildcard DNS records.

That means it **appears** available. Availability is not a reservation: another
person can register it before the pull request is merged. If it is taken, use
`penumbra-lab.is-a.dev` or `meruyert.is-a.dev`.

## Option A — is-a.dev → GitHub Pages (recommended)

### 1. Publish on GitHub Pages first

Complete the GitHub upload and Pages setup in [`docs/publishing.md`](publishing.md).
You need a live Pages URL before you can show a preview in the is-a.dev request.

### 2. Create the domain file manually

Fork <https://github.com/is-a-dev/register>, then create
`domains/penumbra.json`:

```json
{
  "owner": {
    "username": "meruyert"
  },
  "records": {
    "CNAME": "meruyert.github.io"
  }
}
```

Replace `meruyert` with the GitHub username that owns the Pages repository. The
CNAME target for a project site is always `<username>.github.io`, even when the
site lives at `<username>.github.io/penumbra/`.

### 3. Open the pull request yourself

Use the is-a.dev pull-request template and include:

- the live GitHub Pages URL;
- a screenshot of the dashboard;
- a one-line description: “A reproducible detection-as-code lab and triage
  dashboard.”

**Important:** is-a.dev's Terms of Service explicitly prohibits AI-generated
pull requests. Create the file and submit the PR yourself. Do not ask an agent to
open it, and do not paste an AI-written PR body. This is a service rule, not a
preference.

### 4. After the merge

1. In the GitHub repository, open **Settings → Pages → Custom domain**.
2. Enter `penumbra.is-a.dev` and save.
3. Enable **Enforce HTTPS**.
4. Add `penumbra.is-a.dev` to `docs/CNAME` so `pipeline.publish` copies it into
   `site/`.
5. Re-run `python -m pipeline.publish` and redeploy.
6. Check `https://penumbra.is-a.dev` and `https://penumbra.is-a.dev/design.md`
   (the second must return 404).

If GitHub asks for domain verification, add the TXT record from GitHub to the
is-a.dev JSON as described in the is-a.dev GitHub Pages guide, open a second
small PR, and verify after it merges.

## Option B — Cloudflare Pages (`penumbra.pages.dev`)

This also gives a short permanent hostname and does not need is-a.dev. It needs a
Cloudflare account and an authenticated Wrangler session:

```powershell
npx wrangler pages deploy site --project-name penumbra
```

If `penumbra` is taken, use `penumbra-lab`; the URL becomes
`https://penumbra-lab.pages.dev`. Add the Pages project as a custom domain later
if you also want `penumbra.is-a.dev`.

## Option C — named Cloudflare Tunnel

A named tunnel supports a stable public hostname, but the hostname must be in a
Cloudflare zone you control. `is-a.dev` is not your zone, so a named tunnel does
not give you `penumbra.is-a.dev` directly. A CNAME from is-a.dev to a named tunnel
hostname is possible in principle but adds moving parts; GitHub Pages is simpler
for a static dashboard.

## Checklist

- [ ] GitHub Pages is live.
- [ ] `penumbra.is-a.dev` still appears available.
- [ ] `domains/penumbra.json` uses the correct GitHub username.
- [ ] The is-a.dev PR is human-created and human-submitted.
- [ ] GitHub Pages custom domain is set and HTTPS is enforced.
- [ ] `docs/CNAME` contains the domain and was republished.
- [ ] `https://penumbra.is-a.dev` loads and `/design.md` returns 404.

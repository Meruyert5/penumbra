# Threat model

This is a lab, not a production service. The threat model is deliberately small
and is written down so that a reviewer can see where the boundaries are.

## Assets

| Asset | Why it matters |
|---|---|
| Synthetic telemetry | Reproduces the run; must never contain real customer data |
| Sigma rules and correlations | The detection logic is the portfolio's core evidence |
| Dashboard and case reports | Public-facing proof of the work |
| Elasticsearch/Kibana stack | Local lab only; deliberately insecure |
| CI workflows and dependencies | Supply-chain path into the repository |
| Brand and design | Portfolio identity; not a secret, but not a free-for-all |

## Trust boundaries

1. **Static page ↔ browser.** The dashboard is generated HTML with embedded JSON.
   Values are escaped before insertion; scripts are local and inlined.
2. **Pipeline ↔ Elasticsearch.** The stack binds to localhost, has security and
   TLS disabled, and must never be exposed to an untrusted network.
3. **Repository ↔ GitHub.** The public repository exposes every committed file.
   `site/` is generated and gitignored; `docs/` design notes are not published.
4. **Contributor ↔ CI.** Pull requests run lint, compile, coverage, tests, and a
   secret-pattern check. They do not receive write tokens.

## Threats and mitigations

| Threat | Mitigation |
|---|---|
| Real logs or credentials committed | Synthetic-only policy, RFC 5737 addresses, review checklist, secret-pattern test |
| Secret leaked in a config or workflow | No secrets in the repo; `.env` ignored; GitHub secret scanning; rotate anything exposed |
| XSS from synthetic event fields | `esc()` before HTML insertion; the dashboard has no remote content |
| Elasticsearch exposed publicly | Bind to `127.0.0.1`; `SECURITY.md` warning; do not port-forward |
| Malicious or expensive rule | Rule review, lint metadata, bounded correlation fetch, CI tests |
| Dependency compromise | Pinned requirements, Dependabot, least-privilege CI token |
| Design or brand copied | Copyright notice, brand reservation, separate design licence if needed |
| False confidence in detection quality | `docs/evaluation.md` states the synthetic boundary; no precision/recall claims |

## Residual risk

- The lab intentionally disables Elasticsearch authentication and TLS.
- The design source is public; `pipeline.publish` hides it from the site, not from
  the repository.
- Synthetic telemetry cannot prove production precision or recall.
- The Quick Tunnel was removed; GitHub Pages is the only public host.

## Reporting

Follow [`SECURITY.md`](../SECURITY.md). Do not open a public issue for a
vulnerability, and do not include real telemetry or credentials in a report.

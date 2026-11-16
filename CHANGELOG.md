# Changelog

## Unreleased

- Replayed a combined five-index corpus: 1,381 real events from Windows Security,
  Sysmon, service/Kerberos/SMB XML, Linux auditd and auth, nginx, AWS CloudTrail,
  and Zeek. All 50 rules were evaluable; five matched.
- Added a sample-level benchmark: 6 TP, 0 FP, 1 FN across 16 labelled windows;
  precision 1.000, recall 0.857. The one miss is the SMB rule querying Security
  5140 while the capture logged 5145.
- Added Windows XML, auditd, syslog auth, nginx, and Zeek replay parsers and
  tests; added the CloudTrail mapper and tests.
- Added `docs/validation/labels.json`, the per-rule benchmark results, and the
  Fig. 4 TP/FP/FN, precision, recall, and alert-volume table. Each rule name
  expands to the labelled windows behind its counts.
- Replayed two real OTRF samples: 110 Windows Security events (one `Windows
  Event Log Cleared` match) and 118 richer Sysmon/Security events (two LSASS
  process-access matches and one event-log-cleared match). Recorded the first
  real true-positive candidates and the 25 rules that were not evaluable at the
  time.
- Added a 10× benign baseline run: 89,704 synthetic events, one low-severity SSH
  match, zero correlation alerts.
- Added `pipeline.replay` for OTRF/Mordor-style telemetry and a tested field
  mapping fixture.
- Added `pipeline.validation` and the synthetic per-rule results table.
- Added the real-telemetry validation runbook and results.
- Added `pipeline.publish` and a Pages boundary that excludes design notes,
  research, and the runbook from the public site.
- Added Dependabot, least-privilege CI, a threat model, a notice, and a
  high-confidence secret-pattern test.
- Added Lighthouse CI and a local documentation link check.
- Removed the Cloudflare Quick Tunnel; GitHub Pages is the public host.
- Made the verification stamp a filled solar-gold impression and fixed the
  coverage score from rendering as a gradient rectangle.
- Gave the Totality act a cool inner corona, soft streamers, limb detail, and
  orbital instrument rings.
- Made the Fig. 0 path of totality interactive: contact nodes and the data peak
  marker open their hour in the watch floor.
- Refined the chart with rounded column silhouettes and rounded caps.
- Attributed the project to Meruyert Oshayeva.
- Renamed the Docker containers to `penumbra-*`.

## 0.1.0 - 2026-11-16

- Penumbra detection lab: 50 Sigma rules, 8 correlations, 33 attack scenarios,
  three case reports, an interactive dashboard, and ATT&CK coverage.
- Corona and Umbra themes, a pinned Totality sequence, a phase ticker, a case
  reel, and a self-contained static build.

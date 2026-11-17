# Changelog

## Unreleased

- Reworked the mobile pipeline into a readable single-column stage list, squared
  up the validation tiles, and cleaned up the palette and IR controls on small screens.
- Added the After chapter to the command palette and scroll spy, fixed the keyboard
  help copy, linked the IR hint to the slider, and added Home/End scrubbing.
- Raised the smallest label sizes and added deeper dark-theme shadows so the new
  instrument plates stay separated from the Umbra page.
- Turned the IR timeline markers into non-interactive indicators that pulse as
  the scrub position crosses them, leaving the play control as the only trigger.
- Fixed the Umbra orbit core so the project count stays visible, and locked the
  roadmap orbit palette and node dots across both themes.
- Removed the former project name from the roadmap prose, data, and dashboard.
- Switched pipeline artifact chips to a deep ink surface and removed the pale
  hover fill and lift jitter from the IR timeline markers.
- Rebuilt the validation benchmark detail as a dark instrument plate with warm
  metric chips and window cards, and gave the proof drawer readable dark styling.
- Added an orbiting sweep, concentric rings, core glow, and starfield texture to
  the roadmap orbit, plus a brighter moving scan and shimmer on the IR timeline.
- Gave every new detail pane a grid texture, animated gradient rule, and depth
  shadow. Query boxes now use a deep ink/teal surface. Fixed the hunt/orbit hover
  jump and made the IR scrubber draggable and keyboard-operable.
- Added scanning validation, radar blips, a scrubable IR timeline, twin cloud
  packets, an orbiting roadmap moon, and staggered response-flow pulses.
- Extended guided reading to fifteen steps covering response, hunting, validation,
  the IR casebook, the cloud hand-off, and the roadmap. Added focusable validation
  tiles with a live status readout and arrow-key navigation to the tab groups.
- Moved the response flow, hunt radar, IR timeline, cloud bridge, roadmap orbit,
  and validation matrix onto dark instrument plates, matching the Fig. 1 chart's
  contrast instead of leaving them as pale cards.
- Compacted hunting and roadmap into side-by-side radar/orbit layouts, made the
  validation matrix a full-width 17-column strip, and added count-up motion to
  the instrument totals.
- Added sunburst headers, corona halos, coloured detection nodes, hover light,
  and per-project orbit accents. The palette stays inside Corona/Umbra.
- Gave each instrument its own eclipse accent, soft corona glow, staggered
  detail reveal, and colour on the flow, radar, timeline, bridge, orbit, and
  validation matrix. The accents stay within the existing Corona/Umbra palette.
- Added motion to the new instruments: a response flow, a hunt radar, an IR
  timeline scrubber, a cloud hand-off bridge, and a project orbit. All respect
  reduced-motion and keep a keyboard-accessible selector.
- Rebuilt the new sections as compact selector/detail instruments with light
  surfaces, chips, and one detail pane, matching the watch floor and case chain.
  Removed the repeated validation sample cards from the visible layout.
- Distributed the new evidence views across the chapters: response in
  Instruments, hunting in Umbra, validation in Corona, IR close-outs in Eclipses,
  and the roadmap plus Apsis cloud hand-off in a short After chapter. This
  removes the crowded bottom workspace and keeps each section to one job.
- Made the GitHub repository private while the dashboard integration pass is in
  progress.
- Added the Penumbra response layer: `pipeline.triage` turns 50 alerts into 27
  incidents, selects one of six playbooks, and records 78 recommended actions
  with 85% containment coverage. The engine is a dry run with no external API
  calls.
- Added the cloud detection pack for Apsis: root policy attachment, root user
  creation, and CloudTrail tampering. Two detections fire on the synthetic
  corpus; one is waiting for telemetry.
- Added `cases/ir.json` and `pipeline.casebook` to render three structured IR
  close-outs with metrics, containment, eradication, recovery, communication,
  evidence, lessons, and open questions.
- Added the response, cloud pack, and IR casebook data as interactive sections in
  their natural chapters: response in Instruments, cloud hand-off in After, and
  IR close-outs in Eclipses.
- Added the first Penumbra extension: four hypothesis-driven hunts over the
  deterministic corpus, with queries, evidence, verdicts, and detection changes.
  Added `pipeline.hunts`, `hunts/README.md`, `hunts/results.json`, and tests.
- Added the three-project roadmap to the dashboard: Penumbra, Apsis, and a network threat-hunting lab. Added `docs/roadmap.json` and
  `docs/roadmap.md`.
- Published the public dashboard to GitHub Pages at
  <https://meruyert5.github.io/penumbra/> and wired the live URL into the README
  and handoff notes.
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

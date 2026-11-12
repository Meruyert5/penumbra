# Signal Foundry: Expansion Design

Date: 2026-11-11
Status: approved for implementation

## Intent

Turn the existing Detection Forge prototype into a portfolio project that shows the whole detection-engineering loop at a scale a reviewer can explore: broad telemetry, a real rule library, correlation, ATT&CK coverage, case work, and a frontend that demonstrates product judgment instead of template output.

## Title

**Signal Foundry.** A foundry turns raw material into something useful. This project turns raw telemetry into defensible alerts. The name keeps the workshop metaphor without competing with the well-known DetectionLab repository.

Tagline: *Detection engineering, from raw telemetry to defensible alerts.*

## Goals

- 35+ Sigma rules across Windows, Linux, web, cloud, and network telemetry.
- 20+ deterministic attack scenarios and 2,000+ synthetic events.
- 8 correlation specs with distinct-value support for password spraying.
- 30+ priority ATT&CK techniques with an honest gap list.
- A dependency-free dashboard with a guided investigation, animated signal scope, interactive timeline, coverage matrix, case files, and theme switch.
- 45+ tests, CI drift checks, and a reproducible live run.
- A custom icon and consistent brand across README, dashboard, and docs.

## Non-goals

- Production-grade Elasticsearch security.
- Real malware execution.
- A React or build-step frontend. The dashboard must work from `file://`, GitHub Pages, and offline.
- Claiming production precision from synthetic telemetry.

## Visual direction

The current dashboard uses the default near-black plus acid-green SOC palette. The redesign moves to a foundry palette: deep petrol, bone text, brass, oxidized teal, and clay. Display type is an editorial serif; body type is a humanist sans; evidence stays monospaced.

Layout is asymmetric and forensic: a live signal scope at the top, a ruled detection ledger, an evidence rail, and a full-width ATT&CK matrix. Cards are used only where grouping matters. Motion is orchestrated on load and on user action, with `prefers-reduced-motion` respected.

## Architecture changes

- `dashboard/` holds the HTML template, CSS, JavaScript, and icon as editable source.
- `pipeline/report.py` builds a compact JSON payload and injects it into the template.
- `pipeline/heatmap.py` renders the coverage SVG from the same deduplicated tile data.
- `pipeline/labgen.py` gains event helpers for registry, file, DNS, network, cloud, and security events.
- `pipeline/correlate.py` gains optional distinct-value thresholds.
- `cases/cases.json` provides case metadata for the dashboard.

## Risks

- Sigma field mapping differs by logsource. Each new rule is compiled and tested; Windows rules use the ECS pipeline, other sources use ECS names directly.
- A large dashboard payload can slow first paint. The report trims evidence to three events per alert and computes aggregates in Python.
- More rules can create noisy alerts. Baseline noise is generated deliberately and tests assert that benign scenarios stay quiet.

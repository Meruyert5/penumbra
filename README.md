# Detection Lab

Detection-as-code for a SOC analyst workflow: **Sigma rules → Elasticsearch EQL → triage → written case reports**, with a reproducible telemetry lab so every result in this repo can be regenerated on a fresh machine.

The point of this project is not the dashboard. It is the full loop a Tier 1/Tier 2 analyst actually runs: collect telemetry, write and tune detections, investigate what fires, decide true/false positive, document it, and measure coverage.

---

## What this repo demonstrates

| Skill | Where to look |
|---|---|
| Detection engineering with Sigma | `rules/sigma/` (11 rules, ATT&CK tagged) |
| Backend translation and field mapping | `pipeline/compile.py`, pySigma ECS pipeline for Windows |
| SIEM operations (Elasticsearch/Kibana) | `docker-compose.yml`, `config/`, `pipeline/ingest.py` |
| Threshold/correlation logic | `correlations/`, `pipeline/correlate.py` |
| Alert triage and reporting | `pipeline/detect.py`, `cases/` |
| ATT&CK coverage measurement and gap analysis | `docs/attck-coverage.md` (generated) |
| Tuning against false positives | `docs/tuning.md` |
| Testing detections like software | `tests/` (25 tests, runs in CI) |

**Coverage:** 11 detections across 12 ATT&CK techniques and 7 tactics — see [`docs/attck-coverage.md`](docs/attck-coverage.md), which also lists the priority techniques still uncovered.

---

## Architecture

```
                    ┌──────────────────────────────┐
  Windows VM  ──────┤ Winlogbeat (Sysmon, Security,│──┐
  (optional)        │ System, PowerShell)          │  │
                    └──────────────────────────────┘  │
                                                      ▼
  pipeline/labgen.py ──► lab/logs/*.ndjson ──► Filebeat ──► Elasticsearch
  (synthetic, ECS)                                        (single node)
                                                      │
  rules/sigma/*.yml ──► pipeline/compile.py ──► EQL ──► pipeline/detect.py
        (source of truth)      │                            │
                               └──► rules/compiled/rules.json│
                                                             ▼
                                    correlations/*.yml ──► alerts/alerts.json
                                                             │
                                                             ▼
                                                    alerts/summary.md
                                                    cases/*/report.md
```

Two ingestion paths exist on purpose:

* **Synthetic** (`pipeline/labgen.py`) — deterministic, CI-friendly, no VM required. Every event is generated from a named scenario, so a reviewer can reproduce an alert exactly.
* **Real** (`config/winlogbeat.yml`) — point a Windows VM with Sysmon at the same Elasticsearch and switch `config/logsource_map.yml` to the `logs-windows.*` data streams.

---

## Quickstart

Requires Python 3.11 (pySigma does not support 3.14 yet), Docker Desktop, and ~4 GB of free RAM.

```powershell
# 1. Python environment
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt

# 2. Start Elasticsearch + Kibana
docker compose up -d
# Kibana: http://localhost:5601  (security is disabled: lab only)
#
# Filebeat is optional and only starts with the beats profile:
#   docker compose --profile beats up -d
# The default path below indexes telemetry directly with pipeline/ingest.py,
# so the same events are not loaded twice.

# 3. Generate synthetic telemetry and index it
.\.venv\Scripts\python.exe -m pipeline.labgen --scenario all
.\.venv\Scripts\python.exe -m pipeline.ingest --reset

# 4. Run the detections
.\.venv\Scripts\python.exe -m pipeline.detect --hours 24
# -> alerts/summary.md and alerts/alerts.json

# 5. Inspect an alert in Kibana
#    Create a data view for lab-* and paste any query_kql from
#    rules/compiled/rules.json into Discover.
```

Offline, with no Docker:

```powershell
.\.venv\Scripts\python.exe -m pytest          # rule lint, compilation, correlation, labgen
.\.venv\Scripts\python.exe -m pipeline.lint   # metadata quality gate
.\.venv\Scripts\python.exe -m pipeline.compile
.\.venv\Scripts\python.exe -m pipeline.coverage
```

`scripts/demo.ps1` runs the offline pipeline end to end.

---

## Detections

| Rule | Level | Technique | Source |
|---|---|---|---|
| Suspicious Process Access to LSASS | critical | T1003.001 | Sysmon EID 10 |
| PowerShell Encoded Command Execution | high | T1059.001 | Sysmon EID 1 |
| Certutil Used to Download or Decode a Payload | high | T1105 | Sysmon EID 1 |
| Suspicious Service Installed From User-Writable Path | high | T1543.003 | System EID 7045 |
| Windows Defender Real-Time Protection Disabled | high | T1562.001 | Defender EID 5001/5010/5012 |
| Scheduled Task Created via Schtasks | medium | T1053.005 | Sysmon EID 1 |
| SSH Failed Password Authentication | low | T1110.001 | Linux auth log |
| New Local User Account Created | medium | T1136.001 | Linux auth log |
| Cron Job Executing Remote Content | high | T1053.003 | Linux cron |
| PHP File Uploaded to Web Accessible Directory | high | T1505.003 | nginx access log |
| Web Request to Common Web Shell Parameter | medium | T1505.003 | nginx access log |

Plus two correlations: SSH brute force (8 failures / 5 min / source IP) and web shell command burst (5 requests / 2 min / source IP).

Every rule carries `description`, `references`, `falsepositives`, `level`, and ATT&CK tags. That metadata is enforced by `pipeline/lint.py`, so a rule without tuning notes or a technique mapping fails CI.

---

## Design decisions

**Sigma is the source of truth, not the SIEM query.** Rules are portable; the compiled EQL/KQL under `rules/compiled/` is a build artifact and is regenerated by CI. This is the same split used by mature detection teams and means the repo is not locked to one vendor.

**Threshold logic lives outside Sigma.** Sigma's aggregation support is inconsistent across backends, so base rules stay single-event and portable, and `pipeline/correlate.py` handles "N events in T seconds" with a sliding window. This also makes the correlation testable without a SIEM.

**Synthetic telemetry is labelled synthetic.** `pipeline/labgen.py` produces deterministic ECS-shaped events from named attack scenarios. It is not a substitute for real logs — it exists so results are reproducible and reviewable. The README and the generator both say so.

**Field mapping is explicit.** Windows rules use Sigma-native field names and are passed through pySigma's ECS pipeline, so `Image` becomes `process.executable.caseless` and `EventID` becomes `event.code`. The `.caseless` variants are built by Winlogbeat processors (see `config/winlogbeat.yml`) because case-insensitive path matching is a real-world requirement, not a nicety.

**Tuning is documented, not implied.** `docs/tuning.md` records the false positives found in the lab, the change made, and the effect. A detection without a tuning history is an untested hypothesis.

---

## Case reports

| Case | Scenario | Verdict |
|---|---|---|
| [001 — SSH brute force](cases/case-001-ssh-bruteforce/report.md) | 14 failed logins then a success from 203.0.113.44 | True positive, attempted intrusion |
| [002 — Multi-stage intrusion](cases/case-002-multi-stage-intrusion/report.md) | Macro → encoded PowerShell → certutil → LSASS → persistence | True positive, credential theft and persistence |

Each report follows the same structure: summary, timeline, evidence, scope, ATT&CK mapping, verdict, containment, and lessons learned.

---

## Repository layout

```
rules/sigma/            Sigma rules (source of truth)
rules/compiled/         Generated EQL/KQL + metadata (committed for review)
correlations/           Threshold correlation specs
pipeline/               compile, lint, coverage, labgen, ingest, detect, correlate
config/                 Elasticsearch template, Filebeat, Winlogbeat, index routing
lab/logs/               Generated telemetry (gitignored)
alerts/                 Detection output (gitignored)
cases/                  Analyst case reports
docs/                   Architecture, runbook, tuning log, ATT&CK coverage
tests/                  pytest suite
scripts/                Windows convenience scripts
```

---

## Using real telemetry

1. Install Sysmon on the Windows VM (SwiftOnSecurity or Olaf Hartong config).
2. Copy `config/winlogbeat.yml`, set `output.elasticsearch.hosts` to the lab machine's LAN IP.
3. `.\install-service-winlogbeat.ps1` then `Start-Service winlogbeat`.
4. In `config/logsource_map.yml`, point `windows` at:
   `logs-windows.sysmon_operational-*`, `logs-windows.security-*`, `logs-windows.system-*`.
5. Recompile and re-run: `python -m pipeline.compile && python -m pipeline.detect`.

Verify the fields your rules depend on actually exist before trusting a "no alerts" result:

```powershell
curl.exe "http://localhost:9200/logs-windows.sysmon_operational-*/_mapping" | Select-String "executable.caseless"
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `PUT _index_template` → 400 `can't merge a non object mapping` | Elasticsearch reads dots in field names as object paths, so `process.executable` and `process.executable.caseless` collide | `"subobjects": false` on `process` / `process.parent` (already in `config/index-template.json`) |
| `DELETE lab-*` → 400 `Wildcard expressions or all indices are not allowed` | ES 8 sets `action.destructive_requires_name` | delete named indices; `pipeline/ingest.py` does this |
| Detections report `Unknown index [lab-windows]` | ingestion never created the index, so every EQL search fails | fix ingestion first, confirm with `GET _cat/indices/lab-*` |
| `0 rule matches` but events are indexed | field mapping mismatch (most often a missing `.caseless` field) | `GET lab-*/_mapping` and compare with `docs/architecture.md` |

## Limitations

* Single-node Elasticsearch with security disabled. This is a lab, not a production deployment.
* Synthetic telemetry covers the detections in this repo; it does not model a real enterprise baseline, so precision figures here are illustrative, not production measurements.
* Correlation runs in-process over a bounded event fetch (10k events). Fine for the lab, wrong for production scale.
* 10 of 20 priority techniques are covered; the remaining 10 are listed in `docs/attck-coverage.md` as an explicit gap analysis.

## Roadmap

- [ ] Add the uncovered priority techniques (T1055, T1071.001, T1078, T1486)
- [ ] Kibana saved objects: detection rule + dashboard as code
- [ ] Wire `pipeline/detect.py` into an n8n or webhook notifier for a simulated on-call flow
- [ ] Add a PCAP/Zeek source and one network detection
- [ ] Publish a blog-style write-up of case 002

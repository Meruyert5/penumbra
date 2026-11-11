# Architecture

## Data flow

```
labgen.py ──► lab/logs/{windows,linux,web}.ndjson
                    │
                    ▼
              Filebeat (filestream)          Winlogbeat (Windows VM, optional)
                    │                                   │
                    └──────────────► Elasticsearch ◄────┘
                                          │
rules/sigma/*.yml ──► compile.py ──► EQL ─┘
        │                    │
        │                    └──► rules/compiled/rules.json
        │
        └──► coverage.py ──► docs/attck-coverage.md

detect.py ──► EQL search per rule ──► alerts/alerts.json
     │
     └──► correlate.py (thresholds) ──► alerts/summary.md
```

## Components

| Component | Responsibility | Fails how? |
|---|---|---|
| `pipeline/labgen.py` | Deterministic ECS telemetry from named attack scenarios | Only writes files; no network |
| `pipeline/compile.py` | Sigma → EQL/KQL, index routing, metadata extraction | CI fails on compile error |
| `pipeline/lint.py` | Metadata quality gate (UUID, level, ATT&CK tag, description, FPs) | CI fails on error |
| `pipeline/coverage.py` | ATT&CK matrix and gap list | CI fails if docs are stale |
| `pipeline/ingest.py` | Index template + bulk load | Explicit message if Elasticsearch is down |
| `pipeline/detect.py` | Run EQL, collect matches, write summary | Per-rule errors are captured, not swallowed |
| `pipeline/correlate.py` | Sliding-window thresholds over events | Pure function, unit tested |

## Field mapping

Windows rules are written against Sigma-native Sysmon names and translated by pySigma's `ecs_windows()` pipeline. Non-Windows sources are already ECS-shaped in this lab, so their rules use ECS names directly.

| Sigma field | ECS field (Winlogbeat 8) | Notes |
|---|---|---|
| `EventID` | `event.code` | keyword; compare as string |
| `Channel` | `winlog.channel` | added by the pipeline for service-based rules |
| `Image` | `process.executable.caseless` | lowercase copy, built by Winlogbeat processors |
| `ParentImage` | `process.parent.executable.caseless` | same |
| `CommandLine` | `process.command_line` | mapped as `wildcard` in the lab template |
| `TargetImage` | `winlog.event_data.TargetImage` | Sysmon EID 10, unmapped passthrough |
| `GrantedAccess` | `winlog.event_data.GrantedAccess` | Sysmon EID 10 |
| `ServiceName` / `ImagePath` | `winlog.event_data.*` | System EID 7045 |

The `.caseless` fields are not optional. Sysmon reports `C:\Windows\SYSTEM32\...` and `C:\Windows\System32\...` interchangeably, so case-sensitive matching produces silent false negatives. `config/winlogbeat.yml` copies and lowercases the two process paths before indexing.

## Index routing

`config/logsource_map.yml` maps a Sigma `logsource.product` to one or more index patterns. The synthetic lab writes `lab-windows`, `lab-linux`, and `lab-web`. Real deployments point the same entries at `logs-windows.*`, `logs-system.*`, and `logs-nginx.*` data streams — no rule changes required.

## Why EQL, and why also KQL

* **EQL** is used by `detect.py` because it expresses process/file/network event matching cleanly and is the native query language for Elastic's detection engine. It is what an Elastic-based SOC would actually deploy.
* **KQL/Lucene** is emitted alongside it because analysts triage in Kibana Discover, and a rule that cannot be pasted into Discover is a rule nobody will verify by hand.

Both are generated from the same Sigma source, so they cannot drift.

## Data model assumptions

Every event has:

* `@timestamp` (ISO-8601 UTC, millisecond precision)
* `event.category`, `event.type`, `event.dataset`, `event.module`
* `host.name`, and `host.os.type`
* a source-specific payload (`process.*`, `winlog.*`, `source.ip`, `url.*`, `http.*`)

`pipeline/detect.py` queries with `timestamp_field: "@timestamp"`, which is the one EQL-specific requirement.

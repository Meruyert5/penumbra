# Evaluation and validation

This document states the evidence behind Penumbra, what the current run does and
does not prove, and how the lab should be extended before anyone treats it as a
detection benchmark.

## Scope

Penumbra is a **portfolio detection lab**. It is designed to make the path from
Sigma source to Elasticsearch EQL/KQL, correlation, triage, and analyst reporting
inspectable and reproducible. It is not a production detection product, a vendor
comparison, or a source of real incident telemetry.

The committed dashboard represents one deterministic run: 9,223 synthetic events
across Windows, Linux, web, AWS CloudTrail, and network flow over 24 hours. The
run contains 33 attack scenarios plus a benign baseline, 50 Sigma rules, 8
correlation specs, and three case reports. About 8,280 of the events come from the
benign baseline loop; raw volume is therefore not the main gap. Independent
labels, source diversity, and real noise are.

### Corpus roles

| Corpus | Role | Why it exists |
|---|---|---|
| 9,223-event scenario run | Main dashboard and case corpus | Deterministic, fast, contains 33 labelled attack scenarios plus baseline |
| 89,704-event benign baseline | False-positive and scale test | 10× baseline; no attack scenarios; cannot replace the case corpus |
| 1,381 real multi-source events | Field-behaviour and small-sample benchmark | Windows, Linux, web, cloud, and network telemetry across 16 labelled windows |

The 9,223 run is not pointless. It is the only corpus with attack scenarios,
case narratives, and a deterministic dashboard. The 89,704 run is better for
volume and benign-noise comparison, but it has no attacks and cannot drive the
investigations. The dashboard now shows both separately.

## What the current evidence proves

| Claim | Evidence | Status |
|---|---|---|
| Every rule has the required metadata and ATT&CK tags | `python -m pipeline.lint` | Verified by CI |
| Sigma source compiles to EQL and KQL | `python -m pipeline.compile --check` | Verified by CI |
| Generated coverage and heatmap match the rules | `python -m pipeline.coverage --check`, `pipeline.heatmap`, `git diff --exit-code` | Verified by CI |
| The scenario corpus is deterministic | `pipeline.labgen --scenario all` with a fixed seed and base time | Verified by tests |
| Known attack scenarios produce expected events | `tests/test_labgen.py` and scenario tests | Verified for committed scenarios |
| The benign baseline does not trip the correlation thresholds | `tests/test_labgen.py::test_baseline_is_benign` | Verified for a small baseline |
| The dashboard is assembled from the run data | `tests/test_report.py` and `pipeline.report` | Verified |
| The page meets the published accessibility contract | Lighthouse and manual review | Verified for the built page |
| Per-rule synthetic results | [docs/validation/synthetic-run.md](validation/synthetic-run.md) | Generated from the committed run; not precision or recall |
| Real multi-source samples | [docs/validation/real-telemetry-results.md](validation/real-telemetry-results.md) | 1,381 real events across five indices; 5 rules matched |
| Per-rule benchmark | [docs/validation/benchmark.md](validation/benchmark.md) | 6 TP, 0 FP, 1 FN across 16 labelled windows; precision 1.000, recall 0.857 |
| Large benign baseline | [docs/validation/large-benign-results.md](validation/large-benign-results.md) | 89,704 synthetic benign events, 1 low-severity match, 0 correlations |

## What the current evidence does not prove

* **Stable precision and recall.** A small-sample benchmark now exists: 6 true
  positives, 0 false positives, and 1 false negative across 16 labelled windows.
  But 44 rules had no signal, one false negative is too few for a stable recall
  estimate, and the samples were selected opportunistically rather than randomly.
* **Production noise tolerance.** The benign baseline is intentionally small. It
  does not model shift changes, software deployment, administrative scripts,
  scanners, backup jobs, or the long tail of enterprise activity.
* **Breadth of telemetry.** There is no EDR memory/API telemetry, no macOS, no
  Kubernetes audit log, no identity-provider log, no proxy/TLS metadata, and no
  email gateway data. Windows, Linux, web, AWS CloudTrail, and flow are the only
  modelled sources.
* **Coverage completeness.** The "45 of 45 priority techniques" figure is a
  project-defined priority list. It is not a claim of complete MITRE ATT&CK
  coverage or of detection efficacy for those techniques.
* **Detection decay.** There is no scheduled replay against changing real data, so
  the repository cannot show that a rule still fires after a field rename, a
  product update, or a logging-policy change.

These limits are deliberate and are repeated in the README. The value of the lab
is reproducibility and reviewability, not a performance claim.

## Why synthetic telemetry

Synthetic generation makes the run safe to share, fast enough for CI, and exactly
reproducible. Microsoft's detection research describes synthetic attack logs as a
complement to lab simulation, useful for early-stage design and coverage
expansion, while stressing that realism and benign-versus-malicious separation
still require validation. The same boundary applies here: the generator is a
fixture for the pipeline, not a substitute for recorded telemetry.

The corpus is deliberately committed as code, not as large log files. The event
count and timestamps are stable, the addresses use RFC 5737 documentation ranges,
and no customer data is present.

## External validation plan

The next evidence step is to replay public real telemetry and record per-rule
outcomes. The following sources are suitable because they are used by detection
teams and research groups and include labelled attack activity or benign data.

| Source | What it adds | Proposed use |
|---|---|---|
| [OTRF Security Datasets](https://github.com/OTRF/Security-Datasets) | Real adversary and benign datasets across platforms, mapped to ATT&CK | Replay a sample through the ingest and detect path; record true positives and missed events per rule |
| [Splunk Attack Data](https://github.com/splunk/attack_data) | Large curated attack dataset with metadata | Use attack windows as an independent positive set for Windows and Sysmon rules |
| [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) | Portable technique tests that generate real host telemetry | Execute a bounded set in an isolated VM, capture Sysmon, and compare the rule output |
| [Elastic detection rules](https://github.com/elastic/detection-rules) | Production rule and test conventions | Compare rule structure, test expectations, and field assumptions |
| [Splunk Attack Range](https://github.com/splunk/attack_range) | Instrumented lab orchestration | Use as an alternative to the synthetic path when a full VM range is available |

The combined real-data step is complete: 1,381 events from Windows Security,
Sysmon, service/Kerberos/SMB XML, Linux auditd and auth, nginx, AWS CloudTrail,
and Zeek were replayed into five indices. Sixteen reviewed windows produced 6
sample-level true positives, 0 false positives, and 1 false negative. The SMB
rule queries Security 5140 while the capture logged ADMIN$ access as 5145. Five
rules scored precision 1.000 and recall 1.000; the SMB rule scored recall 0.000.
See [Real-telemetry replay results](validation/real-telemetry-results.md) and the
[Benchmark metrics](validation/benchmark.md). A separate 89,704-event synthetic
benign baseline produced one low-severity SSH match; see
[Large benign baseline](validation/large-benign-results.md).

### Metrics to record

For each rule and correlation:

* true positives, false positives, and false negatives in the replayed window;
* precision, recall, and alert volume per 24 hours;
* first-seen and last-seen timestamps versus the labelled attack window;
* field dependencies that fail silently, especially `.caseless` process fields;
* tuning changes made after the replay, with the reason and the new result.

### Acceptance criteria

A rule is considered validated for this lab when:

1. it fires on at least one independent positive sample;
2. it does not fire on the benign sample outside the labelled attack window;
3. its required fields exist in the target index mapping;
4. the result is recorded in the rule's tuning notes and in this document.

These are lab acceptance criteria, not production service-level objectives.

## Reproduce the current run

```powershell
python -m pipeline.labgen --scenario all --base-time 2026-11-11T12:30:00Z
python -m pipeline.ingest --reset
python -m pipeline.compile
python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z
python -m pipeline.report
python -m pipeline.publish
```

Without Docker, the deterministic checks still run:

```powershell
python -m pytest
python -m pipeline.lint
python -m pipeline.compile --check
python -m pipeline.coverage --check
python -m pipeline.heatmap
```

## Status and next steps

| Item | Status |
|---|---|
| Deterministic synthetic run | Done |
| Benign baseline | Done, small |
| Per-rule false-positive suite | Partial |
| External real-telemetry replay | Done: 1,381 events across five indices, 16 labelled windows |
| Larger benign baseline | Done: 89,704 synthetic events, 1 low-severity match |
| Precision / recall table | Done: 6 TP, 0 FP, 1 FN; precision 1.000, recall 0.857 |
| Field-mapping gap review | Done: 0 not evaluable, 0 missing-index, 0 missing-field errors |
| Atomic Red Team Sysmon capture | Not started; needs an isolated Windows VM |
| Scheduled detection-decay check | Not started |

Roadmap items that close these gaps are tracked in the README. The most valuable
next change is a benign replay and a label manifest, because that turns the first
true-positive candidate into a measured result.

## Sources

* Microsoft Security Blog, "Accelerating detection engineering using AI-assisted
  synthetic attack logs generation", 12 May 2026.
  <https://www.microsoft.com/en-us/security/blog/2026/05/12/accelerating-detection-engineering-using-ai-assisted-synthetic-attack-logs-generation/>
* OTRF Security Datasets. <https://github.com/OTRF/Security-Datasets>
* Splunk Attack Data. <https://github.com/splunk/attack_data>
* Atomic Red Team. <https://github.com/redcanaryco/atomic-red-team>
* Elastic Detection Rules. <https://github.com/elastic/detection-rules>
* Splunk Attack Range. <https://github.com/splunk/attack_range>
* Cisco Talos EvidenceForge, synthetic log generation research.
  <https://github.com/Cisco-Talos/EvidenceForge/blob/main/docs/design/synthetic-log-generation-research.md>

Accessed 16 November 2026.

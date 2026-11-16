# Real-telemetry replay results

Two public OTRF samples have been replayed end to end through the same ingest and
detect path as the synthetic run. They are deliberately small and are not a
benchmark. A separate 89,704-event synthetic benign baseline is recorded in
[Large benign baseline](large-benign-results.md).

## Sample A — Windows Security 110 events

| Field | Value |
|---|---|
| Dataset | `psh_powershell_httplistener_2020-11-0204130683.json` |
| Source | <https://github.com/OTRF/Security-Datasets> |
| Label | Malicious (Atomic Red Team capture) |
| Raw events | 110 |
| Window | 2020-11-02T04:12:58Z to 04:13:05Z |
| Rules evaluated | 50 |
| Correlations evaluated | 8 |
| Rules not evaluable | 25 (20 missing index, 5 missing field) |
| Evaluation errors | 28 (including 3 correlation fetches) |

| Rule | Level | Technique | Matches | Host | Verdict |
|---|---|---:|---:|---|---|
| Windows Event Log Cleared | high | T1070.001 | 1 | WORKSTATION5 | True-positive candidate |

The sample's first event is a real Windows Security **1102**: the audit log was
cleared. The rule matched it. That is a credible true positive for this labelled
sample, not a precision or recall measurement.

## Sample B — richer Sysmon / Security capture, 118 events

| Field | Value |
|---|---|
| Dataset | `cmd_lsass_memory_dumpert_syscalls_2020-10-1822561997.json` |
| Source | <https://github.com/OTRF/Security-Datasets> |
| Label | Malicious (Atomic Red Team capture) |
| Raw events | 118 |
| Window | 2020-10-18T10:56:18Z to 2020-10-19T02:56:05Z |
| Rules evaluated | 50 |
| Correlations evaluated | 8 |
| Rules not evaluable | 25 (20 missing index, 5 missing field) |
| Evaluation errors | 28 (including 3 correlation fetches) |

| Rule | Level | Technique | Matches | Host | Verdict |
|---|---|---:|---:|---|---|
| Suspicious Process Access to LSASS | critical | T1003.001 | 2 | WORKSTATION5 | True-positive candidate |
| Windows Event Log Cleared | high | T1070.001 | 1 | WORKSTATION5 | True-positive candidate |

This sample is much richer than Sample A: it contains Sysmon process access,
process create, file create, registry, image load, network, and Security events.
The normalizer was extended to map `SourceImage`, `TargetImage`, `GrantedAccess`,
`TargetObject`, and the common `winlog.event_data.*` fields. That let the LSASS
process-access rule evaluate and match two real events.

## Commands

```powershell
python -m pipeline.replay `
  --source ..\Security-Datasets\datasets\atomic\windows\credential_access\host\cmd_lsass_memory_dumpert_syscalls_2020-10-1822561997.json `
  --out lab\replay-rich --file windows --label malicious

python -m pipeline.ingest --logs lab\replay-rich --reset
python -m pipeline.detect --hours 24 --end 2020-10-19T03:00:00Z --out lab\replay-rich-results
```

The data was not committed. The replay alerts stay in `lab/replay-rich-results/`,
which is gitignored.

## What these runs prove

- The OTRF/Mordor normalizer works end to end on real Windows Security and Sysmon
  telemetry.
- The index template accepts the normalized ECS fields, including `event.code`,
  `process.*`, `registry.path`, and `winlog.event_data.*`.
- Two Sigma rules compiled to EQL can fire on public real telemetry, not only the
  synthetic corpus.
- A richer sample materially changes the evaluation: Sample A could not evaluate
  the LSASS rule because its event types were absent; Sample B could, and the rule
  matched twice.

## What these runs do not prove

- **Precision:** the samples are labelled malicious; there is no benign real-data
  set in these runs. The 89,704-event benign baseline is synthetic.
- **Recall:** the datasets do not contain a complete expected-rule manifest, so
  missed detections cannot be counted.
- **Coverage of the rule library:** 25 rules were not evaluable because the
  samples lack the relevant index or fields. Missing indices account for 20
  Linux, web, cloud, and network rules; missing fields account for 5 service,
  Kerberoasting, SMB, and registry rules. Three correlation fetches also failed
  on the missing indices. The 28 total errors are an evaluation-coverage gap, not
  28 false negatives.
- **Production behaviour:** 110 and 118 events are not enterprise baselines.

## Findings to act on

1. Predefine the common `winlog.event_data.*` fields in the index template, or
   treat a missing mapped field as “not evaluable” rather than a rule error.
2. Add a real benign sample and record false positives against it.
3. Replay one dataset per source family (Windows Security, Sysmon, Linux, AWS)
   before claiming cross-source validation.
4. Build a label manifest with the attack window and expected techniques so
   TP/FP/FN can be computed rather than inferred.
5. Use a larger capture for the next comparison; these are deliberately small,
   legal-to-share samples.

## Source and licence

OTRF Security-Datasets is a public project under the terms in its repository.
The datasets are referenced by URL and are not redistributed here. Only the
normalized results, commands, and observations are recorded.

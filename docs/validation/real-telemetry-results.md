# Real-telemetry replay results

This is the first real-data result for Penumbra. It is deliberately small and
should not be read as a benchmark.

## Run

| Field | Value |
|---|---|
| Date | 2026-11-16 |
| Dataset | OTRF Security-Datasets, `datasets/atomic/windows/execution/host/psh_powershell_httplistener_2020-11-0204130683.json` |
| Source | <https://github.com/OTRF/Security-Datasets> |
| Label | Malicious (Atomic Red Team capture) |
| Raw events | 110 |
| Replay window | 2020-11-02T04:12:58Z to 2020-11-02T04:13:05Z |
| Index | `lab-windows` |
| Elasticsearch | 8.15.3, single node, local Docker |
| Rules evaluated | 50 |
| Correlations evaluated | 8 |

The data was not committed. It lives outside the repository and is normalized by
`pipeline.replay`. The synthetic dashboard data was left untouched; the replay
alerts were written to `lab/replay-results/`.

## Commands

```powershell
python -m pipeline.replay `
  --source ..\Security-Datasets\datasets\atomic\windows\execution\host\psh_powershell_httplistener_2020-11-0204130683.json `
  --out lab\replay --file windows --label malicious

python -m pipeline.ingest --logs lab\replay --reset
python -m pipeline.detect --hours 24 --end 2020-11-02T05:00:00Z --out lab\replay-results
```

## Result

| Rule | Level | Technique | Matches | Host | Verdict |
|---|---|---:|---:|---|---|
| Windows Event Log Cleared | high | T1070.001 | 1 | WORKSTATION5 | True-positive candidate |

The dataset's first event is a real Windows Security **1102** event: the audit
log was cleared. The rule matched that event on `WORKSTATION5`. Because the
dataset is a labelled Atomic Red Team capture, this is a credible true positive
for this sample. It is not a precision or recall measurement.

## What this proves

- The OTRF/Mordor normalizer works end to end on a real Windows Security sample.
- The index template accepts the normalized ECS fields, including `event.code`.
- A Sigma rule compiled to EQL can fire on public real telemetry, not only the
  synthetic corpus.
- The report path can be pointed at a separate output directory, so validation
  does not overwrite the portfolio dashboard.

## What it does not prove

- **Precision:** there is no benign sample in this run, so the false-positive
  rate is unknown.
- **Recall:** the dataset does not contain a complete expected-rule manifest, so
  missed detections cannot be counted.
- **Coverage of the rule library:** 28 rules were not evaluable because the
  sample does not contain their index or fields. The errors included missing
  `lab-linux`, `lab-web`, `lab-cloud`, and `lab-network` indices, plus absent
  `winlog.event_data` fields such as `ServiceName`, `ImagePath`, `ShareName`,
  `TicketEncryptionType`, and `GrantedAccess`.
- **Production behaviour:** one 110-event capture is not an enterprise baseline.

## Findings to act on

1. Predefine the common `winlog.event_data.*` fields in the index template, or
   treat a missing mapped field as “not evaluable” rather than a rule error.
2. Add a benign OTRF or Splunk Attack Data window and record false positives.
3. Replay one dataset per source family (Windows Security, Sysmon, Linux, AWS)
   before claiming cross-source validation.
4. Keep a small label manifest with the attack window and expected techniques so
   TP/FP/FN can be computed rather than inferred.

## Source and licence

OTRF Security-Datasets is a public project under the terms in its repository.
The dataset is referenced by URL and is not redistributed here. Only the
normalized result, commands, and observations are recorded.

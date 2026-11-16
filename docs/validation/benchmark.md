# Benchmark metrics

The dashboard's Fig. 4 shows **coverage**, not a precision/recall benchmark.
`pipeline.benchmark` is the metrics engine that turns labelled outcomes into
per-rule TP/FP/FN, precision, recall, and alert volume.

It does not download data and it does not infer labels from what happened to fire.
A human-reviewed labels manifest is required.

## Labels manifest

See [`labels.example.json`](labels.example.json):

```json
{
  "samples": [
    {
      "id": "otrf-sysmon",
      "label": "malicious",
      "start": "2020-10-18T10:56:18Z",
      "end": "2020-10-19T02:56:05Z",
      "techniques": ["T1003.001", "T1070.001"],
      "expected_rules": [
        "Suspicious Process Access to LSASS",
        "Windows Event Log Cleared"
      ]
    },
    {
      "id": "large-benign",
      "label": "benign",
      "start": "2026-11-10T13:30:00Z",
      "end": "2026-11-11T12:30:00Z",
      "expected_rules": []
    }
  ]
}
```

- `expected_rules` is the reviewed set of rules that should fire in the window.
- If omitted, the engine derives expected rules from the sample's ATT&CK
  techniques. Treat that as a shortcut, not a substitute for review.
- A benign sample has no expected rules; any alert is a false positive.

## Run

```powershell
python -m pipeline.benchmark `
  --alerts lab/combined-results/alerts.json `
  --labels docs/validation/labels.json `
  --out docs/validation/benchmark-results.json `
  --markdown docs/validation/benchmark-results.md
```

The engine writes a JSON summary and an optional Markdown table:

| Rule | TP | FP | FN | Precision | Recall | Alert volume |
|---|---:|---:|---:|---:|---:|---:|

## Source map for the full comparison

| Index | Public source candidate | Blocker |
|---|---|---|
| Windows Security | OTRF Security-Datasets (done) | None; two samples replayed |
| Sysmon | OTRF Security-Datasets (done) | None; richer 118-event sample replayed |
| Linux audit/auth | OTRF `datasets/atomic/linux` | Samples are auditd `.log`, not JSON; a parser is needed |
| Web / nginx | Splunk Attack Data | Large mixed corpus; web mapping and labels needed |
| AWS CloudTrail | OTRF `datasets/atomic/aws` | CloudTrail JSON mapping needed for `event.action`, `user.name`, `event.outcome` |
| Network flow | Splunk Attack Data / Zeek captures | Mapping and labels needed |
| Real benign | Public benign capture (to be selected) | Must be vetted and safe to download |

## What the current 25 not-evaluable rules mean

- **20 missing-index rules**: the Windows sample did not contain Linux, web,
  cloud, or network data. Add one sample per index to make them evaluable.
- **5 missing-field rules**: the sample did not contain service, Kerberos, SMB,
  or registry events. Use a capture with those event types.
- **3 correlation fetches**: the same missing indices block the correlation
  layer.

## What the 23 no-match rules mean

They were evaluated and did not fire. That is **not automatically a failure**:

- if the attack technique was present and the rule missed it, that is a false
  negative;
- if the technique was absent, it is a true negative;
- the labels manifest decides which.

The current Fig. 4 is an honest coverage panel. It should not be presented as a
precision/recall result until the source matrix and labels exist.

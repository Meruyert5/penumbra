# Large benign baseline results

This is a larger synthetic benign run, separate from the committed dashboard. It
tests whether the rule set stays quiet when the corpus is scaled up.

## Run

| Field | Value |
|---|---|
| Generator | `pipeline.labgen --scenario baseline --baseline-loops 6900` |
| Base time | 2026-11-11T12:30:00Z |
| Window | 24 hours |
| Events | 89,704 |
| Indices | Windows 20,701; Linux 20,703; web 20,700; cloud 13,800; network 13,800 |
| Rules evaluated | 50 |
| Correlations evaluated | 8 |
| Rule matches | 1 |
| Correlation alerts | 0 |
| Rules not evaluable | 7 field-dependent Windows rules |

The default committed baseline is 690 loops. This run uses **6,900 loops**, a
10× increase, and spreads the activity over the same 23-hour window.

## Result

| Rule | Level | Technique | Matches | Host | Interpretation |
|---|---|---:|---:|---|---|
| SSH Failed Password Authentication | low | T1110.001 | 3 | linux01 | Known benign match: isolated failed logins |

The baseline intentionally includes a few isolated failed SSH logins so the
correlation layer has realistic noise to reject. The single-event low-severity
rule matches those three events; the **correlation** rule does not fire, which is
the correct incident-level behaviour. This is a real per-rule false-positive
candidate for tuning, not an incident.

## What the result means

- Scaling the benign corpus 10× does not create a flood of alerts.
- The correlation layer remains clean at 89,704 events.
- The low-severity SSH rule is sensitive by design. A production tuning pass
  should decide whether to keep it as an event-level signal, add a host/user
  exclusion, or rely on the correlation for escalation.
- Seven Windows rules could not be evaluated because the benign generator does
  not emit the fields they need (`ServiceName`, `ImagePath`, `Details`,
  `TargetImage`, `GrantedAccess`, `ShareName`, `TicketEncryptionType`). These are
  field-coverage gaps, not rule failures.

## Commands

```powershell
python -m pipeline.labgen `
  --scenario baseline --baseline-loops 6900 `
  --base-time 2026-11-11T12:30:00Z --out lab\large-benign

python -m pipeline.ingest --logs lab\large-benign --reset
python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z --out lab\large-benign-results
```

The generated events and result files are gitignored.

## Comparison

| Run | Events | Rule matches | Correlation alerts | Nature |
|---|---:|---:|---:|---|
| Committed dashboard run | 9,223 | 50 | 9 | Synthetic scenarios + baseline |
| Large benign baseline | 89,704 | 1 | 0 | Synthetic benign only |
| OTRF Sample A | 110 | 1 | 0 | Real Windows Security 1102 |
| OTRF Sample B | 118 | 3 | 0 | Real Sysmon/Security capture |

The large benign run is the useful comparison for false-positive behaviour; the
OTRF runs are the useful comparison for real-field behaviour. Neither replaces a
production precision/recall benchmark.

## Next step

Add a real benign dataset and a label manifest. The synthetic baseline proves
volume scaling; it cannot prove real-world noise tolerance.

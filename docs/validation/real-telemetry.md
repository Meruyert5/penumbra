# Real-telemetry validation

This is the runbook for moving beyond the synthetic corpus. The mapping harness is
implemented and tested; the replay and VM steps have **not** been executed in this
repository. Do not describe them as completed until the results are recorded.

> **Treat public attack datasets as untrusted.** Some OTRF archives contain real
> attack tooling or binaries, not just telemetry. Download telemetry JSON only,
> keep it outside the repository, scan it with your own endpoint protection, and
> delete it after the replay. Never disable real-time protection to force a
> download, and never commit the raw dataset. The two samples replayed here were
> JSON event logs; a 44 MB archive that expanded from a 1 MB zip was removed
> rather than forced open.

## Current status

| Step | Status |
|---|---|
| OTRF/Mordor field mapping | Implemented in `pipeline/replay.py`, covered by `tests/test_replay.py` |
| OTRF sample replay | **Done for two samples**: 110 Security events + 118 richer Sysmon events; see [results](real-telemetry-results.md) |
| Atomic Red Team Sysmon capture | Not executed here; needs an isolated Windows VM |
| Per-rule TP/FP/FN table | 4 real TP candidate matches across 2 rules; full table pending |
| Larger benign baseline | Done: 89,704 synthetic events; see [large benign](large-benign-results.md) |
| Entra ID or Kubernetes source | Not added; only if it matches the target role |

Two samples have been replayed: 110 Windows Security events and 118 richer
Sysmon/Security events. The results, commands, and the 25 rules that were not
evaluable are recorded in
[Real-telemetry replay results](real-telemetry-results.md). The 10× synthetic
benign run is in [Large benign baseline](large-benign-results.md).

## 1. Replay a small OTRF sample

Use a small, labelled public dataset. Keep the download outside the repository so
the public tree stays small.

```powershell
# Example: clone only what you need from the OTRF repository.
git clone --depth 1 https://github.com/OTRF/Security-Datasets.git ..\Security-Datasets

# Normalize one file into the lab's ECS subset.
python -m pipeline.replay `
  --source ..\Security-Datasets\datasets\<path>\<file>.json `
  --file windows `
  --label malicious `
  --limit 5000

# Inspect the mapping before indexing.
python -m pipeline.replay --source ..\Security-Datasets\datasets\<path>\<file>.json --dry-run
```

The replay writes `lab/logs/<index>.ndjson` and
`lab/logs/replay-manifest.json`. Then run:

```powershell
docker compose up -d
python -m pipeline.ingest --reset
python -m pipeline.compile
python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z
python -m pipeline.validation
```

The `--end` value must cover the dataset's labelled attack window. Check the
dataset's own metadata; do not assume the synthetic run's clock.

### What to record

For each rule, record:

| Field | Meaning |
|---|---|
| `matches` | Rule matches in the replay window |
| `positive_window` | The labelled attack window from the dataset |
| `tp` | Matches inside the positive window |
| `fp` | Matches outside the positive window |
| `fn` | Labelled events in the window with no match |
| `precision` | `tp / (tp + fp)` |
| `recall` | `tp / (tp + fn)` |
| `alert_volume_24h` | Matches per 24 hours |

Do not call a match a true positive just because the dataset is labelled
malicious; the timestamp and the rule's event must line up.

## 2. Atomic Red Team on an isolated Windows VM

This step needs a Windows guest with Sysmon, not the host machine and not a Linux
container:

1. Build an isolated Windows VM with no route to production networks.
2. Install Sysmon with the SwiftOnSecurity or Olaf Hartong configuration.
3. Install Winlogbeat and point it at the lab Elasticsearch, or export the Sysmon
   channel to JSON and use `pipeline.replay`.
4. Install Invoke-AtomicRedTeam and run **one** technique, for example T1059.001
   (PowerShell) or T1003.001 (LSASS memory).
5. Record the VM snapshot, the command, the UTC start/end, and the Sysmon event
   IDs produced.
6. Normalize the capture, replay it, and record the per-rule result.

The repository does not ship a Windows VM image. Do not run Atomic Red Team on a
host you care about, and do not run the LSASS test on a machine with real
credentials.

## 3. Larger benign baseline

Use a benign dataset or a quiet window from the same environment. Label it
`benign` in the replay manifest and run the same rules. Any match outside the
labelled attack window is a candidate false positive and needs a tuning note in
`docs/tuning.md`.

## 4. Add a source only if it matches the target role

If the target roles are cloud detection, add **Entra ID sign-in logs** or
**Kubernetes audit logs**. If the target roles are endpoint detection, add EDR
process/network telemetry. Do not add a source just to increase the platform
count; every source needs a field mapping, at least one rule, and a benign test.

## 5. Record the outcome

Copy the result into `docs/validation/real-telemetry-results.md` when the run is
complete. Keep the dataset version, commit, time window, and command in the file.
Until that file exists, the repository's evidence remains synthetic and
structural.

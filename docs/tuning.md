# Tuning Log

A detection is a hypothesis. This file records what each rule assumed, which benign activity broke that assumption in the lab, and what changed. Reviewers should read this before the rules: it shows the reasoning, not just the regex.

## Baseline noise inventory

`python -m pipeline.labgen --scenario baseline` produces 1,954 benign events: Chrome and Notepad process creation, a legitimate administrative PowerShell command, successful SSH logins, normal web traffic, routine AWS API calls, ordinary network flows, and a handful of isolated failed logins from a known admin workstation (`198.51.100.9`).

Every rule was run against that baseline. The table below is the result and the fix.

| Rule | What fired on benign activity | Change made | Trade-off accepted |
|---|---|---|---|
| PowerShell Encoded Command | Software deployment agents wrap scripts in `-enc` | Exclude `ParentImage` ending in `ccmexec.exe` / `Microsoft.ConfigurationManagement.exe` | A loader spawned by a compromised SCCM agent is missed; compensated by alerting on SCCM-spawned network connections |
| LSASS Process Access | EDR/AV scanners (`MsMpEng.exe`, `MpCmdRun.exe`) and Windows components (`svchost.exe`, `csrss.exe`) legitimately open LSASS | Source-image allowlist | An attacker masquerading as `svchost.exe` is missed; real deployments should validate the image path and signature, not just the name |
| Service Installed From User Path | Windows servicing creates services from `ProgramData` | `ServiceName` allowlist (`WaaSMedicSvc`, `BITS`, `WinDefend`) | Attackers can reuse those names; the `ImagePath` condition still catches a swapped binary |
| Scheduled Task Created | System accounts (`*$`) register tasks during boot | Exclude `User` ending in `$` | SYSTEM-level attacker persistence is missed; pair with a 4698-based rule for coverage |
| SSH Failed Password | Three benign typos from a known workstation | Kept as `low` single-event rule; volume escalation moved to `corr-ssh-bruteforce` (8 / 5 min) | A slow brute force below 8 attempts per 5 minutes needs a longer-window correlation |
| Web Shell Upload | Some applications accept PHP uploads | Restricted to writable-looking directories (`/upload`, `/images`, `/tmp`, `/files`) | Uploads to other paths are missed; the `web_shell_parameter` rule covers interaction regardless of path |

## Why the SSH rule is split in two

The single-event rule fires on every typo, which is unusable at `high` severity. Lowering the severity hides a real intrusion; raising the threshold inside Sigma is not portable. Splitting it is the standard answer:

* `linux_ssh_failed_password.yml` → one event, `low`, useful as context in a timeline.
* `correlations/ssh_bruteforce.yml` → 8 events / 5 minutes / source IP, `high`, actionable.

The correlation is a pure function with unit tests (`tests/test_correlate.py`), including the case that matters most: **events just outside the window must not count**.

## Measuring precision

Do not guess at a false-positive rate. For a one-week window:

```json
POST lab-*/_search
{ "size": 0, "query": { "range": { "@timestamp": { "gte": "now-7d" } } },
  "aggs": { "by_rule": { "terms": { "field": "rule.id", "size": 50 } } } }
```

Then fill in:

| Rule | Alerts (7d) | Verified TP | False positives | Precision | Action |
|---|---|---|---|---|---|
| PowerShell Encoded Command | _tbd_ | _tbd_ | _tbd_ | _tbd_ | |
| LSASS Process Access | _tbd_ | _tbd_ | _tbd_ | _tbd_ | |
| SSH Brute Force (correlation) | _tbd_ | _tbd_ | _tbd_ | _tbd_ | |

Precision = TP / (TP + FP). Anything below ~0.5 either needs a filter or should be demoted to `low` and used as context rather than a queue item.

The synthetic baseline is deliberately small, so these numbers are not production measurements. The point of the table is the method: every rule has an owner, a count, and a decision.

## Second tuning pass

The expanded telemetry exposed three more assumptions worth recording.

| Detection | Problem in the lab | Change made | Trade-off accepted |
|---|---|---|---|
| Critical Service Stopped Before Impact | Watching only `VSS` missed the backup agent stop that followed it | Watch `VSS`, `BackupExecAgentBrowser`, `SQLSERVERAGENT`, and `WinDefend`, and raise to `high` | A planned maintenance stop needs an allowlist or a change ticket |
| Ransomware File Burst (correlation) | Extension matching is the easiest signal for an operator to change | Keep the extension rule as context, and add a volume rule: 15 writes / 2 min / host | A legitimate bulk import can trip it; pair with a note or recovery-deletion alert |
| Password Spray (correlation) | A single-account brute force satisfied a pure volume threshold | Add `distinct_by: user.name` with a minimum of 8 distinct accounts | A slow spray across fewer accounts per window needs a longer lookback |

## Known blind spots

* **No memory or API telemetry.** Process injection (T1055) and in-memory credential theft beyond LSASS handle access are invisible.
* **No proxy or TLS metadata.** Beaconing and web-protocol C2 (T1071.001) need flow timing and certificate data that the current sources do not carry.
* **Limited logon analysis.** 4624 and 4625 are ingested, but lateral movement still lacks an internal-source baseline, so SSH and SMB movement remain documented gaps.
* **No asset criticality.** A critical alert on a build agent and on a domain controller currently look identical. Real triage needs an asset inventory.

These are listed in `docs/attck-coverage.md` as coverage gaps, not hidden.

# Case 003 - Ransomware Pre-Encryption Sequence on a Workstation

| Field | Value |
|---|---|
| Case ID | DL-2026-003 |
| Date | 2026-11-11 |
| Analyst | Meruyert |
| Severity | Critical |
| Status | Contained, host rebuilt |
| Data source | Sysmon (EID 1, 11), System (EID 7036), `WIN10-LAB` (synthetic lab telemetry) |
| Detections | `win_shadow_copy_deletion`, `win_bcdedit_recovery_disabled`, `win_service_stop`, `win_ransomware_note`, `corr-ransomware-file-burst` |

## Summary

At 11:25Z `WIN10-LAB` ran `vssadmin delete shadows /all /quiet`, then `wmic shadowcopy delete`, then disabled boot recovery with `bcdedit`. The host stopped the VSS and backup agent services 50 seconds later, dropped two ransom notes, and wrote 24 encrypted files in under a minute. Five detections fired in sequence. The file-write correlation reached 15 writes in 2 minutes while the single-event rules had already named the recovery steps. I contained the host before encryption spread to the file share.

## Timeline

`T+00:00` = 2026-11-11 11:25:00Z (all times UTC).

| Offset | Event | Detection |
|---|---|---|
| T+00:00 | `vssadmin.exe delete shadows /all /quiet` | Shadow Copy Deletion (high) |
| T+00:20 | `wmic.exe shadowcopy delete` | Shadow Copy Deletion (high) |
| T+00:40 | `bcdedit.exe /set {default} recoveryenabled no` | Boot Recovery Disabled (high) |
| T+00:50 | Service `VSS` entered the stopped state | Critical Service Stopped (high) |
| T+00:55 | Service `BackupExecAgentBrowser` entered the stopped state | Critical Service Stopped (high) |
| T+01:00 | `READ_ME.txt` written to the analyst desktop | Ransomware Note (critical) |
| T+01:05 | `DECRYPT_INSTRUCTIONS.txt` written to the finance share | Ransomware Note (critical) |
| T+01:10 | First `.locked` file written | none (volume signal) |
| T+01:22 | 15th file write inside the 2 minute window | Ransomware File Burst (critical) |
| T+01:56 | 24th `.locked` file written | Ransomware File Burst (critical) |

## Evidence

```text
2026-11-11T11:25:00.100Z  EID 1   vssadmin.exe delete shadows /all /quiet
2026-11-11T11:25:20.100Z  EID 1   wmic.exe shadowcopy delete
2026-11-11T11:25:40.100Z  EID 1   bcdedit.exe /set {default} recoveryenabled no
2026-11-11T11:25:50.100Z  EID 7036 The VSS service entered the stopped state.
2026-11-11T11:26:00.100Z  EID 11  C:\Users\analyst\Desktop\READ_ME.txt
2026-11-11T11:26:10.100Z  EID 11  C:\Users\analyst\Documents\file00.docx.locked
2026-11-11T11:26:56.100Z  EID 11  C:\Users\analyst\Documents\file23.jpg.locked
```

## Analysis

The three recovery steps are the strongest evidence. Each has a legitimate administrative use, but they appeared together, in order, on a workstation, with no change ticket. The service stops removed the two fastest recovery paths before the first note appeared. File writes at roughly two per second exceed any human editing pattern, and the `.locked` extension is appended rather than replacing the original.

What I did not find: no outbound transfer above 10 MB, no new service install, no scheduled task, and no successful remote logon. That limits the confirmed scope to this host, though the finance share write means the share must be treated as exposed.

## ATT&CK mapping

| Technique | Evidence |
|---|---|
| T1490 Inhibit System Recovery | vssadmin and wmic shadow copy deletion, bcdedit recovery disabled |
| T1489 Service Stop | VSS and BackupExecAgentBrowser stopped |
| T1486 Data Encrypted for Impact | 24 `.locked` writes in 46 seconds |
| T1486 Impact | Ransom notes written to desktop and finance share |

## Verdict

True positive. The ordered recovery deletion, service stops, notes, and file-write volume support ransomware execution, not a backup or maintenance task.

## Containment and recommendations

1. Isolate `WIN10-LAB` from the network and revoke the logged-on user's sessions.
2. Snapshot the finance share and check for `.locked` files before restoring.
3. Restore from an offline backup that predates T+00:00.
4. Hunt for the same command sequence on every host for 30 days.
5. Block shadow copy deletion for non-approved service accounts with a controlled change process.

## Detection improvements

The service-stop rule originally watched only `VSS`. Adding `BackupExecAgentBrowser`, `SQLSERVERAGENT`, and `WinDefend` caught the second stop that the first version missed. The file-write correlation also proved more durable than the extension match, because the extension is the easiest thing for an operator to change.

## Reproduce

```powershell
python -m pipeline.labgen --scenario ransomware --out lab/logs
python -m pipeline.ingest --reset
python -m pipeline.detect --hours 24
```

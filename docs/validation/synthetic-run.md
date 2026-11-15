# Synthetic run: per-rule results

> **This is a synthetic, construction-labelled run.** It shows what fired in the
> committed lab corpus. It is not a precision or recall measurement. The corpus
> is generated to exercise these rules, so a match is expected by construction.
> Real-telemetry validation is tracked in [Evaluation and validation](../evaluation.md).

## Summary

| Metric | Value |
|---|---|
| Rule alerts | 50 |
| Correlation alerts | 9 |
| Sum of rule match counts | 190 |
| Rules linked to a case | 11 |
| Rules without a case link | 39 |
| Precision / recall | Not measured |
| False-positive rate | Not measured |
| Real telemetry | Not yet replayed |

## Rule results

| Rule | Level | Matches | Hosts | First | Last | Case |
|---|---|---:|---|---|---|---|
| LSASS Memory Dumped via Comsvcs | critical | 1 | WIN10-LAB | 12:10Z | 12:10Z | - |
| Linux Reverse Shell Command | critical | 1 | linux01 | 09:12Z | 09:12Z | - |
| Ransomware Note Dropped on Disk | critical | 2 | WIN10-LAB | 11:56Z | 11:56Z | PNB-2026-003 |
| SAM or SECURITY Hive Dumped with Reg.exe | critical | 1 | WIN10-LAB | 12:11Z | 12:11Z | - |
| Suspicious Process Access to LSASS | critical | 1 | WIN10-LAB | 12:10Z | 12:10Z | PNB-2026-002 |
| AMSI Bypass via Reflection | high | 1 | WIN10-LAB | 12:13Z | 12:13Z | - |
| Boot Recovery Disabled via BCDEdit | high | 1 | WIN10-LAB | 11:55Z | 11:55Z | PNB-2026-003 |
| Certutil Used to Download or Decode a Payload | high | 1 | WIN10-LAB | 12:07Z | 12:07Z | PNB-2026-002 |
| Cloud Access Key Created | high | 1 | aws-prod | 00:35Z | 00:35Z | - |
| Cloud Root Account Console Login | high | 1 | aws-prod | 00:35Z | 00:35Z | - |
| Command Injection Attempt in Web Request | high | 1 | web01 | 06:16Z | 06:16Z | - |
| Critical Service Stopped Before Impact | high | 4 | WIN10-LAB | 11:55Z | 12:17Z | PNB-2026-003 |
| Cron Job Executing Remote Content | high | 1 | linux01 | 22:47Z | 22:47Z | - |
| Kerberoasting Service Ticket Request | high | 12 | DC01 | 08:09Z | 08:10Z | - |
| Large Outbound Network Transfer | high | 2 | edge-fw01 | 05:12Z | 05:12Z | - |
| Linux Log File Tampering | high | 2 | linux01 | 09:13Z | 09:13Z | - |
| Mshta Executing Remote or Script Content | high | 2 | WIN10-LAB | 11:19Z | 12:04Z | - |
| Office Application Spawns a Shell | high | 2 | WIN10-LAB | 12:04Z | 12:05Z | - |
| PHP File Uploaded to Web Accessible Directory | high | 1 | web01 | 19:20Z | 19:20Z | - |
| Periodic Web Beacon to a Command Endpoint | high | 12 | web01 | 22:21Z | 22:24Z | - |
| PowerShell Download Cradle | high | 1 | WIN10-LAB | 12:04Z | 12:04Z | - |
| PowerShell Encoded Command Execution | high | 1 | WIN10-LAB | 12:05Z | 12:05Z | PNB-2026-002 |
| PsExec Service Creation | high | 1 | WIN10-LAB | 21:01Z | 21:01Z | - |
| Registry Run Key Persistence | high | 2 | WIN10-LAB | 00:57Z | 00:57Z | - |
| Remote Thread Created by a User-Writable Binary | high | 2 | WIN10-LAB | 18:22Z | 18:22Z | - |
| Root SSH Login from an External Address | high | 1 | linux01 | 00:26Z | 00:26Z | - |
| Rundll32 or Regsvr32 Remote Payload | high | 2 | WIN10-LAB | 11:19Z | 11:19Z | - |
| SMB Administrative Share Access | high | 2 | DC01 | 02:23Z | 02:23Z | - |
| SSH Authorized Keys Modified | high | 1 | linux01 | 09:11Z | 09:11Z | - |
| Shadow Copy Deletion via VSSAdmin or WMIC | high | 2 | WIN10-LAB | 11:55Z | 11:55Z | PNB-2026-003 |
| Sudoers File Modified | high | 1 | linux01 | 09:11Z | 09:11Z | - |
| Suspicious Service Installed From User-Writable Path | high | 1 | WIN10-LAB | 12:14Z | 12:14Z | PNB-2026-002 |
| Systemd Service Unit Created | high | 1 | linux01 | 09:11Z | 09:11Z | - |
| UAC Bypass via Auto-Elevating Binary | high | 1 | WIN10-LAB | 07:06Z | 07:06Z | - |
| Valid Service Account Login from an External Address | high | 2 | linux01 | 20:25Z | 20:25Z | - |
| WMI Event Subscription Persistence | high | 2 | WIN10-LAB | 01:59Z | 01:59Z | - |
| Windows Command Shell Spawning a Remote Payload | high | 1 | WIN10-LAB | 16:24Z | 16:24Z | - |
| Windows Defender Real-Time Protection Disabled | high | 1 | WIN10-LAB | 12:12Z | 12:12Z | PNB-2026-002 |
| Windows Event Log Cleared | high | 1 | WIN10-LAB | 12:13Z | 12:13Z | - |
| DNS Query to Exfiltration Domain | medium | 25 | WIN10-LAB | 04:08Z | 04:10Z | - |
| Data Staged with Archive Utility | medium | 2 | WIN10-LAB | 10:15Z | 10:15Z | - |
| New Local User Account Created | medium | 1 | linux01 | 20:45Z | 20:45Z | - |
| Path Traversal Attempt in Web Request | medium | 2 | web01 | 06:16Z | 06:16Z | - |
| SQL Injection Attempt in Web Request | medium | 5 | web01 | 06:16Z | 06:16Z | - |
| Scheduled Task Created via Schtasks | medium | 1 | WIN10-LAB | 12:14Z | 12:14Z | PNB-2026-002 |
| Web Request to Common Web Shell Parameter | medium | 10 | web01 | 19:20Z | 06:16Z | - |
| Windows Firewall Disabled | medium | 1 | WIN10-LAB | 12:13Z | 12:13Z | - |
| Host and Account Discovery Command | low | 8 | WIN10-LAB | 23:03Z | 23:04Z | - |
| SSH Failed Password Authentication | low | 39 | linux01 | 16:40Z | 12:21Z | PNB-2026-001 |
| Web Scanner User Agent | low | 20 | web01 | 06:16Z | 06:17Z | - |

## Correlation results

| Correlation | Level | Count | Group | Window | Technique |
|---|---|---:|---|---:|---|
| Account and Domain Discovery Burst | medium | 4 | host.name=WIN10-LAB | 300 | T1087 |
| Sustained DNS Queries to an External Domain | high | 12 | host.name=WIN10-LAB | 120 | T1071.004 |
| High-Volume File Writes Consistent with Encryption | critical | 15 | host.name=WIN10-LAB | 120 | T1486 |
| Password Spray Across Many Accounts | high | 10 | source.ip=198.51.100.23 | 600 | T1110.003 |
| SSH Brute Force Against a Single Host | high | 8 | source.ip=198.51.100.23 | 300 | T1110.001 |
| SSH Brute Force Against a Single Host | high | 8 | source.ip=203.0.113.44 | 300 | T1110.001 |
| Horizontal Port Scan from One Source | medium | 20 | source.ip=192.0.2.66 | 60 | T1046 |
| Web Enumeration from One Source | low | 20 | source.ip=203.0.113.77 | 60 | T1595.002 |
| Repeated Web Shell Command Execution | high | 5 | source.ip=203.0.113.77 | 120 | T1505.003 |

## How to read this

- `Matches` is the rule's event count in the committed run, not a count of independent incidents.
- A case link means the rule is referenced by one of the three analyst reports.
- A blank case link does not mean the rule is unimportant; it means the rule is not the spine of a written case.
- True positive, false positive, and false negative labels require an independent benign set and a labelled attack window. That is the next validation step.

## Reproduce

```powershell
python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z
python -m pipeline.validation
```

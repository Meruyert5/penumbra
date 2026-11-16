# Triage and response

A dry-run triage engine over the detection run. It enriches alerts, groups
them into incidents, selects a playbook, and records the actions a real SOAR
worker would take. No EDR, cloud, or ticketing API is called.

- Alerts ingested: **50**
- Incidents: **27**
- Alerts grouped into incidents: **23**
- Playbooks: **6**
- Actions: **78**
- Containment coverage: **85.2%**
- Timing: dry run; external API latency is not measured

## Playbooks

| Playbook | Incidents |
|---|---:|
| Standard triage | 19 |
| Persistence response | 8 |
| Authentication response | 3 |
| Ransomware containment | 1 |
| Credential theft response | 1 |
| Cloud identity response | 1 |

## Incidents

| Incident | Host | Highest level | Alerts | Playbooks | Actions |
|---|---|---|---:|---|---:|
| INC-001 | linux01 | critical | 5 | Authentication response, Persistence response, Standard triage | 8 |
| INC-002 | WIN10-LAB | critical | 4 | Persistence response, Ransomware containment, Standard triage | 9 |
| INC-003 | WIN10-LAB | critical | 9 | Credential theft response, Persistence response, Standard triage | 9 |
| INC-004 | WIN10-LAB | high | 1 | Standard triage | 2 |
| INC-005 | WIN10-LAB | high | 1 | Standard triage | 2 |
| INC-006 | web01 | high | 2 | Standard triage | 2 |
| INC-007 | linux01 | high | 1 | Persistence response | 3 |
| INC-008 | WIN10-LAB | high | 1 | Persistence response | 3 |
| INC-009 | web01 | high | 1 | Standard triage | 2 |
| INC-010 | linux01 | high | 1 | Standard triage | 2 |
| INC-011 | linux01 | high | 1 | Authentication response | 3 |
| INC-012 | aws-prod | high | 2 | Cloud identity response | 3 |
| INC-013 | WIN10-LAB | high | 1 | Persistence response | 3 |
| INC-014 | WIN10-LAB | high | 1 | Persistence response | 3 |
| INC-015 | DC01 | high | 1 | Standard triage | 2 |
| INC-016 | edge-fw01 | high | 1 | Standard triage | 2 |
| INC-017 | web01 | high | 4 | Standard triage | 2 |
| INC-018 | WIN10-LAB | high | 1 | Standard triage | 2 |
| INC-019 | DC01 | high | 1 | Persistence response | 3 |
| INC-020 | WIN10-LAB | high | 2 | Standard triage | 2 |
| INC-021 | WIN10-LAB | high | 2 | Standard triage | 2 |
| INC-022 | WIN10-LAB | high | 2 | Standard triage | 2 |
| INC-023 | linux01 | medium | 1 | Standard triage | 1 |
| INC-024 | WIN10-LAB | medium | 1 | Standard triage | 1 |
| INC-025 | WIN10-LAB | medium | 1 | Standard triage | 1 |
| INC-026 | linux01 | low | 1 | Authentication response | 3 |
| INC-027 | WIN10-LAB | low | 1 | Standard triage | 1 |

### INC-001 — linux01

**Window.** 2026-11-11T09:11:00.000Z to 2026-11-11T09:13:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Linux Reverse Shell Command | critical | T1059.004 | 1 |
| Sudoers File Modified | high | T1548.003 | 1 |
| SSH Authorized Keys Modified | high | T1098.004 | 1 |
| Systemd Service Unit Created | high | T1543.002 | 1 |
| Linux Log File Tampering | high | T1070.002 | 2 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context
- `block_source` (dry_run): Stop the login attempts
- `reset_password` (dry_run): Secure the targeted account
- `review_sessions` (dry_run): Check for post-login activity
- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-002 — WIN10-LAB

**Window.** 2026-11-11T11:55:00.000Z to 2026-11-11T11:56:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Ransomware Note Dropped on Disk | critical | T1486 | 2 |
| Shadow Copy Deletion via VSSAdmin or WMIC | high | T1490 | 2 |
| Boot Recovery Disabled via BCDEdit | high | T1490 | 1 |
| Critical Service Stopped Before Impact | high | T1489 | 4 |

**Actions.**

- `isolate_host` (dry_run): Stop encryption spread
- `preserve_memory` (dry_run): Capture volatile evidence
- `snapshot_share` (dry_run): Preserve the file share before restore
- `notify_ir_lead` (dry_run): Critical impact
- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context
- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-003 — WIN10-LAB

**Window.** 2026-11-11T12:10:08.000Z to 2026-11-11T12:14:30.000Z

**Enrichment.** asset `high`, privileged technique `True`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Suspicious Process Access to LSASS | critical | T1003.001 | 1 |
| LSASS Memory Dumped via Comsvcs | critical | T1003.001 | 1 |
| SAM or SECURITY Hive Dumped with Reg.exe | critical | T1003.002 | 1 |
| Windows Defender Real-Time Protection Disabled | high | T1562.001 | 1 |
| AMSI Bypass via Reflection | high | T1562.001 | 1 |
| Windows Event Log Cleared | high | T1070.001 | 1 |
| Suspicious Service Installed From User-Writable Path | high | T1543.003 | 1 |
| Windows Firewall Disabled | medium | T1562.004 | 1 |
| Scheduled Task Created via Schtasks | medium | T1053.005 | 1 |

**Actions.**

- `isolate_host` (dry_run): Prevent credential reuse
- `reset_credentials` (dry_run): Assume cached secrets are compromised
- `collect_memory` (dry_run): Preserve LSASS evidence
- `hunt_hashes` (dry_run): Find the payload on other hosts
- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context
- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-004 — WIN10-LAB

**Window.** 2026-11-10T16:24:00.000Z to 2026-11-10T16:24:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Windows Command Shell Spawning a Remote Payload | high | T1059.003 | 1 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-005 — WIN10-LAB

**Window.** 2026-11-10T18:22:00.000Z to 2026-11-10T18:22:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Remote Thread Created by a User-Writable Binary | high | T1055 | 2 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-006 — web01

**Window.** 2026-11-10T19:20:00.000Z to 2026-11-10T19:20:20.000Z

**Enrichment.** asset `medium`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| PHP File Uploaded to Web Accessible Directory | high | T1505.003 | 1 |
| Web Request to Common Web Shell Parameter | medium | T1505.003 | 10 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-007 — linux01

**Window.** 2026-11-10T20:25:00.000Z to 2026-11-10T20:25:00.000Z

**Enrichment.** asset `high`, privileged technique `True`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Valid Service Account Login from an External Address | high | T1078 | 2 |

**Actions.**

- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-008 — WIN10-LAB

**Window.** 2026-11-10T21:01:00.000Z to 2026-11-10T21:01:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| PsExec Service Creation | high | T1569.002 | 1 |

**Actions.**

- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-009 — web01

**Window.** 2026-11-10T22:21:00.000Z to 2026-11-10T22:21:00.000Z

**Enrichment.** asset `medium`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Periodic Web Beacon to a Command Endpoint | high | T1071.001 | 12 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-010 — linux01

**Window.** 2026-11-10T22:47:00.000Z to 2026-11-10T22:47:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Cron Job Executing Remote Content | high | T1053.003 | 1 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-011 — linux01

**Window.** 2026-11-11T00:26:00.000Z to 2026-11-11T00:26:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Root SSH Login from an External Address | high | T1021.004 | 1 |

**Actions.**

- `block_source` (dry_run): Stop the login attempts
- `reset_password` (dry_run): Secure the targeted account
- `review_sessions` (dry_run): Check for post-login activity

### INC-012 — aws-prod

**Window.** 2026-11-11T00:35:00.000Z to 2026-11-11T00:35:30.000Z

**Enrichment.** asset `critical`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Cloud Root Account Console Login | high | T1078.004 | 1 |
| Cloud Access Key Created | high | T1098.001 | 1 |

**Actions.**

- `disable_access_key` (dry_run): Stop key abuse
- `review_cloudtrail` (dry_run): Scope the principal activity
- `export_to_apsis` (dry_run): Check reachable IAM paths

### INC-013 — WIN10-LAB

**Window.** 2026-11-11T00:57:00.000Z to 2026-11-11T00:57:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Registry Run Key Persistence | high | T1547.001 | 2 |

**Actions.**

- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-014 — WIN10-LAB

**Window.** 2026-11-11T01:59:00.000Z to 2026-11-11T01:59:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| WMI Event Subscription Persistence | high | T1546.003 | 2 |

**Actions.**

- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-015 — DC01

**Window.** 2026-11-11T02:23:00.000Z to 2026-11-11T02:23:00.000Z

**Enrichment.** asset `medium`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| SMB Administrative Share Access | high | T1021.002 | 2 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-016 — edge-fw01

**Window.** 2026-11-11T05:12:00.000Z to 2026-11-11T05:12:00.000Z

**Enrichment.** asset `medium`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Large Outbound Network Transfer | high | T1041 | 2 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-017 — web01

**Window.** 2026-11-11T06:16:00.000Z to 2026-11-11T06:16:26.000Z

**Enrichment.** asset `medium`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Command Injection Attempt in Web Request | high | T1059 | 1 |
| SQL Injection Attempt in Web Request | medium | T1190 | 5 |
| Path Traversal Attempt in Web Request | medium | T1190 | 2 |
| Web Scanner User Agent | low | T1595.002 | 20 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-018 — WIN10-LAB

**Window.** 2026-11-11T07:06:00.000Z to 2026-11-11T07:06:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| UAC Bypass via Auto-Elevating Binary | high | T1548.002 | 1 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-019 — DC01

**Window.** 2026-11-11T08:09:00.000Z to 2026-11-11T08:09:00.000Z

**Enrichment.** asset `medium`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Kerberoasting Service Ticket Request | high | T1558.003 | 12 |

**Actions.**

- `collect_binary` (dry_run): Hash and detonate safely
- `disable_persistence` (dry_run): Remove service or task
- `hunt_service_name` (dry_run): Find the same name on other hosts

### INC-020 — WIN10-LAB

**Window.** 2026-11-11T11:19:00.000Z to 2026-11-11T11:19:40.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Rundll32 or Regsvr32 Remote Payload | high | T1218.011 | 2 |
| Mshta Executing Remote or Script Content | high | T1218.005 | 2 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-021 — WIN10-LAB

**Window.** 2026-11-11T12:04:00.000Z to 2026-11-11T12:04:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Office Application Spawns a Shell | high | T1566.001 | 2 |
| PowerShell Download Cradle | high | T1059.001, T1105 | 1 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-022 — WIN10-LAB

**Window.** 2026-11-11T12:05:00.000Z to 2026-11-11T12:07:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| PowerShell Encoded Command Execution | high | T1027, T1059.001 | 1 |
| Certutil Used to Download or Decode a Payload | high | T1105, T1140 | 1 |

**Actions.**

- `open_case` (dry_run): Analyst review
- `collect_evidence` (dry_run): Preserve context

### INC-023 — linux01

**Window.** 2026-11-10T20:45:00.000Z to 2026-11-10T20:45:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| New Local User Account Created | medium | T1136.001 | 1 |

**Actions.**

- `open_case` (dry_run): Analyst review

### INC-024 — WIN10-LAB

**Window.** 2026-11-11T04:08:00.000Z to 2026-11-11T04:08:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| DNS Query to Exfiltration Domain | medium | T1071.004 | 25 |

**Actions.**

- `open_case` (dry_run): Analyst review

### INC-025 — WIN10-LAB

**Window.** 2026-11-11T10:15:00.000Z to 2026-11-11T10:15:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Data Staged with Archive Utility | medium | T1560.001 | 2 |

**Actions.**

- `open_case` (dry_run): Analyst review

### INC-026 — linux01

**Window.** 2026-11-10T16:40:00.000Z to 2026-11-10T16:40:00.000Z

**Enrichment.** asset `high`, privileged technique `True`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| SSH Failed Password Authentication | low | T1110.001 | 39 |

**Actions.**

- `block_source` (dry_run): Stop the login attempts
- `reset_password` (dry_run): Secure the targeted account
- `review_sessions` (dry_run): Check for post-login activity

### INC-027 — WIN10-LAB

**Window.** 2026-11-10T23:03:00.000Z to 2026-11-10T23:03:00.000Z

**Enrichment.** asset `high`, privileged technique `False`, intel `not queried in the dry run`.

**Alerts.**

| Alert | Level | Techniques | Count |
|---|---|---|---:|
| Host and Account Discovery Command | low | T1087 | 8 |

**Actions.**

- `open_case` (dry_run): Analyst review

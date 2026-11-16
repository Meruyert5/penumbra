# IR casebook

The close-out layer for the three Penumbra cases. The individual reports keep
the narrative and evidence; this page records the observed window, response
decisions, lessons, and open questions in one place.

Response timing is not fabricated. The lab has no live EDR, ticketing, or
containment API, so the close-out records what was recommended and what
remains unmeasured.

| Case | Verdict | Status | Observed | Alerts |
|---|---|---|---:|---:|
| PNB-2026-001 case-001-ssh-bruteforce | true positive | escalated; containment recommended | 270s | 2 |
| PNB-2026-002 case-002-multi-stage-intrusion | true positive | host isolation recommended | 570s | 6 |
| PNB-2026-003 case-003-ransomware | true positive | contained; host rebuilt | 116s | 5 |

## PNB-2026-001 — case-001-ssh-bruteforce

**Verdict.** true positive

**Containment status.** escalated; containment recommended

### Metrics

| Metric | Value |
|---|---|
| Observed start | 2026-11-11T10:50:21Z |
| Observed end | 2026-11-11T10:54:51Z |
| Observed seconds | 270 |
| First detection | 2026-11-11T10:50:21Z |
| Last detection | 2026-11-11T10:52:27Z |
| Detection span (seconds) | 126 |
| Alerts | 2 |
| Response timing | not measured in the synthetic lab |

### Containment

- Block 203.0.113.44 at the perimeter and on linux01.
- Disable deploy, reset its password, and rotate keys in ~deploy/.ssh/.
- Review sudoers, authorized_keys, crontab, and shell history for the account.

### Eradication

- Remove any unauthorized key or cron entry created during the session.
- Confirm there is no second successful login from the same source.
- Add MFA and SSH rate limiting so a password guess is not enough.

### Recovery

- Return deploy to service only after credential rotation and owner approval.
- Monitor linux01 for outbound connections for 24 hours.
- Close the case only after the account owner confirms the session activity.

### Communication

- Notify the linux01 owner and the identity team.
- Share the source IP and the successful-login timestamp with the perimeter team.
- Record the password-rotation decision in the case timeline.

### Evidence

- linux.ndjson authentication events for 203.0.113.44.
- corr-ssh-bruteforce output with threshold and window.
- The accepted-login event and the absence of post-login host activity.

### Lessons

- A success after a failure burst should be one sequence alert, not two unrelated alerts.
- Add ASN and geo enrichment so a hosting-provider source is visible.
- Add password spraying coverage for distributed low-and-slow attempts.

### Open questions

- Is deploy in sudoers, and with which commands?
- Was the successful password reused on another host?
- Did the source IP appear in any other authentication log?

## PNB-2026-002 — case-002-multi-stage-intrusion

**Verdict.** true positive

**Containment status.** host isolation recommended

### Metrics

| Metric | Value |
|---|---|
| Observed start | 2026-11-11T10:38:18Z |
| Observed end | 2026-11-11T10:47:48Z |
| Observed seconds | 570 |
| First detection | 2026-11-11T10:38:18Z |
| Last detection | 2026-11-11T10:47:48Z |
| Detection span (seconds) | 570 |
| Alerts | 6 |
| Response timing | not measured in the synthetic lab |

### Containment

- Isolate WIN10-LAB from the network without powering it off.
- Disable and reset LAB\analyst; assume cached credentials are compromised.
- Block 203.0.113.44 at egress and DNS.

### Eradication

- Remove UpdaterSvc and the Updater scheduled task.
- Collect p.exe, svc.exe, upd.exe, and mimikatz.exe for hashing.
- Hunt the hashes, service name, and task name across the estate.

### Recovery

- Rebuild the host from a trusted image after memory capture.
- Rotate every credential that could have been cached on the host.
- Monitor the rebuilt host for the same parent-child and LSASS patterns.

### Communication

- Notify the endpoint owner and the identity team.
- Tell the email team to search for invoice.docm delivery to other recipients.
- Brief the IR lead on the six-alert chain and the isolation decision.

### Evidence

- Sysmon EID 1, 10, 11, 12, and 13 events for WIN10-LAB.
- Windows Defender EID 5001 and System EID 7045.
- The decoded PowerShell download cradle and the LSASS access event.

### Lessons

- Six alerts in nine minutes should become one incident automatically.
- Decode -enc PowerShell at ingestion so the URL is visible at T+00:00.
- Add 4688 and 4624 telemetry to rule out lateral movement instead of marking it unobserved.

### Open questions

- What is the document hash and who else received it?
- Did the payload run under a second account?
- Was the finance share reachable from this host?

## PNB-2026-003 — case-003-ransomware

**Verdict.** true positive

**Containment status.** contained; host rebuilt

### Metrics

| Metric | Value |
|---|---|
| Observed start | 2026-11-11T11:25:00Z |
| Observed end | 2026-11-11T11:26:56Z |
| Observed seconds | 116 |
| First detection | 2026-11-11T11:25:00Z |
| Last detection | 2026-11-11T11:26:56Z |
| Detection span (seconds) | 116 |
| Alerts | 5 |
| Response timing | not measured in the synthetic lab |

### Containment

- Isolate WIN10-LAB and revoke the logged-on user's sessions.
- Snapshot the finance share and check for .locked files before restoring.
- Stop outbound access from the host while memory is captured.

### Eradication

- Remove the encryptor and any scheduled task or service it created.
- Block shadow-copy deletion for non-approved service accounts.
- Hunt the same recovery-deletion sequence across every host.

### Recovery

- Restore from an offline backup that predates T+00:00.
- Verify the finance share file count and integrity after restore.
- Monitor restored hosts for re-infection and repeated service stops.

### Communication

- Notify the finance share owner and the backup team.
- Brief leadership on the confirmed host scope and the share exposure.
- Record the restore point and the verification result in the case.

### Evidence

- Sysmon EID 1 and 11 events for the recovery commands and .locked writes.
- System EID 7036 service-stop events for VSS and BackupExecAgentBrowser.
- The file-write correlation output and the two ransom-note paths.

### Lessons

- The service-stop list caught the backup agent stop that a VSS-only rule would miss.
- File-write volume is more durable than a file-extension match.
- Backup isolation and restore testing matter more than another alert.

### Open questions

- Was the finance share encrypted beyond the two notes?
- Did the encryptor reach any other host before isolation?
- When was the last successful offline backup verified?

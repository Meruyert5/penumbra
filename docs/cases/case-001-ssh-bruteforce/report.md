# Case 001: SSH Brute Force Followed by a Successful Login

| Field | Value |
|---|---|
| Case ID | PNB-2026-001 |
| Date | 2026-11-11 |
| Analyst | Meruyert |
| Severity | High |
| Status | Escalated to IR |
| Data source | Linux `auth.log` from `linux01` (synthetic lab telemetry) |
| Detections | `corr-ssh-bruteforce`, `linux_ssh_failed_password` |

## Summary

Between 10:50:21Z and 10:54:15Z, `linux01` recorded 14 failed SSH password attempts from `203.0.113.44`, cycling through six usernames at roughly 18-second intervals. Thirty-six seconds after the final failure, the same source successfully authenticated as `deploy`. A success immediately following a brute-force burst from the same address is the signature of a successful password-guessing attack, not background internet noise, so the case was escalated rather than closed.

## Timeline

`T+00:00` = 2026-11-11 10:50:21Z (all times UTC).

| Offset | Event |
|---|---|
| T+00:00 | First failure: `invalid user root` from 203.0.113.44 |
| T+00:18 → T+02:06 | 7 more failures: `admin`, `oracle`, `postgres`, `ubuntu`, `test`, `root`, `admin` |
| T+02:06 | Correlation `corr-ssh-bruteforce` reaches threshold (8 failures / 5 min) |
| T+03:54 | 14th failure: `invalid user admin` |
| T+04:30 | **Success:** `Accepted password for deploy from 203.0.113.44` |
| T+04:30 → T+34:30 | No new user, cron, sudo, or outbound connection attributed to the session |

## Evidence

```text
2026-11-11T10:50:21.435Z  Failed password for invalid user root from 203.0.113.44 port 51000 ssh2
2026-11-11T10:50:39.435Z  Failed password for invalid user admin from 203.0.113.44 port 51001 ssh2
2026-11-11T10:50:57.435Z  Failed password for invalid user oracle from 203.0.113.44 port 51002 ssh2
...
2026-11-11T10:53:57.435Z  Failed password for invalid user root from 203.0.113.44 port 51012 ssh2
2026-11-11T10:54:15.435Z  Failed password for invalid user admin from 203.0.113.44 port 51013 ssh2
2026-11-11T10:54:51.435Z  Accepted password for deploy from 203.0.113.44 port 51999 ssh2
```

Correlation output:

```json
{
  "correlation_id": "corr-ssh-bruteforce",
  "group_by": "source.ip",
  "group_value": "203.0.113.44",
  "count": 8,
  "threshold": 8,
  "window_seconds": 300,
  "first_seen": "2026-11-11T10:50:21.435Z",
  "last_seen": "2026-11-11T10:52:27.435Z"
}
```

## Analysis

* **Why true positive.** Failures are sequential, evenly spaced, and rotate usernames. That pattern is automation, not a human mistyping. The successful login comes from the same IP 36 seconds after the last failure.
* **Why the success matters more than the failures.** Failed logins are commodity internet noise and are deliberately `low` severity. The escalation trigger is `failures → success from the same source`, which is exactly what `corr-ssh-bruteforce` encodes.
* **Scope check.** Querying `lab-*` for `source.ip: 203.0.113.44` over 24 hours returns only these 15 authentication events. No web, process, or file activity from that address.
* **Host check.** Within the session window there is no `new user:`, no `CMD (` cron entry, and no sudo event on `linux01`. Two persistence alerts on the same host at 10:15Z and 10:17Z were reviewed and attributed to a separate maintenance change; they are outside this incident window and were closed independently.
* **What is missing.** `deploy` is a real, privileged-looking account name. Whether it is in `sudoers` is not visible in this telemetry and would be the first question in a real environment.

## ATT&CK mapping

| Technique | Evidence |
|---|---|
| T1110.001: Password Guessing | 14 failures, 6 usernames, one source |
| T1078: Valid Accounts | Successful authentication as `deploy` |
| T1021.004: SSH | Service used for access |

## Verdict

**True positive: successful unauthorized access.** The failed attempts alone would be background noise. The success converts this into a credential compromise.

## Containment and recommendations

1. Block `203.0.113.44` at the perimeter and on `linux01` (`sshd` `DenyUsers`/firewall).
2. Disable `deploy`, force a password reset, and rotate any SSH keys in `~deploy/.ssh/`.
3. Review `sudoers`, `authorized_keys`, `crontab -l`, and `~/.bash_history` for the account.
4. Hunt for outbound connections from `linux01` in the 24 hours after the login.
5. Enable MFA for SSH and add rate limiting (`fail2ban` or `sshd` `MaxAuthTries` plus firewall rules).

## Detection improvements

* Add a `failures → success` sequence rule so the pivot is a first-class alert rather than an analyst inference.
* Enrich `source.ip` with ASN/geo so a hosting-provider source is visibly different from a corporate address.
* Add T1110.003 (password spraying) for distributed low-and-slow attempts, which the per-IP threshold will not catch.

## Reproduce

```powershell
.\.venv\Scripts\python.exe -m pipeline.labgen --scenario ssh-bruteforce
.\.venv\Scripts\python.exe -m pipeline.correlate --input lab/logs/linux.ndjson
```

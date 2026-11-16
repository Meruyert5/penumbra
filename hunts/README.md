# Threat hunts

Hypothesis-driven hunts over the deterministic lab corpus. A hunt starts with a
question, then records the query, evidence, verdict, and the detection change it
recommends.

- Hunts: **4**
- Events reviewed: **9,223**
- Hunts with findings: **4**
- Confirmed true positives: **4**

| Hunt | Title | Events | Verdict |
|---|---|---:|---|
| HUNT-001 | Root identity activity in AWS | 4 | True positive |
| HUNT-002 | Service binary outside a trusted path | 1 | True positive |
| HUNT-003 | DNS tunneling pattern | 25 | True positive |
| HUNT-004 | LSASS access from a user-writable path | 1 | True positive |

## HUNT-001 — Root identity activity in AWS

**Hypothesis.** A root principal should not create access keys, create users, or attach policies. Any root action outside a known break-glass window is worth an investigation.

**Query.**

```eql
any where cloud.provider:"aws" and user.name:"root" and event.action in ("ConsoleLogin", "CreateAccessKey", "CreateUser", "AttachUserPolicy")
```

**Finding.** 4 root events across 4 actions: ConsoleLogin x1, CreateAccessKey x1, AttachUserPolicy x1, CreateUser x1.

**Verdict.** True positive (high confidence).

**Detection change.** Alert on root CreateAccessKey, CreateUser, AttachUserPolicy, and ConsoleLogin. Require a break-glass ticket, and export the finding to Apsis so the IAM graph can show which paths the new principal can reach.

**Limitations.** Synthetic root-compromise scenario. A production rule needs a break-glass allowlist and an approved source-IP or identity-provider context.

**Evidence.**

| Time | Host | User | Source | Detail |
|---|---|---|---|---|
| 2026-11-11T00:35:00.000Z | aws-prod | root | 203.0.113.44 | ConsoleLogin -> success |
| 2026-11-11T00:35:30.000Z | aws-prod | root | 203.0.113.44 | CreateAccessKey -> success |
| 2026-11-11T00:35:45.000Z | aws-prod | root | 203.0.113.44 | AttachUserPolicy -> success |
| 2026-11-11T00:36:00.000Z | aws-prod | root | 203.0.113.44 | CreateUser -> success |

## HUNT-002 — Service binary outside a trusted path

**Hypothesis.** A new service should run from a signed system or application path. A service binary in a user-writable directory, or a shell command as the service image, is a persistence lead.

**Query.**

```eql
any where event.code:"7045" and winlog.event_data.ImagePath like~ ("*\\Users\\Public\\*", "*\\AppData\\*", "*\\Temp\\*", "*\\ProgramData\\*", "*cmd.exe*", "*powershell*")
```

**Finding.** 1 service installs matched the heuristic: UpdaterSvc.

**Verdict.** True positive (high confidence).

**Detection change.** The existing rule covers user-writable service paths. Add a software-inventory allowlist, alert on 7045 from non-admin users, and compare the service name with the installed product.

**Limitations.** PSEXESVC is not flagged by the path heuristic because it runs from C:\Windows. The existing rule catches it by name, which is why hunts and rules are complementary.

**Evidence.**

| Time | Host | User | Source | Detail |
|---|---|---|---|---|
| 2026-11-11T12:14:00.000Z | WIN10-LAB |  |  | UpdaterSvc -> C:\Users\Public\svc.exe |

## HUNT-003 — DNS tunneling pattern

**Hypothesis.** A high volume of unique, long subdomains under one parent domain can indicate data encoded in DNS queries.

**Query.**

```eql
any where event.action:"dns_query" and dns.question.name like~ "*.tunnel.example"
```

**Finding.** 25 queries under tunnel.example, 25 unique subdomains, longest label 38 characters.

**Verdict.** True positive (high confidence).

**Detection change.** Add a DNS tunneling rule that scores parent-domain rarity, unique subdomain count, and label length. Exclude known CDN, telemetry, and mail domains.

**Limitations.** Synthetic labels are regular and deliberately easy to spot. A production hunt needs entropy estimates, baseline parent-domain frequency, and resolver context.

**Evidence.**

| Time | Host | User | Source | Detail |
|---|---|---|---|---|
| 2026-11-11T04:08:00.000Z | WIN10-LAB |  |  | 0000-aaaaaaaaaaaaaaaaaaaaaaaaaa-000000.tunnel.example |
| 2026-11-11T04:08:04.000Z | WIN10-LAB |  |  | 0001-aaaaaaaaaaaaaaaaaaaaaaaaaa-000007.tunnel.example |
| 2026-11-11T04:08:08.000Z | WIN10-LAB |  |  | 0002-aaaaaaaaaaaaaaaaaaaaaaaaaa-000014.tunnel.example |
| 2026-11-11T04:08:12.000Z | WIN10-LAB |  |  | 0003-aaaaaaaaaaaaaaaaaaaaaaaaaa-000021.tunnel.example |
| 2026-11-11T04:08:16.000Z | WIN10-LAB |  |  | 0004-aaaaaaaaaaaaaaaaaaaaaaaaaa-000028.tunnel.example |
| 2026-11-11T04:08:20.000Z | WIN10-LAB |  |  | 0005-aaaaaaaaaaaaaaaaaaaaaaaaaa-000035.tunnel.example |
| 2026-11-11T04:08:24.000Z | WIN10-LAB |  |  | 0006-aaaaaaaaaaaaaaaaaaaaaaaaaa-000042.tunnel.example |
| 2026-11-11T04:08:28.000Z | WIN10-LAB |  |  | 0007-aaaaaaaaaaaaaaaaaaaaaaaaaa-000049.tunnel.example |

## HUNT-004 — LSASS access from a user-writable path

**Hypothesis.** A process outside System32 or SysWOW64 should not open LSASS with credential-dumping access. This is a hunt for credential theft that is independent of the existing rule.

**Query.**

```eql
any where event.code:"10" and winlog.event_data.TargetImage:"*lsass.exe" and not winlog.event_data.SourceImage like~ ("C:\\Windows\\System32\\*", "C:\\Windows\\SysWOW64\\*")
```

**Finding.** 1 LSASS access events came from a user-writable path.

**Verdict.** True positive (high confidence).

**Detection change.** The existing rule catches this path. Add a hunt for LSASS access from user-writable directories, and compare the process signer and parent with the rule verdict.

**Limitations.** Security products and diagnostic tools may legitimately access LSASS. Require signer, parent, and change-ticket context before calling it malicious.

**Evidence.**

| Time | Host | User | Source | Detail |
|---|---|---|---|---|
| 2026-11-11T12:10:08.000Z | WIN10-LAB |  |  | C:\Users\Public\mimikatz.exe -> lsass.exe, access 0x1010 |

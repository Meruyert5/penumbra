# Cloud detection pack

CloudTrail detections that complement the IAM path work in Apsis. This pack
is separate from the 50-rule Sigma core and exports the same evidence shape as
the rest of Penumbra.

- Detections: **3**
- Detections fired: **2**
- Events matched: **2**
- Detections not exercised: **1**

| Detection | Level | Technique | Status | Events |
|---|---|---|---|---:|
| CLOUD-001 Root policy attachment | critical | T1098 | fired | 1 |
| CLOUD-002 Root user creation | critical | T1136.003 | fired | 1 |
| CLOUD-003 CloudTrail tampering | critical | T1562.008 | no_match | 0 |

## CLOUD-001 — Root policy attachment

**Description.** A root principal attached or changed a policy. Root should not be doing routine IAM administration.

**Query.**

```eql
any where cloud.provider:"aws" and user.name:"root" and event.action in ("AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy")
```

**Status.** fired (1 events).

**Response hand-off.** Alert on any root policy change, require a break-glass ticket, and export the finding to Apsis so the graph shows the new reachable paths.

**Evidence.**

| Time | Host | User | Source | Detail |
|---|---|---|---|---|
| 2026-11-11T00:35:45.000Z | aws-prod | root | 203.0.113.44 | AttachUserPolicy -> success |

## CLOUD-002 — Root user creation

**Description.** A root principal created a new IAM user. That user is a persistence candidate and needs immediate review.

**Query.**

```eql
any where cloud.provider:"aws" and user.name:"root" and event.action:"CreateUser"
```

**Status.** fired (1 events).

**Response hand-off.** Alert on root-created IAM users, disable the new principal pending review, and add it to the Apsis inventory.

**Evidence.**

| Time | Host | User | Source | Detail |
|---|---|---|---|---|
| 2026-11-11T00:36:00.000Z | aws-prod | root | 203.0.113.44 | CreateUser -> success |

## CLOUD-003 — CloudTrail tampering

**Description.** A principal stopped, deleted, or changed a CloudTrail trail. This is a defense-evasion lead and a visibility emergency.

**Query.**

```eql
any where cloud.provider:"aws" and event.action in ("StopLogging", "DeleteTrail", "UpdateTrail")
```

**Status.** no_match (0 events).

**Response hand-off.** Alert on trail changes, verify the trail with an independent account-level control, and require a change ticket.

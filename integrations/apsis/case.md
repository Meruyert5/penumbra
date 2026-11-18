# Case 01 — the observed path

**Account:** `555566667777` (Games studio, live services)
**Window:** 2026-11-16 18:00–18:42 UTC
**Finding:** `path.opened` — the signature route from Tools intern to the
administrator became observed in CloudTrail.

## Route

```
Tools intern
  -> Build role              sts:AssumeRole
  -> Art pipeline role       iam:PassRole
  -> Game server role        sts:AssumeRole
  -> Live services role      sts:AssumeRole
  -> Live-ops engineer       sts:AssumeRole
  -> Backup role             sts:AssumeRole
  -> Administrator           iam:CreatePolicyVersion
```

## What happened

The Tools intern assumed the build role from a developer workstation, passed
that role to a Lambda function, and used the function to enter the art pipeline.
From there the chain walked through the game server, live services, live-ops and
backup roles. The final step published a policy version that granted
administrator.

The graph had carried this route as theoretical. The CloudTrail window made
every edge observed, so Apsis emitted `path.opened` with the evidence manifest.

## Cut

- Revoke `iam:CreatePolicyVersion` from the backup policy.
- Revoke `iam:CreateAccessKey` from the support role.

The minimum cut closes all 15 routes; the two actions above are the
human-readable revocation steps.

## Guardrails

- SCP: deny `iam:PassRole` to compute outside the platform role set.
- SCP + Config: deny `iam:CreatePolicyVersion` outside the policy platform role.
- CloudTrail alarm: `CreateAccessKey` outside the key service.

## After

`after.json` shows zero routes. `evidence.json` lists the observed events and
the edge facts. The guardrail is recorded in `guardrail.md`, and `alert.json`
is the validated `penumbra.alert/v1` instance handed to Penumbra.

## What this case is not

This is a synthetic, reproducible case built from the shipped fixture. It does
not describe a customer account. The engine overlay that derives `observed`
from a live CloudTrail export is the next step; this case fixes the contract,
the alert and the narrative first.

# Guardrail — case 01

The cut closes the route. The guardrails keep it closed.

| Control | Scope | Why | Verification |
| --- | --- | --- | --- |
| SCP: deny `iam:PassRole` to compute outside the platform role set | Organization / account | Breaks the build → art → function leg | Re-run Apsis: the edge is theoretical, not observed |
| SCP + Config: deny `iam:CreatePolicyVersion` outside the policy platform role | Account | Breaks the backup → administrator leg | Config rule `iam-policy-version-created` stays compliant |
| CloudTrail alarm: `CreateAccessKey` outside the key service | Account | Catches the alternate support path | Alarm in OK state; no new key events |

## Notes

- The guardrails are recommendations. Apsis never applies them.
- The SCP is the preventive control; the Config rule and the alarm are the
  detective controls. Use both.
- If the platform team needs `PassRole`, scope it to the exact function ARNs
  rather than removing the control.

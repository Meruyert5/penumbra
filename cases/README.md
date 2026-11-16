# Case Reports

Each folder is one investigation, written the way a SOC ticket is written: summary first, then timeline, evidence, scope, ATT&CK mapping, verdict, containment, and lessons learned.

| Case | Scenario | Verdict |
|---|---|---|
| [001: SSH brute force](case-001-ssh-bruteforce/report.md) | 14 failures, then a success from one source | True positive, successful unauthorized access |
| [002: Multi-stage intrusion](case-002-multi-stage-intrusion/report.md) | Macro, encoded PowerShell, certutil, LSASS, persistence | True positive, credential theft and persistence |
| [003: Ransomware sequence](case-003-ransomware/report.md) | Recovery deletion, service stops, notes, 24 encrypted files | True positive, contained before the share was lost |

The close-out layer — metrics, containment, eradication, recovery, communication,
evidence handling, lessons, and open questions — is in
[the IR casebook](IR.md).

## Report template

```markdown
# Case NNN: <short title>

| Field | Value |
|---|---|
| Case ID | DL-YYYY-NNN |
| Date | |
| Analyst | |
| Severity | |
| Status | |
| Data sources | |
| Detections | |

## Summary
Three to five sentences. What happened, on which host, and why it matters.

## Timeline
| Offset | Time | Event | Detection |

## Evidence
Verbatim log lines or query output. Enough that someone else can verify the claim.

## Analysis
What the evidence supports, and what it does not. Name the gaps.

## ATT&CK mapping
| Technique | Evidence |

## Verdict
True positive, benign true positive, or false positive. Give the reason in one sentence.

## Containment and recommendations
Ordered actions, most urgent first.

## Detection improvements
What this case taught you about the rules.

## Reproduce
Exact commands.
```

## Rules for writing these

* Quote real output, not paraphrases. If the log line is synthetic, say so.
* State what you did **not** find. Negative findings are evidence too.
* Never write "looks malicious". Name the behaviour and the technique.
* If the verdict changed after investigation, say so and why.

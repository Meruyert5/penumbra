# Cross-project handoffs

This folder holds incoming contracts from the other flagships. It is data and
documentation, never imported code.

| Handoff | Source | Status | Contents |
| --- | --- | --- | --- |
| [`apsis/`](apsis/) | Apsis (`https://github.com/<owner>/apsis`, link pending) | Delivered | `penumbra.alert/v1`, `penumbra.evidence/v1`, the observed-path case, guardrails and before/after snapshots |
| [`network/`](network/) | Network threat hunting (`https://github.com/<owner>/network-threat-hunting`, link pending) | Planned | Capture plan and acceptance checklist; no capture or evidence yet |

The boundary is the contract:

- Apsis proves the cloud identity route and emits the alert.
- The network lab will prove the traffic and emit the same evidence manifest.
- Penumbra proves the detection and response, and may cite the incoming alert id.
- No connector API, shared database or cross-repository import.

## Why one folder is empty

`network/` contains a plan, not evidence. The network project is still planned;
the dashboard shows its stages as planned and its observed event count as zero.
When the first approved capture is parsed and hunted, the folder will hold the
same artifact set as `apsis/` and the dashboard will switch the source to
delivered without a code change.

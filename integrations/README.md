# Cross-project handoffs

This folder holds delivered contracts from the other flagships. It is data and
documentation, never imported code.

| Handoff | Source | Contents |
| --- | --- | --- |
| [`apsis/`](apsis/) | [Apsis](https://github.com/Meruyert5/apsis), commit `b50f894` | `penumbra.alert/v1`, `penumbra.evidence/v1`, the observed-path case, guardrails and before/after snapshots |

The boundary is the contract:

- Apsis proves the cloud identity route and emits the alert.
- Penumbra proves the detection and response, and may cite the alert id.
- No connector API, shared database or cross-repository import.


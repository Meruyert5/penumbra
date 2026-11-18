# Network handoff - awaiting first capture

This folder is reserved for the network threat-hunting -> Penumbra handoff. No
capture, alert, or evidence manifest exists yet. The dashboard shows the planned
stages and the acceptance checklist; it does not show observed events.

## Why it is empty

The network project is planned in the portfolio roadmap. A handoff is accepted
only after a real, approved capture is parsed, hunted, and written into the
contract. Until then, this folder holds the plan, not evidence. Fabricating
flows would make the cross-project story false and would break the rule that
every number in the dashboard traces to an event.

The dashboard reads `plan.json` for the source name, stages, contract target,
requirements, and stats. It never reads an `events` array from this folder.

## Contract target

| Field | Value |
| --- | --- |
| Source repository | `https://github.com/<owner>/network-threat-hunting` (link pending) |
| Status | Planned; no capture |
| Alert | `penumbra.alert/v1`; a `flow.suspicious` kind lands in a v1.1 revision before first delivery |
| Evidence | `penumbra.evidence/v1` (unchanged) |
| Case | none |

The evidence manifest is already general enough for network flows: an event has
a time, an actor, an action, a target, a source, and an IP. The alert kind set is
specific to Apsis and must be revised before a network finding can validate
against the same schema.

## What must land

| Artifact | Required content |
| --- | --- |
| `alert.json` | One `penumbra.alert/v1` finding with the revised network kind |
| `evidence.json` | One `penumbra.evidence/v1` manifest with the flows and edge facts behind the finding |
| `capture.json` | PCAP source, license, SHA-256, capture window, sensor, and retention note |
| `case.md` | The narrative from capture to verdict, including what was benign and why |
| `response.md` | Containment or blocking guidance for the traffic and the hosts that produced it |
| `schema/` | The alert and evidence contracts copied into the folder |

## Capture rules

- Approved public PCAPs only. No live customer traffic, credentials, or personal
  data.
- Record the source, license, SHA-256, capture window, and parser version for
  every artifact.
- Keep the raw PCAP out of the repository unless its license allows
  redistribution. Commit the hash and the derived telemetry instead.
- One event per observed edge. A route is observed only when every edge in the
  manifest is observed.
- No hand-written events. Every event must be produced by the parser from the
  capture.

## Acceptance

A delivery is accepted only when:

1. `alert.json` and `evidence.json` validate against the copied schemas.
2. Every stage in the finding cites an event id in the manifest.
3. Every event has a source, a timestamp, a parser or query, and a retention
   note.
4. `case.md` and `response.md` exist and agree with the manifest.
5. The dashboard shows the source as delivered and the observed counts are
   non-zero.

## Boundary

- The network lab owns capture, parsing, hunting, and the verdict.
- Penumbra owns intake, triage, response, and casework.
- The contract is the coupling: no connector API, no shared database, no
  cross-repository import.

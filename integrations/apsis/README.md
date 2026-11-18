# Apsis handoff - the observed path

This folder is the delivered Apsis -> Penumbra handoff. It is data, not code: an
alert, the evidence behind it, the human case, the route snapshots and the
schemas that bind them.

| Field | Value |
| --- | --- |
| Source repository | `https://github.com/<owner>/apsis` (link pending) |
| Contract | `penumbra.alert/v1` + `penumbra.evidence/v1` |
| Case | `01-observed-path`, Games Studio fixture `555566667777` |
| Finding | `path.opened` - Tools intern to administrator, seven hops |
| Severity | Critical |
| Data | Synthetic fixture. No customer account, credential or live export |

## Artifacts

| File | Purpose |
| --- | --- |
| `alert.json` | The emitted finding. Principal, route, edges, cut, guardrails |
| `evidence.json` | Seven CloudTrail events and seven observed graph edges |
| `case.md` | The human narrative: route, evidence, cut and guardrails |
| `guardrail.md` | The preventive and detective controls that keep it closed |
| `before.json` | The route state before the cut: 15 routes, observed |
| `after.json` | The route state after the cut: 0 routes |
| `cloudtrail.json` | The synthetic events that made every edge observed |
| `schema/*.json` | The two contracts, copied so this folder is self-contained |

## How to consume it

1. Read `alert.json`. `route` is the ordered principal chain; `edges` are the
   graph edge ids that carry it; `cut` is the minimum revocation set.
2. Open `evidence.json`. It contains the events and the edge facts, with the same
   edge ids. This is the manifest a triage or case view should cite.
3. Use `case.md` for the narrative and `guardrail.md` for the response actions.
4. Do not import Apsis code. Do not write back to the account.

```json
{
  "schema": "penumbra.alert/v1",
  "kind": "path.opened",
  "source": "apsis",
  "account": "555566667777",
  "principal": "gs-intern",
  "route": ["Tools intern", "Build role", "Art pipeline role", "Game server role", "Live services role", "Live-ops engineer", "Backup role", "Administrator"],
  "edges": ["e4", "e3", "e0", "e10", "e5", "e8", "e1"],
  "observed": true,
  "severity": "critical"
}
```

## Validation

Both payloads validate against the copied schemas:

```powershell
python -c "import jsonschema, json; jsonschema.validate(json.load(open('alert.json')), json.load(open('schema/alert.schema.json'))); jsonschema.validate(json.load(open('evidence.json')), json.load(open('schema/evidence.schema.json'))); print('contracts valid')"
```

## Boundary

- Apsis owns the identity graph, the route, the minimum cut and the alert.
- Penumbra owns detection, triage, response and the case narrative after intake.
- The contract is the coupling: no connector API, no shared database, no
  cross-repository import.

## Engine status

The CloudTrail overlay and the read-only IAM import now ship in Apsis. This
handoff was generated from the shipped synthetic observed-path case and is
stable across those engine changes. Apsis tests: 89 Python tests, 5 logic
tests, a successful console build, and valid alert/evidence contracts.


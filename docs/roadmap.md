# Portfolio roadmap

Three complete projects, no connector. Each project owns one question. They share
evidence formats and case studies, not a separate integration layer.

## Principles

- One sentence per project. If a module does not serve that sentence, it belongs
  somewhere else.
- Every module produces evidence or a metric, not just code.
- New work arrives as an optional module, not a rewrite of the core.
- Projects cross-link through schemas and case studies, never through a connector
  repository.

## Penumbra — detection and response

**Thesis:** Prove what a detection fired on, what happened next, and how well it
performed.

| Module | State | Deliverable |
|---|---|---|
| Detection library | Done | 50 Sigma rules compiled to EQL and KQL, with ATT&CK coverage |
| Validation benchmark | Done | 16 labelled windows across five indices; 6 TP, 0 FP, 1 FN |
| Threat hunting | Done | Four hypothesis-driven hunts with queries, evidence, verdicts, and detection changes |
| IR casebook | Done | Three structured close-outs with metrics, containment, eradication, recovery, communication, evidence, lessons, and open questions |
| Triage automation | Done | Dry-run enrichment, incident grouping, playbook selection, and 78 recommended actions; no external API calls |
| Cloud detection pack | Done | Three CloudTrail detections; two fired on the synthetic corpus, one is awaiting telemetry |
| Dashboard integration | Active | Response in Instruments, hunting in Umbra, validation in Corona, IR in Eclipses, and roadmap in After; selector/detail instruments on dark instrument plates with eclipse accents, corona glow, animated flow, radar, timeline, bridge, and vinyl record |

**Done means:** a reviewer can follow a hunt or a case from telemetry to verdict
without reading the source code.

## Apsis — cloud identity

**Thesis:** Find every route from a low-privilege AWS principal to administrator,
prove which ones are real, and sever them.

| Module | State | Deliverable |
|---|---|---|
| IAM graph | Done | Users, roles, policies, and every route to administrator |
| Minimum cut | Done | The fewest permissions to revoke to close every route |
| Drift | Done | Diff two account exports and fail a newly opened route |
| Observed paths | Next | Overlay CloudTrail to mark theoretical and observed graph edges |
| Guardrails | Next | Map each cut to an SCP, permission boundary, or AWS Config rule |
| Case study | Planned | A safe lab path from low privilege to admin, with evidence and a verified fix |

**Done means:** a reviewer can see a path, the evidence that it is real, and the
guardrail that closes it.

## Network threat hunting — packet to detection

**Thesis:** Hunt C2, DNS tunneling, and lateral movement from packet capture to a
defensible detection.

| Module | State | Deliverable |
|---|---|---|
| Capture lab | Planned | Zeek and Suricata telemetry from approved public PCAPs |
| Hunt set | Planned | Five hypotheses: C2 beaconing, DNS tunneling, lateral movement, staging, TLS or JA3 |
| Detections | Planned | Five network detections with ATT&CK mapping and evidence |
| Reports | Planned | Two full hunt reports and one PCAP-to-detection walkthrough |

**Done means:** a reviewer can replay a capture, see the hunt, and explain why the
traffic is benign or malicious.

## Sequence

1. Finish Apsis: observed paths, guardrails, and the attack-path case study.
2. Penumbra extensions: hunting, IR casebook, triage automation, and the cloud
   pack are done; next is the dashboard integration pass.
3. Build the network threat-hunting lab after the two existing projects are
   complete.

The sequence is an order, not a schedule.

## Shared evidence

| Artifact | Purpose |
|---|---|
| Alert schema | Common JSON shape for rule ID, technique, host, user, cloud, and evidence |
| Case template | Summary, timeline, evidence, verdict, containment, eradication, and lessons |
| Evidence manifest | Source, hash, timestamp, query, and retention note for every artifact |

Apsis exports a path-opened finding in the alert schema. Penumbra can triage it.
The network project writes its evidence in the same manifest. That is the
connector: a format, not a repository.

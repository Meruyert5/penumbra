# Benchmark metrics

Fig. 4 now carries a real, small-sample benchmark: 16 reviewed windows across
five indices, scored per rule. `pipeline.benchmark` is the engine. It does not
download data and it does not infer labels from what happened to fire. The labels
manifest is human-reviewed.

## Corpus

| Index | Samples | Events | Rules with signal |
|---|---|---:|---|
| Windows | OTRF Security and Sysmon; Splunk service, Kerberos, and SMB XML | 234 | 4 |
| Linux | OTRF auditd; Splunk auditd; Elastic RHEL auth | 1,021 | 1 |
| Web | Elastic nginx access; Splunk Log4Shell and Bricks SQLi | 18 | 0 |
| Cloud | OTRF AWS CloudTrail S3 exfiltration | 103 | 0 |
| Network | Elastic Zeek connection log | 5 | 0 |
| **Real total** | **16 labelled windows** | **1,381** | **5** |

The 89,704-event benign baseline is synthetic and remains a separate scale test.
The real benign subset is 17 events: 12 nginx requests and 5 Zeek flows.

### Sample provenance

| Sample | Path |
|---|---|
| Windows Security | `OTRF/Security-Datasets` → `datasets/atomic/windows/execution/host/psh_powershell_httplistener.zip` |
| Sysmon / LSASS | `OTRF/Security-Datasets` → `datasets/atomic/windows/credential_access/host/cmd_lsass_memory_dumpert_syscalls.zip` |
| Service creation | `splunk/attack_data` → `datasets/attack_techniques/T1543.003/windows_krbrelayup_service_creation/windows-xml.log` |
| Kerberoasting | `splunk/attack_data` → `datasets/attack_techniques/T1558.003/kerberoasting_spn_request_with_rc4_encryption/windows-xml.log` |
| SMB ADMIN$ | `splunk/attack_data` → `datasets/attack_techniques/T1021.002/executable_in_share/windows_security_xml.log` |
| auditd setuid | `splunk/attack_data` → `datasets/attack_techniques/T1548.001/linux_auditd_setuid/linux_auditd_setuid.log` |
| auditd crontab | `splunk/attack_data` → `datasets/attack_techniques/T1053.003/linux_auditd_crontab_edit_new/linux_auditd_new_crontab.log` |
| auditd ssh_config | `splunk/attack_data` → `datasets/attack_techniques/T1098.004/auditd_path_ssh_config/path_ssh_config.log` |
| Log4Shell | `splunk/attack_data` → `datasets/attack_techniques/T1190/log4j_proxy_logs/log4j_proxy_logs.log` |
| Bricks SQLi | `splunk/attack_data` → `datasets/attack_techniques/T1190/wordpress/bricks_cve_2024_25600.log` |
| nginx access | `elastic/beats` → `filebeat/module/nginx/access/test/access.log` |
| RHEL auth | `elastic/beats` → `filebeat/module/system/auth/test/secure-rhel7.log` |
| Zeek conn | `elastic/beats` → `x-pack/filebeat/module/zeek/connection/test/connection-json.log` |
| AWS CloudTrail | `OTRF/Security-Datasets` → `datasets/atomic/aws/collection/ec2_proxy_s3_exfiltration.zip` |
| Linux auditd `dd` | `OTRF/Security-Datasets` → `datasets/atomic/linux/defense_evasion/host/sh_binary_padding_dd.zip` |

Raw telemetry is kept outside the repository and was deleted after the replay.
Only the labels, metrics, commands, and normalized proof manifest are committed.

## Results

| Metric | Value |
|---|---:|
| True positives | 6 |
| False positives | 0 |
| False negatives | 1 |
| Alert volume | 359 |
| Precision | 1.000 |
| Recall | 0.857 |
| Rules with signal | 6 |
| Rules evaluated | 50 |
| Not evaluable | 0 |

| Rule | TP | FP | FN | Precision | Recall | Alert volume |
|---|---:|---:|---:|---:|---:|---:|
| Windows Event Log Cleared | 2 | 0 | 0 | 1.000 | 1.000 | 2 |
| Kerberoasting Service Ticket Request | 1 | 0 | 0 | 1.000 | 1.000 | 1 |
| SSH Failed Password Authentication | 1 | 0 | 0 | 1.000 | 1.000 | 352 |
| Suspicious Process Access to LSASS | 1 | 0 | 0 | 1.000 | 1.000 | 2 |
| Suspicious Service Installed From User-Writable Path | 1 | 0 | 0 | 1.000 | 1.000 | 2 |
| SMB Administrative Share Access | 0 | 0 | 1 | – | 0.000 | 0 |

Counts are **sample-level**, not event-level. A rule that fires in a labelled
window counts once for that window. Alert volume is the exact count from the
compiled KQL query, not the 100-event EQL sample stored in `alerts.json`.

In Fig. 4, click a rule name to open the labelled windows behind its counts,
including each window's result, date range, expected rule, and note.

## The false negative

The SMB capture contains two Security **5145** records for `\\*\ADMIN$`. The
rule queries **5140**, the older share-access event. The field `ShareName` is
mapped, so the rule evaluates; it simply does not match. That is a real miss:
the detection should cover 5145 or normalize the event code.

## Coverage gaps that are not counted as false negatives

Seven malicious windows exercise techniques with no matching rule:

- binary padding (`dd`) — T1027.001;
- auditd setuid — T1548.001;
- auditd crontab edit — T1053.003;
- `ssh_config` change — T1098.004;
- S3 exfiltration — T1530/T1567;
- Log4Shell JNDI payload — T1190;
- Bricks SQL injection in the request body — T1190.

The web rules only inspect `url.query`, so the body SQLi is invisible to them.
These are coverage gaps, not counted per-rule false negatives because no rule
targets them. They are listed in the dashboard gaps panel.

## Labels manifest

[`labels.json`](labels.json) has one entry per window:

```json
{
  "id": "rhel7-ssh-bruteforce",
  "label": "malicious",
  "start": "2026-02-22T16:45:20Z",
  "end": "2026-02-22T17:04:51Z",
  "techniques": ["T1110.001"],
  "expected_rules": ["SSH Failed Password Authentication"]
}
```

- `expected_rules` is the reviewed set of rules that should fire.
- An explicit empty list means “no rule is expected”, which records a coverage
  gap. It does **not** trigger technique-based derivation.
- If `expected_rules` is omitted, the engine derives expected rules from the
  sample's ATT&CK techniques. That is a shortcut, not a substitute for review.
- A benign sample has no expected rules; any alert is a false positive.

The RHEL auth fixture has no year. The replay anchors it to 2026 for ordering
only; the label and the replay use the same anchor.

## Run

```powershell
python -m pipeline.replay --source <sample> --format <parser> --file <index> --append
python -m pipeline.ingest --logs lab/corpus --reset
python -m pipeline.detect --hours 90000 --end 2026-11-16T00:00:00Z --out lab/corpus-results
python -m pipeline.benchmark `
  --alerts lab/corpus-results/alerts.json `
  --labels docs/validation/labels.json `
  --out docs/validation/benchmark-results.json `
  --markdown docs/validation/benchmark-results.md
```

The parser formats are `otrf`, `winxml`, `auditd`, `auth`, `nginx`, and `zeek`.
`--append` keeps one NDJSON file per index while samples are added one at a time.

## Source map

| Index | Public source | Status |
|---|---|---|
| Windows Security | OTRF Security-Datasets | Done; 110-event sample |
| Sysmon | OTRF Security-Datasets | Done; 118-event sample |
| Service / Kerberos / SMB | Splunk attack_data XML | Done; 6 events close the five missing-field rules |
| Linux audit/auth | OTRF, Splunk attack_data, Elastic Beats | Done; auditd and auth parsers |
| Web / nginx | Elastic Beats, Splunk attack_data | Done; combined and key=value parsers |
| AWS CloudTrail | OTRF Security-Datasets | Done; CloudTrail mapper |
| Network flow | Elastic Beats Zeek fixture | Done; Zeek conn parser |

## Limits

- The corpus is small: 1,381 real events. It is not an enterprise baseline.
- Only 6 of 50 rules had signal, so most per-rule precision and recall values are
  undefined rather than 1.000.
- One false negative is too few to estimate a stable recall.
- The labels are reviewed but the sample selection is opportunistic; it is not a
  random or stratified sample of attacker behaviour.
- Correlation alerts are reported separately and are not part of the per-rule
  precision and recall table.

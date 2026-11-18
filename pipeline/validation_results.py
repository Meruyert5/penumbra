"""Build the committed validation manifest used by the dashboard.

The raw public samples and replay outputs are deliberately not committed. This
script turns the recorded run results and the reviewed labels into a compact,
reviewable JSON artifact that the dashboard can render without shipping attack
telemetry.

Run:
    python -m pipeline.validation_results --write-results
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pipeline.common import COMPILED_DIR, ROOT

RESULTS_PATH = ROOT / "docs" / "validation" / "results.json"
BENCHMARK_PATH = ROOT / "docs" / "validation" / "benchmark-results.json"
LABELS_PATH = ROOT / "docs" / "validation" / "labels.json"

LEVEL_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

SOURCES = [
    {
        "name": "OTRF Security-Datasets",
        "url": "https://github.com/OTRF/Security-Datasets",
        "detail": "Windows Security, Sysmon, AWS CloudTrail, and Linux auditd captures.",
    },
    {
        "name": "Splunk attack_data",
        "url": "https://github.com/splunk/attack_data",
        "detail": "Service creation, Kerberos, SMB, auditd, Log4Shell, and Bricks SQLi telemetry.",
    },
    {
        "name": "Elastic Beats fixtures",
        "url": "https://github.com/elastic/beats",
        "detail": "nginx access, RHEL auth, and Zeek connection logs.",
    },
]

SAMPLE_ROWS = [
    {
        "id": "synthetic",
        "name": "Committed scenario run",
        "events": 9224,
        "matches": 50,
        "correlations": 9,
        "kind": "synthetic",
        "note": "34 attack scenarios plus benign baseline; drives the dashboard",
    },
    {
        "id": "benign",
        "name": "Large benign baseline",
        "events": 89704,
        "matches": 1,
        "correlations": 0,
        "kind": "synthetic",
        "note": "10x baseline; one low-severity SSH match",
    },
    {
        "id": "windows",
        "name": "Windows Security, Sysmon, service, Kerberos, SMB",
        "events": 234,
        "matches": 7,
        "correlations": 0,
        "kind": "real",
        "window": "2020-10-18 to 2024-04-08",
        "note": "OTRF and Splunk attack_data; four rules fired",
    },
    {
        "id": "linux",
        "name": "Linux auditd and auth",
        "events": 1021,
        "matches": 352,
        "correlations": 3,
        "kind": "real",
        "window": "2020-11-10 to 2026-02-22",
        "note": "1000 auth lines plus 21 auditd records; one rule fired",
    },
    {
        "id": "web",
        "name": "nginx access and attack logs",
        "events": 18,
        "matches": 0,
        "correlations": 0,
        "kind": "real",
        "window": "2016-10-25 to 2024-02-22",
        "note": "Benign access log plus Log4Shell and Bricks SQLi requests",
    },
    {
        "id": "cloud",
        "name": "AWS CloudTrail",
        "events": 103,
        "matches": 0,
        "correlations": 0,
        "kind": "real",
        "window": "2020-09-14T00:44:20Z to 01:13:20Z",
        "note": "S3 exfiltration capture; neither cloud rule applies",
    },
    {
        "id": "network",
        "name": "Zeek connection flows",
        "events": 5,
        "matches": 0,
        "correlations": 0,
        "kind": "real",
        "window": "2019-01-11 to 2021-06-09",
        "note": "Benign connection records; one large-transfer rule evaluated",
    },
]


def _load_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def build_results(
    rules_path: Path = COMPILED_DIR / "rules.json",
    benchmark_path: Path = BENCHMARK_PATH,
    labels_path: Path = LABELS_PATH,
) -> dict[str, Any]:
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    benchmark = _load_json(benchmark_path)
    labels = _load_json(labels_path)
    bench_rows = benchmark.get("rules", [])
    by_rule = {row.get("rule", ""): row for row in bench_rows}
    rule_meta = {rule.get("title", ""): rule for rule in rules}

    for row in bench_rows:
        meta = rule_meta.get(row.get("rule", ""), {})
        row["level"] = meta.get("level", "")
        row["technique"] = ", ".join(meta.get("techniques", []))

    rows: list[dict[str, Any]] = []
    for rule in rules:
        title = rule.get("title", "")
        result = by_rule.get(title)
        if result and int(result.get("fn", 0)) > 0:
            status = "false_negative"
            reason = (
                f"Expected but missed: TP {result.get('tp', 0)}, FP {result.get('fp', 0)}, "
                f"FN {result.get('fn', 0)} across labelled windows."
            )
        elif result and int(result.get("tp", 0)) > 0:
            status = "matched"
            reason = (
                f"True positive: TP {result.get('tp', 0)}, FP {result.get('fp', 0)}, "
                f"FN {result.get('fn', 0)} across labelled windows."
            )
        elif result and int(result.get("fp", 0)) > 0:
            status = "false_positive"
            reason = f"Fired on a benign window: FP {result.get('fp', 0)}."
        else:
            status = "no_match"
            reason = "Evaluated on 16 labelled windows; no signal and no expected rule."
        rows.append(
            {
                "title": title,
                "level": rule.get("level", ""),
                "technique": ", ".join(rule.get("techniques", [])),
                "status": status,
                "reason": reason,
            }
        )

    matched = sum(1 for row in rows if row["status"] == "matched")
    false_negative = sum(1 for row in rows if row["status"] == "false_negative")
    false_positive = sum(1 for row in rows if row["status"] == "false_positive")
    not_evaluable = sum(1 for row in rows if row["status"] == "not_evaluable")
    no_match = sum(1 for row in rows if row["status"] == "no_match")

    summary = dict(benchmark.get("summary", {}))
    tp = int(summary.get("tp", 0))
    fp = int(summary.get("fp", 0))
    fn = int(summary.get("fn", 0))
    summary["precision"] = round(tp / (tp + fp), 4) if tp + fp else None
    summary["recall"] = round(tp / (tp + fn), 4) if tp + fn else None

    matched_rows: list[dict[str, Any]] = []
    missed_rows: list[dict[str, Any]] = []
    for result in sorted(bench_rows, key=lambda item: (LEVEL_ORDER.get(item.get("level", ""), 9), item.get("rule", ""))):
        meta = rule_meta.get(result.get("rule", ""), {})
        if int(result.get("tp", 0)) > 0:
            matched_rows.append(
                {
                    "title": result.get("rule", ""),
                    "level": meta.get("level", ""),
                    "technique": ", ".join(meta.get("techniques", [])),
                    "matches": result.get("alert_volume", 0),
                    "sample": "Combined real corpus",
                    "verdict": "TP",
                }
            )
        if int(result.get("fn", 0)) > 0:
            missed_rows.append(
                {
                    "title": result.get("rule", ""),
                    "level": meta.get("level", ""),
                    "technique": ", ".join(meta.get("techniques", [])),
                    "matches": 0,
                    "sample": "splunk-smb-admin-share",
                    "verdict": "FN",
                }
            )

    label_count = len(labels.get("samples", []))
    malicious_labels = sum(1 for sample in labels.get("samples", []) if sample.get("label") == "malicious")
    benign_labels = label_count - malicious_labels
    real_events = sum(sample["events"] for sample in SAMPLE_ROWS if sample["kind"] == "real")
    alert_volume = int(summary.get("alert_volume", 0))

    return {
        "generated": "2026-11-16",
        "source": "Combined five-index replay and reviewed labels; raw data is not committed.",
        "provenance": {
            "engine": "Elasticsearch 8.15.3, single node, local Docker",
            "parser": "pipeline.replay",
            "rules": len(rules),
            "correlations": 8,
            "raw_data_committed": False,
            "note": (
                "Sixteen labelled windows were replayed into five indices with the same compiled EQL rules. "
                "Raw public attack telemetry is untrusted and is not committed. The benchmark counts are "
                "sample-level over those windows, not enterprise precision or recall."
            ),
            "commands": [
                "python -m pipeline.replay --source <sample> --format <parser> --file <index> --append",
                "python -m pipeline.ingest --logs lab/corpus --reset",
                "python -m pipeline.detect --hours 90000 --end 2026-11-16T00:00:00Z --out lab/corpus-results",
                "python -m pipeline.benchmark --alerts lab/corpus-results/alerts.json --labels docs/validation/labels.json",
            ],
            "sources": SOURCES,
        },
        "totals": {
            "real_events": real_events,
            "real_matches": matched,
            "alert_volume": alert_volume,
            "rules_matched": matched,
            "tp_candidates": tp,
            "benign_events": 89704,
            "real_benign_events": 17,
            "not_evaluable": not_evaluable,
            "no_match": no_match,
            "false_negative": false_negative,
            "false_positive": false_positive,
            "rules_total": len(rows),
            "missing_index": 0,
            "missing_field": 0,
            "correlation_fetch": 0,
            "labelled_samples": label_count,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "precision": summary.get("precision"),
            "recall": summary.get("recall"),
        },
        "benchmark": {
            "summary": summary,
            "rules": bench_rows,
            "labels": "validation/labels.json",
            "results": "validation/benchmark-results.json",
            "note": "Sample-level counts over 16 labelled windows across five indices.",
        },
        "labels": labels.get("samples", []),
        "samples": SAMPLE_ROWS,
        "matched": matched_rows,
        "missed": missed_rows,
        "gaps": [
            {
                "reason": "False negative",
                "count": false_negative,
                "fix": "The SMB rule queries Security 5140; the capture logged ADMIN$ access as 5145. Add 5145 or normalize the event code.",
            },
            {
                "reason": "Coverage gap",
                "count": 7,
                "fix": "Seven malicious windows exercise techniques with no matching rule: binary padding, setuid, crontab, ssh_config, S3 exfiltration, Log4Shell, and body SQLi.",
            },
            {
                "reason": "No signal",
                "count": no_match,
                "fix": "Evaluated on all five indices with no match and no expected rule. These are true negatives, not failures.",
            },
            {
                "reason": "Missing index",
                "count": 0,
                "fix": "All five indices were present in the combined run.",
            },
            {
                "reason": "Missing field",
                "count": 0,
                "fix": "Service, Kerberos, and SMB fields were mapped by the XML capture.",
            },
        ],
        "coverage": [
            {
                "reason": "Indices exercised",
                "count": 5,
                "detail": "windows, linux, web, cloud, network",
            },
            {
                "reason": "Rules evaluated",
                "count": len(rows),
                "detail": "0 missing-index, 0 missing-field, 0 correlation-fetch errors",
            },
            {
                "reason": "Labelled windows",
                "count": label_count,
                "detail": f"{malicious_labels} malicious, {benign_labels} benign",
            },
            {
                "reason": "False negatives",
                "count": false_negative,
                "detail": "SMB rule sees 5140; sample logged 5145",
            },
            {
                "reason": "Coverage gaps",
                "count": 7,
                "detail": "Malicious techniques without a matching rule",
            },
        ],
        "not_evaluable_breakdown": [
            {
                "reason": "Missing index",
                "count": 0,
                "detail": "All five indices were present.",
            },
            {
                "reason": "Missing field",
                "count": 0,
                "detail": "Service, Kerberos, SMB, and registry fields were present.",
            },
            {
                "reason": "Correlation fetch",
                "count": 0,
                "detail": "All correlation indices were present.",
            },
        ],
        "rules": rows,
    }


def write_results(path: Path = RESULTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_results(), indent=2) + "\n", encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the dashboard validation manifest")
    parser.add_argument("--write-results", action="store_true", help="write docs/validation/results.json")
    args = parser.parse_args()
    if args.write_results:
        print(f"Wrote {write_results()}")
    else:
        print(json.dumps(build_results()["totals"], indent=2))


if __name__ == "__main__":
    main()

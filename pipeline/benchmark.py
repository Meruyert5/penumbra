"""Compute per-rule TP/FP/FN and precision/recall from labels and a detect run.

This is the metrics engine for a real comparison. It does not download data and
does not infer labels from what happened to fire. A labels manifest must state
the malicious windows and the expected rules (or the expected ATT&CK techniques
used to derive them).

Labels schema:
{
  "samples": [
    {
      "id": "otrf-sysmon",
      "label": "malicious",
      "start": "2020-10-18T10:56:18Z",
      "end": "2020-10-19T02:56:05Z",
      "techniques": ["T1003.001", "T1070.001"],
      "expected_rules": ["Suspicious Process Access to LSASS", "Windows Event Log Cleared"]
    },
    {
      "id": "benign-quiet",
      "label": "benign",
      "start": "2026-11-11T00:00:00Z",
      "end": "2026-11-12T00:00:00Z",
      "techniques": [],
      "expected_rules": []
    }
  ]
}

If expected_rules is omitted, rules are selected by ATT&CK technique from the
compiled rule library. That is a convenience, not a substitute for a reviewed
label set.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.common import ALERTS_DIR, COMPILED_DIR, ROOT

DEFAULT_LABELS = ROOT / "docs" / "validation" / "labels.example.json"
DEFAULT_OUT = ROOT / "docs" / "validation" / "benchmark-results.json"


def _ts(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _overlaps(alert: dict[str, Any], start: datetime, end: datetime) -> bool:
    first = _ts(alert.get("first_seen") or alert.get("last_seen"))
    last = _ts(alert.get("last_seen") or alert.get("first_seen"))
    if first is None or last is None:
        return False
    return first <= end and last >= start


def _expected_rules(sample: dict[str, Any], rules: list[dict[str, Any]]) -> set[str]:
    explicit = sample.get("expected_rules")
    if explicit:
        return set(explicit)
    techniques = {str(item).upper() for item in sample.get("techniques", [])}
    if not techniques:
        return set()
    expected: set[str] = set()
    for rule in rules:
        rule_techniques = {str(item).upper() for item in rule.get("techniques", [])}
        if rule_techniques & techniques:
            expected.add(rule.get("title", ""))
    return expected


def run_benchmark(
    alerts_payload: dict[str, Any],
    rules: list[dict[str, Any]],
    labels: dict[str, Any],
) -> dict[str, Any]:
    alerts = alerts_payload.get("alerts", [])
    titles = [rule.get("title", "") for rule in rules]
    stats: dict[str, dict[str, Any]] = {
        title: {"rule": title, "tp": 0, "fp": 0, "fn": 0, "tn": 0, "alert_volume": 0, "samples": []}
        for title in titles
    }
    sample_results: list[dict[str, Any]] = []

    for sample in labels.get("samples", []):
        start = _ts(sample.get("start"))
        end = _ts(sample.get("end"))
        if start is None or end is None:
            raise SystemExit(f"Sample {sample.get('id', '?')} needs start and end timestamps")
        expected = _expected_rules(sample, rules)
        in_window = [alert for alert in alerts if _overlaps(alert, start, end)]
        fired = {alert.get("title", "") for alert in in_window}
        volume = sum(int(alert.get("count", 0)) for alert in in_window)

        if sample.get("label") == "benign":
            fp = fired
            tp = set()
            fn = set()
            for title in fired:
                if title in stats:
                    stats[title]["fp"] += 1
                    stats[title]["samples"].append({"id": sample.get("id"), "result": "FP"})
            for title in titles:
                if title not in fired:
                    stats[title]["tn"] += 1
        else:
            tp = expected & fired
            fn = expected - fired
            fp = fired - expected
            for title in tp:
                if title in stats:
                    stats[title]["tp"] += 1
                    stats[title]["samples"].append({"id": sample.get("id"), "result": "TP"})
            for title in fn:
                if title in stats:
                    stats[title]["fn"] += 1
                    stats[title]["samples"].append({"id": sample.get("id"), "result": "FN"})
            for title in fp:
                if title in stats:
                    stats[title]["fp"] += 1
                    stats[title]["samples"].append({"id": sample.get("id"), "result": "FP"})

        for title in fired:
            if title in stats:
                stats[title]["alert_volume"] += sum(
                    int(alert.get("count", 0)) for alert in in_window if alert.get("title") == title
                )

        sample_results.append(
            {
                "id": sample.get("id"),
                "label": sample.get("label"),
                "start": sample.get("start"),
                "end": sample.get("end"),
                "alerts": len(in_window),
                "alert_volume": volume,
                "tp": sorted(tp),
                "fp": sorted(fp),
                "fn": sorted(fn),
            }
        )

    rule_rows: list[dict[str, Any]] = []
    for title, row in stats.items():
        tp, fp, fn = row["tp"], row["fp"], row["fn"]
        precision = round(tp / (tp + fp), 4) if tp + fp else None
        recall = round(tp / (tp + fn), 4) if tp + fn else None
        if tp or fp or fn:
            rule_rows.append({**row, "precision": precision, "recall": recall})
    rule_rows.sort(key=lambda item: (-item["tp"], -item["fp"], item["rule"]))

    totals = {
        "tp": sum(row["tp"] for row in stats.values()),
        "fp": sum(row["fp"] for row in stats.values()),
        "fn": sum(row["fn"] for row in stats.values()),
        "alert_volume": sum(row["alert_volume"] for row in stats.values()),
        "rules_with_signal": len(rule_rows),
        "rules_total": len(titles),
    }
    return {"summary": totals, "samples": sample_results, "rules": rule_rows}


def to_markdown(results: dict[str, Any]) -> str:
    lines = [
        "# Benchmark results",
        "",
        "| Metric | Value |",
        "|---|---:|",
        f"| True positives | {results['summary']['tp']} |",
        f"| False positives | {results['summary']['fp']} |",
        f"| False negatives | {results['summary']['fn']} |",
        f"| Alert volume | {results['summary']['alert_volume']} |",
        f"| Rules with signal | {results['summary']['rules_with_signal']} |",
        "",
        "| Rule | TP | FP | FN | Precision | Recall | Alert volume |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for row in results["rules"]:
        precision = "-" if row["precision"] is None else f"{row['precision']:.3f}"
        recall = "-" if row["recall"] is None else f"{row['recall']:.3f}"
        lines.append(
            f"| {row['rule']} | {row['tp']} | {row['fp']} | {row['fn']} | {precision} | {recall} | {row['alert_volume']} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Compute per-rule benchmark metrics")
    parser.add_argument("--alerts", default=str(ALERTS_DIR / "alerts.json"))
    parser.add_argument("--labels", default=str(DEFAULT_LABELS))
    parser.add_argument("--rules", default=str(COMPILED_DIR / "rules.json"))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--markdown", help="optional Markdown output path")
    args = parser.parse_args()

    for required in (args.alerts, args.labels, args.rules):
        if not Path(required).is_file():
            raise SystemExit(f"Missing {required}")
    alerts = json.loads(Path(args.alerts).read_text(encoding="utf-8"))
    labels = json.loads(Path(args.labels).read_text(encoding="utf-8"))
    rules = json.loads(Path(args.rules).read_text(encoding="utf-8"))
    results = run_benchmark(alerts, rules, labels)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(results), encoding="utf-8")
    print(json.dumps(results["summary"], indent=2))


if __name__ == "__main__":
    main()

"""Build a per-rule results table from the committed synthetic run.

This is a reporting step, not a validation claim. It reads
``alerts/alerts.json`` (produced by ``pipeline.detect``) and writes a table that
shows which rules fired, where, and which case references them. It does not
measure precision or recall because the synthetic corpus has no independent
benign label set. See ``docs/evaluation.md`` for that boundary.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pipeline.common import ALERTS_DIR, COMPILED_DIR, LEVEL_RANK, ROOT

DEFAULT_OUT = ROOT / "docs" / "validation" / "synthetic-run.md"
CASES_DIR = ROOT / "cases"


def _short_time(value: str) -> str:
    return value[11:16] + "Z" if value and len(value) >= 16 else value or "-"


def _case_map(cases: list[dict[str, Any]], rules: list[dict[str, Any]]) -> dict[str, list[str]]:
    by_name = {Path(rule.get("source_file", "")).stem: rule.get("title", "") for rule in rules}
    mapping: dict[str, list[str]] = {}
    for case in cases:
        for detection in case.get("detections", []):
            title = by_name.get(detection)
            if title:
                mapping.setdefault(title, []).append(case.get("id", case.get("slug", "")))
    return mapping


def build_markdown(alerts: dict[str, Any], rules: list[dict[str, Any]], cases: list[dict[str, Any]]) -> str:
    rule_alerts = alerts.get("alerts", [])
    correlations = alerts.get("correlations", [])
    case_by_rule = _case_map(cases, rules)
    total_matches = sum(int(alert.get("count", 0)) for alert in rule_alerts)
    linked = sum(1 for alert in rule_alerts if case_by_rule.get(alert.get("title")))

    lines: list[str] = [
        "# Synthetic run: per-rule results",
        "",
        "> **This is a synthetic, construction-labelled run.** It shows what fired in the",
        "> committed lab corpus. It is not a precision or recall measurement. The corpus",
        "> is generated to exercise these rules, so a match is expected by construction.",
        "> Real-telemetry validation is tracked in [Evaluation and validation](../evaluation.md).",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Rule alerts | {len(rule_alerts)} |",
        f"| Correlation alerts | {len(correlations)} |",
        f"| Sum of rule match counts | {total_matches} |",
        f"| Rules linked to a case | {linked} |",
        f"| Rules without a case link | {len(rule_alerts) - linked} |",
        "| Precision / recall | Not measured |",
        "| False-positive rate | Not measured |",
        "| Real telemetry | Not yet replayed |",
        "",
        "## Rule results",
        "",
        "| Rule | Level | Matches | Hosts | First | Last | Case |",
        "|---|---|---:|---|---|---|---|",
    ]

    ranked = sorted(
        rule_alerts,
        key=lambda alert: (-LEVEL_RANK.get(alert.get("level", ""), 0), alert.get("title", "")),
    )
    for alert in ranked:
        cases_for_rule = case_by_rule.get(alert.get("title"), [])
        lines.append(
            "| "
            + " | ".join(
                [
                    str(alert.get("title", "")).replace("|", "\\|"),
                    str(alert.get("level", "")),
                    str(alert.get("count", 0)),
                    ", ".join(alert.get("hosts", [])) or "-",
                    _short_time(alert.get("first_seen", "")),
                    _short_time(alert.get("last_seen", "")),
                    ", ".join(cases_for_rule) or "-",
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## Correlation results",
            "",
            "| Correlation | Level | Count | Group | Window | Technique |",
            "|---|---|---:|---|---:|---|",
        ]
    )
    for correlation in correlations:
        lines.append(
            "| "
            + " | ".join(
                [
                    str(correlation.get("title", "")).replace("|", "\\|"),
                    str(correlation.get("level", "")),
                    str(correlation.get("count", 0)),
                    f"{correlation.get('group_by', '')}={correlation.get('group_value', '')}",
                    str(correlation.get("window_seconds", "")),
                    str(correlation.get("technique", "")),
                ]
            )
            + " |"
        )

    lines.extend(
        [
            "",
            "## How to read this",
            "",
            "- `Matches` is the rule's event count in the committed run, not a count of independent incidents.",
            "- A case link means the rule is referenced by one of the three analyst reports.",
            "- A blank case link does not mean the rule is unimportant; it means the rule is not the spine of a written case.",
            "- True positive, false positive, and false negative labels require an independent benign set and a labelled attack window. That is the next validation step.",
            "",
            "## Reproduce",
            "",
            "```powershell",
            "python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z",
            "python -m pipeline.validation",
            "```",
            "",
        ]
    )
    return "\n".join(lines)


def generate(
    alerts_path: Path = ALERTS_DIR / "alerts.json",
    rules_path: Path = COMPILED_DIR / "rules.json",
    cases_path: Path = CASES_DIR / "cases.json",
    out_path: Path = DEFAULT_OUT,
) -> Path:
    if not alerts_path.is_file():
        raise SystemExit(f"Missing {alerts_path}. Run python -m pipeline.detect first.")
    alerts = json.loads(alerts_path.read_text(encoding="utf-8"))
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(build_markdown(alerts, rules, cases), encoding="utf-8")
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the synthetic per-rule results table")
    parser.add_argument("--alerts", default=str(ALERTS_DIR / "alerts.json"))
    parser.add_argument("--rules", default=str(COMPILED_DIR / "rules.json"))
    parser.add_argument("--cases", default=str(CASES_DIR / "cases.json"))
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    args = parser.parse_args()
    path = generate(Path(args.alerts), Path(args.rules), Path(args.cases), Path(args.out))
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()

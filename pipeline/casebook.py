"""Render the structured IR close-outs into a single casebook document.

The three reports keep their narrative. This module adds the close-out layer:
observed window, detection span, containment, eradication, recovery,
communication, evidence, lessons, and open questions.

Run:
    python -m pipeline.casebook
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pipeline.common import ROOT

CASES_PATH = ROOT / "cases" / "ir.json"
REPORT_PATH = ROOT / "cases" / "IR.md"


def load_casebook(path: Path = CASES_PATH) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def to_markdown(casebook: dict[str, Any]) -> str:
    cases = casebook.get("cases", [])
    lines = [
        "# IR casebook",
        "",
        "The close-out layer for the three Penumbra cases. The individual reports keep",
        "the narrative and evidence; this page records the observed window, response",
        "decisions, lessons, and open questions in one place.",
        "",
        "Response timing is not fabricated. The lab has no live EDR, ticketing, or",
        "containment API, so the close-out records what was recommended and what",
        "remains unmeasured.",
        "",
        "| Case | Verdict | Status | Observed | Alerts |",
        "|---|---|---|---:|---:|",
    ]
    for case in cases:
        metrics = case.get("metrics", {})
        lines.append(
            f"| {case['id']} {case.get('slug', '')} | {case.get('verdict', '')} | "
            f"{case.get('containment_status', '')} | {metrics.get('observed_seconds', 0)}s | "
            f"{metrics.get('alert_count', 0)} |"
        )
    lines.append("")
    for case in cases:
        metrics = case.get("metrics", {})
        lines.extend(
            [
                f"## {case['id']} — {case.get('slug', '')}",
                "",
                f"**Verdict.** {case.get('verdict', '')}",
                "",
                f"**Containment status.** {case.get('containment_status', '')}",
                "",
                "### Metrics",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Observed start | {metrics.get('observed_start') or ''} |",
                f"| Observed end | {metrics.get('observed_end') or ''} |",
                f"| Observed seconds | {metrics.get('observed_seconds', '')} |",
                f"| First detection | {metrics.get('first_detection') or ''} |",
                f"| Last detection | {metrics.get('last_detection') or ''} |",
                f"| Detection span (seconds) | {metrics.get('detection_span_seconds', '')} |",
                f"| Alerts | {metrics.get('alert_count', '')} |",
                f"| Response timing | {metrics.get('response_timing') or ''} |",
                "",
            ]
        )
        for heading, key in (
            ("Containment", "containment"),
            ("Eradication", "eradication"),
            ("Recovery", "recovery"),
            ("Communication", "communication"),
            ("Evidence", "evidence"),
            ("Lessons", "lessons"),
            ("Open questions", "open_questions"),
        ):
            items = case.get(key) or []
            if not items:
                continue
            lines.extend([f"### {heading}", ""])
            lines.extend(f"- {item}" for item in items)
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Render the IR casebook")
    parser.add_argument("--input", default=str(CASES_PATH), help="Structured case data")
    parser.add_argument("--out", default=str(REPORT_PATH), help="Write the Markdown casebook")
    args = parser.parse_args()
    casebook = load_casebook(Path(args.input))
    report = Path(args.out)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(to_markdown(casebook), encoding="utf-8")
    print(f"Wrote {len(casebook.get('cases', []))} cases to {report}")


if __name__ == "__main__":
    main()

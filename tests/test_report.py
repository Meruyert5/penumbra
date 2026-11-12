"""The dashboard is the deliverable, so its payload and assembly are tested."""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from pathlib import Path

from pipeline.common import COMPILED_DIR
from pipeline.compile import compile_all
from pipeline.coverage import PRIORITY_TECHNIQUES
from pipeline.correlate import load_specs
from pipeline.heatmap import build_svg
from pipeline.report import (
    build_html,
    build_payload,
    copy_case_reports,
    load_cases,
    load_dashboard_source,
)

RULES = COMPILED_DIR / "rules.json"
CASES = Path("cases/cases.json")

ALERTS = {
    "meta": {
        "generated": "2026-11-11T12:30:00+00:00",
        "window_hours": 24,
        "events_indexed": 2182,
        "rules_evaluated": 44,
        "correlations_evaluated": 8,
        "errors": [],
    },
    "alerts": [
        {
            "rule_id": "rule-1",
            "title": "Encoded PowerShell",
            "level": "high",
            "techniques": ["T1059.001"],
            "tactics": ["execution"],
            "index": ["lab-windows"],
            "query": "any where process.command_line:*",
            "query_kql": "process.command_line:*",
            "count": 2,
            "host": "WIN10-LAB (2)",
            "hosts": ["WIN10-LAB"],
            "first_seen": "2026-11-11T12:00:00.000Z",
            "last_seen": "2026-11-11T12:01:00.000Z",
            "events": [],
        },
        {
            "rule_id": "rule-2",
            "title": "Shadow Copy Deletion",
            "level": "critical",
            "techniques": ["T1490"],
            "tactics": ["impact"],
            "index": ["lab-windows"],
            "query": "any where process.command_line:*vssadmin*",
            "query_kql": "process.command_line:*vssadmin*",
            "count": 1,
            "host": "WIN10-LAB (1)",
            "hosts": ["WIN10-LAB"],
            "first_seen": "2026-11-11T12:05:00.000Z",
            "last_seen": "2026-11-11T12:05:00.000Z",
            "events": [],
        },
    ],
    "correlations": [
        {
            "correlation_id": "corr-password-spray",
            "title": "Password Spray",
            "level": "high",
            "technique": "T1110.003",
            "group_by": "source.ip",
            "group_value": "198.51.100.23",
            "count": 10,
            "threshold": 10,
            "distinct_by": "user.name",
            "distinct_count": 10,
            "distinct_threshold": 8,
            "window_seconds": 600,
            "first_seen": "2026-11-11T12:00:00.000Z",
            "last_seen": "2026-11-11T12:09:00.000Z",
            "index": "lab-linux",
        }
    ],
    "timeline": [
        {"hour": "2026-11-11T12:00:00Z", "total": 2, "critical": 1, "high": 1, "medium": 0, "low": 0}
    ],
    "hosts": [{"name": "WIN10-LAB", "count": 3}],
    "sources": [{"name": "windows.sysmon", "count": 3}],
    "errors": [],
}


def _write_alerts(tmp_path: Path) -> Path:
    path = tmp_path / "alerts.json"
    path.write_text(json.dumps(ALERTS), encoding="utf-8")
    return path


def test_payload_has_every_dashboard_field(tmp_path):
    payload = build_payload(
        _write_alerts(tmp_path),
        RULES,
        CASES,
    )
    for key in ("meta", "severity", "alerts", "correlations", "timeline", "hosts", "sources", "coverage", "cases", "pipeline"):
        assert key in payload

    assert payload["severity"] == {"critical": 1, "high": 1, "medium": 0, "low": 0}
    assert payload["meta"]["sigma_rules"] == len(compile_all())
    assert payload["meta"]["correlation_specs"] >= 8
    assert payload["meta"]["scenarios"] >= 25
    assert payload["meta"]["priority_techniques"] == len(PRIORITY_TECHNIQUES)
    assert payload["meta"]["covered_priority"] == payload["coverage"]["covered"]
    assert len(payload["pipeline"]) == 5
    assert payload["pipeline"][0]["count"] == "2,182"


def test_payload_includes_case_metadata(tmp_path):
    payload = build_payload(
        _write_alerts(tmp_path),
        RULES,
        CASES,
    )
    cases = payload["cases"]
    assert len(cases) >= 3
    for case in cases:
        assert case["path"].startswith("cases/")
        assert case["path"].endswith("/report.md")
        assert case["severity"] in {"critical", "high", "medium", "low"}


def test_html_inlines_every_source_and_has_no_placeholders(tmp_path):
    payload = build_payload(
        _write_alerts(tmp_path),
        RULES,
        CASES,
    )
    source = load_dashboard_source()
    html = build_html(payload, source)
    for token in ("/*STYLES*/", "/*SCRIPT*/", "__DATA_JSON__", "__FAVICON__", "__ICON_SVG__"):
        assert token not in html
    assert source["styles"][:40] in html
    assert source["icon"] in html
    assert "Signal Foundry" in html
    assert "data:image/svg+xml," in html


def test_case_reports_are_published(tmp_path):
    cases = load_cases(CASES)
    copied = copy_case_reports(cases, tmp_path)
    assert copied == len(cases)
    for case in cases:
        assert (tmp_path / "cases" / case["slug"] / "report.md").exists()


def test_heatmap_is_valid_svg_with_correlations():
    svg = build_svg(compile_all(), load_specs())
    root = ET.fromstring(svg)
    assert root.tag.endswith("svg")
    assert "SIGNAL FOUNDRY" in svg
    assert "gap" in svg

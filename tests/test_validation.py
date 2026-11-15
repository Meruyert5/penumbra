"""Tests for the synthetic per-rule results table."""

from __future__ import annotations

from pipeline.validation import build_markdown


def test_build_markdown_links_cases_and_keeps_the_boundary() -> None:
    alerts = {
        "alerts": [
            {
                "title": "LSASS Memory Dumped via Comsvcs",
                "level": "critical",
                "count": 2,
                "hosts": ["WIN10-LAB"],
                "first_seen": "2026-11-11T12:10:40Z",
                "last_seen": "2026-11-11T12:10:41Z",
            }
        ],
        "correlations": [
            {
                "title": "Account and Domain Discovery Burst",
                "level": "medium",
                "count": 4,
                "group_by": "host.name",
                "group_value": "WIN10-LAB",
                "window_seconds": 300,
                "technique": "T1087",
            }
        ],
    }
    rules = [
        {
            "title": "LSASS Memory Dumped via Comsvcs",
            "source_file": "rules/sigma/win_comsvcs_minidump.yml",
        }
    ]
    cases = [{"id": "PNB-2026-002", "detections": ["win_comsvcs_minidump"]}]

    markdown = build_markdown(alerts, rules, cases)

    assert "This is a synthetic, construction-labelled run" in markdown
    assert "| LSASS Memory Dumped via Comsvcs | critical | 2 | WIN10-LAB | 12:10Z | 12:10Z | PNB-2026-002 |" in markdown
    assert "| Account and Domain Discovery Burst | medium | 4 | host.name=WIN10-LAB | 300 | T1087 |" in markdown
    assert "Precision / recall | Not measured" in markdown

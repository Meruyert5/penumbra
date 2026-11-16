"""Tests for the per-rule benchmark metrics engine."""

from __future__ import annotations

from pipeline.benchmark import run_benchmark, to_markdown


def test_benchmark_counts_tp_fp_fn_and_volume() -> None:
    rules = [
        {"title": "Rule A", "techniques": ["T1003.001"]},
        {"title": "Rule B", "techniques": ["T1070.001"]},
        {"title": "Rule C", "techniques": ["T9999"]},
    ]
    alerts = {
        "alerts": [
            {
                "title": "Rule A",
                "count": 2,
                "first_seen": "2026-11-11T12:00:00Z",
                "last_seen": "2026-11-11T12:10:00Z",
            },
            {
                "title": "Rule C",
                "count": 1,
                "first_seen": "2026-11-11T12:05:00Z",
                "last_seen": "2026-11-11T12:06:00Z",
            },
            {
                "title": "Rule A",
                "count": 4,
                "first_seen": "2026-11-12T12:00:00Z",
                "last_seen": "2026-11-12T12:10:00Z",
            },
        ]
    }
    labels = {
        "samples": [
            {
                "id": "malicious",
                "label": "malicious",
                "start": "2026-11-11T12:00:00Z",
                "end": "2026-11-11T13:00:00Z",
                "expected_rules": ["Rule A", "Rule B"],
            },
            {
                "id": "benign",
                "label": "benign",
                "start": "2026-11-12T12:00:00Z",
                "end": "2026-11-12T13:00:00Z",
            },
        ]
    }

    results = run_benchmark(alerts, rules, labels)
    by_rule = {row["rule"]: row for row in results["rules"]}

    assert by_rule["Rule A"]["tp"] == 1
    assert by_rule["Rule A"]["fp"] == 1
    assert by_rule["Rule A"]["fn"] == 0
    assert by_rule["Rule A"]["alert_volume"] == 6
    assert by_rule["Rule A"]["precision"] == 0.5
    assert by_rule["Rule A"]["recall"] == 1.0

    assert by_rule["Rule B"]["tp"] == 0
    assert by_rule["Rule B"]["fn"] == 1
    assert by_rule["Rule B"]["precision"] is None
    assert by_rule["Rule B"]["recall"] == 0.0

    assert by_rule["Rule C"]["fp"] == 1
    assert by_rule["Rule C"]["precision"] == 0.0
    assert "| Rule A | 1 | 1 | 0 | 0.500 | 1.000 | 6 |" in to_markdown(results)


def test_benchmark_derives_expected_rules_from_techniques() -> None:
    rules = [{"title": "LSASS rule", "techniques": ["T1003.001"]}]
    labels = {
        "samples": [
            {
                "id": "technique-only",
                "label": "malicious",
                "start": "2026-11-11T12:00:00Z",
                "end": "2026-11-11T13:00:00Z",
                "techniques": ["T1003.001"],
            }
        ]
    }
    results = run_benchmark({"alerts": []}, rules, labels)
    row = results["rules"][0]
    assert row["rule"] == "LSASS rule"
    assert row["fn"] == 1


def test_benchmark_does_not_double_count_volume_for_overlapping_samples() -> None:
    rules = [{"title": "Rule A", "techniques": []}]
    alerts = {
        "alerts": [
            {
                "title": "Rule A",
                "count": 5,
                "first_seen": "2026-11-11T12:00:00Z",
                "last_seen": "2026-11-11T14:00:00Z",
            }
        ]
    }
    labels = {
        "samples": [
            {
                "id": "first",
                "label": "malicious",
                "start": "2026-11-11T12:00:00Z",
                "end": "2026-11-11T13:00:00Z",
                "expected_rules": ["Rule A"],
            },
            {
                "id": "second",
                "label": "malicious",
                "start": "2026-11-11T13:00:00Z",
                "end": "2026-11-11T14:00:00Z",
                "expected_rules": ["Rule A"],
            },
        ]
    }
    results = run_benchmark(alerts, rules, labels)
    row = results["rules"][0]
    assert row["tp"] == 2
    assert row["alert_volume"] == 5

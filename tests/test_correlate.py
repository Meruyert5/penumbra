"""Threshold correlation is the part most likely to be wrong; test it directly."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pipeline.correlate import CorrelationSpec, correlate, matches, parse_window

BASE = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def _failed_login(offset_seconds: int, ip: str = "203.0.113.44") -> dict:
    return {
        "@timestamp": (BASE + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z"),
        "source": {"ip": ip},
        "message": f"Failed password for invalid user root from {ip} port 50000 ssh2",
    }


def _spec(threshold: int = 8, window: str = "5m") -> CorrelationSpec:
    return CorrelationSpec(
        id="corr-test",
        title="Test brute force",
        level="high",
        technique="T1110.001",
        group_by="source.ip",
        window_seconds=parse_window(window),
        threshold=threshold,
        match={"message|contains": "Failed password"},
    )


def test_window_parsing():
    assert parse_window("5m") == 300
    assert parse_window("30s") == 30
    assert parse_window("2h") == 7200
    assert parse_window(90) == 90


def test_threshold_reached():
    events = [_failed_login(index * 20) for index in range(8)]
    alerts = correlate(events, [_spec()])
    assert len(alerts) == 1
    assert alerts[0]["count"] >= 8
    assert alerts[0]["group_value"] == "203.0.113.44"


def test_threshold_not_reached():
    events = [_failed_login(index * 20) for index in range(7)]
    assert correlate(events, [_spec()]) == []


def test_events_outside_window_do_not_trigger():
    events = [_failed_login(index * 60) for index in range(10)]  # one per minute, 5m window
    assert correlate(events, [_spec()]) == []


def test_groups_are_independent():
    events = [_failed_login(index * 10, ip=f"203.0.113.{index}") for index in range(10)]
    assert correlate(events, [_spec(threshold=3)]) == []


def test_match_operators():
    event = {"message": "Failed password for root", "event": {"outcome": "failure"}}
    assert matches(event, {"message|contains": "failed PASSWORD"})
    assert matches(event, {"event.outcome": "failure"})
    assert not matches(event, {"event.outcome": "success"})

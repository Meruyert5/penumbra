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


def _spray_spec() -> CorrelationSpec:
    return CorrelationSpec(
        id="corr-spray",
        title="Password spray",
        level="high",
        technique="T1110.003",
        group_by="source.ip",
        window_seconds=parse_window("10m"),
        threshold=8,
        match={"message|contains": "Failed password"},
        distinct_by="user.name",
        distinct_threshold=5,
    )


def _failed_login_for(user: str, offset_seconds: int, ip: str = "198.51.100.23") -> dict:
    return {
        "@timestamp": (BASE + timedelta(seconds=offset_seconds)).isoformat().replace("+00:00", "Z"),
        "source": {"ip": ip},
        "user": {"name": user},
        "message": f"Failed password for invalid user {user} from {ip} port 50000 ssh2",
    }


def test_distinct_threshold_blocks_single_account_bruteforce():
    events = [_failed_login_for("root", index * 20) for index in range(12)]
    assert correlate(events, [_spray_spec()]) == []


def test_distinct_threshold_allows_spray_across_accounts():
    users = ["root", "admin", "deploy", "oracle", "postgres", "ubuntu"]
    events = [_failed_login_for(users[index % len(users)], index * 20) for index in range(12)]
    alerts = correlate(events, [_spray_spec()])
    assert len(alerts) == 1
    assert alerts[0]["distinct_count"] == len(users)
    assert alerts[0]["distinct_threshold"] == 5


def test_committed_correlations_load_and_fire():
    from pipeline.correlate import load_specs
    from pipeline.labgen import generate

    specs = load_specs()
    assert len(specs) >= 8
    assert {spec.id for spec in specs} >= {
        "corr-password-spray",
        "corr-port-scan",
        "corr-ransomware-file-burst",
        "corr-dns-tunnel",
    }
    data = generate("all", seed=42, base_time=BASE)
    fired = set()
    for spec in specs:
        events = data.get(spec.index.replace("lab-", ""), [])
        for alert in correlate(events, [spec]):
            fired.add(alert["correlation_id"])
    assert len(fired) == len(specs), f"unfired correlations: {set(s.id for s in specs) - fired}"

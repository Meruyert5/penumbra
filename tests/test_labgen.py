"""Lab telemetry must be deterministic and must exercise the detections."""

from __future__ import annotations

from datetime import datetime, timezone

from pipeline.labgen import ATTACKER, SCENARIOS, generate

BASE = datetime(2026, 11, 11, 12, 0, tzinfo=timezone.utc)


def test_generation_is_deterministic():
    first = generate("all", seed=42, base_time=BASE)
    second = generate("all", seed=42, base_time=BASE)
    assert first == second


def test_every_event_has_timestamp():
    data = generate("all", seed=1, base_time=BASE)
    for events in data.values():
        for event in events:
            assert "@timestamp" in event


def test_ssh_bruteforce_produces_threshold_volume():
    data = generate("ssh-bruteforce", seed=1, base_time=BASE)
    failures = [
        event
        for event in data["linux"]
        if event["source"]["ip"] == ATTACKER and "Failed password" in event["message"]
    ]
    assert len(failures) >= 8
    span = failures[-1]["@timestamp"] > failures[0]["@timestamp"]
    assert span


def test_encoded_powershell_matches_rule_shape():
    data = generate("encoded-powershell", seed=1, base_time=BASE)
    command_lines = [event["process"]["command_line"] for event in data["windows"]]
    assert any(" -enc " in line for line in command_lines)


def test_webshell_produces_cmd_parameter_burst():
    data = generate("webshell", seed=1, base_time=BASE)
    with_cmd = [event for event in data["web"] if event.get("url", {}).get("query") == "cmd=id"]
    assert len(with_cmd) >= 5


def test_baseline_is_benign():
    from pipeline.correlate import correlate, load_specs

    data = generate("baseline", seed=1, base_time=BASE)
    for event in data["windows"]:
        command_line = event.get("process", {}).get("command_line", "")
        assert "-enc " not in command_line
    # Isolated failed logins are realistic noise, but must not trip the threshold.
    assert correlate(data["linux"], load_specs()) == []
    assert all(event.get("event", {}).get("outcome") != "failure" for event in data["web"])


def test_scenario_catalogue_is_large_and_unique():
    assert len(SCENARIOS) >= 34
    assert len(set(SCENARIOS)) == len(SCENARIOS)
    assert "baseline" in SCENARIOS


def test_gap_scenarios_produce_expected_events():
    data = generate("all", seed=42, base_time=BASE)

    assert any(event.get("url", {}).get("path") == "/api/v2/beacon" for event in data["web"])
    assert any(event.get("event", {}).get("code") == "8" for event in data["windows"])
    assert any(
        event.get("user", {}).get("name") == "backup"
        and event.get("event", {}).get("outcome") == "success"
        for event in data["linux"]
    )
    assert any(
        event.get("user", {}).get("name") == "root"
        and event.get("event", {}).get("outcome") == "success"
        for event in data["linux"]
    )
    assert any(
        event.get("event", {}).get("code") == "5140"
        and "ADMIN$" in str((event.get("winlog") or {}).get("event_data", {}).get("ShareName", ""))
        for event in data["windows"]
    )
    assert any(
        event.get("process", {}).get("name") == "cmd.exe"
        and "powershell" in event.get("process", {}).get("command_line", "").lower()
        for event in data["windows"]
    )


def test_all_run_spans_the_day():
    data = generate("all", seed=42, base_time=BASE)
    timestamps = [event["@timestamp"] for events in data.values() for event in events]
    assert timestamps
    assert min(timestamps)[:10] == "2026-11-10"
    assert max(timestamps)[:10] == "2026-11-11"
    assert len({timestamp[11:13] for timestamp in timestamps}) >= 20


def test_all_run_produces_five_sources():
    data = generate("all", seed=42, base_time=BASE)
    assert set(data) == {"windows", "linux", "web", "cloud", "network"}
    assert all(events for events in data.values())
    total = sum(len(events) for events in data.values())
    assert total >= 8000


def test_every_event_has_dataset_and_action():
    data = generate("all", seed=42, base_time=BASE)
    for events in data.values():
        for event in events:
            assert event.get("event", {}).get("dataset"), event
            assert event.get("event", {}).get("action"), event

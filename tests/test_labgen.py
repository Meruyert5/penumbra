"""Lab telemetry must be deterministic and must exercise the detections."""

from __future__ import annotations

from datetime import datetime, timezone

from pipeline.labgen import ATTACKER, generate

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

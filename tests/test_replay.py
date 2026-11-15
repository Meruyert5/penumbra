"""Tests for the public replay normalizer."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.replay import normalize_event

FIXTURE = Path(__file__).parent / "fixtures" / "otrf_sysmon.json"


def test_normalize_sysmon_process_create() -> None:
    raw = json.loads(FIXTURE.read_text(encoding="utf-8"))[0]
    event = normalize_event(raw)

    assert event is not None
    assert event["@timestamp"] == "2026-11-11T12:10:40Z"
    assert event["host"]["name"] == "WIN10-LAB"
    assert event["event"]["dataset"] == "windows.sysmon_operational"
    assert event["event"]["action"] == "process_start"
    assert event["winlog"]["event_id"] == "1"
    assert event["process"]["executable.caseless"].endswith("rundll32.exe")
    assert "comsvcs.dll" in event["process"]["command_line"]
    assert event["process"]["parent"]["name"] == "cmd.exe"


def test_normalize_without_timestamp_is_skipped() -> None:
    assert normalize_event({"Image": "C:\\Windows\\System32\\cmd.exe"}) is None

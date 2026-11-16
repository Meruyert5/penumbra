"""Tests for the public replay normalizer."""

from __future__ import annotations

import json
from pathlib import Path

from pipeline.replay import normalize_event

FIXTURE = Path(__file__).parent / "fixtures" / "sysmon_process_create.json"


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
    assert event["winlog"]["event_data"]["TargetImage"].endswith("lsass.exe")
    assert event["winlog"]["event_data"]["GrantedAccess"] == "0x1010"


def test_normalize_without_timestamp_is_skipped() -> None:
    assert normalize_event({"Image": "C:\\Windows\\System32\\cmd.exe"}) is None


def test_normalize_sysmon_process_access_and_registry() -> None:
    access = normalize_event(
        {
            "EventID": 10,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WIN10-LAB",
            "UtcTime": "2026-11-11T12:10:40.000Z",
            "SourceImage": "C:\\Tools\\dump.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1010",
            "SourceProcessId": "1234",
            "TargetProcessId": "640",
        }
    )
    assert access is not None
    assert access["event"]["action"] == "process_access"
    assert access["process"]["executable"].endswith("dump.exe")
    assert access["process"]["pid"] == 1234
    assert access["winlog"]["event_data"]["TargetImage"].endswith("lsass.exe")
    assert access["winlog"]["event_data"]["GrantedAccess"] == "0x1010"

    registry = normalize_event(
        {
            "EventID": 13,
            "Channel": "Microsoft-Windows-Sysmon/Operational",
            "Computer": "WIN10-LAB",
            "UtcTime": "2026-11-11T12:10:41.000Z",
            "TargetObject": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            "Details": "C:\\Users\\Public\\updater.exe",
        }
    )
    assert registry is not None
    assert registry["event"]["action"] == "registry_change"
    assert registry["registry"]["path"].endswith("Run\\Updater")
    assert registry["winlog"]["event_data"]["Details"].endswith("updater.exe")

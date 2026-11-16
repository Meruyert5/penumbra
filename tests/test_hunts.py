"""Tests for the hypothesis-driven hunt module."""

from __future__ import annotations

from pipeline.hunts import (
    hunt_dns_tunnel,
    hunt_lsass_access,
    hunt_root_cloud_identity,
    hunt_service_path,
    run_hunts,
)


def _cloud(action: str, user: str) -> dict:
    return {
        "@timestamp": "2026-11-11T12:00:00Z",
        "event": {"action": action, "dataset": "aws.cloudtrail"},
        "cloud": {"provider": "aws"},
        "user": {"name": user},
        "source": {"ip": "203.0.113.10"},
    }


def _service(image: str) -> dict:
    return {
        "@timestamp": "2026-11-11T12:00:00Z",
        "event": {"code": "7045", "dataset": "windows.system"},
        "winlog": {"event_data": {"ServiceName": "TestSvc", "ImagePath": image}},
        "host": {"name": "WIN10-LAB"},
    }


def _dns(name: str) -> dict:
    return {
        "@timestamp": "2026-11-11T12:00:00Z",
        "event": {"action": "dns_query", "dataset": "windows.sysmon_operational"},
        "dns": {"question": {"name": name}},
        "host": {"name": "WIN10-LAB"},
    }


def _lsass(source: str) -> dict:
    return {
        "@timestamp": "2026-11-11T12:00:00Z",
        "event": {"code": "10", "dataset": "windows.sysmon_operational"},
        "winlog": {
            "event_data": {
                "SourceImage": source,
                "TargetImage": "C:\\Windows\\System32\\lsass.exe",
                "GrantedAccess": "0x1010",
            }
        },
        "host": {"name": "WIN10-LAB"},
    }


def test_root_cloud_hunt_finds_root_and_ignores_iam_user() -> None:
    result = hunt_root_cloud_identity(
        [
            _cloud("CreateAccessKey", "root"),
            _cloud("DescribeInstances", "root"),
            _cloud("CreateAccessKey", "svc-automation"),
        ]
    )
    assert result["event_count"] == 1
    assert result["verdict"] == "true_positive"
    assert "CreateAccessKey" in result["finding"]


def test_service_hunt_finds_user_writable_path_and_ignores_system_path() -> None:
    result = hunt_service_path(
        [
            _service("C:\\Users\\Public\\svc.exe"),
            _service("C:\\Windows\\System32\\svc.exe"),
        ]
    )
    assert result["event_count"] == 1
    assert "UpdaterSvc" not in result["finding"]
    assert "TestSvc" in result["finding"]


def test_dns_hunt_needs_volume_uniqueness_and_long_labels() -> None:
    names = [f"{index:04d}-aaaaaaaaaaaaaaaaaaaaaaaaaa.tunnel.example" for index in range(5)]
    result = hunt_dns_tunnel([_dns(name) for name in names])
    assert result["event_count"] == 5
    assert "tunnel.example" in result["finding"]

    short = [_dns(f"host{index}.example.com") for index in range(5)]
    assert hunt_dns_tunnel(short)["event_count"] == 0


def test_lsass_hunt_finds_user_writable_source_and_ignores_system32() -> None:
    result = hunt_lsass_access(
        [
            _lsass("C:\\Users\\Public\\mimikatz.exe"),
            _lsass("C:\\Windows\\System32\\taskmgr.exe"),
        ]
    )
    assert result["event_count"] == 1
    assert "mimikatz.exe" in result["finding"] or "user-writable" in result["finding"]


def test_run_hunts_returns_summary_and_sources() -> None:
    events = [
        _cloud("CreateAccessKey", "root"),
        _service("C:\\Users\\Public\\svc.exe"),
        _dns("0000-aaaaaaaaaaaaaaaaaaaaaaaaaa.tunnel.example"),
        _lsass("C:\\Users\\Public\\mimikatz.exe"),
    ]
    results = run_hunts(events)
    assert results["summary"]["hunts"] == 4
    assert results["summary"]["events_reviewed"] == 4
    assert results["summary"]["findings"] >= 1
    assert results["sources"][0]["events"] >= 1

"""Tests for the cloud detection pack."""

from __future__ import annotations

from pipeline.cloud_pack import run_pack


def _cloud(action: str, user: str = "root") -> dict:
    return {
        "@timestamp": "2026-11-11T00:35:00Z",
        "event": {"action": action, "dataset": "aws.cloudtrail", "outcome": "success"},
        "cloud": {"provider": "aws"},
        "user": {"name": user},
        "source": {"ip": "203.0.113.44"},
        "host": {"name": "aws-prod"},
    }


def test_pack_fires_root_policy_and_root_user_creation() -> None:
    results = run_pack([_cloud("AttachUserPolicy"), _cloud("CreateUser")])
    by_id = {row["id"]: row for row in results["detections"]}
    assert by_id["CLOUD-001"]["event_count"] == 1
    assert by_id["CLOUD-002"]["event_count"] == 1
    assert results["summary"]["fired"] == 2


def test_pack_ignores_non_root_policy_change() -> None:
    results = run_pack([_cloud("AttachUserPolicy", user="deploy")])
    by_id = {row["id"]: row for row in results["detections"]}
    assert by_id["CLOUD-001"]["event_count"] == 0
    assert results["summary"]["fired"] == 0


def test_pack_marks_unexercised_trail_tampering() -> None:
    results = run_pack([_cloud("DescribeInstances")])
    by_id = {row["id"]: row for row in results["detections"]}
    assert by_id["CLOUD-003"]["status"] == "no_match"
    assert results["summary"]["not_exercised"] == 3


def test_pack_fires_trail_tampering_when_present() -> None:
    results = run_pack([_cloud("StopLogging")])
    by_id = {row["id"]: row for row in results["detections"]}
    assert by_id["CLOUD-003"]["event_count"] == 1
    assert by_id["CLOUD-003"]["status"] == "fired"

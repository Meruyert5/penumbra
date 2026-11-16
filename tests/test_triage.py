"""Tests for the dry-run triage engine."""

from __future__ import annotations

from pipeline.triage import enrich, group_incidents, playbook_for, run_triage


def _alert(title: str, level: str, host: str = "WIN10-LAB", technique: str = "T1003.001", first: str = "2026-11-11T12:10:00Z") -> dict:
    return {
        "title": title,
        "level": level,
        "hosts": [host],
        "techniques": [technique],
        "first_seen": first,
        "last_seen": first,
        "count": 1,
    }


def test_enrich_adds_asset_and_privilege_context() -> None:
    context = enrich(_alert("Suspicious Process Access to LSASS", "critical"))
    assert context["host"] == "WIN10-LAB"
    assert context["asset_criticality"] == "high"
    assert context["privileged_technique"] is True
    assert context["threat_intel"].startswith("not queried")


def test_playbook_selection_for_credential_theft_and_ssh() -> None:
    credential = playbook_for(_alert("Suspicious Process Access to LSASS", "critical"))
    assert credential["name"] == "Credential theft response"
    assert "isolate_host" in {action["action"] for action in credential["actions"]}

    ssh = playbook_for(_alert("SSH Failed Password Authentication", "low", host="linux01", technique="T1110.001"))
    assert ssh["name"] == "Authentication response"
    assert "block_source" in {action["action"] for action in ssh["actions"]}


def test_playbook_selection_for_cloud_and_ransomware() -> None:
    cloud = playbook_for(_alert("Cloud Access Key Created", "high", host="aws-prod", technique="T1098"))
    assert cloud["name"] == "Cloud identity response"
    assert "disable_access_key" in {action["action"] for action in cloud["actions"]}

    ransomware = playbook_for(_alert("Ransomware Note Dropped on Disk", "critical", technique="T1486"))
    assert ransomware["name"] == "Ransomware containment"
    assert "snapshot_share" in {action["action"] for action in ransomware["actions"]}


def test_group_incidents_merges_alerts_on_the_same_host_and_window() -> None:
    incidents = group_incidents(
        [
            _alert("Alert A", "high", first="2026-11-11T12:10:00Z"),
            _alert("Alert B", "critical", first="2026-11-11T12:12:00Z"),
            _alert("Alert C", "high", first="2026-11-11T12:20:00Z"),
        ]
    )
    assert len(incidents) == 2
    assert incidents[0]["id"] == "INC-001"
    assert incidents[0]["alert_count"] == 2
    assert incidents[0]["highest_level"] == "critical"


def test_run_triage_returns_summary_and_incidents() -> None:
    results = run_triage(
        [
            _alert("Suspicious Process Access to LSASS", "critical"),
            _alert("SSH Failed Password Authentication", "low", host="linux01", technique="T1110.001"),
        ]
    )
    assert results["summary"]["alerts_ingested"] == 2
    assert results["summary"]["incidents"] == 2
    assert results["summary"]["playbooks"] >= 2
    assert results["summary"]["actions"] >= 2

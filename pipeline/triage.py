"""Turn the detection run into enriched, deduplicated incidents and playbooks.

This is a dry-run triage engine. It enriches alerts from local context, groups
them into incidents, chooses a response playbook, and records the actions an
analyst or SOAR worker would take. It never calls an EDR, cloud, or ticketing
API. The output is evidence for the response design, not a claim that a real
host was isolated.

Run:
    python -m pipeline.triage
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from pipeline.common import ALERTS_DIR, ROOT

RESPONSE_DIR = ROOT / "response"
RESULTS_PATH = RESPONSE_DIR / "results.json"
REPORT_PATH = RESPONSE_DIR / "README.md"

LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}

ASSET_CRITICALITY = {
    "WIN10-LAB": "high",
    "linux01": "high",
    "aws-prod": "critical",
}

PRIVILEGED_TECHNIQUES = {"T1003.001", "T1003.002", "T1068", "T1078", "T1098", "T1110.001"}


def _level(value: str) -> str:
    return value if value in LEVEL_RANK else "informational"


def _first_seen(alert: dict[str, Any]) -> str:
    return str(alert.get("first_seen") or alert.get("last_seen") or "")


def _parse(value: str) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed.astimezone(timezone.utc)


def _bucket(alert: dict[str, Any], minutes: int = 5) -> str:
    parsed = _parse(_first_seen(alert))
    if parsed is None:
        return "unknown"
    floored = parsed.replace(second=0, microsecond=0)
    floored -= timedelta(minutes=floored.minute % minutes)
    return floored.isoformat(timespec="seconds").replace("+00:00", "Z")


def enrich(alert: dict[str, Any]) -> dict[str, Any]:
    hosts = [str(host) for host in alert.get("hosts") or []]
    host = hosts[0] if hosts else "unknown"
    techniques = [str(item).upper() for item in alert.get("techniques") or []]
    privileged = bool(PRIVILEGED_TECHNIQUES & set(techniques))
    return {
        "host": host,
        "asset_criticality": ASSET_CRITICALITY.get(host, "medium"),
        "privileged_technique": privileged,
        "technique_count": len(techniques),
        "source": "local lab corpus",
        "threat_intel": "not queried in the dry run",
    }


def playbook_for(alert: dict[str, Any]) -> dict[str, Any]:
    title = str(alert.get("title") or "")
    level = _level(str(alert.get("level") or ""))
    techniques = {str(item).upper() for item in alert.get("techniques") or []}

    if "ransomware" in title.lower() or "shadow copy" in title.lower() or "T1486" in techniques:
        return {
            "name": "Ransomware containment",
            "actions": [
                {"action": "isolate_host", "mode": "dry_run", "reason": "Stop encryption spread"},
                {"action": "preserve_memory", "mode": "dry_run", "reason": "Capture volatile evidence"},
                {"action": "snapshot_share", "mode": "dry_run", "reason": "Preserve the file share before restore"},
                {"action": "notify_ir_lead", "mode": "dry_run", "reason": "Critical impact"},
            ],
        }
    if "lsass" in title.lower() or "credential" in title.lower() or "T1003" in " ".join(techniques):
        return {
            "name": "Credential theft response",
            "actions": [
                {"action": "isolate_host", "mode": "dry_run", "reason": "Prevent credential reuse"},
                {"action": "reset_credentials", "mode": "dry_run", "reason": "Assume cached secrets are compromised"},
                {"action": "collect_memory", "mode": "dry_run", "reason": "Preserve LSASS evidence"},
                {"action": "hunt_hashes", "mode": "dry_run", "reason": "Find the payload on other hosts"},
            ],
        }
    if "ssh" in title.lower() or "brute" in title.lower() or "T1110" in " ".join(techniques):
        return {
            "name": "Authentication response",
            "actions": [
                {"action": "block_source", "mode": "dry_run", "reason": "Stop the login attempts"},
                {"action": "reset_password", "mode": "dry_run", "reason": "Secure the targeted account"},
                {"action": "review_sessions", "mode": "dry_run", "reason": "Check for post-login activity"},
            ],
        }
    if "cloud" in title.lower() or "console" in title.lower() or "access key" in title.lower():
        return {
            "name": "Cloud identity response",
            "actions": [
                {"action": "disable_access_key", "mode": "dry_run", "reason": "Stop key abuse"},
                {"action": "review_cloudtrail", "mode": "dry_run", "reason": "Scope the principal activity"},
                {"action": "export_to_apsis", "mode": "dry_run", "reason": "Check reachable IAM paths"},
            ],
        }
    if "service" in title.lower() or "scheduled task" in title.lower() or "persistence" in title.lower():
        return {
            "name": "Persistence response",
            "actions": [
                {"action": "collect_binary", "mode": "dry_run", "reason": "Hash and detonate safely"},
                {"action": "disable_persistence", "mode": "dry_run", "reason": "Remove service or task"},
                {"action": "hunt_service_name", "mode": "dry_run", "reason": "Find the same name on other hosts"},
            ],
        }
    actions = [{"action": "open_case", "mode": "dry_run", "reason": "Analyst review"}]
    if level in {"critical", "high"}:
        actions.append({"action": "collect_evidence", "mode": "dry_run", "reason": "Preserve context"})
    return {"name": "Standard triage", "actions": actions}


def group_incidents(alerts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for alert in alerts:
        context = enrich(alert)
        key = (context["host"], _bucket(alert))
        groups.setdefault(key, []).append(alert)

    incidents: list[dict[str, Any]] = []
    for (host, bucket), members in groups.items():
        ordered = sorted(members, key=lambda item: (LEVEL_RANK.get(_level(str(item.get("level") or "")), 9), _first_seen(item)))
        highest = ordered[0]
        actions: list[dict[str, Any]] = []
        playbooks: list[str] = []
        for alert in ordered:
            playbook = playbook_for(alert)
            playbooks.append(playbook["name"])
            for action in playbook["actions"]:
                if action["action"] not in {item["action"] for item in actions}:
                    actions.append(action)
        timestamps = sorted(_first_seen(alert) for alert in ordered if _first_seen(alert))
        incidents.append(
            {
                "id": "",
                "host": host,
                "window_start": timestamps[0] if timestamps else bucket,
                "window_end": timestamps[-1] if timestamps else bucket,
                "highest_level": _level(str(highest.get("level") or "")),
                "alert_count": len(ordered),
                "playbooks": sorted(set(playbooks)),
                "enrichment": enrich(highest),
                "actions": actions,
                "alerts": [
                    {
                        "title": alert.get("title"),
                        "level": alert.get("level"),
                        "techniques": alert.get("techniques") or [],
                        "count": alert.get("count", 0),
                        "first_seen": alert.get("first_seen"),
                        "last_seen": alert.get("last_seen"),
                    }
                    for alert in ordered
                ],
            }
        )
    incidents.sort(key=lambda item: (LEVEL_RANK.get(item["highest_level"], 9), item["window_start"]))
    for index, incident in enumerate(incidents, start=1):
        incident["id"] = f"INC-{index:03d}"
    return incidents


def run_triage(alerts: list[dict[str, Any]]) -> dict[str, Any]:
    incidents = group_incidents(alerts)
    levels = Counter(_level(str(alert.get("level") or "")) for alert in alerts)
    actions = sum(len(incident["actions"]) for incident in incidents)
    playbooks = Counter(name for incident in incidents for name in incident["playbooks"])
    return {
        "summary": {
            "alerts_ingested": len(alerts),
            "incidents": len(incidents),
            "alerts_grouped": len(alerts) - len(incidents),
            "critical_alerts": levels.get("critical", 0),
            "high_alerts": levels.get("high", 0),
            "playbooks": len(playbooks),
            "actions": actions,
            "containment_coverage": round(
                sum(1 for incident in incidents if any(action["action"] != "open_case" for action in incident["actions"]))
                / len(incidents),
                4,
            )
            if incidents
            else 0,
            "timing": "dry run; external API latency is not measured",
        },
        "playbooks": [
            {"name": name, "incidents": count} for name, count in playbooks.most_common()
        ],
        "incidents": incidents,
    }


def to_markdown(results: dict[str, Any]) -> str:
    summary = results["summary"]
    lines = [
        "# Triage and response",
        "",
        "A dry-run triage engine over the detection run. It enriches alerts, groups",
        "them into incidents, selects a playbook, and records the actions a real SOAR",
        "worker would take. No EDR, cloud, or ticketing API is called.",
        "",
        f"- Alerts ingested: **{summary['alerts_ingested']}**",
        f"- Incidents: **{summary['incidents']}**",
        f"- Alerts grouped into incidents: **{summary['alerts_grouped']}**",
        f"- Playbooks: **{summary['playbooks']}**",
        f"- Actions: **{summary['actions']}**",
        f"- Containment coverage: **{summary['containment_coverage']:.1%}**",
        f"- Timing: {summary['timing']}",
        "",
        "## Playbooks",
        "",
        "| Playbook | Incidents |",
        "|---|---:|",
    ]
    for playbook in results["playbooks"]:
        lines.append(f"| {playbook['name']} | {playbook['incidents']} |")
    lines.append("")
    lines.extend(
        [
            "## Incidents",
            "",
            "| Incident | Host | Highest level | Alerts | Playbooks | Actions |",
            "|---|---|---|---:|---|---:|",
        ]
    )
    for incident in results["incidents"]:
        lines.append(
            f"| {incident['id']} | {incident['host']} | {incident['highest_level']} | "
            f"{incident['alert_count']} | {', '.join(incident['playbooks'])} | {len(incident['actions'])} |"
        )
    lines.append("")
    for incident in results["incidents"]:
        lines.extend(
            [
                f"### {incident['id']} — {incident['host']}",
                "",
                f"**Window.** {incident['window_start']} to {incident['window_end']}",
                "",
                f"**Enrichment.** asset `{incident['enrichment']['asset_criticality']}`, "
                f"privileged technique `{incident['enrichment']['privileged_technique']}`, "
                f"intel `{incident['enrichment']['threat_intel']}`.",
                "",
                "**Alerts.**",
                "",
                "| Alert | Level | Techniques | Count |",
                "|---|---|---|---:|",
            ]
        )
        for alert in incident["alerts"]:
            lines.append(
                f"| {alert['title']} | {alert['level']} | {', '.join(alert['techniques'])} | {alert['count']} |"
            )
        lines.extend(["", "**Actions.**", ""])
        for action in incident["actions"]:
            lines.append(f"- `{action['action']}` ({action['mode']}): {action['reason']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run dry-run triage and response playbooks")
    parser.add_argument("--alerts", default=str(ALERTS_DIR / "alerts.json"), help="Detection run alerts JSON")
    parser.add_argument("--out", default=str(RESULTS_PATH), help="Write results JSON")
    parser.add_argument("--report", default=str(REPORT_PATH), help="Write the Markdown report")
    args = parser.parse_args()

    path = Path(args.alerts)
    if not path.is_file():
        raise SystemExit(f"Missing {path}. Run python -m pipeline.detect first.")
    payload = json.loads(path.read_text(encoding="utf-8"))
    alerts = payload.get("alerts", [])
    results = run_triage(alerts)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(to_markdown(results), encoding="utf-8")
    print(json.dumps(results["summary"], indent=2))


if __name__ == "__main__":
    main()

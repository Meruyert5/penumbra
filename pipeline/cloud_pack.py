"""Evaluate the Apsis-facing cloud detection pack over the lab corpus.

The pack is deliberately separate from the 50-rule Sigma core. It contains the
CloudTrail detections that complement the IAM path work in Apsis: root policy
changes, root user creation, and CloudTrail tampering. Each detection carries
the EQL an analyst would run, the evidence it found, and the response hand-off.

Run:
    python -m pipeline.cloud_pack
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Callable

from pipeline.common import LAB_LOGS_DIR, ROOT
from pipeline.hunts import load_events

CLOUD_DIR = ROOT / "cloud"
RESULTS_PATH = CLOUD_DIR / "results.json"
REPORT_PATH = CLOUD_DIR / "README.md"

ROOT_POLICY_ACTIONS = ("AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy")
TRAIL_TAMPER_ACTIONS = ("StopLogging", "DeleteTrail", "UpdateTrail")


def _event(event: dict[str, Any]) -> dict[str, Any]:
    return event.get("event") or {}


def _is_aws(event: dict[str, Any]) -> bool:
    return (event.get("cloud") or {}).get("provider") == "aws"


def _user(event: dict[str, Any]) -> str:
    return str((event.get("user") or {}).get("name") or "")


def _is_root_policy(event: dict[str, Any]) -> bool:
    return _is_aws(event) and _user(event) == "root" and _event(event).get("action") in ROOT_POLICY_ACTIONS


def _is_root_user_creation(event: dict[str, Any]) -> bool:
    return _is_aws(event) and _user(event) == "root" and _event(event).get("action") == "CreateUser"


def _is_trail_tamper(event: dict[str, Any]) -> bool:
    return _is_aws(event) and _event(event).get("action") in TRAIL_TAMPER_ACTIONS


DETECTIONS: list[dict[str, Any]] = [
    {
        "id": "CLOUD-001",
        "title": "Root policy attachment",
        "level": "critical",
        "technique": "T1098",
        "query": 'any where cloud.provider:"aws" and user.name:"root" and event.action in ("AttachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy")',
        "description": "A root principal attached or changed a policy. Root should not be doing routine IAM administration.",
        "predicate": _is_root_policy,
        "detection_change": "Alert on any root policy change, require a break-glass ticket, and export the finding to Apsis so the graph shows the new reachable paths.",
    },
    {
        "id": "CLOUD-002",
        "title": "Root user creation",
        "level": "critical",
        "technique": "T1136.003",
        "query": 'any where cloud.provider:"aws" and user.name:"root" and event.action:"CreateUser"',
        "description": "A root principal created a new IAM user. That user is a persistence candidate and needs immediate review.",
        "predicate": _is_root_user_creation,
        "detection_change": "Alert on root-created IAM users, disable the new principal pending review, and add it to the Apsis inventory.",
    },
    {
        "id": "CLOUD-003",
        "title": "CloudTrail tampering",
        "level": "critical",
        "technique": "T1562.008",
        "query": 'any where cloud.provider:"aws" and event.action in ("StopLogging", "DeleteTrail", "UpdateTrail")',
        "description": "A principal stopped, deleted, or changed a CloudTrail trail. This is a defense-evasion lead and a visibility emergency.",
        "predicate": _is_trail_tamper,
        "detection_change": "Alert on trail changes, verify the trail with an independent account-level control, and require a change ticket.",
    },
]


def _evidence(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": event.get("@timestamp", ""),
        "host": (event.get("host") or {}).get("name"),
        "user": _user(event),
        "source": (event.get("source") or {}).get("ip"),
        "detail": f"{_event(event).get('action')} -> {_event(event).get('outcome') or 'unknown'}",
    }


def run_pack(events: list[dict[str, Any]]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    fired = 0
    total_events = 0
    for detection in DETECTIONS:
        predicate: Callable[[dict[str, Any]], bool] = detection["predicate"]
        hits = [event for event in events if predicate(event)]
        if hits:
            fired += 1
            total_events += len(hits)
        rows.append(
            {
                "id": detection["id"],
                "title": detection["title"],
                "level": detection["level"],
                "technique": detection["technique"],
                "query": detection["query"],
                "description": detection["description"],
                "detection_change": detection["detection_change"],
                "status": "fired" if hits else "not_exercised",
                "event_count": len(hits),
                "evidence": [_evidence(event) for event in hits],
            }
        )
    return {
        "summary": {
            "detections": len(DETECTIONS),
            "fired": fired,
            "events": total_events,
            "not_exercised": sum(1 for row in rows if row["status"] == "not_exercised"),
        },
        "detections": rows,
    }


def to_markdown(results: dict[str, Any]) -> str:
    summary = results["summary"]
    lines = [
        "# Cloud detection pack",
        "",
        "CloudTrail detections that complement the IAM path work in Apsis. This pack",
        "is separate from the 50-rule Sigma core and exports the same evidence shape as",
        "the rest of Penumbra.",
        "",
        f"- Detections: **{summary['detections']}**",
        f"- Detections fired: **{summary['fired']}**",
        f"- Events matched: **{summary['events']}**",
        f"- Detections not exercised: **{summary['not_exercised']}**",
        "",
        "| Detection | Level | Technique | Status | Events |",
        "|---|---|---|---|---:|",
    ]
    for row in results["detections"]:
        lines.append(
            f"| {row['id']} {row['title']} | {row['level']} | {row['technique']} | {row['status'].replace('_', ' ')} | {row['event_count']} |"
        )
    lines.append("")
    for row in results["detections"]:
        lines.extend(
            [
                f"## {row['id']} — {row['title']}",
                "",
                f"**Description.** {row['description']}",
                "",
                "**Query.**",
                "",
                "```eql",
                row["query"],
                "```",
                "",
                f"**Status.** {row['status'].replace('_', ' ')} ({row['event_count']} events).",
                "",
                *(["No matching CloudTrail event exists in this synthetic run; the rule is implemented but not exercised.", ""] if row["status"] == "not_exercised" else []),
                f"**Response hand-off.** {row['detection_change']}",
                "",
            ]
        )
        if row["evidence"]:
            lines.extend(
                [
                    "**Evidence.**",
                    "",
                    "| Time | Host | User | Source | Detail |",
                    "|---|---|---|---|---|",
                ]
            )
            for item in row["evidence"][:10]:
                lines.append(
                    f"| {item.get('time') or ''} | {item.get('host') or ''} | {item.get('user') or ''} | "
                    f"{item.get('source') or ''} | {item.get('detail') or ''} |"
                )
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate the cloud detection pack")
    parser.add_argument("--logs", default=str(LAB_LOGS_DIR), help="Directory of lab NDJSON files")
    parser.add_argument("--out", default=str(RESULTS_PATH), help="Write results JSON")
    parser.add_argument("--report", default=str(REPORT_PATH), help="Write the Markdown report")
    args = parser.parse_args()

    events = load_events(Path(args.logs))
    if not events:
        raise SystemExit(f"No events found in {args.logs}. Run python -m pipeline.labgen first.")
    results = run_pack(events)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(to_markdown(results), encoding="utf-8")
    print(json.dumps(results["summary"], indent=2))


if __name__ == "__main__":
    main()

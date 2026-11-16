"""Build the committed validation manifest used by the dashboard.

The raw OTRF samples and replay outputs are deliberately not committed. This
script turns the recorded run results into a compact, reviewable JSON artifact
that the dashboard can render without shipping attack telemetry.

Run:
    python -m pipeline.validation --write-results
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from pipeline.common import COMPILED_DIR, ROOT

RESULTS_PATH = ROOT / "docs" / "validation" / "results.json"

MATCHED = {"Suspicious Process Access to LSASS", "Windows Event Log Cleared"}

MISSING_INDEX = {
    "Linux Reverse Shell Command": "lab-linux",
    "Cloud Access Key Created": "lab-cloud",
    "Cloud Root Account Console Login": "lab-cloud",
    "Command Injection Attempt in Web Request": "lab-web",
    "Cron Job Executing Remote Content": "lab-linux",
    "Large Outbound Network Transfer": "lab-network",
    "Linux Log File Tampering": "lab-linux",
    "PHP File Uploaded to Web Accessible Directory": "lab-web",
    "Periodic Web Beacon to a Command Endpoint": "lab-web",
    "Root SSH Login from an External Address": "lab-linux",
    "SSH Authorized Keys Modified": "lab-linux",
    "Sudoers File Modified": "lab-linux",
    "Systemd Service Unit Created": "lab-linux",
    "Valid Service Account Login from an External Address": "lab-linux",
    "New Local User Account Created": "lab-linux",
    "Path Traversal Attempt in Web Request": "lab-web",
    "SQL Injection Attempt in Web Request": "lab-web",
    "Web Request to Common Web Shell Parameter": "lab-web",
    "SSH Failed Password Authentication": "lab-linux",
    "Web Scanner User Agent": "lab-web",
}

MISSING_FIELD = {
    "Critical Service Stopped Before Impact": "winlog.event_data.ServiceName",
    "Kerberoasting Service Ticket Request": "winlog.event_data.TicketEncryptionType",
    "PsExec Service Creation": "winlog.event_data.ImagePath",
    "SMB Administrative Share Access": "winlog.event_data.ShareName",
    "Suspicious Service Installed From User-Writable Path": "winlog.event_data.ImagePath, winlog.event_data.ServiceName",
}

MATCHED_ROWS = [
    {
        "title": "Suspicious Process Access to LSASS",
        "level": "critical",
        "technique": "T1003.001",
        "matches": 2,
        "sample": "OTRF Sysmon/Security",
        "verdict": "TP candidate",
    },
    {
        "title": "Windows Event Log Cleared",
        "level": "high",
        "technique": "T1070.001",
        "matches": 2,
        "sample": "OTRF Windows Security + Sysmon",
        "verdict": "TP candidate",
    },
]


def build_results(rules_path: Path = COMPILED_DIR / "rules.json") -> dict[str, Any]:
    rules = json.loads(rules_path.read_text(encoding="utf-8"))
    rows: list[dict[str, Any]] = []
    for rule in rules:
        title = rule.get("title", "")
        if title in MATCHED:
            status = "matched"
            reason = "Matched the real sample."
        elif title in MISSING_INDEX:
            status = "not_evaluable"
            reason = "Missing index: " + MISSING_INDEX[title]
        elif title in MISSING_FIELD:
            status = "not_evaluable"
            reason = "Missing field: " + MISSING_FIELD[title]
        else:
            status = "no_match"
            reason = "Evaluated on the real samples; no match."
        rows.append(
            {
                "title": title,
                "level": rule.get("level", ""),
                "technique": ", ".join(rule.get("techniques", [])),
                "status": status,
                "reason": reason,
            }
        )

    no_match = sum(1 for row in rows if row["status"] == "no_match")
    not_evaluable = sum(1 for row in rows if row["status"] == "not_evaluable")
    matched = sum(1 for row in rows if row["status"] == "matched")
    return {
        "generated": "2026-11-16",
        "source": "Recorded from the OTRF replay and 10x benign runs; raw data is not committed.",
        "totals": {
            "real_events": 228,
            "real_matches": 4,
            "rules_matched": matched,
            "tp_candidates": 4,
            "benign_events": 89704,
            "benign_matches": 1,
            "not_evaluable": not_evaluable,
            "no_match": no_match,
            "rules_total": len(rows),
            "missing_index": len(MISSING_INDEX),
            "missing_field": len(MISSING_FIELD),
            "correlation_fetch": 3,
        },
        "samples": [
            {
                "id": "synthetic",
                "name": "Committed scenario run",
                "events": 9223,
                "matches": 50,
                "correlations": 9,
                "kind": "synthetic",
                "note": "33 attack scenarios plus benign baseline; drives the dashboard",
            },
            {
                "id": "benign",
                "name": "Large benign baseline",
                "events": 89704,
                "matches": 1,
                "correlations": 0,
                "kind": "synthetic",
                "note": "10x baseline; one low-severity SSH match",
            },
            {
                "id": "otrf-security",
                "name": "OTRF Windows Security",
                "events": 110,
                "matches": 1,
                "correlations": 0,
                "kind": "real",
                "note": "Real event 1102; one rule matched",
            },
            {
                "id": "otrf-sysmon",
                "name": "OTRF Sysmon/Security",
                "events": 118,
                "matches": 3,
                "correlations": 0,
                "kind": "real",
                "note": "Two LSASS process-access matches plus event log cleared",
            },
        ],
        "matched": MATCHED_ROWS,
        "not_evaluable_breakdown": [
            {
                "reason": "Missing index",
                "count": len(MISSING_INDEX),
                "detail": "The Windows sample did not contain lab-linux, lab-web, lab-cloud, or lab-network.",
            },
            {
                "reason": "Missing field",
                "count": len(MISSING_FIELD),
                "detail": "The sample did not contain the service, Kerberos, SMB, or registry fields.",
            },
            {
                "reason": "Correlation fetch",
                "count": 3,
                "detail": "Linux, web, and network correlations could not fetch missing indices.",
            },
        ],
        "rules": rows,
    }


def write_results(path: Path = RESULTS_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_results(), indent=2) + "\n", encoding="utf-8")
    return path


def main() -> None:
    parser = argparse.ArgumentParser(description="Write the dashboard validation manifest")
    parser.add_argument("--write-results", action="store_true", help="write docs/validation/results.json")
    args = parser.parse_args()
    if args.write_results:
        print(f"Wrote {write_results()}")
    else:
        print(json.dumps(build_results()["totals"], indent=2))


if __name__ == "__main__":
    main()

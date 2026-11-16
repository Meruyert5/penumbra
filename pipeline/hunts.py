"""Run hypothesis-driven hunts over the deterministic lab corpus.

A hunt starts with a question, not an alert. Each hunt returns the evidence it
found, the query a production analyst would use, a verdict, and the detection
change it recommends. The module reads the local NDJSON corpus so it works
without a running Elasticsearch stack.

Run:
    python -m pipeline.hunts
"""

from __future__ import annotations

import argparse
import json
import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from pipeline.common import LAB_LOGS_DIR, ROOT

HUNTS_DIR = ROOT / "hunts"
RESULTS_PATH = HUNTS_DIR / "results.json"
REPORT_PATH = HUNTS_DIR / "README.md"

ROOT_ACTIONS = (
    "ConsoleLogin",
    "CreateAccessKey",
    "CreateUser",
    "AttachUserPolicy",
    "PutUserPolicy",
    "CreateLoginProfile",
    "UpdateLoginProfile",
)

USER_WRITABLE = re.compile(r"(?i)(\\users\\public\\|\\appdata\\|\\temp\\|\\programdata\\)")
SHELL = re.compile(r"(?i)(cmd\.exe|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32)")


def load_events(logs_dir: Path = LAB_LOGS_DIR) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in sorted(Path(logs_dir).glob("*.ndjson")):
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


def _event(event: dict[str, Any]) -> dict[str, Any]:
    return event.get("event") or {}


def _winlog_data(event: dict[str, Any]) -> dict[str, Any]:
    return (event.get("winlog") or {}).get("event_data") or {}


def _event_data(event: dict[str, Any]) -> dict[str, Any]:
    return {
        "time": event.get("@timestamp", ""),
        "host": (event.get("host") or {}).get("name"),
        "user": (event.get("user") or {}).get("name"),
        "source": (event.get("source") or {}).get("ip"),
    }


def _range(hits: list[dict[str, Any]]) -> tuple[str | None, str | None]:
    times = [str(event.get("@timestamp", "")) for event in hits if event.get("@timestamp")]
    return (min(times), max(times)) if times else (None, None)


def _result(
    hunt_id: str,
    title: str,
    hypothesis: str,
    query: str,
    finding: str,
    hits: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    detection_change: str,
    limitations: str,
    confidence: str = "high",
) -> dict[str, Any]:
    first, last = _range(hits)
    return {
        "id": hunt_id,
        "title": title,
        "hypothesis": hypothesis,
        "query": query,
        "finding": finding,
        "verdict": "true_positive" if hits else "no_finding",
        "confidence": confidence if hits else "none",
        "event_count": len(hits),
        "first_seen": first,
        "last_seen": last,
        "evidence": evidence,
        "detection_change": detection_change,
        "limitations": limitations,
    }


def hunt_root_cloud_identity(events: list[dict[str, Any]]) -> dict[str, Any]:
    hits = [
        event
        for event in events
        if (event.get("cloud") or {}).get("provider") == "aws"
        and (event.get("user") or {}).get("name") == "root"
        and _event(event).get("action") in ROOT_ACTIONS
    ]
    actions = Counter(_event(event).get("action") for event in hits)
    action_text = ", ".join(f"{name} x{count}" for name, count in actions.most_common())
    evidence = [
        {
            **_event_data(event),
            "detail": f"{_event(event).get('action')} -> {_event(event).get('outcome') or 'unknown'}",
        }
        for event in hits
    ]
    return _result(
        "HUNT-001",
        "Root identity activity in AWS",
        "A root principal should not create access keys, create users, or attach policies. Any root action outside a known break-glass window is worth an investigation.",
        'any where cloud.provider:"aws" and user.name:"root" and event.action in ("ConsoleLogin", "CreateAccessKey", "CreateUser", "AttachUserPolicy")',
        f"{len(hits)} root events across {len(actions)} actions: {action_text}.",
        hits,
        evidence,
        "Alert on root CreateAccessKey, CreateUser, AttachUserPolicy, and ConsoleLogin. Require a break-glass ticket, and export the finding to Apsis so the IAM graph can show which paths the new principal can reach.",
        "Synthetic root-compromise scenario. A production rule needs a break-glass allowlist and an approved source-IP or identity-provider context.",
    )


def hunt_service_path(events: list[dict[str, Any]]) -> dict[str, Any]:
    services = [event for event in events if _event(event).get("code") in {"7045", "4697"}]
    hits: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for event in services:
        data = _winlog_data(event)
        image = str(data.get("ImagePath") or "")
        if image and (USER_WRITABLE.search(image) or SHELL.search(image)):
            hits.append(event)
            evidence.append(
                {
                    **_event_data(event),
                    "detail": f"{data.get('ServiceName') or 'unknown'} -> {image}",
                }
            )
    names = ", ".join(str(_winlog_data(event).get("ServiceName") or "unknown") for event in hits)
    return _result(
        "HUNT-002",
        "Service binary outside a trusted path",
        "A new service should run from a signed system or application path. A service binary in a user-writable directory, or a shell command as the service image, is a persistence lead.",
        'any where event.code:"7045" and winlog.event_data.ImagePath like~ ("*\\\\Users\\\\Public\\\\*", "*\\\\AppData\\\\*", "*\\\\Temp\\\\*", "*\\\\ProgramData\\\\*", "*cmd.exe*", "*powershell*")',
        f"{len(hits)} service installs matched the heuristic: {names}.",
        hits,
        evidence,
        "The existing rule covers user-writable service paths. Add a software-inventory allowlist, alert on 7045 from non-admin users, and compare the service name with the installed product.",
        "PSEXESVC is not flagged by the path heuristic because it runs from C:\\Windows. The existing rule catches it by name, which is why hunts and rules are complementary.",
    )


def _dns_name(event: dict[str, Any]) -> str:
    question = (event.get("dns") or {}).get("question") or {}
    return str(question.get("name") or "").lower()


def _parent_domain(name: str) -> str:
    labels = name.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else name


def hunt_dns_tunnel(events: list[dict[str, Any]]) -> dict[str, Any]:
    dns = [event for event in events if _event(event).get("action") == "dns_query"]
    groups: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for event in dns:
        name = _dns_name(event)
        if name:
            groups[_parent_domain(name)].append((name, event))

    hits: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    findings: list[str] = []
    for parent, items in groups.items():
        names = {name for name, _ in items}
        labels = [label for name in names for label in name.split(".")[:-2]]
        longest = max((len(label) for label in labels), default=0)
        if len(items) >= 5 and len(names) >= 5 and longest >= 20:
            hits.extend(event for _, event in items)
            findings.append(
                f"{len(items)} queries under {parent}, {len(names)} unique subdomains, longest label {longest} characters"
            )
            evidence.extend(
                {
                    **_event_data(event),
                    "detail": name,
                }
                for name, event in items[:8]
            )
    return _result(
        "HUNT-003",
        "DNS tunneling pattern",
        "A high volume of unique, long subdomains under one parent domain can indicate data encoded in DNS queries.",
        'any where event.action:"dns_query" and dns.question.name like~ "*.tunnel.example"',
        "; ".join(findings) + "." if findings else "No parent domain passed the volume, uniqueness, and label-length thresholds.",
        hits,
        evidence,
        "Add a DNS tunneling rule that scores parent-domain rarity, unique subdomain count, and label length. Exclude known CDN, telemetry, and mail domains.",
        "Synthetic labels are regular and deliberately easy to spot. A production hunt needs entropy estimates, baseline parent-domain frequency, and resolver context.",
    )


def hunt_lsass_access(events: list[dict[str, Any]]) -> dict[str, Any]:
    access = [
        event
        for event in events
        if _event(event).get("code") == "10"
        and "lsass.exe" in str(_winlog_data(event).get("TargetImage") or "").lower()
    ]
    hits: list[dict[str, Any]] = []
    evidence: list[dict[str, Any]] = []
    for event in access:
        source = str(_winlog_data(event).get("SourceImage") or "")
        if source and not source.lower().startswith(("c:\\windows\\system32\\", "c:\\windows\\syswow64\\")):
            hits.append(event)
            evidence.append(
                {
                    **_event_data(event),
                    "detail": f"{source} -> lsass.exe, access {_winlog_data(event).get('GrantedAccess') or 'unknown'}",
                }
            )
    return _result(
        "HUNT-004",
        "LSASS access from a user-writable path",
        "A process outside System32 or SysWOW64 should not open LSASS with credential-dumping access. This is a hunt for credential theft that is independent of the existing rule.",
        'any where event.code:"10" and winlog.event_data.TargetImage:"*lsass.exe" and not winlog.event_data.SourceImage like~ ("C:\\\\Windows\\\\System32\\\\*", "C:\\\\Windows\\\\SysWOW64\\\\*")',
        f"{len(hits)} LSASS access events came from a user-writable path.",
        hits,
        evidence,
        "The existing rule catches this path. Add a hunt for LSASS access from user-writable directories, and compare the process signer and parent with the rule verdict.",
        "Security products and diagnostic tools may legitimately access LSASS. Require signer, parent, and change-ticket context before calling it malicious.",
    )


def run_hunts(events: list[dict[str, Any]]) -> dict[str, Any]:
    hunts = [
        hunt_root_cloud_identity(events),
        hunt_service_path(events),
        hunt_dns_tunnel(events),
        hunt_lsass_access(events),
    ]
    sources = Counter((event.get("event") or {}).get("dataset") or "unknown" for event in events)
    return {
        "summary": {
            "hunts": len(hunts),
            "events_reviewed": len(events),
            "findings": sum(1 for hunt in hunts if hunt["event_count"]),
            "confirmed": sum(1 for hunt in hunts if hunt["verdict"] == "true_positive"),
        },
        "sources": [{"name": name, "events": count} for name, count in sources.most_common()],
        "hunts": hunts,
    }


def _verdict_label(value: str) -> str:
    return "True positive" if value == "true_positive" else "No finding"


def to_markdown(results: dict[str, Any]) -> str:
    summary = results["summary"]
    lines = [
        "# Threat hunts",
        "",
        "Hypothesis-driven hunts over the deterministic lab corpus. A hunt starts with a",
        "question, then records the query, evidence, verdict, and the detection change it",
        "recommends.",
        "",
        f"- Hunts: **{summary['hunts']}**",
        f"- Events reviewed: **{summary['events_reviewed']:,}**",
        f"- Hunts with findings: **{summary['findings']}**",
        f"- Confirmed true positives: **{summary['confirmed']}**",
        "",
        "| Hunt | Title | Events | Verdict |",
        "|---|---|---:|---|",
    ]
    for hunt in results["hunts"]:
        lines.append(
            f"| {hunt['id']} | {hunt['title']} | {hunt['event_count']} | {_verdict_label(hunt['verdict'])} |"
        )
    lines.append("")
    for hunt in results["hunts"]:
        lines.extend(
            [
                f"## {hunt['id']} — {hunt['title']}",
                "",
                f"**Hypothesis.** {hunt['hypothesis']}",
                "",
                "**Query.**",
                "",
                "```eql",
                hunt["query"],
                "```",
                "",
                f"**Finding.** {hunt['finding']}",
                "",
                f"**Verdict.** {_verdict_label(hunt['verdict'])} ({hunt['confidence']} confidence).",
                "",
                f"**Detection change.** {hunt['detection_change']}",
                "",
                f"**Limitations.** {hunt['limitations']}",
                "",
            ]
        )
        if hunt["evidence"]:
            lines.extend(
                [
                    "**Evidence.**",
                    "",
                    "| Time | Host | User | Source | Detail |",
                    "|---|---|---|---|---|",
                ]
            )
            for row in hunt["evidence"][:10]:
                lines.append(
                    f"| {row.get('time') or ''} | {row.get('host') or ''} | {row.get('user') or ''} | "
                    f"{row.get('source') or ''} | {row.get('detail') or ''} |"
                )
            if len(hunt["evidence"]) > 10:
                lines.append("")
                lines.append(f"Showing 10 of {len(hunt['evidence'])} evidence rows. Full data is in `results.json`.")
            lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run hypothesis-driven hunts")
    parser.add_argument("--logs", default=str(LAB_LOGS_DIR), help="Directory of lab NDJSON files")
    parser.add_argument("--out", default=str(RESULTS_PATH), help="Write results JSON")
    parser.add_argument("--report", default=str(REPORT_PATH), help="Write the Markdown report")
    args = parser.parse_args()

    events = load_events(Path(args.logs))
    if not events:
        raise SystemExit(f"No events found in {args.logs}. Run python -m pipeline.labgen first.")

    results = run_hunts(events)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    report = Path(args.report)
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(to_markdown(results), encoding="utf-8")
    print(json.dumps(results["summary"], indent=2))


if __name__ == "__main__":
    main()

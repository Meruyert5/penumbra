"""Build the MITRE ATT&CK coverage report from compiled rules and correlations.

Run with:  python -m pipeline.coverage
Writes docs/attck-coverage.md (committed, so reviewers see it on GitHub).
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from typing import Any

from pipeline.common import (
    COMPILED_DIR,
    DOCS_DIR,
    LEVEL_RANK,
    TACTIC_ORDER,
    ensure_dir,
    tactics,
)
from pipeline.correlate import load_specs

# Techniques a SOC hiring manager expects an analyst to know about.
# Anything here that is not covered shows up as a documented gap, which is a
# more honest (and more useful) artifact than claiming full coverage.
PRIORITY_TECHNIQUES = {
    "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1059.004": ("Unix Shell", "execution"),
    "T1003.001": ("LSASS Memory", "credential_access"),
    "T1003.002": ("Security Account Manager", "credential_access"),
    "T1055": ("Process Injection", "defense_evasion"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1053.003": ("Cron", "persistence"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1543.002": ("Systemd Service", "persistence"),
    "T1547.001": ("Registry Run Keys", "persistence"),
    "T1546.003": ("WMI Event Subscription", "persistence"),
    "T1098.001": ("Additional Cloud Credentials", "persistence"),
    "T1098.004": ("SSH Authorized Keys", "persistence"),
    "T1110.001": ("Password Guessing", "credential_access"),
    "T1110.003": ("Password Spraying", "credential_access"),
    "T1078": ("Valid Accounts", "initial_access"),
    "T1078.004": ("Cloud Accounts", "initial_access"),
    "T1071.001": ("Web Protocols", "command_and_control"),
    "T1071.004": ("DNS", "command_and_control"),
    "T1105": ("Ingress Tool Transfer", "command_and_control"),
    "T1562.001": ("Disable or Modify Tools", "defense_evasion"),
    "T1562.004": ("Disable or Modify System Firewall", "defense_evasion"),
    "T1070.001": ("Clear Windows Event Logs", "defense_evasion"),
    "T1070.002": ("Clear Linux or Mac System Logs", "defense_evasion"),
    "T1505.003": ("Web Shell", "persistence"),
    "T1136.001": ("Local Account", "persistence"),
    "T1021.004": ("SSH", "lateral_movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral_movement"),
    "T1041": ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1046": ("Network Service Discovery", "discovery"),
    "T1087": ("Account Discovery", "discovery"),
    "T1190": ("Exploit Public-Facing Application", "initial_access"),
    "T1486": ("Data Encrypted for Impact", "impact"),
    "T1490": ("Inhibit System Recovery", "impact"),
    "T1489": ("Service Stop", "impact"),
    "T1560.001": ("Archive via Utility", "collection"),
    "T1218.011": ("Rundll32", "defense_evasion"),
    "T1218.005": ("Mshta", "defense_evasion"),
    "T1548.002": ("Bypass User Account Control", "privilege_escalation"),
    "T1548.003": ("Sudo and Sudo Caching", "privilege_escalation"),
    "T1558.003": ("Kerberoasting", "credential_access"),
    "T1595.002": ("Vulnerability Scanning", "reconnaissance"),
    "T1566.001": ("Spearphishing Attachment", "initial_access"),
    "T1569.002": ("Service Execution", "execution"),
}

TACTIC_LABEL = {
    "reconnaissance": "Reconnaissance",
    "resource_development": "Resource Development",
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _load_compiled() -> list[dict[str, Any]]:
    path = COMPILED_DIR / "rules.json"
    if not path.exists():
        raise SystemExit("rules/compiled/rules.json missing. Run: python -m pipeline.compile")
    return json.loads(path.read_text(encoding="utf-8"))


def _correlation_rules(correlations: list[Any] | None) -> list[dict[str, Any]]:
    """Turn correlation specs into rule-shaped records so coverage counts them."""
    records: list[dict[str, Any]] = []
    for spec in correlations or []:
        records.append(
            {
                "title": spec.title,
                "level": spec.level,
                "techniques": [spec.technique] if spec.technique else [],
                "tactics": tactics(spec.tags),
                "logsource": {"product": spec.index.replace("lab-", "")},
                "kind": "correlation",
            }
        )
    return records


def build_markdown(compiled: list[dict[str, Any]], correlations: list[Any] | None = None) -> str:
    rules = list(compiled) + _correlation_rules(correlations)
    by_tactic: dict[str, list[dict[str, Any]]] = defaultdict(list)
    technique_rows: list[tuple[str, str, str, str, str]] = []
    covered: set[str] = set()

    for rule in rules:
        for tactic in rule.get("tactics") or ["uncategorised"]:
            by_tactic[tactic].append(rule)
        for technique in rule.get("techniques") or []:
            covered.add(technique)
            for tactic in rule.get("tactics") or ["uncategorised"]:
                technique_rows.append(
                    (
                        technique,
                        TACTIC_LABEL.get(tactic, tactic),
                        rule["level"],
                        rule["title"],
                        rule.get("logsource", {}).get("product", "-"),
                    )
                )

    techniques = {row[0] for row in technique_rows}
    tactics_covered = [t for t in TACTIC_ORDER if t in by_tactic]

    lines: list[str] = []
    lines.append("# MITRE ATT&CK Coverage")
    lines.append("")
    lines.append("> Generated by `python -m pipeline.coverage`. Do not edit by hand.")
    lines.append("> Source of truth: `rules/sigma/*.yml` plus `correlations/*.yml`.")
    lines.append("")
    lines.append(
        f"**{len(compiled)} Sigma rules + {len(correlations or [])} correlations** covering "
        f"**{len(techniques)} techniques** across **{len(tactics_covered)} tactics**."
    )
    lines.append("")

    lines.append("## Coverage by tactic")
    lines.append("")
    lines.append("| Tactic | Techniques | Detections |")
    lines.append("|---|---|---|")
    for tactic in tactics_covered:
        tactic_rules = by_tactic[tactic]
        tactic_techniques = sorted({t for rule in tactic_rules for t in rule.get("techniques") or []})
        lines.append(
            f"| {TACTIC_LABEL.get(tactic, tactic)} | {', '.join(tactic_techniques) or '-'} | {len(tactic_rules)} |"
        )
    lines.append("")

    lines.append("## Detection detail")
    lines.append("")
    lines.append("| Technique | Tactic | Level | Detection | Source |")
    lines.append("|---|---|---|---|---|")
    for technique, tactic, level, title, source in sorted(
        technique_rows,
        key=lambda row: (
            TACTIC_ORDER.index(next((t for t in TACTIC_ORDER if TACTIC_LABEL[t] == row[1]), TACTIC_ORDER[0])),
            row[0],
            row[3],
        ),
    ):
        lines.append(f"| {technique} | {tactic} | {level} | {title} | {source} |")
    lines.append("")

    gaps = [
        f"{technique} ({name})"
        for technique, (name, _tactic) in PRIORITY_TECHNIQUES.items()
        if technique not in covered
    ]
    lines.append("## Known gaps")
    lines.append("")
    if gaps:
        lines.append("Priority techniques not yet covered. These are the next detections to write:")
        lines.append("")
        for gap in gaps:
            lines.append(f"- {gap}")
    else:
        lines.append("All priority techniques are covered.")
    lines.append("")

    return "\n".join(lines)


def technique_name(technique: str, fallback: str) -> str:
    return PRIORITY_TECHNIQUES.get(technique, (fallback, None))[0]


def coverage_tiles(
    compiled: list[dict[str, Any]], correlations: list[Any] | None = None
) -> tuple[dict[str, dict[str, dict[str, Any]]], set[str]]:
    """tactic -> technique -> best tile (deduplicated), plus the covered technique set.

    A technique can legitimately appear under more than one tactic; it must not
    appear twice under the same tactic, which is what this dedupe prevents.
    """
    tiles: dict[str, dict[str, dict[str, Any]]] = {}
    covered: set[str] = set()
    for rule in list(compiled) + _correlation_rules(correlations):
        for technique in rule["techniques"]:
            covered.add(technique)
            name = technique_name(technique, rule["title"])
            for tactic in rule["tactics"]:
                bucket = tiles.setdefault(tactic, {})
                current = bucket.get(technique)
                if current is None or LEVEL_RANK[rule["level"]] > LEVEL_RANK[current["level"]]:
                    bucket[technique] = {"level": rule["level"], "title": rule["title"], "name": name}
    for technique, (name, tactic) in PRIORITY_TECHNIQUES.items():
        if technique not in covered:
            tiles.setdefault(tactic, {})[technique] = {"level": None, "title": "not covered", "name": name}
    return tiles, covered


def main() -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Generate the ATT&CK coverage report")
    parser.add_argument("--check", action="store_true", help="fail if docs/attck-coverage.md is stale (for CI)")
    args = parser.parse_args()

    compiled = _load_compiled()
    correlations = load_specs()
    markdown = build_markdown(compiled, correlations)
    target = DOCS_DIR / "attck-coverage.md"

    if args.check:
        current = target.read_text(encoding="utf-8") if target.exists() else ""
        if current != markdown:
            print("docs/attck-coverage.md is stale. Run: python -m pipeline.coverage")
            return 1
        print("ATT&CK coverage report is up to date.")
        return 0

    ensure_dir(DOCS_DIR)
    target.write_text(markdown, encoding="utf-8")
    print(f"Wrote docs/attck-coverage.md ({len(compiled)} rules, {len(correlations)} correlations)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Static checks for Sigma rules: metadata quality, not detection correctness.

Run with:  python -m pipeline.lint
Exit code is 1 when any error is found, so CI fails on a bad rule.
"""

from __future__ import annotations

import re
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pipeline.common import (
    LEVELS,
    STATUSES,
    load_rules,
    techniques,
)

REQUIRED_FIELDS = (
    "title",
    "id",
    "status",
    "level",
    "description",
    "author",
    "date",
    "logsource",
    "detection",
    "tags",
)

FILENAME_RE = re.compile(r"^(win|linux|web|cloud|net|macos)_[a-z0-9_]+\.yml$")
MIN_DESCRIPTION = 40


@dataclass(frozen=True)
class Issue:
    path: Path
    severity: str  # "error" | "warning"
    message: str

    def __str__(self) -> str:
        return f"[{self.severity:7}] {self.path.name}: {self.message}"


def _is_uuid(value: Any) -> bool:
    try:
        uuid.UUID(str(value))
    except (ValueError, AttributeError, TypeError):
        return False
    return True


def lint_rule(path: Path, rule: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []

    def error(message: str) -> None:
        issues.append(Issue(path, "error", message))

    def warn(message: str) -> None:
        issues.append(Issue(path, "warning", message))

    if not isinstance(rule, dict):
        error("file does not contain a YAML mapping")
        return issues

    for field in REQUIRED_FIELDS:
        if not rule.get(field):
            error(f"missing required field '{field}'")

    rule_id = rule.get("id")
    if rule_id and not _is_uuid(rule_id):
        error(f"id '{rule_id}' is not a valid UUID")
    elif rule_id:
        try:
            if uuid.UUID(str(rule_id)).version != 4:
                warn("id is not a UUIDv4")
        except ValueError:
            pass

    level = str(rule.get("level", "")).lower()
    if level and level not in LEVELS:
        error(f"level '{level}' is not one of {', '.join(LEVELS)}")

    status = str(rule.get("status", "")).lower()
    if status and status not in STATUSES:
        error(f"status '{status}' is not one of {', '.join(STATUSES)}")

    tags = rule.get("tags") or []
    if tags and not techniques(tags):
        error("no MITRE ATT&CK technique tag (expected e.g. attack.t1059.001)")

    description = str(rule.get("description") or "").strip()
    if description and len(description) < MIN_DESCRIPTION:
        error(f"description is shorter than {MIN_DESCRIPTION} characters")

    detection = rule.get("detection") or {}
    if detection and "condition" not in detection:
        error("detection block has no 'condition'")

    logsource = rule.get("logsource") or {}
    if logsource and not (logsource.get("category") or logsource.get("service")):
        error("logsource needs a category or service")

    if not rule.get("falsepositives"):
        warn("no falsepositives documented; tuning notes make a rule reviewable")
    if not rule.get("references"):
        warn("no references")
    if not FILENAME_RE.match(path.name):
        warn("filename should look like '<platform>_<subject>.yml'")

    return issues


def lint_rules(rules: list[tuple[Path, dict[str, Any]]]) -> list[Issue]:
    issues: list[Issue] = []
    seen_ids: dict[str, Path] = {}
    seen_titles: dict[str, Path] = {}

    for path, rule in rules:
        issues.extend(lint_rule(path, rule))
        if not isinstance(rule, dict):
            continue
        rule_id = str(rule.get("id") or "")
        title = str(rule.get("title") or "").lower()
        if rule_id:
            if rule_id in seen_ids:
                issues.append(Issue(path, "error", f"duplicate id, also used by {seen_ids[rule_id].name}"))
            seen_ids[rule_id] = path
        if title:
            if title in seen_titles:
                issues.append(Issue(path, "error", f"duplicate title, also used by {seen_titles[title].name}"))
            seen_titles[title] = path

    return issues


def main() -> int:
    rules = load_rules()
    if not rules:
        print("No rules found in rules/sigma")
        return 1

    issues = lint_rules(rules)
    errors = [issue for issue in issues if issue.severity == "error"]
    warnings = [issue for issue in issues if issue.severity == "warning"]

    for issue in errors + warnings:
        print(issue)

    print()
    print(f"{len(rules)} rules checked: {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())

"""Shared paths, configuration and Sigma helpers for the detection lab."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules" / "sigma"
COMPILED_DIR = ROOT / "rules" / "compiled"
CONFIG_DIR = ROOT / "config"
DOCS_DIR = ROOT / "docs"
LAB_LOGS_DIR = ROOT / "lab" / "logs"
ALERTS_DIR = ROOT / "alerts"
CORRELATIONS_DIR = ROOT / "correlations"

LEVELS = ("informational", "low", "medium", "high", "critical")
LEVEL_RANK = {name: index for index, name in enumerate(LEVELS)}
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")

# Ordered by the ATT&CK enterprise kill chain so reports read naturally.
TACTIC_ORDER = (
    "reconnaissance",
    "resource_development",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
)

TECHNIQUE_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
TACTIC_RE = re.compile(r"^attack\.([a-z_]+)$", re.IGNORECASE)


def ensure_dir(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    return path


def read_yaml(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def rule_paths() -> list[Path]:
    """All Sigma rule files, sorted for deterministic output."""
    return sorted(RULES_DIR.glob("*.yml"))


def load_rules() -> list[tuple[Path, dict[str, Any]]]:
    """Return (path, parsed_rule) pairs."""
    return [(path, read_yaml(path)) for path in rule_paths()]


def techniques(tags: list[str]) -> list[str]:
    found: list[str] = []
    for tag in tags or []:
        match = TECHNIQUE_RE.match(str(tag))
        if match:
            found.append(match.group(1).upper())
    return sorted(set(found))


def tactics(tags: list[str]) -> list[str]:
    found: set[str] = set()
    for tag in tags or []:
        match = TACTIC_RE.match(str(tag))
        if match and match.group(1).lower() in TACTIC_ORDER:
            found.add(match.group(1).lower())
    return sorted(found, key=TACTIC_ORDER.index)


def logsource_map() -> dict[str, Any]:
    return read_yaml(CONFIG_DIR / "logsource_map.yml")


def resolve_index(rule: dict[str, Any], mapping: dict[str, Any] | None = None) -> list[str]:
    mapping = mapping or logsource_map()
    product = (rule.get("logsource") or {}).get("product")
    entry = (mapping.get("products") or {}).get(product)
    if entry and entry.get("index"):
        return list(entry["index"])
    return list((mapping.get("default") or {}).get("index") or ["lab-*"])


def es_url() -> str:
    return os.environ.get("ELASTICSEARCH_URL", "http://localhost:9200").rstrip("/")


def write_json(path: Path, payload: Any) -> None:
    ensure_dir(path.parent)
    path.write_text(json.dumps(payload, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def severity_counts(rules: list[dict[str, Any]]) -> dict[str, int]:
    counts = {level: 0 for level in LEVELS}
    for rule in rules:
        level = str(rule.get("level", "informational")).lower()
        counts[level] = counts.get(level, 0) + 1
    return counts

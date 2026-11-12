"""Threshold correlation on top of single-event detections.

Sigma base rules stay portable and simple; anything that needs "N events in T
seconds" lives here instead of in a backend-specific aggregation. This mirrors
how most SOCs split base detections from correlation logic.

Run with:  python -m pipeline.correlate --input alerts/events.ndjson
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from pipeline.common import CORRELATIONS_DIR, read_yaml

WINDOW_RE = re.compile(r"^(\d+)\s*(s|m|h|d)$", re.IGNORECASE)
WINDOW_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


@dataclass
class CorrelationSpec:
    id: str
    title: str
    level: str
    technique: str
    group_by: str
    window_seconds: int
    threshold: int
    match: dict[str, str]
    index: str = "lab-*"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    distinct_by: str | None = None
    distinct_threshold: int = 0


def parse_window(value: str | int) -> int:
    if isinstance(value, int):
        return value
    match = WINDOW_RE.match(str(value).strip())
    if not match:
        raise ValueError(f"invalid window '{value}', expected e.g. 5m or 30s")
    amount, unit = match.groups()
    return int(amount) * WINDOW_UNITS[unit.lower()]


def parse_timestamp(value: str) -> datetime:
    text = str(value).replace("Z", "+00:00")
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def get_field(event: dict[str, Any], path: str) -> Any:
    current: Any = event
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _compare(value: Any, operator: str, expected: str) -> bool:
    if value is None:
        return False
    if isinstance(value, list):
        return any(_compare(item, operator, expected) for item in value)
    text = str(value)
    expected = str(expected)
    if operator == "contains":
        return expected.lower() in text.lower()
    if operator == "startswith":
        return text.lower().startswith(expected.lower())
    if operator == "endswith":
        return text.lower().endswith(expected.lower())
    if operator == "equals":
        return text.lower() == expected.lower()
    raise ValueError(f"unsupported match operator '{operator}'")


def matches(event: dict[str, Any], match: dict[str, str]) -> bool:
    for key, expected in match.items():
        if "|" in key:
            field_name, operator = key.split("|", 1)
        else:
            field_name, operator = key, "equals"
        if not _compare(get_field(event, field_name), operator, expected):
            return False
    return True


def correlate(events: Iterable[dict[str, Any]], specs: Iterable[CorrelationSpec]) -> list[dict[str, Any]]:
    alerts: list[dict[str, Any]] = []
    events = list(events)

    for spec in specs:
        groups: dict[Any, list[tuple[datetime, dict[str, Any]]]] = defaultdict(list)
        for event in events:
            if not matches(event, spec.match):
                continue
            raw_ts = event.get("@timestamp") or event.get("timestamp")
            if not raw_ts:
                continue
            groups[get_field(event, spec.group_by)].append((parse_timestamp(raw_ts), event))

        for group_value, items in groups.items():
            items.sort(key=lambda item: item[0])
            left = 0
            for right in range(len(items)):
                while items[right][0] - items[left][0] > timedelta(seconds=spec.window_seconds):
                    left += 1
                window = items[left : right + 1]
                count = len(window)
                distinct_count = 0
                if spec.distinct_by:
                    distinct_count = len(
                        {
                            str(get_field(item[1], spec.distinct_by))
                            for item in window
                            if get_field(item[1], spec.distinct_by) is not None
                        }
                    )
                distinct_ok = not spec.distinct_by or distinct_count >= spec.distinct_threshold
                if count >= spec.threshold and distinct_ok:
                    alerts.append(
                        {
                            "correlation_id": spec.id,
                            "title": spec.title,
                            "level": spec.level,
                            "technique": spec.technique,
                            "group_by": spec.group_by,
                            "group_value": group_value,
                            "count": count,
                            "threshold": spec.threshold,
                            "distinct_by": spec.distinct_by,
                            "distinct_count": distinct_count,
                            "distinct_threshold": spec.distinct_threshold,
                            "window_seconds": spec.window_seconds,
                            "first_seen": window[0][0].isoformat().replace("+00:00", "Z"),
                            "last_seen": window[-1][0].isoformat().replace("+00:00", "Z"),
                            "index": spec.index,
                        }
                    )
                    break  # one alert per group per run is enough for triage

    return alerts


def load_specs(directory: Path | None = None) -> list[CorrelationSpec]:
    directory = directory or CORRELATIONS_DIR
    specs: list[CorrelationSpec] = []
    for path in sorted(directory.glob("*.yml")):
        data = read_yaml(path)
        specs.append(
            CorrelationSpec(
                id=data["id"],
                title=data["title"],
                level=str(data.get("level", "medium")).lower(),
                technique=str(data.get("technique", "")).upper(),
                group_by=data["group_by"],
                window_seconds=parse_window(data["window"]),
                threshold=int(data["threshold"]),
                match=data["match"],
                index=data.get("index", "lab-*"),
                description=" ".join(str(data.get("description", "")).split()),
                tags=data.get("tags") or [],
                distinct_by=data.get("distinct_by"),
                distinct_threshold=int(data.get("distinct_threshold", 0)),
            )
        )
    return specs


def main() -> int:
    parser = argparse.ArgumentParser(description="Run threshold correlations over exported events")
    parser.add_argument("--input", required=True, help="NDJSON file of events")
    parser.add_argument("--out", default="alerts/correlations.json")
    args = parser.parse_args()

    events = [json.loads(line) for line in Path(args.input).read_text(encoding="utf-8").splitlines() if line.strip()]
    alerts = correlate(events, load_specs())

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(alerts, indent=2) + "\n", encoding="utf-8")
    print(f"{len(alerts)} correlation alerts from {len(events)} events -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

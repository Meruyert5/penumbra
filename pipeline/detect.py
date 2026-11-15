"""Execute compiled detections against Elasticsearch and write a triage summary.

Run with:  python -m pipeline.detect --hours 24
Requires the Docker stack to be up and telemetry ingested.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests

from pipeline.common import ALERTS_DIR, COMPILED_DIR, LEVEL_RANK, ensure_dir, es_url
from pipeline.correlate import correlate, load_specs

MAX_EVENTS_PER_RULE = 100


def require_elasticsearch(url: str) -> None:
    try:
        requests.get(f"{url}/_cluster/health", timeout=5).raise_for_status()
    except requests.RequestException as exc:
        raise SystemExit(f"Cannot reach Elasticsearch at {url}. Start it with: docker compose up -d\n{exc}")


def _range(hours: int, end: datetime | None) -> dict[str, str]:
    if end is None:
        return {"gte": f"now-{hours}h"}
    start = end - timedelta(hours=hours)
    return {
        "gte": start.astimezone(timezone.utc).isoformat(timespec="seconds"),
        "lte": end.astimezone(timezone.utc).isoformat(timespec="seconds"),
    }


def run_eql(
    url: str,
    index: list[str],
    query: str,
    hours: int,
    end: datetime | None = None,
) -> list[dict[str, Any]]:
    body = {
        "query": query,
        "size": MAX_EVENTS_PER_RULE,
        "timestamp_field": "@timestamp",
        "filter": {"range": {"@timestamp": _range(hours, end)}},
    }
    response = requests.post(
        f"{url}/{','.join(index)}/_eql/search",
        json=body,
        params={"filter_path": "hits.total,hits.events"},
        timeout=120,
    )
    if response.status_code >= 400:
        # Surface the Elasticsearch reason: field mapping errors are the usual cause.
        raise RuntimeError(f"EQL failed ({response.status_code}): {response.text[:500]}")
    payload = response.json()
    return [event["_source"] for event in payload.get("hits", {}).get("events", [])]


def fetch_events(
    url: str,
    index: list[str],
    hours: int,
    limit: int = 10000,
    end: datetime | None = None,
) -> list[dict[str, Any]]:
    body = {
        "size": limit,
        "sort": [{"@timestamp": "asc"}],
        "query": {"range": {"@timestamp": _range(hours, end)}},
    }
    response = requests.post(f"{url}/{','.join(index)}/_search", json=body, timeout=120)
    response.raise_for_status()
    return [hit["_source"] for hit in response.json().get("hits", {}).get("hits", [])]


def summarize(alerts: list[dict[str, Any]], correlations: list[dict[str, Any]], hours: int) -> str:
    lines: list[str] = []
    lines.append("# Detection Run Summary")
    lines.append("")
    lines.append(f"Window: last {hours}h | generated {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    lines.append("")
    lines.append(f"**{len(alerts)} rule matches** | **{len(correlations)} correlation alerts**")
    lines.append("")

    by_level = Counter(alert["level"] for alert in alerts)
    if by_level:
        lines.append("| Level | Matches |")
        lines.append("|---|---|")
        for level in sorted(by_level, key=lambda name: -LEVEL_RANK.get(name, 0)):
            lines.append(f"| {level} | {by_level[level]} |")
        lines.append("")

    lines.append("## Rule matches")
    lines.append("")
    if not alerts:
        lines.append("No rule matched. Confirm telemetry is indexed (`GET lab-*/_count`).")
    else:
        lines.append("| Level | Detection | Technique | Host | Count |")
        lines.append("|---|---|---|---|---|")
        for alert in sorted(alerts, key=lambda item: -LEVEL_RANK.get(item["level"], 0)):
            host = alert.get("host") or "-"
            lines.append(
                f"| {alert['level']} | {alert['title']} | {', '.join(alert.get('techniques') or []) or '-'} | {host} | {alert['count']} |"
            )
    lines.append("")

    lines.append("## Correlation alerts")
    lines.append("")
    if not correlations:
        lines.append("No correlation threshold reached.")
    else:
        lines.append("| Level | Detection | Group | Count / threshold | Window |")
        lines.append("|---|---|---|---|---|")
        for alert in correlations:
            lines.append(
                f"| {alert['level']} | {alert['title']} | {alert['group_by']}={alert['group_value']} | "
                f"{alert['count']}/{alert['threshold']} | {alert['window_seconds']}s |"
            )
    lines.append("")
    return "\n".join(lines)


def build_timeline(matched: list[tuple[str, str, str, str]]) -> list[dict[str, Any]]:
    """Hourly alert volume by severity, with the quiet edges kept in view.

    The chart spans the alert activity plus a two hour shoulder on each side.
    Filling the entire detection window would bury a short scenario burst in
    twenty empty buckets and make the baseline look like missing data.
    """
    if not matched:
        return []
    buckets: dict[str, dict[str, int]] = {}
    for timestamp, level, _host, _source in matched:
        if len(timestamp) < 13:
            continue
        hour = timestamp[:13] + ":00:00Z"
        bucket = buckets.setdefault(hour, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
        bucket["total"] += 1
        bucket[level] = bucket.get(level, 0) + 1

    ordered = sorted(buckets)
    first = datetime.fromisoformat(ordered[0].replace("Z", "+00:00"))
    last = datetime.fromisoformat(ordered[-1].replace("Z", "+00:00"))
    start = first - timedelta(hours=2)
    end = last + timedelta(hours=2)
    rows: list[dict[str, Any]] = []
    current = start
    while current <= end:
        key = current.strftime("%Y-%m-%dT%H:00:00Z")
        bucket = buckets.get(key, {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0})
        rows.append({"hour": key, **bucket})
        current += timedelta(hours=1)
    return rows


def index_count(url: str) -> int | None:
    try:
        response = requests.get(f"{url}/lab-*/_count", params={"ignore_unavailable": "true"}, timeout=10)
        if response.status_code == 200:
            return response.json().get("count")
    except requests.RequestException:
        pass
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description="Run compiled detections against Elasticsearch")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--end", help="ISO timestamp to anchor the window, for a reproducible snapshot (default: now)")
    parser.add_argument("--url", default=es_url())
    parser.add_argument("--out", default=str(ALERTS_DIR))
    parser.add_argument("--dry-run", action="store_true", help="print queries without running them")
    args = parser.parse_args()

    end = None
    if args.end:
        try:
            end = datetime.fromisoformat(args.end.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError as exc:
            raise SystemExit(f"Invalid --end timestamp: {args.end!r} ({exc})")

    rules = json.loads((COMPILED_DIR / "rules.json").read_text(encoding="utf-8"))
    if args.dry_run:
        for rule in rules:
            print(f"# {rule['title']} [{rule['level']}] -> {','.join(rule['index'])}")
            print(rule["query"])
            print()
        return 0

    require_elasticsearch(args.url)

    alerts: list[dict[str, Any]] = []
    errors: list[str] = []
    matched: list[tuple[str, str, str, str]] = []
    for rule in rules:
        try:
            events = run_eql(args.url, rule["index"], rule["query"], args.hours, end)
        except RuntimeError as exc:
            errors.append(f"{rule['title']}: {exc}")
            continue
        if not events:
            continue
        hosts = Counter((event.get("host") or {}).get("name", "-") for event in events)
        for event in events:
            matched.append(
                (
                    str(event.get("@timestamp", "")),
                    rule["level"],
                    str((event.get("host") or {}).get("name", "-")),
                    str((event.get("event") or {}).get("dataset", "unknown")),
                )
            )
        alerts.append(
            {
                "rule_id": rule["id"],
                "title": rule["title"],
                "level": rule["level"],
                "techniques": rule["techniques"],
                "tactics": rule["tactics"],
                "index": rule["index"],
                "query": rule["query"],
                "query_kql": rule["query_kql"],
                "count": len(events),
                "host": ", ".join(f"{name} ({count})" for name, count in hosts.most_common()),
                "hosts": sorted(hosts),
                "first_seen": min(event["@timestamp"] for event in events),
                "last_seen": max(event["@timestamp"] for event in events),
                "events": events[:3],
            }
        )

    specs = load_specs()
    correlations: list[dict[str, Any]] = []
    specs_by_index: dict[str, list[Any]] = {}
    for spec in specs:
        specs_by_index.setdefault(spec.index, []).append(spec)
    for index, index_specs in specs_by_index.items():
        try:
            events = fetch_events(args.url, [index], args.hours, end=end)
            correlations.extend(correlate(events, index_specs))
        except requests.RequestException as exc:
            errors.append(f"correlation fetch for {index} failed: {exc}")

    timeline = build_timeline(matched)
    host_counts = Counter(item[2] for item in matched)
    source_counts = Counter(item[3] for item in matched)

    out_dir = ensure_dir(Path(args.out))
    meta = {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "window_hours": args.hours,
        "window_end": (end or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
        "events_indexed": index_count(args.url),
        "rules_evaluated": len(rules),
        "correlations_evaluated": len(specs),
        "errors": errors,
    }
    (out_dir / "alerts.json").write_text(
        json.dumps(
            {
                "meta": meta,
                "alerts": alerts,
                "correlations": correlations,
                "timeline": timeline,
                "hosts": [{"name": name, "count": count} for name, count in host_counts.most_common()],
                "sources": [{"name": name, "count": count} for name, count in source_counts.most_common()],
                "errors": errors,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    summary = summarize(alerts, correlations, args.hours)
    (out_dir / "summary.md").write_text(summary + "\n", encoding="utf-8")

    print(summary)
    if errors:
        print("\nErrors:")
        for error in errors:
            print(f"  - {error}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

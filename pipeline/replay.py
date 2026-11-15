"""Normalize a public replay dataset into the lab's ECS-shaped NDJSON.

This module does not claim detection results. It maps common OTRF/Mordor-style
Sysmon and Windows Security fields into the subset the Sigma rules consume, so a
small public sample can be replayed through the same ingest and detect path.

Example:
    python -m pipeline.replay --source path/to/otrf.json --file windows --label malicious
    python -m pipeline.ingest --reset
    python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pipeline.common import LAB_LOGS_DIR, ensure_dir

CHANNEL_DATASET = {
    "microsoft-windows-sysmon/operational": "windows.sysmon_operational",
    "security": "windows.security",
    "system": "windows.system",
}


def _lookup(raw: dict[str, Any], event_data: dict[str, Any], *names: str) -> Any:
    for name in names:
        value = raw.get(name)
        if value in (None, ""):
            value = event_data.get(name)
        if value not in (None, ""):
            return value
    return None


def _timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, dict):
        value = value.get("SystemTime") or value.get("systemTime")
    if isinstance(value, (int, float)):
        seconds = value / 1000 if value > 10_000_000_000 else value
        return datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    if isinstance(value, str):
        text = value.strip().replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    return None


def _basename(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    return value.replace("/", "\\").split("\\")[-1]


def _first_ip(value: Any) -> str | None:
    if isinstance(value, list):
        return str(value[0]) if value else None
    if isinstance(value, str):
        return value.split(",")[0].strip() or None
    return None


def _as_int(value: Any) -> int | None:
    try:
        return int(str(value), 10)
    except (TypeError, ValueError):
        return None


def infer_file(raw: dict[str, Any], event_data: dict[str, Any]) -> str:
    channel = str(_lookup(raw, event_data, "Channel", "channel") or "").lower()
    image = str(_lookup(raw, event_data, "Image", "ProcessPath", "NewProcessName") or "")
    if "sysmon" in channel or channel == "security" or channel == "system" or "windows" in image.lower():
        return "windows"
    if "linux" in channel or "audit" in channel:
        return "linux"
    if "aws" in channel or "cloudtrail" in channel:
        return "cloud"
    if "nginx" in channel or "http" in channel:
        return "web"
    if "zeek" in channel or "flow" in channel:
        return "network"
    return "windows"


def normalize_event(raw: dict[str, Any]) -> dict[str, Any] | None:
    """Map one OTRF/Mordor-style event to the lab's ECS subset.

    Returns None when the event has no usable timestamp. The original event is
    not copied into the output; only the fields needed for detection and triage
    are retained.
    """
    raw = dict(raw or {})
    event_data = raw.get("EventData") or raw.get("event_data") or {}
    if isinstance(event_data, str):
        event_data = {}
    if not isinstance(event_data, dict):
        event_data = {}

    timestamp = _timestamp(
        _lookup(raw, event_data, "@timestamp", "timestamp", "UtcTime", "TimeCreated", "TimeGenerated")
    )
    if timestamp is None:
        return None

    channel = str(_lookup(raw, event_data, "Channel", "channel") or "")
    event_id = _lookup(raw, event_data, "EventID", "event_id", "EventId")
    event_id = str(event_id) if event_id is not None else None
    host = _lookup(raw, event_data, "Computer", "Hostname", "host.name", "host")
    if isinstance(host, dict):
        host = host.get("name")

    image = _lookup(raw, event_data, "Image", "ProcessPath", "NewProcessName", "process.executable")
    command = _lookup(raw, event_data, "CommandLine", "ProcessCommandLine", "command_line", "process.command_line")
    parent_image = _lookup(raw, event_data, "ParentImage", "ParentProcessName", "process.parent.executable")
    parent_command = _lookup(raw, event_data, "ParentCommandLine", "process.parent.command_line")
    user = _lookup(raw, event_data, "User", "SubjectUserName", "TargetUserName", "user.name")
    pid = _lookup(raw, event_data, "ProcessId", "NewProcessId", "process.pid")

    category = "process"
    action = "process_start"
    if event_id in {"3", "5156"}:
        category, action = "network", "network_connection"
    elif event_id in {"11"}:
        category, action = "file", "file_create"
    elif event_id in {"12", "13", "14"}:
        category, action = "registry", "registry_change"
    elif event_id in {"22"}:
        category, action = "network", "dns_query"
    elif event_id in {"4688"}:
        category, action = "process", "process_start"

    event: dict[str, Any] = {
        "@timestamp": timestamp,
        "event": {
            "kind": "event",
            "module": "otrf",
            "dataset": CHANNEL_DATASET.get(channel.lower(), "otrf.replay"),
            "category": category,
            "type": ["start"] if action == "process_start" else ["info"],
            "action": action,
        },
        "host": {"name": str(host)} if host else {},
        "user": {"name": str(user)} if user else {},
        "process": {},
        "winlog": {
            "channel": channel,
            "event_id": event_id,
            "computer_name": str(host) if host else None,
        },
    }
    if image:
        event["process"]["executable"] = str(image)
        event["process"]["executable.caseless"] = str(image).lower()
        event["process"]["name"] = _basename(image)
    if command:
        event["process"]["command_line"] = str(command)
    if parent_image:
        event["process"]["parent"] = {
            "executable": str(parent_image),
            "executable.caseless": str(parent_image).lower(),
            "name": _basename(parent_image),
        }
    if parent_command:
        event["process"].setdefault("parent", {})["command_line"] = str(parent_command)
    if pid is not None:
        event["process"]["pid"] = _as_int(pid)

    source_ip = _first_ip(_lookup(raw, event_data, "SourceIp", "SourceIP", "source.ip", "src_ip"))
    dest_ip = _first_ip(_lookup(raw, event_data, "DestinationIp", "DestinationIP", "destination.ip", "dest_ip"))
    dest_port = _as_int(_lookup(raw, event_data, "DestinationPort", "destination.port", "dest_port"))
    if source_ip or dest_ip:
        event["source"] = {"ip": source_ip} if source_ip else {}
        event["destination"] = {"ip": dest_ip, "port": dest_port} if dest_ip or dest_port else {}
        event["network"] = {"transport": _lookup(raw, event_data, "Protocol", "network.transport")}
    target_file = _lookup(raw, event_data, "TargetFilename", "file.path")
    if target_file:
        event["file"] = {"path": str(target_file)}
    query = _lookup(raw, event_data, "QueryName", "dns.question.name")
    if query:
        event["dns"] = {"question": {"name": str(query)}}
    script = _lookup(raw, event_data, "ScriptBlockText", "powershell.file.script_block_text")
    if script:
        event["powershell"] = {"file": {"script_block_text": str(script)}}

    # Drop empty nested objects so the index template stays clean.
    event = {key: value for key, value in event.items() if value not in ({}, None)}
    if "process" in event and not event["process"]:
        del event["process"]
    if "winlog" in event:
        event["winlog"] = {key: value for key, value in event["winlog"].items() if value not in (None, "")}
    return event


def load_events(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".ndjson", ".jsonl"}:
        return [json.loads(line) for line in text.splitlines() if line.strip()]
    payload = json.loads(text)
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("events"), list):
        return payload["events"]
    if isinstance(payload, dict):
        return [payload]
    raise SystemExit(f"Unsupported replay payload in {path}")


def replay(source: Path, out_dir: Path, file_name: str | None, label: str, limit: int | None) -> dict[str, Any]:
    raw_events = load_events(source)
    if limit:
        raw_events = raw_events[:limit]
    normalized: list[dict[str, Any]] = []
    unmapped = 0
    for raw in raw_events:
        event = normalize_event(raw)
        if event is None:
            unmapped += 1
            continue
        normalized.append(event)

    if not normalized:
        raise SystemExit("No events had a usable timestamp; nothing was written.")

    if file_name is None:
        first_raw = raw_events[0] if raw_events else {}
        data = first_raw.get("EventData") or first_raw.get("event_data") or {}
        file_name = infer_file(first_raw, data if isinstance(data, dict) else {})

    ensure_dir(out_dir)
    target = out_dir / f"{file_name}.ndjson"
    target.write_text("".join(json.dumps(event, sort_keys=False) + "\n" for event in normalized), encoding="utf-8")

    manifest = {
        "source": str(source),
        "file": str(target),
        "index": file_name,
        "label": label,
        "events": len(normalized),
        "skipped": unmapped,
        "first": normalized[0]["@timestamp"],
        "last": normalized[-1]["@timestamp"],
        "note": "Normalized replay data; detection results require pipeline.ingest and pipeline.detect.",
    }
    (out_dir / "replay-manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Normalize a public replay dataset for the lab")
    parser.add_argument("--source", required=True, help="OTRF/Mordor JSON or NDJSON file")
    parser.add_argument("--out", default=str(LAB_LOGS_DIR), help="Output directory for lab NDJSON")
    parser.add_argument("--file", choices=("windows", "linux", "web", "cloud", "network"), help="Target index family")
    parser.add_argument("--label", choices=("malicious", "benign", "unlabeled"), default="unlabeled")
    parser.add_argument("--limit", type=int, help="Only normalize the first N events")
    parser.add_argument("--dry-run", action="store_true", help="Print a sample instead of writing")
    args = parser.parse_args()

    source = Path(args.source)
    if not source.is_file():
        raise SystemExit(f"Replay source not found: {source}")

    if args.dry_run:
        events = load_events(source)[: args.limit or 1]
        sample = normalize_event(events[0]) if events else None
        print(json.dumps(sample, indent=2) if sample else "No usable event")
        return

    manifest = replay(source, Path(args.out), args.file, args.label, args.limit)
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()

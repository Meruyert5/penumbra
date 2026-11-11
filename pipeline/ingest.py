"""Load lab telemetry into Elasticsearch.

Run with:  python -m pipeline.ingest --reset
Requires the Docker stack to be up:  docker compose up -d
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

import requests

from pipeline.common import CONFIG_DIR, LAB_LOGS_DIR, es_url

INDEX_BY_FILE = {
    "windows": "lab-windows",
    "linux": "lab-linux",
    "web": "lab-web",
}

TEMPLATE_NAME = "lab-template"


def require_elasticsearch(url: str) -> None:
    try:
        response = requests.get(f"{url}/_cluster/health", timeout=5)
        response.raise_for_status()
    except requests.RequestException as exc:
        raise SystemExit(
            f"Cannot reach Elasticsearch at {url}.\n"
            "Start the stack with:  docker compose up -d\n"
            f"Underlying error: {exc}"
        )


def install_template(url: str) -> None:
    template = json.loads((CONFIG_DIR / "index-template.json").read_text(encoding="utf-8"))
    response = requests.put(f"{url}/_index_template/{TEMPLATE_NAME}", json=template, timeout=30)
    response.raise_for_status()


def reset_indices(url: str) -> None:
    response = requests.delete(f"{url}/lab-*", timeout=30)
    if response.status_code not in (200, 404):
        response.raise_for_status()


def bulk_index(url: str, index: str, events: list[dict[str, Any]]) -> int:
    if not events:
        return 0
    lines: list[str] = []
    for event in events:
        lines.append(json.dumps({"index": {"_index": index}}))
        lines.append(json.dumps(event, sort_keys=False))
    body = "\n".join(lines) + "\n"

    response = requests.post(
        f"{url}/_bulk",
        data=body.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        params={"refresh": "true"},
        timeout=120,
    )
    response.raise_for_status()
    payload = response.json()
    if payload.get("errors"):
        first_error = next((item["index"]["error"] for item in payload["items"] if item["index"].get("error")), None)
        raise SystemExit(f"Bulk indexing failed: {first_error}")
    return len(events)


def main() -> int:
    parser = argparse.ArgumentParser(description="Index lab telemetry into Elasticsearch")
    parser.add_argument("--logs", default=str(LAB_LOGS_DIR))
    parser.add_argument("--url", default=es_url())
    parser.add_argument("--reset", action="store_true", help="delete lab-* indices first")
    args = parser.parse_args()

    require_elasticsearch(args.url)
    install_template(args.url)
    if args.reset:
        reset_indices(args.url)

    total = 0
    for name, index in INDEX_BY_FILE.items():
        path = Path(args.logs) / f"{name}.ndjson"
        if not path.exists():
            print(f"skip {path.name}: not found (run python -m pipeline.labgen)")
            continue
        events = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        count = bulk_index(args.url, index, events)
        total += count
        print(f"{index}: {count} events")

    print(f"Indexed {total} events into {args.url}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

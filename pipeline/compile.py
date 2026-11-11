"""Compile Sigma rules into Elasticsearch EQL and KQL.

Sigma is the source of truth. Every rule is compiled twice:
  * EQL  -> executed by pipeline/detect.py against Elasticsearch
  * KQL  -> paste-able into Kibana Discover for manual triage

Windows rules are passed through pySigma's ECS mapping pipeline so that
Sysmon field names (Image, CommandLine, ...) resolve to Winlogbeat ECS fields.

Run with:  python -m pipeline.compile
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.windows import ecs_windows

from pipeline.common import (
    COMPILED_DIR,
    LEVEL_RANK,
    ROOT,
    logsource_map,
    resolve_index,
    rule_paths,
    read_text,
    tactics,
    techniques,
    write_json,
    read_yaml,
)


def _backend(rule: dict[str, Any], backend_cls):
    """Windows rules get the ECS mapping pipeline; other platforms are native."""
    product = (rule.get("logsource") or {}).get("product")
    pipeline = ecs_windows() if product == "windows" else None
    return backend_cls(processing_pipeline=pipeline)


def compile_rule(path: Path, mapping: dict[str, Any]) -> dict[str, Any]:
    text = read_text(path)
    rule = read_yaml(path)
    collection = SigmaCollection.from_yaml(text)

    eql_queries = _backend(rule, EqlBackend).convert(collection)
    kql_queries = _backend(rule, LuceneBackend).convert(collection)
    if not eql_queries or not kql_queries:
        raise ValueError(f"{path.name}: backend produced no query")

    tags = rule.get("tags") or []
    logsource = rule.get("logsource") or {}

    return {
        "id": rule["id"],
        "title": rule["title"],
        "status": rule.get("status"),
        "level": str(rule.get("level", "informational")).lower(),
        "description": " ".join(str(rule.get("description", "")).split()),
        "author": rule.get("author"),
        "date": str(rule.get("date")),
        "references": rule.get("references") or [],
        "falsepositives": rule.get("falsepositives") or [],
        "tags": tags,
        "techniques": techniques(tags),
        "tactics": tactics(tags),
        "logsource": logsource,
        "index": resolve_index(rule, mapping),
        "query": eql_queries[0],
        "query_kql": kql_queries[0],
        "source_file": f"rules/sigma/{path.name}",
    }


def compile_all() -> list[dict[str, Any]]:
    mapping = logsource_map()
    compiled = [compile_rule(path, mapping) for path in rule_paths()]
    compiled.sort(key=lambda rule: (-LEVEL_RANK.get(rule["level"], 0), rule["title"]))
    return compiled


def write_outputs(compiled: list[dict[str, Any]]) -> None:
    write_json(COMPILED_DIR / "rules.json", compiled)
    ndjson = "".join(json.dumps(rule, sort_keys=False) + "\n" for rule in compiled)
    (COMPILED_DIR / "rules.ndjson").write_text(ndjson, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compile Sigma rules to EQL/KQL")
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail if the committed compiled output is stale (for CI)",
    )
    args = parser.parse_args()

    compiled = compile_all()
    expected = json.dumps(compiled, indent=2, sort_keys=False) + "\n"
    current_path = COMPILED_DIR / "rules.json"

    if args.check:
        current = current_path.read_text(encoding="utf-8") if current_path.exists() else ""
        if current != expected:
            print("Compiled rules are stale. Run: python -m pipeline.compile")
            return 1
        print(f"Compiled rules are up to date ({len(compiled)} rules).")
        return 0

    write_outputs(compiled)
    print(f"Compiled {len(compiled)} rules -> {current_path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

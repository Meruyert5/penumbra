"""Every rule must compile to both EQL and KQL, and route to the right index."""

from __future__ import annotations

import json

from pipeline.compile import compile_all
from pipeline.common import COMPILED_DIR, ROOT


def test_every_rule_compiles():
    compiled = compile_all()
    assert len(compiled) >= 10
    for rule in compiled:
        assert rule["query"].startswith("any where"), rule["title"]
        assert rule["query_kql"], rule["title"]
        assert rule["techniques"], rule["title"]


def test_windows_rules_use_ecs_fields():
    import re

    native = re.compile(r"(?<![A-Za-z0-9_.])(Image|CommandLine|ParentImage|TargetFilename):")
    for rule in compile_all():
        if rule["logsource"].get("product") != "windows":
            continue
        query = rule["query"]
        # Sigma-native names must have been translated by the ECS pipeline.
        assert not native.search(query), f"{rule['title']} still uses Sigma-native fields: {query}"
        assert "winlog." in query or "process." in query


def test_index_routing():
    for rule in compile_all():
        product = rule["logsource"].get("product")
        expected = {"windows": "lab-windows", "linux": "lab-linux", "nginx": "lab-web"}.get(product, "lab-*")
        assert expected in rule["index"], rule["title"]


def test_compiled_output_is_current():
    compiled = compile_all()
    committed = json.loads((COMPILED_DIR / "rules.json").read_text(encoding="utf-8"))
    assert committed == compiled, "rules/compiled/rules.json is stale; run python -m pipeline.compile"
    assert (ROOT / "rules" / "compiled" / "rules.ndjson").exists()


def test_no_rule_can_be_silently_dropped():
    compiled = compile_all()
    ids = {rule["id"] for rule in compiled}
    titles = {rule["title"] for rule in compiled}
    assert len(ids) == len(compiled), "duplicate rule ids"
    assert len(titles) == len(compiled), "duplicate rule titles"

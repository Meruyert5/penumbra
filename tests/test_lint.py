"""Rule metadata must stay reviewable: every rule in the repo must lint clean."""

from __future__ import annotations

import copy

from pipeline.common import load_rules
from pipeline.lint import lint_rule, lint_rules


def _base_rule() -> dict:
    return {
        "title": "Example Rule",
        "id": "2f1a6c3e-8b47-4d92-a1f5-0c9e7b3d5a28",
        "status": "experimental",
        "level": "high",
        "description": "A sufficiently long description that explains what the rule detects.",
        "author": "Test",
        "date": "2026/11/11",
        "references": ["https://example.com"],
        "falsepositives": ["None known"],
        "tags": ["attack.execution", "attack.t1059.001"],
        "logsource": {"category": "process_creation", "product": "windows"},
        "detection": {"selection": {"Image|endswith": "\\cmd.exe"}, "condition": "selection"},
    }


def test_repository_rules_have_no_errors():
    issues = lint_rules(load_rules())
    errors = [issue for issue in issues if issue.severity == "error"]
    assert errors == []


def test_valid_rule_passes():
    from pathlib import Path

    assert lint_rule(Path("win_example.yml"), _base_rule()) == []


def test_missing_required_field_fails():
    from pathlib import Path

    rule = _base_rule()
    del rule["description"]
    issues = lint_rule(Path("win_example.yml"), rule)
    assert any("description" in issue.message for issue in issues)


def test_invalid_level_fails():
    from pathlib import Path

    rule = _base_rule()
    rule["level"] = "urgent"
    issues = lint_rule(Path("win_example.yml"), rule)
    assert any("level" in issue.message for issue in issues)


def test_missing_attack_tag_fails():
    from pathlib import Path

    rule = _base_rule()
    rule["tags"] = ["attack.execution"]
    issues = lint_rule(Path("win_example.yml"), rule)
    assert any("ATT&CK technique" in issue.message for issue in issues)


def test_duplicate_ids_are_errors():
    from pathlib import Path

    rule = _base_rule()
    issues = lint_rules([(Path("win_a.yml"), rule), (Path("win_b.yml"), copy.deepcopy(rule))])
    assert any("duplicate id" in issue.message for issue in issues)

"""Coverage output is a deliverable, so it is tested like one."""

from __future__ import annotations

from pipeline.compile import compile_all
from pipeline.coverage import build_markdown


def test_coverage_lists_every_technique():
    compiled = compile_all()
    markdown = build_markdown(compiled)
    for rule in compiled:
        for technique in rule["techniques"]:
            assert technique in markdown


def test_coverage_reports_gaps():
    markdown = build_markdown(compile_all())
    assert "## Known gaps" in markdown
    assert "## Coverage by tactic" in markdown
    assert "## Detection detail" in markdown

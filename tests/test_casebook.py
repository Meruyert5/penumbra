"""Tests for the structured IR casebook."""

from __future__ import annotations

from pipeline.casebook import load_casebook, to_markdown


def test_casebook_has_three_complete_cases() -> None:
    casebook = load_casebook()
    assert len(casebook["cases"]) == 3
    for case in casebook["cases"]:
        for key in ("id", "slug", "metrics", "containment", "eradication", "recovery", "communication", "evidence", "lessons", "open_questions"):
            assert key in case
        metrics = case["metrics"]
        assert metrics["observed_seconds"] > 0
        assert metrics["response_timing"].startswith("not measured")


def test_casebook_markdown_keeps_the_boundary() -> None:
    markdown = to_markdown(load_casebook())
    assert "PNB-2026-001" in markdown
    assert "PNB-2026-002" in markdown
    assert "PNB-2026-003" in markdown
    assert "Response timing is not fabricated" in markdown
    assert "Open questions" in markdown

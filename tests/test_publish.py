"""Tests for the public-site publish step."""

from pathlib import Path

from pipeline.publish import publish


def test_publish_copies_only_public_surface(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    (docs / "assets").mkdir(parents=True)
    (docs / "cases" / "case-001").mkdir(parents=True)
    (docs / "index.html").write_text("<html>dashboard</html>", encoding="utf-8")
    (docs / "CNAME").write_text("penumbra.is-a.dev", encoding="utf-8")
    (docs / "assets" / "icon.svg").write_text("<svg/>", encoding="utf-8")
    (docs / "cases" / "case-001" / "report.md").write_text("# case", encoding="utf-8")
    (docs / "validation").mkdir(parents=True)
    (docs / "validation" / "results.json").write_text('{"totals":{}}', encoding="utf-8")
    (docs / "design.md").write_text("private design notes", encoding="utf-8")
    (docs / "runbook.md").write_text("private runbook", encoding="utf-8")

    site = tmp_path / "site"
    counts = publish(docs, site)

    assert (site / "index.html").is_file()
    assert (site / "CNAME").read_text(encoding="utf-8") == "penumbra.is-a.dev"
    assert (site / "assets" / "icon.svg").is_file()
    assert (site / "cases" / "case-001" / "report.md").is_file()
    assert (site / "validation" / "results.json").is_file()
    assert (site / ".nojekyll").is_file()
    assert not (site / "design.md").exists()
    assert not (site / "runbook.md").exists()
    assert counts["files"] == 5
    assert counts["directories"] == 2


def test_publish_requires_a_built_dashboard(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    try:
        publish(docs, tmp_path / "site")
    except SystemExit as error:
        assert "not built" in str(error)
    else:
        raise AssertionError("publish should fail when index.html is missing")

"""Coverage output is a deliverable, so it is tested like one."""

from __future__ import annotations

from pipeline.common import tactics
from pipeline.compile import compile_all
from pipeline.coverage import PRIORITY_TECHNIQUES, build_markdown, coverage_tiles
from pipeline.correlate import load_specs


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


def test_priority_list_is_substantial():
    assert len(PRIORITY_TECHNIQUES) >= 40


def test_coverage_tiles_include_gaps_and_correlations():
    compiled = compile_all()
    specs = load_specs()
    tiles, covered = coverage_tiles(compiled, specs)
    tile_techniques = {technique for rows in tiles.values() for technique in rows}

    # Every priority technique appears once in the matrix.
    assert set(PRIORITY_TECHNIQUES) <= tile_techniques
    # Correlations close techniques that no single Sigma rule covers.
    assert {"T1046", "T1087", "T1110.003", "T1071.004"} <= covered

    known_tactics = {tactic for rule in compiled for tactic in rule["tactics"]}
    known_tactics |= {tactic for spec in specs for tactic in tactics(spec.tags)}
    for tactic, rows in tiles.items():
        assert tactic in known_tactics, tactic
        for technique, meta in rows.items():
            if meta["level"] is None:
                assert technique not in covered
            else:
                assert meta["level"] in {"low", "medium", "high", "critical"}

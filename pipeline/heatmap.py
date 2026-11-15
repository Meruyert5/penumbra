"""Render the ATT&CK coverage matrix as a standalone SVG for the README.

Run with:  python -m pipeline.heatmap
Writes docs/assets/attck-heatmap.svg. GitHub renders it inline.

The SVG is sized to GitHub's README content width (~1000px), so technique
tiles show the ATT&CK ID only. Full names and rule mapping live in
docs/attck-coverage.md and the interactive dashboard.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from pipeline.common import COMPILED_DIR, DOCS_DIR, TACTIC_ORDER, ensure_dir
from pipeline.coverage import PRIORITY_TECHNIQUES, TACTIC_LABEL, coverage_tiles
from pipeline.correlate import load_specs

WIDTH = 1000
PAD = 26
COL_GAP = 8
TILE_H = 22
TILE_GAP = 5
HEADER_H = 92
LEGEND_H = 34

# Penumbra palette: totality black, paper, ember, corona amber, stone.
BG = "#0B0A09"
PANEL = "#141210"
TILE = "#1B1612"
LINE = "#332C25"
LINE_SOFT = "#241F1A"
BONE = "#F6F4F1"
MUTED = "#A79E91"
BRASS = "#FBB931"
TEAL = "#FFE3B3"
CLAY = "#F95C4B"

LEVEL_COLOR = {
    "critical": "#F95C4B",
    "high": "#EA6113",
    "medium": "#FBB931",
    "low": "#B9A88F",
}


def _wrap(label: str, width: int) -> list[str]:
    words = label.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) <= width:
            current = candidate
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines[:2]


def build_svg(compiled: list[dict[str, Any]], correlations: list[Any] | None = None) -> str:
    tiles, covered = coverage_tiles(compiled, correlations)
    tactics = [tactic for tactic in TACTIC_ORDER if tactic in tiles]
    gaps = {technique for technique in PRIORITY_TECHNIQUES if technique not in covered}
    covered_priority = len(PRIORITY_TECHNIQUES) - len(gaps)

    rows = max(len(tiles[tactic]) for tactic in tactics)
    col_w = (WIDTH - 2 * PAD - COL_GAP * (len(tactics) - 1)) / len(tactics)
    height = HEADER_H + 26 + rows * (TILE_H + TILE_GAP) + LEGEND_H + PAD

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height:.0f}" '
        f'viewBox="0 0 {WIDTH} {height:.0f}" '
        f'font-family="Cascadia Code,JetBrains Mono,Consolas,monospace" role="img" '
        f'aria-label="MITRE ATT&amp;CK coverage matrix">'
    )
    parts.append(f'<rect width="{WIDTH}" height="{height:.0f}" fill="{BG}"/>')
    parts.append(f'<rect width="{WIDTH}" height="4" fill="{BRASS}"/>')
    parts.append(
        f'<text x="{PAD}" y="40" fill="{BONE}" font-size="20" font-weight="700" '
        f'letter-spacing="0.2">Penumbra</text>'
    )
    parts.append(
        f'<text x="{PAD}" y="62" fill="{MUTED}" font-size="11">'
        f"MITRE ATT&amp;CK coverage · {len(compiled)} Sigma rules"
        f"{f' + {len(correlations)} correlations' if correlations else ''} · "
        f"{len(covered)} techniques · {covered_priority}/{len(PRIORITY_TECHNIQUES)} priority · "
        f"{len(gaps)} gaps</text>"
    )
    parts.append(
        f'<line x1="{PAD}" y1="{HEADER_H - 10}" x2="{WIDTH - PAD}" y2="{HEADER_H - 10}" '
        f'stroke="{LINE_SOFT}"/>'
    )

    for index, tactic in enumerate(tactics):
        x = PAD + index * (col_w + COL_GAP)
        label_lines = _wrap(TACTIC_LABEL.get(tactic, tactic).upper(), 13)
        for line_index, line in enumerate(label_lines):
            parts.append(
                f'<text x="{x:.1f}" y="{HEADER_H + 6 + line_index * 10}" fill="{BRASS}" '
                f'font-size="8.5" letter-spacing="0.8">{escape(line)}</text>'
            )

        for row_index, (technique, item) in enumerate(sorted(tiles[tactic].items())):
            y = HEADER_H + 26 + row_index * (TILE_H + TILE_GAP)
            is_gap = item["level"] is None
            if is_gap:
                fill, stroke, dash, text_fill = BG, LINE, ' stroke-dasharray="3 3"', "#5f6f68"
            else:
                fill, stroke, dash, text_fill = TILE, LINE, "", BONE

            parts.append(f"<g><title>{escape(technique)} · {escape(item['name'])}")
            if not is_gap:
                parts.append(f" · {escape(item['title'])}")
            parts.append("</title>")
            parts.append(
                f'<rect x="{x:.1f}" y="{y}" width="{col_w:.1f}" height="{TILE_H}" rx="4" '
                f'fill="{fill}" stroke="{stroke}"{dash}/>'
            )
            if not is_gap:
                parts.append(
                    f'<rect x="{x:.1f}" y="{y}" width="3" height="{TILE_H}" rx="1.5" '
                    f'fill="{LEVEL_COLOR.get(item["level"], TEAL)}"/>'
                )
            parts.append(
                f'<text x="{x + 8:.1f}" y="{y + 14.5}" fill="{text_fill}" font-size="8.5">'
                f"{escape(technique)}</text>"
            )
            parts.append("</g>")

    legend_y = height - PAD - 4
    parts.append(
        f'<text x="{PAD}" y="{legend_y:.0f}" fill="{MUTED}" font-size="9" letter-spacing="0.8">'
        f"SEVERITY</text>"
    )
    legend = [("critical", "critical"), ("high", "high"), ("medium", "medium"), ("low", "low")]
    lx = PAD + 72
    for level, label in legend:
        parts.append(
            f'<rect x="{lx}" y="{legend_y - 8:.0f}" width="8" height="8" rx="2" '
            f'fill="{LEVEL_COLOR[level]}"/>'
        )
        parts.append(
            f'<text x="{lx + 13}" y="{legend_y:.0f}" fill="{MUTED}" font-size="9">{label}</text>'
        )
        lx += 13 + len(label) * 5.5 + 14
    parts.append(
        f'<rect x="{lx}" y="{legend_y - 8:.0f}" width="8" height="8" rx="2" '
        f'fill="{BG}" stroke="{LINE}" stroke-dasharray="3 3"/>'
    )
    parts.append(
        f'<text x="{lx + 13}" y="{legend_y:.0f}" fill="{MUTED}" font-size="9">gap</text>'
    )
    parts.append(
        f'<text x="{WIDTH - PAD}" y="{legend_y:.0f}" fill="{MUTED}" font-size="9" '
        f'text-anchor="end">generated by python -m pipeline.heatmap</text>'
    )

    parts.append("</svg>")
    return "".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the ATT&CK coverage SVG")
    parser.add_argument("--rules", default=str(COMPILED_DIR / "rules.json"))
    parser.add_argument("--out", default=str(DOCS_DIR / "assets" / "attck-heatmap.svg"))
    args = parser.parse_args()

    compiled = json.loads(Path(args.rules).read_text(encoding="utf-8"))
    correlations = load_specs()
    svg = build_svg(compiled, correlations)
    out = Path(args.out)
    ensure_dir(out.parent)
    out.write_text(svg, encoding="utf-8")
    print(f"Wrote {out} ({len(svg) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

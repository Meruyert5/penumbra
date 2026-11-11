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

WIDTH = 1000
PAD = 26
COL_GAP = 8
TILE_H = 22
TILE_GAP = 5
HEADER_H = 82
LEGEND_H = 30

LEVEL_COLOR = {
    "critical": "#ff5d5d",
    "high": "#ff9f43",
    "medium": "#ffd166",
    "low": "#4cc9f0",
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


def build_svg(compiled: list[dict[str, Any]]) -> str:
    tiles, covered = coverage_tiles(compiled)
    tactics = [tactic for tactic in TACTIC_ORDER if tactic in tiles]
    covered_tactics = {tactic for rule in compiled for tactic in rule["tactics"]}
    gaps = {technique for technique in PRIORITY_TECHNIQUES if technique not in covered}

    rows = max(len(tiles[tactic]) for tactic in tactics)
    col_w = (WIDTH - 2 * PAD - COL_GAP * (len(tactics) - 1)) / len(tactics)
    height = HEADER_H + 22 + rows * (TILE_H + TILE_GAP) + LEGEND_H + PAD

    parts: list[str] = []
    parts.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" height="{height:.0f}" '
        f'viewBox="0 0 {WIDTH} {height:.0f}" '
        f'font-family="ui-monospace,SFMono-Regular,Consolas,monospace">'
    )
    parts.append(f'<rect width="{WIDTH}" height="{height:.0f}" fill="#080c11"/>')
    parts.append(
        f'<text x="{PAD}" y="38" fill="#e6edf3" font-size="19" font-weight="700">'
        f"MITRE ATT&amp;CK Coverage</text>"
    )
    parts.append(
        f'<text x="{PAD}" y="58" fill="#8b9aab" font-size="11">'
        f"{len(compiled)} detections · {len(covered)} techniques · "
        f"{len(covered_tactics)} tactics covered · {len(gaps)} priority gaps</text>"
    )

    for index, tactic in enumerate(tactics):
        x = PAD + index * (col_w + COL_GAP)
        label_lines = _wrap(TACTIC_LABEL.get(tactic, tactic).upper(), 13)
        for line_index, line in enumerate(label_lines):
            parts.append(
                f'<text x="{x:.1f}" y="{HEADER_H + line_index * 10}" fill="#8b9aab" '
                f'font-size="8.5" letter-spacing="0.5">{escape(line)}</text>'
            )

        for row_index, (technique, item) in enumerate(sorted(tiles[tactic].items())):
            y = HEADER_H + 22 + row_index * (TILE_H + TILE_GAP)
            is_gap = item["level"] is None
            if is_gap:
                fill, stroke, dash, text_fill = "#0b1119", "#26313d", ' stroke-dasharray="3 3"', "#5f6f7f"
            else:
                fill, stroke, dash, text_fill = "#111c26", "#22384a", "", "#c8d7e6"

            parts.append(f"<g><title>{escape(technique)} · {escape(item['name'])}</title>")
            parts.append(
                f'<rect x="{x:.1f}" y="{y}" width="{col_w:.1f}" height="{TILE_H}" rx="4" '
                f'fill="{fill}" stroke="{stroke}"{dash}/>'
            )
            if not is_gap:
                parts.append(
                    f'<rect x="{x:.1f}" y="{y}" width="3" height="{TILE_H}" rx="1.5" '
                    f'fill="{LEVEL_COLOR.get(item["level"], "#7ee787")}"/>'
                )
            parts.append(
                f'<text x="{x + 8:.1f}" y="{y + 14.5}" fill="{text_fill}" font-size="8.5">'
                f"{escape(technique)}</text>"
            )
            parts.append("</g>")

    legend_y = height - PAD - 6
    parts.append(
        f'<text x="{PAD}" y="{legend_y:.0f}" fill="#8b9aab" font-size="9">'
        f"severity</text>"
    )
    legend = [("critical", "critical"), ("high", "high"), ("medium", "medium"), ("low", "low")]
    lx = PAD + 62
    for level, label in legend:
        parts.append(
            f'<rect x="{lx}" y="{legend_y - 8:.0f}" width="8" height="8" rx="2" '
            f'fill="{LEVEL_COLOR[level]}"/>'
        )
        parts.append(
            f'<text x="{lx + 13}" y="{legend_y:.0f}" fill="#8b9aab" font-size="9">{label}</text>'
        )
        lx += 13 + len(label) * 5.5 + 14
    parts.append(
        f'<rect x="{lx}" y="{legend_y - 8:.0f}" width="8" height="8" rx="2" '
        f'fill="#0b1119" stroke="#26313d" stroke-dasharray="3 3"/>'
    )
    parts.append(
        f'<text x="{lx + 13}" y="{legend_y:.0f}" fill="#8b9aab" font-size="9">gap</text>'
    )

    parts.append("</svg>")
    return "".join(parts)


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the ATT&CK coverage SVG")
    parser.add_argument("--rules", default=str(COMPILED_DIR / "rules.json"))
    parser.add_argument("--out", default=str(DOCS_DIR / "assets" / "attck-heatmap.svg"))
    args = parser.parse_args()

    compiled = json.loads(Path(args.rules).read_text(encoding="utf-8"))
    svg = build_svg(compiled)
    out = Path(args.out)
    ensure_dir(out.parent)
    out.write_text(svg, encoding="utf-8")
    print(f"Wrote {out} ({len(svg) // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

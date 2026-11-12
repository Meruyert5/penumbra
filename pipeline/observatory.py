"""Render the Transient observatory dashboard from the same deterministic run.

Run with:  python -m pipeline.observatory
Writes docs/transient.html. Signal Foundry stays at docs/index.html; both pages
share the alert, correlation, coverage, and case payload.
"""

from __future__ import annotations

import argparse
import sys
import webbrowser
from pathlib import Path

from pipeline.common import ALERTS_DIR, COMPILED_DIR, DOCS_DIR, ROOT, ensure_dir
from pipeline.report import build_html, build_payload, copy_case_reports, load_dashboard_source

DASHBOARD_DIR = ROOT / "observatory"
CASES_DIR = ROOT / "cases"

FONT_FILES = {
    "Newsreader": [
        {"file": "newsreader-latin.woff2", "weight": "200 800", "style": "normal"},
        {"file": "newsreader-italic-latin.woff2", "weight": "200 800", "style": "italic"},
    ],
    "IBM Plex Mono": [
        {"file": "ibm-plex-mono-400-latin.woff2", "weight": "400"},
        {"file": "ibm-plex-mono-500-latin.woff2", "weight": "500"},
    ],
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the Transient detection observatory")
    parser.add_argument("--alerts", default=str(ALERTS_DIR / "alerts.json"))
    parser.add_argument("--rules", default=str(COMPILED_DIR / "rules.json"))
    parser.add_argument("--cases", default=str(CASES_DIR / "cases.json"))
    parser.add_argument("--out", default=str(DOCS_DIR / "transient.html"))
    parser.add_argument("--open", action="store_true", help="open the report in a browser")
    args = parser.parse_args()

    source = load_dashboard_source(DASHBOARD_DIR, FONT_FILES)
    payload = build_payload(Path(args.alerts), Path(args.rules), Path(args.cases))
    html = build_html(payload, source)

    out = Path(args.out)
    ensure_dir(out.parent)
    out.write_text(html, encoding="utf-8")

    assets = ensure_dir(out.parent / "assets")
    (assets / "transient-icon.svg").write_text(source["icon"], encoding="utf-8")
    copied = copy_case_reports(payload["cases"], out.parent)

    size_kb = len(html.encode("utf-8")) // 1024
    print(
        f"Wrote {out} ({size_kb} KB, {len(payload['alerts'])} detections, "
        f"{len(payload['correlations'])} correlations, {copied} case reports)"
    )
    print(
        f"Coverage: {payload['coverage']['covered']}/{payload['coverage']['priority']} priority techniques, "
        f"{len(payload['coverage']['gaps'])} gaps"
    )

    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())

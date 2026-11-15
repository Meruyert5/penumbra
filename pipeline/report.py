"""Render the detection run as a self-contained interactive HTML dashboard.

Run with:  python -m pipeline.report
Writes docs/index.html, which works offline, from file://, and on GitHub Pages.

The dashboard source lives in dashboard/ as four files (template.html,
styles.css, app.js, icon.svg). This module inlines them and injects one JSON
payload, so the published page has no external requests and no build step.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import shutil
import sys
import webbrowser
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote

from pipeline.common import (
    ALERTS_DIR,
    COMPILED_DIR,
    DOCS_DIR,
    ROOT,
    TACTIC_ORDER,
    ensure_dir,
)
from pipeline.coverage import PRIORITY_TECHNIQUES, TACTIC_LABEL, coverage_tiles
from pipeline.correlate import load_specs
from pipeline.labgen import SCENARIOS

LEVELS = ["critical", "high", "medium", "low"]
DASHBOARD_DIR = ROOT / "dashboard"
CASES_DIR = ROOT / "cases"
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# Local font files keep the report self-contained. All families are SIL OFL 1.1.
FONT_FILES = {
    "Archivo": [
        {"file": "archivo-latin.woff2", "weight": "100 900"}
    ],
    "Space Mono": [
        {"file": "space-mono-400-latin.woff2", "weight": "400"},
        {"file": "space-mono-700-latin.woff2", "weight": "700"},
    ],
    "Bodoni Moda": [
        {"file": "bodoni-moda-latin.woff2", "weight": "400 900"},
        {"file": "bodoni-moda-italic-latin.woff2", "weight": "400 900", "style": "italic"},
    ],
}


def load_font_css(
    dashboard_dir: Path = DASHBOARD_DIR,
    font_files: dict[str, list[Any]] | None = None,
) -> str:
    entries_by_family = font_files or FONT_FILES
    rules: list[str] = []
    for family, entries in entries_by_family.items():
        for entry in entries:
            if isinstance(entry, dict):
                filename = str(entry["file"])
                weight = str(entry.get("weight", "400"))
                style = str(entry.get("style", "normal"))
                stretch = str(entry.get("stretch", "100%"))
            else:
                filename, weight = entry
                style = "normal"
                stretch = "100%"
            path = dashboard_dir / "fonts" / filename
            if not path.exists():
                raise SystemExit(f"Dashboard font missing: {path}")
            encoded = base64.b64encode(path.read_bytes()).decode("ascii")
            rules.append(
                '@font-face{font-family:"' + family + '";'
                f"font-style:{style};font-weight:{weight};font-stretch:{stretch};"
                "font-display:swap;"
                f'src:url(data:font/woff2;base64,{encoded}) format("woff2");'
                "}"
            )
    return "\n".join(rules)


def load_dashboard_source(
    dashboard_dir: Path = DASHBOARD_DIR,
    font_files: dict[str, list[Any]] | None = None,
) -> dict[str, str]:
    required = {
        "template": dashboard_dir / "template.html",
        "styles": dashboard_dir / "styles.css",
        "script": dashboard_dir / "app.js",
        "icon": dashboard_dir / "icon.svg",
    }
    missing = [str(path) for path in required.values() if not path.exists()]
    if missing:
        raise SystemExit("Dashboard source missing: " + ", ".join(missing))
    source = {key: path.read_text(encoding="utf-8") for key, path in required.items()}
    source["fonts"] = load_font_css(dashboard_dir, font_files)
    return source


def load_cases(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, list):
        raise SystemExit(f"{path} must contain a JSON list of case records")
    cases: list[dict[str, Any]] = []
    for item in document:
        slug = str(item.get("slug", ""))
        if not SLUG_RE.match(slug):
            raise SystemExit(f"Unsafe or missing case slug: {slug!r}")
        cases.append(
            {
                "id": item.get("id", ""),
                "slug": slug,
                "title": item.get("title", ""),
                "severity": str(item.get("severity", "medium")).lower(),
                "status": item.get("status", ""),
                "verdict": item.get("verdict", ""),
                "opened": item.get("opened", ""),
                "hosts": item.get("hosts") or [],
                "techniques": item.get("techniques") or [],
                "detections": item.get("detections") or [],
                "summary": item.get("summary", ""),
                "path": f"cases/{slug}/report.md",
            }
        )
    return cases


def copy_case_reports(cases: list[dict[str, Any]], docs_dir: Path) -> int:
    """Publish each case report beside the dashboard so links resolve on Pages."""
    copied = 0
    for case in cases:
        source = CASES_DIR / case["slug"] / "report.md"
        if not source.exists():
            print(f"  warning: {source} not found, case card will link to a missing file")
            continue
        target = docs_dir / "cases" / case["slug"] / "report.md"
        ensure_dir(target.parent)
        shutil.copy2(source, target)
        copied += 1
    return copied


def coverage_payload(compiled: list[dict[str, Any]], correlations: list[Any]) -> dict[str, Any]:
    tiles, covered = coverage_tiles(compiled, correlations)
    tactics: list[dict[str, Any]] = []
    for tactic in TACTIC_ORDER:
        if tactic not in tiles:
            continue
        rows = []
        for technique, meta in sorted(tiles[tactic].items()):
            rows.append(
                {
                    "technique": technique,
                    "name": meta["name"],
                    "level": meta["level"],
                    "title": meta["title"],
                }
            )
        tactics.append({"tactic": tactic, "label": TACTIC_LABEL.get(tactic, tactic), "tiles": rows})

    priority = list(PRIORITY_TECHNIQUES)
    covered_priority = [technique for technique in priority if technique in covered]
    gaps = [
        {"technique": technique, "name": PRIORITY_TECHNIQUES[technique][0]}
        for technique in priority
        if technique not in covered
    ]
    return {
        "tactics": tactics,
        "priority": len(priority),
        "covered": len(covered_priority),
        "gaps": gaps,
        "covered_techniques": sorted(covered),
    }


def pipeline_payload(
    meta: dict[str, Any],
    alerts: list[dict[str, Any]],
    correlations: list[dict[str, Any]],
    cases: list[dict[str, Any]],
    events: int,
) -> list[dict[str, Any]]:
    return [
        {
            "label": "Generate",
            "title": "Seeded telemetry",
            "detail": f"{len(SCENARIOS) - 1} attack scenarios plus a benign baseline across Windows, Linux, web, cloud, and network sources.",
            "count": f"{events:,}",
            "artifact": "lab/logs/*.ndjson",
        },
        {
            "label": "Compile",
            "title": "Sigma to EQL",
            "detail": "Every rule is translated to Elasticsearch EQL and Kibana KQL with ECS field names.",
            "count": str(meta.get("sigma_rules", 0)),
            "artifact": "rules/compiled/rules.json",
        },
        {
            "label": "Detect",
            "title": "Execute the library",
            "detail": "Queries run against live indices in one window. Errors surface instead of silently dropping.",
            "count": str(meta.get("rules_evaluated", 0)),
            "artifact": "alerts/alerts.json",
        },
        {
            "label": "Correlate",
            "title": "Add the volume logic",
            "detail": "Threshold and distinct-value specs catch spraying, scanning, and file bursts that single events miss.",
            "count": str(len(correlations)),
            "artifact": "alerts/correlations.json",
        },
        {
            "label": "Triage",
            "title": "Write the case",
            "detail": "Alerts become investigations with timeline, evidence, verdict, containment, and detection fixes.",
            "count": str(len(cases)),
            "artifact": "cases/*/report.md",
        },
    ]


def build_payload(
    alerts_path: Path,
    rules_path: Path,
    cases_path: Path,
) -> dict[str, Any]:
    if not alerts_path.exists():
        raise SystemExit(f"{alerts_path} not found. Run: python -m pipeline.detect")
    if not rules_path.exists():
        raise SystemExit(f"{rules_path} not found. Run: python -m pipeline.compile")

    document = json.loads(alerts_path.read_text(encoding="utf-8"))
    compiled = json.loads(rules_path.read_text(encoding="utf-8"))
    specs = load_specs()
    cases = load_cases(cases_path)

    alerts = document.get("alerts") or []
    correlations = document.get("correlations") or []
    errors = document.get("errors") or []
    meta = dict(document.get("meta") or {})

    # Case reports name rules by file stem, not UUID. Annotate each match so the
    # dashboard can join a case to the exact detection row that fired.
    rule_names = {
        str(rule.get("id")): Path(str(rule.get("source_file", ""))).stem
        for rule in compiled
    }
    for alert in alerts:
        alert["rule"] = rule_names.get(str(alert.get("rule_id")), "")

    severity = Counter(str(alert.get("level", "low")).lower() for alert in alerts)
    severity_counts = {level: severity.get(level, 0) for level in LEVELS}

    coverage = coverage_payload(compiled, specs)
    techniques = {technique for rule in compiled for technique in rule.get("techniques") or []}
    tactics = {tactic for rule in compiled for tactic in rule.get("tactics") or []}
    events = int(meta.get("events_indexed") or 0)

    meta.update(
        {
            "sigma_rules": len(compiled),
            "correlation_specs": len(specs),
            "scenarios": len(SCENARIOS),
            "priority_techniques": coverage["priority"],
            "covered_priority": coverage["covered"],
            "gaps": len(coverage["gaps"]),
            "techniques": len(techniques),
            "tactics": len(tactics),
            "errors": errors,
            "generated": meta.get("generated") or datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "events_indexed": events,
        }
    )

    timeline = document.get("timeline") or []
    hosts = document.get("hosts") or []
    sources = document.get("sources") or []
    if not hosts:
        counts: Counter[str] = Counter()
        for alert in alerts:
            for host in alert.get("hosts") or []:
                counts[host] += int(alert.get("count") or 0)
        hosts = [{"name": name, "count": count} for name, count in counts.most_common()]
    if not sources:
        counts = Counter(str(alert.get("index", ["unknown"])[0]) for alert in alerts)
        sources = [{"name": name, "count": count} for name, count in counts.most_common()]

    return {
        "meta": meta,
        "severity": severity_counts,
        "alerts": alerts,
        "correlations": correlations,
        "timeline": timeline,
        "hosts": hosts,
        "sources": sources,
        "coverage": coverage,
        "cases": cases,
        "pipeline": pipeline_payload(meta, alerts, correlations, cases, events),
    }


def build_html(payload: dict[str, Any], source: dict[str, str]) -> str:
    html = source["template"]
    data_json = json.dumps(payload, separators=(",", ":"), sort_keys=False).replace("</", "<\\/")
    favicon = "data:image/svg+xml," + quote(source["icon"], safe="")

    replacements = {
        "/*FONTS*/": source["fonts"],
        "/*STYLES*/": source["styles"],
        "/*SCRIPT*/": source["script"],
        "__DATA_JSON__": data_json,
        "__FAVICON__": favicon,
        "__ICON_SVG__": source["icon"],
    }
    for token, value in replacements.items():
        if token not in html:
            raise SystemExit(f"Dashboard template is missing the {token} placeholder")
        html = html.replace(token, value)
    return html


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the Umbra dashboard")
    parser.add_argument("--alerts", default=str(ALERTS_DIR / "alerts.json"))
    parser.add_argument("--rules", default=str(COMPILED_DIR / "rules.json"))
    parser.add_argument("--cases", default=str(CASES_DIR / "cases.json"))
    parser.add_argument("--out", default=str(DOCS_DIR / "index.html"))
    parser.add_argument("--open", action="store_true", help="open the report in a browser")
    args = parser.parse_args()

    source = load_dashboard_source()
    payload = build_payload(Path(args.alerts), Path(args.rules), Path(args.cases))
    html = build_html(payload, source)

    out = Path(args.out)
    ensure_dir(out.parent)
    out.write_text(html, encoding="utf-8")

    assets = ensure_dir(out.parent / "assets")
    (assets / "icon.svg").write_text(source["icon"], encoding="utf-8")
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

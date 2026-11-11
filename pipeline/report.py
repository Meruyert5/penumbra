"""Render the detection run as a self-contained interactive HTML dashboard.

Run with:  python -m pipeline.report
Writes docs/index.html, which works offline, from file://, and on GitHub Pages.
"""

from __future__ import annotations

import argparse
import json
import sys
import webbrowser
from collections import Counter
from pathlib import Path
from typing import Any

from pipeline.common import ALERTS_DIR, COMPILED_DIR, DOCS_DIR, TACTIC_ORDER, ensure_dir
from pipeline.coverage import PRIORITY_TECHNIQUES, TACTIC_LABEL, coverage_tiles

LEVELS = ["critical", "high", "medium", "low"]

HTML_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Detection Forge — detection run</title>
<style>
:root{
  --bg:#080c11; --panel:#0e151e; --panel-2:#121b26; --border:#1c2836;
  --text:#e6edf3; --muted:#8b9aab; --accent:#7ee787;
  --critical:#ff5d5d; --high:#ff9f43; --medium:#ffd166; --low:#4cc9f0;
  --mono:ui-monospace,SFMono-Regular,Consolas,"Liberation Mono",monospace;
}
*{box-sizing:border-box}
body{margin:0;background:radial-gradient(1200px 600px at 20% -10%,#12202e 0%,var(--bg) 55%);
  color:var(--text);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
.wrap{max-width:1240px;margin:0 auto;padding:32px 24px 64px}
header{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;flex-wrap:wrap;margin-bottom:28px}
.brand{display:flex;gap:16px;align-items:center}
.mark{width:52px;height:52px;border-radius:14px;display:grid;place-items:center;
  background:linear-gradient(145deg,#16324a,#0d1a26);border:1px solid #24405c;
  color:var(--accent);font:700 18px/1 var(--mono);letter-spacing:.5px}
h1{margin:0;font-size:26px;letter-spacing:-.3px}
.tag{margin:2px 0 0;color:var(--muted);font-size:13px}
.runmeta{text-align:right;font:12px/1.7 var(--mono);color:var(--muted)}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;border:1px solid var(--border);
  background:var(--panel-2);font:11px/1.6 var(--mono);color:var(--muted)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:24px}
.kpi{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:14px 16px}
.kpi .n{font:700 26px/1.1 var(--mono);letter-spacing:-1px}
.kpi .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.8px;margin-top:4px}
.kpi.crit .n{color:var(--critical)}
.controls{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-bottom:22px;
  padding:12px;background:var(--panel);border:1px solid var(--border);border-radius:12px}
.chip{cursor:pointer;border:1px solid var(--border);background:var(--panel-2);color:var(--muted);
  border-radius:999px;padding:6px 13px;font:12px/1 var(--mono);transition:.15s}
.chip:hover{color:var(--text);border-color:#2c3d51}
.chip.active{color:#08110a;background:var(--accent);border-color:var(--accent);font-weight:700}
.chip[data-level="critical"].active{background:var(--critical);border-color:var(--critical);color:#1a0505}
.chip[data-level="high"].active{background:var(--high);border-color:var(--high);color:#1a0d00}
.chip[data-level="medium"].active{background:var(--medium);border-color:var(--medium);color:#1a1400}
.chip[data-level="low"].active{background:var(--low);border-color:var(--low);color:#001219}
.spacer{flex:1}
select,input{background:var(--panel-2);border:1px solid var(--border);color:var(--text);
  border-radius:8px;padding:8px 10px;font:13px var(--mono);outline:none}
input:focus,select:focus{border-color:#33506d}
.grid{display:grid;grid-template-columns:minmax(0,1.65fr) minmax(300px,.95fr);gap:20px;align-items:start}
@media(max-width:980px){.grid{grid-template-columns:1fr}}
h2{font-size:13px;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted);margin:0 0 12px}
.card{background:var(--panel);border:1px solid var(--border);border-left:3px solid var(--border);
  border-radius:12px;padding:16px 18px;margin-bottom:12px;transition:.15s}
.card:hover{border-color:#2a3b4f}
.card.critical{border-left-color:var(--critical)}
.card.high{border-left-color:var(--high)}
.card.medium{border-left-color:var(--medium)}
.card.low{border-left-color:var(--low)}
.card .top{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}
.card h3{margin:0;font-size:15.5px;font-weight:600}
.lvl{font:700 10px/1 var(--mono);text-transform:uppercase;letter-spacing:.9px;padding:5px 8px;border-radius:6px;white-space:nowrap}
.lvl.critical{background:rgba(255,93,93,.14);color:var(--critical);border:1px solid rgba(255,93,93,.35)}
.lvl.high{background:rgba(255,159,67,.14);color:var(--high);border:1px solid rgba(255,159,67,.35)}
.lvl.medium{background:rgba(255,209,102,.13);color:var(--medium);border:1px solid rgba(255,209,102,.32)}
.lvl.low{background:rgba(76,201,240,.13);color:var(--low);border:1px solid rgba(76,201,240,.32)}
.meta{display:flex;gap:14px;flex-wrap:wrap;color:var(--muted);font:12px/1.6 var(--mono);margin-top:8px}
.tech{display:inline-block;margin-top:10px;margin-right:6px;padding:3px 8px;border-radius:6px;
  background:#101c28;border:1px solid #1f3143;color:#9fd0ff;font:11px/1.4 var(--mono)}
details{margin-top:12px;border-top:1px solid var(--border);padding-top:10px}
summary{cursor:pointer;color:var(--muted);font:12px var(--mono)}
summary:hover{color:var(--text)}
pre{background:#070b10;border:1px solid var(--border);border-radius:8px;padding:12px;
  overflow:auto;max-height:320px;font:11.5px/1.6 var(--mono);color:#b7c9da;margin:10px 0 0}
.panel{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:16px 18px;margin-bottom:20px}
.panel h3{margin:0 0 14px;font-size:13px;text-transform:uppercase;letter-spacing:1.2px;color:var(--muted)}
.seq{position:relative;margin-left:6px;padding-left:18px;border-left:1px solid var(--border)}
.seq .ev{position:relative;padding:0 0 16px}
.seq .ev:last-child{padding-bottom:0}
.seq .dot{position:absolute;left:-24px;top:4px;width:9px;height:9px;border-radius:50%;background:var(--border);
  box-shadow:0 0 0 3px var(--panel)}
.seq .dot.critical{background:var(--critical)}.seq .dot.high{background:var(--high)}
.seq .dot.medium{background:var(--medium)}.seq .dot.low{background:var(--low)}
.seq .t{font:11px var(--mono);color:var(--muted)}
.seq .d{font-size:13px;margin-top:2px}
.donut{display:flex;align-items:center;gap:16px}
.donut .cap{font-size:12px;color:var(--muted);line-height:1.5}
.donut .cap b{color:var(--text);font:700 20px/1.2 var(--mono);display:block}
.hosts{list-style:none;margin:0;padding:0;font:12px var(--mono)}
.hosts li{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px dashed var(--border);color:var(--muted)}
.hosts li:last-child{border-bottom:0}
.hosts b{color:var(--text)}
.heat{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}
.tac{background:var(--panel-2);border:1px solid var(--border);border-radius:10px;padding:10px}
.tac .name{font:10px/1.4 var(--mono);text-transform:uppercase;letter-spacing:.7px;color:var(--muted);margin-bottom:8px}
.tile{display:block;width:100%;text-align:left;cursor:pointer;border-radius:6px;padding:5px 7px;margin-bottom:5px;
  border:1px solid transparent;font:10.5px/1.35 var(--mono);transition:.12s;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.tile.covered{background:#12251a;border-color:#1f4630;color:#bdf5c8}
.tile.covered.high{background:#2a1c10;border-color:#5a3a1c;color:#ffd2a8}
.tile.covered.critical{background:#2b1214;border-color:#5c2427;color:#ffb9b9}
.tile.covered.medium{background:#2a2410;border-color:#5a4c1c;color:#ffe9ad}
.tile.covered.low{background:#0f2430;border-color:#1d4457;color:#b6e9fa}
.tile.gap{background:transparent;border:1px dashed #26313d;color:#5f6f7f}
.tile:hover{border-color:var(--accent);color:#fff}
.tile .id{opacity:.65;margin-right:5px}
footer{margin-top:36px;padding-top:18px;border-top:1px solid var(--border);color:var(--muted);font:12px/1.8 var(--mono)}
footer code{color:#b7c9da}
.empty{color:var(--muted);font:13px var(--mono);padding:24px;text-align:center;border:1px dashed var(--border);border-radius:12px}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand">
      <div class="mark">DF</div>
      <div>
        <h1>Detection Forge</h1>
        <p class="tag">Detection-as-code run · Sigma &rarr; EQL &rarr; triage</p>
      </div>
    </div>
    <div class="runmeta">
      <div><span class="pill">window __WINDOW__h</span> <span class="pill">__EVENTS__ events</span></div>
      <div>generated __GENERATED__</div>
    </div>
  </header>

  <section class="kpis">
    <div class="kpi crit"><div class="n">__N_CRIT__</div><div class="l">critical</div></div>
    <div class="kpi"><div class="n">__N_MATCHES__</div><div class="l">rule matches</div></div>
    <div class="kpi"><div class="n">__N_CORR__</div><div class="l">correlations</div></div>
    <div class="kpi"><div class="n">__N_TECH__</div><div class="l">techniques</div></div>
    <div class="kpi"><div class="n">__N_TACTICS__</div><div class="l">tactics</div></div>
  </section>

  <section class="controls">
    <button class="chip active" data-level="all">All __N_MATCHES__</button>
    <button class="chip" data-level="critical">Critical __C_CRIT__</button>
    <button class="chip" data-level="high">High __C_HIGH__</button>
    <button class="chip" data-level="medium">Medium __C_MED__</button>
    <button class="chip" data-level="low">Low __C_LOW__</button>
    <div class="spacer"></div>
    <select id="host"><option value="all">all hosts</option>__HOST_OPTIONS__</select>
    <input id="q" type="search" placeholder="search title, technique, host  ( / )" size="32">
  </section>

  <main class="grid">
    <section>
      <h2>Detections</h2>
      <div id="alerts"></div>
      <h2 style="margin-top:26px">Correlation alerts</h2>
      <div id="correlations"></div>
    </section>

    <aside>
      <div class="panel">
        <h3>Attack sequence · __FOCUS_HOST__</h3>
        <div class="seq">__SEQUENCE__</div>
      </div>
      <div class="panel">
        <h3>Priority coverage</h3>
        <div class="donut">
          __DONUT__
          <div class="cap"><b>__COVERED__/__PRIORITY__</b>priority techniques covered<br>__GAP_COUNT__ documented gaps</div>
        </div>
      </div>
      <div class="panel">
        <h3>Events by host</h3>
        <ul class="hosts">__HOSTS__</ul>
      </div>
    </aside>
  </main>

  <section class="panel" style="margin-top:8px">
    <h3>MITRE ATT&amp;CK coverage</h3>
    <div class="heat">__HEATMAP__</div>
  </section>

  <footer>
    Reproduce: <code>python -m pipeline.labgen --scenario all</code> &rarr;
    <code>python -m pipeline.ingest --reset</code> &rarr;
    <code>python -m pipeline.detect</code> &rarr;
    <code>python -m pipeline.report</code><br>
    Rules are Sigma in <code>rules/sigma/</code>. Evidence in this report is synthetic lab telemetry.
  </footer>
</div>

<script>
const DATA = __DATA_JSON__;
const state = { level: "all", host: "all", q: "" };

const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (c) => (
  { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]
));
const clock = (value) => String(value || "").slice(11, 19);

function evidence(alert) {
  const events = (alert.events || []).slice(0, 3);
  return `<details>
    <summary>evidence &amp; detection query</summary>
    <pre>${esc(JSON.stringify(events, null, 2))}</pre>
    <pre>${esc(alert.query || "")}</pre>
  </details>`;
}

function alertCard(alert) {
  const tech = (alert.techniques || []).map((t) => `<span class="tech">${esc(t)}</span>`).join("");
  return `<article class="card ${esc(alert.level)}" data-level="${esc(alert.level)}"
      data-host="${esc(alert.host)}" data-text="${esc((alert.title + " " + (alert.techniques || []).join(" ")).toLowerCase())}">
    <div class="top">
      <h3>${esc(alert.title)}</h3>
      <span class="lvl ${esc(alert.level)}">${esc(alert.level)}</span>
    </div>
    <div class="meta">
      <span>host: ${esc(alert.host)}</span>
      <span>matches: ${esc(alert.count)}</span>
      <span>${esc(clock(alert.first_seen))}Z &rarr; ${esc(clock(alert.last_seen))}Z</span>
    </div>
    <div>${tech}</div>
    ${evidence(alert)}
  </article>`;
}

function corrCard(corr) {
  return `<article class="card ${esc(corr.level)}" data-level="${esc(corr.level)}"
      data-host="${esc(corr.group_value)}" data-text="${esc((corr.title + " " + corr.technique).toLowerCase())}">
    <div class="top">
      <h3>${esc(corr.title)}</h3>
      <span class="lvl ${esc(corr.level)}">${esc(corr.level)}</span>
    </div>
    <div class="meta">
      <span>${esc(corr.group_by)}: ${esc(corr.group_value)}</span>
      <span>${esc(corr.count)}/${esc(corr.threshold)} in ${esc(corr.window_seconds)}s</span>
      <span>${esc(corr.first_seen).slice(11, 19)}Z &rarr; ${esc(corr.last_seen).slice(11, 19)}Z</span>
    </div>
    <div><span class="tech">${esc(corr.technique)}</span></div>
  </article>`;
}

function render() {
  const alerts = DATA.alerts.filter((alert) => {
    if (state.level !== "all" && alert.level !== state.level) return false;
    if (state.host !== "all" && !String(alert.host).includes(state.host)) return false;
    if (state.q) {
      const hay = (alert.title + " " + (alert.techniques || []).join(" ") + " " + alert.host).toLowerCase();
      if (!hay.includes(state.q)) return false;
    }
    return true;
  });
  const corrs = DATA.correlations.filter((corr) => state.level === "all" || corr.level === state.level);

  document.getElementById("alerts").innerHTML = alerts.length
    ? alerts.map(alertCard).join("")
    : '<div class="empty">no detections match this filter</div>';
  document.getElementById("correlations").innerHTML = corrs.length
    ? corrs.map(corrCard).join("")
    : '<div class="empty">no correlation alerts match this filter</div>';
}

document.querySelectorAll(".chip").forEach((chip) => {
  chip.addEventListener("click", () => {
    document.querySelectorAll(".chip").forEach((c) => c.classList.remove("active"));
    chip.classList.add("active");
    state.level = chip.dataset.level;
    render();
  });
});

document.getElementById("host").addEventListener("change", (event) => {
  state.host = event.target.value;
  render();
});

document.getElementById("q").addEventListener("input", (event) => {
  state.q = event.target.value.toLowerCase().trim();
  render();
});

document.addEventListener("keydown", (event) => {
  if (event.key === "/" && document.activeElement !== document.getElementById("q")) {
    event.preventDefault();
    document.getElementById("q").focus();
  }
});

document.querySelectorAll(".tile").forEach((tile) => {
  tile.addEventListener("click", () => {
    const technique = tile.dataset.tech;
    if (!technique) return;
    document.getElementById("q").value = technique;
    state.q = technique.toLowerCase();
    render();
    document.getElementById("alerts").scrollIntoView({ behavior: "smooth", block: "start" });
  });
});

render();
</script>
</body>
</html>
"""


def _donut(covered: int, total: int) -> str:
    radius = 34
    circumference = 2 * 3.14159 * radius
    filled = circumference * (covered / total if total else 0)
    return (
        f'<svg width="92" height="92" viewBox="0 0 92 92" role="img" aria-label="coverage">'
        f'<circle cx="46" cy="46" r="{radius}" fill="none" stroke="#1c2836" stroke-width="9"/>'
        f'<circle cx="46" cy="46" r="{radius}" fill="none" stroke="#7ee787" stroke-width="9"'
        f' stroke-linecap="round" stroke-dasharray="{filled:.1f} {circumference:.1f}"'
        f' transform="rotate(-90 46 46)"/>'
        f'<text x="46" y="51" text-anchor="middle" fill="#e6edf3" font-size="16"'
        f' font-family="ui-monospace,monospace">{covered}</text></svg>'
    )


def _sequence(alerts: list[dict[str, Any]]) -> tuple[str, str, list[tuple[str, int]]]:
    host_counts: Counter[str] = Counter()
    host_rules: dict[str, set[str]] = {}
    for alert in alerts:
        for event in alert.get("events") or []:
            host = (event.get("host") or {}).get("name", "unknown")
            host_counts[host] += 1
            host_rules.setdefault(host, set()).add(alert["rule_id"])
    if not host_counts:
        return "no events", "—", []

    # Prefer the host with the most distinct detections: that is the incident,
    # not the host with the noisiest single rule.
    focus = max(host_rules, key=lambda host: (len(host_rules[host]), host_counts[host]))
    events: list[tuple[str, str, str, str]] = []
    for alert in alerts:
        for event in alert.get("events") or []:
            if (event.get("host") or {}).get("name") == focus:
                events.append(
                    (
                        str(event.get("@timestamp", "")),
                        alert["level"],
                        alert["title"],
                        (alert.get("techniques") or ["-"])[0],
                    )
                )
    events.sort(key=lambda item: item[0])

    rows = []
    for timestamp, level, title, technique in events:
        clock = timestamp[11:19] if len(timestamp) >= 19 else timestamp
        rows.append(
            f'<div class="ev"><span class="dot {level}"></span>'
            f'<div class="t">{clock}Z · {technique}</div>'
            f'<div class="d">{title}</div></div>'
        )
    return "".join(rows), focus, [(host, count) for host, count in host_counts.most_common()]


def _heatmap(compiled: list[dict[str, Any]]) -> str:
    tiles_by_tactic, _covered = coverage_tiles(compiled)

    blocks = []
    for tactic in TACTIC_ORDER:
        if tactic not in tiles_by_tactic:
            continue
        tiles = []
        for technique, meta in sorted(tiles_by_tactic[tactic].items()):
            if meta["level"] is None:
                tiles.append(
                    f'<button class="tile gap" data-tech="{technique}" '
                    f'title="{technique} · {meta["name"]} (not covered)">'
                    f'<span class="id">{technique}</span>{meta["name"]}</button>'
                )
            else:
                tiles.append(
                    f'<button class="tile covered {meta["level"]}" data-tech="{technique}" '
                    f'title="{technique} · {meta["title"]} ({meta["level"]})">'
                    f'<span class="id">{technique}</span>{meta["name"]}</button>'
                )
        blocks.append(
            f'<div class="tac"><div class="name">{TACTIC_LABEL.get(tactic, tactic)}</div>'
            f'{"".join(tiles)}</div>'
        )
    return "".join(blocks)


def build_html(payload: dict[str, Any]) -> str:
    alerts = payload["alerts"]
    correlations = payload["correlations"]
    compiled = payload["compiled"]
    meta = payload["meta"]

    counts = Counter(alert["level"] for alert in alerts)
    covered_priority = sum(1 for technique in PRIORITY_TECHNIQUES if technique in payload["covered"])
    total_priority = len(PRIORITY_TECHNIQUES)

    hosts = sorted({host for host, _count in payload["host_counts"]})
    host_options = "".join(f'<option value="{host}">{host}</option>' for host in hosts)
    host_list = "".join(
        f"<li><span>{host}</span><b>{count}</b></li>" for host, count in payload["host_counts"]
    )

    html = HTML_TEMPLATE
    replacements = {
        "__WINDOW__": str(meta.get("window_hours", 24)),
        "__EVENTS__": str(meta.get("events_indexed") or "—"),
        "__GENERATED__": str(meta.get("generated", ""))[:19].replace("T", " "),
        "__N_CRIT__": str(counts.get("critical", 0)),
        "__N_MATCHES__": str(len(alerts)),
        "__N_CORR__": str(len(correlations)),
        "__N_TECH__": str(len(payload["covered"])),
        "__N_TACTICS__": str(len(payload["tactics"])),
        "__C_CRIT__": str(counts.get("critical", 0)),
        "__C_HIGH__": str(counts.get("high", 0)),
        "__C_MED__": str(counts.get("medium", 0)),
        "__C_LOW__": str(counts.get("low", 0)),
        "__HOST_OPTIONS__": host_options,
        "__SEQUENCE__": payload["sequence_html"],
        "__FOCUS_HOST__": payload["focus_host"],
        "__DONUT__": _donut(covered_priority, total_priority),
        "__COVERED__": str(covered_priority),
        "__PRIORITY__": str(total_priority),
        "__GAP_COUNT__": str(total_priority - covered_priority),
        "__HOSTS__": host_list,
        "__HEATMAP__": _heatmap(compiled),
        "__DATA_JSON__": json.dumps(
            {"alerts": alerts, "correlations": correlations}, sort_keys=False
        ).replace("</", "<\\/"),
    }
    for token, value in replacements.items():
        html = html.replace(token, value)
    return html


def build_payload(alerts_path: Path, rules_path: Path) -> dict[str, Any]:
    if not alerts_path.exists():
        raise SystemExit(f"{alerts_path} not found. Run: python -m pipeline.detect")
    document = json.loads(alerts_path.read_text(encoding="utf-8"))
    compiled = json.loads(rules_path.read_text(encoding="utf-8"))

    alerts = document.get("alerts", [])
    correlations = document.get("correlations", [])
    meta = document.get("meta", {})

    sequence_html, focus_host, host_counts = _sequence(alerts)
    covered = {technique for rule in compiled for technique in rule["techniques"]}
    tactics = {tactic for rule in compiled for tactic in rule["tactics"]}

    return {
        "alerts": alerts,
        "correlations": correlations,
        "compiled": compiled,
        "meta": meta,
        "sequence_html": sequence_html,
        "focus_host": focus_host,
        "host_counts": host_counts,
        "covered": covered,
        "tactics": tactics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Render the interactive detection dashboard")
    parser.add_argument("--alerts", default=str(ALERTS_DIR / "alerts.json"))
    parser.add_argument("--rules", default=str(COMPILED_DIR / "rules.json"))
    parser.add_argument("--out", default=str(DOCS_DIR / "index.html"))
    parser.add_argument("--open", action="store_true", help="open the report in a browser")
    args = parser.parse_args()

    payload = build_payload(Path(args.alerts), Path(args.rules))
    html = build_html(payload)

    out = Path(args.out)
    ensure_dir(out.parent)
    out.write_text(html, encoding="utf-8")
    print(f"Wrote {out} ({len(html) // 1024} KB, {len(payload['alerts'])} detections)")

    if args.open:
        webbrowser.open(out.resolve().as_uri())
    return 0


if __name__ == "__main__":
    sys.exit(main())

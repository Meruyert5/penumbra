(() => {
  "use strict";

  const DATA = JSON.parse(document.getElementById("sf-data").textContent);
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const LEVELS = ["critical", "high", "medium", "low"];
  const RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const state = { level: "all", host: "all", q: "", sort: "severity", tab: "detections", gaps: false, tour: -1 };

  document.documentElement.classList.add("js");

  const esc = (value) => String(value == null ? "" : value).replace(/[&<>"']/g, (char) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]
  ));
  const clock = (value) => String(value || "").slice(11, 19);
  const dayHour = (value) => {
    const text = String(value || "");
    return text.length >= 16 ? text.slice(5, 10) + " " + text.slice(11, 16) : text;
  };
  const number = (value) => Number(value || 0).toLocaleString("en-US");
  const percent = (value, total) => (total ? Math.round((value / total) * 100) : 0);

  /* ------------------------------------------------------------------ theme */
  const themeLabel = $("#themeLabel");
  function setTheme(theme) {
    document.documentElement.dataset.theme = theme;
    themeLabel.textContent = theme === "dark" ? "Light" : "Dark";
    try { localStorage.setItem("sf-theme", theme); } catch (error) { /* file:// storage can be blocked */ }
  }
  let savedTheme = "dark";
  try { savedTheme = localStorage.getItem("sf-theme") || "dark"; } catch (error) { savedTheme = "dark"; }
  setTheme(savedTheme);
  $("#themeBtn").addEventListener("click", () => {
    setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
  });

  /* ------------------------------------------------------------------ toast */
  let toastTimer = 0;
  function toast(message) {
    const node = $("#toast");
    node.textContent = message;
    node.classList.add("on");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => node.classList.remove("on"), 1900);
  }

  /* --------------------------------------------------------------- counters */
  function animateNumber(node, target, suffix) {
    const end = Number(target || 0);
    if (Number.isNaN(end)) { node.textContent = String(target || 0); return; }
    if (reduce) { node.textContent = number(end) + (suffix || ""); return; }
    const start = performance.now();
    const duration = 1100;
    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      node.textContent = number(Math.round(end * eased)) + (suffix || "");
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  function animateCounters(root) {
    $$("[data-count]", root).forEach((node) => {
      if (node.dataset.done) return;
      node.dataset.done = "1";
      animateNumber(node, node.dataset.count, node.dataset.suffix || "");
    });
  }

  /* ---------------------------------------------------------------- reveal */
  const revealObserver = "IntersectionObserver" in window
    ? new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          entry.target.classList.add("in");
          animateCounters(entry.target);
          revealObserver.unobserve(entry.target);
        });
      }, { threshold: 0.12, rootMargin: "0px 0px -8% 0px" })
    : null;

  function observeReveals() {
    $$("[data-reveal]").forEach((node) => {
      if (reduce || !revealObserver) { node.classList.add("in"); animateCounters(node); return; }
      revealObserver.observe(node);
    });
  }

  /* ------------------------------------------------------------------- meta */
  const meta = DATA.meta || {};
  const severity = DATA.severity || { critical: 0, high: 0, medium: 0, low: 0 };
  const totalAlerts = Object.values(severity).reduce((sum, value) => sum + value, 0);

  const runAt = meta.window_end || meta.generated;
  $("#railGenerated").textContent = runAt ? dayHour(runAt) + "Z" : "unknown";
  $("#railWindow").textContent = (meta.window_hours || 24) + " hours";
  $("#railEvents").textContent = number(meta.events_indexed || 0) + " events";
  $("#railRules").textContent = number(meta.sigma_rules || 0) + " Sigma rules";
  $("#railCorr").textContent = number(meta.correlation_specs || 0) + " specs";
  $("#railErrors").textContent = (meta.errors && meta.errors.length ? meta.errors.length : 0) + " execution errors";
  $("#footerGenerated").textContent = "generated " + (meta.generated ? meta.generated.slice(0, 19).replace("T", " ") + "Z" : "");

  const kpis = [
    { value: severity.critical || 0, label: "Critical alerts", sub: (severity.high || 0) + " high behind them", fill: 1 },
    { value: meta.sigma_rules || 0, label: "Sigma rules", sub: "compiled to EQL and KQL", fill: 0.92 },
    { value: meta.correlation_specs || 0, label: "Correlations", sub: "threshold and distinct-value", fill: 0.64 },
    { value: meta.events_indexed || 0, label: "Telemetry events", sub: "five data sources", fill: 1 },
    { value: meta.scenarios || 0, label: "ATT&CK scenarios", sub: "deterministic, seeded", fill: 0.78 },
    { value: (meta.covered_priority || 0) + "/" + (meta.priority_techniques || 0), label: "Priority coverage", sub: (meta.gaps || 0) + " documented gaps", fill: percent(meta.covered_priority || 0, meta.priority_techniques || 1) / 100 }
  ];
  $("#kpis").innerHTML = kpis.map((kpi) => (
    '<div class="kpi" style="--fill:' + kpi.fill + '%">' +
      '<span class="value" data-count="' + esc(kpi.value) + '">0</span>' +
      '<span class="label">' + esc(kpi.label) + "</span>" +
      '<span class="sub">' + esc(kpi.sub) + "</span>" +
    "</div>"
  )).join("");
  animateCounters($("#kpis"));

  /* ------------------------------------------------------------- run readout */
  const readout = [
    ["Rules evaluated", number(meta.rules_evaluated || 0)],
    ["Correlations evaluated", number(meta.correlations_evaluated || 0)],
    ["Detection matches", number(DATA.alerts.length)],
    ["Correlation alerts", number(DATA.correlations.length)],
    ["Techniques covered", number(meta.techniques || 0)],
    ["Tactics covered", number(meta.tactics || 0)],
    ["Execution errors", number((meta.errors || []).length)]
  ];
  $("#runReadout").innerHTML = readout.map(([label, value]) => (
    '<div class="readout-row"><span>' + esc(label) + "</span><b>" + esc(value) + "</b></div>"
  )).join("");

  const sources = (DATA.sources || []).slice(0, 7);
  $("#telemetryRows").innerHTML = sources.length
    ? sources.map((source) => (
        '<div class="readout-row"><span>' + esc(source.name) + "</span><b>" + number(source.count) + "</b></div>"
      )).join("")
    : '<div class="readout-row"><span>No matched telemetry</span><b>0</b></div>';

  /* ------------------------------------------------------------- scope chart */
  const chart = $("#scopeChart");
  const NS = "http://www.w3.org/2000/svg";
  function svgNode(name, attrs) {
    const node = document.createElementNS(NS, name);
    Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, value));
    return node;
  }

  function buildScope() {
    const timeline = (DATA.timeline || []).filter((row) => row && row.hour);
    chart.innerHTML = "";
    const width = Math.max(280, Math.round(chart.getBoundingClientRect().width || 900));
    const height = width < 560 ? 320 : 400;
    chart.setAttribute("viewBox", "0 0 " + width + " " + height);
    if (!timeline.length) {
      chart.innerHTML = '<text x="' + (width / 2) + '" y="' + (height / 2) + '" text-anchor="middle" fill="var(--muted)" font-family="var(--mono)" font-size="12">No alert volume in this window</text>';
      $("#scopeHint").textContent = "no data";
      return;
    }

    const left = width < 560 ? 34 : 38;
    const right = 14;
    const top = 16;
    const bottom = 34;
    const plotW = width - left - right;
    const plotH = height - top - bottom;
    const totals = timeline.map((row) => Number(row.total || 0));
    const max = Math.max(1, ...totals);
    const step = timeline.length > 1 ? plotW / (timeline.length - 1) : 0;
    const x = (index) => left + index * step;
    const y = (value) => top + (1 - value / max) * plotH;

    const defs = svgNode("defs");
    const gradient = svgNode("linearGradient", { id: "scopeFill", x1: "0", y1: "0", x2: "0", y2: "1" });
    gradient.appendChild(svgNode("stop", { offset: "0", "stop-color": "var(--teal)", "stop-opacity": "0.42" }));
    gradient.appendChild(svgNode("stop", { offset: "1", "stop-color": "var(--teal)", "stop-opacity": "0.02" }));
    defs.appendChild(gradient);
    chart.appendChild(defs);

    const axis = svgNode("g", { class: "axis" });
    [0, 0.25, 0.5, 0.75, 1].forEach((ratio) => {
      const value = Math.round(max * ratio);
      const lineY = y(value);
      axis.appendChild(svgNode("line", { class: "gridline", x1: left, y1: lineY, x2: width - right, y2: lineY }));
      axis.appendChild(svgNode("text", { x: left - 8, y: lineY + 3, "text-anchor": "end" })).textContent = String(value);
    });
    chart.appendChild(axis);

    const linePoints = timeline.map((row, index) => [x(index), y(Number(row.total || 0))]);
    const linePath = linePoints.map((point, index) => (index ? "L" : "M") + point[0].toFixed(1) + " " + point[1].toFixed(1)).join(" ");
    const areaPath = linePath + " L" + x(timeline.length - 1).toFixed(1) + " " + (height - bottom) + " L" + left + " " + (height - bottom) + " Z";

    chart.appendChild(svgNode("path", { class: "scope-area", d: areaPath }));
    const line = svgNode("path", { class: "scope-line", d: linePath });
    chart.appendChild(line);
    const length = line.getTotalLength ? line.getTotalLength() : 0;
    if (length && !reduce) {
      line.style.strokeDasharray = String(length);
      line.style.strokeDashoffset = String(length);
      requestAnimationFrame(() => {
        line.style.transition = "stroke-dashoffset 1.6s cubic-bezier(0.16,1,0.3,1)";
        line.style.strokeDashoffset = "0";
      });
    }

    timeline.forEach((row, index) => {
      const dominant = LEVELS.find((level) => Number(row[level] || 0) > 0) || "low";
      const point = svgNode("circle", {
        class: "scope-point " + dominant,
        cx: x(index).toFixed(1),
        cy: y(Number(row.total || 0)).toFixed(1),
        r: index === timeline.length - 1 ? 4.5 : 3.2
      });
      const title = svgNode("title");
      title.textContent = row.hour + " · " + number(row.total) + " alerts · critical " + number(row.critical) + " · high " + number(row.high);
      point.appendChild(title);
      point.addEventListener("mouseenter", () => {
        $("#scopeHint").textContent = row.hour.slice(5, 13).replace("T", " ") + "Z · " + number(row.total) + " alerts";
      });
      chart.appendChild(point);
    });

    chart.appendChild(svgNode("line", {
      class: "scanline",
      x1: left,
      y1: top,
      x2: left,
      y2: height - bottom
    }));

    const labels = svgNode("g", { class: "axis" });
    const tickIndexes = timeline.length <= 6
      ? timeline.map((_, index) => index)
      : [0, Math.floor((timeline.length - 1) / 2), timeline.length - 1];
    tickIndexes.forEach((index) => {
      const label = svgNode("text", { x: x(index), y: height - 12, "text-anchor": index === 0 ? "start" : index === timeline.length - 1 ? "end" : "middle" });
      label.textContent = dayHour(timeline[index].hour).slice(6);
      labels.appendChild(label);
    });
    chart.appendChild(labels);

    $("#scopeHint").textContent = timeline.length + " hourly buckets · peak " + number(max);
  }
  buildScope();

  let scopeWidth = chart.getBoundingClientRect().width || 0;
  let scopeResize = 0;
  window.addEventListener("resize", () => {
    window.clearTimeout(scopeResize);
    scopeResize = window.setTimeout(() => {
      const next = chart.getBoundingClientRect().width || 0;
      if (Math.abs(next - scopeWidth) > 24) {
        scopeWidth = next;
        buildScope();
      }
    }, 180);
  });

  /* ---------------------------------------------------------------- pipeline */
  const pipeline = DATA.pipeline || [];
  $("#pipelineGrid").innerHTML = pipeline.map((step, index) => (
    '<div class="pipe-step">' +
      '<span class="n">' + String(index + 1).padStart(2, "0") + " · " + esc(step.label) + "</span>" +
      '<span class="count">' + esc(step.count) + "</span>" +
      "<h3>" + esc(step.title) + "</h3>" +
      "<p>" + esc(step.detail) + "</p>" +
    "</div>"
  )).join("");

  /* ------------------------------------------------------------------ ledger */
  const detections = (DATA.alerts || []).map((alert) => ({
    kind: "detection",
    id: alert.rule_id,
    title: alert.title,
    level: alert.level,
    techniques: alert.techniques || [],
    tactics: alert.tactics || [],
    hosts: alert.hosts || [],
    host: alert.host || "",
    count: alert.count || 0,
    first_seen: alert.first_seen,
    last_seen: alert.last_seen,
    index: (alert.index || []).join(", "),
    query: alert.query || "",
    query_kql: alert.query_kql || "",
    events: alert.events || [],
    description: ""
  }));
  const correlations = (DATA.correlations || []).map((corr) => ({
    kind: "correlation",
    id: corr.correlation_id,
    title: corr.title,
    level: corr.level,
    techniques: corr.technique ? [corr.technique] : [],
    tactics: corr.tags || [],
    hosts: [corr.group_value],
    host: corr.group_by + " = " + corr.group_value,
    count: corr.count || 0,
    first_seen: corr.first_seen,
    last_seen: corr.last_seen,
    index: corr.index || "",
    query: "",
    query_kql: "",
    events: [],
    description: corr.description || "",
    threshold: corr.threshold,
    distinct_by: corr.distinct_by,
    distinct_count: corr.distinct_count,
    distinct_threshold: corr.distinct_threshold,
    window_seconds: corr.window_seconds,
    group_by: corr.group_by,
    group_value: corr.group_value
  }));

  const hosts = new Set();
  detections.forEach((alert) => (alert.hosts || []).forEach((host) => hosts.add(host)));
  correlations.forEach((corr) => (corr.hosts || []).forEach((host) => hosts.add(host)));
  $("#hostFilter").innerHTML = '<option value="all">all hosts</option>' +
    Array.from(hosts).sort().map((host) => '<option value="' + esc(host) + '">' + esc(host) + "</option>").join("");

  $("#tabDetectionsN").textContent = detections.length;
  $("#tabCorrelationsN").textContent = correlations.length;

  function rows() {
    return state.tab === "detections" ? detections : correlations;
  }

  function filtered() {
    const query = state.q.toLowerCase();
    return rows().filter((row) => {
      if (state.level !== "all" && row.level !== state.level) return false;
      if (state.host !== "all" && !(row.hosts || []).some((host) => String(host).includes(state.host))) return false;
      if (query) {
        const haystack = [row.title, row.host, row.id, (row.techniques || []).join(" "), (row.tactics || []).join(" ")].join(" ").toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    }).sort((a, b) => {
      if (state.sort === "time") return String(b.last_seen || "").localeCompare(String(a.last_seen || ""));
      if (state.sort === "count") return b.count - a.count;
      return (RANK[b.level] || 0) - (RANK[a.level] || 0) || String(b.last_seen || "").localeCompare(String(a.last_seen || ""));
    });
  }

  function evidenceBlock(row) {
    if (row.kind === "correlation") {
      const lines = [
        "correlation: " + row.id,
        "group_by:   " + row.group_by + " = " + row.group_value,
        "window:     " + row.window_seconds + "s",
        "threshold:  " + row.count + " / " + row.threshold
      ];
      if (row.distinct_by) lines.push("distinct:   " + row.distinct_count + " " + row.distinct_by + " (minimum " + row.distinct_threshold + ")");
      lines.push("first_seen: " + row.first_seen, "last_seen:  " + row.last_seen, "index:      " + row.index);
      return (
        '<div class="evidence"><div class="evidence-inner">' +
          "<h4>Correlation detail</h4>" +
          '<pre>' + esc(lines.join("\n")) + "</pre>" +
          (row.description ? "<h4>Why it fired</h4><pre>" + esc(row.description) + "</pre>" : "") +
        "</div></div>"
      );
    }
    return (
      '<div class="evidence"><div class="evidence-inner">' +
        "<h4>Matching events · first 3</h4>" +
        '<pre>' + esc(JSON.stringify(row.events, null, 2)) + "</pre>" +
        "<h4>Compiled EQL</h4>" +
        '<pre>' + esc(row.query) + "</pre>" +
        "<h4>Kibana KQL</h4>" +
        '<pre>' + esc(row.query_kql || "not generated") + "</pre>" +
      "</div></div>"
    );
  }

  function alertMarkup(row, index) {
    const techs = (row.techniques || []).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const copyText = row.kind === "detection" ? row.query : (row.description || row.id);
    return (
      '<article class="alert" data-level="' + esc(row.level) + '" data-id="' + esc(row.id) + '" style="animation-delay:' + Math.min(index, 12) * 28 + 'ms">' +
        '<div class="rail"></div>' +
        '<div class="alert-main">' +
          '<div class="alert-top"><h3 class="alert-title">' + esc(row.title) + '</h3><span class="sev ' + esc(row.level) + '">' + esc(row.level) + "</span></div>" +
          '<div class="alert-meta">' +
            "<span>host <b>" + esc(row.host) + "</b></span>" +
            "<span>matches <b>" + number(row.count) + "</b></span>" +
            "<span>" + esc(clock(row.first_seen)) + "Z → " + esc(clock(row.last_seen)) + "Z</span>" +
            (row.index ? "<span>" + esc(row.index) + "</span>" : "") +
          "</div>" +
          (techs ? '<div class="techs">' + techs + "</div>" : "") +
          '<div class="alert-actions">' +
            '<button class="expand" type="button" aria-expanded="false" data-label="' + (row.kind === "detection" ? "evidence & query" : "correlation detail") + '">' + (row.kind === "detection" ? "evidence & query" : "correlation detail") + "</button>" +
            (copyText ? '<button class="copy" type="button" data-copy="' + esc(copyText) + '">copy ' + (row.kind === "detection" ? "EQL" : "detail") + "</button>" : "") +
          "</div>" +
          evidenceBlock(row) +
        "</div>" +
      "</article>"
    );
  }

  function renderLedger() {
    const result = filtered();
    $("#ledgerCount").textContent = result.length + " of " + rows().length + " rows";
    $("#ledgerBody").innerHTML = result.length
      ? result.map(alertMarkup).join("")
      : '<div class="empty">No ' + esc(state.tab) + " match this filter. Clear the search or pick another host.</div>";
  }

  function renderAll() {
    renderLedger();
    renderAside();
  }

  $$(".chip[data-level]").forEach((chip) => {
    chip.addEventListener("click", () => {
      $$(".chip[data-level]").forEach((item) => item.classList.remove("active"));
      chip.classList.add("active");
      state.level = chip.dataset.level;
      renderLedger();
    });
  });
  $("#hostFilter").addEventListener("change", (event) => { state.host = event.target.value; renderLedger(); });
  $("#sortFilter").addEventListener("change", (event) => { state.sort = event.target.value; renderLedger(); });
  $("#search").addEventListener("input", (event) => { state.q = event.target.value.trim(); renderLedger(); });
  $("#tabDetections").addEventListener("click", () => switchTab("detections"));
  $("#tabCorrelations").addEventListener("click", () => switchTab("correlations"));
  function switchTab(tab) {
    state.tab = tab;
    $("#tabDetections").classList.toggle("active", tab === "detections");
    $("#tabCorrelations").classList.toggle("active", tab === "correlations");
    $("#tabDetections").setAttribute("aria-selected", String(tab === "detections"));
    $("#tabCorrelations").setAttribute("aria-selected", String(tab === "correlations"));
    renderLedger();
  }

  $("#ledgerBody").addEventListener("click", (event) => {
    const button = event.target.closest(".expand");
    if (!button) return;
    const row = button.closest(".alert");
    const open = row.classList.toggle("open");
    button.setAttribute("aria-expanded", String(open));
    button.textContent = open ? "hide detail" : button.dataset.label;
  });

  /* ------------------------------------------------------------------- aside */
  function renderAside() {
    const total = detections.length;
    const radius = 52;
    const circumference = 2 * Math.PI * radius;
    let offset = 0;
    const segments = LEVELS.map((level) => {
      const count = detections.filter((row) => row.level === level).length;
      const length = total ? (count / total) * circumference : 0;
      const circle = '<circle cx="64" cy="64" r="' + radius + '" fill="none" stroke="var(--' + level + ')" stroke-width="12" stroke-dasharray="' + length.toFixed(2) + " " + (circumference - length).toFixed(2) + '" stroke-dashoffset="' + (-offset).toFixed(2) + '" stroke-linecap="butt"></circle>';
      offset += length;
      return { level, count, circle };
    });
    $("#donut").innerHTML = '<svg viewBox="0 0 128 128" aria-hidden="true"><circle cx="64" cy="64" r="' + radius + '" fill="none" stroke="var(--panel-3)" stroke-width="12"></circle>' + segments.map((segment) => segment.circle).join("") + "</svg>";
    $("#donutTotal").textContent = number(total);
    $("#donutLegend").innerHTML = segments.map((segment) => (
      '<div><span><i style="background:var(--' + segment.level + ')"></i>' + segment.level + "</span><b>" + number(segment.count) + "</b></div>"
    )).join("");

    const hostRows = (DATA.hosts || []).slice(0, 6);
    const maxHost = Math.max(1, ...hostRows.map((row) => row.count));
    $("#hostBars").innerHTML = hostRows.length
      ? hostRows.map((row) => (
          '<div class="bar-row"><div class="bar-label"><span>' + esc(row.name) + "</span><b>" + number(row.count) + '</b></div><div class="bar-track"><div class="bar-fill" data-width="' + percent(row.count, maxHost) + '"></div></div></div>'
        )).join("")
      : '<div class="bar-row"><div class="bar-label"><span>No host activity</span><b>0</b></div></div>';

    $("#sourceList").innerHTML = (DATA.sources || []).slice(0, 6).map((source) => (
      '<div class="source-row"><span>' + esc(source.name) + "</span><b>" + number(source.count) + "</b></div>"
    )).join("") || '<div class="source-row"><span>No matched sources</span><b>0</b></div>';

    const critical = detections.filter((row) => row.level === "critical");
    const topHost = hostRows[0];
    const note = critical.length
      ? "Start with <b>" + critical.length + " critical detection" + (critical.length === 1 ? "" : "s") + "</b>. " +
        (topHost ? "The busiest host is <b>" + esc(topHost.name) + "</b> with " + number(topHost.count) + " matched events. " : "") +
        "Correlations are grouped by source or host, so you can triage the cluster instead of each event."
      : "No critical detection fired. Work the high band first, then check the correlation tab for volume that single events miss.";
    $("#triageNote").innerHTML = note;

    requestAnimationFrame(() => {
      $$(".bar-fill").forEach((bar) => { bar.style.transform = "scaleX(" + (Number(bar.dataset.width) / 100) + ")"; });
    });
  }

  /* ---------------------------------------------------------------- coverage */
  const coverage = DATA.coverage || { tactics: [], priority: 0, covered: 0, gaps: [] };
  const coveragePct = percent(coverage.covered || 0, coverage.priority || 1);
  const coverageNumber = $("#coveragePct");
  coverageNumber.textContent = coveragePct + "%";
  if (!reduce) {
    coverageNumber.textContent = "0%";
    animateNumber({ set textContent(value) { coverageNumber.textContent = value; } }, coveragePct, "%");
  }
  $("#coverageSub").textContent = (coverage.covered || 0) + " of " + (coverage.priority || 0) + " priority techniques · " + (coverage.gaps || []).length + " documented gaps";

  function renderCoverage() {
    const tactics = coverage.tactics || [];
    $("#tacticBars").innerHTML = tactics.map((tactic) => {
      const tiles = tactic.tiles || [];
      const covered = tiles.filter((tile) => tile.level).length;
      const pct = percent(covered, tiles.length || 1);
      return (
        '<div class="tactic-bar"><div class="name">' + esc(tactic.label) + '</div><div class="num">' + covered + "/" + tiles.length + '</div><div class="track"><div class="fill" data-width="' + pct + '"></div></div></div>'
      );
    }).join("");

    const visible = tactics.map((tactic) => {
      const tiles = (tactic.tiles || []).filter((tile) => !state.gaps || !tile.level);
      return { ...tactic, tiles };
    }).filter((tactic) => tactic.tiles.length);

    $("#matrix").innerHTML = visible.length ? visible.map((tactic) => (
      '<div class="tactic"><h4>' + esc(tactic.label) + "</h4><div class=\"tiles\">" +
        tactic.tiles.map((tile, tileIndex) => {
          const level = tile.level || "gap";
          const label = tile.level ? tile.level : "gap";
          return '<button class="tile ' + (tile.level ? "covered " + esc(tile.level) : "gap") + '" type="button" data-tech="' + esc(tile.technique) + '" style="animation-delay:' + Math.min(tileIndex, 10) * 18 + 'ms" title="' + esc(tile.technique + " · " + tile.name + " · " + label) + '">' +
            '<span class="id">' + esc(tile.technique) + '</span><span class="nm">' + esc(tile.name) + "</span></button>";
        }).join("") +
      "</div></div>"
    )).join("") : '<div class="empty">No techniques match this view.</div>';

    requestAnimationFrame(() => {
      $$("#tacticBars .fill").forEach((bar) => { bar.style.transform = "scaleX(" + (Number(bar.dataset.width) / 100) + ")"; });
    });
  }
  renderCoverage();

  $("#gapsBtn").addEventListener("click", () => {
    state.gaps = !state.gaps;
    $("#gapsBtn").classList.toggle("active", state.gaps);
    $("#gapsBtn").textContent = state.gaps ? "show all techniques" : "show gaps only";
    renderCoverage();
  });

  $("#matrix").addEventListener("click", (event) => {
    const tile = event.target.closest(".tile");
    if (!tile) return;
    const technique = tile.dataset.tech;
    $("#search").value = technique;
    state.q = technique;
    switchTab("detections");
    renderLedger();
    $("#ledger").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    toast(technique + " filtered into the ledger");
  });

  /* ------------------------------------------------------------------- cases */
  const cases = DATA.cases || [];
  $("#caseGrid").innerHTML = cases.map((item) => {
    const techs = (item.techniques || []).slice(0, 4).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const extra = (item.techniques || []).length > 4 ? '<span class="tech">+' + ((item.techniques || []).length - 4) + "</span>" : "";
    return (
      '<article class="case" data-level="' + esc(item.severity) + '">' +
        '<div class="case-top"><span class="case-id">' + esc(item.id) + '</span><span class="case-status">' + esc(item.status) + "</span></div>" +
        "<h3>" + esc(item.title) + "</h3>" +
        "<p>" + esc(item.summary) + "</p>" +
        '<div class="techs">' + techs + extra + "</div>" +
        '<div class="case-foot"><span class="case-status">' + esc(item.verdict) + '</span><a href="' + esc(item.path) + '">read the case →</a></div>' +
      "</article>"
    );
  }).join("") || '<div class="empty">No case files committed yet.</div>';

  /* -------------------------------------------------------------------- copy */
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise((resolve, reject) => {
      const area = document.createElement("textarea");
      area.value = text;
      area.style.position = "fixed";
      area.style.opacity = "0";
      document.body.appendChild(area);
      area.select();
      try { document.execCommand("copy"); resolve(); } catch (error) { reject(error); }
      document.body.removeChild(area);
    });
  }
  document.addEventListener("click", (event) => {
    const button = event.target.closest("[data-copy]");
    if (!button) return;
    const original = button.dataset.original || button.textContent;
    button.dataset.original = original;
    copyText(button.dataset.copy).then(() => {
      window.clearTimeout(Number(button.dataset.timer || 0));
      button.textContent = "copied";
      button.classList.add("done");
      toast("copied");
      button.dataset.timer = String(window.setTimeout(() => {
        button.textContent = original;
        button.classList.remove("done");
      }, 1300));
    }).catch(() => toast("copy failed"));
  });

  /* -------------------------------------------------------------------- tour */
  const steps = [
    { target: "#overview", title: "A run you can inspect", body: "Signal Foundry is a detection-as-code pipeline. This page is the output of one deterministic run: 2,182 events, a 44-rule Sigma library, and eight correlation specs." },
    { target: "#scope .chart", title: "Read the signal", body: "The chart shows hourly alert volume. Peaks are attack scenarios. The quiet hours are the baseline, and they matter because a rule that fires on everything is not a detection." },
    { target: "#pipeline", title: "Follow the method", body: "Sigma compiles to Elasticsearch EQL and KQL. Detection executes the queries, correlation adds the volume logic, and triage turns matches into a queue with evidence." },
    { target: "#ledger .ledger", title: "Work the queue", body: "Filter by severity, host, or technique. Open a row for the matching events and the exact query. Switch to correlations to see what single events missed." },
    { target: "#coverage .matrix", title: "Check the gaps", body: "Coverage only counts priority techniques, and every gap stays visible. A dashed tile is the next rule to write, not a number hidden inside a percentage." },
    { target: "#cases .case-grid", title: "Read the investigations", body: "Each case follows the same structure: summary, timeline, evidence, analysis, verdict, containment, and the detection improvement that came out of it." },
    { target: "#reproduce .terminal", title: "Reproduce it", body: "Generation is seeded. The same commands produce the same events, the same alerts, and the same dashboard. Swap the logsource map when you connect real telemetry." }
  ];
  const spot = $("#tourSpot");
  const card = $("#tourCard");

  function updateSpot() {
    if (state.tour < 0) return;
    const target = $(steps[state.tour].target);
    if (!target) return;
    const rect = target.getBoundingClientRect();
    const pad = 10;
    spot.style.top = Math.max(8, rect.top - pad) + "px";
    spot.style.left = Math.max(8, rect.left - pad) + "px";
    spot.style.width = Math.min(window.innerWidth - 16, rect.width + pad * 2) + "px";
    spot.style.height = Math.min(window.innerHeight - 16, rect.height + pad * 2) + "px";
  }

  function goStep(index) {
    if (index < 0) index = 0;
    if (index >= steps.length) return endTour();
    state.tour = index;
    const step = steps[index];
    $("#tourStep").textContent = String(index + 1).padStart(2, "0") + " / " + String(steps.length).padStart(2, "0");
    $("#tourTitle").textContent = step.title;
    $("#tourBody").textContent = step.body;
    $("#tourDots").innerHTML = steps.map((_, dot) => '<i class="' + (dot === index ? "on" : "") + '"></i>').join("");
    $("#tourPrev").disabled = index === 0;
    $("#tourNext").textContent = index === steps.length - 1 ? "finish" : "next";
    const target = $(step.target);
    if (target) target.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
    window.setTimeout(updateSpot, reduce ? 30 : 420);
    spot.classList.add("on");
    card.classList.add("on");
    card.focus();
  }

  function startTour() {
    goStep(0);
    toast("walkthrough started");
  }
  function endTour() {
    state.tour = -1;
    spot.classList.remove("on");
    card.classList.remove("on");
  }
  $("#tourBtn").addEventListener("click", startTour);
  $("#heroTour").addEventListener("click", startTour);
  $("#tourNext").addEventListener("click", () => goStep(state.tour + 1));
  $("#tourPrev").addEventListener("click", () => goStep(state.tour - 1));
  $("#tourSkip").addEventListener("click", endTour);
  $("#tourClose").addEventListener("click", endTour);
  window.addEventListener("scroll", updateSpot, { passive: true });
  window.addEventListener("resize", updateSpot);

  /* ----------------------------------------------------------------- shortcuts */
  const keysModal = $("#keysModal");
  function openKeys() { keysModal.classList.add("on"); $("#keysClose").focus(); }
  function closeKeys() { keysModal.classList.remove("on"); }
  $("#keysBtn").addEventListener("click", openKeys);
  $("#keysClose").addEventListener("click", closeKeys);
  keysModal.addEventListener("click", (event) => { if (event.target === keysModal) closeKeys(); });

  document.addEventListener("keydown", (event) => {
    const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
    if (event.key === "Escape") { closeKeys(); endTour(); return; }
    if (typing) return;
    if (event.key === "/") { event.preventDefault(); $("#search").focus(); }
    else if (event.key.toLowerCase() === "t") setTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    else if (event.key.toLowerCase() === "g") startTour();
    else if (event.key === "?") openKeys();
  });

  /* ----------------------------------------------------------------- progress */
  const progressBar = $("#scrollProgress");
  function updateProgress() {
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const value = max > 0 ? window.scrollY / max : 0;
    progressBar.style.transform = "scaleX(" + Math.min(1, Math.max(0, value)).toFixed(4) + ")";
  }
  window.addEventListener("scroll", updateProgress, { passive: true });
  window.addEventListener("resize", updateProgress);
  updateProgress();

  /* -------------------------------------------------------------------- init */
  observeReveals();
  renderAll();
  renderLedger();
  requestAnimationFrame(() => {
    $$("#kpis .kpi").forEach((kpi) => kpi.classList.add("in"));
  });

  if (meta.errors && meta.errors.length) {
    console.warn("Detection run reported errors:", meta.errors);
  }
})();

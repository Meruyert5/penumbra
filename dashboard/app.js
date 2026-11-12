(() => {
  "use strict";

  const DATA = JSON.parse(document.getElementById("sf-data").textContent);
  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));
  const LEVELS = ["critical", "high", "medium", "low"];
  const RANK = { critical: 4, high: 3, medium: 2, low: 1 };
  const params = new URLSearchParams(window.location.search);
  const staticMode = params.get("static") === "1";
  if (staticMode) document.documentElement.classList.add("static");
  const reduce = staticMode || window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const state = {
    level: "all",
    host: "all",
    q: "",
    hour: null,
    sort: "severity",
    tab: "detections",
    gaps: false,
    pinnedHour: null,
    hoverHour: null,
    tour: -1,
    path: 0
  };

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
  const unit = (value, one, many) => number(value) + " " + (Number(value) === 1 ? one : many);
  const percent = (value, total) => (total ? Math.round((value / total) * 100) : 0);
  const hourKey = (value) => String(value || "").slice(0, 13);
  const overlapsHour = (row, hour) => {
    const start = Date.parse(hour);
    const end = start + 3600 * 1000;
    const first = Date.parse(row.first_seen || row.last_seen || "");
    const last = Date.parse(row.last_seen || row.first_seen || "");
    if (!Number.isFinite(start)) return false;
    if (!Number.isFinite(first) || !Number.isFinite(last)) {
      return hourKey(row.last_seen || row.first_seen) === hourKey(hour);
    }
    return first < end && last >= start;
  };
  const activeCounts = (hour) => ({
    detections: (DATA.alerts || []).filter((row) => overlapsHour(row, hour)).length,
    correlations: (DATA.correlations || []).filter((row) => overlapsHour(row, hour)).length
  });

  /* ------------------------------------------------------------------ theme */
  const themeLabel = $("#themeLabel");
  const themeButton = $("#themeBtn");
  function setTheme(theme, instant) {
    const root = document.documentElement;
    if (instant) root.classList.add("no-transition");
    root.dataset.theme = theme;
    themeLabel.textContent = theme === "dark" ? "Paper theme" : "Night theme";
    themeButton.setAttribute("aria-label", theme === "dark" ? "Switch to paper theme" : "Switch to night theme");
    const meta = $('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", theme === "dark" ? "#080f11" : "#edf0e9");
    try { localStorage.setItem("sf-theme", theme); } catch (error) { /* file:// storage can be blocked */ }
    if (instant) {
      requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("no-transition")));
    }
  }
  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
    if (!reduce && document.startViewTransition) {
      document.startViewTransition(() => setTheme(next, true));
    } else {
      setTheme(next, true);
    }
  }
  const requestedTheme = params.get("theme");
  const themeOverride = requestedTheme === "dark" || requestedTheme === "light" ? requestedTheme : "";
  let savedTheme = themeOverride || "light";
  if (!themeOverride) {
    try { savedTheme = localStorage.getItem("sf-theme") || "light"; } catch (error) { savedTheme = "light"; }
  }
  setTheme(savedTheme);
  themeButton.addEventListener("click", toggleTheme);

  const isMac = /Mac|iPhone|iPad/.test(navigator.platform);
  if (isMac) {
    $$(".cmd-key").forEach((node) => { node.textContent = node.textContent.replace("Ctrl", "⌘"); });
  }

  /* ------------------------------------------------------------------ toast */
  let toastTimer = 0;
  function toast(message) {
    const node = $("#toast");
    node.textContent = message;
    node.classList.add("on");
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(() => node.classList.remove("on"), 1900);
  }

  /* Modal/palette behavior: keep the page still and the focus inside. */
  function syncOverlayLock() {
    const open = ["#palette", "#keysModal", "#caseModal"].some((selector) => {
      const node = $(selector);
      return node && node.classList.contains("on");
    });
    document.documentElement.classList.toggle("modal-open", open);
    document.body.classList.toggle("modal-open", open);
  }

  function focusableIn(container) {
    return $$('a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])', container)
      .filter((node) => node.getClientRects().length > 0);
  }

  function trapFocus(event, container) {
    if (event.key !== "Tab") return;
    const items = focusableIn(container);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    if (document.activeElement === container) {
      event.preventDefault();
      (event.shiftKey ? last : first).focus();
    } else if (event.shiftKey && document.activeElement === first) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault();
      first.focus();
    }
  }

  /* --------------------------------------------------------------- counters */
  function animateCount(node) {
    const target = Number(node.dataset.count);
    if (!Number.isFinite(target)) return;
    const suffix = node.dataset.suffix || "";
    if (reduce) { node.textContent = number(target) + suffix; return; }
    const start = performance.now();
    const duration = 900;
    function tick(now) {
      const progress = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      node.textContent = number(Math.round(target * eased)) + suffix;
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  const countObserver = "IntersectionObserver" in window
    ? new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          animateCount(entry.target);
          countObserver.unobserve(entry.target);
        });
      }, { threshold: 0.45 })
    : null;
  function observeCounts() {
    $$("[data-count]").forEach((node) => {
      if (reduce || !countObserver) { animateCount(node); return; }
      countObserver.observe(node);
    });
  }

  /* ------------------------------------------------------------------- meta */
  const meta = DATA.meta || {};
  const severity = DATA.severity || { critical: 0, high: 0, medium: 0, low: 0 };
  const errors = meta.errors || [];
  const runAt = meta.window_end || meta.generated;

  $("#railGenerated").textContent = runAt ? dayHour(runAt) + "Z" : "unknown";
  $("#railWindow").textContent = (meta.window_hours || 24) + " hours";
  $("#railErrors").textContent = errors.length + " execution errors";
  $("#coverRunLine").textContent = "Run 001 / " + (meta.window_end ? meta.window_end.slice(0, 10) : "dated run");
  $("#ticketWindow").textContent = (meta.window_hours || 24) + " hour window";
  $("#railEvents").dataset.count = String(meta.events_indexed || 0);
  $("#railRules").dataset.count = String(meta.sigma_rules || 0);
  $("#railCorr").dataset.count = String(meta.correlation_specs || 0);

  const coverFacts = [
    { value: number((DATA.alerts || []).length), label: "detections", tone: "" },
    { value: number((DATA.correlations || []).length), label: "correlations", tone: "signal" },
    { value: number(severity.critical || 0), label: "critical detections", tone: "critical" },
    { value: (meta.covered_priority || 0) + "/" + (meta.priority_techniques || 0), label: "priority coverage", tone: "forest" },
    { value: number(errors.length), label: "execution errors", tone: "" }
  ];
  $("#coverFoot").innerHTML = coverFacts.map((fact) => (
    '<div class="cf"><b' + (fact.tone ? ' class="tone-' + fact.tone + '"' : "") + '>' + esc(fact.value) + "</b><span>" + esc(fact.label) + "</span></div>"
  )).join("");

  const timeline = (DATA.timeline || []).filter((row) => row && row.hour);
  const factLine = [
    { value: number((DATA.alerts || []).length), label: "detections", tone: "" },
    { value: number((DATA.correlations || []).length), label: "correlations", tone: "signal" },
    { value: number(severity.critical || 0), label: "critical detections", tone: "critical" },
    { value: number(timeline.length), label: "hourly buckets", tone: "" },
    { value: number(errors.length), label: "execution errors", tone: "" }
  ];
  $("#factLine").innerHTML = factLine.map((fact) => (
    '<div class="fact"><b' + (fact.tone ? ' class="tone-' + fact.tone + '"' : "") + '>' + esc(fact.value) + "</b><span>" + esc(fact.label) + "</span></div>"
  )).join("");

  /* ------------------------------------------------------------- scope chart */
  const chart = $("#scopeChart");
  const readout = $("#scopeReadout");
  const NS = "http://www.w3.org/2000/svg";
  let geometry = null;

  function svgNode(name, attrs) {
    const node = document.createElementNS(NS, name);
    Object.entries(attrs || {}).forEach(([key, value]) => node.setAttribute(key, value));
    return node;
  }

  function chartMax(value) {
    if (value <= 5) return 5;
    if (value <= 20) return Math.ceil(value / 4) * 4;
    return Math.ceil(value / 45) * 45;
  }

  function activeLabel(hour) {
    const active = activeCounts(hour);
    const det = active.detections;
    const detText = det + (det === 1 ? " detection" : " detections");
    const corrText = active.correlations
      ? " / " + active.correlations + " correlation" + (active.correlations === 1 ? "" : "s")
      : "";
    return detText + corrText;
  }

  function chartIndexAt(clientX) {
    if (!geometry) return 0;
    const rect = chart.getBoundingClientRect();
    const x = (clientX - rect.left) * (geometry.width / rect.width);
    const raw = geometry.step > 0 ? (x - geometry.left) / geometry.step : 0;
    return Math.max(0, Math.min(timeline.length - 1, Math.round(raw)));
  }

  function readoutMarkup(row, pinned) {
    const counts = LEVELS.map((level) => (
      '<div class="ro-row"><i class="' + level + '"></i><span>' + level + "</span><b>" + number(row[level] || 0) + "</b></div>"
    )).join("");
    return (
      '<div class="ro-head"><span>' + (pinned ? "Pinned hour" : "Selected hour") + "</span><span>" + (pinned ? "click to unpin" : "click to pin") + "</span></div>" +
      '<div class="ro-hour">' + esc(row.hour.slice(11, 16)) + "<small>Z</small></div>" +
      '<div class="ro-total"><b>' + number(row.total) + "</b> " + (Number(row.total) === 1 ? "matched event" : "matched events") + " in this hour</div>" +
      '<div class="ro-sub">event severity</div>' +
      '<div class="ro-list">' + counts + "</div>" +
      '<div class="ro-active"><i class="live-dot" aria-hidden="true"></i><span><b>' + esc(activeLabel(row.hour)) + "</b> in the queue</span></div>" +
      '<div class="ro-note">The chart counts matched events. The ledger groups them into detections.</div>' +
      '<button class="mini ro-btn" type="button" data-hour="' + esc(row.hour) + '">Show detections active here</button>'
    );
  }

  function paintHour(index, pinned) {
    if (!geometry || !timeline[index]) return;
    const row = timeline[index];
    const x = geometry.x(index);
    const crosshair = $("#chartCrosshair");
    const focus = $("#chartFocus");
    if (crosshair) {
      crosshair.setAttribute("x1", String(x));
      crosshair.setAttribute("x2", String(x));
      crosshair.classList.add("on");
    }
    if (focus) {
      focus.setAttribute("x", String(x - geometry.step / 2));
      focus.setAttribute("width", String(Math.max(8, geometry.step)));
      focus.classList.add("on");
    }
    readout.innerHTML = readoutMarkup(row, pinned);
    $("#scopeHint").textContent = row.hour.slice(11, 16) + "Z / " + unit(row.total, "event", "events");
  }

  function paintDefault() {
    const crosshair = $("#chartCrosshair");
    const focus = $("#chartFocus");
    if (crosshair) crosshair.classList.remove("on");
    if (focus) focus.classList.remove("on");
    if (state.pinnedHour) {
      const index = timeline.findIndex((row) => row.hour === state.pinnedHour);
      if (index >= 0) { paintHour(index, true); return; }
    }
    if (!timeline.length) {
      readout.innerHTML = '<div class="ro-head"><span>No data</span></div><div class="ro-note">No alert volume in this window.</div>';
      return;
    }
    let peak = 0;
    timeline.forEach((row, index) => { if (Number(row.total) > Number(timeline[peak].total)) peak = index; });
    const row = timeline[peak];
    const counts = LEVELS.map((level) => (
      '<div class="ro-row"><i class="' + level + '"></i><span>' + level + "</span><b>" + number(row[level] || 0) + "</b></div>"
    )).join("");
    readout.innerHTML =
      '<div class="ro-head"><span>Peak hour</span><span>' + timeline.length + " buckets</span></div>" +
      '<div class="ro-hour">' + esc(row.hour.slice(11, 16)) + "<small>Z</small></div>" +
      '<div class="ro-total"><b>' + number(row.total) + "</b> " + (Number(row.total) === 1 ? "matched event" : "matched events") + " in this hour</div>" +
      '<div class="ro-sub">event severity</div>' +
      '<div class="ro-list">' + counts + "</div>" +
      '<div class="ro-active"><i class="live-dot" aria-hidden="true"></i><span><b>' + esc(activeLabel(row.hour)) + "</b> in the queue</span></div>" +
      '<div class="ro-note">The chart counts matched events. The ledger groups them into detections.</div>' +
      '<div class="ro-note">Hover or tap a column to inspect it. Click to pin the hour.</div>' +
      '<button class="mini ro-btn" type="button" data-hour="' + esc(row.hour) + '">Show detections active here</button>';
    $("#scopeHint").textContent = "peak " + number(row.total) + " events at " + row.hour.slice(11, 16) + "Z";
  }

  function buildScope() {
    chart.innerHTML = "";
    chart.classList.remove("draw");
    if (!timeline.length) {
      chart.innerHTML = '<text x="20" y="40" fill="var(--muted)" font-family="var(--mono)" font-size="11">No matched events in this window</text>';
      paintDefault();
      return;
    }
    const width = Math.max(300, Math.round(chart.getBoundingClientRect().width || 860));
    const height = width < 560 ? 288 : 340;
    chart.setAttribute("viewBox", "0 0 " + width + " " + height);
    const left = 42;
    const right = 18;
    const top = 26;
    const bottom = 38;
    const plotW = width - left - right;
    const plotH = height - top - bottom;
    const totals = timeline.map((row) => Number(row.total || 0));
    const max = chartMax(Math.max(1, ...totals));
    const step = timeline.length > 1 ? plotW / (timeline.length - 1) : plotW;
    const barWidth = Math.min(22, Math.max(8, step * 0.34));
    const x = (index) => left + (timeline.length === 1 ? plotW / 2 : index * step);
    const y = (value) => top + (1 - value / max) * plotH;
    geometry = { width, height, left, right, top, bottom, plotW, plotH, step, x, y, max };

    const desc = svgNode("desc", {});
    const peakIndex = totals.indexOf(Math.max(...totals));
    desc.textContent = "Hourly matched events. " + number(totals[peakIndex]) + " at " +
      timeline[peakIndex].hour.slice(11, 16) + "Z, with isolated single events earlier in the window.";
    chart.appendChild(desc);

    const grid = svgNode("g", { class: "chart-axis" });
    [0, 0.25, 0.5, 0.75, 1].forEach((ratio) => {
      const value = Math.round(max * ratio);
      const lineY = y(value);
      grid.appendChild(svgNode("line", { class: "chart-grid", x1: left, y1: lineY, x2: width - right, y2: lineY }));
      grid.appendChild(svgNode("text", { x: left - 8, y: lineY + 3, "text-anchor": "end" })).textContent = String(value);
    });
    chart.appendChild(grid);
    chart.appendChild(svgNode("line", { class: "chart-base", x1: left, y1: height - bottom, x2: width - right, y2: height - bottom }));

    const focus = svgNode("rect", { id: "chartFocus", class: "col-focus", y: top, height: plotH, x: left, width: step });
    chart.appendChild(focus);

    timeline.forEach((row, index) => {
      const total = Number(row.total || 0);
      const stem = svgNode("g", { class: "stem" });
      stem.style.setProperty("--stem-delay", (index * 38) + "ms");
      if (total > 0) {
        let base = height - bottom;
        ["low", "medium", "high", "critical"].forEach((level) => {
          const value = Number(row[level] || 0);
          if (!value) return;
          const segHeight = (value / max) * plotH;
          const rect = svgNode("rect", {
            class: "seg-" + level,
            x: (x(index) - barWidth / 2).toFixed(1),
            y: (base - segHeight).toFixed(1),
            width: barWidth.toFixed(1),
            height: Math.max(0.8, segHeight).toFixed(1)
          });
          stem.appendChild(rect);
          base -= segHeight;
        });
        stem.appendChild(svgNode("line", {
          class: "stem-cap",
          x1: (x(index) - barWidth / 2).toFixed(1),
          y1: y(total).toFixed(1),
          x2: (x(index) + barWidth / 2).toFixed(1),
          y2: y(total).toFixed(1)
        }));
      } else {
        stem.appendChild(svgNode("line", {
          class: "hour-tick",
          x1: x(index).toFixed(1),
          y1: height - bottom - 3,
          x2: x(index).toFixed(1),
          y2: height - bottom
        }));
      }
      chart.appendChild(stem);
    });

    // The three one-event hours are the baseline. Make them visible instead of
    // letting a linear axis flatten them into the floor.
    const quiet = timeline
      .map((row, index) => ({ row, index }))
      .filter(({ row }) => Number(row.total) > 0 && Number(row.total) <= 3);
    if (quiet.length) {
      const bracket = svgNode("g", { class: "quiet-bracket-group" });
      const first = quiet[0];
      const last = quiet[quiet.length - 1];
      const bx1 = x(first.index) - 12;
      const bx2 = x(last.index) + 12;
      const by = top + 8;
      bracket.appendChild(svgNode("path", {
        class: "quiet-bracket",
        d: "M" + bx1.toFixed(1) + " " + (by + 6) + " V" + by + " H" + bx2.toFixed(1) + " V" + (by + 6)
      }));
      const label = svgNode("text", { class: "quiet-label", x: bx1.toFixed(1), y: by + 18 });
      label.textContent = "QUIET BASELINE";
      bracket.appendChild(label);
      const count = svgNode("text", { class: "quiet-label", x: bx1.toFixed(1), y: by + 28 });
      count.textContent = quiet.length + " SINGLE EVENTS";
      bracket.appendChild(count);
      chart.appendChild(bracket);
      quiet.forEach(({ row, index }, order) => {
        const dot = svgNode("circle", {
          class: "quiet-dot",
          cx: x(index).toFixed(1),
          cy: y(Number(row.total)).toFixed(1),
          r: "3.2"
        });
        dot.style.animationDelay = (order * 0.28) + "s";
        chart.appendChild(dot);
        const labelNode = svgNode("text", {
          class: "quiet-count",
          x: x(index).toFixed(1),
          y: (y(Number(row.total)) - 8).toFixed(1),
          "text-anchor": "middle"
        });
        labelNode.textContent = number(row.total);
        chart.appendChild(labelNode);
      });
    }

    if (totals[peakIndex] > 0) {
      const peakX = x(peakIndex).toFixed(1);
      const peakY = y(totals[peakIndex]).toFixed(1);
      chart.appendChild(svgNode("circle", {
        class: "peak-halo",
        cx: peakX,
        cy: peakY,
        r: "6"
      }));
      chart.appendChild(svgNode("circle", {
        class: "peak-dot",
        cx: peakX,
        cy: peakY,
        r: "2.6"
      }));
    }

    const scan = svgNode("rect", {
      class: "chart-scan",
      x: left,
      y: top,
      width: "1.5",
      height: plotH
    });
    scan.style.setProperty("--sweep-w", plotW + "px");
    chart.appendChild(scan);

    const labels = svgNode("g", { class: "chart-axis" });
    const showEvery = width < 560 ? 2 : 1;
    timeline.forEach((row, index) => {
      if (index % showEvery !== 0 && index !== timeline.length - 1) return;
      const label = svgNode("text", {
        x: x(index).toFixed(1),
        y: height - 14,
        "text-anchor": index === 0 ? "start" : index === timeline.length - 1 ? "end" : "middle"
      });
      label.textContent = row.hour.slice(11, 13) + ":00";
      labels.appendChild(label);
    });
    const axisNote = svgNode("text", { x: width - right, y: height - 2, "text-anchor": "end", "font-size": "8" });
    axisNote.textContent = "hour / UTC";
    labels.appendChild(axisNote);
    chart.appendChild(labels);

    const crosshair = svgNode("line", {
      id: "chartCrosshair",
      class: "crosshair",
      x1: left,
      y1: top,
      x2: left,
      y2: height - bottom
    });
    chart.appendChild(crosshair);

    const hits = svgNode("g");
    timeline.forEach((row, index) => {
      const hit = svgNode("rect", {
        class: "col-hit",
        x: (x(index) - step / 2).toFixed(1),
        y: top,
        width: Math.max(10, step).toFixed(1),
        height: plotH,
        "data-index": index
      });
      hits.appendChild(hit);
    });
    chart.appendChild(hits);

    requestAnimationFrame(() => chart.classList.add("draw"));
    paintDefault();
  }

  chart.addEventListener("pointermove", (event) => {
    if (!geometry) return;
    const index = chartIndexAt(event.clientX);
    state.hoverHour = timeline[index].hour;
    paintHour(index, state.pinnedHour === timeline[index].hour);
  });
  chart.addEventListener("pointerleave", () => {
    state.hoverHour = null;
    paintDefault();
  });
  chart.addEventListener("click", (event) => {
    if (!geometry) return;
    const index = chartIndexAt(event.clientX);
    const hour = timeline[index].hour;
    state.pinnedHour = state.pinnedHour === hour ? null : hour;
    if (state.pinnedHour) paintHour(index, true); else paintDefault();
  });
  chart.addEventListener("keydown", (event) => {
    if (!geometry || !timeline.length) return;
    if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
    event.preventDefault();
    const current = state.pinnedHour
      ? timeline.findIndex((row) => row.hour === state.pinnedHour)
      : timeline.findIndex((row) => Number(row.total) === Math.max(...timeline.map((item) => Number(item.total))));
    const next = Math.max(0, Math.min(timeline.length - 1, current + (event.key === "ArrowRight" ? 1 : -1)));
    state.pinnedHour = timeline[next].hour;
    paintHour(next, true);
  });

  readout.addEventListener("click", (event) => {
    const button = event.target.closest("[data-hour]");
    if (!button) return;
    state.hour = button.dataset.hour;
    state.level = "all";
    state.q = "";
    $("#search").value = "";
    paintLevelChips();
    switchTab("detections");
    renderLedger();
    $("#ledgerPanel").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    toast("Showing detections active at " + state.hour.slice(11, 16) + "Z");
  });

  let scopeWidth = 0;
  let scopeBuilt = false;
  function initScope() {
    if (scopeBuilt) return;
    scopeBuilt = true;
    buildScope();
    scopeWidth = (geometry && geometry.width) || 0;
  }
  let scopeResize = 0;
  window.addEventListener("resize", () => {
    if (!scopeBuilt) return;
    window.clearTimeout(scopeResize);
    scopeResize = window.setTimeout(() => {
      const next = chart.getBoundingClientRect().width || 0;
      if (Math.abs(next - scopeWidth) > 24) {
        scopeWidth = next;
        buildScope();
      }
    }, 180);
  });

  /* The chart is a signal instrument, not a static figure. It replays while it
     is on screen, pauses when it leaves, and yields to reduced motion. */
  const chartPlate = $("#scopePlate");
  const replayButton = $("#chartReplay");
  let replayTimer = 0;
  let chartVisible = false;
  let chartSeen = false;

  function replayChart() {
    if (!scopeBuilt || !timeline.length) return;
    chart.classList.remove("draw");
    void chart.getBoundingClientRect();
    requestAnimationFrame(() => chart.classList.add("draw"));
  }

  function scheduleReplay() {
    window.clearTimeout(replayTimer);
    if (reduce || !chartVisible || document.hidden) return;
    replayTimer = window.setTimeout(() => {
      replayChart();
      scheduleReplay();
    }, 8000);
  }

  if (!reduce && "IntersectionObserver" in window) {
    const chartObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        chartVisible = entry.isIntersecting;
        chartPlate.classList.toggle("live", chartVisible);
        if (chartVisible) {
          if (!scopeBuilt) initScope();
          if (!chartSeen) {
            chartSeen = true;
            replayChart();
          }
          scheduleReplay();
        } else {
          window.clearTimeout(replayTimer);
        }
      });
    }, { threshold: 0.28 });
    chartObserver.observe(chartPlate);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) window.clearTimeout(replayTimer);
      else scheduleReplay();
    });
  }

  if (replayButton) {
    replayButton.addEventListener("click", () => {
      replayChart();
      scheduleReplay();
    });
  }

  /* ------------------------------------------------------------------- path */
  const pipeline = DATA.pipeline || [];
  $("#pathStrip").innerHTML = pipeline.map((step, index) => (
    '<button class="path-step' + (index === 0 ? " active" : "") + '" type="button" role="tab" aria-selected="' + (index === 0) + '" data-index="' + index + '">' +
      '<span class="path-dot">' + String(index + 1).padStart(2, "0") + "</span>" +
      '<span class="path-label">' + esc(step.label) + "</span>" +
      '<span class="path-title">' + esc(step.title) + "</span>" +
      '<span class="path-count">' + esc(step.count) + "</span>" +
    "</button>"
  )).join("");

  function renderPathDetail(index) {
    const step = pipeline[index];
    if (!step) return;
    state.path = index;
    $$("#pathStrip .path-step").forEach((node) => {
      const active = Number(node.dataset.index) === index;
      node.classList.toggle("active", active);
      node.setAttribute("aria-selected", String(active));
    });
    $("#pathDetail").innerHTML = '<span class="pd-label">' + esc(step.label) + "</span><p>" + esc(step.detail) + "</p>";
  }
  renderPathDetail(0);
  $("#pathStrip").addEventListener("click", (event) => {
    const step = event.target.closest(".path-step");
    if (step) renderPathDetail(Number(step.dataset.index));
  });
  const pathStrip = $("#pathStrip");
  function updatePathSignalWidth() {
    pathStrip.style.setProperty("--path-w", pathStrip.clientWidth + "px");
  }
  window.addEventListener("resize", updatePathSignalWidth);

  /* ----------------------------------------------------------------- ledger */
  const detections = (DATA.alerts || []).map((alert) => ({
    kind: "detection",
    id: alert.rule_id,
    title: alert.title,
    level: String(alert.level || "low").toLowerCase(),
    techniques: alert.techniques || [],
    tactics: alert.tactics || [],
    hosts: alert.hosts || [],
    host: alert.host || (alert.hosts || []).join(", "),
    count: alert.count || 0,
    first_seen: alert.first_seen,
    last_seen: alert.last_seen,
    index: (alert.index || []).join(", "),
    query: alert.query || "",
    query_kql: alert.query_kql || "",
    events: alert.events || []
  }));
  const correlations = (DATA.correlations || []).map((corr) => ({
    kind: "correlation",
    id: corr.correlation_id,
    title: corr.title,
    level: String(corr.level || "low").toLowerCase(),
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
    threshold: corr.threshold,
    distinct_by: corr.distinct_by,
    distinct_count: corr.distinct_count,
    distinct_threshold: corr.distinct_threshold,
    window_seconds: corr.window_seconds,
    group_by: corr.group_by,
    group_value: corr.group_value
  }));

  const rowIndex = new Map();
  detections.forEach((row) => rowIndex.set(row.kind + ":" + row.id, row));
  correlations.forEach((row) => rowIndex.set(row.kind + ":" + row.id, row));

  const hostSet = new Set();
  detections.forEach((row) => (row.hosts || []).forEach((host) => hostSet.add(host)));
  correlations.forEach((row) => (row.hosts || []).forEach((host) => hostSet.add(host)));
  $("#hostFilter").innerHTML = '<option value="all">all hosts</option>' +
    Array.from(hostSet).sort().map((host) => '<option value="' + esc(host) + '">' + esc(host) + "</option>").join("");
  $("#tabDetectionsN").textContent = String(detections.length);
  $("#tabCorrelationsN").textContent = String(correlations.length);

  function activeRows() {
    return state.tab === "detections" ? detections : correlations;
  }

  function filteredRows() {
    const query = state.q.toLowerCase();
    return activeRows().filter((row) => {
      if (state.level !== "all" && row.level !== state.level) return false;
      if (state.host !== "all" && !(row.hosts || []).some((host) => String(host).includes(state.host))) return false;
      if (state.hour && !overlapsHour(row, state.hour)) return false;
      if (query) {
        const haystack = [row.title, row.host, row.id, row.index, (row.techniques || []).join(" "), (row.tactics || []).join(" ")].join(" ").toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      return true;
    }).sort((a, b) => {
      if (state.sort === "time") return String(b.last_seen || "").localeCompare(String(a.last_seen || ""));
      if (state.sort === "count") return b.count - a.count;
      return (RANK[b.level] || 0) - (RANK[a.level] || 0) || String(b.last_seen || "").localeCompare(String(a.last_seen || ""));
    });
  }

  function kvRows(pairs) {
    return '<dl class="kv">' + pairs.filter(([, value]) => value != null && value !== "").map(([key, value]) => (
      "<div><dt>" + esc(key) + "</dt><dd>" + esc(value) + "</dd></div>"
    )).join("") + "</dl>";
  }

  function eventMarkup(event, index) {
    const host = event.host && (event.host.name || event.host.hostname);
    const user = event.user && (event.user.name || event.user.id);
    const process = event.process || {};
    const parent = process.parent || {};
    const pairs = [
      ["timestamp", event["@timestamp"]],
      ["host", host],
      ["user", user],
      ["process", process.name],
      ["command", process.command_line],
      ["parent", parent.name],
      ["parent cmd", parent.command_line],
      ["action", event.event && event.event.action]
    ];
    return (
      '<div class="event">' +
        '<div class="event-head"><b>#' + (index + 1) + "</b><span>" + esc(event["@timestamp"] || "") + "</span><span>" + esc(host || "") + "</span></div>" +
        kvRows(pairs) +
      "</div>"
    );
  }

  function evidenceMarkup(row) {
    if (row.kind === "correlation") {
      const detail = kvRows([
        ["correlation", row.id],
        ["group by", row.group_by],
        ["group value", row.group_value],
        ["window", row.window_seconds + " seconds"],
        ["threshold", row.count + " / " + row.threshold],
        ["distinct", row.distinct_by ? row.distinct_count + " " + row.distinct_by + " (minimum " + row.distinct_threshold + ")" : "not used"],
        ["first seen", row.first_seen],
        ["last seen", row.last_seen],
        ["index", row.index]
      ]);
      const rationale = "The correlation groups events by " + row.group_by + ". The group " + row.group_value +
        " produced " + row.count + " events inside " + row.window_seconds + " seconds, meeting the threshold of " + row.threshold + "." +
        (row.distinct_by ? " It also reached " + row.distinct_count + " distinct " + row.distinct_by + " values against a minimum of " + row.distinct_threshold + "." : "");
      return (
        '<div class="drawer-pad">' +
          '<div class="ev-tabs" role="tablist"><button class="ev-tab active" type="button" role="tab" aria-selected="true" data-tab="detail">Detail</button><button class="ev-tab" type="button" role="tab" aria-selected="false" data-tab="rationale">Rationale</button></div>' +
          '<div class="ev-panel" data-panel="detail"><div class="ev-head"><h4>Correlation record</h4><button class="mini" type="button" data-copy="' + esc(row.id + " | " + row.group_by + "=" + row.group_value) + '">copy id</button></div>' + detail + "</div>" +
          '<div class="ev-panel" data-panel="rationale" hidden><div class="ev-head"><h4>Why it fired</h4></div><p class="ro-note">' + esc(rationale) + "</p></div>" +
        "</div>"
      );
    }
    const events = (row.events || []).slice(0, 3);
    const eventHtml = events.length
      ? events.map(eventMarkup).join("")
      : '<div class="empty">No event bodies were stored for this match.</div>';
    return (
      '<div class="drawer-pad">' +
        '<div class="ev-tabs" role="tablist">' +
          '<button class="ev-tab active" type="button" role="tab" aria-selected="true" data-tab="events">Events</button>' +
          '<button class="ev-tab" type="button" role="tab" aria-selected="false" data-tab="eql">EQL</button>' +
          '<button class="ev-tab" type="button" role="tab" aria-selected="false" data-tab="kql">KQL</button>' +
        "</div>" +
        '<div class="ev-panel" data-panel="events"><div class="ev-head"><h4>Matching events / first 3</h4><span class="ro-note">' + events.length + " shown</span></div>" + eventHtml + "</div>" +
        '<div class="ev-panel" data-panel="eql" hidden><div class="ev-head"><h4>Compiled EQL</h4><button class="mini" type="button" data-copy="' + esc(row.query) + '">copy EQL</button></div><pre class="ev-pre">' + esc(row.query || "not generated") + "</pre></div>" +
        '<div class="ev-panel" data-panel="kql" hidden><div class="ev-head"><h4>Kibana KQL</h4><button class="mini" type="button" data-copy="' + esc(row.query_kql) + '">copy KQL</button></div><pre class="ev-pre">' + esc(row.query_kql || "not generated") + "</pre></div>" +
      "</div>"
    );
  }

  function rowMarkup(row, index) {
    const techs = (row.techniques || []).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const meta = [
      '<span><i>host</i><b>' + esc(row.host || "unassigned") + "</b></span>",
      '<span><i>events</i><b>' + number(row.count) + "</b></span>",
      '<span><i>last</i><b>' + esc(clock(row.last_seen)) + "Z</b></span>",
      row.index ? '<span><i>source</i><b>' + esc(row.index) + "</b></span>" : ""
    ].join("");
    return (
      '<article class="row' + (reduce ? "" : " enter") + '" tabindex="0" aria-expanded="false" data-level="' + esc(row.level) + '" data-id="' + esc(row.id) + '" data-kind="' + esc(row.kind) + '"' + (reduce ? "" : ' style="animation-delay:' + Math.min(index, 12) * 22 + 'ms"') + ">" +
        '<span class="row-index">' + String(index + 1).padStart(2, "0") + "</span>" +
        '<div class="row-body">' +
          '<div class="row-top"><h3 class="row-title">' + esc(row.title) + '</h3><span class="sev ' + esc(row.level) + '">' + esc(row.level) + "</span></div>" +
          '<div class="row-meta">' + meta + "</div>" +
          (techs ? '<div class="row-techs">' + techs + "</div>" : "") +
        "</div>" +
        '<button class="row-open" type="button" aria-label="Open evidence">' +
          '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M6 9l6 6 6-6"/></svg>' +
        "</button>" +
        '<div class="drawer"><div class="drawer-inner" data-evidence-pending="true"></div></div>' +
      "</article>"
    );
  }

  function renderActiveFilters() {
    const items = [];
    if (state.hour) {
      items.push('<span class="filter-pill">active ' + esc(state.hour.slice(11, 16)) + 'Z <button type="button" data-clear="hour" aria-label="Clear active-hour filter">x</button></span>');
    }
    if (state.q) {
      items.push('<span class="filter-pill">search "' + esc(state.q) + '" <button type="button" data-clear="q" aria-label="Clear search filter">x</button></span>');
    }
    $("#activeFilters").innerHTML = items.join("");
  }

  let ledgerRendered = false;
  function renderLedger() {
    ledgerRendered = true;
    const result = filteredRows();
    $("#ledgerCount").textContent = result.length + " of " + activeRows().length + " rows";
    renderActiveFilters();
    if (!result.length) {
      $("#ledgerBody").innerHTML = '<div class="empty">No ' + esc(state.tab) + " match this filter. Clear the search, pick another host, or remove the active-hour filter.</div>";
      return;
    }
    $("#ledgerBody").innerHTML = result.map(rowMarkup).join("");
  }

  function ensureLedger() {
    if (!ledgerRendered) renderLedger();
  }

  function switchTab(tab) {
    state.tab = tab;
    $("#tabDetections").classList.toggle("active", tab === "detections");
    $("#tabCorrelations").classList.toggle("active", tab === "correlations");
    $("#tabDetections").setAttribute("aria-selected", String(tab === "detections"));
    $("#tabCorrelations").setAttribute("aria-selected", String(tab === "correlations"));
    renderLedger();
  }

  function paintLevelChips() {
    $$(".chip[data-level]").forEach((chip) => {
      const active = chip.dataset.level === state.level;
      chip.classList.toggle("active", active);
      chip.setAttribute("aria-pressed", String(active));
    });
  }

  function setLevel(level) {
    state.level = level;
    paintLevelChips();
    renderLedger();
  }

  function toggleRow(row, force) {
    const open = typeof force === "boolean" ? force : !row.classList.contains("open");
    if (open) {
      const inner = $(".drawer-inner", row);
      if (inner && inner.dataset.evidencePending) {
        const data = rowIndex.get(row.dataset.kind + ":" + row.dataset.id);
        if (data) {
          inner.innerHTML = evidenceMarkup(data);
          delete inner.dataset.evidencePending;
        }
      }
    }
    row.classList.toggle("open", open);
    row.setAttribute("aria-expanded", String(open));
    const button = $(".row-open", row);
    if (button) button.setAttribute("aria-label", open ? "Close evidence" : "Open evidence");
  }

  function activateEvidenceTab(tab) {
    const scope = tab.closest(".drawer-inner");
    if (!scope) return;
    $$(".ev-tab", scope).forEach((node) => {
      const active = node === tab;
      node.classList.toggle("active", active);
      node.setAttribute("aria-selected", String(active));
    });
    $$(".ev-panel", scope).forEach((panel) => { panel.hidden = panel.dataset.panel !== tab.dataset.tab; });
  }

  function focusRow(direction) {
    const rows = $$("#ledgerBody .row");
    if (!rows.length) return;
    const current = document.activeElement && document.activeElement.closest ? document.activeElement.closest(".row") : null;
    let index = current ? rows.indexOf(current) : -1;
    index = direction === "next" ? Math.min(rows.length - 1, index + 1) : Math.max(0, index - 1);
    if (index < 0) index = 0;
    rows[index].focus({ preventScroll: true });
    rows[index].scrollIntoView({ block: "nearest", behavior: reduce ? "auto" : "smooth" });
  }

  $$(".chip[data-level]").forEach((chip) => {
    chip.addEventListener("click", () => setLevel(chip.dataset.level));
  });
  $("#hostFilter").addEventListener("change", (event) => { state.host = event.target.value; renderLedger(); });
  $("#sortFilter").addEventListener("change", (event) => { state.sort = event.target.value; renderLedger(); });
  $("#search").addEventListener("input", (event) => { state.q = event.target.value.trim(); renderLedger(); });
  $("#tabDetections").addEventListener("click", () => switchTab("detections"));
  $("#tabCorrelations").addEventListener("click", () => switchTab("correlations"));

  $("#activeFilters").addEventListener("click", (event) => {
    const clear = event.target.closest("[data-clear]");
    if (!clear) return;
    if (clear.dataset.clear === "hour") state.hour = null;
    if (clear.dataset.clear === "q") { state.q = ""; $("#search").value = ""; }
    renderLedger();
  });

  $("#ledgerBody").addEventListener("click", (event) => {
    const tab = event.target.closest(".ev-tab");
    if (tab) { activateEvidenceTab(tab); return; }
    const row = event.target.closest(".row");
    if (!row) return;
    if (event.target.closest(".drawer")) return;
    toggleRow(row);
  });

  $("#ledgerBody").addEventListener("keydown", (event) => {
    const row = event.target.closest(".row");
    if (!row) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      toggleRow(row);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      focusRow("next");
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      focusRow("prev");
    }
  });

  renderLedger();

  /* --------------------------------------------------------------- coverage */
  const coverage = DATA.coverage || { tactics: [], priority: 0, covered: 0, gaps: [] };
  const allTiles = (coverage.tactics || []).flatMap((tactic) => (tactic.tiles || []).map((tile) => ({ ...tile, tactic: tactic.label })));
  $("#coverageCovered").dataset.count = String(coverage.covered || 0);
  $("#coverageCovered").textContent = "0";
  $("#coverageTotal").textContent = String(coverage.priority || 0);
  $("#coverageNote").textContent = (coverage.covered || 0) + " covered / " + (coverage.gaps || []).length + " gaps";
  $("#coverageGauge").innerHTML = allTiles.map((tile, index) => (
    '<span class="gauge-tick ' + (tile.level ? "on" : "gap") + '" style="--i:' + index + '" title="' + esc(tile.technique + " " + tile.name + (tile.level ? " / covered" : " / gap")) + '"></span>'
  )).join("");

  function renderMatrix() {
    const visible = (coverage.tactics || []).map((tactic) => ({
      ...tactic,
      tiles: (tactic.tiles || []).filter((tile) => !state.gaps || !tile.level)
    })).filter((tactic) => tactic.tiles.length);

    $("#matrix").innerHTML = visible.length ? visible.map((tactic) => {
      const covered = tactic.tiles.filter((tile) => tile.level).length;
      const tiles = tactic.tiles.map((tile, index) => {
        const label = tile.level ? tile.level : "gap";
        return '<button class="tile ' + (tile.level ? "covered " + esc(tile.level) : "gap") + '" type="button" data-tech="' + esc(tile.technique) + '" style="animation-delay:' + Math.min(index, 12) * 16 + 'ms" title="' + esc(tile.technique + " / " + tile.name + " / " + label) + '">' +
          '<span class="id">' + esc(tile.technique) + '</span><span class="nm">' + esc(tile.name) + "</span></button>";
      }).join("");
      return (
        '<div class="tactic">' +
          '<div class="tactic-head"><h3>' + esc(tactic.label) + '</h3><span class="tactic-count">' + covered + "/" + tactic.tiles.length + "</span></div>" +
          '<div class="tiles">' + tiles + "</div>" +
        "</div>"
      );
    }).join("") : '<div class="empty">No techniques match this view.</div>';

    if (reduce) $("#matrix").classList.add("in");
  }
  renderMatrix();

  function toggleGaps() {
    state.gaps = !state.gaps;
    $("#gapsBtn").classList.toggle("active", state.gaps);
    $("#gapsBtn").setAttribute("aria-pressed", String(state.gaps));
    $("#gapsBtn").textContent = state.gaps ? "show all techniques" : "show gaps only";
    renderMatrix();
  }
  $("#gapsBtn").addEventListener("click", toggleGaps);

  $("#matrix").addEventListener("click", (event) => {
    const tile = event.target.closest(".tile");
    if (!tile) return;
    const technique = tile.dataset.tech;
    $("#search").value = technique;
    state.q = technique;
    state.hour = null;
    state.level = "all";
    paintLevelChips();
    switchTab("detections");
    $("#ledgerPanel").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    toast(technique + " filtered into the ledger");
  });

  if ("IntersectionObserver" in window && !reduce) {
    const matrixObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("in");
        matrixObserver.unobserve(entry.target);
      });
    }, { threshold: 0.12 });
    matrixObserver.observe($("#matrix"));
  }

  /* ------------------------------------------------------------------ cases */
  const cases = DATA.cases || [];
  $("#caseGrid").innerHTML = cases.map((item, index) => {
    const techs = (item.techniques || []).slice(0, 4).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const extra = (item.techniques || []).length > 4 ? '<span class="tech">+' + ((item.techniques || []).length - 4) + "</span>" : "";
    return (
      '<article class="case-card" tabindex="0" role="button" data-case="' + index + '" aria-haspopup="dialog" style="animation-delay:' + index * 70 + 'ms">' +
        '<span class="case-top"><span class="case-id">' + esc(item.id) + '</span><span class="case-verdict">' + esc(item.verdict) + "</span></span>" +
        "<h3>" + esc(item.title) + "</h3>" +
        "<p>" + esc(item.summary) + "</p>" +
        '<span class="case-techs">' + techs + extra + "</span>" +
        '<span class="case-foot"><span><b>' + esc(item.hosts.join(", ")) + "</b></span><span>open file</span></span>" +
      "</article>"
    );
  }).join("") || '<div class="empty">No case files committed yet.</div>';

  if ("IntersectionObserver" in window && !reduce) {
    const caseObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("in");
        caseObserver.unobserve(entry.target);
      });
    }, { threshold: 0.1 });
    caseObserver.observe($("#caseGrid"));
  } else {
    $("#caseGrid").classList.add("in");
  }

  let caseReturnFocus = null;
  function closeCase() {
    const modal = $("#caseModal");
    if (!modal.classList.contains("on")) return;
    modal.classList.remove("on");
    modal.setAttribute("aria-hidden", "true");
    syncOverlayLock();
    if (caseReturnFocus && caseReturnFocus.focus) caseReturnFocus.focus({ preventScroll: true });
  }
  function openCase(index) {
    const item = cases[index];
    if (!item) return;
    caseReturnFocus = document.activeElement;
    const techs = (item.techniques || []).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const detectionsList = (item.detections || []).map((id) => '<span class="tech">' + esc(id) + "</span>").join("");
    $("#caseFile").innerHTML =
      '<button class="mini file-close" type="button" data-close-case>close</button>' +
      '<p class="file-kicker">' + esc(item.id) + " / Case file</p>" +
      '<h2 id="caseModalTitle">' + esc(item.title) + "</h2>" +
      '<p class="file-summary">' + esc(item.summary) + "</p>" +
      '<dl class="file-grid">' +
        "<div><dt>Severity</dt><dd>" + esc(item.severity) + "</dd></div>" +
        "<div><dt>Verdict</dt><dd>" + esc(item.verdict) + "</dd></div>" +
        "<div><dt>Status</dt><dd>" + esc(item.status) + "</dd></div>" +
        "<div><dt>Opened</dt><dd>" + esc(item.opened) + "</dd></div>" +
        "<div><dt>Hosts</dt><dd>" + esc((item.hosts || []).join(", ")) + "</dd></div>" +
        "<div><dt>Detections</dt><dd>" + esc((item.detections || []).join(", ")) + "</dd></div>" +
      "</dl>" +
      '<div class="file-block"><h3>ATT&CK techniques</h3><div class="case-techs">' + techs + "</div></div>" +
      '<div class="file-block"><h3>Detection IDs</h3><div class="case-techs">' + detectionsList + "</div></div>" +
      '<div class="file-actions">' +
        '<a class="btn primary" href="' + esc(item.path) + '">Open the full report</a>' +
        '<button class="btn" type="button" data-copy="' + esc(item.path) + '">Copy report path</button>' +
      "</div>";
    $("#caseModal").classList.add("on");
    $("#caseModal").setAttribute("aria-hidden", "false");
    syncOverlayLock();
    $(".file-close", $("#caseFile")).focus();
  }
  $("#caseGrid").addEventListener("click", (event) => {
    const card = event.target.closest(".case-card");
    if (card) openCase(Number(card.dataset.case));
  });
  $("#caseGrid").addEventListener("keydown", (event) => {
    const card = event.target.closest(".case-card");
    if (!card || (event.key !== "Enter" && event.key !== " ")) return;
    event.preventDefault();
    openCase(Number(card.dataset.case));
  });
  $("#caseModal").addEventListener("click", (event) => {
    if (event.target === $("#caseModal") || event.target.closest("[data-close-case]")) closeCase();
  });

  /* ------------------------------------------------------------------- copy */
  function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) return navigator.clipboard.writeText(text);
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
  const reproduceCommands = [
    "python -m pipeline.labgen --scenario all --out lab/logs",
    "python -m pipeline.compile",
    "docker compose up -d",
    "python -m pipeline.ingest --reset",
    "python -m pipeline.detect --hours 24",
    "python -m pipeline.report"
  ].join("\n");
  $("#copyAll").addEventListener("click", () => {
    copyText(reproduceCommands).then(() => toast("six commands copied")).catch(() => toast("copy failed"));
  });

  /* ------------------------------------------------------------------ tour */
  const steps = [
    { target: "#cover .ticket", title: "A run you can inspect", body: "This is the output of one deterministic run: 2,182 events, a 44-rule Sigma library, and eight correlation specs. The ticket is the receipt." },
    { target: "#scopePlate", title: "Read the signal", body: "Eleven hourly buckets. Three isolated events, then 167 matched events in the 11:00 hour. The quiet hours matter because a rule that fires on everything cannot discriminate." },
    { target: "#pathStrip", title: "Follow the chain", body: "Sigma compiles to Elasticsearch EQL and KQL. Detection executes the queries, correlation adds volume logic, and triage turns matches into a queue with evidence." },
    { target: "#ledgerPanel", title: "Work the queue", body: "Filter by severity, host, or technique. Open a row for the matching events and the exact query. J and K move between rows; Enter opens the drawer." },
    { target: "#matrix", title: "Check the gaps", body: "Coverage only counts priority techniques, and every gap stays visible. A hatched tile is the next rule to write, not a number hidden inside a percentage." },
    { target: "#caseGrid", title: "Read the investigations", body: "Each case follows the same structure: summary, timeline, evidence, analysis, verdict, containment, and the detection improvement that came out of it." },
    { target: "#reproduce .terminal", title: "Reproduce it", body: "Generation is seeded. The same commands produce the same events, the same alerts, and this same page. Swap the logsource map when you connect real telemetry." }
  ];
  const spot = $("#tourSpot");
  const tourCard = $("#tourCard");
  let tourReturnFocus = null;

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

    // Keep the card off the thing it is describing. Prefer below, then above.
    const gap = 14;
    const cardH = tourCard.offsetHeight || 200;
    const rail = $(".rail");
    const railH = window.matchMedia("(max-width: 1080px)").matches && rail
      ? rail.getBoundingClientRect().height
      : 0;
    const below = window.innerHeight - rect.bottom - gap;
    const above = rect.top - gap;
    if (below >= cardH + 6) {
      tourCard.style.top = "auto";
      tourCard.style.bottom = gap + "px";
    } else if (above >= cardH + 6) {
      tourCard.style.bottom = "auto";
      tourCard.style.top = Math.max(railH + 12, gap) + "px";
    } else if (below >= above) {
      tourCard.style.top = "auto";
      tourCard.style.bottom = gap + "px";
    } else {
      tourCard.style.bottom = "auto";
      tourCard.style.top = Math.max(railH + 12, gap) + "px";
    }
  }

  function scrollTarget(target) {
    const rail = $(".rail");
    const railH = window.matchMedia("(max-width: 1080px)").matches && rail
      ? rail.getBoundingClientRect().height
      : 0;
    const base = railH + (railH ? 14 : 24);
    const cardH = tourCard.offsetHeight || 200;
    const room = window.innerHeight - base - cardH - 24;
    const rect = target.getBoundingClientRect();
    const offset = rect.height <= room ? base : base + cardH + 20;
    window.scrollTo({
      top: Math.max(0, rect.top + window.scrollY - offset),
      behavior: reduce ? "auto" : "smooth"
    });
  }

  function goStep(index) {
    if (index < 0) index = 0;
    if (index >= steps.length) { endTour(); return; }
    state.tour = index;
    const step = steps[index];
    $("#tourStep").textContent = String(index + 1).padStart(2, "0") + " / " + String(steps.length).padStart(2, "0");
    $("#tourTitle").textContent = step.title;
    $("#tourBody").textContent = step.body;
    $("#tourDots").innerHTML = steps.map((_, dot) => '<i class="' + (dot === index ? "on" : "") + '"></i>').join("");
    $("#tourPrev").disabled = index === 0;
    $("#tourNext").textContent = index === steps.length - 1 ? "finish" : "next";
    const target = $(step.target);
    if (target) scrollTarget(target);
    window.setTimeout(updateSpot, reduce ? 30 : 420);
    spot.classList.add("on");
    tourCard.classList.add("on");
    tourCard.setAttribute("aria-hidden", "false");
    tourCard.focus({ preventScroll: true });
  }
  function startTour() {
    tourReturnFocus = document.activeElement;
    goStep(0);
  }
  function endTour() {
    state.tour = -1;
    spot.classList.remove("on");
    tourCard.classList.remove("on");
    tourCard.setAttribute("aria-hidden", "true");
    tourCard.style.top = "";
    tourCard.style.bottom = "";
    if (tourReturnFocus && tourReturnFocus.focus) tourReturnFocus.focus({ preventScroll: true });
  }
  $("#tourBtn").addEventListener("click", startTour);
  $("#tourNext").addEventListener("click", () => goStep(state.tour + 1));
  $("#tourPrev").addEventListener("click", () => goStep(state.tour - 1));
  $("#tourSkip").addEventListener("click", endTour);
  $("#tourClose").addEventListener("click", endTour);
  window.addEventListener("scroll", updateSpot, { passive: true });
  window.addEventListener("resize", updateSpot);

  /* ------------------------------------------------------------------ keys */
  let keysReturnFocus = null;
  function openKeys() {
    keysReturnFocus = document.activeElement;
    $("#keysModal").classList.add("on");
    $("#keysModal").setAttribute("aria-hidden", "false");
    syncOverlayLock();
    $("#keysClose").focus();
  }
  function closeKeys() {
    const modal = $("#keysModal");
    if (!modal.classList.contains("on")) return;
    modal.classList.remove("on");
    modal.setAttribute("aria-hidden", "true");
    syncOverlayLock();
    if (keysReturnFocus && keysReturnFocus.focus) keysReturnFocus.focus({ preventScroll: true });
  }
  $("#keysBtn").addEventListener("click", openKeys);
  $("#keysClose").addEventListener("click", closeKeys);
  $("#keysModal").addEventListener("click", (event) => { if (event.target === $("#keysModal")) closeKeys(); });

  /* --------------------------------------------------------------- palette */
  const palette = $("#palette");
  const paletteInput = $("#paletteInput");
  const paletteList = $("#paletteList");
  let paletteCommands = [];
  let paletteActive = 0;
  let paletteReturnFocus = null;

  function goTo(selector) {
    const target = $(selector);
    if (target) target.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
  }

  paletteCommands = [
    { group: "Go", label: "Cover", hint: "00", run: () => goTo("#cover") },
    { group: "Go", label: "The run", hint: "01", run: () => goTo("#run") },
    { group: "Go", label: "Method", hint: "02", run: () => goTo("#method") },
    { group: "Go", label: "Ledger", hint: "03", run: () => goTo("#ledger") },
    { group: "Go", label: "Coverage", hint: "04", run: () => goTo("#coverage") },
    { group: "Go", label: "Cases", hint: "05", run: () => goTo("#cases") },
    { group: "Go", label: "Proof", hint: "06", run: () => goTo("#reproduce") },
    { group: "Filter", label: "All detections", hint: "clear severity", run: () => { setLevel("all"); goTo("#ledger"); } },
    { group: "Filter", label: "Critical detections", hint: number(severity.critical || 0), run: () => { setLevel("critical"); goTo("#ledger"); } },
    { group: "Filter", label: "High detections", hint: number(severity.high || 0), run: () => { setLevel("high"); goTo("#ledger"); } },
    { group: "Filter", label: "Medium detections", hint: number(severity.medium || 0), run: () => { setLevel("medium"); goTo("#ledger"); } },
    { group: "Filter", label: "Low detections", hint: number(severity.low || 0), run: () => { setLevel("low"); goTo("#ledger"); } },
    { group: "View", label: state.gaps ? "Show all techniques" : "Show gaps only", hint: "coverage", run: () => { toggleGaps(); goTo("#coverage"); } },
    { group: "View", label: "Switch theme", hint: "paper / night", run: toggleTheme },
    { group: "Reading", label: "Start guided reading", hint: "7 steps", run: startTour },
    { group: "Reading", label: "Keyboard shortcuts", hint: "?", run: openKeys }
  ];
  cases.forEach((item, index) => {
    paletteCommands.push({ group: "Case", label: item.id + " / " + item.title, hint: item.severity, run: () => openCase(index) });
  });
  paletteCommands.push({ group: "Copy", label: "Copy the reproduce commands", hint: "6 lines", run: () => { copyText(reproduceCommands).then(() => toast("six commands copied")).catch(() => toast("copy failed")); } });

  function renderPalette(query) {
    const text = String(query || "").toLowerCase();
    const items = paletteCommands.filter((command) => (command.group + " " + command.label + " " + command.hint).toLowerCase().includes(text));
    paletteActive = 0;
    paletteList.innerHTML = items.length ? items.map((command, index) => (
      '<button class="palette-item' + (index === 0 ? " active" : "") + '" type="button" role="option" aria-selected="' + (index === 0) + '" data-index="' + index + '">' +
        '<span class="pi-group">' + esc(command.group) + "</span>" +
        "<span>" + esc(command.label) + "</span>" +
        '<span class="pi-hint">' + esc(command.hint || "") + "</span>" +
      "</button>"
    )).join("") : '<div class="palette-empty">No command matches that search.</div>';
    paletteList.dataset.count = String(items.length);
    paletteList._items = items;
  }

  function setPaletteActive(index) {
    const items = $$(".palette-item", paletteList);
    if (!items.length) return;
    paletteActive = Math.max(0, Math.min(items.length - 1, index));
    items.forEach((item, itemIndex) => {
      const active = itemIndex === paletteActive;
      item.classList.toggle("active", active);
      item.setAttribute("aria-selected", String(active));
      if (active) item.scrollIntoView({ block: "nearest" });
    });
  }

  function runPalette(index) {
    const items = paletteList._items || [];
    const command = items[index];
    if (!command) return;
    closePalette();
    command.run();
  }

  function openPalette() {
    paletteReturnFocus = document.activeElement;
    palette.classList.add("on");
    palette.setAttribute("aria-hidden", "false");
    paletteInput.value = "";
    renderPalette("");
    syncOverlayLock();
    paletteInput.focus();
  }
  function closePalette() {
    if (!palette.classList.contains("on")) return;
    palette.classList.remove("on");
    palette.setAttribute("aria-hidden", "true");
    syncOverlayLock();
    if (paletteReturnFocus && paletteReturnFocus.focus) paletteReturnFocus.focus({ preventScroll: true });
  }
  $("#paletteBtn").addEventListener("click", openPalette);
  $("#paletteBtnCover").addEventListener("click", openPalette);
  $("#paletteClose").addEventListener("click", closePalette);
  palette.addEventListener("click", (event) => { if (event.target === palette) closePalette(); });
  paletteInput.addEventListener("input", () => renderPalette(paletteInput.value));
  paletteInput.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown") { event.preventDefault(); setPaletteActive(paletteActive + 1); }
    else if (event.key === "ArrowUp") { event.preventDefault(); setPaletteActive(paletteActive - 1); }
    else if (event.key === "Enter") { event.preventDefault(); runPalette(paletteActive); }
    else if (event.key === "Escape") { event.preventDefault(); closePalette(); }
  });
  paletteList.addEventListener("click", (event) => {
    const item = event.target.closest(".palette-item");
    if (item) runPalette(Number(item.dataset.index));
  });
  paletteList.addEventListener("mousemove", (event) => {
    const item = event.target.closest(".palette-item");
    if (item) setPaletteActive(Number(item.dataset.index));
  });

  /* -------------------------------------------------------------- shortcuts */
  document.addEventListener("keydown", (event) => {
    const typing = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName) || document.activeElement.isContentEditable;
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
      event.preventDefault();
      if (palette.classList.contains("on")) closePalette(); else openPalette();
      return;
    }
    if (event.key === "Escape") {
      closePalette();
      closeKeys();
      closeCase();
      endTour();
      return;
    }
    const overlay = palette.classList.contains("on") ? palette
      : $("#caseModal").classList.contains("on") ? $("#caseModal")
      : $("#keysModal").classList.contains("on") ? $("#keysModal")
      : tourCard.classList.contains("on") ? tourCard
      : null;
    if (overlay) {
      trapFocus(event, overlay);
      return;
    }
    if (typing) return;
    if (event.key === "/") { event.preventDefault(); $("#search").focus(); }
    else if (event.key.toLowerCase() === "j") { event.preventDefault(); focusRow("next"); }
    else if (event.key.toLowerCase() === "k") { event.preventDefault(); focusRow("prev"); }
    else if (event.key.toLowerCase() === "t") toggleTheme();
    else if (event.key.toLowerCase() === "g") startTour();
    else if (event.key === "?") openKeys();
  });

  /* -------------------------------------------------------------- scroll UI */
  const progressBar = $("#scrollProgress");
  const railFill = $("#railFill");
  function updateScroll() {
    const max = document.documentElement.scrollHeight - window.innerHeight;
    const value = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
    progressBar.style.transform = "scaleX(" + value.toFixed(4) + ")";
    railFill.style.height = (value * 100).toFixed(2) + "%";
  }
  window.addEventListener("scroll", updateScroll, { passive: true });
  window.addEventListener("resize", updateScroll);

  const railNav = $("#railNav");
  function updateNavMask() {
    if (!railNav) return;
    if (!window.matchMedia("(max-width: 1080px)").matches) {
      railNav.classList.remove("has-left", "has-right");
      return;
    }
    const max = railNav.scrollWidth - railNav.clientWidth;
    railNav.classList.toggle("has-left", railNav.scrollLeft > 2);
    railNav.classList.toggle("has-right", railNav.scrollLeft < max - 2);
  }
  if (railNav) {
    railNav.addEventListener("scroll", updateNavMask, { passive: true });
    window.addEventListener("resize", updateNavMask);
  }

  const chapterLinks = $$("#railNav a");
  let activeChapterId = "cover";
  function setActiveChapter(id) {
    if (id === activeChapterId) return;
    activeChapterId = id;
    let activeLink = null;
    chapterLinks.forEach((link) => {
      const active = link.dataset.chapter === id;
      link.classList.toggle("active", active);
      if (active) {
        activeLink = link;
        link.setAttribute("aria-current", "location");
      } else {
        link.removeAttribute("aria-current");
      }
    });
    const nav = $("#railNav");
    const horizontal = window.matchMedia("(max-width: 1080px)").matches;
    if (horizontal && activeLink && nav && nav.scrollWidth > nav.clientWidth + 2) {
      const navRect = nav.getBoundingClientRect();
      const linkRect = activeLink.getBoundingClientRect();
      if (linkRect.left < navRect.left) nav.scrollLeft -= navRect.left - linkRect.left + 10;
      else if (linkRect.right > navRect.right) nav.scrollLeft += linkRect.right - navRect.right + 14;
      updateNavMask();
    }
  }
  if ("IntersectionObserver" in window) {
    const chapterObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => { if (entry.isIntersecting) setActiveChapter(entry.target.id); });
    }, { rootMargin: "-28% 0px -62% 0px", threshold: 0 });
    ["cover", "run", "method", "ledger", "coverage", "cases", "reproduce"].forEach((id) => {
      const node = document.getElementById(id);
      if (node) chapterObserver.observe(node);
    });
  }
  setActiveChapter("cover");
  if ("requestIdleCallback" in window) {
    window.requestIdleCallback(updateNavMask, { timeout: 700 });
  } else {
    window.setTimeout(updateNavMask, 0);
  }

  /* --------------------------------------------------------------- entrances */
  const revealNodes = $$("[data-reveal]");
  if (!reduce && "IntersectionObserver" in window) {
    const revealObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        entry.target.classList.add("in");
        if (entry.target.id === "scopePlate") initScope();
        if (entry.target.id === "pathStrip") updatePathSignalWidth();
        if (entry.target.id === "ledgerPanel") ensureLedger();
        revealObserver.unobserve(entry.target);
      });
    }, { threshold: 0.08, rootMargin: "0px 0px -6% 0px" });
    revealNodes.forEach((node) => revealObserver.observe(node));
  } else {
    revealNodes.forEach((node) => node.classList.add("in"));
    initScope();
    updatePathSignalWidth();
    ensureLedger();
  }

  /* -------------------------------------------------------------------- init */
  observeCounts();
  updateScroll();
  if ("requestIdleCallback" in window) {
    window.requestIdleCallback(ensureLedger, { timeout: 900 });
  } else {
    window.setTimeout(ensureLedger, 0);
  }

  if (errors.length) console.warn("Detection run reported errors:", errors);
})();

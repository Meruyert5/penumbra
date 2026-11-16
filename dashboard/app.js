(() => {
  "use strict";

  const DATA = JSON.parse(document.getElementById("penumbra-data").textContent);
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
    path: 0,
    selected: null
  };
  const desktopFloor = window.matchMedia("(min-width: 981px)");

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
  const THEME_COLOR = { corona: "#F6F4F1", umbra: "#0B0A09" };
  function normalizeTheme(value) {
    if (value === "umbra" || value === "totality" || value === "dark") return "umbra";
    if (value === "corona" || value === "light") return "corona";
    return "";
  }
  function setTheme(theme, instant) {
    const root = document.documentElement;
    if (instant) root.classList.add("no-transition");
    root.dataset.theme = theme;
    const isUmbra = theme === "umbra";
    themeLabel.textContent = isUmbra ? "Umbra / corona" : "Corona / umbra";
    themeButton.setAttribute("aria-label", isUmbra ? "Umbra / corona: switch to the Corona theme" : "Corona / umbra: switch to the Umbra theme");
    const coverMode = $("#coverMode");
    if (coverMode) coverMode.textContent = isUmbra ? "Umbra" : "Corona";
    const meta = $('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", THEME_COLOR[theme] || THEME_COLOR.corona);
    document.dispatchEvent(new CustomEvent("penumbra:theme", { detail: theme }));
    try { localStorage.setItem("penumbra-theme", theme); } catch (error) { /* file:// storage can be blocked */ }
    if (instant) {
      requestAnimationFrame(() => requestAnimationFrame(() => root.classList.remove("no-transition")));
    }
  }
  function toggleTheme() {
    const next = document.documentElement.dataset.theme === "umbra" ? "corona" : "umbra";
    if (!reduce && document.startViewTransition) {
      const rect = themeButton.getBoundingClientRect();
      const root = document.documentElement;
      root.style.setProperty("--tx", (rect.left + rect.width / 2) + "px");
      root.style.setProperty("--ty", (rect.top + rect.height / 2) + "px");
      document.startViewTransition(() => setTheme(next, true));
    } else {
      setTheme(next, true);
    }
  }
  const requestedTheme = normalizeTheme(params.get("theme"));
  let storedTheme = "";
  if (!requestedTheme) {
    try {
      storedTheme = normalizeTheme(
        localStorage.getItem("penumbra-theme") ||
        localStorage.getItem("umbra-theme") ||
        localStorage.getItem("sf-theme")
      );
    } catch (error) { storedTheme = ""; }
  }
  const prefersUmbra = window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches;
  setTheme(requestedTheme || storedTheme || (prefersUmbra ? "umbra" : "corona"));
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

  /* ------------------------------------------------------------- validation */
  const validationPanel = $("#validationPanel");
  const validation = DATA.validation;
  if (validationPanel && validation) {
    const totals = validation.totals || {};
    const stats = [
      [totals.real_events, "real events"],
      [totals.rules_matched, "rules matched"],
      [totals.alert_volume, "alert events"],
      [totals.labelled_samples, "labelled windows"],
      [totals.not_evaluable, "not evaluable"]
    ];
    $("#validationStats").innerHTML = stats.map(([value, label]) => (
      '<div class="validation-stat"><b>' + esc(number(value)) + "</b><span>" + esc(label) + "</span></div>"
    )).join("");

    const rules = validation.rules || [];
    $("#validationMatrix").innerHTML = rules.map((rule) => {
      const status = String(rule.status || "no_match").replace(/_/g, "-");
      const statusLabel = String(rule.status || "no_match").replace(/_/g, " ");
      return '<span class="validation-cell is-' + esc(status) + '" role="img" title="' +
        esc(rule.title) + " — " + esc(rule.reason) + '" aria-label="' +
        esc(rule.title + ": " + statusLabel + ". " + rule.reason) + '"></span>';
    }).join("");
    const matched = rules.filter((rule) => rule.status === "matched").length;
    const notEvaluable = rules.filter((rule) => rule.status === "not_evaluable").length;
    const falseNegative = rules.filter((rule) => rule.status === "false_negative").length;
    const noMatch = rules.filter((rule) => rule.status === "no_match").length;
    $("#validationCount").textContent = matched + " matched / " + falseNegative + " missed / " +
      noMatch + " no match / " + notEvaluable + " not evaluable";

    $("#validationSamples").innerHTML = (validation.samples || []).map((sample) => (
      '<div class="validation-sample"><div class="validation-sample-head"><span>' + esc(sample.name) +
      '</span><span class="validation-sample-kind">' + esc(sample.kind) + "</span></div>" +
      '<div class="validation-sample-stats"><span><b>' + esc(number(sample.events)) + "</b> events</span><span><b>" +
      esc(number(sample.matches)) + "</b> matches</span><span><b>" + esc(number(sample.correlations)) +
      "</b> correlations</span></div></div>"
    )).join("");

    const coverage = validation.coverage || validation.not_evaluable_breakdown || [];
    $("#validationBreakdown").innerHTML =
      "<h4>Coverage ledger</h4><ul>" +
      coverage.map((item) => (
        "<li><span>" + esc(item.reason) + " <small>" + esc(item.detail) + "</small></span><b>" + esc(number(item.count)) + "</b></li>"
      )).join("") +
      "</ul>";

    const fired = (validation.matched || []).concat(validation.missed || []);
    $("#validationRows").innerHTML = fired.map((row) => (
      "<tr" + (row.verdict === "FN" ? ' class="is-miss"' : "") + "><td>" + esc(row.title) + "</td><td>" + esc(row.level) +
      "</td><td>" + esc(row.technique) + "</td><td>" + esc(number(row.matches)) + "</td><td>" + esc(row.sample) +
      '</td><td class="v-verdict">' + esc(row.verdict) + "</td></tr>"
    )).join("");

    const benchmark = validation.benchmark || {};
    const benchmarkSummary = benchmark.summary || {};
    const benchmarkRows = benchmark.rules || [];
    const budget = (value) => value === null || value === undefined ? "–" : Number(value).toFixed(3);
    if (benchmarkRows.length) {
      $("#validationBenchmarkScore").textContent =
        (benchmarkSummary.tp || 0) + " TP · " + (benchmarkSummary.fp || 0) + " FP · " +
        (benchmarkSummary.fn || 0) + " FN · precision " + budget(benchmarkSummary.precision) +
        " · recall " + budget(benchmarkSummary.recall);
      const labelById = new Map((validation.labels || []).map((sample) => [sample.id, sample]));
      const detail = $("#validationBenchmarkDetail");
      const emptyDetail = '<p class="validation-detail-empty">Select a rule to see the labelled windows behind its counts.</p>';
      const renderDetail = (row) => {
        if (!row) {
          detail.innerHTML = emptyDetail;
          return;
        }
        const windows = (row.samples || []).map((result) => {
          const label = labelById.get(result.id) || {};
          const note = label.note ? '<p class="validation-detail-note">' + esc(label.note) + "</p>" : "";
          const expected = (label.expected_rules || []).length
            ? '<p class="validation-detail-expected">Expected: ' + esc(label.expected_rules.join(", ")) + "</p>"
            : '<p class="validation-detail-expected">Expected: no rule (coverage gap)</p>';
          return '<li class="is-' + esc(String(result.result || "").toLowerCase()) + '">' +
            "<b>" + esc(result.result || "") + "</b>" +
            "<span>" + esc(result.id || "") + "</span>" +
            "<small>" + esc(label.start || "") + " - " + esc(label.end || "") + "</small>" +
            note + expected + "</li>";
        }).join("");
        detail.innerHTML =
          '<div class="validation-detail-head"><b>' + esc(row.rule) + "</b>" +
          '<span class="validation-detail-level">' + esc(row.level || "") + "</span>" +
          '<span class="validation-detail-tech">' + esc(row.technique || "") + "</span></div>" +
          '<div class="validation-detail-metrics">' +
          "<span><b>" + esc(number(row.tp)) + "</b> TP</span>" +
          "<span><b>" + esc(number(row.fp)) + "</b> FP</span>" +
          "<span><b>" + esc(number(row.fn)) + "</b> FN</span>" +
          "<span><b>" + esc(budget(row.precision)) + "</b> precision</span>" +
          "<span><b>" + esc(budget(row.recall)) + "</b> recall</span>" +
          "<span><b>" + esc(number(row.alert_volume)) + "</b> " +
          (Number(row.alert_volume) === 1 ? "alert" : "alerts") + "</span></div>" +
          '<ul class="validation-detail-windows">' + windows + "</ul>";
      };

      $("#validationBenchmarkRows").innerHTML = benchmarkRows.map((row, index) => (
        "<tr" + (Number(row.fn) > 0 ? ' class="is-miss"' : "") + "><td>" +
        '<button type="button" class="validation-rule-button" data-index="' + index +
        '" aria-expanded="false" aria-controls="validationBenchmarkDetail">' + esc(row.rule) + "</button></td>" +
        "<td>" + esc(number(row.tp)) + "</td><td>" + esc(number(row.fp)) + "</td><td>" +
        esc(number(row.fn)) + "</td><td>" + esc(budget(row.precision)) + "</td><td>" +
        esc(budget(row.recall)) + "</td><td>" + esc(number(row.alert_volume)) + "</td></tr>"
      )).join("");
      detail.innerHTML = emptyDetail;
      const buttons = Array.from(document.querySelectorAll("#validationBenchmarkRows .validation-rule-button"));
      buttons.forEach((button) => {
        button.addEventListener("click", () => {
          const index = Number(button.dataset.index);
          const wasOpen = button.getAttribute("aria-expanded") === "true";
          buttons.forEach((item) => {
            item.setAttribute("aria-expanded", "false");
            const parent = item.closest("tr");
            if (parent) parent.classList.remove("is-open");
          });
          if (wasOpen) {
            renderDetail(null);
            return;
          }
          button.setAttribute("aria-expanded", "true");
          const parent = button.closest("tr");
          if (parent) parent.classList.add("is-open");
          renderDetail(benchmarkRows[index]);
        });
      });
      $("#validationBenchmarkNote").textContent = (benchmark.note || "") +
        " Alert volume is the exact count from the compiled KQL query, not the 100-event EQL sample cap.";
    } else {
      $("#validationBenchmark").hidden = true;
    }

    const provenance = validation.provenance || {};
    const realSamples = (validation.samples || []).filter((sample) => sample.kind === "real");
    const sources = provenance.sources || [];
    const sourceRows = sources.length
      ? sources.map((source) => (
        '<div class="validation-proof-row"><span>' + esc(source.name) + " — " + esc(source.detail) + "</span>" +
        '<span class="validation-proof-links"><a href="' + esc(source.url || "#") +
        '" target="_blank" rel="noreferrer">source</a></span></div>'
      )).join("")
      : realSamples.map((sample) => (
        '<div class="validation-proof-row"><span>' + esc(sample.name) + " · " + esc(number(sample.events)) +
        " events · " + esc(sample.window || "") + " · " + esc(number(sample.matches)) + " matches</span>" +
        '<span class="validation-proof-links"><a href="' + esc(sample.source_url || "#") +
        '" target="_blank" rel="noreferrer">source</a><code>' + esc(sample.git_blob_sha || "") +
        "</code><span>" + esc(number(sample.archive_bytes)) + " bytes</span></span></div>"
      )).join("");
    $("#validationProofBody").innerHTML =
      "<p><b>Engine:</b> " + esc(provenance.engine || "Elasticsearch") +
      ". <b>Parser:</b> " + esc(provenance.parser || "pipeline.replay") +
      ". <b>Raw data committed:</b> " + (provenance.raw_data_committed ? "yes" : "no") + ".</p>" +
      "<p>" + esc(provenance.note || "") + "</p>" +
      "<p><b>Metrics engine:</b> <code>pipeline.benchmark</code> computed TP/FP/FN, precision, recall, and alert volume from the reviewed labels manifest.</p>" +
      '<div class="validation-proof-samples">' + sourceRows + "</div>" +
      '<pre class="validation-commands"><code>' + esc((provenance.commands || []).join("\n")) + "</code></pre>" +
      '<div class="validation-fixes"><b>How to close the gaps</b><ul>' +
      (validation.gaps || []).map((gap) => (
        "<li>" + esc(gap.reason) + " (" + esc(number(gap.count)) + "): " + esc(gap.fix) + "</li>"
      )).join("") +
      "</ul></div>" +
      '<div class="validation-proof-foot"><a class="validation-download" href="validation/results.json" download>Download results.json</a>' +
      '<span>' + esc(validation.generated || "") + " · " + esc(provenance.rules || 50) + " rules · " +
      esc(provenance.correlations || 8) + " correlations</span></div>";

    $("#validationAllRows").innerHTML = rules.map((rule) => (
      "<tr><td>" + esc(rule.title) + "</td><td>" + esc(rule.level) + "</td><td>" +
      esc(String(rule.status || "").replace(/_/g, " ")) + "</td><td>" + esc(rule.reason) + "</td></tr>"
    )).join("");
  } else if (validationPanel) {
    validationPanel.hidden = true;
  }

  /* ------------------------------------------------------------- hunts */
  const huntsPanel = $("#huntsPanel");
  const hunts = DATA.hunts;
  if (huntsPanel && hunts && (hunts.hunts || []).length) {
    const summary = hunts.summary || {};
    $("#huntsStats").innerHTML = [
      [summary.hunts, "hunts"],
      [summary.events_reviewed, "events reviewed"],
      [summary.findings, "hunts with findings"],
      [summary.confirmed, "confirmed true positives"]
    ].map(([value, label]) => (
      '<div class="validation-stat"><b>' + esc(number(value)) + "</b><span>" + esc(label) + "</span></div>"
    )).join("");

    $("#huntGrid").innerHTML = hunts.hunts.map((hunt) => {
      const verdict = hunt.verdict === "true_positive" ? "True positive" : "No finding";
      const evidence = (hunt.evidence || []).slice(0, 8).map((row) => (
        "<tr><td>" + esc(row.time || "") + "</td><td>" + esc(row.host || "") + "</td><td>" +
        esc(row.user || "") + "</td><td>" + esc(row.source || "") + "</td><td>" +
        esc(row.detail || "") + "</td></tr>"
      )).join("");
      return '<article class="hunt-card ' + (hunt.verdict === "true_positive" ? "is-positive" : "is-empty") + '">' +
        '<div class="hunt-card-head"><span class="hunt-id">' + esc(hunt.id) + "</span>" +
        '<span class="hunt-verdict">' + esc(verdict) + "</span></div>" +
        "<h4>" + esc(hunt.title) + "</h4>" +
        '<p class="hunt-hypothesis">' + esc(hunt.hypothesis) + "</p>" +
        '<p class="hunt-finding">' + esc(hunt.finding) + "</p>" +
        '<div class="hunt-meta"><span><b>' + esc(number(hunt.event_count)) + "</b> events</span>" +
        "<span>" + esc(hunt.first_seen || "") + " → " + esc(hunt.last_seen || "") + "</span>" +
        "<span>" + esc(hunt.confidence || "") + " confidence</span></div>" +
        '<details class="hunt-evidence"><summary>Query, evidence, and detection change</summary>' +
        '<p class="hunt-label">Query</p><pre class="hunt-query"><code>' + esc(hunt.query) + "</code></pre>" +
        '<p class="hunt-label">Detection change</p><p class="hunt-copy">' + esc(hunt.detection_change) + "</p>" +
        '<p class="hunt-label">Limitations</p><p class="hunt-copy">' + esc(hunt.limitations) + "</p>" +
        (evidence ? '<div class="validation-table-wrap"><table class="validation-table hunt-table"><thead><tr><th>Time</th><th>Host</th><th>User</th><th>Source</th><th>Detail</th></tr></thead><tbody>' + evidence + "</tbody></table></div>" : "") +
        "</details></article>";
    }).join("");
    $("#huntsNote").innerHTML = "Hunts read the same deterministic corpus as the dashboard. Full reports: " +
      '<a href="https://github.com/Meruyert5/penumbra/blob/main/hunts/README.md" target="_blank" rel="noreferrer">hunts/README.md</a>.';
  } else if (huntsPanel) {
    huntsPanel.hidden = true;
  }

  /* ------------------------------------------------------------- operations */
  const opsPanel = $("#opsPanel");
  const response = DATA.response;
  const cloudPack = DATA.cloud_pack;
  const ir = DATA.ir;
  if (opsPanel && (response || cloudPack || ir)) {
    const tabs = Array.from(document.querySelectorAll(".ops-tab"));
    const views = tabs.map((tab) => document.getElementById(tab.getAttribute("aria-controls")));
    const activate = (index) => {
      tabs.forEach((tab, position) => {
        const selected = position === index;
        tab.setAttribute("aria-selected", String(selected));
        tab.tabIndex = selected ? 0 : -1;
        views[position].hidden = !selected;
      });
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener("click", () => activate(index));
      tab.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
        event.preventDefault();
        const step = event.key === "ArrowRight" ? 1 : -1;
        const next = (index + step + tabs.length) % tabs.length;
        tabs[next].focus();
        activate(next);
      });
    });
    activate(0);

    if (response) {
      const summary = response.summary || {};
      $("#opsResponseStats").innerHTML = [
        [summary.alerts_ingested, "alerts ingested"],
        [summary.incidents, "incidents"],
        [summary.actions, "recommended actions"],
        [Number(summary.containment_coverage || 0) * 100, "containment coverage", true]
      ].map(([value, label, percent]) => (
        '<div class="validation-stat"><b>' + esc(percent ? number(Math.round(value)) + "%" : number(value)) +
        "</b><span>" + esc(label) + "</span></div>"
      )).join("");
      $("#opsIncidents").innerHTML = (response.incidents || []).map((incident) => {
        const alerts = (incident.alerts || []).map((alert) => (
          "<li><b>" + esc(alert.level) + "</b> " + esc(alert.title) +
          " <small>" + esc((alert.techniques || []).join(", ")) + "</small></li>"
        )).join("");
        const actions = (incident.actions || []).map((action) => (
          "<li><code>" + esc(action.action) + "</code> <small>" + esc(action.reason) + "</small></li>"
        )).join("");
        return '<article class="ops-card is-' + esc(incident.highest_level) + '">' +
          '<div class="ops-card-head"><span class="ops-id">' + esc(incident.id) + "</span>" +
          '<span class="ops-chip">' + esc(incident.highest_level) + "</span></div>" +
          "<h4>" + esc(incident.host) + "</h4>" +
          '<div class="ops-metrics"><span><b>' + esc(number(incident.alert_count)) + "</b> alerts</span>" +
          "<span><b>" + esc(number((incident.actions || []).length)) + "</b> actions</span>" +
          "<span>" + esc(incident.window_start || "") + "</span></div>" +
          '<p class="ops-playbooks">' + esc((incident.playbooks || []).join(" · ")) + "</p>" +
          '<details class="ops-details"><summary>Alerts and actions</summary>' +
          '<p class="hunt-label">Alerts</p><ul class="ops-list">' + alerts + "</ul>" +
          '<p class="hunt-label">Recommended actions</p><ul class="ops-list ops-actions">' + actions + "</ul>" +
          "</details></article>";
      }).join("");
    }

    if (cloudPack) {
      const summary = cloudPack.summary || {};
      $("#opsCloudStats").innerHTML = [
        [summary.detections, "detections"],
        [summary.fired, "fired"],
        [summary.events, "matched events"],
        [summary.not_exercised, "not exercised"]
      ].map(([value, label]) => (
        '<div class="validation-stat"><b>' + esc(number(value)) + "</b><span>" + esc(label) + "</span></div>"
      )).join("");
      $("#opsCloudCards").innerHTML = (cloudPack.detections || []).map((detection) => {
        const evidence = (detection.evidence || []).slice(0, 8).map((row) => (
          "<tr><td>" + esc(row.time || "") + "</td><td>" + esc(row.user || "") + "</td><td>" +
          esc(row.source || "") + "</td><td>" + esc(row.detail || "") + "</td></tr>"
        )).join("");
        return '<article class="ops-card is-' + (detection.status === "fired" ? "critical" : "empty") + '">' +
          '<div class="ops-card-head"><span class="ops-id">' + esc(detection.id) + "</span>" +
          '<span class="ops-chip">' + esc(detection.status) + "</span></div>" +
          "<h4>" + esc(detection.title) + "</h4>" +
          '<div class="ops-metrics"><span><b>' + esc(number(detection.event_count)) + "</b> events</span>" +
          "<span>" + esc(detection.technique) + "</span><span>" + esc(detection.level) + "</span></div>" +
          '<p class="ops-copy">' + esc(detection.description) + "</p>" +
          '<details class="ops-details"><summary>Query and evidence</summary>' +
          '<pre class="hunt-query"><code>' + esc(detection.query) + "</code></pre>" +
          '<p class="hunt-label">Response hand-off</p><p class="ops-copy">' + esc(detection.detection_change) + "</p>" +
          (evidence ? '<div class="validation-table-wrap"><table class="validation-table hunt-table"><thead><tr><th>Time</th><th>User</th><th>Source</th><th>Detail</th></tr></thead><tbody>' + evidence + "</tbody></table></div>" : "") +
          "</details></article>";
      }).join("");
    }

    if (ir) {
      $("#opsIrCards").innerHTML = (ir.cases || []).map((item) => {
        const metrics = item.metrics || {};
        return '<article class="ops-card ops-case is-' + esc(item.severity) + '">' +
          '<div class="ops-card-head"><span class="ops-id">' + esc(item.id) + "</span>" +
          '<span class="ops-chip">' + esc(item.verdict) + "</span></div>" +
          "<h4>" + esc(item.slug) + "</h4>" +
          '<p class="ops-copy">' + esc(item.containment_status) + "</p>" +
          '<div class="ops-metrics"><span><b>' + esc(number(metrics.observed_seconds)) + "</b> observed seconds</span>" +
          "<span><b>" + esc(number(metrics.alert_count)) + "</b> alerts</span>" +
          "<span><b>" + esc(number(metrics.detection_span_seconds)) + "</b> detection seconds</span></div>" +
          '<p class="ops-case-links"><a href="cases/' + esc(item.slug) + '/report.md">Report</a>' +
          '<a href="cases/IR.md">Close-out</a></p></article>';
      }).join("");
    }

    $("#opsNote").innerHTML = "Dry-run response: no EDR, cloud, or ticketing API was called. " +
      'Full data: <a href="https://github.com/Meruyert5/penumbra/blob/main/response/README.md" target="_blank" rel="noreferrer">response</a>, ' +
      '<a href="https://github.com/Meruyert5/penumbra/blob/main/cloud/README.md" target="_blank" rel="noreferrer">cloud pack</a>, ' +
      '<a href="https://github.com/Meruyert5/penumbra/blob/main/cases/IR.md" target="_blank" rel="noreferrer">IR casebook</a>.';
  } else if (opsPanel) {
    opsPanel.hidden = true;
  }

  /* ------------------------------------------------------------- roadmap */
  const roadmapPanel = $("#roadmapPanel");
  const roadmap = DATA.roadmap;
  if (roadmapPanel && roadmap && (roadmap.projects || []).length) {
    $("#roadmapKicker").textContent = roadmap.kicker || "Portfolio roadmap";
    $("#roadmapTitle").textContent = roadmap.title || "Three complete projects, no connector.";
    $("#roadmapIntro").innerHTML = esc(roadmap.intro || "") +
      ' <a class="roadmap-link" href="https://github.com/Meruyert5/penumbra/blob/main/docs/roadmap.md" target="_blank" rel="noreferrer">Read the full roadmap</a>.';
    $("#roadmapProjects").innerHTML = roadmap.projects.map((project) => {
      const modules = (project.modules || []).map((module) => (
        '<li><span class="roadmap-module-name">' + esc(module.name) + "</span>" +
        '<span class="roadmap-state is-' + esc(module.state) + '">' + esc(module.state) + "</span>" +
        "<small>" + esc(module.detail) + "</small></li>"
      )).join("");
      return '<article class="roadmap-card is-' + esc(project.status) + '">' +
        '<div class="roadmap-card-head"><div><p class="roadmap-role">' + esc(project.role) + "</p>" +
        "<h4>" + esc(project.name) + "</h4>" +
        (project.former_name ? '<span class="roadmap-former">formerly ' + esc(project.former_name) + "</span>" : "") +
        '</div><span class="roadmap-status">' + esc(project.status) + "</span></div>" +
        '<p class="roadmap-thesis">' + esc(project.thesis) + "</p>" +
        '<ul class="roadmap-modules">' + modules + "</ul>" +
        '<p class="roadmap-done"><b>Done means</b> ' + esc(project.done) + "</p></article>";
    }).join("");
    $("#roadmapSequence").innerHTML = (roadmap.sequence || []).map((item) => "<li>" + esc(item) + "</li>").join("");
    $("#roadmapPrinciples").innerHTML = (roadmap.principles || []).map((item) => "<li>" + esc(item) + "</li>").join("");
    $("#roadmapShared").innerHTML = (roadmap.shared || []).map((item) => (
      "<li><b>" + esc(item.name) + "</b><span>" + esc(item.detail) + "</span></li>"
    )).join("");
  } else if (roadmapPanel) {
    roadmapPanel.hidden = true;
  }

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

  /* Catmull-Rom to cubic Bezier: the envelope reads as a signal, not a stencil. */
  function smoothSvg(list) {
    if (!list.length) return "";
    let d = "M" + list[0][0].toFixed(1) + " " + list[0][1].toFixed(1);
    for (let i = 0; i < list.length - 1; i++) {
      const p0 = list[i === 0 ? 0 : i - 1];
      const p1 = list[i];
      const p2 = list[i + 1];
      const p3 = list[i + 2] || p2;
      // Clamp control heights to the segment so the curve never overshoots a data point.
      const lo = Math.min(p1[1], p2[1]);
      const hi = Math.max(p1[1], p2[1]);
      const c1y = Math.min(hi, Math.max(lo, p1[1] + (p2[1] - p0[1]) / 6));
      const c2y = Math.min(hi, Math.max(lo, p2[1] - (p3[1] - p1[1]) / 6));
      d += " C" +
        (p1[0] + (p2[0] - p0[0]) / 6).toFixed(1) + " " + c1y.toFixed(1) + "," +
        (p2[0] - (p3[0] - p1[0]) / 6).toFixed(1) + " " + c2y.toFixed(1) + "," +
        p2[0].toFixed(1) + " " + p2[1].toFixed(1);
    }
    return d;
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
      '<div class="ro-note">The chart counts matched events. The watch floor groups them into detections.</div>' +
      '<button class="mini ro-btn" type="button" data-hour="' + esc(row.hour) + '">Open the watch floor at this hour</button>'
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
      '<div class="ro-note">The chart counts matched events. The watch floor groups them into detections.</div>' +
      '<div class="ro-note">Hover or tap a column to inspect it. Click to pin the hour.</div>' +
      '<button class="mini ro-btn" type="button" data-hour="' + esc(row.hour) + '">Open the watch floor at this hour</button>';
    $("#scopeHint").textContent = "peak " + number(row.total) + " events at " + row.hour.slice(11, 16) + "Z";
  }

  function openHourInLedger(hour) {
    state.pinnedHour = hour;
    state.hour = hour;
    state.level = "all";
    state.q = "";
    const search = $("#search");
    if (search) search.value = "";
    paintLevelChips();
    const index = timeline.findIndex((row) => row.hour === hour);
    initScope();
    if (index >= 0 && geometry) paintHour(index, true);
    else paintDefault();
    switchTab("detections");
    renderLedger();
    goTo("#ledger");
    const row = index >= 0 ? timeline[index] : null;
    toast("Pinned " + hour.slice(11, 16) + "Z" + (row ? " / " + unit(row.total, "event", "events") + " in the hour" : ""));
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
      timeline[peakIndex].hour.slice(11, 16) + "Z, with shadow bands between the bursts.";
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

    // The envelope joins the hourly totals into one signal behind the stacked bars.
    const envelopePoints = timeline.map((row, index) => [x(index), y(Number(row.total || 0))]);
    const envelopeD = smoothSvg(envelopePoints);
    const baseline = height - bottom;
    chart.appendChild(svgNode("path", {
      class: "chart-envelope-fill",
      d: envelopeD + " L" + envelopePoints[envelopePoints.length - 1][0].toFixed(1) + " " + baseline +
        " L" + envelopePoints[0][0].toFixed(1) + " " + baseline + " Z"
    }));
    chart.appendChild(svgNode("path", { class: "chart-envelope", d: envelopeD, pathLength: "1" }));
    chart.appendChild(svgNode("line", {
      class: "chart-quiet-line",
      x1: left,
      y1: y(Math.min(3, max)),
      x2: width - right,
      y2: y(Math.min(3, max))
    }));

    const focus = svgNode("rect", { id: "chartFocus", class: "col-focus", y: top, height: plotH, x: left, width: step });
    chart.appendChild(focus);

    const stemDefs = svgNode("defs");
    chart.appendChild(stemDefs);

    timeline.forEach((row, index) => {
      const total = Number(row.total || 0);
      const stem = svgNode("g", { class: "stem" });
      stem.style.setProperty("--stem-delay", (index * 38) + "ms");
      if (total > 0) {
        const base = height - bottom;
        const topY = y(total);
        const x0 = x(index) - barWidth / 2;
        const x1 = x(index) + barWidth / 2;
        const radius = Math.min(4, barWidth / 2);
        const clipId = "stem-clip-" + index;
        const clip = svgNode("clipPath", { id: clipId });
        clip.appendChild(svgNode("path", {
          d: "M" + x0.toFixed(1) + " " + base.toFixed(1) +
            " L" + x0.toFixed(1) + " " + (topY + radius).toFixed(1) +
            " Q" + x0.toFixed(1) + " " + topY.toFixed(1) + " " + (x0 + radius).toFixed(1) + " " + topY.toFixed(1) +
            " L" + (x1 - radius).toFixed(1) + " " + topY.toFixed(1) +
            " Q" + x1.toFixed(1) + " " + topY.toFixed(1) + " " + x1.toFixed(1) + " " + (topY + radius).toFixed(1) +
            " L" + x1.toFixed(1) + " " + base.toFixed(1) + " Z"
        }));
        stemDefs.appendChild(clip);
        const clipped = svgNode("g", { class: "stem-clip", "clip-path": "url(#" + clipId + ")" });
        let baseY = base;
        ["low", "medium", "high", "critical"].forEach((level) => {
          const value = Number(row[level] || 0);
          if (!value) return;
          const segHeight = (value / max) * plotH;
          const rect = svgNode("rect", {
            class: "seg-" + level,
            x: x0.toFixed(1),
            y: (baseY - segHeight).toFixed(1),
            width: barWidth.toFixed(1),
            height: Math.max(0.8, segHeight).toFixed(1)
          });
          clipped.appendChild(rect);
          baseY -= segHeight;
        });
        stem.appendChild(clipped);
        stem.appendChild(svgNode("path", {
          class: "stem-cap",
          d: "M" + x0.toFixed(1) + " " + (topY + radius).toFixed(1) +
            " Q" + x0.toFixed(1) + " " + topY.toFixed(1) + " " + (x0 + radius).toFixed(1) + " " + topY.toFixed(1) +
            " L" + (x1 - radius).toFixed(1) + " " + topY.toFixed(1) +
            " Q" + x1.toFixed(1) + " " + topY.toFixed(1) + " " + x1.toFixed(1) + " " + (topY + radius).toFixed(1)
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

    // The quiet stretches are the baseline. Label the longest one instead of
    // bracketing every scattered low hour across a multi-burst window.
    const quietRuns = [];
    let quietRun = [];
    timeline.forEach((row, index) => {
      if (Number(row.total) <= 3) {
        quietRun.push({ row, index });
      } else if (quietRun.length) {
        quietRuns.push(quietRun);
        quietRun = [];
      }
    });
    if (quietRun.length) quietRuns.push(quietRun);
    const longestQuiet = quietRuns.sort((a, b) => b.length - a.length)[0];
    if (longestQuiet && longestQuiet.length) {
      const bracket = svgNode("g", { class: "quiet-bracket-group" });
      const bx1 = x(longestQuiet[0].index) - 12;
      const bx2 = x(longestQuiet[longestQuiet.length - 1].index) + 12;
      const by = top + 8;
      bracket.appendChild(svgNode("path", {
        class: "quiet-bracket",
        d: "M" + bx1.toFixed(1) + " " + (by + 6) + " V" + by + " H" + bx2.toFixed(1) + " V" + (by + 6)
      }));
      const label = svgNode("text", { class: "quiet-label", x: bx1.toFixed(1), y: by + 18 });
      label.textContent = "SHADOW BANDS";
      bracket.appendChild(label);
      const count = svgNode("text", { class: "quiet-label", x: bx1.toFixed(1), y: by + 28 });
      count.textContent = longestQuiet.length + " HOURS / 3 EVENTS";
      bracket.appendChild(count);
      chart.appendChild(bracket);
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
    const showEvery = timeline.length > 14
      ? (width < 430 ? 8 : width < 620 ? 6 : 3)
      : (width < 560 ? 2 : 1);
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
    const firstDay = timeline.length ? timeline[0].hour.slice(8, 10) : "";
    const lastDay = timeline.length ? timeline[timeline.length - 1].hour.slice(8, 10) : "";
    axisNote.textContent = firstDay && lastDay && firstDay !== lastDay
      ? "hour / UTC / " + firstDay + "–" + lastDay + " Nov"
      : "hour / UTC";
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

  /* The contact ribbon is a control: each phase pins its nearest hour, and
     "play the eclipse" walks the contacts without scrolling the page. */
  const phaseSteps = $$(".phase-step");
  const phasePlay = $("#phasePlay");
  const heroPlate = $(".totality-plate");
  const heroPhaseLabel = $("#heroPhase");
  const railPhaseLabel = $("#railPhase");
  const heroPhaseNames = ["first contact", "second contact", "totality", "third contact", "fourth contact"];
  function setHeroPhase(index) {
    if (!heroPlate) return;
    const n = Math.max(0, Math.min(4, Number(index) || 0));
    const contact = n === 1 || n === 3;
    heroPlate.style.setProperty("--phase", String(n));
    heroPlate.style.setProperty("--corona", n === 2 ? "1" : "0.45");
    heroPlate.style.setProperty("--beads", contact ? "1" : "0");
    heroPlate.style.setProperty("--diamond", contact ? "1" : "0.35");
    if (heroPhaseLabel) heroPhaseLabel.textContent = heroPhaseNames[n];
    if (railPhaseLabel) railPhaseLabel.textContent = heroPhaseNames[n];
  }
  setHeroPhase(2);
  let phaseTimer = 0;
  let phaseIndex = 0;
  const phasePlayIcon = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg>';
  const phaseStopIcon = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 5h4v14H7zM13 5h4v14h-4z"/></svg>';
  function stopPhasePlay(clear) {
    if (phaseTimer) window.clearInterval(phaseTimer);
    phaseTimer = 0;
    phaseIndex = 0;
    if (phasePlay) {
      phasePlay.classList.remove("is-running");
      phasePlay.setAttribute("aria-pressed", "false");
      phasePlay.innerHTML = phasePlayIcon + " play the eclipse";
    }
    if (clear) phaseSteps.forEach((step) => step.classList.remove("is-active"));
  }
  if (phaseSteps.length && timeline.length) {
    const phaseTotals = timeline.map((row) => Number(row.total || 0));
    const phasePeak = phaseTotals.indexOf(Math.max(...phaseTotals));
    function activatePhase(step, scroll) {
      if (!step) return;
      const offset = Number(step.dataset.phaseOffset || 0);
      const index = Math.max(0, Math.min(timeline.length - 1, phasePeak + offset));
      setHeroPhase(phaseSteps.indexOf(step));
      state.pinnedHour = timeline[index].hour;
      initScope();
      paintHour(index, true);
      phaseSteps.forEach((node) => node.classList.toggle("is-active", node === step));
      if (scroll) $("#run").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      toast("Pinned " + timeline[index].hour.slice(11, 16) + "Z / " + step.dataset.phaseName);
    }
    phaseSteps.forEach((step) => {
      step.addEventListener("click", () => {
        stopPhasePlay(true);
        activatePhase(step, true);
      });
    });
    if (phasePlay) {
      phasePlay.addEventListener("click", () => {
        if (phaseTimer) { stopPhasePlay(true); return; }
        phaseIndex = 0;
        phasePlay.classList.add("is-running");
        phasePlay.setAttribute("aria-pressed", "true");
        phasePlay.innerHTML = phaseStopIcon + " stop the eclipse";
        const tick = () => {
          if (phaseIndex >= phaseSteps.length) { stopPhasePlay(false); return; }
          activatePhase(phaseSteps[phaseIndex], false);
          phaseIndex++;
        };
        tick();
        phaseTimer = window.setInterval(tick, 1100);
      });
    }
  }

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

  /* ----------------------------------------------------------- hero starfield
     A light dust field and rare shooting star behind the cover. It pauses
     offscreen, settles under reduced motion, and never intercepts a pointer. */
  const heroSky = $("#heroSky");
  const heroCover = $("#cover");
  if (heroSky && heroCover) {
    const skyCtx = heroSky.getContext("2d");
    let skyW = 0;
    let skyH = 0;
    let skyDpr = 1;
    let stars = [];
    let dust = [];
    let skyRaf = 0;
    let skyRunning = false;
    let skyLast = 0;
    const skyBorn = performance.now();
    const skyPointer = { x: 0.5, y: 0.5, tx: 0.5, ty: 0.5 };
    function seedSky() {
      const count = Math.round(Math.min(150, Math.max(54, skyW * skyH / 9000)));
      stars = Array.from({ length: count }, () => ({
        x: Math.random() * skyW,
        y: Math.random() * skyH,
        r: Math.random() * 1.2 + 0.25,
        a: Math.random() * 0.55 + 0.12,
        s: Math.random() * 0.9 + 0.25,
        p: Math.random() * Math.PI * 2
      }));
      dust = Array.from({ length: 5 }, () => ({
        x: Math.random() * skyW,
        y: Math.random() * skyH,
        r: Math.random() * 22 + 10,
        a: Math.random() * 0.05 + 0.02
      }));
    }
    function resizeSky() {
      const rect = heroCover.getBoundingClientRect();
      skyW = Math.max(1, Math.round(rect.width));
      skyH = Math.max(1, Math.round(rect.height));
      skyDpr = Math.min(2, window.devicePixelRatio || 1);
      heroSky.width = Math.round(skyW * skyDpr);
      heroSky.height = Math.round(skyH * skyDpr);
      heroSky.style.width = skyW + "px";
      heroSky.style.height = skyH + "px";
      skyCtx.setTransform(skyDpr, 0, 0, skyDpr, 0, 0);
      seedSky();
      if (!skyRunning) drawSky(performance.now());
    }
    function drawSky(now) {
      const t = (now - skyBorn) / 1000;
      skyCtx.clearRect(0, 0, skyW, skyH);
      dust.forEach((d) => {
        const glow = skyCtx.createRadialGradient(d.x, d.y, 0, d.x, d.y, d.r);
        glow.addColorStop(0, "rgba(248, 143, 34, " + d.a + ")");
        glow.addColorStop(1, "rgba(248, 143, 34, 0)");
        skyCtx.fillStyle = glow;
        skyCtx.beginPath();
        skyCtx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
        skyCtx.fill();
      });
      skyPointer.x += (skyPointer.tx - skyPointer.x) * 0.04;
      skyPointer.y += (skyPointer.ty - skyPointer.y) * 0.04;
      const ox = (skyPointer.x - 0.5) * 14;
      const oy = (skyPointer.y - 0.5) * 10;
      stars.forEach((s) => {
        const twinkle = reduce ? 1 : 0.72 + 0.28 * Math.sin(t * s.s + s.p);
        skyCtx.globalAlpha = s.a * twinkle;
        skyCtx.fillStyle = "#FFE3B3";
        skyCtx.beginPath();
        skyCtx.arc(s.x + ox * s.s, s.y + oy * s.s, s.r, 0, Math.PI * 2);
        skyCtx.fill();
      });
      skyCtx.globalAlpha = 1;
      if (!reduce) {
        const period = 9;
        const local = (t % period) / period;
        if (local < 0.18) {
          const k = local / 0.18;
          const sx = skyW * (0.12 + k * 0.28);
          const sy = skyH * (0.18 + k * 0.08);
          const grad = skyCtx.createLinearGradient(sx, sy, sx + 70, sy + 32);
          grad.addColorStop(0, "rgba(255, 227, 179, 0)");
          grad.addColorStop(0.6, "rgba(255, 227, 179, 0.7)");
          grad.addColorStop(1, "rgba(255, 227, 179, 0)");
          skyCtx.strokeStyle = grad;
          skyCtx.lineWidth = 1;
          skyCtx.beginPath();
          skyCtx.moveTo(sx, sy);
          skyCtx.lineTo(sx + 70, sy + 32);
          skyCtx.stroke();
        }
      }
    }
    function skyFrame(now) {
      if (!skyRunning) return;
      if (now - skyLast > 1000 / 30) {
        drawSky(now);
        skyLast = now;
      }
      skyRaf = requestAnimationFrame(skyFrame);
    }
    function startSky() {
      if (reduce || skyRunning || document.hidden) return;
      skyRunning = true;
      skyRaf = requestAnimationFrame(skyFrame);
    }
    function stopSky() {
      skyRunning = false;
      cancelAnimationFrame(skyRaf);
    }
    resizeSky();
    window.addEventListener("resize", resizeSky);
    heroCover.addEventListener("pointermove", (event) => {
      const rect = heroCover.getBoundingClientRect();
      skyPointer.tx = Math.max(0, Math.min(1, (event.clientX - rect.left) / rect.width));
      skyPointer.ty = Math.max(0, Math.min(1, (event.clientY - rect.top) / rect.height));
    });
    heroCover.addEventListener("pointerleave", () => {
      skyPointer.tx = 0.5;
      skyPointer.ty = 0.5;
    });
    const skyObserver = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) startSky(); else stopSky();
      });
    }, { threshold: 0.02 });
    skyObserver.observe(heroCover);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stopSky(); else startSky();
    });
    if (reduce) drawSky(performance.now());
  }

  /* The ghost wordmark lags the scroll, so the night stage has depth. */
  const heroGhost = $(".cover-ghost");
  if (heroGhost && !reduce) {
    let ghostTick = 0;
    const moveGhost = () => {
      const y = Math.min(90, Math.max(0, window.scrollY * 0.14));
      heroGhost.style.transform = "translate(-50%, " + y.toFixed(1) + "px)";
      ghostTick = 0;
    };
    window.addEventListener("scroll", () => {
      if (!ghostTick) ghostTick = requestAnimationFrame(moveGhost);
    }, { passive: true });
  }

  /* ------------------------------------------------------- pinned totality act
     Native scroll is the source of truth. The stage is sticky; one normalized
     progress value drives the moon, corona, Baily's beads, diamond ring, copy,
     and the progress rail. Reduced motion gets the static totality frame. */
  const totalityAct = $("#totalityAct");
  if (totalityAct) {
    const taPhase = $("#taPhase");
    const taHint = $("#taHint");
    const taProgress = $("#taProgress");
    const taWords = ["First contact", "Baily's beads", "Second contact", "Totality", "Third contact", "Fourth contact"];
    let taTick = 0;
    let taWordIndex = -1;

    /* The act is not decoration: it reports the run's peak hour and opens it. */
    const taPeak = timeline.reduce(
      (best, row) => (best === null || Number(row.total) > Number(best.total) ? row : best),
      null
    );
    if (taPeak) {
      const taActive = activeCounts(taPeak.hour);
      const taPeakTime = $("#taPeakTime");
      if (taPeakTime) taPeakTime.textContent = taPeak.hour.slice(11, 16) + "Z";
      const taValues = {
        "#taEvents": taPeak.total,
        "#taDetections": taActive.detections,
        "#taCorrelations": taActive.correlations,
        "#taCritical": taPeak.critical
      };
      Object.entries(taValues).forEach(([selector, value]) => {
        const node = $(selector);
        if (node) node.textContent = number(value);
      });
      const taLabels = {
        "#taEventsLabel": taPeak.total === 1 ? "event" : "events",
        "#taDetectionsLabel": taActive.detections === 1 ? "detection" : "detections",
        "#taCorrelationsLabel": taActive.correlations === 1 ? "correlation" : "correlations",
        "#taCriticalLabel": "critical"
      };
      Object.entries(taLabels).forEach(([selector, value]) => {
        const node = $(selector);
        if (node) node.textContent = value;
      });
      const taOpen = $("#taOpen");
      if (taOpen) {
        taOpen.textContent = "Open " + taPeak.hour.slice(11, 16) + "Z in the watch floor";
        taOpen.addEventListener("click", () => openHourInLedger(taPeak.hour));
      }
    }
    function renderTotality(value) {
      const t = Math.min(1, Math.max(0, value));
      totalityAct.style.setProperty("--moon", ((1 - t * 2) * 82).toFixed(1));
      totalityAct.style.setProperty("--corona", (0.12 + 0.88 * (1 - Math.abs(t - 0.5) * 2)).toFixed(3));
      const beads = Math.max(0, 1 - Math.abs(t - 0.34) / 0.12, 1 - Math.abs(t - 0.66) / 0.12);
      totalityAct.style.setProperty("--beads", Math.min(1, beads).toFixed(3));
      const diamond = Math.max(0, 1 - Math.abs(t - 0.27) / 0.045, 1 - Math.abs(t - 0.73) / 0.045);
      totalityAct.style.setProperty("--diamond", Math.min(1, diamond).toFixed(3));
      let word = 0;
      if (t >= 0.16) word = 1;
      if (t >= 0.30) word = 2;
      if (t >= 0.44) word = 3;
      if (t >= 0.62) word = 4;
      if (t >= 0.82) word = 5;
      if (taPhase && word !== taWordIndex) {
        taPhase.textContent = taWords[word];
        taWordIndex = word;
      }
      if (taHint) taHint.style.opacity = String(Math.max(0, 1 - t * 5));
      if (taProgress) taProgress.style.transform = "scaleX(" + t.toFixed(4) + ")";
    }
    function updateTotality() {
      const rect = totalityAct.getBoundingClientRect();
      const span = Math.max(1, rect.height - window.innerHeight);
      renderTotality((0 - rect.top) / span);
    }
    function scheduleTotality() {
      if (taTick) return;
      taTick = requestAnimationFrame(() => {
        taTick = 0;
        updateTotality();
      });
    }
    if (reduce) {
      renderTotality(0.5);
    } else {
      renderTotality(0);
      window.addEventListener("scroll", scheduleTotality, { passive: true });
      window.addEventListener("resize", updateTotality);
    }
  }

  /* ---------------------------------------------------- Fig. 0 path instrument
     The path is a contact instrument, not a drawing: each node opens its hour in
     the watch floor, and the peak marker is placed from the actual peak row. */
  const pathRoute = $("#pathRoute");
  const pathPeakMarker = $("#pathPeakMarker");
  const pathPeakReadout = $("#pathPeakReadout");
  const pathPeakRow = timeline.reduce(
    (best, row) => (best === null || Number(row.total) > Number(best.total) ? row : best),
    null
  );
  if (pathRoute && pathPeakMarker && pathPeakRow) {
    const pathStart = Date.parse("2026-11-11T11:58:00Z");
    const pathEnd = Date.parse("2026-11-11T12:12:00Z");
    const fraction = Math.min(1, Math.max(0, (Date.parse(pathPeakRow.hour) - pathStart) / (pathEnd - pathStart)));
    const point = pathRoute.getPointAtLength(pathRoute.getTotalLength() * fraction);
    pathPeakMarker.setAttribute("transform", "translate(" + point.x.toFixed(1) + " " + point.y.toFixed(1) + ")");
    const peakLabel = "Peak " + pathPeakRow.hour.slice(11, 16) + "Z / " + pathPeakRow.total + " events";
    if (pathPeakReadout) pathPeakReadout.textContent = peakLabel;
    pathPeakMarker.setAttribute("aria-label", "PEAK hour. " + peakLabel + ". Open this hour in the watch floor.");
    const openPeak = () => openHourInLedger(pathPeakRow.hour);
    pathPeakMarker.addEventListener("click", openPeak);
    pathPeakMarker.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        openPeak();
      }
    });
  }
  document.querySelectorAll(".path-node[data-hour]").forEach((node) => {
    const hour = node.dataset.hour;
    const open = () => openHourInLedger(hour);
    node.addEventListener("click", open);
    node.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        open();
      }
    });
  });

  /* -------------------------------------------------------------- live scope
     The cover instrument reads the same hourly payload as Fig. 1, but draws it
     as an oscilloscope: a trace, two quiet echoes, a scan slit, and pings where
     the scan finds volume. It pauses offscreen and draws once in static mode. */
  const fieldBox = $("#scopeField");
  const fieldCanvas = $("#signalField");
  if (fieldBox && fieldCanvas && timeline.length) {
    const ctx = fieldCanvas.getContext("2d");
    const totals = timeline.map((row) => Number(row.total || 0));
    const peakTotal = Math.max(1, ...totals);
    const peakIndex = totals.indexOf(Math.max(...totals));
    const fieldReadout = $("#fieldReadout");
    $("#fieldPeak").textContent = "peak " + number(totals[peakIndex]) + " events at " + timeline[peakIndex].hour.slice(11, 16) + "Z";
    let width = 0;
    let height = 0;
    let dpr = 1;
    let points = [];
    let scanX = 0;
    let lastFrame = 0;
    let raf = 0;
    let running = false;
    let born = performance.now();
    const pings = [];
    const pinged = new Set();
    const pointer = { x: -1, active: false };

    function fieldPoints() {
      const padX = 18;
      const padTop = 42;
      const padBottom = 30;
      const usableW = Math.max(1, width - padX * 2);
      const usableH = Math.max(1, height - padTop - padBottom);
      const step = timeline.length > 1 ? usableW / (timeline.length - 1) : usableW;
      return totals.map((total, index) => [
        padX + index * step,
        padTop + (1 - total / peakTotal) * usableH * 0.86
      ]);
    }

    function smoothPath(list) {
      const path = new Path2D();
      if (!list.length) return path;
      path.moveTo(list[0][0], list[0][1]);
      for (let i = 0; i < list.length - 1; i++) {
        const p0 = list[i === 0 ? 0 : i - 1];
        const p1 = list[i];
        const p2 = list[i + 1];
        const p3 = list[i + 2] || p2;
        path.bezierCurveTo(
          p1[0] + (p2[0] - p0[0]) / 6,
          p1[1] + (p2[1] - p0[1]) / 6,
          p2[0] - (p3[0] - p1[0]) / 6,
          p2[1] - (p3[1] - p1[1]) / 6,
          p2[0],
          p2[1]
        );
      }
      return path;
    }

    function resizeField() {
      const rect = fieldBox.getBoundingClientRect();
      width = Math.max(280, Math.round(rect.width));
      height = Math.max(140, Math.round(rect.height));
      dpr = Math.min(2, window.devicePixelRatio || 1);
      fieldCanvas.width = Math.round(width * dpr);
      fieldCanvas.height = Math.round(height * dpr);
      fieldCanvas.style.width = width + "px";
      fieldCanvas.style.height = height + "px";
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      points = fieldPoints();
      if (!running) drawField(performance.now());
    }

    function drawField(now) {
      const elapsed = now - born;
      const reveal = reduce ? 1 : Math.min(1, elapsed / 1500);
      const count = Math.max(2, Math.round(points.length * reveal));
      const visible = points.slice(0, count);
      ctx.clearRect(0, 0, width, height);

      const ink = getComputedStyle(document.documentElement);
      const readColor = (name, fallback) => ink.getPropertyValue(name).trim() || fallback;
      const signal = readColor("--scope-trace", "#FBB931");
      const grid = readColor("--scope-grid", "rgba(255,227,179,0.12)");
      const fillTop = readColor("--scope-fill", "rgba(248,143,34,0.20)");
      const echoColor = readColor("--scope-echo", "rgba(249,92,75,0.30)");
      const beamColor = readColor("--scope-beam", "rgba(251,185,49,0.16)");
      const pingColor = readColor("--scope-ping", "rgba(255,227,179,0.55)");
      const peakColor = readColor("--scope-peak", "#F95C4B");
      const scanColor = readColor("--scope-scan", "rgba(255,227,179,0.50)");
      const pointerColor = readColor("--scope-pointer", "rgba(255,227,179,0.35)");
      const sun1 = readColor("--sun-1", "#EA6113");
      const sun2 = readColor("--sun-2", "#F88F22");
      const sun3 = readColor("--sun-3", "#FBB931");
      const sun4 = readColor("--sun-4", "#FFE3B3");
      const totality = readColor("--totality", "#0B0A09");
      const traceGrade = ctx.createLinearGradient(0, 0, width, 0);
      traceGrade.addColorStop(0, sun1);
      traceGrade.addColorStop(0.42, sun2);
      traceGrade.addColorStop(0.74, sun3);
      traceGrade.addColorStop(1, sun4);
      const fillGrade = ctx.createLinearGradient(0, 30, 0, height - 22);
      fillGrade.addColorStop(0, fillTop);
      fillGrade.addColorStop(1, "transparent");

      // Etched graticule.
      ctx.strokeStyle = grid;
      ctx.lineWidth = 1;
      ctx.beginPath();
      for (let i = 0; i < points.length; i += 2) {
        ctx.moveTo(points[i][0], 34);
        ctx.lineTo(points[i][0], height - 22);
      }
      [0.25, 0.5, 0.75].forEach((ratio) => {
        const y = 42 + ratio * (height - 72);
        ctx.moveTo(14, y);
        ctx.lineTo(width - 14, y);
      });
      ctx.stroke();

      // Area under the trace: the corona, warming toward the horizon.
      const trace = smoothPath(visible);
      if (visible.length > 1) {
        const area = smoothPath(visible);
        area.lineTo(visible[visible.length - 1][0], height - 22);
        area.lineTo(visible[0][0], height - 22);
        area.closePath();
        ctx.fillStyle = fillGrade;
        ctx.fill(area);
      }

      // Two quiet echoes: the instrument is live, the data is not moving.
      if (!reduce) {
        [0.9, 1.6].forEach((amp, index) => {
          const echo = visible.map(([x, y], i) => [x, y + Math.sin(now / (900 + index * 260) + i * 0.6) * amp * 3]);
          ctx.strokeStyle = echoColor;
          ctx.globalAlpha = 0.55 - index * 0.2;
          ctx.lineWidth = 1;
          ctx.stroke(smoothPath(echo));
        });
        ctx.globalAlpha = 1;
      }

      // Main trace: a warm light curve, not a cyan oscilloscope.
      ctx.save();
      ctx.shadowColor = sun2;
      ctx.shadowBlur = document.documentElement.dataset.theme === "umbra" ? 14 : 9;
      ctx.strokeStyle = traceGrade;
      ctx.lineWidth = 2;
      ctx.lineJoin = "round";
      ctx.lineCap = "round";
      ctx.stroke(trace);
      ctx.restore();

      // Hour points and the eclipse marker at the brightest hour.
      ctx.fillStyle = sun4;
      visible.forEach(([x, y], index) => {
        const total = totals[index] || 0;
        if (total <= 0) return;
        const near = pointer.active && Math.abs(pointer.x - x) < 26;
        ctx.globalAlpha = near ? 1 : 0.62;
        ctx.beginPath();
        ctx.arc(x, y, near ? 3.6 : 2.2, 0, Math.PI * 2);
        ctx.fill();
      });
      ctx.globalAlpha = 1;
      if (reveal >= 1 && points[peakIndex]) {
        const [px, py] = points[peakIndex];
        const halo = ctx.createRadialGradient(px, py, 0, px, py, 30);
        halo.addColorStop(0, "rgba(249, 92, 75, 0.55)");
        halo.addColorStop(0.55, "rgba(248, 143, 34, 0.24)");
        halo.addColorStop(1, "rgba(248, 143, 34, 0)");
        ctx.fillStyle = halo;
        ctx.beginPath();
        ctx.arc(px, py, 30, 0, Math.PI * 2);
        ctx.fill();
        ctx.fillStyle = totality;
        ctx.beginPath();
        ctx.arc(px, py, 7, 0, Math.PI * 2);
        ctx.fill();
        ctx.strokeStyle = peakColor;
        ctx.lineWidth = 1.8;
        ctx.stroke();
        ctx.strokeStyle = sun3;
        ctx.globalAlpha = 0.7;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.arc(px, py, 12.5, 0, Math.PI * 2);
        ctx.stroke();
        // A diamond-ring flare on the corona edge.
        const fx = px + 11;
        const fy = py - 11;
        ctx.globalAlpha = 0.95;
        ctx.fillStyle = sun4;
        ctx.beginPath();
        ctx.moveTo(fx, fy - 9);
        ctx.lineTo(fx + 1.8, fy - 1.8);
        ctx.lineTo(fx + 9, fy);
        ctx.lineTo(fx + 1.8, fy + 1.8);
        ctx.lineTo(fx, fy + 9);
        ctx.lineTo(fx - 1.8, fy + 1.8);
        ctx.lineTo(fx - 9, fy);
        ctx.lineTo(fx - 1.8, fy - 1.8);
        ctx.closePath();
        ctx.fill();
        ctx.globalAlpha = 1;
      }

      // Scan slit and the pings it triggers.
      if (!reduce) {
        scanX = 14 + ((now - born) % 9000) / 9000 * (width - 28);
        const beam = ctx.createLinearGradient(scanX - 60, 0, scanX + 8, 0);
        beam.addColorStop(0, "transparent");
        beam.addColorStop(1, beamColor);
        ctx.fillStyle = beam;
        ctx.fillRect(scanX - 60, 30, 68, height - 52);
        ctx.strokeStyle = scanColor;
        ctx.beginPath();
        ctx.moveTo(scanX, 30);
        ctx.lineTo(scanX, height - 22);
        ctx.stroke();

        points.forEach(([x, y], index) => {
          if ((totals[index] || 0) < Math.max(4, peakTotal * 0.35)) return;
          if (scanX >= x && !pinged.has(index)) {
            pinged.add(index);
            pings.push({ x, y, start: now });
          }
        });
        for (let i = pings.length - 1; i >= 0; i--) {
          const age = (now - pings[i].start) / 1200;
          if (age >= 1) { pings.splice(i, 1); continue; }
          ctx.strokeStyle = pingColor;
          ctx.globalAlpha = 0.9 * (1 - age);
          ctx.lineWidth = 1.2;
          ctx.beginPath();
          ctx.arc(pings[i].x, pings[i].y, 3 + age * 22, 0, Math.PI * 2);
          ctx.stroke();
        }
        ctx.globalAlpha = 1;
      }

      if (pointer.active) {
        ctx.strokeStyle = pointerColor;
        ctx.setLineDash([2, 4]);
        ctx.beginPath();
        ctx.moveTo(pointer.x, 30);
        ctx.lineTo(pointer.x, height - 22);
        ctx.stroke();
        ctx.setLineDash([]);
      }
    }

    function frame(now) {
      if (!running) return;
      if (now - lastFrame > 1000 / 40) {
        drawField(now);
        lastFrame = now;
      }
      raf = requestAnimationFrame(frame);
    }

    function startField() {
      if (reduce || running || document.hidden) return;
      running = true;
      raf = requestAnimationFrame(frame);
    }
    function stopField() {
      running = false;
      cancelAnimationFrame(raf);
    }

    fieldBox.addEventListener("pointermove", (event) => {
      const rect = fieldBox.getBoundingClientRect();
      pointer.x = event.clientX - rect.left;
      pointer.active = true;
      const nearest = points.reduce((best, point, index) => (
        Math.abs(point[0] - pointer.x) < Math.abs(points[best][0] - pointer.x) ? index : best
      ), 0);
      if (timeline[nearest]) {
        fieldReadout.textContent = timeline[nearest].hour.slice(11, 16) + "Z / " + unit(totals[nearest], "event", "events");
      }
      if (!running) drawField(performance.now());
    });
    fieldBox.addEventListener("pointerleave", () => {
      pointer.active = false;
      fieldReadout.textContent = timeline.length + " hourly buckets";
      if (!running) drawField(performance.now());
    });
    function pinFieldHour(index) {
      if (!timeline[index]) return;
      state.pinnedHour = timeline[index].hour;
      initScope();
      paintHour(index, true);
      $("#run").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      toast("Pinned " + timeline[index].hour.slice(11, 16) + "Z on the chart");
    }
    fieldBox.addEventListener("click", (event) => {
      if (!points.length) return;
      const rect = fieldBox.getBoundingClientRect();
      const x = event.clientX - rect.left;
      const nearest = points.reduce((best, point, index) => (
        Math.abs(point[0] - x) < Math.abs(points[best][0] - x) ? index : best
      ), 0);
      pinFieldHour(nearest);
    });
    fieldBox.addEventListener("keydown", (event) => {
      if (event.key !== "Enter" && event.key !== " ") return;
      event.preventDefault();
      pinFieldHour(peakIndex);
    });
    window.addEventListener("resize", resizeField);
    document.addEventListener("visibilitychange", () => {
      if (document.hidden) stopField();
      else if (fieldVisible) startField();
    });
    let fieldVisible = false;
    if ("IntersectionObserver" in window) {
      new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          fieldVisible = entry.isIntersecting;
          if (fieldVisible) {
            born = performance.now();
            pinged.clear();
            startField();
          } else {
            stopField();
          }
        });
      }, { threshold: 0.15 }).observe(fieldBox);
    }
    document.addEventListener("penumbra:theme", () => {
      if (!running) drawField(performance.now());
    });
    resizeField();
    drawField(performance.now());
  }

  /* ------------------------------------------------------------------- path */
  const pipeline = DATA.pipeline || [];
  const stageIcons = [
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h10"/><circle cx="19" cy="18" r="2"/></svg>',
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="m8 6-5 6 5 6M16 6l5 6-5 6M13 4l-2 16"/></svg>',
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4M11 8v3l2 2"/></svg>',
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M4 17V7m5 10V9m5 8V5m5 12v-6"/></svg>',
    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true"><path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 13h6M9 17h4"/></svg>'
  ];
  const stagePhases = ["C1 / first contact", "C2 / corona", "MAX / totality", "C3 / beads", "C4 / last light"];
  $("#pathStrip").innerHTML = pipeline.map((step, index) => (
    '<button class="path-step' + (index === 0 ? " active" : "") + '" type="button" role="tab" aria-selected="' + (index === 0) + '" data-index="' + index + '">' +
      '<span class="path-top"><span class="path-dot">' + String(index + 1).padStart(2, "0") + "</span>" +
      '<span class="path-icon">' + (stageIcons[index] || stageIcons[0]) + "</span></span>" +
      '<span class="path-phase">' + stagePhases[index] + "</span>" +
      '<span class="path-label">' + esc(step.label) + "</span>" +
      '<span class="path-title">' + esc(step.title) + "</span>" +
      '<span class="path-bottom"><span class="path-count">' + esc(step.count) + "</span>" +
      '<span class="path-artifact">' + esc(step.artifact || "") + "</span></span>" +
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
    $("#pathDetail").innerHTML = '<span class="pd-label">' + esc(step.label) + "</span><p>" + esc(step.detail) + "</p>" +
      (step.artifact ? '<code class="pd-artifact">' + esc(step.artifact) + "</code>" : "");
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
    name: alert.rule || "",
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
  detections.forEach((row) => {
    row.key = row.kind + ":" + row.id;
    rowIndex.set(row.key, row);
  });
  correlations.forEach((row) => {
    // Two specs can share a correlation_id; the group value is part of the identity.
    row.key = row.kind + ":" + row.id + ":" + row.group_value;
    rowIndex.set(row.key, row);
  });
  const rowsById = new Map();
  detections.forEach((row) => {
    rowsById.set(row.id, row);
    if (row.name) rowsById.set(row.name, row);
  });
  correlations.forEach((row) => { if (!rowsById.has(row.id)) rowsById.set(row.id, row); });

  const hostSet = new Set();
  detections.forEach((row) => (row.hosts || []).forEach((host) => hostSet.add(host)));
  correlations.forEach((row) => (row.hosts || []).forEach((host) => hostSet.add(host)));
  const maxRowCount = Math.max(1, ...detections.map((row) => row.count), ...correlations.map((row) => row.count));
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

  /* Tokenise before escaping so query markup can never break out of the pre. */
  function highlightQuery(text) {
    const source = String(text || "not generated");
    const pattern = /("(?:[^"\\]|\\.)*")|(\b(?:any|where|sequence|by|and|or|not|with|maxspan|runs|of|near|until|true|false)\b)|(\b(?:process|event|file|registry|network|user|host|source|destination|winlog|url|dns|agent|message)\.[a-zA-Z0-9_.]+)|(\b\d+(?:\.\d+)?\b)|([*?])/gi;
    let out = "";
    let last = 0;
    source.replace(pattern, (match, str, keyword, field, num, wild, offset) => {
      out += esc(source.slice(last, offset));
      const cls = str ? "q-str" : keyword ? "q-kw" : field ? "q-field" : num ? "q-num" : "q-wild";
      out += '<span class="' + cls + '">' + esc(match) + "</span>";
      last = offset + match.length;
      return match;
    });
    out += esc(source.slice(last));
    return out;
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
        '<div class="ev-panel" data-panel="eql" hidden><div class="ev-head"><h4>Compiled EQL</h4><button class="mini" type="button" data-copy="' + esc(row.query) + '">copy EQL</button></div><pre class="ev-pre"><code>' + highlightQuery(row.query) + "</code></pre></div>" +
        '<div class="ev-panel" data-panel="kql" hidden><div class="ev-head"><h4>Kibana KQL</h4><button class="mini" type="button" data-copy="' + esc(row.query_kql) + '">copy KQL</button></div><pre class="ev-pre"><code>' + highlightQuery(row.query_kql) + "</code></pre></div>" +
      "</div>"
    );
  }

  function rowMarkup(row, index) {
    const techs = (row.techniques || []).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const volume = Math.max(4, Math.round((row.count / maxRowCount) * 100));
    const meta = [
      '<span><i>host</i><b>' + esc(row.host || "unassigned") + "</b></span>",
      '<span><i>events</i><b>' + number(row.count) + "</b></span>",
      '<span><i>last</i><b>' + esc(clock(row.last_seen)) + "Z</b></span>",
      row.index ? '<span><i>source</i><b>' + esc(row.index) + "</b></span>" : ""
    ].join("");
    return (
      '<article class="row' + (reduce ? "" : " enter") + '" tabindex="0" aria-expanded="false" data-level="' + esc(row.level) + '" data-id="' + esc(row.id) + '" data-key="' + esc(row.key) + '" data-kind="' + esc(row.kind) + '"' + (reduce ? "" : ' style="animation-delay:' + Math.min(index, 12) * 22 + 'ms"') + ">" +
        '<span class="row-index">' + String(index + 1).padStart(2, "0") + "</span>" +
        '<div class="row-body">' +
          '<div class="row-top"><h3 class="row-title">' + esc(row.title) + '</h3><span class="sev ' + esc(row.level) + '">' + esc(row.level) + "</span></div>" +
          '<div class="row-meta">' + meta + "</div>" +
          (techs ? '<div class="row-techs">' + techs + "</div>" : "") +
          '<div class="row-volume" aria-hidden="true"><i style="--vol:' + volume + '%"></i></div>' +
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

  function inspectorDefault() {
    return (
      '<div class="wf-inspector-head"><span>Evidence</span><span>Awaiting selection</span></div>' +
      '<div class="wf-inspector-empty"><b>Work the floor</b><p>Select a detection or correlation from the queue. Its events, EQL, and KQL stay here while you work the list. The host lanes below show where the hour landed.</p></div>'
    );
  }

  function inspectorHead(row) {
    const kind = row.kind === "correlation" ? "Coincidence" : "Detection";
    const techs = (row.techniques || []).slice(0, 2).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    let timing = "";
    if (timeline.length > 1) {
      const startMs = Date.parse(timeline[0].hour);
      const endMs = Date.parse(timeline[timeline.length - 1].hour) + 3600 * 1000;
      const first = Date.parse(row.first_seen || row.last_seen || "");
      const last = Date.parse(row.last_seen || row.first_seen || "");
      if (Number.isFinite(first) && Number.isFinite(last) && endMs > startMs) {
        const left = Math.max(0, Math.min(100, ((first - startMs) / (endMs - startMs)) * 100));
        const right = Math.max(0, Math.min(100, ((last - startMs) / (endMs - startMs)) * 100));
        const widthPct = Math.max(1.2, right - left);
        const dots = (row.events || []).map((ev) => {
          const at = Date.parse(ev["@timestamp"] || "");
          if (!Number.isFinite(at)) return "";
          const pct = Math.max(0, Math.min(100, ((at - startMs) / (endMs - startMs)) * 100));
          return '<b style="left:' + pct.toFixed(2) + '%"></b>';
        }).join("");
        timing =
          '<div class="wf-timing" aria-hidden="true"><i style="left:' + left.toFixed(2) + "%;width:" + widthPct.toFixed(2) + '%"></i>' + dots + "</div>" +
          '<div class="wf-timing-labels"><span>first ' + esc(dayHour(row.first_seen || row.last_seen)) + 'Z</span><span>last ' + esc(dayHour(row.last_seen || row.first_seen)) + 'Z</span></div>';
      }
    }
    return (
      '<div class="wf-inspector-head"><span>' + esc(kind) + " / " + esc(row.level) + "</span><span>" + esc(clock(row.last_seen)) + "Z</span></div>" +
      '<h3 class="wf-inspector-title">' + esc(row.title) + "</h3>" +
      '<div class="wf-inspector-meta"><span>' + esc(row.host || "unassigned") + "</span><span>" + number(row.count) + " events</span>" + (techs ? "<span>" + techs + "</span>" : "") + "</div>" +
      timing
    );
  }

  function renderInspector() {
    const node = $("#wfInspector");
    if (!node) return;
    const data = state.selected ? rowIndex.get(state.selected) : null;
    node.innerHTML = data ? inspectorHead(data) + evidenceMarkup(data) : inspectorDefault();
  }

  function selectRow(row) {
    if (!row) return;
    if (!desktopFloor.matches) {
      toggleRow(row, true);
      row.scrollIntoView({ block: "nearest", behavior: reduce ? "auto" : "smooth" });
      return;
    }
    state.selected = row.dataset.key;
    $$("#ledgerBody .row").forEach((node) => {
      const active = node === row;
      node.classList.toggle("selected", active);
      node.setAttribute("aria-expanded", String(active));
    });
    $$(".wf-pip").forEach((pip) => pip.classList.toggle("on", pip.dataset.key === state.selected));
    $$(".wf-corr-item").forEach((item) => item.classList.toggle("on", item.dataset.key === state.selected));
    renderInspector();
  }

  function selectKey(key) {
    const data = rowIndex.get(key);
    if (!data) return;
    state.tab = data.kind === "correlation" ? "correlations" : "detections";
    state.level = "all";
    state.host = "all";
    state.q = "";
    state.hour = null;
    $("#search").value = "";
    $("#hostFilter").value = "all";
    paintLevelChips();
    switchTab(state.tab);
    const row = $$("#ledgerBody .row").find((node) => node.dataset.key === key);
    if (row) selectRow(row);
    if (desktopFloor.matches) {
      const target = $("#wfInspector");
      if (target) target.scrollIntoView({ block: "nearest", behavior: reduce ? "auto" : "smooth" });
    }
  }

  function renderLanes() {
    const laneList = $("#wfLaneList");
    if (!laneList) return;
    const hosts = DATA.hosts || [];
    const startMs = timeline.length ? Date.parse(timeline[0].hour) : Date.now() - 10 * 3600 * 1000;
    const endMs = timeline.length ? Date.parse(timeline[timeline.length - 1].hour) : Date.now();
    const span = Math.max(1, endMs - startMs);
    const dayLabel = (value) => {
      const text = String(value || "");
      const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
      const day = Number(text.slice(8, 10));
      const month = months[Number(text.slice(5, 7)) - 1] || "";
      return day + " " + month + " " + text.slice(11, 16);
    };
    $("#wfLaneHint").textContent = hosts.length + " hosts / " + detections.length + " marks / " +
      (timeline.length ? dayLabel(timeline[0].hour) + "–" + dayLabel(timeline[timeline.length - 1].hour) : "03:00–13:00") + " UTC";
    const axisTicks = [0, 25, 50, 75, 100].map((pct) => {
      const iso = new Date(startMs + span * (pct / 100)).toISOString();
      return '<span style="left:' + pct + '%">' + iso.slice(11, 16) + "</span>";
    }).join("");
    laneList.innerHTML = '<div class="wf-lane-axis"><span></span><div class="wf-lane-axis-track">' + axisTicks + "</div><span></span></div>" + hosts.map((host) => {
      const rows = detections.filter((row) => (row.hosts || []).includes(host.name));
      const marks = rows.map((row, index) => {
        const time = row.last_seen || row.first_seen;
        const timeMs = Date.parse(time);
        const pct = Math.max(1, Math.min(99, ((Number.isFinite(timeMs) ? timeMs : startMs) - startMs) / span * 100));
        return '<span class="wf-pip" data-level="' + esc(row.level) + '" data-key="' + esc(row.key) + '" style="left:' + pct.toFixed(2) + "%;top:" + (30 + (index % 3) * 18) + '%" title="' + esc(row.title + " / " + clock(time) + "Z") + '" aria-hidden="true"></span>';
      }).join("");
      return '<div class="wf-lane">' +
        '<button type="button" class="wf-lane-name" data-host="' + esc(host.name) + '" title="Filter the watch floor to ' + esc(host.name) + '">' + esc(host.name) + "</button>" +
        '<button type="button" class="wf-lane-track" data-host="' + esc(host.name) + '" aria-label="Open a detection on the ' + esc(host.name) + ' lane">' + marks + "</button>" +
        '<span class="wf-lane-n">' + rows.length + "</span>" +
      "</div>";
    }).join("");
  }

  function renderCorrStrip() {
    const grid = $("#wfCorrGrid");
    if (!grid) return;
    $("#wfCorrHint").textContent = correlations.length + " coincidences";
    grid.innerHTML = correlations.map((row) => (
      '<button type="button" class="wf-corr-item" data-key="' + esc(row.key) + '" title="' + esc(row.title + " / " + row.host) + '">' +
        '<span class="wf-corr-dot ' + esc(row.level) + '"></span>' +
        "<span>" + esc(row.title) + "</span>" +
        "<b>" + number(row.count) + "</b>" +
      "</button>"
    )).join("");
  }

  function syncFloorStatus() {
    $("#wfDetections").textContent = number(detections.length);
    $("#wfCorrelations").textContent = number(correlations.length);
    $("#wfErrors").textContent = number(errors.length);
    const total = LEVELS.reduce((sum, level) => sum + Number(severity[level] || 0), 0);
    const mix = $("#wfMix");
    if (mix) {
      mix.innerHTML = LEVELS.map((level) => (
        '<i class="' + level + '" style="width:' + (total ? (Number(severity[level] || 0) / total) * 100 : 0).toFixed(1) + '%"></i>'
      )).join("");
      mix.title = LEVELS.map((level) => Number(severity[level] || 0) + " " + level).join(" / ");
      mix.setAttribute("aria-label", "Severity mix: " + mix.title);
    }
    const end = meta.window_end ? String(meta.window_end).slice(11, 16) + "Z" : "dated run";
    $("#wfClock").textContent = "window end " + end;
  }

  let ledgerRendered = false;
  function renderLedger() {
    ledgerRendered = true;
    const result = filteredRows();
    $("#ledgerCount").textContent = result.length + " of " + activeRows().length + " rows";
    $("#wfQueueHint").textContent = result.length + " in queue";
    renderActiveFilters();
    if (!result.length) {
      $("#ledgerBody").innerHTML = '<div class="empty">No ' + esc(state.tab) + " match this filter. Clear the search, pick another host, or remove the active-hour filter.</div>";
      $("#wfInspector").innerHTML = '<div class="wf-inspector-empty"><b>No match</b><p>Widen the filters to bring the queue back.</p></div>';
      return;
    }
    $("#ledgerBody").innerHTML = result.map(rowMarkup).join("");
    if (desktopFloor.matches) {
      const rows = $$("#ledgerBody .row");
      const active = rows.find((row) => row.dataset.key === state.selected) || rows[0];
      selectRow(active);
    } else {
      state.selected = null;
      $("#wfInspector").innerHTML = inspectorDefault();
    }
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
        const data = rowIndex.get(row.dataset.key);
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
    const scope = tab.closest(".drawer-inner, .wf-inspector");
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
    if (desktopFloor.matches) selectRow(rows[index]);
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
    if (desktopFloor.matches) selectRow(row);
    else toggleRow(row);
  });

  $("#ledgerBody").addEventListener("keydown", (event) => {
    const row = event.target.closest(".row");
    if (!row) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      if (desktopFloor.matches) selectRow(row);
      else toggleRow(row);
    } else if (event.key === "ArrowDown") {
      event.preventDefault();
      focusRow("next");
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      focusRow("prev");
    }
  });

  $("#wfInspector").addEventListener("click", (event) => {
    const tab = event.target.closest(".ev-tab");
    if (tab) activateEvidenceTab(tab);
  });

  $("#wfLaneList").addEventListener("click", (event) => {
    const label = event.target.closest(".wf-lane-name");
    if (label) {
      state.host = label.dataset.host;
      $("#hostFilter").value = state.host;
      renderLedger();
      return;
    }
    const track = event.target.closest(".wf-lane-track");
    if (!track) return;
    const pips = $$(".wf-pip", track);
    if (!pips.length) return;
    const rect = track.getBoundingClientRect();
    const x = event.clientX - rect.left;
    let best = pips[0];
    let distance = Infinity;
    pips.forEach((pip) => {
      const pipRect = pip.getBoundingClientRect();
      const delta = Math.abs(pipRect.left + pipRect.width / 2 - rect.left - x);
      if (delta < distance) { distance = delta; best = pip; }
    });
    selectKey(best.dataset.key);
  });

  $("#wfCorrGrid").addEventListener("click", (event) => {
    const item = event.target.closest("[data-key]");
    if (item) selectKey(item.dataset.key);
  });

  desktopFloor.addEventListener("change", renderLedger);

  syncFloorStatus();
  renderLanes();
  renderCorrStrip();
  renderLedger();

  /* --------------------------------------------------------------- coverage */
  const coverage = DATA.coverage || { tactics: [], priority: 0, covered: 0, gaps: [] };
  const allTiles = (coverage.tactics || []).flatMap((tactic) => (tactic.tiles || []).map((tile) => ({ ...tile, tactic: tactic.label })));
  $("#coverageCovered").dataset.count = String(coverage.covered || 0);
  $("#coverageCovered").textContent = "0";
  $("#coverageTotal").textContent = String(coverage.priority || 0);
  const gapCount = (coverage.gaps || []).length;
  $("#coverageNote").textContent = (coverage.covered || 0) + " covered / " + gapCount + " gaps";
  if (!gapCount) {
    $("#gapsBtn").disabled = true;
    $("#gapsBtn").textContent = "no gaps";
  }
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
      const ratio = tactic.tiles.length ? covered / tactic.tiles.length : 0;
      const tiles = tactic.tiles.map((tile, index) => {
        const label = tile.level ? tile.level : "gap";
        return '<button class="tile ' + (tile.level ? "covered " + esc(tile.level) : "gap") + '" type="button" data-tech="' + esc(tile.technique) + '"' +
          ' data-name="' + esc(tile.name) + '" data-tactic="' + esc(tactic.label) + '" data-detect="' + esc(tile.title || "not covered") + '" data-level="' + esc(label) + '"' +
          ' style="animation-delay:' + Math.min(index, 12) * 16 + 'ms" title="' + esc(tile.technique + " / " + tile.name + " / " + label) + '">' +
          '<span class="id">' + esc(tile.technique) + '</span><span class="nm">' + esc(tile.name) + "</span></button>";
      }).join("");
      return (
        '<div class="tactic">' +
          '<div class="tactic-head"><h3>' + esc(tactic.label) + '</h3><span class="tactic-count">' + covered + "/" + tactic.tiles.length + "</span></div>" +
          '<div class="tactic-meter" aria-hidden="true"><i style="width:' + (ratio * 100).toFixed(1) + '%"></i></div>' +
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
    toast(technique + " filtered into the watch floor");
  });

  const techTip = $("#techTip");
  function showTechTip(tile) {
    if (!techTip) return;
    techTip.innerHTML =
      '<span class="tt-tech">' + esc(tile.dataset.tech) + "</span>" +
      "<b>" + esc(tile.dataset.name) + "</b>" +
      '<span class="tt-meta">' + esc(tile.dataset.tactic) + " / " + esc(tile.dataset.level) + "</span>" +
      "<p>" + esc(tile.dataset.detect) + "</p>";
    techTip.hidden = false;
    const rect = tile.getBoundingClientRect();
    const tipRect = techTip.getBoundingClientRect();
    const left = Math.min(window.innerWidth - tipRect.width - 12, Math.max(12, rect.left + rect.width / 2 - tipRect.width / 2));
    let top = rect.top - tipRect.height - 10;
    if (top < 12) top = rect.bottom + 10;
    techTip.style.left = left + "px";
    techTip.style.top = top + "px";
  }
  function hideTechTip() {
    if (techTip) techTip.hidden = true;
  }
  if (techTip) {
    $("#matrix").addEventListener("pointerover", (event) => {
      const tile = event.target.closest(".tile");
      if (tile) showTechTip(tile);
    });
    $("#matrix").addEventListener("pointerout", (event) => {
      if (event.target.closest(".tile")) hideTechTip();
    });
    $("#matrix").addEventListener("focusin", (event) => {
      const tile = event.target.closest(".tile");
      if (tile) showTechTip(tile);
    });
    $("#matrix").addEventListener("focusout", hideTechTip);
    $("#matrix").addEventListener("click", hideTechTip);
    window.addEventListener("scroll", hideTechTip, { passive: true });
  }

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
  const chainAt = (row) => String(row.kind === "correlation" ? (row.last_seen || row.first_seen) : (row.first_seen || row.last_seen) || "");
  const caseChains = cases.map((item) => {
    const seen = new Set();
    const steps = (item.detections || [])
      .map((id) => rowsById.get(id))
      .filter((row) => row && !seen.has(row.key) && seen.add(row.key))
      .sort((a, b) => chainAt(a).localeCompare(chainAt(b)));
    return { item, steps };
  });
  const ccTabs = $("#ccTabs");
  const ccStage = $("#ccStage");
  const ccDetail = $("#ccDetail");
  const ccTitle = $("#ccTitle");
  const ccPlay = $("#ccPlay");
  const ccPrev = $("#ccPrev");
  const ccNext = $("#ccNext");
  let ccCase = 0;
  let ccStep = 0;
  let ccTimer = 0;
  let ccPlaying = false;

  function stopChain() {
    ccPlaying = false;
    window.clearInterval(ccTimer);
    if (ccPlay) ccPlay.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M8 5v14l11-7z"/></svg> play chain';
  }

  function chainDetail(step) {
    const { item, steps } = caseChains[ccCase];
    const row = steps[step];
    if (!row) return;
    const techs = (row.techniques || []).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const query = row.query
      ? '<code class="cc-query">' + highlightQuery(row.query) + "</code>"
      : row.kind === "correlation"
        ? '<code class="cc-query">' + esc(row.count + " events / " + row.window_seconds + "s / " + row.group_by + " = " + row.group_value) + "</code>"
        : "";
    ccDetail.innerHTML =
      '<div class="cc-detail-main">' +
        '<span class="cc-stepno">Step ' + String(step + 1).padStart(2, "0") + " / " + String(steps.length).padStart(2, "0") + "</span>" +
        "<h4>" + esc(row.title) + "</h4>" +
        '<div class="cc-detail-meta"><span class="sev ' + esc(row.level) + '">' + esc(row.level) + "</span>" +
          "<span>" + esc(clock(chainAt(row))) + "Z</span><span>" + esc(row.host || "unassigned") + "</span><span>" + number(row.count) + " events</span>" + techs + "</div>" +
        query +
      "</div>" +
      '<div class="cc-detail-actions">' +
        '<button class="mini" type="button" data-cc-open="' + esc(row.key) + '">Open in watch floor</button>' +
        '<button class="mini" type="button" data-cc-case="' + ccCase + '">Open case file</button>' +
      "</div>";
  }

  function setCaseStep(step, scroll) {
    const { steps } = caseChains[ccCase];
    if (!steps.length) return;
    ccStep = Math.max(0, Math.min(steps.length - 1, step));
    $$("#ccStage .cc-node").forEach((node) => {
      const index = Number(node.dataset.step);
      node.classList.toggle("active", index === ccStep);
      node.classList.toggle("seen", index < ccStep);
      node.setAttribute("aria-current", index === ccStep ? "step" : "false");
    });
    const active = $("#ccStage .cc-node.active");
    const progress = $("#ccProgress");
    if (active && progress) {
      const p = steps.length > 1 ? ccStep / (steps.length - 1) : 1;
      progress.style.transform = "scaleX(" + p.toFixed(4) + ")";
    }
    ccPrev.disabled = ccStep === 0;
    ccNext.disabled = ccStep === steps.length - 1;
    chainDetail(ccStep);
    if (scroll && active) active.scrollIntoView({ block: "nearest", inline: "center", behavior: reduce ? "auto" : "smooth" });
  }

  function renderCaseChain(index) {
    if (!caseChains.length) return;
    ccCase = Math.max(0, Math.min(caseChains.length - 1, index));
    const { item, steps } = caseChains[ccCase];
    ccTitle.innerHTML = esc(item.id) + ' <span>/</span> ' + esc(item.title);
    ccTabs.innerHTML = caseChains.map((chain, tab) => (
      '<button class="cc-tab' + (tab === ccCase ? " active" : "") + '" type="button" role="tab" aria-selected="' + (tab === ccCase) + '" data-case="' + tab + '">' +
        "<b>" + esc(chain.item.id.slice(-3)) + "</b><span>" + esc(chain.item.title.split(" ").slice(0, 3).join(" ")) + "</span>" +
      "</button>"
    )).join("");
    if (!steps.length) {
      ccStage.innerHTML = '<div class="empty">No matching detections in this run.</div>';
      ccDetail.innerHTML = "";
      return;
    }
    const nodes = steps.map((row, step) => {
      const x = steps.length === 1 ? 50 : 6 + step * (88 / (steps.length - 1));
      return '<button class="cc-node ' + esc(row.level) + '" type="button" data-step="' + step + '" style="--x:' + x.toFixed(2) + "%;--i:" + step + '" aria-current="' + (step === 0 ? "step" : "false") + '">' +
        '<span class="sr-only">Step ' + (step + 1) + ": " + esc(row.title) + ' at ' + esc(clock(chainAt(row))) + 'Z, technique ' + esc((row.techniques || [])[0] || row.kind) + "</span>" +
        '<span class="cc-time">' + esc(clock(chainAt(row))) + "Z</span>" +
        '<span class="cc-dot" aria-hidden="true"></span>' +
        '<span class="cc-tech">' + esc((row.techniques || [])[0] || row.kind) + "</span>" +
      "</button>";
    }).join("");
    ccStage.innerHTML = '<div class="cc-scroll"><div class="cc-track"><i id="ccProgress"></i></div><div class="cc-nodes">' + nodes + "</div></div>";
    setCaseStep(0);
  }

  function playChain() {
    if (ccPlaying) { stopChain(); return; }
    const total = caseChains[ccCase].steps.length;
    if (!total) return;
    if (ccStep >= total - 1) setCaseStep(0);
    ccPlaying = true;
    ccPlay.innerHTML = '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M7 5h4v14H7zM13 5h4v14h-4z"/></svg> pause';
    ccTimer = window.setInterval(() => {
      if (ccStep >= total - 1) { stopChain(); return; }
      setCaseStep(ccStep + 1, true);
    }, 1200);
  }

  if (ccTabs) {
    const initialCase = caseChains.reduce((best, chain, index) => (
      chain.steps.length > caseChains[best].steps.length ? index : best
    ), 0);
    renderCaseChain(initialCase);
    ccTabs.addEventListener("click", (event) => {
      const tab = event.target.closest(".cc-tab");
      if (!tab) return;
      stopChain();
      renderCaseChain(Number(tab.dataset.case));
    });
    ccStage.addEventListener("click", (event) => {
      const node = event.target.closest(".cc-node");
      if (!node) return;
      stopChain();
      setCaseStep(Number(node.dataset.step));
    });
    ccDetail.addEventListener("click", (event) => {
      const open = event.target.closest("[data-cc-open]");
      if (open) {
        stopChain();
        selectKey(open.dataset.ccOpen);
        $("#ledgerPanel").scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
        return;
      }
      const caseButton = event.target.closest("[data-cc-case]");
      if (caseButton) openCase(Number(caseButton.dataset.ccCase));
    });
    ccPlay.addEventListener("click", playChain);
    ccPrev.addEventListener("click", () => { stopChain(); setCaseStep(ccStep - 1, true); });
    ccNext.addEventListener("click", () => { stopChain(); setCaseStep(ccStep + 1, true); });
  }


  $("#caseGrid").innerHTML = cases.map((item, index) => {
    const techs = (item.techniques || []).slice(0, 4).map((tech) => '<span class="tech">' + esc(tech) + "</span>").join("");
    const extra = (item.techniques || []).length > 4 ? '<span class="tech">+' + ((item.techniques || []).length - 4) + "</span>" : "";
    const chain = (item.detections || []).slice(0, 5).map((id, step) => (
      '<span class="chain-node" title="' + esc(id) + '"><i>' + String(step + 1).padStart(2, "0") + "</i></span>"
    )).join('<span class="chain-link" aria-hidden="true"></span>');
    return (
      '<article class="case-card" tabindex="0" role="button" data-case="' + index + '" aria-haspopup="dialog" style="animation-delay:' + index * 70 + 'ms">' +
        '<span class="case-mark" aria-hidden="true">' + String(index + 1).padStart(2, "0") + "</span>" +
        '<span class="case-top"><span class="case-id">' + esc(item.id) + '</span><span class="case-verdict">' + esc(item.verdict) + "</span></span>" +
        "<h3>" + esc(item.title) + "</h3>" +
        "<p>" + esc(item.summary) + "</p>" +
        (chain ? '<div class="case-chain" aria-hidden="true">' + chain + "</div>" : "") +
        '<span class="case-techs">' + techs + extra + "</span>" +
        '<span class="case-foot"><span><b>' + esc(item.hosts.join(", ")) + "</b></span><span>open file</span></span>" +
      "</article>"
    );
  }).join("") || '<div class="empty">No case files committed yet.</div>';

  /* The case cards are a horizontal reel: native scroll-snap plus explicit
     previous/next controls so it is discoverable without a trackpad gesture. */
  const caseReel = $("#caseGrid");
  const casePrev = $("#casePrev");
  const caseNext = $("#caseNext");
  function updateCaseReel() {
    if (!caseReel || !casePrev || !caseNext) return;
    const max = caseReel.scrollWidth - caseReel.clientWidth;
    casePrev.disabled = caseReel.scrollLeft <= 4;
    caseNext.disabled = caseReel.scrollLeft >= max - 4;
  }
  if (caseReel && casePrev && caseNext) {
    const reelStep = () => {
      const card = caseReel.querySelector(".case-card");
      return card ? card.offsetWidth + 12 : caseReel.clientWidth * 0.82;
    };
    casePrev.addEventListener("click", () => caseReel.scrollBy({ left: -reelStep(), behavior: reduce ? "auto" : "smooth" }));
    caseNext.addEventListener("click", () => caseReel.scrollBy({ left: reelStep(), behavior: reduce ? "auto" : "smooth" }));
    caseReel.addEventListener("scroll", updateCaseReel, { passive: true });
    window.addEventListener("resize", updateCaseReel);
    updateCaseReel();
  }

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
    const caseModal = $("#caseModal");
    const card = document.querySelector('.case-card[data-case="' + index + '"]');
    if (caseModal && card) {
      const r = card.getBoundingClientRect();
      caseModal.style.setProperty("--case-x", (r.left + r.width / 2) + "px");
      caseModal.style.setProperty("--case-y", (r.top + r.height / 2) + "px");
    }
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
    "python -m pipeline.labgen --scenario all --base-time 2026-11-11T12:30:00Z",
    "python -m pipeline.compile",
    "docker compose up -d",
    "python -m pipeline.ingest --reset",
    "python -m pipeline.detect --hours 24 --end 2026-11-11T12:30:00Z",
    "python -m pipeline.report"
  ].join("\n");
  $("#copyAll").addEventListener("click", () => {
    copyText(reproduceCommands).then(() => toast("six commands copied")).catch(() => toast("copy failed"));
  });

  /* ------------------------------------------------------------------ tour */
  const steps = [
    { target: "#cover .ticket", title: "A run you can inspect", body: "This is the output of one deterministic run: 9,223 events, a 50-rule Sigma library, and eight correlation specs. The ticket is the receipt." },
    { target: "#scopePlate", title: "Read the light curve", body: "The light curve counts matched events across the full day. Several hours carry bursts; the shadow bands between them are part of the shape. A rule that fires on everything cannot discriminate." },
    { target: "#pathStrip", title: "Follow the chain", body: "Sigma compiles to Elasticsearch EQL and KQL. Detection executes the queries, correlation adds volume logic, and triage turns matches into a queue with evidence." },
    { target: "#ledger .chapter-head", title: "Enter the Umbra", body: "Umbra is the working console. The queue, the evidence inspector, the host lanes, and the coincidence strip all read from the same detection run." },
    { target: "#ledgerPanel", title: "Work the queue", body: "Filter by severity, host, or technique. Select a detection to keep its events and exact EQL beside the queue. J and K move; Enter selects." },
    { target: "#wfLaneList", title: "Read the field", body: "Every mark is a detection against the 24-hour window, one lane per host. The coincidence strip below adds the volume conditions that a single event cannot carry." },
    { target: "#matrix", title: "Read the corona", body: "The corona ring only counts priority techniques. All 45 are closed in this run; the gaps view stays available as a regression check." },
    { target: "#caseGrid", title: "Read the investigations", body: "Each case follows the same structure: summary, timeline, evidence, analysis, verdict, containment, and the detection improvement that came out of it." },
    { target: "#reproduce .terminal", title: "Repeat the orbit", body: "Generation is seeded. The same commands produce the same events, the same alerts, and this same page. Swap the logsource map when you connect real telemetry." }
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
    // Guided reading should land on the step immediately. The page sets
    // scroll-behavior: smooth for anchor links, which can swallow a programmatic
    // scroll and leave the tour card describing something off screen.
    const root = document.documentElement;
    const previous = root.style.scrollBehavior;
    root.style.scrollBehavior = "auto";
    window.scrollTo({ top: Math.max(0, rect.top + window.scrollY - offset), behavior: "auto" });
    root.style.scrollBehavior = previous;
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
    if (target) {
      const reveal = target.closest("[data-reveal]");
      if (reveal) reveal.classList.add("in");
      scrollTarget(target);
    }
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
    { group: "Go", label: "Penumbra", hint: "00", run: () => goTo("#cover") },
    { group: "Go", label: "First light", hint: "01", run: () => goTo("#run") },
    { group: "Go", label: "Instruments", hint: "02", run: () => goTo("#method") },
    { group: "Go", label: "Umbra", hint: "03", run: () => goTo("#ledger") },
    { group: "Go", label: "Corona", hint: "04", run: () => goTo("#coverage") },
    { group: "Go", label: "Eclipses", hint: "05", run: () => goTo("#cases") },
    { group: "Go", label: "Recurrence", hint: "06", run: () => goTo("#reproduce") },
    { group: "Filter", label: "All detections", hint: "clear severity", run: () => { setLevel("all"); goTo("#ledger"); } },
    { group: "Filter", label: "Critical detections", hint: number(severity.critical || 0), run: () => { setLevel("critical"); goTo("#ledger"); } },
    { group: "Filter", label: "High detections", hint: number(severity.high || 0), run: () => { setLevel("high"); goTo("#ledger"); } },
    { group: "Filter", label: "Medium detections", hint: number(severity.medium || 0), run: () => { setLevel("medium"); goTo("#ledger"); } },
    { group: "Filter", label: "Low detections", hint: number(severity.low || 0), run: () => { setLevel("low"); goTo("#ledger"); } },
    { group: "View", label: state.gaps ? "Show all techniques" : "Show gaps only", hint: "coverage", run: () => { toggleGaps(); goTo("#coverage"); } },
    { group: "View", label: "Switch theme", hint: "paper / night", run: toggleTheme },
    { group: "Reading", label: "Start guided reading", hint: steps.length + " steps", run: startTour },
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
    else if (event.key.toLowerCase() === "p") { const play = $("#phasePlay"); if (play) play.click(); }
    else if (event.key === "?") openKeys();
  });

  /* -------------------------------------------------------------- scroll UI */
  const progressBar = $("#scrollProgress");
  const railFill = $("#railFill");

  /* The corona ring turns slightly as the coverage section passes. */
  const coverageSection = $("#coverage");
  const coverageGauge = $(".gauge");
  if (coverageSection && coverageGauge && !reduce) {
    let gaugeTick = 0;
    const turnGauge = () => {
      const rect = coverageSection.getBoundingClientRect();
      const p = Math.min(1, Math.max(0, (window.innerHeight - rect.top) / (window.innerHeight + rect.height)));
      coverageGauge.style.transform = "rotate(" + ((p - 0.5) * 18).toFixed(2) + "deg)";
      gaugeTick = 0;
    };
    window.addEventListener("scroll", () => {
      if (!gaugeTick) gaugeTick = requestAnimationFrame(turnGauge);
    }, { passive: true });
    turnGauge();
  }
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

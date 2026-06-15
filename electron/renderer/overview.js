// Overview dashboard controller.
//
// This is the default landing page. Every value shown here is loaded from real
// HomeGuard state through the existing `window.homeguard` IPC bridge -- latest
// scan report, known-device baseline, definition status, scan history, schedule
// state, AI bridge status, and persisted UI preferences. There is NO mock or
// sample data: when a value cannot be loaded we show an explicit "no scan yet"
// or "not available" state instead of inventing numbers.
//
// The module is intentionally self-contained (an IIFE that only touches its own
// DOM ids and the homeguard bridge) so it does not entangle with renderer.js.
(function () {
  "use strict";

  const hg = () => (typeof window !== "undefined" ? window.homeguard : null);
  const byId = (id) => document.getElementById(id);

  // ---- small helpers -------------------------------------------------------

  function setText(id, value) {
    const el = byId(id);
    if (el) el.textContent = value == null ? "" : String(value);
  }

  function clear(el) {
    while (el && el.firstChild) el.removeChild(el.firstChild);
  }

  function greetingForHour(hour) {
    if (hour >= 5 && hour < 12) return "Good morning";
    if (hour >= 12 && hour < 17) return "Good afternoon";
    if (hour >= 17 && hour < 22) return "Good evening";
    return "Good night";
  }

  function relativeTime(iso) {
    if (!iso) return "";
    const then = new Date(iso);
    if (Number.isNaN(then.getTime())) return "";
    const diff = Math.max(0, Date.now() - then.getTime());
    const min = Math.floor(diff / 60000);
    if (min < 1) return "just now";
    if (min < 60) return `${min}m ago`;
    const hr = Math.floor(min / 60);
    if (hr < 24) return `${hr}h ago`;
    const day = Math.floor(hr / 24);
    if (day < 7) return `${day}d ago`;
    return then.toISOString().slice(0, 10);
  }

  const SEVERITY_RANK = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
  const RISKY_RISK = new Set(["medium", "high", "critical", "elevated", "guarded"]);

  // Tracks the latest loaded state so the assistant quick-actions and the
  // greeting can react without re-fetching.
  const state = {
    report: null, // summarized report or null when no scan exists
    scanning: false,
    uiPrefs: { show_chat_bubble: true, show_weather_greeting: false },
  };

  // The spinning GreyNOC globe in the hero (shared Three.js orb renderer). It
  // idles with a slow rotation and spins faster while a scan is running.
  let globe = null;

  // ---- data loading --------------------------------------------------------

  async function safeInvoke(fn, fallback) {
    try {
      const value = await fn();
      return value == null ? fallback : value;
    } catch {
      return fallback;
    }
  }

  async function loadAll() {
    const bridge = hg();
    if (!bridge) return null;
    const [report, devices, defs, history, schedule, ai, prefs] = await Promise.all([
      safeInvoke(() => bridge.latestReport?.(), { ok: false }),
      safeInvoke(() => bridge.devices?.(), { devices: [] }),
      safeInvoke(() => bridge.definitionsStatus?.(), { status: {} }),
      safeInvoke(() => bridge.historyState?.(), { entries: [] }),
      safeInvoke(() => bridge.schedule?.(), { schedule: {} }),
      safeInvoke(() => bridge.ai?.status?.(), null),
      safeInvoke(() => bridge.uiPrefs?.get?.(), state.uiPrefs),
    ]);
    return { report, devices, defs, history, schedule, ai, prefs };
  }

  // ---- rendering -----------------------------------------------------------

  function reportData(reportResult) {
    // latest-report returns { ok, report } on success, { ok:false } otherwise.
    if (reportResult && reportResult.ok && reportResult.report && typeof reportResult.report === "object") {
      return reportResult.report;
    }
    return null;
  }

  function renderGreeting(report) {
    setText("ovGreeting", greetingForHour(new Date().getHours()));
    let subtext;
    if (state.scanning) {
      subtext = "Scanning your network now.";
    } else if (!report) {
      subtext = "Run your first scan to check your home network.";
    } else {
      const risk = String(report.overall_risk || "").toLowerCase();
      subtext = RISKY_RISK.has(risk) ? "A few items need your review." : "Your network is protected.";
    }
    setText("ovSubtext", subtext);
  }

  function renderRiskCard(report) {
    if (!report) {
      setText("ovRiskValue", "No scan yet");
      setText("ovRiskDetail", "Run your first scan");
      return;
    }
    const risk = String(report.overall_risk || "unknown");
    setText("ovRiskValue", risk.charAt(0).toUpperCase() + risk.slice(1));
    const score = Number(report.overall_score || 0);
    setText("ovRiskDetail", RISKY_RISK.has(risk.toLowerCase()) ? `Score ${score} - review recommended` : "No urgent issues");
  }

  function renderDevicesCard(report, devicesResult) {
    const rows = devicesResult && Array.isArray(devicesResult.devices) ? devicesResult.devices : [];
    const count = report ? Number(report.device_count || rows.length || 0) : rows.length;
    if (!report && !rows.length) {
      setText("ovDeviceCount", "-");
      setText("ovDeviceDetail", "Run a scan to see this");
      return;
    }
    setText("ovDeviceCount", String(count));
    const unknown = rows.filter((r) => String(r.trust || "unknown").toLowerCase() === "unknown").length;
    setText("ovDeviceDetail", unknown ? `${unknown} unknown` : "All recognized");
  }

  function findingsBySeverity(report) {
    const findings = report && Array.isArray(report.findings) ? report.findings : [];
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of findings) {
      const sev = String(f.severity || "info").toLowerCase();
      if (counts[sev] != null) counts[sev] += 1;
    }
    return counts;
  }

  function renderAlertsCard(report) {
    if (!report) {
      setText("ovAlertCount", "-");
      setText("ovAlertDetail", "Run a scan to see this");
      return;
    }
    const total = Number(report.finding_count || (report.findings || []).length || 0);
    setText("ovAlertCount", String(total));
    if (!total) {
      setText("ovAlertDetail", "No active alerts");
      return;
    }
    const counts = findingsBySeverity(report);
    const serious = counts.critical + counts.high;
    setText("ovAlertDetail", serious ? `${serious} high-priority` : "Review recommended");
  }

  function securityUpdateFindingCount(report) {
    const findings = report && Array.isArray(report.findings) ? report.findings : [];
    return findings.filter((f) => {
      const cat = String(f.category || "").toLowerCase();
      return cat === "known_exploited_vulnerability" || cat === "security_update";
    }).length;
  }

  function renderUpdatesCard(report, defsResult) {
    const status = defsResult && defsResult.status && typeof defsResult.status === "object" ? defsResult.status : {};
    const updateFindings = securityUpdateFindingCount(report);
    const updateStatus = String(status.update_status || "").toLowerCase();
    if (!status.update_status && !report) {
      setText("ovUpdateCount", "-");
      setText("ovUpdateDetail", "Definitions status unavailable");
      return;
    }
    if (updateFindings > 0) {
      setText("ovUpdateCount", String(updateFindings));
      setText("ovUpdateDetail", "Important available");
      return;
    }
    // No patch-priority findings: surface definition freshness instead.
    const fresh = ["current", "ok", "up-to-date", "up to date", "fresh", "updated"].includes(updateStatus);
    setText("ovUpdateCount", fresh ? "0" : "1");
    setText("ovUpdateDetail", fresh ? "Up to date" : updateStatus ? "Definitions update available" : "Definitions status unavailable");
  }

  function renderRecommended(report) {
    const container = byId("ovRecommended");
    if (!container) return;
    clear(container);
    if (!report) {
      const empty = document.createElement("p");
      empty.className = "ov-muted";
      empty.textContent = "Run your first scan to get personalized recommendations.";
      container.appendChild(empty);
      return;
    }
    // Prefer the grouped priority_actions (action + count); fall back to the
    // flat next_steps list. Both come straight from the real report.
    let items = [];
    if (Array.isArray(report.priority_actions) && report.priority_actions.length) {
      items = report.priority_actions.map((a) => ({
        title: String(a.action || ""),
        detail: String(a.detail || ""),
        count: Number(a.count || 0),
      }));
    } else if (Array.isArray(report.next_steps) && report.next_steps.length) {
      items = report.next_steps.slice(0, 5).map((s) => ({ title: String(s), detail: "", count: 0 }));
    }
    if (!items.length) {
      const empty = document.createElement("p");
      empty.className = "ov-muted";
      empty.textContent = "No actions needed right now. Keep your definitions current.";
      container.appendChild(empty);
      return;
    }
    for (const item of items.slice(0, 5)) {
      const row = document.createElement("button");
      row.type = "button";
      row.className = "ov-reco";
      const label = item.count ? `${item.title} (${item.count})` : item.title;
      const title = document.createElement("b");
      title.textContent = label;
      const detail = document.createElement("span");
      detail.textContent = item.detail || "";
      row.appendChild(title);
      row.appendChild(detail);
      // Recommendations route to the assistant for a deeper explanation, using
      // the real report context.
      row.addEventListener("click", () => sendToAssistant(`What should I do about: ${item.title}?`));
      container.appendChild(row);
    }
  }

  function renderActivity(report, historyResult, defsResult, scheduleResult) {
    const container = byId("ovActivity");
    if (!container) return;
    clear(container);
    const events = [];
    const entries = historyResult && Array.isArray(historyResult.entries) ? historyResult.entries : [];
    for (const entry of entries.slice(0, 6)) {
      if (entry && entry.created_at) {
        events.push({ when: entry.created_at, icon: "ok", text: "Scan completed" });
      }
    }
    const defs = defsResult && defsResult.status ? defsResult.status : {};
    const defUpdated = defs.last_updated || defs.updated_at;
    if (defUpdated) events.push({ when: defUpdated, icon: "info", text: "Definitions updated" });
    const schedule = scheduleResult && scheduleResult.schedule ? scheduleResult.schedule : {};
    if (schedule.enabled && schedule.next_run) {
      events.push({ when: schedule.next_run, icon: "cal", text: "Scan scheduled", future: true });
    }
    if (!events.length) {
      const empty = document.createElement("p");
      empty.className = "ov-muted";
      empty.textContent = "No activity yet. Run a scan to start your history.";
      container.appendChild(empty);
      return;
    }
    // Most recent first (scheduled future events sort to the bottom by time).
    events.sort((a, b) => new Date(b.when).getTime() - new Date(a.when).getTime());
    for (const ev of events.slice(0, 6)) {
      const row = document.createElement("div");
      row.className = "ov-activity-row";
      const dot = document.createElement("span");
      dot.className = `ov-dot ov-dot-${ev.icon}`;
      const text = document.createElement("span");
      text.className = "ov-activity-text";
      text.textContent = ev.text;
      const time = document.createElement("span");
      time.className = "ov-activity-time";
      time.textContent = relativeTime(ev.when) || "";
      row.appendChild(dot);
      row.appendChild(text);
      row.appendChild(time);
      container.appendChild(row);
    }
  }

  function renderLastScan(report, historyResult) {
    let created = report ? report.created_at : "";
    if (!created) {
      const entries = historyResult && Array.isArray(historyResult.entries) ? historyResult.entries : [];
      created = entries.length ? entries[0].created_at : "";
    }
    setText("ovLastScan", created ? `Last scan: ${relativeTime(created)}` : "No scan yet");
  }

  function renderProtectionSummary(report, defsResult) {
    const state = byId("ovProtectionState");
    const detail = byId("ovProtectionDetail");
    if (!report) {
      if (state) state.textContent = "Not scanned yet";
      if (detail) detail.textContent = "Run your first scan";
      return;
    }
    const risk = String(report.overall_risk || "").toLowerCase();
    const ok = !RISKY_RISK.has(risk);
    if (state) state.textContent = ok ? "All systems protected" : "A few items need review";
    const defs = defsResult && defsResult.status ? defsResult.status : {};
    const updated = defs.last_updated || defs.updated_at;
    if (detail) detail.textContent = updated ? `Definitions updated ${relativeTime(updated)}` : "Definitions status unavailable";
  }

  function renderScanMode() {
    // Active scan is opt-in and off by default. Reflect the Console toggle if it
    // exists; otherwise show the safe passive default.
    const activeScan = byId("activeScan");
    const isActive = Boolean(activeScan && activeScan.checked);
    setText("ovScanModeValue", isActive ? "Active scan on" : "Passive mode");
    setText("ovScanModeDetail", isActive ? "Bounded private-network checks" : "Active scans disabled");
  }

  function renderAssistantMode(aiStatus) {
    const el = byId("ovAssistantMode");
    if (!el) return;
    // ai.status() shape varies; derive a human label conservatively and never
    // claim a provider is active unless the bridge says so.
    let label = "Local AI (Sterile)";
    if (aiStatus && typeof aiStatus === "object") {
      const enabled = aiStatus.enabled ?? aiStatus.configured ?? aiStatus.active;
      const provider = aiStatus.provider || aiStatus.model;
      const sterile = aiStatus.sterile ?? aiStatus.offline;
      if (enabled === false || aiStatus.mode === "disabled") {
        label = "AI disabled";
      } else if (provider && enabled) {
        label = `${String(provider)}`;
      } else if (sterile === false && provider) {
        label = String(provider);
      } else {
        label = "Local AI (Sterile)";
      }
    }
    el.textContent = label;
  }

  // ---- assistant quick actions --------------------------------------------

  // Route a prompt into the existing, report-aware chat assistant on the
  // Console tab. This reuses the real AI pipeline (chat-assistant.js) instead
  // of duplicating it, so "no scan" / sterile / disabled states are handled in
  // exactly one place.
  function sendToAssistant(prompt) {
    const protectionTab = byId("protectionTab");
    if (protectionTab) protectionTab.click();
    const input = byId("chatInput");
    const form = byId("chatForm");
    if (input && form) {
      input.value = prompt;
      // Submit through the existing composer so chat history + AI routing apply.
      form.requestSubmit ? form.requestSubmit() : form.dispatchEvent(new Event("submit", { cancelable: true, bubbles: true }));
    }
  }

  function wireQuickActions() {
    const actions = {
      ovQuickExplain: () => {
        const report = state.report;
        const findings = report && Array.isArray(report.findings) ? report.findings.slice() : [];
        if (!report || !findings.length) {
          sendToAssistant("Explain my most important alert.");
          return;
        }
        findings.sort((a, b) => (SEVERITY_RANK[String(b.severity || "info").toLowerCase()] || 0) - (SEVERITY_RANK[String(a.severity || "info").toLowerCase()] || 0));
        const top = findings[0];
        sendToAssistant(`Explain this alert: ${String(top.title || top.rule_id || "the top finding")}.`);
      },
      ovQuickFirst: () => sendToAssistant("What should I do first?"),
      ovQuickSecure: () => sendToAssistant("How do I secure my home network?"),
      ovQuickSummarize: () => sendToAssistant("Summarize my last scan."),
    };
    for (const [id, handler] of Object.entries(actions)) {
      const btn = byId(id);
      if (btn) btn.addEventListener("click", handler);
    }
  }

  // ---- settings + floating bubble -----------------------------------------

  function applyBubbleVisibility(show) {
    const bubble = byId("floatingChatBubble");
    if (bubble) bubble.classList.toggle("is-hidden", !show);
  }

  function renderSettings(prefs) {
    state.uiPrefs = {
      show_chat_bubble: prefs?.show_chat_bubble !== false,
      show_weather_greeting: prefs?.show_weather_greeting === true,
    };
    const bubbleToggle = byId("ovToggleBubble");
    const weatherToggle = byId("ovToggleWeather");
    if (bubbleToggle) bubbleToggle.checked = state.uiPrefs.show_chat_bubble;
    if (weatherToggle) weatherToggle.checked = state.uiPrefs.show_weather_greeting;
    applyBubbleVisibility(state.uiPrefs.show_chat_bubble);
  }

  async function persistPref(patch) {
    const bridge = hg();
    if (!bridge?.uiPrefs?.set) return;
    const updated = await safeInvoke(() => bridge.uiPrefs.set(patch), null);
    if (updated) renderSettings(updated);
  }

  function wireSettings() {
    const toggle = byId("ovSettingsToggle");
    const panel = byId("ovSettingsPanel");
    if (toggle && panel) {
      toggle.addEventListener("click", () => panel.classList.toggle("is-open"));
      document.addEventListener("click", (event) => {
        if (!panel.contains(event.target) && event.target !== toggle && !toggle.contains(event.target)) {
          panel.classList.remove("is-open");
        }
      });
    }
    const bubbleToggle = byId("ovToggleBubble");
    if (bubbleToggle) {
      bubbleToggle.addEventListener("change", () => {
        applyBubbleVisibility(bubbleToggle.checked);
        persistPref({ show_chat_bubble: bubbleToggle.checked });
      });
    }
    const weatherToggle = byId("ovToggleWeather");
    if (weatherToggle) {
      weatherToggle.addEventListener("change", () => persistPref({ show_weather_greeting: weatherToggle.checked }));
    }
    const bubble = byId("floatingChatBubble");
    if (bubble) {
      bubble.addEventListener("click", () => {
        const protectionTab = byId("protectionTab");
        if (protectionTab) protectionTab.click();
        const input = byId("chatInput");
        if (input) input.focus();
      });
    }
  }

  // ---- scan flow -----------------------------------------------------------

  function wireScanNow() {
    const btn = byId("ovScanNow");
    if (!btn) return;
    btn.addEventListener("click", async () => {
      const bridge = hg();
      if (!bridge?.scan || state.scanning) return;
      state.scanning = true;
      btn.disabled = true;
      if (globe) globe.setActive(true);
      renderGreeting(state.report);
      setText("ovLastScan", "Scanning...");
      const activeScan = byId("activeScan");
      try {
        await bridge.scan({ active: Boolean(activeScan && activeScan.checked), probeAll: false });
      } catch {
        /* errors surface on refresh below */
      } finally {
        state.scanning = false;
        btn.disabled = false;
        if (globe) globe.setActive(false);
        await refresh();
      }
    });
  }

  // ---- orchestration -------------------------------------------------------

  async function refresh() {
    // loadAll() returns null only when the IPC bridge is unavailable. We still
    // render the honest empty state in that case rather than leaving stale
    // "loading" text on screen -- we never invent placeholder data.
    const data = await loadAll();
    const report = data ? reportData(data.report) : null;
    state.report = report;
    renderGreeting(report);
    renderRiskCard(report);
    renderDevicesCard(report, data ? data.devices : null);
    renderAlertsCard(report);
    renderUpdatesCard(report, data ? data.defs : null);
    renderRecommended(report);
    renderActivity(report, data ? data.history : null, data ? data.defs : null, data ? data.schedule : null);
    renderLastScan(report, data ? data.history : null);
    renderProtectionSummary(report, data ? data.defs : null);
    renderScanMode();
    renderAssistantMode(data ? data.ai : null);
    renderSettings(data ? data.prefs : state.uiPrefs);
  }

  function init() {
    // Spin up the shared GreyNOC globe in the hero. It rotates on its own (idle
    // spin); we only toggle the brighter "active" state while scanning.
    if (typeof window.initScanOrb3D === "function") {
      globe = window.initScanOrb3D(byId("ovGlobe"));
      if (globe) globe.setActive(false);
    }
    wireQuickActions();
    wireSettings();
    wireScanNow();
    // Live progress: when a scan reports progress (from any trigger), reflect it.
    const bridge = hg();
    if (bridge?.onScanProgress) {
      bridge.onScanProgress(() => {
        if (globe) globe.setActive(true);
        if (!state.scanning) {
          state.scanning = true;
          renderGreeting(state.report);
        }
      });
    }
    // Initial paint with a calm placeholder before data resolves.
    setText("ovGreeting", greetingForHour(new Date().getHours()));
    refresh();
  }

  window.HomeGuardOverview = { init, refresh };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();

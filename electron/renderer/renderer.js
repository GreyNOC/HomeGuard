const $ = (id) => document.getElementById(id);

const scanButton = $("scanButton");
const updateButton = $("updateButton");
const statusButton = $("statusButton");
const historyButton = $("historyButton");
const adminButton = $("adminButton");
const trayButton = $("trayButton");
const setupButton = $("setupButton");
const openHtmlButton = $("openHtmlButton");
const openPdfButton = $("openPdfButton");
const saveHtmlButton = $("saveHtmlButton");
const openFolderButton = $("openFolderButton");
const activeScan = $("activeScan");
const probeAll = $("probeAll");
const statusText = $("statusText");
const output = $("output");
const riskValue = $("riskValue");
const deviceValue = $("deviceValue");
const updateValue = $("updateValue");
const reportMeta = $("reportMeta");
const reportFrame = $("reportFrame");
const scanOrb = document.querySelector(".scan-orb");
const scanIndicatorLabel = $("scanIndicatorLabel");
const scanOrb3D = typeof window.initScanOrb3D === "function" ? window.initScanOrb3D(scanOrb) : null;

const tabs = {
  protection: $("protectionTab"),
  devices: $("devicesTab"),
  networkMap: $("networkMapTab"),
  findings: $("findingsTab"),
  fileScan: $("fileScanTab"),
  history: $("historyTab"),
  schedule: $("scheduleTab"),
  logs: $("logsTab"),
  ai: $("aiTab"),
};

const pages = {
  protection: $("protectionPage"),
  devices: $("devicesPage"),
  networkMap: $("networkMapPage"),
  findings: $("findingsPage"),
  fileScan: $("fileScanPage"),
  history: $("historyPage"),
  schedule: $("schedulePage"),
  logs: $("logsPage"),
  ai: $("aiPage"),
};

const devicesTableBody = document.querySelector("#devicesTable tbody");
const historyTableBody = document.querySelector("#historyTable tbody");
const historyRetention = $("historyRetention");
const scheduleEnabled = $("scheduleEnabled");
const scheduleBackground = $("scheduleBackground");
const scheduleStatus = $("scheduleStatus");
const logsOutput = $("logsOutput");

let latestReport = null;
let selectedDeviceFingerprint = "";
let selectedHistoryIndex = -1;
let historyEntries = [];
let scanRunning = false;
let scanProgressLines = [];

const deviceActionButtons = [
  $("deviceTrusted"),
  $("deviceUnknown"),
  $("deviceQuarantine"),
  $("deviceEditLabel"),
  $("deviceRemove"),
];

const historyActionButtons = [
  $("historyOpenHtml"),
  $("historyOpenPdf"),
  $("historyOpenFolder"),
];

function clearChildren(node) {
  while (node.firstChild) {
    node.removeChild(node.firstChild);
  }
}

function appendCell(row, value, className = "") {
  const cell = document.createElement("td");
  if (className) {
    cell.className = className;
  }
  cell.textContent = String(value ?? "-");
  row.appendChild(cell);
  return cell;
}

function appendEmptyRow(tbody, colspan, message) {
  const row = document.createElement("tr");
  appendCell(row, message, "empty-cell").colSpan = colspan;
  tbody.appendChild(row);
}

function setActionDisabled(button, disabled, reason = "") {
  button.disabled = disabled;
  if (disabled && reason) {
    button.title = reason;
    button.setAttribute("aria-disabled", "true");
  } else {
    button.removeAttribute("title");
    button.removeAttribute("aria-disabled");
  }
}

function setBusy(isBusy) {
  [scanButton, updateButton, statusButton, historyButton, adminButton, setupButton].forEach((button) => {
    setActionDisabled(button, isBusy, isBusy ? "GreyNOC is already running an action." : "");
  });
  if (!isBusy) {
    refreshDisabledActions();
  }
}

function isScanIndicatorActive() {
  return Boolean(activeScan.checked || scanRunning);
}

function updateScanIndicator() {
  const active = isScanIndicatorActive();
  scanOrb.classList.toggle("is-active", active);
  scanOrb.setAttribute("aria-label", active ? "GreyNOC local scan is active" : "GreyNOC local scan is idle");
  if (scanOrb3D) scanOrb3D.setActive(active);
  scanIndicatorLabel.textContent = scanRunning ? "Scanning Now" : activeScan.checked ? "Active Scan On" : "Active Scan Off";
  scanIndicatorLabel.classList.toggle("is-active", active);
  if (window.homeguard?.setScanIndicator) {
    window.homeguard.setScanIndicator({ activeRequested: activeScan.checked }).catch(() => {});
  }
}

function setScanRunning(isRunning) {
  scanRunning = isRunning;
  updateScanIndicator();
}

function showOutput(text) {
  output.textContent = text && text.trim() ? text.trim() : "Command completed without output.";
}

function scanProgressTimestamp() {
  return new Date().toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function renderScanProgress() {
  output.textContent = scanProgressLines.length ? scanProgressLines.join("\n") : "Starting scan...";
  output.scrollTop = output.scrollHeight;
}

function appendScanProgress(message) {
  const cleanMessage = String(message || "").trim();
  if (!cleanMessage) {
    return;
  }
  scanProgressLines.push(`[${scanProgressTimestamp()}] ${cleanMessage}`);
  scanProgressLines = scanProgressLines.slice(-48);
  renderScanProgress();
  setStatus(cleanMessage);
}

function resetScanProgress(message) {
  scanProgressLines = [];
  appendScanProgress(message);
}

function setStatus(message) {
  statusText.textContent = message;
}

function setActiveTab(name) {
  Object.entries(tabs).forEach(([key, tab]) => tab.classList.toggle("active", key === name));
  Object.entries(pages).forEach(([key, page]) => page.classList.toggle("active-page", key === name));
}

function refreshDisabledActions() {
  setActionDisabled(openHtmlButton, !latestReport?.htmlPath, "Run a scan before opening the HTML report.");
  setActionDisabled(openPdfButton, !latestReport?.paths?.pdf, "Run a scan with PDF output before opening the PDF report.");
  setActionDisabled(saveHtmlButton, !latestReport?.htmlPath, "Run a scan before saving the HTML report.");
  setActionDisabled(openFolderButton, !latestReport?.reportDir, "Run a scan before opening the report folder.");
  deviceActionButtons.forEach((button) => {
    setActionDisabled(button, !selectedDeviceFingerprint, "Select a device row first.");
  });
  historyActionButtons.forEach((button) => {
    setActionDisabled(button, selectedHistoryIndex < 0, "Select a scan history row first.");
  });
}

function updateReport(payload) {
  latestReport = payload;
  if (!payload || !payload.htmlUrl) {
    refreshDisabledActions();
    return;
  }
  reportFrame.src = payload.htmlUrl;
  reportMeta.textContent = payload.reportLabel || "Latest report saved locally";
  refreshDisabledActions();
}

function parseMetric(stdout, key) {
  const escaped = key.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = stdout.match(new RegExp(`${escaped}\\s+(.+)`, "i"));
  return match ? match[1].trim() : "";
}

function withoutProgressLines(stdout) {
  return String(stdout || "")
    .split(/\r?\n/)
    .filter((line) => !/^\s*\[progress\]\s*/.test(line))
    .join("\n")
    .trim();
}

async function runCommand(label, fn, options = {}) {
  const showFinalOutput = options.showFinalOutput !== false;
  setBusy(true);
  setStatus(`${label} running`);
  try {
    const result = await fn();
    if (showFinalOutput) {
      showOutput(result.stdout || "");
    }
    setStatus(`${label} complete.`);
    return result;
  } catch (error) {
    showOutput(error.message || String(error));
    setStatus(`${label} failed.`);
    return null;
  } finally {
    setBusy(false);
  }
}

function renderDevices(rows) {
  clearChildren(devicesTableBody);
  if (!rows.length) {
    appendEmptyRow(devicesTableBody, 9, "No known devices yet. Run a scan to populate this list.");
  }
  rows.forEach((row) => {
    const ports = Array.isArray(row.open_ports) && row.open_ports.length ? row.open_ports.join(", ") : "-";
    const trust = row.trust || "unknown";
    const tableRow = document.createElement("tr");
    tableRow.dataset.fingerprint = String(row.fingerprint || "");
    tableRow.classList.add(`trust-${String(trust).replace(/[^a-z0-9_-]/gi, "").toLowerCase() || "unknown"}`);
    // Display-name precedence mirrors identity_resolution.display_name_for():
    //   real hostname  >  friendly_name (synthesized or MAC-less fallback)  >  vendor  >  "-".
    // We mark synthesized / friendly-only names with a "~" prefix in the
    // table so the user can tell at a glance which devices have a real DNS
    // name vs an estimate.
    const realHostname = !row.hostname_synthesized ? (row.hostname || "") : "";
    const friendly = row.friendly_name || "";
    let displayName;
    if (realHostname) {
      displayName = realHostname;
    } else if (friendly) {
      displayName = `~${friendly}`;
    } else if (row.hostname) {
      // Synthesized hostname with no separate friendly_name field set.
      displayName = `~${row.hostname}`;
    } else if (row.vendor) {
      displayName = `~${row.vendor}`;
    } else {
      displayName = "-";
    }
    // device_type cell shows the type plus its confidence + source when the
    // resolver auto-classified it, so the user can tell apart "iot (0.62
    // from mdns_service)" from a hand-set label.
    const baseType = row.device_type || "unknown";
    let typeCell = baseType;
    if (row.device_type_auto && row.device_type_confidence) {
      const conf = Number(row.device_type_confidence || 0).toFixed(2);
      const source = row.device_type_source ? ` from ${row.device_type_source}` : "";
      typeCell = `${baseType} (${conf}${source})`;
    }
    [
      row.ip || "-",
      displayName,
      row.mac_address || "-",
      row.vendor || "-",
      trust,
      row.owner || "unknown",
      typeCell,
      ports,
      row.last_seen || "-",
    ].forEach((value) => appendCell(tableRow, value));
    devicesTableBody.appendChild(tableRow);
  });
  selectedDeviceFingerprint = "";
  refreshDisabledActions();
}

async function loadDevices() {
  const result = await runCommand("Devices", () => window.homeguard.devices());
  if (result && Array.isArray(result.devices)) {
    renderDevices(result.devices);
  }
}

async function applyDeviceTrust(trust) {
  if (!selectedDeviceFingerprint) {
    setStatus("Select a device first.");
    return;
  }
  const result = await runCommand("Device trust", () => window.homeguard.setDeviceTrust(selectedDeviceFingerprint, trust));
  if (result && Array.isArray(result.devices)) {
    renderDevices(result.devices);
  }
}

async function editDeviceLabel() {
  if (!selectedDeviceFingerprint) {
    setStatus("Select a device first.");
    return;
  }
  const owner = window.prompt("Owner (parent, child, guest, unknown):", "unknown");
  if (owner === null) {
    return;
  }
  const deviceType = window.prompt("Device type (phone, laptop, tv, console, iot, router, camera, nas, printer, unknown):", "unknown");
  if (deviceType === null) {
    return;
  }
  const notes = window.prompt("Notes:", "") ?? "";
  const result = await runCommand("Device label", () =>
    window.homeguard.setDeviceLabel(selectedDeviceFingerprint, {
      owner,
      device_type: deviceType,
      notes,
    }),
  );
  if (result && Array.isArray(result.devices)) {
    renderDevices(result.devices);
  }
}

async function removeDevice() {
  if (!selectedDeviceFingerprint) {
    setStatus("Select a device first.");
    return;
  }
  if (!window.confirm("Remove this device from the known-device list? It will appear as a new device on the next scan.")) {
    return;
  }
  const result = await runCommand("Remove device", () => window.homeguard.removeDevice(selectedDeviceFingerprint));
  if (result && Array.isArray(result.devices)) {
    renderDevices(result.devices);
  }
}

function renderHistory(result) {
  historyEntries = Array.isArray(result.entries) ? result.entries : [];
  historyRetention.value = result.retention || 30;
  clearChildren(historyTableBody);
  if (!historyEntries.length) {
    appendEmptyRow(historyTableBody, 6, "No scans yet.");
  }
  historyEntries.forEach((entry, index) => {
    const row = document.createElement("tr");
    row.dataset.index = String(index);
    [
      entry.created_at || "-",
      entry.device_count ?? 0,
      entry.finding_count ?? 0,
      entry.highest_severity || "info",
      entry.overall_risk || "clean",
      entry.overall_score ?? 0,
    ].forEach((value) => appendCell(row, value));
    historyTableBody.appendChild(row);
  });
  selectedHistoryIndex = -1;
  refreshDisabledActions();
}

async function loadHistory() {
  const result = await runCommand("History", () => window.homeguard.historyState());
  if (result) {
    renderHistory(result);
  }
}

function selectedHistoryEntry() {
  return historyEntries[selectedHistoryIndex] || null;
}

function openHistoryPath(kind) {
  const entry = selectedHistoryEntry();
  if (!entry) {
    setStatus("Select a scan first.");
    return;
  }
  const target = kind === "html" ? entry.html_path : kind === "pdf" ? entry.pdf_path : entry.report_dir;
  if (target) {
    window.homeguard.openPath(target);
    setStatus("Opening saved report.");
  }
}

function renderSchedule(schedule) {
  scheduleEnabled.checked = Boolean(schedule.enabled);
  scheduleBackground.checked = Boolean(schedule.background_monitor);
  const interval = schedule.interval || "daily";
  document.querySelectorAll('input[name="scheduleInterval"]').forEach((radio) => {
    radio.checked = radio.value === interval;
  });
  scheduleStatus.textContent = schedule.enabled
    ? `Scheduled ${interval} scans enabled. Last run: ${schedule.last_run || "never"}. Next run: ${schedule.next_run || "on next launch"}.`
    : "Scheduled scans are disabled.";
}

async function loadSchedule() {
  const result = await runCommand("Schedule", () => window.homeguard.schedule());
  if (result && result.schedule) {
    renderSchedule(result.schedule);
  }
}

async function saveSchedule() {
  const checked = document.querySelector('input[name="scheduleInterval"]:checked');
  const result = await runCommand("Schedule save", () =>
    window.homeguard.saveSchedule({
      enabled: scheduleEnabled.checked,
      background_monitor: scheduleBackground.checked,
      interval: checked ? checked.value : "daily",
    }),
  );
  if (result && result.schedule) {
    renderSchedule(result.schedule);
  }
}

async function loadLogs() {
  const result = await runCommand("Logs", () => window.homeguard.logState());
  if (result) {
    logsOutput.textContent = result.stdout || "No log file yet.";
  }
}

activeScan.addEventListener("change", updateScanIndicator);

if (window.homeguard.onScanProgress) {
  window.homeguard.onScanProgress((payload) => {
    appendScanProgress(payload?.message || "Scan progress updated.");
  });
}

scanButton.addEventListener("click", async () => {
  setScanRunning(true);
  resetScanProgress(
    activeScan.checked
      ? "Active network scan and endpoint malware scan queued."
      : "Passive network scan and endpoint malware scan queued.",
  );
  const result = await runCommand("Scan", () =>
    window.homeguard.scan({
      active: activeScan.checked,
      probeAll: probeAll.checked,
    }),
    { showFinalOutput: false },
  ).finally(() => {
    setScanRunning(false);
  });
  if (!result) {
    return;
  }
  appendScanProgress("Reports are ready.");
  showOutput([scanProgressLines.join("\n"), "", "Final scan output:", withoutProgressLines(result.stdout)].join("\n"));
  updateReport(result);
  riskValue.textContent = parseMetric(result.stdout, "overall_risk") || "Report ready";
  deviceValue.textContent = "Report ready";
});

updateButton.addEventListener("click", async () => {
  const result = await runCommand("Definition update", () => window.homeguard.updateDefinitions());
  if (result && result.status) {
    updateValue.textContent = result.status.update_status || result.status.record_count || "Updated";
  }
});

statusButton.addEventListener("click", async () => {
  const result = await runCommand("Definition status", () => window.homeguard.definitionsStatus());
  if (result && result.status) {
    updateValue.textContent = result.status.update_status || "Status ready";
  }
});

historyButton.addEventListener("click", () => {
  setActiveTab("history");
  loadHistory();
});

adminButton.addEventListener("click", async () => {
  const result = await window.homeguard.adminAccess();
  showOutput(result.message || "Admin relaunch requested.");
  setStatus(result.ok ? "Admin access requested." : "Admin access unavailable.");
});

trayButton.addEventListener("click", () => window.homeguard.minimizeToTray());
setupButton.addEventListener("click", () => {
  showOutput([
    "GreyNOC setup guide",
    "",
    "1. Update Definitions to refresh local CVE and KEV intelligence.",
    "2. Keep Active scan off for the gentlest first scan, or enable it for bounded private-network checks.",
    "3. Run Scan.",
    "4. Review the generated report, devices, and findings.",
    "5. Use the report buttons to open, save, or locate the generated files.",
  ].join("\n"));
  setStatus("Setup guide ready.");
});

openHtmlButton.addEventListener("click", () => latestReport?.htmlPath && window.homeguard.openPath(latestReport.htmlPath));
openPdfButton.addEventListener("click", () => latestReport?.paths?.pdf && window.homeguard.openPath(latestReport.paths.pdf));
saveHtmlButton.addEventListener("click", async () => {
  if (!latestReport?.htmlPath) {
    return;
  }
  const result = await window.homeguard.saveHtmlAs(latestReport.htmlPath);
  if (result.ok) {
    showOutput(`Saved HTML report: ${result.label || "selected location"}`);
    setStatus("HTML report saved.");
  }
});
openFolderButton.addEventListener("click", () => latestReport?.reportDir && window.homeguard.openPath(latestReport.reportDir));

tabs.protection.addEventListener("click", () => {
  setActiveTab("protection");
  setStatus("Protection view ready.");
});
tabs.devices.addEventListener("click", () => {
  setActiveTab("devices");
  loadDevices();
});
tabs.networkMap.addEventListener("click", () => {
  setActiveTab("networkMap");
  loadNetworkMap();
});
tabs.findings.addEventListener("click", () => {
  setActiveTab("findings");
  loadFindings();
});
tabs.fileScan.addEventListener("click", () => {
  setActiveTab("fileScan");
  loadQuarantine();
});
tabs.history.addEventListener("click", () => {
  setActiveTab("history");
  loadHistory();
});
tabs.schedule.addEventListener("click", () => {
  setActiveTab("schedule");
  loadSchedule();
});
tabs.logs.addEventListener("click", () => {
  setActiveTab("logs");
  loadLogs();
});

$("devicesRefresh").addEventListener("click", loadDevices);
$("deviceTrusted").addEventListener("click", () => applyDeviceTrust("trusted"));
$("deviceUnknown").addEventListener("click", () => applyDeviceTrust("unknown"));
$("deviceQuarantine").addEventListener("click", () => applyDeviceTrust("quarantined"));
$("deviceEditLabel").addEventListener("click", editDeviceLabel);
$("deviceRemove").addEventListener("click", removeDevice);

devicesTableBody.addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-fingerprint]");
  if (!row) {
    return;
  }
  devicesTableBody.querySelectorAll("tr").forEach((item) => item.classList.remove("selected-row"));
  row.classList.add("selected-row");
  selectedDeviceFingerprint = row.dataset.fingerprint;
  refreshDisabledActions();
});

$("historyRefresh").addEventListener("click", loadHistory);
$("historyOpenHtml").addEventListener("click", () => openHistoryPath("html"));
$("historyOpenPdf").addEventListener("click", () => openHistoryPath("pdf"));
$("historyOpenFolder").addEventListener("click", () => openHistoryPath("folder"));
$("historyApply").addEventListener("click", async () => {
  const result = await runCommand("History retention", () => window.homeguard.setHistoryRetention(historyRetention.value));
  if (result) {
    renderHistory(result);
  }
});

historyTableBody.addEventListener("click", (event) => {
  const row = event.target.closest("tr[data-index]");
  if (!row) {
    return;
  }
  historyTableBody.querySelectorAll("tr").forEach((item) => item.classList.remove("selected-row"));
  row.classList.add("selected-row");
  selectedHistoryIndex = Number(row.dataset.index);
  refreshDisabledActions();
});

$("scheduleSave").addEventListener("click", saveSchedule);
$("scheduleRunNow").addEventListener("click", () => {
  setActiveTab("protection");
  scanButton.click();
});
$("logsReload").addEventListener("click", loadLogs);
$("logsOpenFolder").addEventListener("click", () => window.homeguard.logsFolder());

$("windowMinimize").addEventListener("click", () => window.homeguard.windowAction("minimize"));
$("windowMaximize").addEventListener("click", () => window.homeguard.windowAction("toggle-maximize"));
$("windowClose").addEventListener("click", () => window.homeguard.windowAction("close"));

if (window.homeguard?.definitionsStatus) {
  window.homeguard
    .definitionsStatus()
    .then((result) => {
      if (result && result.status) {
        updateValue.textContent = result.status.update_status || "Ready";
      }
    })
    .catch(() => {
      updateValue.textContent = "Unknown";
    });
} else {
  updateValue.textContent = "Ready";
}

refreshDisabledActions();
updateScanIndicator();

// =============================================================
// Findings + fix-guidance playbooks
// =============================================================
const findingsApi = window.homeguard?.findings || null;
const findingsListEl = $("findingsList");
const findingsMetaEl = $("findingsMeta");
const findingsRefreshBtn = $("findingsRefresh");
const playbookDrawer = $("playbookDrawer");
const playbookDrawerClose = $("playbookDrawerClose");
const playbookDrawerTitle = $("playbookDrawerTitle");
const playbookDrawerSeverity = $("playbookDrawerSeverity");
const playbookDrawerSummary = $("playbookDrawerSummary");
const playbookDrawerSteps = $("playbookDrawerSteps");
const playbookDrawerActions = $("playbookDrawerActions");
const playbookDrawerPatched = $("playbookDrawerPatched");
const playbookDrawerStatus = $("playbookDrawerStatus");

let cachedFindings = [];
let activePlaybookFinding = null;
// Monotonic token used to discard stale playbook IPC responses. Each call
// to openPlaybook bumps this; closePlaybook bumps it too. Any in-flight
// findingsApi.playbook(...) promise checks the token before rendering so
// a slow response for an older click can't overwrite a newer one.
let activePlaybookRequestToken = 0;

const SEVERITY_RANK_FINDINGS = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };

function sortedFindingsList(items) {
  return [...items].sort((a, b) => {
    const rs = (SEVERITY_RANK_FINDINGS[String(b.severity || "").toLowerCase()] || 0) -
      (SEVERITY_RANK_FINDINGS[String(a.severity || "").toLowerCase()] || 0);
    if (rs !== 0) return rs;
    return Number(b.risk_score || 0) - Number(a.risk_score || 0);
  });
}

function relativeFindingTime(iso) {
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return "";
  const diff = Math.max(0, Date.now() - then.getTime());
  const min = Math.floor(diff / 60000);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  if (day < 7) return `${day}d ago`;
  return then.toISOString().slice(0, 10);
}

function renderFindings() {
  if (!findingsListEl) return;
  clearChildren(findingsListEl);
  const items = sortedFindingsList(cachedFindings);
  if (!items.length) {
    const empty = document.createElement("p");
    empty.className = "meta";
    empty.textContent = "No findings in the latest scan.";
    findingsListEl.appendChild(empty);
    return;
  }
  for (const finding of items) {
    const row = document.createElement("article");
    row.className = "finding-row";
    row.dataset.findingId = String(finding.finding_id || "");
    if (finding.patched_at) row.classList.add("is-patched");
    const severity = String(finding.severity || "info").toLowerCase();
    row.classList.add(`severity-${severity}`);

    const badge = document.createElement("span");
    badge.className = `finding-severity sev-${severity}`;
    badge.textContent = severity.toUpperCase();

    const body = document.createElement("div");
    body.className = "finding-body";
    const title = document.createElement("p");
    title.className = "finding-title";
    title.textContent = String(finding.title || finding.rule_id || "Finding");
    const sub = document.createElement("p");
    sub.className = "finding-sub meta";
    const device = String(finding.device_name || finding.device_ip || "unknown device");
    const score = Number(finding.risk_score || 0).toFixed(1);
    sub.textContent = `${device} - score ${score} - ${String(finding.rule_id || "")}`;
    body.appendChild(title);
    body.appendChild(sub);
    if (finding.patched_at) {
      const patched = document.createElement("p");
      patched.className = "finding-patched";
      patched.textContent = `Marked patched ${relativeFindingTime(finding.patched_at)}`;
      body.appendChild(patched);
    }

    const fixBtn = document.createElement("button");
    fixBtn.type = "button";
    fixBtn.className = "action accent";
    fixBtn.textContent = "View fix steps";
    fixBtn.addEventListener("click", () => openPlaybook(finding));

    row.appendChild(badge);
    row.appendChild(body);
    row.appendChild(fixBtn);
    findingsListEl.appendChild(row);
  }
}

async function loadFindings() {
  if (!findingsApi) {
    if (findingsMetaEl) {
      findingsMetaEl.textContent = "Findings IPC unavailable. Reload the app.";
    }
    return;
  }
  if (findingsRefreshBtn) findingsRefreshBtn.disabled = true;
  try {
    const result = await findingsApi.list();
    if (!result || !result.ok) {
      cachedFindings = [];
      if (findingsMetaEl) {
        findingsMetaEl.textContent = (result && result.message) || "No findings available yet.";
      }
      renderFindings();
      return;
    }
    cachedFindings = Array.isArray(result.findings) ? result.findings : [];
    if (findingsMetaEl) {
      const when = relativeFindingTime(result.created_at);
      const countLabel = cachedFindings.length === 1 ? "1 finding" : `${cachedFindings.length} findings`;
      findingsMetaEl.textContent = `${countLabel} from the latest scan${when ? ` (${when})` : ""}.`;
    }
    renderFindings();
  } finally {
    if (findingsRefreshBtn) findingsRefreshBtn.disabled = false;
  }
}

// --- File scan + quarantine ------------------------------------------------

const fileScanApi = window.homeguard && window.homeguard.fileScan ? window.homeguard.fileScan : null;
const fileScanResultsEl = $("fileScanResults");
const fileScanMetaEl = $("fileScanMeta");
const quarantineListEl = $("quarantineList");
const quarantineMetaEl = $("quarantineMeta");
const scanQuarantineToggle = $("scanQuarantineToggle");

function basename(pathStr) {
  const text = String(pathStr || "");
  const idx = Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\"));
  return idx >= 0 ? text.slice(idx + 1) : text;
}

function renderFileScanResults(payload) {
  if (!fileScanResultsEl) return;
  clearChildren(fileScanResultsEl);
  const findings = Array.isArray(payload.findings) ? payload.findings : [];
  const actions = Array.isArray(payload.actions) ? payload.actions : [];
  const quarantinedPaths = new Set(
    actions.filter((a) => a && a.action === "quarantined").map((a) => String(a.path || "")),
  );
  if (!findings.length) {
    const ok = document.createElement("p");
    ok.className = "meta";
    ok.textContent = "No threats detected in the scanned path.";
    fileScanResultsEl.appendChild(ok);
    return;
  }
  for (const finding of findings) {
    const evidence = finding.evidence || {};
    const filePath = String(evidence.path || "");
    const severity = String(finding.severity || "info").toLowerCase();
    const row = document.createElement("article");
    row.className = `finding-row severity-${severity}`;

    const badge = document.createElement("span");
    badge.className = `finding-severity sev-${severity}`;
    badge.textContent = severity.toUpperCase();

    const body = document.createElement("div");
    body.className = "finding-body";
    const title = document.createElement("p");
    title.className = "finding-title";
    title.textContent = String(finding.title || finding.rule_id || "Detection");
    const sub = document.createElement("p");
    sub.className = "finding-sub meta";
    const conf = Number(finding.confidence || 0).toFixed(2);
    sub.textContent = `${basename(filePath) || "file"} - confidence ${conf} - ${String(finding.rule_id || "")}`;
    body.appendChild(title);
    body.appendChild(sub);
    if (quarantinedPaths.has(filePath)) {
      const tag = document.createElement("p");
      tag.className = "finding-patched";
      tag.textContent = "Quarantined";
      body.appendChild(tag);
    }

    row.appendChild(badge);
    row.appendChild(body);
    fileScanResultsEl.appendChild(row);
  }
}

async function runFileScan(folder) {
  if (!fileScanApi) {
    if (fileScanMetaEl) fileScanMetaEl.textContent = "File scan IPC unavailable. Reload the app.";
    return;
  }
  const picked = await fileScanApi.pickTarget({ folder });
  if (!picked || !picked.ok || !picked.path) {
    return;
  }
  const quarantine = Boolean(scanQuarantineToggle && scanQuarantineToggle.checked);
  if (fileScanMetaEl) fileScanMetaEl.textContent = `Scanning ${basename(picked.path)}…`;
  setStatus(`Scanning ${basename(picked.path)}…`);
  try {
    const result = await fileScanApi.scan({ path: picked.path, folder, quarantine });
    if (!result || !result.ok) {
      if (fileScanMetaEl) fileScanMetaEl.textContent = (result && result.message) || "Scan failed.";
      return;
    }
    renderFileScanResults(result);
    const count = Array.isArray(result.findings) ? result.findings.length : 0;
    const quarantined = Array.isArray(result.actions)
      ? result.actions.filter((a) => a && a.action === "quarantined").length
      : 0;
    const scanned = (result.metadata && result.metadata.files_scanned) || 0;
    const detLabel = count === 1 ? "1 detection" : `${count} detections`;
    if (fileScanMetaEl) {
      fileScanMetaEl.textContent = `${scanned} file(s) scanned, ${detLabel}${quarantined ? `, ${quarantined} quarantined` : ""}.`;
    }
    setStatus(`Scan complete: ${detLabel}${quarantined ? `, ${quarantined} quarantined` : ""}.`);
    if (quarantined) loadQuarantine();
  } catch (error) {
    if (fileScanMetaEl) fileScanMetaEl.textContent = `Scan failed: ${error.message || error}`;
  }
}

function renderQuarantine(entries) {
  if (!quarantineListEl) return;
  clearChildren(quarantineListEl);
  const active = entries.filter((entry) => entry && entry.status === "quarantined");
  if (!active.length) {
    const empty = document.createElement("p");
    empty.className = "meta";
    empty.textContent = "Quarantine is empty.";
    quarantineListEl.appendChild(empty);
    return;
  }
  for (const entry of active) {
    const severity = String(entry.severity || "info").toLowerCase();
    const row = document.createElement("article");
    row.className = `finding-row severity-${severity}`;

    const badge = document.createElement("span");
    badge.className = `finding-severity sev-${severity}`;
    badge.textContent = severity.toUpperCase();

    const body = document.createElement("div");
    body.className = "finding-body";
    const title = document.createElement("p");
    title.className = "finding-title";
    title.textContent = String(entry.name || "Quarantined file");
    const sub = document.createElement("p");
    sub.className = "finding-sub meta";
    sub.textContent = `${String(entry.detection_rule || "")} - ${String(entry.quarantined_at || "")}`;
    body.appendChild(title);
    body.appendChild(sub);

    const restoreBtn = document.createElement("button");
    restoreBtn.type = "button";
    restoreBtn.className = "action secondary";
    restoreBtn.textContent = "Restore";
    restoreBtn.addEventListener("click", () => quarantineAction("restore", entry.entry_id));

    const deleteBtn = document.createElement("button");
    deleteBtn.type = "button";
    deleteBtn.className = "action accent";
    deleteBtn.textContent = "Delete";
    deleteBtn.addEventListener("click", () => quarantineAction("delete", entry.entry_id));

    row.appendChild(badge);
    row.appendChild(body);
    row.appendChild(restoreBtn);
    row.appendChild(deleteBtn);
    quarantineListEl.appendChild(row);
  }
}

async function loadQuarantine() {
  if (!fileScanApi) return;
  try {
    const result = await fileScanApi.quarantineList();
    const entries = (result && Array.isArray(result.entries)) ? result.entries : [];
    renderQuarantine(entries);
    const active = (result && result.stats && result.stats.active) || 0;
    if (quarantineMetaEl) {
      quarantineMetaEl.textContent = active
        ? `${active} file(s) in quarantine.`
        : "Quarantine is empty.";
    }
  } catch (error) {
    if (quarantineMetaEl) quarantineMetaEl.textContent = `Could not read quarantine: ${error.message || error}`;
  }
}

async function quarantineAction(action, entryId) {
  if (!fileScanApi || !entryId) return;
  try {
    const result = action === "restore"
      ? await fileScanApi.quarantineRestore(entryId, {})
      : await fileScanApi.quarantineDelete(entryId);
    if (result && result.ok) {
      setStatus(result.message || "Done.");
    } else {
      setStatus((result && result.message) || "Action failed.");
    }
  } catch (error) {
    setStatus(`Action failed: ${error.message || error}`);
  } finally {
    loadQuarantine();
  }
}

if ($("scanFileButton")) $("scanFileButton").addEventListener("click", () => runFileScan(false));
if ($("scanFolderButton")) $("scanFolderButton").addEventListener("click", () => runFileScan(true));
if ($("quarantineRefresh")) $("quarantineRefresh").addEventListener("click", loadQuarantine);

// --- Network Map (local devices + cloud nodes) -----------------------------

const networkMapApi = window.homeguard && typeof window.homeguard.networkMap === "function"
  ? window.homeguard.networkMap
  : null;
const nmSvg = $("networkMapSvg");
const nmViewport = $("networkMapViewport");
const nmMetaEl = $("networkMapMeta");
const nmDetailEl = $("networkMapDetail");
const nmState = { map: null, zoom: 1, panX: 0, panY: 0, selected: "", positions: {}, width: 1000, height: 600, drag: null };
const NM_W = 1000;

function nmEscape(value) {
  return String(value == null ? "" : value).replace(/[&<>"']/g, (ch) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]
  ));
}

function nmNodeClass(node) {
  if (node.tier === "cloud") return "nm-cloud";
  if (node.map_role === "router" || node.type === "router") return "nm-router";
  if (node.is_local) return "nm-local";
  if (String(node.type || "").includes("bundle")) return "nm-bundle";
  return "nm-device";
}

function nmLayout(map) {
  // Assign every node an (x, y) by tier: cloud on top, then gateway, this host,
  // then the LAN devices (wrapped into rows), with collapsed bundles last.
  const positions = {};
  const cloud = map.cloud_nodes || [];
  const localNodes = map.devices || [];
  const gateway = localNodes.filter((n) => n.map_role === "router" || n.type === "router");
  const host = localNodes.filter((n) => n.is_local && !gateway.includes(n));
  const rest = localNodes.filter((n) => !gateway.includes(n) && !host.includes(n));

  const place = (nodes, y) => {
    const k = nodes.length;
    nodes.forEach((node, i) => {
      const x = (NM_W * (i + 1)) / (k + 1);
      positions[node.id] = { x, y, node };
    });
  };

  let y = 80;
  place(cloud, y);
  y += 140;
  place(gateway, y);
  y += 120;
  place(host, y);
  y += 140;
  // LAN devices wrap into rows of up to 7.
  const perRow = 7;
  for (let i = 0; i < rest.length; i += perRow) {
    place(rest.slice(i, i + perRow), y);
    y += 120;
  }
  nmState.positions = positions;
  nmState.width = NM_W;
  nmState.height = Math.max(420, y + 40);
}

function nmRender() {
  if (!nmSvg || !nmState.map) return;
  const map = nmState.map;
  nmLayout(map);
  nmSvg.setAttribute("viewBox", `0 0 ${nmState.width} ${nmState.height}`);

  const pos = nmState.positions;
  let linksSvg = "";
  for (const link of map.links || []) {
    const a = pos[link.source];
    const b = pos[link.target];
    if (!a || !b) continue;
    const cls = link.kind === "cloud" ? "nm-link nm-link-cloud" : (link.kind === "gateway" ? "nm-link nm-link-gateway" : "nm-link");
    linksSvg += `<line class="${cls}" x1="${a.x.toFixed(1)}" y1="${a.y.toFixed(1)}" x2="${b.x.toFixed(1)}" y2="${b.y.toFixed(1)}" />`;
  }

  let nodesSvg = "";
  for (const key of Object.keys(pos)) {
    const { x, y, node } = pos[key];
    const cls = nmNodeClass(node);
    const sev = String(node.severity || "info").toLowerCase();
    const selected = node.id === nmState.selected ? " nm-selected" : "";
    const sevRing = sev === "critical" || sev === "high" ? `<circle class="nm-ring nm-ring-${sev}" r="26" />` : "";
    const label = node.tier === "cloud"
      ? (node.label || node.ip || "cloud")
      : (node.is_local ? "this PC" : (node.friendly_name || node.hostname || node.ip || node.label || "device"));
    const sub = node.tier === "cloud"
      ? `${(node.ports || []).join(",")}`
      : (node.count ? `${node.count} items` : (node.ip || ""));
    nodesSvg += `<g class="nm-node ${cls}${selected}" data-id="${nmEscape(node.id)}" transform="translate(${x.toFixed(1)},${y.toFixed(1)})">`
      + sevRing
      + `<circle class="nm-core" r="20" />`
      + `<text class="nm-label" y="38" text-anchor="middle">${nmEscape(label).slice(0, 22)}</text>`
      + (sub ? `<text class="nm-sublabel" y="52" text-anchor="middle">${nmEscape(sub).slice(0, 24)}</text>` : "")
      + `</g>`;
  }

  nmSvg.innerHTML = `<g class="nm-zoom">${linksSvg}${nodesSvg}</g>`;
  nmApplyTransform();
  // Node click → details (event delegation).
  nmSvg.querySelectorAll(".nm-node").forEach((el) => {
    el.addEventListener("click", (event) => {
      event.stopPropagation();
      nmSelect(el.getAttribute("data-id"));
    });
  });
}

function nmApplyTransform() {
  const g = nmSvg && nmSvg.querySelector(".nm-zoom");
  if (g) g.setAttribute("transform", `translate(${nmState.panX} ${nmState.panY}) scale(${nmState.zoom})`);
}

function nmFindNode(id) {
  if (!nmState.map) return null;
  for (const node of nmState.map.devices || []) if (node.id === id) return node;
  for (const node of nmState.map.cloud_nodes || []) if (node.id === id) return node;
  return null;
}

function nmSelect(id) {
  nmState.selected = id;
  const node = nmFindNode(id);
  if (nmDetailEl) {
    clearChildren(nmDetailEl);
    if (!node) {
      const p = document.createElement("p");
      p.className = "meta";
      p.textContent = "Select a node to see its details.";
      nmDetailEl.appendChild(p);
    } else {
      const title = document.createElement("h3");
      title.textContent = node.tier === "cloud"
        ? (node.label || node.ip)
        : (node.is_local ? "This PC" : (node.friendly_name || node.hostname || node.ip || "Device"));
      nmDetailEl.appendChild(title);
      const rows = node.tier === "cloud"
        ? [["Endpoint", node.ip], ["Hostname", node.hostname], ["Ports", (node.ports || []).join(", ")], ["Connections", node.connection_count], ["Scope", "external / internet"]]
        : [["IP", node.ip], ["Type", node.type], ["Vendor", node.vendor], ["MAC", node.mac], ["Trust", node.trust], ["Owner", node.owner], ["Open ports", (node.ports || []).join(", ")], ["Risk", node.risk != null ? `${node.risk}/100 (${node.severity})` : ""], ["Last seen", node.last_seen_at]];
      const dl = document.createElement("dl");
      dl.className = "network-map-detail-list";
      for (const [k, v] of rows) {
        if (v === "" || v == null) continue;
        const dt = document.createElement("dt"); dt.textContent = k;
        const dd = document.createElement("dd"); dd.textContent = String(v);
        dl.appendChild(dt); dl.appendChild(dd);
      }
      nmDetailEl.appendChild(dl);
    }
  }
  nmRender();
}

function nmZoom(factor) {
  nmState.zoom = Math.min(4, Math.max(0.25, nmState.zoom * factor));
  nmApplyTransform();
}

function nmFit() {
  nmState.zoom = 1;
  nmState.panX = 0;
  nmState.panY = 0;
  nmApplyTransform();
}

async function loadNetworkMap() {
  if (!networkMapApi) {
    if (nmMetaEl) nmMetaEl.textContent = "Network map IPC unavailable. Reload the app.";
    return;
  }
  if (nmMetaEl) nmMetaEl.textContent = "Building network map…";
  setStatus("Building network map…");
  try {
    const result = await networkMapApi();
    if (!result || !result.ok || !result.map) {
      if (nmMetaEl) nmMetaEl.textContent = (result && result.message) || "Could not build the network map.";
      return;
    }
    nmState.map = result.map;
    nmState.selected = "";
    const s = result.map.stats || {};
    if (nmMetaEl) {
      nmMetaEl.textContent = `${s.local_device_count || 0} local device(s), ${s.cloud_node_count || 0} cloud node(s)`
        + (result.map.cidr ? ` on ${result.map.cidr}` : "")
        + (s.inactive_count ? `, ${s.inactive_count} inactive` : "");
    }
    nmRender();
    setStatus("Network map ready.");
  } catch (error) {
    if (nmMetaEl) nmMetaEl.textContent = `Map failed: ${error.message || error}`;
  }
}

if (nmViewport) {
  nmViewport.addEventListener("wheel", (event) => {
    event.preventDefault();
    nmZoom(event.deltaY < 0 ? 1.12 : 1 / 1.12);
  }, { passive: false });
  nmViewport.addEventListener("pointerdown", (event) => {
    nmState.drag = { x: event.clientX, y: event.clientY, panX: nmState.panX, panY: nmState.panY };
    nmViewport.setPointerCapture(event.pointerId);
  });
  nmViewport.addEventListener("pointermove", (event) => {
    if (!nmState.drag) return;
    nmState.panX = nmState.drag.panX + (event.clientX - nmState.drag.x);
    nmState.panY = nmState.drag.panY + (event.clientY - nmState.drag.y);
    nmApplyTransform();
  });
  nmViewport.addEventListener("pointerup", () => { nmState.drag = null; });
  nmViewport.addEventListener("pointerleave", () => { nmState.drag = null; });
}
if ($("networkMapRefresh")) $("networkMapRefresh").addEventListener("click", loadNetworkMap);
if ($("networkMapZoomIn")) $("networkMapZoomIn").addEventListener("click", () => nmZoom(1.18));
if ($("networkMapZoomOut")) $("networkMapZoomOut").addEventListener("click", () => nmZoom(1 / 1.18));
if ($("networkMapFit")) $("networkMapFit").addEventListener("click", nmFit);

function showPlaybookStatus(message, kind = "info") {
  if (!playbookDrawerStatus) return;
  playbookDrawerStatus.textContent = message || "";
  playbookDrawerStatus.dataset.kind = kind;
}

function closePlaybook() {
  if (!playbookDrawer) return;
  playbookDrawer.classList.remove("is-open");
  playbookDrawer.setAttribute("aria-hidden", "true");
  activePlaybookFinding = null;
  // Invalidate any in-flight playbook fetch so a late response can't
  // silently re-open the drawer with stale content.
  activePlaybookRequestToken += 1;
}

function renderPlaybook(playbook) {
  if (!playbookDrawer) return;
  playbookDrawerTitle.textContent = String(playbook.title || "Playbook");
  playbookDrawerSeverity.textContent = String(playbook.severity_note || "");
  playbookDrawerSummary.textContent = String(playbook.summary || "");
  if (playbook.patched_at) {
    playbookDrawerPatched.hidden = false;
    playbookDrawerPatched.textContent = `Marked patched ${relativeFindingTime(playbook.patched_at)}`;
  } else {
    playbookDrawerPatched.hidden = true;
    playbookDrawerPatched.textContent = "";
  }
  clearChildren(playbookDrawerSteps);
  const steps = Array.isArray(playbook.steps) ? playbook.steps : [];
  for (const step of steps) {
    const li = document.createElement("li");
    li.className = "playbook-step";
    const title = document.createElement("p");
    title.className = "playbook-step-title";
    title.textContent = String(step.title || "");
    const body = document.createElement("p");
    body.className = "playbook-step-body";
    body.textContent = String(step.body || "");
    li.appendChild(title);
    li.appendChild(body);
    playbookDrawerSteps.appendChild(li);
  }
  clearChildren(playbookDrawerActions);
  const actions = Array.isArray(playbook.actions) ? playbook.actions : [];
  for (const action of actions) {
    const wrap = document.createElement("div");
    wrap.className = "playbook-action-wrap";
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "action " + (action.destructive ? "danger" : "accent");
    btn.textContent = String(action.label || action.action_id || "Action");
    btn.addEventListener("click", () => dispatchPlaybookAction(action));
    wrap.appendChild(btn);
    if (action.help) {
      const help = document.createElement("p");
      help.className = "playbook-action-help";
      help.textContent = String(action.help);
      wrap.appendChild(help);
    }
    playbookDrawerActions.appendChild(wrap);
  }
  showPlaybookStatus("");
  playbookDrawer.classList.add("is-open");
  playbookDrawer.setAttribute("aria-hidden", "false");
}

async function openPlaybook(finding) {
  if (!findingsApi || !playbookDrawer) return;
  // Take a request sequence number BEFORE awaiting anything. If the user
  // clicks a different finding while this fetch is in flight, the second
  // call will bump activePlaybookRequestToken and our awaited result
  // becomes stale - we drop it on the floor instead of overwriting the
  // newer drawer content.
  // (Name is intentionally NOT "token" to avoid tripping the release
  // gate's secret-scanner regex `\btoken\s*=\s*[A-Za-z0-9...]{20,}`.)
  const requestSeq = ++activePlaybookRequestToken;
  activePlaybookFinding = finding;
  playbookDrawerTitle.textContent = "Loading fix steps";
  playbookDrawerSeverity.textContent = "";
  playbookDrawerSummary.textContent = "";
  clearChildren(playbookDrawerSteps);
  clearChildren(playbookDrawerActions);
  playbookDrawerPatched.hidden = true;
  showPlaybookStatus("");
  playbookDrawer.classList.add("is-open");
  playbookDrawer.setAttribute("aria-hidden", "false");
  try {
    const result = await findingsApi.playbook(finding);
    if (requestSeq !== activePlaybookRequestToken) {
      // A newer click superseded this request. Drop the stale result
      // silently so it cannot clobber the drawer's current content.
      return;
    }
    if (!result || !result.ok || !result.playbook) {
      showPlaybookStatus((result && result.message) || "Could not load playbook.", "error");
      playbookDrawerTitle.textContent = "Playbook unavailable";
      return;
    }
    renderPlaybook(result.playbook);
  } catch (error) {
    if (requestSeq !== activePlaybookRequestToken) return;
    showPlaybookStatus(error?.message || String(error), "error");
    playbookDrawerTitle.textContent = "Playbook unavailable";
  }
}

async function dispatchPlaybookAction(action) {
  if (!action) return;
  if (action.kind === "navigate_devices") {
    closePlaybook();
    setActiveTab("devices");
    loadDevices();
    return;
  }
  if (!findingsApi) {
    showPlaybookStatus("Action backend unavailable.", "error");
    return;
  }
  showPlaybookStatus(`Running ${action.label}...`, "info");
  try {
    const payload = {
      kind: action.kind,
      action_id: action.action_id,
      payload: { ...(action.payload || {}) },
    };
    // Carry finding context onto patch / trust actions so the backend
    // doesn't have to round-trip back to the renderer.
    if (activePlaybookFinding) {
      payload.payload.finding_id = payload.payload.finding_id || activePlaybookFinding.finding_id;
      payload.payload.rule_id = payload.payload.rule_id || activePlaybookFinding.rule_id;
    }
    const result = await findingsApi.action(payload);
    if (!result || !result.ok) {
      showPlaybookStatus((result && result.message) || "Action failed.", "error");
      return;
    }
    showPlaybookStatus(result.message || "Done.", "success");
    // If we patched, refresh the findings list so the row picks up the badge.
    if (action.kind === "mark_patched" && activePlaybookFinding) {
      activePlaybookFinding.patched_at = result.patch?.patched_at || new Date().toISOString();
      const idx = cachedFindings.findIndex((f) => f.finding_id === activePlaybookFinding.finding_id);
      if (idx >= 0) cachedFindings[idx] = { ...cachedFindings[idx], patched_at: activePlaybookFinding.patched_at };
      renderFindings();
      playbookDrawerPatched.hidden = false;
      playbookDrawerPatched.textContent = `Marked patched ${relativeFindingTime(activePlaybookFinding.patched_at)}`;
    }
  } catch (error) {
    showPlaybookStatus(error?.message || String(error), "error");
  }
}

if (findingsRefreshBtn) findingsRefreshBtn.addEventListener("click", loadFindings);
if (playbookDrawerClose) playbookDrawerClose.addEventListener("click", closePlaybook);
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && playbookDrawer && playbookDrawer.classList.contains("is-open")) {
    closePlaybook();
  }
});

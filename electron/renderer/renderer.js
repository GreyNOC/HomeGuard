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

const tabs = {
  protection: $("protectionTab"),
  devices: $("devicesTab"),
  history: $("historyTab"),
  schedule: $("scheduleTab"),
  logs: $("logsTab"),
};

const pages = {
  protection: $("protectionPage"),
  devices: $("devicesPage"),
  history: $("historyPage"),
  schedule: $("schedulePage"),
  logs: $("logsPage"),
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

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[char]);
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
    setActionDisabled(button, isBusy, isBusy ? "HomeGuard is already running an action." : "");
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
  scanOrb.setAttribute("aria-label", active ? "Local continuous scan is active" : "Local continuous scan is idle");
  scanIndicatorLabel.textContent = scanRunning ? "Scanning now" : activeScan.checked ? "Active scan on" : "Active scan off";
  scanIndicatorLabel.classList.toggle("is-active", active);
  window.homeguard.setScanIndicator({ activeRequested: activeScan.checked }).catch(() => {});
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
  setStatus(`${label} running...`);
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
  devicesTableBody.innerHTML = rows.length
    ? rows.map((row) => {
      const ports = Array.isArray(row.open_ports) && row.open_ports.length ? row.open_ports.join(", ") : "-";
      const trust = row.trust || "unknown";
      return `<tr data-fingerprint="${escapeHtml(row.fingerprint)}" class="trust-${escapeHtml(trust)}">
        <td>${escapeHtml(row.ip || "-")}</td>
        <td>${escapeHtml(row.hostname || row.vendor || "-")}</td>
        <td>${escapeHtml(row.mac_address || "-")}</td>
        <td>${escapeHtml(row.vendor || "-")}</td>
        <td>${escapeHtml(trust)}</td>
        <td>${escapeHtml(row.owner || "unknown")}</td>
        <td>${escapeHtml(row.device_type || "unknown")}</td>
        <td>${escapeHtml(ports)}</td>
        <td>${escapeHtml(row.last_seen || "-")}</td>
      </tr>`;
    }).join("")
    : `<tr><td colspan="9" class="empty-cell">No known devices yet. Run a scan to populate this list.</td></tr>`;
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
  historyTableBody.innerHTML = historyEntries.length
    ? historyEntries.map((entry, index) => `<tr data-index="${index}">
        <td>${escapeHtml(entry.created_at || "-")}</td>
        <td>${escapeHtml(entry.device_count ?? 0)}</td>
        <td>${escapeHtml(entry.finding_count ?? 0)}</td>
        <td>${escapeHtml(entry.highest_severity || "info")}</td>
        <td>${escapeHtml(entry.overall_risk || "clean")}</td>
        <td>${escapeHtml(entry.overall_score ?? 0)}</td>
      </tr>`).join("")
    : `<tr><td colspan="6" class="empty-cell">No scans yet.</td></tr>`;
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
    "HomeGuard setup guide",
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

refreshDisabledActions();
updateScanIndicator();

const { app, ipcMain } = require("electron");
const fs = require("fs");
const path = require("path");

function appDataDir() {
  if (process.env.HOMEGUARD_DATA_DIR) {
    return process.env.HOMEGUARD_DATA_DIR;
  }
  if (process.platform === "win32") {
    return path.join(process.env.LOCALAPPDATA || process.env.APPDATA || app.getPath("userData"), "GreyNOC", "HomeGuard");
  }
  if (process.platform === "darwin") {
    return path.join(app.getPath("home"), "Library", "Application Support", "GreyNOC", "HomeGuard");
  }
  return path.join(process.env.XDG_DATA_HOME || path.join(app.getPath("home"), ".local", "share"), "homeguard");
}

function appDataPath(...parts) {
  return path.join(appDataDir(), ...parts);
}

function isPathInside(rootPath, targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return false;
  }
  const root = path.resolve(rootPath);
  const target = path.resolve(targetPath);
  const relative = path.relative(root, target);
  return Boolean(relative && !relative.startsWith("..") && !path.isAbsolute(relative)) || target === root;
}

function isAllowedReportJsonPath(targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return false;
  }
  const target = path.resolve(targetPath);
  if (!isPathInside(appDataPath("reports"), target)) {
    return false;
  }
  if (path.extname(target).toLowerCase() !== ".json") {
    return false;
  }
  try {
    return fs.existsSync(target) && fs.statSync(target).isFile();
  } catch {
    return false;
  }
}

function scrubText(value) {
  return String(value ?? "")
    .replace(/[A-Za-z]:\\Users\\[^\\\r\n\t"'<>]+(?:\\[^\\\r\n\t"'<>]*)*/gi, "local app data")
    .replace(/[^ \r\n\t"'<>]*AppData[^ \r\n\t"'<>]*/gi, "local app data")
    .replace(/\/Users\/[^/\s"'<>]+(?:\/[^/\s"'<>]+)*/gi, "local app data")
    .replace(/\b(HOME|USERNAME|USERPROFILE|LOCALAPPDATA|APPDATA)=\S+/gi, "redacted")
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi, "redacted")
    .replace(/\b(token|api[_-]?key|password|secret|credential)s?\b\s*[:=]\s*[^\s,;]+/gi, "redacted")
    .replace(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi, (mac) => {
      const parts = String(mac).toLowerCase().split(":");
      return `device id ending ${parts.at(-2)}:${parts.at(-1)}`;
    });
}

function scrubObject(value) {
  if (Array.isArray(value)) {
    return value.map((item) => scrubObject(item));
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [key, scrubObject(item)]));
  }
  return typeof value === "string" ? scrubText(value) : value;
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function latestHistoryEntry() {
  const historyPath = appDataPath("history", "protection_history.json");
  const history = readJson(historyPath, { entries: [] });
  const entries = Array.isArray(history.entries) ? history.entries : [];
  return entries.find((entry) => entry && typeof entry === "object" && entry.json_path) || null;
}

function summarizeReport(report, entry) {
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const devices = Array.isArray(report.devices) ? report.devices : [];
  return {
    ok: true,
    entry: scrubObject(entry || {}),
    report: scrubObject({
      report_id: report.report_id || entry?.report_id || "",
      created_at: report.created_at || entry?.created_at || "",
      summary: report.summary || "",
      overall_risk: report.overall_risk || entry?.overall_risk || "unknown",
      overall_score: Number(report.overall_score || entry?.overall_score || 0),
      device_count: devices.length || Number(entry?.device_count || 0),
      finding_count: findings.length || Number(entry?.finding_count || 0),
      devices,
      findings,
      next_steps: Array.isArray(report.next_steps) ? report.next_steps : [],
      scan_metadata: report.scan_metadata && typeof report.scan_metadata === "object" ? report.scan_metadata : {},
    }),
  };
}

function registerReportAssistantIpc() {
  ipcMain.handle("homeguard:latest-report", async () => {
    const entry = latestHistoryEntry();
    if (!entry) {
      return { ok: false, message: "No HomeGuard report is available yet. Run a scan first." };
    }
    const reportPath = String(entry.json_path || "");
    if (!isAllowedReportJsonPath(reportPath)) {
      return { ok: false, message: "The latest report JSON is missing or outside the HomeGuard reports folder." };
    }
    const report = readJson(reportPath, null);
    if (!report || typeof report !== "object") {
      return { ok: false, message: "The latest report JSON could not be read." };
    }
    return summarizeReport(report, entry);
  });
}

module.exports = { registerReportAssistantIpc };

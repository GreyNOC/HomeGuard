const { app, BrowserWindow, Tray, Menu, nativeImage, ipcMain, shell, dialog } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const { pathToFileURL } = require("url");
const zlib = require("zlib");
const { registerReportAssistantIpc } = require("./report_assistant_ipc");

const repoRoot = path.resolve(__dirname, "..");
let mainWindow = null;
let tray = null;
let isQuitting = false;
let scanIndicatorTimer = null;
let scanIndicatorFrame = 0;
const scanIndicatorState = {
  activeRequested: false,
  scanning: false,
};
const trayIconCache = new Map();
let crcTable = null;

function bundledHomeGuardExecutable() {
  const exeName = process.platform === "win32" ? "HomeGuard-Core.exe" : "HomeGuard-Core";
  const candidates = [];
  if (process.env.HOMEGUARD_CORE_EXE) {
    candidates.push(process.env.HOMEGUARD_CORE_EXE);
  }
  if (app.isPackaged) {
    candidates.push(path.join(process.resourcesPath, "backend", "HomeGuard-Core", exeName));
    candidates.push(path.join(process.resourcesPath, "backend", exeName));
  }
  return candidates.find((candidate) => candidate && fs.existsSync(candidate)) || "";
}

function pythonInvocations() {
  const candidates = [];
  const envPython = process.env.HOMEGUARD_PYTHON || process.env.PYTHON;
  if (envPython) {
    candidates.push({ command: envPython, prefix: [] });
  }

  const localPython =
    process.platform === "win32"
      ? path.join(repoRoot, ".venv", "Scripts", "python.exe")
      : path.join(repoRoot, ".venv", "bin", "python");
  if (fs.existsSync(localPython)) {
    candidates.push({ command: localPython, prefix: [] });
  }

  if (process.platform === "win32") {
    candidates.push({ command: "py", prefix: ["-3"] });
    candidates.push({ command: "python", prefix: [] });
  } else {
    candidates.push({ command: "python3", prefix: [] });
    candidates.push({ command: "python", prefix: [] });
  }
  return candidates;
}

function parseKeyValueOutput(stdout) {
  const result = {};
  for (const line of stdout.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z0-9_\-[\]]+)\s*:?\s+(.+?)\s*$/);
    if (match) {
      result[match[1]] = match[2];
    }
  }
  return result;
}

function scrubText(value) {
  return String(value ?? "")
    .replace(/[A-Za-z]:\\Users\\[^\\\r\n\t"'<>]+(?:\\[^\\\r\n\t"'<>]*)*/gi, "local app data")
    .replace(/[^ \r\n\t"'<>]*AppData[^ \r\n\t"'<>]*/gi, "local app data")
    .replace(/\/Users\/[^/\s"'<>]+(?:\/[^/\s"'<>]+)*/gi, "local app data")
    .replace(/\b(HOME|USERNAME|USERPROFILE|LOCALAPPDATA|APPDATA)=\S+/gi, "redacted")
    .replace(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----/gi, "redacted")
    .replace(/\b(token|api[_-]?key|password|secret|credential)s?\b\s*[:=]\s*[^\s,;]+/gi, "redacted")
    .replace(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/gi, (value) => maskIdentifier(value));
}

function maskIdentifier(value) {
  const text = String(value ?? "");
  const match = text.match(/\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/i);
  if (!match) {
    return text;
  }
  const parts = match[0].toLowerCase().split(":");
  return `device id ending ${parts.at(-2)}:${parts.at(-1)}`;
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

function isPlainObject(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function cleanString(value, maxLength = 500) {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim().slice(0, maxLength);
}

function clampInteger(value, fallback, min, max) {
  const parsed = Number.parseInt(String(value), 10);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return Math.max(min, Math.min(max, parsed));
}

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

function isAllowedReportOrLogPath(targetPath, options = {}) {
  if (!targetPath || typeof targetPath !== "string") {
    return false;
  }
  const target = path.resolve(targetPath);
  const allowedRoot = [appDataPath("reports"), appDataPath("logs")].some((root) => isPathInside(root, target));
  if (!allowedRoot) {
    return false;
  }
  if (options.allowDirectory) {
    return true;
  }
  try {
    return fs.existsSync(target) && fs.statSync(target).isFile();
  } catch {
    return false;
  }
}

const OPENABLE_REPORT_EXTENSIONS = new Set([
  ".csv",
  ".html",
  ".htm",
  ".json",
  ".log",
  ".md",
  ".pdf",
  ".sha256",
  ".txt",
]);

function isAllowedOpenPath(targetPath) {
  if (!targetPath || typeof targetPath !== "string") {
    return false;
  }
  const target = path.resolve(targetPath);
  if (!isAllowedReportOrLogPath(target, { allowDirectory: true })) {
    return false;
  }
  try {
    const stat = fs.statSync(target);
    if (stat.isDirectory()) {
      return true;
    }
    return stat.isFile() && OPENABLE_REPORT_EXTENSIONS.has(path.extname(target).toLowerCase());
  } catch {
    return false;
  }
}

function safePathLabel(targetPath, fallback = "local file") {
  if (!targetPath) {
    return fallback;
  }
  const name = path.basename(targetPath);
  return name || fallback;
}

function readJson(filePath, fallback) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return fallback;
  }
}

function writeJson(filePath, payload) {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), "utf8");
}

function utcNow() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
}

function baselinePath() {
  return appDataPath("known_devices.json");
}

function historyPath() {
  return appDataPath("history", "protection_history.json");
}

function schedulePath() {
  return appDataPath("schedule_config.json");
}

function logPath() {
  return appDataPath("logs", "homeguard.log");
}

function sortedDeviceRows() {
  const baseline = readJson(baselinePath(), { schema_version: "2.0", devices: {} });
  const devices = baseline.devices && typeof baseline.devices === "object" ? baseline.devices : {};
  return Object.entries(devices)
    .filter(([, value]) => value && typeof value === "object")
    .map(([fingerprint, value]) => ({
      fingerprint,
      trust: "unknown",
      owner: "unknown",
      device_type: "unknown",
      notes: "",
      ...value,
      mac_address: maskIdentifier(value.mac_address || ""),
      fingerprint,
    }))
    .sort((a, b) => `${a.trust || ""}${a.ip || ""}`.localeCompare(`${b.trust || ""}${b.ip || ""}`));
}

function updateDeviceRecord(fingerprint, updater) {
  const filePath = baselinePath();
  const baseline = readJson(filePath, { schema_version: "2.0", devices: {} });
  baseline.devices = baseline.devices && typeof baseline.devices === "object" ? baseline.devices : {};
  const record = baseline.devices[fingerprint];
  if (!record || typeof record !== "object") {
    return false;
  }
  updater(record);
  writeJson(filePath, baseline);
  return true;
}

function historyState() {
  const payload = readJson(historyPath(), { schema_version: "1.0", retention: 30, entries: [] });
  return {
    retention: Number(payload.retention || 30),
    entries: Array.isArray(payload.entries) ? payload.entries : [],
  };
}

function scheduleState() {
  const payload = readJson(schedulePath(), {});
  const interval = ["daily", "hourly", "weekly"].includes(String(payload.interval || "").toLowerCase())
    ? String(payload.interval).toLowerCase()
    : "daily";
  return {
    enabled: Boolean(payload.enabled),
    interval,
    last_run: String(payload.last_run || ""),
    next_run: String(payload.next_run || ""),
    background_monitor: Boolean(payload.background_monitor),
  };
}

function nextRun(interval) {
  const ms = { hourly: 3600000, daily: 86400000, weekly: 604800000 }[interval] || 86400000;
  return new Date(Date.now() + ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function toReportPayload(stdout) {
  const paths = parseKeyValueOutput(stdout);
  const htmlPath = paths.html || "";
  const jsonPath = paths.json || "";
  return {
    stdout: scrubText(stdout),
    paths,
    htmlPath,
    jsonPath,
    reportDir: htmlPath ? path.dirname(htmlPath) : "",
    htmlUrl: htmlPath ? pathToFileURL(htmlPath).toString() : "",
    reportLabel: "Latest report saved locally",
  };
}

function runHomeGuard(args, onStdout) {
  const bundledExecutable = bundledHomeGuardExecutable();
  if (bundledExecutable) {
    return new Promise((resolve, reject) => {
      const child = spawn(bundledExecutable, args, {
        cwd: path.dirname(bundledExecutable),
        env: process.env,
        windowsHide: true,
      });

      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (chunk) => {
        const text = chunk.toString();
        stdout += text;
        if (onStdout) {
          onStdout(text);
        }
      });
      child.stderr.on("data", (chunk) => {
        stderr += chunk.toString();
      });
      child.on("error", reject);
      child.on("close", (code) => {
        if (code === 0) {
          resolve({ code, stdout, stderr });
          return;
        }
        reject(new Error((stderr || stdout || `HomeGuard exited with code ${code}`).trim()));
      });
    });
  }

  const candidates = pythonInvocations();
  const errors = [];

  function attempt(index) {
    return new Promise((resolve, reject) => {
      const py = candidates[index];
      if (!py) {
        reject(new Error(`Could not start Python. Tried: ${errors.join(" | ")}`));
        return;
      }

    const child = spawn(py.command, [...py.prefix, "-m", "greynoc_homeguard", ...args], {
      cwd: repoRoot,
      env: {
        ...process.env,
        PYTHONPATH: [path.join(repoRoot, "src"), process.env.PYTHONPATH || ""]
          .filter(Boolean)
          .join(path.delimiter),
      },
      windowsHide: true,
    });

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => {
      const text = chunk.toString();
      stdout += text;
      if (onStdout) {
        onStdout(text);
      }
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      errors.push(`${py.command}: ${error.message}`);
      attempt(index + 1).then(resolve).catch(reject);
    });
    child.on("close", (code) => {
      if (code === 0) {
        resolve({ code, stdout, stderr });
        return;
      }
      reject(new Error((stderr || stdout || `HomeGuard exited with code ${code}`).trim()));
    });
  });
  }

  return attempt(0);
}

function createWindow() {
  const window = new BrowserWindow({
    width: 1320,
    height: 900,
    minWidth: 1040,
    minHeight: 720,
    title: "GreyNOC HomeGuard",
    frame: false,
    backgroundColor: "#03101d",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  mainWindow = window;
  window.webContents.setWindowOpenHandler(() => ({ action: "deny" }));
  window.webContents.on("will-navigate", (event) => {
    event.preventDefault();
  });
  window.loadFile(path.join(__dirname, "renderer", "index.html"));
  ensureTray();
  window.on("minimize", (event) => {
    if (!isQuitting) {
      event.preventDefault();
      hideWindowToTray(window);
    }
  });
  window.on("closed", () => {
    mainWindow = null;
  });
  return window;
}

function crc32(buffer) {
  if (!crcTable) {
    crcTable = Array.from({ length: 256 }, (_value, index) => {
      let crc = index;
      for (let bit = 0; bit < 8; bit += 1) {
        crc = crc & 1 ? 0xedb88320 ^ (crc >>> 1) : crc >>> 1;
      }
      return crc >>> 0;
    });
  }
  let crc = 0xffffffff;
  for (const byte of buffer) {
    crc = crcTable[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function pngChunk(type, data = Buffer.alloc(0)) {
  const typeBuffer = Buffer.from(type, "ascii");
  const chunk = Buffer.alloc(8 + data.length + 4);
  chunk.writeUInt32BE(data.length, 0);
  typeBuffer.copy(chunk, 4);
  data.copy(chunk, 8);
  chunk.writeUInt32BE(crc32(Buffer.concat([typeBuffer, data])), 8 + data.length);
  return chunk;
}

function rgbaToPng(width, height, rgba) {
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y += 1) {
    const rowStart = y * (width * 4 + 1);
    raw[rowStart] = 0;
    rgba.copy(raw, rowStart + 1, y * width * 4, (y + 1) * width * 4);
  }
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8;
  header[9] = 6;
  const signature = Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  return Buffer.concat([
    signature,
    pngChunk("IHDR", header),
    pngChunk("IDAT", zlib.deflateSync(raw)),
    pngChunk("IEND"),
  ]);
}

function setPixel(rgba, width, x, y, color) {
  if (x < 0 || y < 0 || x >= width || y >= width) {
    return;
  }
  const offset = (y * width + x) * 4;
  rgba[offset] = color[0];
  rgba[offset + 1] = color[1];
  rgba[offset + 2] = color[2];
  rgba[offset + 3] = color[3];
}

function fillRect(rgba, width, x, y, size, color) {
  for (let yy = y; yy < y + size; yy += 1) {
    for (let xx = x; xx < x + size; xx += 1) {
      setPixel(rgba, width, xx, yy, color);
    }
  }
}

function fillCircle(rgba, width, centerX, centerY, radius, color) {
  for (let y = Math.floor(centerY - radius); y <= Math.ceil(centerY + radius); y += 1) {
    for (let x = Math.floor(centerX - radius); x <= Math.ceil(centerX + radius); x += 1) {
      if ((x - centerX) ** 2 + (y - centerY) ** 2 <= radius ** 2) {
        setPixel(rgba, width, x, y, color);
      }
    }
  }
}

function drawLine(rgba, width, x1, y1, x2, y2, color, thickness = 1) {
  const steps = Math.max(Math.abs(x2 - x1), Math.abs(y2 - y1), 1);
  for (let step = 0; step <= steps; step += 1) {
    const t = step / steps;
    const x = Math.round(x1 + (x2 - x1) * t);
    const y = Math.round(y1 + (y2 - y1) * t);
    fillRect(rgba, width, x - Math.floor(thickness / 2), y - Math.floor(thickness / 2), thickness, color);
  }
}

function trayIcon(frame = 0, active = false) {
  const key = `${active ? "active" : "idle"}:${frame}`;
  const cached = trayIconCache.get(key);
  if (cached) {
    return cached;
  }
  const width = 32;
  const rgba = Buffer.alloc(width * width * 4);
  fillRect(rgba, width, 0, 0, width, [2, 9, 18, 255]);
  fillCircle(rgba, width, 16, 16, 14, active ? [7, 35, 70, 255] : [4, 22, 42, 255]);
  fillCircle(rgba, width, 16, 16, 11, active ? [10, 113, 220, 255] : [8, 61, 120, 255]);
  fillCircle(rgba, width, 16, 16, 8, active ? [42, 193, 255, 245] : [18, 123, 210, 220]);
  fillCircle(rgba, width, 16, 16, 4, active ? [204, 250, 255, 245] : [115, 221, 255, 210]);

  const rotation = active ? frame * 12 : 0;
  const nodeSpecs = [
    [-90, 13],
    [-42, 12],
    [0, 13],
    [42, 12],
    [90, 13],
    [138, 12],
    [180, 13],
    [222, 12],
  ];
  const nodes = nodeSpecs.map(([degrees, radius]) => {
    const angle = ((degrees + rotation) * Math.PI) / 180;
    return {
      x: Math.round(16 + Math.cos(angle) * radius),
      y: Math.round(16 + Math.sin(angle) * radius),
    };
  });
  const lineColor = active ? [246, 254, 255, 238] : [150, 231, 255, 158];
  const innerLineColor = active ? [145, 246, 255, 205] : [83, 174, 235, 135];
  [
    [0, 1], [1, 2], [2, 3], [3, 4], [4, 5], [5, 6], [6, 7], [7, 0],
    [0, 2], [2, 4], [4, 6], [6, 0],
  ].forEach(([a, b], index) => {
    drawLine(rgba, width, nodes[a].x, nodes[a].y, nodes[b].x, nodes[b].y, index < 8 ? lineColor : innerLineColor, active ? 2 : 1);
  });
  nodes.forEach((node, index) => {
    const size = active && index % 2 === 0 ? 4 : 3;
    fillCircle(rgba, width, node.x, node.y, Math.max(1, Math.floor(size / 2)), active ? [255, 255, 255, 255] : [194, 246, 255, 210]);
  });
  const icon = nativeImage.createFromBuffer(rgbaToPng(width, width, rgba));
  icon.setTemplateImage(false);
  trayIconCache.set(key, icon);
  return icon;
}

function isScanIndicatorActive() {
  return Boolean(scanIndicatorState.activeRequested || scanIndicatorState.scanning);
}

function updateTrayIndicator() {
  if (!tray) {
    return;
  }
  const active = isScanIndicatorActive();
  tray.setImage(trayIcon(scanIndicatorFrame, active));
  tray.setToolTip(active ? "GreyNOC - Scanning Now" : "GreyNOC HomeGuard");
  if (active && !scanIndicatorTimer) {
    scanIndicatorTimer = setInterval(() => {
      scanIndicatorFrame = (scanIndicatorFrame + 1) % 16;
      if (tray) {
        tray.setImage(trayIcon(scanIndicatorFrame, true));
      }
    }, 140);
  } else if (!active && scanIndicatorTimer) {
    clearInterval(scanIndicatorTimer);
    scanIndicatorTimer = null;
    scanIndicatorFrame = 0;
    tray.setImage(trayIcon(0, false));
  }
}

function setScanIndicatorState(nextState) {
  scanIndicatorState.activeRequested = Boolean(nextState.activeRequested);
  scanIndicatorState.scanning = Boolean(nextState.scanning);
  updateTrayIndicator();
}

function showMainWindow() {
  if (!mainWindow) {
    mainWindow = createWindow();
    return;
  }
  if (mainWindow.isMinimized()) {
    mainWindow.restore();
  }
  mainWindow.show();
  mainWindow.focus();
}

function hideWindowToTray(window) {
  ensureTray();
  if (window) {
    window.hide();
  }
}

function ensureTray() {
  if (tray) {
    return tray;
  }
  tray = new Tray(trayIcon(0, isScanIndicatorActive()));
  tray.setToolTip("GreyNOC HomeGuard");
  tray.setContextMenu(
    Menu.buildFromTemplate([
      {
        label: "Show GreyNOC",
        click: () => {
          showMainWindow();
        },
      },
      {
        label: "Quit",
        click: () => {
          isQuitting = true;
          app.quit();
        },
      },
    ]),
  );
  tray.on("click", () => {
    showMainWindow();
  });
  tray.on("double-click", () => {
    showMainWindow();
  });
  return tray;
}

ipcMain.handle("homeguard:scan", async (event, options = {}) => {
  options = isPlainObject(options) ? options : {};
  const args = ["scan"];
  if (options.active === true) {
    args.push("--active");
  }
  if (options.probeAll === true) {
    args.push("--probe-all");
  }
  let progressBuffer = "";
  const handleScanOutput = (text) => {
    progressBuffer += text;
    const lines = progressBuffer.split(/\r?\n/);
    progressBuffer = lines.pop() || "";
    for (const line of lines) {
      const match = line.match(/^\s*\[(?:progress|scan)\]\s*(.+?)\s*$/);
      if (match) {
        event.sender.send("homeguard:scan-progress", { message: scrubText(match[1]) });
      }
    }
  };
  setScanIndicatorState({ activeRequested: scanIndicatorState.activeRequested, scanning: true });
  try {
    const result = await runHomeGuard(args, handleScanOutput);
    return toReportPayload(result.stdout);
  } finally {
    setScanIndicatorState({ activeRequested: scanIndicatorState.activeRequested, scanning: false });
  }
});

ipcMain.handle("homeguard:scan-indicator", async (_event, state = {}) => {
  state = isPlainObject(state) ? state : {};
  setScanIndicatorState({
    activeRequested: state.activeRequested === true,
    scanning: scanIndicatorState.scanning,
  });
  return { ok: true, active: isScanIndicatorActive(), ...scanIndicatorState };
});

ipcMain.handle("homeguard:update-definitions", async () => {
  const result = await runHomeGuard(["update-definitions"]);
  return { stdout: scrubText(result.stdout), status: scrubObject(parseKeyValueOutput(result.stdout)) };
});

ipcMain.handle("homeguard:definitions-status", async () => {
  const result = await runHomeGuard(["definitions-status"]);
  return { stdout: scrubText(result.stdout), status: scrubObject(parseKeyValueOutput(result.stdout)) };
});

ipcMain.handle("homeguard:history", async () => {
  const result = await runHomeGuard(["history", "--limit", "10"]);
  return { stdout: scrubText(result.stdout) };
});

ipcMain.handle("homeguard:devices", async () => {
  const rows = sortedDeviceRows();
  return {
    stdout: rows.length ? `Loaded ${rows.length} known device(s).` : "No known devices yet. Run a scan to populate the device list.",
    devices: rows,
  };
});

ipcMain.handle("homeguard:schedule", async () => {
  const schedule = scheduleState();
  return {
    stdout: schedule.enabled
      ? `Scheduled ${schedule.interval} scans enabled. Last run: ${schedule.last_run || "never"}. Next run: ${schedule.next_run || "on next launch"}.`
      : "Scheduled scans are disabled.",
    schedule,
  };
});

ipcMain.handle("homeguard:device-trust", async (_event, fingerprint, trust) => {
  const cleanTrust = cleanString(trust, 32).toLowerCase();
  if (!["trusted", "unknown", "quarantined"].includes(cleanTrust)) {
    return { ok: false, message: "Invalid trust value." };
  }
  const cleanFingerprint = cleanString(fingerprint, 160);
  const ok = updateDeviceRecord(cleanFingerprint, (record) => {
    record.trust = cleanTrust;
    record.trust_updated_at = utcNow();
  });
  return { ok, message: ok ? `Set device trust to ${cleanTrust}.` : "Select a device first.", devices: sortedDeviceRows() };
});

ipcMain.handle("homeguard:device-label", async (_event, fingerprint, label = {}) => {
  label = isPlainObject(label) ? label : {};
  const owners = new Set(["parent", "child", "guest", "unknown"]);
  const types = new Set(["phone", "laptop", "tv", "console", "iot", "router", "camera", "nas", "printer", "unknown"]);
  const cleanFingerprint = cleanString(fingerprint, 160);
  const ok = updateDeviceRecord(cleanFingerprint, (record) => {
    const owner = cleanString(label.owner || record.owner || "unknown", 40).toLowerCase();
    const deviceType = cleanString(label.device_type || record.device_type || "unknown", 40).toLowerCase();
    record.owner = owners.has(owner) ? owner : "unknown";
    record.device_type = types.has(deviceType) ? deviceType : "unknown";
    record.notes = cleanString(label.notes ?? record.notes ?? "", 500);
    record.labels_updated_at = utcNow();
  });
  return { ok, message: ok ? "Updated device label." : "Select a device first.", devices: sortedDeviceRows() };
});

ipcMain.handle("homeguard:device-remove", async (_event, fingerprint) => {
  const filePath = baselinePath();
  const baseline = readJson(filePath, { schema_version: "2.0", devices: {} });
  baseline.devices = baseline.devices && typeof baseline.devices === "object" ? baseline.devices : {};
  const key = cleanString(fingerprint, 160);
  const ok = Boolean(key && baseline.devices[key]);
  if (ok) {
    delete baseline.devices[key];
    writeJson(filePath, baseline);
  }
  return { ok, message: ok ? "Removed device from known devices." : "Select a device first.", devices: sortedDeviceRows() };
});

ipcMain.handle("homeguard:history-state", async () => {
  const state = historyState();
  return { stdout: state.entries.length ? `Loaded ${state.entries.length} scan history entrie(s).` : "No scans yet.", ...state };
});

ipcMain.handle("homeguard:history-retention", async (_event, retention) => {
  const value = clampInteger(retention, 30, 1, 365);
  const filePath = historyPath();
  const payload = readJson(filePath, { schema_version: "1.0", entries: [] });
  payload.retention = value;
  payload.entries = Array.isArray(payload.entries) ? payload.entries.slice(0, value) : [];
  writeJson(filePath, payload);
  const state = historyState();
  return { ok: true, stdout: `History retention set to ${value}.`, ...state };
});

ipcMain.handle("homeguard:schedule-save", async (_event, schedule = {}) => {
  schedule = isPlainObject(schedule) ? schedule : {};
  const requestedInterval = cleanString(schedule.interval, 20).toLowerCase();
  const interval = ["daily", "hourly", "weekly"].includes(requestedInterval)
    ? requestedInterval
    : "daily";
  const payload = {
    enabled: schedule.enabled === true,
    interval,
    last_run: cleanString(schedule.last_run || scheduleState().last_run || "", 80),
    next_run: schedule.enabled === true ? nextRun(interval) : "",
    background_monitor: schedule.background_monitor === true,
  };
  writeJson(schedulePath(), payload);
  return {
    ok: true,
    stdout: payload.enabled
      ? `Scheduled ${payload.interval} scans enabled. Last run: ${payload.last_run || "never"}. Next run: ${payload.next_run || "on next launch"}.`
      : "Scheduled scans are disabled.",
    schedule: payload,
  };
});

ipcMain.handle("homeguard:log-state", async () => {
  const filePath = logPath();
  let text = "No log file yet.";
  if (fs.existsSync(filePath)) {
    text = scrubText(fs.readFileSync(filePath, "utf8"));
  }
  return { stdout: text, logLabel: "Local GreyNOC HomeGuard log" };
});

ipcMain.handle("homeguard:logs-folder", async () => {
  const logsPath = path.join(appDataDir(), "logs");
  fs.mkdirSync(logsPath, { recursive: true });
  if (!isAllowedReportOrLogPath(logsPath, { allowDirectory: true })) {
    return { ok: false, message: "The logs folder is outside the GreyNOC HomeGuard report/log area." };
  }
  const message = await shell.openPath(logsPath);
  return { ok: !message, message: scrubText(message), stdout: "Opened the local logs folder." };
});

ipcMain.handle("homeguard:window-action", async (event, action) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  if (!window) {
    return { ok: false };
  }
  action = cleanString(action, 40);
  if (action === "minimize") {
    hideWindowToTray(window);
    return { ok: true };
  }
  if (action === "toggle-maximize") {
    if (window.isMaximized()) {
      window.unmaximize();
    } else {
      window.maximize();
    }
    return { ok: true, maximized: window.isMaximized() };
  }
  if (action === "close") {
    window.close();
    return { ok: true };
  }
  return { ok: false };
});

ipcMain.handle("homeguard:minimize-to-tray", async (event) => {
  const window = BrowserWindow.fromWebContents(event.sender);
  hideWindowToTray(window);
  return { ok: true };
});

ipcMain.handle("homeguard:save-html-as", async (event, htmlPath) => {
  const sourcePath = cleanString(htmlPath, 1000);
  if (
    !sourcePath ||
    !isAllowedReportOrLogPath(sourcePath) ||
    path.extname(sourcePath).toLowerCase() !== ".html"
  ) {
    return { ok: false, message: "No HTML report is available yet." };
  }
  const window = BrowserWindow.fromWebContents(event.sender);
  const result = await dialog.showSaveDialog(window || undefined, {
    title: "Save GreyNOC HTML Report",
    defaultPath: path.basename(sourcePath),
    filters: [{ name: "HTML Report", extensions: ["html"] }],
  });
  if (result.canceled || !result.filePath) {
    return { ok: false, canceled: true };
  }
  fs.copyFileSync(sourcePath, result.filePath);
  return { ok: true, label: safePathLabel(result.filePath, "HTML report") };
});

ipcMain.handle("homeguard:admin-access", async () => {
  if (process.platform !== "win32") {
    return { ok: false, message: "Admin relaunch is only available on Windows." };
  }
  const executable = process.execPath;
  const args = process.defaultApp ? [path.join(repoRoot, ".")] : process.argv.slice(1);
  const escapedArgs = args.map((arg) => `"${String(arg).replace(/"/g, '\\"')}"`).join(" ");
  const command = [
    "-NoProfile",
    "-Command",
    `Start-Process -FilePath '${executable.replace(/'/g, "''")}' -ArgumentList '${escapedArgs.replace(/'/g, "''")}' -Verb RunAs`,
  ];
  return new Promise((resolve) => {
    const child = spawn("powershell.exe", command, { windowsHide: true });
    let stderr = "";
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (error) => {
      resolve({ ok: false, message: scrubText(error.message) });
    });
    child.on("close", (code) => {
      resolve({ ok: code === 0, message: code === 0 ? "Admin relaunch requested." : scrubText(stderr.trim()) });
    });
  });
});

ipcMain.handle("homeguard:open-path", async (_event, targetPath) => {
  const safeTarget = cleanString(targetPath, 1000);
  if (!safeTarget || !isAllowedOpenPath(safeTarget)) {
    return { ok: false, message: "This path is outside the GreyNOC HomeGuard report/log area or is not a report/log file." };
  }
  const message = await shell.openPath(path.resolve(safeTarget));
  return { ok: !message, message: scrubText(message) };
});

ipcMain.handle("homeguard:show-item", async (_event, targetPath) => {
  const safeTarget = cleanString(targetPath, 1000);
  if (!safeTarget || !isAllowedOpenPath(safeTarget)) {
    return { ok: false };
  }
  shell.showItemInFolder(path.resolve(safeTarget));
  return { ok: true };
});

// =============================================================
// Chat history (Ask GreyNOC conversation persistence)
// -------------------------------------------------------------
// Chats are stored as a single JSON file under appData. Each chat
// is a list of {role, content, ts} messages plus a title and
// timestamps. The renderer drives all writes via IPC; main.js is
// the only process that touches the file so we have one
// well-defined sanitization point and no race against scans.
// =============================================================

const CHATS_SCHEMA_VERSION = "1.0";
const MAX_CHATS = 100;
const MAX_MESSAGES_PER_CHAT = 200;
const MAX_MESSAGE_LEN = 8192;
const MAX_TITLE_LEN = 120;
const MAX_CHAT_ID_LEN = 64;
const VALID_CHAT_ROLES = new Set(["user", "assistant"]);
const VALID_CHAT_ID_RE = /^chat-[a-z0-9]{6,32}$/;

function chatsPath() {
  return appDataPath("chats", "chats.json");
}

function emptyChatStore() {
  return { schema_version: CHATS_SCHEMA_VERSION, active_chat_id: "", chats: [] };
}

function chatTitleFromMessages(messages) {
  const firstUser = Array.isArray(messages) ? messages.find((m) => m && m.role === "user") : null;
  if (!firstUser) {
    return "";
  }
  const raw = String(firstUser.content || "").replace(/\s+/g, " ").trim();
  return raw.slice(0, 60);
}

function sanitizeChatMessage(message) {
  if (!isPlainObject(message)) {
    return null;
  }
  const role = String(message.role || "").trim().toLowerCase();
  if (!VALID_CHAT_ROLES.has(role)) {
    return null;
  }
  const content = cleanString(message.content, MAX_MESSAGE_LEN);
  if (!content) {
    return null;
  }
  const ts = typeof message.ts === "string" && message.ts.length <= 32 ? message.ts : utcNow();
  return { role, content, ts };
}

function sanitizeChat(chat) {
  if (!isPlainObject(chat)) {
    return null;
  }
  const id = String(chat.id || "").trim();
  if (!VALID_CHAT_ID_RE.test(id)) {
    return null;
  }
  const messages = Array.isArray(chat.messages)
    ? chat.messages.map(sanitizeChatMessage).filter(Boolean).slice(-MAX_MESSAGES_PER_CHAT)
    : [];
  const created_at = typeof chat.created_at === "string" && chat.created_at.length <= 32
    ? chat.created_at
    : utcNow();
  const updated_at = typeof chat.updated_at === "string" && chat.updated_at.length <= 32
    ? chat.updated_at
    : created_at;
  let title = cleanString(chat.title, MAX_TITLE_LEN);
  if (!title) {
    title = chatTitleFromMessages(messages) || "New chat";
  }
  return { id, title, created_at, updated_at, messages };
}

function readChatStore() {
  const data = readJson(chatsPath(), emptyChatStore());
  if (!isPlainObject(data)) {
    return emptyChatStore();
  }
  const chats = Array.isArray(data.chats) ? data.chats.map(sanitizeChat).filter(Boolean) : [];
  let active_chat_id = typeof data.active_chat_id === "string" && VALID_CHAT_ID_RE.test(data.active_chat_id)
    ? data.active_chat_id
    : "";
  if (active_chat_id && !chats.some((c) => c.id === active_chat_id)) {
    active_chat_id = "";
  }
  return { schema_version: CHATS_SCHEMA_VERSION, active_chat_id, chats };
}

function writeChatStore(store) {
  const chats = Array.isArray(store.chats) ? store.chats.map(sanitizeChat).filter(Boolean) : [];
  let active_chat_id = store.active_chat_id && VALID_CHAT_ID_RE.test(store.active_chat_id)
    ? store.active_chat_id
    : "";
  if (active_chat_id && !chats.some((c) => c.id === active_chat_id)) {
    active_chat_id = "";
  }
  const safe = { schema_version: CHATS_SCHEMA_VERSION, active_chat_id, chats };
  writeJson(chatsPath(), safe);
  return safe;
}

function generateChatId() {
  const ts = Date.now().toString(36);
  const rand = Math.random().toString(36).slice(2, 10).padEnd(8, "0");
  return `chat-${ts}${rand}`.slice(0, 32);
}

function chatSummary(chat) {
  return {
    id: chat.id,
    title: chat.title,
    created_at: chat.created_at,
    updated_at: chat.updated_at,
    message_count: Array.isArray(chat.messages) ? chat.messages.length : 0,
  };
}

function sortChatsByUpdated(chats) {
  return [...chats].sort((a, b) => String(b.updated_at || "").localeCompare(String(a.updated_at || "")));
}

ipcMain.handle("homeguard:chats-list", async () => {
  const store = readChatStore();
  return {
    ok: true,
    chats: sortChatsByUpdated(store.chats).map(chatSummary),
    active_chat_id: store.active_chat_id,
  };
});

ipcMain.handle("homeguard:chats-get", async (_event, id) => {
  const safeId = cleanString(id, MAX_CHAT_ID_LEN);
  if (!VALID_CHAT_ID_RE.test(safeId)) {
    return { ok: false, message: "Invalid chat id." };
  }
  const store = readChatStore();
  const chat = store.chats.find((c) => c.id === safeId);
  if (!chat) {
    return { ok: false, message: "Chat not found." };
  }
  return { ok: true, chat };
});

ipcMain.handle("homeguard:chats-save", async (_event, payload = {}) => {
  if (!isPlainObject(payload)) {
    return { ok: false, message: "Invalid chat payload." };
  }
  const store = readChatStore();
  const now = utcNow();
  let id = cleanString(payload.id, MAX_CHAT_ID_LEN);
  if (!VALID_CHAT_ID_RE.test(id)) {
    id = generateChatId();
  }
  const incomingMessages = Array.isArray(payload.messages)
    ? payload.messages.map(sanitizeChatMessage).filter(Boolean).slice(-MAX_MESSAGES_PER_CHAT)
    : [];
  const existing = store.chats.find((c) => c.id === id);
  const created_at = existing ? existing.created_at : now;
  let title = cleanString(payload.title, MAX_TITLE_LEN);
  if (!title) {
    title = (existing && existing.title) || chatTitleFromMessages(incomingMessages) || "New chat";
  }
  const chat = { id, title, created_at, updated_at: now, messages: incomingMessages };
  if (existing) {
    Object.assign(existing, chat);
  } else {
    store.chats.push(chat);
  }
  if (store.chats.length > MAX_CHATS) {
    const sorted = sortChatsByUpdated(store.chats);
    const kept = new Set(sorted.slice(0, MAX_CHATS).map((c) => c.id));
    store.chats = store.chats.filter((c) => kept.has(c.id));
  }
  store.active_chat_id = id;
  writeChatStore(store);
  return { ok: true, chat: chatSummary(chat), active_chat_id: id };
});

ipcMain.handle("homeguard:chats-delete", async (_event, id) => {
  const safeId = cleanString(id, MAX_CHAT_ID_LEN);
  if (!VALID_CHAT_ID_RE.test(safeId)) {
    return { ok: false, message: "Invalid chat id." };
  }
  const store = readChatStore();
  const before = store.chats.length;
  store.chats = store.chats.filter((c) => c.id !== safeId);
  if (store.chats.length === before) {
    return { ok: false, message: "Chat not found." };
  }
  if (store.active_chat_id === safeId) {
    const sorted = sortChatsByUpdated(store.chats);
    store.active_chat_id = sorted[0]?.id || "";
  }
  writeChatStore(store);
  return {
    ok: true,
    active_chat_id: store.active_chat_id,
    chats: sortChatsByUpdated(store.chats).map(chatSummary),
  };
});

ipcMain.handle("homeguard:chats-set-active", async (_event, id) => {
  const safeId = cleanString(id, MAX_CHAT_ID_LEN);
  if (safeId && !VALID_CHAT_ID_RE.test(safeId)) {
    return { ok: false, message: "Invalid chat id." };
  }
  const store = readChatStore();
  if (safeId && !store.chats.some((c) => c.id === safeId)) {
    return { ok: false, message: "Chat not found." };
  }
  store.active_chat_id = safeId;
  writeChatStore(store);
  return { ok: true, active_chat_id: store.active_chat_id };
});

ipcMain.handle("homeguard:chats-rename", async (_event, id, title) => {
  const safeId = cleanString(id, MAX_CHAT_ID_LEN);
  if (!VALID_CHAT_ID_RE.test(safeId)) {
    return { ok: false, message: "Invalid chat id." };
  }
  const safeTitle = cleanString(title, MAX_TITLE_LEN);
  if (!safeTitle) {
    return { ok: false, message: "Title cannot be empty." };
  }
  const store = readChatStore();
  const chat = store.chats.find((c) => c.id === safeId);
  if (!chat) {
    return { ok: false, message: "Chat not found." };
  }
  chat.title = safeTitle;
  chat.updated_at = utcNow();
  writeChatStore(store);
  return { ok: true, chat: chatSummary(chat) };
});

// =============================================================
// Fix-guidance playbooks per finding
// -------------------------------------------------------------
// Surface findings from the latest report, render a step-by-step
// remediation playbook on click, and execute the playbook's actions
// (open update page, mark patched, mark trusted/quarantined, run
// Defender scan, open Windows Firewall settings). Playbook CONTENT
// is generated by the Python side (playbooks.py) so the same
// guidance flows through reports / AI bridge / CLI; ACTIONS live
// here in main.js because they touch the OS and the local stores.
// =============================================================

function patchesPath() {
  return appDataPath("patches.json");
}

function readPatchesStore() {
  const data = readJson(patchesPath(), { schema_version: "1.0", patches: {} });
  if (!isPlainObject(data)) {
    return { schema_version: "1.0", patches: {} };
  }
  return {
    schema_version: typeof data.schema_version === "string" ? data.schema_version : "1.0",
    patches: isPlainObject(data.patches) ? data.patches : {},
  };
}

function writePatchesStore(store) {
  const safe = {
    schema_version: "1.0",
    patches: isPlainObject(store.patches) ? store.patches : {},
  };
  writeJson(patchesPath(), safe);
  return safe;
}

function recordPatch(findingId, ruleId, note) {
  const cleanId = cleanString(findingId, 128);
  if (!cleanId) return null;
  const store = readPatchesStore();
  store.patches[cleanId] = {
    finding_id: cleanId,
    rule_id: cleanString(ruleId || "", 80),
    patched_at: utcNow(),
    note: cleanString(note || "", 500),
  };
  writePatchesStore(store);
  return store.patches[cleanId];
}

function loadLatestReportJson() {
  const historyFile = appDataPath("history", "protection_history.json");
  const history = readJson(historyFile, { entries: [] });
  const entries = Array.isArray(history.entries) ? history.entries : [];
  const entry = entries.find((e) => e && typeof e === "object" && e.json_path);
  if (!entry) {
    return { ok: false, message: "No HomeGuard report yet. Run a scan first." };
  }
  const reportPath = String(entry.json_path || "");
  const reportsRoot = appDataPath("reports");
  if (
    !isPathInside(reportsRoot, reportPath) ||
    path.extname(reportPath).toLowerCase() !== ".json"
  ) {
    return { ok: false, message: "Latest report JSON is missing or outside the reports folder." };
  }
  const report = readJson(reportPath, null);
  if (!report || typeof report !== "object") {
    return { ok: false, message: "Could not read the latest report JSON." };
  }
  return { ok: true, report, entry };
}

ipcMain.handle("homeguard:findings-list", async () => {
  const result = loadLatestReportJson();
  if (!result.ok) {
    return { ok: false, message: result.message, findings: [] };
  }
  const findings = Array.isArray(result.report.findings) ? result.report.findings : [];
  const patches = readPatchesStore().patches;
  const enriched = findings
    .filter(isPlainObject)
    .map((finding) => {
      const id = String(finding.finding_id || "");
      const patch = id ? patches[id] : null;
      return {
        ...finding,
        patched_at: patch ? String(patch.patched_at || "") : "",
      };
    });
  return {
    ok: true,
    findings: enriched,
    report_id: String(result.report.report_id || ""),
    created_at: String(result.report.created_at || ""),
  };
});

ipcMain.handle("homeguard:playbook-get", async (_event, finding) => {
  if (!isPlainObject(finding)) {
    return { ok: false, message: "Invalid finding payload." };
  }
  const payload = JSON.stringify(finding);
  try {
    const result = await runHomeGuard(["playbook", "show", "--finding-json", payload]);
    let playbook;
    try {
      playbook = JSON.parse(result.stdout || "{}");
    } catch (parseErr) {
      return { ok: false, message: `Playbook output was not valid JSON: ${parseErr.message}` };
    }
    const findingId = String(finding.finding_id || "");
    if (findingId) {
      const patch = readPatchesStore().patches[findingId];
      if (patch && patch.patched_at) {
        playbook.patched_at = String(patch.patched_at);
      }
    }
    return { ok: true, playbook };
  } catch (err) {
    return { ok: false, message: scrubText(err && err.message ? err.message : String(err)) };
  }
});

const ALLOWED_PLAYBOOK_URL_SCHEMES = new Set([
  "http:",
  "https:",
  "windowsdefender:",
  "ms-settings:",
]);

ipcMain.handle("homeguard:playbook-action", async (_event, payload = {}) => {
  if (!isPlainObject(payload)) {
    return { ok: false, message: "Invalid payload." };
  }
  const kind = cleanString(payload.kind, 64);
  const data = isPlainObject(payload.payload) ? payload.payload : {};

  switch (kind) {
    case "open_url": {
      const rawUrl = cleanString(data.url, 1024);
      if (!rawUrl) return { ok: false, message: "No URL provided." };
      let url;
      try {
        url = new URL(rawUrl);
      } catch (err) {
        return { ok: false, message: `Invalid URL: ${err.message}` };
      }
      if (!ALLOWED_PLAYBOOK_URL_SCHEMES.has(url.protocol)) {
        return { ok: false, message: `Unsupported URL scheme: ${url.protocol}` };
      }
      try {
        await shell.openExternal(url.toString());
        return { ok: true, message: `Opened ${url.toString()}` };
      } catch (err) {
        return { ok: false, message: scrubText(err && err.message ? err.message : String(err)) };
      }
    }
    case "mark_patched": {
      const findingId = cleanString(data.finding_id, 128);
      if (!findingId) return { ok: false, message: "Missing finding id." };
      const patch = recordPatch(
        findingId,
        cleanString(data.rule_id, 80),
        cleanString(data.note, 500),
      );
      return { ok: true, message: "Marked as patched.", patch };
    }
    case "mark_trusted":
    case "mark_quarantined":
    case "mark_unknown": {
      const fingerprint = cleanString(data.fingerprint, 160);
      if (!fingerprint) return { ok: false, message: "Missing device fingerprint." };
      const trust =
        kind === "mark_trusted"
          ? "trusted"
          : kind === "mark_quarantined"
            ? "quarantined"
            : "unknown";
      const ok = updateDeviceRecord(fingerprint, (record) => {
        record.trust = trust;
        record.trust_updated_at = utcNow();
      });
      return {
        ok,
        message: ok ? `Set device trust to ${trust}.` : "Device not found in known-device list.",
      };
    }
    case "run_defender_scan": {
      if (process.platform !== "win32") {
        return { ok: false, message: "Defender scan is only available on Windows." };
      }
      const scanType = cleanString(data.scan_type, 16) === "quick" ? "1" : "2";
      // ``spawn()`` does NOT throw synchronously when the executable is
      // missing - it emits an asynchronous "error" event instead. The
      // previous version swallowed that event and still returned
      // ok: true, so users could be told "Defender full scan started"
      // when MpCmdRun.exe wasn't on PATH at all. We now race the spawn
      // event (success) against the error event (failure) with a short
      // timeout backstop, and only return ok: true once the child has
      // actually started.
      return new Promise((resolve) => {
        let child;
        try {
          child = spawn(
            "MpCmdRun.exe",
            ["-Scan", "-ScanType", scanType],
            { windowsHide: true, detached: true, stdio: "ignore" },
          );
        } catch (err) {
          // Synchronous spawn failures (rare - bad argv shape) still
          // throw. Catch defensively.
          resolve({
            ok: false,
            message: scrubText(
              `Could not start Defender scan: ${err && err.message ? err.message : String(err)}`,
            ),
          });
          return;
        }
        let settled = false;
        const settle = (result) => {
          if (settled) return;
          settled = true;
          resolve(result);
        };
        child.once("spawn", () => {
          // MpCmdRun launched. Detach so it survives this handler returning.
          try { child.unref(); } catch (_) {}
          settle({
            ok: true,
            message:
              scanType === "2"
                ? "Started Defender full scan (runs in the background; 30-90 minutes)."
                : "Started Defender quick scan.",
          });
        });
        child.once("error", (err) => {
          // Most commonly ENOENT: MpCmdRun.exe is not on PATH or Defender
          // isn't installed / has been replaced by another EDR.
          settle({
            ok: false,
            message: scrubText(
              `Could not start Defender scan: ${err && err.message ? err.message : String(err)}`,
            ),
          });
        });
        // Backstop: if neither "spawn" nor "error" fires within 2 seconds,
        // assume the spawn is silently stuck and report failure rather
        // than a false-positive success.
        setTimeout(() => {
          settle({
            ok: false,
            message: "Defender scan did not start (timed out waiting for MpCmdRun.exe).",
          });
        }, 2000);
      });
    }
    default:
      return { ok: false, message: `Unknown action kind: ${kind}` };
  }
});

registerReportAssistantIpc();

app.whenReady().then(createWindow);

app.on("before-quit", () => {
  isQuitting = true;
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") {
    app.quit();
  }
});

app.on("activate", () => {
  if (BrowserWindow.getAllWindows().length === 0) {
    createWindow();
  }
});

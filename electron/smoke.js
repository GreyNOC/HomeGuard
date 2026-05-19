const fs = require("fs");
const path = require("path");
const { spawnSync } = require("child_process");

const root = path.resolve(__dirname, "..");
const required = [
  "package.json",
  "electron/main.secure.js",
  "electron/main.js",
  "electron/preload.js",
  "electron/report_assistant_ipc.js",
  "electron/renderer/index.html",
  "electron/renderer/styles.css",
  "electron/renderer/renderer.js",
  "electron/renderer/chat-assistant.js",
];

for (const relativePath of required) {
  const absolutePath = path.join(root, relativePath);
  if (!fs.existsSync(absolutePath)) {
    throw new Error(`Missing ${relativePath}`);
  }
}

const packageJson = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
if (packageJson.main !== "electron/main.secure.js") {
  throw new Error("package.json does not point at the secure Electron entrypoint.");
}

const secureMain = fs.readFileSync(path.join(root, "electron", "main.secure.js"), "utf8");
if (!secureMain.includes("HOMEGUARD_DEV_MODE") || !secureMain.includes("HOMEGUARD_CORE_EXE") || !secureMain.includes("HOMEGUARD_PYTHON")) {
  throw new Error("Secure Electron entrypoint is not guarding packaged environment overrides.");
}
if (!secureMain.includes("registerReportAssistantIpc()")) {
  throw new Error("Secure Electron entrypoint does not register report assistant IPC.");
}
if (!secureMain.includes('require("./main.js")')) {
  throw new Error("Secure Electron entrypoint does not load the main process.");
}

const reportAssistant = fs.readFileSync(path.join(root, "electron", "report_assistant_ipc.js"), "utf8");
if (!reportAssistant.includes("homeguard:latest-report")) {
  throw new Error("Report assistant IPC channel is missing.");
}
if (!reportAssistant.includes("isAllowedReportJsonPath") || !reportAssistant.includes('appDataPath("reports")')) {
  throw new Error("Report assistant IPC does not restrict latest-report JSON to HomeGuard reports.");
}
if (!reportAssistant.includes("scrubObject") || !reportAssistant.includes("summarizeReport")) {
  throw new Error("Report assistant IPC is not sanitizing and summarizing reports.");
}

const main = fs.readFileSync(path.join(root, "electron", "main.js"), "utf8");
if (!main.includes("frame: false")) {
  throw new Error("Electron BrowserWindow is not configured as frameless.");
}

if (!main.includes("sandbox: true") || !main.includes("setWindowOpenHandler") || !main.includes('will-navigate"')) {
  throw new Error("Electron navigation hardening is not enabled.");
}

if (!main.includes("isAllowedReportOrLogPath") || !main.includes("appDataPath(\"reports\")") || !main.includes("appDataPath(\"logs\")")) {
  throw new Error("Electron file-opening IPC is not limited to report/log paths.");
}

if (!main.includes("OPENABLE_REPORT_EXTENSIONS") || !main.includes("isAllowedOpenPath")) {
  throw new Error("Electron file-opening IPC does not restrict report/log file types.");
}

if (!main.includes("(?:progress|scan)")) {
  throw new Error("Electron scan progress parser is not compatible with current CLI progress output.");
}

if (!main.includes('window.on("minimize"') || !main.includes("hideWindowToTray(window)")) {
  throw new Error("Minimize is not wired to hide the window to the tray.");
}

if (!main.includes("ensureTray();") || !main.includes("nativeImage.createFromBuffer")) {
  throw new Error("Tray icon is not initialized with the scan indicator artwork.");
}

if (!main.includes("bundledHomeGuardExecutable") || !main.includes("process.resourcesPath")) {
  throw new Error("Packaged Electron builds are not wired to the bundled HomeGuard backend.");
}

for (const channel of [
  "homeguard:scan",
  "homeguard:scan-indicator",
  "homeguard:update-definitions",
  "homeguard:definitions-status",
  "homeguard:history",
  "homeguard:devices",
  "homeguard:schedule",
  "homeguard:device-trust",
  "homeguard:device-label",
  "homeguard:device-remove",
  "homeguard:history-state",
  "homeguard:history-retention",
  "homeguard:schedule-save",
  "homeguard:log-state",
  "homeguard:logs-folder",
  "homeguard:window-action",
  "homeguard:minimize-to-tray",
  "homeguard:save-html-as",
  "homeguard:admin-access",
]) {
  if (!main.includes(channel)) {
    throw new Error(`Missing IPC channel ${channel}`);
  }
}

const preload = fs.readFileSync(path.join(root, "electron", "preload.js"), "utf8");
for (const apiName of [
  "latestReport",
  "devices",
  "setScanIndicator",
  "schedule",
  "setDeviceTrust",
  "setDeviceLabel",
  "removeDevice",
  "historyState",
  "setHistoryRetention",
  "saveSchedule",
  "logState",
  "logsFolder",
  "adminAccess",
  "minimizeToTray",
  "saveHtmlAs",
  "windowAction",
]) {
  if (!preload.includes(`${apiName}:`)) {
    throw new Error(`Missing preload API ${apiName}`);
  }
}

const indexHtml = fs.readFileSync(path.join(root, "electron", "renderer", "index.html"), "utf8");
if (!indexHtml.includes("chatMessages") || !indexHtml.includes("chatForm") || !indexHtml.includes("chat-assistant.js")) {
  throw new Error("Renderer HTML is not wired as a chat assistant surface.");
}

const css = fs.readFileSync(path.join(root, "electron", "renderer", "styles.css"), "utf8");
if (!css.includes("--app-bg") || !css.includes("--accent") || !css.includes("--scan")) {
  throw new Error("Renderer app background is not the chat-first GreyNOC theme.");
}

if (!css.includes(".chat-page") || !css.includes(".chat-composer") || !css.includes(".message-card")) {
  throw new Error("Renderer chat layout styles are missing.");
}

if (css.includes("background: white")) {
  throw new Error("Renderer still contains white panel styling.");
}

if (!css.includes(".scan-orb.is-active") || !css.includes("scan-orb-spin")) {
  throw new Error("Renderer scan indicator is not wired to active scan state.");
}

const renderer = fs.readFileSync(path.join(root, "electron", "renderer", "renderer.js"), "utf8");
if (!renderer.includes("activeScan.addEventListener(\"change\", updateScanIndicator)")) {
  throw new Error("Active scan toggle does not drive the scan indicator.");
}
if (!renderer.includes("Active scan on") || !renderer.includes("Scanning now")) {
  throw new Error("Active scan state is not labeled under the scan indicator.");
}
if (renderer.includes("devicesTableBody.innerHTML") || renderer.includes("historyTableBody.innerHTML")) {
  throw new Error("Renderer data tables must be built with DOM nodes instead of HTML strings.");
}

const chatAssistant = fs.readFileSync(path.join(root, "electron", "renderer", "chat-assistant.js"), "utf8");
for (const expected of [
  "latestReport",
  "answerFixFirst",
  "answerRiskyDevices",
  "answerPortOrDevice",
  "sortedFindings",
  "findingActions",
  "isScanCommand",
]) {
  if (!chatAssistant.includes(expected)) {
    throw new Error(`Chat assistant is missing report-aware behavior: ${expected}`);
  }
}
if (chatAssistant.includes("The next phase will connect this chat directly to report JSON")) {
  throw new Error("Chat assistant still contains placeholder report-answer text.");
}

const scanRunner = fs.readFileSync(path.join(root, "src", "greynoc_homeguard", "scan_runner.py"), "utf8");
if (
  !scanRunner.includes("passive_only=not active") ||
  !scanRunner.includes("allow_ping_sweep=active") ||
  !scanRunner.includes("allow_tcp_port_check=active") ||
  !scanRunner.includes("engine.build_report")
) {
  throw new Error("Active scans are not wired through network discovery and the detection engine.");
}

function pythonCandidates() {
  const localPython =
    process.platform === "win32"
      ? path.join(root, ".venv", "Scripts", "python.exe")
      : path.join(root, ".venv", "bin", "python");
  const candidates = [];
  if (process.env.HOMEGUARD_PYTHON || process.env.PYTHON) {
    candidates.push({ command: process.env.HOMEGUARD_PYTHON || process.env.PYTHON, prefix: [] });
  }
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

let pythonCheck = null;
const pythonErrors = [];
for (const candidate of pythonCandidates()) {
  const result = spawnSync(
    candidate.command,
    [...candidate.prefix, "-m", "greynoc_homeguard", "definitions-status"],
    {
      cwd: root,
      env: {
        ...process.env,
        PYTHONPATH: [path.join(root, "src"), process.env.PYTHONPATH || ""]
          .filter(Boolean)
          .join(path.delimiter),
        PYTHONDONTWRITEBYTECODE: "1",
      },
      encoding: "utf8",
      windowsHide: true,
    },
  );
  if (result.status === 0) {
    pythonCheck = result;
    break;
  }
  pythonErrors.push(result.error ? result.error.message : result.stderr || result.stdout || "unknown failure");
}

if (!pythonCheck) {
  const allBlocked = pythonErrors.length > 0 && pythonErrors.every((message) => message.includes("EPERM"));
  if (allBlocked) {
    console.warn("Python subprocess smoke check skipped: this sandbox blocks Node from spawning Python.");
  } else {
    throw new Error(`Python CLI wiring failed: ${pythonErrors.join(" | ")}`);
  }
}

if (
  pythonCheck &&
  !pythonCheck.stdout.includes("HomeGuard security definitions") &&
  !pythonCheck.stdout.includes("Security Definitions")
) {
  throw new Error("Python CLI wiring did not return the expected HomeGuard output.");
}

console.log("Electron frontend smoke check passed.");

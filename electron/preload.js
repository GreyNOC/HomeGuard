const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("homeguard", {
  scan: (options) => ipcRenderer.invoke("homeguard:scan", options),
  onScanProgress: (callback) => {
    const listener = (_event, payload) => callback(payload);
    ipcRenderer.on("homeguard:scan-progress", listener);
    return () => ipcRenderer.removeListener("homeguard:scan-progress", listener);
  },
  setScanIndicator: (state) => ipcRenderer.invoke("homeguard:scan-indicator", state),
  updateDefinitions: () => ipcRenderer.invoke("homeguard:update-definitions"),
  definitionsStatus: () => ipcRenderer.invoke("homeguard:definitions-status"),
  uiPrefs: {
    get: () => ipcRenderer.invoke("homeguard:ui-prefs"),
    set: (prefs) => ipcRenderer.invoke("homeguard:ui-prefs-set", prefs),
  },
  latestReport: () => ipcRenderer.invoke("homeguard:latest-report"),
  history: () => ipcRenderer.invoke("homeguard:history"),
  devices: () => ipcRenderer.invoke("homeguard:devices"),
  schedule: () => ipcRenderer.invoke("homeguard:schedule"),
  setDeviceTrust: (fingerprint, trust) => ipcRenderer.invoke("homeguard:device-trust", fingerprint, trust),
  setDeviceLabel: (fingerprint, label) => ipcRenderer.invoke("homeguard:device-label", fingerprint, label),
  removeDevice: (fingerprint) => ipcRenderer.invoke("homeguard:device-remove", fingerprint),
  historyState: () => ipcRenderer.invoke("homeguard:history-state"),
  setHistoryRetention: (retention) => ipcRenderer.invoke("homeguard:history-retention", retention),
  saveSchedule: (schedule) => ipcRenderer.invoke("homeguard:schedule-save", schedule),
  logState: () => ipcRenderer.invoke("homeguard:log-state"),
  logsFolder: () => ipcRenderer.invoke("homeguard:logs-folder"),
  adminAccess: () => ipcRenderer.invoke("homeguard:admin-access"),
  minimizeToTray: () => ipcRenderer.invoke("homeguard:minimize-to-tray"),
  saveHtmlAs: (htmlPath) => ipcRenderer.invoke("homeguard:save-html-as", htmlPath),
  openPath: (targetPath) => ipcRenderer.invoke("homeguard:open-path", targetPath),
  showItem: (targetPath) => ipcRenderer.invoke("homeguard:show-item", targetPath),
  windowAction: (action) => ipcRenderer.invoke("homeguard:window-action", action),
  findings: {
    list: () => ipcRenderer.invoke("homeguard:findings-list"),
    playbook: (finding) => ipcRenderer.invoke("homeguard:playbook-get", finding),
    action: (payload) => ipcRenderer.invoke("homeguard:playbook-action", payload),
  },
  fileScan: {
    pickTarget: (options) => ipcRenderer.invoke("homeguard:pick-scan-target", options),
    scan: (payload) => ipcRenderer.invoke("homeguard:scan-file", payload),
    quarantineList: () => ipcRenderer.invoke("homeguard:quarantine-list"),
    quarantineRestore: (entryId, options) => ipcRenderer.invoke("homeguard:quarantine-restore", entryId, options),
    quarantineDelete: (entryId) => ipcRenderer.invoke("homeguard:quarantine-delete", entryId),
  },
  networkMap: (options) => ipcRenderer.invoke("homeguard:network-map", options),
  chats: {
    list: () => ipcRenderer.invoke("homeguard:chats-list"),
    get: (id) => ipcRenderer.invoke("homeguard:chats-get", id),
    save: (chat) => ipcRenderer.invoke("homeguard:chats-save", chat),
    delete: (id) => ipcRenderer.invoke("homeguard:chats-delete", id),
    setActive: (id) => ipcRenderer.invoke("homeguard:chats-set-active", id),
    rename: (id, title) => ipcRenderer.invoke("homeguard:chats-rename", id, title),
  },
  ai: {
    status: () => ipcRenderer.invoke("homeguard:ai-status"),
    sterile: () => ipcRenderer.invoke("homeguard:ai-sterile"),
    configure: (payload) => ipcRenderer.invoke("homeguard:ai-configure", payload),
    chat: (payload) => ipcRenderer.invoke("homeguard:ai-chat", payload),
    memoryShow: () => ipcRenderer.invoke("homeguard:ai-memory-show"),
    memoryAdd: (payload) => ipcRenderer.invoke("homeguard:ai-memory-add", payload),
    memoryClear: () => ipcRenderer.invoke("homeguard:ai-memory-clear"),
    traffic: () => ipcRenderer.invoke("homeguard:ai-traffic"),
  },
  platform: process.platform,
});

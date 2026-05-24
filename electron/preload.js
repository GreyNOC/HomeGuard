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
  chats: {
    list: () => ipcRenderer.invoke("homeguard:chats-list"),
    get: (id) => ipcRenderer.invoke("homeguard:chats-get", id),
    save: (chat) => ipcRenderer.invoke("homeguard:chats-save", chat),
    delete: (id) => ipcRenderer.invoke("homeguard:chats-delete", id),
    setActive: (id) => ipcRenderer.invoke("homeguard:chats-set-active", id),
    rename: (id, title) => ipcRenderer.invoke("homeguard:chats-rename", id, title),
  },
  platform: process.platform,
});

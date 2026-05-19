const { app } = require("electron");
const { registerReportAssistantIpc } = require("./report_assistant_ipc");

function developmentOverrideAllowed() {
  const value = String(process.env.HOMEGUARD_DEV_MODE || "").trim().toLowerCase();
  return value === "1" || value === "true" || value === "yes";
}

function removePackagedExecutionOverrides() {
  if (!app.isPackaged || developmentOverrideAllowed()) {
    return;
  }

  for (const key of [
    "HOMEGUARD_CORE_EXE",
    "HOMEGUARD_PYTHON",
    "PYTHON",
  ]) {
    delete process.env[key];
  }
}

removePackagedExecutionOverrides();
registerReportAssistantIpc();
require("./main.js");

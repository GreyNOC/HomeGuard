const { app, ipcMain } = require("electron");
const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

// ai_bridge_ipc wires the renderer chat UI to greynoc_homeguard.ai_bridge.
// It runs the Python CLI as a child process and never persists API keys -
// only the environment-variable name. The renderer is responsible for
// reminding the user to set the env var before launching HomeGuard.

const CLI_TIMEOUT_MS = 60000;
const CHAT_TIMEOUT_MS = 120000;

function repoRoot() {
  return path.resolve(__dirname, "..");
}

function bundledHomeGuardExecutable() {
  if (!app.isPackaged) return "";
  const exeName = process.platform === "win32" ? "HomeGuard-Core.exe" : "HomeGuard-Core";
  const candidates = [
    process.env.HOMEGUARD_CORE_EXE,
    path.join(process.resourcesPath, "backend", "HomeGuard-Core", exeName),
    path.join(process.resourcesPath, "backend", exeName),
  ].filter(Boolean);
  return candidates.find((candidate) => fs.existsSync(candidate)) || "";
}

function pythonInvocations() {
  const candidates = [];
  const envPython = process.env.HOMEGUARD_PYTHON || process.env.PYTHON;
  if (envPython) candidates.push({ command: envPython, prefix: [] });
  const localPython =
    process.platform === "win32"
      ? path.join(repoRoot(), ".venv", "Scripts", "python.exe")
      : path.join(repoRoot(), ".venv", "bin", "python");
  if (fs.existsSync(localPython)) candidates.push({ command: localPython, prefix: [] });
  if (process.platform === "win32") {
    candidates.push({ command: "py", prefix: ["-3"] });
    candidates.push({ command: "python", prefix: [] });
  } else {
    candidates.push({ command: "python3", prefix: [] });
    candidates.push({ command: "python", prefix: [] });
  }
  return candidates;
}

function runAiBridge(args, options = {}) {
  const bundled = bundledHomeGuardExecutable();
  const timeout = options.timeout || CLI_TIMEOUT_MS;
  if (bundled) {
    return execProcess(bundled, ["ai-bridge", ...args], { timeout, options });
  }
  const candidates = pythonInvocations();
  return tryCandidates(candidates, ["-m", "greynoc_homeguard.ai_bridge", ...args], { timeout, options });
}

function tryCandidates(candidates, args, { timeout, options }) {
  return new Promise((resolve, reject) => {
    const errors = [];
    function attempt(index) {
      const py = candidates[index];
      if (!py) {
        reject(new Error(`Could not start Python. Tried: ${errors.join(" | ") || "no candidates"}`));
        return;
      }
      execProcess(py.command, [...py.prefix, ...args], { timeout, options })
        .then(resolve)
        .catch((err) => {
          errors.push(`${py.command}: ${err.message}`);
          attempt(index + 1);
        });
    }
    attempt(0);
  });
}

function execProcess(command, args, { timeout, options }) {
  return new Promise((resolve, reject) => {
    const env = { ...process.env };
    if (!app.isPackaged) {
      env.PYTHONPATH = [path.join(repoRoot(), "src"), env.PYTHONPATH || ""]
        .filter(Boolean)
        .join(path.delimiter);
    }
    const child = spawn(command, args, {
      cwd: repoRoot(),
      env,
      windowsHide: true,
    });
    let stdout = "";
    let stderr = "";
    const killTimer = setTimeout(() => {
      try {
        child.kill();
      } catch (_) {
        /* noop */
      }
      reject(new Error(`AI bridge command timed out after ${timeout}ms`));
    }, timeout);
    child.stdout.on("data", (chunk) => {
      stdout += chunk.toString();
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk.toString();
    });
    child.on("error", (err) => {
      clearTimeout(killTimer);
      reject(err);
    });
    child.on("close", (code) => {
      clearTimeout(killTimer);
      if (code === 0) {
        resolve({ code, stdout, stderr });
        return;
      }
      const message = (stderr || stdout || `ai_bridge exited with code ${code}`).trim();
      reject(new Error(message));
    });
    if (options && options.stdin) {
      try {
        child.stdin.write(options.stdin);
      } finally {
        child.stdin.end();
      }
    }
  });
}

function parseJson(stdout, fallback = null) {
  try {
    return JSON.parse(stdout);
  } catch (_) {
    return fallback;
  }
}

function maskEnvName(name) {
  if (!name) return "";
  return String(name).trim().toUpperCase();
}

function isSetEnv(name) {
  if (!name) return false;
  const value = process.env[name];
  return typeof value === "string" && value.length > 0;
}

function registerAiBridgeIpc() {
  ipcMain.handle("homeguard:ai-status", async () => {
    try {
      const result = await runAiBridge(["status", "--json"]);
      const payload = parseJson(result.stdout, {});
      payload.api_key_present = isSetEnv(payload.api_key_env);
      return { ok: true, settings: payload };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });

  ipcMain.handle("homeguard:ai-sterile", async () => {
    try {
      const result = await runAiBridge(["sterile", "--json"]);
      return { ok: true, settings: parseJson(result.stdout, {}) };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });

  ipcMain.handle("homeguard:ai-configure", async (_event, payload = {}) => {
    const provider = String(payload.provider || "").trim().toLowerCase();
    if (!provider) {
      return { ok: false, message: "Provider is required." };
    }
    const args = ["configure", provider, "--json"];
    const model = String(payload.model || "").trim();
    if (model) {
      args.push("--model", model);
    }
    const apiKeyEnv = maskEnvName(payload.api_key_env);
    if (apiKeyEnv) {
      args.push("--api-key-env", apiKeyEnv);
    }
    const endpoint = String(payload.endpoint || "").trim();
    if (endpoint) {
      args.push("--endpoint", endpoint);
    }
    const shareLevel = String(payload.share_level || "minimal").trim().toLowerCase();
    if (["minimal", "standard", "full"].includes(shareLevel)) {
      args.push("--share-level", shareLevel);
    }
    args.push("--tools", payload.use_engine_tools === false ? "off" : "on");
    args.push("--traffic", payload.use_traffic_context === true ? "on" : "off");
    args.push("--memory", payload.use_memory_context === false ? "off" : "on");
    try {
      const result = await runAiBridge(args);
      const settings = parseJson(result.stdout, {});
      settings.api_key_present = isSetEnv(settings.api_key_env);
      return { ok: true, settings };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });

  ipcMain.handle("homeguard:ai-chat", async (_event, payload = {}) => {
    const message = String(payload.message || "").trim();
    if (!message) {
      return { ok: false, message: "Empty prompt." };
    }
    const history = Array.isArray(payload.history)
      ? payload.history
          .map((entry) => ({
            role: entry && entry.role === "assistant" ? "assistant" : "user",
            content: String((entry && entry.content) || ""),
          }))
          .filter((entry) => entry.content.trim())
      : [];
    const stdin = JSON.stringify({ message, history, include_traffic: Boolean(payload.include_traffic) });
    try {
      const result = await runAiBridge(["chat-ipc"], { timeout: CHAT_TIMEOUT_MS, options: { stdin } });
      const response = parseJson(result.stdout, null);
      if (!response) {
        return { ok: false, message: "AI bridge returned no JSON." };
      }
      return { ok: Boolean(response.ok || response.sterile), response };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });

  ipcMain.handle("homeguard:ai-memory-show", async () => {
    try {
      const result = await runAiBridge(["memory", "show"]);
      return { ok: true, memory: parseJson(result.stdout, {}) };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });

  ipcMain.handle("homeguard:ai-memory-add", async (_event, payload = {}) => {
    const text = String(payload.text || "").trim();
    if (!text) {
      return { ok: false, message: "Note text is required." };
    }
    const args = ["memory", "add", text];
    const tags = Array.isArray(payload.tags) ? payload.tags : [];
    for (const tag of tags) {
      const cleanTag = String(tag || "").trim();
      if (cleanTag) {
        args.push("--tag", cleanTag);
      }
    }
    try {
      const result = await runAiBridge(args);
      return { ok: true, note: parseJson(result.stdout, {}) };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });

  ipcMain.handle("homeguard:ai-memory-clear", async () => {
    try {
      await runAiBridge(["memory", "clear"]);
      return { ok: true };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });

  ipcMain.handle("homeguard:ai-traffic", async () => {
    try {
      const result = await runAiBridge(["traffic", "--json"]);
      return { ok: true, traffic: parseJson(result.stdout, {}) };
    } catch (err) {
      return { ok: false, message: String(err.message || err) };
    }
  });
}

module.exports = { registerAiBridgeIpc };

#!/usr/bin/env node
"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..");
const useColor = process.stdout.isTTY && !process.env.NO_COLOR && process.env.TERM !== "dumb";

function paint(code, text) {
  return useColor ? `\x1b[${code}m${text}\x1b[0m` : text;
}

const cyan = (text) => paint("36", text);
const brightCyan = (text) => paint("96", text);
const bold = (text) => paint("1", text);
const dim = (text) => paint("2", text);

function commandBase() {
  if (process.env.GNHL_LAUNCHER === "repo") {
    return process.platform === "win32" ? ".\\GNHL" : "./GNHL";
  }
  if (process.env.npm_lifecycle_event === "cli") {
    return "npm run cli --";
  }
  return "GNHL";
}

function renderSplash() {
  const base = commandBase();
  const lines = [
    "",
    `       ${cyan("/\\")}          ${brightCyan("HOME GUARD")}`,
    `      ${cyan("/  \\")}        ${cyan("GNHL Direct App CLI")}`,
    `     ${cyan("/ () \\")}       ${cyan("Network Review Ready")}`,
    `    ${cyan("/______\\")}`,
    bold("GNHL command center"),
    dim("Home network inventory and security indicator review from your terminal."),
    "",
    brightCyan("[Start Here]"),
    `  scan         ${dim(`${base} --scan --active`)}`,
    `  status       ${dim(`${base} --status`)}`,
    `  devices      ${dim(`${base} --devices list`)}`,
    `  dashboard    ${dim(`${base} --dashboard --report <report.json>`)}`,
    "",
    brightCyan("[All commands]"),
    "  scan, analyze, update-definitions, import-definitions,",
    "  definitions-status, custom-rules, dashboard, gui, tray,",
    "  history, schedule, devices",
    "",
    brightCyan("[Direct invocation]"),
    `  ${dim("GNHL <command-or-app-option> [options]")}`,
    `  ${dim("python -m greynoc_homeguard <command> [options]")}`,
    "",
    `Run ${bold(`\`${base} --help\``)} for every command and option.`,
    "",
  ];
  return lines.join("\n");
}

function pythonInvocations() {
  const candidates = [];
  const envPython = process.env.HOMEGUARD_PYTHON || process.env.PYTHON || process.env.PYTHON_EXE;
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

function runHomeGuard(args) {
  const candidates = pythonInvocations();
  const errors = [];
  return new Promise((resolve, reject) => {
    function attempt(index) {
      const py = candidates[index];
      if (!py) {
        reject(new Error(`Could not start Python 3.10+. Tried: ${errors.join(" | ")}`));
        return;
      }
      const launcher = process.env.GNHL_LAUNCHER || (process.env.npm_lifecycle_event === "cli" ? "npm" : "");
      const child = spawn(py.command, [...py.prefix, "-B", "-m", "greynoc_homeguard", ...args], {
        cwd: repoRoot,
        stdio: "inherit",
        env: {
          ...process.env,
          PYTHONPATH: [path.join(repoRoot, "src"), process.env.PYTHONPATH || ""]
            .filter(Boolean)
            .join(path.delimiter),
          GNHL_LAUNCHER: launcher,
        },
        windowsHide: true,
      });
      child.on("error", (error) => {
        errors.push(`${py.command}: ${error.message}`);
        attempt(index + 1);
      });
      child.on("close", (code) => {
        resolve(typeof code === "number" ? code : 1);
      });
    }
    attempt(0);
  });
}

async function main() {
  const args = process.argv.slice(2);
  if (args.length === 0) {
    process.stdout.write(renderSplash());
    return;
  }
  const code = await runHomeGuard(args);
  process.exit(code);
}

main().catch((error) => {
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});

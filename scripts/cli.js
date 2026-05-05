#!/usr/bin/env node
"use strict";

// HomeGuard Node CLI splash. When run with no arguments it prints a banner
// listing the supported HomeGuard subcommands. Any positional arguments are
// forwarded to `python -m greynoc_homeguard ...`, which is the actual CLI
// implementation in src/greynoc_homeguard/cli.py.

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const repoRoot = path.resolve(__dirname, "..");

const useColor =
  process.stdout.isTTY &&
  !process.env.NO_COLOR &&
  process.env.TERM !== "dumb";

function paint(code, text) {
  return useColor ? `\x1b[${code}m${text}\x1b[0m` : text;
}

const cyan = (text) => paint("36", text);
const brightCyan = (text) => paint("96", text);
const bold = (text) => paint("1", text);
const dim = (text) => paint("2", text);

function renderSplash() {
  const lines = [
    "",
    `       ${cyan("/\\")}          ${brightCyan("HOME GUARD")}`,
    `      ${cyan("/  \\")}        ${cyan("Network Protection CLI")}`,
    `     ${cyan("/ () \\")}       ${cyan("All-Seeing Home Sentinel")}`,
    `    ${cyan("/______\\")}`,
    bold("Home Guard command center"),
    dim("Consumer-friendly network protection from your terminal."),
    "",
    brightCyan("[Start Here]"),
    `  scan         ${dim("npm run cli -- scan --active")}`,
    `  status       ${dim("npm run cli -- definitions-status")}`,
    `  devices      ${dim("npm run cli -- devices list")}`,
    `  dashboard    ${dim("npm run cli -- dashboard --report <report.json>")}`,
    "",
    brightCyan("[All commands]"),
    `  scan, analyze, update-definitions, definitions-status,`,
    `  dashboard, gui, tray, history, schedule, devices`,
    "",
    brightCyan("[Direct invocation]"),
    `  ${dim("homeguard <command> [options]")}`,
    `  ${dim("python -m greynoc_homeguard <command> [options]")}`,
    "",
    `Run ${bold("`npm run cli -- --help`")} for every command and option.`,
    "",
  ];
  return lines.join("\n");
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

function runHomeGuard(args) {
  const candidates = pythonInvocations();
  const errors = [];
  return new Promise((resolve, reject) => {
    function attempt(index) {
      const py = candidates[index];
      if (!py) {
        reject(
          new Error(
            `Could not start Python. Install Python 3.10+ and retry. Tried: ${errors.join(
              " | "
            )}`
          )
        );
        return;
      }
      const child = spawn(
        py.command,
        [...py.prefix, "-m", "greynoc_homeguard", ...args],
        {
          cwd: repoRoot,
          stdio: "inherit",
          env: {
            ...process.env,
            PYTHONPATH: [
              path.join(repoRoot, "src"),
              process.env.PYTHONPATH || "",
            ]
              .filter(Boolean)
              .join(path.delimiter),
          },
          windowsHide: true,
        }
      );
      child.on("error", (error) => {
        errors.push(`${py.command}: ${error.message}`);
        attempt(index + 1);
      });
      child.on("close", (code) => {
        resolve(typeof code === "number" ? code : 0);
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

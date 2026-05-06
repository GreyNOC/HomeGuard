#!/usr/bin/env node

const { spawnSync } = require("child_process");
const path = require("path");

const root = path.resolve(__dirname, "..");
const src = path.join(root, "src");
const python = process.env.PYTHON || process.env.PYTHON_EXE || "python";
const separator = process.platform === "win32" ? ";" : ":";
const launcher =
  process.env.GNHL_LAUNCHER ||
  (process.env.npm_lifecycle_event === "cli" ? "npm" : "");
const env = {
  ...process.env,
  PYTHONPATH: process.env.PYTHONPATH ? `${src}${separator}${process.env.PYTHONPATH}` : src,
  GNHL_LAUNCHER: launcher,
};

const result = spawnSync(
  python,
  ["-B", "-m", "greynoc_homeguard", ...process.argv.slice(2)],
  {
    cwd: root,
    env,
    stdio: "inherit",
    windowsHide: false,
  },
);

if (result.error) {
  console.error(`GNHL launcher failed: ${result.error.message}`);
  process.exit(1);
}

process.exit(typeof result.status === "number" ? result.status : 1);

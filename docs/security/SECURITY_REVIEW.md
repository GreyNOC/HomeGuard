# HomeGuard Security Review

Review date: 2026-05-03
Last hardening update: 2026-05-13

## Scope Reviewed

- Python scan, detection, definitions, report, history, logging, and firewall helpers.
- Electron main/preload/renderer IPC boundary.
- Windows build/signing scripts.
- Report outputs: HTML, PDF, JSON, Markdown, CSV, and manifest.
- Existing CI test workflow.

## Findings Fixed In V1 Candidate

- Reports could include internal app-data paths through scan metadata such as `baseline_path`. Fixed by removing the path and exporting share-safe report data.
- Definition status and command output could surface absolute paths in Electron. Fixed by redacting renderer-facing output.
- Logs could persist local paths or secret-shaped strings. Fixed with a redacting logging formatter and log display redaction.
- Reports exposed full MAC addresses. Fixed by masking them as device IDs in exported reports and normal UI tables.
- Electron `open-path` and `show-item` accepted arbitrary renderer-supplied paths. Fixed by limiting open/show operations to the HomeGuard app-data area.
- Save-as accepted any renderer-supplied HTML source path. Fixed by requiring the source report to be inside HomeGuard app data.
- Admin relaunch used `ExecutionPolicy Bypass`. Removed the bypass flag; admin relaunch remains explicit and user-triggered.
- Release signing only covered the PyInstaller executable and did not enforce a signed installer. Added signed installer build, signing, verification, and release gate scripts.

## Additional Hardening Applied After Review

- Electron release dependencies are pinned to exact versions in `package.json` to reduce build drift between tested and released artifacts.
- Dashboard LAN mode now creates a random per-session token and rejects requests without the token.
- Dashboard responses now include `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy: no-referrer`.
- Dashboard download links include the session token when LAN mode is intentionally enabled.

## Back Door / Remote Control Review

No hidden remote access, telemetry, webhook, back door, or undocumented command channel was found in the application code reviewed.

Network calls are limited to user-triggered security definition updates from CISA KEV and NVD CVE sources. No analytics or cloud telemetry was added.

## Human Review Required

- Validate the real GreyNOC code-signing certificate chain and publisher name before public release.
- Run the signed installer build on a clean Windows release machine.
- Review `npm audit` output at release time because dependency advisories change.
- Confirm the final installed app launches from `Program Files` without exposing build paths in Windows metadata or installer logs.
- Generate and commit a package lockfile from a trusted release workstation using `npm install --package-lock-only` or regenerate the full dependency tree with `npm ci` once a lockfile exists.
- Add CI checks for `npm audit`, `pip-audit`, and IPC path traversal tests before public release.

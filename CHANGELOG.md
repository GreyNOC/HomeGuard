# Changelog

## 1.0.4 - PowerSploit Resistance Release

- Added defensive PowerSploit-style endpoint artifact signatures for process command lines, downloaded scripts, startup entries, and sampled memory strings.
- Added a passive Windows privilege-escalation audit for common hardening risks such as AlwaysInstallElevated, AutoLogon, weak service paths, scheduled task paths, PowerShell logging, Defender posture, and credential exposure indicators.
- Added report-aware assistant answers for PowerSploit resistance, credential theft, privilege escalation, persistence, service/DLL hijack risk, and hardening priority questions.
- Expanded smoke and unit coverage for endpoint abuse signatures, passive audit safety, redaction, and report assistant wiring.
- Documented that HomeGuard detects and reports defensive indicators only; it does not run offensive tools, generate payloads, bypass controls, dump credentials, or exploit misconfigurations.

## 1.0.3 - V1.0 Security Release

- Removed PowerShell `ExecutionPolicy Bypass` from the endpoint process inventory scanner.
- Made the full Electron dependency audit a blocking GitHub Actions gate.
- Updated release commands and package metadata for the signed V1.0.3 release line.
- Promoted package metadata from beta to production/stable for V1.0 release readiness.

## 1.0.0 - V1 Release Candidate

- Promoted HomeGuard to V1 release-candidate versioning.
- Added shared privacy redaction for reports, logs, command output, and Electron display text.
- Masked full MAC addresses in generated reports and normal UI tables.
- Removed report metadata paths from generated report exports.
- Hardened Electron file-open IPC to the HomeGuard app-data area.
- Removed PowerShell `ExecutionPolicy Bypass` from the admin relaunch action.
- Added signed Windows installer tooling with Inno Setup, Authenticode signing, timestamping, and signature verification.
- Added a strict V1 release gate for tests, dependency checks, secret scans, privacy checks, UI placeholder checks, and installer signature verification.
- Added practical V1 release, privacy, security, and build/signing documentation.

## 0.4.0

- Added the dedicated `HomeGuardDetectionEngine` rule evaluator used by both GUI and CLI flows.
- Added detection-engine metadata and telemetry to report output.
- Rebranded the desktop GUI with a HomeGuard header.
- Added antivirus-style status cards for Network Protection, Device Trust, and Security Updates.
- Added report HTML status cards and detection-engine details.

## 0.3.0

- Removed all trial-only user flows from the GUI and CLI.
- Removed bundled test inventory and generated showcase reports from the release package.
- Added HomeGuard PDF report export.
- Added downloadable HTML report controls.
- Added report download links for PDF, JSON, and device CSV.
- Updated the local dashboard to serve report assets for downloading.
- Updated the PyInstaller build script to package the production app only.

## 0.2.0

- Added antivirus-style Protection Center to the desktop GUI.
- Added security definition updater for CISA KEV and recent NVD CVEs.
- Added local `security_definitions.json` storage in app data.
- Added automatic known-device database in app data.
- Removed baseline folder/file selection from the GUI.
- Added CVE/known-exploited-vulnerability patch-priority hints.
- Added router, camera, NAS, and Windows remote-access security-definition hints.
- Added CLI commands: `update-definitions` and `definitions-status`.
- Added Windows `update_definitions.bat`.
- Expanded tests for custom definitions and KEV hints.

## 0.1.1

- Added desktop GUI (`homeguard gui`).
- Added Windows one-click launcher (`run.bat`).
- Added Windows EXE compiler script (`compile_exe.bat`).
- Added PyInstaller helper (`scripts/build_exe.py`).

## 0.1.0

- Initial HomeGuard repo.
- Safe local discovery, consumer risk scoring, reports, dashboard, and tests.

# Changelog

## 1.2.0 - Active Discovery Release

- Promoted the vendored saturn `_noc_core` multi-vector discovery engine to the default scan path. `run_full_scan` now discovers hosts through the engine — ARP, neighbor cache, mDNS/SSDP, and router DHCP, plus ICMP/TCP/ARP probes when Active scan is enabled — for both passive and active scans. This supersedes the conservative `discover_lan_hosts()` path that 1.1.0 deliberately kept as the default.
- Wired the Active scan and "Probe all bounded hosts" controls end to end: the renderer toggles flow through Electron IPC and the CLI `--active` / `--probe-all` flags into `run_full_scan` and the discovery engine.
- Added `discover_lan_hosts_noc_core()` to `greynoc_homeguard.network` — runs the engine against every detected private IPv4 interface and merges the rich `DiscoveryDevice` results into HomeGuard `Device` objects.
- Extended `discover_local_network()` with a `tcp_ports` argument that overrides the engine's built-in inventory port set, so active TCP probes check exactly the risky ports the detection engine knows about, sourced from the live security definitions.
- Tagged scan reports with `scan_metadata.discovery_engine = "noc_core"`.
- Sharpened the Electron UI: squared every `border-radius` across panels, cards, buttons, inputs, chat surfaces, the scan-orb frame, and status badges for a crisp, technical look. Only the scan orb's concentric radar rings remain circular.
- Added repository CODEOWNERS rules and a security reporting policy, and updated the contribution rules.
- Added support for unsigned installer builds and excluded tooling directories from the dependency audit.

## 1.1.0 - Discovery Engine Release

- Vendored the GreyNOC saturn `noc_core` multi-vector discovery engine (discovery.py, network_discovery.py, network_sensor.py, map_accuracy.py) into a private `_noc_core` subpackage under `src/greynoc_homeguard/`. Pure stdlib (optional psutil), no new HomeGuard runtime dependencies.
- Added `discover_local_network()` to `greynoc_homeguard.network` — a HomeGuard-safe wrapper around the saturn engine with passive_only defaults, no public/large-subnet probing, and no radio/bluetooth scanning. The engine's internal `target.is_private` / `target.is_loopback` / `target.is_link_local` gates remain in force.
- Re-exported `DiscoveryDevice`, `DiscoveryOptions`, `DiscoveryResult`, `guess_device_type`, `recompute_confidence`, `is_randomized_mac`, `source_count`, and `distinct_method_categories` from `greynoc_homeguard.network` so callers can opt into the richer engine surface alongside the existing scan flow.
- Added `discovery_device_to_device()` adapter that normalizes saturn-shaped device dicts into HomeGuard's `Device` model, including MAC normalization and the home-IoT-focused `COMMON_VENDOR_PREFIXES` OUI lookup.
- Kept the existing conservative `discover_lan_hosts()` scan path untouched — the saturn engine is an additive capability, not a replacement.
- Replaced the CSS pseudo-element scan orb with a real Three.js WebGL scene: faceted icosahedron core with shifting emissive color, additive wireframe lattice, multi-ring synapse particles, and synapse-flash line streaks. Idle vs. active is smoothed via a single intensity value driving rotation speed, glow, and synapse flash rate. Vendored Three.js r149 UMD locally to satisfy the renderer's strict script-src CSP.
- Tracked the in-flight requestAnimationFrame id on the 3D scan orb so a paused (document-hidden) callback can never stack with a freshly scheduled one on restore, preventing doubled render loops on hide/show cycles.
- Dropped a stale Electron smoke assertion that contradicted the IPC dedup fix in 39b8ef9.
- Added a `${{ secrets.X }}` / `${{ env.X }}` / `${{ inputs.X }}` carve-out to `security_release_gate.py` so the secret detector no longer flags correct GitHub Actions context references in workflows.

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

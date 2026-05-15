# HomeGuard

HomeGuard is a home network security indicator scanner, inventory, and risk-review tool. It scans local devices, checks for risky services, watches for new devices, updates security definitions, compares devices against CVE and known-exploited-vulnerability hints, and explains everything in plain English.

This repo is built as a bounded local discovery and review tool with detection rules, severity/confidence scoring, alert explanations, and report output.

## What it does

- Desktop GUI for non-technical users.
- One-click Windows launcher with `run.bat`.
- Windows EXE compiler script with `compile_exe.bat`.
- System tray background mode with scan/update alerts while HomeGuard keeps running.
- Optional one-click definition updater with `update_definitions.bat`.
- Protection status dashboard in the GUI with three large status cards: Network Protection, Device Trust, and Security Updates.
- Automatic known-device baseline stored in app data; no baseline folder picker.
- Security definition updates from:
  - CISA Known Exploited Vulnerabilities catalog
  - NVD CVE API recent CVE feed
- Passive discovery from ARP and neighbor tables.
- Optional active ping and TCP checks, guarded to private/local networks only.
- Consumer-oriented risk findings:
  - newly seen device
  - risky open services like Telnet, SMB, RDP, VNC, FTP
  - many open services
  - missing MAC or unknown identity
  - router, camera, NAS, and remote-access hardening hints
  - CVE/known-exploited-vulnerability patch-priority hints
- Plain-English explanations and recommended actions.
- Markdown, HTML, PDF, JSON, CSV, and SHA-256 manifest output.
- Download buttons in the HTML report for HTML, PDF, JSON, and CSV.
- HomeGuard HTML/PDF reports with executive summary, protection status, findings, next steps, and device inventory.
- Local browser dashboard using Python's standard library HTTP server.
- Skippable first-run setup guide for definitions, scan depth, first scan, and device trust review.
- Possible-intrusion findings for unknown devices with remote-access exposure or clustered admin services.
- Active scan checks a bounded set of private/local ports for remote-control, unsafe sharing, camera, debug bridge, and other unusual-service indicators.
- One-click fix option for local findings: HomeGuard can close or reopen inbound TCP ports on the computer running the app using reversible Windows Firewall rules.
- Unit tests.


## Quality / detection engine

HomeGuard uses `HomeGuardDetectionEngine` for the consumer findings. The engine loads rules from built-in logic and security definitions, evaluates each device, emits severity/confidence/risk-priority findings, and records engine metadata in every report. The GUI and CLI both call the same `HomeGuardEngine` report orchestrator, so scans, imports, HTML reports, PDF reports, and the desktop app use the same detection path.

## Safety model

HomeGuard is designed for networks you own or are authorized to assess.

By default it uses passive discovery. Active probing is opt-in, limited to private/local networks, and bounded by host count, ports, and timeouts. It does not exploit, brute-force, bypass authentication, capture passwords, or alter devices.

CVE, KEV, possible-intrusion, unusual-service, and endpoint findings are indicators for review, not proof of compromise. A home network scan usually cannot prove the exact firmware/software version running on a device, and it is not a replacement for full endpoint protection on the device itself.

HomeGuard can only close/reopen ports on the local computer where it is running. For another device on the network, it will guide you to disable the service on that device, block it in the router, or quarantine it in HomeGuard.

## Windows quick start

Double-click:

```text
run.bat
```

That script creates a local virtual environment, installs HomeGuard in editable mode with tray support, and launches the desktop GUI.

Inside the GUI you can:

- update security definitions
- run a passive home scan
- enable an optional bounded active scan
- view security indicators and devices in tables
- open the generated HTML report
- open the generated PDF report
- save a copy of the HTML report
- open the report folder
- minimize or close to the system tray and keep background monitoring active

## Electron frontend

For the Electron desktop frontend, double-click:

```text
run_electron.bat
```

The Electron app uses the existing HomeGuard Python engine through local IPC-backed
CLI calls. It can run scans, update definitions, show definition status, list scan
history, and preview the generated HTML report inside the desktop window.

## Update security definitions

From the GUI, click:

```text
Update Definitions
```

From Windows, double-click:

```text
update_definitions.bat
```

From CLI:

```bash
GNHL --status
GNHL --update-definitions --nvd-days 30
GNHL --definitions-status
```

Definition data is stored automatically in the user's app-data folder.

Windows:

```text
%LOCALAPPDATA%\GreyNOC\HomeGuard\definitions\security_definitions.json
%LOCALAPPDATA%\GreyNOC\HomeGuard\known_devices.json
```

HomeGuard includes this NVD notice:

```text
This product uses data from the NVD API but is not endorsed or certified by the NVD.
```

## Build a Signed Windows V1 Installer

V1 customer releases are signed setup installers. Configure a GreyNOC code-signing certificate through secure local storage or CI/CD secrets, then run:

```powershell
powershell -NoProfile -File scripts\build_windows_installer.ps1 -Version 1.0.3
```

Expected artifact:

```text
dist\installer\HomeGuard-Setup-v1.0.3.exe
```

Verify before publishing:

```powershell
powershell -NoProfile -File scripts\verify_windows_signature.ps1 -Path dist\installer\HomeGuard-Setup-v1.0.3.exe -ExpectedPublisher GreyNOC
```

See `docs/release/BUILD_AND_SIGNING.md` and `docs/release/RELEASE_CHECKLIST.md` for the full release gate.

## Build the Windows Electron EXE

Double-click:

```text
compile_exe.bat
```

The compiler script creates `.venv-build`, installs PyInstaller and Electron
Builder dependencies, bumps the patch version, bundles the HomeGuard Python
engine as an Electron backend helper, embeds GreyNOC publisher metadata, and
builds:

```text
dist\electron\win-unpacked\HomeGuard.exe
```

To sign the Windows build as GreyNOC, configure one of these before running
`compile_exe.bat`:

```text
HOMEGUARD_SIGN_CERT_PATH=C:\path\to\GreyNOC-CodeSigning.pfx
HOMEGUARD_SIGN_CERT_PASSWORD=your-certificate-password
```

or use a certificate already in the Windows certificate store:

```text
HOMEGUARD_SIGN_CERT_SHA1=certificate-thumbprint
```

Set `HOMEGUARD_REQUIRE_SIGNING=1` to make the compiler fail unless signing and
verification both complete. Trusted Publisher status comes from the code-signing
certificate subject, so the certificate must be issued to GreyNOC.

You can also run the underlying Python build script directly:

```bash
python scripts/build_electron.py
```

## Build the Android App

The Android app is under `mobile/android/` and builds with Kivy + Buildozer.
From Linux/macOS, or from Windows through WSL:

```bash
bash scripts/compile_android.sh debug
```

On Windows, use the wrapper:

```text
compile_android.bat
```

Artifacts are copied into:

```text
dist/android/
```

Release and Play Store bundle modes are also available:

```bash
bash scripts/compile_android.sh release
bash scripts/compile_android.sh aab
```

## Install from source

```bash
python -m venv .venv
. .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install -e .
```

For system tray support when installing manually:

```bash
python -m pip install -e ".[tray]"
```

## Launch the desktop GUI manually

```bash
GNHL --gui
```

or:

```bash
python -m greynoc_homeguard gui
```

## Scan your home network from CLI

After installing from source, use the normal app command:

```bash
GNHL --status
GNHL --scan --active
```

From this repository checkout without installing first, use the repo-local launcher:

```powershell
.\GNHL --status
.\GNHL --scan --active
```

Command-center overview:

```bash
GNHL --status
```

Passive only:

```bash
GNHL --scan
```

Optional active scan of private/local network addresses only:

```bash
GNHL --scan --active
```

The older subcommand form still works too, for example `GNHL scan --active`.

Reports are written to the app-data reports folder by default. A scan generates:

```text
report.html
report.pdf
report.json
findings.json
devices.csv
report.md
manifest.sha256
```

## Run browser dashboard

After a scan, run:

```bash
GNHL --dashboard --report out/scan/report.json --port 8765
```

Open `http://127.0.0.1:8765` in your browser.

The dashboard serves the report and supports downloads for the PDF, JSON, and CSV files when they exist beside `report.json`.

## Analyze an existing device JSON file

```bash
GNHL --analyze --input devices.json --out out/imported
```

The input can be either:

```json
[
  {"ip": "192.168.1.10", "mac_address": "00:11:22:33:44:55", "hostname": "laptop", "open_ports": [22]}
]
```

or:

```json
{"devices": [ ... ]}
```

## Repo layout

```text
run.bat                         # Windows one-click GUI launcher
compile_exe.bat                 # Windows EXE compiler script
update_definitions.bat          # Windows one-click definition updater
scripts/build_exe.py            # PyInstaller build helper
scripts/compile_android.sh      # Linux/macOS Android build helper
scripts/compile_macos.sh        # macOS app build helper
src/greynoc_homeguard/
  cli.py                        # command-line interface
  gui.py                        # desktop GUI / Protection Center
  network.py                    # safe local network discovery
  engine.py                     # report orchestrator that calls the detection engine
  detection.py                  # rule-driven HomeGuard detection engine
  definitions.py                # security definition updater and matcher
  reports.py                    # JSON/Markdown/HTML/PDF/CSV exporters
  dashboard.py                  # local web UI server
  baseline.py                   # automatic known-device tracking
  paths.py                      # app-data storage paths
  models.py                     # dataclasses
docs/
  SECURITY.md
  SECURITY_DEFINITIONS.md
  PRODUCTION_READINESS.md
  release/
    BUILD_AND_SIGNING.md
    RELEASE_CHECKLIST.md
  security/
    PRIVACY_REVIEW.md
    SECURITY_REVIEW.md
tests/
  test_homeguard.py             # unit tests
```

## GitHub push checklist

```bash
git init
git add .
git commit -m "HomeGuard"
git branch -M main
git remote add origin https://github.com/GreyNOC/HomeGuard.git
git push -u origin main
```

## Important notes

- HomeGuard is not a replacement for a full EDR, firewall, or professional incident response tool.
- Findings are indicators for home users, not proof of compromise.

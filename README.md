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
- Optional user-owned AI bridge that can route bounded HomeGuard signals and chat messages to the user's preferred AI API, or stay fully sterile/offline by default.
- Markdown, HTML, PDF, JSON, CSV, and SHA-256 manifest output.
- Download buttons in the HTML report for HTML, PDF, JSON, and CSV.
- HomeGuard HTML/PDF reports with executive summary, protection status, findings, next steps, and device inventory.
- Local browser dashboard using Python's standard library HTTP server.
- Skippable first-run setup guide for definitions, scan depth, first scan, and device trust review.
- Possible-intrusion findings for unknown devices with remote-access exposure or clustered admin services.
- Active scan checks a bounded set of private/local ports for remote-control, unsafe sharing, camera, debug bridge, and other unusual-service indicators.
- One-click fix option for local findings: HomeGuard can close or reopen inbound TCP ports on the computer running the app using reversible Windows Firewall rules.
- Defensive PowerSploit resistance checks: static endpoint artifact detection plus passive Windows privilege-escalation hardening review.
- On-demand antivirus file/folder scanning of any path, layering exact known-bad SHA-256 hash matches, embedded content signatures, deceptive double-extension detection, and a packed-executable entropy heuristic.
- Real malware remediation: a local quarantine vault that neutralizes a flagged file (per-entry XOR so the stored copy can't run or re-trigger scanners), removes the live original only after a recoverable copy is verified on disk, and supports full restore and permanent delete.
- Real-time protection: a background watcher that scans files as they appear or change in watched folders and auto-quarantines high-confidence threats on write.
- Cryptographically-signed cloud hash feeds: the known-bad hash set can be refreshed from a remote feed whose RSA signature is verified against a bundled public key before anything is trusted (fails closed on tamper).
- Bring-your-own threat intelligence: known-bad file hashes ship in the security definitions and can be extended through `custom_rules.json`.
- Unit tests.


## Quality / detection engine

HomeGuard uses `HomeGuardDetectionEngine` for the consumer findings. The engine loads rules from built-in logic and security definitions, evaluates each device, emits severity/confidence/risk-priority findings, and records engine metadata in every report. The GUI and CLI both call the same `HomeGuardEngine` report orchestrator, so scans, imports, HTML reports, PDF reports, and the desktop app use the same detection path.

## Optional AI bridge

HomeGuard is sterile by default: it does not send scan signals, reports, device inventory, or chat messages to an AI provider unless the user explicitly enables one.

Users can choose OpenAI, Anthropic, OpenRouter, Gemini, or a custom OpenAI-compatible endpoint. API keys stay in environment variables; HomeGuard only stores provider settings and the name of the key variable. The configuration UI is built into the desktop app under **AI Settings** in the sidebar — open it to pick a provider, paste a model name, set the env-var that holds your key, and tune share-level and feature toggles.

When a provider is configured, the in-app chat routes through your chosen LLM and the assistant can:

- **Use the engine via tool calls** — the model can read the latest scan, list devices, look up findings, scan a file or folder for malware (and quarantine high-confidence detections), list the quarantine vault, snapshot current network connections, and read/write the local AI memory on its own. Bounded to four tool iterations per turn.
- **Train on your network locally** — HomeGuard does not fine-tune cloud LLMs, but it persists a bounded local memory store (notes, device facts, recent scan-trend snapshots) and re-injects it into every chat. The assistant gets steadily smarter about *this* network without anything leaving the box.
- **See bounded current network traffic** — a connection-summary feed derived from `psutil`/`netstat` (no packet capture) can be attached to chats. External endpoints are hashed in `minimal` share level.

CLI:

```bash
python -m greynoc_homeguard.ai_bridge status
python -m greynoc_homeguard.ai_bridge sterile
python -m greynoc_homeguard.ai_bridge configure openai --model gpt-4.1-mini --share-level minimal
python -m greynoc_homeguard.ai_bridge explain --report path/to/report.json
python -m greynoc_homeguard.ai_bridge chat "What should I fix first?"
python -m greynoc_homeguard.ai_bridge memory show
python -m greynoc_homeguard.ai_bridge memory add "trust the camera on 192.168.1.42"
python -m greynoc_homeguard.ai_bridge traffic --json
```

See `docs/AI_BRIDGE.md` for provider setup, privacy levels, the engine tool list, and custom endpoint examples.

## Safety model

HomeGuard is designed for networks you own or are authorized to assess.

By default it uses passive discovery. Active probing is opt-in, limited to private/local networks, and bounded by host count, ports, and timeouts. It does not exploit, brute-force, bypass authentication, capture passwords, or alter devices.

CVE, KEV, possible-intrusion, unusual-service, and endpoint findings are indicators for review, not proof of compromise. A home network scan usually cannot prove the exact firmware/software version running on a device, and it is not a replacement for full endpoint protection on the device itself.

File quarantine is reversible by design. Auto-quarantine only fires on the highest-confidence detections (an exact known-bad hash or a critical signature at near-certain confidence); lower-confidence hints are reported, not removed. HomeGuard refuses to quarantine its own files and operating-system critical paths, and every quarantined file can be restored to its exact original bytes.

HomeGuard can only close/reopen ports on the local computer where it is running. For another device on the network, it will guide you to disable the service on that device, block it in the router, or quarantine it in HomeGuard.

PowerSploit resistance is detection, reporting, and hardening guidance only. HomeGuard does not run offensive tools, generate payloads, dump credentials, bypass security controls, or exploit Windows misconfigurations. See `docs/POWERSPOIT_RESISTANCE.md` for the passive checks and hardening checklist.

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

## Build a Signed Windows Installer

Customer releases are signed setup installers. Configure a GreyNOC
code-signing certificate through secure local storage or CI/CD secrets,
then run (the build script reads the version from `pyproject.toml`):

```powershell
powershell -NoProfile -File scripts\build_windows_installer.ps1
```

Expected artifact for the current release:

```text
dist\installer\HomeGuard-Setup-v1.5.0.exe
```

Verify before publishing:

```powershell
powershell -NoProfile -File scripts\verify_windows_signature.ps1 -Path dist\installer\HomeGuard-Setup-v1.5.0.exe -ExpectedPublisher GreyNOC
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

## Scan a file or folder for malware

HomeGuard can scan any path on demand, not just the browser Downloads folder.
Detections are layered highest-confidence first: exact known-bad SHA-256 hash,
embedded content signatures (EICAR, credential-theft tooling, loader cradles),
deceptive double extensions, and a packed-executable entropy hint.

```bash
GNHL --scan-file C:\Users\you\Downloads\setup.exe
GNHL --scan-folder C:\Users\you\Downloads
```

Add `--quarantine` to neutralize high-confidence detections (an exact hash
match, or a critical signature at near-certain confidence) into the local
quarantine vault. Lower-confidence hints are reported but left in place for you
to review:

```bash
GNHL --scan-file C:\Users\you\Downloads\setup.exe --quarantine
```

## Quarantine vault

Quarantine moves a flagged file into a protected vault, stored neutralized so
the copy can neither run nor re-trigger antivirus engines. The live original is
removed only after a recoverable copy is verified on disk, and every action is
reversible.

```bash
GNHL --quarantine list                 # show quarantined files
GNHL quarantine restore <id>           # put a file back (verifies its hash)
GNHL quarantine restore <id> --to D:\recovered\file.exe
GNHL quarantine delete <id>            # permanently destroy the vault copy
GNHL quarantine purge --yes            # permanently destroy all quarantined files
```

Entry ids accept a unique prefix, so `quarantine restore 1ccb5945` works.

The vault and its index live under the app-data folder:

```text
%LOCALAPPDATA%\GreyNOC\HomeGuard\quarantine\index.json
%LOCALAPPDATA%\GreyNOC\HomeGuard\quarantine\blobs\
```

### Bring your own hash intelligence

Add known-bad file hashes to `custom_rules.json` and HomeGuard will match them
during file scans:

```json
{
  "malware_hashes": [
    {"sha256": "<64-hex-sha256>", "name": "My IOC", "severity": "critical"}
  ]
}
```

Run `GNHL custom-rules init` to seed a starter file with an example entry.

## Real-time protection

The real-time watcher scans files for malware the moment they appear or change
in watched folders (Downloads by default) and auto-quarantines high-confidence
threats on write.

```bash
GNHL --watch                       # run protection in the foreground (Ctrl+C to stop)
GNHL watch --dir C:\Users\you\Downloads --dir D:\Incoming
GNHL watch --once                  # single pass (for cron / scripts)
GNHL watch --no-quarantine         # detect and report only
GNHL --watch --events              # show recent real-time detections
GNHL watch --enable                # persist real-time protection as on
```

When real-time protection is enabled in settings, the system-tray app starts
the watcher automatically and pops a notification each time a threat is caught.
It is a lightweight polling watcher (no kernel driver), with a "settle window"
so half-written downloads are not scanned mid-flight.

## Signed cloud hash feeds

The known-bad hash set can be refreshed from a remote feed. Feeds are
**cryptographically signed**: HomeGuard verifies an RSA-PKCS#1v1.5 / SHA-256
signature against a public key bundled in the binary before trusting a single
hash, and fails closed if the signature is missing, tampered, or signed by the
wrong key. The local definitions are never modified unless verification passes.

```bash
GNHL --update-hashes --url https://feeds.greynoc.example/hashes.json
GNHL update-hashes --file signed_hashes.json     # offline / air-gapped
```

A signed feed document is JSON with a base64 `data` payload and a base64
`signature` over those exact bytes:

```json
{
  "key_id": "greynoc-hashfeed-2026",
  "data": "<base64 of {\"feed_version\": \"...\", \"malware_hashes\": [ ... ]}>",
  "signature": "<base64 RSA-PKCS#1v1.5 SHA-256 signature over the data bytes>"
}
```

Feeds are signed offline with the matching private key, e.g.
`openssl dgst -sha256 -sign private.pem -out data.sig data.json`. The bundled
trust anchor in `signed_feed.py` is a development key; replace it with your
production public key before publishing feeds.

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
  ai_bridge.py                  # opt-in user AI routing / sterile mode
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
  AI_BRIDGE.md
  SECURITY.md
  SECURITY_DEFINITIONS.md
  POWERSPOIT_RESISTANCE.md
  PRODUCTION_READINESS.md
  release/
    BUILD_AND_SIGNING.md
    RELEASE_CHECKLIST.md
  security/
    PRIVACY_REVIEW.md
    SECURITY_REVIEW.md
tests/
  test_homeguard.py             # unit tests
  test_ai_bridge.py             # AI bridge sterile mode and redaction tests
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

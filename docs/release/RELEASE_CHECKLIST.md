# HomeGuard V1 Release Checklist

Release artifact: `HomeGuard-Setup-v1.0.0.exe`

## Required CI Gate

Before publishing a public installer, confirm the GitHub Actions workflow below passes on the release commit:

```text
Security Gates
```

The workflow must pass all required jobs:

- Python unit tests.
- `pip-audit` dependency review.
- HomeGuard release security preflight: `python scripts/security_release_gate.py`.
- Locked Node install with `npm ci`.
- `npm audit --audit-level=high`.
- Electron smoke test when present.

Do not publish from a commit where this workflow is failing, skipped, or disabled.

## Required Local Windows Release Gate

Run from a clean Windows release workstation after building the installer:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\release_gate.ps1 -InstallerPath dist\installer\HomeGuard-Setup-v1.0.0.exe -ExpectedPublisher GreyNOC
```

The release is not V1-ready unless all items pass:

- Python unit tests pass.
- Electron smoke test passes.
- Python dependency check passes.
- npm audit completes with no high/critical findings.
- Secret and personal-path scan passes.
- Report privacy checks pass.
- Placeholder UI scan passes.
- Installer exists at the expected V1 filename.
- Installer Authenticode signature is valid.
- Signer certificate subject contains `GreyNOC`.

## Manual Review Before Publishing

- Confirm no certificates, PFX/P12 files, passwords, private keys, API keys, tokens, or signing logs were added to the repo.
- Confirm generated reports do not contain `C:\Users\`, `/Users/`, `AppData`, environment variables, private keys, or tokens.
- Confirm the Electron UI shows report labels such as `Latest report saved locally`, not local filesystem paths.
- Confirm active scan remains opt-in and bounded to private/local networks.
- Confirm dashboard LAN mode requires explicit user action and displays a per-session tokenized URL only when intentionally enabled.
- Confirm endpoint scanning behavior is disclosed to the user before release builds are promoted.
- Confirm admin relaunch is user-triggered only.
- Confirm release notes match the artifact being shipped.
- Confirm offline/imported security definition bundles came from trusted GreyNOC release sources.

## Release Commands

Build signed installer:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\build_windows_installer.ps1 -Version 1.0.0
```

Verify signature:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\verify_windows_signature.ps1 -Path dist\installer\HomeGuard-Setup-v1.0.0.exe -ExpectedPublisher GreyNOC
```

Run local security preflight:

```powershell
python scripts\security_release_gate.py
```

Run tests:

```powershell
python -m unittest discover -s tests -v
```

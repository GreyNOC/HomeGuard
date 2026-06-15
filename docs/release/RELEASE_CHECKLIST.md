# HomeGuard Release Checklist

Release artifact: `HomeGuard-Setup-v<version>.exe`, where `<version>` is read
from `pyproject.toml` (currently `1.8.0`).

The build, signing, and release-gate scripts derive the version from
`pyproject.toml` when no `-Version` / `-InstallerPath` is passed, so the
commands below stay correct as the project version moves forward. Any explicit
version shown below (for example `vX.Y.Z`) is illustrative only; the current
project version is `1.8.0` (see `pyproject.toml`).

## Required CI Gate

Before publishing a public installer, confirm the GitHub Actions workflow below passes on the release commit:

```text
Security Gates
```

The workflow must pass all required jobs:

- Python unit tests (`pytest`).
- `pip-audit` dependency review.
- HomeGuard release security preflight: `python scripts/security_release_gate.py`.
- Locked Node install with `npm ci`.
- Production-only audit with `npm audit --omit=dev --audit-level=high`.
- Full Electron dependency audit with `npm audit --audit-level=high`.
- Electron smoke test (`npm run smoke --if-present`) after HomeGuard backend install.

Do not publish from a commit where this workflow is failing, skipped, or disabled.

## Required Local Windows Release Gate

Run from a clean Windows release workstation after building the installer.
The script reads the current project version from `pyproject.toml` and
resolves the installer path automatically:

```powershell
powershell -NoProfile -File scripts\release_gate.ps1
```

If you need to gate a specific artifact path, pass it explicitly:

```powershell
powershell -NoProfile -File scripts\release_gate.ps1 -InstallerPath dist\installer\HomeGuard-Setup-vX.Y.Z.exe -ExpectedPublisher GreyNOC
```

The release is not ready unless all items pass:

- Python unit tests pass.
- Electron smoke test passes.
- Python dependency check passes.
- npm audit completes with no high/critical findings.
- Secret and personal-path scan passes.
- Report privacy checks pass.
- Placeholder UI scan passes.
- Installer exists at the expected release filename.
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

Build signed installer (reads the version from `pyproject.toml`):

```powershell
powershell -NoProfile -File scripts\build_windows_installer.ps1
```

Verify signature (current release):

```powershell
powershell -NoProfile -File scripts\verify_windows_signature.ps1 -Path dist\installer\HomeGuard-Setup-vX.Y.Z.exe -ExpectedPublisher GreyNOC
```

Run local security preflight:

```powershell
python scripts\security_release_gate.py
```

Run tests:

```powershell
python -m unittest discover -s tests -v
```

## Production Release Procedure

Use this exact flow for a signed production vX.Y.Z release (substitute the
version from `pyproject.toml`). Do not skip
steps and do not commit anything inside `dist\`, signing logs, or any
certificate material.

1. **Cut release branch**
   ```powershell
   git checkout -b release/vX.Y.Z
   ```
2. **Confirm Security Gates passes on the release branch.** The
   `Security Gates` workflow run on `release/vX.Y.Z` (push or
   workflow_dispatch) must be green.
3. **Prepare the clean Windows release workstation.** Use a clean
   Windows 10 or Windows 11 build host with:
   - Python 3.10+ on `PATH`
   - Node.js / npm on `PATH`
   - Inno Setup 6 (`ISCC.exe` on `PATH`)
   - GreyNOC Authenticode code-signing certificate available locally
4. **Configure signing inputs through secure local storage or CI/release
   secrets.** Do not commit certificates or passwords.
   ```powershell
   $env:HOMEGUARD_SIGN_CERT_PATH="<secure local path to GreyNOC PFX>"
   $env:HOMEGUARD_SIGN_CERT_PASSWORD="<from secret store>"
   # or, if the cert is already installed in the user store:
   $env:HOMEGUARD_SIGN_CERT_SHA1="<certificate thumbprint>"
   ```
5. **Build the signed installer.**
   ```powershell
   powershell -NoProfile -File scripts\build_windows_installer.ps1
   ```
6. **Run the release gate.**
   ```powershell
   powershell -NoProfile -File scripts\release_gate.ps1
   ```
7. **Verify the final artifact exists.**
   ```text
   dist\installer\HomeGuard-Setup-vX.Y.Z.exe
   ```
8. **Record the SHA-256 checksum.**
   ```powershell
   Get-FileHash -Algorithm SHA256 dist\installer\HomeGuard-Setup-vX.Y.Z.exe
   ```
   Save the value in the release notes; do not commit signing or hash
   logs from the build host.
9. **Smoke test install and uninstall on a clean Windows VM.** Install
   from the signed artifact, then uninstall. Confirm clean removal.
10. **Verify runtime behavior on the clean VM:**
    - App launches from `Program Files\GreyNOC HomeGuard`.
    - Passive scan works without elevation.
    - Active scan requires an explicit, in-app opt-in.
    - Reports generate (HTML / PDF / JSON / CSV / manifest).
    - Reports do not expose secrets, full local filesystem paths, or
      private tokens.
    - Dashboard LAN mode requires explicit user action and the URL is
      tokenized per session.
    - AI bridge remains sterile / offline unless explicitly configured.
    - Admin relaunch is user-triggered only.
11. **Create the signed git tag.**
    ```powershell
    git tag -s vX.Y.Z -m "HomeGuard vX.Y.Z"
    git push origin vX.Y.Z
    ```
12. **Publish release notes that match the exact signed artifact and
    SHA-256 checksum.** Attach only the signed installer (and matching
    checksum file). Do not attach build logs, certificates, or unsigned
    internal builds.

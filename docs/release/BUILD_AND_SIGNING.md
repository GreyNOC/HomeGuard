# HomeGuard Build and Signing

Windows production releases are built as a PyInstaller application folder and
packaged with Inno Setup into a signed setup executable. The build and
release-gate scripts both read the current project version from
`pyproject.toml`, so most commands do not need a hardcoded version. Where an
explicit version is useful, the current production release is `1.5.0`.

## Required Local Tools

- Windows 10/11
- Python 3.10+
- Node.js/npm for Electron smoke checks
- Inno Setup 6 (`ISCC.exe` on `PATH`)
- Windows code-signing certificate issued to GreyNOC
- PowerShell Authenticode support

## Signing Inputs

Use one of these secure inputs. Do not commit certificates, passwords, PFX/P12 files, private keys, or thumbprints tied to private infrastructure.

Certificate file:

```powershell
$env:HOMEGUARD_SIGN_CERT_PATH="<secure local path to GreyNOC PFX>"
$env:HOMEGUARD_SIGN_CERT_PASSWORD="<provided by secret store>"
```

Certificate already installed in the current user's Windows certificate store:

```powershell
$env:HOMEGUARD_SIGN_CERT_SHA1="<certificate thumbprint>"
```

All signing uses SHA-256 and trusted timestamping through `http://timestamp.digicert.com`.

## Build Signed Installer

The build script reads the version from `pyproject.toml`:

```powershell
powershell -NoProfile -File scripts\build_windows_installer.ps1
```

Expected final artifact for the current release:

```text
dist\installer\HomeGuard-Setup-v1.5.0.exe
```

The build fails if:

- the PyInstaller application executable cannot be signed
- Inno Setup is unavailable
- the setup installer cannot be produced
- the setup installer cannot be signed
- Authenticode verification is not `Valid`
- the signer subject does not contain `GreyNOC`

### Unsigned builds

`-Unsigned` is for internal/test builds only. It is **not** a production
release path. Unsigned builds trigger a Windows SmartScreen "unknown
publisher" warning on download and must not be shipped to users.

```powershell
powershell -NoProfile -File scripts\build_windows_installer.ps1 -Unsigned
```

## Verify Installer Signature

```powershell
powershell -NoProfile -File scripts\verify_windows_signature.ps1 -Path dist\installer\HomeGuard-Setup-v1.5.0.exe -ExpectedPublisher GreyNOC
```

Do not publish the installer unless this command succeeds.

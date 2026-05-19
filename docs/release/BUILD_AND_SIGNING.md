# HomeGuard Build and Signing

V1 Windows releases are built as a PyInstaller application folder and packaged with Inno Setup into a signed setup executable.

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
$env:HOMEGUARD_SIGN_CERT_PATH="D:\secure\GreyNOC-CodeSigning.pfx"
$env:HOMEGUARD_SIGN_CERT_PASSWORD="<provided by secret store>"
```

Certificate already installed in the current user's Windows certificate store:

```powershell
$env:HOMEGUARD_SIGN_CERT_SHA1="<certificate thumbprint>"
```

All signing uses SHA-256 and trusted timestamping through `http://timestamp.digicert.com`.

## Build Signed V1 Installer

```powershell
powershell -NoProfile -File scripts\build_windows_installer.ps1 -Version 1.1.0
```

Expected final artifact:

```text
dist\installer\HomeGuard-Setup-v1.1.0.exe
```

The build fails if:

- the PyInstaller application executable cannot be signed
- Inno Setup is unavailable
- the setup installer cannot be produced
- the setup installer cannot be signed
- Authenticode verification is not `Valid`
- the signer subject does not contain `GreyNOC`

## Verify Installer Signature

```powershell
powershell -NoProfile -File scripts\verify_windows_signature.ps1 -Path dist\installer\HomeGuard-Setup-v1.1.0.exe -ExpectedPublisher GreyNOC
```

Do not publish the installer unless this command succeeds.

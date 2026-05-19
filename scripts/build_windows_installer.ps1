param(
    [string]$Version = "",
    [string]$ExpectedPublisher = "GreyNOC",
    # Build without Authenticode signing. Use only until GreyNOC has a
    # code-signing certificate; unsigned installers trigger a Windows
    # SmartScreen "unknown publisher" warning on download.
    [switch]$Unsigned
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")

if (-not $Version) {
    $pyproject = Get-Content -Raw -LiteralPath (Join-Path $repo "pyproject.toml")
    if ($pyproject -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw "Could not read project version from pyproject.toml"
    }
    $Version = $Matches[1]
}

if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    throw "Release version must be semantic version X.Y.Z. Got: $Version"
}

$iscc = (Get-Command "ISCC.exe" -ErrorAction SilentlyContinue).Source
if (-not $iscc) {
    $candidate = Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"
    if (Test-Path -LiteralPath $candidate) {
        $iscc = $candidate
    }
}
if (-not $iscc) {
    throw "Inno Setup 6 is required to build the V1 setup installer. Install it and ensure ISCC.exe is on PATH."
}

$env:HOMEGUARD_RELEASE_VERSION = $Version
$env:HOMEGUARD_REPO_ROOT = [string]$repo
if ($Unsigned) {
    Remove-Item Env:\HOMEGUARD_REQUIRE_SIGNING -ErrorAction SilentlyContinue
    Write-Warning "Building UNSIGNED installer. Windows SmartScreen will warn users on download."
} else {
    $env:HOMEGUARD_REQUIRE_SIGNING = "1"
}

Write-Host "Building application executable..."
$buildArgs = @((Join-Path $repo "scripts\build_electron.py"), "--no-version-bump")
if (-not $Unsigned) {
    $buildArgs += "--require-signing"
}
python @buildArgs

Write-Host "Building setup installer with Inno Setup..."
& $iscc (Join-Path $repo "installer\homeguard.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed with exit code $LASTEXITCODE"
}

$artifact = Join-Path $repo "dist\installer\HomeGuard-Setup-v$Version.exe"
if (-not (Test-Path -LiteralPath $artifact)) {
    throw "Expected installer was not produced: $artifact"
}

if ($Unsigned) {
    Write-Host "Unsigned V1 installer ready: $artifact"
} else {
    Write-Host "Signing setup installer..."
    & (Join-Path $repo "scripts\sign_windows_artifact.ps1") -Path $artifact -ExpectedPublisher $ExpectedPublisher

    Write-Host "Verifying setup installer signature..."
    & (Join-Path $repo "scripts\verify_windows_signature.ps1") -Path $artifact -ExpectedPublisher $ExpectedPublisher

    Write-Host "Signed V1 installer ready: $artifact"
}

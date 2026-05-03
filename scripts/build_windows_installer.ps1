param(
    [string]$Version = "",
    [string]$ExpectedPublisher = "GreyNOC"
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
$env:HOMEGUARD_REQUIRE_SIGNING = "1"

Write-Host "Building signed application executable..."
python (Join-Path $repo "scripts\build_electron.py") --no-version-bump --require-signing

Write-Host "Building setup installer with Inno Setup..."
& $iscc (Join-Path $repo "installer\homeguard.iss")
if ($LASTEXITCODE -ne 0) {
    throw "Inno Setup failed with exit code $LASTEXITCODE"
}

$artifact = Join-Path $repo "dist\installer\HomeGuard-Setup-v$Version.exe"
if (-not (Test-Path -LiteralPath $artifact)) {
    throw "Expected installer was not produced: $artifact"
}

Write-Host "Signing setup installer..."
& (Join-Path $repo "scripts\sign_windows_artifact.ps1") -Path $artifact -ExpectedPublisher $ExpectedPublisher

Write-Host "Verifying setup installer signature..."
& (Join-Path $repo "scripts\verify_windows_signature.ps1") -Path $artifact -ExpectedPublisher $ExpectedPublisher

Write-Host "Signed V1 installer ready: $artifact"

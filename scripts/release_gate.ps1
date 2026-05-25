param(
    [string]$InstallerPath = "",
    [string]$ExpectedPublisher = "GreyNOC"
)

$ErrorActionPreference = "Stop"
$repo = Resolve-Path (Join-Path $PSScriptRoot "..")

if (-not $InstallerPath) {
    $pyproject = Get-Content -Raw -LiteralPath (Join-Path $repo "pyproject.toml")
    if ($pyproject -notmatch '(?m)^version\s*=\s*"([^"]+)"') {
        throw "Could not read project version from pyproject.toml"
    }
    $InstallerPath = Join-Path $repo "dist\installer\HomeGuard-Setup-v$($Matches[1]).exe"
}

if (-not (Test-Path -LiteralPath $InstallerPath)) {
    throw "Installer not found at expected release path: $InstallerPath. Run scripts\build_windows_installer.ps1 first."
}

function Invoke-GateStep {
    param([string]$Name, [scriptblock]$Step)
    Write-Host "== $Name =="
    & $Step
}

Invoke-GateStep "Python tests" {
    python -m unittest discover -s tests -v
}

# npm ci ensures the release gate runs against the locked Electron dependency
# tree (package-lock.json) instead of whatever happens to be in node_modules
# on the release workstation. Required for reproducibility of the audit +
# smoke checks below.
Invoke-GateStep "Locked Node install" {
    npm ci
}

Invoke-GateStep "Electron smoke test" {
    npm run smoke
}

Invoke-GateStep "Python dependency check" {
    python -m pip check
}

Invoke-GateStep "npm dependency audit" {
    npm audit --audit-level=high
}

Invoke-GateStep "Secret and personal-path scan" {
    $patterns = @(
        'C:\\Users\\',
        '/Users/',
        'AppData',
        'HOME=',
        'USERNAME=',
        'BEGIN .*PRIVATE KEY',
        'api[_-]?key\s*[:=]',
        'token\s*[:=]',
        'password\s*[:=]'
    )
    $excluded = '\\node_modules\\|\\.venv\\|\\.venv-build\\|\\build\\|\\dist\\|\\__pycache__\\|\\pytest-cache-files-|\\src\\greynoc_homeguard\.egg-info\\'
    $files = Get-ChildItem -LiteralPath $repo -Recurse -File |
        Where-Object { $_.FullName -notmatch $excluded -and $_.Extension -match '\.(py|js|html|css|md|bat|ps1|yml|yaml|toml|sh|spec|iss|json)$' }
    $hits = $files | Select-String -Pattern $patterns -CaseSensitive:$false
    $allowed = $hits | Where-Object {
        $_.Path -notmatch 'BUILD_AND_SIGNING.md|RELEASE_CHECKLIST.md|SECURITY_REVIEW.md|PRIVACY_REVIEW.md|README.md|docs\\SECURITY_DEFINITIONS.md|scripts\\release_gate.ps1|scripts\\build_exe.py|scripts\\sign_windows_artifact.ps1|scripts\\build_windows_installer.ps1|compile_exe.bat|src\\greynoc_homeguard\\privacy.py|electron\\main.js|tests\\test_homeguard.py'
    }
    if ($allowed) {
        $allowed | Select-Object -First 20 | ForEach-Object { Write-Error "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
        throw "Secret/personal-path scan failed."
    }
}

Invoke-GateStep "Placeholder UI scan" {
    $uiFiles = @(
        Join-Path $repo "electron\renderer\index.html",
        Join-Path $repo "electron\renderer\renderer.js",
        Join-Path $repo "electron\renderer\styles.css"
    )
    $hits = $uiFiles | Select-String -Pattern 'lorem ipsum|todo|mock data|demo data|coming soon|fake' -CaseSensitive:$false
    if ($hits) {
        $hits | ForEach-Object { Write-Error "$($_.Path):$($_.LineNumber): $($_.Line.Trim())" }
        throw "Placeholder UI scan failed."
    }
}

Invoke-GateStep "Installer signature verification" {
    & (Join-Path $repo "scripts\verify_windows_signature.ps1") -Path $InstallerPath -ExpectedPublisher $ExpectedPublisher
}

Write-Host "Production release gate passed."

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$CertificatePath = $env:HOMEGUARD_SIGN_CERT_PATH,
    [string]$CertificatePassword = $env:HOMEGUARD_SIGN_CERT_PASSWORD,
    [string]$CertificateThumbprint = $env:HOMEGUARD_SIGN_CERT_SHA1,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$ExpectedPublisher = "GreyNOC"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Artifact does not exist: $Path"
}

if (-not $CertificatePath -and -not $CertificateThumbprint) {
    throw "Signing requires HOMEGUARD_SIGN_CERT_PATH or HOMEGUARD_SIGN_CERT_SHA1. No certificate material is stored in the repo."
}

$signParams = @{
    FilePath = $Path
    TimestampServer = $TimestampUrl
    HashAlgorithm = "SHA256"
}

if ($CertificatePath) {
    if (-not (Test-Path -LiteralPath $CertificatePath)) {
        throw "Signing certificate file was not found."
    }
    if (-not $CertificatePassword) {
        throw "HOMEGUARD_SIGN_CERT_PASSWORD is required when HOMEGUARD_SIGN_CERT_PATH is used."
    }
    $securePassword = ConvertTo-SecureString -String $CertificatePassword -AsPlainText -Force
    $certificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2
    $certificate.Import($CertificatePath, $securePassword, "Exportable,PersistKeySet")
    $signParams.Certificate = $certificate
} else {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "My", "CurrentUser"
    $store.Open("ReadOnly")
    try {
        $matches = $store.Certificates | Where-Object { $_.Thumbprint -eq $CertificateThumbprint }
        if (-not $matches -or $matches.Count -lt 1) {
            throw "Certificate thumbprint was not found in CurrentUser\My."
        }
        $signParams.Certificate = $matches[0]
    } finally {
        $store.Close()
    }
}

$result = Set-AuthenticodeSignature @signParams
if ($result.Status -ne "Valid") {
    throw "Signing failed for $Path. Status: $($result.Status)"
}

& "$PSScriptRoot\verify_windows_signature.ps1" -Path $Path -ExpectedPublisher $ExpectedPublisher

param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$ExpectedPublisher = "GreyNOC"
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path)) {
    throw "Artifact does not exist: $Path"
}

$signature = Get-AuthenticodeSignature -LiteralPath $Path
if ($signature.Status -ne "Valid") {
    throw "Authenticode signature is not valid for $Path. Status: $($signature.Status)"
}

if (-not $signature.SignerCertificate) {
    throw "No signer certificate was found on $Path"
}

$subject = [string]$signature.SignerCertificate.Subject
if ($ExpectedPublisher -and $subject -notlike "*$ExpectedPublisher*") {
    throw "Signer subject '$subject' does not contain expected publisher '$ExpectedPublisher'"
}

Write-Host "Signature valid: $Path"
Write-Host "Publisher: $subject"
Write-Host "Thumbprint: $($signature.SignerCertificate.Thumbprint)"

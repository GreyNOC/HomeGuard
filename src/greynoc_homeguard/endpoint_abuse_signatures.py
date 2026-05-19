"""Defensive endpoint signatures for PowerShell abuse and credential access.

These signatures are detection-only. They do not execute the referenced tools or
attempt to remove them; they enrich the existing HomeGuard endpoint scanner so
local scans can flag suspicious process command lines, downloaded scripts,
startup entries, and sampled memory artifacts.
"""

from __future__ import annotations

import re
from typing import Iterable

POWERSHELL_ABUSE_COMMANDS = {
    "Invoke-TokenManipulation": "PowerShell token manipulation / impersonation behavior",
    "Invoke-CredentialInjection": "PowerShell credential injection behavior",
    "Invoke-NinjaCopy": "Raw NTFS file copy behavior",
    "Invoke-Mimikatz": "PowerShell credential dumping behavior",
    "Get-Keystrokes": "PowerShell keystroke logging behavior",
    "Get-GPPPassword": "Group Policy Preferences password retrieval behavior",
    "Get-GPPAutologon": "Group Policy Preferences autologon credential retrieval behavior",
    "Get-TimedScreenshot": "Timed screenshot capture behavior",
    "New-VolumeShadowCopy": "Volume shadow copy creation behavior",
    "Get-VolumeShadowCopy": "Volume shadow copy enumeration behavior",
    "Mount-VolumeShadowCopy": "Volume shadow copy mount behavior",
    "Remove-VolumeShadowCopy": "Volume shadow copy deletion behavior",
    "Get-VaultCredential": "Windows Vault credential access behavior",
    "Out-Minidump": "Process memory minidump behavior",
    "Get-MicrophoneAudio": "Microphone capture behavior",
}

CREDENTIAL_ACCESS_TERMS = {
    "sekurlsa::": "Credential dumping command artifact",
    "lsadump::": "LSA secret dumping command artifact",
    "vault::cred": "Windows Vault credential artifact",
    "mimikatz": "Credential dumping tool artifact",
    "minidump": "Process minidump artifact",
    "procdump": "Process dumping tool artifact",
    "nanodump": "Process dumping tool artifact",
    "comsvcs.dll": "Windows comsvcs minidump artifact",
    "MiniDumpWriteDump": "Process memory dump API artifact",
}


def _word_pattern(values: Iterable[str]) -> str:
    return r"(?<![A-Za-z0-9_-])(?:" + "|".join(re.escape(value) for value in values) + r")(?![A-Za-z0-9_-])"


def _bytes_pattern(values: Iterable[str]) -> bytes:
    return _word_pattern(values).encode("ascii")


def install_endpoint_abuse_signatures() -> None:
    """Attach the defensive signature pack to ``virus_scanner`` once."""

    try:
        from . import virus_scanner
    except Exception:
        return

    if getattr(virus_scanner, "_HOMEGUARD_ENDPOINT_ABUSE_SIGNATURES_INSTALLED", False):
        return

    command_pattern = re.compile(_word_pattern(POWERSHELL_ABUSE_COMMANDS), re.IGNORECASE)
    credential_pattern = re.compile(_word_pattern(CREDENTIAL_ACCESS_TERMS), re.IGNORECASE)
    command_bytes_pattern = re.compile(_bytes_pattern(POWERSHELL_ABUSE_COMMANDS), re.IGNORECASE)
    credential_bytes_pattern = re.compile(_bytes_pattern(CREDENTIAL_ACCESS_TERMS), re.IGNORECASE)

    virus_scanner.SUSPICIOUS_CMD_PATTERNS.extend(
        [
            (command_pattern, "PowerShell abuse framework command"),
            (credential_pattern, "Credential access or process dump artifact"),
            (
                re.compile(r"\b(?:vssadmin|wmic|powershell(?:\.exe)?)\b.{0,220}\b(?:shadowcopy|shadow copy|win32_shadowcopy)\b", re.IGNORECASE),
                "Shadow copy manipulation behavior",
            ),
            (
                re.compile(r"\b(?:rundll32(?:\.exe)?\s+)?comsvcs\.dll\b.{0,220}\b(?:minidump|MiniDump)\b", re.IGNORECASE),
                "Process minidump through comsvcs.dll",
            ),
            (
                re.compile(r"\b(?:procdump|nanodump|out-minidump)\b", re.IGNORECASE),
                "Process memory dumping behavior",
            ),
        ]
    )

    virus_scanner.FILE_CONTENT_SIGNATURES.extend(
        [
            (command_bytes_pattern, "PowerShell abuse framework command artifact", "high", 0.78),
            (credential_bytes_pattern, "Credential access or process dump artifact", "high", 0.76),
            (
                re.compile(rb"(?:vssadmin|wmic|powershell(?:\.exe)?).{0,220}(?:shadowcopy|shadow copy|win32_shadowcopy)", re.IGNORECASE),
                "Shadow copy manipulation script artifact",
                "high",
                0.7,
            ),
            (
                re.compile(rb"(?:get-keystrokes|get-timedscreenshot|get-microphoneaudio)", re.IGNORECASE),
                "User surveillance script artifact",
                "high",
                0.82,
            ),
            (
                re.compile(rb"(?:get-gpppassword|get-gppautologon|get-vaultcredential|invoke-credentialinjection)", re.IGNORECASE),
                "Credential collection script artifact",
                "critical",
                0.82,
            ),
        ]
    )

    for signature, label in {
        **{key.lower().encode("ascii"): value for key, value in POWERSHELL_ABUSE_COMMANDS.items()},
        **{key.lower().encode("ascii"): value for key, value in CREDENTIAL_ACCESS_TERMS.items()},
    }.items():
        virus_scanner.MEMORY_SIGNATURES.setdefault(signature, label)

    virus_scanner._HOMEGUARD_ENDPOINT_ABUSE_SIGNATURES_INSTALLED = True


__all__ = ["POWERSHELL_ABUSE_COMMANDS", "CREDENTIAL_ACCESS_TERMS", "install_endpoint_abuse_signatures"]

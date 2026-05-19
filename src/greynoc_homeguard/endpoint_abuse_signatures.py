"""Defensive endpoint-abuse signature metadata for HomeGuard.

The entries in this module are passive string indicators only. They are used to
flag PowerSploit-style artifacts and related Windows hardening risks in command
lines, downloaded/script content, persistence entries, and sampled memory. The
module does not execute, import, download, or generate any offensive tool code.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class EndpointAbuseSignature:
    pattern: str
    label: str
    category: str
    severity: str
    confidence: float
    plain_english: str
    recommended_actions: tuple[str, ...]
    mitre_tactic: str
    mitre_technique: str
    sources: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["recommended_actions"] = list(self.recommended_actions)
        payload["sources"] = list(self.sources)
        return payload


POWERSPOIT_RESISTANCE_CATEGORIES = {
    "powershell_abuse",
    "credential_access",
    "token_manipulation",
    "raw_ntfs_copy",
    "surveillance",
    "shadow_copy_abuse",
    "process_dumping",
    "persistence",
    "privesc_audit",
    "service_abuse",
    "dll_hijack_risk",
    "recon",
    "script_obfuscation",
    "code_execution",
    "destructive_or_mayhem_behavior",
}

POWERSPOIT_FUNCTION_NAMES = [
    "Invoke-TokenManipulation",
    "Invoke-CredentialInjection",
    "Invoke-NinjaCopy",
    "Invoke-Mimikatz",
    "Get-Keystrokes",
    "Get-GPPPassword",
    "Get-GPPAutologon",
    "Get-TimedScreenshot",
    "New-VolumeShadowCopy",
    "Get-VolumeShadowCopy",
    "Mount-VolumeShadowCopy",
    "Remove-VolumeShadowCopy",
    "Get-VaultCredential",
    "Out-Minidump",
    "Get-MicrophoneAudio",
    "Invoke-PrivescAudit",
    "Get-ServiceUnquoted",
    "Get-ModifiableServiceFile",
    "Get-ModifiableService",
    "Get-ModifiablePath",
    "Get-ModifiableScheduledTaskFile",
    "Get-UnattendedInstallFile",
    "Get-Webconfig",
    "Get-ApplicationHost",
    "Get-RegistryAlwaysInstallElevated",
    "Get-RegistryAutoLogon",
    "Get-ProcessTokenPrivilege",
    "Get-System",
    "Invoke-ServiceAbuse",
    "Write-ServiceBinary",
    "Install-ServiceBinary",
    "Restore-ServiceBinary",
    "Find-ProcessDLLHijack",
    "Find-PathDLLHijack",
    "Write-HijackDll",
    "Add-Persistence",
    "Install-SSP",
    "Get-SecurityPackages",
    "Invoke-Shellcode",
    "Invoke-DllInjection",
    "Invoke-ReflectivePEInjection",
    "Invoke-WmiCommand",
    "Out-EncodedCommand",
    "Out-CompressedDll",
    "Out-EncryptedScript",
    "Remove-Comment",
    "Find-AVSignature",
]

# Backward-compatible alias for the correctly spelled project/tool family name.
POWERSPLOIT_RESISTANCE_CATEGORIES = POWERSPOIT_RESISTANCE_CATEGORIES
POWERSPLOIT_FUNCTION_NAMES = POWERSPOIT_FUNCTION_NAMES


def _artifact_pattern(name: str) -> str:
    return rf"(?<![A-Za-z0-9_-]){re.escape(name)}(?![A-Za-z0-9_-])"


def _actions(*extra: str) -> tuple[str, ...]:
    base = (
        "Confirm whether the artifact came from an expected defensive test or administrative audit.",
        "Review the process parent, startup item, downloaded file, or script source that introduced the artifact.",
        "Run a full endpoint protection scan and preserve the HomeGuard report if the activity is unexpected.",
    )
    return (*base, *extra)


_FUNCTION_METADATA: dict[str, dict[str, Any]] = {
    "Invoke-TokenManipulation": {
        "category": "token_manipulation",
        "severity": "high",
        "confidence": 0.84,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1134 - Access Token Manipulation",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with manipulating Windows logon identity context.",
    },
    "Invoke-CredentialInjection": {
        "category": "credential_access",
        "severity": "critical",
        "confidence": 0.86,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1555 - Credentials from Password Stores",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with injecting or replaying saved sign-in material.",
    },
    "Invoke-NinjaCopy": {
        "category": "raw_ntfs_copy",
        "severity": "high",
        "confidence": 0.86,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1006 - Direct Volume Access",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with raw NTFS file access that may bypass normal file locks.",
    },
    "Invoke-Mimikatz": {
        "category": "credential_access",
        "severity": "critical",
        "confidence": 0.92,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003 - OS Credential Dumping",
        "plain_english": "HomeGuard saw a credential-theft artifact name commonly associated with attempts to access Windows sign-in material.",
    },
    "Get-Keystrokes": {
        "category": "surveillance",
        "severity": "high",
        "confidence": 0.88,
        "mitre_tactic": "Collection",
        "mitre_technique": "T1056.001 - Keylogging",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with keyboard surveillance.",
    },
    "Get-GPPPassword": {
        "category": "credential_access",
        "severity": "high",
        "confidence": 0.87,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552.006 - Group Policy Preferences",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with cached Group Policy Preference passwords.",
    },
    "Get-GPPAutologon": {
        "category": "credential_access",
        "severity": "high",
        "confidence": 0.85,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552 - Unsecured Credentials",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with autologon credential discovery.",
    },
    "Get-TimedScreenshot": {
        "category": "surveillance",
        "severity": "high",
        "confidence": 0.86,
        "mitre_tactic": "Collection",
        "mitre_technique": "T1113 - Screen Capture",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with timed screen capture.",
    },
    "New-VolumeShadowCopy": {
        "category": "shadow_copy_abuse",
        "severity": "high",
        "confidence": 0.8,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1006 - Direct Volume Access",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with creating volume shadow copies for offline file access.",
    },
    "Get-VolumeShadowCopy": {
        "category": "shadow_copy_abuse",
        "severity": "medium",
        "confidence": 0.76,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1083 - File and Directory Discovery",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with inspecting volume shadow copies.",
    },
    "Mount-VolumeShadowCopy": {
        "category": "shadow_copy_abuse",
        "severity": "high",
        "confidence": 0.8,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1006 - Direct Volume Access",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with mounting volume shadow copies for offline file access.",
    },
    "Remove-VolumeShadowCopy": {
        "category": "destructive_or_mayhem_behavior",
        "severity": "high",
        "confidence": 0.8,
        "mitre_tactic": "Impact",
        "mitre_technique": "T1490 - Inhibit System Recovery",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with removing recovery snapshots.",
    },
    "Get-VaultCredential": {
        "category": "credential_access",
        "severity": "high",
        "confidence": 0.84,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1555 - Credentials from Password Stores",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with Windows vault credential discovery.",
    },
    "Out-Minidump": {
        "category": "process_dumping",
        "severity": "critical",
        "confidence": 0.9,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1003.001 - LSASS Memory",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with process memory dumps, a common credential-theft precursor.",
    },
    "Get-MicrophoneAudio": {
        "category": "surveillance",
        "severity": "high",
        "confidence": 0.87,
        "mitre_tactic": "Collection",
        "mitre_technique": "T1123 - Audio Capture",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with microphone capture.",
    },
    "Invoke-PrivescAudit": {
        "category": "privesc_audit",
        "severity": "medium",
        "confidence": 0.74,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1069 - Permission Groups Discovery",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with auditing Windows privilege escalation opportunities.",
    },
    "Get-ServiceUnquoted": {
        "category": "service_abuse",
        "severity": "medium",
        "confidence": 0.73,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1574.009 - Path Interception by Unquoted Path",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with finding unquoted Windows service paths.",
    },
    "Get-ModifiableServiceFile": {
        "category": "service_abuse",
        "severity": "medium",
        "confidence": 0.73,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1574.011 - Services File Permissions Weakness",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with finding writable service executable files.",
    },
    "Get-ModifiableService": {
        "category": "service_abuse",
        "severity": "medium",
        "confidence": 0.72,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1543.003 - Windows Service",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with finding services that may be changeable by non-admin users.",
    },
    "Get-ModifiablePath": {
        "category": "privesc_audit",
        "severity": "medium",
        "confidence": 0.72,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1574 - Hijack Execution Flow",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with finding writable directories in executable search paths.",
    },
    "Get-ModifiableScheduledTaskFile": {
        "category": "privesc_audit",
        "severity": "medium",
        "confidence": 0.72,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1053.005 - Scheduled Task",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with finding scheduled task executables that may be writable.",
    },
    "Get-UnattendedInstallFile": {
        "category": "credential_access",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552.001 - Credentials In Files",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with unattended Windows install files that may contain saved secrets.",
    },
    "Get-Webconfig": {
        "category": "credential_access",
        "severity": "medium",
        "confidence": 0.78,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552.001 - Credentials In Files",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with web configuration files that may contain saved secrets.",
    },
    "Get-ApplicationHost": {
        "category": "credential_access",
        "severity": "medium",
        "confidence": 0.78,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552.001 - Credentials In Files",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with IIS applicationHost configuration review.",
    },
    "Get-RegistryAlwaysInstallElevated": {
        "category": "privesc_audit",
        "severity": "medium",
        "confidence": 0.76,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1548 - Abuse Elevation Control Mechanism",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with checking whether Windows Installer can elevate packages.",
    },
    "Get-RegistryAutoLogon": {
        "category": "credential_access",
        "severity": "medium",
        "confidence": 0.76,
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1552.002 - Credentials in Registry",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with checking Windows autologon registry values.",
    },
    "Get-ProcessTokenPrivilege": {
        "category": "privesc_audit",
        "severity": "medium",
        "confidence": 0.74,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1069 - Permission Groups Discovery",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with enumerating sensitive Windows process privileges.",
    },
    "Get-System": {
        "category": "token_manipulation",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1134 - Access Token Manipulation",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with trying to obtain local SYSTEM-level execution context.",
    },
    "Invoke-ServiceAbuse": {
        "category": "service_abuse",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1543.003 - Windows Service",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with abusing Windows service configuration.",
    },
    "Write-ServiceBinary": {
        "category": "service_abuse",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1543.003 - Windows Service",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with writing a service executable.",
    },
    "Install-ServiceBinary": {
        "category": "service_abuse",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1543.003 - Windows Service",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with installing a service executable.",
    },
    "Restore-ServiceBinary": {
        "category": "service_abuse",
        "severity": "medium",
        "confidence": 0.74,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1036 - Masquerading",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with restoring a changed service executable.",
    },
    "Find-ProcessDLLHijack": {
        "category": "dll_hijack_risk",
        "severity": "medium",
        "confidence": 0.74,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1574.001 - DLL Search Order Hijacking",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with finding DLL hijack opportunities in running processes.",
    },
    "Find-PathDLLHijack": {
        "category": "dll_hijack_risk",
        "severity": "medium",
        "confidence": 0.74,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1574.001 - DLL Search Order Hijacking",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with finding DLL hijack opportunities in PATH directories.",
    },
    "Write-HijackDll": {
        "category": "dll_hijack_risk",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1574.001 - DLL Search Order Hijacking",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with writing a DLL for hijack testing or abuse.",
    },
    "Add-Persistence": {
        "category": "persistence",
        "severity": "high",
        "confidence": 0.84,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1547 - Boot or Logon Autostart Execution",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with adding automatic startup persistence.",
    },
    "Install-SSP": {
        "category": "persistence",
        "severity": "high",
        "confidence": 0.84,
        "mitre_tactic": "Persistence",
        "mitre_technique": "T1547.005 - Security Support Provider",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with installing a Windows Security Support Provider.",
    },
    "Get-SecurityPackages": {
        "category": "recon",
        "severity": "medium",
        "confidence": 0.72,
        "mitre_tactic": "Discovery",
        "mitre_technique": "T1012 - Query Registry",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with enumerating Windows security packages.",
    },
    "Invoke-Shellcode": {
        "category": "code_execution",
        "severity": "critical",
        "confidence": 0.9,
        "mitre_tactic": "Execution",
        "mitre_technique": "T1055 - Process Injection",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with in-memory code execution.",
    },
    "Invoke-DllInjection": {
        "category": "code_execution",
        "severity": "critical",
        "confidence": 0.9,
        "mitre_tactic": "Privilege Escalation",
        "mitre_technique": "T1055.001 - Dynamic-link Library Injection",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with DLL injection.",
    },
    "Invoke-ReflectivePEInjection": {
        "category": "code_execution",
        "severity": "critical",
        "confidence": 0.9,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1620 - Reflective Code Loading",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with reflective PE loading.",
    },
    "Invoke-WmiCommand": {
        "category": "code_execution",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Execution",
        "mitre_technique": "T1047 - Windows Management Instrumentation",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with WMI-based command execution.",
    },
    "Out-EncodedCommand": {
        "category": "script_obfuscation",
        "severity": "high",
        "confidence": 0.84,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1027 - Obfuscated Files or Information",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with encoded command generation.",
    },
    "Out-CompressedDll": {
        "category": "script_obfuscation",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1027 - Obfuscated Files or Information",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with compressing DLL content into script form.",
    },
    "Out-EncryptedScript": {
        "category": "script_obfuscation",
        "severity": "high",
        "confidence": 0.82,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1027 - Obfuscated Files or Information",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with encrypted script content.",
    },
    "Remove-Comment": {
        "category": "script_obfuscation",
        "severity": "medium",
        "confidence": 0.7,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1027 - Obfuscated Files or Information",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with preparing harder-to-read script content.",
    },
    "Find-AVSignature": {
        "category": "script_obfuscation",
        "severity": "high",
        "confidence": 0.84,
        "mitre_tactic": "Defense Evasion",
        "mitre_technique": "T1027 - Obfuscated Files or Information",
        "plain_english": "HomeGuard saw a PowerShell artifact associated with probing endpoint protection signatures.",
    },
}

_GROUP_SIGNATURES = [
    EndpointAbuseSignature(
        pattern=r"\b(?:powershell|pwsh)(?:\.exe)?\b.{0,240}\b(?:-enc(?:odedcommand)?|frombase64string|downloadstring|invoke-expression|\biex\b)",
        label="PowerShell loader or encoded command behavior",
        category="powershell_abuse",
        severity="high",
        confidence=0.72,
        plain_english="A PowerShell command line matched a pattern commonly used to hide or load script content.",
        recommended_actions=_actions("Enable PowerShell script block logging and review recent PowerShell history for the same time window."),
        mitre_tactic="Execution",
        mitre_technique="T1059.001 - PowerShell",
        sources=("process_command_line", "startup_persistence", "downloaded_script_content"),
    ),
    EndpointAbuseSignature(
        pattern=r"\b(?:frombase64string|encodedcommand|out-encodedcommand|out-encryptedscript|out-compresseddll|remove-comment)\b",
        label="PowerShell script obfuscation artifact",
        category="script_obfuscation",
        severity="high",
        confidence=0.78,
        plain_english="HomeGuard saw script text associated with hiding or transforming PowerShell content.",
        recommended_actions=_actions("Preserve the script for defensive review and verify whether it was created by an approved admin tool."),
        mitre_tactic="Defense Evasion",
        mitre_technique="T1027 - Obfuscated Files or Information",
        sources=("process_command_line", "startup_persistence", "downloaded_script_content", "memory_string"),
    ),
    EndpointAbuseSignature(
        pattern=r"\b(?:sekurlsa::|lsadump::|logonpasswords|vaultcredential|gpppassword|gppautologon)\b",
        label="High-risk credential access string",
        category="credential_access",
        severity="critical",
        confidence=0.88,
        plain_english="HomeGuard saw text associated with attempts to find or access saved Windows sign-in material.",
        recommended_actions=_actions("Change important passwords from a trusted device if this activity is unexpected."),
        mitre_tactic="Credential Access",
        mitre_technique="T1003 - OS Credential Dumping",
        sources=("downloaded_script_content", "memory_string", "process_command_line"),
    ),
    EndpointAbuseSignature(
        pattern=r"\b(?:keystrokes|timedscreenshot|microphoneaudio|screen\s*capture|audio\s*capture)\b",
        label="Surveillance collection string",
        category="surveillance",
        severity="high",
        confidence=0.82,
        plain_english="HomeGuard saw text associated with keyboard, screen, or microphone surveillance.",
        recommended_actions=_actions("Avoid entering sensitive information on this PC until the finding is reviewed."),
        mitre_tactic="Collection",
        mitre_technique="T1056/T1113/T1123 - Input, Screen, or Audio Capture",
        sources=("downloaded_script_content", "memory_string", "process_command_line"),
    ),
    EndpointAbuseSignature(
        pattern=r"\b(?:minidump|out-minidump|procdump|createdump|lsass\.dmp)\b",
        label="Process dump artifact",
        category="process_dumping",
        severity="critical",
        confidence=0.84,
        plain_english="HomeGuard saw text associated with dumping process memory, which can expose sensitive sign-in material.",
        recommended_actions=_actions("Review whether LSASS protection is enabled and investigate the process that produced the artifact."),
        mitre_tactic="Credential Access",
        mitre_technique="T1003.001 - LSASS Memory",
        sources=("downloaded_script_content", "memory_string", "process_command_line"),
    ),
    EndpointAbuseSignature(
        pattern=r"\b(?:delete\s+shadows|remove-volumeshadowcopy|clear-eventlog|wevtutil\s+cl|ransom\s*note|mass\s+file\s+deletion)\b",
        label="Destructive or recovery-impacting behavior string",
        category="destructive_or_mayhem_behavior",
        severity="critical",
        confidence=0.82,
        plain_english="HomeGuard saw text associated with destructive activity, recovery snapshot removal, or event log clearing.",
        recommended_actions=_actions("Check backup health and avoid rebooting or deleting files until the system is reviewed."),
        mitre_tactic="Impact",
        mitre_technique="T1490 - Inhibit System Recovery",
        sources=("process_command_line", "startup_persistence", "downloaded_script_content", "memory_string"),
    ),
]


def _function_signatures() -> list[EndpointAbuseSignature]:
    signatures: list[EndpointAbuseSignature] = []
    for name in POWERSPOIT_FUNCTION_NAMES:
        metadata = _FUNCTION_METADATA[name]
        label = f"PowerSploit-style artifact: {name}"
        signatures.append(
            EndpointAbuseSignature(
                pattern=_artifact_pattern(name),
                label=label,
                category=metadata["category"],
                severity=metadata["severity"],
                confidence=metadata["confidence"],
                plain_english=metadata["plain_english"],
                recommended_actions=_actions(),
                mitre_tactic=metadata["mitre_tactic"],
                mitre_technique=metadata["mitre_technique"],
                sources=("process_command_line", "startup_persistence", "downloaded_script_content", "memory_string"),
            )
        )
    return signatures


ENDPOINT_ABUSE_SIGNATURES = tuple([*_function_signatures(), *_GROUP_SIGNATURES])
PROCESS_COMMANDLINE_SIGNATURES = tuple(
    signature for signature in ENDPOINT_ABUSE_SIGNATURES if "process_command_line" in signature.sources
)
DOWNLOADED_CONTENT_SIGNATURES = tuple(
    signature for signature in ENDPOINT_ABUSE_SIGNATURES if "downloaded_script_content" in signature.sources
)
PERSISTENCE_COMMAND_SIGNATURES = tuple(
    signature for signature in ENDPOINT_ABUSE_SIGNATURES if "startup_persistence" in signature.sources
)
MEMORY_STRING_SIGNATURES = tuple(
    signature for signature in ENDPOINT_ABUSE_SIGNATURES if "memory_string" in signature.sources
)


def signature_metadata_by_label() -> dict[str, dict[str, Any]]:
    return {signature.label: signature.as_dict() for signature in ENDPOINT_ABUSE_SIGNATURES}


def compile_text_signature(signature: EndpointAbuseSignature) -> re.Pattern[str]:
    return re.compile(signature.pattern, re.IGNORECASE)


def compile_bytes_signature(signature: EndpointAbuseSignature) -> re.Pattern[bytes]:
    return re.compile(signature.pattern.encode("utf-8"), re.IGNORECASE)


def memory_marker_for_signature(signature: EndpointAbuseSignature) -> bytes:
    marker = signature.pattern
    if marker.startswith("(?<![A-Za-z0-9_-])") and marker.endswith("(?![A-Za-z0-9_-])"):
        marker = marker.removeprefix("(?<![A-Za-z0-9_-])").removesuffix("(?![A-Za-z0-9_-])")
        marker = re.sub(r"\\(.)", r"\1", marker)
    elif "|" in marker:
        marker = signature.label
    return marker.lower().encode("utf-8", errors="ignore")


def install_into_virus_scanner(scanner_module: Any | None = None) -> bool:
    """Install the static signatures into the legacy endpoint scanner lists.

    Returns True when signatures were installed and False when the scanner had
    already been patched. The operation is idempotent and uses a marker flag on
    the scanner module.
    """

    if scanner_module is None:
        from . import virus_scanner as scanner_module

    if getattr(scanner_module, "_HOMEGUARD_ENDPOINT_ABUSE_SIGNATURES_INSTALLED", False):
        return False

    metadata = getattr(scanner_module, "ENDPOINT_ABUSE_SIGNATURE_METADATA", {})
    if not isinstance(metadata, dict):
        metadata = {}
    metadata.update(signature_metadata_by_label())
    scanner_module.ENDPOINT_ABUSE_SIGNATURE_METADATA = metadata

    existing_command = {
        (getattr(pattern, "pattern", str(pattern)), label)
        for pattern, label in getattr(scanner_module, "SUSPICIOUS_CMD_PATTERNS", [])
    }
    for signature in PROCESS_COMMANDLINE_SIGNATURES:
        key = (signature.pattern, signature.label)
        if key not in existing_command:
            scanner_module.SUSPICIOUS_CMD_PATTERNS.append((compile_text_signature(signature), signature.label))
            existing_command.add(key)

    existing_content = {
        (getattr(pattern, "pattern", str(pattern)), label)
        for pattern, label, _severity, _confidence in getattr(scanner_module, "FILE_CONTENT_SIGNATURES", [])
    }
    for signature in DOWNLOADED_CONTENT_SIGNATURES:
        key = (signature.pattern.encode("utf-8"), signature.label)
        text_key = (signature.pattern, signature.label)
        if text_key not in existing_content and key not in existing_content:
            scanner_module.FILE_CONTENT_SIGNATURES.append(
                (compile_bytes_signature(signature), signature.label, signature.severity, signature.confidence)
            )
            existing_content.add(text_key)

    memory_signatures = getattr(scanner_module, "MEMORY_SIGNATURES", {})
    for signature in MEMORY_STRING_SIGNATURES:
        marker = memory_marker_for_signature(signature)
        if marker and marker not in memory_signatures:
            memory_signatures[marker] = signature.label
    scanner_module.MEMORY_SIGNATURES = memory_signatures

    scanner_module._HOMEGUARD_ENDPOINT_ABUSE_SIGNATURES_INSTALLED = True
    return True

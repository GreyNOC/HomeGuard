"""Passive Windows privilege-escalation and hardening audit checks.

This module only reads bounded local state: selected registry keys, service and
scheduled-task metadata, known configuration file locations, and selected
Windows security settings. It never runs exploit helpers, payloads, offensive
PowerShell modules, credential dumping tools, or bypass commands.
"""

from __future__ import annotations

import csv
import json
import os
import platform
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4

from .models import Finding
from .privacy import scrub_text

try:  # pragma: no cover - imported only on Windows
    import winreg
except ImportError:  # pragma: no cover - non-Windows
    winreg = None  # type: ignore[assignment]


CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def _windows_system_tool(name: str) -> str:
    """Resolve a Windows system binary to its absolute path under %SystemRoot%.

    These checks frequently run inside an elevated process. Resolving by
    absolute path stops a binary planted in a user-writable PATH entry from
    being executed in place of the genuine system tool. Falls back to the bare
    name when the expected file is absent so unusual installs behave as before.
    """
    if platform.system() != "Windows":
        return name
    system_root = os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows"
    if name.lower() == "powershell.exe":
        candidate = os.path.join(system_root, "System32", "WindowsPowerShell", "v1.0", name)
    else:
        candidate = os.path.join(system_root, "System32", name)
    return candidate if os.path.isfile(candidate) else name


SEVERITY_SCORE = {"critical": 95.0, "high": 78.0, "medium": 54.0, "low": 26.0, "info": 8.0}
PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}

AUTOLOGON_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
INSTALLER_POLICY_KEY = r"SOFTWARE\Policies\Microsoft\Windows\Installer"
SCRIPT_BLOCK_LOGGING_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
MODULE_LOGGING_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
TRANSCRIPTION_KEY = r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription"
LSA_KEY = r"SYSTEM\CurrentControlSet\Control\Lsa"
CREDENTIAL_GUARD_KEY = r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard"
DEFENDER_FEATURES_KEY = r"SOFTWARE\Microsoft\Windows Defender\Features"

RISKY_PRIVILEGES = {
    "SeDebugPrivilege": "debug running processes",
    "SeImpersonatePrivilege": "impersonate authenticated clients",
    "SeAssignPrimaryTokenPrivilege": "assign primary process identity context",
    "SeBackupPrivilege": "read protected files for backup",
    "SeRestorePrivilege": "write protected files during restore",
    "SeTakeOwnershipPrivilege": "take ownership of protected objects",
    "SeLoadDriverPrivilege": "load kernel drivers",
}

SECRET_PATTERNS = {
    "password": re.compile(
        r"(?i)\b(?:password|passwd|pwd|defaultpassword|cpassword)\b\s*(?:=|:|>|&quot;|\"|')\s*[^<\r\n,;\"]+"
    ),
    "connection_string": re.compile(r"(?i)\b(?:connectionstring|connectionStrings)\b.{0,220}\b(?:password|pwd)\b"),
    "private_key": re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    "api_key": re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|access[_-]?key)\b\s*(?:=|:)\s*[^\s,;]+"),
    "autologon": re.compile(r"(?i)\b(?:AutoAdminLogon|DefaultPassword|DefaultUserName)\b"),
}


@dataclass(slots=True)
class WindowsPrivescAuditResult:
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def _finding(
    *,
    rule_id: str,
    title: str,
    severity: str,
    confidence: float,
    category: str,
    plain_english: str,
    recommended_actions: list[str],
    evidence: dict[str, Any],
) -> Finding:
    clean_severity = severity if severity in SEVERITY_SCORE else "medium"
    return Finding(
        finding_id=f"hg_privesc_{uuid4().hex[:16]}",
        rule_id=rule_id,
        title=title,
        severity=clean_severity,
        confidence=confidence,
        risk_score=round(SEVERITY_SCORE[clean_severity] * confidence, 2),
        priority=PRIORITY[clean_severity],
        category=category,
        device_ip="local-host",
        device_name="This PC",
        plain_english=plain_english,
        recommended_actions=recommended_actions,
        evidence=_scrub_evidence(evidence),
    )


def _scrub_evidence(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _scrub_evidence(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_scrub_evidence(item) for item in value]
    if isinstance(value, tuple):
        return [_scrub_evidence(item) for item in value]
    if isinstance(value, str):
        return scrub_text(_redact_inline_secret_values(value))
    return value


def _redact_inline_secret_values(text: str) -> str:
    cleaned = str(text or "")
    cleaned = re.sub(
        r"(?i)(\b(?:password|passwd|pwd|defaultpassword|cpassword|api[_-]?key|client[_-]?secret)\b\s*(?:=|:)\s*)[^\s,;]+",
        r"\1<redacted>",
        cleaned,
    )
    cleaned = re.sub(
        r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        "<redacted private key>",
        cleaned,
        flags=re.IGNORECASE | re.DOTALL,
    )
    return cleaned


def secret_types_in_text(text: str) -> list[str]:
    found = [name for name, pattern in SECRET_PATTERNS.items() if pattern.search(text or "")]
    return sorted(set(found))


def secret_evidence(location: str, text: str) -> dict[str, Any]:
    return {
        "location": scrub_text(location),
        "secret_types": secret_types_in_text(text),
        "secret_values_redacted": True,
    }


def read_registry_value(root: str, subkey: str, name: str) -> Any:
    if platform.system() != "Windows" or winreg is None:
        return None
    roots = {
        "HKLM": winreg.HKEY_LOCAL_MACHINE,
        "HKCU": winreg.HKEY_CURRENT_USER,
    }
    hive = roots.get(root.upper())
    if hive is None:
        return None
    try:
        with winreg.OpenKey(hive, subkey) as handle:
            value, _kind = winreg.QueryValueEx(handle, name)
            return value
    except OSError:
        return None


def _reg_enabled(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "enabled"}


def check_always_install_elevated(
    registry_reader: Callable[[str, str, str], Any] = read_registry_value,
) -> list[Finding]:
    hklm = _reg_enabled(registry_reader("HKLM", INSTALLER_POLICY_KEY, "AlwaysInstallElevated"))
    hkcu = _reg_enabled(registry_reader("HKCU", INSTALLER_POLICY_KEY, "AlwaysInstallElevated"))
    if not hklm and not hkcu:
        return []
    both_enabled = hklm and hkcu
    return [
        _finding(
            rule_id="windows_privesc_always_install_elevated",
            title="Windows Installer elevation policy is risky",
            severity="high" if both_enabled else "medium",
            confidence=0.9 if both_enabled else 0.76,
            category="windows_privesc",
            plain_english=(
                "Windows Installer policy is configured in a way that can let installer packages run with elevated local rights."
                if both_enabled
                else "One Windows Installer elevation policy value is enabled. The paired machine/user setting should be reviewed."
            ),
            recommended_actions=[
                "Disable AlwaysInstallElevated in both machine and user policy unless there is a documented business need.",
                "Review local administrators and software deployment policy after changing this setting.",
            ],
            evidence={
                "hklm_policy_enabled": hklm,
                "hkcu_policy_enabled": hkcu,
                "registry_values": [
                    r"HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated",
                    r"HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated",
                ],
            },
        )
    ]


def check_autologon(
    registry_reader: Callable[[str, str, str], Any] = read_registry_value,
) -> list[Finding]:
    enabled = _reg_enabled(registry_reader("HKLM", AUTOLOGON_KEY, "AutoAdminLogon"))
    default_user = registry_reader("HKLM", AUTOLOGON_KEY, "DefaultUserName")
    default_password = registry_reader("HKLM", AUTOLOGON_KEY, "DefaultPassword")
    if not enabled and not default_password:
        return []
    secret_types = ["password"] if default_password else []
    if default_user:
        secret_types.append("username")
    return [
        _finding(
            rule_id="windows_privesc_autologon_secret",
            title="Windows AutoLogon configuration should be reviewed",
            severity="high" if default_password else "medium",
            confidence=0.88 if default_password else 0.72,
            category="windows_credential_exposure",
            plain_english=(
                "Windows AutoLogon appears to have saved sign-in material in the registry."
                if default_password
                else "Windows AutoLogon appears enabled. This can weaken local account protection even when no password value was readable."
            ),
            recommended_actions=[
                "Disable AutoLogon unless the device is intentionally kiosk-style and physically controlled.",
                "Rotate the affected local or domain account password if a saved password was present.",
            ],
            evidence={
                "registry_key": r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                "autologon_enabled": enabled,
                "secret_types": sorted(set(secret_types)),
                "secret_values_redacted": True,
            },
        )
    ]


def _system_root() -> Path:
    return Path(os.environ.get("SystemRoot") or os.environ.get("WINDIR") or r"C:\Windows")


def _program_data() -> Path:
    return Path(os.environ.get("ProgramData") or r"C:\ProgramData")


def _bounded_file_candidates() -> dict[str, list[Path]]:
    system_root = _system_root()
    return {
        "unattended_install": [
            system_root / "Panther" / "Unattend.xml",
            system_root / "Panther" / "Unattended.xml",
            system_root / "Panther" / "unattend.xml",
            system_root / "System32" / "Sysprep" / "Unattend.xml",
            system_root / "System32" / "Sysprep" / "Panther" / "Unattend.xml",
        ],
        "iis_or_web_config": [
            system_root / "System32" / "inetsrv" / "config" / "applicationHost.config",
            Path(r"C:\inetpub\wwwroot\web.config"),
            Path(r"C:\inetpub\wwwroot\appsettings.json"),
        ],
    }


def _read_text_sample(path: Path, *, max_bytes: int = 1024 * 1024) -> str:
    try:
        with path.open("rb") as handle:
            data = handle.read(max_bytes)
    except OSError:
        return ""
    return data.decode("utf-8", errors="ignore")


def _iter_bounded_files(
    roots: Iterable[Path],
    *,
    names: set[str],
    max_files: int = 80,
    max_depth: int = 6,
) -> Iterable[Path]:
    emitted = 0
    for root in roots:
        if emitted >= max_files or not root.exists():
            continue
        base_depth = len(root.parts)
        for current, dirnames, filenames in os.walk(root):
            current_path = Path(current)
            depth = len(current_path.parts) - base_depth
            if depth >= max_depth:
                dirnames[:] = []
            for filename in filenames:
                if filename.lower() not in names:
                    continue
                emitted += 1
                yield current_path / filename
                if emitted >= max_files:
                    return


def _file_secret_findings(paths: Iterable[Path], *, rule_id: str, title: str, source: str) -> list[Finding]:
    findings: list[Finding] = []
    for path in paths:
        if not path.exists() or not path.is_file():
            continue
        sample = _read_text_sample(path)
        secret_types = secret_types_in_text(sample)
        if not secret_types:
            continue
        findings.append(
            _finding(
                rule_id=rule_id,
                title=title,
                severity="high" if "password" in secret_types or "private_key" in secret_types else "medium",
                confidence=0.78,
                category="windows_credential_exposure",
                plain_english=f"HomeGuard found a known {source} file location containing secret-like fields.",
                recommended_actions=[
                    "Remove saved secrets from configuration files when possible and use a protected secret store.",
                    "Rotate any affected credentials from a trusted device.",
                    "Restrict file permissions so standard users cannot read sensitive configuration files.",
                ],
                evidence={
                    **secret_evidence(str(path), sample),
                    "file_name": path.name,
                    "source": source,
                },
            )
        )
    return findings


def check_unattended_install_files() -> list[Finding]:
    return _file_secret_findings(
        _bounded_file_candidates()["unattended_install"],
        rule_id="windows_privesc_unattended_install_secret",
        title="Unattended Windows install file may contain saved secrets",
        source="unattended_install_file",
    )


def check_gpp_password_files() -> list[Finding]:
    roots = [
        _program_data() / "Microsoft" / "Group Policy" / "History",
        _system_root() / "SYSVOL",
        _system_root() / "System32" / "GroupPolicy",
    ]
    names = {"groups.xml", "services.xml", "scheduledtasks.xml", "datasources.xml", "printers.xml", "drives.xml"}
    return _file_secret_findings(
        _iter_bounded_files(roots, names=names, max_files=80, max_depth=7),
        rule_id="windows_privesc_gpp_password_file",
        title="Cached Group Policy Preferences file may contain saved secrets",
        source="group_policy_preferences_cache",
    )


def check_iis_and_web_config_files() -> list[Finding]:
    return _file_secret_findings(
        _bounded_file_candidates()["iis_or_web_config"],
        rule_id="windows_privesc_web_config_secret",
        title="Web or IIS configuration file may contain saved secrets",
        source="web_or_iis_config",
    )


def _run_command(args: list[str], *, timeout: int = 15) -> subprocess.CompletedProcess[str] | None:
    try:
        return subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return None


def _run_powershell_json(script: str, *, timeout: int = 20) -> list[dict[str, Any]]:
    result = _run_command([_windows_system_tool("powershell.exe"), "-NoProfile", "-Command", script], timeout=timeout)
    if not result or result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    if isinstance(payload, dict):
        return [payload]
    return [row for row in payload if isinstance(row, dict)] if isinstance(payload, list) else []


def query_services() -> list[dict[str, str]]:
    if platform.system() != "Windows":
        return []
    rows = _run_powershell_json(
        "Get-CimInstance Win32_Service | "
        "Select-Object Name,DisplayName,PathName,StartName | "
        "ConvertTo-Json -Compress",
        timeout=25,
    )
    services: list[dict[str, str]] = []
    for row in rows:
        services.append(
            {
                "name": str(row.get("Name") or ""),
                "display_name": str(row.get("DisplayName") or ""),
                "path": str(row.get("PathName") or ""),
                "start_name": str(row.get("StartName") or ""),
            }
        )
    return services


def extract_executable_path(command: str) -> str:
    text = str(command or "").strip()
    if not text:
        return ""
    if text.startswith('"'):
        end = text.find('"', 1)
        return text[1:end].strip() if end > 1 else ""
    lowered = text.lower()
    endings = [".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js"]
    positions = [(lowered.find(ending), ending) for ending in endings if lowered.find(ending) >= 0]
    if positions:
        position, ending = min(positions, key=lambda item: item[0])
        return text[: position + len(ending)].strip()
    return text.split()[0].strip()


def is_unquoted_service_path_risky(command: str) -> bool:
    text = str(command or "").strip()
    if not text or text.startswith('"'):
        return False
    exe_path = extract_executable_path(text)
    return bool(exe_path and " " in exe_path and Path(exe_path).suffix.lower() in {".exe", ".com", ".bat", ".cmd"})


def _is_system_path(path: str | Path) -> bool:
    text = str(path or "").replace("/", "\\").lower()
    system_root = str(_system_root()).replace("/", "\\").lower()
    return text.startswith(system_root.lower() + "\\system32\\") or text.startswith(system_root.lower() + "\\syswow64\\")


def _is_user_writable_location(path: str | Path) -> bool:
    lowered = str(path or "").replace("/", "\\").lower()
    markers = (
        "\\users\\",
        "\\appdata\\",
        "\\temp\\",
        "\\tmp\\",
        "\\downloads\\",
        "\\programdata\\",
    )
    return any(marker in lowered for marker in markers)


def path_is_writable(path: str | Path) -> bool:
    target = Path(path)
    candidates = [target]
    if target.suffix:
        candidates.append(target.parent)
    for candidate in candidates:
        try:
            if candidate.exists() and os.access(candidate, os.W_OK):
                return True
        except OSError:
            continue
    return False


def classify_scheduled_task_command(
    command: str,
    *,
    is_writable_path: Callable[[str | Path], bool] | None = None,
) -> dict[str, Any]:
    exe_path = extract_executable_path(command)
    if not exe_path:
        return {"path": "", "risky": False, "reason": "empty"}
    if _is_system_path(exe_path):
        if is_writable_path is not None and is_writable_path(exe_path):
            return {"path": exe_path, "risky": True, "reason": "path_or_directory_writable"}
        return {"path": exe_path, "risky": False, "reason": "windows_system_path"}
    writable_checker = is_writable_path or path_is_writable
    if _is_user_writable_location(exe_path):
        return {"path": exe_path, "risky": True, "reason": "user_writable_location"}
    if writable_checker(exe_path):
        return {"path": exe_path, "risky": True, "reason": "path_or_directory_writable"}
    return {"path": exe_path, "risky": False, "reason": "not_writable_or_not_risky"}


def check_service_paths(services: Iterable[dict[str, str]] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for service in list(services if services is not None else query_services())[:120]:
        command = str(service.get("path") or "")
        exe_path = extract_executable_path(command)
        service_name = str(service.get("name") or service.get("display_name") or "service")
        if is_unquoted_service_path_risky(command):
            findings.append(
                _finding(
                    rule_id="windows_privesc_unquoted_service_path",
                    title=f"Unquoted service path with spaces: {service_name}",
                    severity="medium",
                    confidence=0.76,
                    category="windows_service_hardening",
                    plain_english="A Windows service path contains spaces and is not quoted. This can create a path interception risk.",
                    recommended_actions=[
                        "Quote the full service executable path in the service ImagePath value.",
                        "Keep service executables under protected directories with standard user write access removed.",
                    ],
                    evidence={"service": service_name, "path_hint": exe_path, "source": "Win32_Service"},
                )
            )
        if exe_path and path_is_writable(exe_path):
            findings.append(
                _finding(
                    rule_id="windows_privesc_writable_service_binary",
                    title=f"Service executable appears writable: {service_name}",
                    severity="high",
                    confidence=0.72,
                    category="windows_service_hardening",
                    plain_english="The service executable path appears writable from this account. That can let local users alter service code.",
                    recommended_actions=[
                        "Move the service executable to a protected directory or remove standard user write permissions.",
                        "Restart the service only after confirming the executable is trusted.",
                    ],
                    evidence={"service": service_name, "path_hint": exe_path, "source": "filesystem_access_check"},
                )
            )
        parent = str(Path(exe_path).parent) if exe_path else ""
        if parent and path_is_writable(parent):
            findings.append(
                _finding(
                    rule_id="windows_privesc_writable_service_directory",
                    title=f"Service directory appears writable: {service_name}",
                    severity="high",
                    confidence=0.72,
                    category="windows_service_hardening",
                    plain_english="The service executable directory appears writable from this account. This can enable service file replacement or path interception.",
                    recommended_actions=[
                        "Remove write permissions for standard users from service directories.",
                        "Review other files in the directory for unexpected changes.",
                    ],
                    evidence={"service": service_name, "directory_hint": parent, "source": "filesystem_access_check"},
                )
            )
    return findings


def service_sddl_has_weak_permissions(sddl: str) -> bool:
    weak_trustees = {"WD", "BU", "AU", "IU", "SU"}
    weak_rights = {"GA", "KA", "RP", "WP", "DT", "WD", "WO"}
    for ace in re.findall(r"\(([^)]+)\)", sddl or ""):
        parts = ace.split(";")
        if len(parts) < 6 or parts[0] != "A":
            continue
        rights = parts[2]
        trustee = parts[5]
        if trustee in weak_trustees and any(right in rights for right in weak_rights):
            return True
    return False


def check_weak_service_permissions(services: Iterable[dict[str, str]] | None = None, *, max_services: int = 60) -> list[Finding]:
    if platform.system() != "Windows":
        return []
    findings: list[Finding] = []
    for service in list(services if services is not None else query_services())[:max_services]:
        name = str(service.get("name") or "")
        if not name:
            continue
        result = _run_command([_windows_system_tool("sc.exe"), "sdshow", name], timeout=5)
        if not result or result.returncode != 0 or not service_sddl_has_weak_permissions(result.stdout):
            continue
        findings.append(
            _finding(
                rule_id="windows_privesc_weak_service_permissions",
                title=f"Service permissions should be tightened: {name}",
                severity="high",
                confidence=0.7,
                category="windows_service_hardening",
                plain_english="The service security descriptor appears to grant broad users rights that can change or control the service.",
                recommended_actions=[
                    "Restrict service control and configuration permissions to Administrators and the service owner.",
                    "Review the service owner, executable path, and recent changes before restarting it.",
                ],
                evidence={"service": name, "source": "sc_sdshow", "sddl_value_redacted": True},
            )
        )
    return findings


def query_scheduled_tasks() -> list[dict[str, str]]:
    if platform.system() != "Windows":
        return []
    result = _run_command([_windows_system_tool("schtasks.exe"), "/Query", "/FO", "CSV", "/V"], timeout=25)
    if not result or result.returncode != 0:
        return []
    tasks: list[dict[str, str]] = []
    for row in csv.DictReader(result.stdout.splitlines()):
        command = row.get("Task To Run") or ""
        task_name = row.get("TaskName") or row.get("Task Name") or ""
        if command and command.upper() != "N/A":
            tasks.append({"name": task_name, "command": command})
    return tasks


def check_scheduled_tasks(tasks: Iterable[dict[str, str]] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for task in list(tasks if tasks is not None else query_scheduled_tasks())[:160]:
        command = str(task.get("command") or "")
        classification = classify_scheduled_task_command(command)
        if not classification["risky"]:
            continue
        findings.append(
            _finding(
                rule_id="windows_privesc_modifiable_scheduled_task_path",
                title=f"Scheduled task executable path should be reviewed: {task.get('name') or 'task'}",
                severity="medium",
                confidence=0.7,
                category="windows_scheduled_task_hardening",
                plain_english="A scheduled task points to a path that appears user-writable or otherwise risky.",
                recommended_actions=[
                    "Move scheduled task executables to protected directories.",
                    "Remove write permissions for standard users from task executable paths.",
                ],
                evidence={
                    "task_name": str(task.get("name") or ""),
                    "path_hint": classification["path"],
                    "risk_reason": classification["reason"],
                },
            )
        )
    return findings


def check_path_directories() -> list[Finding]:
    findings: list[Finding] = []
    seen: set[str] = set()
    for item in os.environ.get("PATH", "").split(os.pathsep):
        if not item:
            continue
        path = str(Path(item))
        key = path.lower()
        if key in seen or _is_system_path(path):
            continue
        seen.add(key)
        if not (_is_user_writable_location(path) or path_is_writable(path)):
            continue
        findings.append(
            _finding(
                rule_id="windows_privesc_user_writable_path_directory",
                title="Executable search path includes a writable directory",
                severity="medium",
                confidence=0.68,
                category="windows_path_hardening",
                plain_english="The executable search path includes a directory that appears writable. This can allow path interception when software starts helper programs.",
                recommended_actions=[
                    "Remove user-writable directories from the system PATH where possible.",
                    "Prefer fully qualified executable paths in services and scheduled tasks.",
                ],
                evidence={"directory_hint": path, "source": "PATH_environment"},
            )
        )
    return findings[:10]


def check_whoami_privileges() -> list[Finding]:
    if platform.system() != "Windows":
        return []
    result = _run_command([_windows_system_tool("whoami.exe"), "/priv"], timeout=10)
    if not result or result.returncode != 0:
        return []
    findings: list[Finding] = []
    for line in result.stdout.splitlines():
        match = re.search(r"\b(Se[A-Za-z0-9]+Privilege)\b.*\bEnabled\b", line)
        if not match:
            continue
        privilege = match.group(1)
        if privilege not in RISKY_PRIVILEGES:
            continue
        findings.append(
            _finding(
                rule_id="windows_privesc_sensitive_privilege_enabled",
                title=f"Sensitive Windows privilege is enabled: {privilege}",
                severity="medium",
                confidence=0.72,
                category="windows_privesc",
                plain_english=f"The current account has an enabled Windows privilege that can {RISKY_PRIVILEGES[privilege]}.",
                recommended_actions=[
                    "Use a standard daily account and reserve admin rights for intentional maintenance.",
                    "Review local group membership and remove unnecessary administrative roles.",
                ],
                evidence={"privilege": privilege, "source": "whoami_priv"},
            )
        )
    return findings


def check_powershell_v2() -> list[Finding]:
    if platform.system() != "Windows":
        return []
    rows = _run_powershell_json(
        "Get-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root | "
        "Select-Object FeatureName,State | ConvertTo-Json -Compress",
        timeout=20,
    )
    state = str(rows[0].get("State") or "") if rows else ""
    if state.lower() not in {"enabled", "enablepending"}:
        return []
    return [
        _finding(
            rule_id="windows_hardening_powershell_v2_enabled",
            title="PowerShell v2 appears enabled",
            severity="medium",
            confidence=0.78,
            category="windows_powershell_hardening",
            plain_english="PowerShell v2 lacks modern logging and security controls and should be disabled on current Windows systems.",
            recommended_actions=[
                "Disable the Windows PowerShell v2 optional feature if you do not need legacy compatibility.",
                "Keep PowerShell 5 or newer logging enabled for defensive visibility.",
            ],
            evidence={"feature": "MicrosoftWindowsPowerShellV2Root", "state": state},
        )
    ]


def _logging_enabled(
    key: str,
    value_name: str,
    registry_reader: Callable[[str, str, str], Any] = read_registry_value,
) -> bool:
    return _reg_enabled(registry_reader("HKLM", key, value_name)) or _reg_enabled(registry_reader("HKCU", key, value_name))


def check_powershell_logging(
    registry_reader: Callable[[str, str, str], Any] = read_registry_value,
) -> list[Finding]:
    checks = [
        ("script_block_logging", SCRIPT_BLOCK_LOGGING_KEY, "EnableScriptBlockLogging", "PowerShell script block logging is not enabled"),
        ("module_logging", MODULE_LOGGING_KEY, "EnableModuleLogging", "PowerShell module logging is not enabled"),
        ("transcription", TRANSCRIPTION_KEY, "EnableTranscripting", "PowerShell transcription is not enabled"),
    ]
    findings: list[Finding] = []
    for rule_suffix, key, value_name, title in checks:
        if _logging_enabled(key, value_name, registry_reader):
            continue
        findings.append(
            _finding(
                rule_id=f"windows_hardening_{rule_suffix}_disabled",
                title=title,
                severity="low",
                confidence=0.74,
                category="windows_powershell_hardening",
                plain_english="HomeGuard could not confirm this PowerShell logging control is enabled by policy.",
                recommended_actions=[
                    "Enable PowerShell logging through Group Policy or local policy.",
                    "Forward PowerShell logs to a protected location if you have central logging available.",
                ],
                evidence={"registry_key": rf"HKLM/HKCU\{key}", "value": value_name, "enabled": False},
            )
        )
    return findings


def check_lsass_and_credential_guard(
    registry_reader: Callable[[str, str, str], Any] = read_registry_value,
) -> list[Finding]:
    findings: list[Finding] = []
    run_as_ppl = registry_reader("HKLM", LSA_KEY, "RunAsPPL")
    if not _reg_enabled(run_as_ppl):
        findings.append(
            _finding(
                rule_id="windows_hardening_lsass_protection_disabled",
                title="LSASS protected process mode is not confirmed",
                severity="medium",
                confidence=0.72,
                category="windows_credential_hardening",
                plain_english="HomeGuard could not confirm LSASS protected process mode is enabled.",
                recommended_actions=[
                    "Enable LSASS protection where supported and test line-of-business compatibility first.",
                    "Keep endpoint protection and credential theft mitigations enabled.",
                ],
                evidence={"registry_key": rf"HKLM\{LSA_KEY}", "value": "RunAsPPL", "enabled": False},
            )
        )
    credential_guard = registry_reader("HKLM", CREDENTIAL_GUARD_KEY, "Enabled")
    if not _reg_enabled(credential_guard):
        findings.append(
            _finding(
                rule_id="windows_hardening_credential_guard_disabled",
                title="Credential Guard is not confirmed",
                severity="medium",
                confidence=0.68,
                category="windows_credential_hardening",
                plain_english="HomeGuard could not confirm Windows Credential Guard is enabled on this PC.",
                recommended_actions=[
                    "Enable Credential Guard on supported Windows editions and hardware.",
                    "Use standard user accounts for daily work even when hardware-backed protection is available.",
                ],
                evidence={"registry_key": rf"HKLM\{CREDENTIAL_GUARD_KEY}", "value": "Enabled", "enabled": False},
            )
        )
    return findings


def check_defender_status(
    registry_reader: Callable[[str, str, str], Any] = read_registry_value,
) -> list[Finding]:
    findings: list[Finding] = []
    rows = _run_powershell_json(
        "Get-MpPreference | "
        "Select-Object DisableRealtimeMonitoring,DisableBehaviorMonitoring,DisableIOAVProtection,"
        "DisableBlockAtFirstSeen,DisableScriptScanning,MAPSReporting,SubmitSamplesConsent,CloudBlockLevel | "
        "ConvertTo-Json -Compress",
        timeout=15,
    )
    if rows:
        prefs = rows[0]
        disabled_controls = [
            name
            for name in (
                "DisableRealtimeMonitoring",
                "DisableBehaviorMonitoring",
                "DisableIOAVProtection",
                "DisableScriptScanning",
            )
            if _reg_enabled(prefs.get(name))
        ]
        if disabled_controls:
            findings.append(
                _finding(
                    rule_id="windows_hardening_defender_core_controls_disabled",
                    title="Microsoft Defender protection controls appear disabled",
                    severity="high",
                    confidence=0.82,
                    category="windows_defender_hardening",
                    plain_english="One or more Defender protection controls appear disabled.",
                    recommended_actions=[
                        "Re-enable Defender real-time, behavior, script, and downloaded-file scanning unless another managed endpoint tool is active.",
                        "Run a full Defender scan after restoring protection.",
                    ],
                    evidence={"disabled_controls": disabled_controls, "source": "Get-MpPreference"},
                )
            )
        cloud_reporting = int(prefs.get("MAPSReporting") or 0) if str(prefs.get("MAPSReporting") or "0").isdigit() else 0
        block_at_first_seen_disabled = _reg_enabled(prefs.get("DisableBlockAtFirstSeen"))
        if cloud_reporting <= 0 or block_at_first_seen_disabled:
            findings.append(
                _finding(
                    rule_id="windows_hardening_defender_cloud_protection_weak",
                    title="Defender cloud protection should be strengthened",
                    severity="medium",
                    confidence=0.74,
                    category="windows_defender_hardening",
                    plain_english="HomeGuard could not confirm Defender cloud protection and block-at-first-sight protections are fully enabled.",
                    recommended_actions=[
                        "Enable Defender cloud-delivered protection and automatic sample submission according to your privacy policy.",
                        "Keep security intelligence updates current.",
                    ],
                    evidence={
                        "maps_reporting": cloud_reporting,
                        "block_at_first_seen_disabled": block_at_first_seen_disabled,
                        "source": "Get-MpPreference",
                    },
                )
            )
    tamper_value = registry_reader("HKLM", DEFENDER_FEATURES_KEY, "TamperProtection")
    if tamper_value is not None and str(tamper_value) not in {"5", "4"}:
        findings.append(
            _finding(
                rule_id="windows_hardening_defender_tamper_protection_off",
                title="Defender Tamper Protection is not confirmed",
                severity="medium",
                confidence=0.68,
                category="windows_defender_hardening",
                plain_english="HomeGuard could not confirm Defender Tamper Protection is enabled.",
                recommended_actions=[
                    "Enable Tamper Protection in Windows Security when Defender is your primary endpoint protection.",
                    "If another endpoint product manages this setting, confirm the managed policy state.",
                ],
                evidence={"registry_key": rf"HKLM\{DEFENDER_FEATURES_KEY}", "value": "TamperProtection", "enabled": False},
            )
        )
    return findings


def _base_metadata() -> dict[str, Any]:
    return {
        "privesc_audit_enabled": True,
        "privesc_audit_platform": platform.system(),
        "privesc_checks_run": [],
        "privesc_checks_skipped": [],
        "privesc_audit_partial_results": False,
        "privesc_audit_safety": "passive_bounded_no_exploitation",
    }


def run_windows_privesc_audit() -> WindowsPrivescAuditResult:
    metadata = _base_metadata()
    findings: list[Finding] = []
    if platform.system() != "Windows":
        metadata["privesc_checks_skipped"].append("non_windows_platform")
        return WindowsPrivescAuditResult(findings=findings, metadata=metadata)

    services_cache: list[dict[str, str]] | None = None
    checks: list[tuple[str, Callable[[], list[Finding]]]] = [
        ("always_install_elevated", check_always_install_elevated),
        ("autologon", check_autologon),
        ("unattended_install_files", check_unattended_install_files),
        ("gpp_password_files", check_gpp_password_files),
        ("iis_and_web_config_files", check_iis_and_web_config_files),
        ("scheduled_tasks", check_scheduled_tasks),
        ("path_directories", check_path_directories),
        ("whoami_privileges", check_whoami_privileges),
        ("powershell_v2", check_powershell_v2),
        ("powershell_logging", check_powershell_logging),
        ("lsass_and_credential_guard", check_lsass_and_credential_guard),
        ("defender_status", check_defender_status),
    ]

    def service_path_check() -> list[Finding]:
        nonlocal services_cache
        services_cache = services_cache if services_cache is not None else query_services()
        return check_service_paths(services_cache)

    def service_permission_check() -> list[Finding]:
        nonlocal services_cache
        services_cache = services_cache if services_cache is not None else query_services()
        return check_weak_service_permissions(services_cache)

    checks.insert(5, ("service_paths", service_path_check))
    checks.insert(6, ("service_permissions", service_permission_check))

    for name, check in checks:
        try:
            findings.extend(check())
            metadata["privesc_checks_run"].append(name)
        except Exception as exc:  # pragma: no cover - defensive
            metadata["privesc_checks_skipped"].append({"check": name, "reason": scrub_text(str(exc))})
            metadata["privesc_audit_partial_results"] = True

    metadata["privesc_findings_emitted"] = len(findings)
    if metadata["privesc_checks_skipped"]:
        metadata["privesc_audit_partial_results"] = True
    return WindowsPrivescAuditResult(findings=findings, metadata=metadata)


def audit_windows_privesc() -> list[Finding]:
    return run_windows_privesc_audit().findings

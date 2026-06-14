"""Local endpoint malware indicator scanner.

This is not a replacement for a full antivirus engine. It layers local endpoint
checks onto HomeGuard scans: running process inspection, internal file and
browser download review, startup persistence review, and a bounded best-effort
process-memory string scan.
"""

from __future__ import annotations

import csv
import ctypes
import hashlib
import json
import math
import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable
from uuid import uuid4

from .logging_setup import get_logger
from .models import Finding
from .privacy import scrub_text
from .windows_privesc_audit import run_windows_privesc_audit

LOG = get_logger("virus_scanner")
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)

SEVERITY_SCORE = {"critical": 95.0, "high": 78.0, "medium": 54.0, "low": 26.0, "info": 8.0}
PRIORITY = {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}

EXECUTABLE_DOWNLOAD_SUFFIXES = {
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".hta",
    ".iso",
    ".jar",
    ".js",
    ".jse",
    ".lnk",
    ".msi",
    ".ps1",
    ".scr",
    ".vbe",
    ".vbs",
    ".wsf",
}

SUSPICIOUS_PROCESS_NAMES = {
    "mimikatz.exe",
    "nc.exe",
    "netcat.exe",
    "psexec.exe",
    "powersploit.exe",
    "procdump.exe",
}

SUSPICIOUS_CMD_PATTERNS = [
    (re.compile(r"\b-enc(?:odedcommand)?\b", re.IGNORECASE), "PowerShell encoded command"),
    (re.compile(r"\bfrombase64string\b", re.IGNORECASE), "Base64 loader behavior"),
    (re.compile(r"\biex\b|\binvoke-expression\b", re.IGNORECASE), "PowerShell invoke-expression"),
    (re.compile(r"\bdownloadstring\b|\bdownloadfile\b", re.IGNORECASE), "Download cradle behavior"),
    (re.compile(r"\bcertutil\b.*\b(?:urlcache|decode)\b", re.IGNORECASE), "Certutil download/decode behavior"),
    (re.compile(r"\bbitsadmin\b.*\btransfer\b", re.IGNORECASE), "BITS transfer behavior"),
    (re.compile(r"\bmshta\b.*https?://", re.IGNORECASE), "MSHTA remote script execution"),
    (re.compile(r"\bregsvr32\b.*https?://", re.IGNORECASE), "Regsvr32 remote script execution"),
    (re.compile(r"\brundll32\b.*javascript:", re.IGNORECASE), "Rundll32 JavaScript execution"),
]

MEMORY_SIGNATURES = {
    b"invoke-mimikatz": "Mimikatz-style credential theft artifact",
    b"sekurlsa::": "Credential dumping command artifact",
    b"meterpreter": "Meterpreter artifact",
    b"cobalt strike": "Cobalt Strike artifact",
    b"beacon.x64": "Beacon artifact",
    b"frombase64string": "In-memory Base64 loader artifact",
    b"downloadstring": "In-memory download cradle artifact",
}

ENDPOINT_ABUSE_SIGNATURE_METADATA: dict[str, dict[str, Any]] = {}

FILE_CONTENT_SIGNATURES = [
    (
        re.compile(rb"X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*", re.IGNORECASE),
        "EICAR antivirus test signature",
        "critical",
        0.99,
    ),
    (re.compile(rb"HOMEGUARD-INTERNAL-SCANNER-TEST-SIGNATURE", re.IGNORECASE), "HomeGuard internal scanner test signature", "critical", 0.99),
    (re.compile(rb"invoke-mimikatz|sekurlsa::", re.IGNORECASE), "Credential theft script artifact", "high", 0.78),
    (re.compile(rb"mimikatz|kiwi::|lsadump::", re.IGNORECASE), "Credential dumping tool artifact", "high", 0.72),
    (re.compile(rb"meterpreter|cobalt strike|beacon\.x64|beacon\.x86", re.IGNORECASE), "Offensive payload artifact", "high", 0.68),
    (
        re.compile(rb"frombase64string|downloadstring|invoke-expression|\biex\b", re.IGNORECASE),
        "PowerShell loader or download cradle artifact",
        "high",
        0.62,
    ),
    (re.compile(rb"powershell(?:\.exe)?\s+-enc(?:odedcommand)?\b", re.IGNORECASE), "Encoded PowerShell command", "high", 0.7),
    (re.compile(rb"certutil(?:\.exe)?.{0,160}\b(?:urlcache|decode)\b", re.IGNORECASE), "Certutil download/decode behavior", "medium", 0.64),
    (re.compile(rb"mshta(?:\.exe)?.{0,160}https?://", re.IGNORECASE), "MSHTA remote script execution", "high", 0.66),
    (re.compile(rb"regsvr32(?:\.exe)?.{0,160}https?://", re.IGNORECASE), "Regsvr32 remote script execution", "high", 0.66),
]

TEXT_LIKE_SUFFIXES = {
    ".bat",
    ".cmd",
    ".hta",
    ".js",
    ".jse",
    ".ps1",
    ".txt",
    ".vbe",
    ".vbs",
    ".wsf",
}

ARCHIVE_SUFFIXES = {".7z", ".cab", ".gz", ".rar", ".tar", ".zip"}

# Native executable image suffixes. The entropy heuristic only fires on these
# (and only when the file actually starts with the PE "MZ" magic) so the high
# false-positive risk of "this file looks packed" stays scoped to real
# Windows binaries rather than every compressed asset on disk.
EXECUTABLE_BINARY_SUFFIXES = {".exe", ".dll", ".scr", ".sys", ".com", ".cpl", ".ocx", ".efi"}

# Shannon entropy at/above this (out of 8.0) means the bytes are close to
# random — the signature of packing or encryption. Legitimate installers are
# often packed too, so this is a low-severity hint, never an auto-remediation
# trigger.
ENTROPY_PACKED_THRESHOLD = 7.2
ENTROPY_SAMPLE_BYTES = 256 * 1024

# On-demand scans inspect more of each file than the passive download sweep,
# since the user explicitly pointed HomeGuard at the target.
ONDEMAND_MAX_BYTES_PER_FILE = 8 * 1024 * 1024

DOUBLE_EXTENSION_RE = re.compile(
    r"\.(?:doc|docx|htm|html|jpg|jpeg|pdf|png|rtf|txt|xls|xlsx)\.(?:bat|cmd|com|exe|hta|js|jse|lnk|ps1|scr|vbe|vbs|wsf)$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class EndpointScanResult:
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
        finding_id=f"hg_endpoint_{uuid4().hex[:16]}",
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
        evidence=evidence,
    )


def _abuse_metadata(label: str) -> dict[str, Any]:
    metadata = ENDPOINT_ABUSE_SIGNATURE_METADATA.get(label)
    return metadata if isinstance(metadata, dict) else {}


def _signature_category(metadata: dict[str, Any], fallback: str) -> str:
    category = str(metadata.get("category") or "").strip()
    if not category:
        return fallback
    return f"endpoint_{category}"


def _signature_plain_english(metadata: dict[str, Any], fallback: str) -> str:
    return str(metadata.get("plain_english") or fallback)


def _signature_actions(metadata: dict[str, Any], fallback: list[str]) -> list[str]:
    actions = metadata.get("recommended_actions")
    if isinstance(actions, list) and all(isinstance(action, str) for action in actions):
        return actions
    if isinstance(actions, tuple) and all(isinstance(action, str) for action in actions):
        return list(actions)
    return fallback


def _signature_evidence(metadata: dict[str, Any]) -> dict[str, Any]:
    if not metadata:
        return {}
    evidence: dict[str, Any] = {
        "signature_category": str(metadata.get("category") or ""),
        "mitre_tactic": str(metadata.get("mitre_tactic") or ""),
    }
    technique = str(metadata.get("mitre_technique") or "")
    if technique:
        evidence["mitre_technique_id"] = technique.split(" ", 1)[0]
    return {key: value for key, value in evidence.items() if value}


def default_download_dirs() -> list[Path]:
    home = Path.home()
    candidates = [
        home / "Downloads",
        Path(os.environ.get("USERPROFILE", "")) / "Downloads" if os.environ.get("USERPROFILE") else None,
    ]
    return sorted({path for path in candidates if path and path.exists()})


def _sha256(path: Path, *, max_bytes: int = 128 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    remaining = max_bytes
    try:
        with path.open("rb") as handle:
            while remaining > 0:
                chunk = handle.read(min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                remaining -= len(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _is_recent(path: Path, *, max_age_days: int) -> bool:
    try:
        age_seconds = max(0.0, __import__("time").time() - path.stat().st_mtime)
    except OSError:
        return False
    return age_seconds <= max_age_days * 86400


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


def _iter_recent_files(scan_dirs: Iterable[Path], *, max_files: int) -> tuple[list[Path], int]:
    files: list[Path] = []
    inaccessible = 0
    for directory in scan_dirs:
        if not directory.exists():
            continue
        try:
            for root, dirnames, filenames in os.walk(directory):
                dirnames[:] = [
                    name
                    for name in dirnames
                    if name.lower() not in {"$recycle.bin", "node_modules", ".git", "__pycache__"}
                ]
                root_path = Path(root)
                for filename in filenames:
                    path = root_path / filename
                    if _safe_stat(path):
                        files.append(path)
                    else:
                        inaccessible += 1
        except OSError:
            inaccessible += 1
    files = sorted(files, key=lambda path: (_safe_stat(path).st_mtime if _safe_stat(path) else 0), reverse=True)
    return files[:max_files], inaccessible


def _read_scan_sample(path: Path, *, max_bytes: int) -> tuple[bytes, bool]:
    stat = _safe_stat(path)
    if not stat or stat.st_size <= 0:
        return b"", False
    truncated = stat.st_size > max_bytes
    head_size = min(stat.st_size, max_bytes)
    try:
        with path.open("rb") as handle:
            data = handle.read(head_size)
            if truncated and max_bytes >= 131072:
                tail_size = min(65536, stat.st_size)
                handle.seek(max(0, stat.st_size - tail_size))
                tail = handle.read(tail_size)
                data = data[: max_bytes - len(tail)] + tail
            return data, truncated
    except OSError:
        return b"", truncated


def _mark_of_the_web(path: Path) -> bool:
    if platform.system() != "Windows":
        return False
    try:
        return (Path(f"{path}:Zone.Identifier")).exists()
    except (OSError, ValueError):
        return False


def _file_evidence(path: Path, *, source: str, sample_sha256: str | None = None) -> dict[str, Any]:
    stat = _safe_stat(path)
    evidence: dict[str, Any] = {
        "file_name": path.name,
        "suffix": path.suffix.lower(),
        "source": source,
    }
    if stat:
        evidence["size_bytes"] = stat.st_size
    if sample_sha256:
        evidence["sha256_first_128mb"] = sample_sha256
    evidence["downloaded_from_browser"] = _mark_of_the_web(path)
    return evidence


def _homeguard_own_paths() -> list[Path]:
    """Filesystem paths that belong to HomeGuard itself.

    HomeGuard's own modules contain every detection signature as literal text
    (and install_into_virus_scanner injects dozens more), so scanning them
    would flag the scanner itself. Returns the installed package directory
    and, for frozen builds, the HomeGuard executable file.

    The executable's *parent* directory is intentionally not excluded: a
    frozen binary can be run straight from a shared folder such as
    ~/Downloads, and excluding that whole directory would silently disable
    the download scan for every unrelated file in it.
    """
    paths: set[Path] = set()
    try:
        paths.add(Path(__file__).resolve().parent)
    except OSError:
        pass
    if getattr(sys, "frozen", False):
        try:
            paths.add(Path(sys.executable).resolve())
        except OSError:
            pass
    return sorted(paths)


def _path_within(path: Path, owned: Iterable[Path]) -> bool:
    """True when ``path`` is one of, or lives inside, the ``owned`` paths."""
    try:
        resolved = path.resolve()
    except OSError:
        return False
    for entry in owned:
        if resolved == entry or entry in resolved.parents:
            return True
    return False


def scan_downloads(
    download_dirs: Iterable[Path] | None = None,
    *,
    max_files: int = 500,
    max_bytes_per_file: int = 4 * 1024 * 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    dirs = list(download_dirs or default_download_dirs())
    files, inaccessible = _iter_recent_files(dirs, max_files=max_files)
    # HomeGuard's own modules carry every detection signature as literal text,
    # so reviewing them would flag the scanner itself. Drop our own files
    # before the content scan.
    own_paths = _homeguard_own_paths()
    discovered_count = len(files)
    files = [path for path in files if not _path_within(path, own_paths)]
    self_excluded = discovered_count - len(files)
    reviewed = 0
    executable_count = 0
    content_hits = 0
    archive_count = 0
    truncated_count = 0
    sampled_bytes = 0
    for path in files:
        reviewed += 1
        if progress and (reviewed == 1 or reviewed % 25 == 0 or reviewed == len(files)):
            progress(f"Endpoint scan: internally scanning file {reviewed}/{len(files)} in browser downloads")
        suffix = path.suffix.lower()
        stat = _safe_stat(path)
        if not stat:
            inaccessible += 1
            continue
        if suffix in ARCHIVE_SUFFIXES:
            archive_count += 1
        sample = b""
        truncated = False
        should_sample = (
            suffix in EXECUTABLE_DOWNLOAD_SUFFIXES
            or suffix in TEXT_LIKE_SUFFIXES
            or suffix in ARCHIVE_SUFFIXES
            or stat.st_size <= max_bytes_per_file
        )
        if should_sample and sampled_bytes < max_total_bytes:
            sample, truncated = _read_scan_sample(path, max_bytes=max_bytes_per_file)
            sampled_bytes += len(sample)
            truncated_count += int(truncated)

        sample_sha = _sha256(path) if suffix in EXECUTABLE_DOWNLOAD_SUFFIXES or sample else None
        evidence = _file_evidence(path, source="internal_file_scanner", sample_sha256=sample_sha)
        if truncated:
            evidence["sample_truncated"] = True

        if suffix in EXECUTABLE_DOWNLOAD_SUFFIXES and _is_recent(path, max_age_days=30):
            executable_count += 1
            severity = "medium" if suffix in {".scr", ".hta", ".ps1", ".vbs", ".js", ".jse", ".lnk"} else "low"
            findings.append(
                _finding(
                    rule_id="endpoint_browser_download_executable",
                    title=f"Executable or script in browser downloads: {path.name}",
                    severity=severity,
                    confidence=0.54,
                    category="endpoint_download_review",
                    plain_english=(
                        f"{path.name} is an executable or script-like download. This is not proof of malware, "
                        "but browser downloads are a common place for droppers, fake installers, and phishing payloads."
                    ),
                    recommended_actions=[
                        "Only run this file if you recognize why it was downloaded.",
                        "Quarantine or delete it if it is unexpected or came from an untrusted site.",
                        "Check whether any startup entry or running process references this file.",
                    ],
                    evidence=evidence,
                )
            )
        if DOUBLE_EXTENSION_RE.search(path.name):
            findings.append(
                _finding(
                    rule_id="endpoint_deceptive_double_extension",
                    title=f"Deceptive double extension in downloads: {path.name}",
                    severity="high",
                    confidence=0.7,
                    category="endpoint_file_signature",
                    plain_english=(
                        f"{path.name} looks like a document or image but ends with an executable/script extension. "
                        "Malware commonly uses this trick to make payloads look safe."
                    ),
                    recommended_actions=[
                        "Do not open this file.",
                        "Delete or quarantine it unless you can verify exactly where it came from.",
                        "Review recent browser activity and downloads around the same time.",
                    ],
                    evidence=evidence,
                )
            )
        if sample:
            matches_for_file = 0
            for pattern, label, severity, confidence in FILE_CONTENT_SIGNATURES:
                if not pattern.search(sample):
                    continue
                metadata = _abuse_metadata(label)
                plain_english = _signature_plain_english(
                    metadata,
                    (
                        f"HomeGuard's internal scanner found {label} inside {path.name}. "
                        "This can indicate malware, a loader script, or a security test file."
                    ),
                )
                recommended_actions = _signature_actions(
                    metadata,
                    [
                        "Do not run or open this file.",
                        "Quarantine or delete it if it is not a deliberate security test.",
                        "If the file was already opened, review running processes and startup entries.",
                    ],
                )
                content_hits += 1
                matches_for_file += 1
                findings.append(
                    _finding(
                        rule_id="endpoint_internal_file_signature",
                        title=f"Suspicious file content: {label}",
                        severity=str(metadata.get("severity") or severity),
                        confidence=float(metadata.get("confidence") or confidence),
                        category=_signature_category(metadata, "endpoint_file_signature"),
                        plain_english=plain_english,
                        recommended_actions=recommended_actions,
                        evidence={**evidence, "matched_artifact": label, **_signature_evidence(metadata)},
                    )
                )
                if matches_for_file >= 3:
                    break
    return findings, {
        "download_dirs_reviewed": len(dirs),
        "download_files_reviewed": reviewed,
        "executable_downloads_seen": executable_count,
        "archive_downloads_seen": archive_count,
        "internal_file_scan": True,
        "internal_file_scan_max_files": max_files,
        "internal_file_scan_sampled_bytes": sampled_bytes,
        "internal_file_scan_truncated_files": truncated_count,
        "internal_file_scan_content_hits": content_hits,
        "internal_files_self_excluded": self_excluded,
        "inaccessible_download_files": inaccessible,
    }


def _run_json_powershell(script: str, *, timeout: int = 20) -> Any:
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", script],
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0 or not result.stdout.strip():
        return []
    try:
        payload = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []
    return payload if isinstance(payload, list) else [payload]


def running_processes() -> list[dict[str, Any]]:
    if platform.system() != "Windows":
        return []
    script = (
        "Get-CimInstance Win32_Process | "
        "Select-Object ProcessId,Name,ExecutablePath,CommandLine | "
        "ConvertTo-Json -Compress"
    )
    rows = _run_json_powershell(script)
    processes: list[dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        processes.append(
            {
                "pid": int(row.get("ProcessId") or 0),
                "name": str(row.get("Name") or ""),
                "path": str(row.get("ExecutablePath") or ""),
                "command_line": str(row.get("CommandLine") or ""),
            }
        )
    return processes


def analyze_processes(processes: Iterable[dict[str, Any]]) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    reviewed = 0
    for process in processes:
        reviewed += 1
        name = str(process.get("name") or "").lower()
        command_line = str(process.get("command_line") or "")
        pid = int(process.get("pid") or 0)
        if name in SUSPICIOUS_PROCESS_NAMES:
            findings.append(
                _finding(
                    rule_id="endpoint_suspicious_process_name",
                    title=f"Suspicious process name observed: {name}",
                    severity="high",
                    confidence=0.72,
                    category="endpoint_process",
                    plain_english=f"A running process named {name} matches a tool commonly used for intrusion activity.",
                    recommended_actions=[
                        "Do not terminate it blindly if this is a work or admin tool; first verify why it is running.",
                        "Use the HomeGuard endpoint findings to review recent downloads and startup entries.",
                        "If unexpected, disconnect from the network and preserve the report for review.",
                    ],
                    evidence={"pid": pid, "process_name": name, "source": "running_processes"},
                )
            )
        for pattern, label in SUSPICIOUS_CMD_PATTERNS:
            if not pattern.search(command_line):
                continue
            metadata = _abuse_metadata(label)
            plain_english = _signature_plain_english(
                metadata,
                (
                    f"A running process command line matched {label}. Attackers and malware often use this "
                    "style of command to download, decode, or execute payloads."
                ),
            )
            recommended_actions = _signature_actions(
                metadata,
                [
                    "Review the parent application or scheduled task that launched this command.",
                    "Run a full antivirus scan and check startup entries.",
                    "If this was not expected administrative work, isolate this PC from the network.",
                ],
            )
            findings.append(
                _finding(
                    rule_id="endpoint_suspicious_process_command",
                    title=f"Suspicious process command line: {label}",
                    severity=str(metadata.get("severity") or "high"),
                    confidence=float(metadata.get("confidence") or 0.68),
                    category=_signature_category(metadata, "endpoint_process"),
                    plain_english=plain_english,
                    recommended_actions=recommended_actions,
                    evidence={
                        "pid": pid,
                        "process_name": str(process.get("name") or ""),
                        "matched_behavior": label,
                        "command_line_hint": scrub_text(command_line[:260]),
                        "source": "running_processes",
                        **_signature_evidence(metadata),
                    },
                )
            )
    return findings, {"processes_reviewed": reviewed}


def _registry_run_values() -> list[dict[str, str]]:
    if platform.system() != "Windows":
        return []
    keys = [
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]
    rows: list[dict[str, str]] = []
    for key in keys:
        try:
            result = subprocess.run(
                ["reg.exe", "query", key],
                capture_output=True,
                text=True,
                timeout=10,
                creationflags=CREATE_NO_WINDOW,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            parts = re.split(r"\s{2,}", line.strip(), maxsplit=2)
            if len(parts) == 3 and parts[1].startswith("REG_"):
                rows.append({"source": key, "name": parts[0], "command": parts[2]})
    return rows


def _scheduled_tasks() -> list[dict[str, str]]:
    if platform.system() != "Windows":
        return []
    try:
        result = subprocess.run(
            ["schtasks.exe", "/Query", "/FO", "CSV", "/V"],
            capture_output=True,
            text=True,
            timeout=25,
            creationflags=CREATE_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return []
    if result.returncode != 0:
        return []
    rows: list[dict[str, str]] = []
    for row in csv.DictReader(result.stdout.splitlines()):
        command = row.get("Task To Run") or ""
        task_name = row.get("TaskName") or row.get("Task Name") or ""
        if command and command.upper() != "N/A":
            rows.append({"source": "scheduled_task", "name": task_name, "command": command})
    return rows


def _startup_folder_values() -> list[dict[str, str]]:
    candidates = [
        Path(os.environ.get("APPDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if os.environ.get("APPDATA")
        else None,
        Path(os.environ.get("PROGRAMDATA", "")) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if os.environ.get("PROGRAMDATA")
        else None,
    ]
    rows: list[dict[str, str]] = []
    for folder in [path for path in candidates if path and path.exists()]:
        try:
            for item in folder.iterdir():
                rows.append({"source": "startup_folder", "name": item.name, "command": str(item)})
        except OSError:
            continue
    return rows


def scan_persistence() -> tuple[list[Finding], dict[str, Any]]:
    entries = _registry_run_values() + _scheduled_tasks() + _startup_folder_values()
    findings: list[Finding] = []
    suspicious_locations = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\programdata\\")
    for entry in entries:
        command = str(entry.get("command") or "")
        command_lower = command.lower()
        matched_behavior = ""
        matched_metadata: dict[str, Any] = {}
        for pattern, label in SUSPICIOUS_CMD_PATTERNS:
            if pattern.search(command):
                matched_behavior = label
                matched_metadata = _abuse_metadata(label)
                break
        suspicious_location = any(token in command_lower for token in suspicious_locations)
        script_like = Path(command.strip('"').split(" ")[0]).suffix.lower() in EXECUTABLE_DOWNLOAD_SUFFIXES
        if not matched_behavior and not (suspicious_location and script_like):
            continue
        plain_english = _signature_plain_english(
            matched_metadata,
            (
                "A startup entry or scheduled task points to behavior commonly used by malware persistence. "
                "This can also be caused by legitimate admin tools, so review before deleting."
            ),
        )
        recommended_actions = _signature_actions(
            matched_metadata,
            [
                "Verify whether this startup item is expected.",
                "Disable the startup item if it is unknown, then run a full antivirus scan.",
                "Check recent downloads and browser extensions if the entry appeared recently.",
            ],
        )
        findings.append(
            _finding(
                rule_id="endpoint_suspicious_persistence",
                title=f"Suspicious startup persistence: {entry.get('name') or 'startup entry'}",
                severity=str(matched_metadata.get("severity") or ("high" if matched_behavior else "medium")),
                confidence=float(matched_metadata.get("confidence") or 0.66),
                category=_signature_category(matched_metadata, "endpoint_persistence"),
                plain_english=plain_english,
                recommended_actions=recommended_actions,
                evidence={
                    "entry_name": str(entry.get("name") or ""),
                    "entry_source": str(entry.get("source") or ""),
                    "matched_behavior": matched_behavior or "script_or_executable_in_user_writable_location",
                    "command_hint": scrub_text(command[:260]),
                    **_signature_evidence(matched_metadata),
                },
            )
        )
    return findings, {"persistence_entries_reviewed": len(entries)}


def _read_process_memory(pid: int, *, max_bytes: int = 2 * 1024 * 1024) -> list[bytes]:
    if platform.system() != "Windows" or pid <= 0:
        return []
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_VM_READ = 0x0010
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", ctypes.c_ulong),
            ("RegionSize", ctypes.c_size_t),
            ("State", ctypes.c_ulong),
            ("Protect", ctypes.c_ulong),
            ("Type", ctypes.c_ulong),
        ]

    handle = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not handle:
        return []
    chunks: list[bytes] = []
    address = 0
    total = 0
    mbi = MEMORY_BASIC_INFORMATION()
    try:
        while total < max_bytes and address < 0x7FFFFFFFFFFF:
            result = kernel32.VirtualQueryEx(
                handle,
                ctypes.c_void_p(address),
                ctypes.byref(mbi),
                ctypes.sizeof(mbi),
            )
            if not result:
                break
            base = int(mbi.BaseAddress or 0)
            size = int(mbi.RegionSize or 0)
            protect = int(mbi.Protect or 0)
            if size <= 0:
                break
            if mbi.State == MEM_COMMIT and not (protect & PAGE_NOACCESS) and not (protect & PAGE_GUARD):
                to_read = min(size, 65536, max_bytes - total)
                buffer = ctypes.create_string_buffer(to_read)
                bytes_read = ctypes.c_size_t()
                if kernel32.ReadProcessMemory(handle, ctypes.c_void_p(base), buffer, to_read, ctypes.byref(bytes_read)):
                    data = buffer.raw[: bytes_read.value]
                    if data:
                        chunks.append(data)
                        total += len(data)
            address = base + size
    finally:
        kernel32.CloseHandle(handle)
    return chunks


def _safe_pid(value: Any) -> int:
    """Parse a process-id value, returning 0 when it is missing or malformed."""
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def scan_process_memory(processes: Iterable[dict[str, Any]], *, max_processes: int = 48) -> tuple[list[Finding], dict[str, Any]]:
    findings: list[Finding] = []
    reviewed = 0
    signatures = {signature.lower(): label for signature, label in MEMORY_SIGNATURES.items()}
    # HomeGuard's own process keeps every MEMORY_SIGNATURES marker in plain
    # module memory, so reading it back always self-matches and reports the
    # scanner itself as malware. Drop our PID before applying the budget so a
    # real process is never displaced by the skipped one. _safe_pid coerces a
    # malformed PID to 0 (filtered out below) so one bad row cannot abort the
    # whole scan.
    own_pid = os.getpid()
    all_rows = list(processes)
    candidates = [row for row in all_rows if _safe_pid(row.get("pid")) != own_pid]
    self_excluded = len(candidates) != len(all_rows)
    for process in candidates[:max_processes]:
        pid = _safe_pid(process.get("pid"))
        if pid <= 4:
            continue
        reviewed += 1
        try:
            chunks = _read_process_memory(pid)
        except Exception:
            continue
        haystack = b"\n".join(chunk.lower() for chunk in chunks)
        for signature, label in signatures.items():
            if signature not in haystack:
                continue
            metadata = _abuse_metadata(label)
            plain_english = _signature_plain_english(
                metadata,
                (
                    f"Readable memory from process {process.get('name') or pid} contained a string associated "
                    "with malware, credential theft, or in-memory payload loading."
                ),
            )
            recommended_actions = _signature_actions(
                metadata,
                [
                    "Run a full offline antivirus scan if available.",
                    "Do not enter passwords on this PC until the process is reviewed.",
                    "If this was unexpected, isolate this PC from the network and preserve the report.",
                ],
            )
            findings.append(
                _finding(
                    rule_id="endpoint_memory_signature",
                    title=f"Suspicious memory artifact: {label}",
                    severity=str(metadata.get("severity") or "high"),
                    confidence=float(metadata.get("confidence") or 0.62),
                    category=_signature_category(metadata, "endpoint_memory"),
                    plain_english=plain_english,
                    recommended_actions=recommended_actions,
                    evidence={
                        "pid": pid,
                        "process_name": str(process.get("name") or ""),
                        "matched_artifact": label,
                        "source": "process_memory",
                        **_signature_evidence(metadata),
                    },
                )
            )
    return findings, {
        "memory_processes_reviewed": reviewed,
        "memory_signatures": len(signatures),
        "memory_self_process_excluded": self_excluded,
    }


def run_endpoint_malware_scan(
    *,
    include_defender: bool = False,
    include_file_scan: bool = True,
    include_memory: bool = True,
    include_privesc_audit: bool = True,
    download_dirs: Iterable[Path] | None = None,
    process_rows: Iterable[dict[str, Any]] | None = None,
    progress: Callable[[str], None] | None = None,
) -> EndpointScanResult:
    if progress:
        progress("Endpoint scan: collecting running process inventory")
    processes = list(process_rows) if process_rows is not None else running_processes()
    all_findings: list[Finding] = []
    metadata: dict[str, Any] = {
        "scanner": "GreyNOC Endpoint Malware Indicator Scanner",
        "scanner_version": "0.2.0",
        "scope": ["processes", "browser_downloads", "startup_persistence"],
        "limits": {
            "memory_scan": "best_effort_readable_process_memory",
            "download_file_hashing": "first_128mb_when_reviewed",
            "internal_file_scan": "newest_500_files_first_4mb_plus_tail_bounded_to_256mb",
        },
        "external_antivirus": "not_used",
        "privesc_audit_enabled": include_privesc_audit,
    }

    if progress:
        progress(f"Endpoint scan: analyzing {len(processes)} running processes")
    process_findings, process_meta = analyze_processes(processes)
    all_findings.extend(process_findings)
    metadata.update(process_meta)

    if include_file_scan:
        if progress:
            progress("Endpoint scan: internally scanning browser download files")
        download_findings, download_meta = scan_downloads(download_dirs, progress=progress)
        all_findings.extend(download_findings)
        metadata.update(download_meta)
    else:
        metadata["internal_file_scan"] = False

    if progress:
        progress("Endpoint scan: reviewing startup entries and scheduled tasks")
    persistence_findings, persistence_meta = scan_persistence()
    all_findings.extend(persistence_findings)
    metadata.update(persistence_meta)

    if include_memory:
        if progress:
            progress("Endpoint scan: sampling readable process memory")
        memory_findings, memory_meta = scan_process_memory(processes)
        all_findings.extend(memory_findings)
        metadata.update(memory_meta)
        if "process_memory" not in metadata["scope"]:
            metadata["scope"].append("process_memory")

    if include_privesc_audit:
        if progress:
            progress("Endpoint scan: running passive Windows privilege escalation audit")
        privesc = run_windows_privesc_audit()
        all_findings.extend(privesc.findings)
        metadata.update(privesc.metadata)
        if "windows_privesc_audit" not in metadata["scope"]:
            metadata["scope"].append("windows_privesc_audit")
    else:
        metadata.update(
            {
                "privesc_checks_run": [],
                "privesc_checks_skipped": ["disabled_by_caller"],
                "privesc_audit_platform": platform.system(),
                "privesc_audit_partial_results": False,
            }
        )

    if include_defender:
        metadata["external_antivirus_requested"] = "ignored_internal_scanner_only"

    metadata["findings_emitted"] = len(all_findings)
    if progress:
        progress(f"Endpoint scan: complete with {len(all_findings)} endpoint finding(s)")
    return EndpointScanResult(findings=all_findings, metadata=metadata)


# ---------------------------------------------------------------------------
# On-demand file/folder scanning
#
# The download sweep above only ever looks at the browser Downloads folder.
# A real antivirus must also let the user point it at *any* file or folder and
# get back actionable findings — including exact-content hash matches, the
# highest-confidence signal an AV has. These functions power `scan-file` /
# `scan-folder` and the AI `homeguard_scan_path` tool, and produce findings
# whose evidence carries the absolute path so the remediation layer can act.
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of ``data`` in bits/byte (0.0 .. 8.0)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / length
            entropy -= probability * math.log2(probability)
    return entropy


def sha256_file(path: Path) -> str:
    """Full-file SHA-256 (streamed). Empty string on read error.

    Unlike :func:`_sha256` this hashes the *entire* file with no byte cap so
    the digest can be matched against a known-bad hash set exactly.
    """
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
    except OSError:
        return ""
    return digest.hexdigest()


def _malware_hash_set(malware_hashes: dict[str, dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    if malware_hashes is not None:
        return malware_hashes
    try:
        from .definitions import active_malware_hashes

        return active_malware_hashes()
    except Exception:  # pragma: no cover - defensive
        return {}


def scan_file(
    path: str | Path,
    *,
    malware_hashes: dict[str, dict[str, Any]] | None = None,
    max_bytes_per_file: int = ONDEMAND_MAX_BYTES_PER_FILE,
    compute_hash: bool = True,
) -> list[Finding]:
    """Scan a single file and return findings.

    Layers, highest-confidence first: known-bad SHA-256 match, embedded
    content signatures (EICAR, credential-theft tooling, loader cradles),
    deceptive double extensions, and a packed-executable entropy hint.
    Findings carry the absolute ``path`` in evidence so remediation can act.
    """
    target = Path(path)
    findings: list[Finding] = []
    stat = _safe_stat(target)
    if not stat or not target.is_file():
        return findings
    # Never flag HomeGuard's own modules/binary — they carry every signature
    # as literal text and would self-trigger.
    if _path_within(target, _homeguard_own_paths()):
        return findings

    suffix = target.suffix.lower()
    evidence = _file_evidence(target, source="on_demand_scanner")
    evidence["path"] = str(target)

    hash_set = _malware_hash_set(malware_hashes) if compute_hash else {}
    digest = sha256_file(target) if (compute_hash and stat.st_size <= max(max_bytes_per_file, 512 * 1024 * 1024)) else ""
    if digest:
        evidence["sha256"] = digest
        match = hash_set.get(digest)
        if match:
            severity = str(match.get("severity") or "high")
            findings.append(
                _finding(
                    rule_id="endpoint_known_malware_hash",
                    title=f"Known-bad file hash: {match.get('name') or target.name}",
                    severity=severity,
                    confidence=0.99,
                    category="endpoint_file_signature",
                    plain_english=(
                        f"{target.name} matches a known-bad file signature by exact content hash. "
                        f"{match.get('why') or 'This file is on HomeGuard’s known-malware list.'}"
                    ),
                    recommended_actions=[
                        "Quarantine or delete this file now.",
                        "Run a full system antivirus scan; a known-bad file rarely arrives alone.",
                        "Review how it reached this machine (downloads, email, USB) to close the gap.",
                    ],
                    evidence={**evidence, "matched_name": str(match.get("name") or ""), "detection": "sha256_match"},
                )
            )

    sample, truncated = _read_scan_sample(target, max_bytes=max_bytes_per_file)
    if truncated:
        evidence["sample_truncated"] = True
    if sample:
        matches_for_file = 0
        for pattern, label, severity, confidence in FILE_CONTENT_SIGNATURES:
            if not pattern.search(sample):
                continue
            metadata = _abuse_metadata(label)
            findings.append(
                _finding(
                    rule_id="endpoint_internal_file_signature",
                    title=f"Suspicious file content: {label}",
                    severity=str(metadata.get("severity") or severity),
                    confidence=float(metadata.get("confidence") or confidence),
                    category=_signature_category(metadata, "endpoint_file_signature"),
                    plain_english=_signature_plain_english(
                        metadata,
                        (
                            f"HomeGuard's scanner found {label} inside {target.name}. "
                            "This can indicate malware, a loader script, or a security test file."
                        ),
                    ),
                    recommended_actions=_signature_actions(
                        metadata,
                        [
                            "Do not run or open this file.",
                            "Quarantine or delete it if it is not a deliberate security test.",
                            "If the file was already opened, review running processes and startup entries.",
                        ],
                    ),
                    evidence={**evidence, "matched_artifact": label, **_signature_evidence(metadata)},
                )
            )
            matches_for_file += 1
            if matches_for_file >= 3:
                break

    if DOUBLE_EXTENSION_RE.search(target.name):
        findings.append(
            _finding(
                rule_id="endpoint_deceptive_double_extension",
                title=f"Deceptive double extension: {target.name}",
                severity="high",
                confidence=0.7,
                category="endpoint_file_signature",
                plain_english=(
                    f"{target.name} looks like a document or image but ends with an executable/script extension. "
                    "Malware commonly uses this trick to make payloads look safe."
                ),
                recommended_actions=[
                    "Do not open this file.",
                    "Quarantine or delete it unless you can verify exactly where it came from.",
                    "Review recent downloads and email attachments around the same time.",
                ],
                evidence=evidence,
            )
        )

    if sample[:2] == b"MZ" and suffix in EXECUTABLE_BINARY_SUFFIXES:
        entropy = shannon_entropy(sample[:ENTROPY_SAMPLE_BYTES])
        if entropy >= ENTROPY_PACKED_THRESHOLD:
            findings.append(
                _finding(
                    rule_id="endpoint_high_entropy_executable",
                    title=f"Packed or encrypted executable: {target.name}",
                    severity="low",
                    confidence=0.35,
                    category="endpoint_heuristic",
                    plain_english=(
                        f"{target.name} is an executable whose contents look packed or encrypted "
                        f"(entropy {entropy:.2f}/8.0). Many legitimate installers are packed too, so this "
                        "is only a hint — treat it as suspicious mainly if you did not expect this program."
                    ),
                    recommended_actions=[
                        "Only run this program if you trust its source and expected to download it.",
                        "Scan it with a second antivirus engine if you are unsure.",
                        "Quarantine it if you cannot account for where it came from.",
                    ],
                    evidence={**evidence, "entropy": round(entropy, 3), "heuristic": "high_entropy_pe"},
                )
            )

    return findings


def scan_path(
    target: str | Path,
    *,
    malware_hashes: dict[str, dict[str, Any]] | None = None,
    max_files: int = 5000,
    max_bytes_per_file: int = ONDEMAND_MAX_BYTES_PER_FILE,
    progress: Callable[[str], None] | None = None,
) -> tuple[list[Finding], dict[str, Any]]:
    """Scan an arbitrary file or directory tree on demand.

    Returns ``(findings, metadata)``. Directory walks are bounded by
    ``max_files`` and skip well-known noise directories. Malware-hash lookups
    are resolved once up front so a folder scan does not reload definitions
    per file.
    """
    root = Path(target)
    resolved_hashes = _malware_hash_set(malware_hashes)
    findings: list[Finding] = []
    files_scanned = 0
    files_skipped = 0
    truncated = False

    if not root.exists():
        return findings, {
            "scan_target": str(root),
            "target_exists": False,
            "files_scanned": 0,
            "hash_signatures": len(resolved_hashes),
        }

    if root.is_file():
        targets: list[Path] = [root]
    else:
        targets = []
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [
                name
                for name in dirnames
                if name.lower() not in {"$recycle.bin", "node_modules", ".git", "__pycache__"}
            ]
            base = Path(dirpath)
            for name in filenames:
                targets.append(base / name)
                if len(targets) >= max_files:
                    truncated = True
                    break
            if truncated:
                break

    total = len(targets)
    for index, file_path in enumerate(targets, start=1):
        if progress and (index == 1 or index % 100 == 0 or index == total):
            progress(f"On-demand scan: inspecting file {index}/{total}")
        try:
            file_findings = scan_file(
                file_path,
                malware_hashes=resolved_hashes,
                max_bytes_per_file=max_bytes_per_file,
            )
        except Exception as exc:  # pragma: no cover - defensive against one bad file
            LOG.debug("scan_file failed for %s: %s", file_path, exc)
            files_skipped += 1
            continue
        files_scanned += 1
        findings.extend(file_findings)

    metadata = {
        "scanner": "GreyNOC On-Demand File Scanner",
        "scan_target": str(root),
        "target_exists": True,
        "target_is_dir": root.is_dir(),
        "files_scanned": files_scanned,
        "files_skipped": files_skipped,
        "files_truncated_at_limit": truncated,
        "max_files": max_files,
        "hash_signatures": len(resolved_hashes),
        "content_signatures": len(FILE_CONTENT_SIGNATURES),
        "findings_emitted": len(findings),
    }
    return findings, metadata

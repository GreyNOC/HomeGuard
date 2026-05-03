from __future__ import annotations

import platform
import re
import subprocess
from dataclasses import dataclass
from typing import Callable

from .models import Finding
from .network import NetworkSensorConfig, detect_local_interfaces

RULE_PREFIX = "HomeGuard Block"


@dataclass(slots=True)
class PortActionResult:
    ok: bool
    message: str
    command: list[str] | None = None


def rule_name(port: int, protocol: str = "TCP") -> str:
    return f"{RULE_PREFIX} {protocol.upper()} {int(port)}"


def port_from_finding(finding: Finding) -> int | None:
    evidence = finding.evidence or {}
    for key in ("port",):
        try:
            port = int(evidence.get(key))
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535:
            return port
    for key in ("suspicious_ports", "remote_admin_ports", "file_sharing_ports", "service_cluster_ports"):
        values = evidence.get(key)
        if not isinstance(values, list):
            continue
        for value in values:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if 0 < port <= 65535:
                return port
    match = re.search(r"\b([1-9][0-9]{0,4})\b", finding.title)
    if match:
        port = int(match.group(1))
        if 0 < port <= 65535:
            return port
    return None


def local_ips(config: NetworkSensorConfig | None = None) -> set[str]:
    ips = {"127.0.0.1", "::1"}
    try:
        for interface in detect_local_interfaces(config or NetworkSensorConfig()):
            if interface.ip:
                ips.add(interface.ip)
    except Exception:
        pass
    return ips


def finding_is_local(finding: Finding, *, ips: set[str] | None = None) -> bool:
    return finding.device_ip in (ips if ips is not None else local_ips())


def _run(args: list[str], runner: Callable[..., subprocess.CompletedProcess[str]] | None = None) -> PortActionResult:
    run = runner or subprocess.run
    try:
        result = run(args, capture_output=True, text=True, timeout=12, check=False)
    except OSError as exc:
        return PortActionResult(False, f"Could not run firewall command: {exc}", args)
    except subprocess.TimeoutExpired:
        return PortActionResult(False, "Firewall command timed out.", args)
    output = " ".join(part.strip() for part in [getattr(result, "stdout", ""), getattr(result, "stderr", "")] if part)
    if result.returncode == 0:
        return PortActionResult(True, output or "Firewall rule updated.", args)
    if "requires elevation" in output.lower() or "administrator" in output.lower() or "access is denied" in output.lower():
        return PortActionResult(False, "Administrator permission is required to change firewall rules.", args)
    return PortActionResult(False, output or f"Firewall command failed with exit code {result.returncode}.", args)


def close_local_port(
    port: int,
    *,
    protocol: str = "TCP",
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> PortActionResult:
    if platform.system().lower() != "windows":
        return PortActionResult(False, "Automatic close/reopen is currently supported on Windows Firewall only.")
    port = int(port)
    if not 0 < port <= 65535:
        return PortActionResult(False, f"Invalid port: {port}")
    protocol = protocol.upper()
    name = rule_name(port, protocol)
    delete_result = _run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
        runner,
    )
    if not delete_result.ok and "no rules match" not in delete_result.message.lower():
        return delete_result
    return _run(
        [
            "netsh",
            "advfirewall",
            "firewall",
            "add",
            "rule",
            f"name={name}",
            "dir=in",
            "action=block",
            f"protocol={protocol}",
            f"localport={port}",
        ],
        runner,
    )


def reopen_local_port(
    port: int,
    *,
    protocol: str = "TCP",
    runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
) -> PortActionResult:
    if platform.system().lower() != "windows":
        return PortActionResult(False, "Automatic close/reopen is currently supported on Windows Firewall only.")
    port = int(port)
    if not 0 < port <= 65535:
        return PortActionResult(False, f"Invalid port: {port}")
    name = rule_name(port, protocol)
    result = _run(
        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"],
        runner,
    )
    if result.ok:
        return result
    if "no rules match" in result.message.lower():
        return PortActionResult(True, "No HomeGuard firewall rule was present for this port.", result.command)
    return result

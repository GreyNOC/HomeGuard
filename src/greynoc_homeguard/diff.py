"""Compute a delta between two HomeGuard reports.

The history infrastructure stores the full ``report.json`` for every
scan, but the engine only ever shows users the latest snapshot. That
makes it hard to answer the most useful question a consumer can ask:
"What is different from yesterday?"

This module compares a current report against a previous one and emits
a structured delta covering devices that appeared or disappeared, ports
that newly opened or closed on persistent devices, findings that were
introduced or resolved, and the overall risk trajectory. The result is
attached to ``HomeGuardReport.scan_metadata`` and surfaced by both the
HTML report and the CLI summary so the change is visible without the
user having to diff JSON files by hand.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import Device, Finding, HomeGuardReport

RISK_RANK = {"clean": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _device_key(payload: dict[str, Any] | Device) -> str:
    """Stable identity for diff matching.

    Falls through the same priority list as ``Device.fingerprint`` so
    matched records line up regardless of whether the previous scan
    produced a MAC or a hostname-only fingerprint.
    """

    if isinstance(payload, Device):
        return payload.fingerprint()
    fingerprint = str(payload.get("fingerprint") or "").strip()
    if fingerprint:
        return fingerprint
    mac = str(payload.get("mac_address") or payload.get("mac") or "").strip().lower()
    if mac:
        return f"mac:{mac}"
    hostname = str(payload.get("hostname") or "").strip().lower()
    if hostname:
        return f"host:{hostname}"
    ip = str(payload.get("ip") or "").strip()
    return f"ip:{ip}" if ip else ""


def _device_label(payload: dict[str, Any] | Device) -> str:
    if isinstance(payload, Device):
        return payload.hostname or payload.vendor or payload.ip
    return str(
        payload.get("hostname")
        or payload.get("name")
        or payload.get("vendor")
        or payload.get("ip")
        or "device"
    )


def _device_ip(payload: dict[str, Any] | Device) -> str:
    if isinstance(payload, Device):
        return payload.ip
    return str(payload.get("ip") or "")


def _device_ports(payload: dict[str, Any] | Device) -> set[int]:
    if isinstance(payload, Device):
        ports: Iterable[int] = payload.open_ports
    else:
        raw = payload.get("open_ports") or payload.get("ports") or []
        ports = []
        for value in raw if isinstance(raw, list) else []:
            try:
                ports.append(int(value))  # type: ignore[arg-type]
            except (TypeError, ValueError):
                continue
    return {port for port in ports if isinstance(port, int) and 0 < port <= 65535}


def _finding_key(payload: dict[str, Any] | Finding) -> tuple[str, str]:
    """Pair (rule_id, device_ip) so a re-emitted same finding doesn't look new.

    ``finding_id`` is a hash that includes evidence — a MAC or port set
    that flips between scans gives a different ``finding_id`` even when
    the underlying issue is the same. Matching by (rule_id, device_ip)
    is the closest stable identity for "the same thing the user already
    saw last time."
    """

    if isinstance(payload, Finding):
        return (payload.rule_id, payload.device_ip)
    return (
        str(payload.get("rule_id") or ""),
        str(payload.get("device_ip") or ""),
    )


def _finding_summary(payload: dict[str, Any] | Finding) -> dict[str, Any]:
    if isinstance(payload, Finding):
        return {
            "finding_id": payload.finding_id,
            "rule_id": payload.rule_id,
            "title": payload.title,
            "severity": payload.severity,
            "category": payload.category,
            "device_ip": payload.device_ip,
            "device_name": payload.device_name,
        }
    return {
        "finding_id": str(payload.get("finding_id") or ""),
        "rule_id": str(payload.get("rule_id") or ""),
        "title": str(payload.get("title") or ""),
        "severity": str(payload.get("severity") or "info"),
        "category": str(payload.get("category") or "general"),
        "device_ip": str(payload.get("device_ip") or ""),
        "device_name": str(payload.get("device_name") or ""),
    }


def _risk_direction(previous: float, current: float) -> str:
    if current > previous + 0.5:
        return "worsened"
    if current < previous - 0.5:
        return "improved"
    return "unchanged"


def _empty_delta() -> dict[str, Any]:
    return {
        "available": False,
        "reason": "no previous scan",
        "devices": {
            "added": [],
            "removed": [],
            "with_new_ports": [],
            "with_closed_ports": [],
        },
        "findings": {"added": [], "resolved": []},
        "risk": {
            "previous_risk": "",
            "previous_score": 0.0,
            "current_risk": "",
            "current_score": 0.0,
            "direction": "unchanged",
        },
    }


def compute_scan_diff(
    current: HomeGuardReport,
    previous: dict[str, Any] | None,
) -> dict[str, Any]:
    """Compute the delta between ``current`` and a previously-saved report dict.

    ``previous`` is the ``as_dict()`` form (i.e. the JSON written to
    history) so the diff can run even when the previous report was
    produced by an older HomeGuard version with slightly different
    dataclass fields.
    """

    delta = _empty_delta()
    if not isinstance(previous, dict):
        return delta

    previous_devices = previous.get("devices") or []
    previous_findings = previous.get("findings") or []

    prev_device_map: dict[str, dict[str, Any]] = {}
    for row in previous_devices:
        if not isinstance(row, dict):
            continue
        key = _device_key(row)
        if key:
            prev_device_map[key] = row

    current_device_map: dict[str, Device] = {}
    for device in current.devices:
        key = _device_key(device)
        if key:
            current_device_map[key] = device

    added_devices = []
    removed_devices = []
    with_new_ports = []
    with_closed_ports = []

    for key, device in current_device_map.items():
        if key not in prev_device_map:
            added_devices.append(
                {"key": key, "ip": device.ip, "name": _device_label(device)}
            )
            continue
        previous_ports = _device_ports(prev_device_map[key])
        current_ports = _device_ports(device)
        new_ports = sorted(current_ports - previous_ports)
        closed_ports = sorted(previous_ports - current_ports)
        if new_ports:
            with_new_ports.append(
                {
                    "key": key,
                    "ip": device.ip,
                    "name": _device_label(device),
                    "newly_open": new_ports,
                }
            )
        if closed_ports:
            with_closed_ports.append(
                {
                    "key": key,
                    "ip": device.ip,
                    "name": _device_label(device),
                    "newly_closed": closed_ports,
                }
            )

    for key, row in prev_device_map.items():
        if key in current_device_map:
            continue
        removed_devices.append(
            {"key": key, "ip": _device_ip(row), "name": _device_label(row)}
        )

    prev_finding_keys: dict[tuple[str, str], dict[str, Any]] = {}
    for row in previous_findings:
        if not isinstance(row, dict):
            continue
        prev_finding_keys[_finding_key(row)] = row

    current_finding_keys: dict[tuple[str, str], Finding] = {
        _finding_key(finding): finding for finding in current.findings
    }

    added_findings = [
        _finding_summary(finding)
        for key, finding in current_finding_keys.items()
        if key not in prev_finding_keys
    ]
    resolved_findings = [
        _finding_summary(row)
        for key, row in prev_finding_keys.items()
        if key not in current_finding_keys
    ]

    previous_risk = str(previous.get("overall_risk") or "")
    try:
        previous_score = float(previous.get("overall_score") or 0.0)
    except (TypeError, ValueError):
        previous_score = 0.0

    delta["available"] = True
    delta["reason"] = ""
    delta["previous_report_id"] = str(previous.get("report_id") or "")
    delta["previous_created_at"] = str(previous.get("created_at") or "")
    delta["devices"] = {
        "added": added_devices,
        "removed": removed_devices,
        "with_new_ports": with_new_ports,
        "with_closed_ports": with_closed_ports,
    }
    delta["findings"] = {
        "added": added_findings,
        "resolved": resolved_findings,
    }
    delta["risk"] = {
        "previous_risk": previous_risk,
        "previous_score": round(previous_score, 2),
        "current_risk": current.overall_risk,
        "current_score": round(current.overall_score, 2),
        "direction": _risk_direction(previous_score, current.overall_score),
    }
    return delta


def load_previous_report(json_path: str | Path | None) -> dict[str, Any] | None:
    """Read a saved report.json file. Returns None on any I/O or parse error."""

    if not json_path:
        return None
    try:
        return json.loads(Path(json_path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def render_summary(delta: dict[str, Any]) -> str:
    """One-line human summary for the CLI / status bar."""

    if not delta or not delta.get("available"):
        return ""
    devices = delta.get("devices") or {}
    findings = delta.get("findings") or {}
    risk = delta.get("risk") or {}
    bits: list[str] = []
    added_d = len(devices.get("added") or [])
    removed_d = len(devices.get("removed") or [])
    new_ports = sum(
        len(item.get("newly_open") or []) for item in devices.get("with_new_ports") or []
    )
    closed_ports = sum(
        len(item.get("newly_closed") or [])
        for item in devices.get("with_closed_ports") or []
    )
    if added_d:
        bits.append(f"{added_d} new device(s)")
    if removed_d:
        bits.append(f"{removed_d} device(s) gone")
    if new_ports:
        bits.append(f"{new_ports} newly open port(s)")
    if closed_ports:
        bits.append(f"{closed_ports} newly closed port(s)")
    added_f = len(findings.get("added") or [])
    resolved_f = len(findings.get("resolved") or [])
    if added_f:
        bits.append(f"{added_f} new finding(s)")
    if resolved_f:
        bits.append(f"{resolved_f} resolved finding(s)")
    direction = str(risk.get("direction") or "")
    if direction == "worsened":
        bits.append(
            f"risk worsened {risk.get('previous_risk') or '?'} → {risk.get('current_risk') or '?'}"
        )
    elif direction == "improved":
        bits.append(
            f"risk improved {risk.get('previous_risk') or '?'} → {risk.get('current_risk') or '?'}"
        )
    if not bits:
        return "No changes since the previous scan."
    return "Since previous scan: " + ", ".join(bits) + "."

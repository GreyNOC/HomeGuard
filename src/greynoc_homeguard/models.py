from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(slots=True)
class Device:
    ip: str
    mac_address: str = ""
    hostname: str = ""
    interface: str = ""
    source: str = "passive"
    status: str = "observed"
    open_ports: list[int] = field(default_factory=list)
    vendor: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "Device":
        ports = payload.get("open_ports", payload.get("ports", [])) or []
        parsed_ports: list[int] = []
        for port in ports:
            try:
                p = int(port)
            except (TypeError, ValueError):
                continue
            if 0 < p <= 65535:
                parsed_ports.append(p)
        mac = str(payload.get("mac_address") or payload.get("mac") or "")
        return cls(
            ip=str(payload.get("ip") or ""),
            mac_address=mac,
            hostname=str(payload.get("hostname") or payload.get("name") or ""),
            interface=str(payload.get("interface") or ""),
            source=str(payload.get("source") or "imported"),
            status=str(payload.get("status") or "observed"),
            open_ports=sorted(set(parsed_ports)),
            vendor=str(payload.get("vendor") or ""),
            metadata=dict(payload.get("metadata") or {}),
        )

    def fingerprint(self) -> str:
        if self.mac_address:
            return f"mac:{self.mac_address.lower()}"
        if self.hostname:
            return f"host:{self.hostname.lower()}"
        return f"ip:{self.ip}"

    def as_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "mac_address": self.mac_address,
            "mac": self.mac_address,
            "hostname": self.hostname,
            "interface": self.interface,
            "source": self.source,
            "status": self.status,
            "open_ports": list(self.open_ports),
            "ports": list(self.open_ports),
            "vendor": self.vendor,
            "metadata": dict(self.metadata),
            "fingerprint": self.fingerprint(),
        }


@dataclass(slots=True)
class Finding:
    finding_id: str
    rule_id: str
    title: str
    severity: str
    confidence: float
    risk_score: float
    priority: str
    category: str
    device_ip: str
    device_name: str
    plain_english: str
    recommended_actions: list[str]
    evidence: dict[str, Any] = field(default_factory=dict)
    created_at: str = field(default_factory=utcnow)

    def as_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "priority": self.priority,
            "category": self.category,
            "device_ip": self.device_ip,
            "device_name": self.device_name,
            "plain_english": self.plain_english,
            "recommended_actions": list(self.recommended_actions),
            "evidence": dict(self.evidence),
            "created_at": self.created_at,
        }


@dataclass(slots=True)
class HomeGuardReport:
    report_id: str
    created_at: str
    summary: str
    overall_risk: str
    overall_score: float
    devices: list[Device]
    findings: list[Finding]
    next_steps: list[str]
    scan_metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "report_id": self.report_id,
            "created_at": self.created_at,
            "summary": self.summary,
            "overall_risk": self.overall_risk,
            "overall_score": self.overall_score,
            "devices": [device.as_dict() for device in self.devices],
            "findings": [finding.as_dict() for finding in self.findings],
            "next_steps": list(self.next_steps),
            "scan_metadata": dict(self.scan_metadata),
        }

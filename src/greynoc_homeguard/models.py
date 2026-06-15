from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .guidance import REPORT_DISCLAIMER, priority_actions


def utcnow() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


# Evidence keys, in priority order, used as the *stable* identifying part of a
# finding's signature. Deliberately excludes volatile values like
# ``definitions_version``, the full ``open_ports`` list, ``pid``, and timestamps.
_SIGNATURE_EVIDENCE_KEYS = (
    "path",
    "command",
    "matched_artifact",
    "matched_name",
    "process_name",
    "name",
    "cve_id",
    "port",
    "service",
    "fingerprint",
    "mac_address",
    "matched_pattern",
    "matched_prefix",
    "hostname",
)


def finding_signature(finding: Any) -> str:
    """Stable, mostly-unique identity for a finding across scans.

    Unlike ``finding_id`` (which hashes volatile evidence such as
    ``definitions_version`` or the full open-port list, and is even random for
    endpoint findings), this keys on the rule, the device, and the single most
    identifying *stable* piece of evidence (a file path, a port, a CVE id, a
    device fingerprint). That lets a user "clear" a risk and have it stay
    cleared on later scans even after definitions update. The discriminator is
    hashed, so no raw path/host ever appears in the signature itself.
    """

    rule_id = str(getattr(finding, "rule_id", "") or "")
    device = str(getattr(finding, "device_ip", "") or "")
    evidence = getattr(finding, "evidence", {}) or {}
    discriminator = ""
    if isinstance(evidence, dict):
        for key in _SIGNATURE_EVIDENCE_KEYS:
            value = evidence.get(key)
            if value not in (None, "", 0):
                discriminator = f"{key}={value}"
                break
    material = f"{rule_id}|{device}|{discriminator}"
    return "sig_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


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
            # Stable cross-scan identity used by the "clear risk" feature.
            "signature": finding_signature(self),
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
            # Additive, backward-compatible consumer-guidance fields. Existing
            # keys are unchanged; readers that do not know these simply ignore
            # them. Both are derived from data already present on the report.
            "disclaimer": REPORT_DISCLAIMER,
            "priority_actions": priority_actions(self),
        }

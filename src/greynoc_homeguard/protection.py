from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .baseline import BaselineStore, TRUST_QUARANTINED, TRUST_TRUSTED
from .definitions import (
    DEFINITION_FRESH_DAYS,
    UPDATE_STATUS_AVAILABLE,
    UPDATE_STATUS_CURRENT,
    UPDATE_STATUS_FAILED,
    UPDATE_STATUS_NEVER,
)
from .models import Device, Finding

NETWORK_PROTECTED = "Protected"
NETWORK_REVIEW = "Review Needed"
NETWORK_ACTION = "Action Needed"

DEVICE_TRUSTED = "Trusted"
DEVICE_NEW = "New Devices Found"
DEVICE_RISKY = "Risky Devices Found"

UPDATES_CURRENT = "Current"
UPDATES_AVAILABLE = "Update Available"
UPDATES_FAILED = "Update Failed"
UPDATES_NEVER = "Never Updated"


@dataclass
class ProtectionStatus:
    network: str = NETWORK_PROTECTED
    network_detail: str = "No active findings"
    device_trust: str = DEVICE_TRUSTED
    device_trust_detail: str = "All devices recognized"
    updates: str = UPDATES_NEVER
    updates_detail: str = "Run Update Definitions"
    quarantined_count: int = 0
    new_device_count: int = 0
    risky_device_count: int = 0
    high_severity_count: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "network": {"value": self.network, "detail": self.network_detail},
            "device_trust": {"value": self.device_trust, "detail": self.device_trust_detail},
            "updates": {"value": self.updates, "detail": self.updates_detail},
            "metrics": {
                "quarantined_count": self.quarantined_count,
                "new_device_count": self.new_device_count,
                "risky_device_count": self.risky_device_count,
                "high_severity_count": self.high_severity_count,
            },
            "metadata": dict(self.metadata),
        }


def _updates_status(definition_status: dict[str, Any]) -> tuple[str, str]:
    if not isinstance(definition_status, dict):
        return UPDATES_NEVER, "Definitions have not been downloaded yet."
    raw = str(definition_status.get("update_status") or UPDATE_STATUS_NEVER)
    age = definition_status.get("age_days")
    version = str(definition_status.get("definitions_version") or "unknown")
    age_text = "" if age is None else f" ({int(age)} day(s) old)"
    if raw == UPDATE_STATUS_FAILED:
        return UPDATES_FAILED, f"Last definition update failed{age_text}. Try again."
    if raw == UPDATE_STATUS_NEVER:
        return UPDATES_NEVER, "Run Update Definitions to download CVE/KEV intelligence."
    if raw == UPDATE_STATUS_AVAILABLE:
        return UPDATES_AVAILABLE, f"Definitions {version}{age_text}. Refresh recommended."
    if raw == UPDATE_STATUS_CURRENT:
        if isinstance(age, int) and age > DEFINITION_FRESH_DAYS:
            return UPDATES_AVAILABLE, f"Definitions {version} are {age} day(s) old."
        return UPDATES_CURRENT, f"Definitions {version}{age_text}."
    return UPDATES_NEVER, "Definition state unknown."


def _network_status(findings: list[Finding], quarantined_count: int) -> tuple[str, str, int]:
    high_count = sum(1 for f in findings if f.severity in {"critical", "high"})
    medium_count = sum(1 for f in findings if f.severity == "medium")
    if quarantined_count or high_count:
        return (
            NETWORK_ACTION,
            f"{quarantined_count} quarantined device(s), {high_count} high-priority finding(s).",
            high_count,
        )
    if medium_count or any(f.severity == "low" for f in findings):
        return (
            NETWORK_REVIEW,
            f"{medium_count} medium and {len(findings) - high_count - medium_count} lower findings to review.",
            high_count,
        )
    return NETWORK_PROTECTED, "No active findings.", high_count


def _device_trust_status(
    devices: list[Device],
    findings: list[Finding],
    baseline: BaselineStore | None,
) -> tuple[str, str, int, int]:
    new_count = sum(1 for f in findings if f.rule_id == "new_device")
    risky_count = 0
    quarantined_in_scan = 0
    if baseline is not None:
        seen = {device.fingerprint() for device in devices}
        for record in baseline.all_records():
            if record.get("trust") == TRUST_QUARANTINED and record.get("fingerprint") in seen:
                quarantined_in_scan += 1
    risky_findings = {
        f.device_ip
        for f in findings
        if f.severity in {"critical", "high"} or f.category == "exposed_service"
    }
    risky_count = len(risky_findings)
    if quarantined_in_scan or risky_count:
        return (
            DEVICE_RISKY,
            f"{risky_count} device(s) flagged as risky"
            + (f", {quarantined_in_scan} quarantined." if quarantined_in_scan else "."),
            new_count,
            risky_count,
        )
    if new_count:
        return (
            DEVICE_NEW,
            f"{new_count} new device(s) since the last known-device update.",
            new_count,
            risky_count,
        )
    trusted = (
        sum(1 for record in baseline.all_records() if record.get("trust") == TRUST_TRUSTED)
        if baseline is not None
        else len(devices)
    )
    return DEVICE_TRUSTED, f"{trusted} trusted device(s).", new_count, risky_count


def compute_protection_status(
    devices: list[Device],
    findings: list[Finding],
    *,
    definition_status: dict[str, Any] | None = None,
    baseline: BaselineStore | None = None,
) -> ProtectionStatus:
    quarantined_count = 0
    if baseline is not None:
        for record in baseline.all_records():
            if record.get("trust") == TRUST_QUARANTINED:
                quarantined_count += 1
    network, network_detail, high_count = _network_status(findings, quarantined_count)
    device_trust, device_trust_detail, new_count, risky_count = _device_trust_status(
        devices, findings, baseline
    )
    updates, updates_detail = _updates_status(definition_status or {})
    return ProtectionStatus(
        network=network,
        network_detail=network_detail,
        device_trust=device_trust,
        device_trust_detail=device_trust_detail,
        updates=updates,
        updates_detail=updates_detail,
        quarantined_count=quarantined_count,
        new_device_count=new_count,
        risky_device_count=risky_count,
        high_severity_count=high_count,
        metadata={
            "device_count": len(devices),
            "finding_count": len(findings),
        },
    )

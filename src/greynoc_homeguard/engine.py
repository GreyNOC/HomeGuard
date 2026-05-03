from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from uuid import uuid4

from .baseline import BaselineStore
from . import __version__
from .definitions import DefinitionManager
from .detection import HomeGuardDetectionEngine
from .models import Device, Finding, HomeGuardReport, utcnow
from .protection import compute_protection_status


@dataclass(slots=True)
class HomeGuardEngine:
    app_version: str = __version__
    definitions: dict[str, Any] | None = None
    definition_status: dict[str, Any] = field(default_factory=dict)
    detection_engine: HomeGuardDetectionEngine = field(init=False)

    def __post_init__(self) -> None:
        if self.definitions is None:
            manager = DefinitionManager()
            self.definitions = manager.load()
            self.definition_status = manager.status()
        elif not self.definition_status:
            self.definition_status = {
                "definitions_version": str(self.definitions.get("definitions_version") or "custom"),
                "updated_at": str(self.definitions.get("updated_at") or "unknown"),
                "kev_count": len(self.definitions.get("kev_catalog") or []),
                "recent_cve_count": len(self.definitions.get("recent_cves") or []),
                "update_status": str(self.definitions.get("update_status") or "current"),
            }
        self.detection_engine = HomeGuardDetectionEngine(self.definitions or {})

    def evaluate_device(self, device: Device, baseline: BaselineStore | None = None) -> list[Finding]:
        return self.detection_engine.evaluate_device(device, baseline)

    def build_report(
        self,
        devices: list[Device],
        *,
        baseline: BaselineStore | None = None,
        scan_metadata: dict[str, Any] | None = None,
    ) -> HomeGuardReport:
        findings = self.detection_engine.evaluate(devices, baseline)
        overall_score = round(max([finding.risk_score for finding in findings], default=0.0), 2)
        if overall_score >= 70:
            overall_risk = "high"
        elif overall_score >= 40:
            overall_risk = "medium"
        elif overall_score > 0:
            overall_risk = "low"
        else:
            overall_risk = "clean"
        protection = compute_protection_status(
            devices, findings, definition_status=self.definition_status, baseline=baseline
        )
        family_summary = build_family_summary(devices, baseline)
        quarantined = build_quarantined_inventory(devices, baseline)
        metadata = dict(scan_metadata or {})
        metadata.setdefault("app_version", self.app_version)
        metadata.setdefault("definition_status", self.definition_status)
        metadata.setdefault("detection_engine", self.detection_engine.health())
        metadata.setdefault("detection_telemetry", self.detection_engine.telemetry.as_dict())
        metadata["protection_status"] = protection.as_dict()
        metadata["family_summary"] = family_summary
        metadata["quarantined_devices"] = quarantined
        summary = self._summary(devices, findings, overall_risk, protection)
        return HomeGuardReport(
            report_id=f"hg_report_{uuid4().hex[:12]}",
            created_at=utcnow(),
            summary=summary,
            overall_risk=overall_risk,
            overall_score=overall_score,
            devices=devices,
            findings=findings,
            next_steps=self._top_next_steps(findings, protection),
            scan_metadata=metadata,
        )

    def _summary(
        self,
        devices: list[Device],
        findings: list[Finding],
        overall_risk: str,
        protection,
    ) -> str:
        if not findings:
            return f"HomeGuard found {len(devices)} device(s) and no active risk indicators."
        high_count = sum(1 for item in findings if item.severity in {"critical", "high"})
        med_count = sum(1 for item in findings if item.severity == "medium")
        kev_count = sum(1 for item in findings if item.category == "known_exploited_vulnerability")
        extras: list[str] = []
        if kev_count:
            extras.append(f"{kev_count} CVE/known-exploited vulnerability hint(s)")
        if protection.quarantined_count:
            extras.append(f"{protection.quarantined_count} quarantined device(s)")
        extra = (" " + ", ".join(extras) + ".") if extras else ""
        return (
            f"HomeGuard found {len(devices)} device(s), {len(findings)} finding(s), "
            f"{high_count} high-priority item(s), and {med_count} medium item(s). Overall risk is {overall_risk}.{extra}"
        )

    def _top_next_steps(self, findings: list[Finding], protection) -> list[str]:
        steps: list[str] = []
        if protection.quarantined_count:
            steps.append("Block your quarantined devices from the router or change the WiFi password.")
        if not findings:
            steps.extend(
                [
                    "Keep this scan as your current known-device baseline.",
                    "Run HomeGuard again after adding new smart-home devices.",
                    "Use Update Definitions regularly so CVE and security rules stay current.",
                ]
            )
            return steps[:6]
        if any(f.category in {"known_exploited_vulnerability", "security_update"} for f in findings):
            steps.append("Run device firmware/software updates for anything HomeGuard identified as a security-update priority.")
        for finding in findings:
            for action in finding.recommended_actions:
                if action not in steps:
                    steps.append(action)
                if len(steps) >= 6:
                    return steps
        return steps


def build_family_summary(devices: list[Device], baseline: BaselineStore | None) -> dict[str, Any]:
    by_owner: dict[str, int] = {}
    by_type: dict[str, int] = {}
    rows: list[dict[str, Any]] = []
    for device in devices:
        if baseline is not None and baseline.known(device):
            record = baseline.get(device)
            owner = str(record.get("owner") or "unknown")
            device_type = str(record.get("device_type") or "unknown")
        else:
            owner = "unknown"
            device_type = "unknown"
        by_owner[owner] = by_owner.get(owner, 0) + 1
        by_type[device_type] = by_type.get(device_type, 0) + 1
        rows.append(
            {
                "ip": device.ip,
                "name": device.hostname or device.vendor or device.ip,
                "owner": owner,
                "device_type": device_type,
            }
        )
    return {
        "by_owner": by_owner,
        "by_type": by_type,
        "devices": rows,
    }


def build_quarantined_inventory(devices: list[Device], baseline: BaselineStore | None) -> list[dict[str, Any]]:
    if baseline is None:
        return []
    seen = {device.fingerprint(): device for device in devices}
    rows: list[dict[str, Any]] = []
    for record in baseline.all_records():
        if record.get("trust") != "quarantined":
            continue
        fp = record.get("fingerprint", "")
        device = seen.get(fp)
        rows.append(
            {
                "fingerprint": fp,
                "ip": (device.ip if device else record.get("ip", "")),
                "name": (
                    (device.hostname or device.vendor or device.ip)
                    if device
                    else (record.get("hostname") or record.get("vendor") or record.get("ip", ""))
                ),
                "mac_address": (device.mac_address if device else record.get("mac_address", "")),
                "owner": record.get("owner") or "unknown",
                "device_type": record.get("device_type") or "unknown",
                "active_in_scan": device is not None,
                "first_seen": record.get("first_seen", ""),
                "last_seen": record.get("last_seen", ""),
                "notes": record.get("notes", ""),
            }
        )
    return rows

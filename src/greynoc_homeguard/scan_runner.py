"""Shared scan flow used by the GUI, tray, scheduler, and CLI.

This module is the single place that runs:

  network discovery -> detection engine -> protection status -> reports -> history.

It always uses the platform app-data directory for output and updates the
known-device store and protection history.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from types import SimpleNamespace

from .baseline import BaselineStore
from .definitions import DefinitionManager, active_scan_ports
from .edr.assessment import assess_endpoint_findings
from .diff import compute_scan_diff, load_previous_report, render_summary
from .engine import HomeGuardEngine
from .guidance import priority_actions
from .history import HistoryEntry, ProtectionHistory
from .logging_setup import get_logger
from .models import Finding, HomeGuardReport, finding_signature
from .network import detect_local_interfaces, discover_lan_hosts_noc_core
from .paths import default_baseline_path, default_output_dir, latest_report_dir
from .reports import export_report
from .scheduler import ScheduleManager
from .settings import AppSettings
from .virus_scanner import run_endpoint_malware_scan

LOG = get_logger("scan_runner")


def _emit(progress: Callable[[str], None] | None, message: str) -> None:
    if progress:
        progress(message)


def _risk_label(score: float) -> str:
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


def _refresh_report_risk(report: HomeGuardReport) -> None:
    report.overall_score = round(max([finding.risk_score for finding in report.findings], default=0.0), 2)
    report.overall_risk = _risk_label(report.overall_score)


def _add_unique_steps(existing: list[str], additions: list[str]) -> list[str]:
    steps = list(existing)
    for item in additions:
        if item and item not in steps:
            steps.append(item)
    return steps[:8]


def _attach_endpoint_scan(report: HomeGuardReport, findings: list[Finding], metadata: dict[str, object]) -> None:
    report.scan_metadata["endpoint_malware_scan"] = metadata
    if not findings:
        report.summary = f"{report.summary} Endpoint malware scan produced no additional findings."
        return
    report.findings.extend(findings)
    _refresh_report_risk(report)
    report.summary = (
        f"{report.summary} Endpoint malware scan added {len(findings)} local endpoint finding(s). "
        f"Overall risk is now {report.overall_risk}."
    )
    report.next_steps = _add_unique_steps(
        report.next_steps,
        [
            "Review endpoint malware findings for suspicious processes, startup entries, memory artifacts, or downloaded files.",
            "Run a full Microsoft Defender scan and remove unexpected downloaded executables or scripts.",
            "If a high-severity endpoint finding is unexpected, disconnect this PC from the network until reviewed.",
        ],
    )


def _partition_cleared(
    findings: list[Finding], cleared: set[str]
) -> tuple[list[Finding], list[Finding]]:
    """Split findings into (active, cleared) by stable signature."""
    if not cleared:
        return list(findings), []
    active: list[Finding] = []
    removed: list[Finding] = []
    for finding in findings:
        (removed if finding_signature(finding) in cleared else active).append(finding)
    return active, removed


def _build_this_device_summary(report: HomeGuardReport, local_ips: set[str]) -> dict[str, Any]:
    """Summarize only the findings that belong to THIS computer.

    "This device" = findings on a local interface IP plus endpoint/malware
    findings (which carry the ``local-host`` sentinel device IP). The Overview
    page uses this so it reflects the user's own machine, not other LAN devices.
    """
    local = set(local_ips) | {"local-host"}
    findings = [finding for finding in report.findings if finding.device_ip in local]
    score = round(max([finding.risk_score for finding in findings], default=0.0), 2)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        if finding.severity in severity_counts:
            severity_counts[finding.severity] += 1
    local_devices = [device for device in report.devices if device.ip in local_ips]
    open_services = sorted({port for device in local_devices for port in device.open_ports})
    device_name = next((device.hostname for device in local_devices if device.hostname), "") or "This PC"
    # Scope the prioritized guidance to this device's findings only (no other
    # LAN devices, no network-wide quarantine list).
    shim = SimpleNamespace(
        findings=findings,
        scan_metadata={
            "definition_status": report.scan_metadata.get("definition_status", {}),
            "quarantined_devices": [],
        },
    )
    return {
        "device_name": device_name,
        "overall_risk": _risk_label(score),
        "overall_score": score,
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "open_services": open_services,
        "open_service_count": len(open_services),
        "priority_actions": priority_actions(shim),
        "signatures": [finding_signature(finding) for finding in findings],
    }


def _scan_dir(timestamp: datetime | None = None) -> Path:
    when = (timestamp or datetime.now(timezone.utc)).strftime("%Y%m%dT%H%M%SZ")
    return default_output_dir() / when


def run_full_scan(
    *,
    active: bool = False,
    probe_all: bool = False,
    output_dir: str | Path | None = None,
    update_known_devices: bool = True,
    endpoint_scan: bool = False,
    progress: Callable[[str], None] | None = None,
) -> tuple[HomeGuardReport, dict[str, Path], HistoryEntry]:
    """Run a full scan, write reports, and update history.

    Returns the report, the dict of report file paths, and the new history entry.
    """

    LOG.info(
        "Scan start (active=%s, probe_all=%s, endpoint_scan=%s, output_dir=%s)",
        active,
        probe_all,
        endpoint_scan,
        str(output_dir) if output_dir else "<default>",
    )
    out = Path(output_dir) if output_dir else _scan_dir()
    _emit(progress, "Preparing local network and endpoint scan")
    # Source the active TCP probe set from the live security definitions so
    # every risky port the detection engine knows about is actually checked.
    # Falls back gracefully if the definitions store cannot be read.
    try:
        definitions = DefinitionManager().load()
        scan_ports = active_scan_ports(definitions)
    except Exception as exc:  # pragma: no cover - defensive
        LOG.warning("Falling back to built-in port list: %s", exc)
        scan_ports = active_scan_ports({})
    _emit(progress, "Network scan: detecting local interfaces")
    interfaces = detect_local_interfaces()
    _emit(
        progress,
        "Network scan: multi-vector discovery with active ICMP/TCP probes"
        if active
        else "Network scan: passive multi-vector discovery (ARP, neighbor, mDNS/SSDP)",
    )
    devices = discover_lan_hosts_noc_core(
        interfaces, active=active, probe_all=probe_all, tcp_ports=scan_ports
    )
    _emit(progress, f"Network scan: found {len(devices)} local device(s)")
    _emit(progress, "Loading local known-device trust database")
    baseline = BaselineStore(default_baseline_path()).load()
    cleared_signatures = AppSettings().load().cleared_signatures()
    metadata: dict[str, Any] = {
        "mode": "active" if active else "passive",
        "discovery_engine": "noc_core",
        "interfaces": [item.as_dict() for item in interfaces],
        "ports": list(scan_ports),
        "known_device_store": "local app data",
    }
    _emit(progress, "Detection engine: evaluating network risk rules")
    engine = HomeGuardEngine()
    report = engine.build_report(
        devices, baseline=baseline, scan_metadata=metadata, cleared_signatures=cleared_signatures
    )
    _emit(progress, f"Detection engine: emitted {len(report.findings)} network finding(s)")

    # Compute "what changed since last scan" using the previous report's
    # JSON. Done before endpoint findings are attached so the diff
    # reflects the same network-only baseline across scans.
    history_for_diff = ProtectionHistory().load()
    previous_entry = history_for_diff.latest()
    previous_report = (
        load_previous_report(previous_entry.json_path) if previous_entry else None
    )
    delta = compute_scan_diff(report, previous_report)
    report.scan_metadata["delta"] = delta
    summary_line = render_summary(delta)
    if summary_line:
        _emit(progress, summary_line)
    if endpoint_scan:
        endpoint_findings_for_assessment: list[Finding] = []
        try:
            endpoint = run_endpoint_malware_scan(progress=progress)
            # Drop endpoint findings the user has cleared so they are not
            # re-flagged each scan (and do not drive the EDR assessment).
            active_endpoint, cleared_endpoint = _partition_cleared(
                list(endpoint.findings or []), cleared_signatures
            )
            _attach_endpoint_scan(report, active_endpoint, endpoint.metadata)
            endpoint_findings_for_assessment = list(active_endpoint)
            if cleared_endpoint:
                existing = report.scan_metadata.get("cleared_findings")
                existing = list(existing) if isinstance(existing, list) else []
                existing.extend(finding.as_dict() for finding in cleared_endpoint)
                report.scan_metadata["cleared_findings"] = existing
                report.scan_metadata["cleared_finding_count"] = len(existing)
        except Exception as exc:
            LOG.error("Endpoint malware scan failed: %s", exc)
            report.scan_metadata["endpoint_malware_scan"] = {
                "scanner": "GreyNOC Endpoint Malware Indicator Scanner",
                "status": "failed",
                "error": str(exc),
            }
            # EDR Phase 1: a failed endpoint scan still gets an assessment
            # block so reports always have a consistent endpoint_assessment
            # key; the level is "not_run" so consumers don't alert on it.
            report.scan_metadata["endpoint_assessment"] = {
                "level": "not_run",
                "summary": "Endpoint assessment was not run because the endpoint scan failed.",
                "metadata": {"phase": "edr_phase_1", "reason": "endpoint_scan_failed"},
            }
        else:
            # EDR Phase 1: translate the endpoint findings into an evidence
            # chain + a single compromise level call, then attach to
            # report.scan_metadata so downstream JSON / HTML / PDF readers
            # can surface it without doing their own scoring.
            assessment = assess_endpoint_findings(
                endpoint_findings_for_assessment,
                metadata={"scanner": "homeguard_endpoint_scan"},
            )
            report.scan_metadata["endpoint_assessment"] = assessment.as_dict()
    else:
        # Endpoint scan disabled via --no-endpoint-scan. Stamp the field so
        # consumers always see *something* under endpoint_assessment.
        report.scan_metadata["endpoint_assessment"] = {
            "level": "not_run",
            "summary": "Endpoint assessment was not run for this scan.",
            "metadata": {"phase": "edr_phase_1", "reason": "endpoint_scan_disabled"},
        }
    # Per-computer ("this device") summary for the Overview page: scoped to this
    # machine's own findings and open services, computed from the interfaces we
    # already detected.
    local_ips = {iface.ip for iface in interfaces if iface.ip} | {"127.0.0.1", "::1"}
    report.scan_metadata["this_device"] = _build_this_device_summary(report, local_ips)

    _emit(progress, "Writing local HTML, PDF, JSON, and CSV reports")
    paths = export_report(report, out)
    if update_known_devices:
        _emit(progress, "Updating local known-device baseline")
        baseline.update(devices)
        baseline.save()

    # Mirror to "latest" for easy access from the tray and GUI.
    try:
        latest = latest_report_dir()
        latest.mkdir(parents=True, exist_ok=True)
        for src in paths.values():
            target = latest / src.name
            target.write_bytes(src.read_bytes())
        paths["latest_dir"] = latest
    except OSError as exc:
        LOG.warning("Could not mirror report to latest folder: %s", exc)

    history = ProtectionHistory().load()
    _emit(progress, "Saving scan history")
    entry = history.add(report, paths)
    history.save()

    try:
        schedule = ScheduleManager()
        schedule.load()
        if schedule.config.enabled:
            schedule.mark_ran()
    except Exception as exc:
        LOG.debug("Scheduler mark_ran skipped: %s", exc)

    LOG.info(
        "Scan complete (devices=%d, findings=%d, risk=%s, score=%s)",
        len(report.devices),
        len(report.findings),
        report.overall_risk,
        report.overall_score,
    )
    _emit(progress, f"Scan complete: {len(report.devices)} device(s), {len(report.findings)} finding(s), risk {report.overall_risk}")
    return report, paths, entry


def run_scheduled_scan() -> tuple[HomeGuardReport, dict[str, Path], HistoryEntry] | None:
    """Run the scan triggered by the scheduler / tray. Always passive."""

    schedule = ScheduleManager()
    schedule.load()
    try:
        result = run_full_scan(active=False, probe_all=False)
        schedule.mark_ran()
        return result
    except Exception as exc:
        LOG.error("Scheduled scan failed: %s", exc)
        return None


def latest_history_entry() -> HistoryEntry | None:
    return ProtectionHistory().load().latest()

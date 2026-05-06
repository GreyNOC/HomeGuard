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

from .baseline import BaselineStore
from .definitions import DefinitionManager, active_scan_ports
from .engine import HomeGuardEngine
from .history import HistoryEntry, ProtectionHistory
from .logging_setup import get_logger
from .models import Finding, HomeGuardReport
from .network import NetworkSensorConfig, detect_local_interfaces, discover_lan_hosts
from .paths import default_baseline_path, default_output_dir, latest_report_dir
from .reports import export_report
from .scheduler import ScheduleManager
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
    config = NetworkSensorConfig(
        passive_only=not active,
        allow_ping_sweep=active,
        allow_tcp_port_check=active,
        tcp_probe_all_hosts=probe_all,
        tcp_ports=scan_ports,
        max_hosts_per_scan=128,
        discovery_workers=32,
    )
    _emit(progress, "Network scan: detecting local interfaces")
    interfaces = detect_local_interfaces(config)
    _emit(
        progress,
        "Network scan: active ping sweep and TCP service checks"
        if active
        else "Network scan: reading local ARP and neighbor observations",
    )
    devices = discover_lan_hosts(config)
    _emit(progress, f"Network scan: found {len(devices)} local device(s)")
    _emit(progress, "Loading local known-device trust database")
    baseline = BaselineStore(default_baseline_path()).load()
    metadata: dict[str, Any] = {
        "mode": "active" if active else "passive",
        "interfaces": [item.as_dict() for item in interfaces],
        "ports": list(scan_ports),
        "known_device_store": "local app data",
    }
    _emit(progress, "Detection engine: evaluating network risk rules")
    engine = HomeGuardEngine()
    report = engine.build_report(devices, baseline=baseline, scan_metadata=metadata)
    _emit(progress, f"Detection engine: emitted {len(report.findings)} network finding(s)")
    if endpoint_scan:
        try:
            endpoint = run_endpoint_malware_scan(progress=progress)
            _attach_endpoint_scan(report, endpoint.findings, endpoint.metadata)
        except Exception as exc:
            LOG.error("Endpoint malware scan failed: %s", exc)
            report.scan_metadata["endpoint_malware_scan"] = {
                "scanner": "GreyNOC Endpoint Malware Indicator Scanner",
                "status": "failed",
                "error": str(exc),
            }
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

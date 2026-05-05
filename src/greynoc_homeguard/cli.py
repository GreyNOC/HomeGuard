from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from .baseline import (
    BaselineStore,
    OWNER_VALUES,
    DEVICE_TYPES,
    TRUST_VALUES,
    TRUST_UNKNOWN,
)
from .dashboard import serve_report
from .definitions import DefinitionManager
from .engine import HomeGuardEngine
from .history import ProtectionHistory
from .logging_setup import setup_logging
from .models import Device
from .paths import default_baseline_path, default_output_dir, ensure_app_dirs
from .reports import export_report
from .scan_runner import run_full_scan
from .scheduler import INTERVAL_VALUES, ScheduleManager


def _load_devices(path: str | Path) -> list[Device]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows: Any = data.get("devices") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ValueError("Input must be a list of devices or an object with a devices list.")
    return [Device.from_dict(row) for row in rows if isinstance(row, dict) and row.get("ip")]


def _print_paths(paths: dict[str, Path]) -> None:
    print("HomeGuard report written:")
    for key, path in paths.items():
        print(f"  {key:13s} {path}")


def cmd_scan(args: argparse.Namespace) -> int:
    def progress(message: str) -> None:
        print(f"[progress] {message}", flush=True)

    if args.out:
        report, paths, _entry = run_full_scan(
            active=args.active,
            probe_all=args.probe_all,
            output_dir=args.out,
            endpoint_scan=not args.no_endpoint_scan,
            progress=progress,
        )
    else:
        report, paths, _entry = run_full_scan(
            active=args.active,
            probe_all=args.probe_all,
            endpoint_scan=not args.no_endpoint_scan,
            progress=progress,
        )
    _print_paths(paths)
    print(f"  overall_risk  {report.overall_risk}")
    print(f"  overall_score {report.overall_score}")
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    devices = _load_devices(args.input)
    baseline = (
        BaselineStore(args.baseline or default_baseline_path()).load()
        if not getattr(args, "no_baseline", False)
        else None
    )
    report = HomeGuardEngine().build_report(
        devices,
        baseline=baseline,
        scan_metadata={
            "mode": "imported",
            "known_device_store": "local app data" if baseline is not None else "disabled",
        },
    )
    paths = export_report(report, args.out)
    if baseline is not None and not args.no_update_baseline:
        baseline.update(devices)
        baseline.save()
    _print_paths(paths)
    return 0


def cmd_update_definitions(args: argparse.Namespace) -> int:
    status = DefinitionManager().update_from_sources(nvd_days=args.nvd_days)
    print("HomeGuard security definitions updated:")
    print(f"  version       : {status.get('definitions_version')}")
    print(f"  last_updated  : {status.get('last_updated') or status.get('updated_at')}")
    print(f"  update_status : {status.get('update_status')}")
    print(f"  record_count  : {status.get('record_count')}")
    print(f"  CISA KEV      : {status.get('kev_count')}")
    print(f"  recent NVD    : {status.get('recent_cve_count')}")
    for source, details in (status.get("source_status") or {}).items():
        if isinstance(details, dict):
            state = "ok" if details.get("ok") else "problem"
            print(f"  {source}: {state} - {details.get('message')}")
    return 0


def cmd_definitions_status(_args: argparse.Namespace) -> int:
    status = DefinitionManager().status()
    print("HomeGuard security definitions:")
    print(f"  path          : {status.get('path')}")
    print(f"  version       : {status.get('definitions_version')}")
    print(f"  last_updated  : {status.get('last_updated') or status.get('updated_at')}")
    print(f"  update_status : {status.get('update_status')}")
    print(f"  age_days      : {status.get('age_days')}")
    print(f"  record_count  : {status.get('record_count')}")
    print(f"  CISA KEV      : {status.get('kev_count')}")
    print(f"  recent NVD    : {status.get('recent_cve_count')}")
    feed_versions = status.get("feed_versions") or {}
    for source, version in feed_versions.items():
        print(f"  feed[{source}]: {version}")
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    serve_report(args.report, host=args.host, port=args.port)
    return 0


def cmd_gui(_args: argparse.Namespace) -> int:
    from .gui import launch_gui

    launch_gui()
    return 0


def cmd_tray(_args: argparse.Namespace) -> int:
    from .tray import run_tray

    return run_tray()


def cmd_schedule_show(_args: argparse.Namespace) -> int:
    cfg = ScheduleManager().load()
    print("HomeGuard schedule:")
    print(f"  enabled            : {cfg.enabled}")
    print(f"  interval           : {cfg.interval}")
    print(f"  background_monitor : {cfg.background_monitor}")
    print(f"  last_run           : {cfg.last_run or 'never'}")
    print(f"  next_run           : {cfg.next_run or '-'}")
    return 0


def cmd_schedule_set(args: argparse.Namespace) -> int:
    manager = ScheduleManager()
    manager.load()
    enabled = None
    if args.enable:
        enabled = True
    if args.disable:
        enabled = False
    background = None
    if args.background:
        background = True
    if args.no_background:
        background = False
    interval = args.interval
    cfg = manager.set(enabled=enabled, interval=interval, background_monitor=background)
    print(
        f"Schedule saved: enabled={cfg.enabled}, interval={cfg.interval}, "
        f"background_monitor={cfg.background_monitor}, next_run={cfg.next_run or '-'}"
    )
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    history = ProtectionHistory().load()
    entries = history.entries()
    if not entries:
        print("No scans yet.")
        return 0
    for entry in entries[: args.limit]:
        print(
            f"{entry.created_at} | risk={entry.overall_risk} score={entry.overall_score} "
            f"devices={entry.device_count} findings={entry.finding_count} "
            f"highest={entry.highest_severity} html={entry.html_path}"
        )
    return 0


def cmd_devices_list(_args: argparse.Namespace) -> int:
    store = BaselineStore(default_baseline_path()).load()
    rows = store.all_records()
    if not rows:
        print("No known devices yet. Run a scan to populate the device list.")
        return 0
    for row in rows:
        print(
            f"{row.get('ip', '-'):<16}  trust={row.get('trust', TRUST_UNKNOWN):<12}  "
            f"owner={row.get('owner', 'unknown'):<8}  type={row.get('device_type', 'unknown'):<8}  "
            f"name={row.get('hostname') or row.get('vendor') or '-':<24}  "
            f"mac={row.get('mac_address') or '-':<17}  fingerprint={row.get('fingerprint', '')}"
        )
    return 0


def _resolve_fingerprint(store: BaselineStore, identifier: str) -> str | None:
    identifier = identifier.strip()
    if not identifier:
        return None
    rows = store.all_records()
    for row in rows:
        if row.get("fingerprint") == identifier:
            return identifier
    for row in rows:
        if row.get("ip") == identifier or row.get("mac_address", "").lower() == identifier.lower():
            return row.get("fingerprint")
    return None


def cmd_devices_trust(args: argparse.Namespace) -> int:
    store = BaselineStore(default_baseline_path()).load()
    fingerprint = _resolve_fingerprint(store, args.device)
    if not fingerprint:
        print(f"error: device not found: {args.device}", file=sys.stderr)
        return 2
    if not store.set_trust(fingerprint, args.trust):
        print(f"error: failed to set trust for {fingerprint}", file=sys.stderr)
        return 2
    store.save()
    print(f"Set trust={args.trust} for {fingerprint}")
    return 0


def cmd_devices_label(args: argparse.Namespace) -> int:
    store = BaselineStore(default_baseline_path()).load()
    fingerprint = _resolve_fingerprint(store, args.device)
    if not fingerprint:
        print(f"error: device not found: {args.device}", file=sys.stderr)
        return 2
    store.set_label(fingerprint, owner=args.owner, device_type=args.device_type, notes=args.notes)
    store.save()
    print(f"Updated labels for {fingerprint}")
    return 0


def cmd_devices_remove(args: argparse.Namespace) -> int:
    store = BaselineStore(default_baseline_path()).load()
    fingerprint = _resolve_fingerprint(store, args.device)
    if not fingerprint:
        print(f"error: device not found: {args.device}", file=sys.stderr)
        return 2
    if store.remove(fingerprint):
        store.save()
        print(f"Removed {fingerprint} from known devices.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="homeguard",
        description="HomeGuard consumer network protection",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan the local home network and this PC for endpoint malware indicators")
    scan.add_argument("--out", default="", help="Output directory (default: app data folder)")
    scan.add_argument("--active", action="store_true", help="Enable bounded active ping/TCP checks on private/local networks")
    scan.add_argument("--probe-all", action="store_true", help="Run TCP checks against all bounded active targets, not just passive hosts")
    scan.add_argument(
        "--no-endpoint-scan",
        action="store_true",
        help="Skip process, memory, browser download file, and startup persistence endpoint checks",
    )
    scan.set_defaults(func=cmd_scan)

    analyze = sub.add_parser("analyze", help="Analyze an existing device JSON file")
    analyze.add_argument("--input", required=True, help="Device JSON input file")
    analyze.add_argument("--out", default=str(default_output_dir() / "analyze"), help="Output directory")
    analyze.add_argument("--baseline", default="", help=argparse.SUPPRESS)
    analyze.add_argument("--no-baseline", action="store_true", help="Do not use/update the device trust store")
    analyze.add_argument("--no-update-baseline", action="store_true", help="Do not update trust store after report")
    analyze.set_defaults(func=cmd_analyze)

    update_defs = sub.add_parser("update-definitions", help="Update CVE and security definitions")
    update_defs.add_argument("--nvd-days", type=int, default=30, help="Number of recent NVD publication days to cache, max 120")
    update_defs.set_defaults(func=cmd_update_definitions)

    defs_status = sub.add_parser("definitions-status", help="Show local security definition status")
    defs_status.set_defaults(func=cmd_definitions_status)

    dash = sub.add_parser("dashboard", help="Serve a local dashboard for a report JSON")
    dash.add_argument("--report", required=True, help="Path to report.json")
    dash.add_argument("--host", default="127.0.0.1")
    dash.add_argument("--port", type=int, default=8765)
    dash.set_defaults(func=cmd_dashboard)

    gui = sub.add_parser("gui", help="Launch the desktop GUI")
    gui.set_defaults(func=cmd_gui)

    tray = sub.add_parser("tray", help="Launch the system tray protection mode")
    tray.set_defaults(func=cmd_tray)

    history = sub.add_parser("history", help="List past protection scans")
    history.add_argument("--limit", type=int, default=20)
    history.set_defaults(func=cmd_history)

    schedule = sub.add_parser("schedule", help="Manage scheduled scans")
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_show = schedule_sub.add_parser("show", help="Show current schedule")
    schedule_show.set_defaults(func=cmd_schedule_show)
    schedule_set = schedule_sub.add_parser("set", help="Update schedule settings")
    schedule_set.add_argument("--enable", action="store_true", help="Enable scheduled scans")
    schedule_set.add_argument("--disable", action="store_true", help="Disable scheduled scans")
    schedule_set.add_argument(
        "--interval",
        choices=sorted(INTERVAL_VALUES),
        help="Schedule interval",
    )
    schedule_set.add_argument("--background", action="store_true", help="Enable background monitor")
    schedule_set.add_argument("--no-background", action="store_true", help="Disable background monitor")
    schedule_set.set_defaults(func=cmd_schedule_set)

    devices = sub.add_parser("devices", help="Manage the device trust list")
    devices_sub = devices.add_subparsers(dest="devices_command", required=True)
    devices_list = devices_sub.add_parser("list", help="List known devices")
    devices_list.set_defaults(func=cmd_devices_list)
    devices_trust = devices_sub.add_parser("trust", help="Set trust for a device")
    devices_trust.add_argument("device", help="Device IP, MAC, or fingerprint")
    devices_trust.add_argument("trust", choices=sorted(TRUST_VALUES))
    devices_trust.set_defaults(func=cmd_devices_trust)
    devices_label = devices_sub.add_parser("label", help="Set family/device-type labels for a device")
    devices_label.add_argument("device", help="Device IP, MAC, or fingerprint")
    devices_label.add_argument("--owner", choices=sorted(OWNER_VALUES))
    devices_label.add_argument("--device-type", choices=sorted(DEVICE_TYPES))
    devices_label.add_argument("--notes", default=None)
    devices_label.set_defaults(func=cmd_devices_label)
    devices_remove = devices_sub.add_parser("remove", help="Remove a device from the known list")
    devices_remove.add_argument("device", help="Device IP, MAC, or fingerprint")
    devices_remove.set_defaults(func=cmd_devices_remove)

    return parser


def main(argv: list[str] | None = None) -> int:
    setup_logging()
    ensure_app_dirs()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

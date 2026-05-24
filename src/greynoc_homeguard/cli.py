from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import textwrap
import traceback
from pathlib import Path
from typing import Any

from . import __version__
from .baseline import (
    BaselineStore,
    OWNER_VALUES,
    DEVICE_TYPES,
    TRUST_VALUES,
    TRUST_UNKNOWN,
    TRUST_TRUSTED,
    TRUST_QUARANTINED,
)
from .custom_rules import (
    has_any_rules,
    load_custom_rules,
    write_example,
)
from .dashboard import serve_report
from .definitions import DefinitionManager
from .engine import HomeGuardEngine
from .history import ProtectionHistory
from .logging_setup import setup_logging
from .models import Device
from .playbooks import playbook_for_finding
from .paths import (
    custom_rules_file,
    default_baseline_path,
    default_output_dir,
    ensure_app_dirs,
    user_data_dir,
)
from .reports import export_report
from .scan_runner import run_full_scan
from .scheduler import INTERVAL_VALUES, ScheduleManager


_COLOR = False
_JSON_MODE = False
_DEBUG = False
_RESET = "\033[0m"
_PALETTE = {
    "blue": "\033[38;5;39m",
    "cyan": "\033[38;5;45m",
    "green": "\033[38;5;82m",
    "muted": "\033[38;5;245m",
    "red": "\033[38;5;203m",
    "yellow": "\033[38;5;220m",
    "bold": "\033[1m",
}
_SEVERITY_COLOR = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "info": "muted",
}
_RISK_COLOR = {
    "critical": "red",
    "high": "red",
    "medium": "yellow",
    "low": "cyan",
    "clean": "green",
    "unknown": "muted",
}
_BANNER = r"""
        /\                 HOME GUARD
       /  \          GNHL Direct App CLI
      / () \         Network Review Ready
     /______\        No npm wrapper required
"""
_APP_STYLE_COMMANDS = {
    "--status": "status",
    "--scan": "scan",
    "--update-definitions": "update-definitions",
    "--definitions-status": "definitions-status",
    "--dashboard": "dashboard",
    "--analyze": "analyze",
    "--gui": "gui",
    "--tray": "tray",
    "--history": "history",
    "--schedule": "schedule",
    "--devices": "devices",
}
_COMMAND_NAMES = set(_APP_STYLE_COMMANDS.values())
_GLOBAL_OPTIONS_WITH_VALUE = {"--color"}


class HomeGuardHelpFormatter(argparse.RawDescriptionHelpFormatter):
    def _format_action_invocation(self, action: argparse.Action) -> str:
        if not action.option_strings:
            return super()._format_action_invocation(action)
        opts = ", ".join(action.option_strings)
        if action.nargs == 0:
            return opts
        metavar = self._format_args(action, self._get_default_metavar_for_optional(action))
        return f"{opts} {metavar}"


def _terminal_width() -> int:
    return max(72, min(120, shutil.get_terminal_size((96, 24)).columns))


def _configure_color(mode: str) -> None:
    global _COLOR
    if mode == "always":
        _COLOR = True
        return
    if mode == "never" or os.environ.get("NO_COLOR"):
        _COLOR = False
        return
    if os.environ.get("FORCE_COLOR"):
        _COLOR = True
        return
    _COLOR = bool(getattr(sys.stdout, "isatty", lambda: False)()) and os.environ.get("TERM") != "dumb"


def _style(text: object, *names: str) -> str:
    value = str(text)
    if not _COLOR:
        return value
    codes = "".join(_PALETTE[name] for name in names if name in _PALETTE)
    return f"{codes}{value}{_RESET}" if codes else value


def _badge(value: object, palette: dict[str, str] | None = None) -> str:
    text = str(value or "-")
    color = (palette or {}).get(text.lower(), "muted")
    return _style(text.upper(), "bold", color)


def _muted(text: object) -> str:
    return _style(text, "muted")


def _command_base() -> str:
    launcher = os.environ.get("GNHL_LAUNCHER", "").lower()
    if launcher == "npm":
        return "npm run cli --"
    if launcher == "repo":
        return ".\\GNHL" if os.name == "nt" else "./GNHL"
    return "GNHL"


def _command(args: str = "") -> str:
    base = _command_base()
    return f"{base} {args}".strip()


def _has_explicit_subcommand(argv: list[str]) -> bool:
    index = 0
    while index < len(argv):
        token = argv[index]
        if token == "--":
            return False
        if token in _APP_STYLE_COMMANDS:
            return False
        if token in _GLOBAL_OPTIONS_WITH_VALUE:
            index += 2
            continue
        if any(token.startswith(f"{option}=") for option in _GLOBAL_OPTIONS_WITH_VALUE):
            index += 1
            continue
        if token.startswith("-"):
            index += 1
            continue
        return token in _COMMAND_NAMES
    return False


def _normalize_app_style_args(argv: list[str]) -> list[str]:
    if _has_explicit_subcommand(argv):
        return argv
    for index, token in enumerate(argv):
        command = _APP_STYLE_COMMANDS.get(token)
        if command is not None:
            return [*argv[:index], command, *argv[index + 1 :]]
    return argv


def _rule(title: str = "") -> None:
    width = _terminal_width()
    if title:
        title = f" {title} "
        side = max(2, (width - len(title)) // 2)
        print(_style("=" * side + title + "=" * max(2, width - side - len(title)), "muted"))
    else:
        print(_style("=" * width, "muted"))


def _wrap(value: object, width: int) -> list[str]:
    text = str(value if value is not None else "-")
    lines = textwrap.wrap(text, width=max(8, width), replace_whitespace=False) or [""]
    return lines


def _panel(title: str, rows: list[tuple[str, object]], *, accent: str = "cyan") -> None:
    key_width = max([len(key) for key, _value in rows] + [8])
    print(_style(f"\n[{title}]", "bold", accent))
    for key, value in rows:
        print(f"  {_muted(key.ljust(key_width))}  {value}")


def _clip(value: object, width: int) -> str:
    text = str(value if value is not None else "-")
    if len(text) <= width:
        return text
    return text[: max(0, width - 3)] + "..."


def _table(headers: list[str], rows: list[list[object]], *, max_cell: int = 34) -> None:
    if not rows:
        print(_muted("  No rows."))
        return
    widths: list[int] = []
    for index, header in enumerate(headers):
        values = [str(row[index] if index < len(row) else "") for row in rows]
        widths.append(min(max_cell, max(len(header), *(len(value) for value in values))))
    header_line = "  " + "  ".join(_style(header.ljust(widths[index]), "bold", "cyan") for index, header in enumerate(headers))
    print(header_line)
    print(_muted("  " + "  ".join("-" * width for width in widths)))
    for row in rows:
        cells = []
        for index, width in enumerate(widths):
            value = row[index] if index < len(row) else ""
            cells.append(_clip(value, width).ljust(width))
        print("  " + "  ".join(cells))


def _emit_json(payload: Any) -> None:
    print(json.dumps(payload, default=str, indent=2, sort_keys=True))


def _ok(message: str) -> None:
    print(f"{_style('[ok]', 'bold', 'green')} {message}")


def _warn(message: str) -> None:
    print(f"{_style('[!]', 'bold', 'yellow')} {message}")


def _section_title(title: str) -> None:
    print(_style(f"\n{title}", "bold", "blue"))


def _welcome(_parser: argparse.ArgumentParser) -> None:
    print(_style(_BANNER.rstrip(), "bold", "cyan"))
    print(_style("GNHL command center", "bold"))
    print(_muted("Direct app commands are ready. Use --scan, --status, and friends."))
    _panel(
        "App Commands",
        [
            ("scan", _command("--scan --active")),
            ("status", _command("--status")),
            ("devices", _command("--devices list")),
            ("dashboard", _command("--dashboard --report <report.json>")),
        ],
    )
    print()
    print(_muted(f"Subcommands still work too, for example `{_command('scan --active')}`."))
    print()
    print(_muted(f"Run `{_command('--help')}` for every command and option."))


def _parse_ports(value: str) -> list[int]:
    ports: list[int] = []
    for item in (value or "").split(","):
        item = item.strip()
        if not item:
            continue
        try:
            port = int(item)
        except ValueError:
            raise argparse.ArgumentTypeError(f"Invalid port: {item}")
        if not 0 < port <= 65535:
            raise argparse.ArgumentTypeError(f"Port out of range: {item}")
        ports.append(port)
    return sorted(set(ports))


def _load_devices(path: str | Path) -> list[Device]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rows: Any = data.get("devices") if isinstance(data, dict) else data
    if not isinstance(rows, list):
        raise ValueError("Input must be a list of devices or an object with a devices list.")
    return [Device.from_dict(row) for row in rows if isinstance(row, dict) and row.get("ip")]


def _print_paths(paths: dict[str, Path]) -> None:
    rows = [[key, path] for key, path in paths.items()]
    _section_title("Report Outputs")
    _table(["artifact", "path"], rows, max_cell=72)


def cmd_scan(args: argparse.Namespace) -> int:
    # In --json mode we suppress per-line progress chatter so the only thing
    # on stdout is a single JSON object the caller can parse.
    def progress(message: str) -> None:
        if _JSON_MODE:
            return
        print(f"{_style('[scan]', 'bold', 'cyan')} {message}", flush=True)

    if not _JSON_MODE:
        _rule("HomeGuard Scan")
    report, paths, _entry = run_full_scan(
        active=args.active,
        probe_all=args.probe_all,
        output_dir=args.out or None,
        endpoint_scan=not args.no_endpoint_scan,
        progress=progress,
    )
    if _JSON_MODE:
        _emit_json(
            {
                "report_id": report.report_id,
                "created_at": report.created_at,
                "overall_risk": report.overall_risk,
                "overall_score": report.overall_score,
                "device_count": len(report.devices),
                "finding_count": len(report.findings),
                "summary": report.summary,
                "paths": {key: str(path) for key, path in paths.items()},
            }
        )
        return 0
    _print_paths(paths)
    _panel(
        "Scan Summary",
        [
            ("risk", _badge(report.overall_risk, _RISK_COLOR)),
            ("score", f"{report.overall_score:.1f}"),
            ("devices", len(report.devices)),
            ("findings", len(report.findings)),
            ("report_id", report.report_id),
        ],
        accent="green" if str(report.overall_risk).lower() == "clean" else "yellow",
    )
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
    if _JSON_MODE:
        _emit_json(
            {
                "report_id": report.report_id,
                "overall_risk": report.overall_risk,
                "overall_score": report.overall_score,
                "device_count": len(report.devices),
                "finding_count": len(report.findings),
                "paths": {key: str(path) for key, path in paths.items()},
            }
        )
        return 0
    _print_paths(paths)
    return 0


def cmd_update_definitions(args: argparse.Namespace) -> int:
    status = DefinitionManager().update_from_sources(nvd_days=args.nvd_days)
    if _JSON_MODE:
        _emit_json(status)
        return 0
    _rule("Definition Update")
    _panel(
        "Security Definitions",
        [
            ("version", status.get("definitions_version")),
            ("updated", status.get("last_updated") or status.get("updated_at")),
            ("status", _badge(status.get("update_status"), {"current": "green", "update_available": "yellow", "update_failed": "red"})),
            ("records", status.get("record_count")),
            ("CISA KEV", status.get("kev_count")),
            ("recent NVD", status.get("recent_cve_count")),
        ],
    )
    source_rows = []
    for source, details in (status.get("source_status") or {}).items():
        if isinstance(details, dict):
            state = _badge("ok" if details.get("ok") else "problem", {"ok": "green", "problem": "red"})
            source_rows.append([source, state, details.get("message")])
    if source_rows:
        _section_title("Sources")
        _table(["source", "state", "message"], source_rows, max_cell=58)
    return 0


def cmd_import_definitions(args: argparse.Namespace) -> int:
    result = DefinitionManager().import_from_file(args.input)
    if not result.get("ok"):
        print(f"error: {result.get('message') or 'Import failed'}", file=sys.stderr)
        return 2
    print(f"Imported HomeGuard security definitions from {args.input}")
    print(f"  KEV records   : {result.get('kev_count', 0)}")
    print(f"  CVE records   : {result.get('cve_count', 0)}")
    print(f"  version       : {result.get('definitions_version')}")
    return 0


def cmd_custom_rules_show(_args: argparse.Namespace) -> int:
    path = custom_rules_file()
    custom = load_custom_rules(path)
    print("HomeGuard custom rules:")
    print(f"  path                : {path}")
    if not path.exists():
        print("  status              : no file (custom rules disabled)")
        print(f"  hint                : run `{_command('custom-rules init')}` to seed an example")
        return 0
    if not has_any_rules(custom):
        print("  status              : file exists but has zero valid rules")
        return 0
    print(f"  risky_ports         : {len(custom['risky_ports'])}")
    print(f"  watch_hostnames     : {len(custom['watch_hostnames'])}")
    print(f"  watch_mac_prefixes  : {len(custom['watch_mac_prefixes'])}")
    return 0


def cmd_custom_rules_init(args: argparse.Namespace) -> int:
    try:
        target = write_example(force=bool(args.force))
    except FileExistsError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"Wrote starter custom rules to {target}")
    print("Edit the file in any text editor, then run a scan to apply your rules.")
    return 0


def cmd_definitions_status(_args: argparse.Namespace) -> int:
    status = DefinitionManager().status()
    if _JSON_MODE:
        _emit_json(status)
        return 0
    _panel(
        "Security Definitions",
        [
            ("status", _badge(status.get("update_status"), {"current": "green", "update_available": "yellow", "update_failed": "red", "never_updated": "yellow"})),
            ("version", status.get("definitions_version")),
            ("updated", status.get("last_updated") or status.get("updated_at")),
            ("age_days", status.get("age_days")),
            ("records", status.get("record_count")),
            ("CISA KEV", status.get("kev_count")),
            ("recent NVD", status.get("recent_cve_count")),
            ("path", status.get("path")),
        ],
    )
    feed_versions = status.get("feed_versions") or {}
    if feed_versions:
        _section_title("Feeds")
        _table(["feed", "version"], [[source, version] for source, version in feed_versions.items()])
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    serve_report(
        args.report,
        host=args.host,
        port=args.port,
        allow_lan=getattr(args, "allow_lan", False),
    )
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
    if _JSON_MODE:
        _emit_json(
            {
                "enabled": cfg.enabled,
                "interval": cfg.interval,
                "background_monitor": cfg.background_monitor,
                "last_run": cfg.last_run,
                "next_run": cfg.next_run,
            }
        )
        return 0
    _panel(
        "Schedule",
        [
            ("enabled", _badge("on" if cfg.enabled else "off", {"on": "green", "off": "muted"})),
            ("interval", cfg.interval),
            ("background", _badge("on" if cfg.background_monitor else "off", {"on": "green", "off": "muted"})),
            ("last_run", cfg.last_run or "never"),
            ("next_run", cfg.next_run or "-"),
        ],
    )
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
    _ok("Schedule saved.")
    _panel(
        "Schedule",
        [
            ("enabled", _badge("on" if cfg.enabled else "off", {"on": "green", "off": "muted"})),
            ("interval", cfg.interval),
            ("background", _badge("on" if cfg.background_monitor else "off", {"on": "green", "off": "muted"})),
            ("next_run", cfg.next_run or "-"),
        ],
    )
    return 0


def cmd_history(args: argparse.Namespace) -> int:
    history = ProtectionHistory().load()
    entries = history.entries()
    if _JSON_MODE:
        _emit_json({"entries": [entry.as_dict() for entry in entries[: args.limit]]})
        return 0
    if not entries:
        _warn(f"No scans yet. Run `{_command('--scan')}` to create your first report.")
        return 0
    _section_title("Recent Scans")
    rows = []
    for entry in entries[: args.limit]:
        rows.append(
            [
                entry.created_at,
                _badge(entry.overall_risk, _RISK_COLOR),
                f"{entry.overall_score:.1f}",
                entry.device_count,
                entry.finding_count,
                _badge(entry.highest_severity, _SEVERITY_COLOR),
                entry.html_path,
            ]
        )
    _table(["created", "risk", "score", "devices", "findings", "highest", "html"], rows, max_cell=42)
    return 0


def cmd_devices_list(_args: argparse.Namespace) -> int:
    store = BaselineStore(default_baseline_path()).load()
    rows = store.all_records()
    if _JSON_MODE:
        _emit_json({"devices": rows})
        return 0
    if not rows:
        _warn(f"No known devices yet. Run `{_command('--scan')}` to populate the trust list.")
        return 0
    table_rows = []
    for row in rows:
        table_rows.append(
            [
                row.get("ip", "-"),
                _badge(row.get("trust", TRUST_UNKNOWN), {"trusted": "green", "unknown": "yellow", "quarantined": "red"}),
                row.get("owner", "unknown"),
                row.get("device_type", "unknown"),
                row.get("hostname") or row.get("vendor") or "-",
                row.get("mac_address") or "-",
                row.get("fingerprint", ""),
            ]
        )
    _section_title("Known Devices")
    _table(["ip", "trust", "owner", "type", "name", "mac", "fingerprint"], table_rows, max_cell=28)
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
    _ok(f"Set trust={args.trust} for {fingerprint}")
    return 0


def cmd_devices_label(args: argparse.Namespace) -> int:
    store = BaselineStore(default_baseline_path()).load()
    fingerprint = _resolve_fingerprint(store, args.device)
    if not fingerprint:
        print(f"error: device not found: {args.device}", file=sys.stderr)
        return 2
    store.set_label(fingerprint, owner=args.owner, device_type=args.device_type, notes=args.notes)
    store.save()
    _ok(f"Updated labels for {fingerprint}")
    return 0


def cmd_devices_remove(args: argparse.Namespace) -> int:
    store = BaselineStore(default_baseline_path()).load()
    fingerprint = _resolve_fingerprint(store, args.device)
    if not fingerprint:
        print(f"error: device not found: {args.device}", file=sys.stderr)
        return 2
    if store.remove(fingerprint):
        store.save()
        _ok(f"Removed {fingerprint} from known devices.")
    return 0


def cmd_playbook_show(args: argparse.Namespace) -> int:
    """Emit the fix-guidance playbook for a finding as JSON.

    Reads the finding's JSON from --finding-json (string), --finding-file
    (path), or stdin. The renderer uses this to populate the "Show me how
    to fix this" drawer.
    """
    finding_text = ""
    if getattr(args, "finding_json", None):
        finding_text = str(args.finding_json)
    elif getattr(args, "finding_file", None):
        try:
            finding_text = Path(args.finding_file).read_text(encoding="utf-8")
        except OSError as exc:
            print(f"error: could not read --finding-file: {exc}", file=sys.stderr)
            return 2
    else:
        try:
            finding_text = sys.stdin.read()
        except OSError as exc:
            print(f"error: could not read finding from stdin: {exc}", file=sys.stderr)
            return 2

    finding_text = finding_text.strip()
    if not finding_text:
        print("error: no finding JSON provided (use --finding-json, --finding-file, or stdin)", file=sys.stderr)
        return 2
    try:
        finding = json.loads(finding_text)
    except json.JSONDecodeError as exc:
        print(f"error: finding JSON is not valid: {exc}", file=sys.stderr)
        return 2
    if not isinstance(finding, dict):
        print("error: finding JSON must be an object", file=sys.stderr)
        return 2

    playbook = playbook_for_finding(finding)
    print(json.dumps(playbook.as_dict(), indent=2))
    return 0


def cmd_status(_args: argparse.Namespace) -> int:
    definitions = DefinitionManager().status()
    schedule = ScheduleManager().load()
    store = BaselineStore(default_baseline_path()).load()
    devices = store.all_records()
    trusted = sum(1 for row in devices if row.get("trust") == TRUST_TRUSTED)
    quarantined = sum(1 for row in devices if row.get("trust") == TRUST_QUARANTINED)
    unknown = max(0, len(devices) - trusted - quarantined)
    latest = ProtectionHistory().load().latest()

    if _JSON_MODE:
        _emit_json(
            {
                "protection": {
                    "known_devices": len(devices),
                    "trusted": trusted,
                    "unknown": unknown,
                    "quarantined": quarantined,
                    "data_dir": str(user_data_dir()),
                },
                "definitions": definitions,
                "schedule": {
                    "enabled": schedule.enabled,
                    "interval": schedule.interval,
                    "next_run": schedule.next_run,
                    "last_run": schedule.last_run,
                    "background_monitor": schedule.background_monitor,
                },
                "latest_scan": (
                    {
                        "created_at": latest.created_at,
                        "report_id": latest.report_id,
                        "overall_risk": latest.overall_risk,
                        "overall_score": latest.overall_score,
                        "device_count": latest.device_count,
                        "finding_count": latest.finding_count,
                        "html_path": latest.html_path,
                    }
                    if latest is not None
                    else None
                ),
            }
        )
        return 0

    _rule("Mission Control")
    _panel(
        "Protection",
        [
            ("known_devices", len(devices)),
            ("trusted", _style(trusted, "green" if trusted else "muted")),
            ("unknown", _style(unknown, "yellow" if unknown else "muted")),
            ("quarantined", _style(quarantined, "red" if quarantined else "muted")),
            ("data_dir", user_data_dir()),
        ],
    )
    _panel(
        "Definitions",
        [
            ("status", _badge(definitions.get("update_status"), {"current": "green", "update_available": "yellow", "update_failed": "red", "never_updated": "yellow"})),
            ("version", definitions.get("definitions_version")),
            ("updated", definitions.get("last_updated") or definitions.get("updated_at") or "never"),
            ("records", definitions.get("record_count")),
        ],
    )
    _panel(
        "Schedule",
        [
            ("enabled", _badge("on" if schedule.enabled else "off", {"on": "green", "off": "muted"})),
            ("interval", schedule.interval),
            ("next_run", schedule.next_run or "-"),
            ("background", _badge("on" if schedule.background_monitor else "off", {"on": "green", "off": "muted"})),
        ],
    )
    if latest is None:
        _warn(f"No scan history yet. `{_command('--scan')}` is the best first move.")
    else:
        _panel(
            "Latest Scan",
            [
                ("created", latest.created_at),
                ("risk", _badge(latest.overall_risk, _RISK_COLOR)),
                ("score", f"{latest.overall_score:.1f}"),
                ("devices", latest.device_count),
                ("findings", latest.finding_count),
                ("html", latest.html_path or "-"),
            ],
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="GNHL",
        description=_style(_BANNER.rstrip(), "bold", "cyan") + "\n\nHome Guard network indicator review",
        epilog=(
            "App-style runs:\n"
            f"  {_command('--status')}\n"
            f"  {_command('--scan --active')}\n"
            f"  {_command('--devices list')}\n"
            f"  {_command('--update-definitions --nvd-days 30')}\n\n"
            "Subcommands still work too, for example: "
            f"{_command('scan --active')}"
        ),
        formatter_class=HomeGuardHelpFormatter,
    )
    parser.add_argument(
        "--color",
        choices=("auto", "always", "never"),
        default="auto",
        help="Terminal color mode",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"GNHL {__version__}",
        help="Show GNHL version and exit",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_mode",
        help="Emit machine-readable JSON instead of styled tables (status, history, devices list, definitions-status, scan summary)",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print full Python traceback on errors (also enabled by HOMEGUARD_DEBUG=1)",
    )
    sub = parser.add_subparsers(dest="command", metavar="command")

    status = sub.add_parser("status", help="Show the Home Guard command-center overview", formatter_class=HomeGuardHelpFormatter)
    status.set_defaults(func=cmd_status)

    scan = sub.add_parser("scan", help="Scan the local home network and this PC for endpoint security indicators", formatter_class=HomeGuardHelpFormatter)
    scan.add_argument("--out", default="", help="Output directory (default: app data folder)")
    scan.add_argument("--active", action="store_true", help="Enable bounded active ping/TCP checks on private/local networks")
    scan.add_argument("--probe-all", action="store_true", help="Run TCP checks against all bounded active targets, not just passive hosts")
    scan.add_argument(
        "--no-endpoint-scan",
        action="store_true",
        help="Skip process, memory, browser download file, and startup persistence endpoint checks",
    )
    scan.set_defaults(func=cmd_scan)

    analyze = sub.add_parser("analyze", help="Analyze an existing device JSON file", formatter_class=HomeGuardHelpFormatter)
    analyze.add_argument("--input", required=True, help="Device JSON input file")
    analyze.add_argument("--out", default=str(default_output_dir() / "analyze"), help="Output directory")
    analyze.add_argument("--baseline", default="", help=argparse.SUPPRESS)
    analyze.add_argument("--no-baseline", action="store_true", help="Do not use/update the device trust store")
    analyze.add_argument("--no-update-baseline", action="store_true", help="Do not update trust store after report")
    analyze.set_defaults(func=cmd_analyze)

    update_defs = sub.add_parser("update-definitions", help="Update CVE and security definitions", formatter_class=HomeGuardHelpFormatter)
    update_defs.add_argument("--nvd-days", type=int, default=30, help="Number of recent NVD publication days to cache, max 120")
    update_defs.set_defaults(func=cmd_update_definitions)

    defs_status = sub.add_parser("definitions-status", help="Show local security definition status", formatter_class=HomeGuardHelpFormatter)
    defs_status.set_defaults(func=cmd_definitions_status)

    import_defs = sub.add_parser(
        "import-definitions",
        help="Import a HomeGuard security_definitions.json from another machine (offline / air-gapped)",
        formatter_class=HomeGuardHelpFormatter,
    )
    import_defs.add_argument("--input", required=True, help="Path to a HomeGuard security_definitions.json file")
    import_defs.set_defaults(func=cmd_import_definitions)

    custom = sub.add_parser(
        "custom-rules",
        help="Manage user-defined detection rules (custom_rules.json)",
        formatter_class=HomeGuardHelpFormatter,
    )
    custom_sub = custom.add_subparsers(dest="custom_command", required=True)
    custom_show = custom_sub.add_parser("show", help="Show current custom rules path and counts", formatter_class=HomeGuardHelpFormatter)
    custom_show.set_defaults(func=cmd_custom_rules_show)
    custom_init = custom_sub.add_parser("init", help="Write an example custom_rules.json into your app data folder", formatter_class=HomeGuardHelpFormatter)
    custom_init.add_argument("--force", action="store_true", help="Overwrite an existing file")
    custom_init.set_defaults(func=cmd_custom_rules_init)

    dash = sub.add_parser("dashboard", help="Serve a local dashboard for a report JSON", formatter_class=HomeGuardHelpFormatter)
    dash.add_argument("--report", required=True, help="Path to report.json")
    dash.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address (default: 127.0.0.1; non-loopback requires --allow-lan)",
    )
    dash.add_argument("--port", type=int, default=8765)
    dash.add_argument(
        "--allow-lan",
        action="store_true",
        help="Acknowledge that you intend to expose the report to your LAN. Required when --host is not a loopback address.",
    )
    dash.set_defaults(func=cmd_dashboard)

    gui = sub.add_parser("gui", help="Launch the desktop GUI", formatter_class=HomeGuardHelpFormatter)
    gui.set_defaults(func=cmd_gui)

    tray = sub.add_parser("tray", help="Launch the system tray protection mode", formatter_class=HomeGuardHelpFormatter)
    tray.set_defaults(func=cmd_tray)

    history = sub.add_parser("history", help="List past protection scans", formatter_class=HomeGuardHelpFormatter)
    history.add_argument("--limit", type=int, default=20)
    history.set_defaults(func=cmd_history)

    schedule = sub.add_parser("schedule", help="Manage scheduled scans", formatter_class=HomeGuardHelpFormatter)
    schedule_sub = schedule.add_subparsers(dest="schedule_command", required=True)
    schedule_show = schedule_sub.add_parser("show", help="Show current schedule", formatter_class=HomeGuardHelpFormatter)
    schedule_show.set_defaults(func=cmd_schedule_show)
    schedule_set = schedule_sub.add_parser("set", help="Update schedule settings", formatter_class=HomeGuardHelpFormatter)
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

    devices = sub.add_parser("devices", help="Manage the device trust list", formatter_class=HomeGuardHelpFormatter)
    devices_sub = devices.add_subparsers(dest="devices_command", required=True)
    devices_list = devices_sub.add_parser("list", help="List known devices", formatter_class=HomeGuardHelpFormatter)
    devices_list.set_defaults(func=cmd_devices_list)
    devices_trust = devices_sub.add_parser("trust", help="Set trust for a device", formatter_class=HomeGuardHelpFormatter)
    devices_trust.add_argument("device", help="Device IP, MAC, or fingerprint")
    devices_trust.add_argument("trust", choices=sorted(TRUST_VALUES))
    devices_trust.set_defaults(func=cmd_devices_trust)
    devices_label = devices_sub.add_parser("label", help="Set family/device-type labels for a device", formatter_class=HomeGuardHelpFormatter)
    devices_label.add_argument("device", help="Device IP, MAC, or fingerprint")
    devices_label.add_argument("--owner", choices=sorted(OWNER_VALUES))
    devices_label.add_argument("--device-type", choices=sorted(DEVICE_TYPES))
    devices_label.add_argument("--notes", default=None)
    devices_label.set_defaults(func=cmd_devices_label)
    devices_remove = devices_sub.add_parser("remove", help="Remove a device from the known list", formatter_class=HomeGuardHelpFormatter)
    devices_remove.add_argument("device", help="Device IP, MAC, or fingerprint")
    devices_remove.set_defaults(func=cmd_devices_remove)

    playbook = sub.add_parser(
        "playbook",
        help="Show the fix-guidance playbook for a finding",
        formatter_class=HomeGuardHelpFormatter,
    )
    playbook_sub = playbook.add_subparsers(dest="playbook_command")
    playbook_show = playbook_sub.add_parser(
        "show",
        help="Emit the playbook for a finding as JSON",
        formatter_class=HomeGuardHelpFormatter,
    )
    playbook_show.add_argument(
        "--finding-json",
        default=None,
        help="Finding JSON as a literal string (otherwise read from stdin)",
    )
    playbook_show.add_argument(
        "--finding-file",
        default=None,
        help="Path to a JSON file containing the finding (otherwise read from stdin)",
    )
    playbook_show.set_defaults(func=cmd_playbook_show)

    return parser


def main(argv: list[str] | None = None) -> int:
    global _JSON_MODE, _DEBUG
    setup_logging()
    ensure_app_dirs()
    raw_argv = list(sys.argv[1:] if argv is None else argv)
    if "--color" in raw_argv:
        index = raw_argv.index("--color")
        if index + 1 < len(raw_argv):
            _configure_color(raw_argv[index + 1])
        else:
            _configure_color("auto")
    else:
        _configure_color("auto")
    raw_argv = _normalize_app_style_args(raw_argv)
    parser = build_parser()
    args = parser.parse_args(raw_argv)
    _configure_color(args.color)
    _JSON_MODE = bool(getattr(args, "json_mode", False))
    _DEBUG = bool(getattr(args, "debug", False)) or os.environ.get("HOMEGUARD_DEBUG", "").lower() in {"1", "true", "yes"}
    if _JSON_MODE:
        # JSON output is meant to be parsed; ANSI escapes would corrupt it.
        _configure_color("never")
    if not hasattr(args, "func"):
        _welcome(parser)
        return 0
    try:
        return int(args.func(args))
    except Exception as exc:
        if _DEBUG:
            traceback.print_exc(file=sys.stderr)
        else:
            print(f"{_style('error:', 'bold', 'red')} {exc}", file=sys.stderr)
            print(_muted("  Run with --debug to see the full traceback."), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

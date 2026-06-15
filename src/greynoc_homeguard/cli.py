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
from .flow_source import collect_flow_edges
from .network_map import build_network_map
from .quarantine import QuarantineError, QuarantineVault
from .realtime import RealtimeWatcher, append_event, load_events
from .remediation import quarantine_findings, scan_and_remediate
from .reports import export_report
from .scan_runner import run_full_scan
from .scheduler import INTERVAL_VALUES, ScheduleManager
from .settings import AppSettings
from .signed_feed import load_signed_feed_file, update_hashes_from_url


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
    "--scan-file": "scan-file",
    "--scan-folder": "scan-folder",
    "--quarantine": "quarantine",
    "--watch": "watch",
    "--network-map": "network-map",
    "--flow": "flow",
    "--update-hashes": "update-hashes",
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
            ("scan file", _command("--scan-file <path> --quarantine")),
            ("real-time", _command("--watch")),
            ("quarantine", _command("--quarantine list")),
            ("hash feed", _command("--update-hashes --url <https-url>")),
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


def _render_file_findings(findings: list, actions: list[dict[str, Any]]) -> None:
    if findings:
        _section_title("Detections")
        rows = []
        for finding in findings:
            evidence = finding.evidence or {}
            rows.append(
                [
                    _badge(finding.severity, _SEVERITY_COLOR),
                    f"{finding.confidence:.2f}",
                    finding.rule_id,
                    evidence.get("path") or finding.title,
                ]
            )
        _table(["severity", "conf", "rule", "file"], rows, max_cell=52)
    else:
        _ok("No threats detected in the scanned path.")
    if actions:
        quarantined = [a for a in actions if a.get("action") == "quarantined"]
        skipped = [a for a in actions if a.get("action") == "skipped"]
        failed = [a for a in actions if a.get("action") == "failed"]
        _section_title("Remediation")
        if quarantined:
            _ok(f"Quarantined {len(quarantined)} file(s).")
            _table(
                ["entry_id", "rule", "file"],
                [[a.get("entry_id", "")[:12], a.get("rule_id", ""), a.get("path", "")] for a in quarantined],
                max_cell=52,
            )
        for action in failed:
            _warn(f"Could not quarantine {action.get('path')}: {action.get('error')}")
        if skipped:
            _warn(
                f"{len(skipped)} detection(s) left in place (below auto-quarantine bar). "
                "Review them and remove manually if unwanted."
            )


def cmd_scan_path(args: argparse.Namespace) -> int:
    """Scan an arbitrary file or folder for malware, optionally quarantining."""

    def progress(message: str) -> None:
        if _JSON_MODE:
            return
        print(f"{_style('[scan]', 'bold', 'cyan')} {message}", flush=True)

    target = Path(args.path)
    if not target.exists():
        print(f"error: path does not exist: {target}", file=sys.stderr)
        return 2

    if not _JSON_MODE:
        _rule(f"HomeGuard File Scan: {target.name}")
    result = scan_and_remediate(target, quarantine=bool(args.quarantine), progress=progress)
    findings = result["findings"]
    metadata = result["metadata"]
    actions = result["actions"]

    if _JSON_MODE:
        _emit_json(
            {
                "target": str(target),
                "files_scanned": metadata.get("files_scanned", 0),
                "finding_count": len(findings),
                "findings": [finding.as_dict() for finding in findings],
                "actions": actions,
                "metadata": metadata,
            }
        )
        return 0

    _render_file_findings(findings, actions)
    _panel(
        "Scan Summary",
        [
            ("target", str(target)),
            ("files_scanned", metadata.get("files_scanned", 0)),
            ("detections", len(findings)),
            ("quarantined", sum(1 for a in actions if a.get("action") == "quarantined")),
            ("hash_signatures", metadata.get("hash_signatures", 0)),
        ],
        accent="green" if not findings else "yellow",
    )
    if findings and not args.quarantine:
        print()
        print(_muted(f"Tip: re-run with --quarantine to neutralize high-confidence detections."))
    return 0


def _resolve_quarantine_entry(vault: QuarantineVault, identifier: str) -> str | None:
    """Resolve an entry id by exact match or unique prefix."""
    identifier = identifier.strip().lower()
    if not identifier:
        return None
    entries = vault.entries(include_inactive=True)
    for entry in entries:
        if entry.entry_id == identifier:
            return entry.entry_id
    matches = [entry.entry_id for entry in entries if entry.entry_id.startswith(identifier)]
    return matches[0] if len(matches) == 1 else None


def cmd_quarantine_list(_args: argparse.Namespace) -> int:
    vault = QuarantineVault().load()
    entries = vault.entries(include_inactive=getattr(_args, "all", False))
    if _JSON_MODE:
        _emit_json({"entries": [entry.public_dict() for entry in entries], "stats": vault.stats()})
        return 0
    if not entries:
        _ok("Quarantine vault is empty.")
        return 0
    _section_title("Quarantined Files")
    rows = []
    for entry in entries:
        rows.append(
            [
                entry.entry_id[:12],
                _badge(entry.severity or "-", _SEVERITY_COLOR),
                entry.original_name,
                entry.detection_rule,
                entry.status,
                entry.quarantined_at,
            ]
        )
    _table(["id", "severity", "name", "rule", "status", "quarantined"], rows, max_cell=40)
    stats = vault.stats()
    _panel(
        "Vault",
        [
            ("active", stats["active"]),
            ("restored", stats["restored"]),
            ("deleted", stats["deleted"]),
            ("active_bytes", stats["active_bytes"]),
            ("path", stats["vault_path"]),
        ],
    )
    return 0


def cmd_quarantine_restore(args: argparse.Namespace) -> int:
    vault = QuarantineVault().load()
    entry_id = _resolve_quarantine_entry(vault, args.entry_id)
    if not entry_id:
        print(f"error: no quarantine entry matches: {args.entry_id}", file=sys.stderr)
        return 2
    try:
        target = vault.restore(entry_id, dest=args.to or None, overwrite=bool(args.overwrite))
    except QuarantineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    _ok(f"Restored {entry_id[:12]} to {target}")
    return 0


def cmd_quarantine_delete(args: argparse.Namespace) -> int:
    vault = QuarantineVault().load()
    entry_id = _resolve_quarantine_entry(vault, args.entry_id)
    if not entry_id:
        print(f"error: no quarantine entry matches: {args.entry_id}", file=sys.stderr)
        return 2
    try:
        ok = vault.delete(entry_id)
    except QuarantineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if ok:
        _ok(f"Permanently deleted quarantined file {entry_id[:12]}")
    return 0


def cmd_quarantine_purge(args: argparse.Namespace) -> int:
    vault = QuarantineVault().load()
    if not args.yes:
        active = vault.stats()["active"]
        print(f"error: this permanently deletes {active} quarantined file(s). Re-run with --yes to confirm.", file=sys.stderr)
        return 2
    count = vault.purge()
    _ok(f"Purged {count} quarantined file(s).")
    return 0


def _print_realtime_events(events: list[dict[str, Any]], limit: int = 25) -> None:
    if not events:
        _ok("No real-time detections recorded yet.")
        return
    _section_title("Recent Real-Time Detections")
    rows = []
    for event in events[-limit:][::-1]:
        rows.append(
            [
                event.get("detected_at", ""),
                _badge(event.get("severity", "-"), _SEVERITY_COLOR),
                event.get("name", ""),
                event.get("quarantined", 0),
                ", ".join(event.get("rules", []) or []),
            ]
        )
    _table(["detected", "severity", "file", "quarantined", "rules"], rows, max_cell=40)


def cmd_watch(args: argparse.Namespace) -> int:
    """Run (or configure) the real-time file-system protection watcher."""
    settings = AppSettings().load()

    if getattr(args, "enable", False) or getattr(args, "disable", False):
        cfg = settings.set_realtime(enabled=bool(args.enable))
        _ok(f"Real-time protection {'enabled' if cfg['enabled'] else 'disabled'}.")
        return 0

    if getattr(args, "events", False):
        events = load_events()
        if _JSON_MODE:
            _emit_json({"events": events})
            return 0
        _print_realtime_events(events)
        return 0

    cfg = settings.realtime_config()
    directories = [Path(d) for d in (args.dir or cfg.get("directories") or [])]
    watcher = RealtimeWatcher(
        directories=directories,
        interval=float(args.interval if args.interval is not None else cfg.get("interval", 3.0)),
        settle_seconds=float(cfg.get("settle_seconds", 2.0)),
        auto_quarantine=not args.no_quarantine,
        scan_existing=bool(args.scan_existing),
    )

    def handle(event: dict[str, Any]) -> None:
        append_event(event)
        if not _JSON_MODE:
            tag = _style("[threat]", "bold", "red")
            quarantined = " (quarantined)" if event.get("quarantined") else ""
            print(f"{tag} {event.get('severity', '').upper()} {event.get('name', '')}{quarantined}", flush=True)

    watcher.on_event = handle
    watched = ", ".join(str(d) for d in (watcher.directories or [])) or "default download folders"

    if args.once:
        watcher.poll_once()  # prime
        events = watcher.poll_once()
        if _JSON_MODE:
            _emit_json({"events": events})
            return 0
        _ok(f"Single real-time pass complete: {len(events)} detection(s).")
        return 0

    import threading

    stop_event = threading.Event()
    _rule("HomeGuard Real-Time Protection")
    print(_muted(f"Watching: {watched}"))
    print(_muted("Press Ctrl+C to stop."))
    try:
        watcher.run(stop_event)
    except KeyboardInterrupt:
        stop_event.set()
        print()
        _ok("Real-time protection stopped.")
    return 0


def cmd_network_map(args: argparse.Namespace) -> int:
    """Emit the local-device + cloud-node network map."""
    # Per-device cloud edges from the router flow source (opt-in; returns [] when
    # disabled/unconfigured, so the map degrades to host-only cloud nodes).
    flow_edges = collect_flow_edges()
    network_map = build_network_map(
        resolve_dns=bool(getattr(args, "resolve_dns", False)),
        flow_edges=flow_edges or None,
    )
    if _JSON_MODE or args.json_out:
        _emit_json(network_map)
        return 0
    stats = network_map.get("stats", {})
    _rule("HomeGuard Network Map")
    _panel(
        "Map",
        [
            ("cidr", network_map.get("cidr") or "-"),
            ("local_devices", stats.get("local_device_count", 0)),
            ("inactive", stats.get("inactive_count", 0)),
            ("peripherals", stats.get("peripheral_count", 0)),
            ("cloud_nodes", stats.get("cloud_node_count", 0)),
            ("per_device_cloud", stats.get("per_device_cloud_edges", 0)),
            ("gateway", network_map.get("gateway_ip") or "-"),
        ],
    )
    rows = []
    for device in network_map.get("active_devices", []):
        rows.append([
            device.get("ip", "-"),
            _badge(device.get("type", "-"), {}),
            device.get("friendly_name", "-"),
            "local" if device.get("is_local") else ("router" if device.get("map_role") == "router" else ""),
            _badge(device.get("severity", "info"), _SEVERITY_COLOR),
        ])
    if rows:
        _section_title("Local Devices")
        _table(["ip", "type", "name", "role", "severity"], rows, max_cell=30)
    cloud = network_map.get("cloud_nodes", [])
    if cloud:
        _section_title("Cloud Nodes (this host)")
        _table(
            ["endpoint", "ports", "connections"],
            [[c.get("label") or c.get("ip"), ",".join(str(p) for p in c.get("ports", [])), c.get("connection_count", 0)] for c in cloud[:20]],
            max_cell=40,
        )
    return 0


def cmd_flow_status(_args: argparse.Namespace) -> int:
    """Show the router flow source (per-device cloud edges) configuration."""
    cfg = AppSettings().load().flow_source_config()
    if _JSON_MODE:
        safe = dict(cfg)
        safe["key_configured"] = bool(cfg.get("key_env") or cfg.get("key_path"))
        _emit_json(safe)
        return 0
    key_desc = (f"env:{cfg['key_env']}" if cfg["key_env"] else (cfg["key_path"] or "default ssh key/agent"))
    _panel(
        "Flow Source (per-device cloud)",
        [
            ("enabled", _badge("on" if cfg["enabled"] else "off", {"on": "green", "off": "muted"})),
            ("provider", cfg["provider"]),
            ("router", f"{cfg['user']}@{cfg['host']}:{cfg['port']}" if cfg["host"] else "-"),
            ("ssh key", key_desc),
        ],
    )
    print(_muted("  Per-device cloud edges are opt-in. `flow test` verifies connectivity; `flow set --enable` turns it on."))
    return 0


def cmd_flow_test(_args: argparse.Namespace) -> int:
    """Attempt to read per-device cloud edges from the configured router."""
    from .flow_source import test_connection

    cfg = AppSettings().load().flow_source_config()
    if not cfg.get("host"):
        print("error: no router host configured. Run `flow set --host <ip> --user <user>` first.", file=sys.stderr)
        return 2
    result = test_connection(cfg)
    if _JSON_MODE:
        _emit_json(result)
        return 0 if result.get("ok") else 2
    if not result.get("ok"):
        print(f"error: flow source test failed: {result.get('error')}", file=sys.stderr)
        return 2
    edges = result.get("edges", [])
    _ok(f"Collected {result.get('edge_count', 0)} device->cloud edge(s) from the router.")
    if edges:
        _table(
            ["device", "endpoint", "port", "proto"],
            [[e.get("src_lan_ip"), e.get("dst_ip"), e.get("dst_port"), e.get("proto")] for e in edges[:25]],
            max_cell=30,
        )
    else:
        _warn("Connected, but no device->cloud edges yet (conntrack may be empty or all LAN-internal).")
    return 0


def cmd_flow_set(args: argparse.Namespace) -> int:
    """Configure the router flow source."""
    settings = AppSettings().load()
    enabled = True if args.enable else (False if args.disable else None)
    cfg = settings.set_flow_source(
        enabled=enabled,
        host=args.host,
        user=args.user,
        port=args.port,
        key_path=args.key_path,
        key_env=args.key_env,
    )
    _ok("Flow source updated.")
    return cmd_flow_status(args) if not _JSON_MODE else (_emit_json(cfg) or 0)


def cmd_update_hashes(args: argparse.Namespace) -> int:
    """Download/apply a cryptographically-signed malware hash feed."""
    settings = AppSettings().load()
    if args.file:
        result = load_signed_feed_file(args.file)
        source = f"file {args.file}"
    else:
        url = args.url or settings.hash_feed_config().get("url")
        if not url:
            print("error: provide --url or --file (or set a feed URL in settings).", file=sys.stderr)
            return 2
        result = update_hashes_from_url(url)
        source = f"url {url}"
        if result.get("ok"):
            settings.set_hash_feed(url=url, last_updated=str(result.get("feed_version") or ""), last_status="ok")
        else:
            settings.set_hash_feed(last_status=str(result.get("message") or "failed"))

    if _JSON_MODE:
        _emit_json(result)
        return 0
    if not result.get("ok"):
        print(f"error: signed hash feed rejected ({source}): {result.get('message')}", file=sys.stderr)
        return 2
    _ok("Signed hash feed verified and applied.")
    _panel(
        "Hash Feed",
        [
            ("source", source),
            ("verified", _badge("yes", {"yes": "green"})),
            ("feed_version", result.get("feed_version")),
            ("new_hashes", result.get("added")),
            ("updated_hashes", result.get("updated")),
            ("total_hashes", result.get("total")),
        ],
        accent="green",
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
    print(f"  malware_hashes      : {len(custom.get('malware_hashes', []))}")
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

    scan_file = sub.add_parser(
        "scan-file",
        help="Scan a single file for malware (hash, content signature, heuristics)",
        formatter_class=HomeGuardHelpFormatter,
    )
    scan_file.add_argument("path", help="Path to the file to scan")
    scan_file.add_argument(
        "--quarantine",
        action="store_true",
        help="Neutralize high-confidence detections into the local quarantine vault",
    )
    scan_file.set_defaults(func=cmd_scan_path)

    scan_folder = sub.add_parser(
        "scan-folder",
        help="Recursively scan a folder for malware",
        formatter_class=HomeGuardHelpFormatter,
    )
    scan_folder.add_argument("path", help="Path to the folder to scan")
    scan_folder.add_argument(
        "--quarantine",
        action="store_true",
        help="Neutralize high-confidence detections into the local quarantine vault",
    )
    scan_folder.set_defaults(func=cmd_scan_path)

    quarantine = sub.add_parser(
        "quarantine",
        help="Manage the local malware quarantine vault",
        formatter_class=HomeGuardHelpFormatter,
    )
    quarantine_sub = quarantine.add_subparsers(dest="quarantine_command", required=True)
    q_list = quarantine_sub.add_parser("list", help="List quarantined files", formatter_class=HomeGuardHelpFormatter)
    q_list.add_argument("--all", action="store_true", help="Include restored and deleted entries")
    q_list.set_defaults(func=cmd_quarantine_list)
    q_restore = quarantine_sub.add_parser("restore", help="Restore a quarantined file", formatter_class=HomeGuardHelpFormatter)
    q_restore.add_argument("entry_id", help="Quarantine entry id (or unique prefix)")
    q_restore.add_argument("--to", default="", help="Restore to this path instead of the original location")
    q_restore.add_argument("--overwrite", action="store_true", help="Overwrite if the restore target already exists")
    q_restore.set_defaults(func=cmd_quarantine_restore)
    q_delete = quarantine_sub.add_parser("delete", help="Permanently delete a quarantined file", formatter_class=HomeGuardHelpFormatter)
    q_delete.add_argument("entry_id", help="Quarantine entry id (or unique prefix)")
    q_delete.set_defaults(func=cmd_quarantine_delete)
    q_purge = quarantine_sub.add_parser("purge", help="Permanently delete all quarantined files", formatter_class=HomeGuardHelpFormatter)
    q_purge.add_argument("--yes", action="store_true", help="Confirm permanent deletion of every quarantined file")
    q_purge.set_defaults(func=cmd_quarantine_purge)

    watch = sub.add_parser(
        "watch",
        help="Real-time protection: scan files for malware as they appear or change",
        formatter_class=HomeGuardHelpFormatter,
    )
    watch.add_argument("--dir", action="append", default=[], help="Directory to watch (repeatable; default: Downloads)")
    watch.add_argument("--interval", type=float, default=None, help="Seconds between scan passes (default: 3)")
    watch.add_argument("--no-quarantine", action="store_true", help="Detect and report only; do not auto-quarantine")
    watch.add_argument("--scan-existing", action="store_true", help="Scan files already present on the first pass too")
    watch.add_argument("--once", action="store_true", help="Run a single scan pass and exit (for cron/testing)")
    watch.add_argument("--events", action="store_true", help="Show recent real-time detections and exit")
    watch.add_argument("--enable", action="store_true", help="Persist real-time protection as enabled and exit")
    watch.add_argument("--disable", action="store_true", help="Persist real-time protection as disabled and exit")
    watch.set_defaults(func=cmd_watch)

    network_map = sub.add_parser(
        "network-map",
        help="Build the local-device + cloud-node network map (JSON for the GUI)",
        formatter_class=HomeGuardHelpFormatter,
    )
    network_map.add_argument("--json-out", action="store_true", help="Force JSON output even without the global --json flag")
    network_map.add_argument(
        "--resolve-dns",
        action="store_true",
        help="Reverse-DNS the cloud endpoints (off by default; sends current external IPs to your DNS resolver)",
    )
    network_map.set_defaults(func=cmd_network_map)

    flow = sub.add_parser(
        "flow",
        help="Per-device cloud edges from your router's conntrack (opt-in)",
        formatter_class=HomeGuardHelpFormatter,
    )
    flow_sub = flow.add_subparsers(dest="flow_command", required=True)
    flow_status = flow_sub.add_parser("status", help="Show the flow-source configuration", formatter_class=HomeGuardHelpFormatter)
    flow_status.set_defaults(func=cmd_flow_status)
    flow_test = flow_sub.add_parser("test", help="Test reading per-device cloud edges from the router", formatter_class=HomeGuardHelpFormatter)
    flow_test.set_defaults(func=cmd_flow_test)
    flow_set = flow_sub.add_parser("set", help="Configure the router flow source", formatter_class=HomeGuardHelpFormatter)
    flow_set.add_argument("--host", default=None, help="Router IP/hostname")
    flow_set.add_argument("--user", default=None, help="SSH user (default: root)")
    flow_set.add_argument("--port", type=int, default=None, help="SSH port (default: 22)")
    flow_set.add_argument("--key-path", dest="key_path", default=None, help="Path to the SSH private key")
    flow_set.add_argument("--key-env", dest="key_env", default=None, help="Name of an env var holding the SSH key path")
    flow_set.add_argument("--enable", action="store_true", help="Enable per-device cloud edges on the map")
    flow_set.add_argument("--disable", action="store_true", help="Disable per-device cloud edges")
    flow_set.set_defaults(func=cmd_flow_set)

    update_hashes = sub.add_parser(
        "update-hashes",
        help="Download/apply a cryptographically-signed malware hash feed",
        formatter_class=HomeGuardHelpFormatter,
    )
    update_hashes.add_argument("--url", default="", help="HTTPS URL of a signed hash feed (or set one in settings)")
    update_hashes.add_argument("--file", default="", help="Path to a signed hash feed file (offline / air-gapped)")
    update_hashes.set_defaults(func=cmd_update_hashes)

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

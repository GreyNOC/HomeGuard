"""System tray helper for GreyNOC HomeGuard.

The tray fails gracefully on platforms without ``pystray`` installed or
without an available system-tray host. In that case it logs a clear message
and exits with a non-zero return code so the caller can document the
limitation.
"""

from __future__ import annotations

import math
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Callable

from .definitions import DefinitionManager
from .logging_setup import get_logger
from .scheduler import ScheduleManager
from .scan_runner import run_scheduled_scan, latest_history_entry

LOG = get_logger("tray")

TrayCallback = Callable[[], None]


def _open_path(path: Path | str | None) -> None:
    if not path:
        return
    target = Path(str(path))
    if not target.exists():
        return
    webbrowser.open(target.resolve().as_uri())


def _make_icon_image():
    try:
        from PIL import Image, ImageDraw  # type: ignore
    except Exception:
        return None
    img = Image.new("RGBA", (64, 64), (2, 9, 18, 255))
    draw = ImageDraw.Draw(img)
    for y in range(64):
        ratio = y / 63
        r = int(2 + (4 - 2) * ratio)
        g = int(9 + (24 - 9) * ratio)
        b = int(18 + (43 - 18) * ratio)
        draw.line([(0, y), (63, y)], fill=(r, g, b, 255))
    draw.ellipse([6, 6, 58, 58], fill=(4, 28, 55, 255), outline=(255, 255, 255, 220), width=2)
    draw.ellipse([12, 12, 52, 52], fill=(8, 93, 190, 255))
    draw.ellipse([20, 20, 44, 44], fill=(48, 194, 255, 235))
    draw.ellipse([27, 27, 37, 37], fill=(218, 251, 255, 235))

    node_specs = [(-90, 25), (-42, 23), (0, 25), (42, 23), (90, 25), (138, 23), (180, 25), (222, 23)]
    nodes = []
    for degrees, radius in node_specs:
        angle = math.radians(degrees)
        nodes.append((32 + math.cos(angle) * radius, 32 + math.sin(angle) * radius))
    for start, end in [
        (0, 1), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6), (6, 7), (7, 0),
        (0, 2), (2, 4), (4, 6), (6, 0),
    ]:
        draw.line([nodes[start], nodes[end]], fill=(245, 254, 255, 235), width=3)
    for x, y in nodes:
        draw.ellipse([x - 4, y - 4, x + 4, y + 4], fill=(255, 255, 255, 255))
    return img


def _has_pystray() -> bool:
    try:
        import pystray  # noqa: F401
        return True
    except Exception:
        return False


class TrayController:
    """Small wrapper around pystray that can be driven from the Tk GUI."""

    def __init__(
        self,
        *,
        on_show: TrayCallback,
        on_scan: TrayCallback,
        on_open_report: TrayCallback,
        on_update_definitions: TrayCallback,
        on_quit: TrayCallback,
        title: str = "GreyNOC HomeGuard",
    ) -> None:
        self.on_show = on_show
        self.on_scan = on_scan
        self.on_open_report = on_open_report
        self.on_update_definitions = on_update_definitions
        self.on_quit = on_quit
        self.title = title
        self.icon = None
        self.available = False
        self.running = False
        self.error_message = ""
        self._thread: threading.Thread | None = None

    def start(self) -> bool:
        if self.running:
            return True
        if not _has_pystray():
            self.error_message = (
                "System tray support requires the optional 'pystray' and 'pillow' packages. "
                "Install them with: pip install pystray pillow"
            )
            LOG.warning(self.error_message)
            return False
        if sys.platform not in {"win32", "darwin"} and not _linux_tray_likely_available():
            self.error_message = "System tray is not supported in this environment."
            LOG.warning(self.error_message)
            return False

        import pystray  # type: ignore

        icon_image = _make_icon_image()
        if icon_image is None:
            self.error_message = "Pillow is required to render the tray icon. Install with: pip install pillow"
            LOG.warning(self.error_message)
            return False

        menu = pystray.Menu(
            pystray.MenuItem("Show GreyNOC", lambda _icon, _item: self.on_show(), default=True),
            pystray.MenuItem("Scan now", lambda _icon, _item: self.on_scan()),
            pystray.MenuItem("Open latest report", lambda _icon, _item: self.on_open_report()),
            pystray.MenuItem(
                "Update definitions",
                lambda _icon, _item: self.on_update_definitions(),
            ),
            pystray.MenuItem("Quit GreyNOC", lambda _icon, _item: self.on_quit()),
        )
        self.icon = pystray.Icon("GreyNOCHomeGuard", icon_image, self.title, menu)
        self.available = True
        self._thread = threading.Thread(target=self._run_icon, name="HomeGuardTray", daemon=True)
        self._thread.start()
        return True

    def _run_icon(self) -> None:
        if self.icon is None:
            return
        try:
            self.running = True
            LOG.info("Starting HomeGuard tray controller.")
            self.icon.run()
        except Exception as exc:
            self.error_message = str(exc)
            LOG.warning("Tray controller exited unexpectedly: %s", exc)
        finally:
            self.running = False

    def notify(self, title: str, message: str) -> None:
        if self.icon is None or not self.running:
            return
        try:
            self.icon.notify(message, title)
        except Exception as exc:
            LOG.debug("Tray notification failed: %s", exc)

    def stop(self) -> None:
        if self.icon is None:
            return
        try:
            self.icon.stop()
        except Exception as exc:
            LOG.debug("Tray stop failed: %s", exc)


def run_tray() -> int:
    """Run the HomeGuard tray application.

    Returns 0 if the tray ran and the user exited cleanly, non-zero on
    platforms or environments where the tray cannot start.
    """

    if not _has_pystray():
        message = (
            "System tray support requires the optional 'pystray' and 'pillow' packages. "
            "Install them with: pip install pystray pillow"
        )
        LOG.warning(message)
        sys.stderr.write(message + "\n")
        return 2

    if sys.platform not in {"win32", "darwin"} and not _linux_tray_likely_available():
        message = "System tray is not supported in this environment."
        LOG.warning(message)
        sys.stderr.write(message + "\n")
        return 3

    import pystray  # type: ignore

    icon_image = _make_icon_image()
    if icon_image is None:
        message = "Pillow is required to render the tray icon. Install with: pip install pillow"
        LOG.warning(message)
        sys.stderr.write(message + "\n")
        return 4

    schedule_manager = ScheduleManager()
    schedule_manager.load()
    stop_event = threading.Event()
    scan_lock = threading.Lock()

    def notify(icon, title: str, message: str) -> None:
        try:
            icon.notify(message, title)
        except Exception as exc:
            LOG.debug("Tray notification failed: %s", exc)

    def scan_in_background(icon, reason: str) -> None:
        if not scan_lock.acquire(blocking=False):
            notify(icon, "GreyNOC", "A scan is already running.")
            return
        try:
            notify(icon, "GreyNOC", f"{reason} scan started.")
            result = run_scheduled_scan()
            if result is None:
                notify(icon, "GreyNOC", "Background scan failed. Check the logs for details.")
                return
            report, _paths, _entry = result
            notify(
                icon,
                "GreyNOC",
                f"Scan complete: {len(report.devices)} devices, {len(report.findings)} findings.",
            )
        finally:
            scan_lock.release()

    def on_scan(icon, _item) -> None:
        threading.Thread(target=scan_in_background, args=(icon, "Manual"), daemon=True).start()

    def on_open_dashboard(_icon, _item) -> None:
        from .gui import launch_gui

        threading.Thread(target=launch_gui, daemon=True).start()

    def on_open_report(_icon, _item) -> None:
        entry = latest_history_entry()
        if entry and entry.html_path:
            _open_path(entry.html_path)

    def on_update(_icon, _item) -> None:
        threading.Thread(target=DefinitionManager().update_from_sources, daemon=True).start()

    def on_toggle_monitor(icon, item) -> None:
        cfg = schedule_manager.load()
        schedule_manager.set(background_monitor=not cfg.background_monitor)
        icon.update_menu()

    def is_monitor_on(_item) -> bool:
        return bool(schedule_manager.load().background_monitor)

    def on_exit(icon, _item) -> None:
        stop_event.set()
        icon.stop()

    # Real-time protection: a polling watcher that scans new/changed files in
    # the watched folders and auto-quarantines high-confidence threats. Its
    # menu item toggles the persisted setting; the watcher thread starts/stops
    # to match.
    from .settings import AppSettings

    watcher_state: dict[str, object] = {"thread": None}

    def realtime_enabled() -> bool:
        return bool(AppSettings().load().realtime_config().get("enabled"))

    def is_realtime_on(_item) -> bool:
        return realtime_enabled()

    def start_watcher(icon) -> None:
        if watcher_state.get("thread") is not None:
            return
        try:
            from .realtime import RealtimeWatcher, append_event

            cfg = AppSettings().load().realtime_config()

            def on_event(event: dict) -> None:
                append_event(event)
                notify(
                    icon,
                    "GreyNOC real-time protection",
                    f"{str(event.get('severity', '')).upper()} threat caught: {event.get('name', '')}"
                    + (" (quarantined)" if event.get("quarantined") else ""),
                )

            watcher = RealtimeWatcher(
                directories=[__import__("pathlib").Path(d) for d in cfg.get("directories", [])],
                interval=float(cfg.get("interval", 3.0)),
                settle_seconds=float(cfg.get("settle_seconds", 2.0)),
                auto_quarantine=bool(cfg.get("auto_quarantine", True)),
                on_event=on_event,
            )
            thread = threading.Thread(target=watcher.run, args=(stop_event,), name="HomeGuardWatcher", daemon=True)
            thread.start()
            watcher_state["thread"] = thread
            LOG.info("Real-time protection watcher started from tray.")
        except Exception as exc:  # pragma: no cover - defensive
            LOG.warning("Could not start real-time watcher: %s", exc)

    def on_toggle_realtime(icon, _item) -> None:
        settings = AppSettings().load()
        new_value = not settings.realtime_config().get("enabled")
        settings.set_realtime(enabled=new_value)
        if new_value:
            start_watcher(icon)
            notify(icon, "GreyNOC", "Real-time protection enabled.")
        else:
            notify(icon, "GreyNOC", "Real-time protection will stop on next exit.")
        icon.update_menu()

    def monitor_loop(icon) -> None:
        if realtime_enabled():
            start_watcher(icon)
        while not stop_event.is_set():
            cfg = schedule_manager.load()
            if cfg.background_monitor and schedule_manager.is_due():
                scan_in_background(icon, "Scheduled")
            stop_event.wait(60)

    menu = pystray.Menu(
        pystray.MenuItem("Scan now", on_scan),
        pystray.MenuItem("Open dashboard", on_open_dashboard, default=True),
        pystray.MenuItem("Open latest report", on_open_report),
        pystray.MenuItem("Update definitions", on_update),
        pystray.MenuItem(
            "Background monitor",
            on_toggle_monitor,
            checked=is_monitor_on,
        ),
        pystray.MenuItem(
            "Real-time protection",
            on_toggle_realtime,
            checked=is_realtime_on,
        ),
        pystray.MenuItem("Exit", on_exit),
    )

    icon = pystray.Icon("GreyNOCHomeGuard", icon_image, "GreyNOC HomeGuard", menu)
    LOG.info("Starting HomeGuard tray.")
    icon.run(setup=lambda active_icon: threading.Thread(target=monitor_loop, args=(active_icon,), daemon=True).start())
    LOG.info("HomeGuard tray exited.")
    return 0


def _linux_tray_likely_available() -> bool:
    import os

    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))

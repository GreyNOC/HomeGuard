"""HomeGuard desktop GUI.

Security-indicator protection center built on Tkinter (no external deps required).
The GUI surfaces three protection status cards, scan history, scheduled scans,
the device trust list (trust / quarantine / remove / family labels), and a
logs viewer.
"""

from __future__ import annotations

import os
import queue
import shutil
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path
from tkinter import (
    BOTH,
    END,
    LEFT,
    NS,
    NSEW,
    X,
    BooleanVar,
    Canvas,
    StringVar,
    Tk,
    Toplevel,
    filedialog,
    messagebox,
    simpledialog,
    ttk,
)
from tkinter.scrolledtext import ScrolledText
from typing import Any

from .baseline import (
    BaselineStore,
    DEVICE_TYPES,
    OWNER_VALUES,
    TRUST_QUARANTINED,
    TRUST_TRUSTED,
    TRUST_UNKNOWN,
)
from .definitions import DefinitionManager
from .firewall import close_local_port, finding_is_local, port_from_finding, reopen_local_port
from .history import ProtectionHistory
from .logging_setup import get_logger, log_file_path, setup_logging
from .models import HomeGuardReport
from .paths import default_baseline_path, ensure_app_dirs, latest_report_dir, logs_dir
from .scan_runner import run_full_scan
from .scheduler import INTERVAL_VALUES, ScheduleManager
from .settings import AppSettings
from .tray import TrayController

LOG = get_logger("gui")

BRAND_NAVY = "#050B18"
BRAND_DEEP_BLUE = "#0F2A68"
BRAND_BLUE = "#174EA6"
BRAND_CYAN = "#22D3EE"
BRAND_BG = "#EEF3FA"
BRAND_TEXT = "#172033"
BRAND_MUTED = "#64748B"
BRAND_LINE = "#D8E2F1"
BRAND_GREEN = "#16A34A"
BRAND_AMBER = "#D97706"
BRAND_RED = "#DC2626"


def _open_in_explorer(path: Path) -> None:
    path = Path(path)
    if not path.exists():
        return
    if sys.platform == "win32":
        os.startfile(str(path))  # type: ignore[attr-defined]
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def _is_windows_admin() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _relaunch_elevated() -> bool:
    if sys.platform != "win32":
        return False
    try:
        import ctypes

        if getattr(sys, "frozen", False):
            executable = sys.executable
            params = " ".join(f'"{arg}"' for arg in sys.argv[1:])
        else:
            executable = sys.executable
            params = "-m greynoc_homeguard gui"
        result = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            executable,
            params,
            str(Path.cwd()),
            1,
        )
        return int(result) > 32
    except Exception as exc:
        LOG.debug("Admin relaunch failed: %s", exc)
        return False


class HomeGuardGui:
    def __init__(self) -> None:
        ensure_app_dirs()
        setup_logging()
        self.root = Tk()
        self.root.title("HomeGuard")
        self.root.geometry("1280x860")
        self.root.minsize(1040, 720)
        self.root.configure(bg=BRAND_BG)
        self.root.protocol("WM_DELETE_WINDOW", self._on_window_close)
        self.root.bind("<Unmap>", self._on_window_unmap)

        self.definition_manager = DefinitionManager()
        self.definition_status = self.definition_manager.status()
        self.history = ProtectionHistory().load()
        self.schedule_manager = ScheduleManager()
        self.schedule_manager.load()
        self.trust_store = BaselineStore(default_baseline_path()).load()
        self.settings = AppSettings().load()
        scan_defaults = self.settings.scan_defaults()

        self.active_scan = BooleanVar(value=scan_defaults["active_scan"])
        self.probe_all = BooleanVar(value=scan_defaults["probe_all"])
        self.schedule_enabled = BooleanVar(value=self.schedule_manager.config.enabled)
        self.schedule_background = BooleanVar(value=self.schedule_manager.config.background_monitor)
        self.schedule_interval = StringVar(value=self.schedule_manager.config.interval)

        self.network_card_value = StringVar(value="Protected")
        self.network_card_detail = StringVar(value="Run a scan to populate protection status")
        self.device_card_value = StringVar(value="Trusted")
        self.device_card_detail = StringVar(value="Known devices are stored automatically")
        self.updates_card_value = StringVar(value=self._updates_value())
        self.updates_card_detail = StringVar(value=self._definitions_text())
        self.definitions_text = StringVar(value=self._definitions_text())
        self.status = StringVar(value="HomeGuard ready")
        self.scan_indicator_text = StringVar(value="Ready")

        self.last_paths: dict[str, Path] = {}
        self.last_report: HomeGuardReport | None = None
        self._finding_by_id: dict[str, Any] = {}
        self._closed_ports: set[int] = set()
        self._messages: queue.Queue[tuple[str, object]] = queue.Queue()
        self._onboarding_window: Toplevel | None = None
        self._onboarding_step = 0
        self._onboarding_waiting_for_scan = False
        self.finding_port_action_text = StringVar(value="Close Port")
        self._definition_update_running = False
        self._exit_requested = False
        self._hidden_to_tray = False
        self._scan_running = False
        self._scan_indicator_after_id: str | None = None
        self._scan_indicator_frame = 0
        self._scan_indicator_running = False
        self._suppress_iconify_to_tray = False
        self._tray: TrayController | None = None

        self._configure_style()
        self._build_layout()
        self._start_tray()
        self.root.after(150, self._drain_messages)
        self.root.after(5000, self._background_monitor_tick)
        if self.settings.onboarding_needed():
            self.root.after(350, self._show_onboarding)
        self._refresh_status_from_history()

    # ------------------------------------------------------------------
    # styling
    # ------------------------------------------------------------------
    def _configure_style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TFrame", background=BRAND_BG)
        style.configure("Card.TFrame", background="white", relief="solid", borderwidth=1)
        style.configure("TLabelframe", background=BRAND_BG, bordercolor=BRAND_LINE, relief="solid")
        style.configure(
            "TLabelframe.Label",
            background=BRAND_BG,
            foreground=BRAND_TEXT,
            font=("Segoe UI", 10, "bold"),
        )
        style.configure("TLabel", background=BRAND_BG, foreground=BRAND_TEXT, font=("Segoe UI", 10))
        style.configure("Card.TLabel", background="white", foreground=BRAND_TEXT, font=("Segoe UI", 10))
        style.configure(
            "Muted.TLabel", background=BRAND_BG, foreground=BRAND_MUTED, font=("Segoe UI", 9)
        )
        style.configure(
            "CardMuted.TLabel", background="white", foreground=BRAND_MUTED, font=("Segoe UI", 9)
        )
        style.configure("TButton", font=("Segoe UI", 9, "bold"), padding=(10, 7))
        style.configure("Accent.TButton", background=BRAND_BLUE, foreground="white")
        style.map(
            "Accent.TButton",
            background=[("active", "#1D4ED8")],
            foreground=[("active", "white")],
        )
        style.configure("Danger.TButton", background=BRAND_RED, foreground="white")
        style.map(
            "Danger.TButton",
            background=[("active", "#B91C1C")],
            foreground=[("active", "white")],
        )
        style.configure(
            "Scan.TButton",
            background="#EF233C",
            foreground="white",
            font=("Segoe UI", 12, "bold"),
            padding=(22, 10),
        )
        style.map(
            "Scan.TButton",
            background=[("active", "#C1121F")],
            foreground=[("active", "white")],
        )
        style.configure(
            "Treeview",
            rowheight=28,
            fieldbackground="white",
            background="white",
            foreground=BRAND_TEXT,
            bordercolor=BRAND_LINE,
        )
        style.configure(
            "Treeview.Heading",
            font=("Segoe UI", 9, "bold"),
            background="#EAF1FB",
            foreground=BRAND_TEXT,
        )
        style.configure("TNotebook", background=BRAND_BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab",
            background="#E2E8F0",
            foreground=BRAND_TEXT,
            padding=(16, 8),
            font=("Segoe UI", 10, "bold"),
        )
        style.map(
            "TNotebook.Tab",
            background=[("selected", BRAND_BLUE)],
            foreground=[("selected", "white")],
        )

    def _definitions_text(self) -> str:
        age = self.definition_status.get("age_days")
        age_text = "never updated" if age is None else f"{age} day(s) old"
        return (
            f"Definitions {self.definition_status.get('definitions_version', 'unknown')} | "
            f"Status: {self.definition_status.get('update_status', 'unknown')} | "
            f"CISA KEV: {self.definition_status.get('kev_count', 0)} | "
            f"Recent CVEs: {self.definition_status.get('recent_cve_count', 0)} | {age_text}"
        )

    def _updates_value(self) -> str:
        raw = str(self.definition_status.get("update_status") or "never_updated")
        return {
            "current": "Current",
            "update_available": "Update Available",
            "update_failed": "Update Failed",
            "never_updated": "Never Updated",
        }.get(raw, "Never Updated")

    # ------------------------------------------------------------------
    # layout
    # ------------------------------------------------------------------
    def _build_layout(self) -> None:
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill=BOTH, expand=True)

        self.hero = Canvas(outer, height=140, highlightthickness=0, bd=0)
        self.hero.pack(fill=X)
        self.hero.bind("<Configure>", self._draw_header)

        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill=BOTH, expand=True, pady=(12, 0))

        self._build_dashboard_tab()
        self._build_devices_tab()
        self._build_history_tab()
        self._build_schedule_tab()
        self._build_logs_tab()

        footer = ttk.Label(
            outer,
            textvariable=self.status,
            style="Muted.TLabel",
        )
        footer.pack(fill=X, pady=(8, 0))

    # ------------------------------------------------------------------
    # tabs
    # ------------------------------------------------------------------
    def _build_dashboard_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Protection")

        cards = ttk.Frame(tab)
        cards.pack(fill=X, pady=(0, 12))
        self._status_card(
            cards, "Network Protection", self.network_card_value, self.network_card_detail
        ).pack(side=LEFT, fill=X, expand=True, padx=(0, 10))
        self._status_card(
            cards, "Device Trust", self.device_card_value, self.device_card_detail
        ).pack(side=LEFT, fill=X, expand=True, padx=5)
        self._status_card(
            cards, "Security Updates", self.updates_card_value, self.updates_card_detail
        ).pack(side=LEFT, fill=X, expand=True, padx=(10, 0))

        actions = ttk.LabelFrame(tab, text="Quick actions", padding=12)
        actions.pack(fill=X, pady=(0, 10))
        ttk.Checkbutton(actions, text="Active scan", variable=self.active_scan).pack(side=LEFT, padx=(0, 14))
        ttk.Checkbutton(actions, text="Probe all bounded hosts", variable=self.probe_all).pack(
            side=LEFT, padx=(0, 14)
        )
        ttk.Button(actions, text="Scan", command=self._start_scan, style="Scan.TButton").pack(side=LEFT, padx=(4, 8))
        ttk.Button(actions, text="Update Definitions", command=self._start_definition_update, style="Accent.TButton").pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Admin Access", command=self._request_admin_access).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Minimize to Tray", command=self._hide_to_tray).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Setup Guide", command=self._show_onboarding).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Open HTML Report", command=self._open_html).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Open PDF Report", command=self._open_pdf).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Save HTML As...", command=self._save_html_report).pack(side=LEFT, padx=4)
        ttk.Button(actions, text="Open Report Folder", command=self._open_out_folder).pack(side=LEFT, padx=4)

        scan_indicator = ttk.Frame(tab)
        scan_indicator.pack(fill=X, pady=(0, 10))
        self.scan_indicator_canvas = Canvas(
            scan_indicator,
            height=70,
            highlightthickness=0,
            bd=0,
            bg=BRAND_BG,
        )
        self.scan_indicator_canvas.pack(side=LEFT, fill=X, expand=True)
        ttk.Label(
            scan_indicator,
            textvariable=self.scan_indicator_text,
            style="Muted.TLabel",
            width=34,
        ).pack(side=LEFT, padx=(12, 0))
        self.scan_indicator_canvas.bind("<Configure>", self._draw_scan_indicator)
        self._draw_scan_indicator()

        defs_panel = ttk.LabelFrame(tab, text="Security definitions", padding=12)
        defs_panel.pack(fill=X, pady=(0, 10))
        ttk.Label(defs_panel, textvariable=self.definitions_text, style="Muted.TLabel", wraplength=1100).pack(
            anchor="w"
        )

        panes = ttk.PanedWindow(tab, orient="vertical")
        panes.pack(fill=BOTH, expand=True)

        upper = ttk.PanedWindow(panes, orient="horizontal")
        panes.add(upper, weight=3)

        findings_frame = ttk.LabelFrame(upper, text="Risk findings", padding=8)
        finding_actions = ttk.Frame(findings_frame)
        finding_actions.pack(fill=X, pady=(0, 6))
        self.finding_port_action = ttk.Button(
            finding_actions,
            textvariable=self.finding_port_action_text,
            command=self._toggle_selected_finding_port,
            style="Accent.TButton",
        )
        self.finding_port_action.pack(side=LEFT, padx=(0, 4))
        ttk.Button(
            finding_actions,
            text="Ignore",
            command=self._ignore_selected_finding,
        ).pack(side=LEFT, padx=(0, 4))
        self.findings = ttk.Treeview(
            findings_frame,
            columns=("severity", "priority", "risk", "category", "device", "title"),
            show="headings",
            height=10,
        )
        for col, title, width in [
            ("severity", "Severity", 86),
            ("priority", "Priority", 72),
            ("risk", "Risk", 62),
            ("category", "Category", 150),
            ("device", "Device", 150),
            ("title", "Finding", 380),
        ]:
            self.findings.heading(col, text=title)
            self.findings.column(col, width=width, stretch=(col == "title"))
        self.findings.pack(fill=BOTH, expand=True)
        self.findings.bind("<<TreeviewSelect>>", self._refresh_finding_port_action)
        upper.add(findings_frame, weight=3)

        scan_devices = ttk.LabelFrame(upper, text="Devices in last scan", padding=8)
        self.scan_devices = ttk.Treeview(
            scan_devices,
            columns=("ip", "name", "mac", "status", "ports"),
            show="headings",
            height=10,
        )
        for col, title, width in [
            ("ip", "IP", 110),
            ("name", "Name", 160),
            ("mac", "MAC", 140),
            ("status", "Status", 90),
            ("ports", "Ports", 120),
        ]:
            self.scan_devices.heading(col, text=title)
            self.scan_devices.column(col, width=width, stretch=(col in {"name", "ports"}))
        self.scan_devices.pack(fill=BOTH, expand=True)
        upper.add(scan_devices, weight=2)

        log_frame = ttk.LabelFrame(panes, text="Plain-English protection summary", padding=8)
        self.log = ScrolledText(log_frame, height=8, wrap="word", font=("Segoe UI", 10), borderwidth=0)
        self.log.pack(fill=BOTH, expand=True)
        panes.add(log_frame, weight=2)

        self._log("HomeGuard is ready. Run a scan or update definitions to begin.")

    def _show_onboarding(self) -> None:
        if self._onboarding_window is not None:
            try:
                self._onboarding_window.lift()
                return
            except Exception:
                self._onboarding_window = None

        win = Toplevel(self.root)
        self._onboarding_window = win
        win.title("HomeGuard Setup")
        win.geometry("760x610")
        win.minsize(680, 560)
        win.configure(bg=BRAND_BG)
        win.transient(self.root)
        win.protocol("WM_DELETE_WINDOW", lambda: self._skip_onboarding(win))

        body = ttk.Frame(win, padding=18)
        body.pack(fill=BOTH, expand=True)

        ttk.Label(
            body,
            text="HomeGuard guided setup",
            font=("Segoe UI", 22, "bold"),
            foreground=BRAND_NAVY,
            background=BRAND_BG,
        ).pack(anchor="w")
        ttk.Label(
            body,
            text=(
                "Follow each step and HomeGuard will move you through the app: updates, scan settings, "
                "first scan, device review, and the final report."
            ),
            style="Muted.TLabel",
            wraplength=660,
        ).pack(anchor="w", pady=(4, 16))

        self.onboarding_progress = ttk.Label(body, style="Muted.TLabel")
        self.onboarding_progress.pack(anchor="w", pady=(0, 8))

        self.onboarding_card = ttk.Frame(body, padding=16, style="Card.TFrame")
        self.onboarding_card.pack(fill=BOTH, expand=True)
        self.onboarding_title = StringVar()
        self.onboarding_body = StringVar()
        self.onboarding_hint = StringVar()
        ttk.Label(
            self.onboarding_card,
            textvariable=self.onboarding_title,
            font=("Segoe UI", 17, "bold"),
            foreground=BRAND_NAVY,
            background="white",
            wraplength=650,
        ).pack(anchor="w")
        ttk.Label(
            self.onboarding_card,
            textvariable=self.onboarding_body,
            style="Card.TLabel",
            wraplength=670,
            justify=LEFT,
        ).pack(anchor="w", pady=(10, 10))
        ttk.Label(
            self.onboarding_card,
            textvariable=self.onboarding_hint,
            style="CardMuted.TLabel",
            wraplength=670,
            justify=LEFT,
        ).pack(anchor="w")

        self.onboarding_options = ttk.LabelFrame(body, text="Scan options", padding=12)
        self.onboarding_options.pack(fill=X, pady=(12, 0))
        ttk.Checkbutton(
            self.onboarding_options,
            text="Active scan",
            variable=self.active_scan,
            command=self._save_onboarding_scan_defaults,
        ).pack(side=LEFT, padx=(0, 16))
        ttk.Checkbutton(
            self.onboarding_options,
            text="Probe all bounded private hosts",
            variable=self.probe_all,
            command=self._save_onboarding_scan_defaults,
        ).pack(side=LEFT)
        self.onboarding_options_note = ttk.Label(
            self.onboarding_options,
            text="Passive is the gentlest first scan. Active checks common review ports only on private/local addresses.",
            style="Muted.TLabel",
            wraplength=640,
        )
        self.onboarding_options_note.pack(anchor="w", pady=(8, 0))

        actions = ttk.Frame(body)
        self.onboarding_actions = actions
        actions.pack(fill=X, pady=(14, 0))
        ttk.Button(actions, text="Skip", command=lambda: self._skip_onboarding(win)).pack(side=LEFT, padx=3)
        self.onboarding_back = ttk.Button(actions, text="Back", command=self._onboarding_back)
        self.onboarding_back.pack(side=LEFT, padx=3)
        self.onboarding_secondary = ttk.Button(actions, text="Open Devices", command=self._onboarding_secondary_action)
        self.onboarding_secondary.pack(side="right", padx=3)
        self.onboarding_primary = ttk.Button(actions, text="Next", command=self._onboarding_primary_action, style="Accent.TButton")
        self.onboarding_primary.pack(side="right", padx=3)
        self._onboarding_step = 0
        self._render_onboarding_step()

    def _save_onboarding_scan_defaults(self) -> None:
        self.settings.set_scan_defaults(active_scan=self.active_scan.get(), probe_all=self.probe_all.get())

    def _onboarding_steps(self) -> list[dict[str, str]]:
        return [
            {
                "title": "Step 1: Update security definitions",
                "body": (
                    "HomeGuard uses bundled rules, then improves them with current CISA known-exploited "
                    "vulnerabilities and recent NVD CVE hints. Click the button below and watch the Security "
                    "Updates card on the Protection tab."
                ),
                "hint": "This may take a moment. If the network is unavailable, you can continue with starter definitions.",
                "primary": "Update Definitions",
                "secondary": "Continue Without Update",
            },
            {
                "title": "Step 2: Choose scan depth",
                "body": (
                    "The scan controls are on the Protection tab. Passive scan reads local network tables. "
                    "Active scan also checks a bounded set of common ports on private/local addresses."
                ),
                "hint": "For most first runs, leave Probe all bounded private hosts off unless you want a broader active check.",
                "primary": "Use These Settings",
                "secondary": "Show Protection",
            },
            {
                "title": "Step 3: Run the first scan",
                "body": (
                    "Now HomeGuard will scan the home network, run the detection engine, and build the first "
                    "known-device list. The Protection tab will fill with findings, devices, and a plain-English summary."
                ),
                "hint": "Leave this window open. When the scan finishes, the guide will move to device review.",
                "primary": "Run First Scan",
                "secondary": "Show Protection",
            },
            {
                "title": "Step 4: Review devices",
                "body": (
                    "You are now on the Devices tab. Select a device you recognize and use Mark Trusted. "
                    "Use Quarantine for a device you do not recognize, then block it in your router or change the WiFi password."
                ),
                "hint": "Labels are optional, but useful for family devices: owner, type, and notes make later scans easier to understand.",
                "primary": "I Reviewed Devices",
                "secondary": "Refresh Devices",
            },
            {
                "title": "Step 5: Open your report",
                "body": (
                    "The scan generated an HTML and PDF report. Open the report to review the executive summary, "
                    "possible intrusion indicators, recommended actions, and device inventory."
                ),
                "hint": "The report is stored in the HomeGuard reports folder and mirrored to the latest report folder.",
                "primary": "Open HTML Report",
                "secondary": "Open Report Folder",
            },
        ]

    def _render_onboarding_step(self) -> None:
        if self._onboarding_window is None:
            return
        steps = self._onboarding_steps()
        self._onboarding_step = max(0, min(self._onboarding_step, len(steps) - 1))
        step = steps[self._onboarding_step]
        self.onboarding_progress.configure(text=f"Step {self._onboarding_step + 1} of {len(steps)}")
        self.onboarding_title.set(step["title"])
        self.onboarding_body.set(step["body"])
        self.onboarding_hint.set(step["hint"])
        self.onboarding_primary.configure(text=step["primary"], state="normal")
        self.onboarding_secondary.configure(text=step["secondary"], state="normal")
        self.onboarding_back.configure(state=("disabled" if self._onboarding_step == 0 else "normal"))
        if self._onboarding_step == 0:
            self.notebook.select(0)
        elif self._onboarding_step in {1, 2}:
            self.notebook.select(0)
        elif self._onboarding_step == 3:
            self.notebook.select(1)
        elif self._onboarding_step == 4:
            self.notebook.select(0)
        self.onboarding_options.pack_forget()
        if self._onboarding_step == 1:
            self.onboarding_options.pack(fill=X, pady=(12, 0), before=self.onboarding_actions)

    def _onboarding_back(self) -> None:
        self._onboarding_step -= 1
        self._render_onboarding_step()

    def _onboarding_primary_action(self) -> None:
        if self._onboarding_step == 0:
            self._start_definition_update()
            self.onboarding_primary.configure(text="Updating...", state="disabled")
            self.onboarding_hint.set("Downloading definitions. The guide will continue when the update finishes.")
            return
        if self._onboarding_step == 1:
            self._save_onboarding_scan_defaults()
            self._onboarding_step = 2
            self._render_onboarding_step()
            return
        if self._onboarding_step == 2:
            self._save_onboarding_scan_defaults()
            self._onboarding_waiting_for_scan = True
            self.onboarding_primary.configure(text="Scanning...", state="disabled")
            self.onboarding_hint.set("Scanning now. The guide will continue when the report has been generated.")
            self._start_scan()
            return
        if self._onboarding_step == 3:
            self._onboarding_step = 4
            self._render_onboarding_step()
            return
        if self._onboarding_step == 4:
            self._open_html()
            if self._onboarding_window is not None:
                self._finish_onboarding(self._onboarding_window)

    def _onboarding_secondary_action(self) -> None:
        if self._onboarding_step == 0:
            self._onboarding_step = 1
            self._render_onboarding_step()
        elif self._onboarding_step in {1, 2}:
            self.notebook.select(0)
        elif self._onboarding_step == 3:
            self._refresh_devices_tab()
            self.notebook.select(1)
        elif self._onboarding_step == 4:
            self._open_out_folder()

    def _onboarding_definition_complete(self) -> None:
        if self._onboarding_window is None or self._onboarding_step != 0:
            return
        self._onboarding_step = 1
        self._render_onboarding_step()

    def _onboarding_scan_complete(self) -> None:
        if self._onboarding_window is None or not self._onboarding_waiting_for_scan:
            return
        self._onboarding_waiting_for_scan = False
        self._onboarding_step = 3
        self._render_onboarding_step()

    def _skip_onboarding(self, win: Toplevel) -> None:
        self.settings.set_scan_defaults(active_scan=self.active_scan.get(), probe_all=self.probe_all.get())
        self.settings.mark_onboarding_skipped()
        self._onboarding_window = None
        win.destroy()
        self._log("Setup guide skipped. You can reopen it from Setup Guide.")

    def _finish_onboarding(self, win: Toplevel) -> None:
        self.settings.set_scan_defaults(active_scan=self.active_scan.get(), probe_all=self.probe_all.get())
        self.settings.mark_onboarding_complete()
        self._onboarding_window = None
        win.destroy()
        self._log("Setup guide completed.")

    def _build_devices_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Devices")

        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=X, pady=(0, 8))
        ttk.Button(toolbar, text="Refresh", command=self._refresh_devices_tab).pack(side=LEFT, padx=2)
        ttk.Button(
            toolbar, text="Mark Trusted", command=lambda: self._set_trust_for_selection(TRUST_TRUSTED), style="Accent.TButton"
        ).pack(side=LEFT, padx=2)
        ttk.Button(
            toolbar, text="Mark Unknown", command=lambda: self._set_trust_for_selection(TRUST_UNKNOWN)
        ).pack(side=LEFT, padx=2)
        ttk.Button(
            toolbar,
            text="Quarantine",
            command=lambda: self._set_trust_for_selection(TRUST_QUARANTINED),
            style="Danger.TButton",
        ).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="Edit Family Label", command=self._edit_family_label).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="Remove from Known Devices", command=self._remove_known_device).pack(
            side=LEFT, padx=2
        )

        self.devices = ttk.Treeview(
            tab,
            columns=("ip", "name", "mac", "vendor", "trust", "owner", "type", "open_ports", "last_seen"),
            show="headings",
        )
        for col, title, width in [
            ("ip", "IP", 110),
            ("name", "Name", 160),
            ("mac", "MAC", 140),
            ("vendor", "Vendor", 120),
            ("trust", "Trust", 100),
            ("owner", "Owner", 90),
            ("type", "Type", 90),
            ("open_ports", "Open ports", 130),
            ("last_seen", "Last seen", 150),
        ]:
            self.devices.heading(col, text=title)
            self.devices.column(col, width=width, stretch=(col == "name"))
        self.devices.pack(fill=BOTH, expand=True)
        self.devices.tag_configure("trusted", foreground=BRAND_GREEN)
        self.devices.tag_configure("quarantined", foreground=BRAND_RED)
        self.devices.tag_configure("unknown", foreground=BRAND_TEXT)

        ttk.Label(
            tab,
            text=(
                "Quarantine flags this device as Action Needed in scans and reports. "
                "To actually block traffic, remove the device from your router or change the WiFi password."
            ),
            style="Muted.TLabel",
            wraplength=1100,
        ).pack(fill=X, pady=(8, 0))

        self._refresh_devices_tab()

    def _build_history_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="History")

        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=X, pady=(0, 8))
        ttk.Button(toolbar, text="Refresh", command=self._refresh_history_tab).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="Open HTML", command=self._history_open_html).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="Open PDF", command=self._history_open_pdf).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="Open Folder", command=self._history_open_folder).pack(side=LEFT, padx=2)
        ttk.Label(toolbar, text="  Retention:", style="TLabel").pack(side=LEFT, padx=(20, 4))
        self.retention_var = StringVar(value=str(self.history.retention))
        ttk.Entry(toolbar, textvariable=self.retention_var, width=5).pack(side=LEFT)
        ttk.Button(toolbar, text="Apply", command=self._apply_retention).pack(side=LEFT, padx=2)

        self.history_tree = ttk.Treeview(
            tab,
            columns=("created", "devices", "findings", "severity", "risk", "score"),
            show="headings",
        )
        for col, title, width in [
            ("created", "When", 200),
            ("devices", "Devices", 80),
            ("findings", "Findings", 80),
            ("severity", "Highest severity", 130),
            ("risk", "Risk", 100),
            ("score", "Score", 80),
        ]:
            self.history_tree.heading(col, text=title)
            self.history_tree.column(col, width=width, stretch=(col == "created"))
        self.history_tree.pack(fill=BOTH, expand=True)
        self._refresh_history_tab()

    def _build_schedule_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Schedule")

        ttk.Label(
            tab,
            text=(
                "HomeGuard can run scheduled passive scans automatically. "
                "Scheduled scans use the same detection engine and write reports to the app data folder."
            ),
            style="Muted.TLabel",
            wraplength=1000,
        ).pack(fill=X, pady=(0, 14))

        controls = ttk.LabelFrame(tab, text="Scheduled scans", padding=12)
        controls.pack(fill=X)

        row1 = ttk.Frame(controls)
        row1.pack(fill=X, pady=4)
        ttk.Checkbutton(row1, text="Enable scheduled scans", variable=self.schedule_enabled).pack(
            side=LEFT, padx=(0, 16)
        )
        ttk.Checkbutton(
            row1, text="Background monitor (tray)", variable=self.schedule_background
        ).pack(side=LEFT, padx=(0, 16))

        row2 = ttk.Frame(controls)
        row2.pack(fill=X, pady=4)
        ttk.Label(row2, text="Interval:").pack(side=LEFT, padx=(0, 8))
        for value in sorted(INTERVAL_VALUES):
            ttk.Radiobutton(
                row2, text=value.title(), variable=self.schedule_interval, value=value
            ).pack(side=LEFT, padx=4)

        row3 = ttk.Frame(controls)
        row3.pack(fill=X, pady=8)
        ttk.Button(row3, text="Save schedule", command=self._save_schedule, style="Accent.TButton").pack(
            side=LEFT, padx=4
        )
        ttk.Button(row3, text="Run now", command=self._start_scan).pack(side=LEFT, padx=4)

        self.schedule_status = StringVar(value=self._schedule_status_text())
        ttk.Label(controls, textvariable=self.schedule_status, style="Muted.TLabel", wraplength=1000).pack(
            anchor="w", pady=(8, 0)
        )

    def _build_logs_tab(self) -> None:
        tab = ttk.Frame(self.notebook, padding=12)
        self.notebook.add(tab, text="Logs")

        toolbar = ttk.Frame(tab)
        toolbar.pack(fill=X, pady=(0, 8))
        ttk.Button(toolbar, text="Reload", command=self._reload_log).pack(side=LEFT, padx=2)
        ttk.Button(toolbar, text="Open Logs Folder", command=lambda: _open_in_explorer(logs_dir())).pack(
            side=LEFT, padx=2
        )

        self.logs_view = ScrolledText(tab, height=20, wrap="word", font=("Consolas", 10))
        self.logs_view.pack(fill=BOTH, expand=True)
        self._reload_log()

    # ------------------------------------------------------------------
    # header
    # ------------------------------------------------------------------
    def _draw_header(self, _event: object | None = None) -> None:
        self.hero.delete("all")
        width = max(1, self.hero.winfo_width())
        height = 140
        # blue gradient header for the local status dashboard
        start = (5, 11, 24)
        mid = (15, 42, 104)
        end = (23, 78, 166)
        for x in range(width):
            ratio = x / max(1, width - 1)
            if ratio < 0.5:
                local = ratio * 2
                r = int(start[0] + (mid[0] - start[0]) * local)
                g = int(start[1] + (mid[1] - start[1]) * local)
                b = int(start[2] + (mid[2] - start[2]) * local)
            else:
                local = (ratio - 0.5) * 2
                r = int(mid[0] + (end[0] - mid[0]) * local)
                g = int(mid[1] + (end[1] - mid[1]) * local)
                b = int(mid[2] + (end[2] - mid[2]) * local)
            self.hero.create_line(x, 0, x, height, fill=f"#{r:02x}{g:02x}{b:02x}")
        self.hero.create_rectangle(28, 28, 86, 86, outline="#BFE7FF", width=1)
        self.hero.create_text(57, 57, text="GN", fill="white", font=("Segoe UI", 18, "bold"))
        self.hero.create_text(102, 30, text="GreyNOC", fill="white", anchor="nw", font=("Segoe UI", 30, "bold"))
        self.hero.create_text(104, 74, text="HomeGuard | Home Network Risk Review", fill="#DBEAFE", anchor="nw", font=("Segoe UI", 12))
        self.hero.create_text(width - 28, 38, text=self.network_card_value.get(), fill="white", anchor="ne", font=("Segoe UI", 14, "bold"))
        self.hero.create_text(width - 28, 70, text=self.network_card_detail.get()[:80], fill="#DBEAFE", anchor="ne", font=("Segoe UI", 9))
        self.hero.create_text(width - 28, 100, text=self._updates_value(), fill="white", anchor="ne", font=("Segoe UI", 10, "bold"))

    def _draw_scan_indicator(self, _event: object | None = None) -> None:
        if not hasattr(self, "scan_indicator_canvas"):
            return
        canvas = self.scan_indicator_canvas
        canvas.delete("all")
        width = max(420, canvas.winfo_width())
        height = max(70, canvas.winfo_height())
        y = 25
        phases = ["Wake", "Discover", "Fingerprint", "Score", "Report"]
        step = self._scan_indicator_frame
        active_index = (step // 3) % len(phases) if self._scan_indicator_running else -1
        left = 26
        gap = max(76, min(132, (width - 64) // max(1, len(phases) - 1)))
        usable = min(width - 26, left + gap * (len(phases) - 1))

        canvas.create_rectangle(0, 0, width, height, fill="#E7EDF7", outline="")
        canvas.create_line(left, y, usable, y, fill="#C5D3E8", width=3)
        phase_colors = [
            ("#F59E0B", "#FDE68A"),
            ("#06B6D4", "#A5F3FC"),
            ("#8B5CF6", "#DDD6FE"),
            ("#EF4444", "#FECACA"),
            ("#22C55E", "#BBF7D0"),
        ]
        if self._scan_indicator_running:
            pulse_x = left + ((step * 15) % max(1, usable - left))
            trail = max(left, pulse_x - 80)
            canvas.create_line(left, y, usable, y, fill="#092A63", width=4)
            canvas.create_line(trail, y, pulse_x, y, fill=BRAND_CYAN, width=5)
            canvas.create_oval(
                pulse_x - 7,
                y - 7,
                pulse_x + 7,
                y + 7,
                fill=BRAND_CYAN,
                outline="white",
                width=1,
            )
            canvas.create_text(
                min(usable, max(left, pulse_x + 24)),
                y - 15,
                text="live",
                fill="#0E7490",
                font=("Segoe UI", 8, "bold"),
            )

        for index, label in enumerate(phases):
            x = left + index * gap
            active = index == active_index
            done = self._scan_indicator_running and index < active_index
            color, light = phase_colors[index]
            size = 18 + ((step % 2) * 4 if active else 0)
            half = size // 2
            outline = "#050B18" if active else (color if done else "#9FB2CC")
            fill = color if active or done else "#F8FAFC"
            shadow_offset = 3
            canvas.create_rectangle(
                x - half + shadow_offset,
                y - half + shadow_offset,
                x + half + shadow_offset,
                y + half + shadow_offset,
                fill="#C8D4E6",
                outline="",
            )
            canvas.create_rectangle(x - half, y - half, x + half, y + half, fill=fill, outline=outline, width=2)
            pixel = max(3, size // 5)
            canvas.create_rectangle(x - half + 3, y - half + 3, x - half + 3 + pixel, y - half + 3 + pixel, fill=light, outline="")
            canvas.create_rectangle(x + half - 6, y + half - 6, x + half - 2, y + half - 2, fill="#050B18", outline="")
            if done:
                canvas.create_rectangle(x - 3, y - 1, x + 2, y + 4, fill="white", outline="")
                canvas.create_rectangle(x + 2, y - 6, x + 7, y - 1, fill="white", outline="")
            if active:
                halo = half + 7
                canvas.create_rectangle(
                    x - halo,
                    y - halo,
                    x + halo,
                    y + halo,
                    outline=light,
                    width=2,
                )
                spark_offsets = [(-22, -10), (23, -12), (-17, 16), (20, 15)]
                for spark_index, (dx, dy) in enumerate(spark_offsets):
                    if (step + spark_index) % 2 == 0:
                        sx = x + dx
                        sy = y + dy
                        canvas.create_rectangle(sx - 2, sy - 2, sx + 2, sy + 2, fill=color, outline="")
            canvas.create_text(
                x,
                y + 26,
                text=label,
                fill="#050B18" if active else BRAND_MUTED,
                font=("Segoe UI", 8, "bold" if active else "normal"),
            )
            if active:
                canvas.create_text(
                    x,
                    y + 41,
                    text="working",
                    fill="#0E7490",
                    font=("Segoe UI", 7),
                )

    def _start_scan_indicator(self, *, source: str) -> None:
        self._scan_indicator_running = True
        self._scan_indicator_frame = 0
        self.scan_indicator_text.set("Scheduled discovery running" if source == "scheduled" else "Discovery agents running")
        self._animate_scan_indicator()

    def _animate_scan_indicator(self) -> None:
        if not self._scan_indicator_running:
            self._draw_scan_indicator()
            return
        self._scan_indicator_frame += 1
        phases = [
            "Waking sensors",
            "Discovering local devices",
            "Fingerprinting services",
            "Scoring risk signals",
            "Writing protection report",
        ]
        self.scan_indicator_text.set(phases[(self._scan_indicator_frame // 3) % len(phases)])
        self._draw_scan_indicator()
        self._scan_indicator_after_id = self.root.after(220, self._animate_scan_indicator)

    def _stop_scan_indicator(self, *, ok: bool, detail: str = "") -> None:
        self._scan_indicator_running = False
        if self._scan_indicator_after_id is not None:
            try:
                self.root.after_cancel(self._scan_indicator_after_id)
            except Exception:
                pass
            self._scan_indicator_after_id = None
        self.scan_indicator_text.set(detail or ("Scan complete" if ok else "Scan needs attention"))
        self._draw_scan_indicator()

    def _status_card(
        self, parent: ttk.Frame, title: str, value_var: StringVar, detail_var: StringVar
    ) -> ttk.Frame:
        card = ttk.Frame(parent, padding=14, style="Card.TFrame")
        ttk.Label(card, text=title.upper(), style="CardMuted.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            textvariable=value_var,
            font=("Segoe UI", 22, "bold"),
            foreground=BRAND_NAVY,
            background="white",
        ).pack(anchor="w", pady=(4, 4))
        ttk.Label(card, textvariable=detail_var, style="CardMuted.TLabel", wraplength=320).pack(
            anchor="w"
        )
        return card

    # ------------------------------------------------------------------
    # tray and background mode
    # ------------------------------------------------------------------
    def _start_tray(self) -> None:
        self._tray = TrayController(
            on_show=lambda: self.root.after(0, self._show_from_tray),
            on_scan=lambda: self.root.after(0, self._start_scan),
            on_open_report=lambda: self.root.after(0, self._open_html),
            on_update_definitions=lambda: self.root.after(0, self._start_definition_update),
            on_quit=lambda: self.root.after(0, self._quit_from_tray),
        )
        if self._tray.start():
            self._log("System tray is active. Minimize or close the window to keep HomeGuard running in the background.")
        else:
            detail = self._tray.error_message if self._tray else "Tray support unavailable."
            self._log(f"System tray unavailable: {detail}")

    def _tray_available(self) -> bool:
        return bool(self._tray and self._tray.available)

    def _on_window_close(self) -> None:
        if self._exit_requested or not self._tray_available():
            self._exit_app()
            return
        self._hide_to_tray()

    def _on_window_unmap(self, _event: object | None = None) -> None:
        if self._exit_requested or self._suppress_iconify_to_tray or not self._tray_available():
            return
        self.root.after(120, self._hide_if_iconified)

    def _hide_if_iconified(self) -> None:
        if self._exit_requested or self._suppress_iconify_to_tray or not self._tray_available():
            return
        try:
            if self.root.state() == "iconic":
                self._hide_to_tray()
        except Exception:
            return

    def _hide_to_tray(self) -> None:
        if not self._tray_available():
            messagebox.showinfo(
                "HomeGuard",
                "System tray support is not available. Install the tray extras with: pip install pystray pillow",
            )
            return
        self._hidden_to_tray = True
        self._suppress_iconify_to_tray = True
        try:
            self.root.withdraw()
        finally:
            self._suppress_iconify_to_tray = False
        self.status.set("HomeGuard is running in the background from the system tray")

    def _show_from_tray(self) -> None:
        self._hidden_to_tray = False
        self._suppress_iconify_to_tray = True
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
        finally:
            self._suppress_iconify_to_tray = False

    def _quit_from_tray(self) -> None:
        self._exit_requested = True
        self._exit_app()

    def _exit_app(self) -> None:
        self._exit_requested = True
        if self._tray is not None:
            self._tray.stop()
        self.root.destroy()

    def _notify_tray(self, title: str, message: str) -> None:
        if self._tray is not None:
            self._tray.notify(title, message)

    def _background_monitor_tick(self) -> None:
        try:
            cfg = self.schedule_manager.load()
            if cfg.background_monitor and self.schedule_manager.is_due() and not self._scan_running:
                self._start_scan(active=False, probe_all=False, source="scheduled")
        except Exception as exc:
            LOG.debug("Background monitor tick failed: %s", exc)
        finally:
            if not self._exit_requested:
                self.root.after(60000, self._background_monitor_tick)

    def _request_admin_access(self) -> None:
        if sys.platform != "win32":
            messagebox.showinfo(
                "HomeGuard",
                "Admin Access is only needed for Windows Firewall actions on Windows.",
            )
            return
        if _is_windows_admin():
            messagebox.showinfo("HomeGuard", "HomeGuard already has administrator access.")
            return
        if not messagebox.askyesno(
            "Admin Access",
            (
                "Windows will ask for administrator access and reopen HomeGuard elevated.\n\n"
                "Use this when you want HomeGuard to close or reopen local firewall ports."
            ),
        ):
            return
        if _relaunch_elevated():
            self._exit_requested = True
            self._exit_app()
        else:
            messagebox.showerror(
                "HomeGuard",
                "Windows did not grant administrator access. You can try again or run HomeGuard as administrator.",
            )

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def _start_definition_update(self) -> None:
        if self._definition_update_running:
            self.status.set("Definition update already running")
            return
        self._definition_update_running = True
        self.status.set("Updating definitions...")
        self.updates_card_value.set("Updating")
        self.updates_card_detail.set("Downloading CVE and security feeds")
        self._draw_header()
        self._log("Updating security definitions from CISA KEV and NVD CVE feeds...")
        threading.Thread(target=self._run_definition_update, daemon=True).start()

    def _run_definition_update(self) -> None:
        try:
            status = self.definition_manager.update_from_sources(nvd_days=30)
            self._messages.put(("definitions", status))
        except Exception as exc:
            LOG.exception("Definition update failed")
            self._messages.put(("error", exc))

    def _start_scan(
        self,
        *,
        active: bool | None = None,
        probe_all: bool | None = None,
        source: str = "manual",
    ) -> None:
        if self._scan_running:
            self.status.set("Scan already running")
            self._notify_tray("HomeGuard", "A scan is already running.")
            return
        scan_active = self.active_scan.get() if active is None else active
        scan_probe_all = self.probe_all.get() if probe_all is None else probe_all
        self._scan_running = True
        self.status.set("Scheduled scan running..." if source == "scheduled" else "Scanning network...")
        self.network_card_value.set("Scanning")
        self.network_card_detail.set("Detection engine running")
        self.device_card_value.set("Scanning")
        self.device_card_detail.set("Building device trust inventory")
        self._start_scan_indicator(source=source)
        self._draw_header()
        self._log(
            "Starting scheduled HomeGuard scan..."
            if source == "scheduled"
            else "Starting HomeGuard scan..."
        )
        threading.Thread(
            target=self._run_scan,
            args=(scan_active, scan_probe_all, source),
            daemon=True,
        ).start()

    def _run_scan(self, active: bool, probe_all: bool, source: str) -> None:
        try:
            report, paths, _entry = run_full_scan(
                active=active,
                probe_all=probe_all,
            )
            self._messages.put(("done", (report, paths, source)))
        except Exception as exc:
            LOG.exception("Scan failed")
            self._messages.put(("error", exc))

    def _drain_messages(self) -> None:
        while True:
            try:
                kind, payload = self._messages.get_nowait()
            except queue.Empty:
                break
            if kind == "done":
                report, paths, source = payload  # type: ignore[misc]
                self._scan_running = False
                self.last_report = report
                self.last_paths = paths
                self.history = ProtectionHistory().load()
                self.trust_store = BaselineStore(default_baseline_path()).load()
                self._render_report(report)
                self._refresh_status_cards(report)
                self._refresh_history_tab()
                self._refresh_devices_tab()
                self.status.set(
                    f"Last scan: {len(report.devices)} devices, {len(report.findings)} findings"
                )
                self._stop_scan_indicator(
                    ok=True,
                    detail=f"Scan complete: {len(report.devices)} devices, {len(report.findings)} findings",
                )
                self._draw_header()
                self._log(f"Report written to {paths.get('html') or paths.get('json')}")
                if self._hidden_to_tray or source == "scheduled":
                    self._notify_tray(
                        "HomeGuard scan complete",
                        f"{len(report.devices)} devices, {len(report.findings)} findings.",
                    )
                self._onboarding_scan_complete()
            elif kind == "definitions":
                self._definition_update_running = False
                self.definition_status = (
                    payload if isinstance(payload, dict) else self.definition_manager.status()
                )
                self.definitions_text.set(self._definitions_text())
                self.updates_card_value.set(self._updates_value())
                self.updates_card_detail.set(self._definitions_text())
                self.status.set("Security definitions updated")
                self._draw_header()
                self._log("Security definitions updated.")
                for source, details in (self.definition_status.get("source_status") or {}).items():
                    if isinstance(details, dict):
                        state = "OK" if details.get("ok") else "Problem"
                        self._log(f"- {source}: {state} - {details.get('message')}")
                if self._hidden_to_tray:
                    self._notify_tray("HomeGuard", "Security definitions updated.")
                self._onboarding_definition_complete()
            elif kind == "error":
                self._scan_running = False
                self._definition_update_running = False
                self._stop_scan_indicator(ok=False, detail="Scan stopped with an error")
                self.status.set("Error")
                self.network_card_value.set("Action Needed")
                self.network_card_detail.set("Last operation failed")
                self._draw_header()
                self._log(f"Error: {payload}")
                self._notify_tray("HomeGuard needs attention", str(payload))
                if self._onboarding_window is not None:
                    self.onboarding_primary.configure(state="normal")
                    self.onboarding_hint.set("That action failed. You can try again, skip this step, or continue with the next step.")
                messagebox.showerror("HomeGuard", str(payload))
        self.root.after(150, self._drain_messages)

    def _refresh_status_cards(self, report: HomeGuardReport) -> None:
        protection = report.scan_metadata.get("protection_status") if isinstance(report.scan_metadata, dict) else {}
        if isinstance(protection, dict):
            network = protection.get("network", {}) or {}
            device_trust = protection.get("device_trust", {}) or {}
            updates = protection.get("updates", {}) or {}
            self.network_card_value.set(str(network.get("value") or "Protected"))
            self.network_card_detail.set(str(network.get("detail") or ""))
            self.device_card_value.set(str(device_trust.get("value") or "Trusted"))
            self.device_card_detail.set(str(device_trust.get("detail") or ""))
            self.updates_card_value.set(str(updates.get("value") or self._updates_value()))
            self.updates_card_detail.set(str(updates.get("detail") or self._definitions_text()))
        else:
            self.updates_card_value.set(self._updates_value())
            self.updates_card_detail.set(self._definitions_text())

    def _refresh_status_from_history(self) -> None:
        latest = self.history.latest()
        if latest:
            self.status.set(
                f"Last scan {latest.created_at} | {latest.device_count} devices | {latest.finding_count} findings"
            )

    def _render_report(self, report: HomeGuardReport) -> None:
        for tree in (self.findings, self.scan_devices):
            for item in tree.get_children():
                tree.delete(item)
        self._finding_by_id = {}
        ignored_ids = self.settings.ignored_finding_ids()
        visible_findings = [
            finding for finding in report.findings if finding.finding_id not in ignored_ids
        ]
        for finding in report.findings:
            if finding.finding_id in ignored_ids:
                continue
            self._finding_by_id[finding.finding_id] = finding
            self.findings.insert(
                "",
                END,
                iid=finding.finding_id,
                values=(
                    finding.severity,
                    finding.priority,
                    finding.risk_score,
                    finding.category,
                    finding.device_name or finding.device_ip,
                    finding.title,
                ),
            )
        for device in report.devices:
            self.scan_devices.insert(
                "",
                END,
                values=(
                    device.ip,
                    device.hostname or device.vendor or "-",
                    device.mac_address or "-",
                    device.status,
                    ", ".join(str(port) for port in device.open_ports) or "-",
                ),
            )
        self.log.delete("1.0", END)
        self._log(report.summary)
        self._log("")
        self._log(f"Overall risk: {report.overall_risk.upper()} ({report.overall_score})")
        engine = report.scan_metadata.get("detection_engine") if isinstance(report.scan_metadata, dict) else {}
        if isinstance(engine, dict):
            self._log(
                f"Detection engine: {engine.get('engine')} v{engine.get('engine_version')} | "
                f"Rules loaded: {engine.get('rules_loaded')}"
            )
        self._log(f"Definitions: {self._definitions_text()}")
        self._log("")
        self._log("Top recommended actions:")
        for step in report.next_steps:
            self._log(f"- {step}")
        if ignored_ids:
            ignored_count = len(report.findings) - len(visible_findings)
            if ignored_count:
                self._log("")
                self._log(f"Ignored findings hidden from this view: {ignored_count}")
        if visible_findings:
            self._log("")
            self._log("Highest findings:")
            for finding in visible_findings[:8]:
                self._log(f"- {finding.title}: {finding.plain_english}")

    def _selected_finding(self):
        selection = self.findings.selection()
        if not selection:
            messagebox.showinfo("HomeGuard", "Select a finding first.")
            return None
        return self._finding_by_id.get(selection[0])

    def _refresh_finding_port_action(self, _event: object | None = None) -> None:
        selection = self.findings.selection()
        finding = self._finding_by_id.get(selection[0]) if selection else None
        port = port_from_finding(finding) if finding is not None else None
        self.finding_port_action_text.set("Open Port" if port in self._closed_ports else "Close Port")

    def _ignore_selected_finding(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            return
        if not messagebox.askyesno(
            "Ignore selected risk?",
            (
                f"Ignore this risk in future HomeGuard views?\n\n{finding.title}\n\n"
                "You can still find the full raw report files in the report folder."
            ),
        ):
            return
        self.settings.ignore_finding(finding.finding_id, title=finding.title)
        if self.findings.exists(finding.finding_id):
            self.findings.delete(finding.finding_id)
        self._finding_by_id.pop(finding.finding_id, None)
        self._log(f"Ignored risk: {finding.title}")
        self.status.set("Selected risk ignored")

    def _toggle_selected_finding_port(self) -> None:
        finding = self._selected_finding()
        if finding is None:
            return
        port = port_from_finding(finding)
        if port in self._closed_ports:
            self._reopen_selected_finding_port(finding)
        else:
            self._fix_selected_finding(finding)
        self._refresh_finding_port_action()

    def _fix_selected_finding(self, finding: Any | None = None) -> None:
        finding = finding or self._selected_finding()
        if finding is None:
            return
        port = port_from_finding(finding)
        if port is None:
            messagebox.showinfo(
                "HomeGuard",
                "This finding does not identify a specific port HomeGuard can close.",
            )
            return
        if not finding_is_local(finding):
            messagebox.showinfo(
                "HomeGuard",
                (
                    f"HomeGuard cannot directly close port {port} on {finding.device_name} "
                    f"({finding.device_ip}) because that is another device. Open that device's admin page "
                    "or your router controls, disable the service, then scan again. You can also quarantine "
                    "the device in HomeGuard while you investigate."
                ),
            )
            return
        if not messagebox.askyesno(
            "Close local port?",
            (
                f"Close inbound TCP port {port} on this computer using Windows Firewall?\n\n"
                "HomeGuard will create a reversible block rule. You can use Open Port later."
            ),
        ):
            return
        result = close_local_port(port)
        if result.ok:
            self._closed_ports.add(port)
            self._log(f"Closed local TCP port {port} with a HomeGuard firewall rule.")
            messagebox.showinfo("HomeGuard", f"Closed local TCP port {port}. Run another scan to confirm.")
        else:
            self._log(f"Could not close local TCP port {port}: {result.message}")
            messagebox.showerror("HomeGuard", result.message)

    def _reopen_selected_finding_port(self, finding: Any | None = None) -> None:
        finding = finding or self._selected_finding()
        if finding is None:
            return
        port = port_from_finding(finding)
        if port is None:
            messagebox.showinfo(
                "HomeGuard",
                "This finding does not identify a specific port HomeGuard can open.",
            )
            return
        if not finding_is_local(finding):
            messagebox.showinfo(
                "HomeGuard",
                (
                    f"Port {port} is on another device ({finding.device_ip}). Open it from that "
                    "device or your router if you intentionally use the service."
                ),
            )
            return
        if not messagebox.askyesno(
            "Open local port?",
            (
                f"Remove the HomeGuard firewall block for inbound TCP port {port} on this computer?\n\n"
                "Only the HomeGuard-created rule is removed."
            ),
        ):
            return
        result = reopen_local_port(port)
        if result.ok:
            self._closed_ports.discard(port)
            self._log(f"Reopened local TCP port {port} by removing the HomeGuard firewall rule.")
            messagebox.showinfo("HomeGuard", f"Opened local TCP port {port}.")
        else:
            self._log(f"Could not reopen local TCP port {port}: {result.message}")
            messagebox.showerror("HomeGuard", result.message)

    def _log(self, text: str) -> None:
        if text:
            self.log.insert(END, f"{text}\n")
        self.log.see(END)

    def _open_html(self) -> None:
        path = self.last_paths.get("html") or self._latest_html()
        if not path:
            messagebox.showinfo("HomeGuard", "Run a scan first.")
            return
        webbrowser.open(Path(path).resolve().as_uri())

    def _open_pdf(self) -> None:
        path = self.last_paths.get("pdf") or self._latest_pdf()
        if not path:
            messagebox.showinfo("HomeGuard", "Run a scan first.")
            return
        webbrowser.open(Path(path).resolve().as_uri())

    def _latest_html(self) -> Path | None:
        latest = self.history.latest()
        return Path(latest.html_path) if latest and latest.html_path else None

    def _latest_pdf(self) -> Path | None:
        latest = self.history.latest()
        return Path(latest.pdf_path) if latest and latest.pdf_path else None

    def _save_html_report(self) -> None:
        source = self.last_paths.get("html") or self._latest_html()
        if not source or not Path(source).exists():
            messagebox.showinfo("HomeGuard", "Run a scan first.")
            return
        destination = filedialog.asksaveasfilename(
            title="Save HomeGuard HTML report",
            defaultextension=".html",
            filetypes=[("HTML report", "*.html"), ("All files", "*.*")],
            initialfile=(
                f"HomeGuard-{self.last_report.report_id if self.last_report else 'report'}.html"
            ),
        )
        if destination:
            shutil.copy2(source, destination)
            self._log(f"Saved HTML report to {destination}")

    def _open_out_folder(self) -> None:
        latest_dir = latest_report_dir()
        if not latest_dir.exists():
            latest_dir.mkdir(parents=True, exist_ok=True)
        _open_in_explorer(latest_dir)

    # ------------------------------------------------------------------
    # devices tab handlers
    # ------------------------------------------------------------------
    def _refresh_devices_tab(self) -> None:
        if not hasattr(self, "devices"):
            return
        self.trust_store = BaselineStore(default_baseline_path()).load()
        self.devices.delete(*self.devices.get_children())
        for record in self.trust_store.all_records():
            trust = str(record.get("trust") or TRUST_UNKNOWN)
            tag = trust if trust in {TRUST_TRUSTED, TRUST_QUARANTINED} else TRUST_UNKNOWN
            self.devices.insert(
                "",
                END,
                iid=record.get("fingerprint", ""),
                values=(
                    record.get("ip", "-"),
                    record.get("hostname") or record.get("vendor") or "-",
                    record.get("mac_address") or "-",
                    record.get("vendor") or "-",
                    trust,
                    record.get("owner", "unknown"),
                    record.get("device_type", "unknown"),
                    ", ".join(str(p) for p in record.get("open_ports") or []) or "-",
                    record.get("last_seen", "-"),
                ),
                tags=(tag,),
            )

    def _selected_fingerprint(self) -> str | None:
        selection = self.devices.selection()
        if not selection:
            messagebox.showinfo("HomeGuard", "Select a device first.")
            return None
        return selection[0]

    def _set_trust_for_selection(self, trust: str) -> None:
        fingerprint = self._selected_fingerprint()
        if not fingerprint:
            return
        if self.trust_store.set_trust(fingerprint, trust):
            self.trust_store.save()
            self._refresh_devices_tab()
            self._log(f"Set device {fingerprint} trust to {trust}.")

    def _edit_family_label(self) -> None:
        fingerprint = self._selected_fingerprint()
        if not fingerprint:
            return
        owner = simpledialog.askstring(
            "Family label",
            f"Owner ({', '.join(sorted(OWNER_VALUES))}):",
            parent=self.root,
        )
        device_type = simpledialog.askstring(
            "Family label",
            f"Device type ({', '.join(sorted(DEVICE_TYPES))}):",
            parent=self.root,
        )
        notes = simpledialog.askstring("Family label", "Notes:", parent=self.root)
        if owner is None and device_type is None and notes is None:
            return
        if self.trust_store.set_label(
            fingerprint, owner=owner, device_type=device_type, notes=notes
        ):
            self.trust_store.save()
            self._refresh_devices_tab()
            self._log(f"Updated labels for device {fingerprint}.")

    def _remove_known_device(self) -> None:
        fingerprint = self._selected_fingerprint()
        if not fingerprint:
            return
        if not messagebox.askyesno(
            "HomeGuard",
            "Remove this device from the known-device list? It will appear as 'new device' on the next scan.",
        ):
            return
        if self.trust_store.remove(fingerprint):
            self.trust_store.save()
            self._refresh_devices_tab()
            self._log(f"Removed device {fingerprint} from known devices.")

    # ------------------------------------------------------------------
    # history tab handlers
    # ------------------------------------------------------------------
    def _refresh_history_tab(self) -> None:
        if not hasattr(self, "history_tree"):
            return
        self.history = ProtectionHistory().load()
        self.history_tree.delete(*self.history_tree.get_children())
        for index, entry in enumerate(self.history.entries()):
            self.history_tree.insert(
                "",
                END,
                iid=str(index),
                values=(
                    entry.created_at,
                    entry.device_count,
                    entry.finding_count,
                    entry.highest_severity,
                    entry.overall_risk,
                    entry.overall_score,
                ),
            )

    def _selected_history_entry(self):
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showinfo("HomeGuard", "Select a scan first.")
            return None
        index = int(selection[0])
        entries = self.history.entries()
        return entries[index] if 0 <= index < len(entries) else None

    def _history_open_html(self) -> None:
        entry = self._selected_history_entry()
        if entry and entry.html_path:
            webbrowser.open(Path(entry.html_path).resolve().as_uri())

    def _history_open_pdf(self) -> None:
        entry = self._selected_history_entry()
        if entry and entry.pdf_path:
            webbrowser.open(Path(entry.pdf_path).resolve().as_uri())

    def _history_open_folder(self) -> None:
        entry = self._selected_history_entry()
        if entry and entry.report_dir:
            _open_in_explorer(Path(entry.report_dir))

    def _apply_retention(self) -> None:
        try:
            value = int(self.retention_var.get())
        except ValueError:
            messagebox.showerror("HomeGuard", "Retention must be a number.")
            return
        self.history.set_retention(value)
        self.history.save()
        self._refresh_history_tab()
        self._log(f"History retention set to {value}.")

    # ------------------------------------------------------------------
    # schedule tab
    # ------------------------------------------------------------------
    def _save_schedule(self) -> None:
        try:
            self.schedule_manager.set(
                enabled=self.schedule_enabled.get(),
                interval=self.schedule_interval.get(),
                background_monitor=self.schedule_background.get(),
            )
        except ValueError as exc:
            messagebox.showerror("HomeGuard", str(exc))
            return
        self.schedule_status.set(self._schedule_status_text())
        self._log(
            f"Schedule saved: enabled={self.schedule_enabled.get()}, "
            f"interval={self.schedule_interval.get()}, "
            f"background_monitor={self.schedule_background.get()}"
        )

    def _schedule_status_text(self) -> str:
        cfg = self.schedule_manager.config
        if not cfg.enabled:
            return "Scheduled scans are disabled."
        return (
            f"Scheduled {cfg.interval} scans enabled. "
            f"Last run: {cfg.last_run or 'never'}. "
            f"Next run: {cfg.next_run or 'on next launch'}."
        )

    # ------------------------------------------------------------------
    # logs tab
    # ------------------------------------------------------------------
    def _reload_log(self) -> None:
        if not hasattr(self, "logs_view"):
            return
        path = log_file_path()
        self.logs_view.delete("1.0", END)
        if path.exists():
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError as exc:
                text = f"Failed to read log file: {exc}"
            self.logs_view.insert(END, text)
            self.logs_view.see(END)
        else:
            self.logs_view.insert(END, "No log file yet.")

    def run(self) -> None:
        self.root.mainloop()


def launch_gui() -> None:
    HomeGuardGui().run()

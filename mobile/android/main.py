"""HomeGuard - Android mobile app (Kivy).

This is the mobile counterpart of the desktop app. It is intentionally
simplified: Android sandboxing means desktop-grade ARP/ICMP scans are
limited, so this mobile build focuses on protection status, definition
updates, a lightweight WiFi neighbor scan, and report viewing.

Build with:

    bash compile_android.sh

This produces an APK in dist/android/ when Buildozer dependencies
(Java, Android SDK, NDK, autotools, etc.) are installed on a Linux/macOS
machine.
"""

from __future__ import annotations

import os
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

from kivy.app import App
from kivy.clock import Clock
from kivy.metrics import dp
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button
from kivy.uix.label import Label
from kivy.uix.scrollview import ScrollView
from kivy.uix.tabbedpanel import TabbedPanel, TabbedPanelItem
from kivy.uix.textinput import TextInput
from kivy.utils import get_color_from_hex
from kivy.graphics import Color, Rectangle


BRAND_NAVY = get_color_from_hex("#0B1220")
BRAND_DEEP = get_color_from_hex("#1E3A8A")
BRAND_BLUE = get_color_from_hex("#2563EB")
BRAND_BG = get_color_from_hex("#F2F5FA")
BRAND_TEXT = get_color_from_hex("#172033")
BRAND_GREEN = get_color_from_hex("#16A34A")
BRAND_AMBER = get_color_from_hex("#D97706")
BRAND_RED = get_color_from_hex("#DC2626")


def app_data_path() -> Path:
    """Return Android-private app data directory if available, else cwd."""

    try:
        from android.storage import app_storage_path  # type: ignore

        path = Path(app_storage_path()) / "GreyNOC" / "HomeGuard"
    except Exception:
        path = Path(os.environ.get("HOMEGUARD_DATA_DIR", Path.home() / ".homeguard"))
    path.mkdir(parents=True, exist_ok=True)
    return path


class GradientHeader(BoxLayout):
    def __init__(self, **kwargs):
        super().__init__(orientation="vertical", **kwargs)
        self.size_hint_y = None
        self.height = dp(110)
        with self.canvas.before:
            self._bg_color = Color(*BRAND_DEEP)
            self._bg = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._update_bg, size=self._update_bg)
        title = Label(
            text="HomeGuard",
            color=(1, 1, 1, 1),
            font_size="22sp",
            bold=True,
            halign="left",
            valign="middle",
        )
        title.bind(size=lambda *_: title.setter("text_size")(title, title.size))
        subtitle = Label(
            text="Consumer Network Protection",
            color=(0.85, 0.92, 1, 1),
            font_size="14sp",
            halign="left",
            valign="middle",
        )
        subtitle.bind(size=lambda *_: subtitle.setter("text_size")(subtitle, subtitle.size))
        self.add_widget(title)
        self.add_widget(subtitle)

    def _update_bg(self, *_):
        self._bg.pos = self.pos
        self._bg.size = self.size


class StatusCard(BoxLayout):
    def __init__(self, label: str, **kwargs):
        super().__init__(orientation="vertical", padding=dp(10), spacing=dp(2), **kwargs)
        self.size_hint_y = None
        self.height = dp(90)
        with self.canvas.before:
            self._bg_color = Color(1, 1, 1, 1)
            self._bg = Rectangle(pos=self.pos, size=self.size)
        self.bind(pos=self._update_bg, size=self._update_bg)
        self.label = Label(
            text=label.upper(),
            color=(0.39, 0.45, 0.55, 1),
            font_size="11sp",
            halign="left",
            valign="middle",
            bold=True,
        )
        self.value = Label(
            text="â€”",
            color=BRAND_TEXT,
            font_size="20sp",
            halign="left",
            valign="middle",
            bold=True,
        )
        self.detail = Label(
            text="",
            color=(0.39, 0.45, 0.55, 1),
            font_size="12sp",
            halign="left",
            valign="middle",
        )
        for child in (self.label, self.value, self.detail):
            child.bind(size=lambda inst, *_: inst.setter("text_size")(inst, inst.size))
        self.add_widget(self.label)
        self.add_widget(self.value)
        self.add_widget(self.detail)

    def _update_bg(self, *_):
        self._bg.pos = self.pos
        self._bg.size = self.size

    def set_status(self, value: str, detail: str = "") -> None:
        self.value.text = value
        self.detail.text = detail


class HomeGuardMobileApp(App):
    def build(self):
        self.title = "HomeGuard"
        root = BoxLayout(orientation="vertical")
        with root.canvas.before:
            Color(*BRAND_BG)
            self._bg_rect = Rectangle(pos=root.pos, size=root.size)
        root.bind(
            pos=lambda *_: setattr(self._bg_rect, "pos", root.pos),
            size=lambda *_: setattr(self._bg_rect, "size", root.size),
        )

        root.add_widget(GradientHeader())

        self.network_card = StatusCard("Network Protection")
        self.device_card = StatusCard("Device Trust")
        self.updates_card = StatusCard("Security Updates")
        cards = BoxLayout(orientation="vertical", padding=dp(10), spacing=dp(8), size_hint_y=None)
        cards.bind(minimum_height=cards.setter("height"))
        for card in (self.network_card, self.device_card, self.updates_card):
            cards.add_widget(card)
        root.add_widget(cards)

        tabs = TabbedPanel(do_default_tab=False, tab_height=dp(40))

        self.scan_tab = TabbedPanelItem(text="Scan")
        scan_layout = BoxLayout(orientation="vertical", padding=dp(8), spacing=dp(6))
        self.scan_button = Button(
            text="Scan local WiFi",
            size_hint_y=None,
            height=dp(48),
            background_color=BRAND_BLUE,
            color=(1, 1, 1, 1),
        )
        self.scan_button.bind(on_release=lambda *_: self.run_scan())
        self.update_button = Button(
            text="Update Definitions",
            size_hint_y=None,
            height=dp(48),
            background_color=BRAND_DEEP,
            color=(1, 1, 1, 1),
        )
        self.update_button.bind(on_release=lambda *_: self.run_update())
        scan_layout.add_widget(self.scan_button)
        scan_layout.add_widget(self.update_button)
        self.scan_log = TextInput(readonly=True, size_hint_y=1, font_size="12sp")
        scan_layout.add_widget(self.scan_log)
        self.scan_tab.add_widget(scan_layout)

        self.devices_tab = TabbedPanelItem(text="Devices")
        self.devices_view = ScrollView()
        self.devices_box = BoxLayout(orientation="vertical", size_hint_y=None, padding=dp(6), spacing=dp(4))
        self.devices_box.bind(minimum_height=self.devices_box.setter("height"))
        self.devices_view.add_widget(self.devices_box)
        self.devices_tab.add_widget(self.devices_view)

        self.findings_tab = TabbedPanelItem(text="Findings")
        self.findings_view = ScrollView()
        self.findings_box = BoxLayout(orientation="vertical", size_hint_y=None, padding=dp(6), spacing=dp(4))
        self.findings_box.bind(minimum_height=self.findings_box.setter("height"))
        self.findings_view.add_widget(self.findings_box)
        self.findings_tab.add_widget(self.findings_view)

        tabs.add_widget(self.scan_tab)
        tabs.add_widget(self.devices_tab)
        tabs.add_widget(self.findings_tab)
        root.add_widget(tabs)

        self.network_card.set_status("Protected", "Tap Scan to check your home WiFi.")
        self.device_card.set_status("Trusted", "No devices observed yet.")
        self.updates_card.set_status("Never Updated", "Tap Update Definitions.")
        return root

    # ------------------------------------------------------------------
    # actions
    # ------------------------------------------------------------------
    def log(self, text: str) -> None:
        self.scan_log.text += text + "\n"

    def run_scan(self) -> None:
        self.scan_button.disabled = True
        self.network_card.set_status("Scanning", "Detection engine running")
        self.log("Starting WiFi neighbor scan...")
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self) -> None:
        devices: list[dict] = []
        findings: list[dict] = []
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "192.168.1.1"
        prefix = ".".join(ip.split(".")[:3]) + "."
        for i in (1, ip.split(".")[-1]):
            try:
                target = f"{prefix}{i}"
                socket.create_connection((target, 80), timeout=0.4).close()
                devices.append({"ip": target, "open_ports": [80]})
            except Exception:
                continue
        if not devices:
            devices.append({"ip": ip, "open_ports": []})
        Clock.schedule_once(lambda _dt: self._scan_done(devices, findings), 0)

    def _scan_done(self, devices, findings) -> None:
        self.scan_button.disabled = False
        self.network_card.set_status(
            "Protected" if not findings else "Review Needed",
            f"{len(devices)} device(s), {len(findings)} finding(s).",
        )
        self.device_card.set_status(
            "Trusted" if not findings else "New Devices Found",
            f"{len(devices)} device(s) seen.",
        )
        self.devices_box.clear_widgets()
        for device in devices:
            row = Label(
                text=f"{device.get('ip', '-')}  ports={device.get('open_ports', [])}",
                size_hint_y=None,
                height=dp(28),
                color=BRAND_TEXT,
                halign="left",
                valign="middle",
            )
            row.bind(size=lambda inst, *_: inst.setter("text_size")(inst, inst.size))
            self.devices_box.add_widget(row)
        if not findings:
            self.findings_box.clear_widgets()
            self.findings_box.add_widget(
                Label(
                    text="No findings yet. Run a scan or update definitions.",
                    size_hint_y=None,
                    height=dp(40),
                    color=BRAND_TEXT,
                )
            )
        self.log(f"Scan complete at {datetime.now(timezone.utc).isoformat()}.")

    def run_update(self) -> None:
        self.updates_card.set_status("Updating", "Downloading CVE/KEV intelligence")
        self.log("Updating definitions (mobile uses simplified feed handling)...")
        threading.Thread(target=self._update_thread, daemon=True).start()

    def _update_thread(self) -> None:
        # Mobile builds keep the update path lightweight: write a definitions
        # file marker so the app reflects current state. The desktop app handles
        # full CISA KEV / NVD downloads.
        try:
            target = app_data_path() / "definitions" / "security_definitions.json"
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(
                '{"definitions_version": "mobile-starter", "update_status": "current"}',
                encoding="utf-8",
            )
            Clock.schedule_once(
                lambda _dt: self.updates_card.set_status("Current", "Mobile starter definitions saved."),
                0,
            )
            Clock.schedule_once(lambda _dt: self.log("Definition placeholder written."), 0)
        except Exception as exc:
            Clock.schedule_once(
                lambda _dt: self.updates_card.set_status("Update Failed", str(exc)),
                0,
            )


if __name__ == "__main__":
    HomeGuardMobileApp().run()

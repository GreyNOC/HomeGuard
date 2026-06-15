"""Tests for the live Overview dashboard.

Covers the persistent UI-preference setting (floating chat bubble / weather
greeting) that backs the dashboard, plus static guarantees that the renderer
ships live placeholders instead of mock demo data. The renderer logic itself is
JavaScript exercised by the Electron smoke test; here we assert the Python
settings contract and the no-mock invariants the release gate also enforces.
"""

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("HOMEGUARD_DATA_DIR", tempfile.mkdtemp(prefix="hg_overview_test_"))

from greynoc_homeguard.settings import AppSettings  # noqa: E402

RENDERER = ROOT / "electron" / "renderer"


class UiPrefsSettingsTests(unittest.TestCase):
    def _settings(self):
        tmp = tempfile.mkdtemp(prefix="hg_uiprefs_")
        return AppSettings(path=Path(tmp) / "settings.json").load()

    def test_defaults_bubble_on_weather_off(self):
        prefs = self._settings().ui_prefs()
        self.assertTrue(prefs["show_chat_bubble"])
        self.assertFalse(prefs["show_weather_greeting"])

    def test_set_and_persist_across_reload(self):
        settings = self._settings()
        path = settings.path
        settings.set_ui_prefs(show_chat_bubble=False, show_weather_greeting=True)
        # A fresh load from the same file must see the persisted values.
        reloaded = AppSettings(path=path).load().ui_prefs()
        self.assertFalse(reloaded["show_chat_bubble"])
        self.assertTrue(reloaded["show_weather_greeting"])

    def test_partial_update_leaves_other_pref_untouched(self):
        settings = self._settings()
        settings.set_ui_prefs(show_weather_greeting=True)
        prefs = settings.ui_prefs()
        self.assertTrue(prefs["show_weather_greeting"])
        self.assertTrue(prefs["show_chat_bubble"])  # unchanged default

    def test_unknown_keys_are_ignored_and_coerced_to_bool(self):
        settings = self._settings()
        settings.set_ui_prefs(show_chat_bubble=0)  # truthiness coercion
        self.assertFalse(settings.ui_prefs()["show_chat_bubble"])


class NoMockDashboardTests(unittest.TestCase):
    def setUp(self):
        self.index_html = (RENDERER / "index.html").read_text(encoding="utf-8")
        self.overview_js = (RENDERER / "overview.js").read_text(encoding="utf-8")

    def test_stat_cards_ship_live_placeholders_not_numbers(self):
        for card_id in ("ovRiskValue", "ovDeviceCount", "ovAlertCount", "ovUpdateCount"):
            match = re.search(rf'id="{card_id}"[^>]*>([^<]*)<', self.index_html)
            self.assertIsNotNone(match, f"missing overview card {card_id}")
            initial = match.group(1).strip()
            self.assertFalse(any(ch.isdigit() for ch in initial), f"{card_id} ships a hardcoded number '{initial}'")

    def test_greeting_is_dynamic_not_hardcoded(self):
        for phrase in ("Good morning", "Good afternoon", "Good evening", "Good night"):
            self.assertNotIn(phrase, self.index_html, f"greeting '{phrase}' must not be hardcoded in markup")
        self.assertIn("greetingForHour", self.overview_js)

    def test_no_design_mockup_literals(self):
        for marker in ("18 devices", "Identify 2 unknown devices", "Review 3 security alerts", "Update 2 devices"):
            self.assertNotIn(marker, self.index_html)
            self.assertNotIn(marker, self.overview_js)

    def test_overview_is_wired_as_default_page(self):
        self.assertIn('id="overviewPage"', self.index_html)
        self.assertIn('id="overviewTab"', self.index_html)
        self.assertIn("overview.js", self.index_html)
        self.assertIn("floatingChatBubble", self.index_html)
        # Overview pulls from real bridges, not constants.
        for bridge in ("latestReport", "definitionsStatus", "historyState", "uiPrefs"):
            self.assertIn(bridge, self.overview_js)


class PreloadBridgeTests(unittest.TestCase):
    def test_preload_exposes_ui_prefs(self):
        preload = (ROOT / "electron" / "preload.js").read_text(encoding="utf-8")
        self.assertIn("uiPrefs", preload)
        self.assertIn("homeguard:ui-prefs", preload)
        main = (ROOT / "electron" / "main.js").read_text(encoding="utf-8")
        self.assertIn('ipcMain.handle("homeguard:ui-prefs"', main)
        self.assertIn('ipcMain.handle("homeguard:ui-prefs-set"', main)


if __name__ == "__main__":
    unittest.main()

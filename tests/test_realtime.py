from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_rttest_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard import realtime  # noqa: E402
from greynoc_homeguard.quarantine import QuarantineVault  # noqa: E402

MARKER = b"HOMEGUARD-INTERNAL-SCANNER-TEST-SIGNATURE in a dropped file"


class RealtimeWatcherTest(unittest.TestCase):
    def setUp(self) -> None:
        self._work = tempfile.TemporaryDirectory(prefix="hg_rt_")
        self.work = Path(self._work.name)
        self.vault = QuarantineVault(root=self.work / "vault").load()

    def tearDown(self) -> None:
        self._work.cleanup()

    def _watcher(self, **kwargs):
        kwargs.setdefault("settle_seconds", 0.0)
        return realtime.RealtimeWatcher(
            directories=[self.work],
            malware_hashes={},
            vault=self.vault,
            **kwargs,
        )

    def test_prime_then_detect_and_quarantine(self) -> None:
        watcher = self._watcher()
        # First pass primes existing files without scanning.
        self.assertEqual(watcher.poll_once(), [])
        threat = self.work / "dropper.ps1"
        threat.write_bytes(MARKER)
        clean = self.work / "notes.txt"
        clean.write_bytes(b"nothing bad here")
        events = watcher.poll_once()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["severity"], "critical")
        self.assertEqual(events[0]["quarantined"], 1)
        self.assertFalse(threat.exists())
        self.assertTrue(clean.exists())
        self.assertEqual(self.vault.stats()["active"], 1)

    def test_dedup_unchanged_files(self) -> None:
        watcher = self._watcher()
        (self.work / "x.txt").write_bytes(b"clean")
        watcher.poll_once()  # prime
        # No threats; subsequent polls find nothing new.
        self.assertEqual(watcher.poll_once(), [])
        self.assertEqual(watcher.poll_once(), [])

    def test_detect_without_quarantine(self) -> None:
        watcher = self._watcher(auto_quarantine=False)
        watcher.poll_once()  # prime
        threat = self.work / "loader.ps1"
        threat.write_bytes(MARKER)
        events = watcher.poll_once()
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["quarantined"], 0)
        # Detected but left in place.
        self.assertTrue(threat.exists())
        self.assertEqual(self.vault.stats()["active"], 0)

    def test_scan_existing_on_first_pass(self) -> None:
        threat = self.work / "preexisting.ps1"
        threat.write_bytes(MARKER)
        watcher = self._watcher(scan_existing=True)
        events = watcher.poll_once()
        self.assertEqual(len(events), 1)
        self.assertFalse(threat.exists())

    def test_settle_window_skips_fresh_files(self) -> None:
        # A large settle window means a just-written file is skipped this pass.
        watcher = self._watcher(settle_seconds=10_000.0, scan_existing=True)
        threat = self.work / "fresh.ps1"
        threat.write_bytes(MARKER)
        events = watcher.poll_once()
        self.assertEqual(events, [])
        self.assertTrue(threat.exists())

    def test_on_event_callback_fires(self) -> None:
        captured = []
        watcher = self._watcher(on_event=captured.append)
        watcher.poll_once()  # prime
        (self.work / "evil.ps1").write_bytes(MARKER)
        watcher.poll_once()
        self.assertEqual(len(captured), 1)
        self.assertEqual(captured[0]["name"], "evil.ps1")


class EventLogTest(unittest.TestCase):
    def test_append_load_and_cap(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "events.json"
            for index in range(5):
                realtime.append_event({"name": f"f{index}.ps1", "severity": "high"}, path=log_path, cap=3)
            events = realtime.load_events(log_path)
            self.assertEqual(len(events), 3)
            # Cap keeps the most recent entries.
            self.assertEqual(events[-1]["name"], "f4.ps1")
            realtime.clear_events(log_path)
            self.assertEqual(realtime.load_events(log_path), [])

    def test_load_missing_returns_empty(self) -> None:
        self.assertEqual(realtime.load_events(Path(_TMP_ROOT) / "ghost.json"), [])


class SettingsTest(unittest.TestCase):
    def test_realtime_and_hash_feed_round_trip(self) -> None:
        from greynoc_homeguard.settings import AppSettings

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            settings = AppSettings(path=path).load()
            cfg = settings.realtime_config()
            self.assertFalse(cfg["enabled"])
            settings.set_realtime(enabled=True, interval=5.0, directories=["/tmp/watch"])
            settings.set_hash_feed(url="https://example.test/feed.json")
            # Reload from disk to confirm persistence + merge.
            reloaded = AppSettings(path=path).load()
            self.assertTrue(reloaded.realtime_config()["enabled"])
            self.assertEqual(reloaded.realtime_config()["interval"], 5.0)
            self.assertEqual(reloaded.realtime_config()["directories"], ["/tmp/watch"])
            self.assertEqual(reloaded.hash_feed_config()["url"], "https://example.test/feed.json")


class SeverityHelperTest(unittest.TestCase):
    def test_highest_severity(self) -> None:
        self.assertEqual(realtime._highest_severity(["low", "critical", "medium"]), "critical")
        self.assertEqual(realtime._highest_severity(["info", "low"]), "low")
        self.assertEqual(realtime._highest_severity([]), "info")


if __name__ == "__main__":
    unittest.main()

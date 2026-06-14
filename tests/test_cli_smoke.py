import os
import sys
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


class CliSmokeTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="hg_cli_smoke_")
        os.environ["HOMEGUARD_DATA_DIR"] = self._tmp.name

    def tearDown(self):
        import logging

        logger = logging.getLogger("greynoc_homeguard")
        for handler in list(logger.handlers):
            logger.removeHandler(handler)
            handler.close()

        try:
            import greynoc_homeguard.logging_setup as logging_setup
            logging_setup._initialized = False
        except Exception:
            pass

        self._tmp.cleanup()

    def test_status_command_does_not_crash_on_empty_app_data(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        self.assertEqual(cli.cmd_status(Namespace()), 0)

    def test_definitions_status_command_does_not_crash(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        self.assertEqual(cli.cmd_definitions_status(Namespace()), 0)

    def test_history_command_does_not_crash_without_scans(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        self.assertEqual(cli.cmd_history(Namespace(limit=5)), 0)

    def test_devices_list_command_does_not_crash_without_devices(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        self.assertEqual(cli.cmd_devices_list(Namespace()), 0)

    def test_quarantine_list_command_does_not_crash_when_empty(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        self.assertEqual(cli.cmd_quarantine_list(Namespace(all=False)), 0)

    def test_scan_file_command_detects_and_quarantines(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        target = Path(self._tmp.name) / "dropper.ps1"
        target.write_bytes(b"HOMEGUARD-INTERNAL-SCANNER-TEST-SIGNATURE payload")
        rc = cli.cmd_scan_path(Namespace(path=str(target), quarantine=True))
        self.assertEqual(rc, 0)
        # The critical-signature file should have been quarantined off disk.
        self.assertFalse(target.exists())
        self.assertGreaterEqual(cli.QuarantineVault().load().stats()["active"], 1)

    def test_scan_file_command_rejects_missing_path(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        rc = cli.cmd_scan_path(Namespace(path=str(Path(self._tmp.name) / "ghost.bin"), quarantine=False))
        self.assertEqual(rc, 2)

    def test_watch_once_runs_a_single_pass(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        watch_dir = Path(self._tmp.name) / "watched"
        watch_dir.mkdir()
        rc = cli.cmd_watch(
            Namespace(
                dir=[str(watch_dir)],
                interval=0.0,
                no_quarantine=True,
                scan_existing=False,
                once=True,
                events=False,
                enable=False,
                disable=False,
            )
        )
        self.assertEqual(rc, 0)

    def test_watch_events_view_does_not_crash(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        rc = cli.cmd_watch(
            Namespace(dir=[], interval=None, no_quarantine=False, scan_existing=False, once=False, events=True, enable=False, disable=False)
        )
        self.assertEqual(rc, 0)

    def test_update_hashes_rejects_unsigned_file(self):
        from greynoc_homeguard import cli
        from greynoc_homeguard.paths import ensure_app_dirs

        ensure_app_dirs()
        bad = Path(self._tmp.name) / "bad_feed.json"
        bad.write_text('{"data": "eyJ4IjogMX0=", "signature": "AAAA"}', encoding="utf-8")
        rc = cli.cmd_update_hashes(Namespace(url="", file=str(bad)))
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()

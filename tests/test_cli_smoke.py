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
        self.addCleanup(self._tmp.cleanup)
        os.environ["HOMEGUARD_DATA_DIR"] = self._tmp.name

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


if __name__ == "__main__":
    unittest.main()

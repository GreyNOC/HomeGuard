"""Tests for the "clear risk" (sticky dismissal) and per-computer Overview scope.

Covers the stable finding signature, the cleared-findings settings block, the
engine filtering cleared findings out of every scan, and the this-device summary
that scopes the Overview to the computer it runs on.
"""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("HOMEGUARD_DATA_DIR", tempfile.mkdtemp(prefix="hg_clearrisk_test_"))

from greynoc_homeguard.engine import HomeGuardEngine  # noqa: E402
from greynoc_homeguard.models import Device, Finding, HomeGuardReport, finding_signature  # noqa: E402
from greynoc_homeguard.scan_runner import _build_this_device_summary, _partition_cleared  # noqa: E402
from greynoc_homeguard.settings import AppSettings  # noqa: E402


def _finding(rule_id, *, device_ip, category="exposed_service", severity="high", risk_score=70.0, evidence=None):
    return Finding(
        finding_id="hg_x",
        rule_id=rule_id,
        title=f"{rule_id} finding",
        severity=severity,
        confidence=0.9,
        risk_score=risk_score,
        priority="P2",
        category=category,
        device_ip=device_ip,
        device_name=device_ip,
        plain_english="",
        recommended_actions=[],
        evidence=evidence or {},
    )


class FindingSignatureTests(unittest.TestCase):
    def test_signature_is_stable_across_volatile_evidence(self):
        a = _finding("risky_port_23", device_ip="192.168.1.9", evidence={"port": 23, "open_ports": [23, 80], "definitions_version": "2026-06-01"})
        b = _finding("risky_port_23", device_ip="192.168.1.9", evidence={"port": 23, "open_ports": [23, 80, 443], "definitions_version": "2026-09-09"})
        self.assertEqual(finding_signature(a), finding_signature(b))

    def test_endpoint_findings_with_different_files_are_distinct(self):
        a = _finding("endpoint_file_signature", device_ip="local-host", category="endpoint_file_signature", evidence={"path": "C:/a/evil.exe"})
        b = _finding("endpoint_file_signature", device_ip="local-host", category="endpoint_file_signature", evidence={"path": "C:/b/other.exe"})
        self.assertNotEqual(finding_signature(a), finding_signature(b))

    def test_signature_is_exposed_and_hashed(self):
        f = _finding("risky_port_23", device_ip="192.168.1.9", evidence={"port": 23})
        sig = f.as_dict()["signature"]
        self.assertTrue(sig.startswith("sig_"))
        self.assertNotIn("192.168.1.9", sig)  # raw evidence is hashed, never exposed


class ClearedFindingsSettingsTests(unittest.TestCase):
    def _settings(self):
        tmp = tempfile.mkdtemp(prefix="hg_cleared_")
        return AppSettings(path=Path(tmp) / "settings.json").load()

    def test_clear_restore_and_persist(self):
        settings = self._settings()
        path = settings.path
        self.assertTrue(settings.clear_finding("sig_0123456789abcdef", title="Telnet on cam"))
        self.assertIn("sig_0123456789abcdef", settings.cleared_signatures())
        # Persisted across a fresh load.
        reloaded = AppSettings(path=path).load()
        self.assertIn("sig_0123456789abcdef", reloaded.cleared_signatures())
        self.assertEqual(reloaded.cleared_findings_list()[0]["title"], "Telnet on cam")
        # Restore removes it.
        self.assertTrue(reloaded.restore_finding("sig_0123456789abcdef"))
        self.assertNotIn("sig_0123456789abcdef", AppSettings(path=path).load().cleared_signatures())

    def test_empty_signature_is_rejected(self):
        settings = self._settings()
        self.assertFalse(settings.clear_finding(""))


class EngineClearedFilterTests(unittest.TestCase):
    def test_cleared_finding_stays_filtered_and_lowers_risk(self):
        device = Device(ip="192.168.1.40", hostname="camera", open_ports=[23])
        report = HomeGuardEngine().build_report([device])
        telnet = next(f for f in report.findings if f.rule_id == "risky_port_23")
        signature = finding_signature(telnet)

        cleared = HomeGuardEngine().build_report([device], cleared_signatures={signature})
        self.assertNotIn("risky_port_23", {f.rule_id for f in cleared.findings})
        self.assertGreaterEqual(cleared.scan_metadata["cleared_finding_count"], 1)
        self.assertLessEqual(cleared.overall_score, report.overall_score)

    def test_no_cleared_signatures_is_a_noop(self):
        device = Device(ip="192.168.1.40", hostname="camera", open_ports=[23])
        base = HomeGuardEngine().build_report([device])
        same = HomeGuardEngine().build_report([device], cleared_signatures=set())
        self.assertEqual({f.rule_id for f in base.findings}, {f.rule_id for f in same.findings})
        self.assertEqual(same.scan_metadata["cleared_finding_count"], 0)


class ThisDeviceSummaryTests(unittest.TestCase):
    def _report(self):
        devices = [
            Device(ip="192.168.1.5", hostname="my-pc", open_ports=[22, 445]),
            Device(ip="192.168.1.9", hostname="cam", open_ports=[23]),
        ]
        findings = [
            _finding("risky_port_445", device_ip="192.168.1.5", severity="medium", risk_score=50.0, evidence={"port": 445}),
            _finding("risky_port_23", device_ip="192.168.1.9", severity="high", risk_score=70.0, evidence={"port": 23}),
            _finding("endpoint_file_signature", device_ip="local-host", category="endpoint_file_signature", severity="high", risk_score=70.0, evidence={"path": "C:/x/evil.exe"}),
        ]
        return HomeGuardReport(
            report_id="r", created_at="2026-06-15T00:00:00Z", summary="", overall_risk="high",
            overall_score=70.0, devices=devices, findings=findings,
            next_steps=[], scan_metadata={"definition_status": {}},
        )

    def test_scopes_to_this_computer_only(self):
        td = _build_this_device_summary(self._report(), {"192.168.1.5"})
        # This PC's own port finding + the endpoint finding; NOT the cam at .9.
        self.assertEqual(td["finding_count"], 2)
        self.assertEqual(td["open_service_count"], 2)  # ports 22, 445 on this PC
        self.assertEqual(td["overall_risk"], "high")  # max of this-device findings (70)
        self.assertEqual(td["device_name"], "my-pc")
        self.assertEqual(len(td["signatures"]), 2)

    def test_partition_cleared_splits_by_signature(self):
        findings = self._report().findings
        sig = finding_signature(findings[0])
        active, removed = _partition_cleared(findings, {sig})
        self.assertEqual(len(removed), 1)
        self.assertEqual(len(active), 2)


class ElectronWiringTests(unittest.TestCase):
    def test_preload_and_ipc_expose_risk_controls(self):
        preload = (ROOT / "electron" / "preload.js").read_text(encoding="utf-8")
        self.assertIn("risks", preload)
        self.assertIn("homeguard:clear-risk", preload)
        main = (ROOT / "electron" / "main.js").read_text(encoding="utf-8")
        for channel in ("homeguard:clear-risk", "homeguard:restore-risk", "homeguard:cleared-risks"):
            self.assertIn(f'ipcMain.handle("{channel}"', main)

    def test_overview_scopes_to_this_device(self):
        overview = (ROOT / "electron" / "renderer" / "overview.js").read_text(encoding="utf-8")
        self.assertIn("this_device", overview)
        self.assertIn("renderServicesCard", overview)


if __name__ == "__main__":
    unittest.main()

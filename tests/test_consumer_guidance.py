"""Tests for the consumer-safety language pass and release-doc consistency.

These cover the polish work that keeps HomeGuard's user-facing wording honest
("indicator, not proof"), adds a calm prioritized action summary, and keeps the
release docs from claiming a stale version. They build reports through the
shared ``HomeGuardEngine.build_report`` path rather than asserting on whole
rendered snapshots, so they stay robust to cosmetic report changes.
"""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

os.environ.setdefault("HOMEGUARD_DATA_DIR", tempfile.mkdtemp(prefix="hg_guidance_test_"))

from greynoc_homeguard import reports  # noqa: E402
from greynoc_homeguard.baseline import BaselineStore, TRUST_QUARANTINED  # noqa: E402
from greynoc_homeguard.engine import HomeGuardEngine  # noqa: E402
from greynoc_homeguard.guidance import (  # noqa: E402
    INDICATOR_NOTE,
    QUARANTINE_NOTE,
    REPORT_DISCLAIMER,
    priority_actions,
    with_indicator_note,
)
from greynoc_homeguard.models import Device  # noqa: E402
from greynoc_homeguard.privacy import assert_share_safe, scrub_report  # noqa: E402


def _quarantined_report():
    tmp = tempfile.mkdtemp(prefix="hg_q_")
    baseline = BaselineStore(Path(tmp) / "baseline.json").load()
    device = Device(ip="192.168.1.50", mac_address="aa:bb:cc:dd:ee:ff", hostname="iot")
    baseline.update([device])
    baseline.set_trust(device.fingerprint(), TRUST_QUARANTINED)
    return HomeGuardEngine().build_report([device], baseline=baseline)


class IndicatorNoteTests(unittest.TestCase):
    def test_with_indicator_note_appends_once(self):
        out = with_indicator_note("A device is reachable")
        self.assertIn("not proof of compromise", out.lower())
        # Idempotent: a second pass does not stack a second caveat.
        self.assertEqual(with_indicator_note(out), out)

    def test_with_indicator_note_skips_already_hedged_text(self):
        hedged = "A port-only scan cannot prove compromise here."
        self.assertEqual(with_indicator_note(hedged), hedged)
        self.assertNotIn(INDICATOR_NOTE, with_indicator_note(hedged))

    def test_port_only_finding_says_indicator_not_proof(self):
        device = Device(ip="192.168.1.40", hostname="camera", open_ports=[23])
        report = HomeGuardEngine().build_report([device])
        telnet = next(f for f in report.findings if f.rule_id == "risky_port_23")
        # Severity/scoring is unchanged; only the explanation is softened.
        self.assertEqual(telnet.severity, "high")
        self.assertIn("not proof of compromise", telnet.plain_english.lower())


class QuarantineWordingTests(unittest.TestCase):
    def test_quarantine_finding_distinguishes_flagging_from_isolation(self):
        report = _quarantined_report()
        finding = next(f for f in report.findings if f.rule_id == "quarantined_device")
        self.assertIn("does not block the device by itself", finding.plain_english)

    def test_quarantine_note_present_in_rendered_reports(self):
        report = _quarantined_report()
        markdown = reports.render_markdown(report)
        html = reports.render_html(report)
        self.assertIn("does not block the device by itself", markdown + html)
        # The shared constant is what feeds both the finding and the report note.
        self.assertIn("block it on your router", QUARANTINE_NOTE)


class PriorityActionTests(unittest.TestCase):
    def test_quarantined_review_is_first_action(self):
        report = _quarantined_report()
        actions = priority_actions(report)
        self.assertTrue(actions)
        self.assertEqual(actions[0]["action"], "Review devices you flagged")
        for entry in actions:
            self.assertEqual(set(entry), {"action", "detail", "count"})

    def test_clean_report_only_suggests_definition_maintenance(self):
        device = Device(ip="192.168.1.2", mac_address="aa:aa:aa:aa:aa:aa")
        report = HomeGuardEngine().build_report([device])
        actions = priority_actions(report)
        self.assertEqual([a["action"] for a in actions], ["Keep security definitions current"])

    def test_definitions_reminder_is_always_last(self):
        # Even when definitions are stale (which previously floated the reminder
        # above info-severity finding groups), the maintenance step closes the
        # list so the guidance always ends on a calm note.
        report = _quarantined_report()
        actions = priority_actions(report)
        names = [a["action"] for a in actions]
        self.assertIn("Keep security definitions current", names)
        self.assertEqual(names[-1], "Keep security definitions current")


class ReportDisclaimerTests(unittest.TestCase):
    def test_report_dict_is_backward_compatible_and_adds_guidance(self):
        report = _quarantined_report()
        data = report.as_dict()
        # Every legacy key still present (additive change only).
        for key in (
            "report_id",
            "created_at",
            "summary",
            "overall_risk",
            "overall_score",
            "devices",
            "findings",
            "next_steps",
            "scan_metadata",
        ):
            self.assertIn(key, data)
        self.assertEqual(data["disclaimer"], REPORT_DISCLAIMER)
        self.assertIsInstance(data["priority_actions"], list)
        # Round-trips through JSON unchanged (history/UI consumers stay happy).
        self.assertEqual(json.loads(json.dumps(data))["disclaimer"], REPORT_DISCLAIMER)

    def test_rendered_reports_show_disclaimer_and_first_steps(self):
        report = _quarantined_report()
        markdown = reports.render_markdown(report)
        html = reports.render_html(report)
        self.assertIn(REPORT_DISCLAIMER, markdown)
        self.assertIn("What To Do First", markdown)
        self.assertIn(REPORT_DISCLAIMER, html)
        self.assertIn("What to do first", html)

    def test_added_guidance_text_stays_share_safe(self):
        # Mirror the real export pipeline (scrub_report -> render -> assert) so we
        # are checking that the new disclaimer/action text is share-safe, not the
        # pre-existing metadata paths the export path already redacts.
        report = scrub_report(_quarantined_report())
        assert_share_safe(reports.render_markdown(report))
        assert_share_safe(reports.render_html(report))
        assert_share_safe(json.dumps(report.as_dict()))


class ReleaseDocConsistencyTests(unittest.TestCase):
    def _read(self, *parts):
        return (ROOT.joinpath(*parts)).read_text(encoding="utf-8")

    def test_release_docs_do_not_claim_stale_current_version(self):
        for rel in (
            ("docs", "release", "RELEASE_CHECKLIST.md"),
            ("docs", "release", "BUILD_AND_SIGNING.md"),
        ):
            text = self._read(*rel)
            with self.subTest(doc="/".join(rel)):
                self.assertNotIn("HomeGuard-Setup-v1.5.0.exe", text)
                self.assertNotIn("current production release is `1.5.0`", text)

    def test_release_checklist_documents_version_derivation(self):
        text = self._read("docs", "release", "RELEASE_CHECKLIST.md")
        self.assertIn("pyproject.toml", text)

    def test_version_sources_agree(self):
        pyproject = self._read("pyproject.toml")
        version = ""
        for line in pyproject.splitlines():
            if line.strip().startswith("version"):
                version = line.split("=", 1)[1].strip().strip('"')
                break
        self.assertTrue(version, "could not read version from pyproject.toml")
        package = json.loads(self._read("package.json"))
        lock = json.loads(self._read("package-lock.json"))
        self.assertEqual(package["version"], version)
        self.assertEqual(lock["version"], version)


if __name__ == "__main__":
    unittest.main()

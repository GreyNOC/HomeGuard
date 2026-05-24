import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_test_playbooks_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard.playbooks import (  # noqa: E402
    ACTION_MARK_PATCHED,
    ACTION_MARK_QUARANTINED,
    ACTION_MARK_TRUSTED,
    ACTION_NAVIGATE_DEVICES,
    ACTION_OPEN_URL,
    ACTION_RUN_DEFENDER_SCAN,
    all_playbook_ids,
    playbook_for_finding,
    playbook_id_for_rule,
)


class PlaybookIdMappingTests(unittest.TestCase):
    """Every detection rule routes to one of the five categories."""

    def test_risky_port_rules_map_to_exposed_remote_service(self):
        self.assertEqual(playbook_id_for_rule("risky_port_3389"), "exposed_remote_service")
        self.assertEqual(playbook_id_for_rule("risky_port_23"), "exposed_remote_service")
        self.assertEqual(playbook_id_for_rule("risky_port_445"), "exposed_remote_service")
        self.assertEqual(playbook_id_for_rule("risky_port_5900"), "exposed_remote_service")

    def test_inventory_rules_map_to_unknown_device(self):
        self.assertEqual(playbook_id_for_rule("new_device"), "unknown_device")
        self.assertEqual(playbook_id_for_rule("missing_mac"), "unknown_device")
        self.assertEqual(playbook_id_for_rule("default_name_hint"), "unknown_device")

    def test_quarantined_rule_maps_to_quarantined_device(self):
        self.assertEqual(playbook_id_for_rule("quarantined_device"), "quarantined_device")

    def test_kev_and_product_hint_map_to_cve_kev(self):
        self.assertEqual(playbook_id_for_rule("known_exploited_vulnerability"), "cve_kev")
        self.assertEqual(playbook_id_for_rule("product_hint"), "cve_kev")

    def test_windows_privesc_rules_map_to_endpoint_hardening(self):
        self.assertEqual(
            playbook_id_for_rule("windows_privesc_always_install_elevated"),
            "endpoint_hardening",
        )
        self.assertEqual(
            playbook_id_for_rule("windows_hardening_credential_guard_disabled"),
            "endpoint_hardening",
        )

    def test_unknown_rule_falls_back_to_generic(self):
        self.assertEqual(playbook_id_for_rule("some_made_up_rule"), "generic")
        self.assertEqual(playbook_id_for_rule(""), "generic")

    def test_all_playbook_ids_includes_five_categories_plus_generic(self):
        ids = set(all_playbook_ids())
        self.assertIn("exposed_remote_service", ids)
        self.assertIn("unknown_device", ids)
        self.assertIn("quarantined_device", ids)
        self.assertIn("cve_kev", ids)
        self.assertIn("endpoint_hardening", ids)
        self.assertIn("generic", ids)


class PlaybookContentTests(unittest.TestCase):
    """Each category returns the right shape and actions."""

    def _finding(self, **overrides):
        base = {
            "finding_id": "fid-test",
            "rule_id": "risky_port_3389",
            "severity": "high",
            "title": "RDP exposed",
            "device_ip": "192.168.1.42",
            "device_name": "home-pc",
            "evidence": {
                "port": 3389,
                "device_fingerprint": "mac:aa:bb:cc:dd:ee:ff",
            },
            "plain_english": "Remote Desktop is reachable.",
            "recommended_actions": ["Disable Remote Desktop unless needed."],
        }
        base.update(overrides)
        return base

    def test_exposed_remote_service_bakes_in_port_and_device(self):
        playbook = playbook_for_finding(self._finding())
        self.assertEqual(playbook.id, "exposed_remote_service")
        self.assertIn("Remote Desktop", playbook.title)
        self.assertIn("home-pc", playbook.summary)
        self.assertIn("3389", playbook.summary)
        action_kinds = {a.kind for a in playbook.actions}
        # Quarantine + trust come from the device fingerprint; mark_patched is always present.
        self.assertIn(ACTION_MARK_PATCHED, action_kinds)
        self.assertIn(ACTION_MARK_QUARANTINED, action_kinds)
        self.assertIn(ACTION_MARK_TRUSTED, action_kinds)
        # Firewall settings deep-link is included as an open_url action.
        self.assertTrue(
            any(a.kind == ACTION_OPEN_URL and "ms-settings" in a.payload.get("url", "")
                for a in playbook.actions),
        )

    def test_exposed_service_without_fingerprint_omits_trust_actions(self):
        finding = self._finding(evidence={"port": 3389})  # no fingerprint
        playbook = playbook_for_finding(finding)
        action_kinds = {a.kind for a in playbook.actions}
        self.assertNotIn(ACTION_MARK_TRUSTED, action_kinds)
        self.assertNotIn(ACTION_MARK_QUARANTINED, action_kinds)
        # Mark-patched still applies (purely renderer-side state).
        self.assertIn(ACTION_MARK_PATCHED, action_kinds)

    def test_unknown_device_includes_navigate_action(self):
        finding = self._finding(rule_id="new_device", severity="low")
        playbook = playbook_for_finding(finding)
        self.assertEqual(playbook.id, "unknown_device")
        kinds = {a.kind for a in playbook.actions}
        self.assertIn(ACTION_NAVIGATE_DEVICES, kinds)
        # Vendor hint flows into step text from evidence.
        finding_with_vendor = self._finding(
            rule_id="new_device",
            evidence={
                "device_fingerprint": "mac:b8:78:2e:11:22:33",
                "vendor": "Wyze",
                "mac_address": "b8:78:2e:11:22:33",
            },
        )
        playbook = playbook_for_finding(finding_with_vendor)
        flat_text = " ".join(step.body for step in playbook.steps)
        self.assertIn("Wyze", flat_text)

    def test_quarantined_device_actions(self):
        finding = self._finding(rule_id="quarantined_device", severity="high")
        playbook = playbook_for_finding(finding)
        self.assertEqual(playbook.id, "quarantined_device")
        kinds = {a.kind for a in playbook.actions}
        self.assertIn(ACTION_MARK_TRUSTED, kinds)
        self.assertIn(ACTION_MARK_QUARANTINED, kinds)
        # Router-block / WiFi-change appears in the step bodies (text-only).
        flat = " ".join(step.body for step in playbook.steps)
        self.assertIn("router", flat.lower())
        self.assertIn("wifi", flat.lower())

    def test_cve_kev_includes_open_update_page_action(self):
        finding = self._finding(
            rule_id="known_exploited_vulnerability",
            severity="medium",
            title="KEV match",
            evidence={
                "device_fingerprint": "mac:aa:bb:cc:dd:ee:ff",
                "cve_ids": ["CVE-2024-12345"],
                "vendor": "TP-Link",
                "product": "Archer C7",
            },
        )
        playbook = playbook_for_finding(finding)
        self.assertEqual(playbook.id, "cve_kev")
        kinds = [a.kind for a in playbook.actions]
        self.assertIn(ACTION_OPEN_URL, kinds)
        url_action = next(a for a in playbook.actions if a.kind == ACTION_OPEN_URL)
        self.assertIn("CVE-2024-12345", url_action.payload.get("url", ""))
        self.assertIn(ACTION_MARK_PATCHED, kinds)

    def test_endpoint_hardening_includes_defender_action(self):
        finding = self._finding(
            rule_id="windows_privesc_always_install_elevated",
            severity="high",
            title="AlwaysInstallElevated registry set",
            plain_english="Both registry keys enabled - any user can install MSI as SYSTEM.",
        )
        playbook = playbook_for_finding(finding)
        self.assertEqual(playbook.id, "endpoint_hardening")
        kinds = {a.kind for a in playbook.actions}
        self.assertIn(ACTION_RUN_DEFENDER_SCAN, kinds)
        self.assertIn(ACTION_MARK_PATCHED, kinds)
        # Per-rule hardening body should appear in the step text.
        flat = " ".join(step.body for step in playbook.steps)
        self.assertIn("AlwaysInstallElevated", flat)

    def test_generic_fallback_for_unknown_rule(self):
        finding = self._finding(rule_id="rule_we_dont_know_about")
        playbook = playbook_for_finding(finding)
        self.assertEqual(playbook.id, "generic")
        # Even the generic fallback produces actionable output.
        self.assertTrue(playbook.steps)
        self.assertTrue(playbook.actions)
        self.assertIn(ACTION_MARK_PATCHED, {a.kind for a in playbook.actions})

    def test_serialization_round_trip(self):
        playbook = playbook_for_finding(self._finding())
        as_dict = playbook.as_dict()
        for key in ("id", "title", "summary", "severity_note", "steps", "actions", "patched_at"):
            self.assertIn(key, as_dict)
        # steps + actions are plain JSON-serializable dicts.
        self.assertIsInstance(as_dict["steps"], list)
        self.assertIsInstance(as_dict["actions"], list)
        for action in as_dict["actions"]:
            self.assertIn("kind", action)
            self.assertIn("label", action)


class PlaybookSafetyTests(unittest.TestCase):
    def test_missing_fields_do_not_raise(self):
        playbook = playbook_for_finding({})
        self.assertEqual(playbook.id, "generic")
        self.assertTrue(playbook.steps)

    def test_severity_note_filled_per_severity(self):
        for severity, expected_word in (
            ("critical", "Critical"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Informational"),
        ):
            playbook = playbook_for_finding({"rule_id": "new_device", "severity": severity})
            self.assertIn(expected_word, playbook.severity_note)


if __name__ == "__main__":
    unittest.main()

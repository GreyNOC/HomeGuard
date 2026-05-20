import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from greynoc_homeguard.ai_bridge import (  # noqa: E402
    AISettings,
    configure_ai,
    explain_report,
    load_ai_settings,
    report_to_signal_context,
    save_ai_settings,
    set_sterile,
)
from greynoc_homeguard.models import Device, Finding, HomeGuardReport, utcnow  # noqa: E402


class AIBridgeTests(unittest.TestCase):
    def _report(self) -> HomeGuardReport:
        device = Device(
            ip="192.168.1.25",
            mac_address="AA:BB:CC:DD:EE:FF",
            hostname="family-laptop",
            interface="Wi-Fi",
            open_ports=[3389],
            vendor="ExampleVendor",
            metadata={"path": "C:/Users/Alice/Downloads/tool.exe"},
        )
        finding = Finding(
            finding_id="f1",
            rule_id="risky_port_3389",
            title="Remote desktop is exposed",
            severity="high",
            confidence=0.9,
            risk_score=8.5,
            priority="high",
            category="remote_access",
            device_ip="192.168.1.25",
            device_name="family-laptop",
            plain_english="Remote desktop appears reachable on this device.",
            recommended_actions=["Turn off Remote Desktop if you do not use it."],
            evidence={"ip": "192.168.1.25", "mac": "AA:BB:CC:DD:EE:FF", "port": 3389},
        )
        return HomeGuardReport(
            report_id="r1",
            created_at=utcnow(),
            summary="High risk remote access finding.",
            overall_risk="high",
            overall_score=8.5,
            devices=[device],
            findings=[finding],
            next_steps=["Review Remote Desktop exposure."],
        )

    def test_default_settings_are_sterile(self):
        settings = AISettings()
        self.assertTrue(settings.is_sterile())
        response = explain_report(self._report(), settings=settings)
        self.assertTrue(response.ok)
        self.assertTrue(response.sterile)
        self.assertEqual(response.provider, "sterile")

    def test_settings_round_trip_without_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ai_settings.json"
            settings = configure_ai(
                provider="openai",
                model="gpt-test",
                api_key_env="MY_OPENAI_KEY",
                share_level="minimal",
                path=path,
            )
            self.assertTrue(settings.enabled)
            raw = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(raw["api_key_env"], "MY_OPENAI_KEY")
            self.assertNotIn("api_key", raw)
            loaded = load_ai_settings(path=path)
            self.assertEqual(loaded.provider, "openai")
            self.assertEqual(loaded.model, "gpt-test")

    def test_set_sterile_disables_provider(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ai_settings.json"
            save_ai_settings(AISettings(enabled=True, provider="openai", model="x", api_key_env="KEY"), path=path)
            settings = set_sterile(path=path)
            self.assertTrue(settings.is_sterile())
            self.assertFalse(load_ai_settings(path=path).enabled)

    def test_minimal_signal_context_hashes_identifiers(self):
        context = report_to_signal_context(self._report(), share_level="minimal")
        device = context["devices"][0]
        finding = context["top_findings"][0]
        self.assertNotEqual(device["ip"], "192.168.1.25")
        self.assertNotEqual(device["hostname"], "family-laptop")
        self.assertNotIn("AA:BB:CC:DD:EE:FF", json.dumps(context))
        self.assertNotIn("family-laptop", json.dumps(context))
        self.assertNotEqual(finding["device_ip"], "192.168.1.25")
        self.assertEqual(finding["evidence"]["port"], 3389)

    def test_missing_api_key_returns_clean_error(self):
        env_name = "HOMEGUARD_TEST_MISSING_AI_KEY"
        os.environ.pop(env_name, None)
        settings = AISettings(enabled=True, provider="openai", model="gpt-test", api_key_env=env_name)
        response = explain_report(self._report(), settings=settings)
        self.assertFalse(response.ok)
        self.assertIn(env_name, response.error)


if __name__ == "__main__":
    unittest.main()

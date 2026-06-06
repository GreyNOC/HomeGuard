import os
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from greynoc_homeguard import ai_traffic  # noqa: E402


class AITrafficTests(unittest.TestCase):
    def test_redact_remote_minimal_hashes_external(self):
        external = "8.8.8.8"
        redacted = ai_traffic._redact_remote(external, share_level="minimal")
        self.assertNotEqual(redacted, external)
        self.assertTrue(redacted.startswith("ext-"))

    def test_redact_remote_full_returns_raw(self):
        external = "8.8.8.8"
        self.assertEqual(ai_traffic._redact_remote(external, share_level="full"), external)

    def test_redact_remote_standard_keeps_private_lan(self):
        lan = "192.168.1.10"
        # Standard keeps private LAN addresses as-is; only external is hashed.
        self.assertEqual(ai_traffic._redact_remote(lan, share_level="standard"), lan)
        # 8.8.8.8 is unambiguously a public IP (203.0.113.0/24 is RFC-5737
        # documentation space and Python classifies it as is_private=True).
        external = "8.8.8.8"
        self.assertNotEqual(
            ai_traffic._redact_remote(external, share_level="standard"),
            external,
        )

    def test_split_endpoint_handles_ipv4(self):
        self.assertEqual(ai_traffic._split_endpoint("10.0.0.1:443"), ("10.0.0.1", 443))
        self.assertEqual(ai_traffic._split_endpoint(""), ("", 0))
        self.assertEqual(ai_traffic._split_endpoint("*"), ("", 0))

    def test_split_endpoint_handles_ipv6_bracket(self):
        addr, port = ai_traffic._split_endpoint("[::1]:80")
        self.assertEqual(port, 80)
        self.assertIn(":", addr)

    def test_collect_traffic_summary_returns_structure(self):
        summary = ai_traffic.collect_traffic_summary(share_level="minimal")
        payload = summary.as_dict()
        self.assertIn("captured_at", payload)
        self.assertIn("source", payload)
        self.assertIsInstance(payload["listening_ports"], list)
        self.assertIsInstance(payload["established_remote_top"], list)
        self.assertIsInstance(payload["process_top"], list)

    def test_minimal_share_level_hides_external_ips_in_summary(self):
        summary = ai_traffic.collect_traffic_summary(share_level="minimal")
        for row in summary.established_remote_top:
            if row["scope"] == "external":
                self.assertFalse(
                    row["endpoint"].startswith(("1.", "2.", "3.")),
                    msg=f"External endpoint {row['endpoint']} appears unredacted",
                )


if __name__ == "__main__":
    unittest.main()

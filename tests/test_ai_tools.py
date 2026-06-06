import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from greynoc_homeguard import ai_memory, ai_tools  # noqa: E402


SAMPLE_REPORT = {
    "report_id": "r1",
    "overall_risk": "high",
    "overall_score": 8.0,
    "summary": "Sample summary",
    "devices": [
        {
            "ip": "192.168.1.20",
            "hostname": "kitchen-tablet",
            "mac_address": "AA:BB:CC:DD:EE:01",
            "open_ports": [445],
            "source": "passive",
        }
    ],
    "findings": [
        {
            "finding_id": "f1",
            "rule_id": "risky_port_445",
            "title": "SMB exposed",
            "severity": "high",
            "confidence": 0.85,
            "risk_score": 7.5,
            "priority": "high",
            "category": "remote_access",
            "device_ip": "192.168.1.20",
            "device_name": "kitchen-tablet",
            "plain_english": "SMB sharing is reachable.",
            "recommended_actions": ["Disable SMBv1"],
            "evidence": {"port": 445},
        }
    ],
    "next_steps": ["Audit SMB exposure"],
}


class AIToolsTests(unittest.TestCase):
    def test_dispatch_unknown_tool_returns_error(self):
        result = ai_tools.dispatch_tool("nonexistent_tool", {}, share_level="minimal")
        self.assertIn("error", result)

    def test_get_latest_report_handles_missing(self):
        with mock.patch.object(ai_tools, "_load_latest_report_payload", return_value={}):
            result = ai_tools.tool_get_latest_report({}, "minimal")
        self.assertFalse(result["available"])

    def test_get_latest_report_redacts_in_minimal(self):
        with mock.patch.object(ai_tools, "_load_latest_report_payload", return_value=SAMPLE_REPORT):
            result = ai_tools.tool_get_latest_report({}, "minimal")
        self.assertTrue(result["available"])
        serialized = json.dumps(result)
        self.assertNotIn("192.168.1.20", serialized)
        self.assertNotIn("kitchen-tablet", serialized)
        self.assertNotIn("AA:BB:CC:DD:EE:01", serialized)

    def test_list_devices_honors_limit(self):
        with mock.patch.object(ai_tools, "_load_latest_report_payload", return_value=SAMPLE_REPORT):
            result = ai_tools.tool_list_devices({"limit": 1}, "minimal")
        self.assertEqual(result["count"], 1)
        self.assertEqual(len(result["devices"]), 1)

    def test_get_finding_returns_match(self):
        with mock.patch.object(ai_tools, "_load_latest_report_payload", return_value=SAMPLE_REPORT):
            result = ai_tools.tool_get_finding({"rule_id": "risky_port_445"}, "minimal")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["findings"][0]["rule_id"], "risky_port_445")

    def test_save_memory_note_via_tool(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / "ai_memory.json"
            with mock.patch.object(ai_memory, "memory_file", return_value=tmp_path):
                result = ai_tools.tool_save_memory_note({"text": "trusted printer"}, "minimal")
            self.assertTrue(result["saved"])
            payload = json.loads(tmp_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["notes"][0]["text"], "trusted printer")
            self.assertEqual(payload["notes"][0]["source"], "ai")

    def test_record_device_fact_hashes_in_minimal(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / "ai_memory.json"
            with mock.patch.object(ai_memory, "memory_file", return_value=tmp_path):
                result = ai_tools.tool_record_device_fact(
                    {"fingerprint": "AA:BB:CC:DD:EE:01", "label": "Camera"},
                    "minimal",
                )
            self.assertTrue(result["saved"])
            self.assertNotEqual(result["fingerprint"], "AA:BB:CC:DD:EE:01")

    def test_openai_tool_schema_shape(self):
        defs = ai_tools.tool_definitions_openai()
        self.assertTrue(defs)
        for entry in defs:
            self.assertEqual(entry["type"], "function")
            self.assertIn("name", entry["function"])
            self.assertIn("parameters", entry["function"])

    def test_anthropic_tool_schema_shape(self):
        defs = ai_tools.tool_definitions_anthropic()
        self.assertTrue(defs)
        for entry in defs:
            self.assertIn("name", entry)
            self.assertIn("input_schema", entry)


if __name__ == "__main__":
    unittest.main()

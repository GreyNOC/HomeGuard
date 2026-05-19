import json
import os
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from greynoc_homeguard import windows_privesc_audit as audit  # noqa: E402


class WindowsPrivescAuditTests(unittest.TestCase):
    def test_non_windows_returns_no_findings_without_crash(self):
        with mock.patch("greynoc_homeguard.windows_privesc_audit.platform.system", return_value="Linux"):
            result = audit.run_windows_privesc_audit()
        self.assertEqual(result.findings, [])
        self.assertIn("non_windows_platform", result.metadata["privesc_checks_skipped"])
        self.assertEqual(result.metadata["privesc_audit_platform"], "Linux")

    def test_secret_detection_redacts_values(self):
        evidence = audit.secret_evidence(
            r"C:\Windows\Panther\Unattend.xml",
            "DefaultPassword=SuperSecret123\napi_key=ABCDEF123456",
        )
        rendered = json.dumps(evidence)
        self.assertIn("password", evidence["secret_types"])
        self.assertIn("api_key", evidence["secret_types"])
        self.assertNotIn("SuperSecret123", rendered)
        self.assertNotIn("ABCDEF123456", rendered)
        self.assertTrue(evidence["secret_values_redacted"])

    def test_always_install_elevated_uses_mocked_registry(self):
        values = {
            ("HKLM", audit.INSTALLER_POLICY_KEY, "AlwaysInstallElevated"): 1,
            ("HKCU", audit.INSTALLER_POLICY_KEY, "AlwaysInstallElevated"): "1",
        }

        def reader(root, key, name):
            return values.get((root, key, name))

        findings = audit.check_always_install_elevated(reader)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "windows_privesc_always_install_elevated")
        self.assertEqual(findings[0].severity, "high")
        self.assertTrue(findings[0].evidence["hklm_policy_enabled"])
        self.assertTrue(findings[0].evidence["hkcu_policy_enabled"])

    def test_unquoted_service_path_parser_cases(self):
        self.assertFalse(audit.is_unquoted_service_path_risky(r'"C:\Program Files\App\svc.exe" -k run'))
        self.assertTrue(audit.is_unquoted_service_path_risky(r"C:\Program Files\App\svc.exe -k run"))
        self.assertFalse(audit.is_unquoted_service_path_risky(r"C:\Tools\svc.exe -k run"))
        self.assertFalse(audit.is_unquoted_service_path_risky(""))

    def test_scheduled_task_system_path_is_not_risky_without_writable_indicator(self):
        safe = audit.classify_scheduled_task_command(
            r"C:\Windows\System32\notepad.exe",
            is_writable_path=lambda _path: False,
        )
        self.assertFalse(safe["risky"])
        self.assertEqual(safe["reason"], "windows_system_path")

        writable = audit.classify_scheduled_task_command(
            r"C:\Windows\System32\notepad.exe",
            is_writable_path=lambda _path: True,
        )
        self.assertTrue(writable["risky"])
        self.assertEqual(writable["reason"], "path_or_directory_writable")

    def test_scheduled_task_user_writable_location_is_risky(self):
        result = audit.classify_scheduled_task_command(
            r"C:\Users\Alice\AppData\Local\Temp\helper.exe",
            is_writable_path=lambda _path: False,
        )
        self.assertTrue(result["risky"])
        self.assertEqual(result["reason"], "user_writable_location")

    def test_check_scheduled_tasks_does_not_flag_safe_system_path(self):
        findings = audit.check_scheduled_tasks(
            [{"name": r"\Microsoft\Windows\SafeTask", "command": r"C:\Windows\System32\notepad.exe"}]
        )
        self.assertEqual(findings, [])

    def test_endpoint_scan_attaches_privesc_metadata(self):
        from greynoc_homeguard import virus_scanner

        mocked = audit.WindowsPrivescAuditResult(
            findings=[],
            metadata={
                "privesc_audit_enabled": True,
                "privesc_checks_run": ["mock_check"],
                "privesc_checks_skipped": [],
                "privesc_audit_platform": "Windows",
                "privesc_audit_partial_results": False,
            },
        )
        with mock.patch("greynoc_homeguard.virus_scanner.scan_persistence", return_value=([], {"persistence_entries_reviewed": 0})):
            with mock.patch("greynoc_homeguard.virus_scanner.run_windows_privesc_audit", return_value=mocked):
                result = virus_scanner.run_endpoint_malware_scan(
                    include_file_scan=False,
                    include_memory=False,
                    process_rows=[],
                )
        self.assertTrue(result.metadata["privesc_audit_enabled"])
        self.assertEqual(result.metadata["privesc_checks_run"], ["mock_check"])
        self.assertIn("windows_privesc_audit", result.metadata["scope"])


if __name__ == "__main__":
    unittest.main()

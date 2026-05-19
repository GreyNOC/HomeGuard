from __future__ import annotations

import unittest

from greynoc_homeguard import virus_scanner
from greynoc_homeguard.endpoint_abuse_signatures import POWERSHELL_ABUSE_COMMANDS


class EndpointAbuseSignatureTests(unittest.TestCase):
    def test_powershell_abuse_commands_match_process_command_lines(self) -> None:
        command_lines = [
            "powershell.exe -NoProfile -Command Invoke-TokenManipulation",
            "powershell.exe -NoProfile -Command Invoke-CredentialInjection",
            "powershell.exe -NoProfile -Command Invoke-NinjaCopy",
            "powershell.exe -NoProfile -Command Invoke-Mimikatz",
            "powershell.exe -NoProfile -Command Get-Keystrokes",
            "powershell.exe -NoProfile -Command Get-GPPPassword",
            "powershell.exe -NoProfile -Command Get-GPPAutologon",
            "powershell.exe -NoProfile -Command Get-TimedScreenshot",
            "powershell.exe -NoProfile -Command New-VolumeShadowCopy",
            "powershell.exe -NoProfile -Command Get-VolumeShadowCopy",
            "powershell.exe -NoProfile -Command Mount-VolumeShadowCopy",
            "powershell.exe -NoProfile -Command Remove-VolumeShadowCopy",
            "powershell.exe -NoProfile -Command Get-VaultCredential",
            "powershell.exe -NoProfile -Command Out-Minidump",
            "powershell.exe -NoProfile -Command Get-MicrophoneAudio",
        ]
        patterns = virus_scanner.SUSPICIOUS_CMD_PATTERNS
        for command_line in command_lines:
            with self.subTest(command_line=command_line):
                self.assertTrue(
                    any(pattern.search(command_line) for pattern, _label in patterns),
                    f"No endpoint command-line signature matched {command_line}",
                )

    def test_powershell_abuse_commands_match_downloaded_script_content(self) -> None:
        signatures = virus_scanner.FILE_CONTENT_SIGNATURES
        for command in POWERSHELL_ABUSE_COMMANDS:
            script = f"function Test {{ {command} }}".encode("utf-8")
            with self.subTest(command=command):
                self.assertTrue(
                    any(pattern.search(script) for pattern, _label, _severity, _confidence in signatures),
                    f"No endpoint file-content signature matched {command}",
                )

    def test_memory_signature_pack_includes_credential_access_terms(self) -> None:
        for signature in [b"invoke-mimikatz", b"get-keystrokes", b"get-vaultcredential", b"out-minidump"]:
            with self.subTest(signature=signature):
                self.assertIn(signature, virus_scanner.MEMORY_SIGNATURES)


if __name__ == "__main__":
    unittest.main()

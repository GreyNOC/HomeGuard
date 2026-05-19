import os
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from greynoc_homeguard import endpoint_abuse_signatures as signatures  # noqa: E402
from greynoc_homeguard.virus_scanner import (  # noqa: E402
    FILE_CONTENT_SIGNATURES,
    MEMORY_SIGNATURES,
    SUSPICIOUS_CMD_PATTERNS,
)


class EndpointAbuseSignatureTests(unittest.TestCase):
    def test_every_powersploit_name_matches_process_command_line_signature(self):
        for name in signatures.POWERSPLOIT_FUNCTION_NAMES:
            sample = f'powershell.exe -NoProfile -File "audit.ps1" {name}'
            self.assertTrue(
                any(pattern.search(sample) for pattern, _label in SUSPICIOUS_CMD_PATTERNS),
                f"missing process signature for {name}",
            )

    def test_every_powersploit_name_matches_downloaded_content_signature(self):
        for name in signatures.POWERSPLOIT_FUNCTION_NAMES:
            sample = f"function {name} {{ Write-Output 'defensive fixture' }}".encode("utf-8")
            self.assertTrue(
                any(pattern.search(sample) for pattern, _label, _severity, _confidence in FILE_CONTENT_SIGNATURES),
                f"missing content signature for {name}",
            )

    def test_memory_signatures_include_high_risk_terms(self):
        markers = b"\n".join(MEMORY_SIGNATURES.keys()).lower()
        labels = "\n".join(MEMORY_SIGNATURES.values()).lower()
        for term in [b"invoke-mimikatz", b"get-keystrokes", b"out-minidump", b"get-microphoneaudio"]:
            self.assertIn(term, markers)
        for word in ["credential", "surveillance", "process"]:
            self.assertIn(word, labels)

    def test_signature_installer_is_idempotent(self):
        before = (
            len(SUSPICIOUS_CMD_PATTERNS),
            len(FILE_CONTENT_SIGNATURES),
            len(MEMORY_SIGNATURES),
        )
        installed = signatures.install_into_virus_scanner()
        after = (
            len(SUSPICIOUS_CMD_PATTERNS),
            len(FILE_CONTENT_SIGNATURES),
            len(MEMORY_SIGNATURES),
        )
        self.assertFalse(installed)
        self.assertEqual(before, after)

    def test_required_categories_are_represented(self):
        seen = {signature.category for signature in signatures.ENDPOINT_ABUSE_SIGNATURES}
        self.assertTrue(signatures.POWERSPLOIT_RESISTANCE_CATEGORIES <= seen)

    def test_patterns_are_static_regexes(self):
        for signature in signatures.ENDPOINT_ABUSE_SIGNATURES:
            self.assertIsInstance(re.compile(signature.pattern), re.Pattern)
            self.assertTrue(signature.pattern)
            self.assertTrue(signature.recommended_actions)


if __name__ == "__main__":
    unittest.main()

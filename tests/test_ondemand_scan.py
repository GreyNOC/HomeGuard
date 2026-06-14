from __future__ import annotations

import hashlib
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_scantest_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard import virus_scanner  # noqa: E402
from greynoc_homeguard.quarantine import QuarantineVault  # noqa: E402
from greynoc_homeguard.remediation import (  # noqa: E402
    quarantine_findings,
    scan_and_remediate,
    should_auto_quarantine,
)

# A Defender-safe content marker (the EICAR string would be deleted off disk by
# real-time AV on developer machines, making tests flaky). The scanner treats
# this internal marker as a critical signature.
MARKER = b"HOMEGUARD-INTERNAL-SCANNER-TEST-SIGNATURE embedded in a script"


class EntropyHashTest(unittest.TestCase):
    def test_shannon_entropy_bounds(self) -> None:
        self.assertEqual(virus_scanner.shannon_entropy(b""), 0.0)
        self.assertEqual(virus_scanner.shannon_entropy(b"A" * 1000), 0.0)
        self.assertGreater(virus_scanner.shannon_entropy(os.urandom(4096)), 7.5)

    def test_sha256_file_matches_hashlib(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "f.bin"
            data = b"some content to hash"
            path.write_bytes(data)
            self.assertEqual(virus_scanner.sha256_file(path), hashlib.sha256(data).hexdigest())


class ScanFileTest(unittest.TestCase):
    def setUp(self) -> None:
        self._work = tempfile.TemporaryDirectory(prefix="hg_sf_")
        self.work = Path(self._work.name)

    def tearDown(self) -> None:
        self._work.cleanup()

    def test_hash_detection(self) -> None:
        data = b"benign-bytes-registered-as-known-bad"
        digest = hashlib.sha256(data).hexdigest()
        target = self.work / "sample.bin"
        target.write_bytes(data)
        findings = virus_scanner.scan_file(
            target,
            malware_hashes={digest: {"name": "TEST-IOC", "severity": "critical", "why": "test"}},
        )
        rules = {f.rule_id for f in findings}
        self.assertIn("endpoint_known_malware_hash", rules)
        hit = next(f for f in findings if f.rule_id == "endpoint_known_malware_hash")
        self.assertEqual(hit.severity, "critical")
        self.assertEqual(hit.evidence.get("path"), str(target))
        self.assertEqual(hit.evidence.get("sha256"), digest)

    def test_content_signature_detection(self) -> None:
        target = self.work / "loader.ps1"
        target.write_bytes(MARKER)
        findings = virus_scanner.scan_file(target, malware_hashes={})
        self.assertIn("endpoint_internal_file_signature", {f.rule_id for f in findings})

    def test_double_extension_detection(self) -> None:
        target = self.work / "invoice.pdf.exe"
        target.write_bytes(b"harmless")
        findings = virus_scanner.scan_file(target, malware_hashes={})
        self.assertIn("endpoint_deceptive_double_extension", {f.rule_id for f in findings})

    def test_high_entropy_executable_heuristic(self) -> None:
        packed = self.work / "packed.exe"
        packed.write_bytes(b"MZ" + os.urandom(300 * 1024))
        findings = virus_scanner.scan_file(packed, malware_hashes={})
        self.assertIn("endpoint_high_entropy_executable", {f.rule_id for f in findings})

        # A low-entropy executable is not flagged by the heuristic.
        plain = self.work / "plain.exe"
        plain.write_bytes(b"MZ" + b"A" * 4096)
        plain_rules = {f.rule_id for f in virus_scanner.scan_file(plain, malware_hashes={})}
        self.assertNotIn("endpoint_high_entropy_executable", plain_rules)

    def test_skips_homeguard_own_files(self) -> None:
        import greynoc_homeguard.models as models_mod

        findings = virus_scanner.scan_file(Path(models_mod.__file__))
        self.assertEqual(findings, [])

    def test_clean_file_has_no_findings(self) -> None:
        clean = self.work / "notes.txt"
        clean.write_bytes(b"just an ordinary text file with nothing bad in it")
        self.assertEqual(virus_scanner.scan_file(clean, malware_hashes={}), [])


class ScanPathTest(unittest.TestCase):
    def setUp(self) -> None:
        self._work = tempfile.TemporaryDirectory(prefix="hg_sp_")
        self.work = Path(self._work.name)

    def tearDown(self) -> None:
        self._work.cleanup()

    def test_scan_folder_aggregates(self) -> None:
        (self.work / "a.ps1").write_bytes(MARKER)
        (self.work / "b.txt").write_bytes(b"clean")
        (self.work / "sub").mkdir()
        (self.work / "sub" / "c.pdf.exe").write_bytes(b"x")
        findings, metadata = virus_scanner.scan_path(self.work, malware_hashes={})
        self.assertTrue(metadata["target_is_dir"])
        self.assertEqual(metadata["files_scanned"], 3)
        rules = {f.rule_id for f in findings}
        self.assertIn("endpoint_internal_file_signature", rules)
        self.assertIn("endpoint_deceptive_double_extension", rules)

    def test_scan_missing_path(self) -> None:
        findings, metadata = virus_scanner.scan_path(self.work / "ghost")
        self.assertEqual(findings, [])
        self.assertFalse(metadata["target_exists"])


class HashDefinitionTest(unittest.TestCase):
    def test_default_definitions_include_eicar_hash(self) -> None:
        from greynoc_homeguard.definitions import _default_definitions, active_malware_hashes

        hashes = active_malware_hashes(_default_definitions())
        self.assertIn("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", hashes)

    def test_active_malware_hashes_rejects_malformed(self) -> None:
        from greynoc_homeguard.definitions import active_malware_hashes

        defs = {
            "malware_hashes": [
                {"sha256": "deadbeef", "name": "too short"},  # not 64 hex
                {"sha256": "Z" * 64, "name": "not hex"},
                {"sha256": "a" * 64, "name": "good", "severity": "high"},
            ]
        }
        result = active_malware_hashes(defs)
        self.assertEqual(list(result.keys()), ["a" * 64])

    def test_custom_rules_merge_adds_hashes(self) -> None:
        from greynoc_homeguard.custom_rules import apply_to_definitions, load_custom_rules
        from greynoc_homeguard.definitions import active_malware_hashes
        import json

        with tempfile.TemporaryDirectory() as tmp:
            rules = Path(tmp) / "custom_rules.json"
            digest = "b" * 64
            rules.write_text(json.dumps({"malware_hashes": [{"sha256": digest, "name": "IOC", "severity": "critical"}]}))
            custom = load_custom_rules(rules)
            self.assertEqual(len(custom["malware_hashes"]), 1)
            defs = {"malware_hashes": []}
            apply_to_definitions(defs, custom)
            self.assertIn(digest, active_malware_hashes(defs))


class RemediationTest(unittest.TestCase):
    def setUp(self) -> None:
        self._work = tempfile.TemporaryDirectory(prefix="hg_rem_")
        self.work = Path(self._work.name)
        self.vault = QuarantineVault(root=self.work / "vault").load()

    def tearDown(self) -> None:
        self._work.cleanup()

    def test_should_auto_quarantine_bar(self) -> None:
        self.assertTrue(should_auto_quarantine({"rule_id": "endpoint_known_malware_hash", "severity": "high", "confidence": 0.5}))
        self.assertTrue(should_auto_quarantine({"rule_id": "x", "severity": "critical", "confidence": 0.95}))
        self.assertFalse(should_auto_quarantine({"rule_id": "endpoint_deceptive_double_extension", "severity": "high", "confidence": 0.7}))
        self.assertFalse(should_auto_quarantine({"rule_id": "endpoint_high_entropy_executable", "severity": "low", "confidence": 0.35}))

    def test_auto_quarantine_critical_only(self) -> None:
        threat = self.work / "loader.ps1"
        threat.write_bytes(MARKER)
        weak = self.work / "invoice.pdf.exe"  # double-extension only -> below bar
        weak.write_bytes(b"x")
        findings, _ = virus_scanner.scan_path(self.work, malware_hashes={})
        actions = quarantine_findings(findings, vault=self.vault)
        by_action = {a["action"] for a in actions}
        self.assertIn("quarantined", by_action)
        self.assertIn("skipped", by_action)
        # The critical marker file is gone; the weak-signal file remains.
        self.assertFalse(threat.exists())
        self.assertTrue(weak.exists())

    def test_force_quarantines_everything(self) -> None:
        weak = self.work / "invoice.pdf.exe"
        weak.write_bytes(b"x")
        findings, _ = virus_scanner.scan_path(self.work, malware_hashes={})
        actions = quarantine_findings(findings, vault=self.vault, force=True)
        self.assertTrue(any(a["action"] == "quarantined" for a in actions))
        self.assertFalse(weak.exists())

    def test_scan_and_remediate_round_trip(self) -> None:
        threat = self.work / "dropper.ps1"
        threat.write_bytes(MARKER)
        result = scan_and_remediate(threat, quarantine=True, vault=self.vault)
        self.assertEqual(sum(1 for a in result["actions"] if a["action"] == "quarantined"), 1)
        self.assertFalse(threat.exists())
        # Restore through the same vault.
        entry = self.vault.entries()[0]
        self.vault.restore(entry.entry_id)
        self.assertTrue(threat.exists())
        self.assertEqual(threat.read_bytes(), MARKER)


if __name__ == "__main__":
    unittest.main()

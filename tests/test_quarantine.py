from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_qtest_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard.quarantine import (  # noqa: E402
    STATUS_DELETED,
    STATUS_QUARANTINED,
    STATUS_RESTORED,
    QuarantineError,
    QuarantineVault,
)


class QuarantineVaultTest(unittest.TestCase):
    def setUp(self) -> None:
        self._work = tempfile.TemporaryDirectory(prefix="hg_q_")
        self.work = Path(self._work.name)
        self.vault = QuarantineVault(root=self.work / "vault").load()

    def tearDown(self) -> None:
        self._work.cleanup()

    def _make_file(self, name: str = "threat.bin", data: bytes = b"malicious-payload-bytes") -> Path:
        path = self.work / name
        path.write_bytes(data)
        return path

    def test_round_trip_quarantine_and_restore(self) -> None:
        data = b"the original malicious bytes \x00\x01\x02"
        target = self._make_file(data=data)
        entry = self.vault.quarantine_file(
            target,
            detection_rule="endpoint_known_malware_hash",
            detection_title="Known-bad file",
            severity="critical",
            confidence=0.99,
        )
        # Original is gone; a recoverable copy is in the vault.
        self.assertFalse(target.exists())
        self.assertEqual(entry.status, STATUS_QUARANTINED)
        self.assertEqual(len(self.vault.entries()), 1)

        # The on-disk blob must NOT be a runnable copy of the malware.
        blob = self.vault._blobs_path / entry.blob_name
        self.assertTrue(blob.exists())
        self.assertNotEqual(blob.read_bytes(), data)

        # Restore rebuilds the exact original bytes.
        restored = self.vault.restore(entry.entry_id)
        self.assertEqual(Path(restored), target)
        self.assertTrue(target.exists())
        self.assertEqual(target.read_bytes(), data)
        self.assertEqual(self.vault.get(entry.entry_id).status, STATUS_RESTORED)
        self.assertEqual(len(self.vault.entries()), 0)

    def test_index_persists_across_instances(self) -> None:
        target = self._make_file()
        entry = self.vault.quarantine_file(target)
        # A fresh vault pointed at the same root sees the entry.
        reopened = QuarantineVault(root=self.work / "vault").load()
        self.assertEqual(len(reopened.entries()), 1)
        self.assertEqual(reopened.entries()[0].entry_id, entry.entry_id)

    def test_restore_to_custom_dest_and_overwrite(self) -> None:
        data = b"payload-v1"
        target = self._make_file(data=data)
        entry = self.vault.quarantine_file(target)
        dest = self.work / "recovered" / "out.bin"
        restored = self.vault.restore(entry.entry_id, dest=dest)
        self.assertEqual(Path(restored), dest)
        self.assertEqual(dest.read_bytes(), data)

    def test_restore_refuses_existing_target_without_overwrite(self) -> None:
        target = self._make_file(data=b"x")
        entry = self.vault.quarantine_file(target)
        # Re-create a file where the original was.
        target.write_bytes(b"something-else")
        with self.assertRaises(QuarantineError):
            self.vault.restore(entry.entry_id)
        # With overwrite it succeeds.
        restored = self.vault.restore(entry.entry_id, overwrite=True)
        self.assertEqual(Path(restored), target)
        self.assertEqual(target.read_bytes(), b"x")

    def test_restore_detects_corrupt_blob(self) -> None:
        target = self._make_file(data=b"abc123")
        entry = self.vault.quarantine_file(target)
        blob = self.vault._blobs_path / entry.blob_name
        blob.write_bytes(b"corrupted")
        with self.assertRaises(QuarantineError):
            self.vault.restore(entry.entry_id)

    def test_delete_is_permanent(self) -> None:
        target = self._make_file()
        entry = self.vault.quarantine_file(target)
        blob = self.vault._blobs_path / entry.blob_name
        self.assertTrue(self.vault.delete(entry.entry_id))
        self.assertFalse(blob.exists())
        self.assertEqual(self.vault.get(entry.entry_id).status, STATUS_DELETED)
        # A deleted entry cannot be restored.
        with self.assertRaises(QuarantineError):
            self.vault.restore(entry.entry_id)

    def test_purge_removes_all_active(self) -> None:
        for index in range(3):
            self.vault.quarantine_file(self._make_file(name=f"f{index}.bin"))
        self.assertEqual(self.vault.stats()["active"], 3)
        purged = self.vault.purge()
        self.assertEqual(purged, 3)
        self.assertEqual(self.vault.stats()["active"], 0)

    def test_refuses_missing_file(self) -> None:
        with self.assertRaises(QuarantineError):
            self.vault.quarantine_file(self.work / "nope.bin")

    def test_refuses_directory(self) -> None:
        directory = self.work / "adir"
        directory.mkdir()
        with self.assertRaises(QuarantineError):
            self.vault.quarantine_file(directory)

    def test_refuses_oversize(self) -> None:
        target = self._make_file(data=b"0123456789")
        with self.assertRaises(QuarantineError):
            self.vault.quarantine_file(target, max_bytes=5)
        # The refusal must not have removed the original.
        self.assertTrue(target.exists())

    def test_refuses_homeguard_own_files(self) -> None:
        import greynoc_homeguard.models as models_mod

        own_file = Path(models_mod.__file__)
        with self.assertRaises(QuarantineError):
            self.vault.quarantine_file(own_file)
        # Critically, HomeGuard must not have deleted its own module.
        self.assertTrue(own_file.exists())

    def test_stats_shape(self) -> None:
        self.vault.quarantine_file(self._make_file(name="a.bin", data=b"aaaa"))
        stats = self.vault.stats()
        self.assertEqual(stats["active"], 1)
        self.assertEqual(stats["active_bytes"], 4)
        self.assertIn("vault_path", stats)


if __name__ == "__main__":
    unittest.main()

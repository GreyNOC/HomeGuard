import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

from greynoc_homeguard import ai_memory  # noqa: E402


class AIMemoryTests(unittest.TestCase):
    def _path(self, tmp: str) -> Path:
        return Path(tmp) / "ai_memory.json"

    def test_add_and_remove_note(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._path(tmp)
            ai_memory.add_note("trust the camera on 192.168.1.42", tags=["lan"], path=path)
            payload = ai_memory.load_memory(path=path)
            self.assertEqual(len(payload["notes"]), 1)
            self.assertEqual(payload["notes"][0]["text"], "trust the camera on 192.168.1.42")
            self.assertTrue(ai_memory.remove_note(0, path=path))
            self.assertEqual(ai_memory.load_memory(path=path)["notes"], [])

    def test_upsert_device_fact_merges(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._path(tmp)
            ai_memory.upsert_device_fact(
                ai_memory.DeviceFact(fingerprint="abc", label="Camera", trust="trusted"),
                path=path,
            )
            ai_memory.upsert_device_fact(
                ai_memory.DeviceFact(fingerprint="abc", owner="Alice"),
                path=path,
            )
            facts = ai_memory.load_memory(path=path)["device_facts"]
            self.assertEqual(len(facts), 1)
            self.assertEqual(facts[0]["label"], "Camera")
            self.assertEqual(facts[0]["owner"], "Alice")

    def test_signal_snapshot_history_bounded(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._path(tmp)
            for index in range(ai_memory.MAX_SIGNAL_HISTORY + 5):
                ai_memory.record_signal_snapshot(
                    ai_memory.SignalSnapshot(
                        created_at=float(index),
                        overall_risk="medium",
                        overall_score=float(index),
                        finding_count=index,
                        device_count=1,
                        top_categories=["remote_access"],
                    ),
                    path=path,
                )
            history = ai_memory.load_memory(path=path)["signal_history"]
            self.assertEqual(len(history), ai_memory.MAX_SIGNAL_HISTORY)
            self.assertEqual(history[-1]["overall_score"], float(ai_memory.MAX_SIGNAL_HISTORY + 4))

    def test_summarize_for_prompt_returns_newest_first(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._path(tmp)
            ai_memory.add_note("first", path=path)
            ai_memory.add_note("second", path=path)
            summary = ai_memory.summarize_for_prompt(path=path)
            self.assertEqual(summary["notes"][0]["text"], "second")
            self.assertEqual(summary["notes"][1]["text"], "first")

    def test_empty_note_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = self._path(tmp)
            with self.assertRaises(ValueError):
                ai_memory.add_note("", path=path)


if __name__ == "__main__":
    unittest.main()

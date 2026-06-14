from __future__ import annotations

import base64
import json
import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_feedtest_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard import signed_feed as sf  # noqa: E402
from greynoc_homeguard.definitions import DefinitionManager, active_malware_hashes  # noqa: E402

# A throwaway RSA-2048 keypair used ONLY by these tests to sign feeds. It is
# deliberately NOT the bundled trust anchor, so we can also assert that a feed
# signed by a non-trusted key is rejected by the default verification path.
TEST_PRIVATE_KEY = {
    "n": (
        "00b7701f8c8c7c7f81f7b7ed6b6c56190c4873f1ea70828c015b14fa64039a2780"
        "0538058e293fcc32e9529461257790017c2ed2127969eb9b6351154265012e4163"
        "ae4664e6f555cf08fead9a0675cfc0f783de8a398c5d53923cf11179c38cfc82aa"
        "98a1cadd027b0be7e502222d8fc78a9ddd7d0a6cd855b518b866b13b39109c2fa4"
        "357289d30ecef8245c4fd55b3bcfaba19902541dc550bf0b5af91a32df66e538b9"
        "d5a4491e56c6eebe5920c447f2f080dc0cacdc8331a2418884b65fec95d4c160a7"
        "5236b54d59142e453833fe2c4a05c4d9fd835eefd0fa3746822b2c4e009662847c"
        "921eb83ed9073bdc4f6b60dfeb71b003dbacea861c45e5aea9d5"
    ),
    "e": 65537,
    "d": (
        "304ed3d024b328b526728690d2affddab13def8888e6a84e371958337c8b5d39a6"
        "a6313855fe9a1d123b101e614a925f01c026cc7cb2fb3c29b491bfb16fd5299d41"
        "a9022b9c92637a7fef61efaf98edbd8139daf6fad31d0e17047950b2c1ef41ce01"
        "7222457fc0bdcaed1159c4dbe775c6cb2c81d1564b83eca5ab4da3460c79b42f0c"
        "1a6ed7bb64c56d2d2e1a729264dd769b1ccb681b8bee7d410db48903b35886ff3b"
        "165f8c5f9710649694eecdbad8b06df6bcfde7fca875e90b4a73c946eac8439f60"
        "2d1b4e6988390804fdce8203e1e1291e4d2832ac5675b374cf3acfcdf5660a1f64"
        "3c7c58e3000169d393c4522955f8e63f0c954afcf23c27eaa5"
    ),
}
TEST_PUBLIC_KEY = {"n": TEST_PRIVATE_KEY["n"], "e": TEST_PRIVATE_KEY["e"]}

SAMPLE_PAYLOAD = {
    "feed_version": "2026.06.13.test",
    "malware_hashes": [
        {"sha256": "a" * 64, "name": "FeedThreatOne", "severity": "critical"},
        {"sha256": "b" * 64, "name": "FeedThreatTwo", "severity": "high"},
    ],
}


def _temp_manager() -> DefinitionManager:
    fd, name = tempfile.mkstemp(suffix=".json")
    os.close(fd)
    os.unlink(name)
    return DefinitionManager(path=Path(name))


class SignedFeedVerifyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.doc = sf.build_signed_document(SAMPLE_PAYLOAD, private_key=TEST_PRIVATE_KEY, key_id="")

    def test_valid_signature_verifies(self) -> None:
        ok, data, reason = sf.verify_signed_document(self.doc, public_key=TEST_PUBLIC_KEY)
        self.assertTrue(ok, reason)
        self.assertEqual(json.loads(data)["feed_version"], "2026.06.13.test")

    def test_untrusted_key_rejected_by_default(self) -> None:
        # Signed by the test key, verified against the bundled trust anchor.
        ok, _data, reason = sf.verify_signed_document(self.doc)
        self.assertFalse(ok)
        self.assertIn("did not verify", reason)

    def test_tampered_data_rejected(self) -> None:
        tampered = dict(self.doc)
        payload = json.loads(base64.b64decode(tampered["data"]))
        payload["malware_hashes"][0]["sha256"] = "c" * 64
        tampered["data"] = base64.b64encode(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        ).decode()
        ok, _data, _reason = sf.verify_signed_document(tampered, public_key=TEST_PUBLIC_KEY)
        self.assertFalse(ok)

    def test_tampered_signature_rejected(self) -> None:
        tampered = dict(self.doc)
        sig = bytearray(base64.b64decode(tampered["signature"]))
        sig[0] ^= 0xFF
        tampered["signature"] = base64.b64encode(bytes(sig)).decode()
        ok, _data, _reason = sf.verify_signed_document(tampered, public_key=TEST_PUBLIC_KEY)
        self.assertFalse(ok)

    def test_missing_fields_rejected(self) -> None:
        self.assertFalse(sf.verify_signed_document({}, public_key=TEST_PUBLIC_KEY)[0])
        self.assertFalse(sf.verify_signed_document({"data": "x"}, public_key=TEST_PUBLIC_KEY)[0])
        self.assertFalse(sf.verify_signed_document("notadict", public_key=TEST_PUBLIC_KEY)[0])

    def test_non_base64_rejected(self) -> None:
        ok, _data, _reason = sf.verify_signed_document(
            {"data": "!!!notbase64!!!", "signature": "!!!"}, public_key=TEST_PUBLIC_KEY
        )
        self.assertFalse(ok)


class SignedFeedApplyTest(unittest.TestCase):
    def test_apply_merges_into_definitions(self) -> None:
        manager = _temp_manager()
        doc = sf.build_signed_document(SAMPLE_PAYLOAD, private_key=TEST_PRIVATE_KEY)
        result = sf.apply_signed_feed_document(doc, public_key=TEST_PUBLIC_KEY, manager=manager)
        self.assertTrue(result["ok"])
        self.assertEqual(result["added"], 2)
        hashes = active_malware_hashes(manager.load())
        self.assertIn("a" * 64, hashes)
        self.assertIn("b" * 64, hashes)

    def test_apply_fails_closed_on_bad_signature(self) -> None:
        manager = _temp_manager()
        before = set(active_malware_hashes(manager.load()).keys())
        doc = sf.build_signed_document(SAMPLE_PAYLOAD, private_key=TEST_PRIVATE_KEY)
        # Verify against the (wrong) bundled key -> must reject and NOT mutate.
        result = sf.apply_signed_feed_document(doc, manager=manager)
        self.assertFalse(result["ok"])
        after = set(active_malware_hashes(manager.load()).keys())
        self.assertEqual(before, after)

    def test_load_signed_feed_file(self) -> None:
        manager = _temp_manager()
        doc = sf.build_signed_document(SAMPLE_PAYLOAD, private_key=TEST_PRIVATE_KEY)
        with tempfile.TemporaryDirectory() as tmp:
            feed_path = Path(tmp) / "feed.json"
            feed_path.write_text(json.dumps(doc), encoding="utf-8")
            result = sf.load_signed_feed_file(feed_path, public_key=TEST_PUBLIC_KEY, manager=manager)
        self.assertTrue(result["ok"])
        self.assertIn("a" * 64, active_malware_hashes(manager.load()))

    def test_load_missing_file(self) -> None:
        result = sf.load_signed_feed_file(Path(_TMP_ROOT) / "nope.json", manager=_temp_manager())
        self.assertFalse(result["ok"])


class RsaPrimitiveTest(unittest.TestCase):
    def test_roundtrip_sign_verify(self) -> None:
        message = b"hello signed world"
        # Build EM the same way the signer does, by reusing build_signed_document
        # indirectly through a tiny payload is overkill; verify the primitive
        # directly via a known-good doc.
        doc = sf.build_signed_document({"feed_version": "x", "malware_hashes": []}, private_key=TEST_PRIVATE_KEY)
        data = base64.b64decode(doc["data"])
        sig = base64.b64decode(doc["signature"])
        self.assertTrue(sf.rsa_pkcs1v15_sha256_verify(data, sig, TEST_PUBLIC_KEY))
        self.assertFalse(sf.rsa_pkcs1v15_sha256_verify(message, sig, TEST_PUBLIC_KEY))

    def test_malformed_key_returns_false(self) -> None:
        self.assertFalse(sf.rsa_pkcs1v15_sha256_verify(b"x", b"y", {"n": "zzz", "e": 65537}))
        self.assertFalse(sf.rsa_pkcs1v15_sha256_verify(b"x", b"", TEST_PUBLIC_KEY))


if __name__ == "__main__":
    unittest.main()

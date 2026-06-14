"""Cryptographically-signed cloud definition feeds for the malware hash set.

A consumer antivirus lives or dies by the trustworthiness of its definition
updates: if an attacker can MITM the feed or compromise a mirror, they can
delete the signature that would catch their malware — or push a bogus one that
quarantines a competitor's file. So remote hash feeds are **signed**, and
HomeGuard verifies the signature against a public key bundled in the binary
before a single hash is trusted. Verification fails *closed*: an unsigned,
tampered, or wrong-key feed is rejected and the local definitions are left
untouched.

The verification is RSA PKCS#1 v1.5 with SHA-256, implemented in pure stdlib
(``pow`` is native big-integer modular exponentiation, ``hashlib`` for the
digest) so the runtime takes **no new dependency**. Feeds are signed offline
with the matching private key using standard tooling, e.g.::

    # data.json is the exact bytes embedded (base64) as the "data" field
    openssl dgst -sha256 -sign greynoc-hashfeed-private.pem -out data.sig data.json

A signed feed document is JSON::

    {
      "key_id": "greynoc-hashfeed-2026",
      "data": "<base64 of the canonical feed-data JSON bytes>",
      "signature": "<base64 of the PKCS#1 v1.5 signature over those bytes>"
    }

The signature covers the *exact* decoded ``data`` bytes, so there is no
canonicalization ambiguity between signer and verifier. The decoded data is
itself JSON: ``{"feed_version": "...", "malware_hashes": [ {sha256,name,...} ]}``.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from .logging_setup import get_logger

LOG = get_logger("signed_feed")

# DER prefix for an RSASSA-PKCS1-v1_5 DigestInfo wrapping a SHA-256 hash.
_SHA256_DIGEST_INFO_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")

# Trusted public key bundled with HomeGuard. The matching private key is held
# offline by GreyNOC and never ships. Replace ``n`` (and ``key_id``) with your
# production key before publishing signed feeds; the private key generated for
# this development anchor is intentionally not stored anywhere in the repo.
TRUSTED_HASH_FEED_PUBLIC_KEY: dict[str, Any] = {
    "key_id": "greynoc-hashfeed-2026",
    "e": 65537,
    "n": (
        "0099db743275d68ddfa5a9e39ad5bac5402cab99b0a69e35e161e31bdeae42692e"
        "70e614b71d436727c5e4697818b84615d0eb0c65b59c0b607c8991cfe76a87b265"
        "11b6f16f748d745780aff4847e57d103a9b17ef3073fd51e795b76abd3aaa0096d"
        "01f7f6975e74407ae9d33a53abc800415bb0d59432c482acca9be024472c21a66c"
        "6f7d7f39c96bec2a5ef30bbd1440e892c7310e69af7755fd635097e046be20d8fa"
        "b52a3933c3349e87f49160fbe4a8a49459bf83c05645bfc37f8757471428405b49"
        "3311939e57f56163219ecf6a82ca60715e9ee72b355a1a178adb61fa1183ff9b63"
        "d1243b82fd30087974ced72fda8912c56c94172862467e715bb1"
    ),
}

MAX_FEED_BYTES = 8 * 1024 * 1024


class SignedFeedError(RuntimeError):
    """Raised when a feed cannot be verified or applied."""


def rsa_pkcs1v15_sha256_verify(message: bytes, signature: bytes, public_key: dict[str, Any]) -> bool:
    """Verify an RSASSA-PKCS1-v1_5 / SHA-256 signature with stdlib only.

    Returns True only when ``signature`` is a valid signature over ``message``
    under ``public_key`` (``{"n": <hex>, "e": <int>}``). Any malformed input
    returns False rather than raising, so a corrupt feed is simply rejected.
    """
    try:
        n = int(str(public_key["n"]), 16)
        e = int(public_key["e"])
    except (KeyError, TypeError, ValueError):
        return False
    if n <= 0 or e <= 0 or not signature:
        return False
    k = (n.bit_length() + 7) // 8
    if len(signature) != k:
        return False
    s = int.from_bytes(signature, "big")
    if s >= n:
        return False
    m = pow(s, e, n)
    try:
        em = m.to_bytes(k, "big")
    except OverflowError:
        return False
    digest = hashlib.sha256(message).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    ps_len = k - 3 - len(t)
    if ps_len < 8:  # PKCS#1 requires at least 8 bytes of 0xFF padding.
        return False
    expected = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    return hmac.compare_digest(em, expected)


def verify_signed_document(
    document: Any,
    *,
    public_key: dict[str, Any] | None = None,
) -> tuple[bool, bytes, str]:
    """Verify a signed feed document.

    Returns ``(ok, data_bytes, reason)``. ``data_bytes`` is the verified,
    base64-decoded feed payload (empty when verification fails). Verification
    fails closed: a missing field, base64 error, key-id mismatch, or bad
    signature all return ``ok=False``.
    """
    key = public_key or TRUSTED_HASH_FEED_PUBLIC_KEY
    if not isinstance(document, dict):
        return False, b"", "Feed document must be a JSON object."
    key_id = str(document.get("key_id") or "")
    expected_key_id = str(key.get("key_id") or "")
    if expected_key_id and key_id and key_id != expected_key_id:
        return False, b"", f"Feed key_id '{key_id}' does not match trusted key '{expected_key_id}'."
    raw_data = document.get("data")
    raw_sig = document.get("signature")
    if not isinstance(raw_data, str) or not isinstance(raw_sig, str):
        return False, b"", "Feed document is missing 'data' or 'signature'."
    try:
        data_bytes = base64.b64decode(raw_data, validate=True)
        signature = base64.b64decode(raw_sig, validate=True)
    except (ValueError, base64.binascii.Error):
        return False, b"", "Feed 'data' or 'signature' is not valid base64."
    if len(data_bytes) > MAX_FEED_BYTES:
        return False, b"", "Feed data exceeds the maximum allowed size."
    if not rsa_pkcs1v15_sha256_verify(data_bytes, signature, key):
        return False, b"", "Feed signature did not verify against the trusted key."
    return True, data_bytes, "ok"


def parse_feed_payload(data_bytes: bytes) -> dict[str, Any]:
    """Parse and lightly validate the verified feed payload bytes."""
    try:
        payload = json.loads(data_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SignedFeedError(f"Verified feed payload is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise SignedFeedError("Feed payload must be a JSON object.")
    rows = payload.get("malware_hashes")
    if not isinstance(rows, list):
        raise SignedFeedError("Feed payload must contain a 'malware_hashes' list.")
    return payload


def apply_signed_feed_document(
    document: Any,
    *,
    public_key: dict[str, Any] | None = None,
    manager: Any = None,
) -> dict[str, Any]:
    """Verify a signed document and, only if valid, merge its hashes.

    Returns a status dict. Never mutates the local definitions unless the
    signature verifies.
    """
    ok, data_bytes, reason = verify_signed_document(document, public_key=public_key)
    if not ok:
        return {"ok": False, "verified": False, "message": reason}
    payload = parse_feed_payload(data_bytes)
    from .definitions import DefinitionManager

    manager = manager or DefinitionManager()
    result = manager.merge_malware_hashes(
        payload.get("malware_hashes") or [],
        feed_version=str(payload.get("feed_version") or ""),
        source="hash_feed",
    )
    LOG.info(
        "Applied signed hash feed %s: +%d new, %d updated, %d total",
        result.get("feed_version"),
        result.get("added", 0),
        result.get("updated", 0),
        result.get("total", 0),
    )
    return {"ok": True, "verified": True, "message": "Signed hash feed applied.", **result}


def load_signed_feed_file(
    path: str | Path,
    *,
    public_key: dict[str, Any] | None = None,
    manager: Any = None,
) -> dict[str, Any]:
    """Apply a signed hash feed from a local file (offline / air-gapped)."""
    target = Path(path)
    if not target.exists():
        return {"ok": False, "verified": False, "message": f"File not found: {target}"}
    try:
        document = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "verified": False, "message": f"Could not read feed JSON: {exc}"}
    return apply_signed_feed_document(document, public_key=public_key, manager=manager)


def update_hashes_from_url(
    url: str,
    *,
    public_key: dict[str, Any] | None = None,
    manager: Any = None,
    timeout: float = 25.0,
) -> dict[str, Any]:
    """Download a signed hash feed and apply it after signature verification."""
    from .definitions import _http_json

    try:
        document = _http_json(url, timeout=timeout)
    except Exception as exc:
        return {"ok": False, "verified": False, "message": f"Could not download feed: {exc}"}
    return apply_signed_feed_document(document, public_key=public_key, manager=manager)


def build_signed_document(
    payload: dict[str, Any],
    *,
    private_key: dict[str, Any],
    key_id: str = "",
) -> dict[str, Any]:
    """Build a signed feed document from a payload and an RSA private key.

    Provided for tooling/tests (signing is normally done offline with
    openssl). ``private_key`` is ``{"n": <hex>, "d": <hex>}``. The signature
    covers the exact serialized payload bytes that get embedded.
    """
    data_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    n = int(str(private_key["n"]), 16)
    d = int(str(private_key["d"]), 16)
    k = (n.bit_length() + 7) // 8
    digest = hashlib.sha256(data_bytes).digest()
    t = _SHA256_DIGEST_INFO_PREFIX + digest
    ps_len = k - 3 - len(t)
    if ps_len < 8:
        raise SignedFeedError("RSA key too small to sign a SHA-256 PKCS#1 v1.5 signature.")
    em = b"\x00\x01" + b"\xff" * ps_len + b"\x00" + t
    signature = pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
    return {
        "key_id": key_id,
        "data": base64.b64encode(data_bytes).decode("ascii"),
        "signature": base64.b64encode(signature).decode("ascii"),
    }

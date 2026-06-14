"""Local malware quarantine vault.

This is the piece that turns HomeGuard's endpoint scanner from "detect and
report" into "detect and *act*". When a file is flagged with enough
confidence, the vault:

  1. Hashes the original so a restore can be verified bit-for-bit.
  2. Copies the bytes into the vault **neutralized** — every byte is XOR'd
     with a per-entry random key so the stored blob is not a runnable copy
     of the malware and will not re-trigger this scanner (or another AV)
     watching the app-data folder.
  3. Removes the live original only after the neutralized blob is safely on
     disk, so a crash mid-quarantine never leaves the machine with neither
     the file nor a recoverable copy.

Every action is reversible: ``restore`` rebuilds the exact original bytes
(verified against the recorded SHA-256) and puts them back; ``delete``
permanently destroys the vault copy.

The vault is deliberately conservative. It refuses to quarantine HomeGuard's
own files, operating-system critical paths, anything that is not a regular
file, and anything above a hard size cap. False positives are recoverable;
a deleted system file may not be.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from .logging_setup import get_logger
from .paths import atomic_write_bytes, atomic_write_text, quarantine_dir

LOG = get_logger("quarantine")

INDEX_NAME = "index.json"
BLOBS_DIR = "blobs"
VAULT_SCHEMA_VERSION = "1.0"

# Hard ceiling on a single quarantined file. Above this the neutralize copy
# would cost too much disk/time; the caller is told to remove the file
# manually instead. 2 GiB comfortably covers droppers, scripts, and bloated
# fake installers without letting a disk image fill the vault.
MAX_QUARANTINE_BYTES = 2 * 1024 * 1024 * 1024

STATUS_QUARANTINED = "quarantined"
STATUS_RESTORED = "restored"
STATUS_DELETED = "deleted"

# Path fragments we never quarantine from. These are OS-critical locations
# where deleting a flagged file would do more harm than the file itself.
# Matched case-insensitively against the resolved, normalized path.
_PROTECTED_FRAGMENTS = (
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
    "\\windows\\winsxs\\",
    "/usr/bin/",
    "/usr/sbin/",
    "/bin/",
    "/sbin/",
    "/lib/",
    "/system/",
)


class QuarantineError(RuntimeError):
    """Raised when a file cannot be quarantined or a vault op fails."""


@dataclass(slots=True)
class QuarantineEntry:
    entry_id: str
    original_path: str
    original_name: str
    quarantined_at: str
    size_bytes: int
    sha256: str
    blob_name: str
    xor_key_hex: str
    status: str = STATUS_QUARANTINED
    detection_rule: str = ""
    detection_title: str = ""
    severity: str = ""
    confidence: float = 0.0
    reason: str = ""
    restored_to: str = ""
    restored_at: str = ""
    deleted_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def public_dict(self) -> dict[str, Any]:
        """Listing-friendly view that omits the recovery key."""
        data = self.as_dict()
        data.pop("xor_key_hex", None)
        data.pop("blob_name", None)
        return data

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "QuarantineEntry":
        return cls(
            entry_id=str(payload.get("entry_id") or ""),
            original_path=str(payload.get("original_path") or ""),
            original_name=str(payload.get("original_name") or ""),
            quarantined_at=str(payload.get("quarantined_at") or ""),
            size_bytes=int(payload.get("size_bytes") or 0),
            sha256=str(payload.get("sha256") or ""),
            blob_name=str(payload.get("blob_name") or ""),
            xor_key_hex=str(payload.get("xor_key_hex") or ""),
            status=str(payload.get("status") or STATUS_QUARANTINED),
            detection_rule=str(payload.get("detection_rule") or ""),
            detection_title=str(payload.get("detection_title") or ""),
            severity=str(payload.get("severity") or ""),
            confidence=float(payload.get("confidence") or 0.0),
            reason=str(payload.get("reason") or ""),
            restored_to=str(payload.get("restored_to") or ""),
            restored_at=str(payload.get("restored_at") or ""),
            deleted_at=str(payload.get("deleted_at") or ""),
        )


def _utcnow() -> str:
    # Imported lazily-equivalent: models.utcnow keeps timestamp formatting in
    # one place across the codebase.
    from .models import utcnow

    return utcnow()


def _xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    key_len = len(key)
    return bytes(byte ^ key[index % key_len] for index, byte in enumerate(data))


def _homeguard_own_paths() -> list[Path]:
    """Filesystem paths that belong to HomeGuard itself. The vault must never
    quarantine its own modules, the executable, or the vault folder."""
    paths: set[Path] = set()
    try:
        paths.add(Path(__file__).resolve().parent)
    except OSError:
        pass
    import sys

    if getattr(sys, "frozen", False):
        try:
            paths.add(Path(sys.executable).resolve())
        except OSError:
            pass
    try:
        paths.add(quarantine_dir().resolve())
    except OSError:
        pass
    return sorted(paths)


def _within(path: Path, roots: Iterable[Path]) -> bool:
    try:
        resolved = path.resolve()
    except OSError:
        return False
    for root in roots:
        if resolved == root or root in resolved.parents:
            return True
    return False


def _is_protected_system_path(path: Path) -> bool:
    try:
        resolved = str(path.resolve()).replace("/", os.sep)
    except OSError:
        return False
    normalized = resolved.replace(os.sep, "\\").lower()
    # Compare against both separators so the POSIX fragments match too.
    candidates = (normalized, str(path.resolve()).replace("\\", "/").lower())
    return any(fragment in candidate for fragment in _PROTECTED_FRAGMENTS for candidate in candidates)


@dataclass(slots=True)
class QuarantineVault:
    """File-backed quarantine store under ``<appdata>/quarantine``."""

    root: Path | None = None
    _entries: dict[str, QuarantineEntry] = field(default_factory=dict, init=False)
    _loaded: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        if self.root is None:
            self.root = quarantine_dir()

    # -- storage paths -------------------------------------------------------
    @property
    def _index_path(self) -> Path:
        assert self.root is not None
        return self.root / INDEX_NAME

    @property
    def _blobs_path(self) -> Path:
        assert self.root is not None
        return self.root / BLOBS_DIR

    # -- index load / save ---------------------------------------------------
    def load(self) -> "QuarantineVault":
        self._entries = {}
        path = self._index_path
        if path.exists():
            try:
                raw = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                LOG.warning("Quarantine index unreadable, starting fresh: %s", exc)
                raw = {}
            for row in (raw.get("entries") if isinstance(raw, dict) else None) or []:
                if not isinstance(row, dict):
                    continue
                entry = QuarantineEntry.from_dict(row)
                if entry.entry_id:
                    self._entries[entry.entry_id] = entry
        self._loaded = True
        return self

    def _ensure_loaded(self) -> None:
        if not self._loaded:
            self.load()

    def _save(self) -> None:
        payload = {
            "schema_version": VAULT_SCHEMA_VERSION,
            "entries": [entry.as_dict() for entry in self._entries.values()],
        }
        atomic_write_text(self._index_path, json.dumps(payload, indent=2, sort_keys=True))

    # -- queries -------------------------------------------------------------
    def entries(self, *, include_inactive: bool = False) -> list[QuarantineEntry]:
        self._ensure_loaded()
        rows = list(self._entries.values())
        if not include_inactive:
            rows = [row for row in rows if row.status == STATUS_QUARANTINED]
        return sorted(rows, key=lambda row: row.quarantined_at, reverse=True)

    def get(self, entry_id: str) -> QuarantineEntry | None:
        self._ensure_loaded()
        return self._entries.get(entry_id)

    def stats(self) -> dict[str, Any]:
        self._ensure_loaded()
        active = [row for row in self._entries.values() if row.status == STATUS_QUARANTINED]
        return {
            "active": len(active),
            "restored": sum(1 for row in self._entries.values() if row.status == STATUS_RESTORED),
            "deleted": sum(1 for row in self._entries.values() if row.status == STATUS_DELETED),
            "active_bytes": sum(row.size_bytes for row in active),
            "vault_path": str(self.root),
        }

    # -- core actions --------------------------------------------------------
    def quarantine_file(
        self,
        path: str | Path,
        *,
        detection_rule: str = "",
        detection_title: str = "",
        severity: str = "",
        confidence: float = 0.0,
        reason: str = "",
        max_bytes: int = MAX_QUARANTINE_BYTES,
    ) -> QuarantineEntry:
        """Move ``path`` into the vault, neutralized. Raises
        :class:`QuarantineError` on any refusal or failure; the live file is
        only removed once a recoverable copy is verified on disk."""

        self._ensure_loaded()
        source = Path(path)
        try:
            resolved = source.resolve()
        except OSError as exc:
            raise QuarantineError(f"Cannot resolve path: {exc}") from exc

        if not resolved.exists():
            raise QuarantineError(f"File does not exist: {resolved}")
        if not resolved.is_file():
            raise QuarantineError(f"Not a regular file: {resolved}")
        if _within(resolved, _homeguard_own_paths()):
            raise QuarantineError("Refusing to quarantine HomeGuard's own files.")
        if _is_protected_system_path(resolved):
            raise QuarantineError(
                "Refusing to quarantine an operating-system critical path. "
                "Remove it manually if you are certain it is malicious."
            )

        try:
            size = resolved.stat().st_size
        except OSError as exc:
            raise QuarantineError(f"Cannot stat file: {exc}") from exc
        if size > max_bytes:
            raise QuarantineError(
                f"File is larger than the {max_bytes} byte quarantine limit; remove it manually."
            )

        entry_id = uuid4().hex
        key = secrets.token_bytes(32)
        blob_name = f"{entry_id}.qbin"
        blob_path = self._blobs_path / blob_name

        digest = hashlib.sha256()
        try:
            neutralized = bytearray()
            with resolved.open("rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
                    neutralized.extend(_xor_bytes(chunk, key))
        except OSError as exc:
            raise QuarantineError(f"Could not read file for quarantine: {exc}") from exc

        try:
            atomic_write_bytes(blob_path, bytes(neutralized))
        except OSError as exc:
            raise QuarantineError(f"Could not write vault copy: {exc}") from exc

        # Only now is removing the original safe — a recoverable copy exists.
        try:
            resolved.unlink()
        except OSError as exc:
            # Roll back the blob so we never report a quarantine that left the
            # live malware in place.
            try:
                blob_path.unlink()
            except OSError:
                pass
            raise QuarantineError(
                f"Quarantine copy written but the original could not be removed "
                f"(file may be locked or in use): {exc}"
            ) from exc

        entry = QuarantineEntry(
            entry_id=entry_id,
            original_path=str(resolved),
            original_name=resolved.name,
            quarantined_at=_utcnow(),
            size_bytes=int(size),
            sha256=digest.hexdigest(),
            blob_name=blob_name,
            xor_key_hex=key.hex(),
            status=STATUS_QUARANTINED,
            detection_rule=detection_rule,
            detection_title=detection_title,
            severity=severity,
            confidence=float(confidence or 0.0),
            reason=reason,
        )
        self._entries[entry_id] = entry
        self._save()
        LOG.info("Quarantined %s (%d bytes) as %s", resolved.name, size, entry_id)
        return entry

    def restore(
        self,
        entry_id: str,
        *,
        dest: str | Path | None = None,
        overwrite: bool = False,
    ) -> Path:
        """Rebuild the original bytes from the vault and put them back.

        The recovered bytes are verified against the SHA-256 recorded at
        quarantine time before the vault copy is removed, so a corrupted vault
        blob can never silently restore a wrong/half file."""

        self._ensure_loaded()
        entry = self._entries.get(entry_id)
        if entry is None:
            raise QuarantineError(f"No quarantine entry: {entry_id}")
        if entry.status != STATUS_QUARANTINED:
            raise QuarantineError(f"Entry {entry_id} is not active (status={entry.status}).")

        blob_path = self._blobs_path / entry.blob_name
        if not blob_path.exists():
            raise QuarantineError(f"Vault copy is missing for {entry_id}; cannot restore.")

        try:
            blob = blob_path.read_bytes()
        except OSError as exc:
            raise QuarantineError(f"Could not read vault copy: {exc}") from exc

        original = _xor_bytes(blob, bytes.fromhex(entry.xor_key_hex))
        if hashlib.sha256(original).hexdigest() != entry.sha256:
            raise QuarantineError(
                "Restored bytes do not match the recorded hash; vault copy is corrupt."
            )

        target = Path(dest) if dest else Path(entry.original_path)
        if target.exists() and not overwrite:
            raise QuarantineError(
                f"Restore target already exists: {target}. Pass overwrite=True to replace it."
            )
        try:
            atomic_write_bytes(target, original)
        except OSError as exc:
            raise QuarantineError(f"Could not write restored file: {exc}") from exc

        try:
            blob_path.unlink()
        except OSError:
            pass
        entry.status = STATUS_RESTORED
        entry.restored_to = str(target)
        entry.restored_at = _utcnow()
        self._save()
        LOG.info("Restored %s to %s", entry_id, target)
        return target

    def delete(self, entry_id: str) -> bool:
        """Permanently destroy the vault copy of an entry."""
        self._ensure_loaded()
        entry = self._entries.get(entry_id)
        if entry is None:
            return False
        blob_path = self._blobs_path / entry.blob_name
        try:
            if blob_path.exists():
                blob_path.unlink()
        except OSError as exc:
            raise QuarantineError(f"Could not delete vault copy: {exc}") from exc
        entry.status = STATUS_DELETED
        entry.deleted_at = _utcnow()
        # Drop the recovery key — a deleted entry can never be restored, and
        # keeping the key around is pointless.
        entry.xor_key_hex = ""
        self._save()
        LOG.info("Deleted quarantine entry %s", entry_id)
        return True

    def purge(self) -> int:
        """Permanently delete every active quarantined item. Returns count."""
        self._ensure_loaded()
        active = [row.entry_id for row in self._entries.values() if row.status == STATUS_QUARANTINED]
        for entry_id in active:
            self.delete(entry_id)
        return len(active)

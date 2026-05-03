from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .models import Device, utcnow

TRUST_TRUSTED = "trusted"
TRUST_UNKNOWN = "unknown"
TRUST_QUARANTINED = "quarantined"
TRUST_VALUES = {TRUST_TRUSTED, TRUST_UNKNOWN, TRUST_QUARANTINED}

OWNER_VALUES = {"parent", "child", "guest", "unknown"}
DEVICE_TYPES = {"phone", "laptop", "tv", "console", "iot", "router", "camera", "nas", "printer", "unknown"}


class BaselineStore:
    """Known-device store with trust state, family labels, and device-type labels.

    The store doubles as the device trust / quarantine database used by the
    detection engine and the GUI. The legacy ``BaselineStore`` API (``known``,
    ``update``, ``save``) is preserved so existing callers keep working.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data: dict[str, Any] = {"schema_version": "2.0", "devices": {}}

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------
    def load(self) -> "BaselineStore":
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self.data = loaded
                    self.data.setdefault("schema_version", "2.0")
                    self.data.setdefault("devices", {})
            except (OSError, json.JSONDecodeError):
                self.data = {"schema_version": "2.0", "devices": {}}
        # backfill defaults for older entries
        for entry in self.data.get("devices", {}).values():
            if not isinstance(entry, dict):
                continue
            entry.setdefault("trust", TRUST_UNKNOWN)
            entry.setdefault("owner", "unknown")
            entry.setdefault("device_type", "unknown")
            entry.setdefault("notes", "")
        return self

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8"
        )

    # ------------------------------------------------------------------
    # queries
    # ------------------------------------------------------------------
    def known(self, device: Device) -> bool:
        return device.fingerprint() in self.data.get("devices", {})

    def get(self, device: Device) -> dict[str, Any]:
        return dict(self.data.get("devices", {}).get(device.fingerprint(), {}))

    def trust(self, device: Device) -> str:
        return str(self.get(device).get("trust") or TRUST_UNKNOWN)

    def is_quarantined(self, device: Device) -> bool:
        return self.trust(device) == TRUST_QUARANTINED

    def is_trusted(self, device: Device) -> bool:
        return self.trust(device) == TRUST_TRUSTED

    def all_records(self) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        for fp, entry in (self.data.get("devices") or {}).items():
            if not isinstance(entry, dict):
                continue
            row = dict(entry)
            row.setdefault("fingerprint", fp)
            rows.append(row)
        rows.sort(key=lambda item: (item.get("trust", ""), item.get("ip", "")))
        return rows

    # ------------------------------------------------------------------
    # mutations
    # ------------------------------------------------------------------
    def update(self, devices: Iterable[Device]) -> None:
        now = utcnow()
        rows = self.data.setdefault("devices", {})
        for device in devices:
            key = device.fingerprint()
            row = rows.setdefault(
                key,
                {
                    "first_seen": now,
                    "fingerprint": key,
                    "trust": TRUST_UNKNOWN,
                    "owner": "unknown",
                    "device_type": "unknown",
                    "notes": "",
                },
            )
            row.update(
                {
                    "last_seen": now,
                    "ip": device.ip,
                    "mac_address": device.mac_address,
                    "hostname": device.hostname,
                    "vendor": device.vendor,
                    "open_ports": list(device.open_ports),
                }
            )
            row.setdefault("trust", TRUST_UNKNOWN)
            row.setdefault("owner", "unknown")
            row.setdefault("device_type", "unknown")
            row.setdefault("notes", "")

    def set_trust(self, fingerprint: str, trust: str) -> bool:
        trust = trust.lower().strip()
        if trust not in TRUST_VALUES:
            raise ValueError(f"Unknown trust value: {trust}")
        rows = self.data.setdefault("devices", {})
        row = rows.get(fingerprint)
        if not isinstance(row, dict):
            return False
        row["trust"] = trust
        row["trust_updated_at"] = utcnow()
        return True

    def set_label(
        self,
        fingerprint: str,
        *,
        owner: str | None = None,
        device_type: str | None = None,
        notes: str | None = None,
    ) -> bool:
        rows = self.data.setdefault("devices", {})
        row = rows.get(fingerprint)
        if not isinstance(row, dict):
            return False
        if owner is not None:
            owner_clean = owner.lower().strip() or "unknown"
            row["owner"] = owner_clean if owner_clean in OWNER_VALUES else "unknown"
        if device_type is not None:
            type_clean = device_type.lower().strip() or "unknown"
            row["device_type"] = type_clean if type_clean in DEVICE_TYPES else "unknown"
        if notes is not None:
            row["notes"] = str(notes)[:500]
        row["labels_updated_at"] = utcnow()
        return True

    def remove(self, fingerprint: str) -> bool:
        rows = self.data.setdefault("devices", {})
        if fingerprint in rows:
            del rows[fingerprint]
            return True
        return False

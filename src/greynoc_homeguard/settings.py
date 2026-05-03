from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import utcnow
from .paths import settings_file

SETTINGS_SCHEMA_VERSION = "1.0"
ONBOARDING_VERSION = "2026.05"


@dataclass(slots=True)
class AppSettings:
    """Small persistent settings store for desktop-only preferences."""

    path: Path | None = None
    data: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.path is None:
            self.path = settings_file()
        if not self.data:
            self.data = self._defaults()

    def _defaults(self) -> dict[str, Any]:
        return {
            "schema_version": SETTINGS_SCHEMA_VERSION,
            "onboarding": {
                "version": ONBOARDING_VERSION,
                "completed": False,
                "skipped": False,
                "completed_at": "",
                "skipped_at": "",
            },
            "scan_defaults": {
                "active_scan": False,
                "probe_all": False,
            },
            "ignored_findings": {},
        }

    def load(self) -> "AppSettings":
        assert self.path is not None
        if not self.path.exists():
            self.save()
            return self
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = {}
        if not isinstance(loaded, dict):
            loaded = {}
        defaults = self._defaults()
        self.data = defaults
        self.data.update(loaded)
        onboarding = dict(defaults["onboarding"])
        onboarding.update(loaded.get("onboarding") if isinstance(loaded.get("onboarding"), dict) else {})
        scan_defaults = dict(defaults["scan_defaults"])
        scan_defaults.update(
            loaded.get("scan_defaults") if isinstance(loaded.get("scan_defaults"), dict) else {}
        )
        self.data["onboarding"] = onboarding
        self.data["scan_defaults"] = scan_defaults
        ignored = loaded.get("ignored_findings") if isinstance(loaded.get("ignored_findings"), dict) else {}
        self.data["ignored_findings"] = ignored
        return self

    def save(self) -> None:
        assert self.path is not None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(self.data, indent=2, sort_keys=True), encoding="utf-8")

    def onboarding_needed(self) -> bool:
        onboarding = self.data.get("onboarding") if isinstance(self.data.get("onboarding"), dict) else {}
        return not bool(onboarding.get("completed") or onboarding.get("skipped"))

    def mark_onboarding_complete(self) -> None:
        onboarding = self.data.setdefault("onboarding", {})
        onboarding["version"] = ONBOARDING_VERSION
        onboarding["completed"] = True
        onboarding["skipped"] = False
        onboarding["completed_at"] = utcnow()
        self.save()

    def mark_onboarding_skipped(self) -> None:
        onboarding = self.data.setdefault("onboarding", {})
        onboarding["version"] = ONBOARDING_VERSION
        onboarding["completed"] = False
        onboarding["skipped"] = True
        onboarding["skipped_at"] = utcnow()
        self.save()

    def scan_defaults(self) -> dict[str, bool]:
        defaults = self.data.get("scan_defaults") if isinstance(self.data.get("scan_defaults"), dict) else {}
        return {
            "active_scan": bool(defaults.get("active_scan", False)),
            "probe_all": bool(defaults.get("probe_all", False)),
        }

    def set_scan_defaults(self, *, active_scan: bool, probe_all: bool) -> None:
        self.data["scan_defaults"] = {
            "active_scan": bool(active_scan),
            "probe_all": bool(probe_all),
        }
        self.save()

    def ignored_finding_ids(self) -> set[str]:
        ignored = self.data.get("ignored_findings") if isinstance(self.data.get("ignored_findings"), dict) else {}
        return {str(key) for key, value in ignored.items() if value}

    def ignore_finding(self, finding_id: str, *, title: str = "", reason: str = "user") -> None:
        finding_id = str(finding_id or "").strip()
        if not finding_id:
            return
        ignored = self.data.setdefault("ignored_findings", {})
        ignored[finding_id] = {
            "ignored_at": utcnow(),
            "reason": str(reason or "user"),
            "title": str(title or "")[:250],
        }
        self.save()

    def unignore_finding(self, finding_id: str) -> None:
        ignored = self.data.get("ignored_findings")
        if isinstance(ignored, dict) and finding_id in ignored:
            del ignored[finding_id]
            self.save()

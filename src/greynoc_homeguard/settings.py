from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .models import utcnow
from .paths import atomic_write_text, settings_file

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
            "realtime": {
                "enabled": False,
                "directories": [],
                "interval": 3.0,
                "settle_seconds": 2.0,
                "auto_quarantine": True,
            },
            "hash_feed": {
                "url": "",
                "last_updated": "",
                "last_status": "",
            },
            "flow_source": {
                "enabled": False,
                "provider": "openwrt",
                "host": "",
                "user": "root",
                "port": 22,
                "key_env": "",
                "key_path": "",
            },
            "ui": {
                # Desktop UI preferences. The floating chat bubble is on by
                # default; the weather greeting is opt-in and stays off unless
                # the user enables it (and HomeGuard never fetches weather while
                # it is off -- see docs).
                "show_chat_bubble": True,
                "show_weather_greeting": False,
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
        realtime = dict(defaults["realtime"])
        realtime.update(loaded.get("realtime") if isinstance(loaded.get("realtime"), dict) else {})
        self.data["realtime"] = realtime
        hash_feed = dict(defaults["hash_feed"])
        hash_feed.update(loaded.get("hash_feed") if isinstance(loaded.get("hash_feed"), dict) else {})
        self.data["hash_feed"] = hash_feed
        flow_source = dict(defaults["flow_source"])
        flow_source.update(loaded.get("flow_source") if isinstance(loaded.get("flow_source"), dict) else {})
        self.data["flow_source"] = flow_source
        ui = dict(defaults["ui"])
        ui.update(loaded.get("ui") if isinstance(loaded.get("ui"), dict) else {})
        self.data["ui"] = ui
        ignored = loaded.get("ignored_findings") if isinstance(loaded.get("ignored_findings"), dict) else {}
        self.data["ignored_findings"] = ignored
        return self

    def save(self) -> None:
        assert self.path is not None
        atomic_write_text(self.path, json.dumps(self.data, indent=2, sort_keys=True))

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

    def ui_prefs(self) -> dict[str, bool]:
        prefs = self.data.get("ui") if isinstance(self.data.get("ui"), dict) else {}
        return {
            "show_chat_bubble": bool(prefs.get("show_chat_bubble", True)),
            "show_weather_greeting": bool(prefs.get("show_weather_greeting", False)),
        }

    def set_ui_prefs(
        self,
        *,
        show_chat_bubble: bool | None = None,
        show_weather_greeting: bool | None = None,
    ) -> dict[str, bool]:
        prefs = self.ui_prefs()
        if show_chat_bubble is not None:
            prefs["show_chat_bubble"] = bool(show_chat_bubble)
        if show_weather_greeting is not None:
            prefs["show_weather_greeting"] = bool(show_weather_greeting)
        self.data["ui"] = prefs
        self.save()
        return prefs

    def realtime_config(self) -> dict[str, Any]:
        cfg = self.data.get("realtime") if isinstance(self.data.get("realtime"), dict) else {}
        directories = cfg.get("directories")
        return {
            "enabled": bool(cfg.get("enabled", False)),
            "directories": [str(item) for item in directories] if isinstance(directories, list) else [],
            "interval": float(cfg.get("interval", 3.0) or 3.0),
            "settle_seconds": float(cfg.get("settle_seconds", 2.0) or 2.0),
            "auto_quarantine": bool(cfg.get("auto_quarantine", True)),
        }

    def set_realtime(
        self,
        *,
        enabled: bool | None = None,
        directories: list[str] | None = None,
        interval: float | None = None,
        settle_seconds: float | None = None,
        auto_quarantine: bool | None = None,
    ) -> dict[str, Any]:
        cfg = self.realtime_config()
        if enabled is not None:
            cfg["enabled"] = bool(enabled)
        if directories is not None:
            cfg["directories"] = [str(item) for item in directories]
        if interval is not None:
            cfg["interval"] = float(interval)
        if settle_seconds is not None:
            cfg["settle_seconds"] = float(settle_seconds)
        if auto_quarantine is not None:
            cfg["auto_quarantine"] = bool(auto_quarantine)
        self.data["realtime"] = cfg
        self.save()
        return cfg

    def hash_feed_config(self) -> dict[str, str]:
        cfg = self.data.get("hash_feed") if isinstance(self.data.get("hash_feed"), dict) else {}
        return {
            "url": str(cfg.get("url", "") or ""),
            "last_updated": str(cfg.get("last_updated", "") or ""),
            "last_status": str(cfg.get("last_status", "") or ""),
        }

    def set_hash_feed(self, *, url: str | None = None, last_updated: str | None = None, last_status: str | None = None) -> dict[str, str]:
        cfg = self.hash_feed_config()
        if url is not None:
            cfg["url"] = str(url)
        if last_updated is not None:
            cfg["last_updated"] = str(last_updated)
        if last_status is not None:
            cfg["last_status"] = str(last_status)
        self.data["hash_feed"] = cfg
        self.save()
        return cfg

    def flow_source_config(self) -> dict[str, Any]:
        cfg = self.data.get("flow_source") if isinstance(self.data.get("flow_source"), dict) else {}
        return {
            "enabled": bool(cfg.get("enabled", False)),
            "provider": str(cfg.get("provider", "openwrt") or "openwrt"),
            "host": str(cfg.get("host", "") or ""),
            "user": str(cfg.get("user", "root") or "root"),
            "port": int(cfg.get("port", 22) or 22),
            "key_env": str(cfg.get("key_env", "") or ""),
            "key_path": str(cfg.get("key_path", "") or ""),
        }

    def set_flow_source(
        self,
        *,
        enabled: bool | None = None,
        provider: str | None = None,
        host: str | None = None,
        user: str | None = None,
        port: int | None = None,
        key_env: str | None = None,
        key_path: str | None = None,
    ) -> dict[str, Any]:
        cfg = self.flow_source_config()
        if enabled is not None:
            cfg["enabled"] = bool(enabled)
        if provider is not None:
            cfg["provider"] = str(provider)
        if host is not None:
            cfg["host"] = str(host)
        if user is not None:
            cfg["user"] = str(user)
        if port is not None:
            cfg["port"] = int(port)
        if key_env is not None:
            cfg["key_env"] = str(key_env)
        if key_path is not None:
            cfg["key_path"] = str(key_path)
        self.data["flow_source"] = cfg
        self.save()
        return cfg

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

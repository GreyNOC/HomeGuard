from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .paths import schedule_file

INTERVAL_SECONDS = {
    "hourly": 60 * 60,
    "daily": 24 * 60 * 60,
    "weekly": 7 * 24 * 60 * 60,
}
INTERVAL_VALUES = set(INTERVAL_SECONDS)


@dataclass
class ScheduleConfig:
    enabled: bool = False
    interval: str = "daily"
    last_run: str = ""
    next_run: str = ""
    background_monitor: bool = False

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "ScheduleConfig":
        if not isinstance(payload, dict):
            payload = {}
        interval = str(payload.get("interval") or "daily").lower()
        if interval not in INTERVAL_VALUES:
            interval = "daily"
        return cls(
            enabled=bool(payload.get("enabled", False)),
            interval=interval,
            last_run=str(payload.get("last_run") or ""),
            next_run=str(payload.get("next_run") or ""),
            background_monitor=bool(payload.get("background_monitor", False)),
        )

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def interval_seconds(self) -> int:
        return INTERVAL_SECONDS.get(self.interval, INTERVAL_SECONDS["daily"])


class ScheduleManager:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else schedule_file()
        self.config = ScheduleConfig()

    def load(self) -> ScheduleConfig:
        if self.path.exists():
            try:
                payload = json.loads(self.path.read_text(encoding="utf-8"))
                self.config = ScheduleConfig.from_dict(payload if isinstance(payload, dict) else {})
            except (OSError, json.JSONDecodeError):
                self.config = ScheduleConfig()
        return self.config

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps(self.config.as_dict(), indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def set(self, *, enabled: bool | None = None, interval: str | None = None, background_monitor: bool | None = None) -> ScheduleConfig:
        if enabled is not None:
            self.config.enabled = bool(enabled)
        if interval is not None:
            interval = interval.lower().strip()
            if interval not in INTERVAL_VALUES:
                raise ValueError(f"interval must be one of {sorted(INTERVAL_VALUES)}")
            self.config.interval = interval
        if background_monitor is not None:
            self.config.background_monitor = bool(background_monitor)
        self.config.next_run = self._compute_next_run()
        self.save()
        return self.config

    def mark_ran(self, timestamp: datetime | None = None) -> None:
        when = (timestamp or datetime.now(timezone.utc)).replace(microsecond=0)
        self.config.last_run = when.isoformat().replace("+00:00", "Z")
        self.config.next_run = self._compute_next_run(reference=when)
        self.save()

    def is_due(self, *, now: datetime | None = None) -> bool:
        if not self.config.enabled:
            return False
        now = now or datetime.now(timezone.utc)
        next_run = _parse_dt(self.config.next_run)
        if next_run is None:
            return True
        return now >= next_run

    def _compute_next_run(self, *, reference: datetime | None = None) -> str:
        if not self.config.enabled:
            return ""
        ref = reference or _parse_dt(self.config.last_run) or datetime.now(timezone.utc)
        next_dt = ref + timedelta(seconds=self.config.interval_seconds())
        return next_dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_dt(value: str) -> datetime | None:
    if not value:
        return None
    try:
        clean = value.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None

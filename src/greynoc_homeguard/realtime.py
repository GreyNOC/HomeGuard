"""Real-time file-system watcher with on-write malware scanning.

Scheduled and on-demand scans catch threats that are already sitting on disk.
A real consumer antivirus also wants to catch a malicious file *the moment it
lands* — a fresh download, an email attachment saved to disk, a file copied
from a USB stick. This watcher provides that "real-time protection" layer.

It is a dependency-free **polling** watcher: every ``interval`` seconds it
re-stats the watched directories, scans any file that is new or has changed
since the last pass, and (by default) auto-quarantines high-confidence
detections through the same conservative remediation bar used everywhere else.
Polling was chosen over native ``ReadDirectoryChangesW`` / ``inotify`` so the
watcher behaves identically on every platform and stays trivially testable —
``poll_once()`` is pure and can be driven directly from a test.

Two safeguards keep it well-behaved:

* **Settle window** — a file whose mtime is newer than ``settle_seconds`` is
  skipped this pass and picked up on the next one, so a half-written download
  is not scanned mid-flight.
* **Priming** — by default the first pass records existing files *without*
  scanning them, so enabling protection does not trigger a mass-scan of files
  that were already there; only files that appear or change afterwards are
  scanned. Set ``scan_existing=True`` for a full initial sweep.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from .logging_setup import get_logger
from .models import utcnow
from .paths import atomic_write_text, realtime_events_file
from .quarantine import QuarantineVault
from .remediation import quarantine_findings
from .virus_scanner import default_download_dirs, scan_file

LOG = get_logger("realtime")

_NOISE_DIRS = {"$recycle.bin", "node_modules", ".git", "__pycache__"}
DEFAULT_SETTLE_SECONDS = 2.0
DEFAULT_INTERVAL_SECONDS = 3.0
DEFAULT_MAX_FILE_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_FILES_PER_POLL = 5000
EVENT_LOG_CAP = 200

EventCallback = Callable[[dict[str, Any]], None]


@dataclass(slots=True)
class RealtimeWatcher:
    directories: list[Path] = field(default_factory=list)
    interval: float = DEFAULT_INTERVAL_SECONDS
    settle_seconds: float = DEFAULT_SETTLE_SECONDS
    auto_quarantine: bool = True
    scan_existing: bool = False
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_files_per_poll: int = DEFAULT_MAX_FILES_PER_POLL
    malware_hashes: dict[str, dict[str, Any]] | None = None
    vault: QuarantineVault | None = None
    on_event: EventCallback | None = None
    clock: Callable[[], float] = time.time
    _seen: dict[str, tuple[float, int]] = field(default_factory=dict, init=False)
    _primed: bool = field(default=False, init=False)
    _hashes: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)
    _resolved: bool = field(default=False, init=False)

    def _resolve(self) -> None:
        if self._resolved:
            return
        if not self.directories:
            self.directories = list(default_download_dirs())
        else:
            self.directories = [Path(d) for d in self.directories]
        if self.malware_hashes is not None:
            self._hashes = self.malware_hashes
        else:
            try:
                from .definitions import active_malware_hashes

                self._hashes = active_malware_hashes()
            except Exception:  # pragma: no cover - defensive
                self._hashes = {}
        if self.vault is None:
            self.vault = QuarantineVault().load()
        self._resolved = True

    def _iter_files(self) -> list[tuple[Path, tuple[float, int]]]:
        results: list[tuple[Path, tuple[float, int]]] = []
        for directory in self.directories:
            directory = Path(directory)
            if not directory.exists():
                continue
            if directory.is_file():
                stat = _safe_stat(directory)
                if stat:
                    results.append((directory, (stat.st_mtime, stat.st_size)))
                continue
            try:
                for dirpath, dirnames, filenames in os.walk(directory):
                    dirnames[:] = [name for name in dirnames if name.lower() not in _NOISE_DIRS]
                    base = Path(dirpath)
                    for name in filenames:
                        path = base / name
                        stat = _safe_stat(path)
                        if stat:
                            results.append((path, (stat.st_mtime, stat.st_size)))
                        if len(results) >= self.max_files_per_poll:
                            return results
            except OSError:
                continue
        return results

    def poll_once(self) -> list[dict[str, Any]]:
        """Run one scan pass. Returns the events emitted this pass."""
        self._resolve()
        events: list[dict[str, Any]] = []
        now = self.clock()
        files = self._iter_files()

        # First pass with scan_existing=False just records what's already here.
        if not self._primed and not self.scan_existing:
            for path, fingerprint in files:
                self._seen[str(path)] = fingerprint
            self._primed = True
            return events
        self._primed = True

        for path, fingerprint in files:
            key = str(path)
            mtime, size = fingerprint
            if self._seen.get(key) == fingerprint:
                continue  # unchanged since we last looked
            if self.settle_seconds > 0 and (now - mtime) < self.settle_seconds:
                continue  # still being written; revisit next pass
            self._seen[key] = fingerprint
            if size > self.max_file_bytes:
                continue
            try:
                findings = scan_file(path, malware_hashes=self._hashes)
            except Exception as exc:  # pragma: no cover - one bad file must not kill the loop
                LOG.debug("watcher scan_file failed for %s: %s", path, exc)
                continue
            if not findings:
                continue
            actions: list[dict[str, Any]] = []
            if self.auto_quarantine:
                actions = quarantine_findings(findings, vault=self.vault)
                for action in actions:
                    if action.get("action") == "quarantined":
                        # The file is gone; drop it so a later restore re-scans.
                        self._seen.pop(str(action.get("path") or ""), None)
            severities = [str(f.severity) for f in findings]
            top = _highest_severity(severities)
            quarantined = sum(1 for a in actions if a.get("action") == "quarantined")
            event = {
                "detected_at": utcnow(),
                "path": key,
                "name": path.name,
                "severity": top,
                "detection_count": len(findings),
                "rules": sorted({f.rule_id for f in findings}),
                "quarantined": quarantined,
                "actions": actions,
            }
            events.append(event)
            self._emit(event)
        return events

    def _emit(self, event: dict[str, Any]) -> None:
        LOG.info(
            "Real-time detection: %s (%s, %d finding(s), %d quarantined)",
            event["name"],
            event["severity"],
            event["detection_count"],
            event["quarantined"],
        )
        if self.on_event:
            try:
                self.on_event(event)
            except Exception as exc:  # pragma: no cover - callback bugs must not kill the loop
                LOG.debug("watcher on_event callback failed: %s", exc)

    def run(self, stop_event: threading.Event) -> None:
        """Loop ``poll_once`` until ``stop_event`` is set."""
        self._resolve()
        LOG.info(
            "Real-time watcher started (dirs=%s, interval=%.1fs, auto_quarantine=%s)",
            [str(d) for d in self.directories],
            self.interval,
            self.auto_quarantine,
        )
        while not stop_event.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # pragma: no cover - defensive
                LOG.warning("Real-time watcher poll failed: %s", exc)
            stop_event.wait(self.interval)
        LOG.info("Real-time watcher stopped.")


_SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def _highest_severity(severities: Iterable[str]) -> str:
    best = "info"
    best_rank = -1
    for severity in severities:
        try:
            rank = _SEVERITY_ORDER.index(str(severity).lower())
        except ValueError:
            rank = 0
        if rank > best_rank:
            best_rank = rank
            best = str(severity).lower()
    return best


def _safe_stat(path: Path) -> os.stat_result | None:
    try:
        return path.stat()
    except OSError:
        return None


# --- Persisted event log (for the CLI/GUI "recent threats caught" view) -----


def load_events(path: Path | None = None) -> list[dict[str, Any]]:
    target = Path(path) if path else realtime_events_file()
    if not target.exists():
        return []
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    events = data.get("events") if isinstance(data, dict) else None
    return [row for row in (events or []) if isinstance(row, dict)]


def append_event(event: dict[str, Any], *, path: Path | None = None, cap: int = EVENT_LOG_CAP) -> None:
    target = Path(path) if path else realtime_events_file()
    events = load_events(target)
    events.append(event)
    if len(events) > cap:
        events = events[-cap:]
    atomic_write_text(target, json.dumps({"events": events}, indent=2, sort_keys=True))


def clear_events(path: Path | None = None) -> None:
    target = Path(path) if path else realtime_events_file()
    atomic_write_text(target, json.dumps({"events": []}, indent=2, sort_keys=True))

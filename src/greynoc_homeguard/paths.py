from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

APP_VENDOR = "GreyNOC"
APP_NAME = "HomeGuard"


def atomic_write_text(path: Path, content: str, *, encoding: str = "utf-8") -> None:
    """Write ``content`` to ``path`` atomically.

    The naive ``Path.write_text`` opens the destination in truncate mode and
    can leave a half-written or zero-byte file behind if the process is
    killed mid-write — power loss, ``taskkill``, OOM, or a crash. Several of
    HomeGuard's persistence layers (trust store, definitions cache,
    schedule, history, settings) then fall back to defaults on the next
    load and silently lose user state.

    Write to a sibling tempfile in the same directory (so the rename stays
    on the same filesystem), flush to disk, and ``os.replace`` to swap into
    place. ``os.replace`` is atomic on both POSIX and Windows when source
    and destination are on the same volume, which they are here because
    the temp file is created next to the destination.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding=encoding, newline="") as handle:
            handle.write(content)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                # fsync is best-effort; some filesystems / Windows shares
                # don't support it. The os.replace below still gives us
                # atomic semantics relative to readers.
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise


def app_root() -> Path:
    """Return the best root folder for source, editable installs, or PyInstaller builds."""

    bundled = getattr(sys, "_MEIPASS", None)
    if bundled:
        return Path(str(bundled))
    return Path(__file__).resolve().parents[2]


def user_data_dir() -> Path:
    """Per-user writable app data folder.

    Windows:  %LOCALAPPDATA%\\GreyNOC\\HomeGuard
    macOS:    ~/Library/Application Support/GreyNOC/HomeGuard
    Linux:    $XDG_DATA_HOME/homeguard or ~/.local/share/homeguard
    """

    override = os.environ.get("HOMEGUARD_DATA_DIR")
    if override:
        return Path(override).expanduser()
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        if base:
            return Path(base) / APP_VENDOR / APP_NAME
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / APP_VENDOR / APP_NAME
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "homeguard"


def ensure_app_dirs() -> dict[str, Path]:
    """Create (if missing) and return all standard app data folders."""

    paths = {
        "root": user_data_dir(),
        "definitions": definitions_dir(),
        "reports": default_output_dir(),
        "history": history_dir(),
        "logs": logs_dir(),
    }
    for path in paths.values():
        try:
            path.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass
    return paths


def default_output_dir() -> Path:
    return user_data_dir() / "reports"


def latest_report_dir() -> Path:
    return default_output_dir() / "latest"


def default_baseline_path() -> Path:
    """Legacy known-devices file. Kept for backwards compatibility."""

    return user_data_dir() / "known_devices.json"


def definitions_dir() -> Path:
    return user_data_dir() / "definitions"


def definitions_file() -> Path:
    return definitions_dir() / "security_definitions.json"


def history_dir() -> Path:
    return user_data_dir() / "history"


def history_file() -> Path:
    return history_dir() / "protection_history.json"


def schedule_file() -> Path:
    return user_data_dir() / "schedule_config.json"


def settings_file() -> Path:
    return user_data_dir() / "settings.json"


def logs_dir() -> Path:
    return user_data_dir() / "logs"

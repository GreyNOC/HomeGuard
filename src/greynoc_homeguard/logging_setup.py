from __future__ import annotations

import logging
import logging.handlers
from pathlib import Path

from .paths import logs_dir
from .privacy import scrub_text

LOG_FORMAT = "%(asctime)s %(levelname)s %(name)s: %(message)s"
LOG_FILE_NAME = "homeguard.log"

_initialized = False


class RedactingFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        return scrub_text(rendered)


def setup_logging(level: int = logging.INFO) -> Path:
    """Initialize file + console logging. Idempotent. Returns the log file path."""

    global _initialized
    log_dir = logs_dir()
    log_path = log_dir / LOG_FILE_NAME
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    if _initialized:
        return log_path

    root = logging.getLogger("greynoc_homeguard")
    root.setLevel(level)
    root.propagate = False

    formatter = RedactingFormatter(LOG_FORMAT)

    try:
        file_handler = logging.handlers.RotatingFileHandler(
            log_path,
            maxBytes=1_000_000,
            backupCount=5,
            encoding="utf-8",
        )
    except OSError:
        file_handler = None
    if file_handler is not None:
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.WARNING)
    stream_handler.setFormatter(formatter)
    root.addHandler(stream_handler)

    _initialized = True
    return log_path


def get_logger(name: str) -> logging.Logger:
    setup_logging()
    return logging.getLogger(f"greynoc_homeguard.{name}")


def log_file_path() -> Path:
    return logs_dir() / LOG_FILE_NAME

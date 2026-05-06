"""User-defined custom detection rules.

HomeGuard ships a curated catalog of risky ports, name hints, and product
hints, and pulls KEV / CVE intelligence from CISA and NVD. Power users
with their own threat awareness — a known-bad MAC OUI from a recall, an
internal hostname pattern that should never appear on home WiFi, an
unusual port they want flagged — can drop a JSON file at
``<appdata>/custom_rules.json`` and HomeGuard will merge those rules
into every scan.

The schema is intentionally tolerant: missing keys are skipped, invalid
entries are dropped with a warning logged, and a malformed file simply
produces zero custom rules without breaking the scan. The file is never
mutated by HomeGuard itself, only read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .logging_setup import get_logger
from .paths import atomic_write_text, custom_rules_file

LOG = get_logger("custom_rules")

CUSTOM_SCHEMA_VERSION = "1.0"
SEVERITY_VALUES = {"critical", "high", "medium", "low", "info"}


def example_payload() -> dict[str, Any]:
    """Return a self-documenting example payload. Used by ``custom-rules
    init`` to seed a starter file."""

    return {
        "schema_version": CUSTOM_SCHEMA_VERSION,
        "_doc": (
            "Add custom detection rules to flag devices, ports, or vendors that "
            "should never appear on YOUR home network. Severity must be one of: "
            f"{sorted(SEVERITY_VALUES)}. Hostname patterns use shell-style globs "
            "(* and ?). MAC prefixes accept aa:bb:cc, aa-bb-cc, or aabbcc forms."
        ),
        "risky_ports": [
            {
                "port": 12345,
                "service": "Internal lab",
                "severity": "medium",
                "why": "Lab service that should never be reachable on the home network.",
            }
        ],
        "watch_hostnames": [
            {
                "pattern": "*-lab",
                "severity": "medium",
                "why": "Hostnames ending in '-lab' should not appear at home.",
            }
        ],
        "watch_mac_prefixes": [
            {
                "prefix": "00:11:22",
                "severity": "high",
                "why": "Recalled IoT vendor; replace any device matching this OUI.",
            }
        ],
    }


def _normalize_severity(value: Any, *, default: str = "medium") -> str:
    severity = str(value or default).lower().strip()
    return severity if severity in SEVERITY_VALUES else default


def _validate_risky_port(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    try:
        port = int(row.get("port"))
    except (TypeError, ValueError):
        return None
    if not 0 < port <= 65535:
        return None
    return {
        "port": port,
        "service": str(row.get("service") or f"User-defined port {port}"),
        "severity": _normalize_severity(row.get("severity")),
        "why": str(row.get("why") or "Custom risky port from your local rules file."),
        "category": str(row.get("category") or "exposed_service"),
    }


def _validate_hostname(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    pattern = str(row.get("pattern") or "").strip()
    if not pattern:
        return None
    return {
        "pattern": pattern.lower(),
        "severity": _normalize_severity(row.get("severity")),
        "why": str(row.get("why") or "Hostname matched a custom watch list entry."),
    }


def _normalize_mac_prefix(value: Any) -> str:
    text = str(value or "").lower()
    cleaned = "".join(char for char in text if char in "0123456789abcdef")
    if len(cleaned) < 6:
        return ""
    cleaned = cleaned[:6]
    return ":".join(cleaned[i : i + 2] for i in range(0, 6, 2))


def _validate_mac_prefix(row: Any) -> dict[str, Any] | None:
    if not isinstance(row, dict):
        return None
    prefix = _normalize_mac_prefix(row.get("prefix"))
    if not prefix:
        return None
    return {
        "prefix": prefix,
        "severity": _normalize_severity(row.get("severity")),
        "why": str(row.get("why") or "MAC OUI matched a custom watch list entry."),
    }


def load_custom_rules(path: Path | None = None) -> dict[str, Any]:
    """Load and validate the user's custom rules. Always returns a dict.

    On any I/O / parse / schema error, logs a warning and returns an
    empty payload so the scan keeps running. Invalid individual entries
    are dropped without affecting the remaining valid ones.
    """

    target = Path(path) if path else custom_rules_file()
    payload: dict[str, Any] = {
        "risky_ports": [],
        "watch_hostnames": [],
        "watch_mac_prefixes": [],
    }
    if not target.exists():
        return payload
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOG.warning("Custom rules file ignored (could not parse): %s", exc)
        return payload
    if not isinstance(raw, dict):
        LOG.warning("Custom rules file ignored (top-level value must be an object).")
        return payload
    for row in raw.get("risky_ports") or []:
        clean = _validate_risky_port(row)
        if clean is not None:
            payload["risky_ports"].append(clean)
    for row in raw.get("watch_hostnames") or []:
        clean = _validate_hostname(row)
        if clean is not None:
            payload["watch_hostnames"].append(clean)
    for row in raw.get("watch_mac_prefixes") or []:
        clean = _validate_mac_prefix(row)
        if clean is not None:
            payload["watch_mac_prefixes"].append(clean)
    return payload


def has_any_rules(custom: dict[str, Any] | None) -> bool:
    if not custom:
        return False
    return bool(
        custom.get("risky_ports")
        or custom.get("watch_hostnames")
        or custom.get("watch_mac_prefixes")
    )


def apply_to_definitions(
    definitions: dict[str, Any], custom: dict[str, Any] | None
) -> dict[str, Any]:
    """Merge custom rules into an in-memory definitions dict.

    Custom risky ports are appended after the bundled list so the
    existing ``risky_ports_from_definitions`` helper deduplicates by port
    with the user's entry winning. Hostname and MAC OUI watch lists land
    on dedicated keys consumed by the new detectors. The on-disk
    ``security_definitions.json`` is never modified — custom rules live
    only in memory for the lifetime of a scan.
    """

    if not has_any_rules(custom):
        return definitions
    if custom and custom.get("risky_ports"):
        existing = list(definitions.get("risky_ports") or [])
        definitions["risky_ports"] = existing + list(custom["risky_ports"])
    if custom and custom.get("watch_hostnames"):
        definitions["custom_watch_hostnames"] = list(custom["watch_hostnames"])
    if custom and custom.get("watch_mac_prefixes"):
        definitions["custom_watch_mac_prefixes"] = list(custom["watch_mac_prefixes"])
    return definitions


def write_example(path: Path | None = None, *, force: bool = False) -> Path:
    """Write a self-documenting example payload to the custom-rules path.

    Refuses to overwrite an existing file unless ``force`` is True so the
    user does not accidentally lose their rules by running ``custom-rules
    init`` twice.
    """

    target = Path(path) if path else custom_rules_file()
    if target.exists() and not force:
        raise FileExistsError(
            f"{target} already exists. Pass --force to overwrite (this destroys your existing rules)."
        )
    atomic_write_text(target, json.dumps(example_payload(), indent=2, sort_keys=True))
    return target

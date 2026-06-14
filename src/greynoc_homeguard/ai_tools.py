"""Engine tools exposed to the AI via provider-agnostic tool-calling.

The AI bridge in :mod:`greynoc_homeguard.ai_bridge` translates these tool
definitions into the on-wire shape each provider expects (OpenAI's
``tools`` array, Anthropic's ``input_schema``, etc.). Each tool is a small,
side-effect-bounded handler that already obeys the AI bridge share-level so
the LLM never sees raw identifiers in minimal/standard mode.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any, Callable

from . import ai_memory, ai_traffic
from .paths import latest_report_dir

ToolHandler = Callable[[dict[str, Any], str], dict[str, Any]]


def _stable_token(value: str, prefix: str) -> str:
    if not value:
        return ""
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _load_latest_report_payload() -> dict[str, Any]:
    latest = latest_report_dir() / "report.json"
    if not latest.exists():
        return {}
    try:
        payload = json.loads(latest.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _summarize_report_for_tool(payload: dict[str, Any], *, share_level: str) -> dict[str, Any]:
    from .ai_bridge import report_to_signal_context

    if not payload:
        return {"available": False}
    context = report_to_signal_context(payload, share_level=share_level)
    return {"available": True, "signal_context": context}


def tool_get_latest_report(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    return _summarize_report_for_tool(_load_latest_report_payload(), share_level=share_level)


def tool_list_devices(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    from .ai_bridge import _device_payload

    payload = _load_latest_report_payload()
    devices = payload.get("devices") or []
    limit = int(args.get("limit") or 25)
    limit = max(1, min(60, limit))
    return {
        "available": bool(payload),
        "count": len(devices),
        "devices": [_device_payload(item, share_level) for item in devices[:limit]],
    }


def tool_get_finding(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    from .ai_bridge import _finding_payload

    rule_id = str(args.get("rule_id") or "").strip().lower()
    finding_id = str(args.get("finding_id") or "").strip().lower()
    if not rule_id and not finding_id:
        return {"error": "Provide rule_id or finding_id."}
    payload = _load_latest_report_payload()
    matches = []
    for item in payload.get("findings") or []:
        if not isinstance(item, dict):
            continue
        if rule_id and str(item.get("rule_id", "")).strip().lower() == rule_id:
            matches.append(_finding_payload(item, share_level))
        elif finding_id and str(item.get("finding_id", "")).strip().lower() == finding_id:
            matches.append(_finding_payload(item, share_level))
    return {"count": len(matches), "findings": matches}


def tool_get_traffic_summary(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    summary = ai_traffic.collect_traffic_summary(share_level=share_level)
    return summary.as_dict()


def tool_get_memory(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    return ai_memory.summarize_for_prompt()


def tool_save_memory_note(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    text = str(args.get("text") or "").strip()
    if not text:
        return {"error": "Note text is required."}
    tags = args.get("tags") or []
    if not isinstance(tags, list):
        tags = []
    note = ai_memory.add_note(text=text, tags=[str(tag) for tag in tags], source="ai")
    return {"saved": True, "note": note.as_dict()}


def _display_path(path: str, share_level: str) -> str:
    """Full path only at the 'full' share level; basename otherwise."""
    from pathlib import Path

    if not path:
        return ""
    return path if share_level == "full" else Path(path).name


def tool_scan_path(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    """Scan a file or folder on demand, optionally quarantining threats."""
    from .remediation import scan_and_remediate

    target = str(args.get("path") or "").strip()
    if not target:
        return {"error": "path is required."}
    quarantine = bool(args.get("quarantine"))
    try:
        result = scan_and_remediate(target, quarantine=quarantine)
    except Exception as exc:  # pragma: no cover - defensive
        return {"error": f"Scan failed: {exc}"}
    findings = result["findings"]
    metadata = result["metadata"]
    actions = result["actions"]
    return {
        "target": _display_path(target, share_level),
        "files_scanned": metadata.get("files_scanned", 0),
        "detection_count": len(findings),
        "detections": [
            {
                "rule_id": finding.rule_id,
                "severity": finding.severity,
                "confidence": round(finding.confidence, 2),
                "file": _display_path(str((finding.evidence or {}).get("path") or ""), share_level),
                "title": finding.title,
            }
            for finding in findings[:25]
        ],
        "quarantined": sum(1 for action in actions if action.get("action") == "quarantined"),
        "actions": [
            {
                "action": action.get("action"),
                "rule_id": action.get("rule_id"),
                "file": _display_path(str(action.get("path") or ""), share_level),
            }
            for action in actions[:25]
        ],
    }


def tool_list_quarantine(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    """List files currently held in the local quarantine vault."""
    from .quarantine import QuarantineVault

    vault = QuarantineVault().load()
    entries = vault.entries()
    return {
        "stats": vault.stats(),
        "entries": [
            {
                "entry_id": entry.entry_id,
                "name": entry.original_name,
                "severity": entry.severity,
                "detection_rule": entry.detection_rule,
                "quarantined_at": entry.quarantined_at,
                "original_path": _display_path(entry.original_path, share_level),
            }
            for entry in entries[:50]
        ],
    }


def tool_record_device_fact(args: dict[str, Any], share_level: str) -> dict[str, Any]:
    raw_fingerprint = str(args.get("fingerprint") or "").strip()
    if not raw_fingerprint:
        return {"error": "fingerprint is required."}
    fingerprint = raw_fingerprint if share_level == "full" else _stable_token(raw_fingerprint, "device")
    fact = ai_memory.DeviceFact(
        fingerprint=fingerprint,
        label=str(args.get("label") or ""),
        trust=str(args.get("trust") or ""),
        owner=str(args.get("owner") or ""),
        notes=str(args.get("notes") or ""),
        last_risk=str(args.get("last_risk") or ""),
        last_seen=time.time(),
    )
    ai_memory.upsert_device_fact(fact)
    return {"saved": True, "fingerprint": fingerprint}


TOOLS: list[dict[str, Any]] = [
    {
        "name": "homeguard_get_latest_report",
        "description": (
            "Return the latest HomeGuard scan report as a bounded signal "
            "context. Sensitive identifiers are redacted per the active "
            "share level. Use this to ground answers in real scan data."
        ),
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": tool_get_latest_report,
    },
    {
        "name": "homeguard_list_devices",
        "description": (
            "List up to N devices from the latest scan. Returns hashed "
            "identifiers in minimal/standard share levels."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "limit": {"type": "integer", "minimum": 1, "maximum": 60},
            },
            "additionalProperties": False,
        },
        "handler": tool_list_devices,
    },
    {
        "name": "homeguard_get_finding",
        "description": (
            "Fetch one or more findings by rule_id or finding_id. "
            "Returns the same redaction policy as the report context."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string"},
                "finding_id": {"type": "string"},
            },
            "additionalProperties": False,
        },
        "handler": tool_get_finding,
    },
    {
        "name": "homeguard_get_traffic_summary",
        "description": (
            "Return a bounded snapshot of current TCP/UDP connection state "
            "on this machine: total connections, listening ports, top "
            "remote endpoints, and top processes. No packet content is "
            "captured. External endpoints are hashed in minimal share level."
        ),
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": tool_get_traffic_summary,
    },
    {
        "name": "homeguard_scan_path",
        "description": (
            "Scan a file or folder on this machine for malware using exact "
            "known-bad hash matches, embedded content signatures, deceptive "
            "double extensions, and a packed-executable heuristic. Set "
            "quarantine=true to neutralize high-confidence detections into the "
            "local quarantine vault (recoverable). File paths are reduced to "
            "names unless the user opted into the 'full' share level."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute path to a file or folder."},
                "quarantine": {"type": "boolean", "description": "Quarantine high-confidence detections."},
            },
            "required": ["path"],
            "additionalProperties": False,
        },
        "handler": tool_scan_path,
    },
    {
        "name": "homeguard_list_quarantine",
        "description": (
            "List files currently held in HomeGuard's local quarantine vault, "
            "with the detection that caused each one and vault statistics."
        ),
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": tool_list_quarantine,
    },
    {
        "name": "homeguard_get_memory",
        "description": (
            "Recall what HomeGuard has learned about this network: notes "
            "the user has saved, device facts (label/trust/owner), and "
            "recent scan trend snapshots."
        ),
        "parameters": {"type": "object", "properties": {}, "additionalProperties": False},
        "handler": tool_get_memory,
    },
    {
        "name": "homeguard_save_memory_note",
        "description": (
            "Persist a short note into HomeGuard's local AI memory so "
            "future conversations remember it. Use for facts the user has "
            "confirmed, not speculation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["text"],
            "additionalProperties": False,
        },
        "handler": tool_save_memory_note,
    },
    {
        "name": "homeguard_record_device_fact",
        "description": (
            "Persist structured facts about a device (label/trust/owner) "
            "into HomeGuard's local AI memory. Fingerprints are hashed "
            "unless the user has opted into the 'full' share level."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "fingerprint": {"type": "string"},
                "label": {"type": "string"},
                "trust": {"type": "string", "enum": ["trusted", "quarantined", "unknown"]},
                "owner": {"type": "string"},
                "notes": {"type": "string"},
                "last_risk": {"type": "string"},
            },
            "required": ["fingerprint"],
            "additionalProperties": False,
        },
        "handler": tool_record_device_fact,
    },
]


def tool_definitions_openai() -> list[dict[str, Any]]:
    """OpenAI tool schema shape."""

    return [
        {
            "type": "function",
            "function": {
                "name": tool["name"],
                "description": tool["description"],
                "parameters": tool["parameters"],
            },
        }
        for tool in TOOLS
    ]


def tool_definitions_anthropic() -> list[dict[str, Any]]:
    """Anthropic tool schema shape."""

    return [
        {
            "name": tool["name"],
            "description": tool["description"],
            "input_schema": tool["parameters"],
        }
        for tool in TOOLS
    ]


def dispatch_tool(name: str, args: dict[str, Any], *, share_level: str) -> dict[str, Any]:
    handler = next((tool["handler"] for tool in TOOLS if tool["name"] == name), None)
    if handler is None:
        return {"error": f"Unknown tool: {name}"}
    try:
        return handler(args or {}, share_level)
    except Exception as exc:  # pragma: no cover - defensive against handler bugs
        return {"error": f"Tool '{name}' failed: {exc}"}

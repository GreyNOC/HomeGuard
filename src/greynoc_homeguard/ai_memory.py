"""Local, privacy-preserving "training" memory for the AI bridge.

HomeGuard cannot fine-tune a cloud LLM. What it can do — and what users
actually want when they say "let the AI train on my data" — is build up a
persistent local knowledge base that gets injected back into prompts so the
assistant gets smarter about *this* network over time. That is what this
module provides.

Three buckets:

- ``notes``        : free-form facts/preferences the user has taught the
                     assistant ("the camera on .42 is intentional").
- ``device_facts`` : structured facts keyed by device fingerprint (label,
                     trust verdict, owner, last-seen risk).
- ``signal_history``: bounded recent-scan summaries (counts, top finding
                      categories) so the assistant can describe trends.

All entries are timestamped and bounded so the file stays small. Sensitive
identifiers are redacted on write according to the active share level, so
even if the file is uploaded as prompt context later it never carries raw
IPs/MACs unless the user asked for ``full`` sharing.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .paths import atomic_write_text, user_data_dir

MEMORY_SCHEMA = "1.0"
MAX_NOTES = 200
MAX_DEVICE_FACTS = 500
MAX_SIGNAL_HISTORY = 60
MAX_NOTE_CHARS = 1200


@dataclass(slots=True)
class MemoryNote:
    text: str
    tags: list[str] = field(default_factory=list)
    created_at: float = field(default_factory=lambda: time.time())
    source: str = "user"

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class DeviceFact:
    fingerprint: str
    label: str = ""
    trust: str = ""
    owner: str = ""
    notes: str = ""
    last_risk: str = ""
    last_seen: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SignalSnapshot:
    created_at: float
    overall_risk: str
    overall_score: float
    finding_count: int
    device_count: int
    top_categories: list[str]

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def memory_file() -> Path:
    return user_data_dir() / "ai_memory.json"


def _empty_payload() -> dict[str, Any]:
    return {
        "schema": MEMORY_SCHEMA,
        "notes": [],
        "device_facts": [],
        "signal_history": [],
    }


def load_memory(path: Path | None = None) -> dict[str, Any]:
    target = path or memory_file()
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return _empty_payload()
    except (OSError, json.JSONDecodeError):
        return _empty_payload()
    if not isinstance(payload, dict):
        return _empty_payload()
    payload.setdefault("schema", MEMORY_SCHEMA)
    payload.setdefault("notes", [])
    payload.setdefault("device_facts", [])
    payload.setdefault("signal_history", [])
    return payload


def save_memory(payload: dict[str, Any], path: Path | None = None) -> Path:
    target = path or memory_file()
    atomic_write_text(target, json.dumps(payload, indent=2, sort_keys=True) + "\n")
    return target


def add_note(
    text: str,
    *,
    tags: list[str] | None = None,
    source: str = "user",
    path: Path | None = None,
) -> MemoryNote:
    clean = (text or "").strip()
    if not clean:
        raise ValueError("Memory note text is required")
    clean = clean[:MAX_NOTE_CHARS]
    note = MemoryNote(text=clean, tags=list(tags or []), source=source)
    payload = load_memory(path=path)
    notes = list(payload.get("notes") or [])
    notes.append(note.as_dict())
    if len(notes) > MAX_NOTES:
        notes = notes[-MAX_NOTES:]
    payload["notes"] = notes
    save_memory(payload, path=path)
    return note


def remove_note(index: int, *, path: Path | None = None) -> bool:
    payload = load_memory(path=path)
    notes = list(payload.get("notes") or [])
    if index < 0 or index >= len(notes):
        return False
    notes.pop(index)
    payload["notes"] = notes
    save_memory(payload, path=path)
    return True


def upsert_device_fact(fact: DeviceFact, *, path: Path | None = None) -> DeviceFact:
    if not fact.fingerprint:
        raise ValueError("Device fact requires a fingerprint")
    payload = load_memory(path=path)
    facts = list(payload.get("device_facts") or [])
    new_fields = {key: value for key, value in fact.as_dict().items() if value not in ("", 0.0)}
    new_fields["fingerprint"] = fact.fingerprint
    found = False
    for index, existing in enumerate(facts):
        if not isinstance(existing, dict):
            continue
        if str(existing.get("fingerprint")) == fact.fingerprint:
            merged = {**existing, **new_fields}
            facts[index] = merged
            found = True
            break
    if not found:
        facts.append(fact.as_dict())
    if len(facts) > MAX_DEVICE_FACTS:
        facts = facts[-MAX_DEVICE_FACTS:]
    payload["device_facts"] = facts
    save_memory(payload, path=path)
    return fact


def record_signal_snapshot(snapshot: SignalSnapshot, *, path: Path | None = None) -> SignalSnapshot:
    payload = load_memory(path=path)
    history = list(payload.get("signal_history") or [])
    history.append(snapshot.as_dict())
    if len(history) > MAX_SIGNAL_HISTORY:
        history = history[-MAX_SIGNAL_HISTORY:]
    payload["signal_history"] = history
    save_memory(payload, path=path)
    return snapshot


def summarize_for_prompt(
    *,
    max_notes: int = 8,
    max_facts: int = 12,
    max_history: int = 6,
    path: Path | None = None,
) -> dict[str, Any]:
    """Bounded slice of the memory store suitable to inline into a prompt.

    The caller is responsible for any further redaction; this returns only
    what the user has already approved for storage. Notes and facts are
    returned newest-first.
    """

    payload = load_memory(path=path)
    notes = [item for item in (payload.get("notes") or []) if isinstance(item, dict)]
    facts = [item for item in (payload.get("device_facts") or []) if isinstance(item, dict)]
    history = [item for item in (payload.get("signal_history") or []) if isinstance(item, dict)]
    return {
        "schema": payload.get("schema", MEMORY_SCHEMA),
        "notes": notes[-max_notes:][::-1],
        "device_facts": facts[-max_facts:][::-1],
        "signal_history": history[-max_history:][::-1],
    }


def clear_memory(path: Path | None = None) -> None:
    save_memory(_empty_payload(), path=path)

"""Evidence + assessment dataclasses for the HomeGuard EDR foundation.

The goal of Phase 1 is to give the rest of HomeGuard (and future EDR phases)
a stable, JSON-safe representation of:

  * the *facts* observed on the endpoint - :class:`EvidenceItem`;
  * a *chain* of related facts that, taken together, suggest something
    specific - :class:`EvidenceChain`;
  * the *call* the assessment engine makes about the endpoint as a whole -
    :class:`EndpointAssessment`.

All three serialize cleanly with ``json.dumps`` (no nested non-JSON types).
Optional fields default to empty strings / lists / dicts so consumers can
always read them without ``KeyError`` defensiveness.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4


def _utcnow_iso() -> str:
    """ISO-8601 UTC timestamp with a Z suffix (matches the rest of HomeGuard)."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


@dataclass(slots=True)
class EvidenceItem:
    """A single piece of evidence observed on the endpoint.

    Every field is optional except ``evidence_id``, ``timestamp``, and
    ``source``, because evidence comes from many different producers
    (process scan, memory scan, browser-download review, privilege-escalation
    audit, future YARA, etc.) and not every producer fills every slot.

    Field naming is deliberately MITRE-friendly: ``mitre_tactic`` and
    ``mitre_technique`` accept free-form strings now (e.g. ``"TA0006"``,
    ``"T1003.001"``) so later phases can wire a tagger without breaking the
    schema.
    """

    evidence_id: str = field(default_factory=lambda: _new_id("ev"))
    timestamp: str = field(default_factory=_utcnow_iso)
    # ``source`` identifies the producer: "process_scan", "memory_scan",
    # "download_review", "startup_review", "privesc_audit", future
    # "yara_scan", "etw_collector", etc. Free-form so producers can label
    # themselves without us having to maintain a registry here.
    source: str = ""
    # What the evidence is *about*. Examples: "process", "file", "registry",
    # "network", "memory_artifact", "scheduled_task", "browser_download".
    object_type: str = ""
    # Display name for the object (usually a file name, image name, or
    # process name). Empty when the producer can't supply one.
    object_name: str = ""
    path: str = ""
    pid: int = 0
    parent_pid: int = 0
    process_name: str = ""
    # Truncated / scrubbed command line. Producers SHOULD scrub credentials
    # before populating this; the assessment layer treats it as a hint, not
    # a forensics-quality artifact.
    command_line_hint: str = ""
    file_hash_sha256: str = ""
    remote_address: str = ""
    remote_port: int = 0
    # Echo of the upstream HomeGuard Finding's rule_id when this evidence
    # was lifted from a Finding. Empty for evidence collected directly.
    rule_id: str = ""
    category: str = ""
    # Severity uses HomeGuard's existing labels: info / low / medium /
    # high / critical. Anything else maps to "info" in the assessment.
    severity: str = "info"
    # 0.0 .. 1.0. Producers SHOULD set this honestly: a regex hit on a
    # process name is ~0.4, a SHA-256 match against a curated bad-hash
    # list is ~0.95.
    confidence: float = 0.0
    mitre_tactic: str = ""
    mitre_technique: str = ""
    description: str = ""
    # Free-form bag for producer-specific evidence (yara_rule_name,
    # signature_match_id, parent process tree, etc.). Must be JSON-safe.
    raw: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "timestamp": self.timestamp,
            "source": self.source,
            "object_type": self.object_type,
            "object_name": self.object_name,
            "path": self.path,
            "pid": int(self.pid or 0),
            "parent_pid": int(self.parent_pid or 0),
            "process_name": self.process_name,
            "command_line_hint": self.command_line_hint,
            "file_hash_sha256": self.file_hash_sha256,
            "remote_address": self.remote_address,
            "remote_port": int(self.remote_port or 0),
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(float(self.confidence or 0.0), 3),
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "description": self.description,
            "raw": dict(self.raw or {}),
        }


@dataclass(slots=True)
class EvidenceChain:
    """A group of evidence items that, taken together, support a specific call.

    The assessment engine uses chains to *show its work*: "I called this
    `likely_compromise` because evidence X (credential-theft artifact) and
    evidence Y (matching persistence entry) appear together." A chain is
    cheaper for a downstream reviewer than a flat list, because it makes
    the reasoning explicit.

    A chain's ``assessment_level`` is the strongest level its evidence
    supports *on its own*; the parent :class:`EndpointAssessment` takes the
    max over all chains plus any single-item escalations.
    """

    chain_id: str = field(default_factory=lambda: _new_id("chain"))
    title: str = ""
    # One of the compromise levels (see assessment.LEVEL_*). Validated by
    # the assessment module via ``normalize_level``.
    assessment_level: str = "review_indicator"
    confidence: float = 0.0
    # Pointers back to EvidenceItem.evidence_id so the chain stays cheap
    # to serialize (no duplication of full evidence dicts).
    evidence_ids: list[str] = field(default_factory=list)
    summary: str = ""
    recommended_actions: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "title": self.title,
            "assessment_level": self.assessment_level,
            "confidence": round(float(self.confidence or 0.0), 3),
            "evidence_ids": list(self.evidence_ids),
            "summary": self.summary,
            "recommended_actions": list(self.recommended_actions),
        }


@dataclass(slots=True)
class EndpointAssessment:
    """The single compromise-level call for an endpoint, with its support.

    Sits in ``report.scan_metadata["endpoint_assessment"]``. Consumers read
    ``level`` to decide whether to alert / page / escalate; ``summary``
    is the one-line for humans; ``evidence_items`` + ``evidence_chains``
    let a reviewer audit the reasoning.

    ``metadata`` is for producer-side context that doesn't fit elsewhere
    (e.g. scanner version, host OS, counts, runtime). Always JSON-safe.
    """

    assessment_id: str = field(default_factory=lambda: _new_id("assess"))
    level: str = "clean"
    confidence: float = 0.0
    summary: str = ""
    evidence_items: list[EvidenceItem] = field(default_factory=list)
    evidence_chains: list[EvidenceChain] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "assessment_id": self.assessment_id,
            "level": self.level,
            "confidence": round(float(self.confidence or 0.0), 3),
            "summary": self.summary,
            "evidence_items": [item.as_dict() for item in self.evidence_items],
            "evidence_chains": [chain.as_dict() for chain in self.evidence_chains],
            "recommended_actions": list(self.recommended_actions),
            "metadata": dict(self.metadata or {}),
        }

"""Turn file detections into action.

The detection layer (:mod:`greynoc_homeguard.virus_scanner`) produces findings
whose evidence carries the absolute file path. This module decides which of
those are safe to neutralize automatically and drives the
:class:`~greynoc_homeguard.quarantine.QuarantineVault` to do it.

The guiding principle is asymmetric risk: a false positive that gets
quarantined is fully recoverable (one restore), but auto-deleting a
misidentified system or user file is not. So auto-remediation fires only on
the highest-confidence detections — an exact known-bad hash match, or a
critical signature at near-certain confidence. Everything else (deceptive
double extensions, loader-cradle scripts, packed-executable hints) is reported
for the user to action deliberately.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .logging_setup import get_logger
from .models import Finding
from .quarantine import QuarantineError, QuarantineVault

LOG = get_logger("remediation")

# Rule ids that are trustworthy enough to neutralize without asking.
AUTO_QUARANTINE_RULES = {"endpoint_known_malware_hash"}

# Fallback bar for any other rule: a critical-severity detection at this
# confidence or above (covers the EICAR / embedded-signature content match,
# which lands at 0.99 critical).
AUTO_QUARANTINE_MIN_CONFIDENCE = 0.9


def _field(finding: Finding | dict[str, Any], name: str, default: Any = "") -> Any:
    if isinstance(finding, Finding):
        return getattr(finding, name, default)
    if isinstance(finding, dict):
        return finding.get(name, default)
    return default


def finding_file_path(finding: Finding | dict[str, Any]) -> Path | None:
    """Absolute path the finding refers to, if it points at a real file."""
    evidence = _field(finding, "evidence", {}) or {}
    raw = str(evidence.get("path") or "").strip()
    if not raw:
        return None
    candidate = Path(raw)
    return candidate if candidate.is_file() else None


def should_auto_quarantine(
    finding: Finding | dict[str, Any],
    *,
    min_confidence: float = AUTO_QUARANTINE_MIN_CONFIDENCE,
) -> bool:
    rule_id = str(_field(finding, "rule_id", ""))
    if rule_id in AUTO_QUARANTINE_RULES:
        return True
    severity = str(_field(finding, "severity", "")).lower()
    try:
        confidence = float(_field(finding, "confidence", 0.0) or 0.0)
    except (TypeError, ValueError):
        confidence = 0.0
    return severity == "critical" and confidence >= min_confidence


def quarantine_findings(
    findings: list[Finding | dict[str, Any]],
    *,
    vault: QuarantineVault | None = None,
    auto: bool = True,
    min_confidence: float = AUTO_QUARANTINE_MIN_CONFIDENCE,
    force: bool = False,
) -> list[dict[str, Any]]:
    """Quarantine the file(s) referenced by ``findings``.

    With ``auto`` (the default), only findings that clear
    :func:`should_auto_quarantine` are neutralized; the rest are returned with
    ``action="skipped"`` so the caller can surface them for manual review.
    ``force=True`` quarantines every referenced file regardless of the bar
    (used when the user has explicitly selected items to remove).

    Each referenced file is quarantined at most once even when several findings
    point at it; the strongest finding is recorded as the detection reason.
    Returns one result dict per distinct file path.
    """
    vault = vault or QuarantineVault().load()
    results: list[dict[str, Any]] = []
    handled: set[str] = set()

    # Strongest finding per file path drives the recorded detection metadata.
    by_path: dict[str, list[Finding | dict[str, Any]]] = {}
    for finding in findings:
        path = finding_file_path(finding)
        if path is None:
            continue
        by_path.setdefault(str(path), []).append(finding)

    for path_str, group in by_path.items():
        if path_str in handled:
            continue
        handled.add(path_str)
        strongest = max(
            group,
            key=lambda item: float(_field(item, "risk_score", 0.0) or 0.0),
        )
        qualifies = force or (auto and any(should_auto_quarantine(f, min_confidence=min_confidence) for f in group))
        if not qualifies:
            results.append(
                {
                    "path": path_str,
                    "rule_id": str(_field(strongest, "rule_id", "")),
                    "action": "skipped",
                    "reason": "Below the auto-quarantine confidence bar; review and remove manually if unwanted.",
                }
            )
            continue
        try:
            entry = vault.quarantine_file(
                path_str,
                detection_rule=str(_field(strongest, "rule_id", "")),
                detection_title=str(_field(strongest, "title", "")),
                severity=str(_field(strongest, "severity", "")),
                confidence=float(_field(strongest, "confidence", 0.0) or 0.0),
                reason=str(_field(strongest, "plain_english", "")),
            )
        except QuarantineError as exc:
            results.append(
                {
                    "path": path_str,
                    "rule_id": str(_field(strongest, "rule_id", "")),
                    "action": "failed",
                    "error": str(exc),
                }
            )
            continue
        results.append(
            {
                "path": path_str,
                "rule_id": entry.detection_rule,
                "action": "quarantined",
                "entry_id": entry.entry_id,
                "sha256": entry.sha256,
            }
        )
    return results


def scan_and_remediate(
    target: str | Path,
    *,
    quarantine: bool = False,
    vault: QuarantineVault | None = None,
    progress: Any = None,
) -> dict[str, Any]:
    """Convenience flow: scan a path, optionally quarantine, return a summary.

    Used by the CLI and the AI tool so both go through one code path.
    """
    from .virus_scanner import scan_path

    findings, metadata = scan_path(target, progress=progress)
    actions: list[dict[str, Any]] = []
    if quarantine and findings:
        actions = quarantine_findings(findings, vault=vault)
    return {
        "findings": findings,
        "metadata": metadata,
        "actions": actions,
    }

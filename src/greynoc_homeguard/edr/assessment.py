"""Compromise-level assessment for HomeGuard endpoint findings.

Phase 1 mapping is intentionally conservative. We translate existing
HomeGuard endpoint :class:`~greynoc_homeguard.models.Finding` objects into
:class:`~greynoc_homeguard.edr.models.EvidenceItem` records, build a small
number of evidence chains where the categories are obviously related, then
pick ONE compromise level for the endpoint as a whole.

Design constraints (review before changing):

  * Never overclaim. The summary strings are deliberately hedged
    ("Multiple related indicators *suggest* likely compromise") because
    HomeGuard does not have the runtime evidence (process tree, file hash
    lookup, EDR telemetry) to call confirmed compromise on weak signals.
  * Always show your work. Every level above ``clean`` MUST be backed by
    at least one :class:`EvidenceItem`, and ``confirmed_compromise``
    requires either a "strong" signal token (see ``_STRONG_SIGNAL_TOKENS``
    below) or an explicit ``raw`` metadata flag like ``yara_match`` /
    ``known_malicious_hash``.
  * Single-source-of-truth. ``ALL_LEVELS`` is the only place new levels
    are added; callers use :func:`normalize_level` to validate input.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from .models import EndpointAssessment, EvidenceChain, EvidenceItem


# ----- Compromise levels -----
# Order matters: higher index = more severe. ``level_rank`` reads this list,
# so changing the order changes the semantics. Append-only safe changes;
# inserting in the middle is a breaking change.

LEVEL_CLEAN = "clean"
LEVEL_REVIEW_INDICATOR = "review_indicator"
LEVEL_SUSPICIOUS_ACTIVITY = "suspicious_activity"
LEVEL_LIKELY_COMPROMISE = "likely_compromise"
LEVEL_CONFIRMED_COMPROMISE = "confirmed_compromise"
# Sentinel for "endpoint scan was disabled or failed". Not a real assessment.
LEVEL_NOT_RUN = "not_run"

ALL_LEVELS: tuple[str, ...] = (
    LEVEL_CLEAN,
    LEVEL_REVIEW_INDICATOR,
    LEVEL_SUSPICIOUS_ACTIVITY,
    LEVEL_LIKELY_COMPROMISE,
    LEVEL_CONFIRMED_COMPROMISE,
)


# Tokens we treat as strong, near-certain compromise signals when present in
# rule_id / category / raw evidence / description text. Lower-case match,
# substring is enough.
#
# Notes:
#   * "eicar" is intentionally included even though EICAR is a TEST string -
#     per the spec, an EICAR / internal scanner test signature should map to
#     ``confirmed_compromise``. The producer should write a clear description
#     so reviewers can tell test vs real.
#   * Tool names like "mimikatz" and "cobaltstrike" are diagnostic of
#     credential-dumping / red-team payload activity. We don't carry exploit
#     code; we just recognize the *signature* of one having run.
_STRONG_SIGNAL_TOKENS: tuple[str, ...] = (
    "eicar",
    "mimikatz",
    "cobaltstrike",
    "cobalt_strike",
    "lsass_dump",
    "lsass_dumping",
    "known_malicious_hash",
    "yara_match",
    "malware_payload",
    "ransomware_indicator",
)

# Tokens used to group evidence into "chains". Each entry maps a logical
# bucket (used in chain titles + level escalation rules below) to the
# substring tokens that put a piece of evidence into that bucket. Matching
# is substring-and-case-insensitive against rule_id, category, and the raw
# evidence keys/values.
_CATEGORY_BUCKETS: dict[str, tuple[str, ...]] = {
    "credential_theft": (
        "credential", "lsass", "mimikatz", "gpp", "password_dump",
        "autologon", "minidump",
    ),
    "memory_artifact": (
        "memory_artifact", "process_memory", "memory_scan", "in_memory",
        "process_dumping",
    ),
    "persistence": (
        "persistence", "autorun", "startup", "scheduled_task",
        "run_key", "service_install", "security_support_provider",
    ),
    "suspicious_command_line": (
        "suspicious_command", "powershell_obfuscation", "encodedcommand",
        "invoke-expression", "downloadstring", "script_obfuscation",
        "process_command",
    ),
    "malware_payload": (
        "malware_payload", "ransomware_indicator", "trojan", "rootkit",
        "backdoor", "rat_",
    ),
    "privilege_escalation": (
        "privesc", "always_install_elevated", "sensitive_privilege",
        "uac_bypass", "elevat",
    ),
    "exploit_artifact": (
        "exploit", "cve_", "kev_", "shellcode",
    ),
}

# Chains that, when present together, escalate the call. Each entry is a
# *frozenset* of bucket names that must all appear in evidence; the value
# is the level we escalate to and a short summary the chain inherits.
_RELATED_CHAIN_RULES: tuple[tuple[frozenset[str], str, str], ...] = (
    (
        frozenset({"credential_theft", "memory_artifact"}),
        LEVEL_LIKELY_COMPROMISE,
        "Credential-theft artifact observed alongside a process-memory signal.",
    ),
    (
        frozenset({"suspicious_command_line", "persistence"}),
        LEVEL_LIKELY_COMPROMISE,
        "A suspicious command line is paired with a persistence entry.",
    ),
    (
        frozenset({"malware_payload", "persistence"}),
        LEVEL_CONFIRMED_COMPROMISE,
        "Malware payload artifact is paired with persistence.",
    ),
    (
        frozenset({"credential_theft", "persistence"}),
        LEVEL_LIKELY_COMPROMISE,
        "Credential-theft artifact appears alongside persistence.",
    ),
    (
        frozenset({"suspicious_command_line", "memory_artifact"}),
        LEVEL_LIKELY_COMPROMISE,
        "Suspicious command line appears alongside an in-memory artifact.",
    ),
    (
        frozenset({"exploit_artifact", "persistence"}),
        LEVEL_LIKELY_COMPROMISE,
        "Exploit artifact appears alongside persistence.",
    ),
    (
        frozenset({"privilege_escalation", "credential_theft"}),
        LEVEL_LIKELY_COMPROMISE,
        "Privilege-escalation indicator overlaps with credential-theft evidence.",
    ),
)


_SEVERITY_ORDER = ("info", "low", "medium", "high", "critical")


_SUMMARY_BY_LEVEL: dict[str, str] = {
    LEVEL_CLEAN: "No endpoint compromise indicators were observed.",
    LEVEL_REVIEW_INDICATOR: "Review indicators were observed.",
    LEVEL_SUSPICIOUS_ACTIVITY: "Suspicious endpoint activity was observed.",
    LEVEL_LIKELY_COMPROMISE: "Multiple related indicators suggest likely compromise.",
    LEVEL_CONFIRMED_COMPROMISE: "High-confidence evidence supports confirmed compromise.",
    LEVEL_NOT_RUN: "Endpoint assessment was not run for this scan.",
}


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def normalize_level(value: Any) -> str:
    """Coerce arbitrary input to a known compromise level.

    Unknown / empty / non-string inputs become ``"clean"`` so downstream
    consumers never see a typo or stray value. ``"not_run"`` is preserved
    because it's a valid sentinel that callers explicitly set.
    """
    text = str(value or "").strip().lower()
    if text == LEVEL_NOT_RUN:
        return LEVEL_NOT_RUN
    if text in ALL_LEVELS:
        return text
    return LEVEL_CLEAN


def level_rank(level: Any) -> int:
    """Return a comparable integer for a compromise level.

    Higher = worse. ``not_run`` ranks 0 alongside ``clean`` so callers
    that compare against a threshold don't accidentally escalate for a
    scan that never ran. ``clean`` is rank 0, ``confirmed_compromise``
    is rank 4. Unknown values rank 0.
    """
    normalized = normalize_level(level)
    if normalized == LEVEL_NOT_RUN:
        return 0
    try:
        return ALL_LEVELS.index(normalized)
    except ValueError:
        return 0


def assess_endpoint_findings(
    findings: Iterable[Any],
    metadata: Mapping[str, Any] | None = None,
) -> EndpointAssessment:
    """Translate HomeGuard endpoint findings into a single :class:`EndpointAssessment`.

    The input ``findings`` is an iterable of HomeGuard ``Finding`` objects
    *or* finding-shaped dicts (``as_dict()`` output is fine). The function
    accepts both so callers can hand it the raw scan output without
    pre-converting.

    Behaviour:
      * No findings -> ``clean``.
      * Only info/low findings -> ``review_indicator``.
      * One high/critical finding alone -> ``suspicious_activity``.
      * High/critical findings whose buckets pair via ``_RELATED_CHAIN_RULES``
        -> ``likely_compromise`` (or ``confirmed_compromise`` when the rule
        targets that level).
      * Strong signal token (EICAR / mimikatz / yara_match / known
        malicious hash etc.) anywhere in the evidence -> ``confirmed_compromise``.
      * Explicit ``raw.yara_match`` or ``raw.known_malicious_hash`` keys
        force ``confirmed_compromise`` regardless of severity.
    """
    finding_list = list(findings or [])
    if not finding_list:
        return _empty_assessment(metadata)

    evidence_items: list[EvidenceItem] = [_finding_to_evidence(f) for f in finding_list]
    chains: list[EvidenceChain] = _build_evidence_chains(evidence_items)

    level, confidence, chain_summaries = _decide_level(evidence_items, chains)
    summary_parts = [_SUMMARY_BY_LEVEL.get(level, _SUMMARY_BY_LEVEL[LEVEL_REVIEW_INDICATOR])]
    if chain_summaries:
        summary_parts.append(" ".join(chain_summaries))
    summary = " ".join(summary_parts).strip()

    return EndpointAssessment(
        level=level,
        confidence=confidence,
        summary=summary,
        evidence_items=evidence_items,
        evidence_chains=chains,
        recommended_actions=_recommended_actions(level, evidence_items),
        metadata=_metadata_for(metadata, evidence_items, level),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _empty_assessment(metadata: Mapping[str, Any] | None) -> EndpointAssessment:
    return EndpointAssessment(
        level=LEVEL_CLEAN,
        confidence=0.95,  # we *observed* nothing, but we did look
        summary=_SUMMARY_BY_LEVEL[LEVEL_CLEAN],
        evidence_items=[],
        evidence_chains=[],
        recommended_actions=[],
        metadata=_metadata_for(metadata, [], LEVEL_CLEAN),
    )


def _finding_to_evidence(finding: Any) -> EvidenceItem:
    """Convert either a Finding object or a finding-shaped dict to evidence."""
    if hasattr(finding, "as_dict") and not isinstance(finding, dict):
        try:
            data: Mapping[str, Any] = finding.as_dict()
        except Exception:
            data = {}
    elif isinstance(finding, Mapping):
        data = finding
    else:
        data = {}

    evidence_blob = data.get("evidence") or {}
    if not isinstance(evidence_blob, Mapping):
        evidence_blob = {}

    return EvidenceItem(
        source="endpoint_scan",
        object_type=str(evidence_blob.get("object_type") or evidence_blob.get("artifact_type") or "endpoint_finding"),
        object_name=str(evidence_blob.get("object_name") or evidence_blob.get("artifact_name") or ""),
        path=str(evidence_blob.get("path") or evidence_blob.get("file") or ""),
        pid=_safe_int(evidence_blob.get("pid")),
        parent_pid=_safe_int(evidence_blob.get("parent_pid")),
        process_name=str(evidence_blob.get("process_name") or evidence_blob.get("image") or ""),
        command_line_hint=str(evidence_blob.get("command_line") or evidence_blob.get("command_line_hint") or "")[:512],
        file_hash_sha256=str(evidence_blob.get("sha256") or evidence_blob.get("file_hash_sha256") or ""),
        remote_address=str(evidence_blob.get("remote_address") or ""),
        remote_port=_safe_int(evidence_blob.get("remote_port")),
        rule_id=str(data.get("rule_id") or ""),
        category=str(data.get("category") or ""),
        severity=_normalize_severity(str(data.get("severity") or "info")),
        confidence=_safe_float(data.get("confidence"), default=0.0),
        mitre_tactic=str(evidence_blob.get("mitre_tactic") or ""),
        mitre_technique=str(evidence_blob.get("mitre_technique") or ""),
        description=str(data.get("plain_english") or data.get("title") or ""),
        raw=dict(evidence_blob) if evidence_blob else {},
    )


def _normalize_severity(value: str) -> str:
    text = (value or "").strip().lower()
    return text if text in _SEVERITY_ORDER else "info"


def _safe_int(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _safe_float(value: Any, *, default: float = 0.0) -> float:
    try:
        return float(value if value is not None else default)
    except (TypeError, ValueError):
        return default


def _buckets_for(item: EvidenceItem) -> set[str]:
    """Return the category-bucket names this evidence triggers."""
    haystack_parts = [
        (item.rule_id or "").lower(),
        (item.category or "").lower(),
        (item.description or "").lower(),
        (item.command_line_hint or "").lower(),
        " ".join(str(v) for v in (item.raw or {}).values()).lower(),
        " ".join((item.raw or {}).keys()).lower(),
    ]
    haystack = " ".join(haystack_parts)
    matches: set[str] = set()
    for bucket, tokens in _CATEGORY_BUCKETS.items():
        if any(token in haystack for token in tokens):
            matches.add(bucket)
    return matches


def _is_strong_signal(item: EvidenceItem) -> bool:
    """True when the evidence carries a near-certain compromise marker."""
    raw = item.raw or {}
    # Producers can set explicit boolean / non-empty flags to short-circuit.
    if raw.get("yara_match") or raw.get("known_malicious_hash"):
        return True
    haystack = " ".join(
        [
            (item.rule_id or "").lower(),
            (item.category or "").lower(),
            (item.description or "").lower(),
            (item.object_name or "").lower(),
            (item.process_name or "").lower(),
            (item.file_hash_sha256 or "").lower(),
            " ".join(str(v) for v in raw.values()).lower(),
            " ".join(str(k) for k in raw.keys()).lower(),
        ]
    )
    return any(token in haystack for token in _STRONG_SIGNAL_TOKENS)


def _build_evidence_chains(items: list[EvidenceItem]) -> list[EvidenceChain]:
    """Group evidence into chains and tag each chain with the level it implies."""
    bucket_to_items: dict[str, list[EvidenceItem]] = {}
    for item in items:
        for bucket in _buckets_for(item):
            bucket_to_items.setdefault(bucket, []).append(item)

    chains: list[EvidenceChain] = []
    used_buckets: set[frozenset[str]] = set()

    for required_buckets, escalated_level, summary in _RELATED_CHAIN_RULES:
        if required_buckets in used_buckets:
            continue
        if not required_buckets.issubset(bucket_to_items.keys()):
            continue
        evidence_for_chain: list[EvidenceItem] = []
        for bucket in required_buckets:
            evidence_for_chain.extend(bucket_to_items[bucket])
        # De-dupe by evidence_id while preserving order.
        seen: set[str] = set()
        ordered: list[EvidenceItem] = []
        for evidence in evidence_for_chain:
            if evidence.evidence_id in seen:
                continue
            seen.add(evidence.evidence_id)
            ordered.append(evidence)
        confidence = min(0.95, max(0.4, max((e.confidence for e in ordered), default=0.4) + 0.1))
        chains.append(
            EvidenceChain(
                title=" + ".join(sorted(required_buckets)),
                assessment_level=escalated_level,
                confidence=confidence,
                evidence_ids=[e.evidence_id for e in ordered],
                summary=summary,
                recommended_actions=_recommended_actions(escalated_level, ordered),
            )
        )
        used_buckets.add(required_buckets)
    return chains


def _decide_level(
    items: list[EvidenceItem],
    chains: list[EvidenceChain],
) -> tuple[str, float, list[str]]:
    """Pick the final level + confidence + chain summary strings to surface."""
    strong = [item for item in items if _is_strong_signal(item)]
    chain_summaries = [c.summary for c in chains if c.summary]

    # Strong signal short-circuits everything else.
    if strong:
        # Confidence: weighted to the strongest individual confidence but
        # clamped so a single low-confidence "eicar" string doesn't claim
        # 0.99. Producers can push higher with explicit raw flags.
        max_conf = max((s.confidence for s in strong), default=0.0)
        confidence = min(0.99, max(0.85, max_conf))
        return LEVEL_CONFIRMED_COMPROMISE, confidence, chain_summaries

    # Any chain at confirmed_compromise (only fired by the malware_payload +
    # persistence rule today, but extensible).
    confirmed_chains = [c for c in chains if normalize_level(c.assessment_level) == LEVEL_CONFIRMED_COMPROMISE]
    if confirmed_chains:
        confidence = min(0.95, max(0.7, max(c.confidence for c in confirmed_chains)))
        return LEVEL_CONFIRMED_COMPROMISE, confidence, chain_summaries

    # Any chain at likely_compromise.
    likely_chains = [c for c in chains if normalize_level(c.assessment_level) == LEVEL_LIKELY_COMPROMISE]
    if likely_chains:
        confidence = min(0.9, max(0.55, max(c.confidence for c in likely_chains)))
        return LEVEL_LIKELY_COMPROMISE, confidence, chain_summaries

    # Multiple high/critical findings without a related-chain match still
    # warrant likely_compromise (the producer found unrelated severe things,
    # which is also a bad signal).
    high_or_critical = [
        item for item in items if item.severity in {"high", "critical"}
    ]
    if len(high_or_critical) >= 3:
        avg_conf = sum(item.confidence for item in high_or_critical) / len(high_or_critical)
        return LEVEL_LIKELY_COMPROMISE, min(0.85, max(0.5, avg_conf + 0.1)), chain_summaries

    if high_or_critical:
        max_conf = max(item.confidence for item in high_or_critical)
        return LEVEL_SUSPICIOUS_ACTIVITY, min(0.8, max(0.4, max_conf)), chain_summaries

    # Everything else - info / low / medium without a related chain - is a
    # review indicator. We intentionally don't promote medium to suspicious
    # because medium findings include "device hint matched" and similar
    # advisory signals.
    if any(item.severity == "medium" for item in items):
        max_conf = max(item.confidence for item in items)
        return LEVEL_REVIEW_INDICATOR, min(0.6, max(0.25, max_conf)), chain_summaries

    if items:
        max_conf = max(item.confidence for item in items)
        return LEVEL_REVIEW_INDICATOR, min(0.5, max(0.2, max_conf)), chain_summaries

    return LEVEL_CLEAN, 0.95, chain_summaries


def _recommended_actions(level: str, items: list[EvidenceItem]) -> list[str]:
    """Per-level remediation hints. Kept short; reports / GUI can render verbatim."""
    if level == LEVEL_CLEAN or level == LEVEL_NOT_RUN:
        return []
    if level == LEVEL_REVIEW_INDICATOR:
        return [
            "Review the listed indicators in the HomeGuard report; act if any are unexpected.",
        ]
    if level == LEVEL_SUSPICIOUS_ACTIVITY:
        return [
            "Investigate the listed finding(s) on this host before scheduling another scan.",
            "Run a Microsoft Defender full scan to confirm.",
        ]
    if level == LEVEL_LIKELY_COMPROMISE:
        return [
            "Treat this host as untrusted until reviewed; disconnect from sensitive networks.",
            "Run a Microsoft Defender full scan and review startup / scheduled-task entries.",
            "Rotate any credentials that may have been entered on this host.",
        ]
    if level == LEVEL_CONFIRMED_COMPROMISE:
        return [
            "Isolate this host from the network now.",
            "Preserve the report JSON for incident response before any reboot or remediation.",
            "Rotate every credential that has been entered on this host.",
            "Plan a clean reimage; restore data only from a known-good backup.",
        ]
    return []


def _metadata_for(
    metadata: Mapping[str, Any] | None,
    items: list[EvidenceItem],
    level: str,
) -> dict[str, Any]:
    """Carry caller-supplied metadata + counts useful for downstream UI / logging."""
    payload: dict[str, Any] = {}
    if isinstance(metadata, Mapping):
        # Only keep JSON-safe primitives + nested dicts/lists. We don't deep-copy;
        # callers are expected to hand us already-safe values.
        for key, value in metadata.items():
            if isinstance(value, (str, int, float, bool, list, dict)) or value is None:
                payload[str(key)] = value
    counts_by_severity: dict[str, int] = {sev: 0 for sev in _SEVERITY_ORDER}
    for item in items:
        counts_by_severity[item.severity] = counts_by_severity.get(item.severity, 0) + 1
    payload.setdefault("evidence_count", len(items))
    payload.setdefault("evidence_by_severity", counts_by_severity)
    payload.setdefault("assessment_level", level)
    payload.setdefault("phase", "edr_phase_1")
    return payload


# Compile-time regex sanity check: ensure no _STRONG_SIGNAL_TOKENS slip in as
# regex metacharacters (we use plain substring match, not regex - this is a
# pure assertion for future-proofing).
for _token in _STRONG_SIGNAL_TOKENS:
    if re.search(r"[\\^$.|?*+()\[\]{}]", _token):
        raise RuntimeError(
            f"_STRONG_SIGNAL_TOKENS contains a regex metacharacter: {_token!r}. "
            "Strong-signal matching is substring-only; update the matcher if you "
            "need regex support."
        )

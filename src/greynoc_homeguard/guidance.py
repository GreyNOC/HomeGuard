"""Consumer-facing guidance helpers for HomeGuard reports.

These helpers keep HomeGuard's user-facing language calm, consistent, and honest
about what a local home-network scan can and cannot prove. A passive scan sees
open ports, names, and catalog matches -- it observes *indicators*, not proof of
compromise. The wording here exists so that detection, the report model, and the
report renderers all share one phrasing instead of drifting apart.

This module is intentionally dependency-free (it imports nothing from the rest of
the package and uses duck typing for the report object) so that ``detection``,
``models``, and ``reports`` can all import it without creating import cycles.
"""

from __future__ import annotations

from typing import Any

# Short caveat appended to an individual finding whose evidence is an indicator
# (an open port, a name match, a CVE catalog hit) rather than confirmation.
INDICATOR_NOTE = (
    "This is an indicator to review, not proof of compromise -- confirm it before taking action."
)

# Longer global disclaimer shown near the top of every report.
REPORT_DISCLAIMER = (
    "HomeGuard reports indicators for review, not proof of compromise. "
    "Each item is something to check; confirm a finding before you act on it."
)

# Quarantine in HomeGuard is a label in your own records, not network isolation.
QUARANTINE_NOTE = (
    "Quarantine in HomeGuard flags a device in your reports; it does not block the "
    "device by itself. To actually cut a device off, block it on your router or change "
    "your WiFi password."
)

# Phrases that already carry an "indicator, not proof" caveat. If a finding's text
# already contains one of these, ``with_indicator_note`` leaves it alone so we never
# stack two caveats on the same sentence.
_ALREADY_HEDGED = (
    "not proof of compromise",
    "cannot prove",
    "indicator, not proof",
    "port-only scan",
    "patch-priority hint",
)


def with_indicator_note(text: str) -> str:
    """Append the standard indicator caveat once, idempotently.

    Returns ``text`` unchanged when it already explains its own evidence limits,
    so detectors that are already carefully worded (KEV hints, the unusual-service
    note) do not end up with a redundant second caveat.
    """

    base = (text or "").rstrip()
    if not base:
        return INDICATOR_NOTE
    lowered = base.lower()
    if any(marker in lowered for marker in _ALREADY_HEDGED):
        return base
    separator = " " if base.endswith((".", "!", "?")) else ". "
    return f"{base}{separator}{INDICATOR_NOTE}"


# Practical, non-technical action groups, in the order a home user should work
# through them. ``priority_actions`` only emits the groups that actually apply.
_ACTION_GROUPS: list[dict[str, str]] = [
    {
        "key": "review_flagged",
        "action": "Review devices you flagged",
        "detail": "Check the devices you marked as quarantined and decide whether to block them on your router.",
    },
    {
        "key": "identify_unknown",
        "action": "Identify unknown devices",
        "detail": "Make sure every device on your network is one you or your household recognizes.",
    },
    {
        "key": "disable_services",
        "action": "Turn off services you do not use",
        "detail": "Disable remote-access or file-sharing features that are switched on but unused.",
    },
    {
        "key": "update_software",
        "action": "Update firmware and software",
        "detail": "Install the latest updates for the devices HomeGuard flagged for patching.",
    },
    {
        "key": "keep_definitions_current",
        "action": "Keep security definitions current",
        "detail": "Use Update Definitions regularly so new CVE and security rules stay available.",
    },
]

_GROUP_ORDER = {group["key"]: index for index, group in enumerate(_ACTION_GROUPS)}

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

_CURRENT_DEFINITION_STATES = {"", "current", "ok", "up-to-date", "up to date", "fresh", "updated"}


def _group_for_finding(finding: Any) -> str | None:
    """Map a single finding to one practical action group (or None)."""

    rule_id = str(getattr(finding, "rule_id", "") or "")
    category = str(getattr(finding, "category", "") or "")

    if rule_id == "quarantined_device" or category == "device_trust":
        return "review_flagged"
    if (
        rule_id in {"new_device", "missing_mac", "possible_unauthorized_access", "hostname_collision"}
        or rule_id.startswith("custom_hostname")
        or rule_id.startswith("custom_mac")
        or category in {"device_inventory", "user_custom_rule"}
    ):
        return "identify_unknown"
    if (
        rule_id.startswith("risky_port")
        or rule_id in {"many_open_ports", "remote_admin_cluster", "possible_malware_service"}
        or category in {"exposed_service", "unusual_service"}
    ):
        return "disable_services"
    if (
        rule_id == "default_name_hint"
        or category in {"known_exploited_vulnerability", "security_update", "device_hardening"}
    ):
        return "update_software"
    return None


def priority_actions(report: Any) -> list[dict[str, Any]]:
    """Derive a short, calm "what should I do first?" list from a report.

    Groups the report's existing findings (and quarantine/definition metadata)
    into a handful of plain-language actions, ordered by urgency. Nothing here
    invents a new action: every entry summarizes findings the engine already
    produced. The closing "keep definitions current" reminder is always present
    so the list ends on a calm maintenance step.
    """

    findings = list(getattr(report, "findings", []) or [])
    metadata = getattr(report, "scan_metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    counts: dict[str, int] = {}
    worst: dict[str, int] = {}
    for finding in findings:
        group = _group_for_finding(finding)
        if group is None:
            continue
        counts[group] = counts.get(group, 0) + 1
        rank = _SEVERITY_RANK.get(str(getattr(finding, "severity", "info")).lower(), 0)
        worst[group] = max(worst.get(group, 0), rank)

    # A device can be quarantined in your records even when it is not active in
    # this scan, so count the metadata list too and treat it as high urgency.
    quarantined = metadata.get("quarantined_devices")
    if isinstance(quarantined, list) and quarantined:
        counts["review_flagged"] = max(counts.get("review_flagged", 0), len(quarantined))
        worst["review_flagged"] = max(worst.get("review_flagged", 0), _SEVERITY_RANK["high"])

    def_status = metadata.get("definition_status")
    update_status = ""
    if isinstance(def_status, dict):
        update_status = str(def_status.get("update_status") or "").strip().lower()
    definitions_stale = update_status not in _CURRENT_DEFINITION_STATES

    ranked: list[tuple[int, int, dict[str, Any]]] = []
    for group in _ACTION_GROUPS:
        key = group["key"]
        if key == "keep_definitions_current":
            rank = _SEVERITY_RANK["medium"] if definitions_stale else _SEVERITY_RANK["info"]
            ranked.append((rank, _GROUP_ORDER[key], {**group, "count": 0}))
            continue
        count = counts.get(key, 0)
        if count <= 0:
            continue
        ranked.append((worst.get(key, 0), _GROUP_ORDER[key], {**group, "count": count}))

    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [
        {"action": entry["action"], "detail": entry["detail"], "count": entry["count"]}
        for _, _, entry in ranked
    ]

"""Helpers that refine accuracy signals on the network map.

The discovery pipeline (``noc_core.discovery``) computes a per-device
confidence score from a single source's snapshot.  Once the map builder
in ``noc_core.network_mapper`` folds in additional sources -- the
network inventory, finding evidence, the device hunter, radio scans --
that snapshot score no longer reflects how strongly the device is
corroborated.  This module centralizes the post-merge accuracy logic:

* :func:`is_valid_mac` filters MAC addresses that cannot uniquely
  identify a device (broadcast, multicast, null) and therefore must
  not be used as a dedup key.
* :func:`is_randomized_mac` detects privacy-randomized
  (locally-administered) MACs so the UI can flag the identity as
  unstable.
* :func:`distinct_method_categories` groups discovery methods into
  *independent* evidence categories so a device confirmed by three
  flavors of mDNS does not look as strong as one confirmed by ARP +
  TCP + mDNS.
* :func:`source_count` is a cheap integer the UI can display to expose
  how many distinct methods agreed on the device.
* :func:`recompute_confidence` recomputes the 0.05..0.99 score from
  the final merged device dict, so the score reflects every signal we
  managed to gather rather than just the first.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

_HEX_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
_NULL_MAC = "00:00:00:00:00:00"
_BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


DIRECT_METHODS = frozenset({
    "arp",
    "arp-probe",
    "neighbor-cache",
    "dhcp-lease",
    "router-dhcp",
    "default-gateway",
    "dhcp-server",
    "icmp",
    "local-host",
})
MULTICAST_METHODS = frozenset({"mdns", "ssdp", "ws-discovery", "llmnr", "nbns"})
RADIO_METHODS = frozenset({"bluetooth", "bluetooth-pnp", "wifi-bssid", "radio"})
INFERENCE_METHODS = frozenset({
    "inferred-accessory",
    "inferred-remote",
    "historical-scan",
})
TCP_METHOD_PREFIXES = ("tcp/", "tcp-")


def _norm_methods(device: Mapping[str, Any]) -> set[str]:
    return {
        str(item).strip().lower()
        for item in device.get("discovered_by") or []
        if str(item or "").strip()
    }


def is_valid_mac(value: str = "") -> bool:
    """Return ``True`` if *value* is a syntactically valid MAC that can
    serve as a unique device identifier.

    Broadcast (``ff:ff:ff:ff:ff:ff``), null (``00:00:00:00:00:00``),
    and multicast MACs (LSB of the first octet set) are rejected
    because they often appear in noisy ARP/neighbor-cache reads and
    would otherwise pollute the merge key, causing unrelated devices
    to collapse into one row.
    """
    clean = (value or "").strip().lower()
    if not _HEX_MAC_RE.match(clean):
        return False
    if clean in {_BROADCAST_MAC, _NULL_MAC}:
        return False
    return not bool(int(clean[:2], 16) & 0x01)


def is_randomized_mac(value: str = "") -> bool:
    """Return ``True`` if *value* is a locally-administered MAC.

    iOS, Android, and Windows rotate the MAC per-network for privacy.
    Such addresses are valid for the current session but should not be
    treated as a stable identity; we lower the identity confidence to
    surface this in the UI.
    """
    if not is_valid_mac(value):
        return False
    return bool(int(value.strip().lower()[:2], 16) & 0x02)


def distinct_method_categories(methods: Iterable[str]) -> set[str]:
    """Group discovery methods into independent evidence categories.

    Two ``mdns`` flavors are not independent corroboration; ``arp`` +
    ``mdns`` + ``tcp/80`` are.  The returned set drives the diversity
    bonus in :func:`recompute_confidence`.
    """
    categories: set[str] = set()
    for raw in methods:
        method = str(raw or "").strip().lower()
        if not method:
            continue
        if method in DIRECT_METHODS:
            categories.add("direct")
        elif method in MULTICAST_METHODS:
            categories.add("multicast")
        elif method in RADIO_METHODS:
            categories.add("radio")
        elif method.startswith(TCP_METHOD_PREFIXES):
            categories.add("tcp")
        elif method in INFERENCE_METHODS:
            categories.add("inferred")
        else:
            categories.add("other")
    return categories


def source_count(device: Mapping[str, Any]) -> int:
    """Distinct discovery methods that confirmed *device*."""
    return len(_norm_methods(device))


def recompute_confidence(device: Mapping[str, Any]) -> float:
    """Recompute the 0.05..0.99 confidence score for a merged device.

    Layered scoring:

    1. **Identity** -- IP, valid MAC, hostname, vendor each contribute.
    2. **Liveness/observation** -- ports plus the strongest method
       family seen (direct, multicast, TCP probe, radio).
    3. **Diversity bonus** -- independent corroboration is the
       strongest accuracy signal we have in a passive map.
    4. **Randomized-MAC penalty** -- privacy-rotated MACs reduce
       identity confidence because they cannot be matched across
       scans.

    Inferred devices (accessories, historical replays) are capped at
    0.35 -- they should never look as confident as a directly observed
    host.
    """
    methods = _norm_methods(device)
    ports = {
        int(port)
        for port in (device.get("open_ports") or device.get("ports") or [])
        if str(port).isdigit()
    }
    ip = str(device.get("ip") or "")
    raw_mac = str(device.get("mac") or "")
    mac_valid = is_valid_mac(raw_mac)
    mac_randomized = is_randomized_mac(raw_mac) if mac_valid else False
    hostname = str(device.get("hostname") or "")
    vendor = str(device.get("vendor") or "")
    evidence = str(device.get("evidence_level") or "direct").strip().lower()

    if evidence == "inferred" or methods & INFERENCE_METHODS:
        score = 0.18
        if device.get("parent_device_id"):
            score += 0.08
        if hostname:
            score += 0.04
        return round(min(0.35, score), 2)

    score = 0.15
    if ip:
        score += 0.20
    if mac_valid:
        score += 0.25
    if hostname:
        score += 0.10
    if vendor:
        score += 0.05
    if ports:
        score += 0.15
    if methods & DIRECT_METHODS:
        score += 0.20
    if methods & MULTICAST_METHODS:
        score += 0.18
    if any(method.startswith(TCP_METHOD_PREFIXES) for method in methods):
        score += 0.18
    if methods & RADIO_METHODS:
        score += 0.10

    diversity = max(0, len(distinct_method_categories(methods)) - 1)
    score += min(0.10, diversity * 0.04)

    if "bluetooth-pnp" in methods and not ip:
        score = max(score, 0.55)
    if ip and mac_valid and (
        methods & DIRECT_METHODS
        or any(method.startswith(TCP_METHOD_PREFIXES) for method in methods)
    ):
        score = max(score, 0.86)
    if ip and methods & MULTICAST_METHODS:
        score = max(score, 0.72)

    if mac_randomized:
        score -= 0.08

    return round(max(0.05, min(0.99, score)), 2)

"""Unified device identity resolution layer.

HomeGuard's device-resolution work has historically been split between the
vendored discovery engine (which gives us hostnames from arp/mDNS/SSDP/DHCP/
reverse-DNS/NetBIOS) and ``device_resolution.py`` (which classifies type +
synthesizes a fallback hostname when a MAC is present). The GUI, reports,
and known-device baseline have all wanted a single, evidence-tracked
identity record per device:

  * what the hostname is, where it came from, and whether it was synthesized;
  * a friendly display name even when there's no real hostname AND no MAC
    (for those, the fingerprint stays IP-based and we never overwrite
    ``device.hostname`` -- but the GUI/report can still show a readable
    label instead of a bare IP);
  * the resolved vendor and which lookup table produced it;
  * the resolved device type, its confidence, AND the signal that drove it
    (mDNS service, vendor default, port fingerprint, etc.);
  * a serializable evidence map so the baseline and report layers can
    explain the decision without rerunning resolution.

This module is the single place where all of that lives. It builds on the
existing ``device_resolution`` classifier (port + vendor + hostname patterns)
and adds:

  * A hostname priority chain (discovery / DHCP / mDNS / NetBIOS / reverse-DNS
    / SSDP / synthesized) that records the winning source.
  * Friendly-name generation that ALWAYS produces a readable label, including
    for MAC-less devices. Crucially, the synthesized label is only written
    back to ``device.hostname`` when the device has a MAC -- otherwise the
    fingerprint key (which falls back to hostname for MAC-less devices) would
    silently shift between scans.
  * mDNS / SSDP service classification on top of the existing port-based
    classifier (printers, TVs, Sonos, HomeKit, Matter, Roku, Chromecast,
    AirPlay, ONVIF cameras, NAS, consoles).
  * Vendor source tracking (engine / local-OUI / extended-OUI).

The contract:

  ``resolve_device(device)`` mutates ``device`` in place, writes every
  resolved field into ``device.metadata``, and returns the device. The
  fields are documented in :class:`IdentityResolution`.

Backwards compatibility:
  * ``device.fingerprint()`` behavior is unchanged.
  * Existing ``device_resolution.classify_device`` / ``extended_vendor_from_mac``
    keep working; this module imports them.
  * Devices without a MAC keep ``device.hostname`` blank (so their
    fingerprint stays ``ip:...``) but get a friendly display name in
    ``metadata.friendly_name``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .device_resolution import (
    EXTENDED_OUI,
    HOSTNAME_TYPE_PATTERNS,
    KNOWN_DEVICE_TYPES,
    PORT_SIGNATURES,
    VENDOR_TO_TYPE,
    classify_device,
    extended_vendor_from_mac,
)
from .models import Device


# Hostname source labels. Kept short so they round-trip cleanly through
# baseline.json / reports without escaping concerns.
SOURCE_DISCOVERY = "discovery"
SOURCE_DHCP = "dhcp"
SOURCE_MDNS = "mdns"
SOURCE_NETBIOS = "netbios"
SOURCE_REVERSE_DNS = "reverse_dns"
SOURCE_SSDP = "ssdp"
SOURCE_SYNTHESIZED = "synthesized"
SOURCE_UNRESOLVED = ""

ALL_HOSTNAME_SOURCES = (
    SOURCE_DISCOVERY,
    SOURCE_DHCP,
    SOURCE_MDNS,
    SOURCE_NETBIOS,
    SOURCE_REVERSE_DNS,
    SOURCE_SSDP,
    SOURCE_SYNTHESIZED,
)

# Mapping from engine ``discovered_by`` tokens to our normalized hostname sources.
DISCOVERED_BY_TO_HOSTNAME_SOURCE: dict[str, str] = {
    "router-dhcp": SOURCE_DHCP,
    "dhcp": SOURCE_DHCP,
    "mdns": SOURCE_MDNS,
    "ws-discovery": SOURCE_MDNS,
    "netbios": SOURCE_NETBIOS,
    "reverse-dns": SOURCE_REVERSE_DNS,
    "ssdp": SOURCE_SSDP,
}


# Service tokens we recognize from mDNS / SSDP / engine.services. Each entry
# maps a normalized token to a (device_type, weight, label) triple. Weights
# are relative to the existing port/hostname/vendor signal weights in
# ``device_resolution.classify_device`` (port matches max out around 0.55).
SERVICE_TYPE_SIGNATURES: tuple[tuple[re.Pattern[str], str, float, str], ...] = (
    # Printers
    (re.compile(r"_ipp\._tcp|_ipps\._tcp|_printer\._tcp|_pdl-datastream\._tcp|\bipp\b", re.I),
     "printer", 0.65, "mdns:_ipp._tcp"),
    # Streaming sticks / smart TVs
    (re.compile(r"_googlecast\._tcp|googlecast|chromecast", re.I),
     "tv", 0.62, "mdns:_googlecast._tcp"),
    (re.compile(r"_airplay\._tcp|_raop\._tcp|airplay", re.I),
     "tv", 0.55, "mdns:_airplay._tcp"),
    (re.compile(r"_roku-ecp\._tcp|roku", re.I),
     "tv", 0.6, "service:roku"),
    (re.compile(r"_dial-multiscreen-org\._tcp|dial multiscreen", re.I),
     "tv", 0.55, "mdns:dial"),
    (re.compile(r"mediarenderer|media renderer", re.I),
     "tv", 0.5, "ssdp:MediaRenderer"),
    # Sonos / speakers -- HomeGuard taxonomy collapses speakers into iot.
    (re.compile(r"_sonos\._tcp|sonos", re.I),
     "iot", 0.55, "mdns:_sonos._tcp"),
    (re.compile(r"_spotify-connect\._tcp", re.I),
     "iot", 0.45, "mdns:_spotify-connect._tcp"),
    # HomeKit / Matter / generic IoT hubs
    (re.compile(r"_hap\._tcp|homekit", re.I),
     "iot", 0.6, "mdns:_hap._tcp"),
    (re.compile(r"_matter\._tcp|_matterc\._tcp|matter", re.I),
     "iot", 0.6, "mdns:_matter._tcp"),
    (re.compile(r"_hue\._tcp|philips hue|hue bridge", re.I),
     "iot", 0.55, "mdns:hue"),
    # Cameras (ONVIF + RTSP services)
    (re.compile(r"_rtsp\._tcp|onvif|axis_video", re.I),
     "camera", 0.62, "service:onvif/rtsp"),
    # NAS
    (re.compile(r"_smb\._tcp|_afpovertcp\._tcp|_nfs\._tcp|_adisk\._tcp", re.I),
     "nas", 0.55, "mdns:nas-services"),
    # Game consoles
    (re.compile(r"xbox live|_xbox._tcp|_playstation\._tcp|_nintendo\._tcp|_nintendoswitch", re.I),
     "console", 0.6, "service:console"),
    # Phones / Apple-mobile devices
    (re.compile(r"_companion-link\._tcp|_apple-mobdev2\._tcp|_apple-mobdev\._tcp|_carplay\._tcp", re.I),
     "phone", 0.55, "mdns:apple-mobile"),
    (re.compile(r"_androidtvremote2\._tcp", re.I),
     "tv", 0.5, "mdns:_androidtvremote2._tcp"),
    # Workstations / laptops
    (re.compile(r"_smb\._tcp.*work|_workstation\._tcp|_device-info\._tcp", re.I),
     "laptop", 0.4, "mdns:_workstation._tcp"),
)


# SSDP "ST" header fingerprints. Matched against the joined services /
# device_hints text.
SSDP_TYPE_SIGNATURES: tuple[tuple[re.Pattern[str], str, float, str], ...] = (
    (re.compile(r"InternetGatewayDevice|WANIPConnection|WANConnectionDevice", re.I),
     "router", 0.65, "ssdp:InternetGatewayDevice"),
    (re.compile(r"upnp:rootdevice.*router", re.I),
     "router", 0.4, "ssdp:rootdevice-router"),
)


@dataclass(slots=True)
class IdentityResolution:
    """Resolved identity record for a single :class:`Device`.

    Mirrored into ``device.metadata`` by :func:`resolve_device` so the
    baseline / GUI / report layers can read it without recomputing.
    """

    real_hostname: str = ""
    friendly_name: str = ""
    hostname_source: str = SOURCE_UNRESOLVED
    hostname_synthesized: bool = False
    resolved_vendor: str = ""
    vendor_source: str = ""
    resolved_device_type: str = "unknown"
    resolved_device_type_confidence: float = 0.0
    device_type_source: str = ""
    resolution_evidence: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "real_hostname": self.real_hostname,
            "friendly_name": self.friendly_name,
            "hostname_source": self.hostname_source,
            "hostname_synthesized": self.hostname_synthesized,
            "resolved_vendor": self.resolved_vendor,
            "vendor_source": self.vendor_source,
            "resolved_device_type": self.resolved_device_type,
            "resolved_device_type_confidence": self.resolved_device_type_confidence,
            "device_type_source": self.device_type_source,
            "resolution_evidence": dict(self.resolution_evidence),
        }


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _str_list(value: Any) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value if item]
    if isinstance(value, str) and value:
        return [value]
    return []


def _slug(value: str) -> str:
    return re.sub(r"-+", "-", re.sub(r"[^a-z0-9]+", "-", str(value or "").lower())).strip("-")


def _hostname_source_from_discovered_by(discovered_by: Iterable[str]) -> str:
    """Best-guess hostname source from the engine's ``discovered_by`` list.

    The engine doesn't tag the hostname with the source that supplied it, so
    we use ``discovered_by`` priority order: a device discovered via mDNS
    almost certainly got its hostname from mDNS, etc.
    """
    tokens = [str(item).lower() for item in discovered_by]
    # Priority order matters: DHCP > mDNS > NetBIOS > reverse-DNS > SSDP > other.
    for preferred in ("router-dhcp", "dhcp", "mdns", "netbios", "reverse-dns", "ssdp"):
        if preferred in tokens:
            return DISCOVERED_BY_TO_HOSTNAME_SOURCE.get(preferred, SOURCE_DISCOVERY)
    return SOURCE_DISCOVERY


def _service_text(device: Device) -> str:
    """Joined haystack of every service / hint token attached to the device."""
    metadata = device.metadata or {}
    services = _str_list(metadata.get("services"))
    hints = _str_list(metadata.get("device_hints"))
    discovered_by = _str_list(metadata.get("discovered_by"))
    # ssdp_fields / mdns_services may be passed in by upstream callers that
    # preserve raw protocol output; we walk them defensively.
    ssdp_fields = metadata.get("ssdp_fields")
    if isinstance(ssdp_fields, dict):
        services.extend(str(v) for v in ssdp_fields.values() if v)
    mdns_services = metadata.get("mdns_services")
    if isinstance(mdns_services, list):
        services.extend(str(v) for v in mdns_services if v)
    return " ".join(services + hints + discovered_by).lower()


def _vendor_lookup(device: Device) -> tuple[str, str]:
    """Return (vendor, source).

    Source values: "engine" (vendor came in on the device already),
    "extended_oui" (matched the in-package OUI table), or "" if unknown.
    The local network.py ``COMMON_VENDOR_PREFIXES`` table is consulted by
    the bridge layer before this runs, so by the time we get here ``vendor``
    already reflects the engine + local lookup result.
    """
    if device.vendor:
        return device.vendor, "engine"
    if device.mac_address:
        candidate = extended_vendor_from_mac(device.mac_address)
        if candidate:
            return candidate, "extended_oui"
    return "", ""


def _classify_with_services(device: Device) -> tuple[str, float, str, dict[str, Any]]:
    """Run the upstream classifier and then layer mDNS/SSDP service signals.

    Returns ``(device_type, confidence, source, evidence_signals)``.
    """
    # Start with the existing port / vendor / hostname / engine-guess classifier.
    base_type, base_conf = classify_device(device)
    signals: dict[str, Any] = {}
    # Re-run the port + hostname + vendor weighting to grab the *winning*
    # source label, mirroring the upstream classifier but tracking provenance.
    scored: dict[str, dict[str, Any]] = {}

    def _add(kind: str, weight: float, source_label: str, detail: str = "") -> None:
        entry = scored.setdefault(
            kind,
            {"score": 0.0, "sources": [], "primary_source": "", "primary_weight": 0.0},
        )
        entry["score"] += weight
        if source_label and source_label not in entry["sources"]:
            entry["sources"].append(source_label)
        # "Primary" source = the single signal that contributed the most
        # weight to this type. mDNS / port signatures should beat the much
        # weaker vendor_default fallback when they both fire for the same
        # type.
        if source_label and weight > entry["primary_weight"]:
            entry["primary_weight"] = weight
            entry["primary_source"] = source_label
        if detail:
            signals.setdefault("details", []).append(detail)

    metadata = device.metadata or {}
    engine_guess = str(metadata.get("device_type_guess") or "").strip().lower()
    if engine_guess:
        from .device_resolution import _normalize_engine_type  # local alias
        mapped = _normalize_engine_type(engine_guess)
        if mapped:
            _add(mapped, 0.6, "engine_guess", f"engine_type_guess={engine_guess}")

    hostname = (device.hostname or "").strip()
    if hostname:
        for pattern, kind, weight in HOSTNAME_TYPE_PATTERNS:
            if pattern.search(hostname):
                _add(kind, weight, "hostname_pattern", f"hostname~/{pattern.pattern}/")
                break

    vendor_key = (device.vendor or "").strip().lower()
    if vendor_key:
        for needle, kind in VENDOR_TO_TYPE.items():
            if needle in vendor_key:
                _add(kind, 0.35, "vendor_default", f"vendor={vendor_key}")
                break

    ports: set[int] = set()
    for port in device.open_ports or []:
        try:
            ports.add(int(port))
        except (TypeError, ValueError):
            continue
    for required, kind, weight in PORT_SIGNATURES:
        if required.issubset(ports):
            _add(kind, weight, "port_signature", f"ports={sorted(required)}")

    ip = (device.ip or "").strip()
    if ip and (ip.endswith(".1") or ip.endswith(".254")):
        boost = 0.5 if 53 in ports else 0.3
        _add("router", boost, "ip_position", f"ip_ends_in_1_or_254")

    # mDNS / SSDP service signals
    service_blob = _service_text(device)
    if service_blob:
        for pattern, kind, weight, label in SERVICE_TYPE_SIGNATURES:
            if pattern.search(service_blob):
                _add(kind, weight, "mdns_service", label)
        for pattern, kind, weight, label in SSDP_TYPE_SIGNATURES:
            if pattern.search(service_blob):
                _add(kind, weight, "ssdp_field", label)

    if not scored:
        return ("unknown", 0.0, "", {"signals": []})

    # Pick highest-scoring type.
    best_kind, best_entry = max(scored.items(), key=lambda kv: kv[1]["score"])
    if best_kind not in KNOWN_DEVICE_TYPES or best_kind == "unknown":
        return ("unknown", 0.0, "", {"signals": list(scored.keys())})

    raw_score = best_entry["score"]
    confidence = round(min(0.99, raw_score), 2)
    # Primary source = the signal that contributed the most weight to the
    # winner. Falls back to the first contributor if (somehow) no primary
    # weight got recorded.
    source = best_entry.get("primary_source") or (best_entry["sources"][0] if best_entry["sources"] else "")
    evidence = {
        "scores": {k: round(v["score"], 2) for k, v in scored.items()},
        "sources": {k: list(v["sources"]) for k, v in scored.items()},
        "details": list(signals.get("details") or []),
    }
    # Reconcile with base_type from upstream classify_device: if upstream
    # picked a stronger type (shouldn't happen now that we re-weighted, but
    # defend against drift), prefer the higher confidence.
    if base_conf > confidence and base_type in KNOWN_DEVICE_TYPES and base_type != "unknown":
        return (base_type, base_conf, source or "device_resolution", evidence)
    return (best_kind, confidence, source, evidence)


def _friendly_name_from_signals(device: Device, resolved_type: str) -> str:
    """Build a friendly display name. Always non-empty when device has an IP."""
    ip = (device.ip or "").strip()
    vendor = (device.vendor or "").strip().lower()
    vendor_slug = _slug(vendor) if vendor else ""
    type_slug = resolved_type if resolved_type and resolved_type != "unknown" else ""
    suffix = ""
    if "." in ip:
        suffix = ip.rsplit(".", 1)[-1]
    elif ip:
        suffix = re.sub(r"[^a-z0-9]+", "-", ip.lower())[-6:]

    parts: list[str] = []
    if vendor_slug:
        parts.append(vendor_slug)
    if type_slug:
        parts.append(type_slug)
    if suffix:
        parts.append(suffix)

    if parts:
        return re.sub(r"-+", "-", "-".join(parts)).strip("-")
    if ip:
        return f"unknown-device-{re.sub(r'[^a-z0-9]+', '-', ip.lower())}"
    return "unknown-device"


def _candidate_hostnames_from_metadata(metadata: dict[str, Any]) -> list[tuple[str, str]]:
    """Return [(hostname, source), ...] candidates from metadata, in priority order.

    Order:
      1. dhcp_hostname
      2. mdns_friendly_name / mdns_name
      3. netbios_name
      4. reverse_dns_name
      5. ssdp_friendly_name / ssdp_model

    Each entry is added only if non-empty.
    """
    candidates: list[tuple[str, str]] = []
    pairs = (
        (SOURCE_DHCP, ("dhcp_hostname",)),
        (SOURCE_MDNS, ("mdns_friendly_name", "mdns_name", "mdns_instance")),
        (SOURCE_NETBIOS, ("netbios_name", "netbios_workstation")),
        (SOURCE_REVERSE_DNS, ("reverse_dns_name", "reverse_dns_hostname")),
        (SOURCE_SSDP, ("ssdp_friendly_name", "ssdp_model_name", "ssdp_server")),
    )
    for source, keys in pairs:
        for key in keys:
            value = str(metadata.get(key) or "").strip()
            if value:
                candidates.append((value, source))
                break
    return candidates


def resolve_device(device: Device) -> Device:
    """Apply full identity resolution to ``device``, writing into metadata.

    Sets the following metadata keys (using strings only so JSON round-trips):

      * ``real_hostname``           - the human-supplied / discovered hostname
                                      if any; empty when only a friendly fallback
                                      exists.
      * ``friendly_name``           - always populated when the device has an IP.
                                      Used by the GUI / report as a display label.
      * ``hostname_source``         - one of: discovery, dhcp, mdns, netbios,
                                      reverse_dns, ssdp, synthesized, "".
      * ``hostname_synthesized``    - True when ``device.hostname`` was set to
                                      a synthesized fallback (only happens when
                                      the device has a MAC).
      * ``resolved_vendor``         - the vendor we settled on (mirrors
                                      ``device.vendor`` after enrichment).
      * ``vendor_source``           - "engine", "extended_oui", or "".
      * ``resolved_device_type``    - one of HomeGuard's ten taxonomy types.
      * ``resolved_device_type_confidence`` - 0.0..0.99.
      * ``device_type_source``      - signal label, e.g. "mdns_service",
                                      "port_signature", "vendor_default".
      * ``resolution_evidence``     - dict with classifier scores and signal
                                      detail strings, for the GUI tooltip /
                                      report explanation.

    Crucially, ``device.fingerprint()`` behavior is preserved:
      * MAC-bearing devices keep their MAC-based fingerprint; we can safely
        synthesize a hostname into ``device.hostname``.
      * MAC-less devices keep ``device.hostname`` blank if it was blank; we
        only populate ``metadata.friendly_name`` so they read well in the UI
        without ever changing their fingerprint key.
    """
    metadata = device.metadata if isinstance(device.metadata, dict) else {}
    device.metadata = metadata

    record = IdentityResolution()
    discovered_by = _str_list(metadata.get("discovered_by"))

    # ------- Vendor -------
    vendor, vendor_source = _vendor_lookup(device)
    if vendor and not device.vendor:
        device.vendor = vendor
    record.resolved_vendor = device.vendor or ""
    record.vendor_source = vendor_source

    # ------- Hostname priority chain -------
    real_hostname = (device.hostname or "").strip()
    hostname_source = SOURCE_UNRESOLVED
    if real_hostname:
        hostname_source = _hostname_source_from_discovered_by(discovered_by)
    else:
        for candidate, source in _candidate_hostnames_from_metadata(metadata):
            real_hostname = candidate
            hostname_source = source
            # Promote the discovered hostname onto device.hostname when we have a
            # stable fingerprint key (MAC). Otherwise we leave it on metadata so
            # the fingerprint stays IP-anchored.
            if device.mac_address:
                device.hostname = candidate
            break

    record.real_hostname = real_hostname
    record.hostname_source = hostname_source

    # ------- Classification (uses hostname + ports + vendor + mdns/ssdp signals) -------
    kind, confidence, source, evidence = _classify_with_services(device)
    record.resolved_device_type = kind
    record.resolved_device_type_confidence = confidence
    record.device_type_source = source

    # ------- Friendly name (always populate when we have an IP) -------
    if real_hostname:
        record.friendly_name = real_hostname
    else:
        record.friendly_name = _friendly_name_from_signals(device, kind)

    # ------- Synthesize device.hostname only when MAC is present -------
    if not device.hostname and device.mac_address:
        synthesized = record.friendly_name
        if synthesized:
            device.hostname = synthesized
            record.hostname_synthesized = True
            record.hostname_source = SOURCE_SYNTHESIZED

    # ------- Build evidence dict -------
    record.resolution_evidence = {
        "discovered_by": list(discovered_by),
        "services": _str_list(metadata.get("services")),
        "device_hints": _str_list(metadata.get("device_hints")),
        "classifier": evidence,
        "ports": sorted(set(int(p) for p in (device.open_ports or []) if str(p).strip().isdigit())),
        "ip": device.ip or "",
        "mac": device.mac_address or "",
    }

    # ------- Mirror onto metadata for downstream consumers -------
    payload = record.as_dict()
    for key, value in payload.items():
        metadata[key] = value
    # Keep the legacy keys from device_resolution.py populated too so the
    # baseline-store auto-classify path (which looks at ``resolved_device_type``
    # in metadata) keeps working without modification.
    metadata.setdefault("resolved_device_type", record.resolved_device_type)
    metadata.setdefault("resolved_device_type_confidence", record.resolved_device_type_confidence)
    if record.hostname_synthesized:
        metadata["hostname_synthesized"] = True
    if record.vendor_source == "extended_oui":
        metadata.setdefault("resolved_vendor", record.resolved_vendor)
    return device


def resolve_devices(devices: Iterable[Device]) -> list[Device]:
    """Apply :func:`resolve_device` to every device in the iterable."""
    return [resolve_device(d) for d in devices]


def identity_from_metadata(metadata: dict[str, Any]) -> IdentityResolution:
    """Reconstruct an :class:`IdentityResolution` from a stored metadata dict.

    Used by reports / GUI to read a resolved identity off a baseline row or
    saved device JSON without re-running ``resolve_device``.
    """
    if not isinstance(metadata, dict):
        return IdentityResolution()
    return IdentityResolution(
        real_hostname=str(metadata.get("real_hostname") or ""),
        friendly_name=str(metadata.get("friendly_name") or ""),
        hostname_source=str(metadata.get("hostname_source") or SOURCE_UNRESOLVED),
        hostname_synthesized=bool(metadata.get("hostname_synthesized")),
        resolved_vendor=str(metadata.get("resolved_vendor") or ""),
        vendor_source=str(metadata.get("vendor_source") or ""),
        resolved_device_type=str(metadata.get("resolved_device_type") or "unknown"),
        resolved_device_type_confidence=float(metadata.get("resolved_device_type_confidence") or 0.0),
        device_type_source=str(metadata.get("device_type_source") or ""),
        resolution_evidence=dict(metadata.get("resolution_evidence") or {}),
    )


def display_name_for(device: Device) -> str:
    """Return the best label for a device for display in GUI / reports.

    Falls back through: real hostname → metadata.friendly_name →
    synthesized → vendor → IP. Always returns something readable when the
    device has any identifying info.
    """
    metadata = device.metadata if isinstance(device.metadata, dict) else {}
    real = (device.hostname or "").strip()
    if real and not metadata.get("hostname_synthesized"):
        return real
    friendly = str(metadata.get("friendly_name") or "").strip()
    if friendly:
        return friendly
    if real:
        return real
    if device.vendor:
        suffix = device.ip.rsplit(".", 1)[-1] if "." in (device.ip or "") else (device.ip or "")
        slug = _slug(device.vendor)
        return f"{slug}-{suffix}" if suffix else slug
    return device.ip or "unknown-device"

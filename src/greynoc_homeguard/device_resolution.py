"""Strong device + host resolution algorithm.

The vendored ``_noc_core`` discovery engine produces rich classification
output (per-device ``type`` and OUI-based ``vendor``), but the bridge into
HomeGuard's ``Device`` model historically dropped the type and overrode the
engine vendor with a tiny local OUI table. ``BaselineStore.update`` then
defaulted every fresh record to ``device_type="unknown"`` until the user
hand-labeled it. The net effect was the Devices view showing "unknown" for
every device and "-" for almost every hostname.

This module implements the bridge:

  * ``classify_device(device)`` — multi-signal weighted scoring over vendor,
    hostname patterns, open-port fingerprints, IP position, and the engine's
    own type guess. Maps to HomeGuard's constrained taxonomy and returns a
    ``(device_type, confidence)`` tuple. Returns ``("unknown", 0.0)`` only
    when no signal triggers — never silently picks a type.

  * ``synthesize_hostname(device)`` — friendly fallback name (vendor + type +
    IP last-octet) for devices that have a MAC (stable fingerprint) but no
    real hostname from reverse DNS / NBNS / mDNS. Devices without a MAC are
    intentionally left blank because synthesizing a hostname there would
    shift the device's fingerprint and create duplicate baseline records.

  * ``extended_vendor_from_mac(mac)`` — secondary OUI lookup used only when
    both the engine and ``network.COMMON_VENDOR_PREFIXES`` returned blank.

  * ``resolve_device(device)`` — apply the above to a Device in place,
    writing ``resolved_device_type``, ``resolved_device_type_confidence``,
    and ``resolved_vendor`` into ``device.metadata`` so the baseline can
    consume them on update without overwriting user labels.
"""

from __future__ import annotations

import re
from typing import Iterable

from .models import Device


# Constrained taxonomy used by the UI / BaselineStore. Anything we resolve to
# outside this set is collapsed back to "unknown" so the UI stays consistent.
KNOWN_DEVICE_TYPES: frozenset[str] = frozenset(
    {"phone", "laptop", "tv", "console", "iot", "router", "camera", "nas", "printer", "unknown"}
)


# Map the engine's richer vocabulary into the constrained taxonomy.
ENGINE_TYPE_MAP: dict[str, str] = {
    "router": "router",
    "gateway": "router",
    "access-point": "router",
    "ap": "router",
    "camera": "camera",
    "ipcam": "camera",
    "doorbell": "camera",
    "tv": "tv",
    "smart-tv": "tv",
    "streaming-box": "tv",
    "media-renderer": "tv",
    "set-top": "tv",
    "game-console": "console",
    "console": "console",
    "printer": "printer",
    "scanner": "printer",
    "storage": "nas",
    "nas": "nas",
    "phone": "phone",
    "smartphone": "phone",
    "tablet": "phone",
    "workstation": "laptop",
    "laptop": "laptop",
    "desktop": "laptop",
    "computer": "laptop",
    "speaker": "iot",
    "iot-hub": "iot",
    "iot": "iot",
    "smart-home": "iot",
    "wearable": "iot",
    "remote": "iot",
    "thermostat": "iot",
    "sensor": "iot",
    "bulb": "iot",
    "light": "iot",
    "plug": "iot",
}


# Secondary OUI table. Consulted only when the engine vendor and
# network.COMMON_VENDOR_PREFIXES both return blank. Curated for the most
# common consumer / SOHO devices a home user would meet. Lower-case, 6 hex.
EXTENDED_OUI: dict[str, str] = {
    # Apple
    "001124": "Apple", "002241": "Apple", "0023df": "Apple", "002608": "Apple",
    "087045": "Apple", "0c3e9f": "Apple", "14109f": "Apple", "1499e2": "Apple",
    "186590": "Apple", "1c1ac0": "Apple", "1c5cf2": "Apple", "24a160": "Apple",
    "286c07": "Apple", "286ab8": "Apple", "28cfe9": "Apple", "2c1f23": "Apple",
    "404d7f": "Apple", "503275": "Apple", "684a76": "Apple", "703ed9": "Apple",
    "70cd60": "Apple", "78fd94": "Apple", "7c11be": "Apple", "844167": "Apple",
    "84788b": "Apple", "8c2937": "Apple", "8c8590": "Apple", "9027e4": "Apple",
    "9803a7": "Apple", "9c84bf": "Apple", "a4c361": "Apple", "a4f1e8": "Apple",
    "ac61ea": "Apple", "b418d1": "Apple", "b48b19": "Apple", "b4e62d": "Apple",
    "b853ac": "Apple", "bc92b1": "Apple", "c4b301": "Apple", "c869cd": "Apple",
    "d0034b": "Apple", "d49a20": "Apple", "d8bb2c": "Apple", "dc2b2a": "Apple",
    "f0dbe2": "Apple", "f0db30": "Apple", "f8e94e": "Apple",
    # Samsung
    "00d0e5": "Samsung", "1007b6": "Samsung", "5c497d": "Samsung", "78d6f0": "Samsung",
    "8425db": "Samsung", "a08cfd": "Samsung", "bcd11f": "Samsung", "ccf9e8": "Samsung",
    "d850e6": "Samsung", "e8508b": "Samsung", "ec1f72": "Samsung", "f02f4b": "Samsung",
    "fcf528": "Samsung",
    # Google / Nest / Pixel
    "001a11": "Google", "2c3033": "Google", "f4f5d8": "Google", "f4f5db": "Google",
    "f4f5e8": "Google", "3c5a37": "Google", "18b430": "Nest", "64166d": "Nest",
    "00d8af": "Nest",
    # Amazon Echo / Fire / Ring / Kindle
    "0c47c9": "Amazon", "1c1b68": "Amazon", "44650d": "Amazon", "a0023f": "Amazon",
    "a8e2c1": "Amazon", "ac63be": "Amazon", "b478c1": "Amazon", "f0d2f1": "Amazon",
    "fc65de": "Amazon",
    # Roku
    "6c5ab0": "Roku", "78d75f": "Roku", "8c1f64": "Roku", "8c90d3": "Roku",
    "ac3a7a": "Roku", "b0a737": "Roku", "b83e59": "Roku", "cc6da0": "Roku",
    "d83134": "Roku",
    # Sonos
    "0011fc": "Sonos", "5cb1f4": "Sonos", "7828ca": "Sonos", "94f8ac": "Sonos",
    "b8e937": "Sonos",
    # TP-Link
    "001d0f": "TP-Link", "0c80e7": "TP-Link", "1027f5": "TP-Link", "30b5c2": "TP-Link",
    "50c7bf": "TP-Link", "60a4b7": "TP-Link", "84d81b": "TP-Link", "8c86dd": "TP-Link",
    "8c902d": "TP-Link", "a40bc8": "TP-Link", "a840f8": "TP-Link", "c83a35": "TP-Link",
    "d80d17": "TP-Link", "ec086b": "TP-Link", "f4f26d": "TP-Link",
    # Netgear
    "001b2f": "Netgear", "00224d": "Netgear", "20e52a": "Netgear", "30469a": "Netgear",
    "3498b5": "Netgear", "44a56e": "Netgear", "4c60de": "Netgear", "9c3dcf": "Netgear",
    # Linksys
    "001839": "Linksys", "00146c": "Linksys", "001a70": "Linksys", "002129": "Linksys",
    "20aa4b": "Linksys", "488d36": "Linksys", "6038e0": "Linksys", "98fc11": "Linksys",
    # ASUS
    "04d4c4": "ASUS", "0c9d92": "ASUS", "1c872c": "ASUS", "2c4d54": "ASUS",
    "38d547": "ASUS", "4cedfb": "ASUS", "50465d": "ASUS", "60a44c": "ASUS",
    "7085c2": "ASUS",
    # Ubiquiti
    "0418d6": "Ubiquiti", "245a4c": "Ubiquiti", "44d9e7": "Ubiquiti", "688f84": "Ubiquiti",
    "74acb9": "Ubiquiti", "78a351": "Ubiquiti", "802aa8": "Ubiquiti", "b4fbe4": "Ubiquiti",
    "dc9fdb": "Ubiquiti", "f09fc2": "Ubiquiti", "fcecda": "Ubiquiti",
    # Wyze
    "2cab33": "Wyze", "2cd141": "Wyze", "7c78b2": "Wyze", "b8782e": "Wyze",
    # Hikvision / Dahua / common camera vendors
    "001296": "Hikvision", "00408c": "Hikvision", "0c1163": "Hikvision",
    "44197f": "Hikvision", "4ca164": "Hikvision", "9cb5cd": "Hikvision",
    "9cf6dd": "Hikvision", "bc15a6": "Hikvision",
    "0c41d3": "Dahua", "3c001a": "Dahua", "3c001c": "Dahua", "ac76ea": "Dahua",
    # Microsoft / Xbox
    "001dd8": "Microsoft", "00125a": "Microsoft", "30595b": "Microsoft", "382dd1": "Microsoft",
    "583e94": "Microsoft", "60450d": "Microsoft", "70d4f2": "Microsoft", "98a4ad": "Microsoft",
    "c83f26": "Microsoft", "dc537c": "Microsoft", "ec8eb5": "Microsoft", "002f47": "Xbox",
    # Sony / PlayStation
    "001fa7": "Sony", "00041f": "Sony", "001315": "Sony", "fc0fe6": "Sony",
    "001dba": "Sony", "70269d": "Sony", "a8e3ee": "Sony",
    # Nintendo
    "0009bf": "Nintendo", "0017ab": "Nintendo", "001f32": "Nintendo", "00214d": "Nintendo",
    "002709": "Nintendo", "344b50": "Nintendo", "586b14": "Nintendo", "78a2a0": "Nintendo",
    "98e8fa": "Nintendo",
    # LG
    "001e75": "LG", "002197": "LG", "2c54cf": "LG", "346895": "LG", "606bbd": "LG",
    "947e8c": "LG", "a039f7": "LG", "c8087b": "LG", "e851a0": "LG", "f80cf3": "LG",
    # HP / Brother / Canon / Xerox (printers)
    "001321": "HP", "001cc4": "HP", "002655": "HP", "00306e": "HP", "104f58": "HP",
    "1cc1de": "HP", "30e171": "HP", "382c4a": "HP", "3464a9": "HP", "3ce5a6": "HP",
    "6cc217": "HP", "7c2f80": "HP", "7c4a82": "HP", "a0481c": "HP", "a4b197": "HP",
    "b0aa36": "HP", "b499ba": "HP", "ccbbfe": "HP", "d4c9ef": "HP",
    "001b78": "Brother", "0080a1": "Brother", "0080d3": "Brother", "001ba9": "Brother",
    "30055c": "Brother", "30c9ab": "Brother",
    "0000aa": "Xerox", "0080d4": "Canon", "001be1": "Canon",
    # Raspberry Pi
    "b827eb": "Raspberry Pi", "dca632": "Raspberry Pi", "e45f01": "Raspberry Pi",
    # Intel
    "f0d5bf": "Intel", "0c8bfd": "Intel", "001302": "Intel", "001ef7": "Intel",
    "08d40c": "Intel", "0c54a5": "Intel", "10e7c6": "Intel",
    # D-Link
    "001e58": "D-Link", "0050ba": "D-Link", "1cbdb9": "D-Link", "1cafa7": "D-Link",
    "1cbb78": "D-Link", "1c5f2b": "D-Link", "3c1e04": "D-Link", "78321b": "D-Link",
    "84c9b2": "D-Link", "c8d3a3": "D-Link", "ccb255": "D-Link",
    # Belkin / Wemo
    "000ae5": "Belkin", "001150": "Belkin", "0017f2": "Belkin", "001cdf": "Belkin",
    "08863b": "Belkin", "149182": "Belkin", "9415d7": "Belkin", "ec1a59": "Belkin",
    # Eero
    "049129": "Eero", "84d6d0": "Eero", "f81d0f": "Eero",
    # Synology / Withings / Tuya / Espressif / Sonoff
    "001132": "Synology", "0024e4": "Withings", "7c49eb": "Tuya", "84f3eb": "Tuya",
    "5cf370": "Espressif", "8caab5": "Espressif", "84cca8": "Sonoff",
}


# Vendor (lower-case) → most likely device_type. Ambiguous vendors map to a
# default; the per-device classifier still considers ports + hostname so this
# is a soft signal, not an override.
VENDOR_TO_TYPE: dict[str, str] = {
    "wyze": "camera",
    "hikvision": "camera",
    "dahua": "camera",
    "ring": "camera",
    "nest": "iot",
    "google": "iot",
    "amazon": "iot",
    "roku": "tv",
    "sonos": "iot",
    "tp-link": "router",
    "netgear": "router",
    "linksys": "router",
    "asus": "router",
    "ubiquiti": "router",
    "eero": "router",
    "d-link": "router",
    "belkin": "iot",
    "hp": "printer",
    "brother": "printer",
    "canon": "printer",
    "xerox": "printer",
    "samsung": "phone",       # phone OR TV; ports tip the balance
    "apple": "phone",         # phone OR laptop; ports tip the balance
    "microsoft": "laptop",
    "xbox": "console",
    "sony": "console",        # PlayStation OR TV; ports tip the balance
    "nintendo": "console",
    "lg": "tv",
    "synology": "nas",
    "raspberry pi": "iot",
    "withings": "iot",
    "intel": "laptop",
    "tuya": "iot",
    "espressif": "iot",
    "sonoff": "iot",
}


# Open-port → device_type fingerprints. Each entry is a frozenset of ports
# that MUST all be open for the signature to fire, paired with the inferred
# type and a confidence weight. Weights are tuned so a single strong signal
# (e.g. RTSP/554 = camera) beats a single weak one (e.g. SSH/22 = laptop).
PORT_SIGNATURES: tuple[tuple[frozenset[int], str, float], ...] = (
    (frozenset({554}), "camera", 0.55),
    (frozenset({8554}), "camera", 0.55),
    (frozenset({8009}), "tv", 0.50),       # Chromecast
    (frozenset({8060}), "tv", 0.50),       # Roku ECP
    (frozenset({7000}), "tv", 0.45),       # AirPlay
    (frozenset({1400}), "iot", 0.50),      # Sonos
    (frozenset({1883}), "iot", 0.45),      # MQTT
    (frozenset({8883}), "iot", 0.45),      # MQTTS
    (frozenset({3074}), "console", 0.55),  # Xbox Live
    (frozenset({9295}), "console", 0.45),  # PSN/console
    (frozenset({9308}), "console", 0.45),
    (frozenset({631}), "printer", 0.55),   # IPP
    (frozenset({9100}), "printer", 0.55),  # JetDirect
    (frozenset({515}), "printer", 0.45),   # LPD
    (frozenset({548}), "nas", 0.45),       # AFP
    (frozenset({2049}), "nas", 0.50),      # NFS
    (frozenset({5001}), "nas", 0.40),      # Synology / iperf
    (frozenset({445, 139}), "laptop", 0.45),  # SMB (Windows)
    (frozenset({62078}), "phone", 0.50),   # iPhone sync
    (frozenset({53}), "router", 0.25),     # DNS resolver alone is weak
)


HOSTNAME_TYPE_PATTERNS: tuple[tuple[re.Pattern[str], str, float], ...] = (
    (re.compile(r"\b(router|gateway|edgemax|usg|ubnt|unifi|orbi|deco|asuswrt|eero)\b", re.I), "router", 0.6),
    (re.compile(r"\b(camera|ipcam|cam[\-_]?\d|doorbell|nestcam|wyzecam)\b", re.I), "camera", 0.6),
    (re.compile(r"\b(iphone|ipad|android|pixel|galaxy[\-_]?(s|note|a)\d|oneplus|xiaomi|redmi|oppo|vivo)\b", re.I), "phone", 0.55),
    (re.compile(r"\b(tv|roku|chromecast|appletv|firetv|shield|webos|tizen|bravia|vizio|hisense|androidtv)\b", re.I), "tv", 0.55),
    (re.compile(r"\b(xbox|playstation|ps[345]|switch|nintendo|wii)\b", re.I), "console", 0.6),
    (re.compile(r"\b(printer|brother|laserjet|officejet|envy|deskjet|epson|canon|xerox)\b", re.I), "printer", 0.55),
    (re.compile(r"\b(nas|synology|qnap|drobo|truenas|freenas|diskstation)\b", re.I), "nas", 0.6),
    (re.compile(r"\b(echo|alexa|nest|hub|thermostat|bulb|sonoff|tuya|smartlife|matter|sonos|smartthings)\b", re.I), "iot", 0.5),
    (re.compile(r"\b(laptop|desktop|workstation|macbook|imac|pc[\-_]?\d|surface|thinkpad|latitude)\b", re.I), "laptop", 0.55),
)


def extended_vendor_from_mac(mac: str) -> str:
    """Look up vendor from MAC against the extended OUI table.

    Returns "" when the prefix is not in the table. Callers should consult
    the primary lookups first (engine vendor, ``network.COMMON_VENDOR_PREFIXES``)
    and fall back to this only when both miss.
    """
    clean = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()
    if len(clean) < 6:
        return ""
    return EXTENDED_OUI.get(clean[:6], "")


def _normalize_engine_type(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return ""
    return ENGINE_TYPE_MAP.get(text, "")


def classify_device(device: Device) -> tuple[str, float]:
    """Score a device against multiple signals and return (type, confidence).

    Signals (weighted):
      * Engine's own type guess (``device.metadata['device_type_guess']``): 0.6
      * Hostname regex pattern match: up to 0.6
      * Vendor → default type mapping: 0.35
      * Open-port fingerprint(s): per signature weight, additive
      * IP position (``.1`` / ``.254`` + DNS open = router): 0.3..0.5

    Confidence is clamped to ``[0.0, 0.99]``. Returns ``("unknown", 0.0)``
    when no signal fires — the algorithm never silently invents a type.
    """
    scores: dict[str, float] = {}
    metadata = device.metadata or {}

    # 1. Engine's own guess (already evidence-weighted upstream)
    mapped = _normalize_engine_type(str(metadata.get("device_type_guess") or ""))
    if mapped:
        scores[mapped] = scores.get(mapped, 0.0) + 0.6

    # 2. Hostname pattern (first match wins to keep things deterministic)
    hostname = (device.hostname or "").strip()
    if hostname:
        for pattern, kind, weight in HOSTNAME_TYPE_PATTERNS:
            if pattern.search(hostname):
                scores[kind] = scores.get(kind, 0.0) + weight
                break

    # 3. Vendor default
    vendor_key = (device.vendor or "").strip().lower()
    if vendor_key:
        for needle, kind in VENDOR_TO_TYPE.items():
            if needle in vendor_key:
                scores[kind] = scores.get(kind, 0.0) + 0.35
                break

    # 4. Open-port signatures
    ports: set[int] = set()
    for port in device.open_ports or []:
        try:
            ports.add(int(port))
        except (TypeError, ValueError):
            continue
    if ports:
        for required, kind, weight in PORT_SIGNATURES:
            if required.issubset(ports):
                scores[kind] = scores.get(kind, 0.0) + weight

    # 5. IP position router heuristic
    ip = (device.ip or "").strip()
    if ip and (ip.endswith(".1") or ip.endswith(".254")):
        boost = 0.5 if 53 in ports else 0.3
        scores["router"] = scores.get("router", 0.0) + boost

    if not scores:
        return ("unknown", 0.0)

    kind, raw = max(scores.items(), key=lambda kv: kv[1])
    if kind not in KNOWN_DEVICE_TYPES or kind == "unknown":
        return ("unknown", 0.0)
    return (kind, round(min(0.99, raw), 2))


def synthesize_hostname(device: Device) -> str:
    """Build a friendly fallback name like ``tp-link-router-1``.

    Only meaningful when the caller has already classified the device and
    knows its vendor. Builds from ``vendor`` + resolved type + IP last octet.
    Falls back to ``host-<ip>`` when no signal is available.

    Returns "" if the device has no IP and no MAC — caller decides what to do.
    """
    parts: list[str] = []

    vendor = (device.vendor or "").strip().lower()
    if vendor:
        parts.append(re.sub(r"[^a-z0-9]+", "-", vendor).strip("-"))

    metadata = device.metadata or {}
    resolved = str(metadata.get("resolved_device_type") or "").strip().lower()
    if resolved and resolved != "unknown" and resolved not in parts:
        parts.append(resolved)

    ip = (device.ip or "").strip()
    suffix = ""
    if "." in ip:
        last = ip.rsplit(".", 1)[-1]
        if last:
            suffix = last
    elif ip:
        suffix = re.sub(r"[^a-z0-9]+", "-", ip.lower())[-6:]

    if suffix:
        parts.append(suffix)

    if not parts:
        if ip:
            return f"host-{re.sub(r'[^a-z0-9]+', '-', ip.lower())}"
        return ""

    name = "-".join(parts).strip("-")
    name = re.sub(r"-+", "-", name)
    return name


def resolve_device(device: Device) -> Device:
    """Apply classification + hostname synthesis to a Device, in place.

    Writes into ``device.metadata``:
      * ``resolved_device_type`` (always set, may be ``"unknown"``)
      * ``resolved_device_type_confidence`` (0.0..0.99)
      * ``resolved_vendor`` when the extended OUI table filled a previously
        blank vendor.
      * ``hostname_synthesized`` = True when ``device.hostname`` was blank and
        a fallback name was generated.

    A synthesized hostname is only assigned when the device already has a
    stable MAC-based fingerprint. Without a MAC the fingerprint key uses
    ``hostname``, and rewriting that under the device would create duplicate
    baseline records on the next scan.
    """
    metadata = device.metadata if isinstance(device.metadata, dict) else {}
    device.metadata = metadata

    # Vendor enrichment via extended OUI (only if everything upstream blanked).
    if not device.vendor and device.mac_address:
        candidate = extended_vendor_from_mac(device.mac_address)
        if candidate:
            device.vendor = candidate
            metadata["resolved_vendor"] = candidate

    kind, confidence = classify_device(device)
    metadata["resolved_device_type"] = kind
    metadata["resolved_device_type_confidence"] = confidence

    if not device.hostname and device.mac_address:
        synthesized = synthesize_hostname(device)
        if synthesized:
            device.hostname = synthesized
            metadata["hostname_synthesized"] = True

    return device


def resolve_devices(devices: Iterable[Device]) -> list[Device]:
    """Apply :func:`resolve_device` to every device in the iterable, in place."""
    result: list[Device] = []
    for device in devices:
        result.append(resolve_device(device))
    return result

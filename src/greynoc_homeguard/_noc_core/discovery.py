from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from .network_sensor import (
    NetworkSensorConfig,
    detect_local_interfaces,
    is_private_or_local_network,
    normalize_mac,
)

SAFE_INVENTORY_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    53,
    80,
    81,
    135,
    139,
    443,
    445,
    515,
    548,
    554,
    631,
    1883,
    2049,
    2323,
    2869,
    3074,
    3689,
    5000,
    5001,
    7000,
    8000,
    8001,
    8008,
    8009,
    8060,
    8080,
    8081,
    8443,
    8554,
    8883,
    8899,
    9000,
    9080,
    9100,
    9197,
    9295,
    9308,
    1400,
    49152,
    52323,
    55000,
    56000,
    62078,
)
DEFAULT_MAX_ADDRESSES = 1024
GENERIC_DEVICE_TYPES = {"", "other", "device", "unknown", "workstation"}
DIRECT_DISCOVERY_METHODS = {
    "arp",
    "arp-probe",
    "neighbor-cache",
    "router-dhcp",
    "dhcp-lease",
    "default-gateway",
    "dhcp-server",
    "icmp",
}
VPN_INTERFACE_TOKENS = (
    "tun",
    "tap",
    "tailscale",
    "wireguard",
    "wg",
    "nordlynx",
    "nordvpn",
    "expressvpn",
    "protonvpn",
    "vpn",
    "openvpn",
    "zerotier",
    "hamachi",
    "anyconnect",
    "cisco",
    "cloudflare warp",
    "warp",
    "globalprotect",
    "pulse secure",
    "softether",
)
MULTICAST_DISCOVERY_METHODS = {"mdns", "ssdp", "ws-discovery"}
BLUETOOTH_DISCOVERY_METHODS = {"bluetooth-pnp", "bluetooth", "radio"}
LOW_CONFIDENCE_METHODS = {"inferred-accessory", "inferred-remote"}
SERVICE_NAMES: dict[int, str] = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    53: "dns",
    80: "http",
    81: "http-alt",
    135: "msrpc",
    139: "netbios",
    443: "https",
    445: "smb",
    515: "lpd",
    548: "afp",
    554: "rtsp",
    631: "ipp",
    1883: "mqtt",
    2049: "nfs",
    2323: "telnet-alt",
    2869: "upnp",
    3074: "xbox-live",
    3689: "daap",
    5000: "upnp-http",
    5001: "nas-https",
    7000: "airplay",
    8000: "http-alt",
    8001: "tv-control",
    8008: "googlecast-http",
    8009: "googlecast",
    8060: "roku-ecp",
    8080: "http-alt",
    8081: "http-alt",
    8443: "https-alt",
    8554: "rtsp-alt",
    8883: "mqtts",
    8899: "iot-control",
    9000: "http-alt",
    9080: "http-alt",
    9100: "jetdirect",
    9197: "printer",
    9295: "game-console",
    9308: "game-console",
    1400: "sonos",
    49152: "upnp",
    52323: "tv-control",
    55000: "tv-control",
    56000: "tv-control",
    62078: "apple-mobile",
}
OUI_VENDOR_HINTS: dict[str, str] = {
    "001a11": "Google",
    "001dd8": "Microsoft",
    "0024e4": "Withings",
    "00d0e5": "Samsung",
    "087045": "Apple",
    "0c8bfd": "Intel",
    "1007b6": "Samsung",
    "18b430": "Nest",
    "1c1b68": "Amazon",
    "24a160": "Apple",
    "286c07": "Apple",
    "2c3033": "Google",
    "2c54cf": "LG",
    "3c5a37": "Samsung",
    "44650d": "Amazon",
    "503275": "Apple",
    "5c497d": "Samsung",
    "6c5ab0": "Roku",
    "74acb9": "Ubiquiti",
    "7828ca": "Sonos",
    "78d75f": "Roku",
    "8c86dd": "TP-Link",
    "8c90d3": "Roku",
    "8c902d": "TP-Link",
    "a840f8": "TP-Link",
    "b4e62d": "Apple",
    "b827eb": "Raspberry Pi",
    "dca632": "Raspberry Pi",
    "d8bb2c": "Apple",
    "f0d5bf": "Intel",
    "f4f5d8": "Google",
}
PHONE_HINT_TOKENS = (
    "iphone",
    "android phone",
    "pixel phone",
    "galaxy phone",
    "oneplus",
    "moto ",
    "motorola",
    "xiaomi",
    "redmi",
    "oppo",
    "vivo",
    "xperia",
    "smartphone",
    "apple-mobdev",
    "apple mobdev",
    "airdrop",
    "handoff",
)
TABLET_HINT_TOKENS = (
    "ipad",
    "tablet",
    "kindle",
    "fire hd",
    "galaxy tab",
    "surface",
    "xiaomi pad",
    "pixel tablet",
    "oneplus pad",
)
SMART_TV_HINT_TOKENS = (
    "smart tv",
    "roku tv",
    "samsung tv",
    "lg webos",
    "lgwebostv",
    "webos",
    "tizen",
    "bravia",
    "vizio",
    "hisense",
    "vidaa",
    "tcl tv",
    "android tv",
    "googletv tv",
    "fire tv edition",
    "media renderer",
)
STREAMING_BOX_HINT_TOKENS = (
    "roku",
    "chromecast",
    "google cast",
    "googlecast",
    "google tv",
    "googletv",
    "apple tv",
    "appletv",
    "fire tv",
    "firetv",
    "shield tv",
    "androidtvremote",
    "roku-ecp",
    "dial multiscreen",
)
REMOTE_HINT_TOKENS = (
    "remote",
    "remote control",
    "roku remote",
    "fire tv remote",
    "chromecast remote",
    "google tv remote",
    "android tv remote",
    "apple tv remote",
    "siri remote",
    "xbox wireless controller",
    "dualsense",
    "dualshock",
    "joy-con",
    "gamepad",
    "controller",
)
WEARABLE_HINT_TOKENS = (
    "watch",
    "smart watch",
    "smartwatch",
    "apple watch",
    "galaxy watch",
    "pixel watch",
    "fitbit",
    "garmin",
    "amazfit",
    "wear os",
    "wearable",
    "fitness tracker",
)
SPEAKER_HINT_TOKENS = (
    "sonos",
    "homepod",
    "speaker",
    "smart speaker",
    "echo dot",
    "amazon echo",
    "alexa",
    "google home",
    "nest audio",
    "bose",
    "spotify connect",
    "airplay audio",
)
GAME_CONSOLE_HINT_TOKENS = ("xbox", "playstation", "ps4", "ps5", "nintendo", "switch console", "steam deck")
IOT_HUB_HINT_TOKENS = (
    "home assistant",
    "homeassistant",
    "hubitat",
    "smartthings",
    "hue bridge",
    "philips hue",
    "aqara hub",
    "homekit bridge",
    "matter bridge",
    "thread border router",
    "zigbee hub",
    "z-wave",
)
SMART_HOME_HINT_TOKENS = (
    "thermostat",
    "smart plug",
    "smart bulb",
    "light bulb",
    "doorbell",
    "lock",
    "sensor",
    "kasa",
    "tapo plug",
    "wemo",
    "tuya",
    "shelly",
    "esphome",
    "tasmota",
    "lifx",
    "ecobee",
    "nest thermostat",
    "matter",
)
STREAMING_PORT_HINTS = {7000, 8008, 8009, 8060, 9080, 52323, 55000, 56000}
SMART_TV_PORT_HINTS = {8001, 8002, 9197}
PHONE_TABLET_PORT_HINTS = {62078}
SPEAKER_PORT_HINTS = {1400, 3689}
GAME_CONSOLE_PORT_HINTS = {3074, 9295, 9308}
IOT_HUB_PORT_HINTS = {1883, 8883, 8123, 21063}
SMART_HOME_PORT_HINTS = {1883, 8883, 5683}


ReaderMap = Mapping[str, Mapping[str, Any]]
IpNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class DiscoveryError(ValueError):
    """Raised when a requested discovery range is outside the safe default policy."""


@dataclass(slots=True)
class DiscoveryOptions:
    allow_public: bool = False
    allow_large_subnet: bool = False
    passive_only: bool = False
    enable_arp_probe: bool = True
    enable_icmp: bool = True
    enable_tcp: bool = True
    enable_mdns_ssdp: bool = True
    enable_radio: bool = True
    enable_bluetooth: bool = False
    max_hosts: int = DEFAULT_MAX_ADDRESSES
    max_workers: int = 64
    rate_limit_per_second: float = 96.0
    command_timeout_seconds: float = 2.5
    ping_timeout_ms: int = 350
    tcp_timeout_seconds: float = 0.28
    multicast_timeout_seconds: float = 2.2
    reverse_dns_budget: int = 8
    reverse_dns_timeout: float = 0.08
    cancel_event: threading.Event | None = None
    safe_ports: tuple[int, ...] = field(default_factory=lambda: SAFE_INVENTORY_PORTS)

    # Optional hooks keep the scanner testable and let solin_security reuse its
    # existing OS-specific collectors without coupling this module to routes.
    interface_reader: Callable[[], Sequence[Any]] | None = None
    arp_reader: Callable[[ipaddress.IPv4Network], Mapping[str, str]] | None = None
    arp_probe: Callable[[ipaddress.IPv4Network], Mapping[str, str]] | None = None
    neighbor_reader: Callable[[ipaddress.IPv4Network], ReaderMap] | None = None
    router_dhcp_reader: Callable[[ipaddress.IPv4Network], ReaderMap] | None = None
    ssdp_reader: Callable[[ipaddress.IPv4Network], ReaderMap] | None = None
    mdns_reader: Callable[[ipaddress.IPv4Network], ReaderMap] | None = None
    wsd_reader: Callable[[ipaddress.IPv4Network], ReaderMap] | None = None
    radio_reader: Callable[[ipaddress.IPv4Network], Sequence[Mapping[str, Any]]] | None = None
    icmp_probe: Callable[[str], bool] | None = None
    tcp_port_probe: Callable[[str], Sequence[int]] | None = None
    reverse_dns_lookup: Callable[[str, float], str] | None = None
    smart_home_readers: Mapping[str, Callable[[ipaddress.IPv4Network], Mapping[str, Mapping[str, Any]]]] = field(
        default_factory=dict
    )


@dataclass(slots=True)
class DiscoveryDevice:
    ip: str = ""
    mac: str = ""
    hostname: str = ""
    vendor: str = ""
    open_ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)
    discovered_by: list[str] = field(default_factory=list)
    confidence_score: float = 0.0
    type: str = "other"
    first_seen: str = ""
    last_seen: str = ""
    status: str = "online"
    device_hints: list[str] = field(default_factory=list)
    id: str = ""
    alternate_ips: list[str] = field(default_factory=list)
    parent_device_id: str = ""
    evidence_level: str = "direct"
    radio: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "ip": self.ip,
            "mac": self.mac,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "open_ports": list(self.open_ports),
            "ports": list(self.open_ports),
            "services": list(self.services),
            "discovered_by": list(self.discovered_by),
            "confidence_score": self.confidence_score,
            "type": self.type,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "last_seen_at": self.last_seen,
            "status": self.status,
            "device_hints": list(self.device_hints),
            "alternate_ips": list(self.alternate_ips),
            "parent_device_id": self.parent_device_id,
            "evidence_level": self.evidence_level,
            "radio": self.radio,
        }


@dataclass(slots=True)
class DiscoveryResult:
    cidr: str
    devices: list[DiscoveryDevice]
    links: list[dict[str, Any]]
    summary: dict[str, Any]
    generated_at: str
    warnings: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "cidr": self.cidr,
            "devices": [device.as_dict() for device in self.devices],
            "links": list(self.links),
            "summary": dict(self.summary),
            "generated_at": self.generated_at,
            "warnings": list(self.warnings),
        }


def utcnow() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def validate_discovery_cidr(
    network_cidr: str | None,
    options: DiscoveryOptions | None = None,
) -> ipaddress.IPv4Network:
    options = options or DiscoveryOptions()
    if not network_cidr:
        network = _infer_default_ipv4_network(options)
    else:
        try:
            network = ipaddress.ip_network(str(network_cidr).strip(), strict=False)
        except ValueError as exc:
            raise DiscoveryError(f"bad CIDR: {exc}") from exc

    if network.version != 4:
        raise DiscoveryError("IPv6 subnet discovery is not supported yet")
    if not options.allow_public and not is_private_or_local_network(network):
        raise DiscoveryError("public IP ranges are not scanned unless allow_public is true")
    if not options.allow_large_subnet and network.num_addresses > DEFAULT_MAX_ADDRESSES:
        raise DiscoveryError("network too large; use /22 or smaller unless allow_large_subnet is true")
    return network


def discover_local_network(
    network_cidr: str | None,
    options: DiscoveryOptions | None = None,
) -> DiscoveryResult:
    options = options or DiscoveryOptions()
    network = validate_discovery_cidr(network_cidr, options)
    generated_at = utcnow()
    warnings: list[str] = []
    accumulator = _DeviceAccumulator(generated_at)

    passive_sources = _collect_passive_sources(network, options, warnings)
    arp_hosts = passive_sources.get("arp") if isinstance(passive_sources.get("arp"), dict) else {}
    for ip, mac in arp_hosts.items():
        accumulator.merge({"ip": ip, "mac": mac, "discovered_by": ["arp"], "status": "seen"}, "arp")

    for source_name in ("neighbor-cache", "router-dhcp", "ssdp", "mdns", "ws-discovery"):
        rows = passive_sources.get(source_name) if isinstance(passive_sources.get(source_name), dict) else {}
        for ip, row in rows.items():
            if isinstance(row, Mapping):
                accumulator.merge({"ip": ip, "mac": arp_hosts.get(ip, ""), **dict(row)}, source_name)
    for source_name, rows in passive_sources.items():
        if not str(source_name).startswith("smart-home:") or not isinstance(rows, Mapping):
            continue
        for ip, row in rows.items():
            if isinstance(row, Mapping):
                accumulator.merge({"ip": ip, "mac": arp_hosts.get(ip, ""), **dict(row)}, str(source_name))

    radio_rows = passive_sources.get("radio") if isinstance(passive_sources.get("radio"), list) else []
    for row in radio_rows:
        if isinstance(row, Mapping):
            accumulator.merge(dict(row), "radio")

    if not options.passive_only and options.enable_arp_probe and not _is_cancelled(options):
        for ip, mac in _read_arp_probe(network, options, warnings).items():
            accumulator.merge({"ip": ip, "mac": mac, "discovered_by": ["arp-probe"], "status": "online"}, "arp-probe")

    targets = _target_hosts(network, options.max_hosts)
    scanned_hosts = 0
    if not options.passive_only and targets and not _is_cancelled(options):
        scanned_hosts = _collect_active_sources(targets, arp_hosts, accumulator, options, warnings)

    _fill_reverse_dns(accumulator, options)
    if not options.passive_only and not _is_cancelled(options):
        _fill_netbios_names(accumulator, options)
    devices = _with_inferred_peripherals(accumulator.devices(), generated_at)
    links = _build_inventory_links(devices)
    summary = _build_summary(network, devices, links, scanned_hosts, targets, warnings, options)
    return DiscoveryResult(
        cidr=str(network),
        devices=devices,
        links=links,
        summary=summary,
        generated_at=generated_at,
        warnings=warnings,
    )


def guess_device_type(
    ip: str,
    hostname: str = "",
    mac: str = "",
    ports: Iterable[int] | None = None,
    hints: str = "",
    current_type: str = "",
) -> str:
    normalized = _normalize_device_type(current_type)
    if normalized not in GENERIC_DEVICE_TYPES:
        return normalized

    port_set = {int(port) for port in ports or [] if str(port).isdigit()}
    haystack = f"{hostname} {hints}".lower()
    normalized_hints = re.sub(r"[^a-z0-9]+", " ", haystack)
    consumer_type = _consumer_type_from_fingerprints(
        ip,
        normalized_hints,
        port_set,
        has_direct_host=bool(ip or mac),
    )
    if consumer_type:
        return consumer_type

    helper = _security_helper("_guess_host_type")
    if helper is not None:
        try:
            guessed = _normalize_device_type(
                str(helper(ip, hostname=hostname, mac=mac, ports=list(ports or []), hints=hints))
            )
            if guessed != "other":
                return guessed
        except Exception:
            pass

    if port_set & {554, 8554, 8899} or any(token in normalized_hints for token in (" camera ", " ipcam ", " onvif ")):
        return "camera"
    if port_set & {8060, 8008, 8009, 8001, 7000, 52323, 55000} or any(
        token in normalized_hints for token in (" roku ", " tv ", " chromecast ", " airplay ")
    ):
        return "tv"
    if port_set & {515, 631, 9100} or " printer " in normalized_hints:
        return "printer"
    if port_set & {5000, 5001, 2049, 548} or any(token in normalized_hints for token in (" nas ", " storage ")):
        return "storage"
    if port_set & {3074, 9295, 9308} or any(token in normalized_hints for token in (" xbox ", " playstation ")):
        return "game-console"
    if port_set & {1400, 3689} or any(token in normalized_hints for token in (" sonos ", " speaker ")):
        return "speaker"
    if port_set & {1883, 8883} or any(token in normalized_hints for token in (" mqtt ", " matter ", " iot ")):
        return "iot"
    if (
        ip.endswith(".1")
        or ip.endswith(".254")
        or any(token in normalized_hints for token in (" router ", " gateway "))
    ):
        return "router"
    if hostname or mac:
        return "workstation"
    return "other"


def _consumer_type_from_fingerprints(
    ip: str,
    normalized_hints: str,
    ports: set[int],
    *,
    has_direct_host: bool,
) -> str:
    padded = f" {normalized_hints} "
    if _hint_match(padded, WEARABLE_HINT_TOKENS):
        return "wearable"
    is_smart_tv = (
        _hint_match(padded, SMART_TV_HINT_TOKENS)
        or (ports & SMART_TV_PORT_HINTS and " tv " in padded)
    )
    is_streaming_box = _hint_match(padded, STREAMING_BOX_HINT_TOKENS) or bool(ports & STREAMING_PORT_HINTS)
    if _hint_match(padded, REMOTE_HINT_TOKENS) and not (ip and (is_smart_tv or is_streaming_box)):
        return "remote"
    if _hint_match(padded, TABLET_HINT_TOKENS):
        return "tablet"
    if _hint_match(padded, PHONE_HINT_TOKENS) or (
        ports & PHONE_TABLET_PORT_HINTS and not _hint_match(padded, TABLET_HINT_TOKENS)
    ):
        return "phone"
    if _hint_match(padded, GAME_CONSOLE_HINT_TOKENS) or ports & GAME_CONSOLE_PORT_HINTS:
        return "game-console"
    if _hint_match(padded, SPEAKER_HINT_TOKENS) or ports & SPEAKER_PORT_HINTS:
        return "speaker"
    if _hint_match(padded, IOT_HUB_HINT_TOKENS) or ports & IOT_HUB_PORT_HINTS:
        return "iot-hub"
    if _hint_match(padded, SMART_HOME_HINT_TOKENS) or ports & SMART_HOME_PORT_HINTS:
        return "smart-home"
    if is_smart_tv:
        return "tv"
    if is_streaming_box:
        return "streaming-box"
    if (
        ip.endswith(".1")
        or ip.endswith(".254")
        or any(token in padded for token in (" router ", " gateway "))
    ):
        return "router"
    if has_direct_host and any(token in padded for token in (" hub ", " bridge ", "homekit", "matter")):
        return "iot-hub"
    return ""


def _hint_match(padded_hints: str, tokens: Iterable[str]) -> bool:
    for token in tokens:
        normalized = re.sub(r"[^a-z0-9]+", " ", token.lower()).strip()
        if normalized and f" {normalized} " in padded_hints:
            return True
    return False


def confidence_score(device: Mapping[str, Any]) -> float:
    methods = {str(item).lower() for item in device.get("discovered_by") or [] if item}
    ports = {int(port) for port in device.get("open_ports") or device.get("ports") or [] if str(port).isdigit()}
    if methods & LOW_CONFIDENCE_METHODS or str(device.get("evidence_level") or "").lower() == "inferred":
        score = 0.18
        if device.get("parent_device_id"):
            score += 0.08
        if device.get("hostname"):
            score += 0.04
        return round(min(0.35, score), 2)

    score = 0.15
    if device.get("ip"):
        score += 0.20
    if device.get("mac"):
        score += 0.25
    if device.get("hostname"):
        score += 0.10
    if ports:
        score += 0.15
    if methods & {"arp", "arp-probe", "neighbor-cache"}:
        score += 0.20
    if methods & {"router-dhcp", "dhcp-lease", "default-gateway", "dhcp-server"}:
        score += 0.15
    if methods & MULTICAST_DISCOVERY_METHODS:
        score += 0.18
    if "icmp" in methods:
        score += 0.12
    if any(method.startswith("tcp/") or method == "tcp" for method in methods):
        score += 0.18
    if methods & BLUETOOTH_DISCOVERY_METHODS or methods & {"wifi-bssid"}:
        score += 0.10
    if methods & {"bluetooth-pnp"} and not device.get("ip"):
        score = max(score, 0.55)
    if device.get("ip") and device.get("mac") and (
        methods & DIRECT_DISCOVERY_METHODS
        or any(m.startswith("tcp/") for m in methods)
    ):
        score = max(score, 0.86)
    if device.get("ip") and methods & MULTICAST_DISCOVERY_METHODS:
        score = max(score, 0.72)
    return round(max(0.05, min(0.99, score)), 2)


class _RateLimiter:
    def __init__(self, rate_per_second: float) -> None:
        self._interval = 1.0 / rate_per_second if rate_per_second > 0 else 0.0
        self._lock = threading.Lock()
        self._next_at = 0.0

    def wait(self, options: DiscoveryOptions) -> None:
        if self._interval <= 0 or _is_cancelled(options):
            return
        with self._lock:
            now = time.monotonic()
            if self._next_at > now:
                time.sleep(min(0.25, self._next_at - now))
                now = time.monotonic()
            self._next_at = max(self._next_at, now) + self._interval


class _DeviceAccumulator:
    def __init__(self, timestamp: str) -> None:
        self._timestamp = timestamp
        self._devices: list[dict[str, Any]] = []
        self._by_mac: dict[str, dict[str, Any]] = {}
        self._by_ip: dict[str, dict[str, Any]] = {}
        self._by_hostname: dict[str, dict[str, Any]] = {}

    def merge(self, raw: Mapping[str, Any], source: str = "") -> None:
        row = _normalize_row(raw, source, self._timestamp)
        if not (row["ip"] or row["mac"] or row["hostname"] or row["id"]):
            return
        existing = self._find(row)
        if existing is None:
            existing = {
                "id": row["id"] or _safe_id("device", row["mac"] or row["ip"] or row["hostname"]),
                "ip": row["ip"],
                "mac": row["mac"],
                "hostname": row["hostname"],
                "vendor": row["vendor"],
                "open_ports": [],
                "services": [],
                "discovered_by": [],
                "confidence_score": 0.0,
                "type": row["type"] or "other",
                "first_seen": row["first_seen"] or self._timestamp,
                "last_seen": row["last_seen"] or self._timestamp,
                "status": row["status"] or "online",
                "device_hints": [],
                "alternate_ips": [],
                "parent_device_id": row["parent_device_id"],
                "evidence_level": row["evidence_level"],
                "radio": row["radio"],
            }
            self._devices.append(existing)

        if row["ip"] and not existing.get("ip"):
            existing["ip"] = row["ip"]
        elif row["ip"] and existing.get("ip") and row["ip"] != existing.get("ip"):
            _append_unique(existing.setdefault("alternate_ips", []), [row["ip"]])
        if row["mac"] and not existing.get("mac"):
            existing["mac"] = row["mac"]
        if row["hostname"] and not existing.get("hostname"):
            existing["hostname"] = row["hostname"]
        if row["vendor"] and not existing.get("vendor"):
            existing["vendor"] = row["vendor"]
        if row["parent_device_id"] and not existing.get("parent_device_id"):
            existing["parent_device_id"] = row["parent_device_id"]
        if row["radio"] and not existing.get("radio"):
            existing["radio"] = row["radio"]
        if row["evidence_level"] == "direct" or not existing.get("evidence_level"):
            existing["evidence_level"] = row["evidence_level"]
        if row["status"] == "online" or not existing.get("status"):
            existing["status"] = row["status"] or "online"
        if row["first_seen"] and str(row["first_seen"]) < str(existing.get("first_seen") or row["first_seen"]):
            existing["first_seen"] = row["first_seen"]
        if row["last_seen"] and str(row["last_seen"]) > str(existing.get("last_seen") or ""):
            existing["last_seen"] = row["last_seen"]

        _append_ports(existing.setdefault("open_ports", []), row["open_ports"])
        _append_unique(existing.setdefault("discovered_by", []), row["discovered_by"])
        _append_unique(existing.setdefault("device_hints", []), row["device_hints"])
        _append_unique(existing.setdefault("services", []), row["services"])

        if str(existing.get("type") or "other") in GENERIC_DEVICE_TYPES and row["type"] not in GENERIC_DEVICE_TYPES:
            existing["type"] = row["type"]
        hint_text = " ".join(str(item) for item in existing.get("device_hints") or [])
        existing["type"] = guess_device_type(
            str(existing.get("ip") or ""),
            hostname=str(existing.get("hostname") or ""),
            mac=str(existing.get("mac") or ""),
            ports=list(existing.get("open_ports") or []),
            hints=hint_text,
            current_type=str(existing.get("type") or ""),
        )
        if not existing.get("vendor"):
            existing["vendor"] = _vendor_for(
                str(existing.get("mac") or ""),
                hint_text,
                str(existing.get("hostname") or ""),
            )
        existing["services"] = sorted(
            set(existing.get("services") or [])
            | set(_services_for_ports(existing.get("open_ports") or []))
        )
        existing["confidence_score"] = confidence_score(existing)
        self._index(existing)

    def devices(self) -> list[DiscoveryDevice]:
        rows = sorted(
            self._devices,
            key=lambda item: _device_sort_key(
                str(item.get("ip") or ""),
                str(item.get("hostname") or ""),
            ),
        )
        return [
            DiscoveryDevice(
                id=str(row.get("id") or _safe_id(
                    "device",
                    str(row.get("ip") or row.get("mac") or row.get("hostname") or ""),
                )),
                ip=str(row.get("ip") or ""),
                mac=str(row.get("mac") or ""),
                hostname=str(row.get("hostname") or ""),
                vendor=str(row.get("vendor") or ""),
                open_ports=sorted({int(port) for port in row.get("open_ports") or [] if str(port).isdigit()}),
                services=sorted({str(item) for item in row.get("services") or [] if item}),
                discovered_by=sorted({str(item) for item in row.get("discovered_by") or [] if item}),
                confidence_score=float(row.get("confidence_score") or 0.0),
                type=str(row.get("type") or "other"),
                first_seen=str(row.get("first_seen") or ""),
                last_seen=str(row.get("last_seen") or ""),
                status=str(row.get("status") or "online"),
                device_hints=list(dict.fromkeys(str(item) for item in row.get("device_hints") or [] if item))[:8],
                alternate_ips=sorted({str(item) for item in row.get("alternate_ips") or [] if item}),
                parent_device_id=str(row.get("parent_device_id") or ""),
                evidence_level=str(row.get("evidence_level") or "direct"),
                radio=str(row.get("radio") or ""),
            )
            for row in rows
        ]

    def _find(self, row: Mapping[str, Any]) -> dict[str, Any] | None:
        mac = str(row.get("mac") or "")
        ip = str(row.get("ip") or "")
        hostname = str(row.get("hostname") or "").casefold()
        if mac and mac in self._by_mac:
            return self._by_mac[mac]
        if ip and ip in self._by_ip:
            return self._by_ip[ip]
        if hostname and hostname in self._by_hostname:
            return self._by_hostname[hostname]
        return None

    def _index(self, row: dict[str, Any]) -> None:
        mac = str(row.get("mac") or "")
        ip = str(row.get("ip") or "")
        hostname = str(row.get("hostname") or "").casefold()
        if mac:
            self._by_mac[mac] = row
        if ip:
            self._by_ip[ip] = row
        if hostname:
            self._by_hostname[hostname] = row


def _is_vpn_interface_name(name: str) -> bool:
    lowered = (name or "").strip().lower()
    if not lowered:
        return False
    return any(token in lowered for token in VPN_INTERFACE_TOKENS)


def _narrow_to_lan_subnet(network: ipaddress.IPv4Network, local_ip: str) -> ipaddress.IPv4Network:
    """Reduce an oversized inferred subnet to a /24 around the host's IP.

    VPN tunnels and some corp interfaces report /16 or /8 supernets that are
    far too large to scan; the reachable LAN segment is almost always a /24.
    """
    if network.prefixlen >= 24:
        return network
    try:
        anchor = ipaddress.ip_address(local_ip) if local_ip else None
    except ValueError:
        anchor = None
    if anchor is not None and anchor.version == 4:
        try:
            narrowed = ipaddress.ip_network(f"{anchor}/24", strict=False)
        except ValueError:
            narrowed = None
        if narrowed is not None and narrowed.subnet_of(network):
            return narrowed
    return ipaddress.ip_network(f"{network.network_address}/24", strict=False)


def _infer_default_ipv4_network(options: DiscoveryOptions) -> ipaddress.IPv4Network:
    interfaces: Sequence[Any]
    if options.interface_reader is not None:
        interfaces = options.interface_reader()
    else:
        interfaces = detect_local_interfaces(
            NetworkSensorConfig(command_timeout_seconds=options.command_timeout_seconds)
        )

    route_ip = _default_route_ipv4()
    max_size = max(2, options.max_hosts) if not options.allow_large_subnet else None
    candidates: list[tuple[tuple[int, int, int, str], ipaddress.IPv4Network]] = []
    vpn_fallbacks: list[tuple[tuple[int, int, int, str], ipaddress.IPv4Network]] = []
    for interface in interfaces:
        cidr = str(getattr(interface, "cidr", "") or "")
        name = str(getattr(interface, "name", "") or getattr(interface, "interface", "") or "")
        local_ip = str(getattr(interface, "local_ip", "") or getattr(interface, "ip_address", "") or "")
        gateway = str(getattr(interface, "gateway", "") or "")
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if network.version != 4 or not is_private_or_local_network(network):
            continue

        is_vpn = _is_vpn_interface_name(name)
        scan_network = network
        if max_size is not None and scan_network.num_addresses > max_size:
            scan_network = _narrow_to_lan_subnet(scan_network, local_ip)
        if max_size is not None and scan_network.num_addresses > max_size:
            # Still too large after narrowing; can't scan safely.
            continue

        # Lower score wins. Order by: VPN penalty, oversized penalty,
        # gateway/route preference, then CIDR string for stable order.
        oversized_penalty = 0 if network.prefixlen >= 24 else 4
        gateway_score = 0 if gateway else 5
        route_score = -8 if (route_ip and local_ip == route_ip) else 0
        vpn_score = 50 if is_vpn else 0
        score = (vpn_score, oversized_penalty, gateway_score + route_score, str(network))
        if is_vpn:
            vpn_fallbacks.append((score, scan_network))
        else:
            candidates.append((score, scan_network))

    pool = candidates or vpn_fallbacks
    if pool:
        pool.sort(key=lambda item: item[0])
        return pool[0][1]

    for address in [route_ip, *_fallback_ipv4_addresses()]:
        if not address:
            continue
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.version == 4 and not ip.is_loopback and not ip.is_link_local:
            network = ipaddress.ip_network(f"{ip}/24", strict=False)
            if is_private_or_local_network(network):
                return network
    raise DiscoveryError("could not infer local CIDR")


def _default_route_ipv4() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))
            return str(sock.getsockname()[0])
    except OSError:
        return ""


def _fallback_ipv4_addresses() -> list[str]:
    addresses: list[str] = []
    try:
        addresses.extend(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    return list(dict.fromkeys(addresses))


def _collect_passive_sources(
    network: ipaddress.IPv4Network,
    options: DiscoveryOptions,
    warnings: list[str],
) -> dict[str, object]:
    jobs: dict[str, Callable[[], object]] = {
        "arp": lambda: _read_arp_hosts(network, options),
        "neighbor-cache": lambda: _read_neighbor_hosts(network, options),
        "router-dhcp": lambda: _read_router_dhcp_hosts(network, options),
    }
    if options.enable_mdns_ssdp:
        jobs.update(
            {
                "ssdp": lambda: _read_protocol_hosts("ssdp", network, options),
                "mdns": lambda: _read_protocol_hosts("mdns", network, options),
                "ws-discovery": lambda: _read_protocol_hosts("ws-discovery", network, options),
            }
        )
    if options.enable_radio:
        jobs["radio"] = lambda: _read_radio_devices(network, options)
    for name, reader in options.smart_home_readers.items():
        jobs[f"smart-home:{name}"] = lambda reader=reader: _filter_host_rows(reader(network), network)

    results: dict[str, object] = {}
    with ThreadPoolExecutor(max_workers=min(len(jobs), max(1, options.max_workers))) as pool:
        futures = {pool.submit(job): name for name, job in jobs.items()}
        for future in as_completed(futures):
            name = futures[future]
            if _is_cancelled(options):
                warnings.append("discovery cancelled during passive collection")
                break
            try:
                results[name] = future.result()
            except Exception as exc:
                warnings.append(f"{name} unavailable: {type(exc).__name__}")
                results[name] = [] if name == "radio" else {}
    return results


def _collect_active_sources(
    targets: list[str],
    arp_hosts: Mapping[str, str],
    accumulator: _DeviceAccumulator,
    options: DiscoveryOptions,
    warnings: list[str],
) -> int:
    limiter = _RateLimiter(options.rate_limit_per_second)
    scanned_hosts: set[str] = set()
    jobs: dict[Any, tuple[str, str]] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(options.max_workers, len(targets) * 2))) as pool:
        for ip in targets:
            if _is_cancelled(options):
                break
            if options.enable_icmp:
                jobs[pool.submit(_probe_icmp_host, ip, options, limiter)] = ("icmp", ip)
            if options.enable_tcp:
                jobs[pool.submit(_probe_tcp_host, ip, options, limiter)] = ("tcp", ip)
        for future in as_completed(jobs):
            kind, ip = jobs[future]
            scanned_hosts.add(ip)
            if _is_cancelled(options):
                warnings.append("discovery cancelled during active probes")
                break
            try:
                result = future.result()
            except Exception:
                result = False if kind == "icmp" else []
            if kind == "icmp" and result:
                accumulator.merge(
                    {"ip": ip, "mac": arp_hosts.get(ip, ""), "discovered_by": ["icmp"], "status": "online"},
                    "icmp",
                )
            elif kind == "tcp" and result:
                open_ports = [int(port) for port in result if str(port).isdigit() and 1 <= int(port) <= 65535]
                accumulator.merge(
                    {
                        "ip": ip,
                        "mac": arp_hosts.get(ip, ""),
                        "open_ports": open_ports,
                        "ports": open_ports,
                        "services": _services_for_ports(open_ports),
                        "discovered_by": [f"tcp/{port}" for port in open_ports[:8]],
                        "status": "online",
                    },
                    "tcp",
                )
    return len(scanned_hosts)


def _read_arp_hosts(network: ipaddress.IPv4Network, options: DiscoveryOptions) -> dict[str, str]:
    if options.arp_reader is not None:
        return _filter_ip_mac_map(options.arp_reader(network), network)
    helper = _security_helper("_arp_hosts_for_network")
    if helper is not None:
        try:
            return _filter_ip_mac_map(helper(network), network)
        except Exception:
            pass
    try:
        from .network_discovery import read_arp_table

        rows = read_arp_table(NetworkSensorConfig(command_timeout_seconds=options.command_timeout_seconds))
    except Exception:
        return {}
    return _filter_ip_mac_map({row.ip: row.mac_address for row in rows}, network)


def _read_neighbor_hosts(network: ipaddress.IPv4Network, options: DiscoveryOptions) -> dict[str, dict[str, Any]]:
    if options.neighbor_reader is not None:
        return _filter_host_rows(options.neighbor_reader(network), network)
    helper = _security_helper("_neighbor_cache_hosts_for_network")
    if helper is not None:
        try:
            return _filter_host_rows(helper(network), network)
        except Exception:
            pass
    try:
        from .network_discovery import read_neighbor_table

        rows = read_neighbor_table(NetworkSensorConfig(command_timeout_seconds=options.command_timeout_seconds))
    except Exception:
        return {}
    return _filter_host_rows(
        {
            row.ip: {
                "ip": row.ip,
                "mac": row.mac_address,
                "hostname": row.hostname,
                "status": row.status,
                "ports": row.open_ports,
                "discovered_by": ["neighbor-cache"],
            }
            for row in rows
        },
        network,
    )


def _read_router_dhcp_hosts(network: ipaddress.IPv4Network, options: DiscoveryOptions) -> dict[str, dict[str, Any]]:
    if options.router_dhcp_reader is not None:
        return _filter_host_rows(options.router_dhcp_reader(network), network)
    helper = _security_helper("_router_dhcp_hosts_for_network")
    if helper is None:
        return {}
    try:
        return _filter_host_rows(helper(network), network)
    except Exception:
        return {}


def _read_protocol_hosts(
    name: str,
    network: ipaddress.IPv4Network,
    options: DiscoveryOptions,
) -> dict[str, dict[str, Any]]:
    reader = {
        "ssdp": options.ssdp_reader,
        "mdns": options.mdns_reader,
        "ws-discovery": options.wsd_reader,
    }.get(name)
    if reader is not None:
        return _filter_host_rows(reader(network), network)
    helper_name = {
        "ssdp": "_ssdp_hosts_for_network",
        "mdns": "_mdns_hosts_for_network",
        "ws-discovery": "_wsd_hosts_for_network",
    }[name]
    helper = _security_helper(helper_name)
    if helper is None:
        return {}
    try:
        return _filter_host_rows(helper(network), network)
    except Exception:
        return {}


def _read_radio_devices(network: ipaddress.IPv4Network, options: DiscoveryOptions) -> list[dict[str, Any]]:
    if options.radio_reader is not None:
        rows = [dict(row) for row in options.radio_reader(network) if isinstance(row, Mapping)]
        return _filter_radio_rows(rows, options)
    helper = _security_helper("_radio_devices_for_network")
    if helper is None:
        return []
    try:
        rows = [dict(row) for row in helper(network) if isinstance(row, Mapping)]
        return _filter_radio_rows(rows, options)
    except Exception:
        return []


def _filter_radio_rows(rows: list[dict[str, Any]], options: DiscoveryOptions) -> list[dict[str, Any]]:
    filtered: list[dict[str, Any]] = []
    for row in rows:
        radio = str(row.get("radio") or "").lower()
        methods = {str(item).lower() for item in row.get("discovered_by") or []}
        is_bluetooth = radio == "bluetooth" or "bluetooth-pnp" in methods
        if is_bluetooth and not options.enable_bluetooth:
            continue
        if is_bluetooth:
            row.setdefault("evidence_level", "direct")
            row.setdefault("status", "bluetooth-ok")
        filtered.append(row)
    return filtered


def _read_arp_probe(
    network: ipaddress.IPv4Network,
    options: DiscoveryOptions,
    warnings: list[str],
) -> dict[str, str]:
    if options.arp_probe is not None:
        return _filter_ip_mac_map(options.arp_probe(network), network)
    try:
        from scapy.all import ARP, Ether, srp  # type: ignore[import-not-found]
    except Exception:
        return {}
    if network.num_addresses > min(DEFAULT_MAX_ADDRESSES, max(2, options.max_hosts) + 2):
        return {}
    if _is_cancelled(options):
        return {}
    try:
        answered, _unanswered = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network)),
            timeout=min(1.0, max(0.2, options.tcp_timeout_seconds * 3)),
            verbose=0,
        )
    except Exception as exc:
        warnings.append(f"arp-probe unavailable: {type(exc).__name__}")
        return {}
    hosts: dict[str, str] = {}
    for _sent, received in answered:
        ip = str(getattr(received, "psrc", "") or "")
        mac = normalize_mac(str(getattr(received, "hwsrc", "") or ""))
        if _ip_in_network(ip, network) and mac:
            hosts[ip] = mac
    return hosts


def _probe_icmp_host(ip: str, options: DiscoveryOptions, limiter: _RateLimiter) -> bool:
    if _is_cancelled(options):
        return False
    limiter.wait(options)
    if options.icmp_probe is not None:
        return bool(options.icmp_probe(ip))
    timeout_ms = max(100, int(options.ping_timeout_ms))
    if platform.system().lower().startswith("win"):
        command = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        command = ["ping", "-c", "1", "-W", "1", ip]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=max(1.0, timeout_ms / 1000 + 0.5),
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    text = f"{result.stdout or ''}\n{result.stderr or ''}".lower()
    return result.returncode == 0 or "ttl=" in text or "bytes from" in text


def _probe_tcp_host(ip: str, options: DiscoveryOptions, limiter: _RateLimiter) -> list[int]:
    if _is_cancelled(options):
        return []
    limiter.wait(options)
    if options.tcp_port_probe is not None:
        return [int(port) for port in options.tcp_port_probe(ip) if str(port).isdigit()]
    ports: list[int] = []
    for port in options.safe_ports:
        if _is_cancelled(options):
            break
        limiter.wait(options)
        try:
            with socket.create_connection((ip, int(port)), timeout=options.tcp_timeout_seconds):
                ports.append(int(port))
        except OSError:
            continue
    return ports


def _fill_reverse_dns(accumulator: _DeviceAccumulator, options: DiscoveryOptions) -> None:
    budget = max(0, int(options.reverse_dns_budget))
    if budget <= 0:
        return
    lookups = 0
    for row in accumulator._devices:
        if lookups >= budget or _is_cancelled(options):
            return
        ip = str(row.get("ip") or "")
        if not ip or row.get("hostname"):
            continue
        lookup = options.reverse_dns_lookup or _reverse_dns_lookup
        hostname = lookup(ip, options.reverse_dns_timeout)
        lookups += 1
        if hostname:
            accumulator.merge({"ip": ip, "hostname": hostname, "discovered_by": ["reverse-dns"]}, "reverse-dns")


def _reverse_dns_lookup(ip: str, timeout: float) -> str:
    result: list[str] = []

    def lookup() -> None:
        try:
            result.append(socket.gethostbyaddr(ip)[0].lower())
        except (socket.herror, socket.gaierror, OSError):
            pass

    thread = threading.Thread(target=lookup, daemon=True)
    thread.start()
    thread.join(max(0.01, timeout))
    return result[0] if result else ""


_NETBIOS_NAME_RE = re.compile(
    r"^\s*([A-Z0-9][A-Z0-9_\-\.\$ ]{0,14})\s*<(?P<suffix>[0-9A-F]{2})>"
)


def _netbios_lookup(ip: str, timeout: float) -> str:
    """Resolve a NetBIOS workstation name for ``ip`` (Windows/Samba helper).

    Many home/office devices have empty reverse-DNS but answer NetBIOS name
    requests on UDP/137. We try OS-native helpers (``nbtstat`` on Windows,
    ``nmblookup`` on POSIX) so the discovery output gets a friendly name.
    """
    if not ip:
        return ""
    is_windows = platform.system().lower().startswith("win")
    candidates: list[list[str]] = []
    if is_windows:
        candidates.append(["nbtstat", "-A", ip])
    else:
        candidates.append(["nmblookup", "-A", ip])
    workstation = ""
    server = ""
    for command in candidates:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=max(0.5, float(timeout)),
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        text = (result.stdout or "") + "\n" + (result.stderr or "")
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.lower().startswith(("name", "node", "mac address")):
                continue
            if "<group>" in stripped.lower() or "group" in stripped.lower().split():
                continue
            match = _NETBIOS_NAME_RE.match(stripped)
            if not match:
                continue
            name = match.group(1).strip()
            suffix = match.group("suffix").upper()
            if not name or name.upper() in {"WORKGROUP", "MSBROWSE", "__MSBROWSE__"}:
                continue
            # 0x00 = workstation/standalone; 0x20 = file server. Prefer 0x00.
            if suffix == "00" and not workstation:
                workstation = name
            elif suffix == "20" and not server:
                server = name
        if workstation or server:
            break
    return (workstation or server).lower()


def _fill_netbios_names(accumulator: _DeviceAccumulator, options: DiscoveryOptions) -> None:
    """Resolve NetBIOS hostnames for devices still missing a hostname.

    Bounded by the same reverse-DNS budget so total enrichment stays cheap.
    """
    budget = max(0, int(options.reverse_dns_budget))
    if budget <= 0:
        return
    timeout = max(0.5, float(options.reverse_dns_timeout) * 6)
    lookups = 0
    for row in accumulator._devices:
        if lookups >= budget or _is_cancelled(options):
            return
        ip = str(row.get("ip") or "")
        if not ip or row.get("hostname"):
            continue
        try:
            name = _netbios_lookup(ip, timeout)
        except Exception:
            name = ""
        lookups += 1
        if name:
            accumulator.merge(
                {"ip": ip, "hostname": name, "discovered_by": ["netbios"]},
                "netbios",
            )


def _normalize_row(raw: Mapping[str, Any], source: str, timestamp: str) -> dict[str, Any]:
    ip = str(raw.get("ip") or raw.get("address") or raw.get("host") or "").strip()
    mac = normalize_mac(str(raw.get("mac") or raw.get("mac_address") or ""))
    hostname = str(raw.get("hostname") or raw.get("name") or "").strip()
    ports = _clean_ports([*(raw.get("open_ports") or []), *(raw.get("ports") or [])])
    discovered_by = [str(item) for item in raw.get("discovered_by") or [] if item]
    if source:
        discovered_by.append(source)
    hints = [str(item) for item in raw.get("device_hints") or raw.get("hints") or [] if item]
    radio = str(raw.get("radio") or "").strip().lower()
    if radio == "bluetooth" and "bluetooth-pnp" not in discovered_by:
        discovered_by.append("bluetooth-pnp")
    services = [str(item) for item in raw.get("services") or [] if item]
    services.extend(_services_for_ports(ports))
    vendor = str(raw.get("vendor") or "").strip() or _vendor_for(mac, " ".join(hints), hostname)
    row_type = guess_device_type(
        ip,
        hostname=hostname,
        mac=mac,
        ports=ports,
        hints=" ".join(hints),
        current_type=str(raw.get("type") or raw.get("type_guess") or ""),
    )
    return {
        "id": str(raw.get("id") or "").strip(),
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "vendor": vendor,
        "open_ports": ports,
        "services": list(dict.fromkeys(services)),
        "discovered_by": list(dict.fromkeys(discovered_by)),
        "device_hints": list(dict.fromkeys(hints)),
        "type": row_type,
        "status": str(raw.get("status") or "online").strip().lower() or "online",
        "first_seen": str(raw.get("first_seen") or raw.get("first_seen_at") or timestamp),
        "last_seen": str(raw.get("last_seen") or raw.get("last_seen_at") or timestamp),
        "parent_device_id": str(raw.get("parent_device_id") or raw.get("parent") or "").strip(),
        "evidence_level": _evidence_level_for(discovered_by, str(raw.get("evidence_level") or "")),
        "radio": radio,
    }


def _with_inferred_peripherals(devices: list[DiscoveryDevice], timestamp: str) -> list[DiscoveryDevice]:
    existing_parent_remote = {
        device.parent_device_id
        for device in devices
        if device.parent_device_id and device.type == "remote" and device.evidence_level == "direct"
    }
    enriched = list(devices)
    for parent in devices:
        if not _should_infer_remote(parent) or parent.id in existing_parent_remote:
            continue
        parent_name = parent.hostname or parent.vendor or parent.ip or "media device"
        inferred = DiscoveryDevice(
            id=_safe_id("peripheral", f"{parent.id}-remote-inferred"),
            hostname=f"{parent_name} remote",
            type="remote",
            status="inferred",
            discovered_by=["inferred-accessory"],
            confidence_score=0.26,
            first_seen=timestamp,
            last_seen=timestamp,
            parent_device_id=parent.id,
            evidence_level="inferred",
            device_hints=[
                "Inferred from parent media-control service; accessory was not directly observed.",
            ],
        )
        enriched.append(inferred)
    return enriched


def _should_infer_remote(device: DiscoveryDevice) -> bool:
    if device.evidence_level == "inferred" or not device.id:
        return False
    hints = " ".join([device.hostname, device.vendor, " ".join(device.services), " ".join(device.device_hints)]).lower()
    if device.type in {"streaming-box", "tv", "game-console"} and (
        set(device.open_ports) & {7000, 8001, 8008, 8009, 8060, 9295, 9308}
        or any(token in hints for token in ("roku", "chromecast", "google tv", "apple tv", "airplay", "xbox"))
    ):
        return True
    return False


def _evidence_level_for(discovered_by: Iterable[str], explicit: str = "") -> str:
    clean = str(explicit or "").strip().lower()
    if clean in {"direct", "inferred"}:
        return clean
    methods = {str(item).lower() for item in discovered_by if item}
    if methods & LOW_CONFIDENCE_METHODS:
        return "inferred"
    return "direct"


def _build_inventory_links(devices: list[DiscoveryDevice]) -> list[dict[str, Any]]:
    router = next((device for device in devices if device.type == "router"), None)
    if router is None:
        router = next((device for device in devices if device.ip.endswith(".1") or device.ip.endswith(".254")), None)
    links: list[dict[str, Any]] = []
    device_ids = {device.id for device in devices if device.id}
    for device in devices:
        if device.parent_device_id and device.parent_device_id in device_ids and device.parent_device_id != device.id:
            links.append(
                {
                    "source": device.parent_device_id,
                    "target": device.id,
                    "kind": "peripheral",
                    "label": "accessory",
                    "confidence": device.confidence_score,
                }
            )
    if router is not None:
        for device in devices:
            if device.id == router.id or device.parent_device_id:
                continue
            links.append(
                {
                    "source": router.id,
                    "target": device.id,
                    "kind": "network",
                    "label": "gateway",
                    "confidence": 0.86,
                }
            )
    return links


def _build_summary(
    network: ipaddress.IPv4Network,
    devices: list[DiscoveryDevice],
    links: list[dict[str, Any]],
    scanned_hosts: int,
    targets: list[str],
    warnings: list[str],
    options: DiscoveryOptions,
) -> dict[str, Any]:
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    open_port_count = 0
    peripheral_count = 0
    inferred_count = 0
    for device in devices:
        by_type[device.type] = by_type.get(device.type, 0) + 1
        open_port_count += len(device.open_ports)
        if device.parent_device_id or device.type in {"remote", "wearable"}:
            peripheral_count += 1
        if device.evidence_level == "inferred":
            inferred_count += 1
        for source in device.discovered_by:
            by_source[source] = by_source.get(source, 0) + 1
    return {
        "device_count": len(devices),
        "link_count": len(links),
        "target_count": len(targets),
        "scanned_host_count": scanned_hosts,
        "open_port_count": open_port_count,
        "peripheral_count": peripheral_count,
        "inferred_count": inferred_count,
        "by_type": dict(sorted(by_type.items())),
        "by_discovery_source": dict(sorted(by_source.items())),
        "private_only": not options.allow_public,
        "large_subnet_allowed": bool(options.allow_large_subnet),
        "passive_only": bool(options.passive_only),
        "cancelled": _is_cancelled(options),
        "warnings": list(warnings),
        "cidr": str(network),
        "smart_home_integrations": {
            "home_assistant": "planned",
            "matter": "planned",
            "router_dhcp_leases": "available",
            "vendor_apis": "planned",
        },
    }


def _security_helper(name: str) -> Callable[..., Any] | None:
    try:
        import solin_security  # type: ignore[import-not-found]
    except Exception:
        return None
    helper = getattr(solin_security, name, None)
    return helper if callable(helper) else None


def _filter_ip_mac_map(raw: Mapping[str, Any], network: ipaddress.IPv4Network) -> dict[str, str]:
    hosts: dict[str, str] = {}
    for ip, mac in raw.items():
        clean_ip = str(ip)
        clean_mac = normalize_mac(str(mac or ""))
        if _ip_in_network(clean_ip, network) and clean_mac:
            hosts[clean_ip] = clean_mac
    return hosts


def _filter_host_rows(raw: Mapping[str, Any], network: ipaddress.IPv4Network) -> dict[str, dict[str, Any]]:
    hosts: dict[str, dict[str, Any]] = {}
    for key, row in raw.items():
        if not isinstance(row, Mapping):
            continue
        ip = str(row.get("ip") or key or "")
        if _ip_in_network(ip, network):
            hosts[ip] = {**dict(row), "ip": ip}
    return hosts


def _target_hosts(network: ipaddress.IPv4Network, max_hosts: int) -> list[str]:
    hosts: list[str] = []
    limit = max(0, int(max_hosts))
    for index, host in enumerate(network.hosts()):
        if index >= limit:
            break
        hosts.append(str(host))
    return hosts


def _ip_in_network(value: str, network: ipaddress.IPv4Network) -> bool:
    try:
        return ipaddress.ip_address(value) in network
    except ValueError:
        return False


def _safe_id(prefix: str, value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.:-]+", "_", value.strip()).strip("_")
    return f"{prefix}_{cleaned or 'unknown'}"


def _device_sort_key(ip: str, hostname: str) -> tuple[int, int, int, int, str]:
    try:
        parts = [int(part) for part in ip.split(".")]
    except ValueError:
        parts = [999, 999, 999, 999]
    return (*((parts + [999, 999, 999, 999])[:4]), hostname.lower())


def _normalize_device_type(value: str = "") -> str:
    clean = str(value or "other").strip().lower().replace("_", "-")
    clean = re.sub(r"[^a-z0-9-]+", "", clean)
    aliases = {
        "accesspoint": "ap",
        "access-point": "ap",
        "gameconsole": "game-console",
        "smartphone": "phone",
        "nas": "storage",
        "television": "tv",
        "streamingbox": "streaming-box",
        "streamer": "streaming-box",
        "media-player": "streaming-box",
        "mediaplayer": "streaming-box",
        "smarthome": "smart-home",
        "iotbridge": "iot-hub",
        "iothub": "iot-hub",
        "watch": "wearable",
        "remotecontrol": "remote",
        "remote-control": "remote",
    }
    return aliases.get(clean, clean) or "other"


def _vendor_for(mac: str, hints: str = "", hostname: str = "") -> str:
    oui = re.sub(r"[^0-9a-fA-F]", "", mac or "").lower()[:6]
    if oui in OUI_VENDOR_HINTS:
        return OUI_VENDOR_HINTS[oui]
    haystack = f"{hints} {hostname}".lower()
    for vendor in (
        "apple",
        "samsung",
        "google",
        "amazon",
        "roku",
        "tp-link",
        "tplink",
        "ubiquiti",
        "sonos",
        "synology",
        "qnap",
        "reolink",
        "wyze",
        "dahua",
        "hikvision",
        "axis",
        "brother",
        "canon",
        "epson",
        "hp",
    ):
        if vendor in haystack:
            return "TP-Link" if vendor == "tplink" else vendor.title()
    return ""


def _services_for_ports(ports: Iterable[int]) -> list[str]:
    return [SERVICE_NAMES.get(int(port), f"tcp/{int(port)}") for port in _clean_ports(ports)]


def _clean_ports(ports: Iterable[Any]) -> list[int]:
    clean: list[int] = []
    for port in ports:
        try:
            value = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= value <= 65535 and value not in clean:
            clean.append(value)
    return sorted(clean)


def _append_unique(target: list[Any], values: Iterable[Any]) -> None:
    for value in values:
        if value is None:
            continue
        item = str(value).strip()
        if item and item not in target:
            target.append(item)


def _append_ports(target: list[Any], values: Iterable[Any]) -> None:
    existing = {int(port) for port in target if str(port).isdigit()}
    for port in values:
        try:
            value = int(port)
        except (TypeError, ValueError):
            continue
        if 1 <= value <= 65535 and value not in existing:
            target.append(value)
            existing.add(value)


def _is_cancelled(options: DiscoveryOptions) -> bool:
    event = options.cancel_event
    return bool(event and event.is_set())

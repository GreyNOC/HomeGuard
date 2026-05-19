from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from dataclasses import dataclass, field
from datetime import datetime

try:  # Python 3.11+
    from datetime import UTC
except ImportError:  # Python 3.10 — fall back to the equivalent timezone.utc
    from datetime import timezone

    UTC = timezone.utc
from typing import Any

try:  # pragma: no cover - optional in packaged runtimes
    import psutil

    HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = False


PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
)


@dataclass(slots=True)
class NetworkSensorConfig:
    passive_only: bool = False
    allow_ping_sweep: bool = True
    allow_tcp_port_check: bool = True
    tcp_ports: list[int] = field(default_factory=lambda: [
        21, 22, 23, 53, 80, 81, 135, 139, 443, 445, 515, 548, 554, 631,
        1883, 2049, 2323, 2869, 3074, 3689, 5000, 5001, 7000, 8000, 8008,
        8009, 8080, 8081, 8443, 8554, 9000, 9100, 10001, 49152, 62078,
    ])
    max_hosts_per_scan: int = 256
    scan_interval_seconds: int = 300
    allow_external_active_probe: bool = False
    include_link_local: bool = False
    command_timeout_seconds: float = 3.0
    tcp_connect_timeout_seconds: float = 0.28
    discovery_workers: int = 128
    tcp_probe_all_hosts: bool = True


@dataclass(slots=True)
class LocalInterface:
    name: str
    local_ip: str
    netmask: str
    cidr: str
    mac_address: str = ""
    gateway: str = ""
    is_private: bool = True

    def as_dict(self) -> dict[str, Any]:
        return {
            "interface": self.name,
            "name": self.name,
            "local_ip": self.local_ip,
            "netmask": self.netmask,
            "cidr": self.cidr,
            "mac_address": self.mac_address,
            "gateway": self.gateway,
            "is_private": self.is_private,
        }


def utcnow() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def normalize_mac(value: str = "") -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(clean) != 12:
        return ""
    return ":".join(clean[index : index + 2] for index in range(0, 12, 2)).lower()


def is_link_local_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_link_local
    except ValueError:
        return False


def is_local_active_ip(value: str, *, include_link_local: bool = False) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if ip.is_loopback or ip.is_unspecified or ip.is_multicast:
        return False
    if ip.is_link_local and not include_link_local:
        return False
    return True


def is_private_or_local_network(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    if network.version != 4:
        return False
    if network.is_loopback or network.is_link_local or network.is_multicast:
        return False
    return network.is_private or any(network.subnet_of(private) for private in PRIVATE_NETWORKS)


def is_private_or_local_ip(value: str, *, include_link_local: bool = False) -> bool:
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if ip.is_link_local:
        return include_link_local
    return ip.is_private or any(ip in private for private in PRIVATE_NETWORKS)


def active_probe_allowed(target_ip: str, local_networks: list[str], config: NetworkSensorConfig) -> bool:
    try:
        ip = ipaddress.ip_address(target_ip)
    except ValueError:
        return False
    if ip.version != 4:
        return False
    if any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in local_networks):
        return True
    return bool(config.allow_external_active_probe)


def _run_command(args: list[str], *, timeout: float) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return "\n".join(part for part in [result.stdout, result.stderr] if part)


def _fallback_ipv4_addresses() -> list[str]:
    addresses: set[str] = set()
    try:
        addresses.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 80))
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass
    return sorted(address for address in addresses if is_local_active_ip(address))


def _gateway_rows(timeout: float) -> dict[str, str]:
    system = platform.system().lower()
    if system == "windows":
        text = _run_command(["route", "print", "-4"], timeout=timeout)
        return _parse_windows_gateways(text)
    if system == "linux":
        text = _run_command(["ip", "-4", "route", "show", "default"], timeout=timeout)
        return _parse_unix_gateways(text)
    text = _run_command(["netstat", "-rn", "-f", "inet"], timeout=timeout)
    return _parse_macos_gateways(text)


def _parse_windows_gateways(text: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in text.splitlines():
        columns = line.split()
        if len(columns) >= 5 and columns[0] == "0.0.0.0" and columns[1] == "0.0.0.0":
            gateway, interface_ip = columns[2], columns[3]
            if is_local_active_ip(interface_ip) and gateway != "0.0.0.0":
                rows[interface_ip] = gateway
    return rows


def _parse_unix_gateways(text: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in text.splitlines():
        columns = line.split()
        if columns[:1] != ["default"] or "via" not in columns:
            continue
        gateway = columns[columns.index("via") + 1]
        source = (
            columns[columns.index("src") + 1]
            if "src" in columns and columns.index("src") + 1 < len(columns)
            else ""
        )
        if source and is_local_active_ip(source) and gateway:
            rows[source] = gateway
    return rows


def _parse_macos_gateways(text: str) -> dict[str, str]:
    rows: dict[str, str] = {}
    for line in text.splitlines():
        columns = line.split()
        if columns[:1] == ["default"] and len(columns) >= 2:
            rows[""] = columns[1]
    return rows


def detect_local_interfaces(config: NetworkSensorConfig | None = None) -> list[LocalInterface]:
    config = config or NetworkSensorConfig()
    gateways = _gateway_rows(config.command_timeout_seconds)
    interfaces: list[LocalInterface] = []
    seen: set[tuple[str, str]] = set()

    if HAS_PSUTIL and psutil is not None:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        for name, rows in addrs.items():
            if not stats.get(name) or not stats[name].isup:
                continue
            mac = ""
            for row in rows:
                if getattr(row, "family", None) == getattr(psutil, "AF_LINK", object()):
                    mac = normalize_mac(str(getattr(row, "address", "") or ""))
                    break
            for row in rows:
                if getattr(row, "family", None) != socket.AF_INET:
                    continue
                ip = str(getattr(row, "address", "") or "")
                netmask = str(getattr(row, "netmask", "") or "")
                if not is_local_active_ip(ip, include_link_local=config.include_link_local) or not netmask:
                    continue
                try:
                    network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
                except ValueError:
                    continue
                if not config.include_link_local and network.is_link_local:
                    continue
                if not is_private_or_local_network(network):
                    continue
                key = (name, ip)
                if key in seen:
                    continue
                seen.add(key)
                interfaces.append(
                    LocalInterface(
                        name=name,
                        local_ip=ip,
                        netmask=netmask,
                        cidr=str(network),
                        mac_address=mac,
                        gateway=gateways.get(ip) or gateways.get("") or "",
                        is_private=is_private_or_local_network(network),
                    )
                )

    if interfaces:
        return sorted(interfaces, key=lambda item: (item.name.lower(), item.local_ip))

    for ip in _fallback_ipv4_addresses():
        if not is_private_or_local_ip(ip, include_link_local=config.include_link_local):
            continue
        network = ipaddress.ip_network(f"{ip}/24", strict=False)
        interfaces.append(
            LocalInterface(
                name="default",
                local_ip=ip,
                netmask="255.255.255.0",
                cidr=str(network),
                gateway=gateways.get(ip) or gateways.get("") or "",
            )
        )
    return interfaces


def local_cidrs(config: NetworkSensorConfig | None = None) -> list[str]:
    return sorted({interface.cidr for interface in detect_local_interfaces(config)})

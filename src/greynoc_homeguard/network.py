from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Any

from .models import Device


COMMON_VENDOR_PREFIXES = {
    "001A11": "Google/Nest",
    "18B430": "Nest",
    "3C5A37": "Google/Nest",
    "F4F5D8": "Google",
    "B827EB": "Raspberry Pi",
    "DCA632": "Raspberry Pi",
    "E45F01": "Raspberry Pi",
    "F0D5BF": "Intel",
    "A4C361": "Apple",
    "F0DBE2": "Apple",
    "BC92B1": "Apple",
    "D850E6": "Samsung",
    "FCF528": "Samsung",
    "001E58": "D-Link",
    "001B2F": "Netgear",
    "9C3DCF": "Netgear",
    "C83A35": "TP-Link",
    "F4F26D": "TP-Link",
    "001D0F": "TP-Link",
    "A0F3C1": "Amazon",
    "44650D": "Amazon",
    "FC65DE": "Amazon",
    "B8782E": "Wyze",
    "44D9E7": "Ubiquiti",
    "FCECDA": "Ubiquiti",
}


@dataclass(slots=True)
class LocalInterface:
    name: str
    ip: str
    cidr: str

    def as_dict(self) -> dict[str, str]:
        return {"name": self.name, "ip": self.ip, "cidr": self.cidr}


@dataclass(slots=True)
class NetworkSensorConfig:
    passive_only: bool = True
    allow_ping_sweep: bool = False
    allow_tcp_port_check: bool = False
    tcp_probe_all_hosts: bool = False
    max_hosts_per_scan: int = 128
    discovery_workers: int = 32
    command_timeout_seconds: float = 1.2
    tcp_connect_timeout_seconds: float = 0.45
    tcp_ports: list[int] = field(
        default_factory=lambda: [22, 23, 53, 80, 139, 443, 445, 554, 3389, 4444, 5555, 5900, 6667, 8080, 8443, 31337]
    )
    cidrs: list[str] = field(default_factory=list)


def normalize_mac(value: str) -> str:
    text = re.sub(r"[^0-9a-fA-F]", "", value or "")
    if len(text) != 12:
        return ""
    return ":".join(text[i : i + 2] for i in range(0, 12, 2)).lower()


def vendor_from_mac(mac: str) -> str:
    clean = re.sub(r"[^0-9a-fA-F]", "", mac or "").upper()
    return COMMON_VENDOR_PREFIXES.get(clean[:6], "")


def is_private_or_local_network(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> bool:
    return bool(
        network.is_private
        or network.is_loopback
        or network.is_link_local
        or network.is_reserved
    )


def active_probe_allowed(ip: str, local_cidrs: list[str], config: NetworkSensorConfig) -> bool:
    try:
        target = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if target.is_multicast or target.is_unspecified:
        return False
    allowed_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in local_cidrs + list(config.cidrs or []):
        try:
            allowed_networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    if allowed_networks and not any(target in network for network in allowed_networks):
        return False
    return bool(target.is_private or target.is_loopback or target.is_link_local)


def _run_command(args: list[str], *, timeout: float) -> str:
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return "\n".join(part for part in [result.stdout, result.stderr] if part)


def _ip_sort_key(value: str) -> tuple[int, int, int, int]:
    try:
        parts = [int(part) for part in value.split(".")]
    except ValueError:
        return (999, 999, 999, 999)
    return tuple((parts + [999, 999, 999, 999])[:4])  # type: ignore[return-value]


def _host_limit(network: ipaddress.IPv4Network, max_hosts: int) -> list[str]:
    return [str(host) for index, host in enumerate(network.hosts()) if index < max(0, max_hosts)]


def parse_arp_table(text: str) -> list[Device]:
    hosts: dict[str, Device] = {}
    current_interface = ""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.lower().startswith("interface:"):
            match = re.search(r"Interface:\s*([0-9.]+)", stripped, re.IGNORECASE)
            current_interface = match.group(1) if match else ""
            continue
        match = re.search(
            r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?P<mac>(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})",
            stripped,
        )
        if not match:
            continue
        ip = match.group("ip")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        mac = normalize_mac(match.group("mac"))
        hosts[ip] = Device(
            ip=ip,
            mac_address=mac,
            interface=current_interface,
            source="arp_table",
            status="observed",
            vendor=vendor_from_mac(mac),
        )
    return sorted(hosts.values(), key=lambda item: _ip_sort_key(item.ip))


def parse_neighbor_table(text: str) -> list[Device]:
    hosts: dict[str, Device] = {}
    for line in text.splitlines():
        columns = line.split()
        if not columns:
            continue
        ip = columns[0]
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            continue
        mac = ""
        if "lladdr" in columns and columns.index("lladdr") + 1 < len(columns):
            mac = normalize_mac(columns[columns.index("lladdr") + 1])
        interface = columns[columns.index("dev") + 1] if "dev" in columns and columns.index("dev") + 1 < len(columns) else ""
        state = columns[-1].lower() if columns[-1].isalpha() else "observed"
        hosts[ip] = Device(
            ip=ip,
            mac_address=mac,
            interface=interface,
            source="neighbor_table",
            status=state,
            vendor=vendor_from_mac(mac),
        )
    return sorted(hosts.values(), key=lambda item: _ip_sort_key(item.ip))


def read_arp_table(config: NetworkSensorConfig | None = None) -> list[Device]:
    config = config or NetworkSensorConfig()
    return parse_arp_table(_run_command(["arp", "-a"], timeout=config.command_timeout_seconds))


def read_neighbor_table(config: NetworkSensorConfig | None = None) -> list[Device]:
    config = config or NetworkSensorConfig()
    system = platform.system().lower()
    if system == "windows":
        text = _run_command(["netsh", "interface", "ip", "show", "neighbors"], timeout=config.command_timeout_seconds)
        return parse_arp_table(text)
    text = _run_command(["ip", "-4", "neigh", "show"], timeout=config.command_timeout_seconds)
    return parse_neighbor_table(text)


def _prefix_to_netmask_length(mask: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen
    except Exception:
        return 24


def _detect_windows_interfaces(config: NetworkSensorConfig) -> list[LocalInterface]:
    text = _run_command(["ipconfig"], timeout=config.command_timeout_seconds)
    interfaces: list[LocalInterface] = []
    block_name = "windows"
    current_ip = ""
    current_mask = "255.255.255.0"
    for line in text.splitlines():
        if line and not line.startswith(" ") and line.rstrip().endswith(":"):
            block_name = line.strip().rstrip(":")
            current_ip = ""
            current_mask = "255.255.255.0"
            continue
        if "IPv4 Address" in line:
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            current_ip = match.group(1) if match else ""
        if "Subnet Mask" in line:
            match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line)
            current_mask = match.group(1) if match else current_mask
        if current_ip:
            prefix = _prefix_to_netmask_length(current_mask)
            interfaces.append(LocalInterface(block_name, current_ip, f"{current_ip}/{prefix}"))
            current_ip = ""
    return interfaces


def _detect_unix_interfaces(config: NetworkSensorConfig) -> list[LocalInterface]:
    text = _run_command(["ip", "-o", "-4", "addr", "show", "scope", "global"], timeout=config.command_timeout_seconds)
    interfaces: list[LocalInterface] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        name = parts[1]
        if "inet" in parts:
            idx = parts.index("inet")
            if idx + 1 < len(parts):
                cidr = parts[idx + 1]
                ip = cidr.split("/", 1)[0]
                interfaces.append(LocalInterface(name, ip, cidr))
    if interfaces:
        return interfaces
    text = _run_command(["ifconfig"], timeout=config.command_timeout_seconds)
    current = "unix"
    for line in text.splitlines():
        if line and not line.startswith((" ", "\t")):
            current = line.split(":", 1)[0].strip() or current
        match = re.search(r"inet\s+(\d{1,3}(?:\.\d{1,3}){3})", line)
        if match:
            ip = match.group(1)
            if not ip.startswith("127."):
                interfaces.append(LocalInterface(current, ip, f"{ip}/24"))
    return interfaces


def detect_local_interfaces(config: NetworkSensorConfig | None = None) -> list[LocalInterface]:
    config = config or NetworkSensorConfig()
    explicit: list[LocalInterface] = []
    for cidr in config.cidrs:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        explicit.append(LocalInterface("configured", str(network.network_address + 1), str(network)))
    if explicit:
        return explicit

    if platform.system().lower() == "windows":
        interfaces = _detect_windows_interfaces(config)
    else:
        interfaces = _detect_unix_interfaces(config)
    if interfaces:
        return interfaces

    fallback: list[LocalInterface] = []
    try:
        hostname = socket.gethostname()
        for item in socket.getaddrinfo(hostname, None, family=socket.AF_INET):
            ip = item[4][0]
            if ip and not ip.startswith("127."):
                fallback.append(LocalInterface("hostname", ip, f"{ip}/24"))
    except OSError:
        pass
    return fallback


def _ping_args(ip: str) -> list[str]:
    if platform.system().lower() == "windows":
        return ["ping", "-n", "1", "-w", "700", ip]
    return ["ping", "-c", "1", "-W", "1", ip]


def _ping_host(ip: str, timeout: float) -> bool:
    text = _run_command(_ping_args(ip), timeout=timeout)
    lower = text.lower()
    return "ttl=" in lower or "bytes from" in lower


def _tcp_connect(ip: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((ip, int(port)), timeout=timeout):
            return True
    except OSError:
        return False


def _merge_hosts(hosts: list[Device]) -> list[Device]:
    by_ip: dict[str, Device] = {}
    for host in hosts:
        current = by_ip.get(host.ip)
        if current is None:
            host.open_ports = sorted(set(host.open_ports))
            if not host.vendor:
                host.vendor = vendor_from_mac(host.mac_address)
            by_ip[host.ip] = host
            continue
        current.mac_address = current.mac_address or host.mac_address
        current.hostname = current.hostname or host.hostname
        current.interface = current.interface or host.interface
        current.vendor = current.vendor or host.vendor or vendor_from_mac(current.mac_address)
        current.status = "online" if "online" in {current.status, host.status} else current.status
        current.source = ",".join(sorted(set(current.source.split(",")) | set(host.source.split(","))))
        current.open_ports = sorted(set(current.open_ports) | set(host.open_ports))
        current.metadata.update(host.metadata)
    return sorted(by_ip.values(), key=lambda item: _ip_sort_key(item.ip))


def _read_passive_hosts(config: NetworkSensorConfig) -> list[Device]:
    readers = (read_arp_table, read_neighbor_table)
    hosts: list[Device] = []
    with ThreadPoolExecutor(max_workers=len(readers)) as executor:
        futures = [executor.submit(reader, config) for reader in readers]
        for future in as_completed(futures):
            try:
                hosts.extend(future.result())
            except Exception:
                continue
    return hosts


def _active_targets(
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    local_cidrs: list[str],
    config: NetworkSensorConfig,
) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for network in networks:
        if network.version != 4 or not is_private_or_local_network(network):
            continue
        for ip in _host_limit(network, config.max_hosts_per_scan - len(targets)):
            if ip in seen or not active_probe_allowed(ip, local_cidrs, config):
                continue
            seen.add(ip)
            targets.append(ip)
            if len(targets) >= config.max_hosts_per_scan:
                break
    return targets


def _ping_sweep(targets: list[str], config: NetworkSensorConfig) -> list[Device]:
    discovered: list[Device] = []
    if not targets:
        return discovered
    with ThreadPoolExecutor(max_workers=min(config.discovery_workers, max(1, len(targets)))) as executor:
        futures = {executor.submit(_ping_host, ip, config.command_timeout_seconds): ip for ip in targets}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                online = future.result()
            except Exception:
                online = False
            if online:
                discovered.append(Device(ip=ip, source="ping_sweep", status="online"))
    return discovered


def _tcp_port_checks(target_ips: list[str], local_cidrs: list[str], config: NetworkSensorConfig) -> list[Device]:
    ports = [int(port) for port in config.tcp_ports if 0 < int(port) <= 65535]
    targets = [ip for ip in dict.fromkeys(target_ips) if active_probe_allowed(ip, local_cidrs, config)]
    results: dict[str, list[int]] = {ip: [] for ip in targets}
    checks = [(ip, port) for ip in targets[: config.max_hosts_per_scan] for port in ports]
    if not checks:
        return []
    with ThreadPoolExecutor(max_workers=min(config.discovery_workers, max(1, len(checks)))) as executor:
        futures = {
            executor.submit(_tcp_connect, ip, port, config.tcp_connect_timeout_seconds): (ip, port)
            for ip, port in checks
        }
        for future in as_completed(futures):
            ip, port = futures[future]
            try:
                open_port = future.result()
            except Exception:
                open_port = False
            if open_port:
                results.setdefault(ip, []).append(port)
    return [
        Device(
            ip=ip,
            source="tcp_connect_check",
            status="online",
            open_ports=sorted(open_ports),
            metadata={"active_probe_performed": True, "tcp_ports_checked": len(ports)},
        )
        for ip, open_ports in results.items()
        if open_ports
    ]


def discover_lan_hosts(config: NetworkSensorConfig | None = None) -> list[Device]:
    config = config or NetworkSensorConfig()
    interfaces = detect_local_interfaces(config)
    local_cidrs = [interface.cidr for interface in interfaces]
    local_networks = [ipaddress.ip_network(cidr, strict=False) for cidr in local_cidrs]
    hosts = _read_passive_hosts(config)
    hosts = [
        host
        for host in hosts
        if any(ipaddress.ip_address(host.ip) in network for network in local_networks)
    ]

    if not config.passive_only:
        targets = _active_targets(local_networks, local_cidrs, config)
        active_results: list[Device] = []
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = []
            if config.allow_ping_sweep:
                futures.append(executor.submit(_ping_sweep, targets, config))
            if config.allow_tcp_port_check:
                known_ips = [host.ip for host in _merge_hosts(hosts)]
                tcp_targets = targets if config.tcp_probe_all_hosts else known_ips
                futures.append(executor.submit(_tcp_port_checks, tcp_targets, local_cidrs, config))
            for future in as_completed(futures):
                try:
                    active_results.extend(future.result())
                except Exception:
                    continue
        hosts.extend(active_results)
    return _merge_hosts(hosts)

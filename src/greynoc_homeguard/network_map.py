"""Local device + cloud node network map.

This is HomeGuard's adaptation of the GreyNOC saturn ``noc_core.network_mapper``
engine. Saturn's mapper is coupled to its scan-report ``store``; this module
builds the same shape of graph (nodes + links, local vs cloud) directly from
HomeGuard's own data:

  * **Local devices** come from the latest scan ``report.json`` (already strictly
    LAN-scoped by the discovery pipeline) enriched with trust/owner/type from the
    known-device baseline.
  * **Cloud nodes** come from :mod:`greynoc_homeguard.ai_traffic` — this host's
    live *external* connections (remote IP/port/process). HomeGuard runs on one
    machine, so it can map this host's cloud links reliably; per-device cloud
    edges for other LAN hosts would require router flow data and are out of scope.

The result is a JSON document the Electron "Network Map" tab renders as a
topology: a cloud tier on top, the gateway/router, this host, and the LAN
devices, with peripheral/inactive devices collapsed into bundles so a
decent-sized home lab stays readable.
"""

from __future__ import annotations

import ipaddress
import json
import socket
from typing import Any

from . import ai_traffic
from .logging_setup import get_logger
from .models import utcnow
from .paths import default_baseline_path, latest_report_dir

LOG = get_logger("network_map")

ROUTER_TYPES = {"router", "gateway", "ap", "switch"}
PERIPHERAL_TYPES = {"wearable", "remote", "bluetooth"}
INACTIVE_STATUSES = {"offline", "inactive", "stale", "down"}
SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_SCORE = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 0}
MAX_CLOUD_NODES = 40
MAX_DNS_RESOLVES = 24


def _is_private(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    return bool(parsed.is_private or parsed.is_loopback or parsed.is_link_local)


def _ip_sort_key(value: str) -> tuple[int, int, int, int]:
    try:
        parts = [int(part) for part in str(value).split(".")]
    except ValueError:
        return (999, 999, 999, 999)
    return tuple((parts + [999, 999, 999, 999])[:4])  # type: ignore[return-value]


def _safe_id(prefix: str, value: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in ".:-_" else "_" for ch in str(value).strip())
    return f"{prefix}_{cleaned.strip('_') or 'unknown'}"


def _load_latest_report() -> dict[str, Any]:
    path = latest_report_dir() / "report.json"
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _load_baseline_records() -> dict[str, dict[str, Any]]:
    path = default_baseline_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    devices = data.get("devices") if isinstance(data, dict) else None
    return devices if isinstance(devices, dict) else {}


def _lan_interface_ips_and_cidrs() -> tuple[set[str], list[str]]:
    """LAN interface IPs and CIDRs from the same VPN-filtered source discovery
    uses (:func:`network.detect_local_interfaces`). Empty on any failure."""
    ips: set[str] = set()
    cidrs: list[str] = []
    try:
        from .network import detect_local_interfaces

        for iface in detect_local_interfaces():
            ip = str(getattr(iface, "ip", "") or "")
            cidr = str(getattr(iface, "cidr", "") or "")
            if ip and _is_private(ip) and not ip.startswith("169.254."):
                ips.add(ip)
            if cidr:
                cidrs.append(cidr)
    except Exception:  # pragma: no cover - defensive
        pass
    return ips, cidrs


def _local_host_ips() -> set[str]:
    # Prefer the VPN-filtered LAN interfaces discovery uses, so the map's
    # "this PC" node and CIDR track the physical LAN even on a full-tunnel VPN
    # (where a default-route probe would return the VPN tunnel address and the
    # hostname may only resolve to loopback).
    lan_ips, _ = _lan_interface_ips_and_cidrs()
    if lan_ips:
        return lan_ips
    addresses: set[str] = set()
    try:
        addresses.update(socket.gethostbyname_ex(socket.gethostname())[2])
    except OSError:
        pass
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            addresses.add(sock.getsockname()[0])
    except OSError:
        pass
    return {ip for ip in addresses if _is_private(ip) and not str(ip).startswith("169.254.")}


def _baseline_index(records: dict[str, dict[str, Any]]) -> tuple[dict[str, dict], dict[str, dict]]:
    by_ip: dict[str, dict[str, Any]] = {}
    by_mac: dict[str, dict[str, Any]] = {}
    for record in records.values():
        if not isinstance(record, dict):
            continue
        ip = str(record.get("ip") or "")
        mac = str(record.get("mac_address") or record.get("mac") or "").lower()
        if ip:
            by_ip.setdefault(ip, record)
        if mac:
            by_mac.setdefault(mac, record)
    return by_ip, by_mac


def _device_type(device: dict[str, Any], baseline: dict[str, Any]) -> str:
    metadata = device.get("metadata") if isinstance(device.get("metadata"), dict) else {}
    for candidate in (
        baseline.get("device_type"),
        metadata.get("device_type"),
        metadata.get("device_type_auto"),
        metadata.get("device_type_guess"),
    ):
        clean = str(candidate or "").strip().lower()
        if clean and clean not in {"unknown", "other"}:
            return clean
    return "other"


def _friendly_name(device: dict[str, Any], baseline: dict[str, Any]) -> str:
    metadata = device.get("metadata") if isinstance(device.get("metadata"), dict) else {}
    return str(
        baseline.get("friendly_name")
        or device.get("hostname")
        or baseline.get("hostname")
        or metadata.get("friendly_name")
        or device.get("vendor")
        or baseline.get("vendor")
        or device.get("ip")
        or "device"
    )


def _findings_by_ip(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for finding in report.get("findings") or []:
        if not isinstance(finding, dict):
            continue
        ip = str(finding.get("device_ip") or "")
        if ip:
            grouped.setdefault(ip, []).append(finding)
    return grouped


def _risk_for(findings: list[dict[str, Any]], port_count: int) -> tuple[int, str]:
    severity = "info"
    for finding in findings:
        candidate = str(finding.get("severity") or "info").lower()
        if SEVERITY_RANK.get(candidate, 1) > SEVERITY_RANK.get(severity, 1):
            severity = candidate
    score = min(25, port_count * 4) + SEVERITY_SCORE.get(severity, 0)
    return min(100, score), severity


def _detect_cidr(report: dict[str, Any], host_ips: set[str]) -> str:
    # Prefer a CIDR that actually contains one of the host IPs, drawn from the
    # scan report's interfaces and the live VPN-filtered LAN interfaces.
    candidates: list[str] = []
    metadata = report.get("scan_metadata") if isinstance(report.get("scan_metadata"), dict) else {}
    for interface in metadata.get("interfaces") or []:
        if isinstance(interface, dict) and interface.get("cidr"):
            candidates.append(str(interface.get("cidr")))
    _lan_ips, lan_cidrs = _lan_interface_ips_and_cidrs()
    candidates.extend(lan_cidrs)
    for cidr in candidates:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if any(ipaddress.ip_address(ip) in network for ip in host_ips if _is_private(ip)):
            return str(network)
    for ip in sorted(host_ips):
        try:
            return str(ipaddress.ip_network(f"{ip}/24", strict=False))
        except ValueError:
            continue
    return ""


def _gateway_ip(cidr: str) -> str:
    if not cidr:
        return ""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return ""
    return str(network.network_address + 1)


def _device_node(
    device: dict[str, Any],
    *,
    host_ips: set[str],
    gateway_ip: str,
    by_ip: dict[str, dict],
    by_mac: dict[str, dict],
    findings_by_ip: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    ip = str(device.get("ip") or "")
    mac = str(device.get("mac_address") or device.get("mac") or "").lower()
    baseline = by_ip.get(ip) or by_mac.get(mac) or {}
    metadata = device.get("metadata") if isinstance(device.get("metadata"), dict) else {}
    ports = sorted({int(p) for p in device.get("open_ports") or device.get("ports") or [] if str(p).isdigit()})
    device_type = _device_type(device, baseline)
    is_local = ip in host_ips
    is_gateway = bool(ip and gateway_ip and ip == gateway_ip) or device_type in {"router", "gateway"}
    if is_gateway:
        map_role = "router"
    elif is_local:
        map_role = "local"
    else:
        map_role = ""
    findings = findings_by_ip.get(ip, [])
    risk, severity = _risk_for(findings, len(ports))
    status = str(device.get("status") or "online").lower()
    if status in {"observed", "seen", ""}:
        status = "online"
    return {
        "id": _safe_id("dev", ip or mac or _friendly_name(device, baseline)),
        "tier": "local",
        "ip": ip,
        "mac": mac,
        "hostname": str(device.get("hostname") or baseline.get("hostname") or ""),
        "friendly_name": _friendly_name(device, baseline),
        "vendor": str(device.get("vendor") or baseline.get("vendor") or ""),
        "type": "router" if is_gateway else device_type,
        "status": status,
        "is_local": is_local,
        "map_role": map_role,
        "trust": str(baseline.get("trust") or "unknown"),
        "owner": str(baseline.get("owner") or "unknown"),
        "ports": ports,
        "open_ports": ports,
        "risk": risk,
        "severity": severity,
        "finding_count": len(findings),
        "discovered_by": [s for s in str(device.get("source") or "").split(",") if s],
        "last_seen_at": str(baseline.get("last_seen") or metadata.get("last_seen_at") or ""),
    }


def _ensure_local_host(devices: list[dict[str, Any]], host_ips: set[str]) -> dict[str, Any]:
    for node in devices:
        if node.get("is_local"):
            return node
    hostname = socket.gethostname()
    ip = next(iter(sorted(host_ips)), "127.0.0.1")
    node = {
        "id": _safe_id("dev", ip),
        "tier": "local",
        "ip": ip,
        "mac": "",
        "hostname": hostname,
        "friendly_name": f"{hostname} (this PC)",
        "vendor": "",
        "type": "workstation",
        "status": "online",
        "is_local": True,
        "map_role": "local",
        "trust": "trusted",
        "owner": "unknown",
        "ports": [],
        "open_ports": [],
        "risk": 0,
        "severity": "info",
        "finding_count": 0,
        "discovered_by": ["local-host"],
        "last_seen_at": utcnow(),
    }
    devices.append(node)
    return node


def _cloud_nodes(*, resolve_dns: bool) -> list[dict[str, Any]]:
    try:
        summary = ai_traffic.collect_traffic_summary(share_level="full")
    except Exception as exc:  # pragma: no cover - defensive
        LOG.debug("traffic summary failed: %s", exc)
        return []
    grouped: dict[str, dict[str, Any]] = {}
    for entry in summary.established_remote_top:
        if str(entry.get("scope") or "") != "external":
            continue
        address = str(entry.get("endpoint") or "")
        if not address or _is_private(address):
            continue
        node = grouped.setdefault(
            address,
            {
                "id": _safe_id("cloud", address),
                "tier": "cloud",
                "type": "cloud",
                "ip": address,
                "label": address,
                "hostname": "",
                "ports": [],
                "connection_count": 0,
                "scope": "external",
            },
        )
        port = int(entry.get("port") or 0)
        if port and port not in node["ports"]:
            node["ports"].append(port)
        node["connection_count"] += int(entry.get("count") or 1)
    nodes = sorted(grouped.values(), key=lambda item: item["connection_count"], reverse=True)[:MAX_CLOUD_NODES]
    if resolve_dns:
        for node in nodes[:MAX_DNS_RESOLVES]:
            name = ai_traffic.hostname_for_endpoint(node["ip"])
            if name:
                node["hostname"] = name
                node["label"] = name
    for node in nodes:
        node["ports"] = sorted(node["ports"])
    return nodes


def _build_links(
    devices: list[dict[str, Any]],
    cloud_nodes: list[dict[str, Any]],
    *,
    host_node: dict[str, Any],
    gateway_node: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    links: list[dict[str, Any]] = []
    parent = gateway_node or host_node
    if gateway_node and host_node["id"] != gateway_node["id"]:
        links.append({
            "source": host_node["id"],
            "target": gateway_node["id"],
            "kind": "gateway",
            "label": "gateway",
            "confidence": 0.9,
        })
    for device in devices:
        if device["id"] == parent["id"]:
            continue
        links.append({
            "source": parent["id"],
            "target": device["id"],
            "kind": "network",
            "label": "gateway" if gateway_node else "local-view",
            "confidence": 0.86 if gateway_node else 0.55,
        })
    for node in cloud_nodes:
        links.append({
            "source": host_node["id"],
            "target": node["id"],
            "kind": "cloud",
            "label": "internet",
            "confidence": 0.7,
        })
    return links


def _is_peripheral(node: dict[str, Any]) -> bool:
    return str(node.get("type") or "").lower() in PERIPHERAL_TYPES or "bluetooth" in (node.get("discovered_by") or [])


def _is_inactive(node: dict[str, Any]) -> bool:
    return str(node.get("status") or "").lower() in INACTIVE_STATUSES


def _bundle(node_list: list[dict[str, Any]], *, bundle_id: str, label: str, bundle_type: str) -> dict[str, Any]:
    return {
        "id": bundle_id,
        "tier": "local",
        "type": bundle_type,
        "hostname": f"{len(node_list)} {label}",
        "label": f"{len(node_list)} {label}",
        "ip": "",
        "status": "collapsed",
        "collapsed": True,
        "count": len(node_list),
        "risk": max([int(n.get("risk") or 0) for n in node_list] or [0]),
        "severity": "info",
        "children": [n["id"] for n in node_list],
    }


def _flow_device_node(src_ip: str, *, host_ips: set[str]) -> dict[str, Any]:
    """Minimal local node for a LAN device seen only in router flow data
    (present in conntrack but not in the latest scan report)."""
    return {
        "id": _safe_id("dev", src_ip),
        "tier": "local",
        "ip": src_ip,
        "mac": "",
        "hostname": "",
        "friendly_name": src_ip,
        "vendor": "",
        "type": "other",
        "status": "online",
        "is_local": src_ip in host_ips,
        "map_role": "local" if src_ip in host_ips else "",
        "trust": "unknown",
        "owner": "unknown",
        "ports": [],
        "open_ports": [],
        "risk": 0,
        "severity": "info",
        "finding_count": 0,
        "discovered_by": ["router-flow"],
        "last_seen_at": "",
    }


def _merge_flow_edges(
    active: list[dict[str, Any]],
    peripheral: list[dict[str, Any]],
    inactive: list[dict[str, Any]],
    cloud_nodes: list[dict[str, Any]],
    flow_edges: list[dict[str, Any]],
    *,
    host_ips: set[str],
    resolve_dns: bool,
) -> tuple[list[dict[str, Any]], int]:
    """Fold per-device router-flow edges into the map in place.

    Each edge adds a device->cloud link; external dst IPs become shared cloud
    nodes. Device lookup spans *all* nodes (active + bundled) so an edge never
    creates a duplicate of a device that was collapsed into a bundle; a bundled
    device with live internet flow is **promoted** to the active set (it is not
    really peripheral/inactive). LAN srcs with no known node get a lightweight
    node. Returns ``(flow_links, count)``."""
    cloud_by_ip = {str(n.get("ip")): n for n in cloud_nodes if n.get("ip")}
    device_by_ip = {str(n.get("ip")): n for n in (active + peripheral + inactive) if n.get("ip")}
    active_ids = {n["id"] for n in active}
    flow_links: list[dict[str, Any]] = []
    link_keys: set[tuple[str, str, str]] = set()
    new_cloud: list[dict[str, Any]] = []
    added = 0
    for edge in flow_edges:
        src = str(edge.get("src_lan_ip") or "")
        dst = str(edge.get("dst_ip") or "")
        if not src or not dst:
            continue
        device = device_by_ip.get(src)
        if device is None:
            device = _flow_device_node(src, host_ips=host_ips)
            active.append(device)
            active_ids.add(device["id"])
            device_by_ip[src] = device
        elif device["id"] not in active_ids:
            # A device with live internet flow is active, not peripheral/inactive.
            active.append(device)
            active_ids.add(device["id"])
            for bundle_list in (peripheral, inactive):
                bundle_list[:] = [n for n in bundle_list if n["id"] != device["id"]]
        cloud = cloud_by_ip.get(dst)
        if cloud is None:
            cloud = {
                "id": _safe_id("cloud", dst),
                "tier": "cloud",
                "type": "cloud",
                "ip": dst,
                "label": dst,
                "hostname": "",
                "ports": [],
                "connection_count": 0,
                "scope": "external",
                "source": "router-flow",
            }
            cloud_nodes.append(cloud)
            cloud_by_ip[dst] = cloud
            new_cloud.append(cloud)
        port = int(edge.get("dst_port") or 0)
        if port and port not in cloud["ports"]:
            cloud["ports"].append(port)
        cloud["connection_count"] = int(cloud.get("connection_count") or 0) + 1
        key = (device["id"], cloud["id"], "cloud")
        if key not in link_keys:
            flow_links.append({
                "source": device["id"],
                "target": cloud["id"],
                "kind": "cloud",
                "label": "flow",
                "confidence": 0.8,
            })
            link_keys.add(key)
            added += 1
    if resolve_dns and new_cloud:
        for node in new_cloud[:MAX_DNS_RESOLVES]:
            name = ai_traffic.hostname_for_endpoint(node["ip"])
            if name:
                node["hostname"] = name
                node["label"] = name
    for node in cloud_nodes:
        node["ports"] = sorted(set(node.get("ports") or []))
    active.sort(key=lambda item: _ip_sort_key(str(item.get("ip") or "")))
    return flow_links, added


def build_network_map(
    *,
    report: dict[str, Any] | None = None,
    resolve_dns: bool = False,
    flow_edges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build the local-device + cloud-node map as a JSON-able dict.

    ``resolve_dns`` is **off by default** (sterile/privacy-preserving). When
    enabled, cloud endpoints get a bounded reverse-DNS pass — that sends the
    user's current external connection IPs to their DNS resolver, so it must be
    an explicit opt-in, mirroring :func:`ai_traffic.hostname_for_endpoint`'s
    deliberate avoidance of bulk resolution.
    """
    report = report if report is not None else _load_latest_report()
    baseline_records = _load_baseline_records()
    by_ip, by_mac = _baseline_index(baseline_records)
    host_ips = _local_host_ips()
    cidr = _detect_cidr(report, host_ips)
    gateway_ip = _gateway_ip(cidr)
    findings_by_ip = _findings_by_ip(report)

    seen_ids: set[str] = set()
    all_nodes: list[dict[str, Any]] = []
    for device in report.get("devices") or []:
        if not isinstance(device, dict) or not device.get("ip"):
            continue
        node = _device_node(
            device,
            host_ips=host_ips,
            gateway_ip=gateway_ip,
            by_ip=by_ip,
            by_mac=by_mac,
            findings_by_ip=findings_by_ip,
        )
        if node["id"] in seen_ids:
            continue
        seen_ids.add(node["id"])
        all_nodes.append(node)

    host_node = _ensure_local_host(all_nodes, host_ips)
    gateway_node = next((n for n in all_nodes if n.get("map_role") == "router"), None)

    all_nodes.sort(key=lambda item: _ip_sort_key(str(item.get("ip") or "")))
    peripheral = [n for n in all_nodes if _is_peripheral(n) and not n.get("is_local")]
    inactive = [n for n in all_nodes if _is_inactive(n) and not _is_peripheral(n) and not n.get("is_local")]
    bundled_ids = {n["id"] for n in peripheral} | {n["id"] for n in inactive}
    active = [n for n in all_nodes if n["id"] not in bundled_ids]

    cloud_nodes = _cloud_nodes(resolve_dns=resolve_dns)

    # Merge router-flow edges first (it may promote a bundled device with live
    # internet flow back into the active set) so links are built over the final
    # active set and the promoted device gets its gateway link too.
    flow_links: list[dict[str, Any]] = []
    flow_edge_count = 0
    if flow_edges:
        flow_links, flow_edge_count = _merge_flow_edges(
            active, peripheral, inactive, cloud_nodes, flow_edges, host_ips=host_ips, resolve_dns=resolve_dns
        )

    links = _build_links(active, cloud_nodes, host_node=host_node, gateway_node=gateway_node) + flow_links

    visible = list(active)
    if peripheral:
        visible.append(_bundle(peripheral, bundle_id="bundle_peripheral", label="wearables/remotes", bundle_type="peripheral-bundle"))
    if inactive:
        visible.append(_bundle(inactive, bundle_id="bundle_inactive", label="inactive devices", bundle_type="inactive-bundle"))

    return {
        "generated_at": utcnow(),
        "cidr": cidr,
        "gateway_ip": gateway_ip,
        "host_id": host_node["id"],
        "gateway_id": gateway_node["id"] if gateway_node else "",
        "devices": visible,
        "active_devices": active,
        "inactive_devices": inactive,
        "peripheral_devices": peripheral,
        "cloud_nodes": cloud_nodes,
        "links": links,
        "stats": {
            "local_device_count": len(active),
            "inactive_count": len(inactive),
            "peripheral_count": len(peripheral),
            "cloud_node_count": len(cloud_nodes),
            "finding_count": sum(len(v) for v in findings_by_ip.values()),
            "per_device_cloud_edges": flow_edge_count,
        },
        "source": {
            "report_id": str(report.get("report_id") or ""),
            "last_scan_at": str(report.get("created_at") or ""),
            "has_report": bool(report.get("devices")),
        },
    }

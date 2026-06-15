"""Per-device cloud edges from the router's connection table (Phase 1).

HomeGuard's host-only `ai_traffic` view can't see what *other* LAN devices talk
to on the internet. This module closes that gap by reading the router's
**conntrack** table — which records every ``LAN-device -> external-endpoint``
mapping with the pre-NAT LAN source IP intact — over an outbound SSH poll. There
is **no packet capture** and **no listening socket**: HomeGuard initiates the
connection, so this adds zero inbound attack surface.

Phase 1 ships the **OpenWrt / DD-WRT** connector (``cat /proc/net/nf_conntrack``
over the system ``ssh`` client, so no new Python dependency). The parser and edge
classifier are pure and unit-tested; other router families (OPNsense, pfSense,
MikroTik, UniFi) are additive implementations of the same tiny interface.

Privacy: this is **opt-in, off by default** (sterile parity). Flows are fetched
live when the map is built and are **not persisted** — HomeGuard never stores the
household's browsing-destination history. See ``docs/design/PER_DEVICE_CLOUD_MAP.md``.
"""

from __future__ import annotations

import ipaddress
import os
import re
import subprocess
from dataclasses import dataclass
from typing import Any, Iterable

from .logging_setup import get_logger
from .models import utcnow

LOG = get_logger("flow_source")

CONNTRACK_MAX_LINES = 20000
MAX_FLOW_EDGES = 2000
SSH_CONNECT_TIMEOUT = 10
SSH_OVERALL_TIMEOUT = 20

_SRC_RE = re.compile(r"\bsrc=(\S+)")
_DST_RE = re.compile(r"\bdst=(\S+)")
_DPORT_RE = re.compile(r"\bdport=(\d+)")
_BYTES_RE = re.compile(r"\bbytes=(\d+)")
_PROTO_RE = re.compile(r"\b(tcp|udp|icmp|udplite|sctp|dccp)\b", re.IGNORECASE)
# Conservative allow-lists so an odd/hostile host or user can never be parsed by
# the ssh client as an option (e.g. a leading '-' or whitespace). Hostnames /
# IPv4 / bracketed IPv6 use these chars; users are typical login-name chars.
_SAFE_HOST_RE = re.compile(r"^[A-Za-z0-9_.:\[\]-]+$")
_SAFE_USER_RE = re.compile(r"^[A-Za-z0-9_.-]+$")


class FlowSourceError(RuntimeError):
    """Raised when the router flow source cannot be read."""


@dataclass(slots=True)
class FlowRecord:
    src_lan_ip: str
    dst_ip: str
    dst_port: int = 0
    proto: str = ""
    bytes: int = 0
    last_seen: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "src_lan_ip": self.src_lan_ip,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "bytes": self.bytes,
            "last_seen": self.last_seen,
        }


def _is_private(ip: str) -> bool:
    try:
        parsed = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    return bool(parsed.is_private or parsed.is_loopback or parsed.is_link_local)


def _is_global(ip: str) -> bool:
    """True only for a routable public unicast address.

    ``ipaddress.is_global`` alone treats multicast as global on IPv4, so a
    device's mDNS/SSDP multicast traffic would otherwise become a bogus "cloud
    node". Exclude every non-public-unicast class explicitly.
    """
    try:
        parsed = ipaddress.ip_address(str(ip).split("%", 1)[0])
    except ValueError:
        return False
    return not (
        parsed.is_private
        or parsed.is_loopback
        or parsed.is_link_local
        or parsed.is_multicast
        or parsed.is_reserved
        or parsed.is_unspecified
    )


def parse_nf_conntrack(text: str, *, max_lines: int = CONNTRACK_MAX_LINES, now: str | None = None) -> list[FlowRecord]:
    """Parse Linux ``/proc/net/nf_conntrack`` text into flow records.

    Each line's *original* tuple is the first ``src=``/``dst=``/``dport=`` — for
    an outbound connection that is the LAN device, the external endpoint it dialed,
    and the service port. Lines are not validated as LAN->WAN here; that filtering
    is :func:`classify_edges`'s job.
    """
    stamp = now or utcnow()
    records: list[FlowRecord] = []
    for line in text.splitlines()[:max_lines]:
        src = _SRC_RE.search(line)
        dst = _DST_RE.search(line)
        if not src or not dst:
            continue
        proto = _PROTO_RE.search(line)
        dport = _DPORT_RE.search(line)
        size = _BYTES_RE.search(line)
        records.append(
            FlowRecord(
                src_lan_ip=src.group(1),
                dst_ip=dst.group(1),
                dst_port=int(dport.group(1)) if dport else 0,
                proto=(proto.group(1).lower() if proto else ""),
                bytes=int(size.group(1)) if size else 0,
                last_seen=stamp,
            )
        )
    return records


def classify_edges(
    records: Iterable[FlowRecord],
    *,
    exclude_ips: set[str] | None = None,
    max_edges: int = MAX_FLOW_EDGES,
) -> list[FlowRecord]:
    """Keep only ``private LAN src -> public/global dst`` edges, deduplicated.

    LAN-to-LAN and any non-global destination (multicast, private, CGNAT-internal)
    are dropped, so the result is exactly the device->internet edges the map draws.
    """
    exclude = exclude_ips or set()
    merged: dict[tuple[str, str, int], FlowRecord] = {}
    for record in records:
        src = record.src_lan_ip
        dst = record.dst_ip
        if not src or not dst:
            continue
        if not _is_private(src) or not _is_global(dst):
            continue
        if src in exclude:
            continue
        key = (src, dst, record.dst_port)
        existing = merged.get(key)
        if existing is None:
            merged[key] = record
        else:
            existing.bytes = max(existing.bytes, record.bytes)
            existing.last_seen = record.last_seen or existing.last_seen
        if len(merged) >= max_edges:
            break
    return list(merged.values())


@dataclass(slots=True)
class OpenWrtConntrackSource:
    """Read ``/proc/net/nf_conntrack`` from an OpenWrt/DD-WRT (or any Linux)
    router over the system ``ssh`` client using key-based auth."""

    host: str
    user: str = "root"
    port: int = 22
    key_path: str = ""
    timeout: float = SSH_OVERALL_TIMEOUT
    command: str = "cat /proc/net/nf_conntrack"

    def _ssh_args(self) -> list[str]:
        args = [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", f"ConnectTimeout={int(SSH_CONNECT_TIMEOUT)}",
            "-p", str(int(self.port)),
        ]
        if self.key_path:
            args += ["-i", self.key_path]
        args += [f"{self.user}@{self.host}", self.command]
        return args

    def fetch(self) -> str:
        if not self.host:
            raise FlowSourceError("No router host configured.")
        # Reject anything the ssh client could misread as an option/flag, so a
        # crafted host/user can never inject extra ssh arguments.
        if self.host.startswith("-") or not _SAFE_HOST_RE.match(self.host):
            raise FlowSourceError(f"Invalid router host: {self.host!r}")
        if self.user and (self.user.startswith("-") or not _SAFE_USER_RE.match(self.user)):
            raise FlowSourceError(f"Invalid SSH user: {self.user!r}")
        try:
            result = subprocess.run(
                self._ssh_args(),
                capture_output=True,
                text=True,
                timeout=self.timeout + 5,
                check=False,
            )
        except FileNotFoundError as exc:
            raise FlowSourceError("The 'ssh' client was not found on this system.") from exc
        except subprocess.SubprocessError as exc:
            raise FlowSourceError(f"SSH to the router failed: {exc}") from exc
        if result.returncode != 0:
            raise FlowSourceError(
                f"Router conntrack read failed (exit {result.returncode}): "
                f"{(result.stderr or '').strip()[:200]}"
            )
        return result.stdout

    def collect(self, *, exclude_ips: set[str] | None = None) -> list[FlowRecord]:
        return classify_edges(parse_nf_conntrack(self.fetch()), exclude_ips=exclude_ips)


def _source_from_config(config: dict[str, Any]):
    provider = str(config.get("provider") or "openwrt").lower()
    if provider not in {"openwrt", "ddwrt", "linux"}:
        raise FlowSourceError(f"Unsupported flow provider '{provider}'. Phase 1 supports 'openwrt'.")
    key_env = str(config.get("key_env") or "")
    key_path = str(os.environ.get(key_env) or "") if key_env else str(config.get("key_path") or "")
    return OpenWrtConntrackSource(
        host=str(config.get("host") or ""),
        user=str(config.get("user") or "root"),
        port=int(config.get("port") or 22),
        key_path=key_path,
    )


def test_connection(config: dict[str, Any]) -> dict[str, Any]:
    """Attempt a live fetch and report the outcome (for ``GNHL flow test``).

    Unlike :func:`collect_flow_edges`, this surfaces the error instead of
    swallowing it, so the user can diagnose connectivity/credential problems.
    """
    try:
        source = _source_from_config(config)
        edges = source.collect()
    except FlowSourceError as exc:
        return {"ok": False, "edge_count": 0, "error": str(exc), "edges": []}
    except Exception as exc:  # pragma: no cover - defensive
        return {"ok": False, "edge_count": 0, "error": str(exc), "edges": []}
    return {"ok": True, "edge_count": len(edges), "error": "", "edges": [edge.as_dict() for edge in edges]}


def collect_flow_edges(config: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return per-device cloud edges as JSON-able dicts.

    Reads the ``flow_source`` settings block when ``config`` is omitted. Returns
    an empty list when the source is disabled/unconfigured or unreachable — the
    map degrades gracefully to host-only cloud nodes.
    """
    if config is None:
        try:
            from .settings import AppSettings

            config = AppSettings().load().flow_source_config()
        except Exception as exc:  # pragma: no cover - defensive
            LOG.debug("flow settings unavailable: %s", exc)
            return []
    if not config.get("enabled"):
        return []
    try:
        source = _source_from_config(config)
        edges = source.collect()
    except FlowSourceError as exc:
        LOG.warning("Flow source unavailable: %s", exc)
        return []
    except Exception as exc:  # pragma: no cover - defensive
        LOG.warning("Flow source failed: %s", exc)
        return []
    return [edge.as_dict() for edge in edges]

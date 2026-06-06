"""Bounded network-traffic summary for the AI bridge.

HomeGuard intentionally does NOT capture raw packets here. Packet capture
requires elevated privileges, ships sensitive payload bytes, and is hostile
to a sterile-by-default consumer app. Instead we expose a tightly bounded
*connection-summary* view derived from ``psutil.net_connections`` (when
available) and a graceful ``netstat`` fallback.

The output is aggregated by remote endpoint with private/loopback addresses
collapsed and external endpoints hashed at minimal share-level, so the
summary can be sent into the AI prompt without leaking the user's browsing
history.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
import subprocess
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any

try:  # pragma: no cover - psutil is optional in packaged runtimes
    import psutil

    HAS_PSUTIL = True
except Exception:  # pragma: no cover
    psutil = None  # type: ignore[assignment]
    HAS_PSUTIL = False


MAX_REMOTE_ENDPOINTS = 25
MAX_LOCAL_LISTENERS = 25
MAX_PROCESS_OWNERS = 15
NETSTAT_TIMEOUT_SECONDS = 5.0

_NETSTAT_LINE = re.compile(
    r"^\s*(TCP|UDP)\s+(\S+)\s+(\S+)\s+(\S+)?\s*(\d+)?\s*$",
    re.IGNORECASE,
)


@dataclass(slots=True)
class TrafficSummary:
    captured_at: float
    source: str
    total_connections: int
    listening_ports: list[int]
    established_remote_top: list[dict[str, Any]]
    process_top: list[dict[str, Any]]
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "captured_at": self.captured_at,
            "source": self.source,
            "total_connections": self.total_connections,
            "listening_ports": self.listening_ports,
            "established_remote_top": self.established_remote_top,
            "process_top": self.process_top,
            "note": self.note,
        }


def _stable_token(value: str, prefix: str) -> str:
    if not value:
        return ""
    digest = hashlib.sha256(value.encode("utf-8", errors="ignore")).hexdigest()[:10]
    return f"{prefix}-{digest}"


def _is_private_address(address: str) -> bool:
    try:
        host = address.split("%", 1)[0]
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return False
    return parsed.is_private or parsed.is_loopback or parsed.is_link_local


def _redact_remote(address: str, *, share_level: str) -> str:
    if not address:
        return ""
    if share_level == "full":
        return address
    if share_level == "standard":
        return address if _is_private_address(address) else _stable_token(address, "ext")
    return _stable_token(address, "ext") if not _is_private_address(address) else _stable_token(address, "lan")


def _split_endpoint(endpoint: str) -> tuple[str, int]:
    if not endpoint or endpoint == "*":
        return "", 0
    address, _, port = endpoint.rpartition(":")
    if not address:
        address = endpoint
        port_str = ""
    else:
        port_str = port
    address = address.strip("[]")
    try:
        port_value = int(port_str) if port_str else 0
    except ValueError:
        port_value = 0
    return address, port_value


def _psutil_snapshot(share_level: str) -> TrafficSummary:
    assert HAS_PSUTIL and psutil is not None  # pragma: no cover - guarded by caller
    connections = psutil.net_connections(kind="inet")
    listeners: set[int] = set()
    remote_counter: Counter[tuple[str, int]] = Counter()
    process_counter: Counter[str] = Counter()
    total = 0
    for conn in connections:
        total += 1
        status = str(getattr(conn, "status", "") or "").upper()
        laddr = getattr(conn, "laddr", None)
        raddr = getattr(conn, "raddr", None)
        if status == "LISTEN" and laddr:
            listeners.add(int(getattr(laddr, "port", 0) or 0))
        if raddr and getattr(raddr, "ip", None):
            address = str(raddr.ip)
            port = int(getattr(raddr, "port", 0) or 0)
            if address and not _is_private_address(address):
                remote_counter[(address, port)] += 1
            elif address:
                # private/loopback: still count but bucket separately so the
                # AI can see local listeners vs cloud peers at a glance.
                remote_counter[(address, port)] += 1
        pid = getattr(conn, "pid", None)
        if pid:
            try:
                proc = psutil.Process(int(pid))
                name = proc.name()
            except Exception:
                name = ""
            if name:
                process_counter[name] += 1
    established_remote_top = [
        {
            "endpoint": _redact_remote(address, share_level=share_level),
            "port": port,
            "count": count,
            "scope": "lan" if _is_private_address(address) else "external",
        }
        for (address, port), count in remote_counter.most_common(MAX_REMOTE_ENDPOINTS)
    ]
    process_top = [
        {"process": name, "connections": count}
        for name, count in process_counter.most_common(MAX_PROCESS_OWNERS)
    ]
    return TrafficSummary(
        captured_at=time.time(),
        source="psutil",
        total_connections=total,
        listening_ports=sorted(listeners)[:MAX_LOCAL_LISTENERS],
        established_remote_top=established_remote_top,
        process_top=process_top,
    )


def _netstat_snapshot(share_level: str) -> TrafficSummary:
    command = ["netstat", "-ano"] if _is_windows() else ["netstat", "-an"]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=NETSTAT_TIMEOUT_SECONDS,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return TrafficSummary(
            captured_at=time.time(),
            source="unavailable",
            total_connections=0,
            listening_ports=[],
            established_remote_top=[],
            process_top=[],
            note=f"netstat unavailable: {exc}",
        )
    listeners: set[int] = set()
    remote_counter: Counter[tuple[str, int]] = Counter()
    total = 0
    for raw_line in (completed.stdout or "").splitlines():
        match = _NETSTAT_LINE.match(raw_line)
        if not match:
            continue
        proto, local, remote, state, _pid = match.groups()
        total += 1
        local_address, local_port = _split_endpoint(local)
        if (state or "").upper() == "LISTEN" or (state or "").upper() == "LISTENING":
            if local_port:
                listeners.add(local_port)
        remote_address, remote_port = _split_endpoint(remote)
        if remote_address and remote_address not in {"0.0.0.0", "*", "::"}:
            remote_counter[(remote_address, remote_port)] += 1
    established_remote_top = [
        {
            "endpoint": _redact_remote(address, share_level=share_level),
            "port": port,
            "count": count,
            "scope": "lan" if _is_private_address(address) else "external",
        }
        for (address, port), count in remote_counter.most_common(MAX_REMOTE_ENDPOINTS)
    ]
    return TrafficSummary(
        captured_at=time.time(),
        source="netstat",
        total_connections=total,
        listening_ports=sorted(listeners)[:MAX_LOCAL_LISTENERS],
        established_remote_top=established_remote_top,
        process_top=[],
        note="psutil not available; process owners not enumerated.",
    )


def _is_windows() -> bool:
    import sys

    return sys.platform == "win32"


def collect_traffic_summary(*, share_level: str = "minimal") -> TrafficSummary:
    """Return a bounded snapshot of current TCP/UDP connection state.

    ``share_level`` follows the AI bridge convention. ``minimal`` hashes every
    remote endpoint; ``standard`` keeps private/LAN endpoints visible; ``full``
    returns raw addresses.
    """

    if HAS_PSUTIL:
        try:
            return _psutil_snapshot(share_level)
        except (psutil.AccessDenied, psutil.Error, OSError):  # type: ignore[union-attr]
            pass
    return _netstat_snapshot(share_level)


def hostname_for_endpoint(endpoint: str) -> str:
    """Best-effort reverse DNS for a single endpoint, with a short timeout.

    Used when the LLM asks for a name lookup via a tool call. We deliberately
    don't bulk-resolve every connection because that is both slow and a
    privacy-relevant side channel.
    """

    if not endpoint:
        return ""
    socket.setdefaulttimeout(1.5)
    try:
        return socket.gethostbyaddr(endpoint)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ""
    finally:
        socket.setdefaulttimeout(None)

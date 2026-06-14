from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .models import utcnow
from .paths import atomic_write_text, definitions_file

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_CVE_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFINITIONS_SCHEMA_VERSION = "1.0"
STARTER_VERSION = "2026.06.13.1"

DEFAULT_RISKY_PORTS = [
    {"port": 21, "service": "FTP", "severity": "medium", "why": "FTP is often unencrypted. Do not expose it unless you know why it is needed."},
    {"port": 22, "service": "SSH", "severity": "low", "why": "SSH is normal for some advanced devices, but it should use strong passwords or keys."},
    {"port": 23, "service": "Telnet", "severity": "high", "why": "Telnet sends logins in clear text and is risky on home networks."},
    {"port": 80, "service": "HTTP", "severity": "info", "why": "A web admin page may be normal for routers, cameras, printers, or smart hubs."},
    {"port": 139, "service": "NetBIOS", "severity": "medium", "why": "Windows file-sharing services should not be reachable from untrusted devices."},
    {"port": 445, "service": "SMB", "severity": "medium", "why": "SMB file sharing can expose files if permissions are weak."},
    {"port": 554, "service": "RTSP", "severity": "medium", "why": "Camera streaming services can expose video feeds if default passwords are still used."},
    {"port": 1080, "service": "SOCKS proxy", "severity": "medium", "category": "unusual_service", "why": "Port 1080 is a SOCKS proxy. It can be legitimate, but an unexpected proxy on a home device can relay traffic and should be reviewed."},
    {"port": 2323, "service": "Telnet alternate", "severity": "high", "category": "unusual_service", "why": "Port 2323 is a Telnet variant commonly scanned on IoT devices. A port-only scan cannot prove compromise, but unexpected Telnet exposure should be disabled."},
    {"port": 3306, "service": "MySQL", "severity": "medium", "why": "MySQL databases should not be exposed on the home LAN unless you specifically run a database server."},
    {"port": 3389, "service": "Remote Desktop", "severity": "high", "why": "Remote Desktop should be disabled unless you intentionally use it."},
    {"port": 4444, "service": "Unusual shell or lab listener", "severity": "high", "category": "unusual_service", "why": "Port 4444 is common in labs and testing tools, but it is unusual on normal home devices. Review it if you did not intentionally open it."},
    {"port": 5555, "service": "ADB or debug bridge", "severity": "high", "category": "unusual_service", "why": "Port 5555 is often Android Debug Bridge or a similar debug service. It can be normal for development, but exposed debug access should be confirmed."},
    {"port": 5900, "service": "VNC", "severity": "high", "why": "VNC remote-control services are risky when left open or weakly protected."},
    {"port": 5938, "service": "TeamViewer", "severity": "high", "why": "TeamViewer-style remote-control services should only be reachable when you intentionally use them. Confirm the device and software are expected."},
    {"port": 6667, "service": "IRC-style service", "severity": "medium", "category": "unusual_service", "why": "Port 6667 is commonly associated with IRC-style services. It can be normal, but unexpected listeners should be reviewed."},
    {"port": 7547, "service": "TR-069 router management", "severity": "high", "why": "Port 7547 (CWMP/TR-069) is a router remote-management protocol that has been widely abused against home routers. It should not be reachable unless explicitly required by your provider."},
    {"port": 8080, "service": "HTTP alternate", "severity": "low", "why": "Alternate web admin ports are common but should be reviewed."},
    {"port": 8443, "service": "HTTPS alternate", "severity": "low", "why": "Alternate web admin ports are common but should be reviewed."},
    {"port": 8888, "service": "HTTP alternate admin", "severity": "medium", "category": "unusual_service", "why": "Port 8888 hosts legitimate admin pages for some devices but is unusual on many home endpoints. Confirm the device and service are expected."},
    {"port": 9100, "service": "Raw printing (JetDirect)", "severity": "medium", "why": "Raw print services can be abused to exfiltrate documents or send unwanted print jobs from anywhere on the LAN."},
    {"port": 31337, "service": "Unusual legacy service port", "severity": "high", "category": "unusual_service", "why": "Port 31337 is historically unusual on home devices. A port-only scan cannot prove malicious use, but unexpected exposure should be reviewed."},
]

DEFAULT_NAME_HINTS = ["router", "camera", "cam", "admin", "default", "tplink", "tp-link", "dlink", "netgear", "printer", "nas", "synology", "qnap", "arlo", "ring"]

# Known-bad file hashes (SHA-256, lower-case). This is the foundation of
# signature-based antivirus: an exact-content match is the highest-confidence
# detection there is. The starter set ships the industry-standard EICAR test
# file hash so the hash detector is verifiable out of the box without any
# real malware on disk. Real deployments extend this through
# ``update-definitions`` feeds or a user ``custom_rules.json`` IOC list.
DEFAULT_MALWARE_HASHES = [
    {
        "sha256": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        "name": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE",
        "severity": "critical",
        "why": "Industry-standard antivirus test file. Safe, but proves the hash detector works.",
    },
]

DEFAULT_PRODUCT_HINTS = [
    {
        "id": "consumer_router",
        "keywords": ["router", "gateway", "tplink", "tp-link", "dlink", "netgear", "asus", "linksys", "arris", "ubiquiti"],
        "title": "Router or gateway device should be kept patched",
        "severity": "medium",
        "plain_english": "This looks like networking gear. Routers are common targets because they sit between your home and the internet.",
        "recommended_actions": ["Log in to the router admin page and check for firmware updates.", "Disable remote administration unless you intentionally use it.", "Change default admin credentials."],
    },
    {
        "id": "camera_or_iot",
        "keywords": ["camera", "cam", "rtsp", "arlo", "ring", "wyze", "hikvision", "dahua", "iot"],
        "title": "Camera or smart-home device should be reviewed",
        "severity": "medium",
        "plain_english": "This looks like a camera or smart-home device. These devices are often forgotten after setup and may keep old firmware.",
        "recommended_actions": ["Open the vendor app and check for updates.", "Turn off cloud or remote access features you do not use.", "Move IoT devices to a guest network if your router supports it."],
    },
    {
        "id": "nas_or_storage",
        "keywords": ["nas", "synology", "qnap", "storage", "smb"],
        "title": "Network storage device should be hardened",
        "severity": "medium",
        "plain_english": "This looks like network storage. Storage devices can expose files or become ransomware targets if credentials are weak.",
        "recommended_actions": ["Update the NAS firmware and packages.", "Disable unused sharing protocols.", "Confirm backups are working and not always writable from every device."],
    },
    {
        "id": "windows_remote_access",
        "keywords": ["rdp", "remote desktop", "3389"],
        "required_ports": [3389],
        "title": "Windows remote access should be reviewed",
        "severity": "high",
        "plain_english": "This device may allow remote control. Remote access should only be enabled when you intentionally use it.",
        "recommended_actions": ["Turn off Remote Desktop if you do not use it.", "Require strong passwords and multi-factor protection where available.", "Keep Windows updates enabled."],
    },
]


UPDATE_STATUS_NEVER = "never_updated"
UPDATE_STATUS_CURRENT = "current"
UPDATE_STATUS_AVAILABLE = "update_available"
UPDATE_STATUS_FAILED = "update_failed"
DEFINITION_FRESH_DAYS = 7


def _default_definitions() -> dict[str, Any]:
    return {
        "schema_version": DEFINITIONS_SCHEMA_VERSION,
        "definitions_version": STARTER_VERSION,
        "last_updated": "",
        "updated_at": "",
        "update_status": UPDATE_STATUS_NEVER,
        "record_count": 0,
        "feed_versions": {
            "starter": STARTER_VERSION,
            "cisa_kev": "",
            "nvd_recent_cves": "",
        },
        "feed_timestamps": {
            "starter": utcnow(),
            "cisa_kev": "",
            "nvd_recent_cves": "",
        },
        "source_status": {
            "starter": {"ok": True, "message": "Starter definitions bundled with HomeGuard."},
            "cisa_kev": {"ok": False, "message": "Never updated."},
            "nvd_recent_cves": {"ok": False, "message": "Never updated."},
        },
        "sources": ["starter", "cisa_kev", "nvd_recent_cves"],
        "notice": "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
        "risky_ports": DEFAULT_RISKY_PORTS,
        "device_name_hints": DEFAULT_NAME_HINTS,
        "product_hints": DEFAULT_PRODUCT_HINTS,
        "malware_hashes": DEFAULT_MALWARE_HASHES,
        "kev_catalog": [],
        "recent_cves": [],
    }


def _http_json(
    url: str,
    *,
    timeout: float = 25.0,
    attempts: int = 3,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, Any]:
    last_exc: Exception | None = None
    headers = {
        "User-Agent": "HomeGuard/0.5 security-definitions-updater",
        "Accept": "application/json",
    }
    if extra_headers:
        headers.update(extra_headers)
    for attempt in range(1, max(1, attempts) + 1):
        request = urllib.request.Request(
            url,
            headers=headers,
            method="GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # nosec B310 - user initiated definition updates only
                if response.status < 200 or response.status >= 300:
                    raise RuntimeError(f"HTTP {response.status}")
                raw = response.read(20_000_000)
            parsed = json.loads(raw.decode("utf-8"))
            if not isinstance(parsed, dict):
                raise RuntimeError("Expected JSON object")
            return parsed
        except (urllib.error.URLError, urllib.error.HTTPError, RuntimeError, json.JSONDecodeError, OSError) as exc:
            last_exc = exc
            if attempt < attempts:
                continue
            break
    raise RuntimeError(str(last_exc) if last_exc else "Unknown error")


def _english_description(cve: dict[str, Any]) -> str:
    for item in cve.get("descriptions") or []:
        if isinstance(item, dict) and item.get("lang") == "en":
            return str(item.get("value") or "")[:700]
    return ""


def _cvss_score(cve: dict[str, Any]) -> float:
    metrics = cve.get("metrics") if isinstance(cve.get("metrics"), dict) else {}
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        rows = metrics.get(key)
        if not isinstance(rows, list) or not rows:
            continue
        first = rows[0] if isinstance(rows[0], dict) else {}
        data = first.get("cvssData") if isinstance(first.get("cvssData"), dict) else {}
        try:
            return float(data.get("baseScore"))
        except (TypeError, ValueError):
            continue
    return 0.0


def _normalize_words(text: str) -> set[str]:
    words = {word for word in re.split(r"[^a-z0-9]+", text.lower()) if len(word) >= 3}
    stop = {"the", "and", "for", "with", "from", "this", "that", "device", "devices", "software", "vulnerability"}
    return words - stop


def _compact_kev_item(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "cve_id": str(item.get("cveID") or item.get("cve_id") or ""),
        "vendor_project": str(item.get("vendorProject") or item.get("vendor_project") or ""),
        "product": str(item.get("product") or ""),
        "vulnerability_name": str(item.get("vulnerabilityName") or item.get("vulnerability_name") or ""),
        "date_added": str(item.get("dateAdded") or item.get("date_added") or ""),
        "known_ransomware_use": str(item.get("knownRansomwareCampaignUse") or ""),
        "required_action": str(item.get("requiredAction") or ""),
        "short_description": str(item.get("shortDescription") or "")[:700],
    }


def _compact_nvd_item(item: dict[str, Any]) -> dict[str, Any]:
    cve = item.get("cve") if isinstance(item.get("cve"), dict) else {}
    cve_id = str(cve.get("id") or "")
    desc = _english_description(cve)
    score = _cvss_score(cve)
    return {
        "cve_id": cve_id,
        "published": str(cve.get("published") or ""),
        "last_modified": str(cve.get("lastModified") or ""),
        "status": str(cve.get("vulnStatus") or ""),
        "cvss_score": score,
        "description": desc,
        "keywords": sorted(list(_normalize_words(desc)))[:40],
    }


@dataclass(slots=True)
class DefinitionManager:
    path: Path | None = None

    def __post_init__(self) -> None:
        if self.path is None:
            self.path = definitions_file()

    def load(self) -> dict[str, Any]:
        assert self.path is not None
        if not self.path.exists():
            data = _default_definitions()
            self.save(data)
            return data
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            data = _default_definitions()
            self.save(data)
            return data
        if not isinstance(data, dict):
            data = _default_definitions()
        defaults = _default_definitions()
        # Migrate built-in static rule fields (risky_ports, device_name_hints,
        # product_hints) when the bundled starter version moves forward. Older
        # installs would otherwise be stuck on whatever risky port list shipped
        # the day they first ran HomeGuard, even after `update-definitions`,
        # because that command only refreshes the KEV/CVE feeds.
        feed_versions = dict(data.get("feed_versions") or {})
        bundled_starter = str(feed_versions.get("starter") or "")
        if bundled_starter != STARTER_VERSION:
            data["risky_ports"] = defaults["risky_ports"]
            data["device_name_hints"] = defaults["device_name_hints"]
            data["product_hints"] = defaults["product_hints"]
            data["malware_hashes"] = defaults["malware_hashes"]
            feed_versions["starter"] = STARTER_VERSION
            data["feed_versions"] = feed_versions
            feed_timestamps = dict(data.get("feed_timestamps") or {})
            feed_timestamps["starter"] = utcnow()
            data["feed_timestamps"] = feed_timestamps
            source_status = dict(data.get("source_status") or {})
            source_status["starter"] = {
                "ok": True,
                "message": f"Starter definitions migrated to {STARTER_VERSION}.",
            }
            data["source_status"] = source_status
        for key, value in defaults.items():
            data.setdefault(key, value)
        return data

    def save(self, data: dict[str, Any]) -> None:
        assert self.path is not None
        atomic_write_text(self.path, json.dumps(data, indent=2, sort_keys=True))

    def merge_malware_hashes(
        self,
        rows: Any,
        *,
        feed_version: str = "",
        source: str = "hash_feed",
    ) -> dict[str, Any]:
        """Merge known-bad hash rows into the on-disk definitions.

        Deduplicates by SHA-256 (the incoming row wins), records feed
        provenance, and persists. Used by the signed hash-feed updater so a
        downloaded, signature-verified feed becomes part of the live
        definition set. Malformed rows are skipped, not fatal.
        """

        data = self.load()
        by_hash: dict[str, dict[str, Any]] = {}
        for row in data.get("malware_hashes") or []:
            if isinstance(row, dict):
                digest = str(row.get("sha256") or "").strip().lower()
                if digest:
                    by_hash[digest] = row
        added = 0
        updated = 0
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            digest = str(row.get("sha256") or row.get("hash") or "").strip().lower()
            if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                continue
            severity = str(row.get("severity") or "high").strip().lower()
            clean = {
                "sha256": digest,
                "name": str(row.get("name") or "Known-bad file hash"),
                "severity": severity if severity in {"critical", "high", "medium", "low", "info"} else "high",
                "why": str(row.get("why") or "This file's exact contents match a signed hash-feed entry."),
                "source": source,
            }
            if digest in by_hash:
                updated += 1
            else:
                added += 1
            by_hash[digest] = clean
        data["malware_hashes"] = list(by_hash.values())

        resolved_version = str(feed_version or utcnow())
        feed_versions = dict(data.get("feed_versions") or {})
        feed_versions[source] = resolved_version
        data["feed_versions"] = feed_versions
        feed_timestamps = dict(data.get("feed_timestamps") or {})
        feed_timestamps[source] = utcnow()
        data["feed_timestamps"] = feed_timestamps
        source_status = dict(data.get("source_status") or {})
        source_status[source] = {
            "ok": True,
            "message": f"Merged {added} new and {updated} updated hash signature(s).",
        }
        data["source_status"] = source_status
        sources = list(data.get("sources") or [])
        if source not in sources:
            sources.append(source)
            data["sources"] = sources
        self.save(data)
        return {
            "added": added,
            "updated": updated,
            "total": len(by_hash),
            "feed_version": resolved_version,
        }

    def status(self) -> dict[str, Any]:
        data = self.load()
        updated = str(data.get("last_updated") or data.get("updated_at") or "")
        age_days: int | None = None
        if updated:
            try:
                clean = updated.replace("Z", "+00:00")
                age_days = (datetime.now(timezone.utc) - datetime.fromisoformat(clean)).days
            except Exception:
                age_days = None
        update_status = str(data.get("update_status") or UPDATE_STATUS_NEVER)
        # Promote stale "current" definitions to "update_available" automatically.
        if update_status == UPDATE_STATUS_CURRENT and isinstance(age_days, int) and age_days > DEFINITION_FRESH_DAYS:
            update_status = UPDATE_STATUS_AVAILABLE
        kev_count = len(data.get("kev_catalog") or [])
        cve_count = len(data.get("recent_cves") or [])
        record_count = int(data.get("record_count") or (kev_count + cve_count))
        return {
            "path": str(self.path),
            "definitions_version": str(data.get("definitions_version") or "unknown"),
            "last_updated": updated or "",
            "updated_at": updated or "unknown",
            "age_days": age_days,
            "kev_count": kev_count,
            "recent_cve_count": cve_count,
            "record_count": record_count,
            "update_status": update_status,
            "feed_versions": dict(data.get("feed_versions") or {}),
            "feed_timestamps": dict(data.get("feed_timestamps") or {}),
            "sources": list(data.get("sources") or ["starter", "cisa_kev", "nvd_recent_cves"]),
            "source_status": data.get("source_status") or {},
            "notice": data.get("notice") or "",
        }

    def import_from_file(self, path: str | Path) -> dict[str, Any]:
        """Import a HomeGuard definitions JSON exported from another machine.

        Designed for offline / air-gapped use: a connected device runs
        ``update-definitions``, copies ``security_definitions.json`` to
        a USB stick, and the offline device runs
        ``homeguard import-definitions --input <file>`` to absorb the
        KEV/CVE intelligence without ever reaching CISA or NVD itself.

        Imports the recognized cache fields (``kev_catalog``,
        ``recent_cves``) verbatim. Built-in static fields (risky_ports,
        device_name_hints, product_hints) are NOT touched here so the
        bundled-version migration in ``load()`` remains the single
        source of truth for those, and so two override paths
        (``import-definitions`` and ``custom_rules.json``) don't fight
        each other. Returns a status dict; the file is left untouched
        if any validation step fails.
        """

        target = Path(path)
        if not target.exists():
            return {"ok": False, "message": f"File not found: {path}"}
        try:
            raw = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            return {"ok": False, "message": f"Could not read JSON: {exc}"}
        if not isinstance(raw, dict):
            return {"ok": False, "message": "Top-level JSON value must be an object."}
        known_keys = {"kev_catalog", "recent_cves", "definitions_version", "feed_versions"}
        if not (set(raw.keys()) & known_keys):
            return {
                "ok": False,
                "message": (
                    "File does not contain any HomeGuard definition fields. "
                    "Expected at least one of: " + ", ".join(sorted(known_keys))
                ),
            }

        data = self.load()

        kev_in = raw.get("kev_catalog")
        kev_imported = 0
        if isinstance(kev_in, list):
            compact: list[dict[str, Any]] = []
            for item in kev_in:
                if not isinstance(item, dict):
                    continue
                if item.get("cve_id"):
                    compact.append(item)
                elif item.get("cveID"):
                    compact.append(_compact_kev_item(item))
            data["kev_catalog"] = compact
            kev_imported = len(compact)

        cve_in = raw.get("recent_cves")
        cve_imported = 0
        if isinstance(cve_in, list):
            cves = [
                item for item in cve_in if isinstance(item, dict) and item.get("cve_id")
            ]
            data["recent_cves"] = cves
            cve_imported = len(cves)

        now = datetime.now(timezone.utc).replace(microsecond=0)
        data["definitions_version"] = str(
            raw.get("definitions_version") or now.strftime("%Y.%m.%d.%H%M")
        )
        data["last_updated"] = utcnow()
        data["updated_at"] = data["last_updated"]
        data["update_status"] = UPDATE_STATUS_CURRENT
        data["record_count"] = (
            len(data.get("kev_catalog") or []) + len(data.get("recent_cves") or [])
        )
        statuses = dict(data.get("source_status") or {})
        statuses["imported"] = {
            "ok": True,
            "message": (
                f"Imported {kev_imported} KEV record(s) and {cve_imported} CVE record(s) "
                f"from {target.name}."
            ),
            "updated_at": data["last_updated"],
            "source": str(target),
        }
        data["source_status"] = statuses
        data["sources"] = sorted(
            set(list(data.get("sources") or []) + ["starter", "imported"])
        )
        feed_versions = dict(data.get("feed_versions") or {})
        if isinstance(raw.get("feed_versions"), dict):
            for feed_name in ("cisa_kev", "nvd_recent_cves"):
                if raw["feed_versions"].get(feed_name):
                    feed_versions[feed_name] = str(raw["feed_versions"][feed_name])
        data["feed_versions"] = feed_versions
        feed_timestamps = dict(data.get("feed_timestamps") or {})
        feed_timestamps["imported"] = data["last_updated"]
        data["feed_timestamps"] = feed_timestamps
        self.save(data)
        return {
            "ok": True,
            "message": "Definitions imported.",
            "kev_count": kev_imported,
            "cve_count": cve_imported,
            "definitions_version": str(data["definitions_version"]),
            "source": str(target),
        }

    def update_from_sources(self, *, nvd_days: int = 30) -> dict[str, Any]:
        data = self.load()
        statuses = dict(data.get("source_status") or {})
        feed_versions = dict(data.get("feed_versions") or {})
        feed_timestamps = dict(data.get("feed_timestamps") or {})
        now = datetime.now(timezone.utc).replace(microsecond=0)
        any_failure = False
        any_success = False

        try:
            kev = _http_json(CISA_KEV_URL)
            raw_items = kev.get("vulnerabilities") if isinstance(kev.get("vulnerabilities"), list) else []
            data["kev_catalog"] = [_compact_kev_item(item) for item in raw_items if isinstance(item, dict) and (item.get("cveID") or item.get("cve_id"))]
            kev_version = str(kev.get("catalogVersion") or kev.get("dateReleased") or now.strftime("%Y.%m.%d"))
            feed_versions["cisa_kev"] = kev_version
            feed_timestamps["cisa_kev"] = utcnow()
            statuses["cisa_kev"] = {
                "ok": True,
                "message": f"Downloaded {len(data['kev_catalog'])} known exploited vulnerabilities.",
                "updated_at": utcnow(),
                "url": CISA_KEV_URL,
                "version": kev_version,
            }
            any_success = True
        except Exception as exc:
            statuses["cisa_kev"] = {"ok": False, "message": f"Update failed: {exc}", "updated_at": utcnow(), "url": CISA_KEV_URL}
            any_failure = True

        try:
            days = max(1, min(int(nvd_days), 120))
            start = now - timedelta(days=days)
            query = urllib.parse.urlencode(
                {
                    "pubStartDate": start.isoformat().replace("+00:00", "Z"),
                    "pubEndDate": now.isoformat().replace("+00:00", "Z"),
                    "resultsPerPage": "200",
                }
            )
            url = f"{NVD_CVE_API_URL}?{query}&noRejected"
            # NVD throttles unauthenticated traffic to ~5 requests per 30s
            # without an API key. Users on slower networks or running
            # update-definitions repeatedly hit those limits and get
            # update_failed. An API key (free, request via NVD self-service)
            # raises the limit to ~50/30s. Read it from the environment so
            # the secret never lands in any of HomeGuard's persisted files.
            nvd_headers: dict[str, str] = {}
            api_key = os.environ.get("HOMEGUARD_NVD_API_KEY", "").strip()
            if api_key:
                nvd_headers["apiKey"] = api_key
            nvd = _http_json(url, extra_headers=nvd_headers or None)
            vulns = nvd.get("vulnerabilities") if isinstance(nvd.get("vulnerabilities"), list) else []
            compact = [_compact_nvd_item(item) for item in vulns if isinstance(item, dict)]
            compact.sort(key=lambda item: (float(item.get("cvss_score") or 0.0), str(item.get("published") or "")), reverse=True)
            data["recent_cves"] = compact[:200]
            nvd_version = now.strftime("%Y.%m.%d.%H%M")
            feed_versions["nvd_recent_cves"] = nvd_version
            feed_timestamps["nvd_recent_cves"] = utcnow()
            statuses["nvd_recent_cves"] = {
                "ok": True,
                "message": f"Downloaded {len(data['recent_cves'])} recent CVEs from the last {days} day(s).",
                "updated_at": utcnow(),
                "url": NVD_CVE_API_URL,
                "version": nvd_version,
            }
            any_success = True
        except Exception as exc:
            statuses["nvd_recent_cves"] = {"ok": False, "message": f"Update failed: {exc}", "updated_at": utcnow(), "url": NVD_CVE_API_URL}
            any_failure = True

        data["source_status"] = statuses
        data["sources"] = list(data.get("sources") or ["starter", "cisa_kev", "nvd_recent_cves"])
        data["feed_versions"] = feed_versions
        data["feed_timestamps"] = feed_timestamps
        data["definitions_version"] = now.strftime("%Y.%m.%d.%H%M")
        data["last_updated"] = utcnow()
        data["updated_at"] = data["last_updated"]
        data["record_count"] = len(data.get("kev_catalog") or []) + len(data.get("recent_cves") or [])
        if any_success and not any_failure:
            data["update_status"] = UPDATE_STATUS_CURRENT
        elif any_success and any_failure:
            data["update_status"] = UPDATE_STATUS_AVAILABLE
        else:
            data["update_status"] = UPDATE_STATUS_FAILED
        self.save(data)
        return self.status()


DISCOVERY_BASE_PORTS: tuple[int, ...] = (53, 80, 443)


def active_scan_ports(
    definitions: dict[str, Any] | None = None,
    *,
    extras: tuple[int, ...] = DISCOVERY_BASE_PORTS,
) -> list[int]:
    """Return the active TCP probe port set for HomeGuard scans.

    Sourced from the current ``risky_ports`` definitions plus a small set of
    discovery defaults (DNS/HTTP/HTTPS) so unfamiliar but unrouted devices still
    surface in the report. Centralizing this makes the scanner and the rule
    catalog stay in sync — whenever a port is added to the definitions it is
    automatically probed by active scans.
    """

    if definitions is None:
        definitions = DefinitionManager().load()
    ports: set[int] = set()
    for row in (definitions.get("risky_ports") or []):
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535:
            ports.add(port)
    for port in extras:
        try:
            value = int(port)
        except (TypeError, ValueError):
            continue
        if 0 < value <= 65535:
            ports.add(value)
    return sorted(ports)


def active_malware_hashes(definitions: dict[str, Any] | None = None) -> dict[str, dict[str, str]]:
    """Return the known-bad SHA-256 set keyed by lower-case hash.

    Sourced from the ``malware_hashes`` definitions list (plus any merged from
    a user ``custom_rules.json``). Each value carries the human-readable name,
    severity, and rationale so a hash hit produces a real finding rather than a
    bare hash string. Malformed rows are skipped rather than aborting a scan.
    """

    if definitions is None:
        definitions = DefinitionManager().load()
    result: dict[str, dict[str, str]] = {}
    for row in definitions.get("malware_hashes") or []:
        if not isinstance(row, dict):
            continue
        digest = str(row.get("sha256") or row.get("hash") or "").strip().lower()
        # A SHA-256 is exactly 64 hex characters; anything else is noise.
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            continue
        severity = str(row.get("severity") or "high").strip().lower()
        result[digest] = {
            "name": str(row.get("name") or "Known-bad file hash"),
            "severity": severity if severity in {"critical", "high", "medium", "low", "info"} else "high",
            "why": str(row.get("why") or "This file's exact contents match a known-bad signature."),
        }
    return result


def risky_ports_from_definitions(definitions: dict[str, Any]) -> dict[int, tuple[str, str, str, str]]:
    result: dict[int, tuple[str, str, str, str]] = {}
    for row in definitions.get("risky_ports") or []:
        if not isinstance(row, dict):
            continue
        try:
            port = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        if 0 < port <= 65535:
            result[port] = (
                str(row.get("service") or f"Port {port}"),
                str(row.get("severity") or "info"),
                str(row.get("why") or "This service should be reviewed."),
                str(row.get("category") or "exposed_service"),
            )
    return result


def device_text(device: Any) -> str:
    metadata = getattr(device, "metadata", {}) or {}
    parts = [
        getattr(device, "hostname", ""),
        getattr(device, "vendor", ""),
        getattr(device, "ip", ""),
        " ".join(str(p) for p in getattr(device, "open_ports", []) or []),
    ]
    for value in metadata.values():
        if isinstance(value, (str, int, float)):
            parts.append(str(value))
    ports = set(getattr(device, "open_ports", []) or [])
    if 3389 in ports:
        parts.append("windows rdp remote desktop")
    if 445 in ports or 139 in ports:
        parts.append("smb file sharing nas")
    if 554 in ports:
        parts.append("camera rtsp")
    return " ".join(parts).lower()


def match_product_hints(device: Any, definitions: dict[str, Any], *, limit: int = 4) -> list[dict[str, Any]]:
    text = device_text(device)
    device_ports = {int(port) for port in getattr(device, "open_ports", []) or []}
    matches: list[dict[str, Any]] = []
    for row in definitions.get("product_hints") or []:
        if not isinstance(row, dict):
            continue
        required_ports = set()
        for port in row.get("required_ports") or []:
            try:
                required_ports.add(int(port))
            except (TypeError, ValueError):
                continue
        if required_ports and not required_ports <= device_ports:
            continue
        keywords = [str(item).lower() for item in row.get("keywords") or [] if str(item).strip()]
        if any(keyword and keyword in text for keyword in keywords):
            matches.append(row)
        if len(matches) >= limit:
            break
    return matches


def match_kev_catalog(device: Any, definitions: dict[str, Any], *, limit: int = 3) -> list[dict[str, Any]]:
    text_words = _normalize_words(device_text(device))
    if not text_words:
        return []
    matches: list[dict[str, Any]] = []
    for row in definitions.get("kev_catalog") or []:
        if not isinstance(row, dict):
            continue
        product_words = _normalize_words(" ".join([str(row.get("vendor_project") or ""), str(row.get("product") or "")]))
        if not product_words:
            continue
        # Versionless consumer scans can only provide hints. Require at least
        # one product/vendor word overlap and avoid very generic one-word hits.
        overlap = text_words & product_words
        if overlap and (len(overlap) >= 2 or not {"windows", "linux", "server", "client"} >= overlap):
            item = dict(row)
            item["matched_words"] = sorted(overlap)
            matches.append(item)
        if len(matches) >= limit:
            break
    return matches

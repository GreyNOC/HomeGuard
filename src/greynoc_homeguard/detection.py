from __future__ import annotations

import fnmatch
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Callable

from .baseline import BaselineStore
from .definitions import match_kev_catalog, match_product_hints, risky_ports_from_definitions
from .models import Device, Finding

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SEVERITY_SCORE = {"critical": 95.0, "high": 78.0, "medium": 54.0, "low": 26.0, "info": 8.0}
CRITICAL_REMOTE_PORTS = {23, 2323, 3389, 5900, 5938, 445}
REMOTE_ADMIN_PORTS = {22, 23, 2323, 3389, 5900, 5938, 7547}
FILE_SHARING_PORTS = {139, 445}
UNUSUAL_SERVICE_PORTS = {1080, 2323, 4444, 5555, 6667, 31337}
SUSPICIOUS_MALWARE_PORTS = UNUSUAL_SERVICE_PORTS
SERVICE_CLUSTER_PORTS = {
    21,
    22,
    23,
    80,
    139,
    443,
    445,
    554,
    1080,
    2323,
    3306,
    3389,
    4444,
    5555,
    5900,
    5938,
    6667,
    7547,
    8080,
    8443,
    8888,
    9100,
    31337,
}


@dataclass(slots=True)
class DetectionRule:
    rule_id: str
    rule_type: str
    title: str
    severity: str
    category: str
    confidence: float
    enabled: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_type": self.rule_type,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "confidence": self.confidence,
            "enabled": self.enabled,
            "metadata": dict(self.metadata),
        }


@dataclass(slots=True)
class DetectionTelemetry:
    devices_processed: int = 0
    rules_loaded: int = 0
    rules_evaluated: int = 0
    findings_emitted: int = 0
    matched_rules: list[dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "devices_processed": self.devices_processed,
            "rules_loaded": self.rules_loaded,
            "rules_evaluated": self.rules_evaluated,
            "findings_emitted": self.findings_emitted,
            "matched_rules": list(self.matched_rules),
        }


class HomeGuardDetectionEngine:
    """Rule-driven consumer detection engine for HomeGuard.

    The engine mirrors the GreyNOC SOC-style pattern: rules are loaded, each
    device is normalized as evidence, detectors emit findings with severity,
    confidence, risk score, priority, evidence, and plain-English next steps.
    """

    engine_name = "HomeGuard Detection Engine"
    engine_version = "0.6.0"

    def __init__(self, definitions: dict[str, Any] | None = None) -> None:
        self.definitions = definitions or {}
        self.rules = self._load_rules(self.definitions)
        self.telemetry = DetectionTelemetry(rules_loaded=len(self.rules))

    def health(self) -> dict[str, Any]:
        return {
            "engine": self.engine_name,
            "engine_version": self.engine_version,
            "rules_loaded": len(self.rules),
            "enabled_rules": len([rule for rule in self.rules if rule.enabled]),
            "rule_ids": [rule.rule_id for rule in self.rules if rule.enabled],
            "definitions_version": str(self.definitions.get("definitions_version") or "unknown"),
        }

    def reset_telemetry(self) -> None:
        self.telemetry = DetectionTelemetry(rules_loaded=len(self.rules))

    def evaluate(self, devices: list[Device], baseline: BaselineStore | None = None) -> list[Finding]:
        self.reset_telemetry()
        self.telemetry.devices_processed = len(devices)
        findings: list[Finding] = []
        for device in devices:
            findings.extend(self.evaluate_device(device, baseline))
        findings.sort(key=lambda item: (-item.risk_score, item.device_ip, item.rule_id))
        return findings

    def evaluate_device(self, device: Device, baseline: BaselineStore | None = None) -> list[Finding]:
        findings: list[Finding] = []
        registry: dict[str, Callable[[DetectionRule, Device, BaselineStore | None], list[Finding]]] = {
            "new_device": self._detect_new_device,
            "missing_mac": self._detect_missing_mac,
            "risky_port": self._detect_risky_ports,
            "many_open_ports": self._detect_many_open_ports,
            "default_name_hint": self._detect_default_name_hint,
            "product_hint": self._detect_product_hints,
            "known_exploited_vulnerability": self._detect_kev_hints,
            "quarantined_device": self._detect_quarantined_device,
            "possible_unauthorized_access": self._detect_possible_unauthorized_access,
            "remote_admin_cluster": self._detect_remote_admin_cluster,
            "possible_malware_service": self._detect_possible_malware_service,
            "hostname_collision": self._detect_hostname_collision,
            "custom_hostname_match": self._detect_custom_hostname_match,
            "custom_mac_prefix_match": self._detect_custom_mac_prefix_match,
        }
        for rule in self.rules:
            if not rule.enabled:
                continue
            detector = registry.get(rule.rule_type)
            if detector is None:
                continue
            self.telemetry.rules_evaluated += 1
            emitted = detector(rule, device, baseline)
            for finding in emitted:
                self.telemetry.findings_emitted += 1
                self.telemetry.matched_rules.append(
                    {"rule_id": finding.rule_id, "device": finding.device_ip, "severity": finding.severity}
                )
            findings.extend(emitted)
        return findings

    def _load_rules(self, definitions: dict[str, Any]) -> list[DetectionRule]:
        rules = [
            DetectionRule(
                rule_id="new_device",
                rule_type="new_device",
                title="New device seen on your home network",
                severity="low",
                category="device_inventory",
                confidence=0.82,
            ),
            DetectionRule(
                rule_id="missing_mac",
                rule_type="missing_mac",
                title="Device identity is incomplete",
                severity="info",
                category="device_inventory",
                confidence=0.68,
            ),
            DetectionRule(
                rule_id="many_open_ports",
                rule_type="many_open_ports",
                title="Many services are reachable",
                severity="medium",
                category="exposed_service",
                confidence=0.75,
                metadata={"threshold": 5},
            ),
            DetectionRule(
                rule_id="default_name_hint",
                rule_type="default_name_hint",
                title="Device name suggests a common home device",
                severity="info",
                category="device_hardening",
                confidence=0.58,
            ),
            DetectionRule(
                rule_id="product_hint",
                rule_type="product_hint",
                title="Security definition matched this device",
                severity="medium",
                category="security_update",
                confidence=0.55,
            ),
            DetectionRule(
                rule_id="known_exploited_vulnerability",
                rule_type="known_exploited_vulnerability",
                title="Known exploited vulnerability may apply",
                severity="medium",
                category="known_exploited_vulnerability",
                confidence=0.42,
            ),
            DetectionRule(
                rule_id="quarantined_device",
                rule_type="quarantined_device",
                title="Quarantined device is on the network",
                severity="high",
                category="device_trust",
                confidence=0.95,
            ),
            DetectionRule(
                rule_id="possible_unauthorized_access",
                rule_type="possible_unauthorized_access",
                title="Possible unauthorized device with remote-access exposure",
                severity="high",
                category="possible_intrusion",
                confidence=0.72,
            ),
            DetectionRule(
                rule_id="remote_admin_cluster",
                rule_type="remote_admin_cluster",
                title="Remote-administration service cluster detected",
                severity="high",
                category="possible_intrusion",
                confidence=0.7,
                metadata={"threshold": 2},
            ),
            DetectionRule(
                rule_id="possible_malware_service",
                rule_type="possible_malware_service",
                title="Unusual service requiring review",
                severity="high",
                category="unusual_service",
                confidence=0.66,
            ),
            DetectionRule(
                rule_id="hostname_collision",
                rule_type="hostname_collision",
                title="Possible hostname spoofing detected",
                severity="high",
                category="possible_intrusion",
                confidence=0.65,
            ),
        ]
        risky_ports = risky_ports_from_definitions(definitions)
        for port, (service, severity, why, category) in sorted(risky_ports.items()):
            rules.append(
                DetectionRule(
                    rule_id=f"risky_port_{port}",
                    rule_type="risky_port",
                    title=f"{service} service is reachable",
                    severity=severity,
                    category=category,
                    confidence=0.78 if severity in {"critical", "high", "medium"} else 0.63,
                    metadata={"port": port, "service": service, "why": why},
                )
            )
        # User-defined hostname watch list. Each entry becomes its own rule
        # so the existing telemetry, severity scoring, and dedupe paths all
        # work without special-casing.
        for index, entry in enumerate(definitions.get("custom_watch_hostnames") or []):
            if not isinstance(entry, dict):
                continue
            pattern = str(entry.get("pattern") or "").strip().lower()
            if not pattern:
                continue
            digest = hashlib.sha256(pattern.encode("utf-8")).hexdigest()[:8]
            severity = str(entry.get("severity") or "medium")
            rules.append(
                DetectionRule(
                    rule_id=f"custom_hostname_{digest}",
                    rule_type="custom_hostname_match",
                    title="User-defined hostname watch list match",
                    severity=severity,
                    category="user_custom_rule",
                    confidence=0.6,
                    metadata={
                        "pattern": pattern,
                        "why": str(entry.get("why") or ""),
                        "index": index,
                    },
                )
            )
        # User-defined MAC OUI watch list.
        for index, entry in enumerate(definitions.get("custom_watch_mac_prefixes") or []):
            if not isinstance(entry, dict):
                continue
            prefix = str(entry.get("prefix") or "").strip().lower()
            if not prefix:
                continue
            digest = hashlib.sha256(prefix.encode("utf-8")).hexdigest()[:8]
            severity = str(entry.get("severity") or "medium")
            rules.append(
                DetectionRule(
                    rule_id=f"custom_mac_{digest}",
                    rule_type="custom_mac_prefix_match",
                    title="User-defined MAC OUI watch list match",
                    severity=severity,
                    category="user_custom_rule",
                    confidence=0.65,
                    metadata={
                        "prefix": prefix,
                        "why": str(entry.get("why") or ""),
                        "index": index,
                    },
                )
            )
        return rules

    def _finding_id(self, rule_id: str, device: Device, evidence: dict[str, Any]) -> str:
        material = json.dumps(
            {"rule_id": rule_id, "device": device.fingerprint(), "evidence": evidence},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        )
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
        return f"hg_{digest}"

    def _priority(self, severity: str, risk_score: float) -> str:
        if severity == "critical" or risk_score >= 90:
            return "P1"
        if severity == "high" or risk_score >= 70:
            return "P2"
        if severity == "medium" or risk_score >= 40:
            return "P3"
        return "P4"

    def _mk(
        self,
        *,
        rule_id: str,
        title: str,
        severity: str,
        confidence: float,
        category: str,
        device: Device,
        plain_english: str,
        recommended_actions: list[str],
        evidence: dict[str, Any],
    ) -> Finding:
        severity = severity if severity in SEVERITY_SCORE else "info"
        base = SEVERITY_SCORE.get(severity, 8.0)
        risk_score = round(max(0.0, min(100.0, base * max(0.1, min(confidence, 0.99)))), 2)
        return Finding(
            finding_id=self._finding_id(rule_id, device, evidence),
            rule_id=rule_id,
            title=title,
            severity=severity,
            confidence=round(max(0.0, min(confidence, 0.99)), 4),
            risk_score=risk_score,
            priority=self._priority(severity, risk_score),
            category=category,
            device_ip=device.ip,
            device_name=device.hostname or device.vendor or device.ip,
            plain_english=plain_english,
            recommended_actions=recommended_actions,
            evidence=evidence,
        )

    def _detect_quarantined_device(
        self, rule: DetectionRule, device: Device, baseline: BaselineStore | None
    ) -> list[Finding]:
        if baseline is None or not baseline.is_quarantined(device):
            return []
        record = baseline.get(device)
        name = device.hostname or device.vendor or device.ip
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Quarantined device detected on the network: {name}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"You marked {name} ({device.ip}) as quarantined in HomeGuard. "
                    "It is currently active on your home network."
                ),
                recommended_actions=[
                    "Block this device from your router or change the WiFi password.",
                    "Confirm whether anyone in the household plugged in or paired this device.",
                    "Remove the quarantine flag in HomeGuard once you have resolved the device.",
                ],
                evidence={
                    "ip": device.ip,
                    "mac_address": device.mac_address,
                    "fingerprint": device.fingerprint(),
                    "trust_state": "quarantined",
                    "owner": record.get("owner") or "unknown",
                    "device_type": record.get("device_type") or "unknown",
                },
            )
        ]

    def _detect_hostname_collision(
        self, rule: DetectionRule, device: Device, baseline: BaselineStore | None
    ) -> list[Finding]:
        """Flag when an unknown device on the LAN reuses a baselined hostname.

        ``Device.fingerprint()`` falls back to ``host:<hostname>`` when no
        MAC is visible. Without this check, an attacker connecting to the
        WiFi and configuring the same hostname as a baselined trusted
        device would inherit that trust silently — ``new_device`` and
        ``possible_unauthorized_access`` both gate on ``baseline.known()``
        and would stay quiet. This detector cross-references the live IP
        against the IP stored on the matching baseline record so the user
        gets a clear high-priority signal on the first scan.
        """

        if baseline is None or not baseline.known(device):
            return []
        if baseline.identity_matches(device):
            return []
        record = baseline.get(device)
        name = device.hostname or device.vendor or device.ip
        stored_ip = str(record.get("ip") or "")
        stored_mac = str(record.get("mac_address") or "")
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Possible hostname spoofing on the home network: {name}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"HomeGuard previously saw a device named {name} at {stored_ip or 'a different IP'}. "
                    f"It is now active at {device.ip}, which can happen if you replaced the device or its IP "
                    "address rotated, but it is also one of the clearest signs of an unknown device on your "
                    "network claiming the same name as a trusted one."
                ),
                recommended_actions=[
                    "Confirm whether you replaced or reconfigured this device.",
                    "If you did not, treat the new device as untrusted: change the WiFi password and review "
                    "the router's connected-device list for unfamiliar entries.",
                    "Remove the old known-device entry in HomeGuard once you have verified the change so the "
                    "alert clears on the next scan.",
                ],
                evidence={
                    "fingerprint": device.fingerprint(),
                    "current_ip": device.ip,
                    "current_mac": device.mac_address,
                    "stored_ip": stored_ip,
                    "stored_mac": stored_mac,
                    "baseline_first_seen": record.get("first_seen", ""),
                    "baseline_last_seen": record.get("last_seen", ""),
                },
            )
        ]

    def _detect_new_device(self, rule: DetectionRule, device: Device, baseline: BaselineStore | None) -> list[Finding]:
        if baseline is None or baseline.known(device):
            return []
        name = device.hostname or device.vendor or device.ip
        severity = "medium" if any(port in CRITICAL_REMOTE_PORTS for port in device.open_ports) else rule.severity
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"HomeGuard has not seen {name} before. This may be a new phone, laptop, smart TV, "
                    "camera, guest device, or something you did not approve."
                ),
                recommended_actions=[
                    "Ask household members if they recognize the device.",
                    "Check your router's connected-device list for the same IP or MAC address.",
                    "Change the WiFi password if nobody recognizes it.",
                ],
                evidence={"fingerprint": device.fingerprint(), "ip": device.ip, "mac_address": device.mac_address},
            )
        ]

    def _detect_possible_unauthorized_access(
        self, rule: DetectionRule, device: Device, baseline: BaselineStore | None
    ) -> list[Finding]:
        if baseline is None or baseline.known(device):
            return []
        exposed = sorted(set(device.open_ports) & (REMOTE_ADMIN_PORTS | FILE_SHARING_PORTS))
        if not exposed:
            return []
        name = device.hostname or device.vendor or device.ip
        remote_control = sorted(set(exposed) & REMOTE_ADMIN_PORTS)
        file_sharing = sorted(set(exposed) & FILE_SHARING_PORTS)
        if not remote_control and len(file_sharing) < 2:
            return []
        severity = "critical" if any(port in {23, 3389, 5900} for port in remote_control) else rule.severity
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Possible unauthorized access indicator on {name}",
                severity=severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"{name} is not in your known-device list and has remote-access or file-sharing service(s) "
                    f"reachable on port(s) {', '.join(str(port) for port in exposed)}. This can be a normal new computer, "
                    "but it is also one of the clearest home-network indicators of an unauthorized device."
                ),
                recommended_actions=[
                    "Confirm whether anyone in the household recognizes this device right now.",
                    "If nobody recognizes it, block the device in your router or change the WiFi password.",
                    "Disable remote-access services on the device unless you intentionally use them.",
                    "Mark the device as trusted or quarantined in HomeGuard after you identify it.",
                ],
                evidence={
                    "fingerprint": device.fingerprint(),
                    "ip": device.ip,
                    "mac_address": device.mac_address,
                    "remote_admin_ports": remote_control,
                    "file_sharing_ports": file_sharing,
                    "baseline_known": False,
                },
            )
        ]

    def _detect_remote_admin_cluster(
        self, rule: DetectionRule, device: Device, baseline: BaselineStore | None
    ) -> list[Finding]:
        threshold = int(rule.metadata.get("threshold") or 2)
        exposed = sorted(set(device.open_ports) & SERVICE_CLUSTER_PORTS)
        remote_exposed = sorted(set(device.open_ports) & REMOTE_ADMIN_PORTS)
        unusual_exposed = sorted(set(device.open_ports) & UNUSUAL_SERVICE_PORTS)
        if len(remote_exposed) < threshold and len(unusual_exposed) < 1 and len(exposed) < 5:
            return []
        trusted = bool(baseline is not None and baseline.is_trusted(device))
        if trusted and len(remote_exposed) < 3:
            return []
        name = device.hostname or device.vendor or device.ip
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Remote-administration services clustered on {name}",
                severity=rule.severity,
                confidence=rule.confidence if not trusted else max(0.4, rule.confidence - 0.18),
                category=rule.category,
                device=device,
                plain_english=(
                    f"{name} has several administration or sharing services reachable. Attackers often look for this kind "
                    "of surface after joining a network, and misconfigured home devices can expose it accidentally."
                ),
                recommended_actions=[
                    "Review every open service and turn off anything you do not use.",
                    "Check the router for port forwarding or remote-administration settings.",
                    "Update the device and replace default or weak passwords.",
                    "Move IoT or guest devices to a separate network when your router supports it.",
                ],
                evidence={
                    "ip": device.ip,
                    "open_ports": device.open_ports,
                    "remote_admin_ports": remote_exposed,
                    "unusual_ports": unusual_exposed,
                    "service_cluster_ports": exposed,
                    "trusted": trusted,
                },
            )
        ]

    def _detect_possible_malware_service(
        self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None
    ) -> list[Finding]:
        unusual = sorted(set(device.open_ports) & UNUSUAL_SERVICE_PORTS)
        if not unusual:
            return []
        name = device.hostname or device.vendor or device.ip
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Unusual service requiring review on {name}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"{name} has port(s) {', '.join(str(port) for port in unusual)} reachable. "
                    "A port-only scan cannot prove compromise: these ports may belong to lab tools, developer services, "
                    "debug bridges, or IRC-style services. They are still uncommon on typical home devices and should be "
                    "reviewed if you did not intentionally enable them."
                ),
                recommended_actions=[
                    "Identify the device and confirm whether you intentionally run this service.",
                    "Disable the service if it is not needed or move it to an isolated lab network.",
                    "Check the device owner, firmware, and admin credentials if the service is unexpected.",
                    "Use endpoint security tools on the device itself when the owner cannot explain the service.",
                ],
                evidence={
                    "ip": device.ip,
                    "unusual_ports": unusual,
                    "evidence_note": "Port-only indicator; this may be normal for lab, developer, or debug setups.",
                    "open_ports": device.open_ports,
                },
            )
        ]

    def _detect_missing_mac(self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None) -> list[Finding]:
        if device.mac_address:
            return []
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"HomeGuard could see {device.ip}, but could not confirm a MAC address. "
                    "This can happen with incomplete ARP data, privacy features, or limited permissions."
                ),
                recommended_actions=[
                    "Run again after the device is active on the network.",
                    "Compare with your router's connected-device list.",
                ],
                evidence={"ip": device.ip, "source": device.source},
            )
        ]

    def _detect_risky_ports(self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None) -> list[Finding]:
        port = int(rule.metadata.get("port") or 0)
        if port not in set(device.open_ports):
            return []
        name = device.hostname or device.vendor or device.ip
        service = str(rule.metadata.get("service") or f"Port {port}")
        why = str(rule.metadata.get("why") or "This service should be reviewed.")
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"{service} service is reachable on {name}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=f"{name} has {service} open on port {port}. {why}",
                recommended_actions=[
                    "Confirm what device this is and whether the service is expected.",
                    "Disable the service if you do not use it.",
                    "Make sure the device firmware is updated and default passwords are changed.",
                ],
                evidence={
                    "ip": device.ip,
                    "port": port,
                    "service": service,
                    "open_ports": device.open_ports,
                    "definitions_version": self.definitions.get("definitions_version"),
                },
            )
        ]

    def _detect_many_open_ports(self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None) -> list[Finding]:
        threshold = int(rule.metadata.get("threshold") or 5)
        if len(device.open_ports) < threshold:
            return []
        name = device.hostname or device.vendor or device.ip
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Many services are reachable on {name}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"{name} has {len(device.open_ports)} open services. Home devices usually need very few exposed services."
                ),
                recommended_actions=[
                    "Review the device's admin page and turn off services you do not use.",
                    "Check whether this device is a router, NAS, printer, camera, or lab machine.",
                    "Segment IoT devices onto a guest network if your router supports it.",
                ],
                evidence={"open_ports": device.open_ports, "threshold": threshold},
            )
        ]

    def _detect_default_name_hint(self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None) -> list[Finding]:
        normalized_name = (device.hostname or "").lower()
        name_hints = [str(item).lower() for item in self.definitions.get("device_name_hints") or []]
        if not normalized_name or not any(token in normalized_name for token in name_hints):
            return []
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Device name suggests a common home device: {device.hostname}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"The name {device.hostname!r} looks like a router, camera, printer, storage device, or default device label. "
                    "That is not bad by itself, but these devices are often forgotten after setup."
                ),
                recommended_actions=[
                    "Confirm the device firmware is up to date.",
                    "Change default admin passwords.",
                    "Disable cloud or remote access features you do not use.",
                ],
                evidence={"hostname": device.hostname, "definitions_version": self.definitions.get("definitions_version")},
            )
        ]

    def _detect_product_hints(self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None) -> list[Finding]:
        findings: list[Finding] = []
        for hint in match_product_hints(device, self.definitions):
            hint_id = str(hint.get("id") or "product_hint")
            findings.append(
                self._mk(
                    rule_id=f"definition_hint_{hint_id}",
                    title=str(hint.get("title") or rule.title),
                    severity=str(hint.get("severity") or rule.severity),
                    confidence=rule.confidence,
                    category=rule.category,
                    device=device,
                    plain_english=str(hint.get("plain_english") or "A local security definition matched this device profile."),
                    recommended_actions=[
                        str(item) for item in (hint.get("recommended_actions") or ["Review this device and keep it updated."])
                    ],
                    evidence={"definition_hint": hint_id, "definitions_version": self.definitions.get("definitions_version")},
                )
            )
        return findings

    def _detect_custom_hostname_match(
        self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None
    ) -> list[Finding]:
        pattern = str(rule.metadata.get("pattern") or "").strip().lower()
        hostname = (device.hostname or "").strip().lower()
        if not pattern or not hostname:
            return []
        if not fnmatch.fnmatchcase(hostname, pattern):
            return []
        why = str(rule.metadata.get("why") or "Hostname matched a custom watch list entry.")
        name = device.hostname or device.vendor or device.ip
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Custom hostname watch list match: {name}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"{name} matched the hostname pattern {pattern!r} from your local custom rules. {why}"
                ),
                recommended_actions=[
                    "Confirm this device is supposed to be on your network.",
                    "If it is unexpected, remove it from WiFi or change the WiFi password.",
                    "Edit your custom_rules.json file to refine or remove this rule if it no longer applies.",
                ],
                evidence={
                    "matched_pattern": pattern,
                    "hostname": device.hostname,
                    "ip": device.ip,
                    "rule_source": "custom_rules.json",
                },
            )
        ]

    def _detect_custom_mac_prefix_match(
        self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None
    ) -> list[Finding]:
        prefix = str(rule.metadata.get("prefix") or "").strip().lower()
        mac = (device.mac_address or "").strip().lower()
        if not prefix or not mac:
            return []
        cleaned = "".join(char for char in mac if char in "0123456789abcdef")
        if len(cleaned) < 6:
            return []
        normalized = ":".join(cleaned[i : i + 2] for i in range(0, 6, 2))
        if not normalized.startswith(prefix):
            return []
        why = str(rule.metadata.get("why") or "MAC OUI matched a custom watch list entry.")
        name = device.hostname or device.vendor or device.ip
        return [
            self._mk(
                rule_id=rule.rule_id,
                title=f"Custom MAC OUI watch list match: {name}",
                severity=rule.severity,
                confidence=rule.confidence,
                category=rule.category,
                device=device,
                plain_english=(
                    f"{name} ({device.ip}) has a MAC starting with {prefix} which matches a vendor "
                    f"prefix you flagged in custom rules. {why}"
                ),
                recommended_actions=[
                    "Confirm whether this device is expected.",
                    "Check vendor advisories for known issues with this hardware.",
                    "Edit your custom_rules.json file to refine or remove this rule if it no longer applies.",
                ],
                evidence={
                    "matched_prefix": prefix,
                    "mac_oui": normalized,
                    "ip": device.ip,
                    "rule_source": "custom_rules.json",
                },
            )
        ]

    def _detect_kev_hints(self, rule: DetectionRule, device: Device, _baseline: BaselineStore | None) -> list[Finding]:
        findings: list[Finding] = []
        for match in match_kev_catalog(device, self.definitions):
            cve_id = str(match.get("cve_id") or "CVE")
            product = " ".join(str(match.get(key) or "") for key in ("vendor_project", "product")).strip()
            required_action = str(match.get("required_action") or "Apply updates per vendor instructions.")
            ransomware = str(match.get("known_ransomware_use") or "").lower()
            severity = "high" if ransomware == "known" else rule.severity
            findings.append(
                self._mk(
                    rule_id=f"kev_hint_{cve_id}",
                    title=f"Known exploited vulnerability may apply: {cve_id}",
                    severity=severity,
                    confidence=rule.confidence,
                    category=rule.category,
                    device=device,
                    plain_english=(
                        f"Updated security definitions contain {cve_id} for {product or 'a related product'}. "
                        "HomeGuard cannot prove the exact software version from a home-network scan, so treat this as a patch-priority hint."
                    ),
                    recommended_actions=[
                        required_action,
                        "Check the device vendor app or admin page for firmware/software updates.",
                        "If you do not recognize this device, remove it from WiFi or change the WiFi password.",
                    ],
                    evidence={
                        "cve_id": cve_id,
                        "product": product,
                        "matched_words": match.get("matched_words") or [],
                        "definitions_version": self.definitions.get("definitions_version"),
                    },
                )
            )
        return findings

"""Fix-guidance playbooks for HomeGuard findings.

The detection engine emits findings with a short ``recommended_actions`` list,
but the actions are plain text and don't tell the user *how* to actually fix
the issue on a home network. A router-blocked port, a quarantined IoT camera,
and a KEV match all need very different remediation flows. This module ships
a structured playbook per finding category that the renderer can present as
a step-by-step "Show me how to fix this" panel with concrete action buttons.

Five playbook categories cover the rule taxonomy:

  * ``exposed_remote_service`` - Telnet / RDP / SMB / VNC / TeamViewer etc.
    reachable from the LAN. Steps cover router-block / device-disable /
    quarantine, with actions for closing the local port (when it's the host
    running HomeGuard) and marking the device trusted/quarantined.
  * ``unknown_device`` - new device / missing MAC / generic name hint.
    "Identify this device" workflow: look at vendor / OUI, open the Devices
    tab, mark trusted or quarantined.
  * ``quarantined_device`` - a device the user previously quarantined is on
    the network again. Options: block at router, change WiFi password,
    re-mark trusted.
  * ``cve_kev`` - KEV / product hint matched. Find vendor update page,
    mark patched once installed.
  * ``endpoint_hardening`` - Windows privesc / hardening / endpoint abuse
    finding on the host running HomeGuard. Run Defender full scan, open
    the relevant Settings panel, mark patched.

The map from rule_id → playbook_id is in ``RULE_TO_PLAYBOOK`` and falls back
to a generic playbook so every finding gets *some* guidance.

``playbook_for_finding(finding, baseline=None)`` returns a fully-populated
playbook dict with device-specific context (device name, port, CVE id) baked
into the step text. The renderer just renders the returned JSON.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Mapping


# Action kinds the renderer + Electron main know how to dispatch.
ACTION_OPEN_URL = "open_url"
ACTION_MARK_PATCHED = "mark_patched"
ACTION_MARK_TRUSTED = "mark_trusted"
ACTION_MARK_QUARANTINED = "mark_quarantined"
ACTION_MARK_UNKNOWN = "mark_unknown"
ACTION_RUN_DEFENDER_SCAN = "run_defender_scan"
ACTION_CLOSE_LOCAL_PORT = "close_local_port"
ACTION_NAVIGATE_DEVICES = "navigate_devices"
ACTION_COPY_TEXT = "copy_text"
ACTION_INFO = "info"


REMOTE_ACCESS_PORTS: dict[int, str] = {
    23: "Telnet",
    2323: "Telnet (alt)",
    22: "SSH",
    139: "NetBIOS / SMB",
    445: "SMB",
    3389: "Remote Desktop (RDP)",
    5900: "VNC",
    5938: "TeamViewer",
    5555: "Android Debug Bridge",
    1080: "SOCKS proxy",
    31337: "Back Orifice / backdoor",
    4444: "Metasploit / backdoor",
    6667: "IRC (commonly used by malware)",
}


# Map every detection rule to one of the five playbook templates.
RULE_TO_PLAYBOOK: dict[str, str] = {
    "new_device": "unknown_device",
    "missing_mac": "unknown_device",
    "default_name_hint": "unknown_device",
    "quarantined_device": "quarantined_device",
    "known_exploited_vulnerability": "cve_kev",
    "product_hint": "cve_kev",
    "possible_unauthorized_access": "exposed_remote_service",
    "remote_admin_cluster": "exposed_remote_service",
    "possible_malware_service": "exposed_remote_service",
    "many_open_ports": "exposed_remote_service",
    "hostname_collision": "exposed_remote_service",
}


@dataclass(slots=True)
class PlaybookStep:
    title: str
    body: str
    # Optional inline action that this step "owns" (e.g., "Run scan now" on a
    # Defender step). Pure-text steps leave this empty.
    action_id: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {"title": self.title, "body": self.body, "action_id": self.action_id}


@dataclass(slots=True)
class PlaybookAction:
    label: str
    action_id: str
    kind: str
    # Action-specific data. For open_url: {url}. For mark_trusted: {fingerprint}.
    # For close_local_port: {port}. For run_defender_scan: {scan_type}.
    payload: dict[str, Any] = field(default_factory=dict)
    # Optional explanation shown under the button (1 line).
    help: str = ""
    # When True, the renderer should style this as destructive (red).
    destructive: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "action_id": self.action_id,
            "kind": self.kind,
            "payload": dict(self.payload),
            "help": self.help,
            "destructive": self.destructive,
        }


@dataclass(slots=True)
class Playbook:
    id: str
    title: str
    summary: str
    severity_note: str
    steps: list[PlaybookStep] = field(default_factory=list)
    actions: list[PlaybookAction] = field(default_factory=list)
    # Filled in by the renderer side from patches.json - the playbook itself
    # is stateless. Carried through the dict so the panel can show
    # "Marked patched 2 days ago" without a second IPC call.
    patched_at: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "summary": self.summary,
            "severity_note": self.severity_note,
            "steps": [step.as_dict() for step in self.steps],
            "actions": [action.as_dict() for action in self.actions],
            "patched_at": self.patched_at,
        }


def _device_label(finding: Mapping[str, Any]) -> str:
    name = str(finding.get("device_name") or "").strip()
    ip = str(finding.get("device_ip") or "").strip()
    if name and ip:
        return f"{name} ({ip})"
    return name or ip or "this device"


def _device_fingerprint(finding: Mapping[str, Any]) -> str:
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, dict):
        fp = str(evidence.get("device_fingerprint") or "").strip()
        if fp:
            return fp
    return str(finding.get("device_fingerprint") or "").strip()


def _rule_port(finding: Mapping[str, Any]) -> int:
    evidence = finding.get("evidence") or {}
    if isinstance(evidence, dict):
        try:
            port = int(evidence.get("port") or 0)
            if 0 < port <= 65535:
                return port
        except (TypeError, ValueError):
            pass
    rule_id = str(finding.get("rule_id") or "")
    if rule_id.startswith("risky_port_"):
        try:
            port = int(rule_id.rsplit("_", 1)[-1])
            if 0 < port <= 65535:
                return port
        except (TypeError, ValueError):
            pass
    return 0


def _severity_note(severity: str) -> str:
    s = (severity or "").lower()
    if s == "critical":
        return "Critical - fix as soon as possible."
    if s == "high":
        return "High severity - prioritize this fix."
    if s == "medium":
        return "Medium severity - worth addressing soon."
    if s == "low":
        return "Low severity - review when convenient."
    if s == "info":
        return "Informational - no immediate action required."
    return ""


def _exposed_remote_service_playbook(finding: Mapping[str, Any]) -> Playbook:
    port = _rule_port(finding)
    service = REMOTE_ACCESS_PORTS.get(port, "remote-administration service")
    device = _device_label(finding)
    fingerprint = _device_fingerprint(finding)

    summary = (
        f"{service} (port {port}) is reachable on {device}. Remote-access "
        "services on a home LAN are a frequent intrusion vector - lock it down "
        "at the device, the router, or both."
    ) if port else (
        f"A remote-administration service is reachable on {device}. Close it "
        "down at the device, the router, or both."
    )

    steps: list[PlaybookStep] = [
        PlaybookStep(
            title="1. Confirm whether you actually use this service",
            body=(
                "If you don't recognize the service, don't try to use it - go "
                "straight to step 2. If you do use it (work-from-home RDP, file "
                f"shares, IP camera), at minimum require a strong password and "
                "lock the service to specific IPs in the device's settings."
            ),
        ),
        PlaybookStep(
            title="2. Disable the service on the device when possible",
            body=(
                "Settings paths by device family:\n"
                "  - Windows PC: Settings > System > Remote Desktop (off); Services > Telnet (disabled).\n"
                "  - Smart TV / IoT: Settings > Network > developer / debug mode (off).\n"
                "  - Linux / NAS: stop the service via the web admin or `systemctl disable telnet ssh smbd`.\n"
                "  - Camera / DVR: vendor app > Network > Telnet / RTSP (disabled unless needed)."
            ),
        ),
        PlaybookStep(
            title="3. Block the port at the router as a backstop",
            body=(
                "Log into your router's admin page (typically 192.168.1.1 or "
                "192.168.0.1). Look for Firewall / Access Control / Port "
                f"Forwarding. Make sure port {port or 'this port'} is NOT forwarded "
                "from the WAN. Add a LAN access rule that drops this port from "
                "guest / IoT VLANs if your router supports them."
            ) if port else (
                "Log into your router's admin page (typically 192.168.1.1 or "
                "192.168.0.1). Look for Firewall / Access Control / Port "
                "Forwarding. Make sure no remote-access ports are forwarded "
                "from the WAN."
            ),
        ),
        PlaybookStep(
            title="4. If you can't fix the device, quarantine it",
            body=(
                "Mark the device Quarantined in HomeGuard so future scans flag "
                "it as Action Needed. To actually block it from the network: "
                "remove the device from your router's allowed-clients list, OR "
                "change the WiFi password and don't share the new one with the "
                "device."
            ),
        ),
    ]

    actions: list[PlaybookAction] = [
        PlaybookAction(
            label="Open Windows Firewall settings",
            action_id="open_firewall_settings",
            kind=ACTION_OPEN_URL,
            payload={"url": "ms-settings:network-firewall"},
            help="Lets you add an inbound block rule on the PC running HomeGuard. Use router rules for other devices.",
        ),
    ]
    if fingerprint:
        actions.extend(
            [
                PlaybookAction(
                    label="Quarantine this device",
                    action_id="quarantine",
                    kind=ACTION_MARK_QUARANTINED,
                    payload={"fingerprint": fingerprint},
                    help="Flags as Action Needed in future scans. Does not block traffic by itself.",
                    destructive=True,
                ),
                PlaybookAction(
                    label="Mark trusted (I recognize this)",
                    action_id="trust",
                    kind=ACTION_MARK_TRUSTED,
                    payload={"fingerprint": fingerprint},
                    help="Use only if this device + service is intentional on your network.",
                ),
            ]
        )
    actions.append(
        PlaybookAction(
            label="Mark patched",
            action_id="mark_patched",
            kind=ACTION_MARK_PATCHED,
            payload={"finding_id": str(finding.get("finding_id") or "")},
            help="Records that you've addressed this finding. Won't re-prompt unless the finding re-appears.",
        )
    )
    return Playbook(
        id="exposed_remote_service",
        title=f"Lock down exposed {service}" if port else "Lock down exposed remote-access service",
        summary=summary,
        severity_note=_severity_note(str(finding.get("severity") or "")),
        steps=steps,
        actions=actions,
    )


def _unknown_device_playbook(finding: Mapping[str, Any]) -> Playbook:
    device = _device_label(finding)
    fingerprint = _device_fingerprint(finding)
    evidence = finding.get("evidence") or {}
    vendor = ""
    mac = ""
    if isinstance(evidence, dict):
        vendor = str(evidence.get("vendor") or "")
        mac = str(evidence.get("mac_address") or evidence.get("mac") or "")

    vendor_hint = (
        f"Vendor hint from MAC: {vendor}."
        if vendor
        else "No vendor hint from the MAC address (vendor may use a private OUI)."
    )

    steps = [
        PlaybookStep(
            title="1. Check the vendor and last-seen time",
            body=(
                f"{vendor_hint}\n"
                f"MAC: {mac or 'not available'}.\n"
                "Cross-reference with devices you bought recently (phone, laptop, "
                "tablet, smart bulb, doorbell). New devices often appear within "
                "minutes of being powered on for the first time."
            ),
        ),
        PlaybookStep(
            title="2. Walk to each device and check WiFi status",
            body=(
                "Open WiFi settings on the suspect device and confirm it's on "
                "YOUR network (the SSID should match exactly). Some devices "
                "auto-join open networks - if you see an unfamiliar device, that's "
                "a real find."
            ),
        ),
        PlaybookStep(
            title="3. Identify by open ports",
            body=(
                "The Devices tab shows open ports. Common signatures:\n"
                "  - 23, 80, 554 → IP camera / DVR.\n"
                "  - 8009, 8060, 7000 → streaming stick (Chromecast / Roku / AirPlay).\n"
                "  - 139, 445 → Windows PC or NAS.\n"
                "  - 631, 9100 → printer.\n"
                "  - 1883, 8883 → IoT hub / smart-home device."
            ),
        ),
        PlaybookStep(
            title="4. Decide: trusted, quarantine, or remove",
            body=(
                "If you identified it: mark trusted and label its family / type. "
                "If you can't identify it and don't want it on your network: "
                "quarantine it in HomeGuard AND remove it from your router's "
                "allowed-clients list (or change WiFi password)."
            ),
        ),
    ]

    actions: list[PlaybookAction] = [
        PlaybookAction(
            label="Open Devices tab",
            action_id="open_devices",
            kind=ACTION_NAVIGATE_DEVICES,
            payload={},
            help="See vendor, open ports, and trust state for every device on the LAN.",
        ),
    ]
    if fingerprint:
        actions.extend(
            [
                PlaybookAction(
                    label="Mark trusted",
                    action_id="trust",
                    kind=ACTION_MARK_TRUSTED,
                    payload={"fingerprint": fingerprint},
                    help="Use after you've confirmed the device is yours.",
                ),
                PlaybookAction(
                    label="Quarantine this device",
                    action_id="quarantine",
                    kind=ACTION_MARK_QUARANTINED,
                    payload={"fingerprint": fingerprint},
                    destructive=True,
                    help="Flags as Action Needed in future scans.",
                ),
            ]
        )
    return Playbook(
        id="unknown_device",
        title=f"Identify {device}",
        summary=(
            f"{device} is new (or has incomplete identity) on your network. "
            "Most home-network surprises are a device you bought and forgot about - "
            "walk through this checklist to identify it."
        ),
        severity_note=_severity_note(str(finding.get("severity") or "")),
        steps=steps,
        actions=actions,
    )


def _quarantined_device_playbook(finding: Mapping[str, Any]) -> Playbook:
    device = _device_label(finding)
    fingerprint = _device_fingerprint(finding)

    steps = [
        PlaybookStep(
            title="1. Quarantine in HomeGuard is a label, not a firewall",
            body=(
                "Marking quarantined makes future scans flag the device as Action "
                "Needed and surfaces it in the chat. It does NOT block the device's "
                "traffic. To actually keep this device off the network, use one "
                "of the steps below."
            ),
        ),
        PlaybookStep(
            title="2. Block at the router (preferred)",
            body=(
                "Log into your router's admin page. Look for: Wireless > Access "
                "Control, MAC Filtering, or Allowed Devices. Add this device's "
                "MAC address to the block list. Most consumer routers support "
                "this even on the free tier."
            ),
        ),
        PlaybookStep(
            title="3. Change the WiFi password",
            body=(
                "If router MAC filtering isn't available, change your WiFi "
                "password and reconnect only the devices you trust. The "
                "quarantined device won't have the new password and will drop "
                "off the network. Plan ~15 minutes to reconnect every device."
            ),
        ),
        PlaybookStep(
            title="4. If you changed your mind, mark trusted",
            body=(
                "If the device turned out to be legitimate (a guest device, a "
                "smart appliance you forgot), mark it trusted. Quarantine flags "
                "go away on the next scan."
            ),
        ),
    ]

    actions: list[PlaybookAction] = []
    if fingerprint:
        actions.extend(
            [
                PlaybookAction(
                    label="Mark trusted",
                    action_id="trust",
                    kind=ACTION_MARK_TRUSTED,
                    payload={"fingerprint": fingerprint},
                    help="Removes the quarantine flag in the next scan.",
                ),
                PlaybookAction(
                    label="Keep quarantined (no-op)",
                    action_id="quarantine",
                    kind=ACTION_MARK_QUARANTINED,
                    payload={"fingerprint": fingerprint},
                    help="Confirms the existing quarantine state.",
                ),
                PlaybookAction(
                    label="Remove from known devices",
                    action_id="mark_unknown",
                    kind=ACTION_MARK_UNKNOWN,
                    payload={"fingerprint": fingerprint},
                    help="Resets to unknown trust so the next scan treats it as a new device.",
                    destructive=True,
                ),
            ]
        )
    return Playbook(
        id="quarantined_device",
        title=f"Decide what to do with {device}",
        summary=(
            f"You marked {device} as quarantined and HomeGuard still sees it "
            "active on the network. Pick a follow-through below."
        ),
        severity_note=_severity_note(str(finding.get("severity") or "")),
        steps=steps,
        actions=actions,
    )


def _cve_kev_playbook(finding: Mapping[str, Any]) -> Playbook:
    device = _device_label(finding)
    evidence = finding.get("evidence") or {}
    cves: list[str] = []
    vendor = ""
    product = ""
    if isinstance(evidence, dict):
        raw_cves = evidence.get("cve_ids") or evidence.get("cve_list") or evidence.get("cves")
        if isinstance(raw_cves, list):
            cves = [str(c) for c in raw_cves if c]
        elif raw_cves:
            cves = [str(raw_cves)]
        single = str(evidence.get("cve") or evidence.get("cve_id") or "")
        if single and single not in cves:
            cves.append(single)
        vendor = str(evidence.get("vendor") or "")
        product = str(evidence.get("product") or evidence.get("product_name") or "")

    cve_line = f"CVE(s): {', '.join(cves)}." if cves else "Specific CVE id not attached to this finding."
    vendor_line = f"Vendor / product hint: {vendor} {product}".strip(" /")

    steps = [
        PlaybookStep(
            title="1. Confirm the device and firmware version",
            body=(
                f"{device}\n{cve_line}\n{vendor_line or 'Vendor/product unknown from this finding.'}\n"
                "Open the device's web admin (or its app) and find Settings > "
                "About / Firmware / System Info. Note the exact model and "
                "firmware version - this drives whether an update is even available."
            ),
        ),
        PlaybookStep(
            title="2. Look up the vendor's update page",
            body=(
                "Click the action below to open the vendor's support page (or "
                "the NVD page for the CVE if the vendor is unknown). Look for a "
                "firmware download or a 'check for updates' setting."
            ),
        ),
        PlaybookStep(
            title="3. Install the update",
            body=(
                "Most home devices update via their companion app (Wyze, Ring, "
                "Hue, etc.). Routers usually have an Administration > Firmware "
                "Update page. After updating, reboot the device."
            ),
        ),
        PlaybookStep(
            title="4. Confirm and mark patched",
            body=(
                "Re-check the firmware version after the reboot. Run a HomeGuard "
                "scan and confirm the finding no longer shows up. Then mark "
                "this finding patched to silence it in the panel."
            ),
        ),
    ]

    primary_url = ""
    if cves:
        primary_url = f"https://nvd.nist.gov/vuln/detail/{cves[0]}"
    elif vendor:
        primary_url = f"https://www.google.com/search?q={vendor}+firmware+update"
    else:
        primary_url = "https://nvd.nist.gov/vuln/search"

    actions: list[PlaybookAction] = [
        PlaybookAction(
            label="Open vendor / CVE update page",
            action_id="open_update_page",
            kind=ACTION_OPEN_URL,
            payload={"url": primary_url},
            help=f"Opens {primary_url} in your default browser.",
        ),
        PlaybookAction(
            label="Mark patched",
            action_id="mark_patched",
            kind=ACTION_MARK_PATCHED,
            payload={
                "finding_id": str(finding.get("finding_id") or ""),
                "cves": cves,
            },
            help="Records the patched timestamp. Future scans still flag it if the device firmware regresses.",
        ),
    ]
    return Playbook(
        id="cve_kev",
        title=f"Patch known vulnerability on {device}",
        summary=(
            f"A vulnerability in HomeGuard's local CVE / KEV catalog may apply "
            f"to {device}. Confirm the firmware version and install the vendor "
            "update."
        ),
        severity_note=_severity_note(str(finding.get("severity") or "")),
        steps=steps,
        actions=actions,
    )


def _endpoint_hardening_playbook(finding: Mapping[str, Any]) -> Playbook:
    rule_id = str(finding.get("rule_id") or "")
    title = str(finding.get("title") or "Endpoint hardening finding")
    plain = str(finding.get("plain_english") or "")

    is_defender_related = "defender" in rule_id.lower() or "credential_guard" in rule_id.lower()
    is_privesc = "privesc" in rule_id.lower()

    steps: list[PlaybookStep] = [
        PlaybookStep(
            title="1. Read the finding context",
            body=(plain or title),
        ),
        PlaybookStep(
            title="2. Run a Microsoft Defender full scan",
            body=(
                "A Defender full scan checks every file on disk for known "
                "malware signatures and behavioral indicators. Run it before "
                "you make hardening changes so you have a clean baseline.\n\n"
                "Click 'Run Defender full scan' below, or open Settings > "
                "Privacy & security > Windows Security > Virus & threat "
                "protection > Scan options > Full scan."
            ),
            action_id="run_defender_scan",
        ),
        PlaybookStep(
            title="3. Address the specific hardening control",
            body=(
                _hardening_step_body(rule_id)
            ),
        ),
        PlaybookStep(
            title="4. Re-scan and mark patched",
            body=(
                "Run a fresh HomeGuard scan with the endpoint scan enabled. "
                "If the finding no longer fires, mark it patched here to keep "
                "the panel clean."
            ),
        ),
    ]

    actions: list[PlaybookAction] = [
        PlaybookAction(
            label="Run Defender full scan",
            action_id="run_defender",
            kind=ACTION_RUN_DEFENDER_SCAN,
            payload={"scan_type": "full"},
            help="Launches MpCmdRun.exe -Scan -ScanType 2. Windows only; takes 30-90 minutes.",
        ),
        PlaybookAction(
            label="Open Windows Security",
            action_id="open_security_settings",
            kind=ACTION_OPEN_URL,
            payload={"url": "windowsdefender://"},
            help="Opens the Windows Security control panel directly.",
        ),
        PlaybookAction(
            label="Mark patched",
            action_id="mark_patched",
            kind=ACTION_MARK_PATCHED,
            payload={"finding_id": str(finding.get("finding_id") or "")},
            help="Records that you've addressed this finding.",
        ),
    ]

    if is_privesc:
        actions.insert(
            1,
            PlaybookAction(
                label="Open registry hardening guide",
                action_id="open_privesc_guide",
                kind=ACTION_OPEN_URL,
                payload={
                    "url": "https://learn.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/security-considerations-for-applocker"
                },
                help="Microsoft's hardening reference for application control.",
            ),
        )

    return Playbook(
        id="endpoint_hardening",
        title=f"Harden: {title}",
        summary=(
            "This is an endpoint hardening finding on the PC running HomeGuard. "
            "Run a Defender scan and address the specific control below."
        ) if is_defender_related else (
            "This is an endpoint hardening finding on the PC running HomeGuard. "
            "Address the specific control below, then re-scan to confirm."
        ),
        severity_note=_severity_note(str(finding.get("severity") or "")),
        steps=steps,
        actions=actions,
    )


def _hardening_step_body(rule_id: str) -> str:
    """Per-rule hardening guidance for the endpoint playbook step 3."""
    lookup = {
        "windows_privesc_always_install_elevated": (
            "Open `regedit` and clear AlwaysInstallElevated at both "
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer and "
            "HKCU\\... (set DWORD to 0 or delete the value). Reboot."
        ),
        "windows_privesc_autologon_secret": (
            "Open `netplwiz`, ensure 'Users must enter a user name and password' "
            "is checked. Clear DefaultPassword from "
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon."
        ),
        "windows_privesc_gpp_password_file": (
            "Delete the Group Policy Preferences XML file containing the "
            "encrypted cpassword. Replace the affected accounts' passwords."
        ),
        "windows_privesc_unattended_install_secret": (
            "Delete (or scrub) the Unattend.xml / sysprep.inf file with the "
            "stored password under C:\\Windows\\Panther."
        ),
        "windows_privesc_unquoted_service_path": (
            "Edit the service's ImagePath registry value to wrap the path in "
            "double quotes. Restart the service."
        ),
        "windows_privesc_writable_service_binary": (
            "Reset NTFS permissions on the service binary so only "
            "Administrators / SYSTEM can write to it: `icacls <path> /reset` "
            "then re-grant ACLs as needed."
        ),
        "windows_privesc_sensitive_privilege_enabled": (
            "Open Local Security Policy > Local Policies > User Rights "
            "Assignment. Remove the user from the privilege named in the "
            "finding evidence."
        ),
        "windows_hardening_powershell_v2_enabled": (
            "Run `Disable-WindowsOptionalFeature -Online -FeatureName "
            "MicrosoftWindowsPowerShellV2 -NoRestart` as Administrator. "
            "Reboot."
        ),
        "windows_hardening_lsass_protection_disabled": (
            "Set RunAsPPL under "
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa to DWORD 1, then "
            "reboot. Verify with `Get-ItemProperty -Path HKLM:\\SYSTEM\\...`"
        ),
        "windows_hardening_credential_guard_disabled": (
            "Group Policy: Computer Configuration > Administrative Templates > "
            "System > Device Guard > Turn On Virtualization Based Security > "
            "Enabled, with Credential Guard set to Enabled with UEFI lock."
        ),
    }
    body = lookup.get(rule_id)
    if body:
        return body
    return (
        "Follow the recommended_actions list at the top of this finding in the "
        "HomeGuard report. The fix is usually a registry / Group Policy / "
        "service-permission change."
    )


def _generic_playbook(finding: Mapping[str, Any]) -> Playbook:
    """Fallback playbook when no specific category matches."""
    device = _device_label(finding)
    fingerprint = _device_fingerprint(finding)
    recommended = finding.get("recommended_actions") or []
    if not isinstance(recommended, list):
        recommended = []

    steps = [
        PlaybookStep(
            title="1. Review the finding details",
            body=str(finding.get("plain_english") or finding.get("title") or "Open the finding in the report for full context."),
        ),
        PlaybookStep(
            title="2. Apply the recommended actions",
            body=(
                "\n".join(f"  - {item}" for item in recommended)
                if recommended
                else "See the report for context-specific recommendations."
            ),
        ),
        PlaybookStep(
            title="3. Re-scan and mark patched",
            body=(
                "Run a fresh HomeGuard scan. If the finding no longer appears, "
                "mark it patched below."
            ),
        ),
    ]
    actions: list[PlaybookAction] = []
    if fingerprint:
        actions.append(
            PlaybookAction(
                label="Open Devices tab",
                action_id="open_devices",
                kind=ACTION_NAVIGATE_DEVICES,
                payload={},
            )
        )
    actions.append(
        PlaybookAction(
            label="Mark patched",
            action_id="mark_patched",
            kind=ACTION_MARK_PATCHED,
            payload={"finding_id": str(finding.get("finding_id") or "")},
            help="Records that you've addressed this finding.",
        )
    )
    return Playbook(
        id="generic",
        title=str(finding.get("title") or "Review this finding"),
        summary=str(finding.get("plain_english") or "Use the steps below as a starting point."),
        severity_note=_severity_note(str(finding.get("severity") or "")),
        steps=steps,
        actions=actions,
    )


def playbook_id_for_rule(rule_id: str) -> str:
    """Map a rule_id to one of the five playbook categories."""
    rid = (rule_id or "").lower()
    if rid in RULE_TO_PLAYBOOK:
        return RULE_TO_PLAYBOOK[rid]
    if rid.startswith("risky_port_"):
        return "exposed_remote_service"
    if rid.startswith("windows_privesc_") or rid.startswith("windows_hardening_") or rid.startswith("endpoint_"):
        return "endpoint_hardening"
    if rid.startswith("custom_hostname_") or rid.startswith("custom_mac_"):
        return "unknown_device"
    return "generic"


_PLAYBOOK_BUILDERS = {
    "exposed_remote_service": _exposed_remote_service_playbook,
    "unknown_device": _unknown_device_playbook,
    "quarantined_device": _quarantined_device_playbook,
    "cve_kev": _cve_kev_playbook,
    "endpoint_hardening": _endpoint_hardening_playbook,
    "generic": _generic_playbook,
}


def playbook_for_finding(finding: Mapping[str, Any]) -> Playbook:
    """Return the playbook for a given finding dict.

    The finding is expected to look like ``Finding.as_dict()`` output - with
    ``rule_id``, ``severity``, ``device_ip``, ``device_name``, ``evidence``,
    ``plain_english``, etc. Missing fields fall back to safe defaults so the
    function never raises on incomplete input.
    """
    playbook_id = playbook_id_for_rule(str(finding.get("rule_id") or ""))
    builder = _PLAYBOOK_BUILDERS.get(playbook_id, _generic_playbook)
    playbook = builder(finding)
    playbook.id = playbook_id  # keep the canonical id even after generic fallback
    return playbook


def all_playbook_ids() -> list[str]:
    """Stable list of every playbook id this module ships."""
    return list(_PLAYBOOK_BUILDERS.keys())

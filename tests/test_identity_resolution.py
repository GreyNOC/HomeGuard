import os
import tempfile
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_test_identity_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard._noc_core import discovery as noc_discovery  # noqa: E402
from greynoc_homeguard.baseline import BaselineStore  # noqa: E402
from greynoc_homeguard.identity_resolution import (  # noqa: E402
    SOURCE_DHCP,
    SOURCE_DISCOVERY,
    SOURCE_MDNS,
    SOURCE_NETBIOS,
    SOURCE_REVERSE_DNS,
    SOURCE_SSDP,
    SOURCE_SYNTHESIZED,
    SOURCE_UNRESOLVED,
    display_name_for,
    identity_from_metadata,
    resolve_device,
)
from greynoc_homeguard.models import Device  # noqa: E402


# --------------------------------------------------------------------------
# C / D - synthesized hostname only when device has a MAC
# --------------------------------------------------------------------------


class MacBoundarySynthesisTests(unittest.TestCase):
    """Devices without a MAC get friendly_name but keep device.hostname blank."""

    def test_mac_bearing_device_with_no_hostname_gets_synthesized_hostname(self):
        device = Device(
            ip="192.168.1.42",
            mac_address="c8:3a:35:11:22:33",
            vendor="TP-Link",
            open_ports=[53, 80, 443],
        )
        resolved = resolve_device(device)
        self.assertNotEqual(resolved.hostname, "")
        self.assertTrue(resolved.metadata["hostname_synthesized"])
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_SYNTHESIZED)
        self.assertEqual(resolved.metadata["friendly_name"], resolved.hostname)
        # Fingerprint stays MAC-anchored either way.
        self.assertTrue(resolved.fingerprint().startswith("mac:"))

    def test_mac_less_device_keeps_hostname_blank_but_gets_friendly_name(self):
        device = Device(ip="10.5.0.7", open_ports=[139, 445])
        resolved = resolve_device(device)
        # device.hostname stays blank so the fingerprint key stays IP-based.
        self.assertEqual(resolved.hostname, "")
        self.assertTrue(resolved.fingerprint().startswith("ip:"))
        # But the GUI / report can still show a readable label.
        friendly = resolved.metadata["friendly_name"]
        self.assertTrue(friendly)
        self.assertIn("7", friendly)  # last octet appears
        # Hostname source is unresolved (no DNS / no MAC -> no synthesis).
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_UNRESOLVED)
        self.assertFalse(resolved.metadata["hostname_synthesized"])


# --------------------------------------------------------------------------
# Hostname priority chain
# --------------------------------------------------------------------------


class HostnamePriorityChainTests(unittest.TestCase):
    """Each source slot in the priority chain wins when the slots above are empty."""

    def _device(self, **extra_metadata):
        device = Device(
            ip="192.168.1.42",
            mac_address="aa:bb:cc:dd:ee:ff",
        )
        device.metadata.update(extra_metadata)
        return device

    def test_existing_hostname_with_mdns_in_discovered_by_wins_as_mdns_source(self):
        device = self._device()
        device.hostname = "front-door-cam.local"
        device.metadata["discovered_by"] = ["arp", "mdns"]
        resolved = resolve_device(device)
        self.assertEqual(resolved.hostname, "front-door-cam.local")
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_MDNS)
        self.assertEqual(resolved.metadata["real_hostname"], "front-door-cam.local")
        self.assertFalse(resolved.metadata["hostname_synthesized"])

    def test_dhcp_hostname_metadata_used_when_hostname_blank(self):
        device = self._device(dhcp_hostname="brandons-laptop")
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_DHCP)
        self.assertEqual(resolved.metadata["real_hostname"], "brandons-laptop")
        self.assertEqual(resolved.hostname, "brandons-laptop")  # promoted (has MAC)

    def test_mdns_friendly_name_wins_over_netbios(self):
        device = self._device(mdns_friendly_name="Living Room TV", netbios_name="DESKTOP1")
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_MDNS)
        self.assertEqual(resolved.metadata["real_hostname"], "Living Room TV")

    def test_netbios_used_when_no_dhcp_or_mdns(self):
        device = self._device(netbios_name="DESKTOP-7XB2K")
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_NETBIOS)
        self.assertEqual(resolved.metadata["real_hostname"], "DESKTOP-7XB2K")

    def test_reverse_dns_used_when_only_signal(self):
        device = self._device(reverse_dns_name="host-42.localnet")
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_REVERSE_DNS)

    def test_ssdp_friendly_name_used_last(self):
        device = self._device(ssdp_friendly_name="Roku Express")
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["hostname_source"], SOURCE_SSDP)
        self.assertEqual(resolved.metadata["real_hostname"], "Roku Express")


# --------------------------------------------------------------------------
# E - mDNS / SSDP service-based classification
# --------------------------------------------------------------------------


class ServiceClassificationTests(unittest.TestCase):
    """Service hints classify devices for each taxonomy category."""

    def _device_with_services(self, services):
        device = Device(ip="192.168.1.50", mac_address="aa:bb:cc:11:22:33")
        device.metadata["services"] = list(services)
        return device

    def test_ipp_service_classifies_as_printer(self):
        device = self._device_with_services(["_ipp._tcp.local"])
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "printer")
        self.assertEqual(resolved.metadata["device_type_source"], "mdns_service")

    def test_googlecast_classifies_as_tv(self):
        device = self._device_with_services(["_googlecast._tcp.local"])
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "tv")

    def test_internet_gateway_ssdp_classifies_as_router(self):
        device = Device(ip="192.168.1.5", mac_address="aa:bb:cc:dd:ee:ff")
        device.metadata["device_hints"] = ["urn:schemas-upnp-org:device:InternetGatewayDevice:1"]
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "router")
        self.assertEqual(resolved.metadata["device_type_source"], "ssdp_field")

    def test_rtsp_onvif_service_classifies_as_camera(self):
        device = self._device_with_services(["_rtsp._tcp.local", "onvif:wsdd"])
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "camera")

    def test_xbox_live_hint_classifies_as_console(self):
        device = Device(ip="192.168.1.60", mac_address="aa:bb:cc:11:22:00")
        device.metadata["device_hints"] = ["xbox live device announce"]
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "console")

    def test_homekit_hap_service_classifies_as_iot(self):
        device = self._device_with_services(["_hap._tcp.local"])
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "iot")

    def test_sonos_service_classifies_as_iot(self):
        device = self._device_with_services(["_sonos._tcp.local"])
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "iot")


# --------------------------------------------------------------------------
# F / G - baseline + unknown handling
# --------------------------------------------------------------------------


class BaselineInteractionTests(unittest.TestCase):
    def test_user_set_device_type_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = BaselineStore(Path(tmp) / "b.json").load()
            device = Device(ip="192.168.1.41", mac_address="aa:bb:cc:dd:ee:11", vendor="Wyze")
            device.open_ports = [554]
            resolve_device(device)
            store.update([device])
            # User intentionally relabels.
            store.set_label(device.fingerprint(), device_type="iot")
            # Next scan: resolver still says "camera" but baseline keeps "iot".
            resolve_device(device)
            store.update([device])
            row = store.get(device)
            self.assertEqual(row["device_type"], "iot")
            self.assertTrue(row.get("device_type_user_set"))

    def test_unknown_stays_unknown_with_no_evidence(self):
        # Mid-subnet IP, no MAC, no hostname, no ports, no services. Nothing
        # should fire and the resolver MUST NOT silently invent a type.
        device = Device(ip="10.5.0.50")
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "unknown")
        self.assertEqual(resolved.metadata["resolved_device_type_confidence"], 0.0)

    def test_baseline_persists_resolution_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = BaselineStore(Path(tmp) / "b.json").load()
            device = Device(ip="192.168.1.65", mac_address="8c:90:d3:11:22:33")
            device.metadata["services"] = ["_googlecast._tcp.local"]
            resolve_device(device)
            store.update([device])
            row = store.get(device)
            self.assertEqual(row["device_type"], "tv")
            self.assertEqual(row["device_type_source"], "mdns_service")
            self.assertIn("classifier", row["resolution_evidence"])
            self.assertEqual(row["friendly_name"], device.metadata["friendly_name"])


# --------------------------------------------------------------------------
# A / B - passive-NetBIOS + bounded parallel lookups
# --------------------------------------------------------------------------


class PassiveNetBiosTests(unittest.TestCase):
    """The discovery engine must run NetBIOS enrichment even in passive scans."""

    def test_fill_netbios_runs_during_passive_scan(self):
        opts = noc_discovery.DiscoveryOptions(passive_only=True, hostname_lookup_budget=4, hostname_lookup_workers=2)
        accumulator = noc_discovery._DeviceAccumulator(timestamp="2026-05-23T00:00:00Z")
        accumulator.merge({"ip": "192.168.1.51", "mac": "aa:bb:cc:dd:ee:01", "discovered_by": ["arp"]}, "arp")
        accumulator.merge({"ip": "192.168.1.52", "mac": "aa:bb:cc:dd:ee:02", "discovered_by": ["arp"]}, "arp")
        with mock.patch.object(noc_discovery, "_netbios_lookup", return_value="DESKTOP-7XB2K") as patched:
            noc_discovery._fill_netbios_names(accumulator, opts)
            # Both targets get a lookup, despite passive_only=True.
            self.assertEqual(patched.call_count, 2)
        names = sorted(row.get("hostname") for row in accumulator._devices)
        self.assertEqual(names, ["DESKTOP-7XB2K", "DESKTOP-7XB2K"])

    def test_hostname_lookup_is_bounded_and_does_not_hang(self):
        """A dead lookup must NOT stall the scan; the worker pool drains around it."""
        opts = noc_discovery.DiscoveryOptions(
            passive_only=True,
            hostname_lookup_budget=8,
            hostname_lookup_workers=4,
            reverse_dns_timeout=0.05,
        )
        accumulator = noc_discovery._DeviceAccumulator(timestamp="2026-05-23T00:00:00Z")
        for i in range(8):
            accumulator.merge({"ip": f"192.168.1.{60 + i}", "mac": f"aa:bb:cc:dd:ee:{i:02x}", "discovered_by": ["arp"]}, "arp")

        # 4 of 8 lookups "hang"; the others succeed instantly.
        def fake_lookup(ip, timeout):
            if int(ip.rsplit(".", 1)[-1]) % 2 == 0:
                time.sleep(min(timeout, 0.1))  # bounded hang
                return ""
            return f"host-{ip.rsplit('.', 1)[-1]}"

        opts.reverse_dns_lookup = fake_lookup
        start = time.monotonic()
        noc_discovery._fill_reverse_dns(accumulator, opts)
        elapsed = time.monotonic() - start
        # 8 lookups, 4 workers, each fake_lookup ≤ 0.1s -> total well under 1s.
        self.assertLess(elapsed, 1.0, f"hostname enrichment took {elapsed:.2f}s; should be parallel")
        # Only the odd-IP lookups returned a name.
        resolved_names = {row["ip"]: row.get("hostname", "") for row in accumulator._devices}
        for ip, name in resolved_names.items():
            last = int(ip.rsplit(".", 1)[-1])
            if last % 2 == 0:
                self.assertEqual(name, "", f"{ip} should have stayed blank")
            else:
                self.assertEqual(name, f"host-{last}", f"{ip} should have resolved")

    def test_hostname_lookup_respects_cancel_event(self):
        cancel = mock.MagicMock()
        cancel.is_set.return_value = True
        opts = noc_discovery.DiscoveryOptions(
            passive_only=True,
            hostname_lookup_budget=4,
            hostname_lookup_workers=2,
            cancel_event=cancel,
        )
        accumulator = noc_discovery._DeviceAccumulator(timestamp="2026-05-23T00:00:00Z")
        accumulator.merge({"ip": "192.168.1.71", "mac": "aa:bb:cc:dd:ee:71", "discovered_by": ["arp"]}, "arp")
        # Should bail before any lookup fires.
        with mock.patch.object(noc_discovery, "_netbios_lookup", return_value="X") as patched:
            noc_discovery._fill_netbios_names(accumulator, opts)
            self.assertEqual(patched.call_count, 0)


# --------------------------------------------------------------------------
# H - export/report includes friendly_name + evidence
# --------------------------------------------------------------------------


class ResolutionEvidenceTests(unittest.TestCase):
    def test_resolution_evidence_is_serializable(self):
        device = Device(
            ip="192.168.1.65",
            mac_address="8c:90:d3:11:22:33",
            vendor="Roku",
            open_ports=[8060],
        )
        device.metadata["services"] = ["_googlecast._tcp.local"]
        resolved = resolve_device(device)
        record = identity_from_metadata(resolved.metadata)
        self.assertEqual(record.resolved_device_type, "tv")
        self.assertEqual(record.friendly_name, resolved.metadata["friendly_name"])
        self.assertIn("classifier", record.resolution_evidence)
        self.assertEqual(record.vendor_source, "engine")

    def test_display_name_for_prefers_real_hostname(self):
        device = Device(ip="192.168.1.10", mac_address="aa:bb:cc:dd:ee:01", hostname="livingroom-tv")
        resolve_device(device)
        self.assertEqual(display_name_for(device), "livingroom-tv")

    def test_display_name_for_uses_friendly_name_when_hostname_synthesized(self):
        device = Device(ip="192.168.1.32", mac_address="aa:bb:cc:dd:ee:02", vendor="Apple")
        resolve_device(device)
        # Synthesized -> display name comes from friendly_name (= same string, but
        # signals that it isn't a real DNS name).
        name = display_name_for(device)
        self.assertTrue(name)
        self.assertEqual(name, device.metadata["friendly_name"])

    def test_display_name_for_mac_less_device_uses_friendly_name(self):
        device = Device(ip="10.5.0.7", open_ports=[139, 445])
        resolve_device(device)
        # device.hostname remains blank; display_name_for falls back to friendly_name.
        name = display_name_for(device)
        self.assertTrue(name)
        self.assertEqual(name, device.metadata["friendly_name"])


if __name__ == "__main__":
    unittest.main()

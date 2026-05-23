import os
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_test_devres_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard.baseline import BaselineStore  # noqa: E402
from greynoc_homeguard.device_resolution import (  # noqa: E402
    KNOWN_DEVICE_TYPES,
    classify_device,
    extended_vendor_from_mac,
    resolve_device,
    resolve_devices,
    synthesize_hostname,
)
from greynoc_homeguard.models import Device  # noqa: E402


class ExtendedOuiTests(unittest.TestCase):
    """Secondary OUI lookup covers vendors the engine + local table miss."""

    def test_extended_oui_finds_known_consumer_prefix(self):
        self.assertEqual(extended_vendor_from_mac("8c:90:d3:11:22:33"), "Roku")
        self.assertEqual(extended_vendor_from_mac("78:28:CA:00:00:00"), "Sonos")
        self.assertEqual(extended_vendor_from_mac("dca632aabbcc"), "Raspberry Pi")

    def test_extended_oui_blank_for_unknown_and_invalid(self):
        self.assertEqual(extended_vendor_from_mac(""), "")
        self.assertEqual(extended_vendor_from_mac("zz:zz:zz:11:22:33"), "")
        self.assertEqual(extended_vendor_from_mac("ab"), "")
        # An unallocated OUI we don't ship a hint for.
        self.assertEqual(extended_vendor_from_mac("99:99:99:11:22:33"), "")


class ClassifyDeviceTests(unittest.TestCase):
    """Multi-signal scoring picks the right device_type for common cases."""

    def test_rtsp_camera_with_vendor(self):
        device = Device(
            ip="192.168.1.40",
            mac_address="b8:78:2e:11:22:33",
            vendor="Wyze",
            hostname="front-door-camera",
            open_ports=[23, 80, 554],
        )
        kind, confidence = classify_device(device)
        self.assertEqual(kind, "camera")
        self.assertGreater(confidence, 0.5)

    def test_router_from_ip_and_dns_port(self):
        device = Device(
            ip="192.168.1.1",
            mac_address="c8:3a:35:11:22:33",
            vendor="TP-Link",
            open_ports=[53, 80, 443],
        )
        kind, confidence = classify_device(device)
        self.assertEqual(kind, "router")
        self.assertGreater(confidence, 0.5)

    def test_roku_tv_from_port(self):
        device = Device(
            ip="192.168.1.65",
            mac_address="8c:90:d3:11:22:33",
            open_ports=[8060, 80],
        )
        kind, _ = classify_device(device)
        self.assertEqual(kind, "tv")

    def test_printer_from_port_combo(self):
        device = Device(
            ip="192.168.1.70",
            mac_address="00:13:21:11:22:33",
            open_ports=[631, 9100, 80],
        )
        kind, _ = classify_device(device)
        self.assertEqual(kind, "printer")

    def test_iphone_from_hostname(self):
        device = Device(
            ip="192.168.1.32",
            mac_address="ac:61:ea:11:22:33",
            hostname="Brandons-iPhone",
        )
        kind, _ = classify_device(device)
        self.assertEqual(kind, "phone")

    def test_smb_host_is_laptop(self):
        device = Device(
            ip="10.5.0.2",
            open_ports=[139, 445],
        )
        kind, _ = classify_device(device)
        self.assertEqual(kind, "laptop")

    def test_engine_type_hint_promotes_iot(self):
        device = Device(
            ip="192.168.1.91",
            mac_address="00:11:11:11:22:33",
            metadata={"device_type_guess": "smart-home"},
        )
        kind, _ = classify_device(device)
        self.assertEqual(kind, "iot")

    def test_unknown_when_no_signal(self):
        # Mid-subnet IP with no MAC, hostname, vendor, ports, or engine hint.
        # Nothing should fire and the classifier must NOT silently invent a type.
        device = Device(ip="10.5.0.50")
        kind, confidence = classify_device(device)
        self.assertEqual(kind, "unknown")
        self.assertEqual(confidence, 0.0)

    def test_router_ip_heuristic_fires_alone(self):
        # ``.1`` and ``.254`` are strong-enough router hints by themselves
        # that the classifier should pick "router" even without ports.
        device = Device(ip="192.168.1.1")
        kind, _ = classify_device(device)
        self.assertEqual(kind, "router")

    def test_classified_type_is_always_in_taxonomy(self):
        # Even when several scattered weak signals fire, the chosen type must
        # be one of the constrained taxonomy values the UI knows how to show.
        device = Device(
            ip="192.168.1.45",
            mac_address="aa:bb:cc:dd:ee:ff",
            hostname="some-thing",
            vendor="UnlistedVendor",
            open_ports=[80, 443],
        )
        kind, _ = classify_device(device)
        self.assertIn(kind, KNOWN_DEVICE_TYPES)


class SynthesizeHostnameTests(unittest.TestCase):
    def test_builds_vendor_type_suffix_form(self):
        device = Device(
            ip="192.168.1.1",
            mac_address="c8:3a:35:11:22:33",
            vendor="TP-Link",
            metadata={"resolved_device_type": "router"},
        )
        self.assertEqual(synthesize_hostname(device), "tp-link-router-1")

    def test_camera_with_last_octet(self):
        device = Device(
            ip="192.168.1.40",
            mac_address="b8:78:2e:11:22:33",
            vendor="Wyze",
            metadata={"resolved_device_type": "camera"},
        )
        self.assertEqual(synthesize_hostname(device), "wyze-camera-40")

    def test_collapses_repeated_dashes_and_lowercases(self):
        device = Device(
            ip="192.168.1.5",
            mac_address="00:11:22:33:44:55",
            vendor="TP   Link",
            metadata={"resolved_device_type": "router"},
        )
        # Whitespace collapses to a single dash; no trailing/leading dashes.
        name = synthesize_hostname(device)
        self.assertEqual(name, "tp-link-router-5")

    def test_falls_back_to_host_ip_when_no_vendor_no_type(self):
        device = Device(ip="192.168.1.99", mac_address="aa:aa:aa:aa:aa:aa")
        name = synthesize_hostname(device)
        # No vendor, no resolved type, only IP last octet.
        self.assertEqual(name, "99")  # falls through to the suffix alone

    def test_empty_when_no_ip_no_vendor(self):
        device = Device(ip="", mac_address="aa:bb:cc:dd:ee:ff")
        self.assertEqual(synthesize_hostname(device), "")


class ResolveDeviceTests(unittest.TestCase):
    def test_resolve_sets_metadata_and_synthesizes_hostname(self):
        device = Device(
            ip="192.168.1.40",
            mac_address="b8:78:2e:11:22:33",
            open_ports=[80, 554],
        )
        resolved = resolve_device(device)
        self.assertEqual(resolved.metadata["resolved_device_type"], "camera")
        self.assertGreater(resolved.metadata["resolved_device_type_confidence"], 0.0)
        # Hostname was synthesized because device has MAC + classified type.
        self.assertTrue(resolved.metadata.get("hostname_synthesized"))
        self.assertIn("camera", resolved.hostname)
        self.assertTrue(resolved.hostname.endswith("-40"))

    def test_resolve_does_not_synthesize_without_mac(self):
        # No MAC means the device's fingerprint key is ip-based; rewriting
        # hostname would shift the fingerprint to host-based on the next
        # scan and create a duplicate baseline record.
        device = Device(ip="10.5.0.2", open_ports=[139, 445])
        resolved = resolve_device(device)
        self.assertEqual(resolved.hostname, "")
        self.assertFalse(resolved.metadata.get("hostname_synthesized"))
        # Classification still ran.
        self.assertEqual(resolved.metadata["resolved_device_type"], "laptop")

    def test_resolve_fills_vendor_from_extended_oui_when_blank(self):
        device = Device(
            ip="192.168.1.65",
            mac_address="8c:90:d3:11:22:33",  # Roku in extended OUI
            open_ports=[8060],
        )
        resolved = resolve_device(device)
        self.assertEqual(resolved.vendor, "Roku")
        self.assertEqual(resolved.metadata.get("resolved_vendor"), "Roku")
        self.assertEqual(resolved.metadata["resolved_device_type"], "tv")

    def test_resolve_does_not_override_existing_vendor(self):
        device = Device(
            ip="192.168.1.40",
            mac_address="b8:78:2e:11:22:33",
            vendor="WyzeCam Inc.",
            open_ports=[554],
        )
        resolved = resolve_device(device)
        # The engine already supplied a vendor; we don't clobber it from the
        # extended OUI table.
        self.assertEqual(resolved.vendor, "WyzeCam Inc.")
        self.assertNotIn("resolved_vendor", resolved.metadata)

    def test_resolve_devices_returns_list_in_place(self):
        a = Device(ip="192.168.1.1", mac_address="c8:3a:35:11:22:33", open_ports=[53, 80, 443])
        b = Device(ip="192.168.1.40", mac_address="b8:78:2e:11:22:33", open_ports=[554])
        resolved = resolve_devices([a, b])
        self.assertEqual(len(resolved), 2)
        self.assertEqual(a.metadata["resolved_device_type"], "router")
        self.assertEqual(b.metadata["resolved_device_type"], "camera")


class BaselineAutoClassifyTests(unittest.TestCase):
    """BaselineStore picks up the resolver's guess only when the user hasn't labeled."""

    def test_auto_fills_device_type_from_resolved_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(
                ip="192.168.1.40",
                mac_address="b8:78:2e:11:22:33",
                vendor="Wyze",
                open_ports=[554],
            )
            resolve_device(device)
            store.update([device])
            record = store.get(device)
            self.assertEqual(record["device_type"], "camera")
            self.assertTrue(record.get("device_type_auto"))
            self.assertGreater(record.get("device_type_confidence", 0.0), 0.0)

    def test_user_label_blocks_auto_classification(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(
                ip="192.168.1.40",
                mac_address="b8:78:2e:11:22:33",
                vendor="Wyze",
                open_ports=[554],
            )
            store.update([device])
            # User decides this is an "iot" device (e.g. it's a Wyze plug).
            store.set_label(device.fingerprint(), device_type="iot")
            record = store.get(device)
            self.assertEqual(record["device_type"], "iot")
            self.assertTrue(record.get("device_type_user_set"))
            # Next scan: resolver still says "camera", but baseline must keep "iot".
            resolve_device(device)
            store.update([device])
            record = store.get(device)
            self.assertEqual(record["device_type"], "iot")
            self.assertNotIn("device_type_auto", record)

    def test_baseline_unchanged_when_no_resolved_metadata(self):
        # A device constructed by hand (e.g. an imported CSV row) without
        # metadata['resolved_device_type'] must keep the existing default
        # ("unknown") behavior. This preserves backwards compatibility for
        # callers that don't run the resolver.
        with tempfile.TemporaryDirectory() as tmp:
            store = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(ip="192.168.1.88", mac_address="00:11:22:33:44:55")
            store.update([device])
            record = store.get(device)
            self.assertEqual(record["device_type"], "unknown")
            self.assertFalse(record.get("device_type_auto"))


if __name__ == "__main__":
    unittest.main()

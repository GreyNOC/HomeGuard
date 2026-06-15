from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_maptest_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard import network, network_map  # noqa: E402
from greynoc_homeguard.ai_traffic import TrafficSummary  # noqa: E402
from greynoc_homeguard.network import LocalInterface, is_vpn_interface_name  # noqa: E402


SAMPLE_REPORT = {
    "report_id": "r1",
    "created_at": "2026-06-15T00:00:00Z",
    "scan_metadata": {"interfaces": [{"name": "eth0", "ip": "192.168.1.50", "cidr": "192.168.1.0/24"}]},
    "devices": [
        {"ip": "192.168.1.1", "mac_address": "aa:bb:cc:00:00:01", "hostname": "router", "metadata": {"device_type_auto": "router"}},
        {"ip": "192.168.1.50", "mac_address": "aa:bb:cc:00:00:50", "hostname": "mypc", "metadata": {}},
        {"ip": "192.168.1.20", "mac_address": "aa:bb:cc:00:00:20", "hostname": "phone", "metadata": {"device_type_auto": "phone"}},
        {"ip": "192.168.1.77", "mac_address": "aa:bb:cc:00:00:77", "hostname": "watch", "metadata": {"device_type_auto": "wearable"}},
        {"ip": "192.168.1.88", "mac_address": "aa:bb:cc:00:00:88", "hostname": "old", "status": "offline", "metadata": {}},
    ],
    "findings": [{"device_ip": "192.168.1.20", "severity": "high", "title": "exposed"}],
}


def _fake_traffic(**_kwargs) -> TrafficSummary:
    return TrafficSummary(
        captured_at=0.0,
        source="test",
        total_connections=5,
        listening_ports=[443],
        established_remote_top=[
            {"endpoint": "8.8.8.8", "port": 443, "count": 3, "scope": "external"},
            {"endpoint": "140.82.112.3", "port": 443, "count": 2, "scope": "external"},
            {"endpoint": "192.168.1.1", "port": 53, "count": 9, "scope": "lan"},
        ],
        process_top=[],
    )


class VpnInterfaceTest(unittest.TestCase):
    def test_is_vpn_interface_name(self) -> None:
        self.assertTrue(is_vpn_interface_name("wg0"))
        self.assertTrue(is_vpn_interface_name("tun0"))
        self.assertTrue(is_vpn_interface_name("NordVPN Tap Adapter"))
        self.assertTrue(is_vpn_interface_name("tailscale0"))
        self.assertFalse(is_vpn_interface_name("Ethernet"))
        self.assertFalse(is_vpn_interface_name("Wi-Fi"))
        self.assertFalse(is_vpn_interface_name("eth0"))

    def test_detect_local_interfaces_drops_vpn(self) -> None:
        mixed = [
            LocalInterface("Ethernet", "192.168.1.50", "192.168.1.0/24"),
            LocalInterface("wg0", "10.8.0.2", "10.8.0.0/24"),
        ]
        with mock.patch.object(network.platform, "system", return_value="Linux"), \
             mock.patch.object(network, "_detect_unix_interfaces", return_value=mixed):
            result = network.detect_local_interfaces()
        names = {iface.name for iface in result}
        self.assertIn("Ethernet", names)
        self.assertNotIn("wg0", names)

    def test_detect_local_interfaces_keeps_vpn_if_only_option(self) -> None:
        only_vpn = [LocalInterface("wg0", "10.8.0.2", "10.8.0.0/24")]
        with mock.patch.object(network.platform, "system", return_value="Linux"), \
             mock.patch.object(network, "_detect_unix_interfaces", return_value=only_vpn):
            result = network.detect_local_interfaces()
        # Graceful fallback: never return an empty interface list.
        self.assertEqual([iface.name for iface in result], ["wg0"])


class BuildNetworkMapTest(unittest.TestCase):
    def _build(self):
        with mock.patch.object(network_map, "_local_host_ips", return_value={"192.168.1.50"}), \
             mock.patch.object(network_map, "_load_baseline_records", return_value={}), \
             mock.patch.object(network_map.ai_traffic, "collect_traffic_summary", _fake_traffic):
            return network_map.build_network_map(report=SAMPLE_REPORT, resolve_dns=False)

    def test_cidr_and_gateway(self) -> None:
        result = self._build()
        self.assertEqual(result["cidr"], "192.168.1.0/24")
        self.assertEqual(result["gateway_ip"], "192.168.1.1")

    def test_local_and_router_classification(self) -> None:
        result = self._build()
        by_ip = {n["ip"]: n for n in result["active_devices"]}
        self.assertTrue(by_ip["192.168.1.50"]["is_local"])
        self.assertEqual(by_ip["192.168.1.1"]["map_role"], "router")
        self.assertEqual(by_ip["192.168.1.1"]["type"], "router")

    def test_peripheral_and_inactive_bundled(self) -> None:
        result = self._build()
        peripheral_ips = {n["ip"] for n in result["peripheral_devices"]}
        inactive_ips = {n["ip"] for n in result["inactive_devices"]}
        active_ips = {n["ip"] for n in result["active_devices"]}
        self.assertIn("192.168.1.77", peripheral_ips)
        self.assertIn("192.168.1.88", inactive_ips)
        self.assertNotIn("192.168.1.77", active_ips)
        self.assertNotIn("192.168.1.88", active_ips)

    def test_cloud_nodes_external_only(self) -> None:
        result = self._build()
        cloud_ips = {n["ip"] for n in result["cloud_nodes"]}
        self.assertIn("8.8.8.8", cloud_ips)
        self.assertIn("140.82.112.3", cloud_ips)
        self.assertNotIn("192.168.1.1", cloud_ips)  # LAN endpoint is not a cloud node
        for node in result["cloud_nodes"]:
            self.assertEqual(node["tier"], "cloud")

    def test_links_built(self) -> None:
        result = self._build()
        kinds = {link["kind"] for link in result["links"]}
        self.assertIn("cloud", kinds)
        self.assertIn("network", kinds)
        self.assertIn("gateway", kinds)
        # Every link endpoint resolves to a known node id.
        node_ids = {n["id"] for n in result["devices"]} | {n["id"] for n in result["cloud_nodes"]}
        for link in result["links"]:
            self.assertIn(link["source"], node_ids)
            self.assertIn(link["target"], node_ids)

    def test_finding_drives_risk(self) -> None:
        result = self._build()
        phone = next(n for n in result["active_devices"] if n["ip"] == "192.168.1.20")
        self.assertEqual(phone["severity"], "high")
        self.assertGreater(phone["risk"], 0)

    def test_stats(self) -> None:
        result = self._build()
        stats = result["stats"]
        self.assertEqual(stats["cloud_node_count"], 2)
        self.assertEqual(stats["peripheral_count"], 1)
        self.assertEqual(stats["inactive_count"], 1)


class EmptyReportTest(unittest.TestCase):
    def test_no_report_still_returns_host(self) -> None:
        with mock.patch.object(network_map, "_local_host_ips", return_value={"192.168.1.50"}), \
             mock.patch.object(network_map, "_load_baseline_records", return_value={}), \
             mock.patch.object(network_map.ai_traffic, "collect_traffic_summary", _fake_traffic):
            result = network_map.build_network_map(report={}, resolve_dns=False)
        self.assertTrue(any(n.get("is_local") for n in result["devices"]))
        self.assertEqual(len(result["cloud_nodes"]), 2)


if __name__ == "__main__":
    unittest.main()

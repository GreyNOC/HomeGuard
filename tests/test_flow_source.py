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

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_flowtest_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard import flow_source  # noqa: E402
from greynoc_homeguard.flow_source import (  # noqa: E402
    FlowRecord,
    OpenWrtConntrackSource,
    classify_edges,
    parse_nf_conntrack,
)

# Two outbound flows (LAN -> public) plus one LAN -> LAN that must be dropped.
CONNTRACK = """ipv4 2 tcp 6 431999 ESTABLISHED src=192.168.1.50 dst=142.250.72.110 sport=51000 dport=443 src=142.250.72.110 dst=203.0.113.7 sport=443 dport=51000 [ASSURED] mark=0 use=1
ipv4 2 udp 17 29 src=192.168.1.20 dst=8.8.8.8 sport=5353 dport=53 src=8.8.8.8 dst=203.0.113.7 sport=53 dport=5353 mark=0 use=1
ipv4 2 tcp 6 300 ESTABLISHED src=192.168.1.50 dst=192.168.1.1 sport=40000 dport=53 mark=0 use=1
ipv4 2 tcp 6 120 TIME_WAIT src=10.0.0.5 dst=224.0.0.251 sport=5353 dport=5353 mark=0 use=1"""


class ParseTest(unittest.TestCase):
    def test_parse_extracts_original_tuple(self) -> None:
        recs = parse_nf_conntrack(CONNTRACK, now="2026-06-15T00:00:00Z")
        self.assertEqual(len(recs), 4)
        first = recs[0]
        self.assertEqual(first.src_lan_ip, "192.168.1.50")
        self.assertEqual(first.dst_ip, "142.250.72.110")
        self.assertEqual(first.dst_port, 443)
        self.assertEqual(first.proto, "tcp")
        self.assertEqual(first.last_seen, "2026-06-15T00:00:00Z")

    def test_parse_skips_lines_without_tuple(self) -> None:
        self.assertEqual(parse_nf_conntrack("garbage line\n\n"), [])

    def test_parse_respects_max_lines(self) -> None:
        self.assertEqual(len(parse_nf_conntrack(CONNTRACK, max_lines=1)), 1)


class ClassifyTest(unittest.TestCase):
    def test_keeps_private_to_public_only(self) -> None:
        edges = classify_edges(parse_nf_conntrack(CONNTRACK))
        pairs = {(e.src_lan_ip, e.dst_ip) for e in edges}
        self.assertIn(("192.168.1.50", "142.250.72.110"), pairs)
        self.assertIn(("192.168.1.20", "8.8.8.8"), pairs)
        # LAN->LAN and LAN->multicast dropped.
        self.assertNotIn(("192.168.1.50", "192.168.1.1"), pairs)
        self.assertNotIn(("10.0.0.5", "224.0.0.251"), pairs)

    def test_dedup_and_exclude(self) -> None:
        recs = [
            FlowRecord("192.168.1.50", "8.8.8.8", 443, "tcp"),
            FlowRecord("192.168.1.50", "8.8.8.8", 443, "tcp"),  # dup
            FlowRecord("192.168.1.99", "1.1.1.1", 53, "udp"),
        ]
        edges = classify_edges(recs, exclude_ips={"192.168.1.99"})
        pairs = {(e.src_lan_ip, e.dst_ip, e.dst_port) for e in edges}
        self.assertEqual(pairs, {("192.168.1.50", "8.8.8.8", 443)})

    def test_drops_public_source(self) -> None:
        # A public src (e.g. inbound) is not a device->cloud edge.
        edges = classify_edges([FlowRecord("8.8.4.4", "8.8.8.8", 443, "tcp")])
        self.assertEqual(edges, [])

    def test_drops_multicast_destination(self) -> None:
        edges = classify_edges([FlowRecord("192.168.1.10", "239.255.255.250", 1900, "udp")])
        self.assertEqual(edges, [])


class OpenWrtSourceTest(unittest.TestCase):
    def test_ssh_args(self) -> None:
        src = OpenWrtConntrackSource(host="192.168.1.1", user="root", port=2222, key_path="/k/id_ed25519")
        args = src._ssh_args()
        self.assertEqual(args[0], "ssh")
        self.assertIn("BatchMode=yes", args)
        self.assertIn("-i", args)
        self.assertIn("/k/id_ed25519", args)
        self.assertIn("root@192.168.1.1", args)
        self.assertEqual(args[-1], "cat /proc/net/nf_conntrack")

    def test_collect_parses_fetched_text(self) -> None:
        src = OpenWrtConntrackSource(host="192.168.1.1")
        # The source is a slots dataclass, so patch fetch on the class.
        with mock.patch.object(OpenWrtConntrackSource, "fetch", return_value=CONNTRACK):
            edges = src.collect()
        self.assertEqual(len(edges), 2)

    def test_fetch_requires_host(self) -> None:
        with self.assertRaises(flow_source.FlowSourceError):
            OpenWrtConntrackSource(host="").fetch()

    def test_fetch_rejects_option_like_host_or_user(self) -> None:
        with self.assertRaises(flow_source.FlowSourceError):
            OpenWrtConntrackSource(host="-oProxyCommand=evil").fetch()
        with self.assertRaises(flow_source.FlowSourceError):
            OpenWrtConntrackSource(host="192.168.1.1 -oFoo").fetch()
        with self.assertRaises(flow_source.FlowSourceError):
            OpenWrtConntrackSource(host="192.168.1.1", user="-oProxyCommand=x").fetch()


class CollectAndTestConnectionTest(unittest.TestCase):
    def test_collect_disabled_returns_empty(self) -> None:
        self.assertEqual(flow_source.collect_flow_edges({"enabled": False}), [])

    def test_collect_enabled_uses_source(self) -> None:
        cfg = {"enabled": True, "provider": "openwrt", "host": "192.168.1.1"}
        with mock.patch.object(OpenWrtConntrackSource, "fetch", return_value=CONNTRACK):
            edges = flow_source.collect_flow_edges(cfg)
        self.assertEqual(len(edges), 2)
        self.assertEqual({e["src_lan_ip"] for e in edges}, {"192.168.1.50", "192.168.1.20"})

    def test_collect_swallows_errors(self) -> None:
        cfg = {"enabled": True, "host": "10.0.0.1"}
        with mock.patch.object(OpenWrtConntrackSource, "fetch", side_effect=flow_source.FlowSourceError("nope")):
            self.assertEqual(flow_source.collect_flow_edges(cfg), [])

    def test_test_connection_surfaces_error(self) -> None:
        cfg = {"enabled": True, "host": "10.0.0.1"}
        with mock.patch.object(OpenWrtConntrackSource, "fetch", side_effect=flow_source.FlowSourceError("auth failed")):
            result = flow_source.test_connection(cfg)
        self.assertFalse(result["ok"])
        self.assertIn("auth failed", result["error"])

    def test_unsupported_provider(self) -> None:
        result = flow_source.test_connection({"provider": "cisco", "host": "x"})
        self.assertFalse(result["ok"])

    def test_key_env_resolution(self) -> None:
        with mock.patch.dict(os.environ, {"MY_KEY": "/secret/key"}):
            src = flow_source._source_from_config({"provider": "openwrt", "host": "h", "key_env": "MY_KEY"})
        self.assertEqual(src.key_path, "/secret/key")


class SettingsTest(unittest.TestCase):
    def test_flow_source_round_trip(self) -> None:
        from greynoc_homeguard.settings import AppSettings

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            s = AppSettings(path=path).load()
            self.assertFalse(s.flow_source_config()["enabled"])
            s.set_flow_source(enabled=True, host="192.168.1.1", user="admin", port=2222)
            reloaded = AppSettings(path=path).load().flow_source_config()
            self.assertTrue(reloaded["enabled"])
            self.assertEqual(reloaded["host"], "192.168.1.1")
            self.assertEqual(reloaded["user"], "admin")
            self.assertEqual(reloaded["port"], 2222)


if __name__ == "__main__":
    unittest.main()

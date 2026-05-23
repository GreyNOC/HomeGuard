import json
import io
import ipaddress
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

# Force a per-test temporary HOMEGUARD_DATA_DIR before importing modules that
# read paths at import time.
_TMP_ROOT = tempfile.mkdtemp(prefix="hg_test_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)


from greynoc_homeguard import cli  # noqa: E402
from greynoc_homeguard.baseline import (  # noqa: E402
    BaselineStore,
    TRUST_QUARANTINED,
    TRUST_TRUSTED,
)
from greynoc_homeguard.definitions import (  # noqa: E402
    DefinitionManager,
    UPDATE_STATUS_CURRENT,
    UPDATE_STATUS_FAILED,
    UPDATE_STATUS_NEVER,
)
from greynoc_homeguard.engine import HomeGuardEngine, build_family_summary  # noqa: E402
from greynoc_homeguard.firewall import (  # noqa: E402
    close_local_port,
    finding_is_local,
    port_from_finding,
    reopen_local_port,
    rule_name,
)
from greynoc_homeguard.history import ProtectionHistory  # noqa: E402
from greynoc_homeguard.logging_setup import setup_logging  # noqa: E402
from greynoc_homeguard.models import Device  # noqa: E402
from greynoc_homeguard.network import (  # noqa: E402
    NetworkSensorConfig,
    _active_targets,
    parse_arp_table,
    parse_neighbor_table,
    parse_netsh_neighbor_table,
)
from greynoc_homeguard.paths import ensure_app_dirs, user_data_dir  # noqa: E402
from greynoc_homeguard.privacy import privacy_findings, scrub_text  # noqa: E402
from greynoc_homeguard.protection import (  # noqa: E402
    DEVICE_NEW,
    DEVICE_RISKY,
    DEVICE_TRUSTED,
    NETWORK_ACTION,
    UPDATES_NEVER,
    compute_protection_status,
)
from greynoc_homeguard.reports import export_report  # noqa: E402
from greynoc_homeguard.scan_runner import run_full_scan  # noqa: E402
from greynoc_homeguard.scheduler import ScheduleManager  # noqa: E402
from greynoc_homeguard.settings import AppSettings  # noqa: E402
from greynoc_homeguard.tray import TrayController  # noqa: E402
from greynoc_homeguard.virus_scanner import (  # noqa: E402
    _run_json_powershell,
    analyze_processes,
    run_endpoint_malware_scan,
    scan_downloads,
    scan_process_memory,
)


class _AppDataMixin:
    def _isolate(self) -> Path:
        tmp = tempfile.mkdtemp(prefix="hg_case_")
        os.environ["HOMEGUARD_DATA_DIR"] = tmp
        # Re-create app dirs under the new root
        ensure_app_dirs()
        return Path(tmp)


class NetworkParserTests(unittest.TestCase):
    def test_parse_windows_arp_table(self):
        text = """
Interface: 192.168.1.10 --- 0x13
  Internet Address      Physical Address      Type
  192.168.1.1           c8-3a-35-aa-bb-cc     dynamic
  192.168.1.40          b8-78-2e-44-55-66     dynamic
"""
        hosts = parse_arp_table(text)
        self.assertEqual(len(hosts), 2)
        self.assertEqual(hosts[0].ip, "192.168.1.1")
        self.assertEqual(hosts[0].mac_address, "c8:3a:35:aa:bb:cc")

    def test_parse_linux_neighbor_table(self):
        text = "192.168.1.40 dev wlan0 lladdr b8:78:2e:44:55:66 REACHABLE"
        hosts = parse_neighbor_table(text)
        self.assertEqual(len(hosts), 1)
        self.assertEqual(hosts[0].interface, "wlan0")
        self.assertEqual(hosts[0].status, "reachable")

    def test_parse_windows_netsh_neighbor_table(self):
        text = """
Interface 12: Wi-Fi
Internet Address                              Physical Address   Type
--------------------------------------------  -----------------  -----------
192.168.1.1                                   c8-3a-35-aa-bb-cc  Reachable
224.0.0.22                                    01-00-5e-00-00-16  Permanent
192.168.1.40                                  b8-78-2e-44-55-66  Stale
"""
        hosts = parse_netsh_neighbor_table(text)
        self.assertEqual([host.ip for host in hosts], ["192.168.1.1", "192.168.1.40"])
        self.assertEqual(hosts[0].interface, "Wi-Fi")
        self.assertEqual(hosts[0].source, "netsh_neighbor_table")
        self.assertEqual(hosts[1].status, "stale")

    def test_active_targets_prioritize_passive_then_sample_subnet(self):
        network = ipaddress.ip_network("192.168.50.0/24")
        config = NetworkSensorConfig(max_hosts_per_scan=6)
        passive = [Device(ip="192.168.50.200"), Device(ip="192.168.50.10")]
        targets = _active_targets([network], [str(network)], config, passive_hosts=passive)
        self.assertEqual(targets[:2], ["192.168.50.200", "192.168.50.10"])
        self.assertIn("192.168.50.254", targets)
        self.assertNotIn("192.168.50.2", targets)


class NocCoreDiscoveryTests(unittest.TestCase):
    """Covers the vendored saturn discovery engine surface added in v1.1."""

    def test_passive_discover_local_network_uses_safe_defaults(self):
        from greynoc_homeguard.network import (
            DiscoveryOptions,
            discover_local_network,
            discovery_device_to_device,
            recompute_confidence,
        )

        # No active probes by default; engine bails fast on private CIDR
        # without external IO so the test stays hermetic.
        result = discover_local_network("192.168.99.0/24", max_hosts=8)
        self.assertIsNotNone(result)
        self.assertTrue(hasattr(result, "devices"))
        # Inspecting DiscoveryOptions defaults via re-export is the contract
        # the chat assistant and future map UI will rely on.
        opts = DiscoveryOptions()
        self.assertTrue(opts.enable_arp_probe)  # saturn upstream default
        self.assertFalse(opts.allow_public)
        self.assertFalse(opts.allow_large_subnet)

        # Adapter converts a noc_core-shaped dict into a HomeGuard Device.
        device = discovery_device_to_device(
            {
                "ip": "192.168.1.50",
                "mac_address": "B8:78:2E:11:22:33",
                "hostname": "wyze-cam",
                "open_ports": [80, 554],
                "metadata": {"discovery_methods": ["arp", "mdns"]},
            }
        )
        self.assertEqual(device.ip, "192.168.1.50")
        self.assertEqual(device.mac_address, "b8:78:2e:11:22:33")
        self.assertEqual(device.vendor, "Wyze")
        self.assertEqual(sorted(device.open_ports), [80, 554])

        # confidence_score reads the merged-device evidence shape.
        score = recompute_confidence(
            {
                "mac_address": "b8:78:2e:11:22:33",
                "discovery_methods": ["arp", "mdns", "tcp"],
            }
        )
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 0.99)

    def test_discover_lan_hosts_noc_core_passive_returns_devices(self):
        from greynoc_homeguard.network import LocalInterface, discover_lan_hosts_noc_core

        # Passive run over a fake private /24 exercises the interface loop,
        # the noc_core engine, and the DiscoveryDevice -> Device conversion
        # without emitting any active probes.
        devices = discover_lan_hosts_noc_core(
            [LocalInterface("test", "192.168.123.1", "192.168.123.0/24")],
            active=False,
            probe_all=False,
            tcp_ports=[80, 443],
        )
        self.assertIsInstance(devices, list)
        for device in devices:
            self.assertIsInstance(device, Device)

    def test_discover_lan_hosts_noc_core_narrows_oversized_subnet(self):
        from greynoc_homeguard.network import _narrow_oversized_network

        # A /16 interface exceeds the discovery size cap; it must be bounded to
        # a /24 around the host instead of skipped, or every LAN host vanishes.
        narrowed = _narrow_oversized_network(ipaddress.ip_network("10.0.0.0/16"), "10.0.7.42")
        self.assertEqual(str(narrowed), "10.0.7.0/24")
        unchanged = _narrow_oversized_network(ipaddress.ip_network("192.168.1.0/24"), "192.168.1.5")
        self.assertEqual(str(unchanged), "192.168.1.0/24")


class DetectionEngineTests(unittest.TestCase):
    def test_engine_flags_telnet(self):
        device = Device(ip="192.168.1.40", hostname="camera", open_ports=[23])
        report = HomeGuardEngine().build_report([device])
        rule_ids = {finding.rule_id for finding in report.findings}
        self.assertIn("risky_port_23", rule_ids)
        telnet = next(f for f in report.findings if f.rule_id == "risky_port_23")
        self.assertEqual(telnet.severity, "high")

    def test_baseline_new_device(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(ip="192.168.1.88", mac_address="00:11:22:33:44:55")
            report = HomeGuardEngine().build_report([device], baseline=baseline)
            self.assertIn("new_device", {f.rule_id for f in report.findings})
            baseline.update([device])
            baseline.save()
            baseline2 = BaselineStore(Path(tmp) / "baseline.json").load()
            report2 = HomeGuardEngine().build_report([device], baseline=baseline2)
            self.assertNotIn("new_device", {f.rule_id for f in report2.findings})

    def test_quarantined_device_is_flagged(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(ip="192.168.1.50", mac_address="aa:bb:cc:dd:ee:ff", hostname="iot")
            baseline.update([device])
            baseline.set_trust(device.fingerprint(), TRUST_QUARANTINED)
            report = HomeGuardEngine().build_report([device], baseline=baseline)
            rule_ids = {f.rule_id for f in report.findings}
            self.assertIn("quarantined_device", rule_ids)
            high_or_critical = [f for f in report.findings if f.severity in {"high", "critical"}]
            self.assertTrue(high_or_critical)

    def test_unknown_remote_access_device_is_possible_intrusion(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(
                ip="192.168.1.200",
                mac_address="00:de:ad:be:ef:00",
                hostname="unknown-laptop",
                open_ports=[3389],
            )
            report = HomeGuardEngine().build_report([device], baseline=baseline)
            finding = next(
                f for f in report.findings if f.rule_id == "possible_unauthorized_access"
            )
            self.assertEqual(finding.category, "possible_intrusion")
            self.assertIn(finding.severity, {"high", "critical"})

    def test_remote_admin_cluster_is_flagged(self):
        device = Device(ip="192.168.1.90", hostname="workstation", open_ports=[22, 80, 445, 3389])
        report = HomeGuardEngine().build_report([device])
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("remote_admin_cluster", rule_ids)

    def test_smb_does_not_trigger_windows_remote_access_hint(self):
        device = Device(ip="192.168.1.91", hostname="pc", open_ports=[445])
        report = HomeGuardEngine().build_report([device])
        rule_ids = {f.rule_id for f in report.findings}
        self.assertNotIn("definition_hint_windows_remote_access", rule_ids)
        self.assertNotIn("possible_unauthorized_access", rule_ids)

    def test_rdp_triggers_windows_remote_access_hint(self):
        device = Device(ip="192.168.1.92", hostname="pc", open_ports=[3389])
        report = HomeGuardEngine().build_report([device])
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("definition_hint_windows_remote_access", rule_ids)

    def test_unusual_service_port_is_review_indicator(self):
        device = Device(ip="192.168.1.93", hostname="unknown", open_ports=[4444])
        report = HomeGuardEngine().build_report([device])
        finding = next(f for f in report.findings if f.rule_id == "possible_malware_service")
        self.assertEqual(finding.category, "unusual_service")
        self.assertEqual(finding.severity, "high")
        self.assertEqual(finding.evidence["unusual_ports"], [4444])
        self.assertIn("Port-only indicator", finding.evidence["evidence_note"])
        self.assertNotIn("malware", finding.title.lower())

    def test_mirai_telnet_alternate_is_possible_malware(self):
        # Port 2323 is the Mirai-style Telnet alternate. Without this rule
        # botnet-recruitable IoT exposure passes silently; with it the
        # cluster + per-port detectors both fire.
        device = Device(ip="192.168.1.94", hostname="iot", open_ports=[2323])
        report = HomeGuardEngine().build_report([device])
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("possible_malware_service", rule_ids)
        self.assertIn("risky_port_2323", rule_ids)

    def test_tr069_router_management_port_is_high(self):
        # Port 7547 (TR-069/CWMP) is the router-management vector that
        # recruited millions of home routers into the Mirai/TheMoon botnets.
        device = Device(ip="192.168.1.95", hostname="router", open_ports=[7547])
        report = HomeGuardEngine().build_report([device])
        finding = next(f for f in report.findings if f.rule_id == "risky_port_7547")
        self.assertEqual(finding.severity, "high")

    def test_raw_printer_port_is_flagged(self):
        device = Device(ip="192.168.1.96", hostname="printer", open_ports=[9100])
        report = HomeGuardEngine().build_report([device])
        rule_ids = {f.rule_id for f in report.findings}
        self.assertIn("risky_port_9100", rule_ids)

    def test_active_scan_port_set_covers_every_risky_definition(self):
        # The active TCP probe set must include every port the detection
        # engine has a rule for. If this drifts, exposed services stop
        # surfacing in reports.
        from greynoc_homeguard.definitions import (
            DEFAULT_RISKY_PORTS,
            active_scan_ports,
        )

        ports = set(active_scan_ports({"risky_ports": DEFAULT_RISKY_PORTS}))
        for row in DEFAULT_RISKY_PORTS:
            self.assertIn(row["port"], ports)
        # Discovery defaults are still included so unfamiliar devices show up.
        self.assertTrue({53, 80, 443} <= ports)

    def test_hostname_only_baseline_detects_spoofer_on_different_ip(self):
        # Baseline a device that has a hostname but no MAC. Then a second
        # device joins the network claiming the same hostname from a
        # different IP. Without the hostname-collision detector, the
        # spoofer would inherit trust silently because Device.fingerprint()
        # falls back to host:<name> when MAC is missing.
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "baseline.json").load()
            original = Device(ip="192.168.1.50", hostname="alice-laptop")
            baseline.update([original])
            baseline.save()

            spoofer = Device(ip="192.168.1.99", hostname="alice-laptop")
            baseline2 = BaselineStore(Path(tmp) / "baseline.json").load()
            self.assertTrue(baseline2.known(spoofer))  # naive lookup matches
            self.assertFalse(baseline2.identity_matches(spoofer))

            findings = HomeGuardEngine().detection_engine.evaluate(
                [spoofer], baseline2
            )
            collision = next(f for f in findings if f.rule_id == "hostname_collision")
            self.assertEqual(collision.category, "possible_intrusion")
            self.assertIn(collision.severity, {"high", "critical"})
            self.assertEqual(collision.evidence["stored_ip"], "192.168.1.50")
            self.assertEqual(collision.evidence["current_ip"], "192.168.1.99")

    def test_hostname_collision_silent_when_ip_matches(self):
        # The same hostname-only device coming back at the same IP is not
        # a collision; the detector must not produce false positives for
        # ordinary repeat scans of imported / MAC-less devices.
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(ip="192.168.1.50", hostname="alice-laptop")
            baseline.update([device])
            baseline.save()
            again = BaselineStore(Path(tmp) / "baseline.json").load()
            findings = HomeGuardEngine().detection_engine.evaluate([device], again)
            self.assertNotIn(
                "hostname_collision", {f.rule_id for f in findings}
            )

    def test_mac_based_baseline_is_not_flagged_as_collision_on_ip_change(self):
        # MAC is the identity for MAC-based fingerprints; legitimate DHCP
        # rotation must never trigger the collision detector.
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "baseline.json").load()
            device = Device(
                ip="192.168.1.50",
                mac_address="00:11:22:33:44:55",
                hostname="alice-laptop",
            )
            baseline.update([device])
            baseline.save()
            rotated = Device(
                ip="192.168.1.222",
                mac_address="00:11:22:33:44:55",
                hostname="alice-laptop",
            )
            again = BaselineStore(Path(tmp) / "baseline.json").load()
            self.assertTrue(again.identity_matches(rotated))
            findings = HomeGuardEngine().detection_engine.evaluate([rotated], again)
            self.assertNotIn(
                "hostname_collision", {f.rule_id for f in findings}
            )

    def test_outdated_starter_definitions_are_migrated_on_load(self):
        # Older HomeGuard installs persisted an early `risky_ports` list
        # and never received new rules from `update-definitions` (which
        # only refreshes KEV/CVE feeds). The load() migration path must
        # bring stale bundles up to the current STARTER_VERSION.
        from greynoc_homeguard.definitions import (
            DefinitionManager,
            STARTER_VERSION,
        )

        with tempfile.TemporaryDirectory() as tmp:
            stale = Path(tmp) / "security_definitions.json"
            stale.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "definitions_version": "stale",
                        "feed_versions": {"starter": "2025.01.01.0"},
                        "risky_ports": [
                            {"port": 23, "service": "Telnet", "severity": "high"}
                        ],
                        "device_name_hints": ["router"],
                        "product_hints": [],
                        "kev_catalog": [{"cve_id": "CVE-9999-0001"}],
                        "recent_cves": [],
                    }
                ),
                encoding="utf-8",
            )
            data = DefinitionManager(path=stale).load()
            # New ports landed.
            ports = {row["port"] for row in data["risky_ports"]}
            self.assertIn(2323, ports)
            self.assertIn(7547, ports)
            self.assertIn(9100, ports)
            self.assertEqual(data["feed_versions"]["starter"], STARTER_VERSION)
            # KEV/CVE caches the user already downloaded are preserved.
            self.assertEqual(len(data["kev_catalog"]), 1)


class EndpointMalwareScannerTests(unittest.TestCase):
    def test_powershell_inventory_respects_execution_policy(self):
        fake_result = mock.Mock(returncode=0, stdout="[]")
        with mock.patch("greynoc_homeguard.virus_scanner.subprocess.run", return_value=fake_result) as run:
            _run_json_powershell("Get-CimInstance Win32_Process")

        command = run.call_args.args[0]
        self.assertEqual(command[:2], ["powershell.exe", "-NoProfile"])
        self.assertNotIn("-ExecutionPolicy", command)
        self.assertNotIn("Bypass", command)

    def test_process_scanner_flags_encoded_download_cradle(self):
        findings, meta = analyze_processes(
            [
                {
                    "pid": 1234,
                    "name": "powershell.exe",
                    "command_line": "powershell.exe -EncodedCommand AAAA Invoke-Expression DownloadString",
                }
            ]
        )
        self.assertEqual(meta["processes_reviewed"], 1)
        self.assertTrue(any(f.category == "endpoint_process" for f in findings))
        self.assertTrue(any(f.severity == "high" for f in findings))

    def test_memory_scanner_skips_homeguards_own_process(self):
        # HomeGuard's own process holds every MEMORY_SIGNATURES marker as plain
        # module data, so scanning it must never report the scanner as malware.
        own_pid = os.getpid()
        rows = [
            {"pid": own_pid, "name": "greynoc-homeguard"},
            {"pid": 999_001, "name": "other.exe"},
        ]

        def fake_read(_pid, **_kwargs):
            return [b"invoke-mimikatz"]

        with mock.patch(
            "greynoc_homeguard.virus_scanner._read_process_memory", side_effect=fake_read
        ):
            findings, meta = scan_process_memory(rows)

        self.assertTrue(meta["memory_self_process_excluded"])
        self.assertEqual(meta["memory_processes_reviewed"], 1)
        flagged_pids = {finding.evidence.get("pid") for finding in findings}
        self.assertNotIn(own_pid, flagged_pids)
        self.assertIn(999_001, flagged_pids)

    def test_memory_scanner_tolerates_malformed_pid(self):
        # A malformed PID anywhere in the input must not abort the memory scan.
        rows = [
            {"pid": "not-a-pid", "name": "weird.exe"},
            {"pid": 999_002, "name": "ok.exe"},
        ]
        with mock.patch(
            "greynoc_homeguard.virus_scanner._read_process_memory", return_value=[]
        ):
            findings, meta = scan_process_memory(rows)
        self.assertEqual(findings, [])
        self.assertEqual(meta["memory_processes_reviewed"], 1)

    def test_download_scanner_flags_recent_script_payloads(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "invoice.js"
            payload.write_text("WScript.Echo('test')", encoding="utf-8")
            findings, meta = scan_downloads([Path(tmp)])
        self.assertEqual(meta["download_files_reviewed"], 1)
        self.assertEqual(findings[0].rule_id, "endpoint_browser_download_executable")
        self.assertIn("sha256_first_128mb", findings[0].evidence)
        self.assertTrue(meta["internal_file_scan"])

    def test_internal_file_scanner_flags_content_signature(self):
        with tempfile.TemporaryDirectory() as tmp:
            payload = Path(tmp) / "payload.txt"
            payload.write_text("HOMEGUARD-INTERNAL-SCANNER-TEST-SIGNATURE", encoding="utf-8")
            findings, meta = scan_downloads([Path(tmp)])
        rule_ids = {finding.rule_id for finding in findings}
        self.assertIn("endpoint_internal_file_signature", rule_ids)
        self.assertGreaterEqual(meta["internal_file_scan_content_hits"], 1)

    def test_download_scanner_excludes_homeguards_own_files(self):
        # HomeGuard's own modules contain every detection signature as literal
        # text; pointing the scanner at its own package must flag nothing.
        import greynoc_homeguard

        package_dir = Path(greynoc_homeguard.__file__).resolve().parent
        findings, meta = scan_downloads([package_dir])
        self.assertEqual(findings, [])
        self.assertEqual(meta["download_files_reviewed"], 0)
        self.assertGreater(meta["internal_files_self_excluded"], 0)

    def test_download_scanner_still_scans_when_frozen_exe_shares_the_dir(self):
        # A frozen HomeGuard.exe living directly in a scanned folder must only
        # exclude the exe itself, never the whole folder, or the scan silently
        # reviews zero files and misses real malware.
        from greynoc_homeguard import virus_scanner

        with tempfile.TemporaryDirectory() as tmp:
            tmp_dir = Path(tmp)
            exe = tmp_dir / "HomeGuard.exe"
            exe.write_bytes(b"MZ fake homeguard binary")
            payload = tmp_dir / "invoice.js"
            payload.write_text("WScript.Echo('test')", encoding="utf-8")
            with (
                mock.patch.object(virus_scanner.sys, "frozen", True, create=True),
                mock.patch.object(virus_scanner.sys, "executable", str(exe)),
            ):
                findings, meta = scan_downloads([tmp_dir])
        self.assertEqual(meta["internal_files_self_excluded"], 1)
        self.assertGreaterEqual(meta["download_files_reviewed"], 1)
        self.assertIn(
            "endpoint_browser_download_executable",
            {finding.rule_id for finding in findings},
        )

    def test_endpoint_scan_does_not_launch_external_antivirus(self):
        with mock.patch("greynoc_homeguard.virus_scanner.scan_persistence", return_value=([], {"persistence_entries_reviewed": 0})):
            result = run_endpoint_malware_scan(
                include_defender=True,
                include_file_scan=False,
                include_memory=False,
                include_privesc_audit=False,
                download_dirs=[],
                process_rows=[],
            )
        self.assertEqual(result.metadata["external_antivirus"], "not_used")
        self.assertEqual(result.metadata["external_antivirus_requested"], "ignored_internal_scanner_only")

    def test_endpoint_scan_can_attach_findings_without_defender_or_memory(self):
        with mock.patch("greynoc_homeguard.virus_scanner.scan_persistence", return_value=([], {"persistence_entries_reviewed": 0})):
            result = run_endpoint_malware_scan(
                include_defender=False,
                include_memory=False,
                include_privesc_audit=False,
                download_dirs=[],
                process_rows=[
                    {
                        "pid": 99,
                        "name": "nc.exe",
                        "command_line": "nc.exe -l -p 4444",
                    }
                ],
            )
        self.assertGreaterEqual(len(result.findings), 1)
        self.assertEqual(result.metadata["scanner"], "GreyNOC Endpoint Malware Indicator Scanner")


class TrustStoreTests(unittest.TestCase):
    def test_trust_set_and_remove(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = BaselineStore(Path(tmp) / "k.json").load()
            device = Device(ip="192.168.1.10", mac_address="00:11:22:33:44:55")
            store.update([device])
            self.assertTrue(store.set_trust(device.fingerprint(), TRUST_TRUSTED))
            self.assertEqual(store.trust(device), TRUST_TRUSTED)
            store.set_label(device.fingerprint(), owner="parent", device_type="laptop", notes="kitchen")
            self.assertTrue(store.is_trusted(device))
            self.assertEqual(store.get(device).get("owner"), "parent")
            self.assertTrue(store.remove(device.fingerprint()))
            self.assertFalse(store.known(device))


class FirewallActionTests(unittest.TestCase):
    def test_port_from_finding_prefers_evidence_port(self):
        report = HomeGuardEngine().build_report(
            [Device(ip="192.168.1.10", hostname="camera", open_ports=[23])]
        )
        finding = next(f for f in report.findings if f.rule_id == "risky_port_23")
        self.assertEqual(port_from_finding(finding), 23)

    def test_finding_is_local_uses_known_local_ips(self):
        report = HomeGuardEngine().build_report([Device(ip="192.168.1.10", open_ports=[80])])
        finding = report.findings[0]
        self.assertTrue(finding_is_local(finding, ips={"192.168.1.10"}))
        self.assertFalse(finding_is_local(finding, ips={"192.168.1.20"}))

    def test_windows_close_port_replaces_rule_then_blocks(self):
        calls = []

        def runner(args, **_kwargs):
            calls.append(args)
            return mock.Mock(returncode=0, stdout="Ok.", stderr="")

        with mock.patch("greynoc_homeguard.firewall.platform.system", return_value="Windows"):
            result = close_local_port(3389, runner=runner)
        self.assertTrue(result.ok)
        self.assertEqual(calls[0][:4], ["netsh", "advfirewall", "firewall", "delete"])
        self.assertEqual(calls[1][:4], ["netsh", "advfirewall", "firewall", "add"])
        self.assertIn("action=block", calls[1])
        self.assertIn("localport=3389", calls[1])
        self.assertIn(f"name={rule_name(3389)}", calls[1])

    def test_windows_reopen_port_deletes_homeguard_rule_only(self):
        calls = []

        def runner(args, **_kwargs):
            calls.append(args)
            return mock.Mock(returncode=0, stdout="Deleted.", stderr="")

        with mock.patch("greynoc_homeguard.firewall.platform.system", return_value="Windows"):
            result = reopen_local_port(3389, runner=runner)
        self.assertTrue(result.ok)
        self.assertEqual(len(calls), 1)
        self.assertIn(f"name={rule_name(3389)}", calls[0])


class DefinitionStatusTests(_AppDataMixin, unittest.TestCase):
    def test_default_status_is_never_updated(self):
        self._isolate()
        manager = DefinitionManager()
        status = manager.status()
        self.assertEqual(status["update_status"], UPDATE_STATUS_NEVER)

    def test_update_failure_marks_failed(self):
        self._isolate()
        manager = DefinitionManager()
        with mock.patch(
            "greynoc_homeguard.definitions._http_json",
            side_effect=RuntimeError("network down"),
        ):
            status = manager.update_from_sources(nvd_days=1)
        self.assertEqual(status["update_status"], UPDATE_STATUS_FAILED)

    def test_update_success_marks_current(self):
        self._isolate()
        manager = DefinitionManager()
        with mock.patch(
            "greynoc_homeguard.definitions._http_json",
            side_effect=[
                {"vulnerabilities": [{"cveID": "CVE-2099-0001"}], "catalogVersion": "1.0"},
                {"vulnerabilities": []},
            ],
        ):
            status = manager.update_from_sources(nvd_days=1)
        self.assertEqual(status["update_status"], UPDATE_STATUS_CURRENT)
        self.assertGreaterEqual(status["kev_count"], 1)
        self.assertGreaterEqual(status["record_count"], 1)


class ProtectionStatusTests(unittest.TestCase):
    def test_clean_scan_is_protected_and_never_updated(self):
        protection = compute_protection_status([], [], definition_status={})
        self.assertEqual(protection.updates, UPDATES_NEVER)
        self.assertEqual(protection.device_trust, DEVICE_TRUSTED)

    def test_quarantined_device_triggers_action_needed(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "k.json").load()
            device = Device(ip="192.168.1.66", mac_address="aa:bb:cc:dd:ee:ff")
            baseline.update([device])
            baseline.set_trust(device.fingerprint(), TRUST_QUARANTINED)
            findings = HomeGuardEngine().detection_engine.evaluate([device], baseline)
            protection = compute_protection_status(
                [device], findings, definition_status={}, baseline=baseline
            )
            self.assertEqual(protection.network, NETWORK_ACTION)
            self.assertEqual(protection.quarantined_count, 1)

    def test_new_device_triggers_new_devices_card(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "k.json").load()
            device = Device(ip="192.168.1.77", mac_address="aa:bb:cc:dd:00:11")
            findings = HomeGuardEngine().detection_engine.evaluate([device], baseline)
            protection = compute_protection_status(
                [device], findings, definition_status={}, baseline=baseline
            )
            self.assertIn(protection.device_trust, {DEVICE_NEW, DEVICE_RISKY})


class FamilySummaryTests(unittest.TestCase):
    def test_family_summary_counts_owners_and_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            baseline = BaselineStore(Path(tmp) / "k.json").load()
            d1 = Device(ip="192.168.1.20", mac_address="11:22:33:44:55:66", hostname="phone")
            d2 = Device(ip="192.168.1.21", mac_address="11:22:33:44:55:67", hostname="laptop")
            baseline.update([d1, d2])
            baseline.set_label(d1.fingerprint(), owner="parent", device_type="phone")
            baseline.set_label(d2.fingerprint(), owner="child", device_type="laptop")
            summary = build_family_summary([d1, d2], baseline)
            self.assertEqual(summary["by_owner"].get("parent"), 1)
            self.assertEqual(summary["by_owner"].get("child"), 1)
            self.assertEqual(summary["by_type"].get("phone"), 1)
            self.assertEqual(summary["by_type"].get("laptop"), 1)


class ReportExportTests(unittest.TestCase):
    def test_export_writes_all_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = HomeGuardEngine().build_report([Device(ip="192.168.1.1", open_ports=[80])])
            paths = export_report(report, tmp)
            for key in [
                "json",
                "markdown",
                "html",
                "pdf",
                "devices",
                "findings",
                "findings_csv",
                "manifest",
            ]:
                self.assertTrue(paths[key].exists(), f"missing {key}")
            html = paths["html"].read_text(encoding="utf-8")
            self.assertIn("Network Protection", html)
            self.assertIn("Device Trust", html)
            self.assertIn("Security Updates", html)
            self.assertIn("HomeGuard Detection Engine", html)
            self.assertGreater(paths["pdf"].stat().st_size, 500)

    def test_html_includes_recommended_actions_block(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = HomeGuardEngine().build_report([Device(ip="192.168.1.25", hostname="camera", open_ports=[23])])
            paths = export_report(report, tmp)
            html = paths["html"].read_text(encoding="utf-8")
            self.assertIn("Recommended Actions", html)

    def test_html_uses_dark_greynoc_theme(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = HomeGuardEngine().build_report([Device(ip="192.168.1.1", open_ports=[80])])
            paths = export_report(report, tmp)
            html = paths["html"].read_text(encoding="utf-8")
            self.assertIn("background: #03101D", html)
            self.assertIn("background: #081A2B", html)
            self.assertIn("background:#0B91FF", html)
            self.assertIn("brand-mark", html)
            self.assertIn("GreyNOC", html)

    def test_exported_reports_are_share_safe(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = HomeGuardEngine().build_report(
                [Device(ip="192.168.1.10", hostname="laptop", mac_address="00:11:22:33:44:55")],
                scan_metadata={
                    "baseline_path": r"C:\Users\person\AppData\Local\GreyNOC\HomeGuard\known_devices.json",
                    "diagnostic": "HOME=C:\\Users\\person USERNAME=person token=abcd",
                    "key": "-----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----",
                },
            )
            paths = export_report(report, tmp)
            for key in ("json", "findings", "markdown", "html", "devices", "findings_csv"):
                text = paths[key].read_text(encoding="utf-8", errors="ignore")
                self.assertEqual(privacy_findings(text), [], f"{key} leaked private content")
                self.assertNotIn("00:11:22:33:44:55", text)
            for key in ("json", "markdown", "html", "devices"):
                text = paths[key].read_text(encoding="utf-8", errors="ignore")
                self.assertIn("device id ending 44:55", text)

    def test_exported_reports_do_not_contain_common_mojibake(self):
        markers = ("Ã", "â€”", "â€“", "â€", "�")
        with tempfile.TemporaryDirectory() as tmp:
            report = HomeGuardEngine().build_report([Device(ip="192.168.1.25", hostname="camera", open_ports=[23])])
            paths = export_report(report, tmp)
            for key in ("json", "findings", "markdown", "html", "devices", "findings_csv"):
                text = paths[key].read_text(encoding="utf-8", errors="ignore")
                for marker in markers:
                    self.assertNotIn(marker, text, f"{key} contains mojibake marker {marker!r}")


class PrivacyRedactionTests(unittest.TestCase):
    def test_scrub_text_removes_paths_env_and_secrets(self):
        text = (
            r"C:\Users\person\AppData\Local\GreyNOC HOME=C:\Users\person "
            "USERNAME=person token=abcd -----BEGIN PRIVATE KEY-----abc-----END PRIVATE KEY-----"
        )
        scrubbed = scrub_text(text)
        self.assertEqual(privacy_findings(scrubbed), [])
        self.assertIn("local app data", scrubbed)

    def test_logging_redacts_private_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["HOMEGUARD_DATA_DIR"] = tmp
            import greynoc_homeguard.logging_setup as logging_setup

            logger = logging_setup.logging.getLogger("greynoc_homeguard")
            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                handler.close()
            logging_setup._initialized = False
            log_path = setup_logging()
            logger.info(r"diagnostic path C:\Users\person\AppData\Local token=abcd")
            for handler in logger.handlers:
                handler.flush()
            text = log_path.read_text(encoding="utf-8")
            self.assertEqual(privacy_findings(text), [])
            for handler in list(logger.handlers):
                logger.removeHandler(handler)
                handler.close()
            logging_setup._initialized = False


class ScanWorkflowTests(_AppDataMixin, unittest.TestCase):
    def test_core_scan_workflow_does_not_crash(self):
        self._isolate()
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch("greynoc_homeguard.scan_runner.detect_local_interfaces", return_value=[]):
                with mock.patch(
                    "greynoc_homeguard.scan_runner.discover_lan_hosts_noc_core",
                    return_value=[Device(ip="192.168.1.20", hostname="router", open_ports=[80])],
                ):
                    report, paths, entry = run_full_scan(output_dir=tmp, update_known_devices=False)
            self.assertEqual(report.devices[0].ip, "192.168.1.20")
            self.assertTrue(paths["html"].exists())
            self.assertEqual(entry.report_id, report.report_id)


class HistoryTests(_AppDataMixin, unittest.TestCase):
    def test_history_records_scan(self):
        self._isolate()
        history = ProtectionHistory().load()
        report = HomeGuardEngine().build_report([Device(ip="192.168.1.1", open_ports=[80])])
        with tempfile.TemporaryDirectory() as tmp:
            paths = export_report(report, tmp)
            history.add(report, paths)
            history.save()
        loaded = ProtectionHistory().load()
        self.assertEqual(len(loaded.entries()), 1)
        latest = loaded.latest()
        self.assertIsNotNone(latest)
        self.assertEqual(latest.report_id, report.report_id)


class ScheduleTests(_AppDataMixin, unittest.TestCase):
    def test_schedule_persists(self):
        self._isolate()
        manager = ScheduleManager()
        manager.load()
        manager.set(enabled=True, interval="daily", background_monitor=True)
        again = ScheduleManager()
        cfg = again.load()
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.interval, "daily")
        self.assertTrue(cfg.background_monitor)


class TrayTests(unittest.TestCase):
    def test_tray_controller_reports_missing_optional_dependencies(self):
        controller = TrayController(
            on_show=lambda: None,
            on_scan=lambda: None,
            on_open_report=lambda: None,
            on_update_definitions=lambda: None,
            on_quit=lambda: None,
        )
        with mock.patch("greynoc_homeguard.tray._has_pystray", return_value=False):
            self.assertFalse(controller.start())
        self.assertFalse(controller.available)
        self.assertIn("pystray", controller.error_message)


class SettingsTests(unittest.TestCase):
    def test_onboarding_can_be_completed_or_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            settings = AppSettings(path).load()
            self.assertTrue(settings.onboarding_needed())
            settings.mark_onboarding_skipped()
            self.assertFalse(AppSettings(path).load().onboarding_needed())

            path2 = Path(tmp) / "settings2.json"
            settings2 = AppSettings(path2).load()
            settings2.set_scan_defaults(active_scan=True, probe_all=False)
            settings2.mark_onboarding_complete()
            loaded = AppSettings(path2).load()
            self.assertFalse(loaded.onboarding_needed())
            self.assertTrue(loaded.scan_defaults()["active_scan"])

    def test_ignored_findings_persist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            settings = AppSettings(path).load()
            settings.ignore_finding("hg_test", title="Test finding")
            self.assertIn("hg_test", AppSettings(path).load().ignored_finding_ids())
            settings.unignore_finding("hg_test")
            self.assertNotIn("hg_test", AppSettings(path).load().ignored_finding_ids())


class AtomicWriteTests(unittest.TestCase):
    def test_atomic_write_replaces_existing_file(self):
        from greynoc_homeguard.paths import atomic_write_text

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "data.json"
            atomic_write_text(target, '{"a": 1}')
            self.assertEqual(target.read_text(encoding="utf-8"), '{"a": 1}')
            atomic_write_text(target, '{"a": 2}')
            self.assertEqual(target.read_text(encoding="utf-8"), '{"a": 2}')
            # No leftover .tmp files in the directory.
            leftovers = [
                child for child in target.parent.iterdir() if child.name != target.name
            ]
            self.assertEqual(leftovers, [])

    def test_atomic_write_does_not_truncate_on_failure(self):
        from greynoc_homeguard.paths import atomic_write_text

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "data.json"
            target.write_text('{"existing": true}', encoding="utf-8")
            from unittest.mock import patch

            with patch("os.replace", side_effect=OSError("disk full")):
                with self.assertRaises(OSError):
                    atomic_write_text(target, '{"would corrupt": true}')
            # Original file is intact, no half-written content.
            self.assertEqual(
                target.read_text(encoding="utf-8"), '{"existing": true}'
            )
            # The temp file has been cleaned up.
            leftovers = [
                child for child in target.parent.iterdir() if child.name != target.name
            ]
            self.assertEqual(leftovers, [])


class DashboardHostGuardTests(unittest.TestCase):
    def test_loopback_classification(self):
        from greynoc_homeguard.dashboard import _is_loopback_host

        self.assertTrue(_is_loopback_host("127.0.0.1"))
        self.assertTrue(_is_loopback_host("localhost"))
        self.assertTrue(_is_loopback_host("::1"))
        self.assertFalse(_is_loopback_host("0.0.0.0"))
        self.assertFalse(_is_loopback_host("192.168.1.50"))
        self.assertFalse(_is_loopback_host("example.com"))

    def test_serve_report_refuses_non_loopback_without_allow_lan(self):
        from greynoc_homeguard.dashboard import serve_report

        with tempfile.TemporaryDirectory() as tmp:
            report = HomeGuardEngine().build_report(
                [Device(ip="192.168.1.10", open_ports=[80])]
            )
            paths = export_report(report, tmp)
            with self.assertRaises(ValueError) as ctx:
                serve_report(paths["json"], host="0.0.0.0", port=8765)
            self.assertIn("loopback", str(ctx.exception).lower())


class NvdApiKeyTests(_AppDataMixin, unittest.TestCase):
    def test_api_key_env_is_attached_to_nvd_request(self):
        from greynoc_homeguard.definitions import DefinitionManager

        self._isolate()
        manager = DefinitionManager()
        captured: list[dict[str, str]] = []

        def fake_http_json(url, *, timeout=25.0, attempts=3, extra_headers=None):
            captured.append(dict(extra_headers or {}))
            if "cisa.gov" in url:
                return {"vulnerabilities": [], "catalogVersion": "2026"}
            return {"vulnerabilities": []}

        env = {"HOMEGUARD_NVD_API_KEY": "abcd-1234"}
        with mock.patch(
            "greynoc_homeguard.definitions._http_json", side_effect=fake_http_json
        ), mock.patch.dict(os.environ, env, clear=False):
            manager.update_from_sources(nvd_days=1)

        # Two requests: KEV (no api key needed) and NVD (api key attached).
        nvd_call_headers = captured[1] if len(captured) >= 2 else {}
        self.assertEqual(nvd_call_headers.get("apiKey"), "abcd-1234")


class ScanDiffTests(unittest.TestCase):
    def test_diff_against_no_previous_returns_unavailable(self):
        from greynoc_homeguard.diff import compute_scan_diff

        report = HomeGuardEngine().build_report(
            [Device(ip="192.168.1.10", open_ports=[80])]
        )
        delta = compute_scan_diff(report, None)
        self.assertFalse(delta["available"])

    def test_diff_surfaces_new_devices_new_ports_and_resolved_findings(self):
        from greynoc_homeguard.diff import compute_scan_diff, render_summary

        # Previous scan: just the router on port 80.
        previous_report = HomeGuardEngine().build_report(
            [Device(ip="192.168.1.1", hostname="router", open_ports=[80])]
        ).as_dict()

        # Current scan: router gained Telnet (new port + new high-severity
        # finding), a new device appeared, and the router's HTTP-on-80
        # finding still exists (so should not be 'added').
        current = HomeGuardEngine().build_report(
            [
                Device(ip="192.168.1.1", hostname="router", open_ports=[80, 23]),
                Device(ip="192.168.1.99", hostname="laptop", open_ports=[]),
            ]
        )
        delta = compute_scan_diff(current, previous_report)
        self.assertTrue(delta["available"])

        added_ips = {item["ip"] for item in delta["devices"]["added"]}
        self.assertIn("192.168.1.99", added_ips)
        self.assertEqual(len(delta["devices"]["removed"]), 0)
        new_port_rows = delta["devices"]["with_new_ports"]
        self.assertTrue(
            any(
                row["ip"] == "192.168.1.1" and 23 in row["newly_open"]
                for row in new_port_rows
            )
        )
        added_rule_ids = {item["rule_id"] for item in delta["findings"]["added"]}
        self.assertIn("risky_port_23", added_rule_ids)
        # Re-emitted findings are not flagged as new.
        self.assertNotIn("risky_port_80", added_rule_ids)

        summary = render_summary(delta)
        self.assertIn("new device", summary)
        self.assertIn("newly open port", summary)
        self.assertIn("new finding", summary)

    def test_diff_detects_resolved_findings_and_improved_risk(self):
        from greynoc_homeguard.diff import compute_scan_diff

        # Previous: telnet exposed on a device.
        previous = HomeGuardEngine().build_report(
            [Device(ip="192.168.1.10", hostname="cam", open_ports=[23])]
        ).as_dict()
        # Current: telnet closed.
        current = HomeGuardEngine().build_report(
            [Device(ip="192.168.1.10", hostname="cam", open_ports=[])]
        )
        delta = compute_scan_diff(current, previous)
        resolved_rules = {item["rule_id"] for item in delta["findings"]["resolved"]}
        self.assertIn("risky_port_23", resolved_rules)
        self.assertEqual(delta["risk"]["direction"], "improved")

    def test_run_full_scan_attaches_delta_metadata(self):
        # Two consecutive scans through run_full_scan: the second scan
        # must produce a delta attached to scan_metadata referencing
        # the first scan's report id.
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["HOMEGUARD_DATA_DIR"] = tmp
            ensure_app_dirs()
            with mock.patch(
                "greynoc_homeguard.scan_runner.detect_local_interfaces",
                return_value=[],
            ):
                with mock.patch(
                    "greynoc_homeguard.scan_runner.discover_lan_hosts_noc_core",
                    return_value=[
                        Device(ip="192.168.1.10", hostname="router", open_ports=[80])
                    ],
                ):
                    out1 = Path(tmp) / "s1"
                    first, _, _ = run_full_scan(
                        output_dir=out1, update_known_devices=False
                    )
                with mock.patch(
                    "greynoc_homeguard.scan_runner.discover_lan_hosts_noc_core",
                    return_value=[
                        Device(
                            ip="192.168.1.10",
                            hostname="router",
                            open_ports=[80, 23],
                        )
                    ],
                ):
                    out2 = Path(tmp) / "s2"
                    second, _, _ = run_full_scan(
                        output_dir=out2, update_known_devices=False
                    )

            delta = second.scan_metadata.get("delta") or {}
            self.assertTrue(delta.get("available"))
            self.assertEqual(delta.get("previous_report_id"), first.report_id)
            new_port_rows = delta["devices"]["with_new_ports"]
            self.assertTrue(
                any(23 in row.get("newly_open", []) for row in new_port_rows)
            )


class CustomRulesTests(unittest.TestCase):
    def test_load_returns_empty_payload_when_missing(self):
        from greynoc_homeguard.custom_rules import has_any_rules, load_custom_rules

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "missing.json"
            payload = load_custom_rules(path)
            self.assertFalse(has_any_rules(payload))

    def test_invalid_json_does_not_crash(self):
        from greynoc_homeguard.custom_rules import has_any_rules, load_custom_rules

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("{ not valid json", encoding="utf-8")
            payload = load_custom_rules(path)
            self.assertFalse(has_any_rules(payload))

    def test_invalid_individual_entries_are_dropped(self):
        from greynoc_homeguard.custom_rules import load_custom_rules

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "rules.json"
            path.write_text(
                json.dumps(
                    {
                        "risky_ports": [
                            {"port": 22, "severity": "low"},
                            {"port": 0, "severity": "low"},  # invalid port
                            {"port": "abc"},  # invalid type
                            "string-not-dict",  # invalid row
                        ],
                        "watch_hostnames": [
                            {"pattern": "*-lab", "severity": "high"},
                            {"pattern": "", "severity": "high"},  # empty pattern
                        ],
                        "watch_mac_prefixes": [
                            {"prefix": "aa:bb:cc"},  # ok
                            {"prefix": "shorty"},  # not enough hex chars
                        ],
                    }
                ),
                encoding="utf-8",
            )
            payload = load_custom_rules(path)
            self.assertEqual(len(payload["risky_ports"]), 1)
            self.assertEqual(payload["risky_ports"][0]["port"], 22)
            self.assertEqual(len(payload["watch_hostnames"]), 1)
            self.assertEqual(payload["watch_hostnames"][0]["pattern"], "*-lab")
            self.assertEqual(len(payload["watch_mac_prefixes"]), 1)
            self.assertEqual(payload["watch_mac_prefixes"][0]["prefix"], "aa:bb:cc")

    def test_apply_to_definitions_extends_risky_ports(self):
        from greynoc_homeguard.custom_rules import apply_to_definitions

        definitions = {"risky_ports": [{"port": 80, "severity": "info"}]}
        custom = {
            "risky_ports": [{"port": 12345, "severity": "high", "service": "x", "why": "y"}],
            "watch_hostnames": [],
            "watch_mac_prefixes": [],
        }
        apply_to_definitions(definitions, custom)
        ports = {row["port"] for row in definitions["risky_ports"]}
        self.assertIn(80, ports)
        self.assertIn(12345, ports)

    def test_custom_hostname_pattern_emits_finding(self):
        from greynoc_homeguard.custom_rules import apply_to_definitions
        from greynoc_homeguard.detection import HomeGuardDetectionEngine

        # Hand-roll a definitions dict so the engine isn't loading anything
        # from disk and the test isn't tied to the developer's own
        # custom_rules.json.
        definitions: dict = {"risky_ports": [], "device_name_hints": [], "product_hints": []}
        apply_to_definitions(
            definitions,
            {
                "risky_ports": [],
                "watch_hostnames": [
                    {
                        "pattern": "*-lab",
                        "severity": "high",
                        "why": "Lab hostnames should not appear at home.",
                    }
                ],
                "watch_mac_prefixes": [],
            },
        )
        engine = HomeGuardDetectionEngine(definitions)
        device = Device(
            ip="192.168.1.42", hostname="alice-lab", mac_address="aa:bb:cc:00:01:02"
        )
        findings = engine.evaluate([device])
        custom_hits = [f for f in findings if f.category == "user_custom_rule"]
        self.assertTrue(custom_hits, "expected a custom hostname-match finding")
        self.assertEqual(custom_hits[0].severity, "high")
        self.assertEqual(custom_hits[0].evidence.get("matched_pattern"), "*-lab")

    def test_custom_mac_prefix_emits_finding_and_normalizes_input(self):
        # Round-trip the prefix through load_custom_rules() -> apply_to_definitions
        # -> detection so we exercise the same path the runtime uses. The
        # validator turns "aabb-cc" into "aa:bb:cc" before the detector
        # ever sees it, so a device with MAC AA:BB:CC:* must match while
        # an unrelated MAC must not.
        from greynoc_homeguard.custom_rules import (
            apply_to_definitions,
            load_custom_rules,
        )
        from greynoc_homeguard.detection import HomeGuardDetectionEngine

        with tempfile.TemporaryDirectory() as tmp:
            rules_path = Path(tmp) / "custom_rules.json"
            rules_path.write_text(
                json.dumps(
                    {
                        "watch_mac_prefixes": [
                            {
                                "prefix": "aabb-cc",
                                "severity": "medium",
                                "why": "Recalled vendor.",
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            custom = load_custom_rules(rules_path)
        self.assertEqual(custom["watch_mac_prefixes"][0]["prefix"], "aa:bb:cc")
        definitions: dict = {"risky_ports": [], "device_name_hints": [], "product_hints": []}
        apply_to_definitions(definitions, custom)
        engine = HomeGuardDetectionEngine(definitions)
        match = Device(ip="192.168.1.50", mac_address="AA:BB:CC:11:22:33")
        miss = Device(ip="192.168.1.51", mac_address="11:22:33:44:55:66")
        findings = engine.evaluate([match, miss])
        custom_hits = [f for f in findings if f.category == "user_custom_rule"]
        self.assertEqual(len(custom_hits), 1)
        self.assertEqual(custom_hits[0].device_ip, "192.168.1.50")

    def test_engine_loaded_with_explicit_definitions_does_not_apply_disk_custom_rules(self):
        # Tests pass explicit ``definitions=`` arguments to HomeGuardEngine.
        # Those callers must not silently inherit whatever rules happen to
        # live in the developer's local custom_rules.json or the test
        # results would depend on the developer's environment.
        report = HomeGuardEngine(definitions={"risky_ports": []}).build_report(
            [Device(ip="192.168.1.10", hostname="alice-lab")]
        )
        self.assertFalse(
            any(f.category == "user_custom_rule" for f in report.findings)
        )


class ImportDefinitionsTests(_AppDataMixin, unittest.TestCase):
    def test_missing_file_returns_error_status(self):
        self._isolate()
        result = DefinitionManager().import_from_file(
            Path(tempfile.gettempdir()) / "definitely-not-here.json"
        )
        self.assertFalse(result["ok"])
        self.assertIn("not found", result["message"].lower())

    def test_invalid_json_returns_error_status(self):
        self._isolate()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "broken.json"
            path.write_text("not json", encoding="utf-8")
            result = DefinitionManager().import_from_file(path)
        self.assertFalse(result["ok"])

    def test_unrelated_json_object_is_refused(self):
        self._isolate()
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "unrelated.json"
            path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
            result = DefinitionManager().import_from_file(path)
        self.assertFalse(result["ok"])

    def test_kev_and_cve_are_imported_and_status_is_current(self):
        self._isolate()
        manager = DefinitionManager()
        with tempfile.TemporaryDirectory() as tmp:
            export_path = Path(tmp) / "security_definitions.json"
            export_path.write_text(
                json.dumps(
                    {
                        "kev_catalog": [
                            {
                                "cveID": "CVE-2099-9999",
                                "vendorProject": "Example",
                                "product": "Widget",
                                "vulnerabilityName": "Test",
                                "dateAdded": "2099-01-01",
                                "shortDescription": "Test entry.",
                            }
                        ],
                        "recent_cves": [
                            {"cve_id": "CVE-2099-0001", "description": "From offline import."}
                        ],
                        "definitions_version": "offline.import.1",
                    }
                ),
                encoding="utf-8",
            )
            result = manager.import_from_file(export_path)
        self.assertTrue(result["ok"])
        self.assertEqual(result["kev_count"], 1)
        self.assertEqual(result["cve_count"], 1)
        status = manager.status()
        self.assertEqual(status["update_status"], UPDATE_STATUS_CURRENT)
        self.assertEqual(status["kev_count"], 1)
        self.assertEqual(status["recent_cve_count"], 1)
        # The bundled migration must NOT have wiped the imported version
        # because feed_versions.starter is updated to STARTER_VERSION on
        # first load. Re-loading the saved file should show the imported
        # KEV catalog still present.
        reloaded = manager.load()
        self.assertEqual(len(reloaded.get("kev_catalog") or []), 1)


class CLITests(_AppDataMixin, unittest.TestCase):
    def test_cli_prog_uses_gnhl(self):
        self.assertEqual(cli.build_parser().prog, "GNHL")

    def test_status_command(self):
        self._isolate()
        rc = cli.main(["status"])
        self.assertEqual(rc, 0)

    def test_app_style_status_command(self):
        self._isolate()
        rc = cli.main(["--status"])
        self.assertEqual(rc, 0)

    def test_app_style_scan_alias_preserves_scan_options(self):
        parser = cli.build_parser()
        args = parser.parse_args(
            cli._normalize_app_style_args(["--scan", "--active", "--probe-all", "--no-endpoint-scan"])
        )
        self.assertEqual(args.command, "scan")
        self.assertTrue(args.active)
        self.assertTrue(args.probe_all)
        self.assertTrue(args.no_endpoint_scan)

    def test_welcome_splash_uses_app_style_commands(self):
        self._isolate()
        with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            rc = cli.main([])
        output = stdout.getvalue()
        self.assertEqual(rc, 0)
        self.assertIn("GNHL Direct App CLI", output)
        self.assertIn("Direct app commands are ready", output)
        self.assertIn("GNHL --scan --active", output)
        self.assertIn("GNHL --status", output)
        self.assertNotIn("npm run cli", output)
        self.assertNotIn("homeguard scan", output)

    def test_definitions_status_command(self):
        self._isolate()
        rc = cli.main(["definitions-status"])
        self.assertEqual(rc, 0)

    def test_schedule_show_command(self):
        self._isolate()
        rc = cli.main(["schedule", "show"])
        self.assertEqual(rc, 0)

    def test_devices_list_command_empty(self):
        self._isolate()
        rc = cli.main(["devices", "list"])
        self.assertEqual(rc, 0)

    def test_analyze_command(self):
        self._isolate()
        with tempfile.TemporaryDirectory() as tmp:
            input_path = Path(tmp) / "devices.json"
            input_path.write_text(
                json.dumps(
                    [{"ip": "192.168.1.10", "mac_address": "00:11:22:33:44:55", "hostname": "tv", "open_ports": [80]}]
                ),
                encoding="utf-8",
            )
            out = Path(tmp) / "out"
            rc = cli.main(["analyze", "--input", str(input_path), "--out", str(out)])
            self.assertEqual(rc, 0)
            self.assertTrue((out / "report.html").exists())
            self.assertTrue((out / "findings.csv").exists())


class AppDataPathTests(unittest.TestCase):
    def test_data_dir_under_temporary_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["HOMEGUARD_DATA_DIR"] = tmp
            self.assertEqual(str(user_data_dir()), tmp)


class BuildScriptTests(unittest.TestCase):
    def test_build_scripts_exist(self):
        repo = Path(__file__).resolve().parents[1]
        for path in [
            "GNHL",
            "GNHL.cmd",
            "package.json",
            "run_electron.bat",
            "electron/main.js",
            "electron/preload.js",
            "electron/renderer/index.html",
            "electron/renderer/styles.css",
            "electron/renderer/renderer.js",
            "electron/smoke.js",
            "scripts/build_exe.py",
            "scripts/cli.js",
            "scripts/build_windows_installer.ps1",
            "scripts/sign_windows_artifact.ps1",
            "scripts/verify_windows_signature.ps1",
            "scripts/release_gate.ps1",
            "scripts/build_macos.py",
            "scripts/compile_android.sh",
            "scripts/compile_macos.sh",
            "scripts/notarize_macos.sh",
            "installer/homeguard.iss",
            "compile_exe.bat",
            "mobile/android/buildozer.spec",
            "mobile/android/main.py",
            "mobile/android/README.md",
        ]:
            self.assertTrue((repo / path).exists(), f"missing {path}")

        package = json.loads((repo / "package.json").read_text(encoding="utf-8"))
        self.assertEqual(package["scripts"].get("cli"), "node scripts/cli.js")
        self.assertEqual(package["bin"].get("GNHL"), "scripts/cli.js")
        node_launcher = (repo / "scripts" / "cli.js").read_text(encoding="utf-8")
        self.assertIn("process.env.GNHL_LAUNCHER", node_launcher)
        self.assertIn('npm_lifecycle_event === "cli"', node_launcher)
        self.assertIn("GNHL_LAUNCHER=repo", (repo / "GNHL").read_text(encoding="utf-8"))
        self.assertIn("GNHL_LAUNCHER=repo", (repo / "GNHL.cmd").read_text(encoding="utf-8"))

    def test_signing_verification_script_fails_closed(self):
        repo = Path(__file__).resolve().parents[1]
        verify = (repo / "scripts" / "verify_windows_signature.ps1").read_text(encoding="utf-8")
        sign = (repo / "scripts" / "sign_windows_artifact.ps1").read_text(encoding="utf-8")
        installer = (repo / "scripts" / "build_windows_installer.ps1").read_text(encoding="utf-8")
        inno = (repo / "installer" / "homeguard.iss").read_text(encoding="utf-8")
        self.assertIn("Get-AuthenticodeSignature", verify)
        self.assertIn('Status -ne "Valid"', verify)
        self.assertIn("Set-AuthenticodeSignature", sign)
        self.assertIn("HOMEGUARD_SIGN_CERT_PATH", sign)
        self.assertIn("HOMEGUARD_SIGN_CERT_SHA1", sign)
        self.assertIn("verify_windows_signature.ps1", installer)
        self.assertIn("HomeGuard-Setup-v$Version.exe", installer)
        self.assertIn('"HomeGuard-Setup-v" + AppVersion', inno)

    def test_electron_ui_actions_are_wired_and_private(self):
        repo = Path(__file__).resolve().parents[1]
        html = (repo / "electron" / "renderer" / "index.html").read_text(encoding="utf-8")
        renderer = (repo / "electron" / "renderer" / "renderer.js").read_text(encoding="utf-8")
        main = (repo / "electron" / "main.js").read_text(encoding="utf-8")
        for button_id in [
            "scanButton",
            "updateButton",
            "openHtmlButton",
            "openPdfButton",
            "openFolderButton",
            "devicesRefresh",
            "historyOpenHtml",
            "scheduleSave",
            "logsOpenFolder",
        ]:
            self.assertIn(f'id="{button_id}"', html)
            self.assertIn(f'$("{button_id}")', renderer)
        for channel in ["homeguard:open-path", "homeguard:show-item", "homeguard:log-state"]:
            self.assertIn(channel, main)
        self.assertIn("sandbox: true", main)
        self.assertIn("setWindowOpenHandler", main)
        self.assertIn('will-navigate"', main)
        self.assertIn("isAllowedReportOrLogPath", main)
        self.assertIn("(?:progress|scan)", main)
        self.assertNotIn("isAllowedAppPath", main)
        combined = "\n".join([html, renderer])
        self.assertNotIn(r"C:\Users\\", combined)
        self.assertNotIn("/Users/", combined)
        self.assertNotIn("lorem ipsum", combined.lower())
        self.assertNotIn("mock data", combined.lower())
        self.assertIn("Content-Security-Policy", html)
        self.assertIn("OPENABLE_REPORT_EXTENSIONS", main)
        self.assertNotIn("devicesTableBody.innerHTML", renderer)
        self.assertNotIn("historyTableBody.innerHTML", renderer)

    def test_exported_report_has_csp_without_inline_handlers(self):
        with tempfile.TemporaryDirectory() as tmp:
            report = HomeGuardEngine().build_report(
                [Device(ip="192.168.1.10", hostname="router", open_ports=[80])]
            )
            paths = export_report(report, Path(tmp))
            html_text = paths["html"].read_text(encoding="utf-8")
        self.assertIn("Content-Security-Policy", html_text)
        self.assertIn("script-src 'nonce-", html_text)
        self.assertNotIn("onclick=", html_text)
        self.assertNotIn("oninput=", html_text)
        self.assertNotIn("â", html_text)


if __name__ == "__main__":
    unittest.main()

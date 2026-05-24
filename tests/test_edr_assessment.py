"""EDR Phase 1 assessment + model tests."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
if str(SRC) not in os.sys.path:
    os.sys.path.insert(0, str(SRC))

_TMP_ROOT = tempfile.mkdtemp(prefix="hg_test_edr_")
os.environ.setdefault("HOMEGUARD_DATA_DIR", _TMP_ROOT)

from greynoc_homeguard.edr import (  # noqa: E402
    LEVEL_CLEAN,
    LEVEL_CONFIRMED_COMPROMISE,
    LEVEL_LIKELY_COMPROMISE,
    LEVEL_NOT_RUN,
    LEVEL_REVIEW_INDICATOR,
    LEVEL_SUSPICIOUS_ACTIVITY,
    EndpointAssessment,
    EvidenceChain,
    EvidenceItem,
    assess_endpoint_findings,
    level_rank,
    normalize_level,
)
from greynoc_homeguard.models import Finding  # noqa: E402


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------


def _make_finding(
    *,
    rule_id: str,
    severity: str = "info",
    category: str = "endpoint",
    plain_english: str = "",
    evidence: dict | None = None,
    confidence: float = 0.5,
    title: str | None = None,
) -> Finding:
    """Build a Finding with sensible defaults for assessment tests."""
    return Finding(
        finding_id=f"f-{rule_id}",
        rule_id=rule_id,
        title=title or rule_id.replace("_", " ").title(),
        severity=severity,
        confidence=confidence,
        risk_score=10.0,
        priority="medium",
        category=category,
        device_ip="127.0.0.1",
        device_name="this-host",
        plain_english=plain_english or f"Test finding for {rule_id}",
        recommended_actions=["Investigate."],
        evidence=dict(evidence or {}),
    )


# --------------------------------------------------------------------------
# Level helpers
# --------------------------------------------------------------------------


class LevelHelperTests(unittest.TestCase):
    def test_normalize_level_passthrough(self):
        for level in (LEVEL_CLEAN, LEVEL_REVIEW_INDICATOR, LEVEL_SUSPICIOUS_ACTIVITY,
                      LEVEL_LIKELY_COMPROMISE, LEVEL_CONFIRMED_COMPROMISE, LEVEL_NOT_RUN):
            self.assertEqual(normalize_level(level), level)
            self.assertEqual(normalize_level(level.upper()), level)
            self.assertEqual(normalize_level(f"  {level}  "), level)

    def test_normalize_level_unknown_falls_back_to_clean(self):
        self.assertEqual(normalize_level("nonsense"), LEVEL_CLEAN)
        self.assertEqual(normalize_level(""), LEVEL_CLEAN)
        self.assertEqual(normalize_level(None), LEVEL_CLEAN)
        self.assertEqual(normalize_level(42), LEVEL_CLEAN)

    def test_level_rank_orders_severity(self):
        self.assertLess(level_rank(LEVEL_CLEAN), level_rank(LEVEL_REVIEW_INDICATOR))
        self.assertLess(level_rank(LEVEL_REVIEW_INDICATOR), level_rank(LEVEL_SUSPICIOUS_ACTIVITY))
        self.assertLess(level_rank(LEVEL_SUSPICIOUS_ACTIVITY), level_rank(LEVEL_LIKELY_COMPROMISE))
        self.assertLess(level_rank(LEVEL_LIKELY_COMPROMISE), level_rank(LEVEL_CONFIRMED_COMPROMISE))
        # not_run sits alongside clean for comparison purposes.
        self.assertEqual(level_rank(LEVEL_NOT_RUN), level_rank(LEVEL_CLEAN))
        # Unknown values are safe to compare.
        self.assertEqual(level_rank("garbage"), 0)


# --------------------------------------------------------------------------
# Mapping rules
# --------------------------------------------------------------------------


class AssessmentMappingTests(unittest.TestCase):
    def test_no_findings_is_clean(self):
        result = assess_endpoint_findings([])
        self.assertEqual(result.level, LEVEL_CLEAN)
        self.assertGreater(result.confidence, 0.0)
        self.assertEqual(result.evidence_items, [])
        self.assertEqual(result.evidence_chains, [])
        self.assertIn("No endpoint compromise indicators", result.summary)

    def test_only_info_or_low_findings_are_review_indicator(self):
        result = assess_endpoint_findings([
            _make_finding(rule_id="default_name_hint", severity="info"),
            _make_finding(rule_id="missing_mac", severity="low"),
        ])
        self.assertEqual(result.level, LEVEL_REVIEW_INDICATOR)
        self.assertIn("Review indicators", result.summary)
        self.assertEqual(len(result.evidence_items), 2)

    def test_single_high_severity_is_suspicious_activity(self):
        # A single high-severity suspicious-command-line finding alone -
        # no related chain - rises to suspicious_activity but no further.
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_suspicious_command_powershell",
                severity="high",
                category="suspicious_command_line",
                plain_english="Encoded PowerShell command observed running.",
                confidence=0.7,
            ),
        ])
        self.assertEqual(result.level, LEVEL_SUSPICIOUS_ACTIVITY)
        self.assertEqual(result.evidence_chains, [])  # no pair -> no chain
        self.assertIn("Suspicious endpoint activity", result.summary)

    def test_suspicious_command_plus_persistence_is_likely_compromise(self):
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_powershell_obfuscation",
                severity="high",
                category="suspicious_command_line",
                plain_english="Obfuscated PowerShell invocation.",
                confidence=0.7,
            ),
            _make_finding(
                rule_id="endpoint_run_key_persistence",
                severity="high",
                category="persistence",
                plain_english="Run key startup entry added.",
                confidence=0.7,
            ),
        ])
        self.assertEqual(result.level, LEVEL_LIKELY_COMPROMISE)
        self.assertTrue(result.evidence_chains)
        # The chain that fired should pair persistence + suspicious_command_line.
        titles = {c.title for c in result.evidence_chains}
        self.assertTrue(
            any("persistence" in t and "suspicious_command_line" in t for t in titles),
            f"expected persistence + suspicious_command_line chain, got: {titles}",
        )
        self.assertIn("likely compromise", result.summary.lower())

    def test_eicar_signature_is_confirmed_compromise(self):
        # EICAR is a TEST file but per spec it maps to confirmed_compromise
        # so the alert path is exercised end-to-end. Description text alone
        # is enough to trip the strong-signal path.
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_eicar_signature",
                severity="critical",
                category="malware_payload",
                plain_english="EICAR test string detected in a downloaded file.",
                evidence={"file_signature": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"},
                confidence=0.95,
            ),
        ])
        self.assertEqual(result.level, LEVEL_CONFIRMED_COMPROMISE)
        self.assertIn("confirmed compromise", result.summary.lower())
        # Recommended actions should include isolation.
        self.assertTrue(
            any("isolate" in action.lower() for action in result.recommended_actions),
            result.recommended_actions,
        )

    def test_critical_finding_with_known_malicious_hash_is_confirmed_compromise(self):
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_known_bad_hash",
                severity="critical",
                category="malware_payload",
                evidence={
                    "sha256": "deadbeef" * 8,
                    "known_malicious_hash": True,
                },
                confidence=0.99,
            ),
        ])
        self.assertEqual(result.level, LEVEL_CONFIRMED_COMPROMISE)
        self.assertGreaterEqual(result.confidence, 0.85)

    def test_memory_artifact_plus_suspicious_command_is_likely_compromise(self):
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_process_memory_string",
                severity="high",
                category="memory_artifact",
                plain_english="Suspicious string observed in process memory.",
                confidence=0.75,
            ),
            _make_finding(
                rule_id="endpoint_invoke_expression",
                severity="high",
                category="suspicious_command_line",
                plain_english="Invoke-Expression with remote download string.",
                confidence=0.8,
            ),
        ])
        self.assertEqual(result.level, LEVEL_LIKELY_COMPROMISE)
        titles = {c.title for c in result.evidence_chains}
        self.assertTrue(
            any("memory_artifact" in t and "suspicious_command_line" in t for t in titles),
            titles,
        )

    def test_credential_theft_plus_memory_is_likely_compromise(self):
        # Spec call-out: memory artifact + suspicious process command should
        # land likely_compromise or confirmed depending on confidence. With
        # mimikatz string in evidence the strong-signal path fires confirmed.
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_credential_dump",
                severity="critical",
                category="credential_theft",
                plain_english="Process memory contains mimikatz string.",
                evidence={"matched_artifact": "mimikatz"},
                confidence=0.95,
            ),
            _make_finding(
                rule_id="endpoint_process_memory_string",
                severity="high",
                category="memory_artifact",
                plain_english="Sensitive material observed in process memory.",
                confidence=0.85,
            ),
        ])
        # Strong signal (mimikatz token) escalates to confirmed.
        self.assertEqual(result.level, LEVEL_CONFIRMED_COMPROMISE)

    def test_yara_match_flag_forces_confirmed_compromise(self):
        # Producers can set explicit raw flags to force the call even if
        # severity isn't critical.
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_yara_rule_hit",
                severity="medium",
                category="malware_payload",
                evidence={"yara_match": True, "rule": "Cobalt_Strike_Beacon"},
                confidence=0.6,
            ),
        ])
        self.assertEqual(result.level, LEVEL_CONFIRMED_COMPROMISE)


# --------------------------------------------------------------------------
# Serialization
# --------------------------------------------------------------------------


class SerializationTests(unittest.TestCase):
    def test_as_dict_is_json_serializable(self):
        result = assess_endpoint_findings([
            _make_finding(
                rule_id="endpoint_powershell_obfuscation",
                severity="high",
                category="suspicious_command_line",
                evidence={"sha256": "ab" * 32, "command_line": "powershell -enc ..."},
            ),
            _make_finding(
                rule_id="endpoint_run_key_persistence",
                severity="high",
                category="persistence",
            ),
        ])
        as_dict = result.as_dict()
        # Round-trip through json to confirm everything is JSON-safe.
        round_tripped = json.loads(json.dumps(as_dict))
        self.assertEqual(round_tripped["level"], result.level)
        self.assertEqual(
            len(round_tripped["evidence_items"]),
            len(result.evidence_items),
        )
        self.assertIn("evidence_count", round_tripped["metadata"])
        # Every evidence dict carries the required keys.
        for evidence in round_tripped["evidence_items"]:
            for required in ("evidence_id", "timestamp", "source", "rule_id"):
                self.assertIn(required, evidence)

    def test_evidence_item_default_id_is_unique(self):
        a = EvidenceItem(source="t")
        b = EvidenceItem(source="t")
        self.assertNotEqual(a.evidence_id, b.evidence_id)

    def test_evidence_chain_round_trip(self):
        chain = EvidenceChain(
            title="persistence + suspicious_command_line",
            assessment_level=LEVEL_LIKELY_COMPROMISE,
            confidence=0.7,
            evidence_ids=["ev-a", "ev-b"],
            summary="paired",
            recommended_actions=["Investigate."],
        )
        round_tripped = json.loads(json.dumps(chain.as_dict()))
        self.assertEqual(round_tripped["assessment_level"], LEVEL_LIKELY_COMPROMISE)
        self.assertEqual(round_tripped["evidence_ids"], ["ev-a", "ev-b"])

    def test_endpoint_assessment_dataclass_round_trip(self):
        ev = EvidenceItem(source="memory_scan", severity="high", confidence=0.8)
        chain = EvidenceChain(
            title="memory + cmd",
            assessment_level=LEVEL_LIKELY_COMPROMISE,
            evidence_ids=[ev.evidence_id],
        )
        assessment = EndpointAssessment(
            level=LEVEL_LIKELY_COMPROMISE,
            confidence=0.7,
            summary="t",
            evidence_items=[ev],
            evidence_chains=[chain],
            recommended_actions=["x"],
            metadata={"k": "v"},
        )
        text = json.dumps(assessment.as_dict())
        self.assertIn("memory_scan", text)
        self.assertIn(ev.evidence_id, text)


# --------------------------------------------------------------------------
# scan_runner integration
# --------------------------------------------------------------------------


class ScanRunnerIntegrationTests(unittest.TestCase):
    """Confirm scan_runner.run_full_scan wires endpoint_assessment correctly.

    We mock the heavy pieces (discovery, detection engine, history, reports,
    schedule manager, endpoint scan) so the test runs in milliseconds and
    exercises only the assessment-wiring branch.
    """

    def test_endpoint_assessment_attached_when_endpoint_scan_runs(self):
        from greynoc_homeguard import scan_runner
        from greynoc_homeguard.models import HomeGuardReport
        from greynoc_homeguard.virus_scanner import EndpointScanResult

        # Build a minimal report stub the assessment branch can write into.
        report = HomeGuardReport(
            report_id="r-1",
            created_at="2026-05-24T00:00:00Z",
            summary="t",
            overall_risk="clean",
            overall_score=0.0,
            devices=[],
            findings=[],
            next_steps=[],
            scan_metadata={},
        )

        endpoint_result = EndpointScanResult(
            findings=[
                _make_finding(
                    rule_id="endpoint_eicar_signature",
                    severity="critical",
                    category="malware_payload",
                    evidence={"file_signature": "EICAR-STANDARD-ANTIVIRUS-TEST-FILE"},
                    confidence=0.95,
                ),
            ],
            metadata={"scanner": "test"},
        )

        with mock.patch.object(scan_runner, "DefinitionManager"), \
             mock.patch.object(scan_runner, "detect_local_interfaces", return_value=[]), \
             mock.patch.object(scan_runner, "discover_lan_hosts_noc_core", return_value=[]), \
             mock.patch.object(scan_runner, "BaselineStore") as baseline_cls, \
             mock.patch.object(scan_runner, "ProtectionHistory") as history_cls, \
             mock.patch.object(scan_runner, "ScheduleManager") as schedule_cls, \
             mock.patch.object(scan_runner, "HomeGuardEngine") as engine_cls, \
             mock.patch.object(scan_runner, "export_report", return_value={"json": Path("x.json"), "html": Path("x.html")}), \
             mock.patch.object(scan_runner, "load_previous_report", return_value=None), \
             mock.patch.object(scan_runner, "compute_scan_diff", return_value={}), \
             mock.patch.object(scan_runner, "render_summary", return_value=""), \
             mock.patch.object(scan_runner, "active_scan_ports", return_value=[]), \
             mock.patch.object(scan_runner, "run_endpoint_malware_scan", return_value=endpoint_result), \
             mock.patch.object(scan_runner, "latest_report_dir", return_value=Path(tempfile.mkdtemp(prefix="hg_latest_"))), \
             mock.patch.object(scan_runner, "default_output_dir", return_value=Path(tempfile.mkdtemp(prefix="hg_out_"))), \
             mock.patch.object(scan_runner, "default_baseline_path", return_value=Path(tempfile.mkdtemp(prefix="hg_bl_")) / "b.json"):

            baseline_cls.return_value.load.return_value = mock.MagicMock(
                update=lambda devices: None, save=lambda: None,
            )
            history_cls.return_value.load.return_value = mock.MagicMock(
                latest=lambda: None, add=lambda *a, **k: mock.MagicMock(), save=lambda: None,
            )
            schedule_instance = mock.MagicMock()
            schedule_instance.config.enabled = False
            schedule_cls.return_value = schedule_instance
            engine_instance = mock.MagicMock()
            engine_instance.build_report.return_value = report
            engine_cls.return_value = engine_instance

            result_report, _paths, _entry = scan_runner.run_full_scan(
                active=False, probe_all=False, endpoint_scan=True,
            )

        self.assertIn("endpoint_assessment", result_report.scan_metadata)
        assessment_blob = result_report.scan_metadata["endpoint_assessment"]
        self.assertEqual(assessment_blob["level"], LEVEL_CONFIRMED_COMPROMISE)
        # The blob must be JSON-serializable (no dataclass instances left).
        json.dumps(assessment_blob)

    def test_endpoint_assessment_marked_not_run_when_endpoint_scan_disabled(self):
        from greynoc_homeguard import scan_runner
        from greynoc_homeguard.models import HomeGuardReport

        report = HomeGuardReport(
            report_id="r-2",
            created_at="2026-05-24T00:00:00Z",
            summary="t",
            overall_risk="clean",
            overall_score=0.0,
            devices=[],
            findings=[],
            next_steps=[],
            scan_metadata={},
        )

        with mock.patch.object(scan_runner, "DefinitionManager"), \
             mock.patch.object(scan_runner, "detect_local_interfaces", return_value=[]), \
             mock.patch.object(scan_runner, "discover_lan_hosts_noc_core", return_value=[]), \
             mock.patch.object(scan_runner, "BaselineStore") as baseline_cls, \
             mock.patch.object(scan_runner, "ProtectionHistory") as history_cls, \
             mock.patch.object(scan_runner, "ScheduleManager") as schedule_cls, \
             mock.patch.object(scan_runner, "HomeGuardEngine") as engine_cls, \
             mock.patch.object(scan_runner, "export_report", return_value={"json": Path("x.json"), "html": Path("x.html")}), \
             mock.patch.object(scan_runner, "load_previous_report", return_value=None), \
             mock.patch.object(scan_runner, "compute_scan_diff", return_value={}), \
             mock.patch.object(scan_runner, "render_summary", return_value=""), \
             mock.patch.object(scan_runner, "active_scan_ports", return_value=[]), \
             mock.patch.object(scan_runner, "latest_report_dir", return_value=Path(tempfile.mkdtemp(prefix="hg_latest_"))), \
             mock.patch.object(scan_runner, "default_output_dir", return_value=Path(tempfile.mkdtemp(prefix="hg_out_"))), \
             mock.patch.object(scan_runner, "default_baseline_path", return_value=Path(tempfile.mkdtemp(prefix="hg_bl_")) / "b.json"):

            baseline_cls.return_value.load.return_value = mock.MagicMock(
                update=lambda devices: None, save=lambda: None,
            )
            history_cls.return_value.load.return_value = mock.MagicMock(
                latest=lambda: None, add=lambda *a, **k: mock.MagicMock(), save=lambda: None,
            )
            schedule_instance = mock.MagicMock()
            schedule_instance.config.enabled = False
            schedule_cls.return_value = schedule_instance
            engine_instance = mock.MagicMock()
            engine_instance.build_report.return_value = report
            engine_cls.return_value = engine_instance

            result_report, _paths, _entry = scan_runner.run_full_scan(
                active=False, probe_all=False, endpoint_scan=False,
            )

        self.assertIn("endpoint_assessment", result_report.scan_metadata)
        self.assertEqual(result_report.scan_metadata["endpoint_assessment"]["level"], LEVEL_NOT_RUN)


if __name__ == "__main__":
    unittest.main()

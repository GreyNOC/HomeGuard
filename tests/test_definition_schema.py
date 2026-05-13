import pytest

from greynoc_homeguard.definition_schema import (
    DefinitionSchemaError,
    validate_cisa_kev_payload,
    validate_imported_definitions_payload,
    validate_nvd_cve_payload,
)


def test_cisa_kev_schema_accepts_expected_shape():
    payload = {
        "catalogVersion": "2026.05.13",
        "vulnerabilities": [
            {
                "cveID": "CVE-2026-0001",
                "vendorProject": "Example",
                "product": "Router",
                "vulnerabilityName": "Example issue",
                "dateAdded": "2026-05-13",
                "requiredAction": "Apply updates",
                "shortDescription": "Example public vulnerability description.",
            }
        ],
    }
    assert validate_cisa_kev_payload(payload) is payload


def test_cisa_kev_schema_rejects_missing_cve_id():
    with pytest.raises(DefinitionSchemaError, match="missing cveID"):
        validate_cisa_kev_payload({"vulnerabilities": [{"product": "router"}]})


def test_cisa_kev_schema_rejects_oversized_text():
    payload = {"vulnerabilities": [{"cveID": "CVE-2026-0001", "shortDescription": "x" * 9000}]}
    with pytest.raises(DefinitionSchemaError, match="too long"):
        validate_cisa_kev_payload(payload)


def test_nvd_schema_accepts_expected_shape():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2026-0002",
                    "published": "2026-05-13T00:00:00.000",
                    "lastModified": "2026-05-13T00:00:00.000",
                    "vulnStatus": "Analyzed",
                    "descriptions": [{"lang": "en", "value": "Example description."}],
                    "metrics": {},
                }
            }
        ]
    }
    assert validate_nvd_cve_payload(payload) is payload


def test_nvd_schema_rejects_bad_metrics_shape():
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-2026-0002", "metrics": []}}]}
    with pytest.raises(DefinitionSchemaError, match="metrics"):
        validate_nvd_cve_payload(payload)


def test_imported_definitions_schema_accepts_compact_cache():
    payload = {
        "definitions_version": "2026.05.13.1",
        "kev_catalog": [{"cve_id": "CVE-2026-0003"}],
        "recent_cves": [{"cve_id": "CVE-2026-0004", "description": "Example."}],
        "feed_versions": {"cisa_kev": "2026.05.13"},
    }
    assert validate_imported_definitions_payload(payload) is payload


def test_imported_definitions_schema_rejects_unknown_payload():
    with pytest.raises(DefinitionSchemaError, match="HomeGuard definition"):
        validate_imported_definitions_payload({"hello": "world"})

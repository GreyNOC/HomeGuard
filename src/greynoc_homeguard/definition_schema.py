from __future__ import annotations

from typing import Any

MAX_FEED_ITEMS = 50_000
MAX_TEXT_FIELD = 2_000
MAX_DESCRIPTION = 8_000
MAX_CVE_ID = 64


class DefinitionSchemaError(ValueError):
    """Raised when a remote or imported definition feed has an invalid shape."""


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DefinitionSchemaError(f"{label} must be an object")
    return value


def _require_list(value: Any, label: str, *, max_items: int = MAX_FEED_ITEMS) -> list[Any]:
    if not isinstance(value, list):
        raise DefinitionSchemaError(f"{label} must be a list")
    if len(value) > max_items:
        raise DefinitionSchemaError(f"{label} has too many records")
    return value


def _optional_text(value: Any, label: str, *, max_length: int = MAX_TEXT_FIELD) -> str:
    if value in (None, ""):
        return ""
    if not isinstance(value, str):
        raise DefinitionSchemaError(f"{label} must be a string")
    clean = value.strip()
    if len(clean) > max_length:
        raise DefinitionSchemaError(f"{label} is too long")
    return clean


def _cve_id(value: Any, label: str) -> str:
    clean = _optional_text(value, label, max_length=MAX_CVE_ID)
    if clean and not clean.upper().startswith("CVE-"):
        raise DefinitionSchemaError(f"{label} must look like a CVE id")
    return clean


def validate_cisa_kev_payload(payload: Any) -> dict[str, Any]:
    """Validate the CISA KEV feed shape before compacting it.

    This intentionally validates only public CISA fields used by HomeGuard,
    rejects oversized inputs, and avoids silently accepting arbitrary nested
    structures from a compromised or malformed feed.
    """

    data = _require_object(payload, "CISA KEV payload")
    vulnerabilities = _require_list(data.get("vulnerabilities"), "CISA KEV vulnerabilities")
    _optional_text(data.get("catalogVersion"), "CISA KEV catalogVersion")
    _optional_text(data.get("dateReleased"), "CISA KEV dateReleased")

    for index, item in enumerate(vulnerabilities):
        row = _require_object(item, f"CISA KEV vulnerability[{index}]")
        cve = _cve_id(row.get("cveID") or row.get("cve_id"), f"CISA KEV vulnerability[{index}].cveID")
        if not cve:
            raise DefinitionSchemaError(f"CISA KEV vulnerability[{index}] missing cveID")
        for key in (
            "vendorProject",
            "vendor_project",
            "product",
            "vulnerabilityName",
            "vulnerability_name",
            "dateAdded",
            "date_added",
            "knownRansomwareCampaignUse",
            "requiredAction",
            "shortDescription",
        ):
            _optional_text(row.get(key), f"CISA KEV vulnerability[{index}].{key}", max_length=MAX_DESCRIPTION)
    return data


def validate_nvd_cve_payload(payload: Any) -> dict[str, Any]:
    """Validate the NVD CVE API response shape before compacting it."""

    data = _require_object(payload, "NVD payload")
    vulnerabilities = _require_list(data.get("vulnerabilities"), "NVD vulnerabilities")
    for index, item in enumerate(vulnerabilities):
        row = _require_object(item, f"NVD vulnerability[{index}]")
        cve = _require_object(row.get("cve"), f"NVD vulnerability[{index}].cve")
        cve_id = _cve_id(cve.get("id"), f"NVD vulnerability[{index}].cve.id")
        if not cve_id:
            raise DefinitionSchemaError(f"NVD vulnerability[{index}] missing cve.id")
        for key in ("published", "lastModified", "vulnStatus"):
            _optional_text(cve.get(key), f"NVD vulnerability[{index}].cve.{key}")
        descriptions = cve.get("descriptions") or []
        if descriptions:
            _require_list(descriptions, f"NVD vulnerability[{index}].cve.descriptions", max_items=50)
            for desc_index, desc in enumerate(descriptions):
                desc_obj = _require_object(desc, f"NVD vulnerability[{index}].cve.descriptions[{desc_index}]")
                _optional_text(desc_obj.get("lang"), f"NVD vulnerability[{index}].cve.descriptions[{desc_index}].lang", max_length=16)
                _optional_text(desc_obj.get("value"), f"NVD vulnerability[{index}].cve.descriptions[{desc_index}].value", max_length=MAX_DESCRIPTION)
        metrics = cve.get("metrics") or {}
        if metrics and not isinstance(metrics, dict):
            raise DefinitionSchemaError(f"NVD vulnerability[{index}].cve.metrics must be an object")
    return data


def validate_imported_definitions_payload(payload: Any) -> dict[str, Any]:
    """Validate offline/imported HomeGuard definitions before merging them."""

    data = _require_object(payload, "Imported definitions")
    if not any(key in data for key in ("kev_catalog", "recent_cves", "definitions_version", "feed_versions")):
        raise DefinitionSchemaError(
            "Imported definitions must contain at least one HomeGuard definition field"
        )
    _optional_text(data.get("definitions_version"), "definitions_version")
    if "feed_versions" in data and not isinstance(data.get("feed_versions"), dict):
        raise DefinitionSchemaError("feed_versions must be an object")
    if "kev_catalog" in data:
        kev = _require_list(data.get("kev_catalog"), "kev_catalog")
        for index, item in enumerate(kev):
            row = _require_object(item, f"kev_catalog[{index}]")
            cve = _cve_id(row.get("cve_id") or row.get("cveID"), f"kev_catalog[{index}].cve_id")
            if not cve:
                raise DefinitionSchemaError(f"kev_catalog[{index}] missing cve_id")
    if "recent_cves" in data:
        cves = _require_list(data.get("recent_cves"), "recent_cves")
        for index, item in enumerate(cves):
            row = _require_object(item, f"recent_cves[{index}]")
            cve = _cve_id(row.get("cve_id"), f"recent_cves[{index}].cve_id")
            if not cve:
                raise DefinitionSchemaError(f"recent_cves[{index}] missing cve_id")
            _optional_text(row.get("description"), f"recent_cves[{index}].description", max_length=MAX_DESCRIPTION)
    return data

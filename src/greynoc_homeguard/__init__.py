"""HomeGuard."""

from __future__ import annotations

import json as _json
from pathlib import Path as _Path
from typing import Any as _Any

from .definition_schema import (
    DefinitionSchemaError as _DefinitionSchemaError,
    validate_cisa_kev_payload as _validate_cisa_kev_payload,
    validate_imported_definitions_payload as _validate_imported_definitions_payload,
    validate_nvd_cve_payload as _validate_nvd_cve_payload,
)

__version__ = "1.1.0"


def _install_definition_schema_validation() -> None:
    """Attach strict feed validation to the existing definitions module.

    The definitions module is intentionally large and public-release sensitive.
    Installing a small wrapper here lets the existing CISA/NVD download and
    offline import code keep its behavior while rejecting malformed or oversized
    feed structures before HomeGuard compacts or persists them.
    """

    try:
        from . import definitions as _definitions
    except Exception:
        return

    if getattr(_definitions, "_HOMEGUARD_SCHEMA_VALIDATION_INSTALLED", False):
        return

    original_http_json = _definitions._http_json
    original_import_from_file = _definitions.DefinitionManager.import_from_file

    def guarded_http_json(url: str, *args: _Any, **kwargs: _Any) -> dict[str, _Any]:
        payload = original_http_json(url, *args, **kwargs)
        if url == _definitions.CISA_KEV_URL:
            return _validate_cisa_kev_payload(payload)
        if str(url).startswith(_definitions.NVD_CVE_API_URL):
            return _validate_nvd_cve_payload(payload)
        return payload

    def guarded_import_from_file(self: _Any, path: str | _Path) -> dict[str, _Any]:
        target = _Path(path)
        if not target.exists():
            return {"ok": False, "message": f"File not found: {path}"}
        try:
            raw = _json.loads(target.read_text(encoding="utf-8"))
            _validate_imported_definitions_payload(raw)
        except (OSError, _json.JSONDecodeError, _DefinitionSchemaError) as exc:
            return {"ok": False, "message": f"Invalid definitions file: {exc}"}
        return original_import_from_file(self, path)

    _definitions._http_json = guarded_http_json
    _definitions.DefinitionManager.import_from_file = guarded_import_from_file
    _definitions._HOMEGUARD_SCHEMA_VALIDATION_INSTALLED = True


def _install_endpoint_abuse_signatures() -> None:
    """Attach defensive endpoint-abuse signatures to the local scanner."""

    try:
        from .endpoint_abuse_signatures import install_into_virus_scanner as _install_signatures
    except Exception:
        return
    try:
        _install_signatures()
    except Exception:
        return


_install_definition_schema_validation()
_install_endpoint_abuse_signatures()

from __future__ import annotations

import os
import re
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from typing import Any

from .models import Device, Finding, HomeGuardReport

REDACTED_PATH = "local app data"
REDACTED_SECRET = "redacted"

# Upper bound on a single value handed to the regex stack in ``scrub_text``.
# Real report fields and log records are far shorter; capping pathological,
# delimiter-free input keeps every substitution bounded regardless of pattern
# shape and is a defence-in-depth backstop against regex denial-of-service.
_MAX_SCRUB_CHARS = 100_000

_WINDOWS_USER_PATH = re.compile(r"[A-Za-z]:\\Users\\[^\\\r\n\t\"'<>]+(?:\\[^\\\r\n\t\"'<>]*)*")
_WINDOWS_ABSOLUTE_PATH = re.compile(r"[A-Za-z]:\\(?:[^\\\r\n\t\"'<>]+\\)*[^\\\r\n\t\"'<>]*")
_MAC_USER_PATH = re.compile(r"/Users/[^/\s\"'<>]+(?:/[^/\s\"'<>]+)*")
# A maximal run of "path-ish" characters (no whitespace / quote / angle
# delimiters). AppData tokens are redacted by matching each run ONCE and
# replacing the whole run when it contains "appdata". An equivalent
# "[^x]*AppData[^x]*" pattern backtracks catastrophically — O(n^2), ~24s on a
# 100KB delimiter-free string such as an attacker-chosen device hostname — which
# stalls report generation on every scan. This linear form removes that DoS.
_NON_DELIM_RUN = re.compile(r"[^ \r\n\t\"'<>]+")
_ENV_ASSIGNMENT = re.compile(r"\b(?:HOME|USERNAME|USERPROFILE|LOCALAPPDATA|APPDATA)=\S+", re.IGNORECASE)
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_SECRET_ASSIGNMENT = re.compile(
    r"(\b(?:token|api[_-]?key|password|secret|credential)s?\b\s*[:=]\s*)[^\s,;]+",
    re.IGNORECASE,
)
# Secret shapes the "keyword = value" pattern above misses: HTTP bearer tokens,
# secrets carried in URL query parameters (e.g. a provider ?key=... endpoint),
# and well-known provider key prefixes that appear bare with no label.
_BEARER_TOKEN = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE)
_URL_SECRET_PARAM = re.compile(
    r"([?&](?:key|api[_-]?key|access[_-]?token|token|auth)=)[^&\s\"'<>]+",
    re.IGNORECASE,
)
_KNOWN_KEY_PREFIX = re.compile(
    r"\b(?:gh[opsru]_[A-Za-z0-9]{16,}"   # GitHub PAT / OAuth / app / refresh tokens
    r"|sk-[A-Za-z0-9]{16,}"               # OpenAI-style secret keys
    r"|AKIA[0-9A-Z]{16}"                  # AWS access key id
    r"|xox[baprs]-[A-Za-z0-9-]{8,})"      # Slack tokens
)
_MAC_ADDRESS = re.compile(r"\b[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}\b")

PRIVATE_PATTERNS = [
    re.compile(r"C:\\Users\\", re.IGNORECASE),
    re.compile(r"/Users/", re.IGNORECASE),
    re.compile(r"AppData", re.IGNORECASE),
    re.compile(r"\bHOME=", re.IGNORECASE),
    re.compile(r"\bUSERNAME=", re.IGNORECASE),
    re.compile(r"PRIVATE KEY", re.IGNORECASE),
    re.compile(r"\btoken\b", re.IGNORECASE),
]


def _runtime_tokens() -> list[str]:
    tokens = {
        str(Path.home()),
        os.environ.get("USERPROFILE", ""),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("APPDATA", ""),
        os.environ.get("HOME", ""),
    }
    return sorted({token for token in tokens if len(token) >= 5}, key=len, reverse=True)


def scrub_text(value: Any) -> str:
    text = str(value if value is not None else "")
    if len(text) > _MAX_SCRUB_CHARS:
        text = text[:_MAX_SCRUB_CHARS]
    for token in _runtime_tokens():
        text = text.replace(token, REDACTED_PATH)
    text = _PRIVATE_KEY_BLOCK.sub(REDACTED_SECRET, text)
    text = _ENV_ASSIGNMENT.sub(REDACTED_SECRET, text)
    text = _SECRET_ASSIGNMENT.sub(REDACTED_SECRET, text)
    text = _BEARER_TOKEN.sub(REDACTED_SECRET, text)
    text = _URL_SECRET_PARAM.sub(lambda match: match.group(1) + REDACTED_SECRET, text)
    text = _KNOWN_KEY_PREFIX.sub(REDACTED_SECRET, text)
    text = _WINDOWS_USER_PATH.sub(REDACTED_PATH, text)
    text = _NON_DELIM_RUN.sub(
        lambda match: REDACTED_PATH if "appdata" in match.group(0).lower() else match.group(0),
        text,
    )
    text = _MAC_USER_PATH.sub(REDACTED_PATH, text)
    text = _WINDOWS_ABSOLUTE_PATH.sub(REDACTED_PATH, text)
    text = _MAC_ADDRESS.sub(lambda match: mask_identifier(match.group(0)), text)
    return text


def mask_identifier(value: Any) -> str:
    text = str(value or "").strip()
    match = _MAC_ADDRESS.search(text)
    if not match:
        return text
    parts = match.group(0).lower().split(":")
    return f"device id ending {parts[-2]}:{parts[-1]}"


def scrub_data(value: Any) -> Any:
    if isinstance(value, dict):
        cleaned: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            key_lower = key_text.lower()
            if key_lower in {"path", "baseline_path", "report_dir", "html_path", "pdf_path", "json_path"}:
                cleaned[key_text] = REDACTED_PATH if item else ""
            elif "mac" in key_lower:
                cleaned[key_text] = mask_identifier(item)
            else:
                cleaned[key_text] = scrub_data(item)
        return cleaned
    if isinstance(value, list):
        return [scrub_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(scrub_data(item) for item in value)
    if isinstance(value, str):
        return scrub_text(value)
    return value


def scrub_report(report: HomeGuardReport) -> HomeGuardReport:
    devices = [
        replace(
            device,
            mac_address=mask_identifier(device.mac_address),
            hostname=scrub_text(device.hostname),
            interface=scrub_text(device.interface),
            source=scrub_text(device.source),
            vendor=scrub_text(device.vendor),
            metadata=scrub_data(deepcopy(device.metadata)),
        )
        for device in report.devices
    ]
    findings = [
        replace(
            finding,
            title=scrub_text(finding.title),
            device_name=scrub_text(finding.device_name),
            plain_english=scrub_text(finding.plain_english),
            recommended_actions=[scrub_text(action) for action in finding.recommended_actions],
            evidence=scrub_data(deepcopy(finding.evidence)),
        )
        for finding in report.findings
    ]
    return replace(
        report,
        summary=scrub_text(report.summary),
        devices=devices,
        findings=findings,
        next_steps=[scrub_text(step) for step in report.next_steps],
        scan_metadata=scrub_data(deepcopy(report.scan_metadata)),
    )


def privacy_findings(text: str) -> list[str]:
    findings: list[str] = []
    for pattern in PRIVATE_PATTERNS:
        if pattern.search(text):
            findings.append(pattern.pattern)
    return findings


def assert_share_safe(text: str) -> None:
    findings = privacy_findings(text)
    if findings:
        raise ValueError(f"Privacy check failed: {', '.join(findings)}")

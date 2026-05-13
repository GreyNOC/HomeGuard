#!/usr/bin/env python3
"""HomeGuard release security preflight.

This script is intentionally lightweight and dependency-free so it can run in CI
before packaged release jobs. It verifies that the high-value hardening controls
that protect HomeGuard users are still present, and it catches accidental secret
commits in common text files.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\baws_access_key_id\s*=\s*[^\s]+", re.IGNORECASE),
    re.compile(r"\baws_secret_access_key\s*=\s*[^\s]+", re.IGNORECASE),
    re.compile(r"\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{20,}", re.IGNORECASE),
    re.compile(r"HOMEGUARD_SIGN_CERT_PASSWORD\s*[:=]\s*['\"]?[^\s]+", re.IGNORECASE),
    re.compile(r"HOMEGUARD_NVD_API_KEY\s*[:=]\s*['\"]?[A-Za-z0-9_./+=-]{20,}", re.IGNORECASE),
]

PLACEHOLDER_SECRET_VALUES = {
    "your-certificate-password",
    "certificate-password",
    "your-password",
    "password-placeholder",
    "example-password",
    "your-api-key",
    "api-key-placeholder",
    "example-api-key",
    "your-token",
    "token-placeholder",
    "example-token",
    "dummy-token",
    "dummy-secret",
    "not-a-real-secret",
    "test-secret",
    "test-token",
    "test-password",
}

PLACEHOLDER_LINE_MARKERS = (
    "example",
    "placeholder",
    "dummy",
    "not-a-real",
    "your-",
    "<",
    "...",
)

INTENTIONAL_TEST_FIXTURE_MARKERS = (
    "-----begin private key-----abc-----end private key-----",
    "token=abcd",
)

TEXT_SUFFIXES = {
    ".bat",
    ".cmd",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".ps1",
    ".py",
    ".toml",
    ".txt",
    ".xml",
    ".yml",
    ".yaml",
}

SKIP_DIRS = {
    ".git",
    ".pytest_cache",
    ".venv",
    ".venv-build",
    "build",
    "dist",
    "node_modules",
    "__pycache__",
}

REQUIRED_MARKERS = {
    "dashboard LAN bind refusal": (
        ROOT / "src" / "greynoc_homeguard" / "dashboard.py",
        ["Refusing to bind the HomeGuard dashboard", "secrets.token_urlsafe", "Cache-Control", "no-store"],
    ),
    "network active probe private/local restriction": (
        ROOT / "src" / "greynoc_homeguard" / "network.py",
        ["active_probe_allowed", "target.is_private", "target.is_loopback", "target.is_link_local"],
    ),
    "Electron renderer isolation": (
        ROOT / "electron" / "main.js",
        ["contextIsolation: true", "nodeIntegration: false", "sandbox: true", "will-navigate"],
    ),
    "report CSP and escaping": (
        ROOT / "src" / "greynoc_homeguard" / "reports.py",
        ["Content-Security-Policy", "html.escape", "default-src 'none'"],
    ),
    "privacy redaction": (
        ROOT / "src" / "greynoc_homeguard" / "privacy.py",
        ["PRIVATE KEY", "SECRET_ASSIGNMENT", "mask_identifier", "scrub_report"],
    ),
    "firewall scoped rule prefix": (
        ROOT / "src" / "greynoc_homeguard" / "firewall.py",
        ["RULE_PREFIX = \"HomeGuard Block\"", "localport=", "advfirewall"],
    ),
}


def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="ignore")


def fail(message: str) -> None:
    print(f"[FAIL] {message}", file=sys.stderr)
    raise SystemExit(1)


def check_required_markers() -> None:
    for name, (path, markers) in REQUIRED_MARKERS.items():
        if not path.exists():
            fail(f"Missing expected file for {name}: {path.relative_to(ROOT)}")
        text = read_text(path)
        missing = [marker for marker in markers if marker not in text]
        if missing:
            fail(f"Missing hardening marker(s) for {name}: {', '.join(missing)}")
        print(f"[OK] {name}")


def iter_text_files() -> list[Path]:
    files: list[Path] = []
    for base, dirs, filenames in os.walk(ROOT):
        dirs[:] = [dirname for dirname in dirs if dirname not in SKIP_DIRS]
        base_path = Path(base)
        for filename in filenames:
            path = base_path / filename
            if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"GNHL", "Dockerfile"}:
                files.append(path)
    return files


def _line_has_placeholder_secret(line: str) -> bool:
    clean = line.strip().strip("'\"").lower()
    if not clean:
        return False
    if any(value in clean for value in PLACEHOLDER_SECRET_VALUES):
        return True
    if any(marker in clean for marker in PLACEHOLDER_LINE_MARKERS):
        if any(token in clean for token in ("password", "secret", "token", "api_key", "api-key", "nvd_api_key")):
            return True
    return False


def _line_is_intentional_test_fixture(path: Path, line: str) -> bool:
    """Allow explicit redaction-test fixtures without ignoring the whole tests tree."""

    try:
        rel = path.relative_to(ROOT)
    except ValueError:
        return False
    if not rel.parts or rel.parts[0] != "tests":
        return False
    clean = line.lower()
    return any(marker in clean for marker in INTENTIONAL_TEST_FIXTURE_MARKERS)


def check_secret_patterns() -> None:
    findings: list[str] = []
    for path in iter_text_files():
        rel = path.relative_to(ROOT)
        for line_number, line in enumerate(read_text(path).splitlines(), start=1):
            if _line_has_placeholder_secret(line) or _line_is_intentional_test_fixture(path, line):
                continue
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append(f"{rel}:{line_number}")
                    break
    if findings:
        fail("Potential committed secret(s) found in: " + ", ".join(sorted(findings)))
    print("[OK] no obvious committed secrets in tracked text files")


def check_release_files() -> None:
    required = [
        ROOT / "docs" / "security" / "SECURITY_REVIEW.md",
        ROOT / "docs" / "release" / "RELEASE_CHECKLIST.md",
        ROOT / "package-lock.json",
        ROOT / "pyproject.toml",
    ]
    missing = [str(path.relative_to(ROOT)) for path in required if not path.exists()]
    if missing:
        fail("Missing release/security file(s): " + ", ".join(missing))
    print("[OK] release/security files present")


def main() -> int:
    check_required_markers()
    check_secret_patterns()
    check_release_files()
    print("HomeGuard security preflight passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

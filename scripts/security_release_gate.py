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
import subprocess
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
    "-----begin private " + "key-----abc-----end private key-----",
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


def _tracked_files() -> list[Path]:
    try:
        result = subprocess.run(
            ["git", "ls-files", "-z"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return []
    files: list[Path] = []
    for raw in result.stdout.split(b"\0"):
        if not raw:
            continue
        rel = Path(raw.decode("utf-8", errors="ignore"))
        files.append(ROOT / rel)
    return files


def iter_text_files() -> list[Path]:
    tracked = _tracked_files()
    if tracked:
        files = tracked
    else:
        files = []
        for base, dirs, filenames in os.walk(ROOT):
            dirs[:] = [dirname for dirname in dirs if dirname not in SKIP_DIRS]
            base_path = Path(base)
            files.extend(base_path / filename for filename in filenames)

    text_files: list[Path] = []
    for path in files:
        rel_parts = path.relative_to(ROOT).parts if path.is_relative_to(ROOT) else path.parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"GNHL", "Dockerfile"}:
            text_files.append(path)
    return sorted(text_files)


def _line_has_placeholder_secret(line: str) -> bool:
    clean = line.strip().strip("'\"").lower()
    if not clean:
        return False
    if any(value in clean for value in PLACEHOLDER_SECRET_VALUES):
        return True
    # GitHub Actions context references (${{ secrets.X }}, ${{ env.X }}, ${{ inputs.X }})
    # are the correct, secure way to consume secrets in workflows. They are not
    # committed credentials and must not trip the secret detector.
    if "${{ secrets." in clean or "${{ env." in clean or "${{ inputs." in clean:
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


def check_no_mock_dashboard() -> None:
    """Ensure the Overview dashboard ships live placeholders, not baked-in demo data.

    The Overview is a live, state-driven dashboard. Production renderer code must
    not display sample values (fake device/alert/update counts, a hardcoded
    greeting, or design-mockup copy) -- every number must come from real
    HomeGuard state at runtime. This catches the obvious regressions where a
    static mockup leaks into the packaged renderer.
    """

    renderer = ROOT / "electron" / "renderer"
    index_path = renderer / "index.html"
    overview_path = renderer / "overview.js"
    if not index_path.exists() or not overview_path.exists():
        # Overview is optional; nothing to check if it is not present.
        print("[OK] overview dashboard live-data check (no overview present)")
        return
    index_html = read_text(index_path)
    overview_js = read_text(overview_path)

    # 1. Stat-card values must start as live placeholders, never hardcoded numbers.
    for card_id in ("ovRiskValue", "ovDeviceCount", "ovAlertCount", "ovUpdateCount"):
        match = re.search(rf'id="{card_id}"[^>]*>([^<]*)<', index_html)
        if match is None:
            fail(f"Overview stat card #{card_id} is missing from index.html")
        initial = match.group(1).strip()
        if any(ch.isdigit() for ch in initial):
            fail(f"Overview stat card #{card_id} ships a hardcoded value '{initial}' instead of a live placeholder")

    # 2. The greeting must be computed at runtime, not frozen in markup.
    for phrase in ("Good morning", "Good afternoon", "Good evening", "Good night"):
        if phrase in index_html:
            fail(f"Greeting '{phrase}' is hardcoded in index.html; it must be set dynamically by overview.js")
    if "greetingForHour" not in overview_js:
        fail("overview.js is missing the dynamic time-of-day greeting (greetingForHour)")

    # 3. Known design-mockup literals must never ship in the renderer.
    mock_markers = (
        "18 devices",
        "Identify 2 unknown devices",
        "Review 3 security alerts",
        "Update 2 devices",
        "Your network is protected.</",
    )
    for marker in mock_markers:
        if marker in index_html or marker in overview_js:
            fail(f"Mock dashboard literal '{marker}' found in renderer; dashboard values must come from real state")

    print("[OK] overview dashboard uses live state (no mock constants)")


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
    check_no_mock_dashboard()
    check_release_files()
    print("HomeGuard security preflight passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

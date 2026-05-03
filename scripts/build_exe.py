"""Shared build helpers used by the Electron build pipeline.

Provides version bumping, privacy auditing, dev-artifact cleanup, version
info generation, and Authenticode signing utilities. Authenticode signing
runs when a signing certificate is provided through environment variables:

  HOMEGUARD_SIGN_CERT_PATH       path to a .pfx/.p12 code-signing certificate
  HOMEGUARD_SIGN_CERT_PASSWORD   password for the certificate file

or:

  HOMEGUARD_SIGN_CERT_SHA1       thumbprint of a cert in the Windows cert store

Set HOMEGUARD_REQUIRE_SIGNING=1 to fail the build if signing cannot run.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

APP_NAME = "HomeGuard"
COMPANY_NAME = "GreyNOC"
PRODUCT_NAME = "HomeGuard"
TIMESTAMP_URL = "http://timestamp.digicert.com"
TEXT_SUFFIXES = {
    ".bat",
    ".cfg",
    ".css",
    ".csv",
    ".html",
    ".ini",
    ".js",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".spec",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
AUDIT_EXCLUDE_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".venv",
    ".venv-build",
    "__pycache__",
    "build",
    "dist",
    "FInished Project",
}
AUDIT_EXCLUDE_FILES = {
    f"{APP_NAME}.spec",
    "HomeGuard-Core.spec",
}


def _sensitive_tokens(repo: Path) -> list[str]:
    tokens = {
        str(Path.home()),
        str(repo),
        os.environ.get("USERNAME", ""),
        os.environ.get("USERPROFILE", ""),
    }
    return sorted({token for token in tokens if len(token) >= 5}, key=len, reverse=True)


def _remove_dev_artifacts(repo: Path) -> None:
    generated_names = {"__pycache__", ".pytest_cache"}

    def remove_tree(path: Path) -> None:
        def onerror(func, target, _exc_info) -> None:
            try:
                os.chmod(target, stat.S_IWRITE)
                func(target)
            except OSError:
                pass

        shutil.rmtree(path, onerror=onerror)

    for root, dirs, _files in os.walk(repo):
        root_path = Path(root)
        if set(root_path.relative_to(repo).parts) & AUDIT_EXCLUDE_DIRS:
            dirs[:] = []
            continue
        for dirname in list(dirs):
            if dirname in AUDIT_EXCLUDE_DIRS and dirname not in generated_names:
                dirs.remove(dirname)
                continue
            if dirname in generated_names or dirname.startswith("pytest-cache-files-"):
                remove_tree(root_path / dirname)
                dirs.remove(dirname)
    for egg_info in (repo / "src").glob("*.egg-info"):
        remove_tree(egg_info)
    for spec_file in (repo / f"{APP_NAME}.spec", repo / "HomeGuard-Core.spec"):
        if spec_file.exists():
            try:
                os.chmod(spec_file, stat.S_IWRITE)
            except OSError:
                pass
            try:
                spec_file.unlink()
            except OSError:
                print(f"Cleanup skipped locked generated spec: {spec_file.name}")


def _privacy_audit(repo: Path) -> None:
    tokens = _sensitive_tokens(repo)
    findings: list[str] = []
    for root, dirs, files in os.walk(repo, onerror=lambda error: print(f"Privacy audit skipped: {error}")):
        dirs[:] = [name for name in dirs if name not in AUDIT_EXCLUDE_DIRS]
        root_path = Path(root)
        for name in files:
            path = root_path / name
            if path.name in AUDIT_EXCLUDE_FILES:
                continue
            relative_parts = set(path.relative_to(repo).parts)
            if relative_parts & AUDIT_EXCLUDE_DIRS:
                continue
            if path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for token in tokens:
                if token and token in text:
                    findings.append(f"{path.relative_to(repo)} contains development token: {token}")
    if findings:
        joined = "\n  ".join(findings[:20])
        raise RuntimeError(f"Privacy audit failed:\n  {joined}")
    print("Privacy audit passed: no personal development paths found in source artifacts.")


def _read_version(pyproject: Path) -> str:
    text = pyproject.read_text(encoding="utf-8")
    match = re.search(r'^version\s*=\s*"(\d+)\.(\d+)\.(\d+)"', text, re.MULTILINE)
    if not match:
        raise RuntimeError(f"Could not find project version in {pyproject}")
    return ".".join(match.groups())


def _bump_patch_version(repo: Path) -> str:
    pyproject = repo / "pyproject.toml"
    init_file = repo / "src" / "greynoc_homeguard" / "__init__.py"
    current = _read_version(pyproject)
    major, minor, patch = (int(part) for part in current.split("."))
    new_version = f"{major}.{minor}.{patch + 1}"

    py_text = pyproject.read_text(encoding="utf-8")
    py_text = re.sub(
        r'^version\s*=\s*"\d+\.\d+\.\d+"',
        f'version = "{new_version}"',
        py_text,
        count=1,
        flags=re.MULTILINE,
    )
    pyproject.write_text(py_text, encoding="utf-8")

    init_text = init_file.read_text(encoding="utf-8")
    init_text = re.sub(
        r'__version__\s*=\s*"\d+\.\d+\.\d+"',
        f'__version__ = "{new_version}"',
        init_text,
        count=1,
    )
    init_file.write_text(init_text, encoding="utf-8")
    print(f"Version bumped: {current} -> {new_version}")
    return new_version


def _version_tuple(version: str) -> str:
    parts = [int(part) for part in version.split(".")]
    while len(parts) < 4:
        parts.append(0)
    return ", ".join(str(part) for part in parts[:4])


def _write_version_info(repo: Path, version: str) -> Path:
    version_file = repo / "build" / "version_info.txt"
    version_file.parent.mkdir(parents=True, exist_ok=True)
    tuple_text = _version_tuple(version)
    version_file.write_text(
        f"""# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({tuple_text}),
    prodvers=({tuple_text}),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', '{COMPANY_NAME}'),
        StringStruct('FileDescription', '{PRODUCT_NAME} desktop application'),
        StringStruct('FileVersion', '{version}'),
        StringStruct('InternalName', '{APP_NAME}'),
        StringStruct('LegalCopyright', 'Copyright (c) {COMPANY_NAME}'),
        StringStruct('OriginalFilename', '{APP_NAME}.exe'),
        StringStruct('ProductName', '{PRODUCT_NAME}'),
        StringStruct('ProductVersion', '{version}')])
      ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""",
        encoding="utf-8",
    )
    return version_file


def _find_signtool() -> str | None:
    found = shutil.which("signtool.exe") or shutil.which("signtool")
    if found:
        return found
    roots = [
        Path(os.environ.get("ProgramFiles(x86)", "")) / "Windows Kits" / "10" / "bin",
        Path(os.environ.get("ProgramFiles", "")) / "Windows Kits" / "10" / "bin",
    ]
    for root in roots:
        if not root.exists():
            continue
        candidates = sorted(root.glob("**/x64/signtool.exe"), reverse=True)
        if candidates:
            return str(candidates[0])
    return None


def _sign_executable(output: Path, *, require_signing: bool) -> bool:
    cert_path = os.environ.get("HOMEGUARD_SIGN_CERT_PATH", "").strip()
    cert_password = os.environ.get("HOMEGUARD_SIGN_CERT_PASSWORD", "")
    cert_sha1 = os.environ.get("HOMEGUARD_SIGN_CERT_SHA1", "").strip()
    require_signing = require_signing or os.environ.get("HOMEGUARD_REQUIRE_SIGNING") == "1"

    if not cert_path and not cert_sha1:
        message = (
            "Signing skipped: set HOMEGUARD_SIGN_CERT_PATH and HOMEGUARD_SIGN_CERT_PASSWORD "
            "or HOMEGUARD_SIGN_CERT_SHA1 to sign as GreyNOC."
        )
        if require_signing:
            raise RuntimeError(message)
        print(message)
        return False

    signtool = _find_signtool()
    if not signtool:
        message = "Signing unavailable: signtool.exe was not found."
        if require_signing:
            raise RuntimeError(message)
        print(message)
        return False

    cmd = [signtool, "sign", "/fd", "SHA256", "/tr", TIMESTAMP_URL, "/td", "SHA256"]
    if cert_path:
        cmd.extend(["/f", cert_path])
        if cert_password:
            cmd.extend(["/p", cert_password])
    else:
        cmd.extend(["/sha1", cert_sha1])
    cmd.append(str(output))
    print("Signing:", output)
    subprocess.check_call(cmd)
    subprocess.check_call([signtool, "verify", "/pa", "/v", str(output)])
    print(f"Signed and verified: {output}")
    return True

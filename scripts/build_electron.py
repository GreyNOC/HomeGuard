"""Build the Windows Electron executable for HomeGuard."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from build_exe import (
    _bump_patch_version,
    _privacy_audit,
    _read_version,
    _remove_dev_artifacts,
    _sign_executable,
    _write_version_info,
)

APP_EXE_NAME = "HomeGuard.exe"
BACKEND_NAME = "HomeGuard-Core"


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build HomeGuard Electron for Windows.")
    parser.add_argument(
        "--no-version-bump",
        action="store_true",
        help="Build without bumping the patch version first.",
    )
    parser.add_argument(
        "--require-signing",
        action="store_true",
        help="Fail if Authenticode signing is unavailable or not configured.",
    )
    return parser.parse_args()


def _sync_node_package_version(repo: Path, version: str) -> None:
    for relative_path in ("package.json", "package-lock.json"):
        path = repo / relative_path
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            data["version"] = version
            packages = data.get("packages")
            if isinstance(packages, dict) and isinstance(packages.get(""), dict):
                packages[""]["version"] = version
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"Electron package version synchronized: {version}")


def _copy_tree(source: Path, target: Path) -> None:
    if target.exists():
        _remove_tree(target, required=False)
    shutil.copytree(source, target, dirs_exist_ok=True)


def _remove_tree(path: Path, *, required: bool = True) -> None:
    def onerror(func, target, _exc_info) -> None:
        try:
            os.chmod(target, 0o700)
            func(target)
        except OSError:
            if required:
                raise

    try:
        shutil.rmtree(path, onerror=onerror)
    except OSError:
        if required:
            raise
        print(f"Cleanup skipped locked folder: {path}")


def _build_backend(repo: Path, version: str, *, require_signing: bool) -> Path:
    entry = repo / "src" / "greynoc_homeguard" / "cli_launcher.py"
    if not entry.exists():
        raise RuntimeError(f"Missing CLI launcher: {entry}")

    temp_root = Path(tempfile.gettempdir()) / "HomeGuard" / "electron-backend"
    backend_work = temp_root / "work"
    backend_dist = temp_root / "dist"
    backend_spec = temp_root / "spec"
    resources_root = repo / "build" / "electron-resources"
    resources_backend = resources_root / "backend"
    version_file = _write_version_info(repo, version)

    for folder in (backend_work, backend_dist, backend_spec, resources_backend):
        if folder.exists():
            _remove_tree(folder, required=folder != resources_backend)
    backend_spec.mkdir(parents=True, exist_ok=True)
    resources_backend.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onedir",
        "--console",
        "--name",
        BACKEND_NAME,
        "--distpath",
        str(backend_dist),
        "--workpath",
        str(backend_work),
        "--specpath",
        str(backend_spec),
        "--version-file",
        str(version_file),
        "--collect-all",
        "reportlab",
        "--collect-all",
        "PIL",
        str(entry),
    ]
    print("Building Electron backend:", " ".join(str(part) for part in cmd))
    subprocess.check_call(cmd, cwd=repo)

    built_backend = backend_dist / BACKEND_NAME
    packaged_backend = resources_backend / BACKEND_NAME
    _copy_tree(built_backend, packaged_backend)

    exe_suffix = ".exe" if os.name == "nt" else ""
    backend_exe = packaged_backend / f"{BACKEND_NAME}{exe_suffix}"
    if os.name == "nt":
        _sign_executable(backend_exe, require_signing=require_signing)
    print(f"Electron backend ready: {backend_exe}")
    return backend_exe


def _build_electron_shell(repo: Path) -> Path:
    npm = shutil.which("npm.cmd") or shutil.which("npm")
    if not npm:
        raise RuntimeError("npm was not found. Install Node.js before building the Electron app.")
    cmd = [npm, "run", "electron:dist"]
    print("Building Electron shell:", " ".join(cmd))
    subprocess.check_call(cmd, cwd=repo)
    output = repo / "dist" / "electron" / "win-unpacked" / APP_EXE_NAME
    if not output.exists():
        raise RuntimeError(f"Expected Electron executable was not produced: {output}")
    return output


def main() -> int:
    args = _parse_args()
    repo = Path(__file__).resolve().parents[1]
    pyproject = repo / "pyproject.toml"

    _remove_dev_artifacts(repo)
    _privacy_audit(repo)

    version = _read_version(pyproject)
    if not args.no_version_bump and os.environ.get("HOMEGUARD_SKIP_VERSION_BUMP") != "1":
        version = _bump_patch_version(repo)
    else:
        print(f"Version unchanged: {version}")
    _sync_node_package_version(repo, version)

    _build_backend(repo, version, require_signing=args.require_signing)
    output = _build_electron_shell(repo)
    if os.name == "nt":
        _sign_executable(output, require_signing=args.require_signing)
    print(f"Built Electron app: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

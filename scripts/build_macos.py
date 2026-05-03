"""Build a macOS .app bundle for HomeGuard using PyInstaller.

Output: dist/macos/HomeGuard.app

Real distribution to other macOS machines requires Apple Developer signing
and notarization. See scripts/notarize_macos.sh for placeholder hooks.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def main() -> int:
    if sys.platform != "darwin":
        print("build_macos.py must be run on macOS.", file=sys.stderr)
        return 1

    repo = Path(__file__).resolve().parents[1]
    entry = repo / "src" / "greynoc_homeguard" / "gui_launcher.py"
    dist_root = repo / "dist"
    macos_dist = dist_root / "macos"
    build = repo / "build"

    if not entry.exists():
        print(f"Missing GUI launcher: {entry}", file=sys.stderr)
        return 1

    for folder in (macos_dist, build):
        if folder.exists():
            shutil.rmtree(folder)
    macos_dist.mkdir(parents=True, exist_ok=True)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        "HomeGuard",
        "--distpath",
        str(macos_dist),
        "--workpath",
        str(build),
        "--collect-all",
        "reportlab",
        str(entry),
    ]
    print("Running:", " ".join(str(part) for part in cmd))
    subprocess.check_call(cmd, cwd=repo)
    app = macos_dist / "HomeGuard.app"
    print(f"Built: {app}")
    print(
        "Note: this build is unsigned. To distribute to other Macs, sign and "
        "notarize with your Apple Developer credentials. See "
        "scripts/notarize_macos.sh for placeholder hooks."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

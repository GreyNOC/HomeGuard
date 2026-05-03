"""Placeholder for the macOS HomeGuard build.

The PyInstaller-based Tkinter build path has been retired in favor of the
Electron frontend. A macOS Electron build is not yet wired up; running this
script is a no-op until that pipeline lands.
"""

from __future__ import annotations

import sys


def main() -> int:
    print(
        "build_macos.py: the PyInstaller GUI build was removed. "
        "A macOS Electron build pipeline is not yet implemented.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

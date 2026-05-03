#!/usr/bin/env bash
# GreyNOC HomeGuard - macOS build script
# Builds dist/macos/GreyNOC HomeGuard.app via PyInstaller.

set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
    echo "scripts/compile_macos.sh must be run on macOS." >&2
    exit 1
fi

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

if ! command -v python3 >/dev/null 2>&1; then
    echo "python3 is required. Install Python 3.10+ from https://www.python.org/" >&2
    exit 1
fi

if [[ ! -d ".venv-build" ]]; then
    echo "Creating build virtual environment..."
    python3 -m venv .venv-build
fi

# shellcheck disable=SC1091
source .venv-build/bin/activate
python -m pip install --upgrade pip
python -m pip install -e . pyinstaller

python scripts/build_macos.py

echo
echo "Build complete: dist/macos/GreyNOC HomeGuard.app"
echo "Real distribution requires Apple Developer signing and notarization."
echo "See scripts/notarize_macos.sh for placeholder hooks."

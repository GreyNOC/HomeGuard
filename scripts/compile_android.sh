#!/usr/bin/env bash
# GreyNOC HomeGuard - Android (Kivy + Buildozer) build script.
#
# Run on Linux/macOS, or from Windows through WSL using compile_android.bat.
# Requires Buildozer and its dependencies (Java 17, Android SDK, Android NDK,
# autotools, cython, etc.). On first run Buildozer can download SDK/NDK
# automatically; after that, builds are incremental.

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

MODE="${1:-debug}"

usage() {
    cat <<'EOF'
Usage: ./scripts/compile_android.sh [debug|release|aab|clean]

Build outputs are copied to dist/android/.

  debug    Build a debug APK. This is the default.
  release  Build a release APK. Requires signing configuration for real use.
  aab      Build a Play Store-style Android App Bundle when buildozer.spec is configured.
  clean    Remove Buildozer's mobile/android build artifacts.
EOF
}

case "$MODE" in
    debug|release|aab|clean)
        ;;
    -h|--help|help)
        usage
        exit 0
        ;;
    *)
        echo "ERROR: Unknown Android build mode: $MODE" >&2
        usage >&2
        exit 64
        ;;
esac

UNAME="$(uname || echo unknown)"
case "$UNAME" in
    Linux|Darwin)
        ;;
    *)
        echo "Android builds via Buildozer require Linux or macOS." >&2
        echo "On Windows, use WSL2 (Ubuntu) and re-run this script there." >&2
        exit 1
        ;;
esac

if ! command -v buildozer >/dev/null 2>&1; then
    echo "ERROR: 'buildozer' is not installed." >&2
    echo "Install with: python3 -m pip install buildozer cython" >&2
    echo "Then install the system dependencies described at" >&2
    echo "  https://buildozer.readthedocs.io/en/latest/installation.html" >&2
    exit 2
fi

if ! command -v java >/dev/null 2>&1; then
    echo "ERROR: 'java' is not installed. Install OpenJDK 17 and re-run." >&2
    exit 3
fi

cd mobile/android
case "$MODE" in
    debug)
        buildozer android debug
        ;;
    release)
        buildozer android release
        ;;
    aab)
        if ! grep -Eq '^[[:space:]]*android\.release_artifact[[:space:]]*=[[:space:]]*aab' buildozer.spec; then
            echo "ERROR: AAB builds require this line in mobile/android/buildozer.spec:" >&2
            echo "  android.release_artifact = aab" >&2
            echo "Uncomment/configure it, add signing settings, then re-run." >&2
            exit 4
        fi
        buildozer android release
        ;;
    clean)
        buildozer android clean
        exit 0
        ;;
esac

cd "$REPO_ROOT"
mkdir -p dist/android
find mobile/android/bin -maxdepth 1 \( -name '*.apk' -o -name '*.aab' \) -exec cp {} dist/android/ \; 2>/dev/null || true

echo
echo "Android $MODE build complete. Artifact(s):"
ls -la dist/android/ || true
echo
echo "Note: signing/distribution to the Play Store requires a release keystore"
echo "and a release/AAB build configuration (see mobile/android/README.md)."

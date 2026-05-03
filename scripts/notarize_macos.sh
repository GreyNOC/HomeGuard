#!/usr/bin/env bash
# GreyNOC HomeGuard - macOS signing & notarization placeholders.
#
# Real distribution to other Macs requires:
#   1. An Apple Developer ID Application certificate in your login keychain.
#   2. A notarization-capable app-specific password OR a notarytool keychain profile.
#   3. Your team ID and developer Apple ID.
#
# This script is intentionally a placeholder that fails clearly when those
# variables are not set. Fill in values, or pass them in via environment, and
# uncomment the codesign / notarytool / staple lines.

set -euo pipefail

if [[ "$(uname)" != "Darwin" ]]; then
    echo "notarize_macos.sh must be run on macOS." >&2
    exit 1
fi

APP_PATH="${APP_PATH:-dist/macos/GreyNOC HomeGuard.app}"
APPLE_ID="${APPLE_ID:-}"
TEAM_ID="${TEAM_ID:-}"
APP_PASSWORD="${APP_PASSWORD:-}"
KEYCHAIN_PROFILE="${KEYCHAIN_PROFILE:-}"
DEV_ID_APP="${DEV_ID_APP:-Developer ID Application: YOUR NAME (TEAMID)}"

if [[ ! -d "$APP_PATH" ]]; then
    echo "App bundle not found at: $APP_PATH" >&2
    echo "Build it first with ./scripts/compile_macos.sh" >&2
    exit 2
fi

if [[ -z "$APPLE_ID" || -z "$TEAM_ID" ]]; then
    echo "ERROR: APPLE_ID and TEAM_ID must be set to sign and notarize." >&2
    echo "Example:" >&2
    echo "  APPLE_ID=you@example.com TEAM_ID=ABCD123456 KEYCHAIN_PROFILE=hg-notary ./scripts/notarize_macos.sh" >&2
    exit 3
fi

if [[ -z "$KEYCHAIN_PROFILE" && -z "$APP_PASSWORD" ]]; then
    echo "ERROR: provide either KEYCHAIN_PROFILE (notarytool keychain profile) or APP_PASSWORD (app-specific password)." >&2
    exit 4
fi

echo "App:           $APP_PATH"
echo "Apple ID:      $APPLE_ID"
echo "Team ID:       $TEAM_ID"
echo "Identity:      $DEV_ID_APP"

# Real signing/notarization commands. Uncomment and customize after filling in
# your credentials. Left commented by default so this script does not pretend
# to sign without real Apple credentials.
#
# codesign --force --deep --options runtime --timestamp \
#     --sign "$DEV_ID_APP" "$APP_PATH"
#
# /usr/bin/ditto -c -k --keepParent "$APP_PATH" "$APP_PATH.zip"
#
# if [[ -n "$KEYCHAIN_PROFILE" ]]; then
#     xcrun notarytool submit "$APP_PATH.zip" \
#         --keychain-profile "$KEYCHAIN_PROFILE" --wait
# else
#     xcrun notarytool submit "$APP_PATH.zip" \
#         --apple-id "$APPLE_ID" --team-id "$TEAM_ID" \
#         --password "$APP_PASSWORD" --wait
# fi
#
# xcrun stapler staple "$APP_PATH"

echo
echo "This script is intentionally a placeholder. Edit it and uncomment the"
echo "codesign / notarytool / stapler lines once you have provided credentials."

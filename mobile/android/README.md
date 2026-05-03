# HomeGuard - Android Mobile Build

This folder contains the Kivy-based mobile build of HomeGuard.
The mobile app intentionally focuses on the protection-status experience
(status cards, scan, definition update, view results) rather than
duplicating the full desktop GUI.

## Why a separate mobile app?

The desktop GUI uses Tkinter. Tkinter does not deploy cleanly to Android.
Kivy is a realistic Python mobile framework that can be packaged with
Buildozer into an APK / AAB.

## Build prerequisites

The Android build pipeline must run on Linux or macOS. It does **not**
work on Windows.

You will need:

- Python 3.10+
- Java 17 (OpenJDK)
- Android SDK + Android NDK (Buildozer can install these on first run)
- Buildozer system dependencies: see https://buildozer.readthedocs.io
- `pip install buildozer cython`

## Build

From the repo root:

```bash
bash compile_android.sh
```

The script:

1. Verifies you are on Linux or macOS.
2. Verifies Buildozer is installed.
3. Runs `buildozer android debug` from `mobile/android/`.
4. Copies the resulting APK to `dist/android/`.

You can also choose the build mode explicitly:

```bash
bash compile_android.sh debug
bash compile_android.sh release
bash compile_android.sh aab
```

On Windows, double-click or run the WSL wrapper:

```text
compile_android.bat
compile_android.bat release
compile_android.bat aab
```

The `aab` mode requires `android.release_artifact = aab` and release signing
settings in `buildozer.spec`.

## Android limitations

- ARP table access is restricted on modern Android. The mobile build relies
  on socket-based reachability checks.
- ICMP ping usually requires elevated capabilities on Android and is not
  available to a normal app.
- Some scans require local network permissions or the user opening the app
  while connected to a private WiFi network.

## Permissions

The mobile build requests:

- INTERNET
- ACCESS_NETWORK_STATE
- ACCESS_WIFI_STATE
- CHANGE_WIFI_MULTICAST_STATE

It does **not** request invasive permissions like contacts, SMS, or
location.

## Real release distribution

Real release distribution requires:

- A keystore for code signing.
- A play-console-ready AAB (set `android.release_artifact = aab` in
  `buildozer.spec`).
- Apple Developer (iOS) or Google Play Developer (Android) accounts.

See the placeholders in `buildozer.spec`.

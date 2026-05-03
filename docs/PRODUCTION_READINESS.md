# Production Readiness Plan

HomeGuard is close to a usable beta, but production release should be treated as a security product launch rather than a demo packaging exercise.

## Completed in this pass

- First-run setup guide in the desktop app, with skip and reopen controls.
- Persistent app settings for onboarding state and scan defaults.
- Clearer possible-intrusion findings for unknown devices with remote-access exposure.
- Service-cluster detection for devices exposing multiple administration or sharing ports.
- Reduced false positives by requiring RDP/port 3389 evidence before showing the Windows Remote Desktop hint.
- Added higher-signal active checks for unusual backdoor/debug/bot-style ports.
- Added reversible local-port fixes through Windows Firewall for findings on the computer running HomeGuard.
- Focused tests for onboarding settings and intrusion-oriented detection rules.

## Release gates

- Sign Windows and macOS builds, and document publisher identity.
- Add smoke tests that launch the packaged GUI and run a passive scan with mocked sensors.
- Add a privacy statement that explains local-only scanning, definition downloads, logs, reports, and retained known-device data.
- Add an in-app disclaimer that findings are indicators, not proof of compromise.
- Add structured crash/error reporting that writes local diagnostics without uploading data by default.
- Pin build dependencies and generate reproducible release artifacts.
- Review all generated copy for precise security wording before release.

## Detection roadmap

- Add router configuration checks where supported: UPnP enabled, unexpected port forwards, weak encryption modes, and guest-network availability.
- Add optional vendor OUI enrichment from a locally cached database.
- Add change detection between scans: device disappeared, MAC changed for same hostname/IP, hostname changed for same MAC, and new risky port appeared.
- Add a guided incident flow for possible unauthorized devices: confirm, quarantine, router-block instructions, password-change checklist, and follow-up scan.
- Add optional endpoint checks for the local computer: Windows Defender status, firewall profile, listening processes, startup entries, and suspicious autoruns.
- Add signed privilege elevation UX for local firewall actions, with clear before/after verification scans.
- Add signed/offline security definition bundles for users without direct internet access.

## UX cleanup

- Reduce dense toolbar actions over time by moving report actions into a report menu.
- Add empty states for first launch, no devices, no history, and update failure.
- Add a post-scan review flow that asks the user to trust, label, or quarantine unknown devices.
- Keep language specific: say "possible unauthorized device" or "remote-access exposure" instead of pretending the scan can prove a hacker is present.

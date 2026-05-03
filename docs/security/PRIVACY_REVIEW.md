# HomeGuard Privacy Review

Review date: 2026-05-03

## Data Stored Locally

HomeGuard stores these files under the user's local app-data area:

- known devices
- scan history
- security definitions
- reports
- local logs
- schedule settings

No cloud telemetry, analytics, remote access, or hosted reporting service is used.

## V1 Privacy Controls

- Generated reports are scrubbed before export.
- Local filesystem paths are replaced with `local app data`.
- Environment assignments such as `HOME=` and `USERNAME=` are redacted.
- Private-key blocks and secret-shaped assignments are redacted.
- Full MAC addresses are masked as `device id ending xx:yy`.
- Electron UI shows safe labels such as `Latest report saved locally`.
- Logs are redacted on write and redacted again before display.

## Share-Safe Report Checks

Tests validate exported text artifacts do not contain:

- `C:\Users\`
- `/Users/`
- `AppData`
- `HOME=`
- `USERNAME=`
- private-key text
- token-shaped strings
- full MAC addresses

PDF generation uses the same scrubbed report object as HTML/JSON/CSV output.

## Remaining Privacy Considerations

Reports still include private LAN IP addresses and device names because those are central to a network protection report. Full hardware identifiers are masked. Users should still treat reports as support/security material, not public documents.

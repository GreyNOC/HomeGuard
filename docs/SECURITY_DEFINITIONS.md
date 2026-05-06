# Security Definitions

HomeGuard keeps a local security-definition database in the user's app-data folder instead of making the user choose internal files. Findings are review indicators, not proof that a device is compromised.

Stored data includes:

- risky service and port definitions
- device profile hints for routers, cameras, NAS devices, and Windows remote access
- CISA Known Exploited Vulnerabilities (KEV) records
- recent NVD CVE records
- source update status and timestamps

## Local storage

Known devices and security definitions are stored automatically.

Windows:

```text
%LOCALAPPDATA%\GreyNOC\HomeGuard\known_devices.json
%LOCALAPPDATA%\GreyNOC\HomeGuard\definitions\security_definitions.json
```

macOS:

```text
~/Library/Application Support/GreyNOC/HomeGuard/
```

Linux:

```text
~/.local/share/homeguard/
```

## GUI workflow

The GUI has a Protection Center with an Update Definitions button. Baseline selection was removed. The known-device database is shown for transparency but is not something the user needs to pick.

## CLI workflow

```bash
GNHL --definitions-status
GNHL --update-definitions --nvd-days 30
GNHL --scan
```

## Notes

HomeGuard does not claim a device is definitely vulnerable just because a CVE product name matches a home-network device. Versionless network discovery cannot prove exact firmware versions. Those findings are presented as patch-priority hints.

NVD notice required by NIST:

```text
This product uses data from the NVD API but is not endorsed or certified by the NVD.
```

# PowerSploit Resistance

HomeGuard's PowerSploit resistance feature is defensive only. It does not run
PowerSploit, import PowerSploit, download offensive tooling, create payloads,
dump credentials, bypass security controls, or exploit Windows misconfigurations.

The feature adds two layers:

- Static endpoint indicators for PowerSploit-style artifact names and related
  PowerShell behavior in process command lines, downloaded script content,
  startup entries, and sampled memory strings.
- A passive Windows privilege-escalation audit for common hardening gaps that
  tools like Invoke-PrivescAudit often check.

## What HomeGuard Checks

Endpoint signature coverage includes defensive detection for credential theft
artifacts, process dump strings, service abuse names, DLL hijack risk names,
shadow copy and raw disk access names, surveillance names, persistence names,
PowerShell obfuscation markers, recon markers, and destructive or recovery-impacting
behavior strings.

The Windows audit checks:

- AlwaysInstallElevated policy state.
- AutoLogon configuration and saved-secret indicators.
- Known unattended install file locations.
- Bounded Group Policy Preferences cache locations.
- Known IIS and web application configuration locations.
- Unquoted service paths.
- Service executable and directory writability.
- Service permissions when they can be safely inspected.
- Scheduled task executable paths that are writable or in risky locations.
- User-writable directories in PATH.
- Sensitive enabled Windows privileges visible to the current account.
- PowerShell v2 availability when Windows exposes it safely.
- PowerShell script block logging, module logging, and transcription policy state.
- LSASS protection and Credential Guard policy state.
- Defender real-time, behavior, script, cloud, and tamper-protection status where available.

## Admin Rights

The audit is designed to run without administrator rights. Some Windows security
settings are only partially readable from a standard account. When HomeGuard
cannot inspect a setting, it records partial-result metadata instead of failing
the scan.

Administrator rights can improve visibility for service security descriptors,
Defender policy state, LSASS protection, Credential Guard, and some PowerShell
feature checks. Admin rights are not required for HomeGuard to report what it
can safely see.

## Logging and Visibility

HomeGuard can only detect artifacts that are visible in local process command
lines, startup entries, downloaded files, bounded configuration locations, or
readable memory samples. Best results come from Windows auditing and endpoint
telemetry such as:

- PowerShell script block logging.
- PowerShell module logging.
- PowerShell transcription.
- Process creation command-line auditing.
- Sysmon or managed endpoint telemetry for process, file, and registry events.

## Hardening Checklist

- Enable Microsoft Defender cloud-delivered protection.
- Enable Defender Tamper Protection.
- Enable PowerShell script block logging.
- Enable process command-line auditing.
- Disable PowerShell v2.
- Disable AlwaysInstallElevated in both machine and user policy.
- Disable AutoLogon unless the device is intentionally kiosk-style and physically controlled.
- Review local administrators and remove unnecessary admin membership.
- Lock down service executable paths and service directories.
- Lock down scheduled task executable paths.
- Enable LSASS protection where supported.
- Enable Credential Guard where supported.
- Use standard user accounts for daily work.
- Keep offline or protected backups and test restore paths.

## Report and Assistant Behavior

Endpoint and Windows hardening findings appear in the normal HomeGuard reports.
The desktop assistant answers PowerSploit resistance questions from the latest
report and groups relevant findings into credential theft, privilege escalation,
persistence, PowerShell abuse, surveillance, shadow copy/raw disk, recon, and
service or DLL hijack risk.

If no report exists, run a HomeGuard scan first so the assistant has local
evidence to summarize.

---
name: Release checklist
about: Track a signed Windows HomeGuard release through every gate.
title: "Release: HomeGuard v<X.Y.Z>"
labels: ["release"]
---

## Release metadata

- Version: `vX.Y.Z`
- Release branch: `release/vX.Y.Z`
- Final artifact: `dist\installer\HomeGuard-Setup-vX.Y.Z.exe`
- SHA-256 checksum:

## Pre-flight

- [ ] Version is consistent across all of:
  - `pyproject.toml`
  - `package.json`
  - `package-lock.json`
  - `src/greynoc_homeguard/__init__.py` (`__version__`)
- [ ] `Security Gates` GitHub Actions workflow is green on the release commit.
- [ ] No certificates, PFX/P12 files, signing logs, secrets, generated
      installers, or local user paths are committed to the release branch.

## Build

- [ ] Clean Windows 10/11 release workstation prepared
      (Python 3.10+, Node.js/npm, Inno Setup 6, GreyNOC code-signing cert).
- [ ] Signing configured through secure local storage or release secrets
      (no certs/passwords in the repo).
- [ ] Built with:
      `powershell -NoProfile -File scripts\build_windows_installer.ps1`
- [ ] Installer was signed by GreyNOC (Authenticode `Valid`, signer subject
      contains `GreyNOC`).

## Release gate

- [ ] `powershell -NoProfile -File scripts\release_gate.ps1` passed.
- [ ] SHA-256 checksum of the final installer was recorded above.

## Clean-VM verification

- [ ] Clean Windows VM install of the signed installer succeeded.
- [ ] Clean Windows VM uninstall of the installed app succeeded.
- [ ] Passive scan tested end-to-end.
- [ ] Active scan tested and confirmed opt-in only, bounded to private/local
      networks.
- [ ] Report privacy checked: no `C:\Users\`, `/Users/`, `AppData`, env vars,
      private keys, or tokens in generated reports.
- [ ] Dashboard LAN mode requires explicit user action and uses a tokenized
      per-session URL.
- [ ] AI bridge is sterile/offline unless explicitly configured.
- [ ] Admin relaunch is user-triggered only.

## Publish

- [ ] No secrets, certificates, signing logs, or generated artifacts were
      committed during the release.
- [ ] Release notes match the exact signed artifact and SHA-256 checksum.
- [ ] Signed git tag created and pushed:
      `git tag -s vX.Y.Z -m "HomeGuard vX.Y.Z" && git push origin vX.Y.Z`

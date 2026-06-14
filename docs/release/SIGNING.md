# Windows code signing

HomeGuard's release workflow (`.github/workflows/windows-release.yml`) builds a
Windows installer and a portable EXE and publishes them to a GitHub release when
a `vX.Y.Z` tag is pushed. It supports three signing modes and picks one
automatically:

| Mode | When it's used | Result |
| --- | --- | --- |
| **signpath** | `SIGNPATH_API_TOKEN` secret **and** `SIGNPATH_ORGANIZATION_ID` variable are set | Authenticode-signed, no SmartScreen warning |
| **pfx** | `HOMEGUARD_SIGN_CERT_BASE64` + `HOMEGUARD_SIGN_CERT_PASSWORD` secrets are set | Authenticode-signed with the GreyNOC certificate |
| **unsigned** | nothing is configured (default) | Unsigned build + `SHA256SUMS.txt`; ships, but Windows SmartScreen warns on first run |

Precedence is SignPath → PFX → unsigned. **The release never fails just because
signing is unconfigured** — it falls back to an unsigned build with checksums.

## Why not just make your own certificate?

A self-signed certificate (`New-SelfSignedCertificate`) will make the pipeline
*pass*, but Windows users still get a SmartScreen "unknown publisher" warning
(often a worse one) unless they manually install your certificate as a trusted
root — which nobody does. Self-signing is only useful for internal/test builds,
not public distribution. Real trust requires a certificate that chains to a
Microsoft-trusted CA.

## Recommended: SignPath Foundation (free for open source)

[SignPath](https://signpath.io) donates Authenticode code signing to open-source
projects. HomeGuard is public and MIT-licensed, so it qualifies. This is the
free path to warning-free binaries.

1. Apply at <https://signpath.io/open-source> with the repository URL.
2. After approval, install the **SignPath GitHub app** on the repo and create a
   project + signing policy in the SignPath dashboard.
3. Add the repository **variables** (Settings → Secrets and variables → Actions →
   *Variables*):
   - `SIGNPATH_ORGANIZATION_ID`
   - `SIGNPATH_PROJECT_SLUG`
   - `SIGNPATH_SIGNING_POLICY_SLUG`
4. Add the repository **secret**:
   - `SIGNPATH_API_TOKEN`
5. Push a new tag (or re-run the workflow). The `signpath` mode steps activate:
   the unsigned artifacts are uploaded, submitted to SignPath, and the signed
   results are published.

> First-run note: the SignPath steps in the workflow are a ready-to-activate
> scaffold. Validate the `output-artifact-directory` layout on the first signed
> run — SignPath returns the signed files under `dist/signed`, and the
> "Promote SignPath-signed artifacts" step copies them back over the build
> outputs by filename. Adjust the glob if your SignPath project nests them
> differently.

## Alternative: Azure Trusted Signing (~$10/month)

[Azure Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/) is
Microsoft's cloud signing service — no hardware token, CI-friendly, and cheap.
Good if you want signing immediately without waiting for SignPath approval, or
if the project is not open source. Replace the `signpath` steps with the
`azure/trusted-signing-action`.

## Alternative: GreyNOC certificate (PFX)

If you already hold a GreyNOC code-signing certificate that can be exported to a
`.pfx` (note: OV/EV certificates issued since 2023 must live on a hardware token
and **cannot** be exported to a PFX — those need a cloud-HSM integration
instead):

1. Base64-encode the PFX: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("cert.pfx"))`.
2. Add repository secrets `HOMEGUARD_SIGN_CERT_BASE64` and
   `HOMEGUARD_SIGN_CERT_PASSWORD`.
3. Push a tag — `pfx` mode activates automatically.

## Verifying an unsigned download

Until signing is enabled, verify integrity with the published checksums:

```powershell
Get-FileHash -Algorithm SHA256 .\HomeGuard-Portable-v1.6.0.exe
# compare against SHA256SUMS.txt from the release
```

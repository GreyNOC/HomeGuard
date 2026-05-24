# Release signing

HomeGuard has two distinct signing concerns. They cover different threats and
use different tooling, so don't confuse them:

| Concern | Signs what | Tool | Verifies what |
|---|---|---|---|
| **Authenticode code signing** (production Windows installer) | the `.exe` / `.msi` produced by `electron-builder` | a code-signing certificate (`.pfx`) issued to GreyNOC | end users on Windows see "GreyNOC" rather than "Unknown Publisher" |
| **Git tag GPG signing** (dev / pre-release tags) | the Git tag object itself | a GnuPG key on the maintainer's workstation | downstream consumers can verify the tag was published by an authorized maintainer, even before the Windows installer is built and signed |

This document covers the **GPG-signed-tag** flow for dev and pre-release
builds. For production Windows installer signing, see the `windows-release.yml`
workflow and the `HOMEGUARD_SIGN_CERT_BASE64` / `HOMEGUARD_SIGN_CERT_PASSWORD`
repository secrets.

## One-time GPG setup

Check whether you already have a GnuPG key:

```sh
gpg --list-secret-keys --keyid-format=long
```

If you do not, generate one (interactive — picks defaults, prompts for name /
email / passphrase):

```sh
gpg --full-generate-key
```

Recommended choices:
- Key type: `RSA and RSA` (default)
- Key size: `4096`
- Expiration: `0` (never expires) for personal use, or `1y` for stricter
  rotation policies
- Real name: your name (or `GreyNOC HomeGuard Maintainer`)
- Email: a GitHub-verified email
- Passphrase: a strong, unique passphrase you store in a password manager

After key creation, copy the key ID — it looks like
`sec   rsa4096/ABC123DEF4567890`:

```sh
gpg --list-secret-keys --keyid-format=long
```

Tell Git to use the key for tag and commit signing:

```sh
git config --global user.signingkey ABC123DEF4567890
git config --global commit.gpgsign true
git config --global tag.gpgsign true
```

Add the public key to your GitHub account so the **Verified** badge shows up on
the web UI:

```sh
gpg --armor --export ABC123DEF4567890
# Copy the BEGIN/END PGP PUBLIC KEY BLOCK and paste it into
# https://github.com/settings/gpg/new
```

## Cutting a dev / pre-release tag

For dev builds that don't go through the full Authenticode flow:

```sh
# Make sure main is up to date and the release commit is pushed
git checkout main
git pull --ff-only

# Sign the tag
git tag -s dev-v1.5.0 -m "Dev build v1.5.0"

# Verify the signature
git tag -v dev-v1.5.0

# Push the tag
git push origin dev-v1.5.0
```

Naming conventions:

- **Dev builds tied to a semver release** — `dev-v1.5.0`, `dev-v1.5.1`,
  `dev-v1.6.0`.
- **Date-based dev tags** for ad-hoc builds — `dev-2026.05.24`,
  `dev-2026.05.24-01`.

The `windows-release.yml` workflow only fires for `v*` tags (e.g. `v1.5.0`),
not `dev-*` tags, so dev tags are safe to push without triggering a production
Windows build.

## Cutting a production release tag

Production releases use the unsigned `vX.Y.Z` tag — `windows-release.yml`
then attempts to build, Authenticode-sign, and attach the Windows installer to
the GitHub Release using the repo's `HOMEGUARD_SIGN_CERT_*` secrets. The tag
itself doesn't need GPG signing for the workflow to fire, but signing it is
still recommended.

```sh
git tag -s -a v1.5.0 -m "v1.5.0 - <release theme>"
git push origin v1.5.0
```

## Android dev keystore (when the mobile build pipeline lands)

The Android sub-tree under `mobile/` uses a separate signing concept: a Java
keystore (`.jks`) consumed by Gradle's `signingConfig`. For dev / debug
builds:

```sh
keytool -genkeypair \
  -v \
  -keystore dev-release-key.jks \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000 \
  -alias devkey
```

Then in `app/build.gradle`:

```groovy
android {
    signingConfigs {
        dev {
            storeFile file("dev-release-key.jks")
            storePassword "your_store_password"
            keyAlias "devkey"
            keyPassword "your_key_password"
        }
    }

    buildTypes {
        debug {
            signingConfig signingConfigs.dev
        }
        release {
            signingConfig signingConfigs.dev
        }
    }
}
```

**Do not reuse the dev keystore for production releases.** Use a separate
production keystore stored in an external secret manager (e.g. GitHub
Actions secrets, AWS KMS, HashiCorp Vault) and back it up — losing it means
you can never push an update under the same Android package signature.

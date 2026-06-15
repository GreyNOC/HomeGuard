# Branch Protection Recommendations

These are the recommended GitHub branch protection rules for HomeGuard.
They keep `main` and any `release/*` branch in a known-good, signed-and-
gated state. Configure them under
**Settings → Branches → Branch protection rules** in
`github.com/GreyNOC/HomeGuard`.

## Protected branches

Apply identical protection to:

- `main`
- `release/*` (e.g. `release/vX.Y.Z`)

## Required rules

For each protected branch, enable:

- **Require a pull request before merging.**
  - Require at least 1 approving review.
  - Dismiss stale pull request approvals when new commits are pushed.
- **Require status checks to pass before merging.**
  - Required check: `Security Gates` (from
    `.github/workflows/security.yml`).
  - Required check: `tests` (from `.github/workflows/tests.yml`).
- **Require branches to be up to date before merging.**
- **Require conversation resolution before merging.**
- **Require signed commits.** (Strongly recommended on `release/*`.)
- **Restrict who can push to matching branches.** Only release managers
  may push directly; everyone else opens a PR.
- **Do not allow force pushes.**
- **Do not allow deletions.**

## CODEOWNERS-enforced review

The following high-blast-radius paths must require an explicit
CODEOWNERS review (see `.github/CODEOWNERS`):

- `electron/main.js`
- `electron/preload.js`
- `src/greynoc_homeguard/dashboard.py`
- `src/greynoc_homeguard/network.py`
- `src/greynoc_homeguard/firewall.py`
- `src/greynoc_homeguard/privacy.py`
- `scripts/*sign*`
- `scripts/*release*`
- `scripts/build_windows_installer.ps1`
- `installer/homeguard.iss`
- `.github/workflows/*`

To enforce CODEOWNERS reviews on these paths, also enable
**Require review from Code Owners** on the protection rule for `main`
and `release/*`.

## Tag protection

Add a tag protection rule for `v*` (under **Settings → Tags**) so that
release tags can only be created / pushed by release managers, matching
the signed-tag step in the release procedure.

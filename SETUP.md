# Repository Setup Guide

You're holding the cairn source tree but not a git repository yet. This guide walks through standing up the actual repo, configuring it, and pushing to GitHub. About 15 minutes start to finish, mostly clicking around in GitHub settings.

## 1. Local repo init

```bash
# From inside the extracted cairn/ directory:
git init
git add .
git commit -m "feat: initial cairn release"
git branch -M main
```

That gives you a clean local repo with one commit. The commit message uses the conventional-commits format the release workflow expects.

## 2. Replace placeholder values

Before pushing, four placeholders need your real values. Find them with:

```bash
grep -rln "Your Org\|example.com/cairn\|YourOrg\\\\Cairn" --include="*.py" --include="*.toml" --include="*.wxs" --include="*.md" --include="*.spec" --include="*.sh"
```

You'll get hits in:

| File | Replace |
|---|---|
| `pyproject.toml` | `Your Org` → your organization name; `https://example.com/cairn` → your homepage |
| `LICENSE` | `Your Org` → your copyright holder |
| `windows/cairn.wxs` | `Your Org`, `Software\YourOrg\Cairn` |
| `windows/License.rtf` | `Your Org` |
| `scripts/build-deb.sh` | `Homepage: https://example.com/cairn`, `Maintainer: ops@example.com` |
| `packaging/cairn.spec` | `URL`, maintainer email |
| `README.md` and `docs/*.md` | example URLs |
| `CHANGELOG.md` | `Your Org` |

Critical: in `windows/cairn.wxs`, the `UpgradeCode` GUID (`930ffdcd-a101-4776-8189-816e224d76fb`) is currently the placeholder cairn was developed against. Generate your own with:

```powershell
[guid]::NewGuid()
```

or on Linux:

```bash
python3 -c "import uuid; print(str(uuid.uuid4()))"
```

Once you ship a release using that GUID it's **permanent for your product line** — never change it again, or Windows installs from older versions become invisible to the new installer.

Commit those changes:

```bash
git add .
git commit -m "chore: replace org placeholders with real values"
```

## 3. Create the GitHub repo

Either via the web UI (https://github.com/new) or the CLI:

```bash
gh repo create YOUR-ORG/cairn --private --source=. --remote=origin --push
```

If you used the web UI:

```bash
git remote add origin git@github.com:YOUR-ORG/cairn.git
git push -u origin main
```

## 4. Configure repo settings

These settings are required for the workflows we built to function correctly. Most are one-time clicks.

### Settings → General → Pull Requests

- ✅ **Allow squash merging**
- ✅ **Default to PR title for squash merge commits** ← critical; the PR linter relies on this
- ❌ Allow merge commits (off — keeps history linear)
- ❌ Allow rebase merging (off — bypasses PR title validation)

### Settings → Actions → General → Workflow permissions

- ✅ **Read and write permissions** ← required for semantic-release to push tags + commits
- ✅ Allow GitHub Actions to create and approve pull requests

### Settings → Branches → Add branch protection rule

For `main`:
- ✅ Require a pull request before merging
- ✅ Require status checks to pass before merging
  - Add `Validate PR title`, `linux`, `windows` after the first PR runs them once
- ✅ Require branches to be up to date before merging
- ✅ Do not allow bypassing the above settings

## 5. (Optional but recommended) Code signing

For production, the .deb/.rpm and .msi should be signed. Without signing:

- .deb/.rpm: `apt`/`dnf` will warn that the repo is unsigned
- .msi: SmartScreen will flag it as "unknown publisher" on every install
- exe: AV will flag PyInstaller binaries more aggressively

### GPG (Linux artifacts)

1. Generate or import an org GPG key
2. Export the private key: `gpg --export-secret-keys --armor KEYID > release.key`
3. Add it as a repo secret: **Settings → Secrets → Actions → New secret** named `RELEASE_GPG_KEY` with the key contents as value
4. The release workflow's "sign SHA256SUMS" step will pick it up automatically

### Authenticode (Windows MSI/exe)

Authenticode requires a paid code-signing certificate. Once you have one, add a signing step to `release.yml`'s Windows job before the upload step:

```yaml
- name: sign msi
  run: |
    signtool sign /tr http://timestamp.digicert.com /td sha256 /fd sha256 `
      /f $env:CERT_PATH /p $env:CERT_PASS dist\cairn-*.msi
  env:
    CERT_PATH: ${{ secrets.AUTHENTICODE_CERT_PATH }}
    CERT_PASS: ${{ secrets.AUTHENTICODE_CERT_PASS }}
```

## 6. First test PR

Branch and make a tiny change to validate the workflows:

```bash
git checkout -b chore/test-pr
echo "" >> README.md
git add README.md
git commit -m "chore: validate CI"
git push -u origin chore/test-pr
gh pr create --title "chore: validate CI workflows" --body "Smoke test"
```

You should see three checks fire on the PR: `Validate PR title`, `linux`, `windows`. Once they pass, squash-merge. The merge should kick off the release workflow, but since `chore:` commits don't trigger a release, it will run and exit quietly. That's correct behavior.

To actually cut your first release, make a PR with a `feat:` or `fix:` commit:

```bash
git checkout -b feat/initial-release
# (make any small change, or just push the README again with feat: prefix)
git commit --amend -m "feat: initial release"
git push
gh pr create --title "feat: initial release" --body "Cuts v0.2.1"
```

When merged, the workflow will:
1. Run semantic-release, detect the `feat:`, bump 0.2.0 → 0.3.0 (held back from major by `major_on_zero=false`), tag, and create a GitHub Release
2. Build all artifacts at the new version
3. Upload .deb, .rpm, .msi, .exe, single-binary, wheel, and SHA256SUMS to the release

## 7. Test the artifacts

Before pointing real hosts at this, install from a release and run through the basic workflow:

```bash
# Linux
sudo apt install ./cairn_0.3.0_amd64.deb
sudo cairn files init --config /etc/cairn/cairn.yaml
sudo cairn baseline info --config /etc/cairn/cairn.yaml
# (modify something under /etc)
sudo cairn files scan --config /etc/cairn/cairn.yaml --report drift.md
```

```powershell
# Windows
msiexec /i cairn-0.3.0.msi /qb
cairn files init --config C:\ProgramData\Cairn\cairn.yaml
cairn baseline info --config C:\ProgramData\Cairn\cairn.yaml
# (modify something under C:\Program Files)
cairn files scan --config C:\ProgramData\Cairn\cairn.yaml --report drift.md
```

If anything's off, file a `fix:` PR; semantic-release will cut the patch automatically when it merges.

## Pre-publish TODO (placeholders still in the tree)

These don't block the release *mechanics* — the pipeline runs fine with
them — but they must be replaced before a release goes public:

1. `pyproject.toml` — `authors = [{ name = "Your Org" }]` and
   `Homepage = "https://example.com/cairn"`
2. `LICENSE` — copyright holder
3. `scripts/build-deb.sh` — `Maintainer:` and `Homepage:` fields
4. `packaging/cairn.spec` — `URL:` and the changelog maintainer email
5. `src/cairn/report.py` — the SARIF `informationUri`
   (update `test_sarif_report_parses_and_schema_basics` in the same commit
   if you assert on it)
6. *(deferred with Windows CI)* `windows/cairn.wxs` org strings + a fresh
   `UpgradeCode` GUID, and `windows/License.rtf` — required before
   re-enabling the Windows jobs in ci.yml / release.yml

## 8. Day-2 things you'll want eventually

In rough priority order:

1. **Smoke-test job in CI.** ✅ Done — `scripts/smoke-test.sh` runs in ubuntu:24.04 + almalinux:10 containers on every PR (`ci.yml`) and gates release artifact publishing on both arches (`release.yml`). Run locally with `bash scripts/smoke-local.sh`; full-VM pass (SELinux-enforcing Alma) with `bash scripts/smoke-vm.sh`. To widen distro coverage, add images to the workflow matrices and `SMOKE_IMAGES`.
2. **Your own apt/yum repo.** `apt install cairn` from your domain. Use `aptly` (Debian) and `createrepo` (RPM) on S3+CloudFront, or GitHub Pages for very small fleets.
3. **The Windows half end-to-end.** The .wxs is structurally correct but the MSI hasn't been built on a real Windows host yet. First time `scripts/build-windows.ps1` runs on Windows is when you'll find out if anything's off.

## What this guide doesn't do

These are intentional gaps; address them when they're real needs, not before:

- No central management server
- No automated agent deployment (use Ansible/Salt/Puppet/Chef or your config-management of choice)
- No dashboard (use the JSON/NDJSON output → your existing log aggregator)
- No real-time monitoring (that's not what cairn is)

If any of those become hard requirements, the answer probably isn't "extend cairn" — it's "deploy Wazuh alongside cairn." cairn is meant to stay small.

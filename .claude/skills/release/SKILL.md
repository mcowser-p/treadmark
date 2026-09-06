---
name: release
description: Cut, verify, or debug a treadmark release. Use when asked to release a new version, create a release PR, check why a release didn't happen, fix a failed release build, or explain the release pipeline. Versions are computed from conventional commits, but publishing is PR-gated — a release PR must be created and merged before CI tags anything.
---

# Releasing treadmark

`.github/workflows/release.yml` runs on every push to `main`, but it can
never push *to* `main`: the branch ruleset forbids direct pushes, including
from CI. So a release takes **two pushes to main with one manual step
between them** — the releasable change, then a **release PR** that stamps
the version. Only the second push tags and publishes. Nothing creates the
release PR automatically; a maintainer (or their coding agent) must —
`scripts/release-pr.sh` scaffolds it.

## How to cut a release

1. **Land a release-worthy commit on `main`** via a squash-merged PR:
   `feat:` (minor bump) or `fix:`/`perf:` (patch bump). `docs:`/`chore:`/
   `test:`/`ci:` commits never release.
2. **That push runs the build half of the pipeline**, in order:
   - **test** — pytest on 3.12; fails fast before any build minutes.
   - **version** — computes the next version with
     `semantic-release version --print` (pure: no tag, commit, or push)
     and reads the version already stamped in `pyproject.toml` (`pyver`).
   - **linux** — Nuitka binary + .deb + .rpm for x86_64 and aarch64, built
     in an almalinux:9 container (oldest supported glibc).
   - **windows** — exe + MSI build and MSI smoke test. This is a
     first-class, blocking release gate (the old "commented out" /
     `continue-on-error` soak is over); only the `windows-11` arm64
     footprint job is still a non-gating soak probe.
   - **smoke** — installs the fresh packages on ubuntu:24.04,
     almalinux:10, and amazonlinux:2023, both arches.
   - **release / attach / pypi are skipped**: the release job requires
     `version == pyver`, and `pyproject.toml` still holds the previous
     version. A green run that skips at `release` is the *expected* state
     here — it proves the next release builds and smokes clean.
3. **Create the release PR** (the manual step). From a clean, up-to-date
   `main`:

   ```sh
   bash scripts/release-pr.sh
   ```

   It recomputes the version exactly like CI, creates branch
   `release/vX.Y.Z`, stamps `pyproject.toml` +
   `src/treadmark/__init__.py` (via `scripts/stamp_version.py`), and
   drafts a `CHANGELOG.md` section from the commit subjects since the
   last tag. Then, following the commands it prints: polish the changelog
   into prose (match earlier entries), commit
   `chore(release): cut X.Y.Z`, push, and open the PR with that exact
   title — see merged PR #19/#20 for the shape. `chore(release):` is
   deliberate: the release commit itself must not warrant another bump.
4. **Squash-merge the release PR.** That second push re-runs the whole
   workflow (test/builds/smoke again), and now `version == pyver`, so:
   - **release** — semantic-release runs with `commit: false,
     changelog: false`: it only tags `vX.Y.Z` (tags sit outside the
     branch ruleset) and creates the GitHub Release. It never pushes a
     commit.
   - **attach** — uploads the Linux *and* Windows artifacts plus
     `SHA256SUMS` (GPG-signed only if the `RELEASE_GPG_KEY` secret
     exists) to the Release.
   - **pypi** — checks out the tag, builds sdist + wheel, publishes via
     Trusted Publishing (OIDC, no token secret).

## Verifying a release

```sh
gh run list --workflow=release.yml --limit 3   # expect 2 runs: build-only, then the releasing one
gh release view vX.Y.Z                         # artifacts attached?
```

Expect on the Release: `treadmark-linux-x86_64`, `treadmark-linux-aarch64`,
`.deb` + `.rpm` for both arches, `treadmark-windows-x86_64.exe`, the
`.msi`, and `SHA256SUMS`. **No wheel is attached to the GitHub Release**
(a wheel is literal source; the shipped binaries are compiled) — the
sdist + wheel go to PyPI instead: check `pip index versions treadmark`.
Ideal smoke test: install the .deb in a container, run
`treadmark --version` and an init/scan cycle.

## Debugging

- **Builds green but `release` skipped after your feature merged** — not a
  failure; that's phase 1. The `version` job outputs show `released=true`
  and `version` one ahead of `pyver`: the release PR hasn't been merged
  yet. Cut it (step 3 above).
- **Nothing was warranted at all** (`released=false`) — the commit type
  doesn't release (`chore:`, `docs:`, …), or the PR wasn't squash-merged
  with its title as the commit message. Check `git log --oneline` on main;
  the decision is made from those exact messages. Remedy: land the next
  change as `feat:`/`fix:` — there is no "re-run as release" button.
- **`release` skipped even though a release PR was merged** — more
  releasable commits landed between cutting and merging the PR, so the
  computed version moved past the stamped one (`version != pyver`).
  Re-run `scripts/release-pr.sh` and cut a fresh PR at the new version.
- **test/linux/windows/smoke failed** — nothing was tagged (tagging is the
  last step, deliberately: a tag from a broken build can't be
  un-published). Fix forward. Note a `fix:` commit moves the computed
  version, so any unmerged release PR goes stale — re-cut it after the
  fix lands.
- **attach or pypi failed after the tag exists** — the version is tagged
  but artifacts/PyPI are missing. Do NOT delete the tag. If transient
  (runner flake, network), `gh run rerun <run-id> --failed`. If it's a
  real bug in the build/publish scripts, land it as `fix:` and cut the
  next patch release; the broken tag simply stays artifact-less.
- **Tag creation rejected in the release job** — the branch ruleset does
  not cover tags and `GITHUB_TOKEN` has `contents: write`, so this should
  not happen; if it does, someone added a *tag* ruleset. CI never commits
  to main (`commit: false`), so "can't push branch" errors can't occur.
- **0.x versioning** — `major_on_zero = false`: `feat:` stays within 0.x
  (0.3.0 → 0.4.0). 1.0.0 is a deliberate maintainer act.

## Loose ends before calling a release "public-ready"

The SETUP.md "Pre-publish TODO" (org metadata, license, URLs) is done, but
the Windows org strings and `License.rtf` under `windows/` are still
placeholders — the MSI installs fine, it just isn't brand-correct yet.

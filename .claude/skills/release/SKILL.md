---
name: release
description: Cut, verify, or debug a cairn release. Use when asked to release a new version, check why a release didn't happen, fix a failed release build, or explain the release pipeline. Releases are fully automated from conventional commits — there is no manual tag/version step.
---

# Releasing cairn

Releases are cut by `.github/workflows/release.yml` on every push to `main`.
There is **no manual step**: no tags, no version bumps, no GitHub Release
creation by hand.

## How to cut a release

1. Land at least one release-worthy commit on `main` via a squash-merged PR:
   `feat:` (minor bump) or `fix:`/`perf:` (patch bump). `docs:`/`chore:`/
   `test:`/`ci:` commits never release.
2. The workflow then runs, in order:
   - **test** — pytest on 3.12; a failure stops everything *before* any tag
     exists (deliberate: a tag from a broken commit can't be un-published).
   - **release** — python-semantic-release computes the version from commits
     since the last tag, writes it into `pyproject.toml`, updates
     `CHANGELOG.md`, commits `chore(release): X.Y.Z [skip ci]`, tags
     `vX.Y.Z`, creates the GitHub Release.
   - **linux** — builds wheel + PyInstaller binary + .deb + .rpm for x86_64
     and aarch64. (Windows jobs are deliberately disabled — commented out.)
   - **attach** — uploads all artifacts plus `SHA256SUMS` (GPG-signed only
     if the `RELEASE_GPG_KEY` secret exists) to the Release.

## Verifying a release

```sh
gh run list --workflow=release.yml --limit 3     # pipeline status
gh release view vX.Y.Z                            # artifacts attached?
```

Expect on the release: `.whl`, `cairn-linux-x86_64`, `cairn-linux-aarch64`,
`.deb`, `.rpm`, `SHA256SUMS`. Ideal smoke test: install the .deb in a
container, run `cairn --version` and an init/scan cycle.

## Debugging

- **No release happened after merge** — the commit type doesn't release
  (`chore:`, `docs:`, …), or the PR wasn't squash-merged with its title as
  the commit message. Check `git log --oneline` on main: the release
  decision is made from those exact messages. Remedy: land the next change
  as `feat:`/`fix:`; there is no "re-run as release" button.
- **test job failed** — nothing was tagged; fix and merge normally.
- **linux/attach failed after the tag exists** — the version is tagged but
  artifacts are missing. Do NOT delete the tag. If the failure was
  transient (runner flake, network), re-run the failed jobs from the GitHub
  UI (`gh run rerun <run-id> --failed`). If the failure is a real bug in
  the build scripts, land it as a `fix:` commit — semantic-release then
  cuts a fresh patch release whose builds work, and the broken tag simply
  stays artifact-less.
- **semantic-release can't push** — branch protection is blocking
  `GITHUB_TOKEN`. First release: push to main before enabling protection
  (see SETUP.md).
- **0.x versioning** — `major_on_zero = false`: `feat:` stays within 0.x
  (0.3.0 → 0.4.0). 1.0.0 is a deliberate maintainer act.

## Before the first *public* release

Work through the "Pre-publish TODO" in SETUP.md (placeholder org name,
homepage, maintainer email, SARIF informationUri). The pipeline runs fine
with placeholders; publishing with them is the only thing that's wrong.

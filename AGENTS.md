# AGENTS.md — guide for coding agents working on treadmark

This file is the canonical, tool-agnostic guide for AI coding agents
(Codex, Claude Code, Copilot, Cursor, etc.). `CLAUDE.md` and
`.github/copilot-instructions.md` point here — update THIS file when
guidance changes, not the pointers.

## What this project is

treadmark is a forensic file-integrity tool for Linux (and, later, Windows):
baseline a filesystem into SQLite, scan for drift, compare across hosts,
and capture install-time application footprints (`treadmark footprint`) for
least-privilege policy generation. Single binary, no agent, no daemon.

## Repository layout

| Path | What lives there |
|---|---|
| `src/treadmark/files.py` | Config loading, walking/hashing, SQLite baseline, scan/update/verify, `--root` logical-path mapping, rootfs fidelity check |
| `src/treadmark/__main__.py` | The real CLI (`treadmark files/registry/compare/footprint/baseline`) |
| `src/treadmark/footprint.py` | Install-footprint model: collect → extract → access hints → risks |
| `src/treadmark/semantic.py` | Parsers: systemd units, cron, passwd/group diff, sudoers, setuid analysis |
| `src/treadmark/compare.py` | Golden-baseline compare (live-vs-DB and DB-vs-DB) |
| `src/treadmark/report.py` | 7 output formats (json/ndjson/csv/sarif/md/html/txt) |
| `src/treadmark/winreg_mon.py` | Windows registry monitor (dormant on Linux) |
| `src/treadmark/winsemantic.py` | Windows footprint parsers: services (from registry), scheduled tasks (from XML), path classification — pure, testable anywhere |
| `tests/` | pytest suite — see "Testing" below |
| `packaging/` | Shipped default configs, rpm spec, postinstall |
| `scripts/` | Build scripts, `container-rootfs.sh` extraction helper |
| `.claude/skills/` | Repo skills: `conventional-commits`, `release` |
| `docs/` | Workflow docs (forensic, footprint, golden-baseline, output formats) |

## Dev setup and verification

```sh
pip install -e ".[dev]"     # pytest + PyYAML
pytest                      # must be green before any PR — ~1s, no excuses
bash scripts/build-linux.sh # full artifact build (needs dpkg-deb/rpmbuild)
bash scripts/smoke-local.sh # artifact-level check: builds in a container,
                            # installs + exercises the .deb/.rpm on
                            # ubuntu:24.04, almalinux:10, and
                            # amazonlinux:2023 (docker/podman)
```

CI runs `pytest` on Python 3.9, 3.12, and 3.13 and gates both the PR build
and the release job on it; a distro smoke matrix (ubuntu:24.04,
almalinux:10, amazonlinux:2023) then installs the built packages and gates
release publishing. `scripts/smoke-vm.sh` is the occasional full-VM pass
via Lima. `bash scripts/smoke-aws.sh` runs the smoke on REAL EC2 instances
(AL2023 incl. Graviton, Ubuntu 24.04, Alma 9/10, Windows Server 2022/2025)
— see docs/aws-smoke.md; needs AWS credentials, costs real (tiny) money.

## Commits and PRs (this is how releases get triggered)

Conventional Commits are load-bearing here: **the squash-merged PR title
becomes the commit on `main`, and python-semantic-release parses it to
decide whether to cut a release and what version to bump.** Full rules in
[CONTRIBUTING.md](CONTRIBUTING.md); the critical subset:

- Format: `<type>[(scope)][!]: <lowercase imperative subject>` — e.g.
  `feat(footprint): parse polkit rules`, `fix(linux): handle ENOENT during walk`.
- `feat:` → minor bump and a release. `fix:`/`perf:` → patch bump and a
  release. `docs:`/`test:`/`ci:`/`chore:`/`refactor:`/`style:`/`build:` → no release.
- **Never use `!` or `BREAKING CHANGE:` casually** — on this 0.x project it
  jumps straight to 1.0.0.
- Never hand-edit the version in `pyproject.toml`, never create tags, never
  edit released sections of `CHANGELOG.md`. All three are owned by
  semantic-release. The `[Unreleased]` CHANGELOG section may be edited.
- A local `commit-msg` hook enforces the format; enable with
  `git config core.hooksPath .githooks` (bootstrap.sh does this for you).

To cut a release: land a `feat:` or `fix:` commit on `main` and let the
`release` workflow do everything. See the `release` skill
(`.claude/skills/release/SKILL.md`) for the full procedure and failure modes.

## Testing rules

- Tests invoke the real CLI **in-process**: `treadmark.__main__.main(argv)`
  returns an exit code (0 clean, 1 drift, 2 error) without calling
  `sys.exit`. Don't shell out except in the two packaging smoke tests.
- Use **JSON configs** in tests (`make_config` fixture) — JSON needs no
  PyYAML, keeping most tests dependency-free.
- The rootfs fixture (`linux_rootfs` + `install_app` in `tests/conftest.py`)
  is **built programmatically, never checked in**: git does not preserve
  setuid bits or ownership, which are exactly the properties under test.
- Beware directory noise in assertions: adding/removing files changes the
  parent directory's size/mtime, so dirs appear as "modified" entries.
  Match specific paths instead of asserting exact counts.
- Anything asserting on ownership uniformity must skip when running as
  root (`os.getuid() == 0`) — see `tests/test_fidelity.py`.

## Invariants — do not break these

1. **Zero hard runtime dependencies** in `src/treadmark/`. PyYAML is optional
   (JSON configs work without it); pywin32 is optional and Windows-only.
   Do not add imports of third-party packages to the core.
2. **Python ≥ 3.9.** Keep `from __future__ import annotations` at the top
   of every module; don't use syntax newer than 3.9.
3. **Windows code must stay importable-but-dormant on Linux**: everything
   win32 is gated behind `IS_WINDOWS` / conditional imports. Windows CI is
   active (test + build + MSI smoke on windows-latest); the registry tests
   in `tests/test_registry.py` run only on Windows runners.
4. **Baselines store logical paths.** With `--root`, real on-disk paths are
   mapped through `to_logical()` before persisting; `FileRecord.real_path`
   is never written to the DB. This is what makes baselines portable across
   rootfs. Don't leak real paths into the DB or reports.
5. **Exclude patterns are substrings matched against logical paths**, not
   globs or anchors. Extension excludes are case-insensitive.
6. **Exit codes are API**: 0 = clean, 1 = drift, 2 = error. Alerting
   pipelines depend on them.
7. **`treadmark files update` must never silently accept changes** — explicit
   `--accept`/`--accept-all` is a forensic-integrity feature, not friction.
8. **Fidelity/inspect.json handling is warn-only**: a degraded rootfs or a
   malformed `<root>.inspect.json` must never fail a scan or footprint.
9. Report schema changes are breaking for downstream SIEM consumers —
   additive keys are fine, renames/removals need a `feat!:`.

## Known-pending work (don't "fix" these in passing)

- Org metadata is SET (2026-08: Apache-2.0, `mcowser-p`,
  github.com/mcowser-p/treadmark, GitHub-noreply maintainer address). Two values
  are permanent — do not change: the WiX `UpgradeCode` GUID and the MSI
  state registry path `Software\mcowser-p\Treadmark` (functional, not cosmetic).
- Windows CI is re-enabled but SOAKING: the release.yml windows jobs are
  `continue-on-error` so a flake can't hold Linux releases hostage. Flip to
  blocking (add them to attach.needs, drop continue-on-error) after a couple
  of clean releases. Org strings + License.rtf in windows/ are still
  placeholders (SETUP.md pre-publish TODO) — MSI installs, not brand-correct.
- Windows semantic footprint: **services and scheduled tasks are now parsed**
  (`src/treadmark/winsemantic.py`; `treadmark footprint` dispatches to
  `build_model_windows` on Windows, reconstructing services from the registry
  Services subtree and tasks from Task XML). Still unbuilt: COM registration,
  firewall rules, and local account/group enumeration (Windows accounts live
  in the SAM, not a readable file) — the next gaps.
- Cloud drift (`src/treadmark/awsmon.py`): **DORMANT** — the `treadmark aws`
  subcommand, its dispatch, and the `aws` pyproject extra (plus boto3 in
  `all`) are commented out pending validation against a real AWS account.
  The module and its fake-client unit tests (`tests/test_awsmon.py`) remain
  and must stay green and import-safe without boto3 — azmon/gcpmon/k8smon
  import `DEFAULT_VOLATILE_FIELDS`/`canonicalize` from it. Design notes:
  six curated drivers (iam/s3/ec2/cloudtrail/kms/lambda) in a `DRIVERS`
  registry — broaden by adding drivers, not plumbing; volatile-field
  stripping is the denoise lever (like `NOISE_SERVICES`). One tier below:
  Azure `azmon` / GCP `gcpmon` / k8s `k8smon` are untested scaffolds.
  **Bookmarked, not built:** multi-account org fan-out, GitHub
  alert-workflow wiring. See docs/cloud-workflow.md.

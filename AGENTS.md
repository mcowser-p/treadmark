# AGENTS.md — guide for coding agents working on cairn

This file is the canonical, tool-agnostic guide for AI coding agents
(Codex, Claude Code, Copilot, Cursor, etc.). `CLAUDE.md` and
`.github/copilot-instructions.md` point here — update THIS file when
guidance changes, not the pointers.

## What this project is

cairn is a forensic file-integrity tool for Linux (and, later, Windows):
baseline a filesystem into SQLite, scan for drift, compare across hosts,
and capture install-time application footprints (`cairn footprint`) for
least-privilege policy generation. Single binary, no agent, no daemon.

## Repository layout

| Path | What lives there |
|---|---|
| `src/cairn/files.py` | Config loading, walking/hashing, SQLite baseline, scan/update/verify, `--root` logical-path mapping, rootfs fidelity check |
| `src/cairn/__main__.py` | The real CLI (`cairn files/registry/compare/footprint/baseline`) |
| `src/cairn/footprint.py` | Install-footprint model: collect → extract → access hints → risks |
| `src/cairn/semantic.py` | Parsers: systemd units, cron, passwd/group diff, sudoers, setuid analysis |
| `src/cairn/compare.py` | Golden-baseline compare (live-vs-DB and DB-vs-DB) |
| `src/cairn/report.py` | 7 output formats (json/ndjson/csv/sarif/md/html/txt) |
| `src/cairn/winreg_mon.py` | Windows registry monitor (dormant on Linux) |
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
                            # ubuntu:24.04 and almalinux:10 (docker/podman)
```

CI runs `pytest` on Python 3.9, 3.12, and 3.13 and gates both the PR build
and the release job on it; a distro smoke matrix (ubuntu:24.04,
almalinux:10) then installs the built packages and gates release
publishing. `scripts/smoke-vm.sh` is the occasional full-VM pass via Lima.

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

- Tests invoke the real CLI **in-process**: `cairn.__main__.main(argv)`
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

1. **Zero hard runtime dependencies** in `src/cairn/`. PyYAML is optional
   (JSON configs work without it); pywin32 is optional and Windows-only.
   Do not add imports of third-party packages to the core.
2. **Python ≥ 3.9.** Keep `from __future__ import annotations` at the top
   of every module; don't use syntax newer than 3.9.
3. **Windows code must stay importable-but-dormant on Linux**: everything
   win32 is gated behind `IS_WINDOWS` / conditional imports. Windows CI is
   currently disabled (commented out in the workflows), but the code ships.
4. **Baselines store logical paths.** With `--root`, real on-disk paths are
   mapped through `to_logical()` before persisting; `FileRecord.real_path`
   is never written to the DB. This is what makes baselines portable across
   rootfs. Don't leak real paths into the DB or reports.
5. **Exclude patterns are substrings matched against logical paths**, not
   globs or anchors. Extension excludes are case-insensitive.
6. **Exit codes are API**: 0 = clean, 1 = drift, 2 = error. Alerting
   pipelines depend on them.
7. **`cairn files update` must never silently accept changes** — explicit
   `--accept`/`--accept-all` is a forensic-integrity feature, not friction.
8. **Fidelity/inspect.json handling is warn-only**: a degraded rootfs or a
   malformed `<root>.inspect.json` must never fail a scan or footprint.
9. Report schema changes are breaking for downstream SIEM consumers —
   additive keys are fine, renames/removals need a `feat!:`.

## Known-pending work (don't "fix" these in passing)

- Placeholder metadata (`Your Org`, `example.com`, `ops@example.com`) is
  intentionally unreplaced until the maintainer supplies real values — the
  list lives in SETUP.md's "Pre-publish TODO".
- Windows CI jobs are deliberately commented out for the Linux-only release
  line; re-enabling them is a maintainer decision with prerequisites
  (MSI UpgradeCode GUID, org strings — see release.yml comments).
- Windows-side semantic parsing (services, scheduled tasks, COM, firewall)
  is unbuilt by design; the registry monitor only captures raw keys.

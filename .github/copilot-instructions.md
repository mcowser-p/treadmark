# Copilot instructions for cairn

Canonical agent guide: [AGENTS.md](../AGENTS.md) (layout, testing rules,
invariants). Critical rules:

- cairn is a forensic file-integrity CLI (Linux-first). Core code in
  `src/cairn/` has **zero hard runtime dependencies** (PyYAML optional) and
  targets **Python ≥ 3.9**.
- Verify changes with `pip install -e ".[dev]" && pytest`. Tests call
  `cairn.__main__.main(argv)` in-process and use JSON configs; the rootfs
  fixture is built programmatically (git can't store setuid bits).
- PR titles must be Conventional Commits — they become the squash commit on
  `main` and **trigger releases** via python-semantic-release: `feat:` →
  minor, `fix:`/`perf:` → patch, `docs:`/`test:`/`ci:`/`chore:` → none.
  Never use `!`/`BREAKING CHANGE:` casually (0.x jumps to 1.0.0). See
  [CONTRIBUTING.md](../CONTRIBUTING.md).
- Never hand-edit the `pyproject.toml` version, git tags, or released
  CHANGELOG sections; semantic-release owns them.
- Exit codes are API: 0 clean, 1 drift, 2 error. Baselines store logical
  paths under `--root` — never persist real paths. Exclude patterns are
  substrings on logical paths, not globs.
- Windows code stays gated behind `IS_WINDOWS` and importable on Linux;
  Windows CI is deliberately disabled. Org metadata (Apache-2.0, mcowser-p,
  github.com/mcowser-p/cairn) is set — see SETUP.md for the two permanent
  values (WiX UpgradeCode, MSI registry path) that must never change.

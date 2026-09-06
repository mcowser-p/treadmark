# CLAUDE.md

**Read [AGENTS.md](AGENTS.md) first** — it is the canonical agent guide for
this repo (layout, testing rules, invariants). Keep guidance there; this
file only pins the rules that must survive even a skim:

- Verify with `pip install -e ".[dev]" && pytest` (fast; must be green).
- Commits/PR titles are Conventional Commits and **drive releases**:
  `feat:` → minor release, `fix:`/`perf:` → patch release, everything else
  → no release. Never use `!`/`BREAKING CHANGE:` casually (0.x → 1.0.0).
  Details: [CONTRIBUTING.md](CONTRIBUTING.md), or use the
  `conventional-commits` skill.
- Never touch the version in `pyproject.toml`, tags, or released CHANGELOG
  sections in a normal PR — they change only through the release flow. To
  cut a release: land a `feat:`/`fix:` on `main`, then create and merge the
  release PR (`bash scripts/release-pr.sh`; see the `release` skill).
- Core code (`src/treadmark/`) has zero hard runtime deps and supports
  Python ≥ 3.9. Exit codes 0/1/2 are API.
- Baselines store logical paths (`--root` mapping); never persist real
  paths. Placeholder metadata (`Your Org`/`example.com`) is intentionally
  pending — don't replace it in passing.

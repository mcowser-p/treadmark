---
name: conventional-commits
description: Write commit messages and PR titles for the cairn repo. Use whenever committing, amending, or opening/renaming a PR here — the format is enforced by CI and drives automated releases (wrong type = wrong or missing release).
---

# Conventional commits in cairn

The squash-merged **PR title becomes the commit on `main`**, and
python-semantic-release parses that commit to decide whether to release and
which version to bump. `pr-lint.yml` rejects malformed PR titles; the local
`.githooks/commit-msg` hook rejects malformed commits.

## Format

```
<type>[(scope)][!]: <subject>
```

- Subject: lowercase, imperative, no trailing period, ≤ ~72 chars.
- Scope optional; common ones: `linux`, `windows`, `compare`, `registry`,
  `footprint`, `cli`, `config`, `deb`, `rpm`, `msi`, `ci`, `scripts`.

## Choosing the type (this decides the release)

| Type | Use for | Release |
|---|---|---|
| `feat` | New user-facing capability, new config surface, new report keys | **minor** (0.3.0 → 0.4.0) |
| `fix` | Bug fixes | **patch** |
| `perf` | Performance improvements | **patch** |
| `refactor` / `style` | No behavior change | none |
| `test` / `docs` / `ci` / `chore` / `build` | Self-explanatory | none |

Decision rules that trip people up:

- Shipped default-config changes (`packaging/cairn.yaml`) are user-facing →
  `feat(config):`, not `chore`.
- New keys in report/footprint JSON output → `feat`; renaming/removing keys
  breaks SIEM consumers → needs `feat!:` (think hard first).
- A fix to a build script that ships behavior (e.g. `container-rootfs.sh`)
  is `fix(scripts):`; pure CI wiring is `ci:`.
- **Never use `!` or a `BREAKING CHANGE:` footer casually** — this is a 0.x
  project with `major_on_zero = false`… but `!` still forces 1.0.0. A major
  bump is a maintainer decision, not a commit-style choice.

## Never do by hand

- Don't edit `version` in `pyproject.toml`.
- Don't create or push tags.
- Don't edit released sections of `CHANGELOG.md` (the `[Unreleased]`
  section is fine to edit).

semantic-release owns all three; its own commits look like
`chore(release): X.Y.Z [skip ci]` and are exempt from the hook.

## Verify before committing

```sh
echo "feat(scope): subject" | grep -E '^(feat|fix|perf|refactor|docs|style|test|ci|chore|build)(\([^)]+\))?!?: [a-z]'
```

Or just enable the hook once per clone: `git config core.hooksPath .githooks`
(`scripts/bootstrap.sh` does this automatically).

# Contributing to cairn

## How releases work

cairn uses [Conventional Commits](https://www.conventionalcommits.org/) to drive automated releases. Every PR title that lands on `main` is parsed by [python-semantic-release](https://python-semantic-release.readthedocs.io/), which decides whether a release is warranted and what the next version number should be.

You don't tag releases by hand. You don't bump the version in `pyproject.toml` by hand. Both happen automatically when a release-worthy commit hits `main`.

## PR title format (this is enforced)

```
<type>[optional scope][!]: <subject>
```

Examples that pass the linter:

```
feat: add Windows registry baseline support
fix(linux): handle ENOENT during walk
feat(api)!: rename baseline format
chore: bump pyyaml to 6.0.2
docs: clarify the golden-baseline workflow
```

The PR title becomes the squash-merge commit message on `main`, which is what the release tooling reads. Get the PR title right and everything downstream just works.

## Allowed types and what they trigger

| Type | When to use it | Release impact |
|---|---|---|
| `feat` | New user-facing capability | **Minor** version bump (0.2.0 → 0.3.0) |
| `fix` | Bug fix | **Patch** version bump (0.2.0 → 0.2.1) |
| `perf` | Performance improvement | **Patch** version bump |
| `refactor` | Code restructuring, no behavior change | No release |
| `docs` | Documentation only | No release |
| `style` | Formatting, whitespace, no logic | No release |
| `test` | Test-only changes | No release |
| `ci` | CI/build-pipeline changes | No release |
| `chore` | Dependency bumps, housekeeping | No release |
| `build` | Build-system or packaging changes | No release |

Any commit with `BREAKING CHANGE:` in the footer or `!` after the type triggers a **major** version bump. Don't use `!` casually — for a 0.x project it bumps you straight to 1.0.0.

## Subject style

- Start lowercase: `feat: add foo`, not `feat: Add foo`
- Imperative mood: `fix: correct typo`, not `fix: corrected typo`
- No trailing period
- Keep it under ~72 characters

## Scopes (optional)

Use a scope when it clarifies the area of change:

```
feat(linux): add inotify-based real-time mode
fix(windows): handle long paths over 260 chars
fix(rpm): preserve config on upgrade
```

There's no closed list of valid scopes — use what makes sense. Common ones in this codebase: `linux`, `windows`, `compare`, `registry`, `cli`, `deb`, `rpm`, `msi`, `ci`.

## What happens after merge

When your PR lands on `main`:

1. **The `release` workflow runs.** It analyzes commits since the last tag.
2. **If your commit type warrants a release** (`feat`, `fix`, `perf`, or anything with `BREAKING`), python-semantic-release:
   - Computes the next version
   - Writes it into `pyproject.toml`
   - Updates `CHANGELOG.md`
   - Commits with message `chore(release): X.Y.Z [skip ci]`
   - Tags the commit `vX.Y.Z`
   - Creates a GitHub Release
3. **Build jobs fire automatically** and attach the .deb / .rpm / .msi / binaries / wheel to that release.
4. **A `chore:` or `docs:` commit produces no release** — your change is on main but no version was cut. The next `feat:` or `fix:` will pick it up in the changelog.

## Local checks before opening a PR

```sh
# Make sure the package still builds
bash scripts/build-linux.sh

# Make sure your commit message previews correctly
echo "feat(scope): subject" | grep -E '^(feat|fix|perf|refactor|docs|style|test|ci|chore|build)(\([^)]+\))?!?: [a-z]'
```

## Repository settings checklist

For maintainers — when first wiring this up, verify:

**Settings → General → Pull Requests:**
- ✅ Allow squash merging
- ✅ "Default to PR title for squash merge commits" (this is the critical one)
- ❌ Allow merge commits (off — keeps history linear)
- ❌ Allow rebase merging (off — bypasses PR title validation)

**Settings → Branches → Branch protection rule for `main`:**
- ✅ Require pull request before merging
- ✅ Require status checks: `Validate PR title`, `linux`, `windows`
- ✅ Require branches to be up to date before merging

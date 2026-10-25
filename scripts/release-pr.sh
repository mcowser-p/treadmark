#!/usr/bin/env bash
# Scaffold the release PR that the PR-gated release flow requires.
#
# main's ruleset forbids direct pushes — including from CI — so release.yml
# never commits the version bump. A human (or their coding agent) must land a
# release PR that stamps the computed next version; once it is squash-merged,
# the workflow sees pyproject match that version and tags + publishes.
# This script does the mechanical part:
#
#   1. verify a clean main checkout at origin/main
#   2. compute the next version exactly like CI does
#      (`semantic-release version --print` — pure, no tag/commit/push)
#   3. create branch release/vX.Y.Z
#   4. stamp pyproject.toml + src/treadmark/__init__.py (stamp_version.py)
#   5. draft a CHANGELOG.md section from the commit subjects since last tag
#
# It deliberately stops before committing: the drafted changelog bullets are
# raw commit subjects, and released entries read as curated prose (see
# CHANGELOG.md) — polish first, then commit/push/PR with the printed commands.
#
# Needs: git, python3, python-semantic-release
# (`pip install "python-semantic-release>=10,<11"` — same pin as CI), and
# `gh` for the final step.

set -euo pipefail

die() { echo "release-pr: $*" >&2; exit 1; }

cd "$(git rev-parse --show-toplevel)"

command -v semantic-release >/dev/null 2>&1 \
  || die 'python-semantic-release not found — pip install "python-semantic-release>=10,<11"'
[ -z "$(git status --porcelain)" ] || die "working tree not clean"
[ "$(git branch --show-current)" = "main" ] || die "run this from main"

git fetch --quiet --tags origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
  || die "main is not at origin/main — pull (or push) first"

# The same no-side-effect computation release.yml's `version` job does:
# a release is warranted iff the next version differs from the last released.
next=$(semantic-release version --print 2>/dev/null || true)
last=$(semantic-release version --print-last-released 2>/dev/null || true)
{ [ -n "$next" ] && [ "$next" != "$last" ]; } \
  || die "no release warranted — no feat:/fix:/perf: commit since ${last:-the beginning}"

pyver=$(sed -n 's/^version = "\(.*\)"$/\1/p' pyproject.toml | head -n1)
[ "$pyver" != "$next" ] \
  || die "pyproject.toml is already stamped $next — the release PR is merged or in flight"

branch="release/v$next"
git rev-parse -q --verify "refs/heads/$branch" >/dev/null \
  && die "local branch $branch already exists"
git ls-remote --exit-code --heads origin "$branch" >/dev/null 2>&1 \
  && die "branch $branch already exists on origin — is a release PR open?"

echo "release-pr: next version $next (last released: ${last:-none})"
git switch -c "$branch"
python3 scripts/stamp_version.py "$next"

python3 - "$next" "$last" <<'PYEOF'
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

version, last = sys.argv[1], sys.argv[2]
rng = f"v{last}..HEAD" if last else "HEAD"
subjects = subprocess.run(
    ["git", "log", rng, "--no-merges", "--pretty=%s"],
    check=True, capture_output=True, text=True,
).stdout.splitlines()

sections = {"Breaking Changes": [], "Features": [], "Bug Fixes": [],
            "Performance Improvements": []}
by_type = {"feat": "Features", "fix": "Bug Fixes",
           "perf": "Performance Improvements"}
pat = re.compile(r"^(feat|fix|perf)(?:\(([^)]*)\))?(!)?:\s*(.+)$")
for line in subjects:
    m = pat.match(line)
    if not m:
        continue
    typ, scope, bang, subject = m.groups()
    bullet = f"- **{scope}:** {subject}" if scope else f"- {subject}"
    sections["Breaking Changes" if bang else by_type[typ]].append(bullet)

today = datetime.now(timezone.utc).date().isoformat()
entry = [f"## v{version} ({today})", ""]
for title, bullets in sections.items():
    if bullets:
        entry += [f"### {title}", "", *bullets, ""]
text = "\n".join(entry) + "\n"

path = Path("CHANGELOG.md")
content = path.read_text(encoding="utf-8")
i = content.find("\n## v")
if i == -1:  # no released entries yet — append after the intro
    content = content.rstrip("\n") + "\n\n" + text
else:
    content = content[: i + 1] + text + content[i + 1:]
path.write_text(content, encoding="utf-8")
print(f"release-pr: drafted CHANGELOG.md section for v{version}")
PYEOF

git --no-pager diff --stat
cat <<EOF

Scaffolded on branch $branch. To finish:

  1. Polish the new CHANGELOG.md section into prose — the bullets are raw
     commit subjects; match the tone of the earlier entries.
  2. git add -A && git commit -m "chore(release): cut $next"
  3. git push -u origin $branch
  4. gh pr create --title "chore(release): cut $next" --body \\
       "Stamps $next into pyproject.toml, __init__.py, and CHANGELOG.md. On merge, release.yml sees pyproject match the computed version and tags + publishes v$next."
  5. Squash-merge it (the PR title becomes the commit, as usual). The push
     to main re-runs the workflow, which then tags and publishes v$next.
EOF

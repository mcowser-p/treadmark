#!/usr/bin/env python3
"""Stamp a version into the two files semantic-release owns, without git.

CI computes the next release version up front (a no-side-effect
`semantic-release version --print`) and builds the artifacts BEFORE the tag
or GitHub Release exists — so nothing is published unless the build and smoke
jobs go green. The build jobs call this to write that computed version into
the working tree, so the .deb/.rpm/.msi metadata and `cairn --version` all
report the version that is about to be released.

These are the SAME two locations pinned in pyproject.toml's
[tool.semantic_release] (version_toml + version_variables). Keep them in sync:
    version_toml      = ["pyproject.toml:project.version"]
    version_variables = ["src/cairn/__init__.py:__version__"]

Usage:  python scripts/stamp_version.py 1.2.3
"""

from __future__ import annotations

import pathlib
import re
import sys


def _replace(path: pathlib.Path, pattern: str, repl: str) -> None:
    text = path.read_text(encoding="utf-8")
    new, n = re.subn(pattern, repl, text, count=1, flags=re.MULTILINE)
    if n != 1:
        raise SystemExit(f"stamp_version: no version line matched in {path}")
    path.write_text(new, encoding="utf-8")


def main() -> None:
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        raise SystemExit("usage: stamp_version.py <version>")
    version = sys.argv[1].strip().lstrip("v")
    root = pathlib.Path(__file__).resolve().parent.parent

    # pyproject.toml -> [project] version = "X"  (first `version =`, under [project])
    _replace(
        root / "pyproject.toml",
        r'^(version\s*=\s*)"[^"]*"',
        rf'\1"{version}"',
    )
    # src/cairn/__init__.py -> __version__ = "X"
    _replace(
        root / "src" / "cairn" / "__init__.py",
        r'^(__version__\s*=\s*)"[^"]*"',
        rf'\1"{version}"',
    )
    print(f"stamped version {version}")


if __name__ == "__main__":
    main()

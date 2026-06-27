#!/usr/bin/env bash
# scripts/build-wheel.sh — builds the platform-independent wheel for pipx/PyPI
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
# PEP 668 environments (modern Debian/Ubuntu) need --break-system-packages.
# CI runners don't, but the flag is harmless on a clean Python.
PIP_FLAGS=""
if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    PIP_FLAGS="--break-system-packages"
fi
python3 -m pip install --quiet --upgrade build $PIP_FLAGS
python3 -m build --wheel --outdir dist/

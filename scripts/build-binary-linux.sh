#!/usr/bin/env bash
# scripts/build-binary-linux.sh — single-file PyInstaller binary for Linux
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
PIP_FLAGS=""
if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    PIP_FLAGS="--break-system-packages"
fi
python3 -m pip install --quiet pyinstaller pyyaml $PIP_FLAGS

rm -rf build/_pyi dist/_pyi
pyinstaller \
    --onefile \
    --name cairn \
    --distpath dist/_pyi \
    --workpath build/_pyi \
    --specpath build/ \
    --paths src \
    --hidden-import yaml \
    scripts/cairn_launcher.py >/dev/null

ARCH=$(uname -m)   # x86_64, aarch64, etc.
mv dist/_pyi/cairn "dist/cairn-linux-${ARCH}"
rm -rf dist/_pyi
echo "built: dist/cairn-linux-${ARCH}"

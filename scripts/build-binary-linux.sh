#!/usr/bin/env bash
# scripts/build-binary-linux.sh — single-file COMPILED binary for Linux.
#
# Nuitka, not PyInstaller: PyInstaller bundles bytecode (recoverable to
# near-source with pyinstxtractor + a decompiler); Nuitka transpiles the
# package to C and compiles it, so the shipped binary contains machine
# code, not .pyc payloads. Strings (messages, SQL) remain visible — the
# protected part is the logic.
#
# BUILD HOST SETS THE GLIBC FLOOR: the compiled binary takes the build
# host's versioned glibc symbols, so it only runs on distros with glibc >=
# the build host's. Release/CI builds run in an almalinux:9 container
# (glibc 2.34) so the artifacts run on EL9, EL10, Amazon Linux 2023, and
# Ubuntu 24.04. Building on a newer distro (e.g. Ubuntu 24.04, glibc 2.39)
# produces binaries that die on AL2023/EL9 with "GLIBC_2.38 not found".
set -euo pipefail
cd "$(dirname "$0")/.."

mkdir -p dist
PIP_FLAGS=""
if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    PIP_FLAGS="--break-system-packages"
fi
# patchelf: Nuitka needs the binary on Linux (the PyPI wheel ships it).
# Install treadmark itself so Nuitka resolves the package like any import.
python3 -m pip install --quiet $PIP_FLAGS nuitka patchelf pyyaml
python3 -m pip install --quiet $PIP_FLAGS -e .

# {VERSION} in the tempdir spec requires a declared product version.
VERSION=$(python3 -c "import tomllib; print(tomllib.loads(open('pyproject.toml','rb').read().decode())['project']['version'])")

rm -rf build/_nuitka
python3 -m nuitka \
    --onefile \
    --assume-yes-for-downloads \
    --include-package=treadmark \
    --include-package=yaml \
    --product-version="$VERSION" \
    --onefile-tempdir-spec='{CACHE_DIR}/treadmark/{VERSION}' \
    --output-filename=treadmark \
    --output-dir=build/_nuitka \
    scripts/treadmark_launcher.py
# --onefile-tempdir-spec caches the self-extraction per version: a scan
# tool gets invoked repeatedly (cron, CI), so first-run-only extraction
# matters.

ARCH=$(uname -m)   # x86_64, aarch64, etc.
mv build/_nuitka/treadmark "dist/treadmark-linux-${ARCH}"
rm -rf build/_nuitka
echo "built: dist/treadmark-linux-${ARCH}"

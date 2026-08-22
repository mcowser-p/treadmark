#!/usr/bin/env bash
# scripts/bootstrap.sh
# One-shot setup for a fresh clone of treadmark. Installs build deps so
# `bash scripts/build-linux.sh` works immediately afterward.

set -euo pipefail
cd "$(dirname "$0")/.."

echo ">>> Detecting environment..."

if ! command -v python3 >/dev/null 2>&1; then
    echo "[!] python3 is required (3.9 or later)" >&2
    exit 1
fi

PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "    python3 ${PY_VER}"

# Linux distros only — Windows runs scripts/bootstrap.ps1
if [ "$(uname)" != "Linux" ]; then
    echo "    non-Linux host detected; skipping package-tool checks"
    echo "    (on Windows, run scripts/bootstrap.ps1 instead)"
fi

PIP_FLAGS=""
if python3 -m pip install --help 2>/dev/null | grep -q break-system-packages; then
    PIP_FLAGS="--break-system-packages"
fi

echo ">>> Installing Python build dependencies..."
python3 -m pip install --quiet --upgrade pip $PIP_FLAGS || true
python3 -m pip install --quiet build pyinstaller pyyaml $PIP_FLAGS

if [ "$(uname)" = "Linux" ]; then
    echo ">>> Checking distro packaging tools..."
    MISSING=()
    command -v dpkg-deb >/dev/null 2>&1 || MISSING+=("dpkg-deb (apt: dpkg-dev)")
    command -v rpmbuild >/dev/null 2>&1 || MISSING+=("rpmbuild (apt: rpm | dnf: rpm-build)")
    if [ ${#MISSING[@]} -ne 0 ]; then
        echo "[i] Optional packaging tools missing; install them if you want to build .deb/.rpm:"
        for tool in "${MISSING[@]}"; do
            echo "      - $tool"
        done
    fi
fi

echo ">>> Installing treadmark in editable mode for local testing..."
python3 -m pip install -e ".[all]" $PIP_FLAGS

# Conventional-commit enforcement: PR titles/commits drive releases via
# python-semantic-release, so catch malformed messages at commit time.
if command -v git >/dev/null 2>&1 && [ -d .git ] && [ -d .githooks ]; then
    echo ">>> Enabling repo git hooks (.githooks/commit-msg)..."
    git config core.hooksPath .githooks
    chmod +x .githooks/* 2>/dev/null || true
fi

echo ""
echo "Bootstrap complete. Try:"
echo "  treadmark --version"
echo "  bash scripts/build-linux.sh           # produce dist/*.{whl,deb,rpm,binary}"
echo "  bash scripts/build-wheel.sh           # produce wheel only"
echo ""

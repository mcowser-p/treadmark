#!/usr/bin/env bash
# scripts/build-linux.sh
# Orchestrates Linux artifact builds. Each step is a separate script so
# CI can parallelize and you can run them individually for debugging.
set -euo pipefail
cd "$(dirname "$0")/.."

# NOTE: build-wheel.sh is deliberately NOT run here. A wheel is a zip of
# the literal source — publishing it on releases defeated the compiled
# (Nuitka) binaries. The script is kept for a future private index; run it
# by hand if you need a wheel.
scripts/build-binary-linux.sh
scripts/build-deb.sh
scripts/build-rpm.sh

ls -lh dist/

#!/usr/bin/env bash
# scripts/build-linux.sh
# Orchestrates Linux artifact builds. Each step is a separate script so
# CI can parallelize and you can run them individually for debugging.
set -euo pipefail
cd "$(dirname "$0")/.."

scripts/build-wheel.sh
scripts/build-binary-linux.sh
scripts/build-deb.sh
scripts/build-rpm.sh

ls -lh dist/

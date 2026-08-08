#!/usr/bin/env bash
# scripts/smoke-local.sh — build + smoke-test the packaged artifacts against
# real target distros locally, using docker or podman. Works on macOS
# (Apple Silicon or Intel) and Linux; artifacts are built for the host's
# container architecture.
#
#   bash scripts/smoke-local.sh              # build if needed, test all targets
#   bash scripts/smoke-local.sh --rebuild    # force a fresh artifact build
#   SMOKE_IMAGES="almalinux:10" bash scripts/smoke-local.sh   # subset
#
# Targets default to Ubuntu 24.04 LTS, AlmaLinux 10 (RHEL 10 family), and
# Amazon Linux 2023.

set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)

BUILD_IMAGE="almalinux:9"
SMOKE_IMAGES="${SMOKE_IMAGES:-ubuntu:24.04 almalinux:10 amazonlinux:2023}"

if command -v docker >/dev/null 2>&1; then
    RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
else
    echo "[!] neither docker nor podman found on PATH" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Stage 1: build artifacts inside a Linux container (macOS can't run
# dpkg-deb/rpmbuild/Nuitka-for-linux natively). Produces artifacts for
# the container architecture — arm64 on Apple Silicon, matching the test
# images below.
#
# almalinux:9 on purpose, matching CI: the Nuitka binary takes the build
# host's glibc floor (see build-binary-linux.sh), and EL9's glibc 2.34 is
# the oldest among the supported targets. dpkg-deb comes from EPEL there.
# ---------------------------------------------------------------------------
have_artifacts() {
    ls dist/cairn_*.deb >/dev/null 2>&1 && ls dist/cairn-*.rpm >/dev/null 2>&1
}

if [ "${1:-}" = "--rebuild" ] || ! have_artifacts; then
    echo ">>> building artifacts in $BUILD_IMAGE ($RUNTIME)"
    "$RUNTIME" run --rm -v "$REPO":/src -w /src "$BUILD_IMAGE" bash -ec '
        dnf install -qy epel-release >/dev/null
        dnf install -qy python3.12 python3.12-pip python3.12-devel \
            gcc make dpkg rpm-build binutils file git-core >/dev/null
        ln -sf /usr/bin/python3.12 /usr/local/bin/python3
        bash scripts/bootstrap.sh
        bash scripts/build-linux.sh
    '
else
    echo ">>> reusing existing artifacts in dist/ (pass --rebuild to force)"
fi
ls -lh dist/cairn_*.deb dist/cairn-*.rpm

# ---------------------------------------------------------------------------
# Stage 2: run the smoke test inside each target distro.
#
# Captured footprint JSONs persist under smoke-out/<distro>/ on the host
# for post-run inspection. SMOKE_DEBUG=1 additionally dumps each full
# model into the log (default off — the JSONs in smoke-out/ usually
# suffice).
# ---------------------------------------------------------------------------
declare -a passed=() failed=()
for image in $SMOKE_IMAGES; do
    outdir="$REPO/smoke-out/$(echo "$image" | tr ':/' '--')"
    mkdir -p "$outdir"
    echo ""
    echo "=============================================================="
    echo ">>> smoke: $image   (footprints → ${outdir#"$REPO"/})"
    echo "=============================================================="
    if "$RUNTIME" run --rm \
        -v "$REPO/dist":/dist:ro \
        -v "$REPO/scripts/smoke-test.sh":/smoke-test.sh:ro \
        -v "$outdir":/smoke-out \
        -e FOOTPRINT_DIR=/smoke-out \
        -e SMOKE_DEBUG="${SMOKE_DEBUG:-0}" \
        -e SMOKE_EXTENDED="${SMOKE_EXTENDED:-1}" \
        "$image" bash /smoke-test.sh; then
        passed+=("$image")
    else
        failed+=("$image")
    fi
done

echo ""
echo "=============================================================="
[ ${#passed[@]} -gt 0 ] && echo "PASS: ${passed[*]}"
if [ ${#failed[@]} -gt 0 ]; then
    echo "FAIL: ${failed[*]}"
    exit 1
fi
echo "all targets passed"

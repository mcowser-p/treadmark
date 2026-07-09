#!/usr/bin/env bash
# scripts/smoke-test.sh — artifact-level smoke test, run INSIDE a target
# distro (container or VM) as root.
#
# Installs the built .deb/.rpm from $DIST_DIR (default /dist), then walks a
# full operator cycle with the SHIPPED default config: init → clean scan →
# plant drift → detect → accept → clean again → provenance. Validates the
# packaged binary (glibc compat, bundled PyYAML), the postinstall contract,
# and that the curated exclude list still watches tamper targets.
#
# Used by: scripts/smoke-local.sh (docker/podman), .github/workflows/*.yml
# (container: jobs), and scripts/smoke-vm.sh (Lima VMs).

set -euo pipefail

DIST_DIR="${DIST_DIR:-/dist}"
CFG=/etc/cairn/cairn.yaml

step() { printf '\n>>> %s\n' "$*"; }
fail() { printf '[SMOKE FAIL] %s\n' "$*" >&2; exit 1; }

. /etc/os-release
step "smoke test on: ${PRETTY_NAME:-unknown} ($(uname -m))"

# ---------------------------------------------------------------------------
# 1. Install the packaged artifact
# ---------------------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    DEB_ARCH=$(dpkg --print-architecture)
    pkg=$(ls "$DIST_DIR"/cairn_*_"${DEB_ARCH}".deb 2>/dev/null | head -n1) \
        || fail "no .deb for ${DEB_ARCH} in $DIST_DIR"
    step "installing $pkg"
    # No Depends declared today; fall back to apt -f if that ever changes.
    dpkg -i "$pkg" || { apt-get update -qq && apt-get install -qq -y -f; }
elif command -v dnf >/dev/null 2>&1; then
    RPM_ARCH=$(uname -m)
    pkg=$(ls "$DIST_DIR"/cairn-*."${RPM_ARCH}".rpm 2>/dev/null | head -n1) \
        || fail "no .rpm for ${RPM_ARCH} in $DIST_DIR"
    step "installing $pkg"
    dnf install -qy "$pkg" || rpm -i "$pkg"
else
    fail "neither apt-get nor dnf found; unsupported target"
fi

# ---------------------------------------------------------------------------
# 2. Binary runs, packaged layout is right
# ---------------------------------------------------------------------------
step "cairn --version"
cairn --version || fail "binary does not execute (glibc/arch mismatch?)"

step "packaged layout"
[ -f "$CFG" ] || fail "shipped config missing: $CFG"
[ -d /var/lib/cairn ] || fail "/var/lib/cairn missing (postinstall contract)"
perms=$(stat -c '%a' /var/lib/cairn)
[ "$perms" = "700" ] || fail "/var/lib/cairn is mode $perms, expected 700"

# ---------------------------------------------------------------------------
# 3. Baseline cycle with the shipped default config
# ---------------------------------------------------------------------------
step "init baseline (shipped config — exercises bundled PyYAML)"
cairn files init --config "$CFG" || fail "init failed"

step "clean scan expects exit 0"
rc=0; cairn files scan --config "$CFG" >/tmp/scan-clean.out 2>&1 || rc=$?
[ "$rc" -eq 0 ] || { cat /tmp/scan-clean.out; fail "clean scan exited $rc"; }

step "plant drift (new file + /etc/hosts edit)"
echo "smoke-test marker" > /etc/cairn-smoke-drift.conf
echo "203.0.113.99 smoke-test.invalid" >> /etc/hosts

step "drift scan expects exit 1 and both paths reported"
rc=0; cairn files scan --config "$CFG" --report /tmp/smoke.json >/tmp/scan-drift.out 2>&1 || rc=$?
[ "$rc" -eq 1 ] || { cat /tmp/scan-drift.out; fail "drift scan exited $rc, expected 1"; }
grep -q '"has_drift": true' /tmp/smoke.json || fail "report lacks has_drift=true"
grep -q '/etc/cairn-smoke-drift.conf' /tmp/smoke.json || fail "planted file not reported"
grep -q '/etc/hosts' /tmp/smoke.json \
    || fail "/etc/hosts edit not reported — is the exclude list too aggressive?"

step "accept the drift, rescan expects exit 0"
rc=0; cairn files update --config "$CFG" \
    --accept /etc/cairn-smoke-drift.conf --accept /etc/hosts >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "update run exited $rc (expected 1: it reports the drift it accepts)"
rc=0; cairn files scan --config "$CFG" >/tmp/scan-after.out 2>&1 || rc=$?
[ "$rc" -eq 0 ] || { cat /tmp/scan-after.out; fail "post-accept scan exited $rc"; }

step "baseline provenance"
cairn baseline info --config "$CFG" | grep -q "DB SHA-256" || fail "baseline info broken"

# ---------------------------------------------------------------------------
# 4. Context notes (VMs only — containers have no SELinux of their own)
# ---------------------------------------------------------------------------
if command -v getenforce >/dev/null 2>&1; then
    step "SELinux: $(getenforce)"
fi

printf '\nSMOKE PASS: %s (%s)\n' "${PRETTY_NAME:-unknown}" "$(uname -m)"

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
# Accept the two changed files AND the /etc directory record itself:
# planting a file updates the parent dir's mtime, and if init and the
# plant straddle an integer second, the dir shows as modified too.
# (--accept on a directory covers everything beneath it.)
rc=0; cairn files update --config "$CFG" \
    --accept /etc/cairn-smoke-drift.conf --accept /etc/hosts \
    --accept /etc >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "update run exited $rc (expected 1: it reports the drift it accepts)"
rc=0; cairn files scan --config "$CFG" >/tmp/scan-after.out 2>&1 || rc=$?
[ "$rc" -eq 0 ] || { cat /tmp/scan-after.out; fail "post-accept scan exited $rc"; }

step "baseline provenance"
cairn baseline info --config "$CFG" | grep -q "DB SHA-256" || fail "baseline info broken"

# ---------------------------------------------------------------------------
# 4. Footprint capture of a real package install — the core use case.
# Baseline → install nginx from the distro repos → `cairn footprint` must
# surface the systemd unit, the binary, and the runs-as-root risk.
#
# Uses a dedicated config: units land in /usr/lib/systemd/system, which the
# shipped forensic default deliberately doesn't watch (this mirrors the
# documented footprint workflow of using a footprint-tuned config).
# ---------------------------------------------------------------------------
step "footprint: baseline with footprint-tuned config"
FP_CFG=/tmp/footprint-config.json
cat > "$FP_CFG" <<'EOF'
{
  "db_path": "/var/lib/cairn/footprint-baseline.db",
  "paths": ["/etc", "/usr/bin", "/usr/sbin", "/usr/lib/systemd/system",
            "/var/spool/cron"],
  "exclude": ["/etc/ld.so.cache", "/etc/mtab", "/etc/resolv.conf",
              "/etc/adjtime", "/etc/.pwd.lock"],
  "store_content": true,
  "store_content_max_kb": 512
}
EOF
cairn files init --config "$FP_CFG" || fail "footprint baseline init failed"

step "footprint: install nginx from distro repos"
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -qq -y nginx >/dev/null
else
    dnf install -qy nginx >/dev/null
fi

step "footprint: capture and verify the install footprint"
rc=0; cairn footprint --config "$FP_CFG" --app nginx \
    --report /tmp/footprint.json >/tmp/footprint.out 2>&1 || rc=$?
[ "$rc" -eq 1 ] || { cat /tmp/footprint.out; fail "footprint exited $rc, expected 1 (changes present)"; }

grep -q '"nginx.service"' /tmp/footprint.json \
    || fail "footprint missed the nginx systemd unit"
grep -q '/usr/sbin/nginx' /tmp/footprint.json \
    || fail "footprint missed the nginx binary"
grep -q '"service_runs_as_root"' /tmp/footprint.json \
    || fail "footprint missed the service_runs_as_root risk (nginx unit has no User=)"
grep -q '/etc/nginx' /tmp/footprint.json \
    || fail "footprint missed the /etc/nginx config tree"

# Distro-dependent extras, informational only: Alma's nginx package creates
# an 'nginx' user; Ubuntu reuses the pre-existing www-data.
if grep -q '"name": "nginx"' /tmp/footprint.json; then
    step "footprint: nginx service account creation captured (users_added)"
fi

# ---------------------------------------------------------------------------
# 5. Context notes (VMs only — containers have no SELinux of their own)
# ---------------------------------------------------------------------------
if command -v getenforce >/dev/null 2>&1; then
    step "SELinux: $(getenforce)"
fi

printf '\nSMOKE PASS: %s (%s)\n' "${PRETTY_NAME:-unknown}" "$(uname -m)"

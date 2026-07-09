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
# 3b. Drift detection in EVERY watched top folder — one marker per top dir
# from the shipped config, each individually asserted in the report.
# (/bin and /sbin are usr-merged symlinks on modern distros; the marker
# then also appears under /usr/bin — both spellings being reported is
# correct behavior, we assert the path we planted.)
# ---------------------------------------------------------------------------
step "per-top-folder drift: plant one marker in each watched top dir"
planted=""
for d in /etc /bin /sbin /usr/bin /usr/sbin /boot; do
    if [ ! -d "$d" ]; then
        echo "    (skipping $d — not present on this target)"
        continue
    fi
    marker="$d/cairn-smoke-marker-$(echo "${d#/}" | tr '/' '-')"
    echo "smoke marker" > "$marker"
    planted="$planted $marker"
done
[ -n "$planted" ] || fail "no top dirs available to plant markers in"

step "per-top-folder drift: scan reports every marker"
rc=0; cairn files scan --config "$CFG" --report /tmp/topdirs.json >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "top-folder drift scan exited $rc, expected 1"
for p in $planted; do
    grep -q "\"$p\"" /tmp/topdirs.json \
        || fail "marker not reported: $p — is that top folder being walked?"
done
echo "    all markers reported:$planted"

step "per-top-folder drift: accept-all, rescan expects exit 0"
rc=0; cairn files update --config "$CFG" --accept-all >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "accept-all update exited $rc (expected 1: it reports what it accepts)"
rc=0; cairn files scan --config "$CFG" >/tmp/scan-topdirs.out 2>&1 || rc=$?
[ "$rc" -eq 0 ] || { cat /tmp/scan-topdirs.out; fail "post-accept-all scan exited $rc"; }

# ---------------------------------------------------------------------------
# 3c. A brand-new top-level folder is fully captured. The watched path does
# not exist at baseline time (init warns and skips it); when it appears,
# the scan must report the directory tree AND everything nested inside.
# ---------------------------------------------------------------------------
step "new top folder: baseline a watched path that doesn't exist yet"
NT_CFG=/tmp/newtop-config.json
cat > "$NT_CFG" <<'EOF'
{
  "db_path": "/var/lib/cairn/newtop-baseline.db",
  "paths": ["/cairn-smoke-newtop"],
  "store_content": true
}
EOF
cairn files init --config "$NT_CFG" >/dev/null 2>&1 || fail "newtop baseline init failed"

step "new top folder: create /cairn-smoke-newtop with a nested tree"
mkdir -p /cairn-smoke-newtop/nested/deeper
echo "top-level file"  > /cairn-smoke-newtop/app.conf
echo "nested payload"  > /cairn-smoke-newtop/nested/deeper/data.bin
printf '\x7fELF fake' > /cairn-smoke-newtop/nested/tool
chmod 755 /cairn-smoke-newtop/nested/tool

step "new top folder: scan captures the entire tree"
rc=0; cairn files scan --config "$NT_CFG" --report /tmp/newtop.json >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "newtop scan exited $rc, expected 1"
for p in /cairn-smoke-newtop \
         /cairn-smoke-newtop/app.conf \
         /cairn-smoke-newtop/nested \
         /cairn-smoke-newtop/nested/tool \
         /cairn-smoke-newtop/nested/deeper \
         /cairn-smoke-newtop/nested/deeper/data.bin; do
    grep -q "\"$p\"" /tmp/newtop.json \
        || fail "new top folder capture missed: $p"
done
echo "    full tree captured (dirs + nested files + executable)"

# ---------------------------------------------------------------------------
# 4. Footprint capture of real package installs — the core use case.
# Fresh baseline → install a package from the distro repos → `cairn
# footprint` must surface the systemd unit, the binary, the config tree,
# and the runs-as-root risk. Runs for nginx and Apache — Apache's package,
# unit, binary, and config tree all differ across distro families
# (apache2 on Debian/Ubuntu, httpd on RHEL-family), which is exactly the
# variation worth testing.
#
# Uses a dedicated config: units land in /usr/lib/systemd/system, which the
# shipped forensic default deliberately doesn't watch (this mirrors the
# documented footprint workflow of using a footprint-tuned config).
# ---------------------------------------------------------------------------
step "footprint: write footprint-tuned config"
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

# FOOTPRINT_DIR lets CI place the JSON models somewhere it can collect
# them as artifacts; defaults to /tmp for local runs.
FOOTPRINT_DIR="${FOOTPRINT_DIR:-/tmp}"

if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq
fi

# capture_footprint <app> <package> <unit> <binary> <config-tree>
# Re-baselines first so each footprint contains only its own package,
# then installs, captures, asserts the semantic objects, and prints the
# summary of what the install touched.
capture_footprint() {
    app="$1"; pkg="$2"; unit="$3"; binary="$4"; conf="$5"
    json="$FOOTPRINT_DIR/footprint-$app.json"

    step "footprint($app): fresh baseline"
    cairn files init --config "$FP_CFG" --force >/dev/null \
        || fail "footprint($app): baseline init failed"

    step "footprint($app): install $pkg from distro repos"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -qq -y "$pkg" >/dev/null
    else
        dnf install -qy "$pkg" >/dev/null
    fi

    step "footprint($app): capture and verify"
    rc=0; cairn footprint --config "$FP_CFG" --app "$app" \
        --report "$json" >"/tmp/footprint-$app.out" 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || { cat "/tmp/footprint-$app.out";
        fail "footprint($app) exited $rc, expected 1 (changes present)"; }

    grep -q "\"$unit\"" "$json" \
        || fail "footprint($app) missed the $unit systemd unit"
    grep -q "$binary" "$json" \
        || fail "footprint($app) missed the $binary binary"
    grep -q '"service_runs_as_root"' "$json" \
        || fail "footprint($app) missed the service_runs_as_root risk ($unit has no User=)"
    grep -q "$conf" "$json" \
        || fail "footprint($app) missed the $conf config tree"

    # Show what the install actually did — the whole point of the exercise.
    step "footprint($app): what the install touched"
    cat "/tmp/footprint-$app.out"
    echo "    (full model: $json)"

    # SMOKE_DEBUG=1 dumps the entire JSON model into the log — verbose,
    # but invaluable when a grep assertion above starts failing.
    if [ "${SMOKE_DEBUG:-0}" = "1" ]; then
        step "footprint($app): full model (SMOKE_DEBUG=1)"
        cat "$json"
    fi

    # Informational: some packages create their service account (Alma's
    # nginx/httpd), others reuse a pre-existing one (Ubuntu's www-data).
    if ! grep -q '"users_added": \[\]' "$json"; then
        step "footprint($app): service account creation captured (users_added)"
    fi
}

capture_footprint nginx nginx nginx.service /usr/sbin/nginx /etc/nginx
if command -v apt-get >/dev/null 2>&1; then
    capture_footprint apache apache2 apache2.service /usr/sbin/apache2 /etc/apache2
else
    capture_footprint apache httpd httpd.service /usr/sbin/httpd /etc/httpd
fi

# ---------------------------------------------------------------------------
# 5. Context notes (VMs only — containers have no SELinux of their own)
# ---------------------------------------------------------------------------
if command -v getenforce >/dev/null 2>&1; then
    step "SELinux: $(getenforce)"
fi

printf '\nSMOKE PASS: %s (%s)\n' "${PRETTY_NAME:-unknown}" "$(uname -m)"

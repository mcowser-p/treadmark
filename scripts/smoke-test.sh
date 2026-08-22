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
CFG=/etc/treadmark/treadmark.yaml

step() { printf '\n>>> %s\n' "$*"; }
fail() { printf '[SMOKE FAIL] %s\n' "$*" >&2; exit 1; }

. /etc/os-release
step "smoke test on: ${PRETTY_NAME:-unknown} ($(uname -m))"

# ---------------------------------------------------------------------------
# 1. Install the packaged artifact
# ---------------------------------------------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    DEB_ARCH=$(dpkg --print-architecture)
    pkg=$(ls "$DIST_DIR"/treadmark_*_"${DEB_ARCH}".deb 2>/dev/null | head -n1) \
        || fail "no .deb for ${DEB_ARCH} in $DIST_DIR"
    step "installing $pkg"
    # No Depends declared today; fall back to apt -f if that ever changes.
    dpkg -i "$pkg" || { apt-get update -qq && apt-get install -qq -y -f; }
elif command -v dnf >/dev/null 2>&1; then
    RPM_ARCH=$(uname -m)
    pkg=$(ls "$DIST_DIR"/treadmark-*."${RPM_ARCH}".rpm 2>/dev/null | head -n1) \
        || fail "no .rpm for ${RPM_ARCH} in $DIST_DIR"
    step "installing $pkg"
    dnf install -qy "$pkg" || rpm -i "$pkg"
else
    fail "neither apt-get nor dnf found; unsupported target"
fi

# ---------------------------------------------------------------------------
# 2. Binary runs, packaged layout is right
# ---------------------------------------------------------------------------
step "treadmark --version"
treadmark --version || fail "binary does not execute (glibc/arch mismatch?)"

step "packaged layout"
[ -f "$CFG" ] || fail "shipped config missing: $CFG"
[ -d /var/lib/treadmark ] || fail "/var/lib/treadmark missing (postinstall contract)"
perms=$(stat -c '%a' /var/lib/treadmark)
[ "$perms" = "700" ] || fail "/var/lib/treadmark is mode $perms, expected 700"

# ---------------------------------------------------------------------------
# 3. Baseline cycle with the shipped default config
# ---------------------------------------------------------------------------
step "init baseline (shipped config — exercises bundled PyYAML)"
treadmark files init --config "$CFG" || fail "init failed"

step "clean scan expects exit 0"
rc=0; treadmark files scan --config "$CFG" >/tmp/scan-clean.out 2>&1 || rc=$?
[ "$rc" -eq 0 ] || { cat /tmp/scan-clean.out; fail "clean scan exited $rc"; }

step "plant drift (new file + /etc/hosts edit)"
echo "smoke-test marker" > /etc/treadmark-smoke-drift.conf
echo "203.0.113.99 smoke-test.invalid" >> /etc/hosts

step "drift scan expects exit 1 and both paths reported"
rc=0; treadmark files scan --config "$CFG" --report /tmp/smoke.json >/tmp/scan-drift.out 2>&1 || rc=$?
[ "$rc" -eq 1 ] || { cat /tmp/scan-drift.out; fail "drift scan exited $rc, expected 1"; }
grep -q '"has_drift": true' /tmp/smoke.json || fail "report lacks has_drift=true"
grep -q '/etc/treadmark-smoke-drift.conf' /tmp/smoke.json || fail "planted file not reported"
grep -q '/etc/hosts' /tmp/smoke.json \
    || fail "/etc/hosts edit not reported — is the exclude list too aggressive?"

step "accept the drift, rescan expects exit 0"
# Accept the two changed files AND the /etc directory record itself:
# planting a file updates the parent dir's mtime, and if init and the
# plant straddle an integer second, the dir shows as modified too.
# (--accept on a directory covers everything beneath it.)
rc=0; treadmark files update --config "$CFG" \
    --accept /etc/treadmark-smoke-drift.conf --accept /etc/hosts \
    --accept /etc >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "update run exited $rc (expected 1: it reports the drift it accepts)"
rc=0; treadmark files scan --config "$CFG" >/tmp/scan-after.out 2>&1 || rc=$?
[ "$rc" -eq 0 ] || { cat /tmp/scan-after.out; fail "post-accept scan exited $rc"; }

step "baseline provenance"
treadmark baseline info --config "$CFG" | grep -q "DB SHA-256" || fail "baseline info broken"

# ---------------------------------------------------------------------------
# 3b. Drift detection in EVERY watched top folder — one marker per top dir
# from the shipped config, each individually asserted in the report.
# (/bin and /sbin are usr-merged symlinks on modern distros; the marker
# then also appears under /usr/bin — both spellings being reported is
# correct behavior, we assert the path we planted.)
# ---------------------------------------------------------------------------
step "per-top-folder drift: plant one marker in each watched top dir"
planted=""
for d in /etc /bin /sbin /usr/bin /usr/sbin \
         /usr/local/bin /usr/local/sbin /usr/lib/systemd/system \
         /var/spool/cron /opt /home /root /boot; do
    if [ ! -d "$d" ]; then
        echo "    (skipping $d — not present on this target)"
        continue
    fi
    marker="$d/treadmark-smoke-marker-$(echo "${d#/}" | tr '/' '-')"
    echo "smoke marker" > "$marker"
    planted="$planted $marker"
done
[ -n "$planted" ] || fail "no top dirs available to plant markers in"

step "per-top-folder drift: scan reports every marker"
rc=0; treadmark files scan --config "$CFG" --report /tmp/topdirs.json >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "top-folder drift scan exited $rc, expected 1"
for p in $planted; do
    grep -q "\"$p\"" /tmp/topdirs.json \
        || fail "marker not reported: $p — is that top folder being walked?"
done
echo "    all markers reported:$planted"

step "per-top-folder drift: accept-all, rescan expects exit 0"
rc=0; treadmark files update --config "$CFG" --accept-all >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "accept-all update exited $rc (expected 1: it reports what it accepts)"
rc=0; treadmark files scan --config "$CFG" >/tmp/scan-topdirs.out 2>&1 || rc=$?
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
  "db_path": "/var/lib/treadmark/newtop-baseline.db",
  "paths": ["/treadmark-smoke-newtop"],
  "store_content": true
}
EOF
treadmark files init --config "$NT_CFG" >/dev/null 2>&1 || fail "newtop baseline init failed"

step "new top folder: create /treadmark-smoke-newtop with a nested tree"
mkdir -p /treadmark-smoke-newtop/nested/deeper
echo "top-level file"  > /treadmark-smoke-newtop/app.conf
echo "nested payload"  > /treadmark-smoke-newtop/nested/deeper/data.bin
printf '\x7fELF fake' > /treadmark-smoke-newtop/nested/tool
chmod 755 /treadmark-smoke-newtop/nested/tool

step "new top folder: scan captures the entire tree"
rc=0; treadmark files scan --config "$NT_CFG" --report /tmp/newtop.json >/dev/null 2>&1 || rc=$?
[ "$rc" -eq 1 ] || fail "newtop scan exited $rc, expected 1"
for p in /treadmark-smoke-newtop \
         /treadmark-smoke-newtop/app.conf \
         /treadmark-smoke-newtop/nested \
         /treadmark-smoke-newtop/nested/tool \
         /treadmark-smoke-newtop/nested/deeper \
         /treadmark-smoke-newtop/nested/deeper/data.bin; do
    grep -q "\"$p\"" /tmp/newtop.json \
        || fail "new top folder capture missed: $p"
done
echo "    full tree captured (dirs + nested files + executable)"

# SMOKE_FOOTPRINT=0 skips the package-install footprint captures below (all
# of section 4). Used by the EC2 AMI harness (scripts/smoke-aws.sh), where
# the core install→baseline→drift cycle is the platform-confirmation goal
# and footprints are opt-in. Default 1 keeps every existing caller (CI,
# release, smoke-local, smoke-vm) unchanged.
if [ "${SMOKE_FOOTPRINT:-1}" = "1" ]; then

# ---------------------------------------------------------------------------
# 4. Footprint capture of real package installs — the core use case.
# Fresh baseline → install a package from the distro repos → `treadmark
# footprint` must surface its semantic objects. Covers the common web
# servers and databases; package names, units, binaries, config trees,
# and created service accounts all differ across distro families —
# exactly the variation worth testing.
#
# Uses a dedicated config: units land under /usr/lib/systemd, which the
# shipped forensic default watches but a footprint capture needs paired
# with a matching baseline (this mirrors the documented footprint
# workflow of using a footprint-tuned config).
# ---------------------------------------------------------------------------
step "footprint: write footprint-tuned config"
FP_CFG=/tmp/footprint-config.json
cat > "$FP_CFG" <<'EOF'
{
  "db_path": "/var/lib/treadmark/footprint-baseline.db",
  "paths": ["/etc", "/usr/bin", "/usr/sbin", "/usr/libexec",
            "/usr/lib/systemd", "/usr/lib/postgresql", "/var/spool/cron"],
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

# capture_footprint <app> <package> <required-grep>...
# Re-baselines first so each footprint contains only its own package,
# then installs, captures, asserts every required pattern appears in the
# model, and prints the summary of what the install touched.
capture_footprint() {
    app="$1"; pkg="$2"; shift 2
    json="$FOOTPRINT_DIR/footprint-$app.json"

    step "footprint($app): fresh baseline"
    # Keep the output: a baseline that exits non-zero must name the offending
    # path/exception in the log, not vanish behind /dev/null.
    treadmark files init --config "$FP_CFG" --force >"/tmp/init-$app.out" 2>&1 \
        || { cat "/tmp/init-$app.out"; fail "footprint($app): baseline init failed"; }

    # A package can arrive early as a dependency of a previous capture
    # (e.g. Ubuntu's postgresql pulls in cron) — its own install would then
    # be a no-op with an empty footprint. Skip loudly instead of failing.
    if command -v apt-get >/dev/null 2>&1; then
        if dpkg -s "$pkg" >/dev/null 2>&1; then
            step "footprint($app): $pkg already present (dependency of an earlier capture) — skipped"
            return 0
        fi
    elif rpm -q "$pkg" >/dev/null 2>&1; then
        step "footprint($app): $pkg already present (dependency of an earlier capture) — skipped"
        return 0
    fi

    step "footprint($app): install $pkg from distro repos"
    if command -v apt-get >/dev/null 2>&1; then
        DEBIAN_FRONTEND=noninteractive apt-get install -qq -y "$pkg" >/dev/null
    else
        dnf install -qy "$pkg" >/dev/null
    fi

    step "footprint($app): capture and verify"
    rc=0; treadmark footprint --config "$FP_CFG" --app "$app" \
        --report "$json" >"/tmp/footprint-$app.out" 2>&1 || rc=$?
    [ "$rc" -eq 1 ] || { cat "/tmp/footprint-$app.out";
        fail "footprint($app) exited $rc, expected 1 (changes present)"; }

    for pattern in "$@"; do
        grep -q -- "$pattern" "$json" \
            || fail "footprint($app) model is missing: $pattern"
    done

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
    # Keyed on the summary COUNT — membership_changes entries also carry
    # a users_added list that is [] for new empty groups.
    if ! grep -q '"users_added": 0,' "$json"; then
        step "footprint($app): service account creation captured (users_added)"
    fi
}

# Common assertions: systemd unit parsed, binary analyzed, config tree
# seen, plus package-specific signals (runs-as-root risk where the unit
# has no User=, unit identity extraction where it does, service-account
# creation from the passwd diff).
capture_footprint nginx nginx \
    '"nginx.service"' '/usr/sbin/nginx' '/etc/nginx' '"service_runs_as_root"'

if command -v apt-get >/dev/null 2>&1; then
    # ----- Debian/Ubuntu family -----
    capture_footprint apache apache2 \
        '"apache2.service"' '/usr/sbin/apache2' '/etc/apache2' '"service_runs_as_root"'
    capture_footprint haproxy haproxy \
        '"haproxy.service"' '/usr/sbin/haproxy' '/etc/haproxy'
    capture_footprint lighttpd lighttpd \
        '"lighttpd.service"' '/usr/sbin/lighttpd' '/etc/lighttpd'
    capture_footprint mariadb mariadb-server \
        '"mariadb.service"' '"name": "mysql"' '/etc/mysql'
    capture_footprint postgresql postgresql \
        '"postgresql.service"' '"name": "postgres"' '/etc/postgresql'
    capture_footprint redis redis-server \
        '"redis-server.service"' '/usr/bin/redis-server' '/etc/redis'
else
    # ----- RHEL family (lighttpd is EPEL-only — skipped; Redis was
    # replaced by Valkey in RHEL 10) -----
    # Amazon Linux 2023 versions its database packages and ships no generic
    # alias (dnf can't resolve mariadb-server/postgresql-server there). The
    # units, service accounts, and config paths match the RHEL packages, so
    # only the package NAME changes — the assertions stay identical.
    if [ "${ID:-}" = "amzn" ]; then
        MARIADB_PKG=mariadb105-server; POSTGRES_PKG=postgresql16-server
    else
        MARIADB_PKG=mariadb-server;    POSTGRES_PKG=postgresql-server
    fi
    capture_footprint apache httpd \
        '"httpd.service"' '/usr/sbin/httpd' '/etc/httpd' '"service_runs_as_root"'
    capture_footprint haproxy haproxy \
        '"haproxy.service"' '/usr/sbin/haproxy' '/etc/haproxy'
    capture_footprint mariadb "$MARIADB_PKG" \
        '"mariadb.service"' '"name": "mysql"' '/etc/my.cnf'
    capture_footprint postgresql "$POSTGRES_PKG" \
        '"postgresql.service"' '"name": "postgres"' '"user": "postgres"'
    capture_footprint valkey valkey \
        '"valkey.service"' '/usr/bin/valkey-server' '/etc/valkey'
fi

# ---------------------------------------------------------------------------
# 4b. Extended footprint set: enterprise agents that each exercise a distinct
# semantic-extraction path. SMOKE_EXTENDED=1 enables it (local runs and the
# release pipeline); PR CI runs only the core set above to stay fast.
#
# Trimmed to ~half its original size — kept the captures that hit a UNIQUE
# detector or surfaced a real finding:
#   sssd    → pam_modified (identity-stack tampering)
#   auditd  → the audit ruleset (highest-order tamper target)
#   postfix → setgid_binary (postdrop/postqueue) + service account
#   snmpd   → community-string secrets; also caught RHEL's root-for-life snmpd
#   autofs  → LDAP auth-credential file (0600) on RHEL
#   podman  → large dependency closure + rootless socket
#   fail2ban (Debian only) → log/firewall agent, no PAM
# Dropped (lower signal): chrony, cron, nfs, qemu-guest-agent, and the dev
# toolchains pip/java/nodejs/git (degenerate — no units or service accounts).
# Their footprint models still live in smoke-out/ and their runbooks are
# generated; re-add a line here if a regression needs live coverage.
#
# Not covered on purpose: Grafana Alloy, telegraf, filebeat, zabbix
# (vendor repos only — this suite tests default-repo packages);
# open-vm-tools (x86-oriented, spotty on aarch64 repos); fail2ban on
# RHEL-family (EPEL-only there); podman on Amazon Linux 2023 (not in
# the AL2023 repos — AL2023 ships docker instead).
# ---------------------------------------------------------------------------
if [ "${SMOKE_EXTENDED:-0}" = "1" ]; then
    if command -v apt-get >/dev/null 2>&1; then
        # --- enterprise agents (Debian/Ubuntu) ---
        capture_footprint sssd sssd \
            '"sssd.service"' '/etc/sssd' '"pam_modified"'
        capture_footprint auditd auditd \
            '"auditd.service"' '/etc/audit'
        capture_footprint fail2ban fail2ban \
            '"fail2ban.service"' '/etc/fail2ban'
        capture_footprint postfix postfix \
            '"postfix.service"' '/etc/postfix' '"setgid_binary"' '"name": "postfix"'
        capture_footprint autofs autofs \
            '"autofs.service"' '/etc/auto'
        capture_footprint snmpd snmpd \
            '"snmpd.service"' '/etc/snmp'
        capture_footprint podman podman \
            '"podman.socket"' '/usr/bin/podman' '/etc/containers'
    else
        # --- enterprise agents (RHEL family) ---
        capture_footprint sssd sssd \
            '"sssd.service"' '/etc/sssd'
        capture_footprint auditd audit \
            '"auditd.service"' '/etc/audit'
        capture_footprint postfix postfix \
            '"postfix.service"' '/etc/postfix' '"setgid_binary"' '"name": "postfix"'
        capture_footprint autofs autofs \
            '"autofs.service"' '/etc/auto'
        capture_footprint snmpd net-snmp \
            '"snmpd.service"' '/etc/snmp'
        if [ "${ID:-}" = "amzn" ]; then
            step "footprint(podman): skipped — podman is not in the AL2023 repos"
        else
            capture_footprint podman podman \
                '"podman.socket"' '/usr/bin/podman' '/etc/containers'
        fi
    fi
fi

else
    step "footprint captures skipped (SMOKE_FOOTPRINT=0)"
fi

# ---------------------------------------------------------------------------
# 5. Context notes (VMs only — containers have no SELinux of their own)
# ---------------------------------------------------------------------------
if command -v getenforce >/dev/null 2>&1; then
    step "SELinux: $(getenforce)"
fi

printf '\nSMOKE PASS: %s (%s)\n' "${PRETTY_NAME:-unknown}" "$(uname -m)"

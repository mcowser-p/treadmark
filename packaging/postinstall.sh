#!/bin/sh
# packaging/postinstall.sh
# Runs after .deb/.rpm install or upgrade.

set -e

# Create the data directory if absent. 0700 so only root can read the
# baseline DB — the baseline now optionally contains file contents
# (for diff display), so it's effectively a snapshot of monitored config.
if [ ! -d /var/lib/treadmark ]; then
    mkdir -p /var/lib/treadmark
    chmod 700 /var/lib/treadmark
fi

if [ -d /etc/treadmark ]; then
    chmod 755 /etc/treadmark
    [ -f /etc/treadmark/treadmark.yaml ] && chmod 644 /etc/treadmark/treadmark.yaml
fi

cat <<'EOF'

treadmark installed.

treadmark is a forensic tool: capture a known-good baseline now, then run a
scan after-the-fact to see what changed. It does NOT run on a schedule.

Folder layout:
  /usr/bin/treadmark          - the binary
  /etc/treadmark/treadmark.yaml   - default config (edit before first run)
  /var/lib/treadmark/         - baseline DB lives here (root-only, mode 0700)

Typical workflow:
  1. Edit /etc/treadmark/treadmark.yaml to choose what to monitor.
  2. On a known-good system, capture the baseline:
       treadmark files init --config /etc/treadmark/treadmark.yaml
  3. Inspect the baseline's provenance for evidence purposes:
       treadmark baseline info --config /etc/treadmark/treadmark.yaml
  4. Later, when investigating: run a scan to see what changed:
       treadmark files scan --config /etc/treadmark/treadmark.yaml --report drift.md

See /usr/share/doc/treadmark/forensic-workflow.md for the full investigation
workflow.

EOF

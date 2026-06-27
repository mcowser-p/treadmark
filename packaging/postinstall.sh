#!/bin/sh
# packaging/postinstall.sh
# Runs after .deb/.rpm install or upgrade.

set -e

# Create the data directory if absent. 0700 so only root can read the
# baseline DB — the baseline now optionally contains file contents
# (for diff display), so it's effectively a snapshot of monitored config.
if [ ! -d /var/lib/cairn ]; then
    mkdir -p /var/lib/cairn
    chmod 700 /var/lib/cairn
fi

if [ -d /etc/cairn ]; then
    chmod 755 /etc/cairn
    [ -f /etc/cairn/cairn.yaml ] && chmod 644 /etc/cairn/cairn.yaml
fi

cat <<'EOF'

cairn installed.

cairn is a forensic tool: capture a known-good baseline now, then run a
scan after-the-fact to see what changed. It does NOT run on a schedule.

Folder layout:
  /usr/bin/cairn          - the binary
  /etc/cairn/cairn.yaml   - default config (edit before first run)
  /var/lib/cairn/         - baseline DB lives here (root-only, mode 0700)

Typical workflow:
  1. Edit /etc/cairn/cairn.yaml to choose what to monitor.
  2. On a known-good system, capture the baseline:
       cairn files init --config /etc/cairn/cairn.yaml
  3. Inspect the baseline's provenance for evidence purposes:
       cairn baseline info --config /etc/cairn/cairn.yaml
  4. Later, when investigating: run a scan to see what changed:
       cairn files scan --config /etc/cairn/cairn.yaml --report drift.md

See /usr/share/doc/cairn/forensic-workflow.md for the full investigation
workflow.

EOF

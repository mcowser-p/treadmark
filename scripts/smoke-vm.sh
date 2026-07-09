#!/usr/bin/env bash
# scripts/smoke-vm.sh — run the artifact smoke test inside REAL VMs via Lima.
#
# Containers (scripts/smoke-local.sh) are the everyday check; this is the
# occasional full-VM pass: a real boot with systemd, and — on AlmaLinux —
# SELinux enforcing, which containers never exercise.
#
#   bash scripts/smoke-local.sh        # build artifacts first (required)
#   bash scripts/smoke-vm.sh           # boot each VM, smoke, delete
#   bash scripts/smoke-vm.sh --keep    # leave VMs running afterwards
#
# Requires Lima:  brew install lima
# VMs on failure are always kept for debugging (limactl shell <name>).

set -euo pipefail
cd "$(dirname "$0")/.."
REPO=$(pwd)

KEEP="${1:-}"

if ! command -v limactl >/dev/null 2>&1; then
    echo "[!] limactl not found. Install Lima:  brew install lima" >&2
    exit 1
fi

if ! ls dist/cairn_*.deb >/dev/null 2>&1 || ! ls dist/cairn-*.rpm >/dev/null 2>&1; then
    echo "[!] no artifacts in dist/ — run 'bash scripts/smoke-local.sh' first" >&2
    exit 1
fi

case "$REPO" in
    "$HOME"/*) ;;
    *) echo "[!] repo must live under \$HOME — the Lima templates mount ~ read-only" >&2
       exit 1 ;;
esac

declare -a passed=() failed=()
for tpl in packaging/lima/*.yaml; do
    distro=$(basename "$tpl" .yaml)
    name="cairn-smoke-$distro"
    echo ""
    echo "=============================================================="
    echo ">>> VM smoke: $distro"
    echo "=============================================================="

    limactl delete -f "$name" >/dev/null 2>&1 || true
    limactl start --name "$name" --tty=false "$tpl"

    if limactl shell "$name" sudo DIST_DIR="$REPO/dist" \
            SMOKE_EXTENDED="${SMOKE_EXTENDED:-1}" \
            bash "$REPO/scripts/smoke-test.sh"; then
        passed+=("$distro")
        if [ "$KEEP" = "--keep" ]; then
            echo ">>> keeping VM '$name' (--keep); remove with: limactl delete -f $name"
        else
            limactl delete -f "$name"
        fi
    else
        failed+=("$distro")
        echo ">>> VM '$name' kept for debugging: limactl shell $name" >&2
    fi
done

echo ""
echo "=============================================================="
[ ${#passed[@]} -gt 0 ] && echo "PASS: ${passed[*]}"
if [ ${#failed[@]} -gt 0 ]; then
    echo "FAIL: ${failed[*]}"
    exit 1
fi
echo "all VM targets passed"

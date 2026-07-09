#!/usr/bin/env bash
# scripts/container-rootfs.sh
#
# Extract a container image's filesystem to a directory that `cairn --root`
# can scan.
#
#   ./scripts/container-rootfs.sh myapp:1.4.0 /tmp/rootfs/myapp
#
# Works with docker or podman, whichever is on PATH. No container is started;
# we create a container from the image, export its filesystem, and remove it.
#
# Why export and not `docker save`? `save` gives you layer tarballs plus a
# manifest, which is fine for a file-level layer diff. But it does not give
# you a single coherent filesystem with whiteouts applied, which is what you
# need to read /etc/passwd, /etc/group, and systemd units as they would
# actually exist at runtime. `export` flattens the layers for you.
#
# Note: `export` drops image metadata (ENTRYPOINT, CMD, ENV, USER, exposed
# ports). Those are real parts of a container's access model. Dump them
# alongside with:
#
#   docker image inspect myapp:1.4.0 > /tmp/rootfs/myapp.inspect.json
#
# and feed both to your policy agent.

set -euo pipefail

IMAGE="${1:-}"
DEST="${2:-}"

if [ -z "$IMAGE" ] || [ -z "$DEST" ]; then
    echo "usage: $0 IMAGE DEST_DIR" >&2
    echo "   e.g. $0 myapp:1.4.0 /tmp/rootfs/myapp" >&2
    exit 1
fi

if command -v docker >/dev/null 2>&1; then
    RUNTIME=docker
elif command -v podman >/dev/null 2>&1; then
    RUNTIME=podman
else
    echo "[!] neither docker nor podman found on PATH" >&2
    exit 1
fi

if [ -e "$DEST" ] && [ -n "$(ls -A "$DEST" 2>/dev/null)" ]; then
    echo "[!] $DEST exists and is not empty; refusing to overwrite" >&2
    exit 1
fi

mkdir -p "$DEST"

echo ">>> creating throwaway container from $IMAGE ($RUNTIME)"
CID=$("$RUNTIME" create "$IMAGE" /bin/true 2>/dev/null || "$RUNTIME" create "$IMAGE")
trap '"$RUNTIME" rm -f "$CID" >/dev/null 2>&1 || true' EXIT

echo ">>> exporting filesystem to $DEST"
# --same-owner preserves uid/gid so cairn's ownership attribution is correct.
# Requires root; without it every file lands owned by the extracting user and
# the file-owner access hints become meaningless.
if [ "$(id -u)" -ne 0 ]; then
    echo "[!] not running as root: uid/gid and setuid bits will NOT be preserved." >&2
    echo "    File-ownership hints and setuid risk detection will be wrong." >&2
    echo "    Re-run with sudo for a faithful extraction." >&2
fi
"$RUNTIME" export "$CID" | tar -x -C "$DEST" --same-owner --preserve-permissions 2>/dev/null \
    || "$RUNTIME" export "$CID" | tar -x -C "$DEST"

echo ">>> capturing image metadata (ENTRYPOINT/CMD/USER/ENV/ports)"
"$RUNTIME" image inspect "$IMAGE" > "${DEST%/}.inspect.json" 2>/dev/null \
    || echo "[i] could not inspect image; skipping metadata dump"

echo ""
echo "rootfs: $DEST"
echo "meta:   ${DEST%/}.inspect.json"
echo ""
echo "Next:"
echo "  # baseline the base image, then footprint the derived image"
echo "  cairn files init --config cairn-footprint-linux.yaml --root /tmp/rootfs/base --force"
echo "  cairn footprint --config cairn-footprint-linux.yaml --root $DEST --app ${IMAGE%%:*} --report footprint.json"

#!/usr/bin/env bash
# scripts/build-deb.sh — produce a .deb from the Linux PyInstaller binary.
# Uses dpkg-deb directly (standard on Debian/Ubuntu build hosts) — no fpm.
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(python3 -c "import tomllib; print(tomllib.loads(open('pyproject.toml','rb').read().decode())['project']['version'])")
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64)  DEB_ARCH=amd64 ;;
    aarch64) DEB_ARCH=arm64 ;;
    *)       DEB_ARCH="$ARCH_RAW" ;;
esac

BIN="dist/cairn-linux-${ARCH_RAW}"
[ -f "$BIN" ] || { echo "Binary not found: $BIN — run build-binary-linux.sh first"; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

# ---------------------------------------------------------------------------
# FHS-compliant payload layout
# ---------------------------------------------------------------------------
install -Dm755 "$BIN"                                "$STAGE/usr/bin/cairn"
install -Dm644 packaging/cairn.yaml                  "$STAGE/etc/cairn/cairn.yaml"

# Example scheduling units shipped as DOCS, not active config — operator
# decides whether to enable scheduling and how.
install -Dm644 README.md                             "$STAGE/usr/share/doc/cairn/README.md"
install -Dm644 docs/golden-baseline-workflow.md      "$STAGE/usr/share/doc/cairn/golden-baseline-workflow.md"
install -Dm644 docs/output-formats.md                "$STAGE/usr/share/doc/cairn/output-formats.md"
install -Dm644 docs/forensic-workflow.md             "$STAGE/usr/share/doc/cairn/forensic-workflow.md"

# ---------------------------------------------------------------------------
# DEBIAN/control + maintainer scripts
# ---------------------------------------------------------------------------
mkdir -p "$STAGE/DEBIAN"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: cairn
Version: $VERSION
Section: admin
Priority: optional
Architecture: $DEB_ARCH
Maintainer: mcowser-p <mcowser-p@users.noreply.github.com>
Homepage: https://github.com/mcowser-p/cairn
Description: Cross-platform File Integrity Monitor
 A cairn is a stack of stones marking known-good ground. This is the same
 idea for files: build a baseline once, then verify nothing has been
 disturbed on subsequent scans. AIDE-style, single binary, no agent required.
EOF

# /etc/cairn/cairn.yaml is a conffile — dpkg won't overwrite operator changes
# on upgrade.
echo "/etc/cairn/cairn.yaml" > "$STAGE/DEBIAN/conffiles"

install -m755 packaging/postinstall.sh "$STAGE/DEBIAN/postinst"

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
OUT="dist/cairn_${VERSION}_${DEB_ARCH}.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT"
echo "built: $OUT"
dpkg-deb --info "$OUT" | grep -E '^ (Package|Version|Architecture|Description)'

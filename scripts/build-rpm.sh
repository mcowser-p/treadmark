#!/usr/bin/env bash
# scripts/build-rpm.sh — produce a .rpm from the Linux PyInstaller binary.
# Uses rpmbuild directly (standard on EL/Fedora build hosts).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION=$(python3 -c "import tomllib; print(tomllib.loads(open('pyproject.toml','rb').read().decode())['project']['version'])")
ARCH_RAW=$(uname -m)
case "$ARCH_RAW" in
    x86_64)  RPM_ARCH=x86_64 ;;
    aarch64) RPM_ARCH=aarch64 ;;
    *)       RPM_ARCH="$ARCH_RAW" ;;
esac

BIN="dist/treadmark-linux-${ARCH_RAW}"
[ -f "$BIN" ] || { echo "Binary not found: $BIN — run build-binary-linux.sh first"; exit 1; }

# rpmbuild insists on its own directory tree
TOPDIR=$(mktemp -d)
trap 'rm -rf "$TOPDIR"' EXIT
mkdir -p "$TOPDIR"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Stage the payload under SOURCES/payload/
PAYLOAD="$TOPDIR/SOURCES/payload"
install -Dm755 "$BIN"                                "$PAYLOAD/usr/bin/treadmark"
install -Dm644 packaging/treadmark.yaml                  "$PAYLOAD/etc/treadmark/treadmark.yaml"
install -Dm644 README.md                             "$PAYLOAD/usr/share/doc/treadmark/README.md"
install -Dm644 docs/golden-baseline-workflow.md      "$PAYLOAD/usr/share/doc/treadmark/golden-baseline-workflow.md"
install -Dm644 docs/output-formats.md                "$PAYLOAD/usr/share/doc/treadmark/output-formats.md"
install -Dm644 docs/forensic-workflow.md             "$PAYLOAD/usr/share/doc/treadmark/forensic-workflow.md"

cp packaging/treadmark.spec "$TOPDIR/SPECS/treadmark.spec"

CHANGELOG_DATE=$(LC_ALL=C date '+%a %b %d %Y')

# %dist is pinned empty so the artifact keeps its distro-neutral name
# (treadmark-X.Y.Z-1.<arch>.rpm) regardless of build host. The binary targets a
# glibc FLOOR (built on EL9 — see build-binary-linux.sh), not one distro;
# a .el9 tag would misread as "EL9-only".
rpmbuild \
    --define "_topdir $TOPDIR" \
    --define "_version $VERSION" \
    --define "_target_arch $RPM_ARCH" \
    --define "_changelog_date $CHANGELOG_DATE" \
    --define "dist %{nil}" \
    --target "$RPM_ARCH" \
    -bb "$TOPDIR/SPECS/treadmark.spec"

# rpmbuild's exact filename varies by distro (the %{?dist} tag), so just glob
OUT_SRC=$(ls "$TOPDIR/RPMS/$RPM_ARCH/"*.rpm | head -1)
mkdir -p dist/
cp "$OUT_SRC" dist/
echo "built: dist/$(basename "$OUT_SRC")"
rpm -qpi "dist/$(basename "$OUT_SRC")" | head -10

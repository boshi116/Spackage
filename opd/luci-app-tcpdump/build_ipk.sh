#!/bin/sh

set -eu

PKG_NAME="luci-app-tcpdump"
PKG_VERSION="1.0.0"
PKG_RELEASE="1"
PKG_ARCH="all"
PKG_MAINTAINER="GitHub Copilot"
PKG_SECTION="luci"
PKG_CATEGORY="LuCI"
PKG_TITLE="LuCI tcpdump capture tool"
PKG_DEPENDS="tcpdump"

ROOT_DIR="$(CDPATH= cd -- "$(dirname "$0")" && pwd)"
BUILD_DIR="$ROOT_DIR/.build-ipk"
CONTROL_DIR="$BUILD_DIR/control"
DATA_DIR="$BUILD_DIR/data"
OUTPUT_DIR="$ROOT_DIR/dist"
PACKAGE_FILE="$OUTPUT_DIR/${PKG_NAME}_${PKG_VERSION}-${PKG_RELEASE}_${PKG_ARCH}.ipk"

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		echo "missing required command: $1" >&2
		exit 1
	fi
}

for cmd in tar gzip ar sed; do
	require_cmd "$cmd"
done

tar_pack() {
	archive_path="$1"
	shift
	tar \
		--format=ustar \
		--numeric-owner \
		--owner=0 \
		--group=0 \
		--sort=name \
		--mtime='@0' \
		-czf "$archive_path" \
		"$@"
}

rm -rf "$BUILD_DIR"
mkdir -p \
	"$CONTROL_DIR" \
	"$DATA_DIR/usr/lib/lua/luci/controller" \
	"$DATA_DIR/usr/lib/lua/luci/tcpdump" \
	"$DATA_DIR/usr/lib/lua/luci/view/tcpdump" \
	"$DATA_DIR/usr/bin"

install -m 0644 "$ROOT_DIR/luasrc/controller/tcpdump.lua" \
	"$DATA_DIR/usr/lib/lua/luci/controller/tcpdump.lua"
install -m 0644 "$ROOT_DIR/root/usr/lib/lua/luci/tcpdump/i18n.lua" \
	"$DATA_DIR/usr/lib/lua/luci/tcpdump/i18n.lua"
install -m 0644 "$ROOT_DIR/luasrc/view/tcpdump/index.htm" \
	"$DATA_DIR/usr/lib/lua/luci/view/tcpdump/index.htm"
install -m 0755 "$ROOT_DIR/root/usr/bin/luci-tcpdump" \
	"$DATA_DIR/usr/bin/luci-tcpdump"

INSTALLED_SIZE="$(du -sk "$DATA_DIR" | sed 's/[[:space:]].*$//')"

cat > "$CONTROL_DIR/control" <<EOF
Package: $PKG_NAME
Version: $PKG_VERSION-$PKG_RELEASE
Architecture: $PKG_ARCH
Maintainer: $PKG_MAINTAINER
Section: $PKG_SECTION
Category: $PKG_CATEGORY
Title: $PKG_TITLE
Depends: $PKG_DEPENDS
Installed-Size: $INSTALLED_SIZE
Description: LuCI tcpdump capture tool for OpenWrt
EOF

mkdir -p "$OUTPUT_DIR"

(
	cd "$CONTROL_DIR"
	tar_pack "$BUILD_DIR/control.tar.gz" ./control
)

(
	cd "$DATA_DIR"
	tar_pack "$BUILD_DIR/data.tar.gz" .
)

rm -f "$PACKAGE_FILE"
(
	cd "$BUILD_DIR"
	tar_pack "$PACKAGE_FILE" control.tar.gz data.tar.gz
)

echo "$PACKAGE_FILE"
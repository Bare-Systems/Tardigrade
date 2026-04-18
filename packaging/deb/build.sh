#!/usr/bin/env bash
# Build a Debian/Ubuntu .deb package for Tardigrade.
#
# Usage:
#   ./packaging/deb/build.sh [--version VERSION] [--arch ARCH] [--binary PATH]
#
# Options:
#   --version VERSION   Package version (default: inferred from `git describe`)
#   --arch ARCH         Target architecture: amd64 or arm64 (default: host arch)
#   --binary PATH       Path to pre-built tardigrade binary (default: zig-out/bin/tardigrade)
#   --output DIR        Output directory for .deb file (default: dist/)
#
# Prerequisites:
#   dpkg-deb (part of dpkg, available on Debian/Ubuntu)
#   A pre-built tardigrade binary for the target architecture

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION=""
ARCH=""
BINARY="${REPO_ROOT}/zig-out/bin/tardigrade"
OUTPUT_DIR="${REPO_ROOT}/dist"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --arch)    ARCH="$2";    shift 2 ;;
        --binary)  BINARY="$2";  shift 2 ;;
        --output)  OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# Infer version from git if not specified
if [[ -z "$VERSION" ]]; then
    VERSION=$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null | sed 's/^v//')
fi

# Infer arch from host if not specified
if [[ -z "$ARCH" ]]; then
    case "$(uname -m)" in
        x86_64)  ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) echo "Unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
    esac
fi

echo "Building tardigrade_${VERSION}_${ARCH}.deb ..."

# ── Package tree ─────────────────────────────────────────────────────────────
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

PKG_DIR="${WORK_DIR}/tardigrade_${VERSION}_${ARCH}"
BIN_DIR="${PKG_DIR}/usr/bin"
CONF_DIR="${PKG_DIR}/etc/tardigrade"
SYSTEMD_DIR="${PKG_DIR}/lib/systemd/system"
LOGROTATE_DIR="${PKG_DIR}/etc/logrotate.d"
DEBIAN_DIR="${PKG_DIR}/DEBIAN"

mkdir -p "$BIN_DIR" "$CONF_DIR" "$SYSTEMD_DIR" "$LOGROTATE_DIR" "$DEBIAN_DIR"

# Binary
install -m 0755 "$BINARY" "${BIN_DIR}/tardigrade"

# Default config
cat > "${CONF_DIR}/tardigrade.env" <<'ENVEOF'
# Tardigrade environment configuration
# See https://github.com/Bare-Systems/Tardigrade for full reference.
TARDIGRADE_LISTEN_PORT=8069
TARDIGRADE_LOG_LEVEL=info
TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true
# TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080
# TARDIGRADE_TLS_CERT_PATH=/etc/tardigrade/tls/server.crt
# TARDIGRADE_TLS_KEY_PATH=/etc/tardigrade/tls/server.key
ENVEOF
chmod 0640 "${CONF_DIR}/tardigrade.env"

# systemd unit
cp "${REPO_ROOT}/packaging/systemd/tardigrade.service" "${SYSTEMD_DIR}/tardigrade.service"

# logrotate config
cat > "${LOGROTATE_DIR}/tardigrade" <<'LREOF'
/var/log/tardigrade/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        systemctl kill --kill-who=main --signal=USR1 tardigrade.service 2>/dev/null || true
    endscript
}
LREOF

# DEBIAN/control
cat > "${DEBIAN_DIR}/control" <<CONTROL
Package: tardigrade
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Bare Systems <security@baresystems.dev>
Installed-Size: $(du -sk "$BIN_DIR" | awk '{print $1}')
Depends: libssl3 | libssl1.1
Section: net
Priority: optional
Homepage: https://github.com/Bare-Systems/Tardigrade
Description: Tardigrade edge gateway
 High-performance Zig edge gateway and HTTP server for TLS termination,
 reverse proxying, protocol bridging, and realtime event transport.
CONTROL

# DEBIAN/postinst
cat > "${DEBIAN_DIR}/postinst" <<'POSTINST'
#!/bin/sh
set -e
# Create tardigrade user if missing
if ! id -u tardigrade >/dev/null 2>&1; then
    useradd --system --no-create-home --shell /usr/sbin/nologin tardigrade
fi
chown root:tardigrade /etc/tardigrade/tardigrade.env
systemctl daemon-reload
POSTINST
chmod 0755 "${DEBIAN_DIR}/postinst"

# DEBIAN/prerm
cat > "${DEBIAN_DIR}/prerm" <<'PRERM'
#!/bin/sh
set -e
systemctl stop tardigrade.service 2>/dev/null || true
systemctl disable tardigrade.service 2>/dev/null || true
PRERM
chmod 0755 "${DEBIAN_DIR}/prerm"

# ── Build .deb ────────────────────────────────────────────────────────────────
mkdir -p "$OUTPUT_DIR"
DEB_PATH="${OUTPUT_DIR}/tardigrade_${VERSION}_${ARCH}.deb"
dpkg-deb --build --root-owner-group "$PKG_DIR" "$DEB_PATH"

echo "Built: $DEB_PATH"

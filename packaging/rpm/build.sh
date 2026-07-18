#!/usr/bin/env bash
# Build an RPM package for Tardigrade.
#
# Usage:
#   ./packaging/rpm/build.sh [--version VERSION] [--arch ARCH] [--binary PATH] [--output DIR]
#
# ARCH accepts Debian-style names (amd64, arm64) or RPM-style (x86_64, aarch64).
# Prerequisites:
#   rpm-build (dnf install rpm-build / apt-get install rpm-build)
#   A pre-built tardi binary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION=""
ARCH=""
BINARY="${REPO_ROOT}/zig-out/bin/tardi"
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

if [[ -z "$VERSION" ]]; then
    VERSION=$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null | sed 's/^v//')
fi

# Map Debian-style arch names to RPM arch names
case "$ARCH" in
    amd64)  RPM_ARCH="x86_64" ;;
    arm64)  RPM_ARCH="aarch64" ;;
    "")     RPM_ARCH="$(uname -m)" ;;
    *)      RPM_ARCH="$ARCH" ;;
esac

echo "Building tardigrade-${VERSION}-1.${RPM_ARCH}.rpm ..."

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "${WORK_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cp "$BINARY"                                                  "${WORK_DIR}/SOURCES/tardi"
cp "${REPO_ROOT}/LICENSE"                                     "${WORK_DIR}/SOURCES/LICENSE"
cp "${REPO_ROOT}/packaging/systemd/tardigrade.service"        "${WORK_DIR}/SOURCES/tardigrade.service"
cp "${REPO_ROOT}/packaging/tardigrade.conf"                   "${WORK_DIR}/SOURCES/tardigrade.conf"
cp "${REPO_ROOT}/packaging/rpm/tardigrade.spec"               "${WORK_DIR}/SPECS/tardigrade.spec"

cat > "${WORK_DIR}/SOURCES/tardigrade.env" <<'ENVEOF'
# Tardigrade environment configuration
TARDIGRADE_LISTEN_PORT=8069
TARDIGRADE_LOG_LEVEL=info
TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true
# TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080
ENVEOF

rpmbuild --define "_topdir ${WORK_DIR}" \
         --define "version ${VERSION}" \
         --define "build_arch ${RPM_ARCH}" \
         --define "_unitdir /usr/lib/systemd/system" \
         --target "${RPM_ARCH}-linux" \
         -bb "${WORK_DIR}/SPECS/tardigrade.spec"

mkdir -p "$OUTPUT_DIR"
find "${WORK_DIR}/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT_DIR/" \;
echo "Built RPM(s) in: $OUTPUT_DIR"

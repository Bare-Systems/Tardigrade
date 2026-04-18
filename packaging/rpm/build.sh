#!/usr/bin/env bash
# Build an RPM package for Tardigrade.
#
# Usage:
#   ./packaging/rpm/build.sh [--version VERSION] [--binary PATH] [--output DIR]
#
# Prerequisites:
#   rpm-build (dnf install rpm-build / yum install rpm-build)
#   A pre-built tardigrade binary

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
VERSION=""
BINARY="${REPO_ROOT}/zig-out/bin/tardigrade"
OUTPUT_DIR="${REPO_ROOT}/dist"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) VERSION="$2"; shift 2 ;;
        --binary)  BINARY="$2";  shift 2 ;;
        --output)  OUTPUT_DIR="$2"; shift 2 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

if [[ -z "$VERSION" ]]; then
    VERSION=$(git -C "$REPO_ROOT" describe --tags --always 2>/dev/null | sed 's/^v//')
fi

echo "Building tardigrade-${VERSION}-1.rpm ..."

WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT

mkdir -p "${WORK_DIR}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy sources
cp "$BINARY" "${WORK_DIR}/SOURCES/tardigrade"
cp "${REPO_ROOT}/packaging/systemd/tardigrade.service" "${WORK_DIR}/SOURCES/tardigrade.service"
cat > "${WORK_DIR}/SOURCES/tardigrade.env" <<'ENVEOF'
# Tardigrade environment configuration
TARDIGRADE_LISTEN_PORT=8069
TARDIGRADE_LOG_LEVEL=info
TARDIGRADE_REQUIRE_UNPRIVILEGED_USER=true
# TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080
ENVEOF

cp "${REPO_ROOT}/packaging/rpm/tardigrade.spec" "${WORK_DIR}/SPECS/tardigrade.spec"

rpmbuild --define "_topdir ${WORK_DIR}" \
         --define "version ${VERSION}" \
         -bb "${WORK_DIR}/SPECS/tardigrade.spec"

mkdir -p "$OUTPUT_DIR"
find "${WORK_DIR}/RPMS" -name "*.rpm" -exec cp {} "$OUTPUT_DIR/" \;
echo "Built RPM(s) in: $OUTPUT_DIR"

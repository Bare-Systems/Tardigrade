#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BINARY="${REPO_ROOT}/zig-out/bin/tardigrade"
ARCHIVE_NAME=""
OUTPUT_DIR="${REPO_ROOT}"
STAGING_DIR=""

usage() {
    cat <<'EOF'
Usage: package-release-archive.sh --archive-name NAME [--binary PATH] [--output-dir DIR] [--staging-dir DIR]
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --archive-name) ARCHIVE_NAME="$2"; shift 2 ;;
        --binary) BINARY="$2"; shift 2 ;;
        --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
        --staging-dir) STAGING_DIR="$2"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
    esac
done

if [[ -z "$ARCHIVE_NAME" ]]; then
    echo "--archive-name is required" >&2
    exit 1
fi

if [[ ! -f "$BINARY" ]]; then
    echo "Binary not found: $BINARY" >&2
    exit 1
fi

cleanup_dir=""
cleanup() {
    if [[ -n "$cleanup_dir" ]]; then
        rm -rf "$cleanup_dir"
    fi
}

if [[ -z "$STAGING_DIR" ]]; then
    STAGING_DIR="$(mktemp -d)"
    cleanup_dir="$STAGING_DIR"
else
    rm -rf "$STAGING_DIR"
    mkdir -p "$STAGING_DIR"
fi
trap cleanup EXIT

mkdir -p "$OUTPUT_DIR"

install -m 0755 "$BINARY" "${STAGING_DIR}/tardigrade"
ln -s tardigrade "${STAGING_DIR}/tardi"
install -m 0644 "${REPO_ROOT}/LICENSE" "${STAGING_DIR}/LICENSE"
install -m 0644 "${REPO_ROOT}/README.md" "${STAGING_DIR}/README.md"
install -m 0644 "${REPO_ROOT}/CHANGELOG.md" "${STAGING_DIR}/CHANGELOG.md"
install -m 0644 "${REPO_ROOT}/packaging/README.md" "${STAGING_DIR}/PACKAGING.md"

archive_path="${OUTPUT_DIR}/${ARCHIVE_NAME}.tar.gz"
tar -C "$STAGING_DIR" -czf "$archive_path" \
    tardigrade \
    tardi \
    LICENSE \
    README.md \
    CHANGELOG.md \
    PACKAGING.md

archive_listing="$(tar -tzf "$archive_path")"
for expected in tardigrade tardi LICENSE README.md CHANGELOG.md PACKAGING.md; do
    grep -Fx "$expected" <<<"$archive_listing" >/dev/null
done

printf 'Built archive: %s\n' "$archive_path"

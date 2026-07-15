#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

VERSION="v0.0.0-smoke"
RELEASE_ROOT="${TMPDIR}/releases"
INSTALL_DIR="${TMPDIR}/install"

platform() {
    case "$(uname -s)/$(uname -m)" in
        Linux/x86_64|Linux/amd64) printf 'linux-x86_64\n' ;;
        Linux/aarch64|Linux/arm64) printf 'linux-aarch64\n' ;;
        Darwin/x86_64|Darwin/amd64) printf 'darwin-x86_64\n' ;;
        Darwin/arm64|Darwin/aarch64) printf 'darwin-arm64\n' ;;
        *) echo "Unsupported host platform for install smoke test" >&2; exit 1 ;;
    esac
}

sha256_file() {
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$1"
        return
    fi
    shasum -a 256 "$1"
}

host_platform="$(platform)"
mkdir -p "${RELEASE_ROOT}/latest/download" "${RELEASE_ROOT}/download/${VERSION}"

"${REPO_ROOT}/scripts/package-release-archive.sh" \
    --archive-name "tardigrade-${host_platform}" \
    --binary "${REPO_ROOT}/zig-out/bin/tardi" \
    --output-dir "${RELEASE_ROOT}/download/${VERSION}"

cp "${RELEASE_ROOT}/download/${VERSION}/tardigrade-${host_platform}.tar.gz" \
    "${RELEASE_ROOT}/latest/download/tardigrade-${host_platform}.tar.gz"

(
    cd "$RELEASE_ROOT"
    sha256_file "download/${VERSION}/tardigrade-${host_platform}.tar.gz" > "download/${VERSION}/tardigrade-checksums.txt"
    sha256_file "latest/download/tardigrade-${host_platform}.tar.gz" > "latest/download/tardigrade-checksums.txt"
)

for supported in \
    "Linux x86_64 tardigrade-linux-x86_64.tar.gz" \
    "Linux aarch64 tardigrade-linux-aarch64.tar.gz" \
    "Darwin x86_64 tardigrade-darwin-x86_64.tar.gz" \
    "Darwin arm64 tardigrade-darwin-arm64.tar.gz"; do
    read -r os arch asset <<<"$supported"
    output="$(
        TARDIGRADE_TEST_UNAME_S="$os" \
        TARDIGRADE_TEST_UNAME_M="$arch" \
        TARDIGRADE_RELEASE_BASE_URL="file://${RELEASE_ROOT}" \
        "${REPO_ROOT}/scripts/install.sh" --version "$VERSION" --dry-run
    )"
    grep -F "download_url=file://${RELEASE_ROOT}/download/${VERSION}/${asset}" <<<"$output" >/dev/null
done

if TARDIGRADE_TEST_UNAME_S="Linux" TARDIGRADE_TEST_UNAME_M="sparc64" "${REPO_ROOT}/scripts/install.sh" --dry-run >/dev/null 2>"${TMPDIR}/unsupported.log"; then
    echo "unsupported architecture unexpectedly succeeded" >&2
    exit 1
fi
grep -F "unsupported architecture: sparc64" "${TMPDIR}/unsupported.log" >/dev/null

TARDIGRADE_RELEASE_BASE_URL="file://${RELEASE_ROOT}" \
    "${REPO_ROOT}/scripts/install.sh" --version "$VERSION" --dir "$INSTALL_DIR"

test -x "${INSTALL_DIR}/tardi"
test -x "${INSTALL_DIR}/tardigrade"
"${INSTALL_DIR}/tardi" version >/dev/null
"${INSTALL_DIR}/tardigrade" version >/dev/null

mkdir -p "${TMPDIR}/bad-release/download/${VERSION}"
cp "${RELEASE_ROOT}/download/${VERSION}/tardigrade-${host_platform}.tar.gz" "${TMPDIR}/bad-release/download/${VERSION}/"
printf '0000  tardigrade-%s.tar.gz\n' "$host_platform" > "${TMPDIR}/bad-release/download/${VERSION}/tardigrade-checksums.txt"

if TARDIGRADE_RELEASE_BASE_URL="file://${TMPDIR}/bad-release" "${REPO_ROOT}/scripts/install.sh" --version "$VERSION" --dir "${TMPDIR}/bad-install" >/dev/null 2>"${TMPDIR}/checksum.log"; then
    echo "checksum mismatch unexpectedly succeeded" >&2
    exit 1
fi
grep -F "checksum mismatch for tardigrade-${host_platform}.tar.gz" "${TMPDIR}/checksum.log" >/dev/null
test ! -e "${TMPDIR}/bad-install/tardi"
test ! -e "${TMPDIR}/bad-install/tardigrade"

printf 'install smoke test passed\n'

#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

BINARY="${REPO_ROOT}/zig-out/bin/tardi"
VERSION="0.0.0-smoke"
OUTPUT_DIR="${TMPDIR}/dist"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "skipping DEB smoke test outside Linux" >&2
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "skipping DEB smoke test because docker is unavailable" >&2
    exit 0
fi

"${REPO_ROOT}/packaging/deb/build.sh" \
    --version "$VERSION" \
    --arch amd64 \
    --binary "$BINARY" \
    --output "$OUTPUT_DIR"

DEB_PATH="${OUTPUT_DIR}/tardigrade_${VERSION}_amd64.deb"
test -f "$DEB_PATH"

docker run --rm -v "${OUTPUT_DIR}:/artifacts:ro" ubuntu:24.04 bash -euxc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update
    apt-get install -y ca-certificates libssl3 /artifacts/tardigrade_0.0.0-smoke_amd64.deb
    test -x /usr/bin/tardi
    /usr/bin/tardi version >/dev/null
    test -f /etc/tardigrade/tardigrade.conf
    test -f /etc/tardigrade/tardigrade.env
    test -f /lib/systemd/system/tardigrade.service
    test -f /etc/logrotate.d/tardigrade
    test -d /var/lib/tardigrade
    grep -F "EnvironmentFile=-/etc/tardigrade/tardigrade.env" /lib/systemd/system/tardigrade.service
    grep -F "ExecStart=/usr/bin/tardi run -c /etc/tardigrade/tardigrade.conf" /lib/systemd/system/tardigrade.service
    test "$(stat -c "%a %U %G" /etc/tardigrade/tardigrade.env)" = "640 root tardigrade"
    test "$(stat -c "%a %U %G" /etc/tardigrade/tardigrade.conf)" = "644 root root"
    test "$(stat -c "%a %U %G" /etc/logrotate.d/tardigrade)" = "644 root root"
    test "$(stat -c "%a %U %G" /var/lib/tardigrade)" = "755 tardigrade tardigrade"
    apt-get remove -y tardigrade
    test ! -e /usr/bin/tardi
'

printf 'deb smoke test passed\n'

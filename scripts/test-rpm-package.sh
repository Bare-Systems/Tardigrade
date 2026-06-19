#!/usr/bin/env bash
# Smoke-test the RPM package.
#
# Builds the RPM inside a Rocky Linux 9 container (where rpmbuild macros
# and systemd-rpm-macros are defined) then installs and exercises it in
# the same container.
#
# Usage: ./scripts/test-rpm-package.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "skipping RPM smoke test outside Linux" >&2
    exit 0
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "skipping RPM smoke test because docker is unavailable" >&2
    exit 0
fi

OUTPUT_DIR="${TMPDIR}/dist"
mkdir -p "$OUTPUT_DIR"

docker run --rm \
    --volume "${REPO_ROOT}:/repo:ro" \
    --volume "${OUTPUT_DIR}:/output" \
    rockylinux:9 bash -euxc '
        dnf install -y rpm-build openssl-libs

        /repo/packaging/rpm/build.sh \
            --version 0.0.0 \
            --arch x86_64 \
            --binary /repo/zig-out/bin/tardigrade \
            --output /output

        rpm_path=$(find /output -name "tardigrade-*.rpm" | head -1)
        test -n "$rpm_path"
        test -f "$rpm_path"

        dnf install -y "$rpm_path"

        test -x /usr/bin/tardigrade
        /usr/bin/tardigrade version >/dev/null
        test -f /etc/tardigrade/tardigrade.env
        test -f /usr/lib/systemd/system/tardigrade.service
        test -f /usr/share/licenses/tardigrade/LICENSE
        test -d /var/log/tardigrade
        test "$(stat -c "%a %U %G" /etc/tardigrade/tardigrade.env)" = "640 root tardigrade"
        grep -F "EnvironmentFile=-/etc/tardigrade/tardigrade.env" /usr/lib/systemd/system/tardigrade.service
        grep -F "ExecStart=/usr/bin/tardigrade run -c /etc/tardigrade/tardigrade.conf" /usr/lib/systemd/system/tardigrade.service

        dnf remove -y tardigrade
        test ! -e /usr/bin/tardigrade
    '

printf 'rpm smoke test passed\n'

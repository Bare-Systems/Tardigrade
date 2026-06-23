#!/usr/bin/env bash
# Smoke-test the RPM package.
#
# Builds the binary from source inside a Rocky Linux 9 container so it links
# against that platform's glibc (2.34), then builds the RPM and installs it.
# The host Zig install directory is mounted into the container.
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

# Locate the Zig installation directory to mount into the container.
# Zig's binary is statically linked, but it still needs its adjacent lib dir.
ZIG_BIN="${ZIG_BIN:-$(command -v zig 2>/dev/null || true)}"
if [[ -z "$ZIG_BIN" ]]; then
    ZIG_BIN="$(find "${REPO_ROOT}/.zig" -maxdepth 4 -name zig -type f 2>/dev/null | head -1 || true)"
fi
if [[ -z "$ZIG_BIN" ]]; then
    echo "error: zig binary not found; set ZIG_BIN or run scripts/install-zig.sh first" >&2
    exit 1
fi

ZIG_BIN="$(readlink -f "$ZIG_BIN")"
ZIG_DIR="$(cd "$(dirname "$ZIG_BIN")" && pwd)"

if [[ ! -x "${ZIG_DIR}/zig" || ! -d "${ZIG_DIR}/lib" ]]; then
    echo "error: invalid Zig install directory: ${ZIG_DIR}" >&2
    exit 1
fi

OUTPUT_DIR="${TMPDIR}/dist"
mkdir -p "$OUTPUT_DIR"

docker run --rm \
    --volume "${REPO_ROOT}:/repo:ro" \
    --volume "${OUTPUT_DIR}:/output" \
    --volume "${ZIG_DIR}:/opt/zig:ro" \
    rockylinux:9 bash -euxc '
        dnf install -y rpm-build openssl-devel openssl-libs systemd-rpm-macros

        export PATH="/opt/zig:${PATH}"

        # Build from source inside this container so the binary links against
        # Rocky Linux 9'"'"'s glibc (2.34) rather than the CI runner'"'"'s.
        cp -a /repo /tmp/tardigrade
        cd /tmp/tardigrade
        zig build -Doptimize=ReleaseFast

        /repo/packaging/rpm/build.sh \
            --version 0.0.0 \
            --arch x86_64 \
            --binary /tmp/tardigrade/zig-out/bin/tardigrade \
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

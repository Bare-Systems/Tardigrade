#!/usr/bin/env bash
# Verify source builds expose both the canonical CLI and compatibility alias.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

rm -rf zig-out
zig build

test -x zig-out/bin/tardi
test -x zig-out/bin/tardigrade
./zig-out/bin/tardi version >/dev/null
./zig-out/bin/tardigrade version >/dev/null

help_output="$(./zig-out/bin/tardi --help)"
printf '%s\n' "$help_output" | grep -q '^  tardi '
if printf '%s\n' "$help_output" | grep -q '^  tardigrade '; then
    echo 'help still advertises tardigrade as the canonical command' >&2
    exit 1
fi

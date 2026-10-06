#!/usr/bin/env bash
# CI wrapper for the downstream HTTP/3 mTLS interop (#763): provisions the
# pinned external client into a throwaway venv and runs
# run-h3-mtls-interop.sh against the freshly built gateway. Kept under
# scripts/interop/, the audited external-peer boundary
# (scripts/audit-dependencies.sh): the peer's package name never appears
# outside this directory.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
venv="${H3_MTLS_VENV:-${RUNNER_TEMP:-/tmp}/tardigrade-h3-mtls-venv}"

if [ ! -x "$venv/bin/python" ]; then
  python3 -m venv "$venv"
  "$venv/bin/pip" install --quiet 'aioquic==1.3.0'
fi

AIOQUIC_PYTHON="$venv/bin/python" TARDI_BIN="${TARDI_BIN:-$root/zig-out/bin/tardi}" \
  exec "$here/run-h3-mtls-interop.sh"

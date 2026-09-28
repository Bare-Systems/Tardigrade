#!/usr/bin/env bash
# Validates that all example configs parse successfully with `tardi check`.
#
# Usage:
#   ./scripts/validate-examples.sh [path/to/tardi]
#
# The optional argument overrides the default binary path (zig-out/bin/tardi).
# TLS cert/key paths in example configs are overridden with test fixtures so
# the check does not require real certificate files.

set -euo pipefail

TARDI="${1:-zig-out/bin/tardi}"

if [[ ! -x "$TARDI" ]]; then
    echo "error: tardi binary not found at '$TARDI'" >&2
    echo "       Run 'zig build' first, or pass the binary path as an argument." >&2
    exit 1
fi

# Test-fixture cert and key used to satisfy the file-existence check in
# `tardi check` for examples that declare tls_cert_path / tls_key_path.
FIXTURE_CERT="tests/fixtures/tls/server.crt"
FIXTURE_KEY="tests/fixtures/tls/server.key"

if [[ ! -f "$FIXTURE_CERT" || ! -f "$FIXTURE_KEY" ]]; then
    echo "error: TLS fixture files not found (expected $FIXTURE_CERT and $FIXTURE_KEY)" >&2
    exit 1
fi

ok=0
fail=0

check() {
    local name="$1"
    local conf="$2"
    shift 2
    # Remaining args are extra env var assignments exported for this check.
    if env "$@" "$TARDI" check "$conf" >/dev/null 2>&1; then
        echo "  ok  $name"
        ok=$((ok + 1))
    else
        echo "FAIL  $name"
        # Re-run to show the error output.
        env "$@" "$TARDI" check "$conf" || true
        fail=$((fail + 1))
    fi
}

echo "Validating example configs with: $TARDI"
echo

check "static-file-server" \
    examples/static-file-server/tardigrade.conf

check "reverse-proxy" \
    examples/reverse-proxy/tardigrade.conf \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080"

check "tls-termination" \
    examples/tls-termination/tardigrade.conf \
    "TARDIGRADE_TLS_CERT_PATH=$FIXTURE_CERT" \
    "TARDIGRADE_TLS_KEY_PATH=$FIXTURE_KEY" \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080"

check "virtual-hosts" \
    examples/virtual-hosts/tardigrade.conf

check "health-checks" \
    examples/health-checks/tardigrade.conf \
    "TARDIGRADE_UPSTREAM_BASE_URLS=http://127.0.0.1:3001,http://127.0.0.1:3002"

check "rate-limiting" \
    examples/rate-limiting/tardigrade.conf \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080"

check "access-logs" \
    examples/access-logs/tardigrade.conf \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080"

check "prometheus-metrics" \
    examples/prometheus-metrics/tardigrade.conf \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080"

check "graceful-reload" \
    examples/graceful-reload/tardigrade.conf \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080"

check "production-baseline" \
    examples/production-baseline/tardigrade.conf \
    "TARDIGRADE_TLS_CERT_PATH=$FIXTURE_CERT" \
    "TARDIGRADE_TLS_KEY_PATH=$FIXTURE_KEY" \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080" \
    "TARDIGRADE_HSTS_ENABLED=true"

check "forward-auth" \
    examples/forward-auth/tardigrade.conf

check "bearclaw" \
    examples/bearclaw/tardigrade.conf \
    "TARDIGRADE_TLS_CERT_PATH=$FIXTURE_CERT" \
    "TARDIGRADE_TLS_KEY_PATH=$FIXTURE_KEY" \
    "TARDIGRADE_UPSTREAM_BASE_URL=http://127.0.0.1:8080"

echo
echo "Results: $ok passed, $fail failed."

if [[ $fail -gt 0 ]]; then
    exit 1
fi

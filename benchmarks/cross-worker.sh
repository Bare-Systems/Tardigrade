#!/usr/bin/env bash
# Cross-worker upstream-pool reuse benchmark (#147).
#
# Drives uneven proxy traffic across several routes through a multi-threaded
# gateway and scrapes the per-pool reuse split. The point is to demonstrate that
# Tardigrade's single shared upstream pool reuses idle connections *across worker
# threads* — a connection parked by one worker is reclaimed by another — rather
# than fragmenting an idle pool per worker (the failure mode #147 set out to
# avoid). See docs/UPSTREAM_POOLING.md ("Cross-worker sharing").
#
# This is a demonstration/measurement harness, not a pass/fail CI gate (the
# reuse floor is guarded by ci-smoke.sh). It prints:
#   - upstream connections opened (new) vs reused
#   - reused_local   (same worker parked + reclaimed)
#   - reused_cross_worker (a different worker reclaimed it — shared-pool reuse)
#
# Usage: benchmarks/cross-worker.sh [--threads N] [--duration S] [--connections N]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
BINARY="${REPO_ROOT}/zig-out/bin/tardi"
LISTEN_PORT="18079"
UPSTREAM_PORT="18078"
DURATION="15"
CONNECTIONS="64"
THREADS="8"
TMP_DIR=""
UPSTREAM_PID=""
TARDIGRADE_PID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)        BINARY="$2";        shift 2 ;;
        --listen-port)   LISTEN_PORT="$2";   shift 2 ;;
        --upstream-port) UPSTREAM_PORT="$2"; shift 2 ;;
        --duration)      DURATION="$2";      shift 2 ;;
        --connections)   CONNECTIONS="$2";   shift 2 ;;
        --threads)       THREADS="$2";       shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x "$BINARY" ]]; then
    echo "tardi binary not found at ${BINARY} (run: zig build)" >&2
    exit 1
fi
for tool in wrk curl python3 awk; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

cleanup() {
    local status=$?
    [[ -n "$TARDIGRADE_PID" ]] && { kill "$TARDIGRADE_PID" 2>/dev/null || true; wait "$TARDIGRADE_PID" 2>/dev/null || true; }
    [[ -n "$UPSTREAM_PID" ]] && { kill "$UPSTREAM_PID" 2>/dev/null || true; wait "$UPSTREAM_PID" 2>/dev/null || true; }
    [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

wait_for_http() {
    local url="$1" i
    for ((i = 0; i < 50; i += 1)); do
        curl -fsS "$url" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    echo "timed out waiting for ${url}" >&2
    return 1
}

TMP_DIR="$(mktemp -d /tmp/tardigrade-cross-worker-XXXX)"
CONFIG_FILE="${TMP_DIR}/cross-worker.conf"

cat > "${CONFIG_FILE}" <<EOF
listen ${LISTEN_PORT};
metrics_path /status/metrics;
location = /a {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/health;
}
location = /b {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/health;
}
location = /c {
    proxy_pass http://127.0.0.1:${UPSTREAM_PORT}/health;
}
EOF

python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "${UPSTREAM_PORT}" >"${TMP_DIR}/upstream.log" 2>&1 &
UPSTREAM_PID="$!"
wait_for_http "http://127.0.0.1:${UPSTREAM_PORT}/health"

TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_WORKER_THREADS="${THREADS}" \
    "${BINARY}" run -c "${CONFIG_FILE}" >"${TMP_DIR}/tardigrade.log" 2>&1 &
TARDIGRADE_PID="$!"
wait_for_http "http://127.0.0.1:${LISTEN_PORT}/status/metrics"

echo "Driving uneven load: ${THREADS} gateway threads, ${CONNECTIONS} connections, ${DURATION}s"
# Uneven distribution: /a is the hot route, /b and /c get a short secondary pass.
wrk -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" "http://127.0.0.1:${LISTEN_PORT}/a" \
    2>&1 | awk '/Requests\/sec/{print "  hot route /a: "$0}'
wrk -t2 -c8 -d3s "http://127.0.0.1:${LISTEN_PORT}/b" >/dev/null 2>&1 || true
wrk -t2 -c8 -d3s "http://127.0.0.1:${LISTEN_PORT}/c" >/dev/null 2>&1 || true

metrics="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics")"
field() { printf '%s\n' "$metrics" | awk -v k="$1" '$1==k{print $2; exit}'; }

new_c="$(field tardigrade_upstream_connections_new_total)";                       new_c="${new_c:-0}"
reused="$(field tardigrade_upstream_connections_reused_total)";                   reused="${reused:-0}"
local_c="$(field tardigrade_upstream_connections_reused_local_total)";           local_c="${local_c:-0}"
cross_c="$(field tardigrade_upstream_connections_reused_cross_worker_total)";     cross_c="${cross_c:-0}"
total=$((reused + new_c))

echo ""
echo "Upstream connection pool (shared across ${THREADS} worker threads):"
echo "  new (opened)         : ${new_c}"
echo "  reused (total)       : ${reused}"
echo "  reused_local         : ${local_c}"
echo "  reused_cross_worker  : ${cross_c}"
if [[ "$total" -gt 0 ]]; then
    echo "  reuse ratio          : $((reused * 100 / total))%"
fi
if [[ "$reused" -gt 0 ]]; then
    echo "  cross-worker share   : $((cross_c * 100 / reused))% of reuses reclaimed by a different worker"
fi
echo ""
if [[ "$cross_c" -le 0 ]]; then
    echo "WARNING: no cross-worker reuse observed — the pool may be fragmenting per worker." >&2
else
    echo "OK: idle connections are reused across workers (shared pool, not per-worker)."
fi

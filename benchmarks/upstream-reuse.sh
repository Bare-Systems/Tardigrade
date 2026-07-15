#!/usr/bin/env bash
# Upstream connection-pool reuse + active-cap scenario (#141 Phase 1d / #239).
#
# Two phases against the same plain-HTTP origin (fixtures/upstream_server.py):
#
#   reuse : concurrent proxy load through the pooled gateway; reports the
#           reuse ratio (reused / (reused + new)), new-connection count, the
#           local vs cross-worker reuse split (#147), and stale retries. This
#           formalizes the ad-hoc runs from #226/#230 — the pass/fail CI gate
#           for reuse >= 80% lives in benchmarks/ci-smoke.sh.
#   cap   : restarts the gateway with TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST
#           and drives more concurrency than the cap at a slow origin endpoint
#           (/slow?ms=...). Demonstrates fail-fast 503 upstream_saturated at
#           saturation, the at_capacity counter, and that a subsequent
#           sequential request still succeeds (saturation is a local policy
#           rejection — it must not trip upstream passive health).
#
# This is a demonstration/measurement harness, not a pass/fail CI gate.
# Requires: wrk, curl, python3, awk.
#
# Usage: benchmarks/upstream-reuse.sh [--duration S] [--connections N]
#        [--threads N] [--cap N] [--slow-ms MS]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
BINARY="${REPO_ROOT}/zig-out/bin/tardi"
LISTEN_PORT="18091"
ORIGIN_PORT="18090"
DURATION="10"
CONNECTIONS="32"
THREADS="4"
CAP="4"
SLOW_MS="250"
TMP_DIR=""
ORIGIN_PID=""
TARDIGRADE_PID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)      BINARY="$2";      shift 2 ;;
        --listen-port) LISTEN_PORT="$2"; shift 2 ;;
        --origin-port) ORIGIN_PORT="$2"; shift 2 ;;
        --duration)    DURATION="$2";    shift 2 ;;
        --connections) CONNECTIONS="$2"; shift 2 ;;
        --threads)     THREADS="$2";     shift 2 ;;
        --cap)         CAP="$2";         shift 2 ;;
        --slow-ms)     SLOW_MS="$2";     shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x "$BINARY" ]]; then
    echo "tardi binary not found at ${BINARY} (run: zig build -Doptimize=ReleaseFast)" >&2
    exit 1
fi
for tool in wrk curl python3 awk; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

cleanup() {
    local status=$?
    [[ -n "$TARDIGRADE_PID" ]] && { kill "$TARDIGRADE_PID" 2>/dev/null || true; wait "$TARDIGRADE_PID" 2>/dev/null || true; }
    [[ -n "$ORIGIN_PID" ]]     && { kill "$ORIGIN_PID"     2>/dev/null || true; wait "$ORIGIN_PID"     2>/dev/null || true; }
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

TMP_DIR="$(mktemp -d /tmp/tardigrade-upstream-reuse-XXXX)"

python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "${ORIGIN_PORT}" \
    >"${TMP_DIR}/origin.log" 2>&1 &
ORIGIN_PID="$!"
wait_for_http "http://127.0.0.1:${ORIGIN_PORT}/health"

cat > "${TMP_DIR}/gateway.conf" <<EOF
listen ${LISTEN_PORT};
metrics_path /status/metrics;
location /proxy/ {
    proxy_pass http://127.0.0.1:${ORIGIN_PORT}/;
}
EOF

start_gateway() { # $1 = max_active_per_host (0 = unlimited)
    TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_WORKER_THREADS="${THREADS}" \
        TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST="$1" \
        "${BINARY}" run -c "${TMP_DIR}/gateway.conf" >"${TMP_DIR}/gateway-cap$1.log" 2>&1 &
    TARDIGRADE_PID="$!"
    wait_for_http "http://127.0.0.1:${LISTEN_PORT}/status/metrics"
}

stop_gateway() {
    [[ -n "$TARDIGRADE_PID" ]] && { kill "$TARDIGRADE_PID" 2>/dev/null || true; wait "$TARDIGRADE_PID" 2>/dev/null || true; }
    TARDIGRADE_PID=""
}

metrics() { curl -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics"; }
mfield()  { printf '%s\n' "$1" | awk -v k="$2" '$1==k{print $2; exit}'; }

# --- phase 1: reuse ---------------------------------------------------------
start_gateway 0
wrk_out="$(wrk -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" \
    "http://127.0.0.1:${LISTEN_PORT}/proxy/health" 2>&1)"
m="$(metrics)"
new="$(mfield "$m" tardigrade_upstream_connections_new_total)"
reused="$(mfield "$m" tardigrade_upstream_connections_reused_total)"
local_r="$(mfield "$m" tardigrade_upstream_connections_reused_local_total)"
cross_r="$(mfield "$m" tardigrade_upstream_connections_reused_cross_worker_total)"
stale="$(mfield "$m" tardigrade_upstream_stale_retries_total)"
rps="$(printf '%s\n' "$wrk_out" | awk '/Requests\/sec/{print $2}')"
non2xx="$(printf '%s\n' "$wrk_out" | awk '/Non-2xx/{print $NF}')"; non2xx="${non2xx:-0}"
ratio="$(awk -v r="${reused:-0}" -v n="${new:-0}" 'BEGIN{t=r+n; if (t==0) print "0"; else printf "%.4f", r/t}')"
stop_gateway

echo ""
echo "== reuse (cap disabled) =="
echo "  throughput            : ${rps:-?} req/s (non-2xx: ${non2xx})"
echo "  connections new/reused: ${new:-0} / ${reused:-0}  (reuse ratio ${ratio})"
echo "  reuse local/cross     : ${local_r:-0} / ${cross_r:-0}"
echo "  stale retries         : ${stale:-0}"

# --- phase 2: active cap ----------------------------------------------------
start_gateway "${CAP}"
wrk_out="$(wrk -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" \
    "http://127.0.0.1:${LISTEN_PORT}/proxy/slow?ms=${SLOW_MS}" 2>&1)"
m="$(metrics)"
at_cap="$(printf '%s\n' "$m" | awk '/tardigrade_upstream_pool_at_capacity_total\{/{print $2; exit}')"
active="$(printf '%s\n' "$m" | awk '/tardigrade_upstream_pool_connections_active\{/{print $2; exit}')"
requests="$(printf '%s\n' "$wrk_out" | awk '/requests in/{print $1; exit}')"
non2xx="$(printf '%s\n' "$wrk_out" | awk '/Non-2xx/{print $NF}')"; non2xx="${non2xx:-0}"
# Let the in-flight /slow requests drain their slots before probing: the cap
# is (correctly) still enforced while they hold the last checkouts.
followup="000"
for _ in 1 2 3 4 5 6 7 8 9 10; do
    followup="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${LISTEN_PORT}/proxy/health")"
    [[ "$followup" == "200" ]] && break
    sleep 0.3
done
m="$(metrics)"
active_after="$(printf '%s\n' "$m" | awk '/tardigrade_upstream_pool_connections_active\{/{print $2; exit}')"
stop_gateway

echo ""
echo "== active cap (MAX_ACTIVE_PER_HOST=${CAP}, /slow?ms=${SLOW_MS}, ${CONNECTIONS} conns) =="
echo "  wrk requests          : ${requests:-?} total, ${non2xx} non-2xx (503 upstream_saturated at the cap)"
echo "  at_capacity_total     : ${at_cap:-0} fail-fast rejections"
echo "  active gauge          : ${active:-0} at load end, ${active_after:-0} after drain (never exceeds the cap)"
echo "  follow-up request     : HTTP ${followup} (saturation must not trip passive upstream health)"
echo ""

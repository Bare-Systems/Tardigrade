#!/usr/bin/env bash
# HTTP/1.1 pool vs HTTP/2 multiplexed upstream benchmark (#145, Phase 4b).
#
# Drives the same concurrent proxy load through the gateway twice and compares
# the two upstream transports:
#   - h1  : gateway -> plain-HTTP origin (upstream_server.py), keep-alive pooled
#           (one pooled TCP connection per busy worker).
#   - h2  : gateway -> TLS h2 origin (nghttpd), multiplexed — many concurrent
#           requests share ONE upstream connection (the #145 capability).
#
# It reports, per transport: throughput, latency, the number of upstream
# connections opened (h1 pool) / kept open (h2 gauge), and error counts. The
# headline is the origin connection count: h2 should serve the whole load over a
# single upstream connection while h1 opens one per concurrently-busy worker.
#
# This is a demonstration/measurement harness, not a pass/fail CI gate.
# Requires: wrk, curl, python3, awk, openssl, and nghttpd (nghttp2-server) for
# the h2 origin (the h2 scenario is skipped with a note if nghttpd is absent).
#
# Usage: benchmarks/h1-vs-h2-upstream.sh [--duration S] [--connections N] [--threads N]

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
BINARY="${REPO_ROOT}/zig-out/bin/tardigrade"
LISTEN_PORT="18089"
H1_ORIGIN_PORT="18088"
H2_ORIGIN_PORT="18087"
DURATION="15"
CONNECTIONS="32"
THREADS="4"
TMP_DIR=""
H1_ORIGIN_PID=""
H2_ORIGIN_PID=""
TARDIGRADE_PID=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)         BINARY="$2";          shift 2 ;;
        --listen-port)    LISTEN_PORT="$2";     shift 2 ;;
        --h1-origin-port) H1_ORIGIN_PORT="$2";  shift 2 ;;
        --h2-origin-port) H2_ORIGIN_PORT="$2";  shift 2 ;;
        --duration)       DURATION="$2";        shift 2 ;;
        --connections)    CONNECTIONS="$2";     shift 2 ;;
        --threads)        THREADS="$2";         shift 2 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

if [[ ! -x "$BINARY" ]]; then
    echo "tardigrade binary not found at ${BINARY} (run: zig build -Doptimize=ReleaseFast)" >&2
    exit 1
fi
for tool in wrk curl python3 awk openssl; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required tool: $tool" >&2; exit 1; }
done

cleanup() {
    local status=$?
    [[ -n "$TARDIGRADE_PID" ]] && { kill "$TARDIGRADE_PID" 2>/dev/null || true; wait "$TARDIGRADE_PID" 2>/dev/null || true; }
    [[ -n "$H1_ORIGIN_PID" ]]  && { kill "$H1_ORIGIN_PID"  2>/dev/null || true; wait "$H1_ORIGIN_PID"  2>/dev/null || true; }
    [[ -n "$H2_ORIGIN_PID" ]]  && { kill "$H2_ORIGIN_PID"  2>/dev/null || true; wait "$H2_ORIGIN_PID"  2>/dev/null || true; }
    [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

wait_for_http() {
    local url="$1" i
    for ((i = 0; i < 50; i += 1)); do
        curl -fsSk "$url" >/dev/null 2>&1 && return 0
        sleep 0.2
    done
    echo "timed out waiting for ${url}" >&2
    return 1
}

TMP_DIR="$(mktemp -d /tmp/tardigrade-h1-vs-h2-XXXX)"

# --- origins -------------------------------------------------------------
python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "${H1_ORIGIN_PORT}" \
    >"${TMP_DIR}/h1-origin.log" 2>&1 &
H1_ORIGIN_PID="$!"
wait_for_http "http://127.0.0.1:${H1_ORIGIN_PORT}/health"

HAVE_H2=0
if command -v nghttpd >/dev/null 2>&1; then
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
        -keyout "${TMP_DIR}/key.pem" -out "${TMP_DIR}/cert.pem" >/dev/null 2>&1
    mkdir -p "${TMP_DIR}/docroot"
    printf 'ok\n' > "${TMP_DIR}/docroot/health"
    nghttpd -d "${TMP_DIR}/docroot" "${H2_ORIGIN_PORT}" "${TMP_DIR}/key.pem" "${TMP_DIR}/cert.pem" \
        >"${TMP_DIR}/h2-origin.log" 2>&1 &
    H2_ORIGIN_PID="$!"
    if wait_for_http "https://127.0.0.1:${H2_ORIGIN_PORT}/health"; then
        HAVE_H2=1
    else
        echo "note: nghttpd did not come up; skipping the h2 scenario" >&2
    fi
else
    echo "note: nghttpd (nghttp2-server) not installed; skipping the h2 scenario" >&2
fi

# --- one scenario --------------------------------------------------------
# $1 = label, $2 = TARDIGRADE_UPSTREAM_PROTOCOL, $3 = proxy_pass target
run_scenario() {
    local label="$1" protocol="$2" target="$3"
    local conf="${TMP_DIR}/${label}.conf" log="${TMP_DIR}/${label}.tardigrade.log"

    cat > "${conf}" <<EOF
listen ${LISTEN_PORT};
metrics_path /status/metrics;
location = /proxy {
    proxy_pass ${target};
}
EOF

    TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_WORKER_THREADS="${THREADS}" \
        TARDIGRADE_UPSTREAM_PROTOCOL="${protocol}" TARDIGRADE_UPSTREAM_TLS_VERIFY=false \
        "${BINARY}" run -c "${conf}" >"${log}" 2>&1 &
    TARDIGRADE_PID="$!"
    wait_for_http "http://127.0.0.1:${LISTEN_PORT}/status/metrics"

    local wrk_out
    wrk_out="$(wrk -t"${THREADS}" -c"${CONNECTIONS}" -d"${DURATION}s" \
        "http://127.0.0.1:${LISTEN_PORT}/proxy" 2>&1)"
    local rps lat non2xx
    rps="$(printf '%s\n' "$wrk_out"    | awk '/Requests\/sec/{print $2}')"
    lat="$(printf '%s\n' "$wrk_out"    | awk '/Latency/{print $2; exit}')"
    non2xx="$(printf '%s\n' "$wrk_out" | awk '/Non-2xx/{print $NF}')"; non2xx="${non2xx:-0}"

    local metrics
    metrics="$(curl -fsS "http://127.0.0.1:${LISTEN_PORT}/status/metrics")"
    mfield() { printf '%s\n' "$metrics" | awk -v k="$1" '$1==k{print $2; exit}'; }

    local h2_reqs h1_reqs new_conns h2_conns h2_resets h2_goaway
    h1_reqs="$(printf '%s\n' "$metrics"   | awk '/protocol="h1"/{print $2}')"
    h2_reqs="$(printf '%s\n' "$metrics"   | awk '/protocol="h2"/{print $2}')"
    new_conns="$(mfield tardigrade_upstream_connections_new_total)"; new_conns="${new_conns:-0}"
    h2_conns="$(mfield tardigrade_upstream_h2_connections_active)";  h2_conns="${h2_conns:-0}"
    h2_resets="$(mfield tardigrade_upstream_h2_stream_resets_total)";h2_resets="${h2_resets:-0}"
    h2_goaway="$(mfield tardigrade_upstream_h2_goaway_total)";       h2_goaway="${h2_goaway:-0}"

    echo ""
    echo "== ${label} (${protocol}) =="
    echo "  throughput           : ${rps:-?} req/s"
    echo "  avg latency          : ${lat:-?}"
    echo "  requests h1 / h2     : ${h1_reqs:-0} / ${h2_reqs:-0}"
    if [[ "$protocol" == "http1" ]]; then
        echo "  upstream conns opened: ${new_conns} (h1 pool: ~one per busy worker)"
    else
        echo "  upstream conns (live): ${h2_conns} (h2: whole load multiplexed over these)"
        echo "  h2 stream resets     : ${h2_resets}"
        echo "  h2 goaway            : ${h2_goaway}"
    fi
    echo "  non-2xx responses    : ${non2xx}"

    kill "${TARDIGRADE_PID}" 2>/dev/null || true
    wait "${TARDIGRADE_PID}" 2>/dev/null || true
    TARDIGRADE_PID=""
}

echo "Load: ${THREADS} threads, ${CONNECTIONS} connections, ${DURATION}s per scenario"
run_scenario "h1-pool" "http1" "http://127.0.0.1:${H1_ORIGIN_PORT}/health"
if [[ "$HAVE_H2" -eq 1 ]]; then
    run_scenario "h2-multiplexed" "h2" "https://127.0.0.1:${H2_ORIGIN_PORT}/health"
fi

echo ""
echo "Interpretation: h2 should carry the entire concurrent load over a single"
echo "upstream connection (conns live == 1), whereas h1 opens one pooled TCP"
echo "connection per concurrently-busy worker thread."

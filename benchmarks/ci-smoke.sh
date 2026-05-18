#!/usr/bin/env bash
# Run a self-contained low-concurrency benchmark smoke test against a local
# Tardigrade instance. Intended for shared CI runners or explicit local-fallback
# runs where only clear regressions should fail the job. This is not the default
# benchmark path; canonical runs belong on a dedicated benchmark target.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BENCH_DIR="${REPO_ROOT}/benchmarks"
BINARY="${REPO_ROOT}/zig-out/bin/tardigrade"
LISTEN_PORT="18069"
UPSTREAM_PORT="18080"
DURATION="30"
CONNECTIONS="10"
THREADS="2"
SAVE_FILE=""
META_FILE="${BENCH_DIR}/targets/ci-smoke.json"
TMP_DIR=""
UPSTREAM_PID=""
TARDIGRADE_PID=""
RESULTS_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)       BINARY="$2";       shift 2 ;;
        --listen-port)  LISTEN_PORT="$2";  shift 2 ;;
        --upstream-port)UPSTREAM_PORT="$2"; shift 2 ;;
        --duration)     DURATION="$2";     shift 2 ;;
        --connections)  CONNECTIONS="$2";  shift 2 ;;
        --threads)      THREADS="$2";      shift 2 ;;
        --save)         SAVE_FILE="$2";    shift 2 ;;
        --meta-file)    META_FILE="$2";    shift 2 ;;
        --help)
            sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

cleanup() {
    local status=$?
    if [[ -n "$TARDIGRADE_PID" ]]; then
        kill "$TARDIGRADE_PID" 2>/dev/null || true
        wait "$TARDIGRADE_PID" 2>/dev/null || true
    fi
    if [[ -n "$UPSTREAM_PID" ]]; then
        kill "$UPSTREAM_PID" 2>/dev/null || true
        wait "$UPSTREAM_PID" 2>/dev/null || true
    fi
    if [[ $status -ne 0 && -n "$TMP_DIR" ]]; then
        if [[ -f "${TMP_DIR}/upstream.log" ]]; then
            echo ""
            echo "---- upstream.log ----"
            cat "${TMP_DIR}/upstream.log"
        fi
        if [[ -f "${TMP_DIR}/tardigrade.log" ]]; then
            echo ""
            echo "---- tardigrade.log ----"
            cat "${TMP_DIR}/tardigrade.log"
        fi
    fi
    [[ -n "$TMP_DIR" ]] && rm -rf "$TMP_DIR"
    exit "$status"
}
trap cleanup EXIT

wait_for_http() {
    local url="$1"
    local attempts="${2:-50}"
    local delay="${3:-0.2}"
    local i
    for ((i = 0; i < attempts; i += 1)); do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep "$delay"
    done
    echo "Timed out waiting for ${url}" >&2
    return 1
}

TMP_DIR="$(mktemp -d /tmp/tardigrade-ci-smoke-XXXX)"
CONFIG_FILE="${TMP_DIR}/ci-smoke.conf"
PID_FILE="${TMP_DIR}/tardigrade.pid"
RESULTS_FILE="${TMP_DIR}/results.json"

sed \
    -e "s|__LISTEN_PORT__|${LISTEN_PORT}|g" \
    -e "s|__UPSTREAM_PORT__|${UPSTREAM_PORT}|g" \
    -e "s|__PID_FILE__|${PID_FILE}|g" \
    "${BENCH_DIR}/fixtures/ci-smoke.conf" > "${CONFIG_FILE}"

python3 "${BENCH_DIR}/fixtures/upstream_server.py" --port "${UPSTREAM_PORT}" >"${TMP_DIR}/upstream.log" 2>&1 &
UPSTREAM_PID="$!"
wait_for_http "http://127.0.0.1:${UPSTREAM_PORT}/health"

TARDIGRADE_RATE_LIMIT_RPS=0 "${BINARY}" run -c "${CONFIG_FILE}" >"${TMP_DIR}/tardigrade.log" 2>&1 &
TARDIGRADE_PID="$!"
wait_for_http "http://127.0.0.1:${LISTEN_PORT}/health"

"${BENCH_DIR}/run.sh" \
    --tool wrk \
    --host 127.0.0.1 \
    --port "${LISTEN_PORT}" \
    --driver "ci-loopback" \
    --config-label "benchmarks/fixtures/ci-smoke.conf" \
    --pid "${TARDIGRADE_PID}" \
    --meta-file "${META_FILE}" \
    --duration "${DURATION}" \
    --connections "${CONNECTIONS}" \
    --threads "${THREADS}" \
    --static-path /health \
    --proxy-path /proxy/health \
    --keepalive-path /health \
    --scenarios static-http1,proxy-http1,keepalive \
    --save "${RESULTS_FILE}"

jq -e '
    ."static-http1".rps >= 250 and
    ."proxy-http1".rps >= 100 and
    .keepalive.rps >= 250 and
    ."static-http1".errors == 0 and
    ."proxy-http1".errors == 0 and
    .keepalive.errors == 0 and
    ."static-http1".p95_ms != null and
    ."static-http1".p999_ms != null and
    ."static-http1".cpu_pct_avg != null and
    ."static-http1".rss_mb_peak != null and
    ."static-http1".p99_ms <= 250 and
    ."proxy-http1".p99_ms <= 250 and
    .keepalive.p99_ms <= 250
' "${RESULTS_FILE}" >/dev/null

if [[ -n "${SAVE_FILE}" ]]; then
    mkdir -p "$(dirname "${SAVE_FILE}")"
    cp "${RESULTS_FILE}" "${SAVE_FILE}"
    echo "Copied smoke results to: ${SAVE_FILE}"
fi

cat "${RESULTS_FILE}" | jq .

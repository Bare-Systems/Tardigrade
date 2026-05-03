#!/usr/bin/env bash
# Run Tardigrade benchmarks using wrk on the Jetson Orin Nano (external load driver).
#
# The Jetson is a separate LAN machine, so measurements are not contaminated by
# sharing physical CPU/RAM/scheduler with the Tardigrade process under test.
#
# Usage:
#   ./benchmarks/jetson-run.sh [OPTIONS]
#
# Options:
#   --host HOST           Target Tardigrade host (default: 192.168.86.55)
#   --port PORT           Target port (default: 8069)
#   --host-header NAME    Override the HTTP Host header
#   --duration SECS       Seconds per scenario (default: 30)
#   --connections N       Concurrent connections (default: 50)
#   --threads N           wrk worker threads (default: 4)
#   --static-path PATH    Path for static-http1 scenario (default: /health)
#   --proxy-path PATH     Path for proxy-http1 scenario (default: /proxy/health)
#   --keepalive-path PATH Path for keepalive scenario (default: /health)
#   --scenarios LIST      Comma-separated scenario names (default: static-http1,proxy-http1,keepalive)
#   --save FILE           Write results JSON to this file
#   --baseline FILE       Compare results against a baseline JSON file
#   --threshold PCT       Regression threshold percentage (default: 10)
#   --jetson SSH_HOST     SSH target for the Jetson (default: jetson)
#   --wrk-path PATH       Path to wrk binary on the Jetson (default: ~/tools/wrk/wrk)
#   --help                Show this message and exit
#
# Prerequisites (local machine):
#   ssh access to the Jetson (SSH host alias "jetson" or --jetson override)
#   jq (for result formatting and baseline comparison)
#
# Prerequisites (Jetson):
#   wrk built at ~/tools/wrk/wrk (or --wrk-path override)
#   Network access to the target host/port
#
# Result layout:
#   Saved files follow the same JSON schema as benchmarks/run.sh so report.sh
#   and baseline comparison work unchanged.

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET_HOST="192.168.86.55"
TARGET_PORT="8069"
HOST_HEADER=""
DURATION=30
CONNECTIONS=50
THREADS=4
STATIC_PATH="/health"
PROXY_PATH="/proxy/health"
KEEPALIVE_PATH="/health"
SCENARIOS="static-http1,proxy-http1,keepalive"
SAVE_FILE=""
BASELINE_FILE=""
REGRESSION_THRESHOLD=10
JETSON_HOST="jetson"
WRK_PATH="~/tools/wrk/wrk"

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)           TARGET_HOST="$2";           shift 2 ;;
        --port)           TARGET_PORT="$2";           shift 2 ;;
        --host-header)    HOST_HEADER="$2";           shift 2 ;;
        --duration)       DURATION="$2";              shift 2 ;;
        --connections)    CONNECTIONS="$2";           shift 2 ;;
        --threads)        THREADS="$2";               shift 2 ;;
        --static-path)    STATIC_PATH="$2";           shift 2 ;;
        --proxy-path)     PROXY_PATH="$2";            shift 2 ;;
        --keepalive-path) KEEPALIVE_PATH="$2";        shift 2 ;;
        --scenarios)      SCENARIOS="$2";             shift 2 ;;
        --save)           SAVE_FILE="$2";             shift 2 ;;
        --baseline)       BASELINE_FILE="$2";         shift 2 ;;
        --threshold)      REGRESSION_THRESHOLD="$2";  shift 2 ;;
        --jetson)         JETSON_HOST="$2";           shift 2 ;;
        --wrk-path)       WRK_PATH="$2";              shift 2 ;;
        --help)           sed -n '/^# Usage/,/^[^#]/p' "$0" | head -n -1; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

BASE_URL="http://${TARGET_HOST}:${TARGET_PORT}"

# ── Verify connectivity ────────────────────────────────────────────────────────
echo "Verifying SSH access to ${JETSON_HOST}..."
if ! ssh -o ConnectTimeout=5 -o BatchMode=yes "$JETSON_HOST" true 2>/dev/null; then
    echo "Cannot reach Jetson at '${JETSON_HOST}' via SSH." >&2
    exit 1
fi

echo "Verifying wrk at ${WRK_PATH} on ${JETSON_HOST}..."
if ! ssh "$JETSON_HOST" "test -x ${WRK_PATH}" 2>/dev/null; then
    echo "wrk not found or not executable at ${WRK_PATH} on ${JETSON_HOST}." >&2
    echo "Build it with: ssh ${JETSON_HOST} 'cd ~/tools/wrk && make'" >&2
    exit 1
fi

echo "Verifying target ${BASE_URL}/health from ${JETSON_HOST}..."
if ! ssh "$JETSON_HOST" "curl -sf --max-time 5 '${BASE_URL}/health' >/dev/null" 2>/dev/null; then
    echo "Target ${BASE_URL}/health did not respond from ${JETSON_HOST}." >&2
    exit 1
fi

# ── Result accumulator ────────────────────────────────────────────────────────
RESULTS_JSON="{}"
add_result() {
    local scenario="$1" rps="$2" p50_ms="$3" p99_ms="$4" errors="$5"
    RESULTS_JSON=$(jq --arg s "$scenario" --argjson rps "$rps" \
        --argjson p50 "$p50_ms" --argjson p99 "$p99_ms" --argjson err "$errors" \
        '.[$s] = {rps: $rps, p50_ms: $p50, p99_ms: $p99, errors: $err}' \
        <<<"$RESULTS_JSON")
}

# ── wrk runner (executes on Jetson via SSH) ───────────────────────────────────
run_wrk_remote() {
    local url="$1" label="$2"
    local header_flags=""
    if [[ -n "$HOST_HEADER" ]]; then
        header_flags="-H 'Host: ${HOST_HEADER}'"
    fi

    local raw
    raw=$(ssh "$JETSON_HOST" \
        "${WRK_PATH} -t${THREADS} -c${CONNECTIONS} -d${DURATION}s -L ${header_flags} '${url}'" \
        2>&1) || true

    local rps p50 p99 errors
    rps=$(echo "$raw" | grep -E "Requests/sec" | awk '{print $2}' | tr -d ',' || echo 0)
    p50=$(echo "$raw" | awk '/50%/{v=$2; sub(/ms$/,"",v); sub(/us$/,"",v); if($2~/us/)v=v/1000; print v+0}' || echo 0)
    p99=$(echo "$raw" | awk '/99%/{v=$2; sub(/ms$/,"",v); sub(/us$/,"",v); if($2~/us/)v=v/1000; print v+0}' || echo 0)
    errors=$(echo "$raw" | grep -E "Non-2xx" | grep -oE '[0-9]+' | head -1 || echo 0)
    rps=${rps:-0}; p50=${p50:-0}; p99=${p99:-0}; errors=${errors:-0}
    echo "  $label — ${rps} req/s  p50=${p50}ms  p99=${p99}ms  errors=${errors}"
    add_result "$label" "$rps" "$p50" "$p99" "$errors"
}

# ── Scenarios ─────────────────────────────────────────────────────────────────
scenario_static_http1() {
    echo "==> static-http1: static file serving over HTTP/1.1 (${STATIC_PATH})"
    run_wrk_remote "${BASE_URL}${STATIC_PATH}" "static-http1"
}

scenario_proxy_http1() {
    echo "==> proxy-http1: reverse proxy route over HTTP/1.1 (${PROXY_PATH})"
    run_wrk_remote "${BASE_URL}${PROXY_PATH}" "proxy-http1"
}

scenario_keepalive() {
    echo "==> keepalive: keep-alive connection reuse (${KEEPALIVE_PATH})"
    run_wrk_remote "${BASE_URL}${KEEPALIVE_PATH}" "keepalive"
}

# ── Main ──────────────────────────────────────────────────────────────────────
echo "Tardigrade benchmark — target: ${BASE_URL}  driver: ${JETSON_HOST} (wrk)"
echo "Duration: ${DURATION}s  Connections: ${CONNECTIONS}  Threads: ${THREADS}"
echo "Paths: static=${STATIC_PATH} proxy=${PROXY_PATH} keepalive=${KEEPALIVE_PATH}"
if [[ -n "$HOST_HEADER" ]]; then
    echo "Host header override: ${HOST_HEADER}"
fi
echo ""

IFS=',' read -ra SCENARIO_LIST <<< "$SCENARIOS"
for scenario in "${SCENARIO_LIST[@]}"; do
    case "$scenario" in
        static-http1) scenario_static_http1 ;;
        proxy-http1)  scenario_proxy_http1 ;;
        keepalive)    scenario_keepalive ;;
        proxy-http2 | reload-under-load | auth-enforcement | rate-limit | spike)
            echo "==> ${scenario}: not supported by jetson-run.sh (use run.sh with --tool k6 or h2load)"
            ;;
        *) echo "Unknown scenario: $scenario" >&2 ;;
    esac
done

# ── Attach metadata ───────────────────────────────────────────────────────────
GIT_TAG=$(git -C "$(dirname "$0")/.." describe --tags --always 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RESULTS_JSON=$(jq \
    --arg tag "$GIT_TAG" --arg ts "$TIMESTAMP" \
    --arg host "$TARGET_HOST" --arg port "$TARGET_PORT" \
    --arg host_header "$HOST_HEADER" \
    --arg static_path "$STATIC_PATH" --arg proxy_path "$PROXY_PATH" --arg keepalive_path "$KEEPALIVE_PATH" \
    --arg driver "${JETSON_HOST}" \
    --argjson dur "$DURATION" --argjson conn "$CONNECTIONS" \
    '. + {_meta: {tag: $tag, timestamp: $ts, host: $host, port: $port,
          tool: "wrk", driver: $driver, duration_s: $dur, connections: $conn,
          host_header: $host_header, static_path: $static_path,
          proxy_path: $proxy_path, keepalive_path: $keepalive_path}}' \
    <<<"$RESULTS_JSON")

# ── Save ──────────────────────────────────────────────────────────────────────
if [[ -n "$SAVE_FILE" ]]; then
    mkdir -p "$(dirname "$SAVE_FILE")"
    echo "$RESULTS_JSON" > "$SAVE_FILE"
    echo ""
    echo "Results saved to: $SAVE_FILE"
fi

# ── Baseline comparison ───────────────────────────────────────────────────────
REGRESSION=0
if [[ -n "$BASELINE_FILE" && -f "$BASELINE_FILE" ]]; then
    echo ""
    echo "Comparing against baseline: $BASELINE_FILE"
    while IFS= read -r scenario; do
        [[ "$scenario" == _meta ]] && continue
        baseline_rps=$(jq -r --arg s "$scenario" '.[$s].rps // 0' "$BASELINE_FILE")
        current_rps=$(echo "$RESULTS_JSON" | jq -r --arg s "$scenario" '.[$s].rps // 0')
        if [[ "$baseline_rps" == "0" || "$baseline_rps" == "null" ]]; then continue; fi
        delta=$(awk -v b="$baseline_rps" -v c="$current_rps" \
            'BEGIN { printf "%.1f", (c - b) / b * 100 }')
        status="OK"
        neg=$(awk -v d="$delta" -v t="$REGRESSION_THRESHOLD" \
            'BEGIN { print (d < -t) ? "yes" : "no" }')
        if [[ "$neg" == "yes" ]]; then status="REGRESSION"; REGRESSION=1; fi
        echo "  $scenario: baseline=${baseline_rps} current=${current_rps} delta=${delta}% [$status]"
    done < <(echo "$RESULTS_JSON" | jq -r 'keys[]')
fi

echo ""
echo "$RESULTS_JSON" | jq .

[[ "$REGRESSION" -eq 0 ]] || exit 2

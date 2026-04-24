#!/usr/bin/env bash
# Tardigrade benchmark runner.
# Runs configurable scenarios against a live Tardigrade instance and
# produces a JSON summary suitable for baseline comparison.
#
# Usage:
#   ./benchmarks/run.sh [OPTIONS]
#
# Options:
#   --host HOST         Target host (default: 127.0.0.1)
#   --port PORT         Target port (default: 8069)
#   --tls               Use HTTPS (default: plain HTTP)
#   --insecure          Skip TLS certificate verification (for self-signed certs)
#   --duration SECS     Benchmark duration per scenario (default: 30)
#   --connections N     Concurrent connections (default: 50)
#   --threads N         Worker threads for wrk (default: 4)
#   --scenarios LIST    Comma-separated scenario names to run (default: all)
#   --tool TOOL         Preferred tool: wrk|h2load|fortio|k6 (default: auto-detect)
#   --baseline FILE     Compare results against a baseline JSON file
#   --save FILE         Write results JSON to this file
#   --help              Show this message and exit
#
# Scenarios:
#   static-http1        Static file serving over HTTP/1.1
#   proxy-http1         Reverse proxy over HTTP/1.1
#   proxy-http2         Reverse proxy over HTTP/2 (requires h2load)
#   keepalive           Keep-alive connection reuse
#   reload-under-load   Trigger SIGHUP during a load run and measure degradation
#
# Prerequisites:
#   At least one of: wrk, h2load (nghttp2), fortio, k6
#   curl, jq (for result formatting and comparison)
#   A running Tardigrade process at the target host/port
#
# Baseline comparison:
#   Run once with --save baselines/$(git describe --tags).json to capture a release.
#   Run again with --baseline baselines/<previous>.json to detect regressions.
#   Exit code 2 indicates a regression above the threshold (default: 10%).

set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
TARGET_HOST="127.0.0.1"
TARGET_PORT="8069"
USE_TLS=false
INSECURE=false
DURATION=30
CONNECTIONS=50
THREADS=4
SCENARIOS="static-http1,proxy-http1,keepalive"
PREFERRED_TOOL=""
BASELINE_FILE=""
SAVE_FILE=""
REGRESSION_THRESHOLD=10  # percent

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)       TARGET_HOST="$2";        shift 2 ;;
        --port)       TARGET_PORT="$2";        shift 2 ;;
        --tls)        USE_TLS=true;            shift ;;
        --insecure)   INSECURE=true;           shift ;;
        --duration)   DURATION="$2";           shift 2 ;;
        --connections)CONNECTIONS="$2";        shift 2 ;;
        --threads)    THREADS="$2";            shift 2 ;;
        --scenarios)  SCENARIOS="$2";          shift 2 ;;
        --tool)       PREFERRED_TOOL="$2";     shift 2 ;;
        --baseline)   BASELINE_FILE="$2";      shift 2 ;;
        --save)       SAVE_FILE="$2";          shift 2 ;;
        --threshold)  REGRESSION_THRESHOLD="$2"; shift 2 ;;
        --help)       sed -n '/^# Usage/,/^[^#]/p' "$0" | head -n -1; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

SCHEME=$( $USE_TLS && echo "https" || echo "http" )
BASE_URL="${SCHEME}://${TARGET_HOST}:${TARGET_PORT}"
INSECURE_FLAG=$( $INSECURE && echo "--insecure" || echo "" )

# ── Tool detection ─────────────────────────────────────────────────────────────
detect_tool() {
    local preferred="$1"
    if [[ -n "$preferred" ]]; then
        if command -v "$preferred" &>/dev/null; then echo "$preferred"; return; fi
        echo "Requested tool '$preferred' not found" >&2; exit 1
    fi
    for t in wrk h2load fortio k6; do
        if command -v "$t" &>/dev/null; then echo "$t"; return; fi
    done
    echo "No benchmark tool found. Install wrk, h2load (nghttp2), fortio, or k6." >&2
    exit 1
}

TOOL=$(detect_tool "$PREFERRED_TOOL")
echo "Using tool: $TOOL"

# ── Result accumulator ────────────────────────────────────────────────────────
RESULTS_JSON="{}"
add_result() {
    local scenario="$1" rps="$2" p50_ms="$3" p99_ms="$4" errors="$5"
    RESULTS_JSON=$(jq --arg s "$scenario" --argjson rps "$rps" \
        --argjson p50 "$p50_ms" --argjson p99 "$p99_ms" --argjson err "$errors" \
        '.[$s] = {rps: $rps, p50_ms: $p50, p99_ms: $p99, errors: $err}' \
        <<<"$RESULTS_JSON")
}

# ── wrk runner ────────────────────────────────────────────────────────────────
run_wrk() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(--insecure)
    local raw
    raw=$(wrk -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" -L \
        ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
    local rps p50 p99 errors
    rps=$(echo "$raw" | grep -E "Requests/sec" | awk '{print $2}' | tr -d ',' || echo 0)
    # -L produces a latency distribution block; parse ms values (wrk may suffix us/ms/s)
    p50=$(echo "$raw" | awk '/50%/{v=$2; sub(/ms$/,"",v); sub(/us$/,"",v); if($2~/us/)v=v/1000; print v+0}' || echo 0)
    p99=$(echo "$raw" | awk '/99%/{v=$2; sub(/ms$/,"",v); sub(/us$/,"",v); if($2~/us/)v=v/1000; print v+0}' || echo 0)
    errors=$(echo "$raw" | grep -E "Non-2xx" | grep -oE '[0-9]+' | head -1 || echo 0)
    rps=${rps:-0}; p50=${p50:-0}; p99=${p99:-0}; errors=${errors:-0}
    echo "  $label — ${rps} req/s  p50=${p50}ms  p99=${p99}ms  errors=${errors}"
    add_result "$label" "$rps" "$p50" "$p99" "$errors"
}

# ── h2load runner ─────────────────────────────────────────────────────────────
run_h2load() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(--insecure)
    local raw
    raw=$(h2load -n $((CONNECTIONS * DURATION * 10)) \
        -c "$CONNECTIONS" -t "$THREADS" ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
    local rps p50 p99 errors
    rps=$(echo "$raw" | grep -E "^finished" | grep -oE '[0-9.]+ req/s' | grep -oE '[0-9.]+' || echo 0)
    p50=$(echo "$raw" | grep -E "50th" | grep -oE '[0-9.]+ us' | grep -oE '[0-9.]+' | \
        awk '{printf "%.2f", $1/1000}' || echo 0)
    p99=$(echo "$raw" | grep -E "99th" | grep -oE '[0-9.]+ us' | grep -oE '[0-9.]+' | \
        awk '{printf "%.2f", $1/1000}' || echo 0)
    errors=$(echo "$raw" | grep -E "failed" | grep -oE '[0-9]+' | head -1 || echo 0)
    rps=${rps:-0}; p50=${p50:-0}; p99=${p99:-0}; errors=${errors:-0}
    echo "  $label — ${rps} req/s  p50=${p50}ms  p99=${p99}ms  errors=${errors}"
    add_result "$label" "$rps" "$p50" "$p99" "$errors"
}

# ── fortio runner ─────────────────────────────────────────────────────────────
run_fortio() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(-insecure)
    local raw
    raw=$(fortio load -c "$CONNECTIONS" -t "${DURATION}s" \
        -json /dev/stdout ${extra[@]+"${extra[@]}"} "$url" 2>/dev/null) || true
    local rps p50 p99 errors
    rps=$(echo "$raw" | jq -r '.ActualQPS // 0')
    p50=$(echo "$raw" | jq -r '(.DurationHistogram.Percentiles[] | select(.Percentile==50) | .Value) // 0' | \
        awk '{printf "%.2f", $1*1000}')
    p99=$(echo "$raw" | jq -r '(.DurationHistogram.Percentiles[] | select(.Percentile==99) | .Value) // 0' | \
        awk '{printf "%.2f", $1*1000}')
    errors=$(echo "$raw" | jq -r '(.ErrorsDurationHistogram.Count // 0)')
    rps=${rps:-0}; p50=${p50:-0}; p99=${p99:-0}; errors=${errors:-0}
    echo "  $label — ${rps} req/s  p50=${p50}ms  p99=${p99}ms  errors=${errors}"
    add_result "$label" "$rps" "$p50" "$p99" "$errors"
}

# ── k6 summary parser ────────────────────────────────────────────────────────
# Parses a k6 --summary-export JSON file (v1.x flat format) and calls add_result.
_k6_parse_summary() {
    local tmpfile="$1" label="$2"
    local rps p50 p99 errors
    # k6 v1.x: metrics are flat objects — .rate/.count/.med/.["p(99)"] directly
    rps=$(jq -r '.metrics.http_reqs.rate // 0' "$tmpfile" | awk '{printf "%.0f", $1}')
    p50=$(jq -r '.metrics.http_req_duration.med // 0' "$tmpfile" | awk '{printf "%.3f", $1}')
    p99=$(jq -r '.metrics.http_req_duration["p(99)"] // 0' "$tmpfile" | awk '{printf "%.3f", $1}')
    # passes = count of http_req_failed=1 samples (i.e. actual failed requests)
    errors=$(jq -r '.metrics.http_req_failed.passes // 0' "$tmpfile")
    rps=${rps:-0}; p50=${p50:-0}; p99=${p99:-0}; errors=${errors:-0}
    echo "  $label — ${rps} req/s  p50=${p50}ms  p99=${p99}ms  errors=${errors}"
    add_result "$label" "$rps" "$p50" "$p99" "$errors"
}

# ── k6 throughput runner ──────────────────────────────────────────────────────
run_k6() {
    local url="$1" label="$2"
    local tmpfile; tmpfile=$(mktemp /tmp/k6-summary-XXXX.json)
    local extra_flags=()
    $INSECURE && extra_flags+=(--insecure-skip-tls-verify)

    # BASE_URL is the scheme+host+port only; the scenario appends /health
    local base_url="${url%/health}"
    base_url="${base_url%/}"

    BASE_URL="$base_url" \
    K6_VUS="$CONNECTIONS" \
    K6_DURATION="${DURATION}s" \
        k6 run --no-color --quiet \
            --summary-export "$tmpfile" \
            ${extra_flags[@]+"${extra_flags[@]}"} \
            "$(dirname "$0")/scenarios/throughput.js" 2>/dev/null || true

    _k6_parse_summary "$tmpfile" "$label"
    rm -f "$tmpfile"
}

# ── k6 behavioral scenario runner ─────────────────────────────────────────────
# Runs a named k6 JS script; passes BASE_URL and env overrides through.
# Results are added to the accumulator with rps/p50/p99/errors extracted from
# the k6 summary export.
run_k6_scenario() {
    local script="$1" label="$2"
    shift 2
    local tmpfile; tmpfile=$(mktemp /tmp/k6-summary-XXXX.json)
    local extra_flags=()
    $INSECURE && extra_flags+=(--insecure-skip-tls-verify)

    BASE_URL="${SCHEME}://${TARGET_HOST}:${TARGET_PORT}" \
        k6 run --no-color --quiet \
            --summary-export "$tmpfile" \
            ${extra_flags[@]+"${extra_flags[@]}"} \
            "$@" \
            "$(dirname "$0")/scenarios/${script}.js" 2>/dev/null || true

    _k6_parse_summary "$tmpfile" "$label"
    rm -f "$tmpfile"
}

# ── Generic runner dispatcher ─────────────────────────────────────────────────
run_scenario() {
    local url="$1" label="$2"
    case "$TOOL" in
        wrk)    run_wrk    "$url" "$label" ;;
        h2load) run_h2load "$url" "$label" ;;
        fortio) run_fortio "$url" "$label" ;;
        k6)     run_k6     "$url" "$label" ;;
        *)      echo "Unsupported tool: $TOOL" >&2; exit 1 ;;
    esac
}

# ── Scenarios ─────────────────────────────────────────────────────────────────
scenario_static_http1() {
    echo "==> static-http1: static file serving over HTTP/1.1"
    run_scenario "${BASE_URL}/health" "static-http1"
}

scenario_proxy_http1() {
    echo "==> proxy-http1: reverse proxy route over HTTP/1.1"
    run_scenario "${BASE_URL}/health" "proxy-http1"
}

scenario_proxy_http2() {
    echo "==> proxy-http2: reverse proxy route over HTTP/2"
    if [[ "$TOOL" != "h2load" ]]; then
        echo "  Skipping — HTTP/2 scenario requires h2load"
        return
    fi
    run_h2load "${BASE_URL}/health" "proxy-http2"
}

scenario_keepalive() {
    echo "==> keepalive: keep-alive connection reuse"
    run_scenario "${BASE_URL}/health" "keepalive"
}

scenario_auth_enforcement() {
    echo "==> auth-enforcement: verify 401 for unauthenticated and 2xx for authenticated requests"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — auth-enforcement scenario requires k6"
        return
    fi
    run_k6_scenario "auth-enforcement" "auth-enforcement" \
        -e K6_VUS="${CONNECTIONS}" \
        -e K6_DURATION="${DURATION}s" \
        ${AUTH_TOKEN:+-e AUTH_TOKEN="$AUTH_TOKEN"} \
        ${AUTH_PROTECTED_PATH:+-e AUTH_PROTECTED_PATH="$AUTH_PROTECTED_PATH"}
}

scenario_rate_limit() {
    echo "==> rate-limit: verify 429s appear when request rate exceeds the configured ceiling"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — rate-limit scenario requires k6"
        return
    fi
    run_k6_scenario "rate-limit" "rate-limit" \
        ${TARDIGRADE_RATE_LIMIT_RPS:+-e RATE_LIMIT_RPS="$TARDIGRADE_RATE_LIMIT_RPS"} \
        ${RATE_LIMIT_PATH:+-e RATE_LIMIT_PATH="$RATE_LIMIT_PATH"}
}

scenario_spike() {
    echo "==> spike: sudden surge to ${SPIKE_PEAK:-150} VUs — measure error rate and p99 under peak load"
    if [[ "$TOOL" != "k6" ]]; then
        echo "  Skipping — spike scenario requires k6"
        return
    fi
    run_k6_scenario "spike" "spike" \
        ${SPIKE_PEAK:+-e SPIKE_PEAK="$SPIKE_PEAK"}
}

scenario_reload_under_load() {
    echo "==> reload-under-load: SIGHUP during load"
    if ! command -v wrk &>/dev/null; then
        echo "  Skipping — reload-under-load requires wrk"
        return
    fi
    local pid_file="${TARDIGRADE_PID_FILE:-/tmp/tardigrade.pid}"
    if [[ ! -f "$pid_file" ]]; then
        echo "  Skipping — no PID file at $pid_file (set TARDIGRADE_PID_FILE)"
        return
    fi
    local pid; pid=$(cat "$pid_file")
    (
        sleep "$((DURATION / 3))"
        echo "  Sending SIGHUP to PID $pid..."
        kill -HUP "$pid" 2>/dev/null || true
    ) &
    run_wrk "${BASE_URL}/health" "reload-under-load"
    wait 2>/dev/null || true
}

# ── Main loop ─────────────────────────────────────────────────────────────────
echo "Tardigrade benchmark — target: ${BASE_URL}  tool: ${TOOL}"
echo "Duration: ${DURATION}s  Connections: ${CONNECTIONS}  Threads: ${THREADS}"
echo ""

IFS=',' read -ra SCENARIO_LIST <<< "$SCENARIOS"
for scenario in "${SCENARIO_LIST[@]}"; do
    case "$scenario" in
        static-http1)       scenario_static_http1 ;;
        proxy-http1)        scenario_proxy_http1 ;;
        proxy-http2)        scenario_proxy_http2 ;;
        keepalive)          scenario_keepalive ;;
        reload-under-load)  scenario_reload_under_load ;;
        auth-enforcement)   scenario_auth_enforcement ;;
        rate-limit)         scenario_rate_limit ;;
        spike)              scenario_spike ;;
        *)                  echo "Unknown scenario: $scenario" >&2 ;;
    esac
done

# ── Attach metadata ──────────────────────────────────────────────────────────
GIT_TAG=$(git -C "$(dirname "$0")/.." describe --tags --always 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
RESULTS_JSON=$(jq \
    --arg tag "$GIT_TAG" --arg ts "$TIMESTAMP" \
    --arg host "$TARGET_HOST" --arg port "$TARGET_PORT" \
    --arg tool "$TOOL" --argjson dur "$DURATION" --argjson conn "$CONNECTIONS" \
    '. + {_meta: {tag: $tag, timestamp: $ts, host: $host, port: $port,
          tool: $tool, duration_s: $dur, connections: $conn}}' \
    <<<"$RESULTS_JSON")

# ── Save ─────────────────────────────────────────────────────────────────────
if [[ -n "$SAVE_FILE" ]]; then
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

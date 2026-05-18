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
#   --host-header NAME  Override the HTTP Host header / :authority
#   --driver LABEL      Load-driver label recorded in metadata
#   --worker-count N    Tardigrade worker count recorded in metadata
#   --config-label STR  Config/profile label recorded in metadata
#   --pid PID           Target Tardigrade process ID for CPU/RSS sampling
#   --pid-file FILE     File containing the target Tardigrade PID for CPU/RSS sampling
#   --tls               Use HTTPS (default: plain HTTP)
#   --insecure          Skip TLS certificate verification (for self-signed certs)
#   --duration SECS     Benchmark duration per scenario (default: 30)
#   --connections N     Concurrent connections (default: 50)
#   --threads N         Worker threads for wrk (default: 4)
#   --static-path PATH  Path for static-http1 and reload-under-load (default: /health)
#   --proxy-path PATH   Path for proxy-http1/proxy-http2/proxy-http3 (default: /proxy/health)
#   --keepalive-path PATH  Path for keepalive (default: /health)
#   --proxy-payload-64k-path PATH  Path for 64 KiB proxied payload benchmark (default: /proxy/payload-64k.bin)
#   --proxy-payload-256k-path PATH  Path for 256 KiB proxied payload benchmark (default: /proxy/payload-256k.bin)
#   --h2-path PATH      Path for static-http2 (default: same as --static-path)
#   --h3-path PATH      Path for static-http3 (default: same as --static-path)
#   --scenarios LIST    Comma-separated scenario names to run (default: all)
#   --tool TOOL         Preferred tool: wrk|h2load|fortio|k6 (default: auto-detect)
#   --baseline FILE     Compare results against a baseline JSON file
#   --save FILE         Write results JSON to this file
#   --meta-file FILE    Merge extra JSON metadata into _meta
#   --sample-interval-ms N  CPU/RSS sample interval in milliseconds (default: 500)
#   --help              Show this message and exit
#
# Scenarios:
#   static-http1        Static file serving over HTTP/1.1
#   proxy-http1         Reverse proxy over HTTP/1.1
#   static-http2        Static file serving over HTTP/2 (requires h2load or k6+TLS)
#   proxy-http2         Reverse proxy over HTTP/2 (requires h2load)
#   static-http3        Static file serving over HTTP/3 (requires h2load with QUIC + --tls)
#   proxy-http3         Reverse proxy over HTTP/3 (requires h2load with QUIC + --tls)
#   keepalive           Keep-alive connection reuse
#   proxy-payload-64k   Reverse proxy 64 KiB payload transfer
#   proxy-payload-256k  Reverse proxy 256 KiB payload transfer
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
HOST_HEADER=""
DRIVER_LABEL="local"
WORKER_COUNT=""
CONFIG_LABEL=""
TARGET_PID=""
PID_FILE=""
USE_TLS=false
INSECURE=false
DURATION=30
CONNECTIONS=50
THREADS=4
STATIC_PATH="/health"
PROXY_PATH="/proxy/health"
KEEPALIVE_PATH="/health"
PROXY_PAYLOAD_64K_PATH="/proxy/payload-64k.bin"
PROXY_PAYLOAD_256K_PATH="/proxy/payload-256k.bin"
H2_PATH=""      # defaults to STATIC_PATH after arg parsing
H3_PATH=""      # defaults to STATIC_PATH after arg parsing
SCENARIOS="static-http1,proxy-http1,keepalive"
PREFERRED_TOOL=""
BASELINE_FILE=""
SAVE_FILE=""
META_FILE=""
REGRESSION_THRESHOLD=10  # percent
SAMPLE_INTERVAL_MS=500

# ── Arg parsing ───────────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        --host)       TARGET_HOST="$2";        shift 2 ;;
        --port)       TARGET_PORT="$2";        shift 2 ;;
        --host-header)HOST_HEADER="$2";        shift 2 ;;
        --driver)     DRIVER_LABEL="$2";       shift 2 ;;
        --worker-count)WORKER_COUNT="$2";      shift 2 ;;
        --config-label)CONFIG_LABEL="$2";      shift 2 ;;
        --pid)        TARGET_PID="$2";         shift 2 ;;
        --pid-file)   PID_FILE="$2";           shift 2 ;;
        --tls)        USE_TLS=true;            shift ;;
        --insecure)   INSECURE=true;           shift ;;
        --duration)   DURATION="$2";           shift 2 ;;
        --connections)CONNECTIONS="$2";        shift 2 ;;
        --threads)    THREADS="$2";            shift 2 ;;
        --static-path)STATIC_PATH="$2";        shift 2 ;;
        --proxy-path) PROXY_PATH="$2";         shift 2 ;;
        --keepalive-path)KEEPALIVE_PATH="$2";  shift 2 ;;
        --proxy-payload-64k-path)PROXY_PAYLOAD_64K_PATH="$2"; shift 2 ;;
        --proxy-payload-256k-path)PROXY_PAYLOAD_256K_PATH="$2"; shift 2 ;;
        --h2-path)    H2_PATH="$2";            shift 2 ;;
        --h3-path)    H3_PATH="$2";            shift 2 ;;
        --scenarios)  SCENARIOS="$2";          shift 2 ;;
        --tool)       PREFERRED_TOOL="$2";     shift 2 ;;
        --baseline)   BASELINE_FILE="$2";      shift 2 ;;
        --save)       SAVE_FILE="$2";          shift 2 ;;
        --meta-file)  META_FILE="$2";          shift 2 ;;
        --threshold)  REGRESSION_THRESHOLD="$2"; shift 2 ;;
        --sample-interval-ms) SAMPLE_INTERVAL_MS="$2"; shift 2 ;;
        --help)       sed -n '/^# Usage/,/^[^#]/p' "$0" | head -n -1; exit 0 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

H2_PATH="${H2_PATH:-$STATIC_PATH}"
H3_PATH="${H3_PATH:-$STATIC_PATH}"
SCHEME=$( $USE_TLS && echo "https" || echo "http" )
BASE_URL="${SCHEME}://${TARGET_HOST}:${TARGET_PORT}"
REQUEST_HEADERS=()
if [[ -n "$HOST_HEADER" ]]; then
    REQUEST_HEADERS+=("Host: $HOST_HEADER")
fi

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

detect_zig_version() {
    if command -v zig &>/dev/null; then
        zig version
    else
        echo "unknown"
    fi
}

detect_os_name() {
    uname -s 2>/dev/null || echo "unknown"
}

detect_kernel_release() {
    uname -r 2>/dev/null || echo "unknown"
}

detect_arch() {
    uname -m 2>/dev/null || echo "unknown"
}

detect_cpu_model() {
    case "$(uname -s 2>/dev/null || true)" in
        Darwin)
            sysctl -n machdep.cpu.brand_string 2>/dev/null || sysctl -n hw.model 2>/dev/null || echo "unknown"
            ;;
        Linux)
            if command -v lscpu &>/dev/null; then
                lscpu | awk -F: '/Model name:/{gsub(/^[ \t]+/, "", $2); print $2; exit}'
            elif [[ -r /proc/cpuinfo ]]; then
                awk -F: '/model name/{gsub(/^[ \t]+/, "", $2); print $2; exit}' /proc/cpuinfo
            else
                echo "unknown"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

detect_cpu_threads() {
    getconf _NPROCESSORS_ONLN 2>/dev/null || echo "unknown"
}

detect_memory_mb() {
    case "$(uname -s 2>/dev/null || true)" in
        Darwin)
            local bytes
            bytes=$(sysctl -n hw.memsize 2>/dev/null || echo 0)
            awk -v b="$bytes" 'BEGIN { printf "%.0f", b / 1048576 }'
            ;;
        Linux)
            if [[ -r /proc/meminfo ]]; then
                awk '/MemTotal:/{printf "%.0f", $2 / 1024}' /proc/meminfo
            else
                echo "unknown"
            fi
            ;;
        *)
            echo "unknown"
            ;;
    esac
}

resolve_target_pid() {
    if [[ -n "$TARGET_PID" ]]; then
        printf '%s\n' "$TARGET_PID"
        return 0
    fi
    if [[ -n "$PID_FILE" ]]; then
        if [[ ! -f "$PID_FILE" ]]; then
            echo "PID file not found: $PID_FILE" >&2
            exit 1
        fi
        tr -d '[:space:]' < "$PID_FILE"
        return 0
    fi
    return 1
}

latency_value_to_ms() {
    local value="$1"
    if [[ -z "$value" || "$value" == "null" ]]; then
        echo "null"
        return 0
    fi
    awk -v v="$value" 'BEGIN {
        if (v ~ /us$/) { sub(/us$/, "", v); printf "%.3f", v / 1000; exit }
        if (v ~ /ms$/) { sub(/ms$/, "", v); printf "%.3f", v + 0; exit }
        if (v ~ /s$/)  { sub(/s$/, "", v);  printf "%.3f", v * 1000; exit }
        printf "%.3f", v + 0
    }'
}

wrk_percentile_ms() {
    local raw="$1" percentile="$2"
    local value
    value=$(printf '%s\n' "$raw" | awk -v pct="$percentile" '$1 == pct { print $2; exit }')
    latency_value_to_ms "$value"
}

extract_h2load_percentile_ms() {
    local raw="$1" percentile="$2"
    local pattern
    case "$percentile" in
        50) pattern='50th' ;;
        95) pattern='95th' ;;
        99) pattern='99th' ;;
        99.9) pattern='99.9th' ;;
        *) echo "null"; return 0 ;;
    esac
    local value
    value=$(printf '%s\n' "$raw" | grep -E "$pattern" | grep -oE '[0-9.]+ (us|ms|s)' | head -1 | tr -d ' ')
    latency_value_to_ms "$value"
}

average_column_or_null() {
    local file="$1" column="$2"
    awk -v col="$column" '
        NF >= col {
            sum += $col
            count += 1
        }
        END {
            if (count > 0) {
                printf "%.2f", sum / count
            } else {
                printf "null"
            }
        }
    ' "$file"
}

peak_rss_mb_or_null() {
    local file="$1"
    awk '
        NF >= 1 && $1 > max { max = $1 }
        END {
            if (max > 0) {
                printf "%.2f", max / 1024
            } else {
                printf "null"
            }
        }
    ' "$file"
}

MONITOR_FILE=""
MONITOR_PID=""
CURRENT_CPU_PCT_AVG="null"
CURRENT_RSS_MB_PEAK="null"

monitor_target_process() {
    local pid="$1" sample_interval_s="$2" outfile="$3"
    while kill -0 "$pid" 2>/dev/null; do
        ps -p "$pid" -o rss= -o %cpu= 2>/dev/null | awk 'NF >= 2 { print $1, $2; exit }' >> "$outfile"
        sleep "$sample_interval_s"
    done
}

start_process_monitor() {
    CURRENT_CPU_PCT_AVG="null"
    CURRENT_RSS_MB_PEAK="null"
    MONITOR_FILE=""
    MONITOR_PID=""

    local pid
    if ! pid=$(resolve_target_pid 2>/dev/null); then
        return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
        echo "Target PID $pid is not running" >&2
        exit 1
    fi

    local sample_interval_s
    sample_interval_s=$(awk -v ms="$SAMPLE_INTERVAL_MS" 'BEGIN { printf "%.3f", ms / 1000 }')
    MONITOR_FILE=$(mktemp /tmp/tardigrade-bench-monitor-XXXX.txt)
    monitor_target_process "$pid" "$sample_interval_s" "$MONITOR_FILE" &
    MONITOR_PID="$!"
}

stop_process_monitor() {
    if [[ -n "$MONITOR_PID" ]]; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
        MONITOR_PID=""
    fi
    if [[ -n "$MONITOR_FILE" && -f "$MONITOR_FILE" ]]; then
        CURRENT_CPU_PCT_AVG=$(average_column_or_null "$MONITOR_FILE" 2)
        CURRENT_RSS_MB_PEAK=$(peak_rss_mb_or_null "$MONITOR_FILE")
        rm -f "$MONITOR_FILE"
        MONITOR_FILE=""
    fi
}

TOOL=$(detect_tool "$PREFERRED_TOOL")
echo "Using tool: $TOOL"

# ── Result accumulator ────────────────────────────────────────────────────────
RESULTS_JSON="{}"
TOOL_HEADERS=()
add_result() {
    local scenario="$1" rps="$2" p50_ms="$3" p95_ms="$4" p99_ms="$5" p999_ms="$6" errors="$7" mbps="${8:-null}" cpu_pct_avg="${9:-null}" rss_mb_peak="${10:-null}"
    RESULTS_JSON=$(jq --arg s "$scenario" \
        --argjson rps "$rps" \
        --argjson p50 "$p50_ms" --argjson p95 "$p95_ms" --argjson p99 "$p99_ms" --argjson p999 "$p999_ms" \
        --argjson err "$errors" --argjson mbps "$mbps" --argjson cpu "$cpu_pct_avg" --argjson rss "$rss_mb_peak" \
        '.[$s] = {
            rps: $rps,
            p50_ms: $p50,
            p95_ms: $p95,
            p99_ms: $p99,
            p999_ms: $p999,
            errors: $err,
            throughput_mbps: $mbps,
            cpu_pct_avg: $cpu,
            rss_mb_peak: $rss
        }' \
        <<<"$RESULTS_JSON")
}

build_tool_headers() {
    local opt="$1"
    TOOL_HEADERS=()
    [[ ${#REQUEST_HEADERS[@]} -eq 0 ]] && return 0
    local header
    for header in "${REQUEST_HEADERS[@]}"; do
        TOOL_HEADERS+=("$opt" "$header")
    done
}

# ── wrk runner ────────────────────────────────────────────────────────────────
run_wrk() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(--insecure)
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    local raw summary_json
    start_process_monitor
    raw=$(wrk --latency -s "$(dirname "$0")/wrk-summary.lua" -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" \
        ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
    stop_process_monitor
    local rps p50 p95 p99 p999 errors
    summary_json=$(printf '%s\n' "$raw" | sed -n 's/^WRK_SUMMARY //p' | tail -1)
    if [[ -z "$summary_json" ]]; then
        echo "wrk summary hook did not emit percentile JSON" >&2
        echo "$raw" >&2
        exit 1
    fi
    rps=$(echo "$summary_json" | jq -r '.rps // 0')
    p50=$(echo "$summary_json" | jq -r '.p50_ms // null')
    p95=$(echo "$summary_json" | jq -r '.p95_ms // null')
    p99=$(echo "$summary_json" | jq -r '.p99_ms // null')
    p999=$(echo "$summary_json" | jq -r '.p999_ms // null')
    errors=$(echo "$raw" | grep -E "Non-2xx|Socket errors" | grep -oE '[0-9]+' | head -1 || echo 0)
    rps=${rps:-0}; errors=${errors:-0}
    local tput_mbps
    tput_mbps=$(echo "$summary_json" | jq -r '.throughput_mbps // null')
    tput_mbps="${tput_mbps:-null}"
    local tput_display=""
    local cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── h2load runner ─────────────────────────────────────────────────────────────
run_h2load() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(--insecure)
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    local raw
    start_process_monitor
    raw=$(h2load -n $((CONNECTIONS * DURATION * 10)) \
        -c "$CONNECTIONS" -t "$THREADS" ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
    stop_process_monitor
    local rps p50 p95 p99 p999 errors
    rps=$(echo "$raw" | grep -E "^finished" | grep -oE '[0-9.]+ req/s' | grep -oE '[0-9.]+' || echo 0)
    p50=$(extract_h2load_percentile_ms "$raw" "50")
    p95=$(extract_h2load_percentile_ms "$raw" "95")
    p99=$(extract_h2load_percentile_ms "$raw" "99")
    p999=$(extract_h2load_percentile_ms "$raw" "99.9")
    errors=$(echo "$raw" | grep -E "failed" | grep -oE '[0-9]+' | head -1 || echo 0)
    rps=${rps:-0}; errors=${errors:-0}
    local tput_mbps
    tput_mbps=$(echo "$raw" | grep -E "^finished" | grep -oE '[0-9.]+[KMG]B/s' | awk '{
        v=$1
        if (v ~ /GB\/s$/) { sub(/GB\/s$/, "", v); printf "%.2f", v*1024; exit }
        if (v ~ /MB\/s$/) { sub(/MB\/s$/, "", v); printf "%.2f", v; exit }
        if (v ~ /KB\/s$/) { sub(/KB\/s$/, "", v); printf "%.2f", v/1024; exit }
    }')
    tput_mbps="${tput_mbps:-null}"
    local tput_display="" cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── h2load HTTP/3 runner ──────────────────────────────────────────────────────
# Requires h2load built with QUIC/nghttp3+ngtcp2 support.
# If --h3 is unknown to this h2load build, the scenario is silently skipped.
run_h2load_h3() {
    local url="$1" label="$2"
    if ! h2load --h3 --help &>/dev/null 2>&1; then
        echo "  Skipping $label — h2load on this system does not support --h3 (HTTP/3)"
        return
    fi
    if ! $USE_TLS; then
        echo "  Skipping $label — HTTP/3 requires TLS; re-run with --tls"
        return
    fi
    local extra=()
    $INSECURE && extra+=(--insecure)
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    local raw
    start_process_monitor
    raw=$(h2load --h3 -n $((CONNECTIONS * DURATION * 10)) \
        -c "$CONNECTIONS" -t "$THREADS" ${extra[@]+"${extra[@]}"} "$url" 2>&1) || true
    stop_process_monitor
    local rps p50 p95 p99 p999 errors
    rps=$(echo "$raw" | grep -E "^finished" | grep -oE '[0-9.]+ req/s' | grep -oE '[0-9.]+' || echo 0)
    p50=$(extract_h2load_percentile_ms "$raw" "50")
    p95=$(extract_h2load_percentile_ms "$raw" "95")
    p99=$(extract_h2load_percentile_ms "$raw" "99")
    p999=$(extract_h2load_percentile_ms "$raw" "99.9")
    errors=$(echo "$raw" | grep -E "failed" | grep -oE '[0-9]+' | head -1 || echo 0)
    rps=${rps:-0}; errors=${errors:-0}
    local tput_mbps
    tput_mbps=$(echo "$raw" | grep -E "^finished" | grep -oE '[0-9.]+[KMG]B/s' | awk '{
        v=$1
        if (v ~ /GB\/s$/) { sub(/GB\/s$/, "", v); printf "%.2f", v*1024; exit }
        if (v ~ /MB\/s$/) { sub(/MB\/s$/, "", v); printf "%.2f", v; exit }
        if (v ~ /KB\/s$/) { sub(/KB\/s$/, "", v); printf "%.2f", v/1024; exit }
    }')
    tput_mbps="${tput_mbps:-null}"
    local tput_display="" cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── fortio runner ─────────────────────────────────────────────────────────────
run_fortio() {
    local url="$1" label="$2"
    local extra=()
    $INSECURE && extra+=(-insecure)
    build_tool_headers -H
    [[ ${#TOOL_HEADERS[@]} -gt 0 ]] && extra+=("${TOOL_HEADERS[@]}")
    local raw
    start_process_monitor
    raw=$(fortio load -c "$CONNECTIONS" -t "${DURATION}s" \
        -json /dev/stdout ${extra[@]+"${extra[@]}"} "$url" 2>/dev/null) || true
    stop_process_monitor
    local rps p50 p95 p99 p999 errors
    rps=$(echo "$raw" | jq -r '.ActualQPS // 0')
    p50=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==50) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    p95=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==95) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    p99=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==99) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    p999=$(echo "$raw" | jq -r '((.DurationHistogram.Percentiles[] | select(.Percentile==99.9) | .Value) // empty)' | awk 'NF {printf "%.3f", $1*1000}' || true)
    errors=$(echo "$raw" | jq -r '(.ErrorsDurationHistogram.Count // 0)')
    p50=${p50:-null}; p95=${p95:-null}; p99=${p99:-null}; p999=${p999:-null}
    rps=${rps:-0}; errors=${errors:-0}
    local cpu_display="" rss_display=""
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "null" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── k6 summary parser ────────────────────────────────────────────────────────
# Parses a k6 --summary-export JSON file (v1.x flat format) and calls add_result.
_k6_parse_summary() {
    local tmpfile="$1" label="$2"
    local rps p50 p95 p99 p999 errors
    # k6 v1.x: metrics are flat objects — .rate/.count/.med/.["p(99)"] directly
    rps=$(jq -r '.metrics.http_reqs.rate // 0' "$tmpfile" | awk '{printf "%.0f", $1}')
    p50=$(jq -r '(.metrics.http_req_duration.med // null)' "$tmpfile")
    p95=$(jq -r '(.metrics.http_req_duration["p(95)"] // null)' "$tmpfile")
    p99=$(jq -r '(.metrics.http_req_duration["p(99)"] // null)' "$tmpfile")
    p999=$(jq -r '(.metrics.http_req_duration["p(99.9)"] // null)' "$tmpfile")
    # passes = count of http_req_failed=1 samples (i.e. actual failed requests)
    errors=$(jq -r '.metrics.http_req_failed.passes // 0' "$tmpfile")
    rps=${rps:-0}; p50=${p50:-null}; p95=${p95:-null}; p99=${p99:-null}; p999=${p999:-null}; errors=${errors:-0}
    local dr_rate tput_mbps
    dr_rate=$(jq -r '.metrics.data_received.rate // 0' "$tmpfile" 2>/dev/null || echo 0)
    tput_mbps=$(awk -v r="${dr_rate:-0}" 'BEGIN { if (r > 0) printf "%.2f", r/1048576; else print "null" }')
    local tput_display="" cpu_display="" rss_display=""
    [[ "$tput_mbps" != "null" ]] && tput_display="  throughput=${tput_mbps}MB/s"
    [[ "$CURRENT_CPU_PCT_AVG" != "null" ]] && cpu_display="  cpu=${CURRENT_CPU_PCT_AVG}%"
    [[ "$CURRENT_RSS_MB_PEAK" != "null" ]] && rss_display="  rss_peak=${CURRENT_RSS_MB_PEAK}MiB"
    echo "  $label — ${rps} req/s  p50=${p50}ms  p95=${p95}ms  p99=${p99}ms  p999=${p999}ms  errors=${errors}${tput_display}${cpu_display}${rss_display}"
    add_result "$label" "$rps" "$p50" "$p95" "$p99" "$p999" "$errors" "$tput_mbps" "$CURRENT_CPU_PCT_AVG" "$CURRENT_RSS_MB_PEAK"
}

# ── k6 throughput runner ──────────────────────────────────────────────────────
run_k6() {
    local url="$1" label="$2"
    local tmpfile; tmpfile=$(mktemp /tmp/k6-summary-XXXX.json)
    local extra_flags=()
    $INSECURE && extra_flags+=(--insecure-skip-tls-verify)

    local base_url="$BASE_URL"
    local target_path="${url#"$BASE_URL"}"

    start_process_monitor
    BASE_URL="$base_url" \
    K6_TARGET_PATH="$target_path" \
    K6_HOST_HEADER="$HOST_HEADER" \
    K6_VUS="$CONNECTIONS" \
    K6_DURATION="${DURATION}s" \
        k6 run --no-color --quiet \
            --summary-export "$tmpfile" \
            ${extra_flags[@]+"${extra_flags[@]}"} \
            "$(dirname "$0")/scenarios/throughput.js" 2>/dev/null || true
    stop_process_monitor

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

    start_process_monitor
    BASE_URL="${SCHEME}://${TARGET_HOST}:${TARGET_PORT}" \
        K6_HOST_HEADER="$HOST_HEADER" \
        k6 run --no-color --quiet \
            --summary-export "$tmpfile" \
            ${extra_flags[@]+"${extra_flags[@]}"} \
            "$@" \
            "$(dirname "$0")/scenarios/${script}.js" 2>/dev/null || true
    stop_process_monitor

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
    echo "==> static-http1: static file serving over HTTP/1.1 (${STATIC_PATH})"
    run_scenario "${BASE_URL}${STATIC_PATH}" "static-http1"
}

scenario_proxy_http1() {
    echo "==> proxy-http1: reverse proxy route over HTTP/1.1 (${PROXY_PATH})"
    run_scenario "${BASE_URL}${PROXY_PATH}" "proxy-http1"
}

scenario_proxy_http2() {
    echo "==> proxy-http2: reverse proxy route over HTTP/2 (${PROXY_PATH})"
    if [[ "$TOOL" != "h2load" ]]; then
        echo "  Skipping — HTTP/2 scenario requires h2load"
        return
    fi
    run_h2load "${BASE_URL}${PROXY_PATH}" "proxy-http2"
}

scenario_static_http2() {
    echo "==> static-http2: static file serving over HTTP/2 (${H2_PATH})"
    if [[ "$TOOL" == "h2load" ]]; then
        run_h2load "${BASE_URL}${H2_PATH}" "static-http2"
    elif [[ "$TOOL" == "k6" ]] && $USE_TLS; then
        # k6 negotiates HTTP/2 automatically over HTTPS
        run_k6 "${BASE_URL}${H2_PATH}" "static-http2"
    else
        echo "  Skipping — static-http2 requires h2load or k6 with --tls"
    fi
}

scenario_static_http3() {
    echo "==> static-http3: static file serving over HTTP/3 (${H3_PATH})"
    if [[ "$TOOL" == "h2load" ]]; then
        run_h2load_h3 "${BASE_URL}${H3_PATH}" "static-http3"
    else
        echo "  Skipping — static-http3 requires h2load with HTTP/3 (QUIC) support"
    fi
}

scenario_proxy_http3() {
    echo "==> proxy-http3: reverse proxy route over HTTP/3 (${PROXY_PATH})"
    if [[ "$TOOL" == "h2load" ]]; then
        run_h2load_h3 "${BASE_URL}${PROXY_PATH}" "proxy-http3"
    else
        echo "  Skipping — proxy-http3 requires h2load with HTTP/3 (QUIC) support"
    fi
}

scenario_keepalive() {
    echo "==> keepalive: keep-alive connection reuse (${KEEPALIVE_PATH})"
    run_scenario "${BASE_URL}${KEEPALIVE_PATH}" "keepalive"
}

scenario_proxy_payload_64k() {
    echo "==> proxy-payload-64k: reverse proxy 64 KiB payload (${PROXY_PAYLOAD_64K_PATH})"
    run_scenario "${BASE_URL}${PROXY_PAYLOAD_64K_PATH}" "proxy-payload-64k"
}

scenario_proxy_payload_256k() {
    echo "==> proxy-payload-256k: reverse proxy 256 KiB payload (${PROXY_PAYLOAD_256K_PATH})"
    run_scenario "${BASE_URL}${PROXY_PAYLOAD_256K_PATH}" "proxy-payload-256k"
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
    echo "==> reload-under-load: SIGHUP during load (${STATIC_PATH})"
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
    run_wrk "${BASE_URL}${STATIC_PATH}" "reload-under-load"
    wait 2>/dev/null || true
}

# ── Main loop ─────────────────────────────────────────────────────────────────
echo "Tardigrade benchmark — target: ${BASE_URL}  tool: ${TOOL}"
echo "Duration: ${DURATION}s  Connections: ${CONNECTIONS}  Threads: ${THREADS}"
echo "Paths: static=${STATIC_PATH} proxy=${PROXY_PATH} keepalive=${KEEPALIVE_PATH} proxy64k=${PROXY_PAYLOAD_64K_PATH} proxy256k=${PROXY_PAYLOAD_256K_PATH} h2=${H2_PATH} h3=${H3_PATH}"
if [[ -n "$HOST_HEADER" ]]; then
    echo "Host header override: ${HOST_HEADER}"
fi
if [[ -n "$TARGET_PID" || -n "$PID_FILE" ]]; then
    echo "Process sampling: CPU/RSS every ${SAMPLE_INTERVAL_MS}ms"
fi
echo ""

IFS=',' read -ra SCENARIO_LIST <<< "$SCENARIOS"
for scenario in "${SCENARIO_LIST[@]}"; do
    case "$scenario" in
        static-http1)       scenario_static_http1 ;;
        proxy-http1)        scenario_proxy_http1 ;;
        static-http2)       scenario_static_http2 ;;
        proxy-http2)        scenario_proxy_http2 ;;
        static-http3)       scenario_static_http3 ;;
        proxy-http3)        scenario_proxy_http3 ;;
        keepalive)          scenario_keepalive ;;
        proxy-payload-64k)  scenario_proxy_payload_64k ;;
        proxy-payload-256k) scenario_proxy_payload_256k ;;
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
ZIG_VERSION=$(detect_zig_version)
OS_NAME=$(detect_os_name)
KERNEL_RELEASE=$(detect_kernel_release)
ARCH_NAME=$(detect_arch)
CPU_MODEL=$(detect_cpu_model)
CPU_THREADS=$(detect_cpu_threads)
MEMORY_MB=$(detect_memory_mb)
RESULTS_JSON=$(jq \
    --arg tag "$GIT_TAG" --arg ts "$TIMESTAMP" \
    --arg host "$TARGET_HOST" --arg port "$TARGET_PORT" \
    --arg host_header "$HOST_HEADER" \
    --arg driver "$DRIVER_LABEL" \
    --arg worker_count "$WORKER_COUNT" \
    --arg config_label "$CONFIG_LABEL" \
    --arg pid_source "$(if [[ -n "$TARGET_PID" ]]; then echo pid; elif [[ -n "$PID_FILE" ]]; then echo pid-file; else echo none; fi)" \
    --arg static_path "$STATIC_PATH" --arg proxy_path "$PROXY_PATH" \
    --arg keepalive_path "$KEEPALIVE_PATH" \
    --arg h2_path "$H2_PATH" --arg h3_path "$H3_PATH" \
    --arg tool "$TOOL" \
    --arg zig_version "$ZIG_VERSION" \
    --arg os_name "$OS_NAME" \
    --arg kernel_release "$KERNEL_RELEASE" \
    --arg arch_name "$ARCH_NAME" \
    --arg cpu_model "$CPU_MODEL" \
    --arg cpu_threads "$CPU_THREADS" \
    --arg memory_mb "$MEMORY_MB" \
    --argjson dur "$DURATION" --argjson conn "$CONNECTIONS" --argjson sample_interval_ms "$SAMPLE_INTERVAL_MS" \
    '. + {_meta: {tag: $tag, timestamp: $ts, host: $host, port: $port,
          tool: $tool, duration_s: $dur, connections: $conn,
          host_header: $host_header, driver: $driver,
          worker_count: (if $worker_count == "" then null else ($worker_count | tonumber) end),
          config_label: (if $config_label == "" then null else $config_label end),
          process_metrics: {
            enabled: ($pid_source != "none"),
            pid_source: $pid_source,
            sample_interval_ms: $sample_interval_ms
          },
          zig_version: $zig_version,
          environment: {
            os: $os_name,
            kernel: $kernel_release,
            arch: $arch_name,
            cpu_model: $cpu_model,
            cpu_threads: $cpu_threads,
            memory_mb: $memory_mb
          },
          static_path: $static_path,
          proxy_path: $proxy_path, keepalive_path: $keepalive_path,
          h2_path: $h2_path, h3_path: $h3_path}}' \
    <<<"$RESULTS_JSON")

if [[ -n "$META_FILE" ]]; then
    if [[ ! -f "$META_FILE" ]]; then
        echo "Metadata file not found: $META_FILE" >&2
        exit 1
    fi
    RESULTS_JSON=$(jq --slurpfile meta "$META_FILE" '._meta += ($meta[0] // {})' <<<"$RESULTS_JSON")
fi

# ── Save ─────────────────────────────────────────────────────────────────────
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
    compare_metric() {
        local scenario="$1" metric="$2" path="$3" direction="$4"
        local baseline_value current_value delta status
        baseline_value=$(jq -r --arg s "$scenario" "$path // null" "$BASELINE_FILE")
        current_value=$(echo "$RESULTS_JSON" | jq -r --arg s "$scenario" "$path // null")
        if [[ "$baseline_value" == "null" || "$current_value" == "null" || "$baseline_value" == "0" ]]; then
            return 0
        fi
        delta=$(awk -v b="$baseline_value" -v c="$current_value" 'BEGIN { printf "%.1f", (c - b) / b * 100 }')
        status="OK"
        case "$direction" in
            higher)
                if awk -v d="$delta" -v t="$REGRESSION_THRESHOLD" 'BEGIN { exit !(d < -t) }'; then
                    status="REGRESSION"
                    REGRESSION=1
                fi
                ;;
            lower)
                if awk -v d="$delta" -v t="$REGRESSION_THRESHOLD" 'BEGIN { exit !(d > t) }'; then
                    status="REGRESSION"
                    REGRESSION=1
                fi
                ;;
        esac
        echo "  ${scenario}.${metric}: baseline=${baseline_value} current=${current_value} delta=${delta}% [${status}]"
    }
    while IFS= read -r scenario; do
        [[ "$scenario" == _meta ]] && continue
        compare_metric "$scenario" "rps" '.[$s].rps' higher
        compare_metric "$scenario" "p95_ms" '.[$s].p95_ms' lower
        compare_metric "$scenario" "p99_ms" '.[$s].p99_ms' lower
        compare_metric "$scenario" "p999_ms" '.[$s].p999_ms' lower
        compare_metric "$scenario" "cpu_pct_avg" '.[$s].cpu_pct_avg' lower
        compare_metric "$scenario" "rss_mb_peak" '.[$s].rss_mb_peak' lower
    done < <(echo "$RESULTS_JSON" | jq -r 'keys[]')
fi

echo ""
echo "$RESULTS_JSON" | jq .

[[ "$REGRESSION" -eq 0 ]] || exit 2

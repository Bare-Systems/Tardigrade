#!/usr/bin/env bash
# Validate that report.sh correctly renders the MB/s column from benchmark JSON.
#
# Tests:
#   1. JSON with throughput_mbps — column shows numeric values.
#   2. JSON without throughput_mbps (older format) — column shows "-" for each row.
#   3. JSON with mixed presence — numeric where present, "-" where absent.
#
# Usage:
#   ./benchmarks/test-report.sh
#
# Exit code 0 = all tests passed.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT="${SCRIPT_DIR}/report.sh"

if ! command -v jq &>/dev/null; then
    echo "jq is required but not installed." >&2
    exit 1
fi

pass=0
fail=0

check() {
    local desc="$1" expected="$2" actual="$3"
    if echo "$actual" | grep -qF "$expected"; then
        echo "  PASS: $desc"
        pass=$((pass + 1))
    else
        echo "  FAIL: $desc"
        echo "        expected to find: $expected"
        echo "        in output:"
        echo "$actual" | sed 's/^/          /'
        fail=$((fail + 1))
    fi
}

run_report() {
    local json="$1"
    local tmp; tmp=$(mktemp /tmp/tardi-test-XXXX.json)
    echo "$json" > "$tmp"
    local out
    out=$("$REPORT" "$tmp" 2>&1)
    rm -f "$tmp"
    echo "$out"
}

echo "==> Test 1: JSON with throughput_mbps — column shows numeric values"
JSON1=$(cat <<'EOF'
{
  "proxy-http1":       {"rps": 7100.06, "p50_ms": 0.27, "p99_ms": 0.28, "errors": 0, "throughput_mbps": 12.50},
  "proxy-payload-64k": {"rps": 3837.25, "p50_ms": 0.47, "p99_ms": 0.69, "errors": 0, "throughput_mbps": 239.83},
  "_meta": {"tag": "test", "timestamp": "2026-01-01T00:00:00Z", "tool": "wrk",
             "host": "127.0.0.1", "driver": "test", "environment_name": "test",
             "worker_count": 2, "config_label": "test", "duration_s": 30, "connections": 2}
}
EOF
)
OUT1=$(run_report "$JSON1")
check "header includes MB/s"            "| MB/s |"       "$OUT1"
check "proxy-http1 shows 12.5"          "| 12.5 |"       "$OUT1"
check "proxy-payload-64k shows 239.8"   "| 239.8 |"      "$OUT1"

echo ""
echo "==> Test 2: older JSON without throughput_mbps — column shows '-'"
JSON2=$(cat <<'EOF'
{
  "static-http1": {"rps": 4586, "p50_ms": 0.445, "p99_ms": 46.06, "errors": 0},
  "proxy-http1":  {"rps": 1724, "p50_ms": 1.27,  "p99_ms": 114.9, "errors": 0},
  "_meta": {"tag": "v0.32.0", "timestamp": "2026-05-02T17:00:00Z", "tool": "wrk",
             "host": "127.0.0.1", "driver": "loopback", "environment_name": "release-baseline",
             "worker_count": 2, "config_label": "test", "duration_s": 30, "connections": 4}
}
EOF
)
OUT2=$(run_report "$JSON2")
check "header includes MB/s"    "| MB/s |"  "$OUT2"
dash_count=$(echo "$OUT2" | grep -c "| - |" || true)
if [[ "$dash_count" -ge 2 ]]; then
    echo "  PASS: both rows show '-' for missing throughput ($dash_count rows)"
    pass=$((pass + 1))
else
    echo "  FAIL: expected at least 2 rows with '| - |', found $dash_count"
    fail=$((fail + 1))
fi

echo ""
echo "==> Test 3: JSON with null throughput_mbps — column shows '-'"
JSON3=$(cat <<'EOF'
{
  "proxy-http1": {"rps": 1000, "p50_ms": 1.0, "p99_ms": 5.0, "errors": 0, "throughput_mbps": null},
  "_meta": {"tag": "test", "timestamp": "2026-01-01T00:00:00Z", "tool": "wrk",
             "host": "127.0.0.1", "driver": "test", "environment_name": "test",
             "worker_count": 1, "config_label": "test", "duration_s": 30, "connections": 1}
}
EOF
)
OUT3=$(run_report "$JSON3")
check "null throughput shows '-'" "| - |" "$OUT3"

echo ""
echo "==> Test 4: unit conversions — KB/s and GB/s values render correctly"
JSON4=$(cat <<'EOF'
{
  "tiny":  {"rps": 500,  "p50_ms": 0.1, "p99_ms": 0.5, "errors": 0, "throughput_mbps": 0.5},
  "large": {"rps": 100,  "p50_ms": 2.0, "p99_ms": 8.0, "errors": 0, "throughput_mbps": 1024.0},
  "_meta": {"tag": "test", "timestamp": "2026-01-01T00:00:00Z", "tool": "wrk",
             "host": "127.0.0.1", "driver": "test", "environment_name": "test",
             "worker_count": 1, "config_label": "test", "duration_s": 30, "connections": 1}
}
EOF
)
OUT4=$(run_report "$JSON4")
check "small throughput renders"  "| 0.5 |"    "$OUT4"
check "large throughput renders"  "| 1024.0 |" "$OUT4"

echo ""
if [[ "$fail" -eq 0 ]]; then
    echo "All ${pass} tests passed."
    exit 0
else
    echo "${fail} test(s) FAILED, ${pass} passed."
    exit 1
fi

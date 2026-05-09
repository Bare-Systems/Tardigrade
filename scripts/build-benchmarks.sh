#!/usr/bin/env bash
# Tardigrade build-time benchmark script.
#
# Measures clean and incremental build times under Zig 0.16 and documents
# the results for comparison across releases or toolchain upgrades.
#
# Usage:
#   ./scripts/build-benchmarks.sh [OPTIONS]
#
# Options:
#   --zig PATH      Path to Zig binary (default: auto-detect 0.16 install)
#   --save FILE     Append a JSON record to FILE (default: stdout only)
#   --optimize OPT  Build mode: Debug|ReleaseSafe|ReleaseFast (default: ReleaseFast)
#   --help          Show this message
#
# Output:
#   Prints build times for clean and incremental builds.
#   With --save, appends a JSON record to the given file.
#
# Notes:
#   - Run on an idle machine; background I/O significantly inflates numbers.
#   - Clean build times include Zig stdlib compilation on first run; subsequent
#     runs benefit from the global Zig cache (~/.cache/zig).
#   - Incremental build is simulated by touching a single source file.

set -euo pipefail

ZIG=${ZIG:-}
SAVE_FILE=""
OPTIMIZE="ReleaseFast"

# Auto-detect Zig 0.16 installation
if [[ -z "$ZIG" ]]; then
  for candidate in \
    .zig/0.16.0/zig-aarch64-macos-0.16.0/zig \
    .zig/0.16.0/zig-x86_64-linux-0.16.0/zig \
    .zig/0.16.0/zig-aarch64-linux-0.16.0/zig \
    "$(command -v zig 2>/dev/null || true)"; do
    if [[ -n "$candidate" && -x "$candidate" ]]; then
      ZIG="$candidate"
      break
    fi
  done
fi

if [[ -z "$ZIG" ]]; then
  echo "Error: Zig not found. Set ZIG=/path/to/zig or run scripts/install-zig.sh 0.16.0" >&2
  exit 1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --zig)      ZIG="$2"; shift 2 ;;
    --save)     SAVE_FILE="$2"; shift 2 ;;
    --optimize) OPTIMIZE="$2"; shift 2 ;;
    --help|-h)
      grep '^#' "$0" | head -30 | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown option: $1"; exit 1 ;;
  esac
done

ZIG_VERSION=$("$ZIG" version 2>/dev/null || echo "unknown")
OS_NAME=$(uname -s)
ARCH_NAME=$(uname -m)
GIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown")
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

echo "=== Tardigrade Build Benchmarks ==="
echo "Zig:      $ZIG_VERSION ($ZIG)"
echo "Platform: $OS_NAME / $ARCH_NAME"
echo "Commit:   $GIT_SHA"
echo "Optimize: $OPTIMIZE"
echo ""

time_cmd() {
  local label="$1"
  shift
  local start
  start=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
  "$@"
  local end
  end=$(date +%s%N 2>/dev/null || python3 -c "import time; print(int(time.time()*1e9))")
  local elapsed_ms=$(( (end - start) / 1000000 ))
  echo "${label}: ${elapsed_ms} ms"
  echo "$elapsed_ms"
}

# ── Clean build ────────────────────────────────────────────────────────────────
echo "--- Clean build (-Doptimize=$OPTIMIZE) ---"
"$ZIG" build --summary none 2>/dev/null || true  # warm Zig cache
rm -rf zig-out

CLEAN_MS=$(time_cmd "Clean build" "$ZIG" build -Doptimize="$OPTIMIZE" --summary none 2>&1 | tail -1)
CLEAN_MS=$(echo "$CLEAN_MS" | grep -Eo '[0-9]+$' || echo 0)
echo "Clean build time: ${CLEAN_MS} ms"
echo ""

# ── Incremental build (single-file touch) ────────────────────────────────────
echo "--- Incremental build (touch src/http/metrics.zig) ---"
touch src/http/metrics.zig
INC_MS=$(time_cmd "Incremental build" "$ZIG" build -Doptimize="$OPTIMIZE" --summary none 2>&1 | tail -1)
INC_MS=$(echo "$INC_MS" | grep -Eo '[0-9]+$' || echo 0)
echo "Incremental build time: ${INC_MS} ms"
echo ""

# ── Test build ────────────────────────────────────────────────────────────────
echo "--- Test build (Debug, unit tests) ---"
TEST_MS=$(time_cmd "Test build" "$ZIG" build test --summary none 2>&1 | tail -1)
TEST_MS=$(echo "$TEST_MS" | grep -Eo '[0-9]+$' || echo 0)
echo "Test build time: ${TEST_MS} ms"
echo ""

echo "=== Summary ==="
echo "Clean build (${OPTIMIZE}): ${CLEAN_MS} ms"
echo "Incremental build:         ${INC_MS} ms"
echo "Test build (Debug):        ${TEST_MS} ms"

# ── Optional JSON save ────────────────────────────────────────────────────────
if [[ -n "$SAVE_FILE" ]]; then
  RECORD=$(cat <<JSON
{"timestamp":"${TIMESTAMP}","git_sha":"${GIT_SHA}","zig_version":"${ZIG_VERSION}","os":"${OS_NAME}","arch":"${ARCH_NAME}","optimize":"${OPTIMIZE}","clean_build_ms":${CLEAN_MS},"incremental_build_ms":${INC_MS},"test_build_ms":${TEST_MS}}
JSON
)
  echo "$RECORD" >> "$SAVE_FILE"
  echo ""
  echo "Record appended to: $SAVE_FILE"
fi

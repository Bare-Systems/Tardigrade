#!/usr/bin/env bash
# Tardigrade profiling helper.
#
# Builds Tardigrade with profiling-friendly flags and shows how to collect
# CPU and memory profiles using platform-native tools.
#
# Usage:
#   ./scripts/profile.sh [COMMAND]
#
# Commands:
#   build          Build a profiling binary (ReleaseSafe + frame pointers).
#   cpu-linux      Show Linux perf CPU profiling instructions.
#   cpu-macos      Show macOS sample/Instruments instructions.
#   mem-linux      Show Linux heap profiling instructions (Valgrind / heaptrack).
#   mem-macos      Show macOS leaks/Instruments instructions.
#   help           Show this message (default).
#
# Prerequisites:
#   Zig 0.16.0 in PATH (or via .zig/0.16.0/zig-*/zig)
#   Linux:  perf, valgrind, heaptrack (optional)
#   macOS:  sample, Instruments (Xcode), leaks

set -euo pipefail

ZIG=${ZIG:-zig}
if ! command -v "$ZIG" &>/dev/null; then
  for candidate in .zig/0.16.0/zig-*/zig; do
    if [[ -x "$candidate" ]]; then
      ZIG="$candidate"
      break
    fi
  done
fi

PROFILE_BIN="./zig-out/bin/tardi"
COMMAND="${1:-help}"

build_profile() {
  echo "Building Tardigrade with ReleaseSafe and frame pointers..."
  "$ZIG" build \
    -Doptimize=ReleaseSafe \
    --summary all
  echo ""
  echo "Binary: $PROFILE_BIN"
  echo ""
  echo "Note: ReleaseSafe keeps safety checks active while optimising."
  echo "      Use -Doptimize=ReleaseFast for pure throughput profiling,"
  echo "      or -Doptimize=Debug for maximum symbol detail."
}

cpu_linux() {
  cat <<'EOF'
──────────────────────────────────────────────────────────────────
CPU Profiling on Linux (perf)
──────────────────────────────────────────────────────────────────

1. Build a profiling binary:
     ./scripts/profile.sh build

2. Start Tardigrade:
     ./zig-out/bin/tardi run

3. In a second terminal, start the benchmark load:
     ./benchmarks/run.sh --host 127.0.0.1 --port 8069 \
       --duration 60 --connections 100

4. Attach perf while the benchmark is running (replace PID):
     perf record -g -F 997 -p $(pgrep tardi) -- sleep 30
     perf report --no-children

   Or profile the entire run from the start:
     perf record -g -F 997 ./zig-out/bin/tardi run
     perf report --no-children

5. Generate a flamegraph (requires FlameGraph scripts):
     git clone https://github.com/brendangregg/FlameGraph /tmp/fg
     perf script | /tmp/fg/stackcollapse-perf.pl | \
       /tmp/fg/flamegraph.pl > /tmp/tardigrade-flame.svg
     open /tmp/tardigrade-flame.svg

Tips:
  - Add --call-graph=dwarf if frame-pointer unwind does not work.
  - perf top -g -p $(pgrep tardi) for live per-function view.
  - To profile a specific path (e.g. TLS), filter the benchmark to TLS:
      ./benchmarks/run.sh --tls --static-path /health --scenarios static-http1
EOF
}

cpu_macos() {
  cat <<'EOF'
──────────────────────────────────────────────────────────────────
CPU Profiling on macOS (sample / Instruments)
──────────────────────────────────────────────────────────────────

1. Build a profiling binary:
     ./scripts/profile.sh build

2. Start Tardigrade:
     ./zig-out/bin/tardi run &

3. While the benchmark runs, sample the process:
     ./benchmarks/run.sh --duration 60 &
     BPID=$!
     sample tardigrade -wait -file /tmp/tardigrade.sample
     wait $BPID
     open /tmp/tardigrade.sample     # opens in Instruments

   Or use Instruments directly:
     instruments -t "Time Profiler" \
       -D /tmp/tardigrade.trace \
       ./zig-out/bin/tardi run
     open /tmp/tardigrade.trace

4. Inspect the Time Profiler trace for the heaviest call stacks.

Tips:
  - The Allocations instrument shows per-call-site allocation counts and sizes.
  - For server processes, attach by PID in Instruments rather than launching
    from Instruments so the listening socket binds normally.
EOF
}

mem_linux() {
  cat <<'EOF'
──────────────────────────────────────────────────────────────────
Memory / Allocation Profiling on Linux
──────────────────────────────────────────────────────────────────

Option A — Valgrind massif (allocation-heavy path identification):
  valgrind --tool=massif --pages-as-heap=yes \
    ./zig-out/bin/tardi run
  # After exit:
  ms_print massif.out.* | head -100

Option B — heaptrack (lower overhead, live view):
  heaptrack ./zig-out/bin/tardi run
  # Analyse the output:
  heaptrack_gui heaptrack.tardigrade.*.gz

Option C — Zig Debug build + ASAN (AddressSanitizer):
  # Rebuild in Debug mode for maximum allocation detail:
  zig build -Doptimize=Debug
  # Run under ASAN (requires clang/GCC asan runtime):
  ASAN_OPTIONS=detect_leaks=1 ./zig-out/bin/tardi run

Tips:
  - Valgrind slows the process ~30×; use a low-concurrency benchmark.
  - heaptrack overhead is ~2×; suitable for moderate loads.
  - A Debug build without heap tools is sufficient to detect safety panics.
EOF
}

mem_macos() {
  cat <<'EOF'
──────────────────────────────────────────────────────────────────
Memory / Allocation Profiling on macOS
──────────────────────────────────────────────────────────────────

Option A — leaks command (post-mortem):
  ./zig-out/bin/tardi run &
  PID=$!
  ./benchmarks/run.sh --duration 30
  leaks $PID
  kill $PID

Option B — Instruments Allocations instrument:
  instruments -t "Allocations" \
    -D /tmp/tardigrade-alloc.trace \
    ./zig-out/bin/tardi run
  open /tmp/tardigrade-alloc.trace
  # Filter by "Generation" to find long-lived allocations.

Option C — Instruments Leaks instrument:
  instruments -t "Leaks" \
    -D /tmp/tardigrade-leaks.trace \
    ./zig-out/bin/tardi run
  open /tmp/tardigrade-leaks.trace

Tips:
  - Instruments "VM Tracker" shows virtual memory growth over time.
  - Enable "Record reference counts" in Allocations for ownership tracing.
EOF
}

case "$COMMAND" in
  build)      build_profile ;;
  cpu-linux)  cpu_linux ;;
  cpu-macos)  cpu_macos ;;
  mem-linux)  mem_linux ;;
  mem-macos)  mem_macos ;;
  help|--help|-h)
    grep '^#' "$0" | head -20 | sed 's/^# \{0,1\}//'
    ;;
  *)
    echo "Unknown command: $COMMAND"
    echo "Run '$0 help' for usage."
    exit 1
    ;;
esac

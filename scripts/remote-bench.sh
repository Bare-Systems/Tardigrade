#!/usr/bin/env bash
# Build the current checkout on a remote Linux host and run the keepalive-parking
# (#138) perf benchmark there. Results are printed locally.
#
# Usage:
#   export BENCH_SSH_TARGET=user@host        # required: any ssh target you control
#   bash scripts/remote-bench.sh
#
# Optional environment variables:
#   BENCH_ZIG            path to a Zig 0.16 binary on the remote (default: `zig` on PATH)
#   BENCH_FRONT_PORT     test listener port              (default: 18069)
#   BENCH_UPSTREAM_PORT  test proxy-upstream port        (default: 18080)
#   BENCH_DURATION       seconds per wrk run             (default: 10)
#   BENCH_REPO           local repo to benchmark         (default: this checkout)
#
# The benchmark only uses the two test ports above and tears its instances down
# afterward; it does not touch any other service on the host. The remote host
# must have a Zig 0.16 toolchain and `wrk` (the script tries `apt-get` if missing).

set -euo pipefail

TARGET="${BENCH_SSH_TARGET:?Set BENCH_SSH_TARGET to your ssh host, e.g. export BENCH_SSH_TARGET=user@host}"
ZIG="${BENCH_ZIG:-zig}"
FRONT_PORT="${BENCH_FRONT_PORT:-18069}"
UP_PORT="${BENCH_UPSTREAM_PORT:-18080}"
DURATION="${BENCH_DURATION:-10}"
REPO="${BENCH_REPO:-$(cd "$(dirname "$0")/.." && pwd)}"
REMOTE_DIR="/tmp/tardigrade-bench"

echo "[1/4] packaging source from $REPO ($(git -C "$REPO" rev-parse --short HEAD 2>/dev/null || echo 'no-git'))"
tar -C "$REPO" -czf /tmp/tardigrade-bench-src.tgz \
  --exclude=.git --exclude=.zig-cache --exclude=.zig --exclude=.zig-toolchain \
  --exclude=zig-out --exclude=dist --exclude='*.tgz' .

echo "[2/4] uploading to $TARGET"
ssh "$TARGET" "rm -rf $REMOTE_DIR && mkdir -p $REMOTE_DIR"
scp -q /tmp/tardigrade-bench-src.tgz "$TARGET:$REMOTE_DIR/src.tgz"

echo "[3/4] building (ReleaseFast) on $TARGET"
ssh "$TARGET" "ZIG='$ZIG' REMOTE_DIR='$REMOTE_DIR' bash -s" <<'REMOTE'
set -e
cd "$REMOTE_DIR" && tar -xzf src.tgz
"$ZIG" version >/dev/null 2>&1 || { echo "Zig not found at '$ZIG' — set BENCH_ZIG to a Zig 0.16 binary"; exit 1; }
case "$("$ZIG" version)" in 0.16.*) ;; *) echo "warning: Zig $("$ZIG" version) is not 0.16.x; build may fail";; esac
if ! command -v wrk >/dev/null 2>&1; then
  command -v apt-get >/dev/null 2>&1 && sudo apt-get install -y wrk >/dev/null 2>&1 || true
fi
command -v wrk >/dev/null 2>&1 || { echo "wrk not found and could not be installed; please install wrk on the remote"; exit 1; }
"$ZIG" build -Doptimize=ReleaseFast 2>&1 | tail -2
test -x "$REMOTE_DIR/zig-out/bin/tardigrade" || { echo "BUILD FAILED"; exit 1; }
echo "  built OK"
REMOTE

echo "[4/4] running benchmark on $TARGET"
ssh "$TARGET" "REMOTE_DIR='$REMOTE_DIR' FRONT_PORT='$FRONT_PORT' UP_PORT='$UP_PORT' DURATION='$DURATION' bash -s" <<'REMOTE'
set -e
BIN="$REMOTE_DIR/zig-out/bin/tardigrade"
D="$REMOTE_DIR/run"; mkdir -p "$D"
printf 'pid %s/up.pid;\nlisten %s;\nlocation = /health {\n    return 200 ok;\n}\n' "$D" "$UP_PORT" > "$D/up.conf"
printf 'pid %s/fr.pid;\nlisten %s;\nlocation = /health {\n    return 200 ok;\n}\nlocation = /proxy/health {\n    proxy_pass http://127.0.0.1:%s/health;\n}\n' "$D" "$FRONT_PORT" "$UP_PORT" > "$D/fr.conf"

start() { # $1=worker_threads (0 = default to CPU count)
  pkill -f "tardigrade run -c $D" 2>/dev/null || true; sleep 1
  TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_WORKER_THREADS="$1" setsid "$BIN" run -c "$D/up.conf" >/dev/null 2>&1 </dev/null &
  TARDIGRADE_RATE_LIMIT_RPS=0 TARDIGRADE_WORKER_THREADS="$1" setsid "$BIN" run -c "$D/fr.conf" >/dev/null 2>&1 </dev/null &
  for i in $(seq 1 40); do curl -fsS "http://127.0.0.1:$FRONT_PORT/health" >/dev/null 2>&1 && break; sleep 0.2; done
}
bench() { # $1=path $2=conns $3=threads $4=label
  wrk -t"$3" -c"$2" -d"${DURATION}s" --latency "http://127.0.0.1:$FRONT_PORT$1" 2>/dev/null | awk -v L="$4" '
    / 50%/{p50=$2} / 90%/{p90=$2} / 99%/{p99=$2} /Requests\/sec/{r=$2}
    END{printf "  %-18s p50=%-9s p90=%-9s p99=%-9s rps=%s\n",L,p50,p90,p99,r}'
}

echo ""
echo "=== $(nproc) cores, $(uname -srm), load$(uptime | sed 's/.*load average//') ==="
echo "--- worker_threads = CPU count (default). Keepalive parking should hold the tail as connections >> workers ---"
start 0
bench /health 10 2 "static c10"
bench /health 50 4 "static c50"
bench /health 100 4 "static c100"
bench /proxy/health 10 2 "proxy  c10"
echo "  parked metrics: $(curl -s "http://127.0.0.1:$FRONT_PORT/status/metrics" | grep -E '^tardigrade_keepalive_(parked|resumes)' | tr '\n' ' ')"
pkill -f "tardigrade run -c $D" 2>/dev/null || true
echo ""
echo "Done (test instances on ports $FRONT_PORT/$UP_PORT torn down)."
REMOTE
echo "DONE"

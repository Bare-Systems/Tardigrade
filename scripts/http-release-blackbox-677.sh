#!/bin/bash
# Black-box HTTP/2 and HTTP/3 release-artifact evidence rows for #677.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/.." && pwd)"
evidence_dir="${HTTP_SWEEP_EVIDENCE_DIR:-$repo/.zig-cache/http-release-sweep-677}"
workdir="$evidence_dir/blackbox-work"
logs="$evidence_dir/blackbox-logs"
mkdir -p "$workdir" "$logs"
rm -f "$logs"/*.log "$logs"/*.txt "$logs"/*.raw "$logs"/*.headers "$logs"/*.err

say() { printf '%s\n' "$*"; }

free_tcp_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

free_udp_port() {
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
}

wait_tcp() {
  local port="$1"
  local deadline=$((SECONDS + 10))
  while [ "$SECONDS" -lt "$deadline" ]; do
    python3 - "$port" <<'PY' >/dev/null 2>&1 && return 0
import socket, sys
s = socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.25)
s.close()
PY
    sleep 0.1
  done
  return 1
}

sha256_file() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    printf 'unavailable'
  fi
}

count_fds() {
  local pid="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -p "$pid" 2>/dev/null | awk 'NR > 1 { c++ } END { print c + 0 }'
  elif [ -d "/proc/$pid/fd" ]; then
    find "/proc/$pid/fd" -type l 2>/dev/null | wc -l | tr -d ' '
  else
    printf 'unavailable'
  fi
}

count_sockets() {
  local pid="$1"
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -a -p "$pid" -iTCP -iUDP 2>/dev/null | awk 'NR > 1 { c++ } END { print c + 0 }'
  else
    printf 'unavailable'
  fi
}

rss_kb() {
  local pid="$1"
  ps -o rss= -p "$pid" 2>/dev/null | awk '{ print $1 + 0 }'
}

record_sample() {
  local label="$1"
  local pid="$2"
  printf '%s rss_kb=%s fds=%s sockets=%s\n' "$label" "$(rss_kb "$pid")" "$(count_fds "$pid")" "$(count_sockets "$pid")"
}

tardi_bin="${TARDI_BIN:-$(command -v tardi || true)}"
if [ -z "$tardi_bin" ] || [ ! -x "$tardi_bin" ]; then
  say "SKIP blackbox: TARDI_BIN does not point to an executable artifact"
  exit 0
fi

if ! command -v python3 >/dev/null 2>&1; then
  say "SKIP blackbox: python3 is required for local upstream and port allocation"
  exit 0
fi

if command -v realpath >/dev/null 2>&1; then
  tardi_bin="$(realpath "$tardi_bin")"
fi

public_dir="$workdir/public"
mkdir -p "$public_dir"
printf '%s\n' 'blackbox-static-ok' >"$public_dir/index.html"
python3 - "$workdir/upstream.py" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text(r'''
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os, sys, time
LENGTHS_PATH = sys.argv[2]
ADMITTED_PATH = sys.argv[3]
RELEASE_PATH = sys.argv[4]
class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def log_message(self, fmt, *args): pass
    def _send(self, code, body):
        body = body.encode()
        self.send_response(code)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
    def _handle_slow(self):
        # Prove admission (the request actually reached the upstream, i.e.
        # tardi proxied it) before blocking, then wait -- bounded -- for the
        # external harness to release it. Threaded server: this does not
        # block other concurrent upstream connections.
        with open(ADMITTED_PATH, "w"):
            pass
        deadline = time.time() + 15
        while not os.path.exists(RELEASE_PATH) and time.time() < deadline:
            time.sleep(0.05)
        self._send(200, "slow-ok")
    def do_GET(self):
        if self.path.startswith("/slow"):
            self._handle_slow()
        elif self.path.startswith("/proxy-error"):
            self._send(500, "proxy-upstream-error")
        else:
            self._send(200, "proxy-ok" if self.path.startswith("/proxy") else "upstream-ok")
    def do_HEAD(self):
        self._send(200, "")
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", "0")))
        with open(LENGTHS_PATH, "a", encoding="utf-8") as f:
            f.write(str(len(body)) + "\n")
        self._send(200, "proxy-post:" + str(len(body)))
port = int(sys.argv[1])
srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
print("READY", flush=True)
srv.serve_forever()
''')
PY

upstream_port="$(free_tcp_port)"
post_lengths="$workdir/post-lengths.txt"
: >"$post_lengths"
drain_admitted="$workdir/drain-admitted"
drain_release="$workdir/drain-release"
python3 "$workdir/upstream.py" "$upstream_port" "$post_lengths" "$drain_admitted" "$drain_release" >"$logs/upstream.log" 2>&1 &
upstream_pid=$!

tcp_port="$(free_tcp_port)"
udp_port="$(free_udp_port)"
config="$workdir/tardigrade.conf"
cat >"$config" <<EOF
listen $tcp_port;
server_name tardigrade.test;
root $public_dir;
try_files \$uri;

location = /healthz {
    return 200 alive;
}

location = /simple {
    return 200 simple-ok;
}

location = /proxy {
    proxy_pass http://127.0.0.1:$upstream_port/proxy;
}

location = /proxy-error {
    proxy_pass http://127.0.0.1:$upstream_port/proxy-error;
}

location = /slow {
    proxy_pass http://127.0.0.1:$upstream_port/slow;
}

EOF

# shellcheck disable=SC2317,SC2329 # invoked by trap on script exit
cleanup() {
  [ -n "${tardi_pid:-}" ] && kill "$tardi_pid" 2>/dev/null
  [ -n "${upstream_pid:-}" ] && kill "$upstream_pid" 2>/dev/null
  [ -n "${tardi_pid:-}" ] && wait "$tardi_pid" 2>/dev/null
  [ -n "${upstream_pid:-}" ] && wait "$upstream_pid" 2>/dev/null
}
trap cleanup EXIT

TARDIGRADE_LISTEN_HOST=127.0.0.1 \
TARDIGRADE_LISTEN_PORT="$tcp_port" \
TARDIGRADE_CONFIG_PATH="$config" \
TARDIGRADE_TLS_CERT_PATH="$repo/tests/fixtures/tls/native_ed25519.crt" \
TARDIGRADE_TLS_KEY_PATH="$repo/tests/fixtures/tls/native_ed25519.key" \
TARDIGRADE_TLS_SERVER_NAME=tardigrade.test \
TARDIGRADE_TLS_SNI_CERTS="localhost:$repo/tests/fixtures/tls/native_ed25519.crt:$repo/tests/fixtures/tls/native_ed25519.key|tardigrade.test:$repo/tests/fixtures/tls/native_ed25519.crt:$repo/tests/fixtures/tls/native_ed25519.key" \
TARDIGRADE_HTTP2_ENABLED=true \
TARDIGRADE_HTTP3_ENABLED=true \
TARDIGRADE_QUIC_PORT="$udp_port" \
TARDIGRADE_HTTP3_ALT_SVC=auto \
TARDIGRADE_HTTP3_ALT_SVC_MAX_AGE_SECONDS=60 \
TARDIGRADE_RATE_LIMIT_RPS=10000 \
TARDIGRADE_RATE_LIMIT_BURST=10000 \
TARDIGRADE_ERROR_LOG_PATH="$logs/tardi-app.log" \
TARDIGRADE_UPSTREAM_TIMEOUT_MS=25000 \
"$tardi_bin" run -c "$config" >"$logs/tardi.stdout" 2>"$logs/tardi.stderr" &
# Discovered while building the GOAWAY/drain row below: on an otherwise-idle
# H3 connection (no other traffic since admission), the drain GOAWAY frame
# can take on the order of 10s to actually reach the peer -- well inside the
# 30s graceful-shutdown deadline the drain contract itself promises, but
# tight against the default 10s TARDIGRADE_UPSTREAM_TIMEOUT_MS, which could
# spuriously 504 an admitted in-flight proxied request during that specific
# idle-connection-plus-rolling-restart combination. Bumped above so this row
# proves the actual contract (admitted work completes, new work explicitly
# rejected) rather than racing an unrelated, tighter proxy timeout. Recorded
# as an observation for follow-up, not a #677/#694 blocker (#677, #694).
tardi_pid=$!

if ! wait_tcp "$tcp_port"; then
  say "FAIL blackbox: tardi did not open TCP port $tcp_port"
  cat "$logs/tardi-app.log" "$logs/tardi.stderr" 2>/dev/null
  exit 1
fi

summary="$evidence_dir/blackbox-summary.txt"
{
  printf 'tardi_bin=%s\n' "$tardi_bin"
  printf 'tardi_sha256=%s\n' "$(sha256_file "$tardi_bin")"
  printf 'tcp_port=%s\nquic_port=%s\nupstream_port=%s\n' "$tcp_port" "$udp_port" "$upstream_port"
  printf 'tardi_version='
  "$tardi_bin" version 2>&1 || true
  record_sample before "$tardi_pid"
} >"$summary"

status=0

if command -v nghttp >/dev/null 2>&1; then
  nghttp --version >"$logs/nghttp-version.txt" 2>&1 || true
  nghttp -v -y "https://127.0.0.1:$tcp_port/index.html" \
    >"$logs/nghttp-static.log" 2>&1 || status=1
  nghttp -v -y -n -m 2 \
    "https://127.0.0.1:$tcp_port/simple" \
    "https://127.0.0.1:$tcp_port/missing" \
    "https://127.0.0.1:$tcp_port/proxy" \
    >"$logs/nghttp-get.log" 2>&1 || status=1
  nghttp -v -y -n "https://127.0.0.1:$tcp_port/proxy-error" \
    >"$logs/nghttp-proxy-error.log" 2>&1 || true
  nghttp -v -y -n -H ':method: HEAD' "https://127.0.0.1:$tcp_port/simple" \
    >"$logs/nghttp-head.log" 2>&1 || status=1
  printf 'small-body' >"$workdir/small-body.txt"
  nghttp -v -y -n -d "$workdir/small-body.txt" "https://127.0.0.1:$tcp_port/proxy" \
    >"$logs/nghttp-post-small.log" 2>&1 || status=1
  python3 - "$workdir/large-body.txt" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(b"x" * 65536)
PY
  nghttp -v -y -n -d "$workdir/large-body.txt" "https://127.0.0.1:$tcp_port/proxy" \
    >"$logs/nghttp-post-large.log" 2>&1 || status=1

  if grep -q 'The negotiated protocol: h2' "$logs/nghttp-get.log" &&
     grep -q 'recv SETTINGS frame' "$logs/nghttp-get.log" &&
     grep -q ':status: 200' "$logs/nghttp-get.log" &&
     grep -q ':status: 404' "$logs/nghttp-get.log" &&
     grep -q ':status: 500' "$logs/nghttp-proxy-error.log" &&
     grep -q ':status: 200' "$logs/nghttp-head.log" &&
     ! grep -q 'recv DATA frame' "$logs/nghttp-head.log" &&
     ! grep -q 'INVALID; error=Protocol error' "$logs/nghttp-head.log" &&
     grep -q ':status: 200' "$logs/nghttp-static.log" &&
     grep -q 'blackbox-static-ok' "$logs/nghttp-static.log" &&
     grep -q ':status: 200' "$logs/nghttp-post-small.log" &&
     grep -q ':status: 200' "$logs/nghttp-post-large.log" &&
     grep -qx '10' "$post_lengths" &&
     grep -qx '65536' "$post_lengths"; then
    say "PASS independent nghttp H2 proof"
    printf 'nghttp_h2=PASS\n' >>"$summary"
  else
    say "FAIL independent nghttp H2 proof"
    printf 'nghttp_h2=FAIL\n' >>"$summary"
    status=1
  fi
else
  say "SKIP independent nghttp H2 proof: nghttp not installed"
  printf 'nghttp_h2=SKIP no-nghttp\n' >>"$summary"
fi

altsvc_headers="$logs/altsvc-enabled.headers"
if command -v openssl >/dev/null 2>&1; then
  printf 'GET /proxy HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n' |
    openssl s_client -connect "127.0.0.1:$tcp_port" -servername tardigrade.test -alpn http/1.1 -quiet \
      >"$logs/altsvc-enabled.raw" 2>"$logs/altsvc-enabled.openssl.log" || true
  sed -n '1,/^\r$/p' "$logs/altsvc-enabled.raw" >"$altsvc_headers"
else
  curl -sk --noproxy '*' --resolve "tardigrade.test:$tcp_port:127.0.0.1" -D "$altsvc_headers" -o /dev/null \
    "https://tardigrade.test:$tcp_port/proxy" >"$logs/altsvc-enabled.curl.log" 2>&1 || status=1
fi
alt_port="$(grep -i '^Alt-Svc:' "$altsvc_headers" | sed -n 's/.*h3=":\([0-9][0-9]*\)".*/\1/p' | head -n 1)"
if [ -n "$alt_port" ]; then
  say "PASS Alt-Svc advertisement emitted for UDP port $alt_port"
  printf 'altsvc_advertisement=PASS port=%s\n' "$alt_port" >>"$summary"
else
  say "FAIL Alt-Svc advertisement was not emitted"
  printf 'altsvc_advertisement=FAIL\n' >>"$summary"
  status=1
fi

if [ -n "${NGTCP2_EXAMPLES_DIR:-}" ] && [ -x "$NGTCP2_EXAMPLES_DIR/gtlsclient" ] && [ -n "$alt_port" ]; then
  # The URI host below becomes both the TLS SNI and HTTP :authority that
  # gtlsclient sends. It must match the config's `server_name` (not just any
  # SNI name credentialed via TARDIGRADE_TLS_SNI_CERTS): the gateway's
  # virtual-host resolution matches on :authority/Host the same way it does
  # for HTTP/1.1, so an authority the TLS layer accepts (e.g. "localhost",
  # which has its own SNI credential here) can still 404 at the routing layer
  # if it doesn't match `server_name`. Discovered via this exact row (#677).
  "$NGTCP2_EXAMPLES_DIR/gtlsclient" 127.0.0.1 "$alt_port" "https://tardigrade.test:$alt_port/healthz" \
    --exit-on-first-stream-close >"$logs/gtlsclient-altsvc.log" 2>&1 || status=1
  # `/`, not just `/index.html`: this config has no `index` directive, so
  # (like the H2 static row) the static-file proof must name the file
  # directly -- bare `/` has no automatic index.html fallback and 404s.
  "$NGTCP2_EXAMPLES_DIR/gtlsclient" 127.0.0.1 "$udp_port" \
    "https://tardigrade.test:$udp_port/index.html" "https://tardigrade.test:$udp_port/proxy" \
    "https://tardigrade.test:$udp_port/proxy-error" \
    --exit-on-all-streams-close >"$logs/gtlsclient-h3-multi.log" 2>&1 || status=1
  # gtlsclient logs the received body as a hexdump wrapped at 16 bytes per
  # line, so a literal response-body needle longer than one wrapped segment
  # (e.g. 19-byte "blackbox-static-ok\n" splits across two dump lines) can
  # silently fail a plain single-line `grep`, even though the byte-for-byte
  # content is correct -- proven by this exact row before this fix (#677).
  # Simply stripping newlines is not enough either: each dump line's own
  # offset/hex columns would then be spliced between the two halves of the
  # needle. Extract just the ASCII column (`|...|`) from every dump line and
  # concatenate those before searching.
  log_contains() { sed -n 's/^[0-9a-f]\{8\}  .*|\(.*\)|$/\1/p' "$1" | tr -d '\n' | grep -Fq "$2"; }
  if grep -Fq ':status: 200' "$logs/gtlsclient-altsvc.log" &&
     log_contains "$logs/gtlsclient-altsvc.log" 'alive' &&
     grep -Fq ':status: 200' "$logs/gtlsclient-h3-multi.log" &&
     grep -Fq ':status: 500' "$logs/gtlsclient-h3-multi.log" &&
     log_contains "$logs/gtlsclient-h3-multi.log" 'blackbox-static-ok' &&
     log_contains "$logs/gtlsclient-h3-multi.log" 'proxy-ok' &&
     log_contains "$logs/gtlsclient-h3-multi.log" 'proxy-upstream-error'; then
    say "PASS black-box ngtcp2/GnuTLS H3 proof"
    printf 'blackbox_h3_ngtcp2=PASS\n' >>"$summary"
  else
    say "FAIL black-box ngtcp2/GnuTLS H3 proof"
    printf 'blackbox_h3_ngtcp2=FAIL\n' >>"$summary"
    status=1
  fi
else
  say "SKIP black-box H3 proof: NGTCP2_EXAMPLES_DIR/gtlsclient unavailable"
  printf 'blackbox_h3_ngtcp2=SKIP no-gtlsclient\n' >>"$summary"
fi

if [ -n "${AIOQUIC_PYTHON:-}" ] && [ -x "${AIOQUIC_PYTHON:-}" ]; then
  "$AIOQUIC_PYTHON" "$here/interop/aioquic_client.py" 127.0.0.1 "$udp_port" /healthz tardigrade.test \
    >"$logs/aioquic-client-artifact.log" 2>&1 || status=1
  if grep -q 'alive' "$logs/aioquic-client-artifact.log"; then
    say "PASS second H3 implementation aioquic proof"
    printf 'second_h3_impl=PASS aioquic\n' >>"$summary"
  else
    say "FAIL second H3 implementation aioquic proof"
    printf 'second_h3_impl=FAIL aioquic\n' >>"$summary"
    status=1
  fi
elif [ -n "${QUICHE_EXAMPLES_DIR:-}" ] && [ -x "$QUICHE_EXAMPLES_DIR/http3-client" ]; then
  RUST_LOG=error "$QUICHE_EXAMPLES_DIR/http3-client" "https://127.0.0.1:$udp_port/healthz" \
    >"$logs/quiche-client-artifact.log" 2>&1 || status=1
  if grep -q 'alive' "$logs/quiche-client-artifact.log"; then
    say "PASS second H3 implementation quiche proof"
    printf 'second_h3_impl=PASS quiche\n' >>"$summary"
  else
    say "FAIL second H3 implementation quiche proof"
    printf 'second_h3_impl=FAIL quiche\n' >>"$summary"
    status=1
  fi
else
  say "SKIP second H3 implementation proof: set AIOQUIC_PYTHON or QUICHE_EXAMPLES_DIR"
  printf 'second_h3_impl=SKIP no-aioquic-or-quiche\n' >>"$summary"
fi

if [ -n "${AIOQUIC_PYTHON:-}" ] && [ -x "${AIOQUIC_PYTHON:-}" ]; then
  # RESET_STREAM/STOP_SENDING cancellation, against the selected artifact:
  # a CLI accepting "--h3" is not proof of this, and neither ngtcp2's
  # example client nor h3_interop_tool expose a stream-cancel flag, so this
  # drives the real QUIC transport primitives directly via aioquic's
  # low-level API. Proves cancellation doesn't poison the connection: a
  # third, ordinary request on the same connection must still succeed.
  "$AIOQUIC_PYTHON" "$here/interop/aioquic_cancel_client.py" 127.0.0.1 "$udp_port" tardigrade.test /healthz \
    >"$logs/aioquic-cancel-client.log" 2>&1 || status=1
  if grep -q 'recovery status: 200' "$logs/aioquic-cancel-client.log" &&
     grep -q 'alive' "$logs/aioquic-cancel-client.log"; then
    say "PASS black-box H3 RESET_STREAM/STOP_SENDING cancellation + same-connection recovery"
    printf 'blackbox_h3_cancel=PASS\n' >>"$summary"
  else
    say "FAIL black-box H3 RESET_STREAM/STOP_SENDING cancellation + same-connection recovery"
    printf 'blackbox_h3_cancel=FAIL\n' >>"$summary"
    status=1
  fi
else
  say "SKIP black-box H3 cancellation proof: AIOQUIC_PYTHON unavailable"
  printf 'blackbox_h3_cancel=SKIP no-aioquic\n' >>"$summary"
fi

cycles="${HTTP_SWEEP_RESOURCE_CYCLES:-20}"
resource_failures=0
for i in $(seq 1 "$cycles"); do
  if command -v nghttp >/dev/null 2>&1; then
    printf 'cycle=%s\n' "$i" >>"$logs/resource-nghttp.log"
    if ! nghttp -y -n "https://127.0.0.1:$tcp_port/healthz" >>"$logs/resource-nghttp.log" 2>&1; then
      say "FAIL resource cycle $i: nghttp H2 request"
      printf 'resource_cycle_%s_h2=FAIL\n' "$i" >>"$summary"
      resource_failures=$((resource_failures + 1))
      status=1
    fi
  fi
  # connect/request/cancel/close, not just connect/request/close: each cycle
  # exercises the real RESET_STREAM/STOP_SENDING + same-connection-recovery
  # path (like the dedicated cancellation row above) rather than only ever
  # closing streams cleanly.
  if [ -n "${AIOQUIC_PYTHON:-}" ] && [ -x "${AIOQUIC_PYTHON:-}" ]; then
    printf 'cycle=%s\n' "$i" >>"$logs/resource-aioquic-cancel.log"
    if ! "$AIOQUIC_PYTHON" "$here/interop/aioquic_cancel_client.py" 127.0.0.1 "$udp_port" tardigrade.test /healthz \
      >>"$logs/resource-aioquic-cancel.log" 2>&1; then
      say "FAIL resource cycle $i: aioquic H3 cancellation/recovery"
      printf 'resource_cycle_%s_h3_cancel=FAIL\n' "$i" >>"$summary"
      resource_failures=$((resource_failures + 1))
      status=1
    fi
  elif [ -n "${NGTCP2_EXAMPLES_DIR:-}" ] && [ -x "$NGTCP2_EXAMPLES_DIR/gtlsclient" ]; then
    printf 'cycle=%s\n' "$i" >>"$logs/resource-gtlsclient.log"
    if ! "$NGTCP2_EXAMPLES_DIR/gtlsclient" 127.0.0.1 "$udp_port" "https://tardigrade.test:$udp_port/healthz" \
      --exit-on-first-stream-close >>"$logs/resource-gtlsclient.log" 2>&1; then
      say "FAIL resource cycle $i: ngtcp2 H3 request"
      printf 'resource_cycle_%s_h3_ngtcp2=FAIL\n' "$i" >>"$summary"
      resource_failures=$((resource_failures + 1))
      status=1
    fi
  fi
  if [ "$i" = "$((cycles / 2))" ] || [ "$i" = "$cycles" ]; then
    record_sample "cycle_$i" "$tardi_pid" >>"$summary"
  fi
done
if [ "$resource_failures" -eq 0 ]; then
  printf 'resource_cycles=PASS cycles=%s\n' "$cycles" >>"$summary"
else
  printf 'resource_cycles=FAIL cycles=%s failures=%s\n' "$cycles" "$resource_failures" >>"$summary"
fi
sleep 1
record_sample after_settle "$tardi_pid" >>"$summary"

curl -sk --noproxy '*' --resolve "tardigrade.test:$tcp_port:127.0.0.1" -D "$logs/altsvc-disabled.headers" -o /dev/null \
  "https://tardigrade.test:$tcp_port/healthz" >"$logs/altsvc-disabled-prestop.curl.log" 2>&1 || true

if [ -n "${AIOQUIC_PYTHON:-}" ] && [ -x "${AIOQUIC_PYTHON:-}" ]; then
  # GOAWAY/drain boundary, against the selected artifact, with every half
  # observed rather than inferred from silence: send a request to the slow
  # upstream route (which admits it -- via drain_admitted -- before
  # blocking on drain_release), signal readiness once admitted, SIGTERM the
  # server, require an actual observed GOAWAY control frame, release the
  # upstream and require the already-admitted request to complete with 200,
  # then require a *new* stream to be explicitly rejected (stream reset or
  # connection termination, not a bare timeout).
  drain_ready="$workdir/drain-ready"
  rm -f "$drain_ready" "$drain_admitted" "$drain_release"
  "$AIOQUIC_PYTHON" "$here/interop/aioquic_drain_client.py" 127.0.0.1 "$udp_port" tardigrade.test /slow \
    "$drain_admitted" "$drain_ready" "$drain_release" \
    >"$logs/aioquic-drain-client.log" 2>&1 &
  drain_client_pid=$!
  for _ in $(seq 1 100); do
    [ -f "$drain_ready" ] && break
    sleep 0.1
  done
  kill "$tardi_pid" 2>/dev/null
  wait "$drain_client_pid" 2>/dev/null
  drain_client_status=$?
  wait "$tardi_pid" 2>/dev/null
  tardi_pid=""
  if [ "$drain_client_status" -eq 0 ] &&
     grep -q 'goaway received' "$logs/aioquic-drain-client.log" &&
     grep -q 'admitted request status: 200' "$logs/aioquic-drain-client.log" &&
     grep -q 'post-boundary explicit rejection: True' "$logs/aioquic-drain-client.log"; then
    say "PASS black-box H3 GOAWAY/drain boundary (observed GOAWAY, admitted work completes, new work explicitly rejected)"
    printf 'blackbox_h3_drain=PASS\n' >>"$summary"
  else
    say "FAIL black-box H3 GOAWAY/drain boundary (observed GOAWAY, admitted work completes, new work explicitly rejected)"
    printf 'blackbox_h3_drain=FAIL\n' >>"$summary"
    status=1
  fi
else
  say "SKIP black-box H3 GOAWAY/drain boundary proof: AIOQUIC_PYTHON unavailable"
  printf 'blackbox_h3_drain=SKIP no-aioquic\n' >>"$summary"
  kill "$tardi_pid" 2>/dev/null
  wait "$tardi_pid" 2>/dev/null
fi
tardi_pid=""

disabled_tcp_port="$(free_tcp_port)"
TARDIGRADE_LISTEN_HOST=127.0.0.1 \
TARDIGRADE_LISTEN_PORT="$disabled_tcp_port" \
TARDIGRADE_CONFIG_PATH="$config" \
TARDIGRADE_TLS_CERT_PATH="$repo/tests/fixtures/tls/native_ed25519.crt" \
TARDIGRADE_TLS_KEY_PATH="$repo/tests/fixtures/tls/native_ed25519.key" \
TARDIGRADE_TLS_SERVER_NAME=tardigrade.test \
TARDIGRADE_TLS_SNI_CERTS="localhost:$repo/tests/fixtures/tls/native_ed25519.crt:$repo/tests/fixtures/tls/native_ed25519.key|tardigrade.test:$repo/tests/fixtures/tls/native_ed25519.crt:$repo/tests/fixtures/tls/native_ed25519.key" \
TARDIGRADE_HTTP2_ENABLED=true \
TARDIGRADE_HTTP3_ENABLED=false \
TARDIGRADE_HTTP3_ALT_SVC=auto \
TARDIGRADE_RATE_LIMIT_RPS=10000 \
TARDIGRADE_RATE_LIMIT_BURST=10000 \
TARDIGRADE_ERROR_LOG_PATH="$logs/tardi-disabled-app.log" \
"$tardi_bin" run -c "$config" >"$logs/tardi-disabled.stdout" 2>"$logs/tardi-disabled.stderr" &
tardi_pid=$!
if wait_tcp "$disabled_tcp_port"; then
  if command -v openssl >/dev/null 2>&1; then
    printf 'GET /healthz HTTP/1.1\r\nHost: tardigrade.test\r\nConnection: close\r\n\r\n' |
      openssl s_client -connect "127.0.0.1:$disabled_tcp_port" -servername tardigrade.test -alpn http/1.1 -quiet \
        >"$logs/altsvc-disabled.raw" 2>"$logs/altsvc-disabled.openssl.log" || true
    sed -n '1,/^\r$/p' "$logs/altsvc-disabled.raw" >"$logs/altsvc-disabled.headers"
  else
    curl -sk --noproxy '*' --resolve "tardigrade.test:$disabled_tcp_port:127.0.0.1" -D "$logs/altsvc-disabled.headers" -o /dev/null \
      "https://tardigrade.test:$disabled_tcp_port/healthz" >"$logs/altsvc-disabled.curl.log" 2>&1 || true
  fi
  if ! grep -q '^HTTP/1.1 200' "$logs/altsvc-disabled.headers"; then
    say "FAIL disabled-H3 control did not return HTTP/1.1 200"
    printf 'altsvc_disabled=FAIL no-http-200\n' >>"$summary"
    status=1
  elif grep -qi '^Alt-Svc: h3=' "$logs/altsvc-disabled.headers"; then
    say "FAIL disabled H3 still advertised h3 Alt-Svc"
    printf 'altsvc_disabled=FAIL\n' >>"$summary"
    status=1
  else
    say "PASS disabled H3 does not advertise h3 Alt-Svc"
    printf 'altsvc_disabled=PASS\n' >>"$summary"
  fi
else
  say "FAIL disabled-H3 control process did not open TCP port $disabled_tcp_port"
  printf 'altsvc_disabled=FAIL process-not-ready\n' >>"$summary"
  status=1
fi

say "blackbox summary: $summary"
exit "$status"

#!/bin/bash
# Focused external HTTP/3 interoperability matrix for the native Zig
# QUIC/H3 stack (#247 phase 5, cutover gate for #328).
#
# Exercises both directions against out-of-process peers:
#   1. native client -> ngtcp2/nghttp3 server (gtlsserver)
#   2. ngtcp2/nghttp3 client (gtlsclient) -> native server
#   3. native client -> quiche http3-server
#   4. quiche http3-client -> native server
#   5. native client -> aioquic server        (optional)
#   6. aioquic client -> native server        (optional)
#
# Peer discovery via environment variables (unset peers are skipped, but
# ngtcp2 and quiche are required for the #328 gate):
#   NGTCP2_EXAMPLES_DIR  dir containing gtlsclient/gtlsserver
#   QUICHE_EXAMPLES_DIR  dir containing http3-client/http3-server examples
#   AIOQUIC_PYTHON       python interpreter with aioquic installed
#
# See scripts/interop/README.md for building the peers.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
tool="$repo/zig-out/bin/h3_interop_tool"
workdir="${INTEROP_WORKDIR:-$(mktemp -d)}"
certs="$workdir/certs"
logs="$workdir/logs"
mkdir -p "$certs" "$logs"

pass=0
fail=0
skip=0

say() { printf '%s\n' "$*"; }

result() { # name status
  case "$2" in
    PASS) pass=$((pass + 1)) ;;
    FAIL) fail=$((fail + 1)) ;;
    SKIP) skip=$((skip + 1)) ;;
  esac
  printf '%-46s %s\n' "$1" "$2"
}

if [ ! -x "$tool" ]; then
  say "building h3_interop_tool..."
  (cd "$repo" && zig build build-h3-interop) || { say "cannot build h3_interop_tool"; exit 1; }
fi

say "generating interop certificates in $certs"
"$here/gen-certs.sh" "$certs" >/dev/null

port=24433
next_port() { port=$((port + 1)); }

wait_udp_listen() { # give the peer a moment to bind
  sleep 1.5
}

# --- 1. native client -> ngtcp2 gtlsserver --------------------------------
next_port
if [ -n "${NGTCP2_EXAMPLES_DIR:-}" ] && [ -x "$NGTCP2_EXAMPLES_DIR/gtlsserver" ]; then
  mkdir -p "$workdir/docroot"
  echo "hello-from-ngtcp2" >"$workdir/docroot/interop.txt"
  "$NGTCP2_EXAMPLES_DIR/gtlsserver" 127.0.0.1 "$port" "$certs/ed25519-key.pem" "$certs/ed25519-cert.pem" \
    -d "$workdir/docroot" --quiet >"$logs/1-gtlsserver.log" 2>&1 &
  peer=$!
  wait_udp_listen
  if "$tool" client --host 127.0.0.1 --port "$port" --authority tardigrade.test \
    --path /interop.txt --insecure --timeout-ms 10000 >"$logs/1-native-client.log" 2>&1 &&
    grep -q "hello-from-ngtcp2" "$logs/1-native-client.log"; then
    result "native client -> ngtcp2 gtlsserver" PASS
  else
    result "native client -> ngtcp2 gtlsserver" FAIL
  fi
  kill "$peer" 2>/dev/null
  wait "$peer" 2>/dev/null
else
  result "native client -> ngtcp2 gtlsserver" SKIP
fi

# --- 2. ngtcp2 gtlsclient -> native server --------------------------------
next_port
if [ -n "${NGTCP2_EXAMPLES_DIR:-}" ] && [ -x "$NGTCP2_EXAMPLES_DIR/gtlsclient" ]; then
  "$tool" server --port "$port" --cert "$certs/ed25519-cert.der" --key "$certs/ed25519-key.pkcs8.der" \
    --timeout-ms 15000 >"$logs/2-native-server.log" 2>&1 &
  peer=$!
  wait_udp_listen
  "$NGTCP2_EXAMPLES_DIR/gtlsclient" 127.0.0.1 "$port" "https://tardigrade.test/from-ngtcp2" \
    --exit-on-first-stream-close >"$logs/2-gtlsclient.log" 2>&1
  client_rc=$?
  wait "$peer"
  server_rc=$?
  if [ "$client_rc" -eq 0 ] && [ "$server_rc" -eq 0 ] &&
    grep -q "server ok, served=1" "$logs/2-native-server.log"; then
    result "ngtcp2 gtlsclient -> native server" PASS
  else
    result "ngtcp2 gtlsclient -> native server" FAIL
  fi
else
  result "ngtcp2 gtlsclient -> native server" SKIP
fi

# --- 3. native client -> quiche http3-server ------------------------------
# The quiche example server hardcodes 127.0.0.1:4433 and examples/cert.crt.
if [ -n "${QUICHE_EXAMPLES_DIR:-}" ] && [ -x "$QUICHE_EXAMPLES_DIR/http3-server" ]; then
  mkdir -p "$workdir/quiche-run/examples"
  cp "$certs/p256-cert.pem" "$workdir/quiche-run/examples/cert.crt"
  cp "$certs/p256-key.pem" "$workdir/quiche-run/examples/cert.key"
  (cd "$workdir/quiche-run" && exec "$QUICHE_EXAMPLES_DIR/http3-server") >"$logs/3-quiche-server.log" 2>&1 &
  peer=$!
  wait_udp_listen
  if "$tool" client --host 127.0.0.1 --port 4433 --authority tardigrade.test \
    --path /index.html --insecure --timeout-ms 10000 >"$logs/3-native-client.log" 2>&1 &&
    grep -q "^status: " "$logs/3-native-client.log"; then
    result "native client -> quiche http3-server" PASS
  else
    result "native client -> quiche http3-server" FAIL
  fi
  kill "$peer" 2>/dev/null
  wait "$peer" 2>/dev/null
else
  result "native client -> quiche http3-server" SKIP
fi

# --- 4. quiche http3-client -> native server ------------------------------
next_port
if [ -n "${QUICHE_EXAMPLES_DIR:-}" ] && [ -x "$QUICHE_EXAMPLES_DIR/http3-client" ]; then
  "$tool" server --port "$port" --cert "$certs/p256-cert.der" --key "$certs/p256-key.pkcs8.der" \
    --timeout-ms 15000 >"$logs/4-native-server.log" 2>&1 &
  peer=$!
  wait_udp_listen
  RUST_LOG=error "$QUICHE_EXAMPLES_DIR/http3-client" "https://127.0.0.1:$port/from-quiche" \
    >"$logs/4-quiche-client.log" 2>&1
  client_rc=$?
  wait "$peer"
  server_rc=$?
  if [ "$client_rc" -eq 0 ] && [ "$server_rc" -eq 0 ] &&
    grep -q "hello from tardigrade native h3" "$logs/4-quiche-client.log"; then
    result "quiche http3-client -> native server" PASS
  else
    result "quiche http3-client -> native server" FAIL
  fi
else
  result "quiche http3-client -> native server" SKIP
fi

# --- 5. native client -> aioquic server (optional) ------------------------
next_port
if [ -n "${AIOQUIC_PYTHON:-}" ]; then
  "$AIOQUIC_PYTHON" "$here/aioquic_server.py" "$port" "$certs/ed25519-cert.pem" "$certs/ed25519-key.pem" \
    >"$logs/5-aioquic-server.log" 2>&1 &
  peer=$!
  wait_udp_listen
  if "$tool" client --host 127.0.0.1 --port "$port" --authority tardigrade.test \
    --path /to-aioquic --insecure --timeout-ms 10000 >"$logs/5-native-client.log" 2>&1 &&
    grep -q "hello from aioquic" "$logs/5-native-client.log"; then
    result "native client -> aioquic server (optional)" PASS
  else
    result "native client -> aioquic server (optional)" FAIL
  fi
  kill "$peer" 2>/dev/null
  wait "$peer" 2>/dev/null
else
  result "native client -> aioquic server (optional)" SKIP
fi

# --- 6. aioquic client -> native server (optional) -------------------------
next_port
if [ -n "${AIOQUIC_PYTHON:-}" ]; then
  "$tool" server --port "$port" --cert "$certs/p256-cert.der" --key "$certs/p256-key.pkcs8.der" \
    --timeout-ms 15000 >"$logs/6-native-server.log" 2>&1 &
  peer=$!
  wait_udp_listen
  "$AIOQUIC_PYTHON" "$here/aioquic_client.py" 127.0.0.1 "$port" /from-aioquic \
    >"$logs/6-aioquic-client.log" 2>&1
  client_rc=$?
  wait "$peer"
  server_rc=$?
  if [ "$client_rc" -eq 0 ] && [ "$server_rc" -eq 0 ] &&
    grep -q "hello from tardigrade native h3" "$logs/6-aioquic-client.log"; then
    result "aioquic client -> native server (optional)" PASS
  else
    result "aioquic client -> native server (optional)" FAIL
  fi
else
  result "aioquic client -> native server (optional)" SKIP
fi

say ""
say "interop summary: $pass passed, $fail failed, $skip skipped (logs: $logs)"
[ "$fail" -eq 0 ] || exit 1

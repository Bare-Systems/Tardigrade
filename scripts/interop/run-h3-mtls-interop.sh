#!/bin/sh
# External-client downstream mTLS interop for HTTP/3 (#763).
#
# Drives the real `tardi` gateway binary with TARDIGRADE_HTTP3_ENABLED and
# TARDIGRADE_TLS_CLIENT_VERIFY against an independently built QUIC/H3 client
# (aioquic) presenting the fixtures in tests/fixtures/tls/h3mtls. Asserts:
#   - a CA-issued clientAuth certificate is served, and the upstream sees the
#     handshake-verified identity as X-Tardigrade-Client-Cert-* (and nothing a
#     client forged);
#   - required mode refuses: no certificate, wrong CA, expired, not yet valid,
#     serverAuth-only EKU -- and the upstream never sees such a request;
#   - optional mode serves an anonymous client with no identity headers, but
#     still refuses a presented certificate that does not verify.
#
# usage: AIOQUIC_PYTHON=/path/to/python scripts/interop/run-h3-mtls-interop.sh
#   TARDI_BIN   gateway binary (default zig-out/bin/tardi)
#   KEEP_LOGS=1 keep the work directory
set -u

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
fixtures="$root/tests/fixtures/tls/h3mtls"
tardi="${TARDI_BIN:-$root/zig-out/bin/tardi}"
py="${AIOQUIC_PYTHON:-}"

if [ -z "$py" ] || [ ! -x "$py" ]; then
  echo "SKIP: set AIOQUIC_PYTHON to a python with aioquic installed"
  exit 0
fi
if [ ! -x "$tardi" ]; then
  echo "error: gateway binary not found at $tardi (zig build)" >&2
  exit 2
fi

work="$(mktemp -d)"
pids=""
cleanup() {
  for p in $pids; do kill "$p" 2>/dev/null; done
  wait 2>/dev/null
  if [ "${KEEP_LOGS:-0}" = 1 ]; then echo "logs kept in $work"; else rm -rf "$work"; fi
}
trap cleanup EXIT INT TERM

# aioquic wants PEM private keys; the fixtures ship PKCS#8 DER (what the native
# tests load), so convert into the work directory.
for name in client client_wrong_ca client_expired client_not_yet_valid client_wrong_eku; do
  openssl pkey -inform DER -in "$fixtures/$name.key.der" -out "$work/$name.key.pem" || exit 2
done

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

free_port() { # tcp|udp
  "$py" - "$1" <<'PY'
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if sys.argv[1] == "tcp" else socket.SOCK_DGRAM)
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
PY
}

# --- upstream: records every request's headers, answers "upstream-ok". ------
up_port="$(free_port tcp)"
upstream_log="$work/upstream.log"
: >"$upstream_log"
"$py" - "$up_port" "$upstream_log" <<'PY' &
import http.server, sys
log = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        with open(log, "a") as f:
            f.write(f"--- {self.command} {self.path}\n")
            for k, v in self.headers.items():
                f.write(f"{k}: {v}\n")
        body = b"upstream-ok"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
pids="$pids $!"

cat >"$work/tardigrade.conf" <<CONF
location / {
    proxy_pass http://127.0.0.1:$up_port;
}
CONF

start_gateway() { # name optional(true|false) -> sets quic_port
  quic_port="$(free_port udp)"
  tcp_port="$(free_port tcp)"
  TARDIGRADE_CONFIG_PATH="$work/tardigrade.conf" \
  TARDIGRADE_LISTEN_HOST=127.0.0.1 TARDIGRADE_LISTEN_PORT="$tcp_port" \
  TARDIGRADE_QUIC_PORT="$quic_port" TARDIGRADE_HTTP3_ENABLED=true \
  TARDIGRADE_TLS_CERT_PATH="$root/tests/fixtures/tls/native_ed25519.crt" \
  TARDIGRADE_TLS_KEY_PATH="$root/tests/fixtures/tls/native_ed25519.key" \
  TARDIGRADE_TLS_SERVER_NAME=tardigrade.test \
  TARDIGRADE_TLS_CLIENT_VERIFY=true TARDIGRADE_TLS_CLIENT_VERIFY_OPTIONAL="$2" \
  TARDIGRADE_TLS_CLIENT_CA_PATH="$fixtures/ca.crt" \
  TARDIGRADE_WORKER_THREADS=1 TARDIGRADE_ERROR_LOG_PATH="$work/$1.log" \
  "$tardi" >"$work/$1.out" 2>&1 &
  gw_pid=$!
  pids="$pids $gw_pid"
}

# aioquic client; $1 = cert name or "-" for none; $2 = extra headers.
h3() {
  if [ "$1" = "-" ]; then
    env -u AIOQUIC_CLIENT_CERT -u AIOQUIC_CLIENT_KEY AIOQUIC_REQUEST_HEADERS="$2" \
      "$py" "$here/aioquic_client.py" 127.0.0.1 "$quic_port" /who tardigrade.test
  else
    AIOQUIC_CLIENT_CERT="$fixtures/$1.crt" AIOQUIC_CLIENT_KEY="$work/$1.key.pem" \
      AIOQUIC_REQUEST_HEADERS="$2" \
      "$py" "$here/aioquic_client.py" 127.0.0.1 "$quic_port" /who tardigrade.test
  fi
}

upstream_requests() { grep -c '^--- ' "$upstream_log"; }

wait_ready() { # a valid-certificate request must succeed
  i=0
  while [ "$i" -lt 40 ]; do
    if h3 client "" >"$work/ready.out" 2>&1 && grep -q 'status: 200' "$work/ready.out"; then return 0; fi
    kill -0 "$gw_pid" 2>/dev/null || return 1
    i=$((i + 1))
    sleep 0.25
  done
  return 1
}

fingerprint="$(openssl x509 -in "$fixtures/client.crt" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')"

expect_refused() { # label cert
  before="$(upstream_requests)"
  if h3 "$2" "" >"$work/refused.out" 2>&1; then
    bad "$1: request unexpectedly succeeded"; cat "$work/refused.out"
  elif [ "$(upstream_requests)" -ne "$before" ]; then
    bad "$1: refused client reached the upstream"
  else
    ok "$1"
  fi
}

# ---------------------------------------------------------------- required --
start_gateway required false
if ! wait_ready; then
  echo "error: gateway did not become ready" >&2; cat "$work/required.log" "$work/required.out" >&2; exit 2
fi

: >"$upstream_log"
if h3 client "x-tardigrade-client-cert-subject:CN=forged,x-tardigrade-client-cert-verified:0" >"$work/valid.out" 2>&1 \
   && grep -q 'status: 200' "$work/valid.out" && grep -q 'upstream-ok' "$work/valid.out"; then
  if grep -qi '^x-tardigrade-client-cert-verified: 1' "$upstream_log" \
     && grep -qi "^x-tardigrade-client-cert-fingerprint-sha256: $fingerprint" "$upstream_log" \
     && grep -qi '^x-tardigrade-client-cert-subject: CN=h3-client.example' "$upstream_log" \
     && grep -qi '^x-tardigrade-client-cert-san-email: h3@example.com' "$upstream_log" \
     && ! grep -qi 'forged' "$upstream_log" \
     && [ "$(grep -ci '^x-tardigrade-client-cert-subject:' "$upstream_log")" -eq 1 ]; then
    ok "required: valid client certificate served; verified identity asserted upstream, forged headers dropped"
  else
    bad "required: identity headers wrong at the upstream"; cat "$upstream_log"
  fi
else
  bad "required: valid client certificate was not served"; cat "$work/valid.out"
fi

expect_refused "required: missing certificate refused" -
expect_refused "required: wrong-CA certificate refused" client_wrong_ca
expect_refused "required: expired certificate refused" client_expired
expect_refused "required: not-yet-valid certificate refused" client_not_yet_valid
expect_refused "required: serverAuth-only (wrong EKU) certificate refused" client_wrong_eku
kill "$gw_pid" 2>/dev/null

# ---------------------------------------------------------------- optional --
start_gateway optional true
i=0
while [ "$i" -lt 40 ]; do
  h3 - "" >"$work/ready.out" 2>&1 && grep -q 'status: 200' "$work/ready.out" && break
  i=$((i + 1)); sleep 0.25
done
: >"$upstream_log"
if h3 - "x-tardigrade-client-cert-verified:1,x-tardigrade-client-cert-subject:CN=forged" >"$work/anon.out" 2>&1 \
   && grep -q 'status: 200' "$work/anon.out" \
   && ! grep -qi 'x-tardigrade-client-cert' "$upstream_log" && ! grep -qi forged "$upstream_log"; then
  ok "optional: anonymous client served with no identity asserted and forged headers dropped"
else
  bad "optional: anonymous client handling"; cat "$work/anon.out" "$upstream_log"
fi
expect_refused "optional: a presented wrong-CA certificate is still refused" client_wrong_ca
: >"$upstream_log"
if h3 client "" >"$work/opt-valid.out" 2>&1 && grep -q 'status: 200' "$work/opt-valid.out" \
   && grep -qi '^x-tardigrade-client-cert-verified: 1' "$upstream_log"; then
  ok "optional: valid client certificate served with verified identity"
else
  bad "optional: valid client certificate"; cat "$work/opt-valid.out"
fi

echo "h3 mTLS interop: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

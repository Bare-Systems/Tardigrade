#!/usr/bin/env bash
# External-client downstream mTLS interop for HTTP/1.1 and HTTP/2 over TCP (#763).
#
# Runs the real `tardi` gateway binary with TARDIGRADE_TLS_CLIENT_VERIFY against
# independent clients that share no code with it: curl (OpenSSL backend) forced
# to `--http1.1` and to `--http2` (ALPN h2, asserted from the negotiated
# version), and `openssl s_client` speaking raw HTTP/1.1. Fixtures are the ones
# in tests/fixtures/tls/h3mtls. Asserts, on both protocols:
#   - required mode: a CA-issued clientAuth certificate is served and the
#     upstream sees the handshake-verified X-Tardigrade-Client-Cert-* identity;
#     forged X-Tardigrade-* request headers are replaced/dropped; no certificate,
#     wrong CA, expired, not-yet-valid and serverAuth-only certificates are
#     refused and never reach the upstream;
#   - optional mode: anonymous is served with no identity, a valid certificate
#     is served with identity, a presented-but-invalid certificate is refused;
#   - per-SNI: two hosts / two unrelated CAs over real TCP, cross-CA refusal in
#     both directions, and 421 when Host/:authority maps to a different policy
#     than the SNI the connection was admitted under;
#   - trust rotation: rewriting the CA bundle and reloading (SIGHUP) swaps the
#     trusted CA atomically, and a bundle that fails to load rejects the whole
#     reload while the serving trust set keeps verifying.
#
# usage: scripts/interop/run-h1-h2-mtls-interop.sh
#   TARDI_BIN   gateway binary (default zig-out/bin/tardi)
#   CURL        curl built with OpenSSL + HTTP/2 (default curl)
#   KEEP_LOGS=1 keep the work directory
set -u

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../.." && pwd)"
fixtures="$root/tests/fixtures/tls/h3mtls"
tardi="${TARDI_BIN:-$root/zig-out/bin/tardi}"
curl_bin="${CURL:-curl}"

if [ ! -x "$tardi" ]; then
  echo "error: gateway binary not found at $tardi (zig build)" >&2
  exit 2
fi
if ! "$curl_bin" --version | grep -q 'OpenSSL' || ! "$curl_bin" --version | grep -qi 'nghttp2'; then
  echo "error: $curl_bin needs an OpenSSL backend and HTTP/2 support (set CURL=)" >&2
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

# curl/openssl want PEM private keys; the fixtures ship PKCS#8 DER.
for name in client client_wrong_ca client_expired client_not_yet_valid client_wrong_eku; do
  openssl pkey -inform DER -in "$fixtures/$name.key.der" -out "$work/$name.key.pem" || exit 2
done

# timeout(1) is absent on stock macOS; fall back to a perl alarm.
with_timeout() {
  if command -v timeout >/dev/null 2>&1; then timeout "$@"
  elif command -v gtimeout >/dev/null 2>&1; then gtimeout "$@"
  else local s="$1"; shift; perl -e 'alarm shift; exec @ARGV' "$s" "$@"; fi
}

# Server identity covering every SNI name used below (self-signed Ed25519; the
# clients do not verify it -- server trust is not what is under test).
openssl genpkey -algorithm ed25519 -out "$work/server.key" 2>/dev/null || exit 2
openssl req -new -x509 -key "$work/server.key" -subj "/CN=a.test" -days 2 \
  -addext "subjectAltName=DNS:a.test,DNS:b.test,DNS:open.test" \
  -out "$work/server.crt" 2>/dev/null || exit 2

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "PASS $1"; }
bad() { fail=$((fail + 1)); echo "FAIL $1"; }

free_port() {
  python3 - <<'PY'
import socket
s = socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
PY
}

# --- upstream: records every request's headers, answers "upstream-ok". ------
up_port="$(free_port)"
upstream_log="$work/upstream.log"
: >"$upstream_log"
python3 - "$up_port" "$upstream_log" <<'PY' &
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
http.server.ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY
pids="$pids $!"

# start_gateway NAME OPTIONAL CA_BUNDLE: config body in $work/NAME.body.
# Sets tcp_port and gw_pid.
start_gateway() {
  tcp_port="$(free_port)"
  { echo "pid $work/$1.pid;"; cat "$work/$1.body"; } >"$work/$1.conf"
  TARDIGRADE_CONFIG_PATH="$work/$1.conf" \
  TARDIGRADE_LISTEN_HOST=127.0.0.1 TARDIGRADE_LISTEN_PORT="$tcp_port" \
  TARDIGRADE_TLS_CERT_PATH="$work/server.crt" \
  TARDIGRADE_TLS_KEY_PATH="$work/server.key" \
  TARDIGRADE_TLS_SERVER_NAME=a.test \
  TARDIGRADE_TLS_CLIENT_VERIFY=true TARDIGRADE_TLS_CLIENT_VERIFY_OPTIONAL="$2" \
  TARDIGRADE_TLS_CLIENT_CA_PATH="$3" \
  TARDIGRADE_WORKER_THREADS=1 TARDIGRADE_ERROR_LOG_PATH="$work/$1.log" \
  "$tardi" >"$work/$1.out" 2>&1 &
  gw_pid=$!
  pids="$pids $gw_pid"
}

# client PROTO SNI CERT [Name: value ...]: one GET /who over real TCP TLS with
# SNI $SNI. PROTO is h1 (curl --http1.1), h2 (curl --http2, ALPN h2) or openssl
# (`openssl s_client` speaking raw HTTP/1.1). CERT is a fixture name or "-".
# Extra args are request headers; `Host: x` overrides Host/:authority
# independently of the SNI. Returns 0 only when an HTTP response arrived; sets
# $status and $negotiated (HTTP version actually spoken).
status=""
negotiated=""
client() {
  local proto="$1" sni="$2" cert="$3"
  shift 3
  status=""; negotiated=""
  if [ "$proto" = openssl ]; then
    local certargs=() host="$sni" h
    [ "$cert" != "-" ] && certargs=(-cert "$fixtures/$cert.crt" -key "$work/$cert.key.pem")
    for h in "$@"; do case "$h" in [Hh]ost:*) host="${h#*: }" ;; esac; done
    {
      printf 'GET /who HTTP/1.1\r\nHost: %s\r\n' "$host"
      for h in "$@"; do case "$h" in [Hh]ost:*) ;; *) printf '%s\r\n' "$h" ;; esac; done
      printf 'Connection: close\r\n\r\n'
    } | with_timeout 15 openssl s_client -connect "127.0.0.1:$tcp_port" -servername "$sni" \
        -tls1_3 -alpn http/1.1 -quiet -ign_eof ${certargs[@]+"${certargs[@]}"} >"$work/client.out" 2>"$work/client.err"
    status="$(sed -n 's/^HTTP\/1\.1 \([0-9]*\).*/\1/p' "$work/client.out" | head -1)"
    negotiated=1.1
    [ -n "$status" ]
    return
  fi
  local ver=--http1.1 args=()
  [ "$proto" = h2 ] && ver=--http2
  [ "$cert" != "-" ] && args+=(--cert "$fixtures/$cert.crt" --key "$work/$cert.key.pem")
  for h in "$@"; do args+=(-H "$h"); done
  "$curl_bin" -sk "$ver" --max-time 15 --tlsv1.3 --resolve "$sni:$tcp_port:127.0.0.1" \
    ${args[@]+"${args[@]}"} -o "$work/client.out" -w '%{http_code} %{http_version}' \
    "https://$sni:$tcp_port/who" >"$work/client.meta" 2>"$work/client.err" || return 1
  read -r status negotiated <"$work/client.meta"
  [ "$status" != 000 ]
}

upstream_requests() { grep -c '^--- ' "$upstream_log"; }
last_request() { awk '/^--- /{buf=""} {buf=buf $0 "\n"} END{printf "%s", buf}' "$upstream_log"; }

expect_version() { # proto -> negotiated version must match the protocol under test
  case "$1" in
    h2) [ "$negotiated" = 2 ] ;;
    *) [ "$negotiated" = 1.1 ] ;;
  esac
}

# label proto sni cert: must be refused and must not reach the upstream.
expect_refused() {
  local label="$1" before
  before="$(upstream_requests)"
  if client "$2" "$3" "$4"; then
    bad "$label: request unexpectedly got HTTP $status"
  elif [ "$(upstream_requests)" -ne "$before" ]; then
    bad "$label: refused client reached the upstream"
  else
    ok "$label"
  fi
}

# label proto sni cert: must be served (200 upstream-ok) over the right protocol.
expect_served() {
  local label="$1"
  if client "$2" "$3" "$4" && [ "$status" = 200 ] && grep -q upstream-ok "$work/client.out" && expect_version "$2"; then
    ok "$label"
  else
    bad "$label: status='$status' version='$negotiated'"; cat "$work/client.err" 2>/dev/null
  fi
}

wait_ready() { # proto sni cert
  local i=0
  while [ "$i" -lt 60 ]; do
    client "$1" "$2" "$3" && [ "$status" = 200 ] && return 0
    kill -0 "$gw_pid" 2>/dev/null || return 1
    i=$((i + 1)); sleep 0.25
  done
  return 1
}

fingerprint="$(openssl x509 -in "$fixtures/client.crt" -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f')"
forged=("X-Tardigrade-Client-Cert-Subject: CN=forged" "X-Tardigrade-Client-Cert-Verified: 0" \
        "X-Tardigrade-Client-Cert-Fingerprint-Sha256: deadbeef" "X-Tardigrade-Auth-User: root-forged")

# label proto sni cert: served with the verified identity, forged headers gone.
expect_identity() {
  local label="$1"
  : >"$upstream_log"
  if client "$2" "$3" "$4" "${forged[@]}" && [ "$status" = 200 ] && expect_version "$2"; then
    local req; req="$(last_request)"
    if echo "$req" | grep -qi '^x-tardigrade-client-cert-verified: 1' \
       && echo "$req" | grep -qi "^x-tardigrade-client-cert-fingerprint-sha256: $fingerprint" \
       && echo "$req" | grep -qi '^x-tardigrade-client-cert-subject: CN=h3-client.example' \
       && echo "$req" | grep -qi '^x-tardigrade-client-cert-san-email: h3@example.com' \
       && ! echo "$req" | grep -qi 'forged\|deadbeef' \
       && [ "$(echo "$req" | grep -ci '^x-tardigrade-client-cert-subject:')" -eq 1 ] \
       && [ "$(echo "$req" | grep -ci '^x-tardigrade-client-cert-verified:')" -eq 1 ]; then
      ok "$label"
    else
      bad "$label: upstream saw wrong identity headers"; echo "$req"
    fi
  else
    bad "$label: not served (status='$status' version='$negotiated')"; cat "$work/client.err"
  fi
}

# label proto sni cert: served anonymously -- no identity, forged headers gone.
expect_anonymous() {
  local label="$1"
  : >"$upstream_log"
  if client "$2" "$3" "$4" "${forged[@]}" && [ "$status" = 200 ] && expect_version "$2"; then
    local req; req="$(last_request)"
    if ! echo "$req" | grep -qi 'x-tardigrade-' ; then ok "$label"; else bad "$label: identity/forged header reached upstream"; echo "$req"; fi
  else
    bad "$label: not served (status='$status')"; cat "$work/client.err"
  fi
}

location="location / {
    proxy_pass http://127.0.0.1:$up_port;
}"
protos="h1 h2 openssl"

# ---------------------------------------------------------------- required --
echo "$location" >"$work/required.body"
start_gateway required false "$fixtures/ca.crt"
if ! wait_ready h1 a.test client; then
  echo "error: gateway did not become ready" >&2; tail -5 "$work/required.log" >&2; exit 2
fi
for p in $protos; do
  expect_identity "required/$p: valid certificate served; verified identity asserted, forged headers replaced" "$p" a.test client
  expect_refused "required/$p: missing certificate refused" "$p" a.test -
  expect_refused "required/$p: wrong-CA certificate refused" "$p" a.test client_wrong_ca
  expect_refused "required/$p: expired certificate refused" "$p" a.test client_expired
  expect_refused "required/$p: not-yet-valid certificate refused" "$p" a.test client_not_yet_valid
  expect_refused "required/$p: serverAuth-only (wrong EKU) certificate refused" "$p" a.test client_wrong_eku
done
kill "$gw_pid" 2>/dev/null

# ---------------------------------------------------------------- optional --
echo "$location" >"$work/optional.body"
start_gateway optional true "$fixtures/ca.crt"
wait_ready h1 a.test - || { echo "error: optional gateway not ready" >&2; tail -5 "$work/optional.log" >&2; exit 2; }
for p in $protos; do
  expect_anonymous "optional/$p: anonymous served, no identity, forged headers dropped" "$p" a.test -
  expect_identity "optional/$p: valid certificate served with verified identity" "$p" a.test client
  expect_refused "optional/$p: presented wrong-CA certificate still refused" "$p" a.test client_wrong_ca
  expect_refused "optional/$p: presented expired certificate still refused" "$p" a.test client_expired
done
kill "$gw_pid" 2>/dev/null

# ------------------------------------------------------------------ per-SNI --
# a.test trusts CA A, b.test trusts the unrelated rogue CA, open.test requests
# no certificate. The server certificate is shared; clients do not verify it.
cat >"$work/sni.body" <<CONF
server {
    server_name a.test;
    tls_client_verify on;
    tls_client_ca_path $fixtures/ca.crt;
    $location
}
server {
    server_name b.test;
    tls_client_verify on;
    tls_client_ca_path $fixtures/rogue_ca.crt;
    $location
}
server {
    server_name open.test;
    tls_client_verify off;
    $location
}
CONF
start_gateway sni false "$fixtures/ca.crt"
wait_ready h1 a.test client || { echo "error: per-SNI gateway not ready" >&2; tail -5 "$work/sni.log" >&2; exit 2; }
for p in h1 h2; do
  expect_served "sni/$p: CA-A certificate served on a.test" "$p" a.test client
  expect_served "sni/$p: CA-B certificate served on b.test" "$p" b.test client_wrong_ca
  expect_refused "sni/$p: CA-B certificate refused on a.test (cross-CA)" "$p" a.test client_wrong_ca
  expect_refused "sni/$p: CA-A certificate refused on b.test (cross-CA)" "$p" b.test client
  expect_refused "sni/$p: missing certificate refused on b.test" "$p" b.test -
  expect_served "sni/$p: anonymous served on open.test (verification off)" "$p" open.test -
  for c in "client:a.test:b.test" "client_wrong_ca:b.test:a.test" "-:open.test:a.test"; do
    cert="${c%%:*}"; rest="${c#*:}"; sni="${rest%%:*}"; host="${rest#*:}"
    before="$(upstream_requests)"
    if client "$p" "$sni" "$cert" "Host: $host" && [ "$status" = 421 ] && [ "$(upstream_requests)" -eq "$before" ]; then
      ok "sni/$p: SNI $sni with Host $host answered 421, upstream untouched"
    else
      bad "sni/$p: SNI $sni with Host $host expected 421, got '$status'"
    fi
  done
  if client "$p" a.test client "Host: open.test" && [ "$status" = 200 ]; then
    ok "sni/$p: SNI a.test with Host open.test (no client auth) is admissible"
  else
    bad "sni/$p: SNI a.test with Host open.test got '$status'"
  fi
done
expect_served "sni/openssl: CA-A certificate served on a.test" openssl a.test client
expect_refused "sni/openssl: CA-B certificate refused on a.test" openssl a.test client_wrong_ca
kill "$gw_pid" 2>/dev/null

# ---------------------------------------------------------------- rotation --
# The CA bundle is rewritten in place and the running process reloaded.
cp "$fixtures/ca.crt" "$work/rot-ca.pem"
echo "$location" >"$work/rot.body"
start_gateway rot false "$work/rot-ca.pem"
wait_ready h1 a.test client || { echo "error: rotation gateway not ready" >&2; tail -5 "$work/rot.log" >&2; exit 2; }
expect_served "rotate: generation 1 trusts CA A" h2 a.test client
expect_refused "rotate: generation 1 refuses CA B" h2 a.test client_wrong_ca

# wait_flip PROTO CERT want(serve|refuse)
wait_flip() {
  local i=0
  while [ "$i" -lt 60 ]; do
    if client "$1" a.test "$2" && [ "$status" = 200 ]; then [ "$3" = serve ] && return 0
    else [ "$3" = refuse ] && return 0; fi
    i=$((i + 1)); sleep 0.25
  done
  return 1
}

cp "$fixtures/rogue_ca.crt" "$work/rot-ca.pem"
kill -HUP "$gw_pid"
if wait_flip h1 client_wrong_ca serve; then
  expect_served "rotate: generation 2 (reload) trusts CA B on h2" h2 a.test client_wrong_ca
  expect_served "rotate: generation 2 (reload) trusts CA B on h1" h1 a.test client_wrong_ca
  expect_refused "rotate: generation 2 no longer trusts CA A" h2 a.test client
  expect_refused "rotate: generation 2 no longer trusts CA A (h1)" h1 a.test client
else
  bad "rotate: reload never took effect"; tail -5 "$work/rot.log"
fi

# A bundle that fails to load rejects the whole reload; the serving trust set
# keeps verifying (CA B still trusted, CA A still refused).
echo "not a pem bundle" >"$work/rot-ca.pem"
kill -HUP "$gw_pid"
i=0
while [ "$i" -lt 40 ] && ! grep -q 'config reload rejected by client trust' "$work/rot.log"; do i=$((i + 1)); sleep 0.25; done
grep -q 'config reload rejected by client trust' "$work/rot.log" \
  && ok "rotate: reload with an unloadable bundle is rejected (logged)" \
  || bad "rotate: unloadable-bundle reload was not rejected"
kill -0 "$gw_pid" 2>/dev/null && ok "rotate: gateway survives a reload with an unloadable bundle" \
  || bad "rotate: gateway died on a bad bundle"
expect_served "rotate: bad-bundle reload rejected, CA B still trusted" h2 a.test client_wrong_ca
expect_refused "rotate: bad-bundle reload rejected, CA A still refused" h2 a.test client

# And a good bundle afterwards is picked up again (rotation back to CA A).
cp "$fixtures/ca.crt" "$work/rot-ca.pem"
kill -HUP "$gw_pid"
if wait_flip h1 client serve; then
  expect_served "rotate: generation 3 trusts CA A again" h2 a.test client
  expect_refused "rotate: generation 3 refuses CA B again" h1 a.test client_wrong_ca
else
  bad "rotate: recovery reload never took effect"; tail -5 "$work/rot.log"
fi

echo "h1/h2 mTLS interop: $pass passed, $fail failed"
[ "$fail" -eq 0 ]

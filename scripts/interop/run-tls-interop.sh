#!/bin/bash
# Shared-TLS-engine interoperability and conformance matrix (#338).
#
# Drives the *same* TLS 1.3 engine that the production listener uses, in both
# client and server roles, over both transports, against out-of-process
# external implementations:
#
#   record transport  tls_interop_tool  <-> openssl s_client / s_server
#                                       <-> gnutls-cli / gnutls-serv
#   QUIC transport    h3_interop_tool   <-> ngtcp2 gtlsclient / gtlsserver
#                                       (native loopback when no peer is set)
#
# Nothing foreign links into Tardigrade: every peer is a separate process.
#
# Positive rows walk the engine's full cipher-suite x group x signature matrix
# and assert on what was actually negotiated, not merely that a handshake
# completed. Negative rows assert the failure class both sides agree on, using
# the RFC 8446 §6 alert where the standard defines one.
#
# usage:
#   scripts/interop/run-tls-interop.sh [--profile ci|full] [--list]
#
# environment:
#   TLS_INTEROP_PROFILE   ci | full   (default: full; --profile wins)
#   TLS_INTEROP_WORKDIR   where certs, logs and transcripts land
#                         (default: a fresh mktemp -d, printed on exit)
#   OPENSSL_BIN           openssl binary            (default: openssl)
#   GNUTLS_CLI/GNUTLS_SERV gnutls binaries          (default: gnutls-cli/-serv)
#   NGTCP2_EXAMPLES_DIR   dir with gtlsclient/gtlsserver, for external QUIC
#
# The `ci` profile keeps both roles, both transports, every negative row, and
# every cipher suite, but reduces the positive record matrix to one
# representative group/signature per suite plus a full sweep on the baseline
# suite. See docs/TLS_INTEROP_MATRIX.md for what each profile covers and why.
set -u

here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

profile="${TLS_INTEROP_PROFILE:-full}"
list_only=0
while [ $# -gt 0 ]; do
  case "$1" in
    --profile) profile="${2:?--profile needs ci|full}"; shift 2 ;;
    --list) list_only=1; shift ;;
    -h|--help) sed -n '2,35p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
case "$profile" in
  ci|full) ;;
  *) echo "unknown profile: $profile (want ci or full)" >&2; exit 2 ;;
esac

openssl_bin="${OPENSSL_BIN:-openssl}"
gnutls_cli="${GNUTLS_CLI:-gnutls-cli}"
gnutls_serv="${GNUTLS_SERV:-gnutls-serv}"

workdir="${TLS_INTEROP_WORKDIR:-$(mktemp -d)}"
certs="$workdir/certs"
logs="$workdir/logs"
transcripts="$workdir/transcripts"
mkdir -p "$certs" "$logs" "$transcripts"

tls_tool="$repo/zig-out/bin/tls_interop_tool"
h3_tool="$repo/zig-out/bin/h3_interop_tool"

pass=0
fail=0
skip=0
failed_rows=()

say() { printf '%s\n' "$*"; }

result() { # name status [detail]
  case "$2" in
    PASS) pass=$((pass + 1)) ;;
    FAIL) fail=$((fail + 1)); failed_rows+=("$1") ;;
    SKIP) skip=$((skip + 1)) ;;
  esac
  printf '%-64s %-4s %s\n' "$1" "$2" "${3:-}"
}

port=25100
# Assigns the global rather than echoing: `p=$(next_port)` would run in a
# subshell and leave `port` unchanged, so every row would reuse one port and
# collide with the previous row's lingering listener.
next_port() { port=$((port + 1)); }

# Wait for the native tool's own readiness line rather than sleeping: loading
# an RSA identity takes over a second, and a fixed sleep would race it.
wait_for_native_listener() { # logfile
  local i
  for i in $(seq 1 150); do
    grep -q 'tls-interop: listening' "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# Wait on the external server's own readiness output. Deliberately *not* a
# `nc -z` connect probe: `openssl s_server -naccept 1` serves exactly one
# connection, and the probe would consume it, leaving the row's real client
# with nothing to talk to.
wait_for_peer_listener() { # logfile pattern
  local i
  for i in $(seq 1 150); do
    grep -qi "$2" "$1" 2>/dev/null && return 0
    sleep 0.1
  done
  return 1
}

# ── matrix vocabulary ───────────────────────────────────────────────────────
# These names are the ones tests/tls_interop_matrix.zig parses; the OpenSSL and
# GnuTLS spellings beside them are how each peer names the same identifier.

suites=(aes128-gcm-sha256 aes256-gcm-sha384 chacha20-poly1305-sha256)
groups=(x25519 secp256r1)
signatures=(ed25519 ecdsa-p256-sha256 rsa-pss-rsae-sha256)

openssl_suite() {
  case "$1" in
    aes128-gcm-sha256) echo TLS_AES_128_GCM_SHA256 ;;
    aes256-gcm-sha384) echo TLS_AES_256_GCM_SHA384 ;;
    chacha20-poly1305-sha256) echo TLS_CHACHA20_POLY1305_SHA256 ;;
  esac
}
openssl_group() {
  case "$1" in
    x25519) echo X25519 ;;
    secp256r1) echo P-256 ;;
  esac
}
openssl_sigalg() {
  case "$1" in
    ed25519) echo ed25519 ;;
    ecdsa-p256-sha256) echo ecdsa_secp256r1_sha256 ;;
    rsa-pss-rsae-sha256) echo rsa_pss_rsae_sha256 ;;
  esac
}
# GnuTLS selects a TLS 1.3 ciphersuite from its cipher plus its hash, so a
# suite contributes two priority tokens.
gnutls_suite() {
  case "$1" in
    aes128-gcm-sha256) echo "+AES-128-GCM:+SHA256" ;;
    aes256-gcm-sha384) echo "+AES-256-GCM:+SHA384" ;;
    chacha20-poly1305-sha256) echo "+CHACHA20-POLY1305:+SHA256" ;;
  esac
}
gnutls_group() {
  case "$1" in
    x25519) echo "+GROUP-X25519" ;;
    secp256r1) echo "+GROUP-SECP256R1" ;;
  esac
}
gnutls_sign() {
  case "$1" in
    ed25519) echo "+SIGN-EDDSA-ED25519" ;;
    ecdsa-p256-sha256) echo "+SIGN-ECDSA-SECP256R1-SHA256" ;;
    rsa-pss-rsae-sha256) echo "+SIGN-RSA-PSS-RSAE-SHA256" ;;
  esac
}
gnutls_priority() { # suite group signature
  echo "NONE:+VERS-TLS1.3:$(gnutls_suite "$1"):+AEAD:$(gnutls_group "$2"):$(gnutls_sign "$3"):+CTYPE-X509"
}

# The signature dimension picks the credential, exactly as
# `identityKeyForSignature` in tests/tls_interop_matrix.zig says it must.
cert_for_signature() {
  case "$1" in
    ed25519) echo "$certs/ed25519" ;;
    ecdsa-p256-sha256) echo "$certs/p256" ;;
    rsa-pss-rsae-sha256) echo "$certs/rsa2048" ;;
  esac
}

# The reduced CI profile: every suite and both roles survive, but the
# group/signature sweep collapses to one representative pairing per suite. The
# baseline suite still walks the full sweep, so a regression in any single
# group or signature is still caught somewhere in CI.
row_in_ci_profile() { # suite group signature
  [ "$1" = "aes128-gcm-sha256" ] && return 0
  [ "$2" = "x25519" ] && [ "$3" = "ed25519" ] && return 0
  return 1
}

# ── row runners ─────────────────────────────────────────────────────────────

# native TLS server <- external client
run_server_row() { # name peer suite group signature [extra native args...]
  local name="$1" peer="$2" suite="$3" group="$4" sig="$5"
  shift 5
  local p log cert peer_groups
  next_port; p="$port"
  log="$logs/${name//\//_}"
  cert="$(cert_for_signature "$sig")"
  # An HRR row wants the peer to offer its first key share for a group the
  # native server does not accept; ordinary rows offer the row's own group.
  peer_groups="$(openssl_group "$group")"
  case " $* " in *" --expect-hrr "*) peer_groups="P-384:$(openssl_group "$group")" ;; esac

  "$tls_tool" server --port "$p" --cert "$cert-cert.pem" --key "$cert-key.pem" \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --alpn http/1.1 --transcript "$transcripts/${name//\//_}.txt" \
    --timeout-ms 20000 "$@" > "$log.native" 2>&1 &
  local native_pid=$!
  if ! wait_for_native_listener "$log.native"; then
    kill "$native_pid" 2>/dev/null
    result "$name" FAIL "native listener never came up"
    return
  fi

  case "$peer" in
    openssl)
      printf 'GET / HTTP/1.0\r\n\r\n' | "$openssl_bin" s_client -connect "127.0.0.1:$p" \
        -servername tardigrade.test -tls1_3 \
        -ciphersuites "$(openssl_suite "$suite")" -groups "$peer_groups" \
        -sigalgs "$(openssl_sigalg "$sig")" -alpn http/1.1 \
        -CAfile "$cert-cert.pem" > "$log.peer" 2>&1
      ;;
    gnutls)
      printf 'GET / HTTP/1.0\r\n\r\n' | "$gnutls_cli" --port "$p" \
        --x509cafile "$cert-cert.pem" --alpn=http/1.1 --sni-hostname=tardigrade.test \
        --priority "$(gnutls_priority "$suite" "$group" "$sig")" 127.0.0.1 > "$log.peer" 2>&1
      ;;
  esac

  if wait "$native_pid"; then
    result "$name" PASS "$(grep -o 'suite=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
}

# native TLS client -> external server
run_client_row() { # name peer suite group signature [extra native args...]
  local name="$1" peer="$2" suite="$3" group="$4" sig="$5"
  shift 5
  local p log cert peer_pid
  next_port; p="$port"
  log="$logs/${name//\//_}"
  cert="$(cert_for_signature "$sig")"

  case "$peer" in
    openssl)
      "$openssl_bin" s_server -accept "$p" -cert "$cert-cert.pem" -key "$cert-key.pem" \
        -tls1_3 -ciphersuites "$(openssl_suite "$suite")" -groups "$(openssl_group "$group")" \
        -sigalgs "$(openssl_sigalg "$sig")" -alpn http/1.1 -www -naccept 1 > "$log.peer" 2>&1 &
      peer_pid=$!
      wait_for_peer_listener "$log.peer" '^ACCEPT'
      ;;
    gnutls)
      "$gnutls_serv" --port "$p" --http --x509certfile "$cert-cert.pem" \
        --x509keyfile "$cert-key.pem" --alpn=http/1.1 \
        --priority "$(gnutls_priority "$suite" "$group" "$sig")" > "$log.peer" 2>&1 &
      peer_pid=$!
      wait_for_peer_listener "$log.peer" 'listening on ipv4'
      ;;
  esac

  "$tls_tool" client --host 127.0.0.1 --port "$p" --pin "$cert-cert.pem" \
    --server-name tardigrade.test \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --alpn http/1.1 --expect-alpn http/1.1 --expect-contains "HTTP/1.0 200" \
    --transcript "$transcripts/${name//\//_}.txt" \
    --timeout-ms 20000 "$@" > "$log.native" 2>&1
  local status=$?

  kill "$peer_pid" 2>/dev/null
  wait "$peer_pid" 2>/dev/null

  if [ $status -eq 0 ]; then
    result "$name" PASS "$(grep -o 'suite=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
}

# A negative row: the native side is expected to fail, with a named alert when
# the standard defines one. `native_args` and `peer_cmd` are supplied per row.
run_negative_server_row() { # name expect_alert native_args... -- peer_cmd...
  local name="$1"; shift
  local expect_alert="$1"; shift
  local native_args=()
  while [ "$1" != "--" ]; do native_args+=("$1"); shift; done
  shift
  local p log
  next_port; p="$port"
  log="$logs/${name//\//_}"

  # An unset-vs-empty array expands to nothing under `set -u` on bash 3.2
  # (still the system bash on macOS), so a row with no expected alert is
  # folded into `native_args` rather than expanded as its own empty array.
  if [ -n "$expect_alert" ]; then
    native_args=(--expect-alert "$expect_alert" "${native_args[@]}")
  fi

  "$tls_tool" server --port "$p" --cert "$certs/ed25519-cert.pem" --key "$certs/ed25519-key.pem" \
    --expect fail "${native_args[@]}" \
    --transcript "$transcripts/${name//\//_}.txt" --timeout-ms 20000 > "$log.native" 2>&1 &
  local native_pid=$!
  if ! wait_for_native_listener "$log.native"; then
    kill "$native_pid" 2>/dev/null
    result "$name" FAIL "native listener never came up"
    return
  fi

  # The peer command receives the port as $PORT.
  PORT="$p" CERT="$certs/ed25519-cert.pem" bash -c "$*" > "$log.peer" 2>&1

  if wait "$native_pid"; then
    result "$name" PASS "$(grep -o 'error=.*' "$log.native" | head -1)"
  else
    result "$name" FAIL "see $log.native"
  fi
}

# ── preflight ───────────────────────────────────────────────────────────────

if [ "$list_only" -eq 1 ]; then
  say "profile: $profile"
  for suite in "${suites[@]}"; do
    for group in "${groups[@]}"; do
      for sig in "${signatures[@]}"; do
        if [ "$profile" = "ci" ] && ! row_in_ci_profile "$suite" "$group" "$sig"; then continue; fi
        say "positive  $suite/$group/$sig"
      done
    done
  done
  exit 0
fi

for tool in "$tls_tool" "$h3_tool"; do
  if [ ! -x "$tool" ]; then
    say "building $(basename "$tool")..."
    (cd "$repo" && zig build build-tls-interop build-h3-interop) || {
      say "cannot build the interop tools"; exit 1;
    }
  fi
done

if ! command -v "$openssl_bin" >/dev/null 2>&1; then
  say "openssl is required for the #338 conformance matrix (set OPENSSL_BIN)"
  exit 1
fi
have_gnutls=0
if command -v "$gnutls_cli" >/dev/null 2>&1 && command -v "$gnutls_serv" >/dev/null 2>&1; then
  have_gnutls=1
fi

say "generating interop certificates in $certs"
"$here/gen-certs.sh" "$certs" >/dev/null || { say "certificate generation failed"; exit 1; }

say ""
say "shared-TLS-engine conformance matrix (#338), profile=$profile"
say "workdir: $workdir"
say "openssl: $("$openssl_bin" version)"
if [ "$have_gnutls" -eq 1 ]; then
  say "gnutls:  $("$gnutls_cli" --version | head -1)"
else
  say "gnutls:  not found -- the independent-implementation rows will be skipped"
fi
say ""

# ── 1. positive record-transport matrix, both roles, both peers ─────────────

say "== record transport: positive tuples =="
for suite in "${suites[@]}"; do
  for group in "${groups[@]}"; do
    for sig in "${signatures[@]}"; do
      if [ "$profile" = "ci" ] && ! row_in_ci_profile "$suite" "$group" "$sig"; then continue; fi
      tuple="$suite/$group/$sig"
      run_server_row "record/server/openssl/$tuple" openssl "$suite" "$group" "$sig"
      run_client_row "record/client/openssl/$tuple" openssl "$suite" "$group" "$sig"
      if [ "$have_gnutls" -eq 1 ]; then
        run_server_row "record/server/gnutls/$tuple" gnutls "$suite" "$group" "$sig"
        run_client_row "record/client/gnutls/$tuple" gnutls "$suite" "$group" "$sig"
      else
        result "record/server/gnutls/$tuple" SKIP "gnutls not installed"
        result "record/client/gnutls/$tuple" SKIP "gnutls not installed"
      fi
    done
  done
done

# ── 2. HelloRetryRequest, both roles ────────────────────────────────────────

say ""
say "== record transport: HelloRetryRequest =="
# The peer's first key share is for P-384, a group the native server does not
# accept, so the server must retry with one it does rather than fail
# (`run_server_row` widens the peer's `-groups` for any `--expect-hrr` row).
# This row is what caught the middlebox-compatibility change_cipher_spec
# rejection after HelloRetryRequest (#338).
run_server_row "record/server/openssl/hrr" openssl aes128-gcm-sha256 x25519 ed25519 --expect-hrr
# The native client omits its initial key share, forcing the peer to retry.
run_client_row "record/client/openssl/hrr" openssl aes128-gcm-sha256 x25519 ed25519 \
  --empty-initial-key-share --expect-hrr

# ── 3. negative conformance rows ────────────────────────────────────────────

say ""
say "== record transport: negative conformance =="

# RFC 7301 §3.2: no mutually supported protocol is fatal no_application_protocol.
run_negative_server_row "record/negative/alpn_no_overlap" no_application_protocol \
  --alpn h2 -- \
  'printf x | '"$openssl_bin"' s_client -connect 127.0.0.1:$PORT -servername tardigrade.test -tls1_3 -alpn http/1.1 -CAfile $CERT'

# RFC 8446 §4.2.1: a TLS 1.2 ClientHello carries no supported_versions, so a
# TLS-1.3-only server rejects it before any version can be negotiated.
run_negative_server_row "record/negative/tls12_downgrade" missing_extension \
  --alpn http/1.1 -- \
  'printf x | '"$openssl_bin"' s_client -connect 127.0.0.1:$PORT -tls1_2 -CAfile $CERT'

# No mutually supported cipher suite: the server has nothing to select.
run_negative_server_row "record/negative/cipher_no_overlap" handshake_failure \
  --cipher-suite chacha20-poly1305-sha256 --alpn http/1.1 -- \
  'printf x | '"$openssl_bin"' s_client -connect 127.0.0.1:$PORT -servername tardigrade.test -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -alpn http/1.1 -CAfile $CERT'

# No mutually supported group: neither the offered share nor a retry can help.
run_negative_server_row "record/negative/group_no_overlap" handshake_failure \
  --group x25519 --alpn http/1.1 -- \
  'printf x | '"$openssl_bin"' s_client -connect 127.0.0.1:$PORT -servername tardigrade.test -tls1_3 -groups P-384 -alpn http/1.1 -CAfile $CERT'

# No signature scheme the server's Ed25519 credential can satisfy
# (RFC 8446 §4.4.2.2 -> handshake_failure).
run_negative_server_row "record/negative/signature_no_overlap" handshake_failure \
  --signature ed25519 --alpn http/1.1 -- \
  'printf x | '"$openssl_bin"' s_client -connect 127.0.0.1:$PORT -servername tardigrade.test -tls1_3 -sigalgs rsa_pss_rsae_sha256 -alpn http/1.1 -CAfile $CERT'

# A ClientHello with no SNI against a server that requires one.
run_negative_server_row "record/negative/sni_absent" "" \
  --require-sni --alpn http/1.1 -- \
  'printf x | '"$openssl_bin"' s_client -connect 127.0.0.1:$PORT -noservername -tls1_3 -alpn http/1.1 -CAfile $CERT'

# Malformed record ordering: an application_data record arriving before any
# ClientHello must be rejected, not buffered until keys exist. Written straight
# to the socket rather than through a TLS client -- piping these bytes to
# `openssl s_client` would send them as post-handshake application data, which
# is a different (and legal) thing entirely.
run_negative_server_row "record/negative/malformed_ordering" "" \
  --alpn http/1.1 --allow-absent-alpn --expect-error UnexpectedRecordContent -- \
  'printf "\x17\x03\x03\x00\x05hello" > /dev/tcp/127.0.0.1/$PORT'

# A middlebox-compat change_cipher_spec with no ClientHello before it. RFC 8446
# §5.1 only tolerates that record *after* a ClientHello has been accepted, so
# the compatibility window must stay shut here -- the companion to the
# post-HelloRetryRequest widening this change makes.
run_negative_server_row "record/negative/ccs_before_clienthello" "" \
  --alpn http/1.1 --allow-absent-alpn --expect-error UnexpectedRecordContent -- \
  'printf "\x14\x03\x03\x00\x01\x01" > /dev/tcp/127.0.0.1/$PORT'

# The native client must reject a server certificate it did not pin.
negative_client_pin() {
  local p log
  next_port; p="$port"
  log="$logs/record_negative_wrong_pin"
  "$openssl_bin" s_server -accept "$p" -cert "$certs/p256-cert.pem" -key "$certs/p256-key.pem" \
    -tls1_3 -alpn http/1.1 -www -naccept 1 > "$log.peer" 2>&1 &
  local peer_pid=$!
  wait_for_peer_listener "$log.peer" '^ACCEPT'
  # Pins the Ed25519 leaf while the peer presents the P-256 one.
  "$tls_tool" client --host 127.0.0.1 --port "$p" --pin "$certs/ed25519-cert.pem" \
    --server-name tardigrade.test --alpn http/1.1 \
    --expect fail --expect-error CertificateInvalid --expect-alert bad_certificate \
    --transcript "$transcripts/record_negative_wrong_pin.txt" --timeout-ms 20000 > "$log.native" 2>&1
  local status=$?
  kill "$peer_pid" 2>/dev/null; wait "$peer_pid" 2>/dev/null
  if [ $status -eq 0 ]; then
    result "record/negative/wrong_pinned_certificate" PASS "$(grep -o 'error=.*' "$log.native" | head -1)"
  else
    result "record/negative/wrong_pinned_certificate" FAIL "see $log.native"
  fi
}
negative_client_pin

# ── 4. QUIC transport: the same tuples through the same engine ──────────────

say ""
say "== QUIC transport: the same tuples =="
# The record rows above and these QUIC rows share one policy builder
# (tests/tls_interop_matrix.zig), so a tuple name means the same engine
# configuration on either transport. External QUIC peers (ngtcp2, quiche,
# aioquic) have their own richer H3 matrix in run-interop.sh; here we prove the
# negotiation tuple itself traverses the QUIC transport.
run_quic_row() { # suite group signature
  local suite="$1" group="$2" sig="$3"
  local name="quic/loopback/$suite/$group/$sig"
  local p log cert
  next_port; p="$port"
  log="$logs/${name//\//_}"
  cert="$(cert_for_signature "$sig")"

  "$h3_tool" server --port "$p" --cert "$cert-cert.pem" --key "$cert-key.pem" \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --timeout-ms 20000 > "$log.server" 2>&1 &
  local server_pid=$!
  sleep 1
  "$h3_tool" client --host 127.0.0.1 --port "$p" --pin "$cert-cert.der" \
    --cipher-suite "$suite" --group "$group" --signature "$sig" \
    --timeout-ms 20000 > "$log.client" 2>&1
  local status=$?
  wait "$server_pid"
  local server_status=$?
  if [ $status -eq 0 ] && [ $server_status -eq 0 ]; then
    result "$name" PASS "$(grep -o 'suite=.*' "$log.client" | head -1)"
  else
    result "$name" FAIL "see $log.client / $log.server"
  fi
}

for suite in "${suites[@]}"; do
  for group in "${groups[@]}"; do
    for sig in "${signatures[@]}"; do
      if [ "$profile" = "ci" ] && ! row_in_ci_profile "$suite" "$group" "$sig"; then continue; fi
      # Ed25519 is not offered by every QUIC peer's default verifier, but the
      # loopback rows pin the leaf directly, so every signature is reachable.
      run_quic_row "$suite" "$group" "$sig"
    done
  done
done

if [ -n "${NGTCP2_EXAMPLES_DIR:-}" ]; then
  say ""
  say "external QUIC peers are configured; run scripts/interop/run-interop.sh"
  say "for the full H3 peer matrix (ngtcp2/quiche/aioquic, both directions)."
fi

# ── summary ─────────────────────────────────────────────────────────────────

say ""
say "----------------------------------------------------------------"
printf 'pass=%d fail=%d skip=%d\n' "$pass" "$fail" "$skip"
say "logs:        $logs"
say "transcripts: $transcripts"
if [ "$fail" -gt 0 ]; then
  say ""
  say "failed rows:"
  for row in "${failed_rows[@]}"; do say "  $row"; done
  exit 1
fi
exit 0

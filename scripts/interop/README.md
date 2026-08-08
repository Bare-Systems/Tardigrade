# Native HTTP/3 external interoperability suite (#247 / #328 gate)

Focused out-of-process interop tests for the native Zig QUIC/HTTP-3 stack
(`src/quic/` + `src/http3/`). External implementations run as **separate
processes**; nothing foreign links into Tardigrade.

> **Looking for the TLS conformance matrix?** `run-tls-interop.sh` (#338) is
> the broad suite: the shared TLS 1.3 engine as both client and server, over
> both the record and QUIC transports, across every supported
> cipher-suite/group/signature tuple, against OpenSSL and GnuTLS, plus the
> negative rows that pin the RFC 8446 §6 failure class. See
> [`docs/TLS_INTEROP_MATRIX.md`](../../docs/TLS_INTEROP_MATRIX.md). This file
> documents the narrower HTTP/3 *peer* matrix, which that suite links to rather
> than duplicates.

## What it exercises

For every peer, in both directions where practical: QUIC v1 + TLS 1.3
handshake, ALPN `h3`, transport parameters (including the RFC 9000 §7.3
CID authentication binding), control streams + SETTINGS, one request and
response with QPACK HEADERS and DATA, and a clean connection close/drain.

Matrix (`run-interop.sh`):

| # | client                | server               | required for #328 |
|---|-----------------------|----------------------|-------------------|
| 1 | native `h3_interop_tool` | ngtcp2 `gtlsserver` | yes |
| 2 | ngtcp2 `gtlsclient`   | native `h3_interop_tool` | yes |
| 3 | native `h3_interop_tool` | quiche `http3-server` | yes |
| 4 | quiche `http3-client` | native `h3_interop_tool` | yes |
| 5 | native `h3_interop_tool` | aioquic             | optional |
| 6 | aioquic               | native `h3_interop_tool` | optional |
| 7 | native HRR client (`h3_interop_tool --empty-initial-key-share`) | ngtcp2 `gtlsserver` | #333 closure |
| 8 | ngtcp2 HRR `gtlsclient` (`--groups=-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:%NO_SHUFFLE_EXTENSIONS`) | native `h3_interop_tool --expect-hrr` | #333 closure |

## #333: focused HelloRetryRequest smoke evidence

The matrix includes two bounded, out-of-process HRR smokes that close the
remaining #333 evidence gap without expanding this script into #338's broad
conformance suite:

- `#333 native HRR client -> ngtcp2 gtlsserver` runs the native client with
  `--empty-initial-key-share`. The ClientHello still advertises X25519, but
  carries an empty initial key-share vector, so the external GnuTLS server must
  send HelloRetryRequest before the HTTP/3 request can complete. The native
  tool asserts `--expect-hrr` by checking its TLS retry state and logs
  `tls retry_state=hrr_received`.
- `#333 ngtcp2 HRR gtlsclient -> native server` runs the external GnuTLS
  client with
  `--groups=-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:%NO_SHUFFLE_EXTENSIONS`
  and the `GNUTLS_KEY_SHARE_TOP` / `%NO_SHUFFLE_EXTENSIONS` patches applied by
  `build-h3-peer-ci.sh`. That keeps X25519 advertised while sending only the
  first P-256 key share in ClientHello1, and keeps ClientHello2 extension order
  deterministic; the native server supports/selects X25519, emits
  HelloRetryRequest, accepts ClientHello2, and completes the HTTP/3 exchange.
  The native server asserts `--expect-hrr` and logs
  `tls hello_retry_request=true`.

Prerequisites are the pinned nghttp3 `v1.18.0` and ngtcp2 `v1.25.0`
GnuTLS example builds documented below, built with GnuTLS >= 3.8.1,
supporting both `GNUTLS_KEY_SHARE_TOP` and `%NO_SHUFFLE_EXTENSIONS`
(CI currently uses 3.8.3). The easiest reproducible build path is:

```sh
scripts/interop/install-h3-peer-deps-ci.sh
H3_PEER_WORKDIR=/tmp/tardigrade-h3-peer scripts/interop/build-h3-peer-ci.sh
gnutls-cli --version
```

Then run the normal matrix command:

```sh
zig build build-h3-interop
NGTCP2_EXAMPLES_DIR=/tmp/tardigrade-h3-peer/client/build/examples \
  scripts/interop/run-interop.sh
```

The exact single-case commands are:

```sh
# native HRR client against external server
mkdir -p /tmp/tardi-hrr/certs /tmp/tardi-hrr/docroot
scripts/interop/gen-certs.sh /tmp/tardi-hrr/certs
printf '%s\n' hello-from-ngtcp2-hrr >/tmp/tardi-hrr/docroot/hrr.txt
/path/to/ngtcp2/build/examples/gtlsserver 127.0.0.1 24434 \
  /tmp/tardi-hrr/certs/ed25519-key.pem \
  /tmp/tardi-hrr/certs/ed25519-cert.pem \
  -d /tmp/tardi-hrr/docroot --quiet \
  >/tmp/tardi-hrr/gtlsserver-hrr.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
sleep 1.5
zig-out/bin/h3_interop_tool client --host 127.0.0.1 --port 24434 \
  --authority tardigrade.test --path /hrr.txt --insecure \
  --empty-initial-key-share --expect-hrr --timeout-ms 10000
kill "$server_pid" 2>/dev/null || true
wait "$server_pid" 2>/dev/null || true
trap - EXIT

# external HRR client against native server
zig-out/bin/h3_interop_tool server --port 24435 \
  --cert /tmp/tardi-hrr/certs/ed25519-cert.der \
  --key /tmp/tardi-hrr/certs/ed25519-key.pkcs8.der \
  --expect-hrr --timeout-ms 15000 \
  >/tmp/tardi-hrr/native-server-hrr.log 2>&1 &
server_pid=$!
trap 'kill "$server_pid" 2>/dev/null || true' EXIT
sleep 1.5
/path/to/ngtcp2/build/examples/gtlsclient \
  --groups=-GROUP-ALL:+GROUP-SECP256R1:+GROUP-X25519:%NO_SHUFFLE_EXTENSIONS \
  127.0.0.1 24435 https://tardigrade.test/from-ngtcp2-hrr \
  --exit-on-first-stream-close
wait "$server_pid"
trap - EXIT
```

The matrix logs stdout/stderr for each side under the printed `logs:` path.
They contain request/response status and the explicit HRR assertion lines
above, but no keylog output or secret material.

## #522: production resumption/0-RTT interop

The matrix above proves baseline wire interoperability against the direct
`Tls13Backend -> quic.Connection -> H3.Conn` harness (`h3_interop_tool`
server mode). It does **not** exercise resumption, 0-RTT, or the shared
HTTP early-data safety policy — those require the real production
`http3_runtime.Runtime` composition (native resumption runtime,
process-local replay gate, HTTP early-data policy engine), which only the
actual Tardigrade edge-gateway binary assembles.

`tests/integration.zig`'s `h3interop.quic.*` cases (run via
`zig build test-integration-resumption-interop`, same step as the
`interop.openssl.*`/`restart.*`/`soak.*` cases — `h3interop.` contains the
`interop.` filter substring) drive the real `tardi` binary, with
`TARDIGRADE_HTTP3_ENABLED`/`TARDIGRADE_HTTP3_ENABLE_0RTT` set, against the
canonical ngtcp2/GnuTLS `gtlsclient` peer — the same binary this matrix
already builds. Point `H3_INTEROP_CLIENT_PATH` at it (a peer-agnostic name:
`tests/integration.zig` isn't scanned by `scripts/audit-dependencies.sh`,
but the CI workflow that sets this variable is, so it deliberately doesn't
carry the peer's own name):

```sh
H3_INTEROP_CLIENT_PATH=/path/to/ngtcp2/build/examples/gtlsclient \
  zig build test-integration-resumption-interop
```

CI runs `scripts/interop/install-h3-peer-deps-ci.sh` then
`scripts/interop/build-h3-peer-ci.sh` to build the pinned ngtcp2/nghttp3
GnuTLS examples. It exports `H3_INTEROP_CLIENT_PATH` before running the same
target with `-Dtls-profile=general`, then passes the peer-neutral
`H3_PEER_EXAMPLES_DIR` output to `scripts/interop/run-h3-peer-ci.sh`. That
wrapper runs the bounded external-peer matrix and asserts both #333 HRR lines
are present as `PASS`:

```text
#333 native HRR client -> ngtcp2 gtlsserver PASS
#333 ngtcp2 HRR gtlsclient -> native server PASS
```

Both scripts live under
`scripts/interop/` specifically because that directory is the policy-exempt
external-peer boundary the dependency audit (`scripts/audit-dependencies.sh`)
excludes -- the peer's actual repository/library names would otherwise trip
the audit if written into `.github/workflows/ci.yml` directly. The pins
default to nghttp3 `v1.18.0` and ngtcp2 `v1.25.0`; override
`H3_PEER_LIB_REF`/`H3_PEER_CLIENT_REF` only when deliberately advancing the
interop peer. ngtcp2 v1.25.0's C++23 example client needs clang >= 19 or
gcc >= 15 (its own README documents this); `install-h3-peer-deps-ci.sh`
installs clang-19 from apt.llvm.org since Ubuntu's default repos don't yet
carry it.

Unlike the wire-interop matrix above, these cases require the **`.general`**
TLS build profile (the default `zig build`, no `-Dtls-profile` flag): the
appliance profile (`-Dtls-profile=appliance`) explicitly rejects
`TARDIGRADE_HTTP3_ENABLE_0RTT` at config-validation time
(`edge_config.zig`'s `validateApplianceTlsProfile`), and QUIC's credential
provider (`native_tls_connection.NativeCredentialStore`) is itself only
constructed under that profile in `edge_gateway.zig`. Cases:

- `h3interop.quic.resume` — authoritative 1-RTT resumption (`tardigrade_tls_
  resumption_outcome_total{transport="quic",outcome="accepted"}`), not
  0-RTT.
- `h3interop.quic.early.accepted` — a real `type=0RTT` QUIC packet accepted
  end to end through the production H3 runtime and the shared HTTP
  early-data policy, with a real upstream execution observed exactly once.
- `h3interop.quic.early.unsafe_425` — a POST offered as early data is
  425'd by the same shared HTTP-level policy H1/H2 use, before any upstream
  side effect. The test also follows with an ordinary post-handshake H3
  request proving the same route still executes normally. `gtlsclient`
  cannot express mixed "early POST, then ordinary GET" streams on one
  connection because method/body are invocation-wide and `--delay-stream`
  applies to every stream; the production H3 runtime's same-connection
  post-425 behavior is covered by the deterministic `http3 (#523): ...`
  runtime test.
- `h3interop.quic.early.replay_fallback` — the same early ticket replayed
  within one process is rejected by the process-local replay gate
  (`tardigrade_tls_early_data_replay_total{outcome="duplicate"}`), not
  re-executed as 0-RTT, and the peer's in-connection 1-RTT fallback
  remains usable afterward.

Known **not** externally reachable through today's production
configuration surface (verified directly against the running server, not
assumed) — see the #522 PR body for the full writeup:

- **replay-store-unavailable fail-closed**: `Runtime`'s `zeroRttCarrierEnabled`
  couples replay-gate presence directly to whether the 0-RTT carrier is
  enabled at all, so "resumption + 0-RTT on, replay gate absent" collapses
  to the already-deterministically-covered `.disabled`/`keys_unavailable`
  state rather than a distinct `replay_unavailable` outcome.
- **H3 SETTINGS incompatibility**: `edge_gateway.zig` never threads an
  operator-facing H3-SETTINGS config surface into `Runtime.Config.h3_
  settings`; it always uses the compiled-in defaults.
- **QUIC transport-parameter incompatibility**: `quicConfigFrom` in
  `http3_runtime.zig` maps only `max_datagram_size` and `zero_rtt_enabled`
  from operator config; `initial_max_data`/stream/stream-count/
  `active_connection_id_limit` stay at their compile-time defaults.

`gtlsclient` sends the literal string `"localhost"` as TLS SNI whenever the
connect host is a numeric IP address, regardless of `--sni` (every
`tls_client_session_*.cc` backend in the checked-out ngtcp2 source has this
fallback) — the test identity is registered under both names via
`TARDIGRADE_TLS_SNI_CERTS`.

## Certificates

`gen-certs.sh` produces two self-signed identities:

- **Ed25519** — the native stack's primary profile; used with GnuTLS-based
  peers (ngtcp2 examples) and aioquic.
- **ECDSA P-256** — used when the *client* is BoringSSL-based (quiche):
  BoringSSL's default verifier does not offer Ed25519 in
  `signature_algorithms`, so the server identity must be P-256 there.

The native tool takes DER cert/key; external peers take PEM.

## Building the peers

Everything below stays outside the Tardigrade build graph.

### ngtcp2 / nghttp3 (GnuTLS example client/server)

Needs `libgnutls28-dev` (GnuTLS >= 3.8.1; CI tested with 3.8.3),
`gnutls-bin`, `libev-dev`, cmake, and a C++23 compiler (clang >= 19 or
gcc >= 15 for `<print>`):

```sh
git clone --depth 1 --branch v1.18.0 https://github.com/ngtcp2/nghttp3 && cd nghttp3
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX -DENABLE_LIB_ONLY=ON
make -C build install
cd ../
git clone --depth 1 --branch v1.25.0 https://github.com/ngtcp2/ngtcp2 && cd ngtcp2
perl -0pi -e 's/GNUTLS_CLIENT \| GNUTLS_ENABLE_EARLY_DATA \|\n\s+GNUTLS_NO_END_OF_EARLY_DATA/GNUTLS_CLIENT | GNUTLS_ENABLE_EARLY_DATA |\n                                 GNUTLS_NO_END_OF_EARLY_DATA |\n                                 GNUTLS_KEY_SHARE_TOP/' examples/tls_client_session_gnutls.cc
gnutls-cli --version
PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig CC=clang-19 CXX=clang++-19 \
  cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=$PREFIX \
  -DENABLE_GNUTLS=ON -DENABLE_OPENSSL=OFF
make -C build
# peers: ngtcp2/build/examples/gtlsclient, .../gtlsserver
```

### quiche (crates.io, vendored BoringSSL)

```sh
cargo init quiche-peer && cd quiche-peer
cat >> Cargo.toml <<'EOF'
quiche = "0.24"
ring = "0.17"
log = "0.4"
env_logger = "0.10"
mio = { version = "0.8", features = ["net", "os-poll"] }
url = "2"
EOF
cargo fetch
mkdir -p examples
cp "$(find ~/.cargo/registry/src -maxdepth 2 -type d -name 'quiche-*' | head -1)"/examples/http3-{client,server}.rs examples/
cargo build --release --examples
# peers: target/release/examples/http3-client, .../http3-server
```

Note: the quiche example server hardcodes `127.0.0.1:4433` and
`examples/cert.crt` / `examples/cert.key` relative to its CWD;
`run-interop.sh` stages those.

### aioquic (optional)

```sh
python3 -m venv aioquic-venv && aioquic-venv/bin/pip install aioquic
```

## Running

```sh
zig build build-h3-interop
NGTCP2_EXAMPLES_DIR=/path/to/ngtcp2/build/examples \
QUICHE_EXAMPLES_DIR=/path/to/quiche-peer/target/release/examples \
AIOQUIC_PYTHON=/path/to/aioquic-venv/bin/python \
  scripts/interop/run-interop.sh
```

Unset peers are skipped. Per-direction logs (native driver events with
`--verbose`, peer stdout/stderr) land in the work dir printed at the end.

## Manual single runs

```sh
# native server for external clients
zig-out/bin/h3_interop_tool server --port 4433 \
  --cert certs/p256-cert.der --key certs/p256-key.pkcs8.der --verbose

# native client against any h3 server
zig-out/bin/h3_interop_tool client --host 127.0.0.1 --port 4433 \
  --authority tardigrade.test --path / --insecure --verbose
```

`--verbose` streams the connection driver's event log (packet tx/rx per
space, key discards, loss, PTO, state transitions, close) to stderr —
usually enough to localize an interop failure. For packet-level capture:
`tcpdump -i lo udp port 4433 -w interop.pcap` alongside a run, and decrypt
with the peer's keylog (native keylog lands with #255).

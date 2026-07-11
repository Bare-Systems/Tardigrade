# Native HTTP/3 external interoperability suite (#247 / #328 gate)

Focused out-of-process interop tests for the native Zig QUIC/HTTP-3 stack
(`src/quic/` + `src/http3/`). External implementations run as **separate
processes**; nothing foreign links into Tardigrade.

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

Needs `libgnutls28-dev` (>= 3.7.2), `libev-dev`, cmake, and a C++23 compiler
(g++ >= 14 for `<print>`):

```sh
git clone --depth 1 https://github.com/ngtcp2/nghttp3 && cd nghttp3
cmake -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$PREFIX -DENABLE_LIB_ONLY=ON
make -C build install
cd ../
git clone --depth 1 https://github.com/ngtcp2/ngtcp2 && cd ngtcp2
PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig CC=gcc-14 CXX=g++-14 \
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

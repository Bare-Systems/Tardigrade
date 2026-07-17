# QUIC TLS 1.3 backend strategy (#296, #329)

This note records the decision for how Tardigrade's pure-Zig QUIC stack drives a
TLS 1.3 handshake, and the staged migration behind the `QuicTlsAdapter` seam
(#249).

## Context

QUIC does not run TLS over a record/stream socket. TLS handshake messages are
carried inside QUIC CRYPTO frames, and TLS supplies QUIC with per-level traffic
secrets, AEAD/header-protection keys, ALPN, certificate state, the QUIC
transport-parameters extension, and key-update material. `QuicTlsAdapter`
(`src/quic/tls_adapter.zig`, #249) is the no-leak boundary for exactly this
material; the rest of `src/quic/` must never see a concrete TLS type.

## Decision

**The QUIC handshake driver is backend-agnostic, and reusable TLS 1.3 state now
lives under a protocol-neutral `src/tls/` core while the QUIC adapter keeps
CRYPTO-frame transport and packet-key installation.**

1. `src/quic/tls_handshake.zig` implements the connection-facing QUIC wrapper
   (`Handshake`) over the shared transport backend contract and generic core
   driver. The wrapper owns none of the TLS cryptography; it only routes
   handshake bytes through the adapter's CRYPTO streams, installs the secrets
   the backend exports at the correct phase, authenticates transport parameters,
   enforces ALPN `h3`, reports certificate state, and classifies failures into
   a typed `HandshakeError`.

2. `src/tls/` is the protocol-neutral TLS 1.3 core. `state.zig` defines roles,
   handshake states, and the explicit `quic` versus `record` transport modes;
   `handshake.zig` owns bounded handshake reassembly, the shared reader/writer,
   transcript updates, message ordering, and explicit traffic-secret epoch
   lifecycle; the QUIC backend consumes those codecs rather than defining a
   second wire-helper implementation;
   `events.zig` defines transport-neutral handshake byte, traffic-secret,
   certificate, ALPN, discard, completion, and TLS-level typed failure
   vocabulary shared by QUIC and future record mode; `transport.zig` defines
   the generic backend vtable and bounded event sink that carriers instantiate
   with their own epoch and transport-parameter payload types; `engine.zig`
   owns generic backend start/receive progression, lifecycle state, and failure
   capture over that contract; `tls13_backend.zig` owns the concrete reusable
   ClientHello, ServerHello, certificate, CertificateVerify, Finished,
   transcript, traffic-secret, and zeroization implementation; and
   `key_schedule.zig` owns the SHA-256 TLS 1.3 key schedule. None imports QUIC,
   HTTP, sockets, or OpenSSL. The concrete backend takes an explicit `.record`
   profile or an opaque extension profile, so record mode selects `h2` /
   `http/1.1` without seeing QUIC types or transport parameters.

3. `src/quic/tls_backend.zig` is a thin adapter from the TLS-owned engine to
   QUIC mode. It owns the RFC 9000 transport-parameter codec, CID binding,
   QUIC/shared epoch conversion, and QUIC error mapping. It configures the
   shared engine with opaque extension type 57 and ALPN `h3`; no TLS message,
   certificate, Finished, transcript, or key-schedule logic is duplicated in
   QUIC. The shared engine's first profile remains deliberately narrow:
   TLS_AES_128_GCM_SHA256 (the adapter's suite), X25519 key exchange, Ed25519
   server certificates (parsed/verified via `std.crypto.Certificate`), and
   pinned-certificate or explicit-insecure trust. The shared key schedule is
   validated against the RFC 8448 trace. Entropy is caller-supplied, like the
   rest of `src/quic/`.

4. A deterministic in-memory `TestTlsBackend` in `tls_handshake.zig` exercises
   the driver end to end. It is a fixture, not a TLS implementation, and it is
   the regression seam that later packet-layer and interop work (#247) build
   on. `src/tls/tls13_backend_tests.zig` separately constructs the concrete
   backend directly in `.record` mode and drives `PureZigRecordStream` across
   fragmented nonblocking socket pairs with ALPN `h2`, no QUIC import, and no
   transport-extension payload.

### Why not `std.crypto.tls`

Zig 0.16's `std.crypto.tls` is **client-only** (`std/crypto/tls/Client.zig`) and
is built around a TLS **record/stream** abstraction driven over a
`std.Io.Reader`/`Writer`. It exposes no way to:

- feed and drain raw handshake bytes (it owns the socket and the record layer),
- run the server role,
- export QUIC traffic secrets or install per-level keys,
- carry the QUIC `transport_parameters` extension or surface key-update events.

Backing QUIC with it would mean inverting QUIC around a TLS record socket — the
exact anti-pattern #242 called out. Its reusable primitives (`hkdfExpandLabel`,
cipher-suite and handshake enums, byte encoders) are still useful and are used
where appropriate, but its `Client` state machine cannot drive a QUIC handshake.

## Handshake phase ordering the driver enforces

- Initial keys exist before the handshake completes (installed from the client
  DCID by the connection layer, not by TLS) and carry Initial CRYPTO.
- Handshake read/write secrets are installed when TLS reaches the Handshake
  level; Initial keys are discarded once Handshake keys are available.
- 1-RTT read/write secrets are installed only after the handshake reaches the
  application traffic secrets.
- Handshake secrets are discarded on handshake confirmation, not merely once the
  first 1-RTT secret is installed.
- 0-RTT stays disabled unless config explicitly enables it, and 0-RTT never
  creates CRYPTO-stream data (the adapter rejects CRYPTO at the 0-RTT level).

## Transport parameters, ALPN, certificates

- Local transport parameters are encoded by the QUIC adapter before the first
  flight and supplied to the TLS engine as an opaque extension payload.
- Peer transport parameters are withheld from connection logic until the
  handshake authenticates them; missing, malformed, or illegal values fail with
  a typed `MissingTransportParameters` / `InvalidTransportParameters`.
- ALPN must negotiate exactly `h3`; anything else fails with `AlpnMismatch`
  rather than silently downgrading.
- The client validates the server certificate and reports
  `valid` / `invalid` / `not_checked`; `not_checked` is accepted at completion
  only when a caller explicitly opts into a local/insecure mode.

## Failure taxonomy and alert mapping

Every handshake failure is a typed `HandshakeError` value so it maps to exactly
one fatal TLS alert (`src/tls/alerts.zig`, RFC 8446 §6) and, in QUIC mode, one
`CRYPTO_ERROR` code (`0x0100 + alert`, RFC 9001 §4.8). Two distinct failure
classes must never collapse into one:

- **`MalformedHandshake` → `decode_error` (CRYPTO_ERROR + 0x32).** The bytes
  could not be decoded: a length was wrong or out of range, the message was
  truncated, or a field could not be parsed at all. This is a syntax/framing
  failure — the wire data itself is wrong.
- **`IllegalParameter` → `illegal_parameter` (CRYPTO_ERROR + 0x2f).** A field
  decoded cleanly but carries a value that is incorrect or inconsistent with
  other fields: a bad `legacy_version`, an unsupported cipher suite or named
  group, a non-null compression method, a key share of the wrong length or a
  low-order point, a HelloRetryRequest this profile never asks for, or a
  repeated extension type (RFC 8446 §4.2). The bytes conform to the formal
  syntax but are otherwise wrong.
- **`UnexpectedHandshakeMessage` → `unexpected_message` (CRYPTO_ERROR + 0x0a).**
  A syntactically valid handshake message arrived in the wrong state or for the
  wrong role — the bytes decode cleanly, but the ordering is illegal (for
  example a ServerHello where a Certificate was expected, a ClientHello a client
  should never receive, a second ClientHello once the server has moved on, or a
  server-only NewSessionTicket delivered to a server).

The line between the first two is exactly RFC 8446 §6's split between
`decode_error` (syntax/length) and `illegal_parameter` (syntactically valid but
semantically wrong).

These are all separate from the QUIC-local encryption-level failures. A CRYPTO
fragment delivered at a packet-number space a message never uses — 0-RTT, or a
handshake-flight message at the Initial level — is a `UnexpectedCryptoLevel`
error (a QUIC seam violation, RFC 9001 §4.1.3), owned by the QUIC handshake
driver rather than the TLS taxonomy; it never becomes a `decode_error`,
`illegal_parameter`, or `unexpected_message` alert. Other typed cases —
`AlpnMismatch` → `no_application_protocol`, `CertificateInvalid` →
`bad_certificate`, and the transport-parameter failures → the QUIC
`TRANSPORT_PARAMETER_ERROR` code — keep their own mappings. No generic
catch-all `MalformedHandshake` is returned for a known ordering or
illegal-value failure.

## Follow-ups

- Integrate the driver with the packet layer and connection state machine.
  This includes the connection-binding transport parameters
  (`initial_source_connection_id`, `original_destination_connection_id`,
  `retry_source_connection_id`, `stateless_reset_token`): carried through
  `config.CidBinding` — the connection driver commits its CIDs via
  `TlsBackend.setCidBinding` before the first flight and validates the peer's
  binding at handshake completion (RFC 9000 §7.3).
- Session resumption / 0-RTT (product decision), HelloRetryRequest, additional
  cipher suites and signature algorithms, and web-PKI certificate-chain
  validation in the pure-Zig backend.
- Fuzz and benchmark coverage (#247); external interop against ngtcp2/nghttp3, quiche, and aioquic runs out of process via `scripts/interop/run-interop.sh`.
- TLS key logging for local decryption (#255): `installSecret` is the single
  choke point where every traffic secret is installed, so the debug-only keylog
  `Sink` (`src/quic/keylog.zig`) is invoked there when `keylog_enabled`. Initial
  secrets are intentionally never logged. See `docs/QUIC_QLOG.md` for the
  sensitive/debug-only handling rules.

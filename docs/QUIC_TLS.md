# QUIC TLS 1.3 backend strategy (#296)

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

**The QUIC handshake driver is backend-agnostic, and the production TLS engine
is a pure-Zig TLS 1.3 implementation behind the runtime `TlsBackend`
interface.**

1. `src/quic/tls_handshake.zig` implements the connection-facing handshake
   driver (`Handshake`) plus the backend interface (`TlsBackend`) and event
   contract (`EventSink`). The driver owns none of the TLS cryptography; it only
   routes handshake bytes through the adapter's CRYPTO streams, installs the
   secrets the backend exports at the correct phase, authenticates transport
   parameters, enforces ALPN `h3`, reports certificate state, and classifies
   failures into a typed `HandshakeError`.

2. `src/quic/tls_backend.zig` is the concrete production backend: a TLS 1.3
   engine operating in QUIC mode, built entirely on `std.crypto` primitives
   (no external TLS library). It consumes and produces raw handshake messages
   per encryption level — there is no record layer; QUIC packet protection
   covers confidentiality — and exports traffic secrets, transport parameters,
   ALPN, and certificate state through the `EventSink`. Its first profile is
   deliberately narrow with one interoperable code path per choice:
   TLS_AES_128_GCM_SHA256 (the adapter's suite), X25519 key exchange, Ed25519
   server certificates (parsed/verified via `std.crypto.Certificate`), and
   pinned-certificate or explicit-insecure trust. The key schedule is validated
   against the RFC 8448 trace. Entropy is caller-supplied, like the rest of
   `src/quic/`.

3. A deterministic in-memory `TestTlsBackend` in `tls_handshake.zig` exercises
   the driver end to end. It is a fixture, not a TLS implementation, and it is
   the regression seam that later packet-layer and interop work (#247) build
   on. `src/quic/testdata/` holds a deterministic self-signed Ed25519
   certificate fixture for the real backend's tests.

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

- Local transport parameters are provided to the backend before the first flight.
- Peer transport parameters are withheld from connection logic until the
  handshake authenticates them; missing, malformed, or illegal values fail with
  a typed `MissingTransportParameters` / `InvalidTransportParameters`.
- ALPN must negotiate exactly `h3`; anything else fails with `AlpnMismatch`
  rather than silently downgrading.
- The client validates the server certificate and reports
  `valid` / `invalid` / `not_checked`; `not_checked` is accepted at completion
  only when a caller explicitly opts into a local/insecure mode.

## Follow-ups

- Integrate the driver with the packet layer and connection state machine.
  This includes the connection-binding transport parameters
  (`initial_source_connection_id`, `original_destination_connection_id`,
  `retry_source_connection_id`, `stateless_reset_token`): the backend's TP
  codec covers the `config.TransportParameters` subset, and per-connection CID
  material must be supplied by the connection layer when it wires up the
  driver — the handshake cannot authenticate CIDs it never sees.
- Session resumption / 0-RTT (product decision), HelloRetryRequest, additional
  cipher suites and signature algorithms, and web-PKI certificate-chain
  validation in the pure-Zig backend.
- Interop, fuzz, and benchmark coverage against ngtcp2/nghttp3 and quiche (#247).

# Shared TLS-engine interoperability and conformance matrix

Tracking issue: [#338](https://github.com/Bare-Systems/Tardigrade/issues/338)
(research story 323-J).

This suite proves that the TLS 1.3 engine Tardigrade ships — one engine, two
transports — interoperates with independent implementations across every
cipher-suite/group/signature tuple it claims to support, in **both** the client
and the server role, and that it fails in the way the standards require when
there is nothing to negotiate.

It complements rather than replaces:

- [`RESUMPTION_TEST_PLAN.md`](RESUMPTION_TEST_PLAN.md) (#369) — resumption and
  0-RTT behaviour through the full gateway process.
- `scripts/interop/run-interop.sh` (#247) — the HTTP/3 peer matrix against
  ngtcp2, quiche, and aioquic.

## Running it

```bash
zig build build-tls-interop build-h3-interop
```

```bash
scripts/interop/run-tls-interop.sh
```

```bash
scripts/interop/run-tls-interop.sh --profile ci
```

```bash
scripts/interop/run-tls-interop.sh --list --profile ci
```

`openssl` is required. `gnutls-cli`/`gnutls-serv` are optional; without them
the independent-implementation rows report `SKIP` rather than failing, so the
suite still runs on a machine that only has OpenSSL.

| Variable | Meaning |
| --- | --- |
| `TLS_INTEROP_PROFILE` | `ci` or `full` (default `full`; `--profile` wins) |
| `TLS_INTEROP_WORKDIR` | Where certificates, logs, and transcripts land (default: a fresh `mktemp -d`, printed in the summary) |
| `OPENSSL_BIN` | OpenSSL binary (default `openssl`) |
| `GNUTLS_CLI` / `GNUTLS_SERV` | GnuTLS binaries |
| `NGTCP2_EXAMPLES_DIR` | Directory holding `gtlsclient`/`gtlsserver`, for the external QUIC/H3 matrix in `run-interop.sh` |

Every row prints `PASS`, `FAIL`, or `SKIP` with the negotiated tuple; the run
exits non-zero if any row failed and lists them at the end.

## What the matrix covers

### The negotiation dimensions

The tuple vocabulary lives in exactly one place,
[`tests/tls_interop_matrix.zig`](../tests/tls_interop_matrix.zig), and is
derived from the engine's own `native_capabilities` rather than restated. A
suite, group, or signature scheme added to the engine therefore becomes a new
matrix row automatically instead of being silently skipped.

| Dimension | Values | Matrix name |
| --- | --- | --- |
| Cipher suite | `TLS_AES_128_GCM_SHA256` | `aes128-gcm-sha256` |
| | `TLS_AES_256_GCM_SHA384` | `aes256-gcm-sha384` |
| | `TLS_CHACHA20_POLY1305_SHA256` | `chacha20-poly1305-sha256` |
| Named group | `x25519` | `x25519` |
| | `secp256r1` | `secp256r1` |
| Signature scheme | `ed25519` | `ed25519` |
| | `ecdsa_secp256r1_sha256` | `ecdsa-p256-sha256` |
| | `rsa_pss_rsae_sha256` | `rsa-pss-rsae-sha256` |

The signature dimension also selects the credential: `identityKeyForSignature`
maps each scheme to the Ed25519, ECDSA P-256, or RSA-2048 identity that
`scripts/interop/gen-certs.sh` produces, so a row can never be issued a
certificate its signature scheme cannot use.

### Both transports, one engine

The point of a *shared* engine suite is that a row means the same thing on
either transport. Both tools build their `tls_core.policy.Policy` from the same
`matrix.Config`; the only transport-specific input is the default ALPN list
(`h3` for QUIC, `h2`/`http/1.1` for the record transport).

| Transport | Tool | Peers |
| --- | --- | --- |
| Record (TCP) | `tls_interop_tool` | `openssl s_client`/`s_server`, `gnutls-cli`/`gnutls-serv` |
| QUIC | `h3_interop_tool` | native loopback per tuple; external peers via `run-interop.sh` |

The QUIC rows in this script are a loopback per tuple: they prove the pinned
negotiation tuple traverses the QUIC transport of the same engine and lands
where it was told to. The external QUIC/H3 peer matrix (ngtcp2, quiche,
aioquic, both directions, HRR included) already exists in
`scripts/interop/run-interop.sh` and is not duplicated here.

### Negative conformance

Each of these asserts the failure **class**, using the RFC 8446 §6 alert where
a standard defines one. The alert is checked whichever side raised it: the
result line reports `alert_origin=local` when the engine rejected the peer and
`alert_origin=peer` when the peer rejected the engine.

| Row | Expectation | Basis |
| --- | --- | --- |
| `alpn_no_overlap` | `no_application_protocol` | RFC 7301 §3.2 |
| `cipher_no_overlap` | `handshake_failure` | RFC 8446 §4.1.1 |
| `group_no_overlap` | `handshake_failure` | RFC 8446 §4.1.1 |
| `signature_no_overlap` | `handshake_failure` | RFC 8446 §4.4.2.2 |
| `tls12_downgrade` | `missing_extension` | RFC 8446 §4.2.1 — a TLS 1.2 hello carries no `supported_versions` |
| `sni_absent` | `missing_extension` | server configured with `require_sni` |
| `wrong_pinned_certificate` | `bad_certificate` | RFC 8446 §6 |
| `malformed_ordering` | `UnexpectedRecordContent` | application data before any ClientHello |
| `ccs_before_clienthello` | `UnexpectedRecordContent` | RFC 8446 §5.1 — the compatibility window is not open yet |

`UnsupportedProtocolVersion` → `protocol_version` (RFC 8446 §4.2.1) has no
external row: it needs a ClientHello whose `supported_versions` is present but
lists no version we accept, and neither OpenSSL nor GnuTLS can be persuaded to
send one — a TLS 1.2 client omits the extension entirely, which is the
`tls12_downgrade` row instead. The mapping is covered by unit tests in
`src/tls/alerts.zig`.

### HelloRetryRequest

Both directions run. The server row has the peer offer its first key share for
`P-384`, which the engine does not accept, so the engine must retry rather than
fail; the client row omits its own initial key share, forcing the peer to
retry. #333/#484/#485 implemented the HRR backend path; this suite consumes it
across the matrix and against real peers.

## Transcripts and failure fixtures

Every record-transport row writes a transcript to `$TLS_INTEROP_WORKDIR/transcripts/`.
Each contains the offered and negotiated tuple, the outcome and failure class,
the record-layer framing of both directions, and a hex-encoded reduced failure
fixture.

**Redaction contract.** The transcript is captured at the carrier, *below* the
record-protection boundary, so it sees exactly what an on-path observer sees
and no more. Payload bytes are retained for exactly two content types:

- **`handshake` (22)** — ClientHello, ServerHello, HelloRetryRequest. In
  TLS 1.3 these are the only handshake messages that cross the wire
  unencrypted; everything after ServerHello is content type 23. Their contents
  (offered algorithms, extensions, public key shares, public randoms) are what
  reproducing a negotiation bug requires and are public by construction.
- **`alert` (21)** at the plaintext epoch — two bytes of level and description,
  which is the failure class a negative row asserts on.

Everything else is recorded as direction, content type, and length only.
Traffic secrets, resumption secrets, session-ticket bytes, and private keys are
not observable at this layer at all, so no filtering step has to be trusted to
strip them.

The `fixture.hex` block is the reduced fixture: replaying those bytes
reproduces the negotiation without the peer being present.

## Profiles

`full` runs every tuple: 3 suites × 2 groups × 3 signatures = 18 tuples, each
in both roles against both peers on the record transport, plus the same 18 on
QUIC, plus HRR and the negative rows.

`ci` keeps **both roles, both transports, every cipher suite, and every
negative row**, and reduces only the positive group/signature sweep: the
baseline suite (`aes128-gcm-sha256`) still walks all six group/signature
pairings, while the other two suites run one representative pairing each. A
regression in any single group or signature is therefore still caught, at a
fraction of the wall-clock cost.

## Adding a row

- **A new cipher suite, group, or signature scheme**: add it to the engine's
  `native_capabilities`. `tests/tls_interop_matrix.zig` picks it up
  automatically; give it a matrix name in that file (its round-trip test will
  fail until you do) and add the OpenSSL/GnuTLS spellings to
  `run-tls-interop.sh`.
- **A new negative case**: add a `run_negative_server_row` call naming the
  expected alert. Leave the alert empty only when no standard defines one, and
  pin `--expect-error` instead so the row still asserts something specific — a
  negative row that only asserts "something went wrong" will pass for the wrong
  reason.

## Findings

Two engine defects were found by building this suite, and are fixed alongside
it:

1. **HelloRetryRequest could not complete against a compatibility-mode client.**
   RFC 8446 §5.1 has a client send `change_cipher_spec` immediately after
   receiving an HRR, before ClientHello2. An HRR flight derives no traffic
   secrets, so the record transport's "has a ClientHello been accepted yet?"
   test — which inferred the answer from encryption-epoch movement — still said
   no, and the legal record was rejected with `UnexpectedRecordContent`. The
   engine now answers that question by asking the backend whether it has sent
   an HRR. A partial ClientHello still cannot open the window.

2. **No-overlap failures sent the wrong alert.** No mutually supported cipher
   suite, group, or signature scheme was reported as `illegal_parameter`,
   telling the peer its ClientHello was malformed when every value in it was
   legal. RFC 8446 §4.1.1 requires `handshake_failure`. The engine now has a
   distinct `NoMutualParameters` failure for this, and a distinct
   `UnsupportedProtocolVersion` mapping to `protocol_version` per §4.2.1.

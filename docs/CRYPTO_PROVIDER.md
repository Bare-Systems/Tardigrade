# Cryptographic-provider boundary (#370, epic #327)

This note records the stable cryptographic-provider boundary Tardigrade's TLS,
QUIC, and PKI code is written against, and the rules every implementation of it
must obey. It is the deliverable of research story **327-A** and the foundation
the rest of epic #327 builds on.

## Context

A working TLS state machine is not enough to replace or complement OpenSSL
safely. The project needs one deliberate place where cryptography enters the
protocol code, so that:

- protocol modules (TLS 1.3, QUIC packet protection, X.509 verification, record
  protection, tickets) never name a concrete primitive or a foreign TLS type;
- more than one backend — a pure-Zig one built on `std.crypto`, and the approved
  production OpenSSL one — can satisfy the same interface where their
  capabilities overlap;
- algorithm selection is explicit and cannot pick something a backend cannot do;
- secret ownership and lifetime are stated, not assumed.

Per epic #327, OpenSSL remains the approved production backend; the pure-Zig
provider grows alongside it as an experimental and eventual alternative. This
boundary is what keeps the two from coupling to each other.

## Where it lives

- `src/crypto/provider.zig` — the boundary: algorithm identifiers, capability
  discovery, the error taxonomy, the injected `Entropy` source, the opaque
  `SigningKey` handle, and the `CryptoProvider` interface (a `context` pointer
  plus a `*const VTable`, the same seam shape as the QUIC `TlsBackend`).
- `src/crypto/secrets.zig` — fixed-size and bounded dynamic secret containers,
  shared secure-zero and constant-time comparison helpers, and the non-formatting
  convention for secret-bearing values.
- `src/crypto/pure_zig.zig` — the first concrete backend, built entirely on
  `std.crypto`. Implements the narrow first profile and advertises exactly that.
- `src/crypto/root.zig` — the package aggregator.
- Tests run under `zig build test-crypto` and as part of `zig build test`.

The OpenSSL adapter is future work: a second file implementing the same
`CryptoProvider.VTable`, selected at the composition root. No protocol code
changes when it lands.

## What the boundary covers

- **HKDF** extract and expand-label over SHA-256 and SHA-384.
- **AEAD** seal/open for AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305.
- **Key exchange** — ephemeral key-share generation and shared-secret derivation
  for X25519 and (declared, not yet implemented in pure Zig) secp256r1.
- **Signatures** — verification, and signing through the opaque `SigningKey`
  handle, for Ed25519 and (declared) ECDSA-P256 and RSA-PSS.
- **Random bytes**, **constant-time comparison**, and **secure zeroing**.
- **Secret containers** for fixed-size stack material and bounded heap material,
  with explicit replacement and deinitialization rules.
- **Opaque private-key handles** and **capability discovery**.

The pure-Zig backend implements the overlap the TLS/QUIC engines need today:
HKDF (SHA-256/384), all three AEADs, X25519, and Ed25519. The remaining
algorithms are named by the interface so protocol and negotiation code is
written once; capability discovery reports them absent and every entry point
returns `error.UnsupportedCapability` until a backend provides them.

## Design rules

### Capability discovery is explicit

A provider advertises exactly what it can do through `Capabilities` (sets of
supported hashes, AEADs, groups, and signature schemes). Negotiation selects
only from that set with the `select*` helpers, and every operation re-checks
membership. An unsupported algorithm is therefore always a typed
`error.UnsupportedCapability` — never a call into a primitive that cannot handle
it, and never undefined behaviour.

### Errors are classified

The taxonomy lets the protocol layer map each failure to the correct alert
without guessing:

| Class | Meaning | Typical protocol response |
| --- | --- | --- |
| `InputError.InvalidInput` | Malformed or wrong-sized caller/peer input (bad point encoding, wrong-length key, undersized output buffer). | `decode_error` / `illegal_parameter`, QUIC `CRYPTO_ERROR`. |
| `CapabilityError.UnsupportedCapability` | Well-formed but this backend cannot do it. A negotiation/config bug, not peer misbehaviour. | internal error; should be unreachable after negotiation. |
| `ProviderError.{EntropyFailure, ProviderFailure}` | The provider itself failed, independent of input. | internal error; not fixable by renegotiating. |
| `AuthError.AuthenticationFailed` | An AEAD tag or a signature did not verify. | `bad_record_mac` / handshake failure; never treated as a benign decode error. |

### Secrets are borrowed, never retained

Every slice handed to the provider — keys, IKM, plaintext, private scalars,
peer public values — is valid only for the duration of the call. A backend must
not retain a pointer to borrowed secret material after it returns. The only
provider-owned secret is a `SigningKey`'s private key, which lives behind the
opaque handle; its owner scrubs it explicitly when retiring the key (for the
pure-Zig backend, `SoftwareSigningKey.deinit` — a Zig value is not zeroed just
by going out of scope). Internally, backends copy secrets into fixed buffers
only as long as a primitive needs them and `secureZero` those buffers on the
way out — including HKDF's per-block temporaries, the X25519 seed, ephemeral
private scalar, and shared-secret copies. AEAD-open zeroes its output buffer on
authentication failure so no unauthenticated plaintext is ever left for the
caller to read.

Secret-bearing protocol state should use `crypto.secrets.FixedSecret(N)` for
fixed-capacity storage and `crypto.secrets.BoundedSecret` for heap-backed
storage with an explicit upper bound. These types copy input into owned memory,
return borrowed slices through `slice`, wipe replaced contents before reuse, and
must be `deinit`ed before the owning connection/key object is discarded. Secret
containers deliberately provide a `format` method that fails compilation so
accidental `{}` logging does not expose key material. `BoundedSecret` is
initialized in place so callers do not receive an owning heap allocation by
value; any ownership transfer must be explicit at the call site.

### Entropy is injected

There is no ambient RNG, matching the rest of `src/quic/`. A provider draws all
randomness — ephemeral scalars, nonces, per-signature noise — from the
`Entropy` source handed in at construction. The composition root wires this to
the OS CSPRNG in production; tests and reproducible fixtures use
`pure_zig.DeterministicEntropy` (a seedable splitmix64 source that is explicitly
*not* a CSPRNG). Entropy failure surfaces as `ProviderError.EntropyFailure`.

### Private keys can move off-host later

`SigningKey` is an opaque `context` + `VTable` pair, so a software key today and
an HSM or remote signer tomorrow present the identical interface. The TLS engine
holds a `SigningKey` and calls `sign`; it never learns where the private key
lives. This is why signing goes through the handle rather than through the main
provider vtable.

## Acceptance criteria mapping (#370)

- *Protocol modules compile against provider-owned types only* — the interface
  exposes only its own enums, error sets, and handles; no `std.crypto` or
  OpenSSL type crosses the seam. Migrating the existing QUIC/TLS modules onto it
  is follow-up implementation work (#323–#326), which this boundary enables.
- *Pure-Zig and OpenSSL providers satisfy the same interface where capabilities
  overlap* — both implement `CryptoProvider.VTable`; overlap is exactly what
  `Capabilities` makes queryable.
- *Capability negotiation is explicit and cannot select unsupported algorithms*
  — see "Capability discovery is explicit" above; covered by tests.
- *Errors distinguish invalid peer input, unsupported capability, and provider
  failure* — see the error taxonomy table; covered by tests.
- *No provider retains borrowed secrets beyond documented call lifetimes* — see
  "Secrets are borrowed, never retained".

## Not in scope here

TLS handshake behaviour (#323), X.509/Web PKI (#324), the TCP record layer
(#325), and resumption/0-RTT (#326) live in their own stories. So do the
differential-testing, Wycheproof-style corpora, fuzzing, performance budgets,
and the pure-Zig production-readiness checklist enumerated in epic #327. This
story defines the boundary they all attach to.

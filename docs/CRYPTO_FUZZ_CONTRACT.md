# Shared crypto fuzzing contract and provider targets (#376, epic #327-G)

This is the shared fuzzing contract for the native TLS program's crypto
surfaces. It defines the rules every fuzz target under epic #327-G must
follow, and owns the standalone targets for the `CryptoProvider` boundary
itself (AEAD, key exchange, signature verification, signing keys, and the
shared secret containers). Protocol-specific fuzzing is owned by the epics
that own those protocol surfaces and must consume this contract rather than
inventing incompatible rules:

- #491 — shared TLS handshake / negotiation / transcript / reassembly (#323)
- #492 — DER / PEM / X.509 / path validation (#324)
- #493 — TLS record / protection / encrypted-stream (#325)
- #494 — session / PSK / ticket / resumption state (#326)
- #247 — QUIC/H3 packet/frame/transport/QPACK/H3 validation

This story does not re-implement those targets. Its own targets stop at the
provider seam (`src/crypto/provider.zig`, `src/crypto/pure_zig.zig`,
`src/crypto/rsa.zig`, `src/crypto/secrets.zig`): malformed input that can
reach `CryptoProvider` directly, without needing a protocol state machine.

## Existing fuzzing pattern in this repo

There is no separate `fuzz/` tree. Fuzzing is inline `test "fuzz: ..."`
blocks using Zig 0.16's built-in `std.testing.fuzz`/`std.testing.Smith`,
next to the code they exercise or in a focused `tests/*.zig` file, each with
a checked-in seed corpus passed as `.corpus = &.{...}`. Under a normal
`zig build test` this deterministically replays only the seed corpus; under
`zig build <step> -Doptimize=ReleaseFast --fuzz=<N>` it becomes real
coverage-guided mutation. This mirrors `docs/QUIC_H3_FUZZ_MATRIX.md`'s
program for QUIC/H3 (#247/#537); this document is the equivalent for the
shared crypto surfaces.

## Commands

```bash
# Deterministic smoke coverage (seed corpus replay only) — part of the
# default `zig build test` and CI.
zig build test-crypto --summary all --error-style verbose

# The standalone provider-boundary targets owned by this story:
zig build test-crypto-provider-fuzz --summary all --error-style verbose

# Shared TLS protocol-engine targets owned by #491:
zig build test-tls-protocol-fuzz --summary all --error-style verbose

# Record/protection/epoch/encrypted-stream targets owned by #493:
zig build test-tls-record-fuzz --summary all --error-style verbose

# Longer local/scheduled coverage-guided runs:
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: AEAD open" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: deriveSharedSecret" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: verify" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: generateKeyShare" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: FixedSecret" --fuzz=10M --summary all --error-style verbose
zig build test-crypto-provider-fuzz -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: BoundedSecret" --fuzz=10M --summary all --error-style verbose
zig build test-tls-protocol-fuzz -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-tls-protocol-fuzz -Doptimize=ReleaseFast -Dtls-protocol-test-filter="fuzz: TLS protocol: ClientHello parse" --fuzz=10M --summary all --error-style verbose
```

`-Dcrypto-test-filter` (added alongside the existing `-Dquic-test-filter`)
gives explicit target selection for the `test-crypto-provider-fuzz` step; the
`--fuzz=<runs>` limit keeps scheduled runs bounded (`K`/`M`/`G` suffixes
scale it). #491–#494 should add their own protocol-scoped test steps and
`-D<area>-test-filter` options following the same pattern rather than
growing this one.
`test-tls-protocol-fuzz` follows that convention with
`-Dtls-protocol-test-filter` and the default `fuzz: TLS protocol:` namespace.

## Seed-corpus and regression update procedure

This is the concrete workflow #491–#494 should follow too, rather than each
inventing their own.

1. **Capture the exact crash input, not a description of it.** A `--fuzz=<N>`
   run that finds a failure persists the exact failing `Smith` byte input
   through Zig's own fuzz engine (the memory-mapped/corpus-backed input the
   coverage-guided runner uses to recover crashing values, per the [Zig
   0.16 release notes' fuzzer
   section](https://ziglang.org/download/0.16.0/release-notes.html#Fuzzer)).
   The `test "fuzz: <name>"` name Zig prints identifies the *target*, and a
   `FUZZING REPORT` run count is not a stable case ID — re-running the same
   coverage-guided command is exploration, not an exact replay. Do not
   substitute a `std.debug.print` of the *values sampled from* the Smith
   stream (lengths, enum choices, etc.): those are derived data, not the
   input itself, and cannot be fed back into `.corpus` to reproduce the
   same run deterministically. Copy the crash input file Zig's fuzzer
   reports into a stable checked-in fixture instead:
   `tests/vectors/fuzz/crypto/<target-slug>/<sha256-of-the-file>.bin`, where
   `<target-slug>` is a short slug for the target (e.g. `aead-open`,
   `derive-shared-secret`, `verify`, `fixed-secret`, `bounded-secret`). The
   SHA-256 digest is both the filename and the deterministic case ID/
   provenance record — identical bytes always hash to the same fixture name,
   so a duplicate find is a no-op rather than a second copy.
2. **Wire it back in with `@embedFile`, always.** Every checked-in crash
   fixture is added to its target's `.corpus` as `@embedFile`, never
   hand-transcribed as a string literal (transcription is exactly the kind
   of lossy transcription step 1 rules out):
   ```zig
   try std.testing.fuzz({}, fuzzAeadOpen, .{ .corpus = &.{
       "",
       // Found 2026-08-04, zig build test-crypto-provider-fuzz
       // -Doptimize=ReleaseFast -Dcrypto-test-filter="fuzz: AEAD open ..." --fuzz=50M
       @embedFile("vectors/fuzz/crypto/aead-open/1f3c9a7e...bin"),
   } });
   ```
   Replay it immediately with the *same* target's filtered non-`--fuzz`
   command (below) to confirm it reproduces deterministically before doing
   anything else with it.
3. **Minimize, then decide what to keep.** Reduce the fixture by repeatedly
   trimming/simplifying its bytes and re-running the same filtered replay
   command until it stops reproducing the failure, keeping the last input
   that still did (manual delta-debugging; Zig 0.16 does not ship an
   automatic minimizer for this workflow). Once the minimal failing input is
   understood:
   - If it has a clean semantic story (a specific field's wrong length, a
     specific tamper, a specific boundary value), translate it into a named
     deterministic `test` block next to the target — this is what every
     regression in `tests/crypto_provider_fuzz.zig` already is, and it
     stays reviewable in a way a byte blob does not. Only remove the raw
     `.corpus`/`@embedFile` fixture once that named regression has been
     confirmed to fail against the pre-fix code and pass against the fix
     (i.e. it exercises the same defect, not a superficially similar one).
   - If it has no clean semantic story (the exact bytes matter and cannot be
     reduced to a short description), keep the minimized fixture itself as
     the permanent regression via `@embedFile`, re-hashing and renaming the
     file to match its minimized content.
4. **Never store real secret material.** Every target in this file
   synthesizes or derives its own key material per case from injected
   deterministic entropy — callers never hand it a real production secret —
   so a captured fixture is inherently synthetic/malformed wire-shaped
   input, never a real private key, certificate, or traffic capture. Corpus
   fixtures and regression tests must stay that way: hand-crafted or
   fuzzer-found malformed input only, never copied from a real deployment.
5. **Record provenance.** Add a one-line comment directly above the new
   `.corpus`/`@embedFile` entry or regression test (see the example in step
   2) noting when it was found and which command found it, so a future
   reader can tell a hand-written edge case from a fuzzer-discovered one;
   the SHA-256 filename itself is the immutable half of that record.
6. **Verify before committing, and pick the right command for the artifact.**
   A raw `.corpus`/`@embedFile` fixture is replayed by the *fuzz test's own*
   filter; a named deterministic regression is a separate `test` and needs
   its *own* name filtered instead (or the whole step, unfiltered) — the
   fuzz-target filter will not run it:
   ```bash
   # Corpus/@embedFile fixture: filter on the fuzz target that owns it.
   zig build test-crypto-provider-fuzz -Dcrypto-test-filter="fuzz: <exact target name>" --summary all --error-style verbose
   # Named deterministic regression: filter on the regression's own name.
   zig build test-crypto-provider-fuzz -Dcrypto-test-filter="<exact regression test name>" --summary all --error-style verbose
   # Always, regardless of artifact type:
   zig build test --summary all --error-style verbose
   ```
   The first confirms the new corpus entry or regression reproduces
   deterministically under plain (non-`--fuzz`) replay; the second confirms
   no other target regressed. Run `zig fmt --check build.zig src/ tests/`
   too, matching every other change in this repo.

## The shared contract

Every target under epic #327-G — this story's provider targets and
#491–#494's protocol targets alike — must satisfy the following.

### Deterministic reproduction

Every failure must identify:

- the target name (the `test "fuzz: ..."` name Zig's runner already prints);
- a deterministic case ID — the SHA-256 digest of the checked-in
  `@embedFile` fixture, or the named regression `test`'s own name; a
  `FUZZING REPORT` run count is not one (see "Seed-corpus and regression
  update procedure" above);
- input length;
- a typed stage/failure class (which operation and which error variant, not
  a bare panic message);
- the exact local reproduction command (the filtered commands in "Seed-corpus
  and regression update procedure" above, chosen by artifact type).

Identical input/configuration must produce identical target behavior unless
the target explicitly injects a deterministic clock/entropy stream. Every
target in this file drives `pure_zig.Provider` through the injected
`provider.Entropy` seam only (`pure_zig.DeterministicEntropy` in tests) —
never ambient randomness. Case isolation matters as much as determinism
here: each test and each fuzz callback constructs its own
`DeterministicEntropy`/`Provider` pair on its own stack frame (the
`TestProvider` helper in `tests/crypto_provider_fuzz.zig`) rather than
sharing one process-global instance. A shared stream would advance
differently depending on how many earlier cases already ran in the same
process, so a case minimized during a full run and later replayed alone
(e.g. via `-Dcrypto-test-filter`) would see a different entropy position
than it had during discovery — reproducible in aggregate, but not
per-case. Constructing fresh state per case removes that dependency
entirely.

### Bounded work

Every target defines explicit limits for the dimensions it can amplify. For
the provider targets in this file that means: input bytes are read from
`std.testing.Smith` into fixed-capacity stack buffers (never an unbounded
`ArrayList`), so a target cannot be driven into an unbounded allocation by
attacker-controlled length fields. There is no nesting/recursion, no graph
exploration, and no allocation inside the hot path of AEAD/KEX/verify calls
— the provider's own contract keeps those operations O(input length). The
`BoundedSecret` property targets are the one place with real allocation, and
they bound capacity to a small fixed maximum (see the test file) and always
`deinit` before the next iteration.

### Arithmetic safety

Provider inputs are lengths and byte buffers, not wire-encoded variable-width
integers, so most of the classic overflow-adjacent boundaries reduce to
buffer-length boundaries. Targets and their deterministic regressions cover:

- zero-length keys/nonces/tags/AD/plaintext/ciphertext and zero-length
  signatures/public keys;
- exact, one-under, and one-over the algorithm's required length for every
  fixed-size field (AEAD key/nonce/tag, key-exchange public value/private
  scalar/shared secret, fixed-length signature encodings);
- a harness-chosen bounded "maximum" plaintext/message length, since AEAD and
  signing have no wire-defined upper bound the way a DER length or QUIC
  varint does.

Checked add/subtract/multiply around offsets, padding, and record/ticket/DER
lengths belongs to #491–#494 and #492 (those are the modules that actually
compute such offsets); this file's targets never perform that arithmetic —
`CryptoProvider` calls take already-sliced buffers.

### Lifetime / borrowed-slice safety

The provider boundary is explicit about this in its own doc comment
(`src/crypto/provider.zig`, "Secrets are borrowed, never retained"): every
slice a caller hands in is valid only for the call's duration, and the sole
provider-owned secret is the opaque `SigningKey` handle. This file's targets
exercise that contract:

- `deinit`/destruction after both success and failure leaves no usable
  private key: `SoftwareSigningKey`/`SoftwareEcdsaP256SigningKey` wipe
  `key_pair.secret_key` in place (stack-resident, directly inspectable after
  `deinit`); `SoftwareRsaSigningKey`/`rsa.PrivateKey` route through
  `secrets.secureZeroAndFree` (heap-resident, inspected via a
  `FixedBufferAllocator` the same way `src/crypto/secrets.zig`'s own
  `BoundedSecret` tests do);
- owned results (a returned shared secret, a returned signature) remain
  stable in the caller's buffer after the call returns — nothing the
  provider does later can invalidate them, because the provider retains no
  pointer into caller-owned output;
- borrowed results are never used outside their owner's lifetime — this is
  structurally enforced here because every provider operation is a single
  synchronous call with no retained borrow, not a stateful handle;
  `SigningKey` is the one exception and it is the type these `deinit` tests
  target;
- allocation-failure and early-return cleanup: the `BoundedSecret` property
  target injects allocator failure at random points via
  `std.testing.FailingAllocator` and asserts no leak (`std.testing.allocator`
  wraps every non-injecting path) and no partially-initialized secret escapes
  a failed `init`;
- partial outputs are not retained after a failed transactional operation:
  AEAD `open` never leaves usable plaintext after `error.AuthenticationFailed`
  (see below), and every `SigningKey.sign` implementation checks the output
  buffer length *before* drawing entropy or computing anything, so a rejected
  call never partially fills `out`.

### Read/write/reentrancy separation

Not applicable to this story's own targets: every `CryptoProvider` operation
is a single synchronous, non-reentrant call with no network I/O, no output
event carrier, and no partial-progress state to resume. State machines with
this shape (TLS transcript, QUIC CRYPTO reassembly, H3 request state) are
owned by #491/#493/#494/#247, which must apply this rule themselves.

### Secret-safe diagnostics

No target in this file ever formats or logs a `SigningKey`, `FixedSecret`,
`BoundedSecret`, private scalar, or shared secret — `format` is a compile
error on every secret-bearing type already (`@compileError("secret values
must not be formatted or logged")` in `secrets.zig` and each
`Software*SigningKey`), so a target that tried would fail to compile, not
just fail to review-catch. Failure output uses case IDs, public lengths,
algorithm/scheme names, and typed error variants, matching #375's audit
posture (`docs/CRYPTO_SECURITY_AUDIT.md`).

### Regression minimization

Every deterministic crash, panic, invariant violation, lifetime failure, or
semantic bug this story's targets find is checked in as a permanent
regression, in the form the "Seed-corpus and regression update procedure"
above prefers for it: normally an inline deterministic `test` block next to
the fuzz target in `tests/crypto_provider_fuzz.zig` (the same pattern
`docs/QUIC_H3_FUZZ_MATRIX.md` uses), or — only when the failure has no clean
semantic story and the exact bytes matter — a checked-in
`tests/vectors/fuzz/crypto/<target-slug>/<sha256>.bin` fixture wired back in
through `@embedFile`. There is no generic top-level `regression/` directory
in this repo; `tests/vectors/fuzz/crypto/` and PKI's
`tests/vectors/pki/reduced/` manifest pattern (reserved for #492's semantic
certificate corpus) are the two directory-backed exceptions to the
inline-`test`-block default. Do not fix a reproducible deterministic failure
by adding a skip; fix the defect or the test's understanding of the
contract.

## Provider targets owned here

`tests/crypto_provider_fuzz.zig` drives the real `pure_zig.Provider` (never a
mock) through `provider.CryptoProvider`, following the same three-tier shape
`tests/security/request_parser_corpus.zig` established: deterministic
regression tests for named edge cases, plus a `std.testing.Smith`-driven
generative `fuzz:` target with a seed corpus for each surface below. It
complements rather than duplicates the deep existing deterministic coverage
already in `src/crypto/pure_zig.zig`, `src/crypto/rsa.zig`, and
`src/crypto/secrets.zig` (key-share buffer sizing, ECDSA/RSA entropy-failure
and malformed-scalar rejection, `BoundedSecret` allocator-observable
zeroization, etc.) — this file adds the pieces that were missing: the
generative fuzz harnesses themselves, plus a small number of genuine
deterministic gaps identified while wiring them up.

| Area | Target | Properties covered | Open follow-up |
| --- | --- | --- | --- |
| AEAD seal/open | `tests/crypto_provider_fuzz.zig` `fuzz: AEAD open never leaves unauthenticated plaintext on arbitrary key/nonce/tag/ciphertext/AD`; deterministic wrong-length, tamper-zeroization, and zero/max-length regressions | Wrong key/nonce/tag length, ciphertext/plaintext length mismatch, truncated/mutated ciphertext/tag/AD rejected as `AuthenticationFailed` with the plaintext buffer fully zeroed, zero-length and harness-bounded maximum-length plaintext round-trip, for all three supported AEADs. | Overlap/alias behavior between `ciphertext` and `plaintext` buffers is not part of the documented provider contract today (`provider.zig`'s `aeadSeal`/`aeadOpen` doc comments are silent on aliasing); add coverage once that contract is decided rather than asserting undocumented behavior. |
| Key exchange | `tests/crypto_provider_fuzz.zig` `fuzz: deriveSharedSecret never panics on arbitrary scalar and peer-public bytes`; `fuzz: generateKeyShare never panics on arbitrary output-buffer lengths`; deterministic wrong-length and output-buffer-bound regressions | Wrong-length private scalars, peer public keys, and output buffers rejected as `InvalidInput` for X25519 and secp256r1; output-buffer-length fuzzing for key-share generation. Complements the existing low-order/all-zero-point and malformed-scalar coverage already in `pure_zig.zig`. | Positive round-trip and deterministic/failing-entropy-during-keygen coverage already exists in `pure_zig.zig` (`"X25519 key shares agree..."`, `"secp256r1 key-share generation rejects bad buffers before entropy and handles entropy failure"`); not duplicated here. |
| Signature verification | `tests/crypto_provider_fuzz.zig` `fuzz: verify never panics on arbitrary public key, message, and signature bytes`; deterministic malformed-key, malformed-signature, tampered-signature, and wrong-message/key regressions | Malformed public-key and signature encodings, structurally-valid single-bit-modified signatures, wrong message, and wrong key rejected without panic for Ed25519, ECDSA-P256/SHA-256, and RSA-PSS-RSAE/SHA-256, using `rsa.testdata`'s fixed RSA-2048 fixture as seed/provenance material rather than re-deriving key material. | None for the current provider `verify` surface. |
| Signing-key boundary | `tests/crypto_provider_fuzz.zig` deterministic undersized-output-buffer and deinit-wipe regressions for all three software signing-key types | Undersized output buffers rejected before any entropy draw or computation, output buffer left untouched, for Ed25519 (new — the ECDSA/RSA equivalents already existed in `pure_zig.zig`); `deinit` wipes the retained private key bytes for `SoftwareSigningKey` and `SoftwareEcdsaP256SigningKey` (RSA's equivalent already exists as `rsa.zig`'s `"PrivateKey.deinit wipes the retained private exponent"`). | Malformed constructor/import input and entropy-failure coverage already exists per-type in `pure_zig.zig`/`rsa.zig`; not duplicated here. |
| Shared secret helpers | `tests/crypto_provider_fuzz.zig` `fuzz: FixedSecret replace/eql/deinit preserve invariants under arbitrary overlapping and non-overlapping input`; `fuzz: BoundedSecret replace/eql/deinit preserve invariants under arbitrary capacity and allocator-failure injection` | `FixedSecret`/`BoundedSecret` `replace`/`copy`/`eql`/`deinit` across randomized capacities, content, and self-overlapping slices; `BoundedSecret` allocation-failure injection via `std.testing.FailingAllocator` with no leak under `std.testing.allocator` and no partially-initialized secret escaping a failed `init`. | `constantTimeEqual`'s functional behavior (equal/unequal/length-mismatch) and the `format`-is-a-compile-error guard are already covered deterministically in `secrets.zig` and `provider.zig`; not duplicated here. |

## Ownership boundaries

Same boundaries as the parent issue, restated for anyone landing on this
document directly:

- **#491** owns handshake message/extensions, canonical negotiation/policy,
  transcript/HRR/ClientHello2 state, and shared TLS reassembly.
- **#492** owns DER/PEM/X.509 semantic parsing, path building/validation,
  graph/resource bounds, and hostile certificate seed reuse.
- **#493** owns record codec/protection, epoch lifecycle, encrypted-stream
  buffering/progression, partial I/O, and authentication-failure record
  behavior.
- **#494** owns `NewSessionTicket`, PSK/binder handling, session
  codecs/cache, protected ticket envelopes/keyrings, resolver/runtime
  selection, and resumption state lifetime.
- **#247** owns QUIC packet/frame/transport-parameter/token/CRYPTO/ACK/
  stream/QPACK/H3 transport fuzzing and related interop/benchmark harnesses.

Do not pull those concerns back into this story merely because their
implementation consumes cryptography, and do not have this story re-fuzz a
protocol module's own state machine — call `CryptoProvider` directly instead.

## CI model

`zig build test` (and therefore every CI job that runs it, per
`.github/workflows/ci.yml`) already includes `test-crypto-provider-fuzz`'s
deterministic seed-corpus replay — no separate CI job was added. Longer
coverage-guided runs use the `-Doptimize=ReleaseFast --fuzz=<N>` commands
above as scheduled or manual local runs, the same model
`docs/QUIC_H3_FUZZ_MATRIX.md` uses; they are not wired into required PR CI
because they are unbounded by design. Coordinate future OSS-Fuzz/OpenSSF
onboarding with #121 rather than making external service integration a
blocker here.

## Protocol-scoped fuzz steps built on this contract

Per the "Commands" section above, #491–#494 do not grow this file's own
`test-crypto-provider-fuzz` step; each adds its own protocol-scoped step
and `-D<area>-test-filter` option instead. This section records the
stable step/filter names as those stories land, so a reader here does not
have to go hunting through `build.zig`.

### #494 — session / PSK / ticket / resumption state (epic #326-K)

Unlike this file's own targets, #494's targets are inline `test "fuzz:
..."` blocks inside the production modules themselves
(`src/tls/new_session_ticket.zig`, `src/tls/session.zig`,
`src/tls/pre_shared_key.zig`, `src/tls/ticket_protection.zig`,
`src/tls/session_cache.zig`) — not a separate `tests/*.zig` root — so they
already replay their deterministic seed corpus under plain
`zig build test-tls` / `zig build test`. The
`test-tls-resumption-fuzz` step exists to give them a stable,
individually filterable/long-runnable name, the same shape as
`-Dcrypto-test-filter` above:

```bash
# Deterministic smoke coverage for every #494 fuzz target (seed corpus
# replay only, "fuzz: TLS resumption:" test-name namespace) — also
# covered by plain `zig build test-tls` / `zig build test` since
# tls_core's test binary already includes these files. The namespace is
# deliberately more specific than a bare "fuzz: " prefix: `tls_core_mod`
# also contains unrelated pre-existing "fuzz: ..." tests
# (sni_provider.zig, ticket_key_snapshot.zig, and ticket_protection.zig's
# own combined identity/resolve target), which a bare prefix would pull
# into this step too.
zig build test-tls-resumption-fuzz --summary all --error-style verbose

# Longer local/scheduled coverage-guided runs, one target at a time:
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: NewSessionTicket wire decode and owned-state construction never panic or corrupt output" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: session codec raw decode never panics and owns its decoded state" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: session codec generated client/server records round-trip and reject cross-kind decode" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: PSK wire codec" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: PSK binder derivation" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: parseEnvelope is allocation-free" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: parseEnvelope single-field mutation" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: Protector.resolve authenticates" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: ticket keyring install/validate/acquire/retain/release/seal sequence" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: client session cache operation sequence preserves transactional state, ownership, eviction, and lease semantics" --fuzz=10M --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Doptimize=ReleaseFast -Dtls-resumption-test-filter="fuzz: TLS resumption: stateful server cache operation sequence preserves transactional indexes, ownership, handle, and lease semantics" --fuzz=10M --summary all --error-style verbose

# Named deterministic regressions (not fuzz-tagged, so outside the
# default "fuzz: TLS resumption:" namespace — filter on their own name):
zig build test-tls-resumption-fuzz -Dtls-resumption-test-filter="parseEnvelope rejects every truncated prefix of a valid envelope below the minimum length" --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Dtls-resumption-test-filter="earlyDataCapableFromRaw never overflows at the u32 boundary" --summary all --error-style verbose
zig build test-tls-resumption-fuzz -Dtls-resumption-test-filter="resolveStatefulServerPsk lease-box OOM releases an acquired single-use pin and permits retry" --summary all --error-style verbose
```

`-Dtls-resumption-test-filter` defaults to `"fuzz: TLS resumption:"` (every
#494 target, none of the much larger surrounding deterministic TLS suite
or the unrelated pre-existing `sni_provider.zig`/`ticket_key_snapshot.zig`/
`ticket_protection.zig` fuzz targets that also happen to start with
`"fuzz: "`); pass an exact `test "fuzz: ..."` name to scope a long
`--fuzz=<N>` run to one target, matching the reproduction-command shape
"Seed-corpus and regression update procedure" above requires. #494-A covers
`NewSessionTicket` wire/owned-state construction, the session client/server
codec, PSK modes/`OfferedPsks`/binder primitives, and allocation-free
ticket-envelope parsing (`parseEnvelope`). #494-B adds authenticated
`Protector.resolve` -- accept, every typed rejection reason, and a full
allocation-failure sweep over every reachable allocation point, all under
`ZeroCheckingAllocator` to prove the temporary plaintext is wiped before
free on every path -- exercised across all three required AEADs, each fuzz
case constructing its own fresh `pure_zig.DeterministicEntropy`-backed
provider rather than sharing static state. The rejection matrix includes
public envelope-field mutation, authenticated plaintext mutation, key state,
and lifetime edges, plus several classes that require successfully
authenticating first:
`not_yet_valid`/`expired` (forged timestamps); an authenticated state
extended with an unknown *optional* field, which must still accept and
round-trip (proving forward compatibility, not just rejection); a
supported SHA-384 suite id paired with the 48-byte PSK it requires, which
must also accept and round-trip (contrasted against the mismatched
pairings below, so acceptance is proven, not just assumed); and
`invalid_plaintext` via an authenticated-but-malformed `TRS1` record
covering the shared header (magic/version/record-type/section-length),
field-level TLV boundaries (duplicate field, missing mandatory field,
exact-width field length one-under/zero/one-over, an unknown *critical*
field, PSK length across zero/one/one-over/the largest supported digest
length, a field whose declared length vastly exceeds the bytes the section
actually has left -- a declaration-only truncation, not a 64 KiB
allocation -- an unknown/unassigned cipher-suite wire value, and a
*supported* suite id whose transcript-hash length disagrees with the
unchanged, authenticated PSK bytes that follow it). The known-field
mutations reuse
`session.fixtureWithFieldRemoved`/`fixtureWithFieldDuplicated`/
`withTlvLengthOverride`/`originalTlvLen`, promoted `pub` from session.zig's
own codec fuzz/test suite rather than re-derived here (that promotion also
fixed `withTlvLengthOverride` to zero-fill a one-over declared length's
excess bytes instead of leaving them as whatever was in the caller's
scratch buffer, so every caller's mutation is deterministic by
construction). `protector.limits` is varied around both the envelope-length
boundary (`max_ticket_len`) and the decoded-state boundary
(`max_serialized_len`). It also adds an
in-memory `Snapshot`/`ReloadableKeyRing` publication target: a bounded
*sequence* of build/install/dry-run-validate/acquire/explicit-retain/
release/`seal` operations (rather than the single-call property fuzzing
`fuzzSnapshotConfig` already covered), driving its own fresh per-case
`pure_zig.DeterministicEntropy`-backed provider (not the shared static
`testProvider()` every ordinary deterministic test in this file uses) for
both the normal seal path and the fault-injecting wrapper below, and
asserting generation monotonicity, ledger growth, nonce uniqueness and
deterministic exhaustion (including right at the `maxInt(u64)` boundary via
an occasional near-wrap lease window), that a failed seal still consumes
its reserved nonce (via a per-case `FaultingSealProvider` that always fails
`aeadSeal` after `NonceLease.reserve()` has already committed), that a
retained old snapshot's key material and lease state stay exactly frozen
once it stops being `keyring.current` (compared via the same constant-time
key fingerprint the keyring's own ledger uses) for as long as it is held,
and that injected allocation failure during build/install leaves
publication state unchanged. Every modeled reference -- acquired or
explicitly retained -- wipes the snapshot exactly once when the last one is
released, and this holds for every bounded program, not just ones where
opcode 4 happens to run again before the sequence ends: a `tracked_snapshot`
flag (set once, on the first acquire, and never reset -- unlike `held`,
which opcode 4 nulls out the moment its own modeled reference count reaches
zero even when the snapshot is still `keyring.current` and therefore not
actually freed yet) drives real end-of-case cleanup code -- not a bare
`defer`, since the final check needs `try testing.expectEqual` rather than
`std.debug.assert` (which lowers through `unreachable` and is therefore not
a reliable runtime check under the documented `-Doptimize=ReleaseFast
--fuzz` configuration) -- that drains every outstanding reference, tears the
keyring down, and only then asserts the snapshot deinitialized exactly once
and unconditionally wipes the stored fingerprint, with the zeroization
probe kept installed through both steps so it can observe whichever one
performs the true final release; a separate `errdefer` covers only the
leak-prevention side of the same cleanup for an early error return elsewhere
in the opcode loop, without a redundant assertion. The existing
`ticket_key_snapshot.zig` persistent-JSON-snapshot fuzz target is unrelated
(on-disk snapshot file parsing, not the in-memory keyring) and is preserved
as-is, per the issue's "existing coverage to preserve, not recreate" list.
#494-C adds two independent bounded operation-sequence targets in
`session_cache.zig`: client cache store/lookup/lease/persistence state and
stateful-server insert/resolve/public-adapter/persistence state. Both
targets use tiny fixed cache limits, at most 16 opcodes per case,
deterministic logical clocks, explicit Smith corpus programs, full
fingerprint snapshots for transactional comparisons, transition-specific
lease oracles, per-op invariant checks, bounded operation-scoped
`FailingAllocator` sweeps, controlled collision programs, and test-only
zeroization/destruction probes for entries and public lease boxes.
Backend/runtime composition follows in #494-D per the issue's PR
decomposition.

### #493 — TLS record / protection / epoch / encrypted-stream state (epic #325-K)

Like #494's targets, #493's are inline `test "fuzz: ..."` blocks inside the
production modules themselves (`src/tls/record_codec.zig`,
`src/tls/record_protection.zig`, `src/tls/record_epoch_bridge.zig`,
`src/tls/encrypted_stream.zig`) rather than a separate `tests/*.zig` root,
so they already replay their deterministic seed corpus under plain
`zig build test-tls` / `zig build test`. The `test-tls-record-fuzz` step
gives them a stable, individually filterable/long-runnable name, matching
`-Dtls-resumption-test-filter`/`-Dtls-protocol-test-filter` above:

```bash
# Deterministic smoke coverage for every #493 fuzz target landed so far
# (seed corpus replay only, "fuzz: TLS record:" namespace) — also covered
# by plain `zig build test-tls` / `zig build test`.
zig build test-tls-record-fuzz --summary all --error-style verbose

# Longer local/scheduled coverage-guided runs, one target at a time:
zig build test-tls-record-fuzz -Doptimize=ReleaseFast --fuzz=10M --summary all --error-style verbose
zig build test-tls-record-fuzz -Doptimize=ReleaseFast -Dtls-record-test-filter="fuzz: TLS record: codec fragmentation, coalescing, and sink saturation preserve exact consumption" --fuzz=10M --summary all --error-style verbose
zig build test-tls-record-fuzz -Doptimize=ReleaseFast -Dtls-record-test-filter="fuzz: TLS record: inner plaintext framing, padding, and bounds remain transactional" --fuzz=10M --summary all --error-style verbose
zig build test-tls-record-fuzz -Doptimize=ReleaseFast -Dtls-record-test-filter="fuzz: TLS record: protection tamper and sequence boundaries preserve authentication state" --fuzz=10M --summary all --error-style verbose
zig build test-tls-record-fuzz -Doptimize=ReleaseFast -Dtls-record-test-filter="fuzz: TLS record: epoch operation sequences preserve one-way key lifecycle" --fuzz=10M --summary all --error-style verbose
zig build test-tls-record-fuzz -Doptimize=ReleaseFast -Dtls-record-test-filter="fuzz: TLS record: encrypted stream scripted carrier progression preserves bytes and terminal state" --fuzz=10M --summary all --error-style verbose
zig build test-tls-record-fuzz -Doptimize=ReleaseFast -Dtls-record-test-filter="fuzz: TLS record: encrypted stream cleanup preserves root errors across alerts and epoch transitions" --fuzz=10M --summary all --error-style verbose

# Replay one named deterministic regression/companion case on its own
# (the same filter option also selects non-"fuzz:" test names):
zig build test-tls-record-fuzz -Dtls-record-test-filter="seal classifies every rejection stage at its exact boundary for every suite" --summary all --error-style verbose
zig build test-tls-record-fuzz -Dtls-record-test-filter="encrypted stream close is terminal and idempotent from every lifecycle state" --summary all --error-style verbose
```

No #493 target performs network I/O, draws ambient entropy, loads a real
key or certificate, or contacts an external peer: every case builds its own
`pure_zig.DeterministicEntropy`/`pure_zig.Provider` pair inside the callback
and works entirely from fixed stack buffers. The explicit bounds are:

| Bound | Value |
| --- | --- |
| Generated records per codec case | 4 (`fuzz_codec_max_records`) |
| Generated record payload | 48 bytes (`fuzz_codec_max_payload`) |
| Codec sink capacity | 1 record |
| Codec parser progress bound | `2 * stream_len + 16` `feedOne` calls |
| Inner-plaintext content / padding | 512 bytes each (boundary arms aside) |
| Protection content / padding | 64 / 32 bytes (boundary arms aside) |
| Protection output buffer | `max_ciphertext_record_len` (16 645 bytes) |
| Epoch operations per program | 48 (`fuzz_epoch_max_operations`) |
| Epoch record content | 24 bytes (`fuzz_epoch_content_len`) |
| Stream operations per program | 24 (`fuzz_stream_max_operations`) |
| Scripted carrier script length | 8 actions, cyclic (`scripted_script_len`) |
| Scripted carrier inbound queue | 4 096 bytes (`scripted_inbound_capacity`) |
| Scripted carrier capture buffer | 4 096 bytes (`scripted_capture_capacity`) |
| Peer plaintext chunk per record | 64 bytes (`fuzz_stream_peer_chunk`) |
| Caller read buffer | 512 bytes (`fuzz_stream_max_read_buf`) |
| Post-program flush rounds | 96 (`fuzz_stream_flush_rounds`) |
| Cleanup-case drives | 4 096 (`fuzz_cleanup_max_drives`) |

The stream targets additionally inherit the production per-`drive()` budgets
and fixed queue capacities, and assert them from the outside:
`drive_read_budget`/`drive_write_budget` (`2 * max_ciphertext_record_len`
each), `drive_read_chunk` (4 096), `drive_record_budget` (8), and the four
owned queues (`max_carrier_input_queue`, `max_plaintext_queue`,
`max_ciphertext_queue`, `max_handshake_queue`).

Boundary arms deliberately reach the real protocol limits
(`max_plaintext_fragment_len`, `max_ciphertext_fragment_len`, and one past
each) plus synthetic near-`usize`-max scalar lengths, which are driven
through length-only helpers rather than allocations.

`-Dtls-record-test-filter` defaults to `"fuzz: TLS record:"` (every #493
target; scoped narrower than a bare `"fuzz: "` prefix for the same reason
as `-Dtls-resumption-test-filter` above). This story is being delivered in
three PRs to keep agent context and review scope manageable, per the
issue's implementation-plan comment:

- **#493-A** (this slice) — build wiring (`test-tls-record-fuzz`,
  `-Dtls-record-test-filter`) and the two `record_codec.zig` targets.

  `codec fragmentation, coalescing, and sink saturation preserve exact
  consumption` generates a bounded oracle stream of valid records and drives
  it through `Parser.feedOne` against a single-record-capacity `RecordSink`,
  offering a **fuzzer-chosen prefix** of the remaining bytes on each call so
  a partial header or body stays buffered across the invocation boundary and
  must resume exactly on a later call (caller-visible fragmentation, not just
  `feedOne`'s internal byte loop); `emitted == false` is a normal outcome and
  must absorb the whole offered fragment. The parser's version policy is part
  of the generated case: when the initial-ClientHello compatibility window is
  selected, the stream becomes the fragments of one real `clientHelloMessage`
  (all handshake-content-type, so RFC 8446 SS5.1's no-interleaving rule
  holds) with each fragment's declared legacy version independently drawn
  from `{0x0303, 0x0301}` — every such fragment is inside the window and so
  must be accepted regardless of the mix, after which a further `0x0301`
  record on the same parser must be refused. The illegal placements are
  asserted against fresh compat-policy parsers: a non-ClientHello
  `msg_type`, a non-handshake content type, and ciphertext mode must each
  yield `InvalidRecordVersion`. A bounded single-record subcase drives the
  record-size boundaries (`0`, `1`, exact-maximum-minus-one, exact maximum,
  for both the plaintext and ciphertext limits) through the valid
  encode/parse/oracle path, and a header that merely *declares*
  maximum-plus-one is refused with `RecordTooLarge` without that payload ever
  existing. The target also asserts an undrained/saturated sink yields
  `consumed == 0` with parser and stale-sink state untouched, that
  `drainReady` publishes an already-buffered complete record without new
  input, that `finish()` only accepts a fully-drained parser, a per-case
  iteration bound (no spin on repeated non-progress), and that arbitrary
  bytes into a fresh parser never panic or exceed the fixed pending-buffer
  bound.

  `inner plaintext framing, padding, and bounds remain transactional`
  classifies the expected outcome of every `encodeInnerPlaintext` call
  **before** making it (`expectedInnerPlaintextEncode`, mirroring the
  documented rejection order: illegal content type, oversized content,
  overflow/oversized total, output capacity) and asserts that exact typed
  error rather than accepting any rejection, with the destination sentinel
  re-verified after each one. Content length, padding length, and output
  capacity each come from a boundary matrix — content around
  `max_plaintext_fragment_len`, total around `max_ciphertext_fragment_len`
  (padding carries the bulk, so exact-max and max-plus-one totals need no
  oversized content buffer), and capacity at exact-minus-one/exact/
  exact-plus-one — and `change_cipher_spec` is generated periodically and
  must always be `InvalidRecordType`. Raw-byte decoding is checked against an
  independent last-nonzero-byte oracle over a length matrix that reaches the
  exact ciphertext-fragment maximum and one past it, asserting borrowed-slice
  containment on every accepted decode. Both targets also drive a synthetic
  near-`usize`-max length (an overflow-adjacent case no real allocation could
  represent) against the checked scalar arithmetic helpers below.

  Because the deterministic `.corpus` replay that plain `zig build test`/CI
  runs is not guaranteed to reach every arm of these classifications, the
  error-class and split-point properties additionally have named
  deterministic tests next to them —
  `encodeInnerPlaintext classifies every rejection stage at its exact
  boundary` and `feedOne preserves exact consumption across every header and
  payload split point`. The former was validated by mutation: swapping
  `encodeInnerPlaintext`'s `out.len < total` error to `RecordTooLarge` makes
  it fail under plain `zig build test-tls`, whereas the corpus replay alone
  did not catch that regression (a coverage-guided run found it in ~15
  runs). Treat that as the standard for future #493 slices: a property worth
  fuzzing that CI's seed replay cannot reliably reach also needs a named
  deterministic case.
- Per the issue's "harden synthetic length arithmetic" requirement, this
  slice also converts the record-length-only calculations reachable from
  fuzzer-chosen scalar lengths to checked arithmetic returning a typed
  `RecordTooLarge` rather than wrapping: `record_codec.Parser`'s
  `checkedOwnedLen`/`checkedRecordLen` (backing
  `pendingRecordBytesNeededWith`/`pendingRecordPayloadLenWith`),
  `record_epoch_bridge.zig`'s `chunkCount`/`plaintextHandshakeRecordLen`/
  `protectedHandshakeRecordLen`/`sealHandshakeFragments`/
  `sealedHandshakeLen`, and `encrypted_stream.zig`'s `handshakeRecordCount`.
  Each of these (following `record_codec.encodeInnerPlaintext`'s existing
  precedent) now uses `std.math.add`/`std.math.mul`/`std.math.divCeil`
  instead of the `a + b - 1` / `a + b` idioms that can silently wrap for a
  synthetic scalar input near the `usize` boundary — a case fuzzing can
  drive directly as a bare length but never as a real allocation. Each
  helper has its own named deterministic boundary test in addition to the
  fuzz corpus; several (`chunkCount`, `handshakeRecordCount`) turn out to be
  overflow-safe *by construction* once expressed via `std.math.divCeil`
  (its `@divFloor(numerator - 1, denominator) + 1` form cannot itself
  overflow for a positive numerator/denominator), so their boundary tests
  assert exact agreement with `std.math.divCeil` at a synthetic near-max
  input rather than an error — the actual overflow these targets guard
  against surfaces one step later, in the callers that add `bytes_len` back
  on top of the chunk overhead.
- **#493-B** (this slice) — the `record_protection.zig` and
  `record_epoch_bridge.zig` targets.

  `protection tamper and sequence boundaries preserve authentication state`
  classifies the expected outcome of every `WriteState.seal` call **before**
  making it (`expectedSeal`, mirroring `seal`'s documented rejection order:
  exhausted sequence, `encodeInnerPlaintext`'s stages, sealed payload size,
  then output capacity) and asserts that exact typed error with the
  destination sentinel and the write sequence re-verified after each one.
  Each case picks one of the three suites, drives the traffic-secret length
  at exact-minus-one/exact/exact-plus-one for that suite's hash, and starts
  both directions at a sequence drawn from `{0, 1, 255, 256, maxInt-1,
  maxInt}`. Padding carries the size boundaries because it is a scalar the
  encoder zero-fills: the exact-maximum sealed payload, one past it, and a
  synthetic `maxInt(usize)` are all expressible without an oversized content
  buffer. On the accepting path the serialized header is re-derived
  independently and compared field by field (it is what the AEAD
  authenticates as associated data), a write at `maxInt(u64)` is proven
  usable exactly once before the state latches exhausted, and every returned
  view is checked for containment in its backing buffer.

  Each sealed record then runs a tamper battery against one shared read
  state — ciphertext bit flip, tag bit flip, tag truncation at every
  representative boundary, associated-data content-type and version
  mutation, a wrong read sequence, a wrong traffic secret, wrong
  suite-derived keys from the same secret, an authenticated-but-malformed
  all-zero inner plaintext, and an exact-minus-one output buffer. Every one
  must fail with its exact typed error and leave the sequence and exhaustion
  flag untouched; failures that reach the AEAD must leave the attempted
  plaintext span zeroed, while validation and preflight failures must leave
  the caller's buffer entirely untouched. Because all of them run against the
  *same* read state, the legitimate open that follows also proves a failed
  open leaves the state usable — and, once it succeeds, that replaying the
  same record at the now-advanced sequence fails closed.

  Provider error classes are exercised through a test-only `FaultProvider`
  wrapper rather than invented: `UnsupportedCapability` comes from masking
  one of the suite's two required capabilities so `TrafficKeys.derive`'s own
  preflight rejects it, and `InvalidInput` is injected at the
  `aeadSeal`/`aeadOpen`/HKDF vtable seam — the record API's own call shapes
  never produce it from a conforming pure-Zig provider, and `HkdfError`/
  `SealError` contain nothing else. The fixture zeroes `plaintext` on a
  forced open failure so the "no unauthenticated plaintext" property is not
  proven against a fixture weaker than the interface it stands in for.
  Teardown is asserted directly on the public `FixedSecret` backing arrays
  (`expectSecretsCleared`): key and IV bytes zero, lengths zero, sequence
  reset, state marked exhausted, and repeated teardown safe.

  `epoch operation sequences preserve one-way key lifecycle` runs a bounded
  program of at most 48 operations — traffic-secret install at every
  epoch/direction with a length matrix, epoch discard, handshake completion,
  negotiated-suite updates including unknown code points, seal and open at
  each epoch, and `deinit` teardown at an arbitrary point followed by
  continued operation — against a `Bridge` and an independent `EpochModel`
  written from the documented transition rules rather than from the
  implementation. After **every** operation, accepted or rejected, a
  `BridgeSnapshot` (both direction phases, all three discard flags,
  completion, the negotiated suite, and for each of the six key slots an
  optional holding its sequence) must equal the model's prediction. Folding
  key presence and sequence into one optional means the comparison catches
  both a key that should have been wiped and a sequence that advanced when
  it should not have; the snapshot also cross-checks `hasReadKeys`/
  `hasWriteKeys` against the private slots at every step. The model predicts
  not only each gate but whether a record can authenticate at all — it
  tracks the suite each slot was installed under and both sequence counters,
  and the target always uses one fixed secret per epoch so identical
  suite plus identical sequence means byte-identical keys. A bridge that
  opened a record under the wrong epoch's keys, or that consumed a read
  sequence number on a failed open, fails here.

  Terminal teardown is stated in the model as its own rule (`torn_down`)
  rather than being re-derived from the per-epoch discard and completion
  flags. That distinction is load-bearing: review of this slice found the
  model had reproduced two real `Bridge` defects instead of detecting them.
  The record contract has **two** session-teardown paths, and both reset
  `handshake_complete` to false — which was the *only* gate
  `installTrafficSecret(.zero_rtt, ...)` checked:

  1. `deinit`, the unconditional wipe for an abandoned or failed handshake;
  2. `discardEpoch(.application)`, the orderly teardown of a completed
     session, which `discardEpoch`'s own documentation calls session
     teardown.

  After either one, a bridge could reinstall both 0-RTT directions and
  resume sealing and opening records on that epoch. Because the model
  derived its rule from the same flags the implementation reset, model and
  implementation compared equal all the way through both resurrections.
  `Bridge` now carries a `torn_down` flag that every teardown path sets and
  nothing clears (starting a new session is `Bridge.init`), the model states
  the rule independently for both paths, and the snapshot compares the flag.
  0-RTT discard is deliberately *not* terminal: it is epoch-scoped, emitted
  whenever early data ends including mid-handshake, so the rule is scoped to
  session teardown rather than to "any discard".

  The general lesson for #493-C and later slices: a reference model that
  paraphrases the implementation's own gate expressions can only find
  inconsistencies, not policy violations — rules the contract requires
  should be written from the contract. The second defect is the sharper
  illustration, because fixing only the first path left the model still
  agreeing with the implementation on the second.

  Following #493-A's standard, both targets have named deterministic
  companions for the classifications CI's seed replay cannot reliably reach:
  `seal classifies every rejection stage at its exact boundary for every
  suite`, `open classifies every rejection stage at its exact boundary and
  never advances read state`, `record protection teardown zeroizes keys,
  resets sequence, and marks state exhausted`, and `the epoch lifecycle
  model agrees with a scripted full progression through teardown`, plus one
  per teardown path for the defects above: `record epoch bridge cannot
  reinstall zero-rtt keys after teardown` and `record epoch bridge cannot
  reinstall zero-rtt keys after orderly application discard`. The scripted
  companion exercises the application-discard window *before* any `deinit`
  call, so the two paths are mutation-detectable independently.

  All were validated by mutation, and in both directions for the terminal
  rule:

  | Mutation | Caught by |
  | --- | --- |
  | Drop `discardEpoch(.application)`'s `handshake_complete = false` | scripted companion (fuzz target in 16 runs) |
  | Swap `seal`'s `RecordBufferOverflow` for `RecordTooLarge` | `seal classifies every rejection stage…` |
  | Remove `installTrafficSecret`'s `torn_down` guard | both named teardown regressions (fuzz target in 17 runs) |
  | Remove production `torn_down` on application discard only | `…after orderly application discard` + companion (fuzz target in 38 runs) |
  | Remove the *model's* `torn_down` rule (either path) | scripted companion |

  The seed-corpus replay alone caught none of them, which is why each has a
  named companion. The last two rows are what keep the oracle honest: the
  model cannot silently regress back to mirroring the implementation on
  either teardown path.
- **#493-C** (this slice) — the `encrypted_stream.zig` targets, the scripted
  in-memory carrier they run on, and this closeout.

  `ScriptedCarrier` is a private test-only `Carrier` implementation built
  entirely from fixed arrays: a bounded inbound queue, a bounded capture
  buffer for everything the stream writes, independent cyclic read and write
  action scripts (`transfer at most N`, `WouldBlock`, zero-byte progress,
  `EndOfStream`, one typed carrier error per direction), and read/write/close
  call counters. It opens no descriptor, and neither stream target calls the
  module's existing socket-pair helpers — those stay behind the deterministic
  integration tests they already serve. A `.transfer` step with nothing to
  move reports `WouldBlock` rather than zero, because a zero-byte carrier
  *read* is EOF to `drive()`; zero-byte *writes* are scripted separately as
  the no-progress case.

  `encrypted stream scripted carrier progression preserves bytes and terminal
  state` runs a bounded program of at most 24 operations — `drive`, plaintext
  `read` with a caller-buffer matrix, plaintext `write` (up to the exact
  `max_plaintext_fragment_len` a single call can accept, so outbound
  saturation is reachable inside the budget), `close`, enqueueing another
  peer record, repeated `drive`, and teardown — against a real
  `PureZigRecordStream` pair. The peer is a full record stream too, so every
  inbound record is genuinely sealed and every outbound record genuinely
  opened; the oracle is checked against the record path rather than a
  hand-rolled encoder.

  Both application byte streams are *generated* (`subjectStreamByte`,
  `peerStreamByte`) rather than buffered, so "no loss or duplication" is
  "the `n`th delivered byte equals `f(n)`" plus a monotone
  delivered-at-most-accepted bound — which keeps a 16 KiB fragment write
  expressible without a 16 KiB oracle buffer.

  The peer is the *validator* for everything the subject emits, so its errors
  are never swallowed: only `WouldBlock` (its own buffer pressure, retried next
  round) and the explicit clean-`close_notify` branch are expected outcomes.
  Any other error from `feedCiphertext`/`readPlaintext`/`writePlaintext` means
  the subject produced bytes the real record path could not authenticate,
  frame, or deliver — exactly the corruption this target exists to catch — and
  propagates out of the case.

  Two structural rules keep the seed-corpus replay from being vacuous. Every
  case carries a **mandatory traffic floor** — at least one inbound record and
  one application write before the fuzzer's program — so there is always
  something to account for. And after the program and its flush loop, a
  **two-stage deterministic epilogue** lifts the scripted obstruction: stage
  one opens the write side only (so every drive is a *write-only* drive and
  carrier bytes are the sole thing that can justify `made_progress`), then
  stage two opens the read side and settles the stream. Without that epilogue a
  case whose script never let a byte through would reach the accounting
  assertions with nothing to assert.

  Around every `drive()` the target asserts:

  - exact outbound byte conservation, `queued_before == queued_after +
    bytes the carrier accepted`, so a partial write discards only the
    written prefix and keeps the unwritten suffix intact (skipped only for
    the two drives that legitimately change the queue by other means:
    sealing `close_notify`, and the close/terminal transition that clears
    every owned queue);
  - the per-drive carrier byte budgets, and — because a successful carrier
    read or write always moves at least one byte — `calls <= bytes + k`,
    which is the "no spin under repeated zero-progress readiness" property
    stated as a bound;
  - `made_progress` is *real*: a drive claiming progress moved a carrier byte
    or changed observable state, and a drive claiming none moved **no carrier
    byte in either direction, changed no observable state, and left every
    owned queue exactly as it was**;
  - `drive`'s returned readiness equals the stream's readiness on return.

  Per operation it also asserts every queue stays inside both its watermark
  and its fixed capacity, the plaintext queue and its provenance shadow move
  together, an owned carrier handle is released at most once ever, and — for
  a stream that has not been torn down — that backpressure pauses and resumes
  strictly alternate (`pauses - resumes == (paused ? 1 : 0)`, exactly, for
  both directions). Errors from plaintext I/O are classified rather than
  swallowed: an un-latched stream may only refuse I/O for one of the two
  deferred terminal conditions (`pending_terminal`,
  `pending_terminal_read_error`) and must report that condition unchanged.

  `encrypted stream cleanup preserves root errors across alerts and epoch
  transitions` covers the security-sensitive terminal paths in four scenario
  families: a deferred fatal-alert flush against a scripted write side that
  may progress partially, block, make no progress, or fail (the root error
  must latch unchanged, within the bounded deadline, with `write_bytes` never
  exceeding what was queued); a record-layer authentication failure behind
  already-delivered genuine plaintext; a `.handshake` epoch discard landing on
  a partially buffered record (`PartialRecordAtEpochTransition`, after which
  neither `handshake_complete` nor a further feed can reinterpret those bytes
  under application keys); and teardown with every owned buffer, both parsers,
  carrier input, and a pending terminal alert populated at once. Every
  terminal outcome runs `expectStreamStateCleared`, which checks that each
  owned buffer is not merely empty but *zeroed* in its backing storage —
  including both parsers' pending arrays and the plaintext provenance shadow —
  and that no key material survives at any epoch in either direction.

  Each family is deterministic once selected, and asserts its own outcome
  unconditionally: the authentication-failure family constructs and delivers
  its tampered record with `try` rather than early-returning on setup trouble,
  and requires `AuthenticationFailed` rather than accepting "no terminal error
  happened"; the teardown family dirties every state whose zeroization it
  checks — both parsers simultaneously, inbound plaintext with its provenance
  shadow, inbound handshake bytes, unparsed carrier input, queued outbound
  ciphertext, and a pending terminal alert — and asserts each one is nonzero
  immediately before `deinit()`. A scenario that cannot reach its own property
  is a gap in the target, not a passing case.

  **Production finding.** Asserting that teardown property against the
  *orderly* close path showed a completed close was not clearing its
  secret-bearing state. `fail()` and `deinit()` each release the handshake
  driver and wipe every bridge key, but a stream that finished a clean
  `close_notify` exchange only called `clearOwnedQueues()` and latched
  `.closed`. Two holders survived until the caller got around to `deinit()`:

  1. the bridge's **application traffic keys**; and
  2. the owned **handshake driver**, whose borrowed `EventSink` may still hold
     copied traffic-secret scratch until `Driver.deinit()` — a retention the
     transport contract documents explicitly.

  Nothing could *use* either (`.closed` rejects every entry point), so this is
  retention rather than an exploitable path, but it is retention with no
  purpose, and the record contract's rule is that a torn-down session keeps no
  secret-bearing state. The five orderly close-completion sites now share one
  `finishClose()` helper that runs the same teardown order as `deinit()` and
  `fail()`: `teardownDriver()`, then the queues, then the bridge.
  `authStillPending()` gained the matching `driver_torn_down` guard, because
  `drive()` can reach it later in the same call after an in-loop
  `queueCloseNotify()` completed the close.

  Following the #493-A/B standard, the scripted corpus classes the issue
  requires that a seed-corpus replay cannot reliably reach have named
  deterministic companions next to the targets:

  | Companion | Pins |
  | --- | --- |
  | `…delivers every byte across one-byte reads and writes` | full bidirectional exchange through single-byte carrier transfers |
  | `…settles without spinning under repeated would-block and zero-progress carriers` | 64 repetitions: no progress claimed, no byte moved, queue unchanged, readiness stable, constant carrier work per drive |
  | `…carrier EOF at every record boundary preserves truncation and delivery order` | EOF before a record, mid-header, mid-payload, one byte short, and exactly after a complete record; buffered plaintext delivered first, then the preserved `TruncatedStream` |
  | `…partial carrier writes preserve the exact unwritten suffix` | written prefix and retained suffix compared byte for byte on every drive, then reassembled and opened at the peer |
  | `…output saturation pauses plaintext writes and resumes below the low watermark` | one pause per crossing, a rejected retry consuming nothing, one resume, no byte lost across the cycle |
  | `…inbound plaintext saturation pauses carrier reads and resumes after draining` | the same, for the read side |
  | `…close is terminal and idempotent from every lifecycle state` | close during handshaking, open, closing, and failed; carrier released exactly once; the `finishClose` key wipe |
  | `…orderly close releases the handshake driver and its secret scratch` | a completed driver-owned session and a mid-handshake cancellation: driver and backend released exactly once *at close*, the sink's used secret scratch zeroed, and a later `deinit()` that does not release the backend twice |

  Mutation-validated:

  | Mutation | Caught by |
  | --- | --- |
  | Drop `bridge.deinit()` from `finishClose` | `…close is terminal and idempotent from every lifecycle state` |
  | Drop `teardownDriver()` from `finishClose` | `…orderly close releases the handshake driver and its secret scratch` |
  | Subject emits one corrupted ciphertext byte toward the peer | progression target, seed replay |
  | A carrier write is not reported as `made_progress` | progression target, seed replay (via the epilogue's write-only stage) |
  | `drive()` latches a carrier error instead of the preserved root error | cleanup target, seed replay |
  | `ByteQueue.clear` stops zeroing its backing storage | cleanup target, seed replay, plus two named cleanup tests |
  | `drive()`'s write loop consumes one byte more than the carrier accepted | `…partial carrier writes preserve the exact unwritten suffix` plus four existing tests |

  The corruption mutation has to be scoped to the subject's own role:
  corrupting *both* directions makes the case terminate early on a bad inbound
  record and never reach the outbound accounting at all — a useful reminder
  that a mutation which merely turns some test red is not the same as one that
  proves the property under test bites.

  TLS-over-TCP KeyUpdate and key replacement remain #357: the bridge exposes
  no such surface today, so the epoch target's operation set is the extension
  point for it rather than a fabricated API. The stream targets' operation
  sets are the corresponding extension point for any future post-handshake
  record-layer operation.

Ownership stays exactly as scoped above and in the issue: shared TLS
message/negotiation/transcript fuzzing is #491; PKI fuzzing is #492;
resumption/PSK/ticket/cache fuzzing is #494; provider primitive
malformed-input fuzzing is this file's own #376 targets; HTTP parsing and
external TLS-over-TCP interop are out of scope entirely. #408's
foundation-layer fixes (exact parser consumption, sink retry behavior,
legal initial-ClientHello `0x0301`, explicit epoch discard, sequence
exhaustion, key cleanup, independent record-protection vectors) are treated
as regression seeds/properties here, not reimplemented — the extensive
pre-existing deterministic `record_codec.zig` test suite already pins most
of them by name, and the #493 property targets promote them into generated
properties rather than leaving them as fixed examples: exact parser
consumption under fragmentation, sink retry behavior, and the
legal/illegal initial-ClientHello `0x0301` window in #493-A, epoch
discard/transition ordering, sequence exhaustion, and key cleanup in
#493-B, and partial-record rejection at an epoch transition, terminal-error
preservation across an alert flush, and byte-exact progression under
fragmented carrier I/O in #493-C.

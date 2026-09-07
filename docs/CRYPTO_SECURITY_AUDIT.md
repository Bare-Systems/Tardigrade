# Native crypto side-channel, secret-lifetime, and observability audit (#375)

This is the checked-in audit matrix required by #375 (epic #327, research
story 327-F). It covers constant-time comparison requirements, secret
ownership/lifetime, zeroization on every exit path, timing/oracle behavior at
protocol boundaries, and logging/diagnostic exposure for native TLS 1.3,
QUIC, PKI, record protection, and ticket/resumption code.

This document is a companion to, not a replacement for,
`docs/CRYPTO_PROVIDER_AUDIT.md` (#490): that document answers "does this code
call a concrete crypto primitive where it should call
`crypto.provider.CryptoProvider` instead?"; this document answers "for every
secret/authentication-derived value that exists once #490's architecture is
in place, is it compared safely, owned by exactly one place, wiped on every
exit, and never leaked through an observable side channel?" #490 closed
before this audit started, so every row below is scoped against its final
architecture, not the direct-`std.crypto` shortcuts it removed.

Audited commit: `728f154cc5d347e579094400ce423e83aa4ffc9c` (main, the same
commit PR #549 — the first #375 installment, secret-lifecycle cleanup paths
— merged as). Toolchain: Zig `0.16.0` (matches `build.zig.zon`'s
`.minimum_zig_version` and `docs/CRYPTO_PROVIDER.md`'s stated floor).

Use `docs/SECURITY_REVIEW_CHECKLIST.md` for reviewing new changes against
the rules this audit establishes; use this document to look up the current
disposition of an existing module.

## Methodology

Inventory seed (repeated against the audited commit; every hit below was
individually classified, not mechanically converted):

```sh
rg -n 'timing_safe|std\.mem\.(eql|order)|constantTimeEqual' src/crypto src/tls src/quic src/pki
rg -n 'secureZero|@memset|volatile|rawFree' src/crypto src/tls src/quic src/pki
rg -n '(key|secret|psk|binder|ticket|nonce|tag|token|private|scalar|fingerprint)' src/crypto src/tls src/quic src/pki
rg -n '(log|debug|print|fmt|metrics|trace|observer|panic)' src/crypto src/tls src/quic src/pki
```

Every secret-bearing struct's `deinit`/replacement/retirement path was
checked against the transitions #375 requires: successful completion,
parse/decrypt/authentication failure, allocation failure,
cancellation/teardown, replacement/reload, rotation/retirement, cache
eviction, snapshot release, and provider/credential destruction.

## Toolchain and platform assumptions

- **Zig floor**: `0.16.0`. `docs/CRYPTO_PROVIDER.md` requires the floor and
  every affected capability-matrix row to be updated together when this
  changes; the same rule applies to any constant-time/zeroization claim in
  this document.
- **Zeroization** is a project-code guarantee, not a toolchain or OS one:
  `crypto.secrets.secureZero` is Tardigrade-owned. It writes zeros through
  `*align(1) volatile @Vector(32, u8)` pointers, with a `*volatile u8` tail
  for the trailing 0–31 bytes. LLVM may not merge, widen, reorder away, or
  drop volatile stores, so the clear survives dead-store elimination in
  `ReleaseFast` by construction rather than by the optimizer's goodwill.
  This project does not layer any additional guarantee (no `mlock`, no
  core-dump suppression, no explicit compiler-barrier intrinsic) on top of
  those volatile stores.

  It deliberately does **not** wrap `std.crypto.secureZero(u8, buffer)`,
  which it used to. That function is `@memset` over a `[]volatile T`, and
  LLVM discards the `volatile` qualifier on such a memset and lowers it to
  an ordinary `memset` libcall. The resulting clear is still performed, so
  this was not a correctness or non-elision defect — but *which* `memset`
  gets linked is platform-dependent, and on x86_64-linux it binds to
  `compiler_rt.memset`, a byte-at-a-time store loop that wins over libc's
  optimised `memset` even with `link_libc = true`. (`compiler_rt.memcpy` is
  size-dispatched and fast; only `memset` is naive.) On aarch64/macOS the
  same source bound to libSystem's vectorised `_bzero`. Measured cost of one
  265,408-byte wipe was 4.35 µs on aarch64 versus 95.9 µs on x86_64 — a 22×
  gap that had nothing to do with CPU class — and 7.6 µs after this change.
  Discovered while triaging a repeatedly-timing-out #675 QUIC fuzz row; see
  that issue for the full measurements.

  Consequence for reviewers and new code: a plain `@memset(buf, 0)` on
  secret-bearing storage is **not** equivalent to `secureZero` and must not
  be used for it. That distinction is now load-bearing rather than
  stylistic. `src/tls/encrypted_stream.zig`'s `ByteQueue` routes all three
  of its wipes (compaction stale-source tail, `discard`, `clear`) through
  the canonical helper for exactly this reason; its sibling
  `PlaintextProvenanceQueue` correctly keeps plain `@memset`, because it
  holds `bool` provenance bookkeeping rather than secret material.

  `crypto.secrets.secureZeroAndFree` exists specifically
  because plain `Allocator.free` is **not** sufficient on its own: safety
  builds run `@memset(bytes, undefined)` *after* any zeroing already done
  (re-poisoning the buffer, which trips allocator "was this zeroized"
  assertions), and in `ReleaseFast` "undefined" carries no required bit
  pattern, so the compiler is free to emit no write at all. Any code path
  that zeroizes and then calls plain `allocator.free`/`.free()` (or, for an
  `ArrayList`, `.deinit()`) instead of `secureZeroAndFree` is not actually
  guaranteed to scrub the buffer in a production build — see
  `src/tls/identity_loader.zig`'s doc comment for the same reasoning,
  independently arrived at, on the loader's PEM/DER cleanup path. This audit
  found and fixed four more instances of exactly that pattern in
  `src/tls/ticket_key_snapshot.zig` (`OwnedSnapshot.deinit`, `loadFromFile`,
  `reserveNonceLeasesInFile`'s serialize buffer, `parse`'s `key_storage`
  `errdefer` — see the ticket-protection row below) and one in
  `crypto.secrets.BoundedSecret.deinit` itself, the shared bounded-secret
  container `appliance_credentials.zig`/`identity_loader.zig` build their
  own PEM/DER/PKCS#8 scratch cleanup on top of — `deinit` called `clearAll()`
  (a real, volatile zero) followed by plain `allocator.free(self.bytes)`,
  so every caller of the shared primitive inherited the same gap even
  though each individually looked correct at the call site. Fixed to route
  through `secureZeroAndFree`. `secureZeroAndFreeAligned(T, allocator, buf)`
  was added alongside these fixes: `secureZeroAndFree` hardcodes
  `alignOf(u8)` when calling `rawFree`, which is safe only for a `[]u8` (or
  a same-alignment byte-cast of a wider type); a typed secret-bearing slice
  whose element alignment differs must go through the generic form instead,
  so `rawFree` receives the same alignment `alloc` originally did.
- **Constant-time comparison**: `crypto.secrets.constantTimeEqual` /
  `crypto.provider.constantTimeEqual` route through `std.crypto.timing_safe`
  (see `src/crypto/secrets.zig`). This project relies on `std.crypto`'s own
  documented constant-time behavior for its comparison and AEAD/signature
  primitives; it does not independently verify constant-time behavior at the
  instruction or microarchitectural level. Whether a given primitive's
  constant-time property holds is therefore inherited from the Zig standard
  library and, transitively, from the target's C/assembly codegen — it is
  target- and optimizer-version-dependent in the same way upstream
  `std.crypto` is, and this project makes no stronger claim.
- **Residual side-channel risk**: cache-timing, branch-prediction, and other
  microarchitectural side channels are explicitly out of scope (#375
  non-goal: "proving arbitrary hardware is immune to microarchitectural side
  channels"). The controlled-appliance hardware profile (#391) may narrow
  the practically relevant threat model (fixed, operator-controlled
  hardware and co-tenancy assumptions) but this document makes no claim that
  it eliminates microarchitectural leakage — only that software-level
  timing/lookup dependence on secret data is what this audit's "constant
  time" language refers to.
- RSA-PSS, Ed25519, ECDSA-P256, X25519, and the AEAD/HKDF primitives used
  under the provider boundary are the pure-Zig `std.crypto`-backed
  implementation (`src/crypto/pure_zig.zig`) per #490; the approved OpenSSL
  production backend is future work and has no code to audit here yet.

## Audit matrix

Status values: `compliant` (already correct, no change), `fixed-in-375`
(this story changed it), `public-no-ct-required` (classified public/
attacker-controlled, ordinary comparison is correct), `follow-up`
(deferred, tracked by a linked issue).

### TLS handshake secrets

| module / function | value | classification | operation | attacker observable? | owner / lifetime | cleanup paths | required treatment | status | rationale |
|---|---|---|---|---|---|---|---|---|---|
| `src/tls/pre_shared_key.zig:verifyBinderFromTranscriptHash` | computed PSK binder vs. wire `candidate_binder` | secret-derived (HMAC output over transcript hash + PSK) | compare | remotely observable (peer controls `candidate_binder` and the transcript that shapes the computed side) | `computed` is a stack buffer local to the call; wiped by `defer crypto.secureZero(u8, out)` before every return, including the early length-mismatch return | wiped on every exit (success, mismatch, length mismatch) | CT compare after ordinary public-length check | fixed-in-375 | Was a direct `crypto.timing_safe.eql` per fixed-length branch (32/48); now routes through `provider.constantTimeEqual` after the same public length check (RFC 8446 §4.2.11.2 fixes binder length to the hash digest length, so the length check itself is public). Wipe coverage was already correct and is unchanged. |
| `src/tls/pre_shared_key.zig:deriveBinderFromTranscriptHash` (both sha256/sha384 branches) | `psk_fixed`, `early_secret`, `binder_key`, `finished_key`, `mac` intermediates | secret / secret-derived | derive (HKDF-Extract/Expand, HMAC) | not directly observable (never returned whole) | stack-local to the function | `defer crypto.secureZero(...)` on every intermediate, unconditionally | wipe on every exit | compliant | Pre-existing; unaffected by this story's changes. |
| `src/tls/tls13_backend.zig:onServerFinished` | computed `expected` verify_data vs. wire Finished `body` | secret-derived (HMAC-based Finished value per RFC 8446 §4.4.4) | compare | remotely observable | `expected` is a local `[hash_len]u8`; `defer crypto.secureZero(u8, &expected)` covers every exit | wiped on every exit | CT compare after ordinary length check (`body.len != hash_len`) | fixed-in-375 | Was `crypto.timing_safe.eql([hash_len]u8, expected, body[0..hash_len].*)`; now `crypto_pkg.provider.constantTimeEqual(&expected, body[0..hash_len])`. Wipe coverage unchanged, already correct. |
| `src/tls/tls13_backend.zig:onClientFinished` | computed `expected` verify_data vs. wire Finished `body` | secret-derived | compare | remotely observable | same shape as `onServerFinished` | wiped on every exit | CT compare after ordinary length check | fixed-in-375 | Same fix, client side. |
| `src/tls/key_schedule.zig` | HKDF-Extract/Expand-Label outputs (early/handshake/master/resumption/PSK secrets, traffic keys, Finished `verify_data` derivation) | secret / secret-derived | derive | not directly observable | provider-owned per #490; `KeySchedule` holds derived secrets, `errdefer`/`defer` armed before the fallible provider call fills the buffer | wipe via `provider.secureZero` on every exit, including a fault-provider partial write (covered by `key_schedule_tests.zig`'s fault-provider fixture) | N/A (no raw comparison here; see #490 for the provider-boundary story) | compliant | Out of #375's direct-fix scope — #490 already completed this migration and its error-cleanup-ordering hardening. Re-audited here and found correct: no raw `std.crypto` HKDF calls remain, cleanup is armed before the fallible call, not after. |
| `src/crypto/rsa.zig` (PSS verification, final hash comparison) | computed `expected` EMSA-PSS hash vs. `h_array` from the encoded message | secret-derived in the sense that this is the authentication decision, though both operands are computed from public signature/message bytes — the *decision* (accept/reject) is what must not leak via timing, not the operand values themselves | compare | remotely observable (signature verification result gates authentication) | both `expected` and `h_array` are stack-local `[h_len]u8`, not retained | no retention, nothing to wipe beyond normal stack reuse | CT compare | fixed-in-375 | Was `crypto.timing_safe.eql([h_len]u8, expected, h_array)`; now `secrets.constantTimeEqual(&expected, &h_array)`. |
| `src/crypto/rsa.zig` (EMSA-PSS structural checks: `em[em.len-1] != 0xbc`, `db_len` bound, unused-bit mask, `masked_db[0]` high-bit check, `PS` zero-padding loop, `db[ps_len] != 1`) | encoded message structure, DB padding | attacker-controlled / public (the signature/message encoding itself, not a secret) | branch / early-reject | remotely observable, but over attacker-supplied structural data, not secret material | N/A | N/A | ordinary branch — explicitly **not** flattened to constant time | public-no-ct-required | #375 explicitly instructs against mechanically converting structural/format validation over attacker-controlled encodings; only the final authentication comparison (above) requires CT treatment. Early-rejecting a malformed signature encoding faster than a well-formed-but-wrong one is a standard, accepted PSS verifier property (RFC 8017 does not require these structural checks to be constant-time, and no PSK/ticket-style decryption oracle exists downstream of an RSA-PSS verification failure — see #490's `tls13_backend.zig` mapping of both malformed-signature and wrong-signature to the single `.invalid_signature`/`decrypt_error` outcome, so the *result* returned to the peer is uniform even though internal rejection speed is not). |
| `src/tls/credentials.zig` (`Identity.sign` / `SigningKey` opaque handle) | private scalar / seed | secret | sign, store | not observable (never leaves the opaque handle) | `crypto_pkg.secrets.FixedSecret(32)` for the ECDSA scalar; `defer crypto.secureZero(u8, &scalar)` wipes the raw scalar immediately after wrapping it; `FixedCredentialProvider.deinit` wipes `identity.key` | wiped on init failure, and on `deinit` | N/A (opaque signing, no raw comparison) | compliant | Per #490, private-key bytes never cross into the TLS state machine; signing goes through `provider.SigningKey`. Re-audited for #375 and found the raw-scalar-to-`FixedSecret` handoff wipes the transient plaintext copy. |
| `src/crypto/rsa.zig` (`PrivateKey`, `validateComponentRelationships`, `isProbablePrime`, `signPssSha256`) / `pure_zig.SoftwareRsaSigningKey` (#565) | RSA private exponent `d` and public exponent `e` (retained); modulus `n` (retained, public); `p`, `q`, `dp`, `dq`, `qInv` (parsed, relationship- and primality-validated at `parsePrivateKeyDer`, then discarded — not retained in `PrivateKey`); the 32-byte PSS salt drawn from `provider.Entropy` per signature | secret (`d`, salt, and `p`/`q`/`dp`/`dq`/`qInv` transiently during validation); public (`n`, `e`) | sign (EMSA-PSS encode + private-exponent modular exponentiation), validate (component relationships and primality), store | not observable (the signature is the only output; a wrong/malformed key or entropy failure never publishes a partial signature — enforced by both `signPssSha256`'s ordering, see below, and `SoftwareRsaSigningKey.signingSignImpl`'s output-length check before the entropy draw, mirroring `SoftwareEcdsaP256SigningKey`) | `PrivateKey.deinit` (`secrets.secureZero(&self.d)`) wipes the retained private exponent; `SoftwareRsaSigningKey.deinit` delegates to it; `FixedCredentialProvider.deinit` wipes the whole `identity.key` union (covers the RSA variant identically to Ed25519/ECDSA); `validateComponentRelationships`'s `FixedBufferAllocator` scratch buffer — which holds working copies of every private component and every intermediate the relationship checks compute — is wiped via `defer secrets.secureZero(&scratch)` on every exit, success or any early return, not left for the next stack frame to overwrite | wiped on `deinit`; scratch buffer wiped unconditionally by `defer` (a v2 review flagged the earlier unwiped version) | modpow (the per-signature hot path): constant-time-oriented by construction; component-relationship and primality validation (the one-time key-import path): not constant-time (see rationale) | compliant | **Constant-time signing, no CRT**: the private operation is a direct `n`/`d` modular exponentiation via `std.crypto.ff.Modulus(4096).powWithEncodedExponent` — the stdlib's non-`public`-exponent path, which the same file's own verification path (`powWithEncodedPublicExponent`) deliberately does *not* use, precisely because `d` is secret. No CRT is used for the *operation*, sidestepping an entire class of CRT-specific side-channel and fault-injection concerns (CRT bit-flip/Bellcore-style attacks) at the cost of the ~4x speedup CRT would give; #565 accepted that trade-off explicitly for a first native implementation. **CRT components are fully relationship-validated at import, not merely range-checked**: `parsePrivateKeyDer` requires `n = p·q`, `p ≠ q`, `dP = d mod (p−1)`, `dQ = d mod (q−1)`, `qInv·q ≡ 1 (mod p)`, and `e·d ≡ 1 (mod lcm(p−1, q−1))` before ever returning a key — implemented with `std.math.big.int.Managed` over a bounded, non-allocator-escaping `FixedBufferAllocator` scratch buffer (an allocator-backed exception to this module's otherwise allocation-free design, deliberately confined to the one-time key-import path, never the per-signature hot path signing itself still never touches). Not constant-time — a v1 review flagged the earlier structural-only version as insufficient per #565's acceptance criteria, and this closes that gap. **`p`/`q` primality is checked, not merely their algebraic relationship to `n`/`d`**: a v2 review correctly observed that every equation above is satisfied by *any* correct factorization of `n`, prime or not, so a composite-factor structure could still pass — proven concretely by a checked-in test that constructs a full 2048-bit key where `p` and `q` are each themselves composite (products of two ~512-bit primes) yet satisfy every relationship exactly (`"RSA private-key DER rejects a full 2048-bit key whose p and q are composite but satisfy every algebraic relation"`). `isProbablePrime` closes this with Miller-Rabin, built on the same `std.crypto.ff.Modulus` primitive signing/verification already use (no new modexp implementation). **Witnesses are drawn randomly from `provider.Entropy` (`drawWitness`'s rejection sampling over `[2, n-2]`), not a fixed set**: a v3 review correctly identified that a first version using 40 fixed small-prime bases is not sound against an *adversarially chosen* key — published strong pseudoprimes to every small prime base already exist in the literature, and a fixed/public witness set gives an attacker who knows it in advance exactly what to construct against. 64 independently random rounds instead bound the false-positive probability by `4^-64` (Monier-Rabin), unpredictable to whoever supplies the candidate key. Because the key type is not known until `rsaKeyDerFromPkcs8` succeeds partway through parsing, `credentials.Identity.initPkcs8` (unchanged, 44 pre-existing call sites across the codebase, none needing modification) now fails closed with `error.InvalidPrivateKey` for an RSA key rather than silently skipping the primality check; a new `Identity.initPkcs8WithEntropy` takes the required `provider.Entropy` and is the only path that can construct an RSA identity. **Every stack value carrying the secret modulus is wiped, not only the raw byte buffers**: a v4 review correctly observed that `n_minus_one`/`d`'s byte buffers being wiped was not enough — `ff.Modulus`/`Fe` values (`modulus_fe`, which literally embeds `p`/`q`; `n_minus_one_fe`; each round's `base_fe`; and the evolving `x` residue through repeated squaring) are separate stack-resident struct values also carrying the secret modulus or values derived from it, and were left live on every exit path. Each is now wiped via `defer secrets.secureZero(std.mem.asBytes(&value))` immediately after its declaration; `base_fe`/`x` are declared inside the per-witness round loop, so their `defer`s fire once per round (before the next witness is even drawn), not only once at function exit. **`EntropyFailure` is preserved distinctly through the credential-import path, not collapsed into `InvalidPrivateKey`**: `credentials.Identity.InitError` gained an `EntropyFailure` case, and `initPkcs8WithEntropy`'s RSA branch maps `pure_zig.SoftwareRsaSigningKey.fromDer`'s `error.EntropyFailure` straight through, so a transient/local entropy-source fault during Miller-Rabin witness-drawing is never misreported as malformed credential data — a v4 review flagged the prior version's blanket `catch return error.InvalidPrivateKey` for conflating the two. This is a strong heuristic, not a formal primality proof at RSA prime sizes — see `isProbablePrime`'s doc comment — but it closes the concrete gap identified, and is regression-tested against real Carmichael numbers (561, 1105, 1729, 8911) and the smallest Fermat pseudoprime to base 2 (341), which a single-base or purely-algebraic check would miss. A key whose components are internally inconsistent or whose `p`/`q` are composite is now rejected at `parsePrivateKeyDer`, not merely self-detected later by a failing signature. Regression-tested by flipping the least-significant byte of each of `n`/`d`/`p`/`q`/`dp`/`dq`/`qinv` independently in a real fixture key (`rsa.zig`'s `"RSA private-key DER rejects every component mutation that breaks a required relationship"` test) and by setting `p == q` directly; `EntropyFailure` preservation is regression-tested by `credentials.zig`'s `"identity parser preserves EntropyFailure distinctly from InvalidPrivateKey for RSA"` test. |
| `src/tls/credentials.zig` (`Identity.initPkcs8`'s RSA branch, `rsa.PrivateKey.matchesPublicKeyDer`) (#565) | the certificate leaf's `RSAPublicKey` (modulus, exponent) vs. the private key's own retained `n`/`e` | public (both operands are public key material) | compare (exact modulus/exponent equality, not a cryptographic operation) | not security-sensitive as a comparison (both sides are public), but its *outcome* gates whether a credential is advertised at all | N/A | N/A | ordinary comparison — no CT requirement (public data) | compliant | A structurally valid, internally consistent RSA private key is not necessarily *this* certificate's key. `initPkcs8` now parses the leaf and requires `pub_key_algo == .rsaEncryption` and `matchesPublicKeyDer` before returning an `Identity` at all, so an unrelated certificate/key pairing is rejected at construction — before any credential is ever selected or a peer sees a doomed-to-fail CertificateVerify — rather than being discovered only when the peer rejects the signature. Regression-tested with a fixture certificate paired against a second, unrelated, individually-valid RSA-2048 key (`"identity parser rejects an RSA certificate paired with an unrelated RSA private key"`). |

### QUIC

| module / function | value | classification | operation | attacker observable? | owner / lifetime | cleanup paths | required treatment | status | rationale |
|---|---|---|---|---|---|---|---|---|---|
| `src/quic/packet.zig:verifyRetryIntegrity` | computed Retry integrity tag vs. wire tag | authentication result over public RFC-fixed key/nonce — the tag values themselves are not secret (the AEAD key is a public constant from RFC 9001 §5.8), but the comparison gates whether a received Retry packet is accepted, i.e. input-validation-sensitive | compare | remotely observable — this is the live production call site (`src/quic/connection.zig:2000`, client-side Retry acceptance) | `expected`/`received` are stack-local, not retained | N/A (no secret retention; the AEAD key/nonce are fixed public constants, not connection-specific secrets) | CT compare (hygiene: treat the accept/reject decision as timing-sensitive input validation even though the key material is public) | fixed-in-375 | Was `std.crypto.timing_safe.eql([retry_integrity_tag_len]u8, expected, received.*)`; now `secrets.constantTimeEqual(&expected, received)`. This is the disposition #375 names explicitly: "document that fixed RFC Retry key/nonce constants are public while the authentication result remains timing-sensitive input validation." |
| `src/quic/path.zig` Retry integrity vector | RFC 9001 §5.8 known-answer coverage for `packet.zig`'s Retry integrity implementation | authentication result over public RFC-fixed key/nonce, exercised only by test | compare | not production-reachable — the test now calls `packet.computeRetryIntegrityTag` / `packet.verifyRetryIntegrity` directly | N/A | N/A | inherited from `packet.zig` live implementation | consolidated-in-555 | The former independent `path.zig` `retryIntegrityTag` / `verifyRetryIntegrity` copy was deleted in #555. The Appendix A.4 vector remains in `path.zig` only as coverage for the single implementation in `packet.zig`, eliminating the prior same-name, reversed-argument-order duplicate. |
| `src/quic/path.zig:validatePathResponse` (PATH_CHALLENGE/PATH_RESPONSE) | locally-generated unpredictable challenge value vs. peer-echoed response | secret-derived in effect: an unpredictable, locally-chosen anti-spoofing nonce (RFC 9000 §8.2) whose correct-guess probability is the entire security property being enforced; not "secret" in the key-material sense, but its comparison functions as authentication of path ownership | compare | remotely observable (an off-path or blind attacker could, in principle, use timing to improve a guessing strategy across repeated PATH_RESPONSE attempts) | `candidate.challenge` is owned by the `PathCandidate` entry in `PathManager.paths`, cleared implicitly when the slot is reused/promoted (no long-lived retention beyond the validation window) | N/A beyond normal candidate-slot reuse; the challenge is not secret material requiring wipe-on-teardown (it is discarded, not retained as a credential) | CT compare (hygiene — the call site already used `timing_safe.eql`, so #375 only routes it through the canonical helper rather than newly introducing CT treatment where none existed) | fixed-in-375 | Was `std.crypto.timing_safe.eql([path_challenge_len]u8, candidate.challenge, data)`; now `secrets.constantTimeEqual(&candidate.challenge, &data)`. Not named explicitly in #375's "known concrete review targets" list, but caught by the issue's own inventory command (`rg 'timing_safe|...' src/quic`) and migrated for the same reason `packet.zig`'s Retry check was: the call was already constant-time, this is a canonical-helper consistency fix, not a new CT requirement being introduced over a value #375's "do not mechanically convert" warning would otherwise protect. |
| `src/quic/path.zig:RetryTokenKeyRing` (`install`/`retire`/`deinit`) | address-validation token AEAD keys | secret | store, retire, replace | not observable | `secrets.FixedSecret(token_key_len)` per slot | `install` → `FixedSecret.replace` wipes the old slot's tail before reuse; `retire`/`deinit` → `FixedSecret.deinit` wipes | wipe on install (replace), retire, and deinit | compliant | Fixed by PR #549 (the first #375 installment, merged as `728f154c`). Re-verified here: no `?[N]u8`-wrapped optional payload (which safety builds could poison-fill, defeating a"was this wiped" assertion — see the type's own doc comment), tracked by `.len` instead. |
| `src/quic/cid.zig:LocalCidRegistry` | stateless-reset derivation key (`reset_token_key`); per-entry stateless reset tokens | derivation key: secret; per-entry tokens: authentication/security-sensitive (locally-derived, used to prove "this reset came from us" if a peer ever needs to recognize it) | store, derive, retire | derivation key: not observable; per-entry tokens: sent to the peer as part of `NewConnectionIdFrame`/transport-parameter reset tokens, so they are intentionally peer-visible once issued — what must not leak is the *derivation key* they came from | `reset_token_key: secrets.FixedSecret(32)`, registry-lifetime; per-entry `stateless_reset_token: [16]u8` inside each `Entry`, entry-lifetime | `deinit` wipes the derivation key and every still-occupied entry's token; `retire` wipes the retired entry's token immediately | wipe on retire and deinit | compliant | Fixed by PR #549. Re-verified: `statelessResetTokenInto`'s intermediate HMAC buffer is also wiped (`defer secrets.secureZero(&mac)`). |
| `src/quic/cid.zig:PeerCidPool.onNewConnectionId` (`std.mem.eql(u8, &token, &frame.stateless_reset_token)`) | previously-stored vs. newly-framed stateless reset token, for the *peer's* connection IDs | public/protocol bookkeeping — this detects an exact-duplicate `NEW_CONNECTION_ID` frame retransmission for the same sequence number, not stateless-reset authentication; the peer already sent us this exact token once, we are only checking it matches on retransmit | compare | remotely observable, but the comparison result only affects idempotent frame-processing (accept/reject a retransmit as a duplicate), not an authentication decision | N/A | N/A | ordinary compare — explicitly **not** CT | public-no-ct-required | #375 explicitly warns against CT-converting CID/token comparisons "merely because they are adjacent to secret material." This is peer-echoed data compared for protocol bookkeeping, not a value this endpoint derived from its own secret; it is the mirror case of the `LocalCidRegistry` row above, not the same value. |
| `src/tls/ticket_protection.zig` / `RetryTokenKeyRing` / `LocalCidRegistry` production callers (`http3_runtime.zig`, `connection.zig`) | — | — | — | — | — | full teardown paths added by PR #549: `Connection` deinit now deinitializes the local CID registry and wipes stateless-reset key material | wipe on connection teardown | N/A | compliant | Confirms #549 closed the "QUIC connection teardown must deinitialize local CID registry and wipe stateless reset key material" gap #375 named explicitly. |

### Ticket protection and resumption

| module / function | value | classification | operation | attacker observable? | owner / lifetime | cleanup paths | required treatment | status | rationale |
|---|---|---|---|---|---|---|---|---|---|
| `src/tls/ticket_protection.zig:validateReplacementLocked` (`entry.key_fingerprint` vs. `key_fingerprint`, both occurrences) | SHA-256-based fingerprint of a configured ticket AEAD key, used to detect duplicate key material on reload | secret-derived (deterministic function of secret key bytes) | compare | local/configuration path (reload-time), not peer-triggered, but #375 explicitly treats this as secret-dependent control flow regardless of remote observability | `key_fingerprint` is a stack-local `defer secrets.secureZero(&key_fingerprint)`-wiped buffer; `entry.key_fingerprint` lives in the ledger, wiped on deinit | wiped on every fingerprint-computation exit and on ledger-entry teardown | CT compare | compliant | Already used `secrets.constantTimeEqual` before this story; no change needed. #375 names this exact site ("Ticket protection: secret-derived fingerprints") as a required-disposition target, and it was already compliant, presumably from earlier #372/#490-adjacent hardening. |
| `src/tls/ticket_protection.zig` (`prior.key.eql(&key.key)`, duplicate-key-in-one-batch check) | configured ticket AEAD key equality (raw key bytes, not fingerprint) | secret | compare | local/configuration path | `key.key` is a `secrets.FixedSecret`; `.eql` is `FixedSecret.eql`, which calls `constantTimeEqual` internally | N/A (comparison only) | CT compare | compliant | #375 names "ordinary equality on raw configured key bytes" as a required audit target; the actual comparison already goes through `FixedSecret.eql` (constant-time), not raw `std.mem.eql`. |
| `src/tls/ticket_protection.zig:zeroAndFree` | ticket plaintext / key buffers | secret | free | N/A | delegates to `secrets.secureZeroAndFree` | wipe-then-free in one call | canonical helper, no custom primitive | compliant | #375 names "ad hoc zero-and-free" as a required audit target; the function already delegates entirely to the canonical helper — it is a one-line named wrapper for call-site clarity, not a reimplementation. |
| `src/tls/ticket_key_snapshot.zig` (`ZeroingAllocator.resize`/`.free`, `OwnedSnapshot.deinit`, `loadFromFile`, `reserveNonceLeasesInFile`'s serialize buffer, `parse`'s `key_storage` `errdefer`) | raw snapshot file bytes, JSON-parser scratch allocations, decoded AEAD key storage, re-serialized plaintext buffer | secret (raw ticket-protection keys) and secret-adjacent (any buffer that held them during decode/encode, including transient JSON parser allocations) | wipe-then-free | not observable (local file I/O) | `key_storage: []KeyStorage` owned by `OwnedSnapshot`; every JSON-parser allocation routed through a purpose-built `ZeroingAllocator` so *any* freed/resized parse-scratch buffer is wiped regardless of which JSON value it backed | wiped on `OwnedSnapshot.deinit`, on `parse`'s `errdefer` (partial `key_storage` on a later field failing), on `loadFromFile`'s raw-bytes `defer`, and on the reload path's re-serialization buffer | canonical helper, freed through `rawFree` | fixed-in-375 | An earlier pass of this audit incorrectly marked this row `fixed-in-375` for only migrating the four listed sites from `std.crypto.secureZero`/`std_crypto` to the canonical `secureZero` wrapper, while `OwnedSnapshot.deinit`, `loadFromFile`, `reserveNonceLeasesInFile`'s serialize buffer, and `parse`'s `key_storage` `errdefer` still handed the zeroed buffer to ordinary `Allocator.free`/`ArrayList.deinit` afterward — exactly the pattern this document's own toolchain-assumptions section says is insufficient (`Allocator.free`'s `@memset(bytes, undefined)` can re-poison the buffer in safety builds, or the compiler may elide it entirely in `ReleaseFast`, so the backing allocator was never guaranteed to observe zero). Re-reviewed and corrected: all four now route through `secrets.secureZeroAndFree` (`loadFromFile`'s raw bytes, the serialize buffer via its full `allocatedSlice()`, matching the exact region handed to `rawFree`) or the new `secrets.secureZeroAndFreeAligned` (`OwnedSnapshot.deinit` and `parse`'s `key_storage` `errdefer` — `secureZeroAndFree` hardcodes `alignOf(u8)`, which understates the alignment contract for a typed `[]KeyStorage` even though `KeyStorage`'s own alignment happens to coincide with `u8`'s). `ZeroingAllocator.resize`/`.free` were already correct: they call the child allocator's vtable function pointer directly, which is the raw-free path, not the poisoning `Allocator.free` wrapper. `crypto.secrets.BoundedSecret.deinit` had the identical zero-then-ordinary-free defect and is fixed alongside these; see its own row below. |
| `src/tls/sni_provider.zig:SignAdapter.release` (`.identity` branch) | `Identity.key` (private scalar/seed wrapper) | secret | wipe on release | not observable | released once per `SignAdapter`, called from `releaseConfiguredSigners` and `CredentialBundle.deinit` | wipe on release | canonical helper | fixed-in-375 | Was `std_crypto.secureZero(u8, ...)` (a locally aliased `std.crypto`, not the canonical wrapper); now `crypto_provider.secureZero(...)`. Same hygiene class as the `ticket_key_snapshot.zig` fixes above. |
| `src/tls/ticket_protection.zig:Protector.resolve` / `resolveInner` | ticket AEAD key, decrypted plaintext, `ResolveRejectReason` classification | secret (key, plaintext) / non-secret-bearing closed enum (rejection reason) | lookup, decrypt, classify | see "Resumption and ticket oracle review" below | key/plaintext scoped to the resolve call; `ResolveRejectReason` is a stack value passed only to the local `Observer` | plaintext/key buffers wiped via `zeroAndFree/secureZero` on every resolve exit | oracle-uniform external result; rich classification kept strictly local | compliant | See the dedicated oracle-review section below for the full failure-class enumeration and the one documented, spec-required asymmetry. |
| `src/tls/session_cache.zig` (`ClientSessionCache`/`StatefulServerCache` `deinit` family; `secrets.constantTimeEqual(&e.handle, &key)` bearer-handle confirmation) | session ticket/PSK bearer handles, persisted entries, resumption state | secret / secret-derived | store, compare, retire | handle-confirmation compare: this endpoint holds the bearer secret and is confirming a caller-supplied one against it, not accepting peer input directly at this layer | entries owned by the cache, `PersistedClientEntry`/`PersistedServerEntry`/`ServerLease`/`ResolveLeaseResult` each wipe their own state in `deinit` | wiped on every listed `deinit`, and explicitly via `secrets.secureZero(std.mem.asBytes(entry))` at the persistence boundary | CT compare for the bearer-handle confirmation; canonical wipe helpers elsewhere | compliant | Already using `secrets.constantTimeEqual`; no change. Included here as an audited, not merely assumed-fine, row per #375's resumption/ticket scope list. |
| `src/tls/appliance_credentials.zig` (`secrets.constantTimeEqual(&leaf_public, &derived_public)`) | leaf certificate's public key vs. the public key derived from the provisioned private-key seed | secret-derived in effect (confirms the private key actually corresponds to the certificate; a mismatch here is a misconfiguration-detection gate, not peer-facing, but the comparison still guards a security property) | compare | local (startup/reload-time credential validation, not peer-triggered) | both operands are stack-local at validation time | N/A (both are public-key bytes, not secret scalars — the *scalar* itself is wiped separately via `FixedSecret`/`BoundedSecret`, see below) | CT compare (defense in depth per the module's own comment) | compliant | Already compliant; included for completeness since #375's scope map names `appliance_credentials.zig` explicitly. `loadPrivateKey`'s intermediate `BoundedSecret`/`FixedSecret` buffers (PEM/base64/DER scratch, PKCS#8 body, extracted seed) are wiped on every path per the module's own "every intermediate secret buffer is wiped on all paths" comment, re-verified here. |
| `src/tls/identity_loader.zig:LoadedIdentity.deinit` and buffer-decode helpers | PEM/base64/DER-decode scratch, retained `key_der`, `Identity.key` | secret (private key material) / public (`cert_raw`, `cert_der` — certificate bytes are not secret) | wipe on deinit / decode-failure | not observable | scratch buffers scoped to the decode call; `key_der`/`identity.key` owned by `LoadedIdentity` | `secrets.secureZero`/`secureZeroAndFree` on every decode exit (success and failure) and on `deinit`; certificate bytes are correctly left un-wiped (public) | canonical helper for key material only | compliant | Fixed by PR #549 ("route TLS identity-loader key-material cleanup through canonical secret helpers"); re-verified for #375, including that the module correctly does *not* wipe certificate bytes (they are public DER, not secret, and wiping them would be a wasted operation, not a bug). |

### Resumption and ticket oracle review

Per #375's required review of the #360–#365 surfaces (PSK binder
verification, selected identity handling, RMS/PSKs, ticket key
lookup/rotation/decryption, cache/session identity comparisons, stateless
ticket resolver normalization, replacement/retirement/eviction cleanup):

- `ticket_protection.Protector.resolveInner` computes a specific
  `ResolveRejectReason` for every distinct peer-controlled failure class
  named by #375: malformed envelope, unsupported version, unsupported AEAD,
  unknown key ID, future key, retired key, authentication failure, invalid
  plaintext, not-yet-valid, and expired. This classification is real and
  detailed — but it is only ever handed to the local `Observer` (a
  closed, non-secret-bearing enum consumed for operator metrics), never
  returned to the caller. `Protector.resolve`'s public signature collapses
  every one of those causes to `ResolveError!bool`.
- `ServerPskResolverAdapter.resolve` (the PSK-binder-facing consumer)
  collapses this further to a `.hit`/`.miss` result. `pre_shared_key.zig`
  documents `.miss` explicitly as covering "malformed, unknown, retired,
  expired, or otherwise unusable" identities uniformly — i.e. the resolver
  boundary #375 asks about ("does public key-ID lookup alone ever mark an
  identity selected, or leak detailed peer-visible failure behavior beyond
  the uniform miss contract?") is already answering "no" by construction: a
  key-ID lookup miss and a decrypt/authentication failure both surface as
  the same `.miss`.
- **One deliberate, spec-required asymmetry exists** and is worth stating
  explicitly rather than leaving implicit: once a PSK identity's binder
  fails verification (as opposed to the identity simply not resolving),
  `tls13_backend.zig` aborts the handshake immediately with a fatal error
  rather than falling back to probe a later offered identity (`onServerHello`
  path, `error.DecryptError` on binder mismatch). An unresolved (`.miss`)
  identity, by contrast, causes the offer-processing loop to continue to the
  next offered identity. This is RFC 8446 §4.2.11.2's required behavior
  ("if any check fails, the server MUST abort the handshake") and #362's
  existing "selected-binder failure remains fatal, never probes a later
  identity" contract — #375 asks explicitly to verify this remains true, and
  it does. It is peer-observable differential behavior between "no PSK of
  mine matched" and "a PSK of mine matched but the binder was wrong," which
  is unavoidable and specification-mandated, not a resolver-boundary leak:
  the peer already knows which identities it offered, so this reveals
  nothing beyond "the server's identity selection landed on one of them,"
  not which one or why the binder failed.
- No decrypted ticket plaintext, PSK, binder, key, or tag is ever compared
  with a raw `std.mem.eql`/`std.mem.order` anywhere in the ticket/resumption
  code path audited here — every such comparison found routes through
  `secrets.constantTimeEqual` (see the matrix rows above).

## Representative public comparisons intentionally left ordinary

So a future reviewer does not infer from the rows above that all
`std.mem.eql` is forbidden project-wide:

| Location | Value | Why ordinary comparison is correct |
|---|---|---|
| `src/quic/cid.zig:PeerCidPool.onNewConnectionId` | peer-echoed stateless-reset token, exact-retransmit detection | Protocol bookkeeping over peer-echoed data, not an authentication decision (see matrix row above). |
| `src/crypto/rsa.zig` EMSA-PSS structural checks | signature/message encoding shape | Attacker-controlled structural data, not secret; RFC 8017 does not require constant-time structural rejection, and downstream authentication results are uniform regardless of which structural check failed. |
| TLS/QUIC algorithm, cipher, group, and signature-scheme selection throughout `src/tls/negotiation.zig`, `src/tls/policy.zig`, `src/tls/algorithms.zig` | negotiated identifiers | Public protocol values by design; RFC 8446/9000 negotiation is not confidential. |
| `src/tls/hello_retry.zig` HRR fixed random value | the RFC 8446 §4.1.3 constant | A fixed public constant, not connection-specific secret material. |
| Certificate/public-key DER encodings throughout `src/pki/` | X.509 bytes | Public by definition; only the final chain-signature *verification* result requires provider-routed, capability-checked treatment (see `docs/CRYPTO_PROVIDER_AUDIT.md`). |
| IP addresses and connection IDs throughout `src/quic/` | routing/path identifiers | Public protocol identifiers (#375 explicitly warns against CT-converting these). |
| `src/tls/ticket_protection.zig` public ticket key IDs used for lookup | key ID bytes | Used only as a routing index into the key ring; #375's own text: "Public key-ID lookup may branch on public data." |

## Observability

No production `std.log`/`std.debug.print`/`std.fmt`-based diagnostic in
`src/crypto`, `src/tls`, `src/quic`, or `src/pki` formats private keys,
traffic secrets, RMS/PSKs/binder keys, ticket encryption keys, decrypted
session state, raw session tickets, or secret-derived fingerprints. This is
enforced structurally, not just by convention, in the highest-risk types:

- `crypto.secrets.FixedSecret`/`BoundedSecret` `format()` methods
  `@compileError` unconditionally (`src/crypto/secrets.zig`).
- `pure_zig.SoftwareSigningKey`/`SoftwareEcdsaP256SigningKey`/
  `SoftwareRsaSigningKey`, `crypto.rsa.PrivateKey` (#565), `credentials
  .Identity`, and `ticket_protection`'s key-record and snapshot types carry
  the same non-formatting guarantee.
- Observer/event-sink seams (`ticket_protection.Event`,
  `session_cache`'s `CacheEvent`, `early_data_replay`'s observer) are closed
  enums documented as carrying only non-secret classification data — never a
  fingerprint, ticket, or key — even for local diagnostics.

The one `std.debug.print` call found in a file this audit covers
(`pre_shared_key.zig`) is inside a test-only fuzz corpus helper printing an
integer truncation index, not secret material.

## Provider/ownership boundary

No new direct `std.crypto` keyed-crypto call was introduced by this story
outside what `docs/CRYPTO_PROVIDER_AUDIT.md` already allowlists; the fixes
in this document are comparison/zeroization *helper routing* changes within
files #490 already classified, not new crypto call sites. `zig build
audit-crypto-boundary` (part of `zig build test`) passes against every
change in this story, and — per #554 below — now also enforces that this
remains true going forward, not just at the moment this story closed.

## Deferred findings and follow-ups

Per #375's requirement that every deferred finding have a tracking issue
before the story closes:

- **#554** — done. `scripts/audit_crypto_boundary.zig` (`zig build
  audit-crypto-boundary`, part of `zig build test`) now also guards the two
  regression classes this story fixed. Went through three review rounds
  before landing:
  - **First pass** found the initial version scanned only `src/tls`/
    `src/quic`/`src/pki` for raw `timing_safe` (missing `src/crypto`'s own
    non-implementation consumers, e.g. `rsa.zig`), used dot-suffixed needles
    a namespace-capture alias (`const timing_safe = std.crypto.timing_safe;`)
    could evade, and protected the zero-and-free finding in exactly three
    files by four exact historical variable names — passable by a new file
    or a harmless rename.
  - **Second pass**, after fixing the above, found the fixes were still
    incomplete: (a) the timing-safe needles remained *qualifier*-dependent,
    so aliasing `std.crypto` itself one level higher
    (`const std_crypto = std.crypto; std_crypto.timing_safe.eql(...)`, the
    exact spelling `sni_provider.zig` already uses elsewhere in this repo)
    defeated them; (b) the general zero-then-plain-free scanner matched
    literal `secureZero(` calls and exact buffer-expression text, which a
    *callee* alias (`const wipe = crypto.secrets.secureZero; wipe(buf);`) or
    a *buffer* rename between the zero call and the free
    (`const doomed = buf; allocator.free(doomed);`) both defeated; (c)
    excluding all of `secrets.zig` from the structural scan left
    `BoundedSecret.deinit`'s exact original regression reintroducible under a
    local rename, since the zeroing (`clearAll`) and the free (`deinit`) live
    in different, textually-out-of-order sibling methods no forward-only
    single-function scan can connect.
  - **Third pass**, after fixing all of the above, found four more gaps: (a)
    scanning only the text *after* the zero call misses the ordinary Zig
    `defer` idiom, since defers run LIFO — a free's `defer` written textually
    *before* a zero's `defer` still executes *after* it at runtime; (b) the
    scanner recognized only `secureZero` (direct or aliased) as a "zero,"
    missing a new ad hoc manual clear (`@memset(secret_buf, 0)`) entirely
    outside the wrapper, which is itself explicitly part of #375's scope;
    (c) `resolveBufferRenames` returned only the first alias of a buffer, so
    a harmless first rename shadowed the actually-freed second rename; (d)
    the `BoundedSecret` check blacklisted known-bad free spellings, so a
    direct `allocator.rawFree(self.bytes, ...)` — bypassing
    `secureZeroAndFree` (and its zeroing) entirely — matched no forbidden
    substring and passed, since `rawFree` is also the *correct* spelling
    inside `secureZeroAndFree`'s own implementation. Widening the scan
    window to the whole enclosing function (fixing (a)) also surfaced a
    latent false-positive risk the narrower window had been masking: a
    candidate key that is merely a *suffix* of a longer identifier
    (`self.selected_client_psk.deinit()` matching a candidate key `psk`) —
    fixed with an identifier-boundary check — and `@memset`-based detection
    specifically misfired on `test` blocks deliberately zero-filling
    fixture data (indistinguishable, lexically, from a secret wipe), fixed
    by scoping the `@memset` trigger to skip `test` blocks (the unambiguous
    `secureZero` trigger still scans them in full).

  The merged version:
  - Matches the bare `timing_safe` token itself, independent of any
    qualifier — sound because Zig aliasing can rename the path *to* a
    namespace member but never the member's own name, so `timing_safe` must
    appear literally in the source for any access to reach it, at any
    aliasing depth — reappearing anywhere in `src/tls`, `src/quic`,
    `src/pki`, or `src/crypto` outside `secrets.zig`'s own
    `constantTimeEqual` implementation (excluded by exact path, checked
    separately with a named exception). Does not flag the public/
    attacker-controlled comparisons in the "representative public
    comparisons" table below — those use ordinary `std.mem.eql`, never
    `timing_safe`.
  - A general zero-then-plain-free scanner, not a three-file/exact-variable-
    name list: it extracts the buffer expression every `secureZero(...)` call
    (any qualifier, a local callee alias of it, or a manual
    `@memset(buf, 0)` clear) zeroes and looks for that same expression —
    including through a `std.mem.sliceAsBytes`/`&`/local-rename indirection
    (every matching rename, not just the first), and the `ArrayList`-style
    "zero `.items`, `.deinit()` the container" shape — handed to an ordinary
    `allocator.free`/`.deinit()` anywhere in the *whole* enclosing function
    (not just the text after the zero call — `defer` runs LIFO, so a free's
    own `defer` written textually before a zero's `defer` still executes
    after it at runtime), across `src/tls`, `src/quic`, `src/pki`, and
    `src/crypto` (excluding `secrets.zig`'s own
    `secureZeroAndFree`/`secureZeroAndFreeAligned`, whose zero-then-`rawFree`
    pairing *is* the canonical helper). The `@memset` trigger specifically
    skips `test` blocks: `@memset(_, 0)` cannot be told apart, lexically,
    from deliberately zero-filling test fixture data, and pairing it with a
    test's own ordinary cleanup is not the regression class this trigger
    exists to catch — the unambiguous `secureZero` trigger still scans test
    blocks in full. Applying this generally — rather than to the three files
    this story originally fixed — surfaced six more genuine instances of the
    same defect this story's own inventory command missed:
    `src/tls/identity_loader.zig` (`LoadedIdentity.deinit`, `loadIdentity`'s
    `cert_raw`/`key_raw`/`key_der` cleanup, `pemBlockToDerFrom`'s
    `compact`/`der` scratch), `src/tls/tls13_backend.zig`
    (`PostHandshakeInput.deinit`/`.discard`, the `NewSessionTicket` message
    buffer `errdefer`), `src/tls/transport.zig` (`EventSink.freeOwnedPayloads`,
    `emitOwnedHandshakeBytesCopy`'s `errdefer`), `src/quic/connection.zig`
    (`CryptoTx.Reservation.deinit`, `CryptoTx.deinit`'s `ArrayList`),
    `src/quic/tls_backend.zig` (`translate`'s oversized-payload error path),
    and `src/tls/session_cache_persistence.zig` (`MemoryBackend.deinit`/
    `.save`, all four `save*Cache`/`load*Cache` plaintext/sealed buffers, and
    every test helper following the same shape) — all fixed alongside the
    guard, routed through `secureZeroAndFree`/`secureZeroAndFreeAligned`.
  - A dedicated *positive-requirement* check for `BoundedSecret.deinit`
    specifically: rather than blacklisting known-bad free spellings (which
    `allocator.rawFree(self.bytes, ...)` — bypassing `secureZeroAndFree`
    entirely — proved unbounded against), it requires `deinit`'s body to
    literally call `secureZeroAndFree(<allocator>, self.bytes)` (or a
    resolved rename of `self.bytes`), searched across the type's *entire*
    struct body so `clearAll`'s zeroing and `deinit`'s free are seen
    together even though they're different, textually-out-of-order sibling
    methods. Asset-specific (`self.bytes`, the one secret buffer this type
    owns) rather than a generic "any zero + any free anywhere in the file"
    rule, which would immediately misfire on this same file's own tests
    calling `secret.deinit()` (the type's own, correct, public API, not a
    bypass).
  - Still not a project-wide ban on the raw `std.crypto.secureZero` spelling
    on its own (a separate, narrower named-file check retained for
    `ticket_key_snapshot.zig`/`sni_provider.zig`/`secrets.zig`): many call
    sites throughout `src/tls`/`src/quic`/`src/http` legitimately zero a
    stack-local buffer with no accompanying free at all (see this document's
    toolchain-assumptions section above) — banning the raw spelling
    everywhere would flag every one of them, the same "mechanical
    conversion" this section's opening paragraph warns against.
  - Not a claim of soundness against arbitrary aliasing depth for the
    zero-and-free scanner (unlike the `timing_safe` token match, which is
    complete for that one narrower question): buffer/callee alias
    resolution goes one hop, and no lexical scan can fully replace real
    semantic analysis. Each mechanism is scoped to catch the specific
    bypasses found in review, not to prove no lexical bypass can ever exist.
- **#555** — consolidate the duplicate RFC 9001 §5.8 Retry-integrity-tag
  implementations in `src/quic/packet.zig` (production) and `src/quic/path.zig`
  (unreachable, KAT-fixture-only). Both copies were fixed for constant-time
  hygiene by this story, but the duplication itself — which is exactly the
  shape of gap that let this story's first pass miss the production copy
  while fixing the unreachable one — is a larger structural cleanup better
  scoped as its own focused change.

No other finding in this audit required a larger redesign, package-
architecture change, persistent data-format migration, or protocol/state-
machine change; every other gap identified was fixed directly in this
story (see `status: fixed-in-375` rows above) or was already compliant.

## Regression tests

The six constant-time-helper migrations and the zeroization-helper-routing
migration are refactors of already-correct behavior (the prior code already
used `std.crypto.timing_safe.eql`/`std.crypto.secureZero`; this story
changes *which* wrapper is called, not the comparison/zeroization semantics
themselves), so the existing test suites already exercise both the accept
and reject paths for every touched comparison:

- `src/tls/pre_shared_key.zig`: `"resumption binder derivation matches an
  independently computed SHA-256/384 binder"`, `"verifyBinder rejects a
  wrong-length candidate without erroring"`, HRR binder tests.
- `src/tls/tls13_backend*_tests.zig`: full handshake integration tests drive
  both Finished paths on every successful handshake; tamper/mismatch
  coverage exists at the transport layer.
- `src/quic/packet.zig`: `"writeRetryV1 roundtrips..."`,
  `"...rejects a tampered token"`, the RFC 9001 Appendix A.4 vector test.
- `src/quic/path.zig`: the full `retry token ...` test group, `"a wrong
  PATH_RESPONSE payload does not validate the path"`.
- `src/crypto/rsa.zig`: `"RSA-PSS rejects short, long, and out-of-range
  signatures"`, `"EMSA-PSS rejects every nonzero PS byte and structural
  corruption"`.
- `src/crypto/secrets.zig` / `src/crypto/provider.zig`: the canonical
  helper's own equal/unequal/length-mismatch battery
  (`"secret helpers expose non-formatting APIs"`,
  `"constantTimeEqual matches semantic equality"`).
- `src/tls/ticket_key_snapshot.zig`: the existing parse/reject/fuzz tests
  exercise every zeroization call site touched by the wrapper-routing fix.

The zero-then-raw-free correction (`OwnedSnapshot.deinit`, `loadFromFile`,
`reserveNonceLeasesInFile`'s serialize buffer, `parse`'s `key_storage`
`errdefer`, and `BoundedSecret.deinit`) is a real behavior change — from a
buffer the backing allocator was not guaranteed to observe as zero, to one
it is — so it gets allocator-observable regression coverage rather than
relying on existing accept/reject tests that never inspected freed memory:

- `src/crypto/secrets.zig`: `"secureZeroAndFreeAligned hands the allocator
  zeroed bytes for a wider-than-u8-aligned element"`,
  `"secureZeroAndFreeAligned tolerates an empty buffer"`, `"bounded secret
  deinit hands the allocator zeroed bytes, not Allocator.free's
  undefined-poison"` — each drives a `FixedBufferAllocator` so the freed
  bytes are directly inspectable, the way `"secureZeroAndFree hands the
  allocator zeroed bytes..."` already did for the plain `[]u8` case.
- `src/tls/ticket_key_snapshot.zig`: `"OwnedSnapshot.deinit hands the
  allocator zeroed key bytes, not Allocator.free's undefined-poison"` runs
  the real `parse`/`deinit` pair against a `FixedBufferAllocator`, captures
  the decoded key bytes before `deinit`, and asserts that exact byte
  pattern is absent anywhere in the shared backing buffer afterward.

`zig build test` (2980 tests, 1 pre-existing skip unrelated to this story)
and `zig build audit-crypto-boundary` both pass against every change in
this document.

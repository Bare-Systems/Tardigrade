//! Deterministic crypto-boundary audit (#490).
//!
//! A small, dependency-free Zig program — not a shell script shelling out to
//! an ambient `rg` — so the checked-in enforcement runs identically on every
//! CI runner and platform without an extra tool to install. It blocks three
//! things in QUIC protocol modules, the native TLS 1.3 engine, and the native
//! HTTP/QUIC composition root:
//!
//!   1. New direct keyed-crypto calls (`std.crypto`'s AEAD/KDF/ECDH/signature
//!      APIs and the `crypto.core.aes` block-cipher form QUIC header
//!      protection is built on) outside the approved provider-owned adapter
//!      (`src/quic/tls_adapter.zig`) and its documented exceptions.
//!   2. Calls to the concrete legacy wrapper names `src/quic/tls_adapter.zig`
//!      still carries for differential test vectors — `sealPayload`,
//!      `openPayload`, `applyHeaderProtection`, `removeHeaderProtection`,
//!      `headerProtectionMask`, `deriveAes128GcmKeys`, `deriveInitialSecretsV1`,
//!      `deriveNextGenerationSecret` — from the live runtime modules that were
//!      migrated onto the `*WithProvider` entry points. This is what catches a
//!      revert of that migration even though the names themselves are
//!      "approved" inside `tls_adapter.zig` and test vector files.
//!   3. The same class of direct keyed-crypto reintroduction in the native
//!      TLS 1.3 key schedule and handshake engine (#490's second migration
//!      target, `src/tls/key_schedule.zig` and `src/tls/tls13_backend.zig`):
//!      HKDF, X25519 key exchange, and CertificateVerify signing/verification
//!      must stay routed through `crypto.provider.CryptoProvider`, with the
//!      same narrow named-exception discipline as the QUIC files above.
//!
//! Every approved exception is narrow: a named function/method body or an
//! exact top-level declaration, blanked out of a file's content before that
//! file is otherwise scanned in full (#490 fourth-pass review) — not a
//! category omitted from a file's forbidden list wholesale, which would also
//! silently allow that category anywhere else new in the same file.
//!
//! Not a semantic proof: a deterministic, narrow pattern match that prevents
//! accidental reintroduction and forces any new exception to be reviewed here
//! and in `docs/CRYPTO_PROVIDER_AUDIT.md`.
//!
//! #554 extends this same tool with two more regression guards, scoped
//! against `docs/CRYPTO_SECURITY_AUDIT.md` (#375) instead of
//! `docs/CRYPTO_PROVIDER_AUDIT.md` (#490):
//!
//!   4. A raw `std.crypto.timing_safe.*`/`crypto.timing_safe.*` call
//!      reappearing anywhere in `src/tls`, `src/quic`, or `src/pki`
//!      (recursive, no exceptions — #375 migrated every such call in these
//!      trees to `crypto.secrets.constantTimeEqual`/
//!      `crypto.provider.constantTimeEqual`, and the one legitimate raw call
//!      left project-wide lives in `src/crypto/secrets.zig`'s own
//!      `constantTimeEqual` implementation, outside this scan entirely).
//!      Deliberately *not* "flag every `std.mem.eql`/`std.mem.order`" — #375
//!      itself classifies several comparisons in this same scope as
//!      public/attacker-controlled and explicitly correct left ordinary (see
//!      that document's "Representative public comparisons intentionally
//!      left ordinary" table); a bare pattern denylist over all comparisons
//!      would flag those too, which is exactly the mechanical
//!      "convert-everything" guard #375 warns against building.
//!   5. The specific ad hoc zero-and-free/raw-secureZero-spelling findings
//!      #375 fixed, reappearing in the same three files: `BoundedSecret`
//!      freeing its backing storage through a plain `allocator.free` after a
//!      separate zero call instead of `secureZeroAndFree`/
//!      `secureZeroAndFreeAligned` (`src/crypto/secrets.zig`); the four
//!      `ticket_key_snapshot.zig` sites that did the same
//!      (`OwnedSnapshot.deinit`, `loadFromFile`,
//!      `reserveNonceLeasesInFile`, `parse`'s `key_storage` `errdefer`); and
//!      `sni_provider.zig`'s `SignAdapter.release` reverting from the
//!      canonical `crypto.provider.secureZero` wrapper back to a raw
//!      `std.crypto.secureZero`/`std_crypto.secureZero` call. Not a
//!      project-wide "raw `std.crypto.secureZero` is forbidden" rule: dozens
//!      of already-compliant call sites throughout `src/tls`/`src/quic`/
//!      `src/http` zero a stack-local buffer with no accompanying free at
//!      all (see `docs/CRYPTO_SECURITY_AUDIT.md`'s toolchain-assumptions
//!      section), and banning the raw spelling project-wide would flag every
//!      one of them — the same "mechanical conversion" #375 and #554 both
//!      warn against. Scoped instead, named-exception style, to the exact
//!      three files/functions #375 found and fixed.
//!   6. Bypasses of the canonical secret-zeroization helpers (#784,
//!      following #750/#751). Two rules:
//!      a. No production `std.crypto.secureZero` anywhere in `src/crypto`,
//!         `src/tls`, `src/quic`, `src/pki`, `src/http`, or `src/http3` —
//!         the direct spelling, a call through a local `std.crypto` alias
//!         (`const crypto = std.crypto;` then `crypto.secureZero(u8, buf)`,
//!         the shape #784 itself migrated ~100 sites off), or any
//!         `secureZero(T, buf)` call with the stdlib's two-argument typed
//!         signature under whatever qualifier. The canonical
//!         `crypto.secrets.secureZero`/`crypto.provider.secureZero` take one
//!         `[]u8` argument, so the argument count alone identifies the
//!         stdlib form without depending on how its namespace was spelled.
//!         Comments, string literals, `test` blocks, and `*_tests.zig`
//!         files are exempt (test fixtures, not production wipes);
//!         `src/crypto/secrets.zig` is exempt here because the narrower
//!         point-5 check above already confines any raw call in that file
//!         to `secureZero`'s own body. This supersedes point 5's "not a
//!         project-wide rule" caveat: #750 made `secureZero` a separate
//!         implementation rather than a wrapper, so a raw call is now a
//!         real (non-elision and performance) divergence, not a synonym.
//!      b. No plain `@memset` anywhere inside a short, named list of
//!         secret-bearing storage declarations (`ByteQueue` in
//!         `encrypted_stream.zig`, the CRYPTO buffers in `tls_adapter.zig`)
//!         — the exact regression #751 fixed. Deliberately *not* a global
//!         `@memset` ban: `PlaintextProvenanceQueue` and plenty of other
//!         non-secret buffers use `@memset` correctly. Fails closed if a
//!         named file or declaration disappears, so a rename cannot
//!         silently drop the protection.

const std = @import("std");
const compat = @import("zig_compat");

/// A single-file check: `path` must not contain any of `forbidden`.
const FileCheck = struct {
    path: []const u8,
    forbidden: []const []const u8,
    rationale: []const u8,
};

/// A single-file check with narrow, named exceptions blanked out before
/// scanning the rest of the file in full against `forbidden` — instead of
/// omitting a whole pattern category from `forbidden` (which would also
/// allow that category anywhere else new in the file, not just the one
/// approved call site; #490 fourth-pass review).
const FileCheckWithExceptions = struct {
    path: []const u8,
    forbidden: []const []const u8,
    /// Named function/method bodies pre-approved for direct keyed-crypto
    /// content (extracted the same way as `FunctionBodyCheck` below).
    exempt_functions: []const []const u8 = &.{},
    /// Exact top-level snippets outside any function (e.g. a type-alias
    /// declaration) pre-approved the same way.
    exempt_exact: []const []const u8 = &.{},
    /// When set, only the file content *before* the first occurrence of this
    /// marker is scanned — for a file whose production code precedes a large
    /// test-only region that legitimately exercises every exempted primitive
    /// directly (differential vectors, KATs). If the marker is not found,
    /// the whole file is scanned instead of silently exempting everything.
    production_only_marker: ?[]const u8 = null,
    rationale: []const u8,
};

/// A directory-wide check: every `*.zig` file inside `dir`, recursively,
/// except `excluded_paths` (matched as exact root-relative paths, at any
/// depth) must not contain any of `forbidden`.
const DirCheck = struct {
    dir: []const u8,
    excluded_paths: []const []const u8,
    forbidden: []const []const u8,
    rationale: []const u8,
};

// ---------------------------------------------------------------------------
// Forbidden-pattern sets
// ---------------------------------------------------------------------------

/// Concrete keyed AEAD/KDF/ECDH/signature primitives. Protocol modules must
/// reach these only through `crypto.provider.CryptoProvider`
/// (`src/quic/tls_adapter.zig`'s `*WithProvider` entry points).
const keyed_crypto_core = [_][]const u8{
    "std.crypto.aead.",
    "crypto.aead.",
    "std.crypto.auth.",
    "crypto.auth.",
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "std.crypto.kdf.",
    "crypto.kdf.",
    "Aes128Gcm.encrypt(",
    "Aes128Gcm.decrypt(",
    "Aes256Gcm.encrypt(",
    "Aes256Gcm.decrypt(",
    "ChaCha20Poly1305.encrypt(",
    "ChaCha20Poly1305.decrypt(",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "hkdfExpandLabel(",
};

/// The exact AES block-cipher construction QUIC header protection is built
/// on — distinct from the AEAD entries above, and the specific gap a prior
/// version of this audit missed (#490 second-pass review).
const aes_block_cipher = [_][]const u8{
    "crypto.core.aes.",
    "Aes128.initEnc(",
    "Aes256.initEnc(",
};

/// Concrete legacy wrapper names retired from the live QUIC send/receive path
/// in favor of the `*WithProvider` entry points on the same types. Kept only
/// as differential test-vector fixtures in `src/quic/tls_adapter.zig` and
/// `tests/crypto_vectors.zig` / `tests/crypto_openssl_diff.zig`; a runtime
/// module calling one directly is exactly the regression this audit exists
/// to catch. Unqualified, not dot-prefixed: a `*WithProvider` implementation
/// and its legacy sibling share one Zig container, so the sibling can be
/// called unqualified (`sealPayload(self, ...)`) as well as by dot-call
/// (`self.sealPayload(...)` / `keys.sealPayload(...)`); both forms are the
/// same regression and #490's fifth-pass review found the dot-only form
/// missed the unqualified one. Each literal still ends at the call
/// parenthesis so it does not also match its own `...WithProvider(` sibling
/// (`sealPayload(` is not a substring of `sealPayloadWithProvider(` because
/// `With...` intervenes before the paren).
const legacy_wrapper_calls = [_][]const u8{
    "sealPayload(",
    "openPayload(",
    "applyHeaderProtection(",
    "removeHeaderProtection(",
    "headerProtectionMask(",
    "deriveAes128GcmKeys(",
    "deriveInitialSecretsV1(",
    "deriveNextGenerationSecret(",
};

const full_forbidden = keyed_crypto_core ++ aes_block_cipher ++ legacy_wrapper_calls;

/// Same as `keyed_crypto_core` except `hkdfExpandLabel(` is qualified with
/// the `tls.` prefix the legacy free function uses in `tls_adapter.zig`,
/// rather than matching bare. The provider-backed `*WithProvider`
/// implementations in that file legitimately call the vtable method
/// `provider.hkdfExpandLabel(...)`, which also contains the bare substring
/// `hkdfExpandLabel(` — this variant is the only way to forbid the legacy
/// free function without also flagging its own approved provider siblings
/// (#490 fourth-pass review).
const tls_adapter_zig_forbidden = [_][]const u8{
    "std.crypto.aead.",
    "crypto.aead.",
    "std.crypto.auth.",
    "crypto.auth.",
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "std.crypto.kdf.",
    "crypto.kdf.",
    "Aes128Gcm.encrypt(",
    "Aes128Gcm.decrypt(",
    "Aes256Gcm.encrypt(",
    "Aes256Gcm.decrypt(",
    "ChaCha20Poly1305.encrypt(",
    "ChaCha20Poly1305.decrypt(",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "tls.hkdfExpandLabel(",
} ++ aes_block_cipher ++ legacy_wrapper_calls;

/// Same as `keyed_crypto_core` except `hkdfExpandLabel(` is qualified with
/// the `crypto.tls.` prefix the one documented comptime exception in
/// `src/tls/key_schedule.zig` uses, rather than matching bare. Every live
/// (non-comptime) HKDF-Expand-Label call in that file goes through the
/// provider vtable method `crypto_provider.hkdfExpandLabel(...)` /
/// `self.provider.hkdfExpandLabel(...)`, which also contains the bare
/// substring `hkdfExpandLabel(` — this variant is the only way to forbid the
/// legacy `std.crypto`-backed spelling without also flagging its own
/// approved provider call sites (same shape as `tls_adapter_zig_forbidden`
/// above, #490 fourth-pass review).
const key_schedule_zig_forbidden = [_][]const u8{
    "std.crypto.aead.",
    "crypto.aead.",
    "std.crypto.auth.",
    "crypto.auth.",
    "std.crypto.dh.",
    "crypto.dh.",
    "std.crypto.sign.",
    "crypto.sign.",
    "std.crypto.kdf.",
    "crypto.kdf.",
    "Aes128Gcm.encrypt(",
    "Aes128Gcm.decrypt(",
    "Aes256Gcm.encrypt(",
    "Aes256Gcm.decrypt(",
    "ChaCha20Poly1305.encrypt(",
    "ChaCha20Poly1305.decrypt(",
    "X25519.",
    "Ed25519.",
    "Ecdsa",
    "Rsa",
    "crypto.tls.hkdfExpandLabel(",
} ++ aes_block_cipher ++ legacy_wrapper_calls;

const file_checks = [_]FileCheck{
    .{
        .path = "src/quic/connection.zig",
        .forbidden = &full_forbidden,
        .rationale = "QUIC connection logic owns framing, packet numbers, and nonce arithmetic only; keyed crypto belongs to src/quic/tls_adapter.zig through CryptoProvider, and every call site there already migrated onto the *WithProvider entry points.",
    },
    .{
        .path = "src/http/http3_runtime.zig",
        .forbidden = &full_forbidden,
        .rationale = "The native HTTP/QUIC composition root selects/constructs a CryptoProvider and injects it into Connection/QuicTlsAdapter, but must not perform packet crypto itself: no direct concrete AEAD/KDF/ECDH/signature primitive, AES block-cipher form, or legacy tls_adapter wrapper call.",
    },
    .{
        .path = "src/tls/tls13_backend.zig",
        .forbidden = &full_forbidden,
        .rationale = "The TLS 1.3 handshake state machine performs no concrete keyed primitive work (#490): X25519 key-share generation and shared-secret derivation route through CryptoProvider.generateKeyShare/.deriveSharedSecret, and CertificateVerify authentication routes through CryptoProvider.verify. Local signing stays behind the opaque CredentialProvider/SelectedCredential contract in credentials.zig, which this file only calls through, never a concrete std.crypto.sign type.",
    },
};

/// Whole-file scans with narrow, named exceptions (#490 fourth-pass review):
/// each of these files has real, approved direct-crypto call sites, but
/// omitting a whole pattern category from the file's forbidden list (the
/// prior approach) would also silently allow that category anywhere else new
/// in the file. Every exception here is instead one exact named function
/// body or top-level declaration, so a *second*, unrelated direct-crypto
/// call anywhere else in the same file still fails.
const file_checks_with_exceptions = [_]FileCheckWithExceptions{
    .{
        .path = "src/quic/packet.zig",
        .forbidden = &full_forbidden,
        // RFC 9001 fixes the Retry integrity key/nonce as public constants;
        // this is not TLS/QUIC-negotiated packet-protection key material.
        .exempt_functions = &.{"computeRetryIntegrityTag"},
        .rationale = "QUIC packet parsing/encoding is public protocol logic; keyed crypto and AES header protection belong to src/quic/tls_adapter.zig through CryptoProvider. computeRetryIntegrityTag is the one documented RFC 9001 Retry-integrity exception (public key/nonce, not packet-protection key material).",
    },
    .{
        .path = "src/quic/path.zig",
        .forbidden = &full_forbidden,
        .exempt_exact = &.{"const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;"},
        // Address-validation token issuance/validation uses AES-GCM with
        // process keys; sealTokenPlaintextForTest is the one test-only helper
        // building a token payload the same way for fuzz coverage.
        .exempt_functions = &.{ "issueRetry", "validateRetry", "sealTokenPlaintextForTest" },
        .rationale = "QUIC path validation may use the existing token-protection exception, but must not add key exchange, signatures, KDF, AES block-cipher shortcuts, or a second Retry-integrity implementation anywhere else in this file.",
    },
    .{
        .path = "src/quic/cid.zig",
        // Blanking the alias declaration only removes the fully-qualified
        // `std.crypto.auth.` spelling from the scan; the locally-aliased
        // short name `HmacSha256` is not itself in `full_forbidden`, so
        // without this addition a second, unrelated `HmacSha256.` call
        // anywhere else in the file would pass (#490 fifth-pass review).
        .forbidden = &(full_forbidden ++ [_][]const u8{"HmacSha256."}),
        .exempt_exact = &.{"const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;"},
        .exempt_functions = &.{"statelessResetTokenInto"},
        .rationale = "Connection-ID/stateless-reset-token derivation (RFC 9000 §10.3.1) is a documented HMAC-SHA256 exception under a static process-lifetime key (docs/CRYPTO_PROVIDER_AUDIT.md), not TLS/QUIC-negotiated packet protection; no AEAD, ECDH, signature, KDF, or AES header-protection shortcuts, and no other HmacSha256 use, may be added here.",
    },
    .{
        .path = "src/quic/tls_handshake.zig",
        // Same alias-name gap as cid.zig, for the locally-aliased
        // `HkdfSha256` (#490 fifth-pass review).
        .forbidden = &(full_forbidden ++ [_][]const u8{"HkdfSha256."}),
        .exempt_exact = &.{"const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;"},
        .exempt_functions = &.{"deriveSecret"},
        .rationale = "The backend-agnostic handshake driver must not add keyed crypto of its own. TestTlsBackend.deriveSecret's deterministic transcript HKDF (one type alias, one method) is the one documented exception; everything else, including the legacy wrapper names and any other HkdfSha256 use, stays forbidden throughout the file.",
    },
    .{
        .path = "src/quic/tls_adapter.zig",
        .forbidden = &tls_adapter_zig_forbidden,
        // The three concrete-primitive type aliases the legacy differential
        // fixtures below are built on.
        .exempt_exact = &.{
            "const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;",
            "const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;",
            "const Aes128 = crypto.core.aes.Aes128;",
        },
        // The eight legacy concrete functions/methods kept only as
        // differential test-vector fixtures compared against the provider
        // path — approved by name here, nowhere else. Every canonical
        // QuicTlsAdapter method (protectionKeys, sealPacketPayload, ...) and
        // every *WithProvider entry point is therefore scanned like any
        // other production code: this is what catches both a canonical
        // method reverting to a legacy call (#490 third-pass review) *and*
        // a *WithProvider implementation silently delegating to its own
        // concrete sibling (#490 fourth-pass review), without having to
        // name either set of functions explicitly.
        .exempt_functions = &.{
            "sealPayload",
            "openPayload",
            "headerProtectionMask",
            "applyHeaderProtection",
            "removeHeaderProtection",
            "deriveInitialSecretsV1",
            "deriveAes128GcmKeys",
            "deriveNextGenerationSecret",
        },
        // Everything from this marker to end of file is the differential
        // test-vector suite, which legitimately calls every exempted
        // primitive/legacy function directly to compare against the
        // provider path.
        .production_only_marker = "\nconst testing = std.testing;",
        .rationale = "QuicTlsAdapter owns provider-backed QUIC packet protection; every canonical method and every *WithProvider entry point must reach CryptoProvider only, never a concrete primitive or its own legacy differential-fixture sibling.",
    },
    .{
        .path = "src/tls/key_schedule.zig",
        .forbidden = &key_schedule_zig_forbidden,
        // `derived_early_secret` is the one documented comptime exception
        // (#490, see docs/CRYPTO_PROVIDER_AUDIT.md): the "derived" early
        // secret for the zero-PSK schedule is a fixed public constant (the
        // all-zero PSK, not connection-specific secret material), computed
        // once at compile time because no provider is available at comptime
        // and none is needed. Two exact lines, not the whole block: the
        // block-scoped `HkdfSha256` alias and the one `crypto.tls.
        // hkdfExpandLabel` call it feeds, each narrow enough that a second,
        // unrelated direct-crypto call added anywhere else in the file still
        // fails (#490 fourth-pass review).
        .exempt_exact = &.{
            "const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;",
            "break :blk crypto.tls.hkdfExpandLabel(HkdfSha256, early_secret, \"derived\", &empty_transcript_hash, hash_len);",
        },
        // No `production_only_marker` (#490 review): a textual "scan only
        // before this position" boundary is not a sound production/test
        // reachability proof — Zig declarations are order-independent, so a
        // production function positioned before such a marker could still
        // call a private helper positioned after it, and the scan would
        // never see the forbidden call (the same structural class of bug
        // #544 fixed for `test_quic_crypto` by moving to a build.zig
        // module-graph boundary instead of a text scan). This module's own
        // tests — including the direct-HMAC cross-check of the
        // HKDF-Extract-as-HMAC `verifyData` trick and the raw
        // `CryptoProvider` vtable fixtures for typed-error-propagation — live
        // in `key_schedule_tests.zig`, a separate file this tool never scans
        // at all (the same way `tests/support/quic_crypto.zig` and
        // `tests/crypto_vectors.zig` aren't scanned), so `key_schedule.zig`
        // itself has no test-only content left to exempt and is scanned in
        // full.
        .rationale = "The TLS 1.3 key schedule performs no keyed HKDF/Finished-MAC work directly (#490): HKDF-Extract, HKDF-Expand-Label, and Finished verify_data (itself expressed as HKDF-Extract per RFC 5869) cross CryptoProvider. derived_early_secret's comptime derivation is the one documented public-constant exception; unkeyed transcript hashing (Sha256.hash) stays provider-independent by design and is not itself a forbidden pattern. Tests live in the separate, unscanned key_schedule_tests.zig.",
    },
};

// Includes legacy_wrapper_calls (#490 fifth-pass review): the recursive scan
// is the catch-all for every QUIC module without its own narrower check, so
// packet-protection code refactored out of connection.zig into a new file
// (e.g. src/quic/nested/protection.zig) must still be rejected for calling
// the legacy wrapper names, not just for raw concrete primitives.
const quic_dir_forbidden = full_forbidden;

const dir_checks = [_]DirCheck{
    .{
        .dir = "src/quic",
        // Every file with its own narrower check above is excluded by its
        // exact root-relative path (not by basename — a nested directory
        // reusing one of these names, e.g. src/quic/nested/connection.zig,
        // gets no free pass; #490 fourth-pass review). Recursive: a new
        // nested directory under src/quic gets no free pass either.
        .excluded_paths = &.{
            "src/quic/tls_adapter.zig",
            "src/quic/path.zig",
            "src/quic/connection.zig",
            "src/quic/packet.zig",
            "src/quic/cid.zig",
            "src/quic/tls_handshake.zig",
        },
        .forbidden = &quic_dir_forbidden,
        .rationale = "QUIC protocol modules outside the allowlist must not add direct keyed crypto or AES block-cipher dependencies.",
    },
};

// ---------------------------------------------------------------------------
// #554: constant-time-comparison and zeroization regression guards
// ---------------------------------------------------------------------------

/// The raw, non-canonical spelling of a constant-time comparison. #375
/// migrated every secret/authentication-derived comparison in `src/tls`,
/// `src/quic`, `src/pki`, and `src/crypto`'s non-implementation consumers
/// (e.g. `rsa.zig`) onto `crypto.secrets.constantTimeEqual` /
/// `crypto.provider.constantTimeEqual`; a new raw call over either spelling
/// reappearing anywhere in those trees is exactly the regression this guards
/// against. The one legitimate raw call left project-wide is inside
/// `crypto.secrets.constantTimeEqual` itself, in `src/crypto/secrets.zig`,
/// which the `src/crypto` directory check below excludes by exact path.
///
/// Matches the bare `timing_safe` token itself, not a qualified spelling
/// (#554 review, second pass): a qualified needle can always be defeated by
/// aliasing one *more* level up the path than the needle anticipates —
///
///     const timing_safe = std.crypto.timing_safe;  // defeats a dotted
///     return timing_safe.eql(...);                 // "std.crypto.timing_safe." needle
///
///     const std_crypto = std.crypto;                // defeats "std.crypto.timing_safe"/
///     return std_crypto.timing_safe.eql(...);       // "crypto.timing_safe" too if the
///                                                    // alias name doesn't itself end in
///                                                    // "crypto"
///
/// — and Zig has no bound on how many hops of local aliasing a call site can
/// introduce, so no finite list of qualified spellings can be complete.
/// `timing_safe` cannot be renamed by an alias — Zig aliases bind a new name
/// to a value, they do not let you address a namespace member under a
/// different member name — so the literal identifier `timing_safe` must
/// appear in the source at least once for any access to reach it, direct or
/// aliased, at any depth. The identifier does not exist anywhere in this
/// project or in `std.crypto` for any other purpose, so a bare, qualifier-
/// independent match is both sound (matches only genuine `timing_safe`
/// references) and complete (no aliasing depth evades it) rather than a
/// finite guess at qualifier spellings.
const timing_safe_forbidden = [_][]const u8{
    "timing_safe",
};

/// The raw, non-canonical spelling of a secret-buffer zero. Reserved for
/// `crypto.secrets.secureZero`'s own one-line implementation
/// (`src/crypto/secrets.zig`) and the handful of named files below that must
/// route every zero exclusively through the canonical wrapper because #375
/// found and fixed a zero-then-plain-free defect there; *not* forbidden
/// project-wide, since many other files legitimately call this directly on a
/// stack-local buffer with nothing to free at all.
const zeroization_forbidden = [_][]const u8{
    "std.crypto.secureZero(",
    "std_crypto.secureZero(",
};

const dir_checks_375 = [_]DirCheck{
    .{
        .dir = "src/tls",
        .excluded_paths = &.{},
        .forbidden = &timing_safe_forbidden,
        .rationale = "Every secret/authentication-derived comparison in src/tls routes through crypto.secrets.constantTimeEqual/crypto.provider.constantTimeEqual per #375; a raw std.crypto.timing_safe (or locally-aliased crypto.timing_safe) call reappearing anywhere in this tree is a constant-time-comparison regression, not a new public comparison (those use ordinary std.mem.eql, never timing_safe, per docs/CRYPTO_SECURITY_AUDIT.md's public-comparisons table).",
    },
    .{
        .dir = "src/quic",
        .excluded_paths = &.{},
        .forbidden = &timing_safe_forbidden,
        .rationale = "Same regression class as src/tls: #375 migrated packet.zig's Retry-integrity check, path.zig's Retry-integrity and PATH_RESPONSE checks, and every other secret/authentication-derived comparison in src/quic onto the canonical constant-time helper. A raw timing_safe call reappearing here — including inside a new nested module, since this scan is recursive — is the regression.",
    },
    .{
        .dir = "src/pki",
        .excluded_paths = &.{},
        .forbidden = &timing_safe_forbidden,
        .rationale = "src/pki has no raw std.crypto.timing_safe call today: its EMSA-PSS-adjacent structural checks live in src/crypto/rsa.zig (see that check below), and everything in src/pki itself is public certificate/DER structure, correctly left as ordinary std.mem.eql per #375. A new raw timing_safe call anywhere in this tree needs the same audit-and-classify treatment #375 gave rsa.zig, not a silent reintroduction.",
    },
    .{
        .dir = "src/crypto",
        // secrets.zig owns constantTimeEqual's one legitimate raw
        // implementation; excluded by exact path (not scanned at all) so it
        // gets its own narrower FileCheckWithExceptions entry below instead,
        // the same "excluded from the recursive scan, checked separately
        // with a named exception" shape src/quic's #490 DirCheck already
        // uses for tls_adapter.zig and friends.
        .excluded_paths = &.{"src/crypto/secrets.zig"},
        .forbidden = &timing_safe_forbidden,
        .rationale = "#554 review: src/crypto/rsa.zig's EMSA-PSS final authentication hash comparison is explicitly in #375's audit matrix and must route through crypto.secrets.constantTimeEqual like every other secret/authentication-derived comparison; the original version of this guard scanned only src/tls/src/quic/src/pki and missed this consumer entirely. Every other src/crypto file (provider.zig, pure_zig.zig, profile.zig, root.zig) has no legitimate raw timing_safe call either.",
    },
};

/// Named-exception guards for the specific ad hoc zero-and-free /
/// raw-secureZero-spelling findings #375 fixed (see the file-level doc
/// comment's point 5). Reuses `file_checks`'/`file_checks_with_exceptions`'
/// mechanism and struct types rather than inventing a new one.
const file_checks_375 = [_]FileCheck{
    .{
        .path = "src/tls/ticket_key_snapshot.zig",
        .forbidden = &zeroization_forbidden,
        .rationale = "#375 fixed ZeroingAllocator.resize/.free and OwnedSnapshot.deinit's KeyStorage loop from a raw std.crypto.secureZero to the canonical provider.secureZero/crypto.secrets wrapper; no raw std.crypto.secureZero/std_crypto.secureZero call has any legitimate purpose in this file. The structural zero-then-plain-free shapes #375 also fixed here (loadFromFile, reserveNonceLeasesInFile, parse's key_storage errdefer) are covered generically by the zero-then-plain-free scan below, which — unlike this literal check — also catches the same defect under a renamed variable or in a file this list does not name.",
    },
    .{
        .path = "src/tls/sni_provider.zig",
        .forbidden = &zeroization_forbidden,
        .rationale = "SignAdapter.release must wipe the retained signing key through the canonical crypto.provider.secureZero wrapper; #375 fixed this file's one call site from a raw std_crypto.secureZero back to the wrapper, and no raw std.crypto.secureZero/std_crypto.secureZero call has any other legitimate purpose in this file.",
    },
};

const file_checks_with_exceptions_375 = [_]FileCheckWithExceptions{
    .{
        .path = "src/crypto/secrets.zig",
        .forbidden = &(zeroization_forbidden ++ timing_safe_forbidden ++ [_][]const u8{".free(self.bytes)"}),
        // The two legitimate raw-primitive call sites project-wide:
        // secureZero's own implementation (std.crypto.secureZero) and
        // constantTimeEqual's own implementation (std.crypto.timing_safe),
        // which every other file/function is supposed to reach only through
        // these wrappers.
        .exempt_functions = &.{ "secureZero", "constantTimeEqual" },
        .rationale = "#375 fixed BoundedSecret.deinit calling clearAll() (which correctly zeroes via the secureZero wrapper) followed by a plain allocator.free(self.bytes) — a zero-then-poisoned-or-unzeroed free, not a zero-then-genuinely-zero one — to route through secureZeroAndFree instead. self.bytes must never be freed any other way, and no code outside secureZero()/constantTimeEqual() may call std.crypto.secureZero/std.crypto.timing_safe directly.",
    },
};

// `test_quic_crypto` (`tests/support/quic_crypto.zig`) owns concrete
// pure-Zig provider construction for tests/tools that exercise the QUIC seam
// directly. Earlier revisions of this audit tried to enforce "no production
// code path may reference it" with a source-text scan: a fixed list of
// importers, then a marker-based "before/after the test boundary" heuristic.
// #490's sixth-pass review found that unsound on two independent axes: a
// renamed import binding or an inline `@import("test_quic_crypto")` defeats
// any scan looking for the literal identifier, and Zig declarations are
// order-independent, so a public declaration before a textual marker can
// call a private helper physically written after it — no text-position
// heuristic makes that region actually unreachable.
//
// The sound fix is structural, not textual: `build.zig` wires
// `test_quic_crypto` only into `quic_test_mod`/`exe_test_mod` (used solely
// by `quic_tests`/`exe_unit_tests`), never into `quic_mod`/`exe_mod` (used
// by `exe`/`run_cmd` and every other production consumer). Any reachable
// reference to it from code compiled as part of the production module graph
// — under any binding name, any indirection, any position in the file — is
// therefore a compiler error ("no module named 'test_quic_crypto' available
// within module 'quic'"), not something this tool has to detect after the
// fact. See the comment beside `test_quic_crypto_mod` in `build.zig`.

// ---------------------------------------------------------------------------
// Scanning
// ---------------------------------------------------------------------------

/// First forbidden needle found in `contents`, or null. Pure and
/// allocation-free so it is directly testable against in-memory fixtures.
fn firstForbidden(contents: []const u8, forbidden: []const []const u8) ?[]const u8 {
    for (forbidden) |needle| {
        if (std.mem.indexOf(u8, contents, needle) != null) return needle;
    }
    return null;
}

const Violation = struct {
    path: []const u8,
    needle: []const u8,
    rationale: []const u8,
};

/// `required`: whether a missing file is itself a violation. `file_checks`/
/// `file_checks_with_exceptions` entries name specific protected files the
/// audit exists to enforce, so a renamed or deleted one must fail closed
/// rather than silently pass with zero violations (#490 third-pass review) —
/// unlike `checkDir`'s per-entry calls, where the file is already known to
/// exist from directory iteration.
fn checkFile(allocator: std.mem.Allocator, root: compat.DirCompat, path: []const u8, forbidden: []const []const u8, rationale: []const u8, required: bool, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            if (required) {
                try violations.append(allocator, .{
                    .path = try allocator.dupe(u8, path),
                    .needle = "<file missing>",
                    .rationale = rationale,
                });
            }
            return;
        },
        else => return err,
    };
    defer allocator.free(contents);
    if (firstForbidden(contents, forbidden)) |needle| {
        try violations.append(allocator, .{ .path = try allocator.dupe(u8, path), .needle = needle, .rationale = rationale });
    }
}

/// Extracts one function/method's source span: from `fn <function_name>(` to
/// (but not including) the next sibling top-level declaration — a
/// `pub fn `/`fn ` at either 4-space struct-method indentation or 0-space
/// top-level indentation, or a 0-space `pub const `/`const ` (for a function
/// immediately followed by a container declaration, e.g. the struct the
/// function's own methods belong to) — or end of file. Narrow and
/// deterministic like the rest of this audit rather than a general Zig
/// parser — a real parser would have to distinguish the function body's
/// opening brace from inline return-type groups like `error{Foo}`, which
/// several target functions here have.
/// Shared "next sibling declaration" boundary markers: a `pub fn `/`fn ` at
/// either 4-space struct-method or 0-space top-level indentation, or a
/// 0-space `pub const `/`const ` (for a declaration immediately followed by
/// a container declaration, e.g. the struct its own methods belong to).
/// Used both by `extractFunctionBody` (bound a *named* function's body) and
/// by the zero-then-plain-free scanner below (bound a forward scan from an
/// arbitrary interior position to "the rest of the enclosing
/// function/declaration" without needing to know where it started).
const declaration_boundaries = [_][]const u8{
    "\n    pub fn ", "\n    fn ",
    "\npub fn ",     "\nfn ",
    "\npub const ",  "\nconst ",
    "\ntest ",
};

fn extractFunctionBody(contents: []const u8, function_name: []const u8) ?[]const u8 {
    var search_from: usize = 0;
    while (true) {
        const rel = std.mem.indexOfPos(u8, contents, search_from, function_name) orelse return null;
        const before_ok = rel >= 3 and std.mem.eql(u8, contents[rel - 3 .. rel], "fn ");
        const after_name = rel + function_name.len;
        const after_ok = after_name < contents.len and contents[after_name] == '(';
        if (before_ok and after_ok) {
            return contents[rel..nextDeclarationBoundary(contents, after_name)];
        }
        search_from = rel + 1;
    }
}

/// The nearest declaration boundary at or after `from`, or `contents.len`.
fn nextDeclarationBoundary(contents: []const u8, from: usize) usize {
    var end = contents.len;
    for (declaration_boundaries) |boundary| {
        if (std.mem.indexOfPos(u8, contents, from, boundary)) |p| end = @min(end, p);
    }
    return end;
}

/// The nearest declaration boundary strictly before `from`, or `0` — the
/// mirror of `nextDeclarationBoundary`, used to find where the *current*
/// enclosing function/declaration starts, scanning backward from an
/// arbitrary interior position (#554 review, third pass: `defer` runs LIFO,
/// so a zero call declared textually *after* a `free`'s own `defer` still
/// executes before it at runtime — a forward-only window from the zero call
/// would never see that earlier `defer`).
fn previousDeclarationBoundary(contents: []const u8, from: usize) usize {
    var start: usize = 0;
    for (declaration_boundaries) |boundary| {
        if (std.mem.lastIndexOf(u8, contents[0..from], boundary)) |p| {
            // `p` is the boundary's own position (starting at its leading
            // `\n`); the declaration itself starts one byte later.
            start = @max(start, p + 1);
        }
    }
    return start;
}

/// Redacts every occurrence of `needle` in `buf` in place (same length, so
/// no other span shifts), for a mutable scratch copy only.
fn blank(buf: []u8, needle: []const u8) void {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, buf, search_from, needle)) |idx| {
        @memset(buf[idx .. idx + needle.len], ' ');
        search_from = idx + needle.len;
    }
}

// ---------------------------------------------------------------------------
// #554: general zero-then-plain-free scanner
// ---------------------------------------------------------------------------
//
// The named-file/exact-variable-name check above (`file_checks_375`'s
// `zeroization_forbidden` entries) only catches the raw-spelling half of
// #375's zero-and-free findings. #554 review (second pass) found it does
// not satisfy the "new ad hoc zero-and-free implementation" half of the
// acceptance criteria at all: a zero routed correctly through the canonical
// `secureZero` wrapper, followed by a plain `allocator.free`/`.deinit()`
// instead of `secureZeroAndFree`/`secureZeroAndFreeAligned`, passes under
// any variable name this list doesn't happen to spell out — including the
// exact historical finding under a harmless local rename. This scanner
// instead extracts the buffer expression every `secureZero(...)` call
// zeroes and looks for that same expression handed to an ordinary free
// within the rest of the enclosing function, so it generalizes to a new
// file, a new function, or a renamed variable without needing a name listed
// anywhere.

/// Extracts the text between a call's opening `(` (`open_paren`, which must
/// index a `(` byte) and its matching `)`, tracking `(`/`[`/`{` nesting so
/// an argument containing its own call or slice expression
/// (`std.mem.sliceAsBytes(storage)`, `self.bytes[a..b]`) does not end the
/// scan early. `null` if the parens never balance before end of file.
fn extractCallArgs(contents: []const u8, open_paren: usize) ?[]const u8 {
    var depth: i32 = 0;
    var i = open_paren;
    while (i < contents.len) : (i += 1) {
        switch (contents[i]) {
            '(', '[', '{' => depth += 1,
            ')', ']', '}' => {
                depth -= 1;
                if (depth == 0) return contents[open_paren + 1 .. i];
            },
            else => {},
        }
    }
    return null;
}

/// The text after the last top-level (bracket/paren/brace depth 0) comma in
/// `args`, trimmed — i.e. the last positional argument of a call. Both
/// `secureZero(buffer)` and the raw two-argument
/// `std.crypto.secureZero(u8, buffer)` spelling reduce to the buffer
/// expression this way, without needing to know which spelling was used.
fn lastArgument(args: []const u8) []const u8 {
    var depth: i32 = 0;
    var last_comma: ?usize = null;
    for (args, 0..) |c, i| {
        switch (c) {
            '(', '[', '{' => depth += 1,
            ')', ']', '}' => depth -= 1,
            ',' => if (depth == 0) {
                last_comma = i;
            },
            else => {},
        }
    }
    const start = if (last_comma) |c| c + 1 else 0;
    return std.mem.trim(u8, args[start..], " \t\r\n");
}

/// The text before the first top-level comma in `args`, trimmed — the
/// *first* positional argument. `@memset(dest, value)` names the buffer
/// being cleared as its first argument, unlike `secureZero`'s single-buffer
/// (or `std.crypto.secureZero(u8, buffer)`'s buffer-last) shape.
fn firstArgument(args: []const u8) []const u8 {
    var depth: i32 = 0;
    for (args, 0..) |c, i| {
        switch (c) {
            '(', '[', '{' => depth += 1,
            ')', ']', '}' => depth -= 1,
            ',' => if (depth == 0) return std.mem.trim(u8, args[0..i], " \t\r\n"),
            else => {},
        }
    }
    return std.mem.trim(u8, args, " \t\r\n");
}

/// True for a literal-zero expression (`0`, `0x0`, `0x00`) — the narrow
/// shape that makes `@memset(dest, <this>)` a manual zero-clear rather than
/// an ordinary fill (`@memset(buf, 0xAA)` poison-filling a test buffer is
/// not zeroization, and #554's own non-goals warn against treating every
/// `@memset` as security-relevant).
fn isZeroLiteral(text: []const u8) bool {
    return std.mem.eql(u8, text, "0") or std.mem.eql(u8, text, "0x0") or std.mem.eql(u8, text, "0x00");
}

fn isIdentStart(c: u8) bool {
    return std.ascii.isAlphabetic(c) or c == '_';
}
fn isIdentCont(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '_';
}

/// Iterates the maximal dotted-identifier-path tokens inside an expression:
/// `std.mem.sliceAsBytes(storage)` yields `std.mem.sliceAsBytes` then
/// `storage`; `self.bytes[value.len..old_len]` yields `self.bytes`,
/// `value.len`, `old_len`. A syntax-agnostic, deliberately over-inclusive
/// stand-in for "every plausible buffer-identity expression this argument
/// could name" — the scan below tries each token as a candidate freed-buffer
/// identity rather than committing to a single guess about which one is the
/// real buffer.
const TokenIterator = struct {
    text: []const u8,
    pos: usize = 0,

    fn next(self: *TokenIterator) ?[]const u8 {
        while (self.pos < self.text.len and !isIdentStart(self.text[self.pos])) : (self.pos += 1) {}
        if (self.pos >= self.text.len) return null;
        const start = self.pos;
        while (self.pos < self.text.len and isIdentCont(self.text[self.pos])) : (self.pos += 1) {}
        while (self.pos + 1 < self.text.len and self.text[self.pos] == '.' and isIdentStart(self.text[self.pos + 1])) {
            self.pos += 1;
            while (self.pos < self.text.len and isIdentCont(self.text[self.pos])) : (self.pos += 1) {}
        }
        return self.text[start..self.pos];
    }
};

/// True if some call `NAME(` in `window` has `key` as its first positional
/// argument, tolerant of interior whitespace/newlines and a trailing comma
/// (`allocator.free(\n    secret_buf,\n)` must match exactly like
/// `allocator.free(secret_buf)` — #554 review, fourth pass: the naive
/// "identifier immediately after `free(`, immediately before `)`" check this
/// replaced rejected anything reformatted across lines). Reuses
/// `extractCallArgs`/`firstArgument` — the same balanced-bracket argument
/// parser the zero-call side already relies on — instead of a second,
/// less careful ad hoc scan.
fn callArgumentMatches(window: []const u8, name: []const u8, key: []const u8) bool {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, window, search_from, name)) |p| {
        search_from = p + 1;
        const open_paren = p + name.len - 1;
        const args = extractCallArgs(window, open_paren) orelse continue;
        if (std.mem.eql(u8, firstArgument(args), key)) return true;
    }
    return false;
}

/// True if `window` contains an ordinary free/deinit of `key`: `key` handed
/// to a `.free(`/`.rawFree(`/`allocator.free(`/`allocator.rawFree(` call as
/// its first argument, or `.deinit(`/`.free(`/`.rawFree(` called *on* `key`
/// as receiver (the `ArrayList`/similar-container shape). Deliberately
/// agnostic about what precedes `free(`/`rawFree(` (the allocator
/// expression — `allocator.free(key)`, `self.allocator.free(key)`, and
/// `fba.allocator().free(key)` are all caught the same way) by searching for
/// the bare call substring rather than requiring a specific receiver
/// spelling. `rawFree` is included (#554 review, fourth pass): it is part of
/// #375's inventory and releases the live buffer directly, bypassing
/// `secureZeroAndFree`/`secureZeroAndFreeAligned` entirely, without matching
/// any of the other forbidden spellings — `src/crypto/secrets.zig`'s own
/// canonical implementations are excluded from this scan by file, not by
/// this function ignoring `rawFree`, so no separate exemption is needed here
/// for the canonical call itself.
fn containsPlainFreeOf(window: []const u8, key: []const u8) bool {
    if (key.len == 0) return false;
    if (callArgumentMatches(window, "free(", key)) return true;
    if (callArgumentMatches(window, "rawFree(", key)) return true;
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, window, search_from, key)) |p| {
        search_from = p + 1;
        // `key` must start a genuine identifier token here, not be a
        // trailing suffix of a longer one (`self.selected_client_psk` must
        // not match key `psk` just because it ends in "psk" immediately
        // followed by `.deinit(` — #554 review, third pass surfaced this as
        // a real false-positive risk once the scan window widened to the
        // whole function).
        if (p > 0 and isIdentCont(window[p - 1])) continue;
        const after = p + key.len;
        if (after + ".deinit(".len <= window.len and std.mem.eql(u8, window[after..][0..".deinit(".len], ".deinit(")) return true;
        if (after + ".free(".len <= window.len and std.mem.eql(u8, window[after..][0..".free(".len], ".free(")) return true;
        if (after + ".rawFree(".len <= window.len and std.mem.eql(u8, window[after..][0..".rawFree(".len], ".rawFree(")) return true;
    }
    return false;
}

fn isSimpleIdent(text: []const u8) bool {
    if (text.len == 0 or !isIdentStart(text[0])) return false;
    for (text) |c| if (!isIdentCont(c)) return false;
    return true;
}

fn isSimplePathExpr(text: []const u8) bool {
    for (text) |c| {
        if (!isIdentCont(c) and c != '.' and !std.ascii.isWhitespace(c)) return false;
    }
    return true;
}

/// The start of the statement containing position `at`: just past the
/// nearest preceding `;` or `{`, or 0. Used to bound alias-declaration
/// lookups to "the current statement," not an unrelated one earlier in the
/// file that happens to share punctuation.
fn statementStart(contents: []const u8, at: usize) usize {
    var i = at;
    while (i > 0) : (i -= 1) {
        if (contents[i - 1] == ';' or contents[i - 1] == '{') return i;
    }
    return 0;
}

const max_aliases = 8;

/// A local callee alias of the zero helper, together with the span of the
/// enclosing function/declaration it was bound in. Calls to `name` are only
/// evidence of zeroing *within* `[scope_start, scope_end)` — resolving the
/// alias's callee scan against the whole file would misattribute an
/// unrelated same-named function or local elsewhere in the file to this
/// alias (#554 review, fourth pass).
const AliasInfo = struct {
    name: []const u8,
    scope_start: usize,
    scope_end: usize,
};

/// Local callee aliases of the zero helper — `const wipe =
/// crypto.secrets.secureZero;` followed by `wipe(buf)` — bound anywhere in
/// `contents` (#554 review, second pass: a check that only recognizes the
/// literal `secureZero(` spelling is defeated by aliasing the function
/// value itself before calling it). One hop: `NAME` must be a simple
/// identifier bound directly to a bare `secureZero` reference (not
/// `secureZeroAndFree`/`secureZeroAndFreeAligned` — excluded by the `next
/// char is 'A'` check, same as the direct-call scan) by a simple dotted-path
/// expression, not an arbitrary computation. Bounded to `max_aliases`
/// entries.
fn findSecureZeroAliases(contents: []const u8, out: *[max_aliases]AliasInfo) usize {
    var count: usize = 0;
    var search_from: usize = 0;
    while (count < max_aliases) {
        const rel = std.mem.indexOfPos(u8, contents, search_from, "secureZero") orelse break;
        search_from = rel + 1;
        const after = rel + "secureZero".len;
        if (after >= contents.len) continue;
        if (contents[after] == 'A') continue; // ...AndFree/...AndFreeAligned
        if (contents[after] != ';' and contents[after] != ',' and contents[after] != ')') continue;

        const stmt = contents[statementStart(contents, rel)..rel];
        const eq_rel = std.mem.lastIndexOfScalar(u8, stmt, '=') orelse continue;
        if (!isSimplePathExpr(stmt[eq_rel + 1 ..])) continue;

        const before_eq = std.mem.trimEnd(u8, stmt[0..eq_rel], " \t\r\n");
        const kw = "const ";
        const kw_at = std.mem.lastIndexOf(u8, before_eq, kw) orelse continue;
        const name = std.mem.trim(u8, before_eq[kw_at + kw.len ..], " \t\r\n");
        if (!isSimpleIdent(name)) continue;
        out[count] = .{
            .name = name,
            .scope_start = previousDeclarationBoundary(contents, rel),
            .scope_end = nextDeclarationBoundary(contents, rel),
        };
        count += 1;
    }
    return count;
}

/// Finds a local rebinding `const NAME = <expr>;` in `text` whose
/// right-hand side (trimmed, one leading `&` stripped) is exactly `key` —
/// one hop of "the buffer got a new local name" resolution (#554 review,
/// second pass: `const doomed = secret_buf; allocator.free(doomed);` defeats
/// a check keyed only on the zero call's own argument expression).
/// Every local rebinding `const NAME = <expr>;` in `text` whose right-hand
/// side (trimmed, one leading `&` stripped) is exactly `key` — up to
/// `out.len` matches, not just the first (#554 review, third pass: a
/// harmless first alias preceding the actually-freed second alias shadowed
/// the real one when only the first match was returned). Still one hop:
/// each returned name is a rename of `key` itself, not of a rename of a
/// rename — `scanZeroCalls`'s caller may re-invoke this on a returned name
/// for a second hop if that becomes necessary, but no current bypass needs
/// it.
fn resolveBufferRenames(text: []const u8, key: []const u8, out: *[max_aliases][]const u8) usize {
    var count: usize = 0;
    if (key.len == 0) return count;
    var search_from: usize = 0;
    while (count < out.len) {
        const kw_pos = std.mem.indexOfPos(u8, text, search_from, "const ") orelse break;
        search_from = kw_pos + 1;
        const after_kw = kw_pos + "const ".len;
        const eq_rel = std.mem.indexOfScalarPos(u8, text, after_kw, '=') orelse continue;
        const name = std.mem.trim(u8, text[after_kw..eq_rel], " \t\r\n");
        if (!isSimpleIdent(name)) continue;
        const semi_rel = std.mem.indexOfScalarPos(u8, text, eq_rel, ';') orelse continue;
        var rhs = std.mem.trim(u8, text[eq_rel + 1 .. semi_rel], " \t\r\n");
        if (rhs.len > 0 and rhs[0] == '&') rhs = std.mem.trim(u8, rhs[1..], " \t\r\n");
        if (std.mem.eql(u8, rhs, key)) {
            out[count] = name;
            count += 1;
        }
    }
    return count;
}

/// The position of the next call `NAME(` in `contents` at or after `from` —
/// `NAME` immediately followed by `(` — or `null`. Shared by the direct
/// `secureZero(` scan and the alias-callee scan below so both go through
/// the same call-site recognition.
fn findNextCall(contents: []const u8, from: usize, name: []const u8) ?usize {
    var search_from = from;
    while (std.mem.indexOfPos(u8, contents, search_from, name)) |rel| {
        search_from = rel + 1;
        const after = rel + name.len;
        if (after < contents.len and contents[after] == '(') return rel;
    }
    return null;
}

/// The buffer-identity token of the first zero call — direct `secureZero(`
/// or through a local callee alias (`findSecureZeroAliases`) — in `contents`
/// whose zeroed buffer, or a local rename of it (`resolveBufferRename`), is
/// later handed to an ordinary free/deinit instead of
/// `secureZeroAndFree`/`secureZeroAndFreeAligned`, scoped to the rest of the
/// enclosing function/declaration.
fn firstZeroThenPlainFree(contents: []const u8) ?[]const u8 {
    var alias_buf: [max_aliases]AliasInfo = undefined;
    const alias_count = findSecureZeroAliases(contents, &alias_buf);

    if (scanZeroCalls(contents, "secureZero")) |key| return key;
    for (alias_buf[0..alias_count]) |alias| {
        // Scoped to the alias's own enclosing declaration, not the whole
        // file (#554 review, fourth pass): searching all of `contents` for
        // calls spelled `alias.name` would treat an unrelated same-named
        // top-level function or a different local elsewhere in the file as
        // if it were this alias.
        if (scanZeroCalls(contents[alias.scope_start..alias.scope_end], alias.name)) |key| return key;
    }
    // Manual zero-and-free / volatile-clear (#554 review, third pass): a
    // clear implementation outside the canonical `secureZero` wrapper
    // entirely, e.g. `@memset(secret_buf, 0)` followed by a plain free.
    if (scanZeroCalls(contents, "@memset")) |key| return key;
    // A hand-written zero-clear loop instead of a builtin/wrapper call
    // (#554 review, fourth pass): neither `secureZero(` nor `@memset(`
    // appears in source that clears a buffer one element at a time through
    // `for (buf) |*byte| byte.* = 0;`.
    if (scanZeroClearLoops(contents)) |key| return key;
    return null;
}

/// The buffer-expression argument for a given zero-call `trigger`: the last
/// positional argument for `secureZero`/its aliases (`secureZero(buffer)`,
/// or the raw two-argument `std.crypto.secureZero(u8, buffer)` — both
/// reduce to the buffer this way), but the *first* argument for `@memset`
/// (`@memset(dest, value)` — `dest` is the buffer being cleared).
fn argForTrigger(trigger: []const u8, args: []const u8) []const u8 {
    if (std.mem.eql(u8, trigger, "@memset")) return firstArgument(args);
    return lastArgument(args);
}

/// True if `window` contains a `return <expr>;` whose expression is exactly
/// `key` (one leading `&` stripped) — evidence the buffer is being handed
/// back to the caller, not destroyed. A zero-fill paired with an
/// `errdefer`-guarded free earlier in the same function (fallible
/// initialization: allocate, `errdefer free` as a failure-path safety net,
/// zero-initialize, then return the buffer to the caller) is ordinary
/// initialization, not the #375 zero-then-destroy defect this scanner
/// exists to catch (#554 review, fourth pass) — the buffer's lifetime
/// continues in the caller, it is not being wiped before release.
fn containsReturnOf(window: []const u8, key: []const u8) bool {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, window, search_from, "return ")) |p| {
        const after = p + "return ".len;
        search_from = after;
        const semi = std.mem.indexOfScalarPos(u8, window, after, ';') orelse continue;
        var expr = std.mem.trim(u8, window[after..semi], " \t\r\n");
        if (expr.len > 0 and expr[0] == '&') expr = std.mem.trim(u8, expr[1..], " \t\r\n");
        if (std.mem.eql(u8, expr, key)) return true;
    }
    return false;
}

/// Checks whether `buf_expr` (the buffer a zero call/loop at `trigger_pos`,
/// ending at `call_end`, clears) is later handed to an ordinary free/deinit
/// within the enclosing function/declaration — the shared "now that we have
/// a zeroed buffer, is it plainly freed?" logic every trigger
/// (`secureZero`, `@memset`, and the manual zero-clear loop) reduces to.
fn checkBufferAgainstPlainFree(contents: []const u8, trigger_pos: usize, call_end: usize, buf_expr: []const u8) ?[]const u8 {
    // The whole enclosing function/declaration, not just the text after the
    // zero call: `defer` runs LIFO, so a free's own `defer` written
    // textually *before* a zero call's `defer` still executes *after* it at
    // runtime (#554 review, third pass) — a forward-only window would miss
    // that free entirely.
    const window_start = previousDeclarationBoundary(contents, trigger_pos);
    const window_end = nextDeclarationBoundary(contents, call_end);
    const window = contents[window_start..window_end];
    var tokens = TokenIterator{ .text = buf_expr };
    while (tokens.next()) |key| {
        if (key.len < 2) continue;
        if (containsReturnOf(window, key)) continue;
        if (containsPlainFreeOf(window, key)) return key;
        var renames: [max_aliases][]const u8 = undefined;
        const rename_count = resolveBufferRenames(window, key, &renames);
        for (renames[0..rename_count]) |renamed| {
            if (containsReturnOf(window, renamed)) continue;
            if (containsPlainFreeOf(window, renamed)) return renamed;
        }
        // The container-field fallback: `secureZero(out.items)` zeroes
        // an `ArrayList`'s current contents, but the matching free is
        // `out.deinit()` on the container itself, not
        // `out.items.deinit()` — so also try the path with its last
        // `.field` segment stripped. `self.bytes[a..b]` (a sub-range,
        // not the whole buffer) reduces the same way to `self`, which
        // `containsPlainFreeOf` still requires an *exact* `free(self)`/
        // `self.deinit(`/`self.free(` match for — a real hit here is
        // still the same true regression class, just via one more field
        // of indirection than the field-only case.
        if (std.mem.lastIndexOfScalar(u8, key, '.')) |dot| {
            const parent = key[0..dot];
            if (parent.len >= 2 and !containsReturnOf(window, parent) and containsPlainFreeOf(window, parent)) return parent;
        }
    }
    return null;
}

fn scanZeroCalls(contents: []const u8, trigger: []const u8) ?[]const u8 {
    var search_from: usize = 0;
    while (findNextCall(contents, search_from, trigger)) |m| {
        search_from = m + 1;
        const open_paren = m + trigger.len;
        const args = extractCallArgs(contents, open_paren) orelse continue;
        const call_end = open_paren + args.len + 2; // past the matching ')'
        if (std.mem.eql(u8, trigger, "@memset") and !isZeroLiteral(lastArgument(args))) continue;
        const buf_expr = argForTrigger(trigger, args);
        if (checkBufferAgainstPlainFree(contents, m, call_end, buf_expr)) |key| return key;
    }
    return null;
}

/// A hand-written zero-clear loop — `for (buf) |*byte| byte.* = 0;` (a
/// braced or single-statement body, with or without a second index capture
/// via `for (buf, 0..) |*byte, _|`) — clears a buffer one element at a time
/// without ever calling `secureZero(` or `@memset(`, so neither existing
/// trigger sees it (#554 review, fourth pass). Reduces to the same
/// `checkBufferAgainstPlainFree` plain-free/rename detection as the other
/// two triggers once the loop's iterable expression and element-assignment
/// body are recognized.
fn scanZeroClearLoops(contents: []const u8) ?[]const u8 {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, contents, search_from, "for (")) |for_pos| {
        search_from = for_pos + 1;
        const open_paren = for_pos + "for (".len - 1;
        const loop_args = extractCallArgs(contents, open_paren) orelse continue;
        const args_end = open_paren + loop_args.len + 2; // past the matching ')'

        var i = args_end;
        while (i < contents.len and std.ascii.isWhitespace(contents[i])) : (i += 1) {}
        if (i >= contents.len or contents[i] != '|') continue;
        i += 1;
        if (i >= contents.len or contents[i] != '*') continue;
        i += 1;
        const name_start = i;
        while (i < contents.len and isIdentCont(contents[i])) : (i += 1) {}
        const elem_name = contents[name_start..i];
        if (!isSimpleIdent(elem_name)) continue;
        const capture_close = std.mem.indexOfScalarPos(u8, contents, i, '|') orelse continue;

        var body_start = capture_close + 1;
        while (body_start < contents.len and std.ascii.isWhitespace(contents[body_start])) : (body_start += 1) {}
        const has_braces = body_start < contents.len and contents[body_start] == '{';
        const body = if (has_braces)
            extractCallArgs(contents, body_start) orelse continue
        else blk: {
            const semi = std.mem.indexOfScalarPos(u8, contents, body_start, ';') orelse continue;
            break :blk contents[body_start..semi];
        };
        const body_end = if (has_braces) body_start + body.len + 2 else body_start + body.len + 1;

        if (!isByteZeroClearBody(body, elem_name)) continue;
        const buf_expr = firstArgument(loop_args);
        if (checkBufferAgainstPlainFree(contents, for_pos, body_end, buf_expr)) |key| return key;
    }
    return null;
}

/// True if `body` (a zero-clear loop's element-capture body) assigns a zero
/// literal through the element pointer `name`: `name.* = 0` (or `0x0`/
/// `0x00`), tolerant of whitespace around `.*`/`=`.
fn isByteZeroClearBody(body: []const u8, name: []const u8) bool {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, body, search_from, name)) |p| {
        search_from = p + 1;
        if (p > 0 and isIdentCont(body[p - 1])) continue;
        const after = p + name.len;
        if (after + 2 > body.len or body[after] != '.' or body[after + 1] != '*') continue;
        var i = after + 2;
        while (i < body.len and std.ascii.isWhitespace(body[i])) : (i += 1) {}
        if (i >= body.len or body[i] != '=') continue;
        i += 1;
        // The single-statement (unbraced) loop-body form strips its own
        // trailing `;` before reaching here, so a missing `;` means "the
        // assignment's RHS runs to the end of this body," not "no match" —
        // falling back to `continue` here would silently reject exactly the
        // `for (buf) |*byte| byte.* = 0;` shape this function exists to
        // recognize.
        const semi = std.mem.indexOfScalarPos(u8, body, i, ';') orelse body.len;
        if (isZeroLiteral(std.mem.trim(u8, body[i..semi], " \t\r\n"))) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// #554 review (second pass): dedicated BoundedSecret.deinit structural check
// ---------------------------------------------------------------------------
//
// `firstZeroThenPlainFree` only looks *forward* from a zero call to a later
// free within one function's textual span. `BoundedSecret`'s real shape
// splits the two across sibling methods — `clearAll`/`clear` do the
// zeroing, `deinit` does the freeing — and `deinit` is declared *before*
// `clearAll` in the file, so a forward-only scan starting from `clearAll`'s
// zero call would never reach back into `deinit`'s free even with an
// unbounded window. A whole-file or whole-struct "any secureZero + any
// free/deinit" rule would also misfire immediately on this file's own tests
// calling `secret.deinit()` — the type's own, correct, public API, not a
// bypass — so this check is deliberately narrow: it tracks only
// `self.bytes`, the one secret buffer `BoundedSecret` owns, through at most
// one local rename, anywhere in the struct's full body (all of its
// methods), and rejects it being freed any way other than
// `secureZeroAndFree`.

/// Extracts a top-level `const NAME = struct { ... };` container declaration
/// (or `pub const`) — brace-matched from the declaration through its
/// closing `}` — as opposed to `extractFunctionBody`'s "next sibling
/// declaration" heuristic, which stops at the first nested method and would
/// never include a second method of the same container.
fn extractContainerBody(contents: []const u8, name: []const u8) ?[]const u8 {
    var search_from: usize = 0;
    while (true) {
        const rel = std.mem.indexOfPos(u8, contents, search_from, name) orelse return null;
        search_from = rel + 1;
        if (rel < "const ".len or !std.mem.eql(u8, contents[rel - "const ".len .. rel], "const ")) continue;
        const after_name = rel + name.len;
        const eq_rel = std.mem.indexOfScalarPos(u8, contents, after_name, '=') orelse continue;
        if (!isAllWhitespace(contents[after_name..eq_rel])) continue;
        const open_brace = std.mem.indexOfScalarPos(u8, contents, eq_rel, '{') orelse continue;
        const between = std.mem.trim(u8, contents[eq_rel + 1 .. open_brace], " \t\r\n");
        if (!std.mem.eql(u8, between, "struct")) continue;

        var depth: i32 = 0;
        var i = open_brace;
        while (i < contents.len) : (i += 1) {
            switch (contents[i]) {
                '{' => depth += 1,
                '}' => {
                    depth -= 1;
                    if (depth == 0) return contents[rel .. i + 1];
                },
                else => {},
            }
        }
        return null;
    }
}

fn isAllWhitespace(text: []const u8) bool {
    for (text) |c| if (!std.ascii.isWhitespace(c)) return false;
    return true;
}

/// True if `struct_body` frees `self.bytes` — or a local rename of it, one
/// hop — any way other than `secureZeroAndFree`/`secureZeroAndFreeAligned`.
/// `containsPlainFreeOf`'s `free(` search already excludes both (the
/// character right after `secureZero` in each is `A`, not the case-sensitive
/// lowercase `f` `containsPlainFreeOf` looks for immediately after `free`),
/// so no separate exemption is needed for the canonical call itself.
/// True if `struct_body`'s `deinit` method positively calls
/// `secureZeroAndFree(<allocator>, self.bytes)` (or a resolved one-hop
/// rename of `self.bytes`) — the *only* authorized way to release
/// `BoundedSecret`'s backing storage. #554 review (third pass): blacklisting
/// known-bad free spellings is unbounded — `allocator.rawFree(self.bytes,
/// ...)` releases the live, unwiped buffer directly, bypassing
/// `secureZeroAndFree` entirely, without matching any forbidden substring
/// (`containsPlainFreeOf` deliberately excludes `rawFree` — the
/// case-sensitive capital `F` — because it's the correct spelling *inside*
/// `secureZeroAndFree`'s own implementation). Positively requiring the
/// canonical call instead means a violation is always "the call isn't
/// there," not "a new bypass spelling wasn't on the blacklist."
fn boundedSecretDeinitCallsCanonicalFree(struct_body: []const u8) bool {
    const deinit_body = extractFunctionBody(struct_body, "deinit") orelse return false;
    var search_from: usize = 0;
    while (findNextCall(deinit_body, search_from, "secureZeroAndFree")) |m| {
        search_from = m + 1;
        const open_paren = m + "secureZeroAndFree".len;
        const args = extractCallArgs(deinit_body, open_paren) orelse continue;
        const buf_expr = lastArgument(args);
        if (std.mem.eql(u8, buf_expr, "self.bytes")) return true;
        var renames: [max_aliases][]const u8 = undefined;
        const rename_count = resolveBufferRenames(deinit_body, "self.bytes", &renames);
        for (renames[0..rename_count]) |renamed| {
            if (std.mem.eql(u8, buf_expr, renamed)) return true;
        }
    }
    return false;
}

fn checkBoundedSecretFile(allocator: std.mem.Allocator, root: compat.DirCompat, path: []const u8, rationale: []const u8, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            try violations.append(allocator, .{
                .path = try allocator.dupe(u8, path),
                .needle = "<file missing>",
                .rationale = rationale,
            });
            return;
        },
        else => return err,
    };
    defer allocator.free(contents);
    const struct_body = extractContainerBody(contents, "BoundedSecret") orelse {
        try violations.append(allocator, .{
            .path = try allocator.dupe(u8, path),
            .needle = "<BoundedSecret declaration missing>",
            .rationale = rationale,
        });
        return;
    };
    if (!boundedSecretDeinitCallsCanonicalFree(struct_body)) {
        try violations.append(allocator, .{
            .path = try allocator.dupe(u8, path),
            .needle = "BoundedSecret.deinit does not call secureZeroAndFree(allocator, self.bytes)",
            .rationale = rationale,
        });
    }
}

const ZeroThenFreeDirCheck = struct {
    dir: []const u8,
    excluded_paths: []const []const u8 = &.{},
    rationale: []const u8,
};

fn checkZeroThenFreeFile(allocator: std.mem.Allocator, root: compat.DirCompat, path: []const u8, rationale: []const u8, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer allocator.free(contents);
    if (firstZeroThenPlainFree(contents) != null) {
        try violations.append(allocator, .{
            .path = try allocator.dupe(u8, path),
            .needle = "zero-then-plain-free",
            .rationale = rationale,
        });
    }
}

fn checkZeroThenFreeDir(allocator: std.mem.Allocator, root: compat.DirCompat, check: ZeroThenFreeDirCheck, dir_path: []const u8, violations: *std.ArrayList(Violation)) !void {
    var dir = root.openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close();
    var it = dir.iterate();
    while (try it.next(compat.io())) |entry| {
        const rel = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(rel);
        var excluded = false;
        for (check.excluded_paths) |excluded_path| {
            if (std.mem.eql(u8, rel, excluded_path)) {
                excluded = true;
                break;
            }
        }
        if (excluded) continue;
        switch (entry.kind) {
            .directory => try checkZeroThenFreeDir(allocator, root, check, rel, violations),
            .file => {
                if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
                try checkZeroThenFreeFile(allocator, root, rel, check.rationale, violations);
            },
            else => {},
        }
    }
}

const zero_then_free_checks_375 = [_]ZeroThenFreeDirCheck{
    .{
        .dir = "src/tls",
        // secrets.zig's own secureZeroAndFree/secureZeroAndFreeAligned
        // implementation legitimately zeroes then frees the same buffer —
        // that *is* the canonical helper, not an ad hoc reimplementation of
        // it — but secrets.zig lives in src/crypto, outside this dir.
        .excluded_paths = &.{},
        .rationale = "A secureZero call whose buffer is later handed to an ordinary allocator.free/.deinit within the same function, instead of crypto.secrets.secureZeroAndFree/secureZeroAndFreeAligned, is the ad hoc zero-and-free defect #375 fixed (BoundedSecret.deinit and four ticket_key_snapshot.zig sites) — general over every file/variable name in src/tls, not just those four historical sites.",
    },
    .{
        .dir = "src/quic",
        .excluded_paths = &.{},
        .rationale = "Same defect class as src/tls, general over src/quic.",
    },
    .{
        .dir = "src/pki",
        .excluded_paths = &.{},
        .rationale = "Same defect class as src/tls, general over src/pki.",
    },
    .{
        .dir = "src/crypto",
        // secureZero/secureZeroAndFree/secureZeroAndFreeAligned's own
        // implementations in secrets.zig legitimately zero then free/rawFree
        // the same buffer — that pairing *is* the canonical helper.
        // rawFree/vtable.free spellings don't match `containsPlainFreeOf`'s
        // lowercase-`free(`/`.free(`/`.deinit(` patterns in the first place
        // (capital F in `rawFree`), but excluding the file entirely avoids
        // relying on that incidentally rather than by design.
        .excluded_paths = &.{"src/crypto/secrets.zig"},
        .rationale = "Same defect class as src/tls, general over src/crypto outside secrets.zig's own canonical-helper implementation.",
    },
};

// ---------------------------------------------------------------------------
// #784: canonical secret-zeroization bypasses (file-level doc, point 6)
// ---------------------------------------------------------------------------

/// Length-preserving copy of `contents` with `//` comments, string and
/// character literal contents, and multiline `\\` string lines blanked to
/// spaces, so neither prose about `std.crypto.secureZero` nor a `{`/`}`
/// inside a format string can affect matching or brace counting. Quote
/// characters themselves are kept so offsets and token boundaries survive.
fn blankCommentsAndStrings(allocator: std.mem.Allocator, contents: []const u8) ![]u8 {
    const out = try allocator.dupe(u8, contents);
    var i: usize = 0;
    while (i < out.len) {
        const c = out[i];
        if (c == '/' and i + 1 < out.len and out[i + 1] == '/') {
            while (i < out.len and out[i] != '\n') : (i += 1) out[i] = ' ';
        } else if (c == '\\' and i + 1 < out.len and out[i + 1] == '\\') {
            while (i < out.len and out[i] != '\n') : (i += 1) out[i] = ' ';
        } else if (c == '"' or c == '\'') {
            i += 1;
            while (i < out.len and out[i] != c and out[i] != '\n') : (i += 1) {
                if (out[i] == '\\' and i + 1 < out.len and out[i + 1] != '\n') {
                    out[i] = ' ';
                    i += 1;
                }
                out[i] = ' ';
            }
            if (i < out.len) i += 1;
        } else {
            i += 1;
        }
    }
    return out;
}

/// Index of the `}` matching the first `{` at or after `from`, or null.
/// Expects a `blankCommentsAndStrings` view.
fn matchingBraceEnd(view: []const u8, from: usize) ?usize {
    const open = std.mem.indexOfScalarPos(u8, view, from, '{') orelse return null;
    var depth: usize = 0;
    var i = open;
    while (i < view.len) : (i += 1) {
        switch (view[i]) {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if (depth == 0) return i;
            },
            else => {},
        }
    }
    return null;
}

/// Blanks every top-level `test` declaration (`test "name" { ... }`,
/// `test name { ... }`, `test { ... }`) in a `blankCommentsAndStrings` view.
fn blankTestBlocks(view: []u8) void {
    var line_start: usize = 0;
    while (line_start < view.len) {
        const line_end = std.mem.indexOfScalarPos(u8, view, line_start, '\n') orelse view.len;
        const rest = view[line_start..];
        if (std.mem.startsWith(u8, rest, "test") and rest.len > 4 and !isIdentCont(rest[4])) {
            if (matchingBraceEnd(view, line_start)) |close| {
                @memset(view[line_start .. close + 1], ' ');
                line_start = close + 1;
                continue;
            }
        }
        line_start = line_end + 1;
    }
}

/// Number of top-level (depth-0) positional arguments in a call's `args`.
fn topLevelArgCount(args: []const u8) usize {
    if (std.mem.trim(u8, args, " \t\r\n").len == 0) return 0;
    var depth: i32 = 0;
    var count: usize = 1;
    var last_comma: ?usize = null;
    for (args, 0..) |c, i| switch (c) {
        '(', '[', '{' => depth += 1,
        ')', ']', '}' => depth -= 1,
        ',' => if (depth == 0) {
            count += 1;
            last_comma = i;
        },
        else => {},
    };
    // A trailing comma (`f(a, b,)`) does not introduce another argument.
    if (last_comma) |lc| {
        if (std.mem.trim(u8, args[lc + 1 ..], " \t\r\n").len == 0) count -= 1;
    }
    return count;
}

/// Whether `view[pos..]` starts a token, i.e. is not the tail of a longer
/// identifier or a member access (`foo.bar` when looking for `bar`).
fn isTokenStart(view: []const u8, pos: usize) bool {
    return pos == 0 or !(isIdentCont(view[pos - 1]) or view[pos - 1] == '.');
}

/// The first way `view` (a production-only `blankCommentsAndStrings` view)
/// reaches the stdlib `secureZero` instead of the canonical helper, or null.
fn firstRawSecureZeroBypass(view: []const u8) ?[]const u8 {
    // The direct spelling, called or bound as a function value; also
    // `@import("std").crypto.secureZero` (the import string is blanked).
    if (std.mem.indexOf(u8, view, "std.crypto.secureZero") != null) return "std.crypto.secureZero";
    if (std.mem.indexOf(u8, view, "\").crypto.secureZero") != null) return "@import(\"std\").crypto.secureZero";

    // Any local alias of the `std.crypto` namespace, then `<alias>.secureZero`.
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, view, search_from, "std.crypto")) |rel| {
        search_from = rel + 1;
        const after = rel + "std.crypto".len;
        if (after < view.len and isIdentCont(view[after])) continue;
        // `const NAME = std.crypto;` — walk back over `=` to the bound name.
        const stmt_end = std.mem.indexOfScalarPos(u8, view, after, ';') orelse continue;
        if (!isAllWhitespace(view[after..stmt_end])) continue;
        var j = rel;
        while (j > 0 and std.ascii.isWhitespace(view[j - 1])) j -= 1;
        if (j == 0 or view[j - 1] != '=') continue;
        j -= 1;
        while (j > 0 and std.ascii.isWhitespace(view[j - 1])) j -= 1;
        const name_end = j;
        while (j > 0 and isIdentCont(view[j - 1])) j -= 1;
        if (j == name_end) continue;
        const name = view[j..name_end];
        var alias_from: usize = 0;
        while (std.mem.indexOfPos(u8, view, alias_from, name)) |use| {
            alias_from = use + 1;
            if (!isTokenStart(view, use)) continue;
            const tail = view[use + name.len ..];
            if (std.mem.startsWith(u8, tail, ".secureZero") and
                (tail.len == ".secureZero".len or !isIdentCont(tail[".secureZero".len])))
                return "std.crypto alias .secureZero";
        }
    }

    // The stdlib's typed two-argument signature, `secureZero(T, buf)`, under
    // any qualifier: the canonical helpers only ever take one `[]u8`.
    search_from = 0;
    while (findNextCall(view, search_from, "secureZero")) |m| {
        search_from = m + 1;
        if (m > 0 and isIdentCont(view[m - 1])) continue;
        const args = extractCallArgs(view, m + "secureZero".len) orelse continue;
        if (topLevelArgCount(args) >= 2) return "secureZero(T, buf)";
    }
    return null;
}

const RawSecureZeroDirCheck = struct {
    dir: []const u8,
    excluded_paths: []const []const u8 = &.{},
};

const raw_secure_zero_rationale = "Production code must wipe secrets through crypto.secrets.secureZero/secureZeroAndFree (or the crypto.provider.secureZero wrapper), never std.crypto.secureZero: since #750 the canonical helper is a separate wide-volatile-store implementation, not a synonym, and the stdlib form lowers to a byte-at-a-time compiler_rt.memset on x86_64 (#784). Test blocks and *_tests.zig fixtures are exempt.";

const raw_secure_zero_checks_784 = [_]RawSecureZeroDirCheck{
    // secrets.zig owns the canonical implementation; the point-5
    // FileCheckWithExceptions above already confines any raw call there to
    // `secureZero`'s own body.
    .{ .dir = "src/crypto", .excluded_paths = &.{"src/crypto/secrets.zig"} },
    .{ .dir = "src/tls" },
    .{ .dir = "src/quic" },
    .{ .dir = "src/pki" },
    .{ .dir = "src/http" },
    .{ .dir = "src/http3" },
};

/// `firstRawSecureZeroBypass` over the production view of raw file `contents`.
fn rawSecureZeroViolation(allocator: std.mem.Allocator, contents: []const u8) !?[]const u8 {
    const view = try blankCommentsAndStrings(allocator, contents);
    defer allocator.free(view);
    blankTestBlocks(view);
    return firstRawSecureZeroBypass(view);
}

fn checkRawSecureZeroFile(allocator: std.mem.Allocator, root: compat.DirCompat, path: []const u8, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer allocator.free(contents);
    if (try rawSecureZeroViolation(allocator, contents)) |needle| {
        try violations.append(allocator, .{ .path = try allocator.dupe(u8, path), .needle = needle, .rationale = raw_secure_zero_rationale });
    }
}

fn checkRawSecureZeroDir(allocator: std.mem.Allocator, root: compat.DirCompat, check: RawSecureZeroDirCheck, dir_path: []const u8, violations: *std.ArrayList(Violation)) !void {
    var dir = root.openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    defer dir.close();
    var it = dir.iterate();
    while (try it.next(compat.io())) |entry| {
        const rel = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(rel);
        var excluded = false;
        for (check.excluded_paths) |excluded_path| {
            if (std.mem.eql(u8, rel, excluded_path)) {
                excluded = true;
                break;
            }
        }
        if (excluded) continue;
        switch (entry.kind) {
            .directory => try checkRawSecureZeroDir(allocator, root, check, rel, violations),
            .file => {
                if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
                // Test-only companion files (e.g. `key_schedule_tests.zig`)
                // are fixtures, not production wipes.
                if (std.mem.endsWith(u8, entry.name, "_tests.zig")) continue;
                try checkRawSecureZeroFile(allocator, root, rel, violations);
            },
            else => {},
        }
    }
}

/// A named declaration whose storage holds secret material: no plain
/// `@memset` may appear anywhere inside it (#751). Matched by `const NAME`
/// (a struct) or `fn NAME(` (a type-returning generic), brace-matched to the
/// end of the declaration.
const SecretStorageCheck = struct {
    path: []const u8,
    decl: []const u8,
    rationale: []const u8,
};

const secret_storage_checks_784 = [_]SecretStorageCheck{
    .{
        .path = "src/tls/encrypted_stream.zig",
        .decl = "ByteQueue",
        .rationale = "ByteQueue backs inbound_plaintext/inbound_handshake/inbound_carrier/outbound_ciphertext; every wipe of it (discard, clear, the compaction tail) must go through crypto.secrets.secureZero, because the wiped bytes are outside the queue's live slice and a plain @memset there is a dead store ReleaseFast may drop (#751). PlaintextProvenanceQueue holds bool bookkeeping and correctly keeps @memset.",
    },
    .{
        .path = "src/quic/tls_adapter.zig",
        .decl = "CryptoStream",
        .rationale = "CryptoStream buffers QUIC CRYPTO-frame handshake bytes; consumed and compacted extents must be wiped with crypto.secrets.secureZero, not a plain @memset the optimizer may elide (#750/#751).",
    },
    .{
        .path = "src/quic/tls_adapter.zig",
        .decl = "CryptoReassembler",
        .rationale = "CryptoReassembler.deinit must wipe its 265 KB of handshake state through crypto.secrets.secureZero; a plain @memset (including a `self.* = .{}` reset's) lowers to compiler_rt's byte loop on x86_64 and is elidable (#750).",
    },
    .{
        .path = "src/quic/tls_adapter.zig",
        .decl = "CryptoOutput",
        .rationale = "CryptoOutput holds outbound handshake bytes; drained and reset extents must be wiped with crypto.secrets.secureZero, not a plain @memset (#750).",
    },
};

/// The body of declaration `name` (`const name` or `fn name(`) in a
/// `blankCommentsAndStrings` view, from the name through its closing brace.
fn findDeclarationBody(view: []const u8, name: []const u8) ?[]const u8 {
    var search_from: usize = 0;
    while (std.mem.indexOfPos(u8, view, search_from, name)) |rel| {
        search_from = rel + 1;
        const after = rel + name.len;
        if (after < view.len and isIdentCont(view[after])) continue;
        const is_const = rel >= "const ".len and std.mem.eql(u8, view[rel - "const ".len .. rel], "const ");
        const is_fn = rel >= "fn ".len and std.mem.eql(u8, view[rel - "fn ".len .. rel], "fn ") and
            after < view.len and view[after] == '(';
        if (!is_const and !is_fn) continue;
        const close = matchingBraceEnd(view, after) orelse return null;
        return view[rel .. close + 1];
    }
    return null;
}

/// Why `decl` in `contents` violates the secret-storage rule, or null.
fn secretStorageViolation(allocator: std.mem.Allocator, contents: []const u8, decl: []const u8) !?[]const u8 {
    const view = try blankCommentsAndStrings(allocator, contents);
    defer allocator.free(view);
    const body = findDeclarationBody(view, decl) orelse return "<secret-bearing declaration missing>";
    if (findNextCall(body, 0, "@memset") != null) return "@memset on secret-bearing storage";
    return null;
}

fn checkSecretStorage(allocator: std.mem.Allocator, root: compat.DirCompat, check: SecretStorageCheck, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, check.path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            try violations.append(allocator, .{ .path = try allocator.dupe(u8, check.path), .needle = "<file missing>", .rationale = check.rationale });
            return;
        },
        else => return err,
    };
    defer allocator.free(contents);
    if (try secretStorageViolation(allocator, contents, check.decl)) |n| {
        try violations.append(allocator, .{ .path = try allocator.dupe(u8, check.path), .needle = n, .rationale = check.rationale });
    }
}

fn checkFileWithExceptions(allocator: std.mem.Allocator, root: compat.DirCompat, check: FileCheckWithExceptions, violations: *std.ArrayList(Violation)) !void {
    const contents = root.readFileAlloc(allocator, check.path, 16 * 1024 * 1024) catch |err| switch (err) {
        error.FileNotFound => {
            try violations.append(allocator, .{
                .path = try allocator.dupe(u8, check.path),
                .needle = "<file missing>",
                .rationale = check.rationale,
            });
            return;
        },
        else => return err,
    };
    defer allocator.free(contents);

    var scan_len = contents.len;
    if (check.production_only_marker) |marker| {
        if (std.mem.indexOf(u8, contents, marker)) |p| scan_len = p;
    }

    const scratch = try allocator.dupe(u8, contents[0..scan_len]);
    defer allocator.free(scratch);

    for (check.exempt_functions) |name| {
        if (extractFunctionBody(scratch, name)) |span| {
            const start = @intFromPtr(span.ptr) - @intFromPtr(scratch.ptr);
            @memset(scratch[start .. start + span.len], ' ');
        }
    }
    for (check.exempt_exact) |snippet| blank(scratch, snippet);

    if (firstForbidden(scratch, check.forbidden)) |needle| {
        try violations.append(allocator, .{ .path = try allocator.dupe(u8, check.path), .needle = needle, .rationale = check.rationale });
    }
}

fn checkDir(allocator: std.mem.Allocator, root: compat.DirCompat, check: DirCheck, dir_path: []const u8, violations: *std.ArrayList(Violation)) !void {
    var dir = root.openDir(dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound => {
            try violations.append(allocator, .{
                .path = try allocator.dupe(u8, dir_path),
                .needle = "<directory missing>",
                .rationale = check.rationale,
            });
            return;
        },
        else => return err,
    };
    defer dir.close();
    var it = dir.iterate();
    while (try it.next(compat.io())) |entry| {
        const rel = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(rel);
        var excluded = false;
        for (check.excluded_paths) |excluded_path| {
            if (std.mem.eql(u8, rel, excluded_path)) {
                excluded = true;
                break;
            }
        }
        if (excluded) continue;
        switch (entry.kind) {
            .directory => try checkDir(allocator, root, check, rel, violations),
            .file => {
                if (!std.mem.endsWith(u8, entry.name, ".zig")) continue;
                try checkFile(allocator, root, rel, check.forbidden, check.rationale, false, violations);
            },
            else => {},
        }
    }
}

fn runAudit(allocator: std.mem.Allocator, root: compat.DirCompat) !std.ArrayList(Violation) {
    var violations: std.ArrayList(Violation) = .empty;
    errdefer violations.deinit(allocator);
    for (file_checks) |check| {
        try checkFile(allocator, root, check.path, check.forbidden, check.rationale, true, &violations);
    }
    for (file_checks_with_exceptions) |check| {
        try checkFileWithExceptions(allocator, root, check, &violations);
    }
    for (dir_checks) |check| {
        try checkDir(allocator, root, check, check.dir, &violations);
    }
    for (file_checks_375) |check| {
        try checkFile(allocator, root, check.path, check.forbidden, check.rationale, true, &violations);
    }
    for (file_checks_with_exceptions_375) |check| {
        try checkFileWithExceptions(allocator, root, check, &violations);
    }
    for (dir_checks_375) |check| {
        try checkDir(allocator, root, check, check.dir, &violations);
    }
    for (zero_then_free_checks_375) |check| {
        try checkZeroThenFreeDir(allocator, root, check, check.dir, &violations);
    }
    for (raw_secure_zero_checks_784) |check| {
        try checkRawSecureZeroDir(allocator, root, check, check.dir, &violations);
    }
    for (secret_storage_checks_784) |check| {
        try checkSecretStorage(allocator, root, check, &violations);
    }
    try checkBoundedSecretFile(
        allocator,
        root,
        "src/crypto/secrets.zig",
        "BoundedSecret.deinit must free self.bytes only through secureZeroAndFree — #375's original finding, reachable again via a local rename of self.bytes even though the zeroing itself (in clearAll, a sibling method) stays untouched.",
        &violations,
    );
    return violations;
}

pub fn main(init: std.process.Init.Minimal) !void {
    const allocator = std.heap.page_allocator;

    var args_iter = init.args.iterate();
    _ = args_iter.next();
    const root_path = args_iter.next() orelse ".";

    var root = compat.cwd().openDir(root_path, .{}) catch |err| {
        var stderr_buf: [512]u8 = undefined;
        var stderr = compat.stderrWriter(&stderr_buf);
        try stderr.print("audit-crypto-boundary: cannot open root '{s}': {s}\n", .{ root_path, @errorName(err) });
        std.process.exit(2);
    };
    defer root.close();

    var violations = try runAudit(allocator, root);
    defer violations.deinit(allocator);

    if (violations.items.len == 0) return;

    var stderr_buf: [512]u8 = undefined;
    var stderr = compat.stderrWriter(&stderr_buf);
    for (violations.items) |v| {
        try stderr.print("disallowed pattern in {s}: \"{s}\"\nrationale: {s}\n\n", .{ v.path, v.needle, v.rationale });
    }
    std.process.exit(1);
}

// ---------------------------------------------------------------------------
// Fixture tests: each class of bypass this audit exists to catch must
// actually make it fail (#490 second-pass review).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "detects a direct AEAD call" {
    try testing.expectEqualStrings("std.crypto.aead.", firstForbidden("const x = std.crypto.aead.aes_gcm.Aes128Gcm;", &keyed_crypto_core).?);
}

test "detects a direct HKDF expand-label call" {
    try testing.expectEqualStrings("hkdfExpandLabel(", firstForbidden("const k = tls.hkdfExpandLabel(Hkdf, secret, \"x\", \"\", 32);", &keyed_crypto_core).?);
}

test "detects a direct ECDH/signature primitive" {
    try testing.expectEqualStrings("X25519.", firstForbidden("var kp = X25519.KeyPair.generateDeterministic(seed);", &keyed_crypto_core).?);
    try testing.expectEqualStrings("Ed25519.", firstForbidden("Ed25519.verify(sig, msg, key) catch return error.Bad;", &keyed_crypto_core).?);
}

test "detects the exact AES header-protection block-cipher form" {
    try testing.expectEqualStrings("Aes128.initEnc(", firstForbidden("const aes = Aes128.initEnc(self.hp);", &aes_block_cipher).?);
    try testing.expectEqualStrings("crypto.core.aes.", firstForbidden("const Aes128 = crypto.core.aes.Aes128;", &aes_block_cipher).?);
}

test "detects each legacy wrapper call name, dot-called or unqualified, without matching its WithProvider sibling" {
    try testing.expectEqualStrings("sealPayload(", firstForbidden("const sealed = keys.sealPayload(pn, header, plain, out);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("openPayload(", firstForbidden("const p = keys.openPayload(pn, header, ct, out);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("applyHeaderProtection(", firstForbidden("keys.applyHeaderProtection(&out[0], pn_field, sample);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("removeHeaderProtection(", firstForbidden("const r = keys.removeHeaderProtection(&b, &pn, sample);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("headerProtectionMask(", firstForbidden("const m = keys.headerProtectionMask(sample);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("deriveAes128GcmKeys(", firstForbidden("return deriveAes128GcmKeys(secret);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("deriveInitialSecretsV1(", firstForbidden("const s = try deriveInitialSecretsV1(dcid);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("deriveNextGenerationSecret(", firstForbidden("return deriveNextGenerationSecret(secret);", &legacy_wrapper_calls).?);

    // The unqualified same-container form (#490 fifth-pass review): a
    // *WithProvider method can call its legacy sibling without a receiver.
    try testing.expectEqualStrings("sealPayload(", firstForbidden("return sealPayload(self, pn, header, plain, out);", &legacy_wrapper_calls).?);
    try testing.expectEqualStrings("headerProtectionMask(", firstForbidden("const mask = headerProtectionMask(self, sample);", &legacy_wrapper_calls).?);

    // The WithProvider siblings must NOT trip the same check — that would
    // make the audit reject the migration this PR performed.
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden("const sealed = keys.sealPayloadWithProvider(cp, pn, header, plain, out);", &legacy_wrapper_calls));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden("keys.applyHeaderProtectionWithProvider(cp, &out[0], pn_field, sample);", &legacy_wrapper_calls));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden("return deriveAes128GcmKeysWithProvider(cp, secret);", &legacy_wrapper_calls));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden("return sealPayloadWithProvider(self, provider, pn, header, plain, out);", &legacy_wrapper_calls));
}

test "tls_adapter_zig_forbidden allows provider.hkdfExpandLabel but forbids the legacy tls.hkdfExpandLabel" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "provider.hkdfExpandLabel(.sha256, &secret, \"quic key\", \"\", &keys.key) catch return error.ProviderUnsupported;",
        &tls_adapter_zig_forbidden,
    ));
    try testing.expectEqualStrings("tls.hkdfExpandLabel(", firstForbidden(
        "const client_secret = tls.hkdfExpandLabel(HkdfSha256, initial_secret, \"client in\", \"\", traffic_secret_len);",
        &tls_adapter_zig_forbidden,
    ).?);
}

test "key_schedule_zig_forbidden allows provider.hkdfExpandLabel but forbids the legacy crypto.tls.hkdfExpandLabel" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "try crypto_provider.hkdfExpandLabel(.sha256, &secret, \"c hs traffic\", &hash, &out);",
        &key_schedule_zig_forbidden,
    ));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "try self.provider.hkdfExpandLabel(.sha256, &self.master_secret, \"c ap traffic\", &hash, &out);",
        &key_schedule_zig_forbidden,
    ));
    try testing.expectEqualStrings("crypto.tls.hkdfExpandLabel(", firstForbidden(
        "break :blk crypto.tls.hkdfExpandLabel(HkdfSha256, early_secret, \"derived\", &empty, hash_len);",
        &key_schedule_zig_forbidden,
    ).?);
}

test "clean protocol-module content produces no violation" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "keys.applyHeaderProtectionWithProvider(self.adapter.provider, &out[0], pn_field, sample) catch unreachable;",
        &full_forbidden,
    ));
}

// #554 unit-level fixtures: fast, isolated proof for each new forbidden set
// before the slower end-to-end fixture-tree test exercises them wired
// through the real directory/file checks.

test "detects a raw constant-time-comparison call, qualified either way a call site might spell it" {
    try testing.expectEqualStrings("timing_safe", firstForbidden(
        "if (!std.crypto.timing_safe.eql([32]u8, expected, candidate)) return error.Bad;",
        &timing_safe_forbidden,
    ).?);
    try testing.expectEqualStrings("timing_safe", firstForbidden(
        "const ok = crypto.timing_safe.eql([16]u8, tag, received);",
        &timing_safe_forbidden,
    ).?);
}

test "detects a namespace-capture alias of timing_safe, not just direct member access" {
    // #554 review (first pass): `const timing_safe = std.crypto.timing_safe;`
    // followed by a call off the captured alias defeated the original
    // dot-suffixed needle entirely — the declaration ends in `;`, and the
    // call site only ever spells the bare `timing_safe.eql(`.
    try testing.expectEqualStrings("timing_safe", firstForbidden(
        "const timing_safe = std.crypto.timing_safe;\nreturn timing_safe.eql([32]u8, expected, candidate);",
        &timing_safe_forbidden,
    ).?);
}

test "detects an alias one level up the qualifier, not just an alias of timing_safe itself" {
    // #554 review (second pass): aliasing `std.crypto` itself under a name
    // that does not end in `crypto` defeats any qualified needle, no matter
    // how many dotted-prefix spellings it lists — only a qualifier-
    // independent match on the `timing_safe` token itself is complete.
    try testing.expectEqualStrings("timing_safe", firstForbidden(
        "const c = std.crypto;\nreturn c.timing_safe.eql([32]u8, expected, candidate);",
        &timing_safe_forbidden,
    ).?);
}

test "canonical constantTimeEqual routing does not trip the raw timing_safe guard" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "if (!secrets.constantTimeEqual(&expected, candidate)) return error.Bad;",
        &timing_safe_forbidden,
    ));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "if (!provider.constantTimeEqual(&expected, candidate)) return error.Bad;",
        &timing_safe_forbidden,
    ));
}

test "detects the raw secureZero spelling, aliased either way a call site might spell it" {
    try testing.expectEqualStrings("std.crypto.secureZero(", firstForbidden(
        "std.crypto.secureZero(u8, buf);",
        &zeroization_forbidden,
    ).?);
    try testing.expectEqualStrings("std_crypto.secureZero(", firstForbidden(
        "std_crypto.secureZero(u8, buf);",
        &zeroization_forbidden,
    ).?);
}

test "canonical secureZero/secureZeroAndFree routing does not trip the raw-spelling guard" {
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "secrets.secureZero(buf);",
        &zeroization_forbidden,
    ));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "crypto.secrets.secureZeroAndFree(allocator, buf);",
        &zeroization_forbidden,
    ));
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "provider.secureZero(memory);",
        &zeroization_forbidden,
    ));
}

test "BoundedSecret.deinit reverting to clearAll + plain allocator.free trips the secrets.zig guard" {
    const forbidden = zeroization_forbidden ++ [_][]const u8{".free(self.bytes)"};
    try testing.expectEqualStrings(".free(self.bytes)", firstForbidden(
        "self.clearAll(); const allocator = self.allocator orelse return; allocator.free(self.bytes);",
        &forbidden,
    ).?);
    try testing.expectEqual(@as(?[]const u8, null), firstForbidden(
        "secureZeroAndFree(allocator, self.bytes);",
        &forbidden,
    ));
}

// #554 review (second pass): BoundedSecret.deinit's exact historical
// regression, reintroduced via a local rename, is reachable across sibling
// methods (`clearAll` zeroes, `deinit` frees) that `firstZeroThenPlainFree`'s
// forward-only single-function scan cannot connect — `deinit` is declared
// *before* `clearAll` in the real file, so a forward-only scan starting from
// `clearAll`'s zero call never reaches back into `deinit`.

test "boundedSecretDeinitCallsCanonicalFree rejects the exact historical regression via a local rename" {
    const struct_body =
        \\const BoundedSecret = struct {
        \\    allocator: ?std.mem.Allocator = null,
        \\    bytes: []u8 = &.{},
        \\    len: usize = 0,
        \\
        \\    pub fn deinit(self: *BoundedSecret) void {
        \\        const bytes = self.bytes;
        \\        self.clearAll();
        \\        const allocator = self.allocator orelse return;
        \\        allocator.free(bytes);
        \\    }
        \\
        \\    fn clearAll(self: *BoundedSecret) void {
        \\        secureZero(self.bytes);
        \\        self.len = 0;
        \\    }
        \\};
    ;
    try testing.expect(!boundedSecretDeinitCallsCanonicalFree(struct_body));
}

test "boundedSecretDeinitCallsCanonicalFree accepts the correct secureZeroAndFree routing" {
    const struct_body =
        \\const BoundedSecret = struct {
        \\    allocator: ?std.mem.Allocator = null,
        \\    bytes: []u8 = &.{},
        \\    len: usize = 0,
        \\
        \\    pub fn deinit(self: *BoundedSecret) void {
        \\        self.len = 0;
        \\        const allocator = self.allocator orelse return;
        \\        secureZeroAndFree(allocator, self.bytes);
        \\        self.allocator = null;
        \\        self.bytes = self.bytes[0..0];
        \\    }
        \\
        \\    fn clearAll(self: *BoundedSecret) void {
        \\        secureZero(self.bytes);
        \\        self.len = 0;
        \\    }
        \\};
    ;
    try testing.expect(boundedSecretDeinitCallsCanonicalFree(struct_body));
}

test "boundedSecretDeinitCallsCanonicalFree rejects a direct rawFree bypassing secureZeroAndFree entirely" {
    const struct_body =
        \\const BoundedSecret = struct {
        \\    allocator: ?std.mem.Allocator = null,
        \\    bytes: []u8 = &.{},
        \\    len: usize = 0,
        \\
        \\    pub fn deinit(self: *BoundedSecret) void {
        \\        self.len = 0;
        \\        const allocator = self.allocator orelse return;
        \\        allocator.rawFree(
        \\            self.bytes,
        \\            .fromByteUnits(@alignOf(u8)),
        \\            @returnAddress(),
        \\        );
        \\    }
        \\
        \\    fn clearAll(self: *BoundedSecret) void {
        \\        secureZero(self.bytes);
        \\        self.len = 0;
        \\    }
        \\};
    ;
    try testing.expect(!boundedSecretDeinitCallsCanonicalFree(struct_body));
}

test "extractContainerBody isolates one struct from a sibling declared right after it" {
    const src =
        \\const Other = struct {
        \\    fn deinit(self: *Other) void {
        \\        allocator.free(self.junk);
        \\    }
        \\};
        \\
        \\pub const BoundedSecret = struct {
        \\    bytes: []u8 = &.{},
        \\
        \\    pub fn deinit(self: *BoundedSecret) void {
        \\        secureZeroAndFree(self.allocator, self.bytes);
        \\    }
        \\};
    ;
    const body = extractContainerBody(src, "BoundedSecret").?;
    try testing.expect(std.mem.indexOf(u8, body, "junk") == null);
    try testing.expect(std.mem.indexOf(u8, body, "secureZeroAndFree") != null);
}

test "raw std.crypto.timing_safe in src/crypto/rsa.zig's shape trips the guard once src/crypto is in scope" {
    // #554 review (second pass): the original guard only scanned
    // src/tls/src/quic/src/pki and missed src/crypto/rsa.zig's own
    // EMSA-PSS final authentication comparison, which #375's audit matrix
    // explicitly covers. This is a unit-level proof that the shape trips
    // timing_safe_forbidden at all (the end-to-end test below proves it's
    // actually wired into a src/crypto directory scan).
    try testing.expectEqualStrings("timing_safe", firstForbidden(
        "if (!crypto.timing_safe.eql([h_len]u8, expected, h_array)) return error.InvalidInput;",
        &timing_safe_forbidden,
    ).?);
}

// #554 review (second pass): the general zero-then-plain-free scanner.
// The prior version of this guard protected exactly three files by exact
// historical variable name (`self.key_storage`, `key_storage`, `bytes`,
// `out`), which a new file or a harmless local rename defeated entirely.
// These prove the general, buffer-identity-tracking replacement instead.

test "firstZeroThenPlainFree detects the canonical BoundedSecret.deinit regression" {
    try testing.expectEqualStrings("self.bytes", firstZeroThenPlainFree(
        "pub fn deinit(self: *BoundedSecret) void {\n    secureZero(self.bytes);\n    const allocator = self.allocator orelse return;\n    allocator.free(self.bytes);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree follows a local rename to the same buffer" {
    // The reviewer's exact bypass example: a plain local alias defeats a
    // check keyed on the original field name, but not one that extracts the
    // buffer expression from the zero call itself.
    try testing.expectEqualStrings("storage", firstZeroThenPlainFree(
        "fn release(self: *Thing) void {\n    const storage = self.key_storage;\n    crypto.secrets.secureZero(std.mem.sliceAsBytes(storage));\n    self.allocator.free(storage);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree catches the ArrayList zero-then-.deinit shape under any variable name" {
    try testing.expectEqualStrings("out", firstZeroThenPlainFree(
        "fn f(allocator: std.mem.Allocator) void {\n    var out = std.array_list.Managed(u8).init(allocator);\n    defer {\n        secrets.secureZero(out.items);\n        out.deinit();\n    }\n}\n",
    ).?);
}

test "firstZeroThenPlainFree now catches a direct rawFree bypass (#554 review, fourth pass)" {
    // This is textually identical to `secureZeroAndFreeAligned`'s own body
    // in `src/crypto/secrets.zig` — taken in isolation, a function-level
    // scan cannot distinguish the canonical helper's own implementation
    // from a copy-pasted bypass of it elsewhere. That is exactly why
    // `zero_then_free_checks_375` excludes `src/crypto/secrets.zig` by
    // *path* at the directory-scan level (see that check's own
    // `excluded_paths`) rather than teaching this function to recognize its
    // own canonical shape: `rawFree` is part of #375's inventory and must
    // be flagged everywhere else.
    try testing.expectEqualStrings("bytes", firstZeroThenPlainFree(
        "pub fn secureZeroAndFreeAligned(comptime T: type, allocator: std.mem.Allocator, buffer: []T) void {\n    const bytes = std.mem.sliceAsBytes(buffer);\n    secureZero(bytes);\n    allocator.rawFree(bytes, .fromByteUnits(@alignOf(T)), @returnAddress());\n}\n",
    ).?);
}

test "firstZeroThenPlainFree catches a multiline/trailing-comma allocator.free bypass (#554 review, fourth pass)" {
    try testing.expectEqualStrings("secret_buf", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    crypto.secrets.secureZero(secret_buf);\n    allocator.free(\n        secret_buf,\n    );\n}\n",
    ).?);
}

test "firstZeroThenPlainFree does not flag a zero call whose buffer is never freed at all" {
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "fn f(out: []u8) void {\n    defer crypto.secureZero(u8, out);\n    doSomething(out);\n}\n",
    ));
}

test "firstZeroThenPlainFree does not flag freeing an unrelated buffer in the same function" {
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "pub fn deinit(self: *Thing) void {\n    std.crypto.secureZero(u8, &self.local_transport_parameters);\n    self.cid_binding.deinit();\n}\n",
    ));
}

test "firstZeroThenPlainFree correctly routed through secureZeroAndFree trips nothing" {
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "pub fn deinit(self: *OwnedSnapshot) void {\n    crypto.secrets.secureZeroAndFreeAligned(KeyStorage, self.allocator, self.key_storage);\n    self.allocator.free(self.configs);\n}\n",
    ));
}

// #554 review (second pass): the general scanner's own bypasses. Matching
// literal `secureZero(` calls and exact buffer-expression text is defeated
// by aliasing either the *callee* (a local binding to the zero function
// itself) or the *buffer* (a local rename between the zero call and the
// free) one hop away. Both need dedicated resolution, not just richer token
// extraction.

test "firstZeroThenPlainFree follows a callee alias of secureZero itself" {
    // `const wipe = crypto.secrets.secureZero;` then calling `wipe(...)`
    // never contains the literal substring `secureZero(` at all.
    try testing.expectEqualStrings("secret_buf", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    const wipe = crypto.secrets.secureZero;\n    wipe(secret_buf);\n    allocator.free(secret_buf);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree follows a rename of the zeroed buffer between the zero call and the free" {
    try testing.expectEqualStrings("doomed", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    crypto.secrets.secureZero(secret_buf);\n    const doomed = secret_buf;\n    allocator.free(doomed);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree does not misfire on an unrelated const binding sharing no expression with the zeroed buffer" {
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8, other: []u8) void {\n    crypto.secrets.secureZero(secret_buf);\n    const label = \"unrelated\";\n    _ = label;\n    allocator.free(other);\n}\n",
    ));
}

// #554 review (third pass): three more bypasses of the general scanner.

test "firstZeroThenPlainFree sees a free whose own defer is written before the zero call's defer" {
    // defer runs LIFO: the free's defer (declared first) actually executes
    // *after* the zero's defer (declared second) at runtime, so this is the
    // exact prohibited zero-then-plain-free sequence — but a forward-only
    // scan starting from the zero call would never see the earlier defer.
    try testing.expectEqualStrings("secret_buf", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    defer allocator.free(secret_buf);\n    defer crypto.secrets.secureZero(secret_buf);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree recognizes a manual @memset(buf, 0) clear, not just the secureZero wrapper" {
    try testing.expectEqualStrings("secret_buf", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    @memset(secret_buf, 0);\n    allocator.free(secret_buf);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree ignores @memset with a non-zero fill value" {
    // @memset(buf, 0xAA) is an ordinary poison/pattern fill, not a
    // zero-clear — #375's own non-goals warn against treating every
    // @memset as security-relevant.
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    @memset(secret_buf, 0xAA);\n    allocator.free(secret_buf);\n}\n",
    ));
}

test "firstZeroThenPlainFree catches a zero-then-free inside a test block same as production (#554 review, fourth pass)" {
    // An earlier version of this scanner exempted every `@memset(_, 0)`
    // inside a `test` block wholesale, reasoning that ordinary
    // zero-filled fixture data is indistinguishable from a real wipe. The
    // review correctly pointed out that reasoning cuts both ways: a
    // genuine ad hoc secret-zero-then-free bug written inside a test is
    // exactly as real a regression as one in production code, and a
    // blanket "it's a test" escape hatch is not a reviewed, fail-closed
    // exception. There is no blanket test exemption anymore — the bare
    // `secureZero` trigger never had one either (see the next test).
    try testing.expectEqualStrings("buf", firstZeroThenPlainFree(
        "test \"secret fixture cleanup\" {\n    const buf = try testing.allocator.alloc(u8, 32);\n    defer testing.allocator.free(buf);\n    @memset(buf, 0);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree still catches a real secureZero-then-free bug inside a test block" {
    try testing.expectEqualStrings("buf", firstZeroThenPlainFree(
        "test \"some fixture behavior\" {\n    const buf = try testing.allocator.alloc(u8, 16);\n    defer testing.allocator.free(buf);\n    crypto.secrets.secureZero(buf);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree does not misfire on a longer identifier that merely ends with the same suffix" {
    // `self.selected_client_psk.deinit()` must not match a candidate key
    // `psk` just because it ends in "psk" immediately followed by
    // `.deinit(` — #554 review, third pass, found this once the scan
    // window widened to the whole function.
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "fn f(self: *Thing) void {\n    crypto.secrets.secureZero(std.mem.asBytes(&self.psk));\n    self.selected_client_psk.deinit();\n}\n",
    ));
}

test "resolveBufferRenames follows the second alias when a harmless first alias precedes it" {
    var out: [max_aliases][]const u8 = undefined;
    const count = resolveBufferRenames(
        "const retained_view = secret_buf;\n_ = retained_view;\nconst doomed = secret_buf;\nallocator.free(doomed);\n",
        "secret_buf",
        &out,
    );
    try testing.expectEqual(@as(usize, 2), count);
    try testing.expectEqualStrings("retained_view", out[0]);
    try testing.expectEqualStrings("doomed", out[1]);
}

test "firstZeroThenPlainFree follows a second alias past a harmless first one" {
    try testing.expectEqualStrings("doomed", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    crypto.secrets.secureZero(secret_buf);\n    const retained_view = secret_buf;\n    _ = retained_view;\n    const doomed = secret_buf;\n    allocator.free(doomed);\n}\n",
    ).?);
}

// #554 review (fourth pass): a manual zero-clear loop, an alias-scope false
// positive, and the zero-init-vs-zero-then-destroy distinction.

test "firstZeroThenPlainFree recognizes a manual zero-clear loop, not just @memset/secureZero" {
    try testing.expectEqualStrings("secret_buf", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    for (secret_buf) |*byte| byte.* = 0;\n    allocator.free(secret_buf);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree recognizes a braced manual zero-clear loop with an index capture" {
    try testing.expectEqualStrings("secret_buf", firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    for (secret_buf, 0..) |*byte, _| {\n        byte.* = 0;\n    }\n    allocator.free(secret_buf);\n}\n",
    ).?);
}

test "firstZeroThenPlainFree does not misfire on an ordinary mutating loop that never zeroes its element" {
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "fn release(allocator: std.mem.Allocator, entries: []Entry) void {\n    for (entries) |*entry| entry.active = false;\n    allocator.free(entries);\n}\n",
    ));
}

test "firstZeroThenPlainFree does not misattribute an unrelated same-named function to a local secureZero alias" {
    // `scrub` is bound as a local alias of `secureZero` only inside
    // `actualWipe`; the unrelated top-level `scrub` in `transform` has
    // nothing to do with zeroing. A file-wide alias-callee scan would
    // wrongly treat `release`'s call to the *unrelated* top-level `scrub`
    // as if it were the local alias, and flag `release`'s ordinary free —
    // #554 review, fourth pass.
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "fn actualWipe(buf: []u8) void {\n    const scrub = crypto.secrets.secureZero;\n    scrub(buf);\n}\n\nfn scrub(buf: []u8) void {\n    transform(buf);\n}\n\nfn release(allocator: std.mem.Allocator, buf: []u8) void {\n    scrub(buf);\n    allocator.free(buf);\n}\n",
    ));
}

test "firstZeroThenPlainFree does not flag a zero-initialized buffer returned to the caller" {
    // Fallible initialization — allocate, install an `errdefer` free as a
    // failure-path safety net, zero-initialize, then hand the buffer back
    // to the caller — is not the #375 zero-then-destroy defect: the
    // buffer's lifetime continues in the caller, it is not being wiped
    // before release. #554 review, fourth pass.
    try testing.expectEqual(@as(?[]const u8, null), firstZeroThenPlainFree(
        "fn allocateFrame(allocator: std.mem.Allocator, len: usize) ![]u8 {\n    const frame = try allocator.alloc(u8, len);\n    errdefer allocator.free(frame);\n    @memset(frame, 0);\n    return frame;\n}\n",
    ));
}

test "extractFunctionBody isolates a struct method from its WithProvider sibling and from the next method" {
    const src =
        \\pub const PacketProtectionKeys = struct {
        \\    pub fn sealPayload(self: *const PacketProtectionKeys, pn: u64) ![]u8 {
        \\        return legacy(pn);
        \\    }
        \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, pn: u64) ![]u8 {
        \\        return provider.aeadSeal(pn);
        \\    }
        \\};
    ;
    const body = extractFunctionBody(src, "sealPayload").?;
    try testing.expect(std.mem.indexOf(u8, body, "legacy(pn)") != null);
    try testing.expect(std.mem.indexOf(u8, body, "aeadSeal") == null);
}

test "extractFunctionBody isolates a top-level free function from the struct declaration that follows it" {
    const src =
        \\pub fn deriveNextGenerationSecret(secret: [32]u8) [32]u8 {
        \\    return tls.hkdfExpandLabel(HkdfSha256, secret, "quic ku", "", 32);
        \\}
        \\pub fn deriveNextGenerationSecretWithProvider(provider: CryptoProvider, secret: [32]u8) ![32]u8 {
        \\    provider.hkdfExpandLabel(.sha256, &secret, "quic ku", "", &out) catch return error.ProviderUnsupported;
        \\    return out;
        \\}
        \\
        \\pub const QuicTlsAdapter = struct {
        \\    provider: CryptoProvider,
        \\
        \\    fn validateProvider(provider: CryptoProvider) !void {}
        \\};
    ;
    const legacy_body = extractFunctionBody(src, "deriveNextGenerationSecret").?;
    try testing.expect(std.mem.indexOf(u8, legacy_body, "tls.hkdfExpandLabel(") != null);
    try testing.expect(std.mem.indexOf(u8, legacy_body, "WithProvider") == null);

    const provider_body = extractFunctionBody(src, "deriveNextGenerationSecretWithProvider").?;
    try testing.expect(std.mem.indexOf(u8, provider_body, "provider.hkdfExpandLabel(") != null);
    try testing.expect(std.mem.indexOf(u8, provider_body, "QuicTlsAdapter") == null);
    try testing.expect(std.mem.indexOf(u8, provider_body, "validateProvider") == null);
}

/// Minimal but realistic stand-in for `src/quic/tls_adapter.zig`: the three
/// exempt type aliases, one legacy/`*WithProvider` method pair
/// (`PacketProtectionKeys.sealPayload` / `.sealPayloadWithProvider`, called
/// by dot-syntax like the real file rather than as free functions), a
/// canonical `QuicTlsAdapter.sealPacketPayload` calling the provider
/// sibling, and a `const testing = std.testing;` boundary followed by a
/// differential-vector-style test using the legacy call directly. Exercises
/// the exact parsing path the real file needs: an inline `error{...}` group
/// in a return type before the real body opens, a legacy method immediately
/// followed by its `*WithProvider` sibling, and content after the
/// production-only marker that must NOT be scanned.
const clean_tls_adapter_fixture =
    \\const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    \\const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    \\const Aes128 = crypto.core.aes.Aes128;
    \\
    \\pub const PacketProtectionKeys = struct {
    \\    pub fn sealPayload(self: *const PacketProtectionKeys, secret: [32]u8) [16]u8 {
    \\        const mask = Aes128.initEnc(secret);
    \\        return Aes128Gcm.encrypt(secret);
    \\    }
    \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, secret: [32]u8) ![16]u8 {
    \\        return provider.aeadSeal(secret);
    \\    }
    \\};
    \\
    \\pub const QuicTlsAdapter = struct {
    \\    provider: CryptoProvider,
    \\
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, keys: PacketProtectionKeys) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayloadWithProvider(self.provider, secret);
    \\    }
    \\};
    \\
    \\pub const CryptoStream = struct {
    \\    buffer: [64]u8 = undefined,
    \\    pub fn discardContiguous(self: *CryptoStream, n: usize) void {
    \\        crypto_secrets.secureZero(self.buffer[0..n]);
    \\    }
    \\};
    \\
    \\pub const CryptoReassembler = struct {
    \\    streams: [4]CryptoStream = .{ .{}, .{}, .{}, .{} },
    \\    pub fn deinit(self: *CryptoReassembler) void {
    \\        // Not a plain `@memset(...)`: see #750.
    \\        crypto_secrets.secureZero(std.mem.asBytes(self));
    \\    }
    \\};
    \\
    \\pub const CryptoOutput = struct {
    \\    buffer: [64]u8 = undefined,
    \\    pub fn deinit(self: *CryptoOutput) void {
    \\        crypto_secrets.secureZero(std.mem.asBytes(self));
    \\    }
    \\};
    \\
    \\const testing = std.testing;
    \\
    \\test "differential vector" {
    \\    var keys: PacketProtectionKeys = undefined;
    \\    try testing.expectEqualSlices(u8, &keys.sealPayload(secret), &(try keys.sealPayloadWithProvider(provider, secret)));
    \\}
    \\
;

/// `clean_tls_adapter_fixture` with `QuicTlsAdapter.sealPacketPayload`
/// reverted to the legacy `keys.sealPayload(...)` call — the exact
/// regression #490's third-pass review named.
const canonical_method_regression_fixture =
    \\const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    \\const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    \\const Aes128 = crypto.core.aes.Aes128;
    \\
    \\pub const PacketProtectionKeys = struct {
    \\    pub fn sealPayload(self: *const PacketProtectionKeys, secret: [32]u8) [16]u8 {
    \\        const mask = Aes128.initEnc(secret);
    \\        return Aes128Gcm.encrypt(secret);
    \\    }
    \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, secret: [32]u8) ![16]u8 {
    \\        return provider.aeadSeal(secret);
    \\    }
    \\};
    \\
    \\pub const QuicTlsAdapter = struct {
    \\    provider: CryptoProvider,
    \\
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, keys: PacketProtectionKeys) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayload(secret);
    \\    }
    \\};
    \\
    \\const testing = std.testing;
    \\
    \\test "differential vector" {
    \\    var keys: PacketProtectionKeys = undefined;
    \\    try testing.expectEqualSlices(u8, &keys.sealPayload(secret), &(try keys.sealPayloadWithProvider(provider, secret)));
    \\}
    \\
;

/// `clean_tls_adapter_fixture` with `sealPayloadWithProvider` reverted to
/// delegate to its own legacy concrete sibling instead of the provider — the
/// mirror regression #490's fourth-pass review named.
const with_provider_delegates_to_legacy_fixture =
    \\const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    \\const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
    \\const Aes128 = crypto.core.aes.Aes128;
    \\
    \\pub const PacketProtectionKeys = struct {
    \\    pub fn sealPayload(self: *const PacketProtectionKeys, secret: [32]u8) [16]u8 {
    \\        const mask = Aes128.initEnc(secret);
    \\        return Aes128Gcm.encrypt(secret);
    \\    }
    \\    pub fn sealPayloadWithProvider(self: *const PacketProtectionKeys, provider: CryptoProvider, secret: [32]u8) ![16]u8 {
    \\        return self.sealPayload(secret);
    \\    }
    \\};
    \\
    \\pub const QuicTlsAdapter = struct {
    \\    provider: CryptoProvider,
    \\
    \\    pub fn sealPacketPayload(self: *QuicTlsAdapter, keys: PacketProtectionKeys) error{ProviderUnsupported}![]u8 {
    \\        return keys.sealPayloadWithProvider(self.provider, secret);
    \\    }
    \\};
    \\
    \\const testing = std.testing;
    \\
    \\test "differential vector" {
    \\    var keys: PacketProtectionKeys = undefined;
    \\    try testing.expectEqualSlices(u8, &keys.sealPayload(secret), &(try keys.sealPayloadWithProvider(provider, secret)));
    \\}
    \\
;

/// Minimal stand-in for `src/crypto/secrets.zig` (#554): the one legitimate
/// raw `std.crypto.secureZero` call — inside `secureZero` itself, the
/// function every other container/method must call instead — and
/// `BoundedSecret.deinit` wired the fixed way (`secureZeroAndFree`, not
/// `clearAll()` followed by a plain `allocator.free`).
const clean_secrets_zig_fixture =
    \\pub fn secureZero(buffer: []u8) void {
    \\    std.crypto.secureZero(u8, buffer);
    \\}
    \\
    \\pub fn secureZeroAndFree(allocator: std.mem.Allocator, buffer: []u8) void {
    \\    secureZero(buffer);
    \\    allocator.rawFree(buffer, .fromByteUnits(@alignOf(u8)), @returnAddress());
    \\}
    \\
    \\pub const BoundedSecret = struct {
    \\    allocator: ?std.mem.Allocator = null,
    \\    bytes: []u8 = &.{},
    \\    len: usize = 0,
    \\
    \\    fn clearAll(self: *BoundedSecret) void {
    \\        secureZero(self.bytes);
    \\        self.len = 0;
    \\    }
    \\
    \\    pub fn deinit(self: *BoundedSecret) void {
    \\        self.len = 0;
    \\        const allocator = self.allocator orelse return;
    \\        secureZeroAndFree(allocator, self.bytes);
    \\        self.allocator = null;
    \\        self.bytes = self.bytes[0..0];
    \\    }
    \\};
    \\
;

/// `clean_secrets_zig_fixture` with `BoundedSecret.deinit` reverted to the
/// exact historical shape: zero via the already-correct `clearAll()` helper,
/// then hand the buffer to a plain `allocator.free` instead of
/// `secureZeroAndFree` — the regression #375 fixed and #554 exists to catch.
const secrets_zig_deinit_regression_fixture =
    \\pub fn secureZero(buffer: []u8) void {
    \\    std.crypto.secureZero(u8, buffer);
    \\}
    \\
    \\pub fn secureZeroAndFree(allocator: std.mem.Allocator, buffer: []u8) void {
    \\    secureZero(buffer);
    \\    allocator.rawFree(buffer, .fromByteUnits(@alignOf(u8)), @returnAddress());
    \\}
    \\
    \\pub const BoundedSecret = struct {
    \\    allocator: ?std.mem.Allocator = null,
    \\    bytes: []u8 = &.{},
    \\    len: usize = 0,
    \\
    \\    fn clearAll(self: *BoundedSecret) void {
    \\        secureZero(self.bytes);
    \\        self.len = 0;
    \\    }
    \\
    \\    pub fn deinit(self: *BoundedSecret) void {
    \\        self.clearAll();
    \\        const allocator = self.allocator orelse return;
    \\        allocator.free(self.bytes);
    \\        self.allocator = null;
    \\        self.bytes = self.bytes[0..0];
    \\    }
    \\};
    \\
;

/// `clean_secrets_zig_fixture` with a brand-new helper function added
/// outside `secureZero` itself that reaches for the raw `std.crypto`
/// spelling directly — proves the guard is not scoped to `BoundedSecret`
/// specifically, but to the raw spelling appearing anywhere in the file
/// outside the one exempted wrapper function.
const secrets_zig_new_raw_call_fixture = clean_secrets_zig_fixture ++
    \\fn helperZero(buf: []u8) void {
    \\    std.crypto.secureZero(u8, buf);
    \\}
    \\
;

/// `clean_secrets_zig_fixture` with `BoundedSecret.deinit` reverting to the
/// historical bug through a *local rename* of `self.bytes`, with the
/// zeroing itself left untouched in the sibling `clearAll` method (#554
/// review, second pass) — the dedicated `checkBoundedSecretFile` structural
/// check exists specifically because neither the literal `.free(self.bytes)`
/// string nor `firstZeroThenPlainFree`'s forward-only single-function scan
/// (the zero call lives in `clearAll`, textually *after* `deinit` in the
/// real file, so a forward-only scan starting there never reaches back into
/// `deinit`) catches this shape.
const secrets_zig_deinit_rename_regression_fixture =
    \\pub fn secureZero(buffer: []u8) void {
    \\    std.crypto.secureZero(u8, buffer);
    \\}
    \\
    \\pub fn secureZeroAndFree(allocator: std.mem.Allocator, buffer: []u8) void {
    \\    secureZero(buffer);
    \\    allocator.rawFree(buffer, .fromByteUnits(@alignOf(u8)), @returnAddress());
    \\}
    \\
    \\pub const BoundedSecret = struct {
    \\    allocator: ?std.mem.Allocator = null,
    \\    bytes: []u8 = &.{},
    \\    len: usize = 0,
    \\
    \\    pub fn deinit(self: *BoundedSecret) void {
    \\        const bytes = self.bytes;
    \\        self.clearAll();
    \\        const allocator = self.allocator orelse return;
    \\        allocator.free(bytes);
    \\    }
    \\
    \\    fn clearAll(self: *BoundedSecret) void {
    \\        secureZero(self.bytes);
    \\        self.len = 0;
    \\    }
    \\};
    \\
;

/// `clean_secrets_zig_fixture` with `BoundedSecret.deinit` releasing
/// `self.bytes` through a direct `rawFree` call — bypassing
/// `secureZeroAndFree` (and its zeroing) entirely — instead of calling it
/// (#554 review, third pass). Proves the positive-requirement check: a
/// blacklist of known-bad free spellings would never have named `rawFree`,
/// since it's the *correct* spelling inside `secureZeroAndFree`'s own body.
const secrets_zig_deinit_rawfree_regression_fixture =
    \\pub fn secureZero(buffer: []u8) void {
    \\    std.crypto.secureZero(u8, buffer);
    \\}
    \\
    \\pub fn secureZeroAndFree(allocator: std.mem.Allocator, buffer: []u8) void {
    \\    secureZero(buffer);
    \\    allocator.rawFree(buffer, .fromByteUnits(@alignOf(u8)), @returnAddress());
    \\}
    \\
    \\pub const BoundedSecret = struct {
    \\    allocator: ?std.mem.Allocator = null,
    \\    bytes: []u8 = &.{},
    \\    len: usize = 0,
    \\
    \\    pub fn deinit(self: *BoundedSecret) void {
    \\        self.len = 0;
    \\        const allocator = self.allocator orelse return;
    \\        allocator.rawFree(
    \\            self.bytes,
    \\            .fromByteUnits(@alignOf(u8)),
    \\            @returnAddress(),
    \\        );
    \\    }
    \\
    \\    fn clearAll(self: *BoundedSecret) void {
    \\        secureZero(self.bytes);
    \\        self.len = 0;
    \\    }
    \\};
    \\
;

/// A trimmed `encrypted_stream.zig`: the secret-bearing `ByteQueue` wipes
/// through the canonical helper, while `PlaintextProvenanceQueue`'s `bool`
/// bookkeeping legitimately keeps `@memset` (#751).
const clean_encrypted_stream_fixture =
    \\fn PlaintextProvenanceQueue(comptime capacity: usize) type {
    \\    return struct {
    \\        buf: [capacity]bool = undefined,
    \\        fn clear(self: *@This()) void {
    \\            @memset(self.buf[0..], false);
    \\        }
    \\    };
    \\}
    \\
    \\/// Every wipe here goes through `crypto.secrets.secureZero`, never a plain
    \\/// `@memset(...)` -- comments mentioning it must not trip the audit.
    \\fn ByteQueue(comptime capacity: usize, comptime full_error: Error) type {
    \\    return struct {
    \\        buf: [capacity]u8 = undefined,
    \\        fn clear(self: *@This()) void {
    \\            crypto.secrets.secureZero(self.buf[0..]);
    \\        }
    \\        fn describe() []const u8 {
    \\            return "not @memset(buf, 0) {";
    \\        }
    \\    };
    \\}
    \\
;

/// `clean_encrypted_stream_fixture` with `ByteQueue.clear` regressed to a
/// plain `@memset` — the exact #751 defect 3 shape.
const byte_queue_memset_regression_fixture =
    \\fn PlaintextProvenanceQueue(comptime capacity: usize) type {
    \\    return struct {
    \\        buf: [capacity]bool = undefined,
    \\        fn clear(self: *@This()) void {
    \\            @memset(self.buf[0..], false);
    \\        }
    \\    };
    \\}
    \\
    \\fn ByteQueue(comptime capacity: usize, comptime full_error: Error) type {
    \\    return struct {
    \\        buf: [capacity]u8 = undefined,
    \\        fn clear(self: *@This()) void {
    \\            @memset(self.buf[0..], 0);
    \\        }
    \\    };
    \\}
    \\
;

test "raw secureZero guard flags the direct std.crypto spelling, called or bound as a value" {
    const a = testing.allocator;
    try testing.expectEqualStrings("std.crypto.secureZero", (try rawSecureZeroViolation(a, "fn wipe(b: []u8) void { std.crypto.secureZero(u8, b); }\n")).?);
    try testing.expectEqualStrings("std.crypto.secureZero", (try rawSecureZeroViolation(a, "const wipe = std.crypto.secureZero;\n")).?);
    try testing.expectEqualStrings("@import(\"std\").crypto.secureZero", (try rawSecureZeroViolation(a, "fn wipe(b: []u8) void { @import(\"std\").crypto.secureZero(u8, b); }\n")).?);
}

test "raw secureZero guard follows a local std.crypto namespace alias" {
    const a = testing.allocator;
    // The shape #784 migrated ~100 production sites off.
    try testing.expectEqualStrings("std.crypto alias .secureZero", (try rawSecureZeroViolation(a, "const crypto = std.crypto;\nfn wipe(k: *[32]u8) void { defer crypto.secureZero(u8, k); }\n")).?);
    // A function-value binding through the alias, then a one-argument call.
    try testing.expectEqualStrings("std.crypto alias .secureZero", (try rawSecureZeroViolation(a, "const c = std.crypto;\nconst z = c.secureZero;\n")).?);
    // An alias used only for other primitives is fine.
    try testing.expect((try rawSecureZeroViolation(a, "const crypto = std.crypto;\nconst Sha256 = crypto.hash.sha2.Sha256;\n")) == null);
}

test "raw secureZero guard flags the stdlib's typed two-argument call under any qualifier" {
    const a = testing.allocator;
    try testing.expectEqualStrings("secureZero(T, buf)", (try rawSecureZeroViolation(a, "fn wipe(b: []u8) void { sc.secureZero(u8, b); }\n")).?);
    try testing.expectEqualStrings("secureZero(T, buf)", (try rawSecureZeroViolation(a, "fn wipe(b: []u8) void { ns.inner.secureZero(\n    u8,\n    b[0..f(1, 2)],\n); }\n")).?);
}

test "raw secureZero guard allows canonical helpers, prose, strings, and test fixtures" {
    const a = testing.allocator;
    const clean =
        \\//! Never `std.crypto.secureZero(u8, buf)` directly -- see #750.
        \\const provider = @import("crypto").provider;
        \\const secrets = @import("crypto").secrets;
        \\fn wipe(k: *[32]u8, buf: []u8, allocator: std.mem.Allocator) void {
        \\    provider.secureZero(k);
        \\    secrets.secureZero(buf[0..f(1, 2)]);
        \\    defer secrets.secureZeroAndFree(allocator, buf);
        \\    const msg = "std.crypto.secureZero(u8, x)";
        \\    _ = msg;
        \\}
        \\test "fixture may wipe with the stdlib form" {
        \\    var k: [4]u8 = .{ 1, 2, 3, 4 };
        \\    if (true) { std.crypto.secureZero(u8, &k); }
        \\}
        \\
    ;
    try testing.expect((try rawSecureZeroViolation(a, clean)) == null);
}

test "raw secureZero guard does not treat a test-named identifier as a test block" {
    const a = testing.allocator;
    const src =
        \\fn testing_helper() void {}
        \\test_value: u8 = 0,
        \\fn wipe(b: []u8) void { std.crypto.secureZero(u8, b); }
        \\
    ;
    try testing.expect((try rawSecureZeroViolation(a, src)) != null);
}

test "secret-storage guard rejects @memset inside ByteQueue but not in PlaintextProvenanceQueue" {
    const a = testing.allocator;
    try testing.expect((try secretStorageViolation(a, clean_encrypted_stream_fixture, "ByteQueue")) == null);
    try testing.expect((try secretStorageViolation(a, clean_encrypted_stream_fixture, "PlaintextProvenanceQueue")) != null);
    try testing.expectEqualStrings("@memset on secret-bearing storage", (try secretStorageViolation(a, byte_queue_memset_regression_fixture, "ByteQueue")).?);
}

test "secret-storage guard covers the tls_adapter CRYPTO buffers and fails closed when one disappears" {
    const a = testing.allocator;
    for ([_][]const u8{ "CryptoStream", "CryptoReassembler", "CryptoOutput" }) |decl| {
        try testing.expect((try secretStorageViolation(a, clean_tls_adapter_fixture, decl)) == null);
    }
    const regressed = "pub const CryptoReassembler = struct {\n    pub fn deinit(self: *CryptoReassembler) void {\n        @memset(std.mem.asBytes(self), 0);\n    }\n};\n";
    try testing.expect((try secretStorageViolation(a, regressed, "CryptoReassembler")) != null);
    // Renamed away: the protection must not silently lapse.
    try testing.expectEqualStrings("<secret-bearing declaration missing>", (try secretStorageViolation(a, "pub const CryptoReassemblerV2 = struct {};\n", "CryptoReassembler")).?);
}

test "end-to-end: the audit fails against a fixture tree reproducing each bypass, and passes once fixed" {
    const allocator = testing.allocator;

    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = compat.wrapDir(tmp.dir);

    try root.makePath("src/quic/nested");
    try root.makePath("src/http");
    try root.makePath("src/tls");
    try root.makePath("src/pki");
    try root.makePath("src/crypto");

    // The protected files/functions the fixture tree must carry so the
    // "clean" baseline below is actually clean, not just missing every
    // fail-closed target.
    try root.writeFile(.{ .sub_path = "src/quic/tls_adapter.zig", .data = clean_tls_adapter_fixture });
    try root.writeFile(.{ .sub_path = "src/quic/cid.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/quic/tls_handshake.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/quic/path.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/quic/packet.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/tls/key_schedule.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/tls/tls13_backend.zig", .data = "" });

    // #554's protected files/functions, same fail-closed requirement.
    try root.writeFile(.{ .sub_path = "src/crypto/secrets.zig", .data = clean_secrets_zig_fixture });
    try root.writeFile(.{ .sub_path = "src/tls/ticket_key_snapshot.zig", .data = "" });
    try root.writeFile(.{ .sub_path = "src/tls/sni_provider.zig", .data = "" });

    // #784's protected secret-bearing storage declarations.
    try root.writeFile(.{ .sub_path = "src/tls/encrypted_stream.zig", .data = clean_encrypted_stream_fixture });

    const bypass_cases = [_]struct { rel: []const u8, contents: []const u8 }{
        .{ .rel = "src/quic/connection.zig", .contents = "const mask = Aes128.initEnc(self.hp);\n" },
        .{ .rel = "src/quic/packet.zig", .contents = "const shared = X25519.scalarmult(a, b) catch unreachable;\n" },
        .{ .rel = "src/quic/path.zig", .contents = "Ed25519.verify(sig, msg, key) catch return error.Bad;\n" },
        .{ .rel = "src/http/http3_runtime.zig", .contents = "keys.applyHeaderProtection(&out[0], pn_field, sample);\n" },
        // The composition root must not perform packet crypto itself even
        // outside the legacy-wrapper-call category.
        .{ .rel = "src/http/http3_runtime.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        .{ .rel = "src/quic/frame.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // A nested subdirectory under src/quic gets no free pass from the
        // (now recursive) directory-wide scan.
        .{ .rel = "src/quic/nested/packet_crypto.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // A file at any depth reusing an excluded file's *basename* still
        // fails: exclusion is by exact root-relative path now.
        .{ .rel = "src/quic/nested/connection.zig", .contents = "const tag = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(...);\n" },
        // tls_handshake.zig is fully scannable now; a legacy wrapper call
        // there must fail too, and so must unrelated KDF use beyond the one
        // named exception.
        .{ .rel = "src/quic/tls_handshake.zig", .contents = "keys.sealPayload(pn, header, plain, out);\n" },
        .{ .rel = "src/quic/tls_handshake.zig", .contents = "const other = std.crypto.kdf.hkdf.HkdfSha384.extract(a, b);\n" },
        // path.zig/cid.zig: a second, unrelated crypto call beyond the named
        // exception must still fail (#490 fourth-pass review) — the whole
        // category is no longer omitted from the forbidden list.
        .{ .rel = "src/quic/path.zig", .contents = "fn unrelated() void { _ = std.crypto.auth.hmac.sha2.HmacSha256.create(&mac, msg, key); }\n" },
        .{ .rel = "src/quic/cid.zig", .contents = "fn unrelated() void { _ = std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(a, b, c, d, e, f); }\n" },
        // The exact regression the tls_adapter.zig checks exist to catch: a
        // canonical method reverting to a legacy wrapper call internally.
        .{ .rel = "src/quic/tls_adapter.zig", .contents = canonical_method_regression_fixture },
        // The mirror regression: a *WithProvider implementation silently
        // delegating to its own legacy concrete sibling instead of the
        // provider.
        .{ .rel = "src/quic/tls_adapter.zig", .contents = with_provider_delegates_to_legacy_fixture },

        // #490's second migration target: src/tls/key_schedule.zig and
        // src/tls/tls13_backend.zig. Each of the three bypass classes the
        // issue calls out — a direct call, an aliased call, and a
        // helper-function indirection — proven separately for both files.
        .{ .rel = "src/tls/key_schedule.zig", .contents = "const shared = crypto.dh.X25519.scalarmult(a, b) catch unreachable;\n" },
        // A differently-named local alias for the same concrete HKDF type:
        // proves the guard catches the underlying crypto.kdf. qualifier
        // regardless of what a caller names the alias, not just the one
        // exact declaration this file's own comptime exception is scoped to.
        .{ .rel = "src/tls/key_schedule.zig", .contents = "const RogueHkdf = crypto.kdf.hkdf.HkdfSha256;\n" },
        // A forbidden call wrapped inside an arbitrarily-named helper
        // function: the audit scans the whole file, not just the one named
        // exempt function, so indirection through a new helper does not
        // evade it. Argument shape deliberately differs from the one exact
        // exempted expand-label call so this does not collide with it.
        .{ .rel = "src/tls/key_schedule.zig", .contents = "fn helperDerive(s: []const u8) [32]u8 { var out: [32]u8 = undefined; crypto.tls.hkdfExpandLabel(HkdfSha256, s, \"other\", \"\", &out); return out; }\n" },
        // #490 review: `key_schedule.zig` has no `production_only_marker` at
        // all, specifically so this exact shape of bug cannot recur — a
        // production declaration positioned before a `const testing =
        // std.testing;`-shaped line, calling a private helper positioned
        // after it, must still fail even though that line would have been a
        // marker under the (now-removed) text-position-based scheme other
        // files in this tool still use.
        .{
            .rel = "src/tls/key_schedule.zig",
            .contents = "pub fn callsHelperBeforeDecoyMarker() [32]u8 { return legacyHelperAfterDecoyMarker(); }\n\nconst testing = std.testing;\n\nfn legacyHelperAfterDecoyMarker() [32]u8 { var out: [32]u8 = undefined; crypto.tls.hkdfExpandLabel(HkdfSha256, \"s\", \"other\", \"\", &out); return out; }\n",
        },
        .{ .rel = "src/tls/tls13_backend.zig", .contents = "var kp = X25519.KeyPair.generateDeterministic(seed) catch unreachable;\n" },
        .{ .rel = "src/tls/tls13_backend.zig", .contents = "const LocalEd25519 = crypto.sign.Ed25519;\n" },
        .{ .rel = "src/tls/tls13_backend.zig", .contents = "fn helperVerify(sig: []const u8, msg: []const u8, key: []const u8) void { Ed25519.verify(sig, msg, key) catch unreachable; }\n" },

        // #554: a raw constant-time-comparison call reappearing anywhere in
        // src/tls, src/quic, src/pki, or src/crypto (outside secrets.zig's
        // own implementation), qualified either way a call site might spell
        // it. The src/crypto case reproduces rsa.zig's actual EMSA-PSS final
        // authentication comparison shape — #554 review (second pass) found
        // the original guard's directory scope missed this file entirely.
        .{ .rel = "src/tls/timing_safe_regression.zig", .contents = "if (!std.crypto.timing_safe.eql([32]u8, expected, candidate)) return error.Bad;\n" },
        .{ .rel = "src/quic/timing_safe_regression.zig", .contents = "const ok = crypto.timing_safe.eql([16]u8, tag, received);\n" },
        .{ .rel = "src/pki/timing_safe_regression.zig", .contents = "return std.crypto.timing_safe.compare(u8, expected, h_array, .big) == .eq;\n" },
        .{ .rel = "src/crypto/rsa_timing_safe_regression.zig", .contents = "if (!crypto.timing_safe.eql([h_len]u8, expected, h_array)) return error.InvalidInput;\n" },
        // The namespace-capture-alias bypass #554 review (first pass) found:
        // neither needle used to end without a trailing `.`, so an aliased
        // capture followed by a call off the alias evaded both.
        .{ .rel = "src/tls/timing_safe_regression.zig", .contents = "const timing_safe = std.crypto.timing_safe;\nreturn timing_safe.eql([32]u8, expected, candidate);\n" },
        // The parent-namespace-alias bypass #554 review (second pass) found:
        // aliasing `std.crypto` itself, one level up from `timing_safe`,
        // under a name that doesn't end in "crypto" (unlike the coincidental
        // `std_crypto` spelling already used elsewhere in this repo).
        .{ .rel = "src/tls/timing_safe_regression.zig", .contents = "const c = std.crypto;\nreturn c.timing_safe.eql([32]u8, expected, candidate);\n" },
        // The exact spelling already used elsewhere in this repo
        // (sni_provider.zig's `std_crypto` alias), confirmed explicitly per
        // the reviewer's request.
        .{ .rel = "src/tls/timing_safe_regression.zig", .contents = "const std_crypto = std.crypto;\nreturn std_crypto.timing_safe.eql([32]u8, expected, candidate);\n" },

        // #554: the raw-secureZero-spelling findings #375 fixed.
        .{ .rel = "src/tls/ticket_key_snapshot.zig", .contents = "fn f(x: []u8) void { std.crypto.secureZero(u8, x); }\n" },
        .{ .rel = "src/tls/sni_provider.zig", .contents = "pub fn release(self: *SignAdapter) void { std_crypto.secureZero(u8, std.mem.asBytes(&self.identity.key)); }\n" },
        .{ .rel = "src/crypto/secrets.zig", .contents = secrets_zig_deinit_regression_fixture },
        .{ .rel = "src/crypto/secrets.zig", .contents = secrets_zig_new_raw_call_fixture },
        // The reviewer's exact cross-function-rename bypass: `clearAll`
        // (unchanged) does the zeroing, `deinit` frees a local rename of
        // `self.bytes` instead of routing through `secureZeroAndFree` — the
        // dedicated `checkBoundedSecretFile` structural check exists
        // specifically to catch this, since it survives both the literal
        // `.free(self.bytes)` string and the general forward-only
        // `firstZeroThenPlainFree` scan.
        .{ .rel = "src/crypto/secrets.zig", .contents = secrets_zig_deinit_rename_regression_fixture },

        // #554 review (second pass): the general zero-then-plain-free
        // scanner, general over file and variable name rather than three
        // named files and four exact historical strings.
        //
        // The exact historical shape, reproduced generically (no literal
        // variable-name list involved — this passes because the scanner
        // pairs the zero call's own argument with a later free of the same
        // expression, not because "self.key_storage" is spelled out
        // anywhere in the tool).
        .{ .rel = "src/tls/ticket_key_snapshot.zig", .contents = "pub fn deinit(self: *OwnedSnapshot) void { crypto.secrets.secureZero(self.key_storage); self.allocator.free(self.key_storage); }\n" },
        // The reviewer's exact bypass example: the same defect survives a
        // harmless local rename that a name-keyed check would miss.
        .{ .rel = "src/tls/ticket_key_snapshot.zig", .contents = "pub fn deinit(self: *OwnedSnapshot) void { const storage = self.key_storage; crypto.secrets.secureZero(std.mem.sliceAsBytes(storage)); self.allocator.free(storage); }\n" },
        // A brand-new ad hoc zero-and-free implementation in a file this
        // tool names nowhere at all.
        .{ .rel = "src/tls/new_ad_hoc_zero_free_site.zig", .contents = "pub fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    crypto.secrets.secureZero(secret_buf);\n    allocator.free(secret_buf);\n}\n" },
        // The ArrayList zero-then-.deinit shape, in a new file.
        .{ .rel = "src/quic/new_ad_hoc_zero_free_site.zig", .contents = "fn f(allocator: std.mem.Allocator) void {\n    var out = std.array_list.Managed(u8).init(allocator);\n    defer {\n        secrets.secureZero(out.items);\n        out.deinit();\n    }\n}\n" },
        // #554 review (second pass): the general scanner's own bypasses —
        // aliasing the callee (the zero function itself) or the buffer
        // (a local rename between the zero call and the free), one hop
        // each, in a file this tool names nowhere.
        .{ .rel = "src/pki/callee_alias_zero_free_site.zig", .contents = "pub fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    const wipe = crypto.secrets.secureZero;\n    wipe(secret_buf);\n    allocator.free(secret_buf);\n}\n" },
        .{ .rel = "src/pki/buffer_rename_zero_free_site.zig", .contents = "pub fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    crypto.secrets.secureZero(secret_buf);\n    const doomed = secret_buf;\n    allocator.free(doomed);\n}\n" },

        // #554 review (third pass): three more bypasses of the general
        // scanner, plus one of the dedicated BoundedSecret check.
        // The defer-LIFO bypass: the free's own defer is written *before*
        // the zero's defer, but defers run LIFO, so the free still executes
        // *after* the zero at runtime — the exact prohibited sequence, in a
        // file this tool names nowhere.
        .{ .rel = "src/quic/defer_order_zero_free_site.zig", .contents = "pub fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    defer allocator.free(secret_buf);\n    defer crypto.secrets.secureZero(secret_buf);\n}\n" },
        // The manual-clear (not `secureZero` at all) bypass.
        .{ .rel = "src/pki/manual_clear_zero_free_site.zig", .contents = "pub fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    @memset(secret_buf, 0);\n    allocator.free(secret_buf);\n}\n" },
        // The chained-alias bypass: a harmless first rename must not shadow
        // the actually-freed second rename.
        .{ .rel = "src/crypto/rsa_chained_alias_zero_free_site.zig", .contents = "pub fn release(allocator: std.mem.Allocator, secret_buf: []u8) void {\n    crypto.secrets.secureZero(secret_buf);\n    const retained_view = secret_buf;\n    _ = retained_view;\n    const doomed = secret_buf;\n    allocator.free(doomed);\n}\n" },
        // BoundedSecret.deinit releasing self.bytes through a direct
        // rawFree call, bypassing secureZeroAndFree (and its zeroing)
        // entirely — the blacklist-style check this replaced would never
        // have named `rawFree`, since it's the *correct* spelling inside
        // secureZeroAndFree's own implementation.
        .{ .rel = "src/crypto/secrets.zig", .contents = secrets_zig_deinit_rawfree_regression_fixture },

        // #784: a direct production std.crypto.secureZero, the std.crypto
        // namespace-alias form, and the typed two-argument form under an
        // unrelated qualifier, each in a file this tool names nowhere
        // (including src/http, which the older checks do not scan).
        .{ .rel = "src/tls/raw_secure_zero_site.zig", .contents = "pub fn wipe(buf: []u8) void {\n    std.crypto.secureZero(u8, buf);\n}\n" },
        .{ .rel = "src/crypto/raw_secure_zero_alias_site.zig", .contents = "const crypto = std.crypto;\npub fn wipe(k: *[32]u8) void {\n    defer crypto.secureZero(u8, k);\n}\n" },
        .{ .rel = "src/http/raw_secure_zero_typed_site.zig", .contents = "pub fn wipe(buf: []u8) void {\n    zeroing.secureZero(u8, buf);\n}\n" },
        // #751's regression: ByteQueue wiping with a plain @memset.
        .{ .rel = "src/tls/encrypted_stream.zig", .contents = byte_queue_memset_regression_fixture },
        // Renaming a protected declaration away must fail, not pass.
        .{ .rel = "src/tls/encrypted_stream.zig", .contents = "fn RenamedQueue(comptime capacity: usize) type { return struct {}; }\n" },
    };

    for (bypass_cases) |case| {
        try root.writeFile(.{ .sub_path = case.rel, .data = case.contents });
        var violations = try runAudit(allocator, root);
        defer violations.deinit(allocator);
        for (violations.items) |v| allocator.free(v.path);
        try testing.expect(violations.items.len > 0);
        // Clean up before the next case so violations don't accumulate
        // across cases sharing a file path.
        const clean = if (std.mem.eql(u8, case.rel, "src/quic/tls_adapter.zig"))
            clean_tls_adapter_fixture
        else if (std.mem.eql(u8, case.rel, "src/crypto/secrets.zig"))
            clean_secrets_zig_fixture
        else if (std.mem.eql(u8, case.rel, "src/tls/encrypted_stream.zig"))
            clean_encrypted_stream_fixture
        else if (std.mem.eql(u8, case.rel, "src/http/http3_runtime.zig"))
            ""
        else
            "";
        try root.writeFile(.{ .sub_path = case.rel, .data = clean });
    }
    try root.deleteFile("src/quic/nested/packet_crypto.zig");
    try root.deleteFile("src/quic/nested/connection.zig");
    try root.deleteFile("src/tls/timing_safe_regression.zig");
    try root.deleteFile("src/quic/timing_safe_regression.zig");
    try root.deleteFile("src/pki/timing_safe_regression.zig");
    try root.deleteFile("src/crypto/rsa_timing_safe_regression.zig");
    try root.deleteFile("src/tls/new_ad_hoc_zero_free_site.zig");
    try root.deleteFile("src/quic/new_ad_hoc_zero_free_site.zig");
    try root.deleteFile("src/pki/callee_alias_zero_free_site.zig");
    try root.deleteFile("src/pki/buffer_rename_zero_free_site.zig");
    try root.deleteFile("src/quic/defer_order_zero_free_site.zig");
    try root.deleteFile("src/pki/manual_clear_zero_free_site.zig");
    try root.deleteFile("src/crypto/rsa_chained_alias_zero_free_site.zig");
    try root.deleteFile("src/tls/raw_secure_zero_site.zig");
    try root.deleteFile("src/crypto/raw_secure_zero_alias_site.zig");
    try root.deleteFile("src/http/raw_secure_zero_typed_site.zig");

    var clean_violations = try runAudit(allocator, root);
    defer clean_violations.deinit(allocator);
    for (clean_violations.items) |v| allocator.free(v.path);
    try testing.expectEqual(@as(usize, 0), clean_violations.items.len);

    // Fail-closed: deleting a protected file must itself be a violation,
    // not a silent pass.
    try root.deleteFile("src/quic/cid.zig");
    var missing_file_violations = try runAudit(allocator, root);
    defer missing_file_violations.deinit(allocator);
    defer for (missing_file_violations.items) |v| allocator.free(v.path);
    try testing.expect(missing_file_violations.items.len > 0);
    try root.writeFile(.{ .sub_path = "src/quic/cid.zig", .data = "" });
}

// test_quic_crypto production/test isolation is no longer this tool's job to
// prove by fixture: it's enforced by build.zig's module graph and the Zig
// compiler, not by pattern-matching source text. See the "Scanning" section
// comment above and build.zig's `test_quic_crypto_mod`.

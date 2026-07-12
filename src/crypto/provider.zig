//! Stable cryptographic-provider boundary (#370, epic #327).
//!
//! One narrow interface for every cryptographic operation the TLS 1.3 engine,
//! QUIC packet protection, X.509 verification, ticket protection, and the TLS
//! record layer consume. Protocol code depends on the types in this file and
//! never on a concrete implementation — neither `std.crypto` primitives nor a
//! future OpenSSL binding leak across the seam.
//!
//! ## Why a provider seam
//!
//! The epic keeps OpenSSL as the approved production backend while a pure-Zig
//! backend grows alongside it (`docs/CRYPTO_PROVIDER.md`). Both must satisfy
//! *this* interface where their capabilities overlap, so protocol modules can
//! be written once and run against either. The interface is intentionally
//! runtime-dispatched (a `context` pointer plus a `*const VTable`) exactly like
//! the QUIC `TlsBackend` seam (`src/quic/tls_handshake.zig`): the composition
//! root picks the provider, the protocol never learns which one it got.
//!
//! ## Design rules encoded here
//!
//!   * **Capability discovery is explicit.** A provider advertises exactly the
//!     hashes, AEADs, groups, and signature schemes it can perform
//!     (`Capabilities`). Negotiation code selects only from that set, and every
//!     operation re-checks it, so an unsupported algorithm is a typed
//!     `error.UnsupportedCapability`, never undefined behaviour.
//!   * **Errors are classified.** `InputError` (malformed/wrong-sized peer or
//!     caller input), `CapabilityError` (well-formed but unsupported), and
//!     `ProviderError` (the provider itself failed) are distinct, plus the
//!     security-critical `error.AuthenticationFailed` for AEAD-open and
//!     signature-verify. The protocol layer maps each class to the right alert
//!     without guessing.
//!   * **Secrets are borrowed, never retained.** Every slice a caller hands in
//!     (keys, IKM, plaintext, private scalars) is valid only for the duration
//!     of the call. A provider must not stash a pointer to borrowed secret
//!     material past return. Provider-owned secrets (a `SigningKey`'s private
//!     key) live behind an opaque handle the caller destroys explicitly.
//!   * **Entropy is injected.** Like the rest of the QUIC stack there is no
//!     ambient RNG; a provider draws randomness from an `Entropy` source given
//!     at construction, which the composition root wires to the OS CSPRNG in
//!     production and to a deterministic generator in tests.
//!
//! This module defines the boundary and its value types only. The pure-Zig
//! implementation lives in `pure_zig.zig`; an OpenSSL adapter is future work
//! that implements the same `VTable`.

const std = @import("std");
const crypto = std.crypto;
const secrets = @import("crypto_secrets");

// ---------------------------------------------------------------------------
// Fixed capacities
//
// The seam moves cryptographic material through caller-owned buffers rather
// than allocating, so it publishes the largest sizes the supported profile can
// produce. Callers size stack buffers against these constants.
// ---------------------------------------------------------------------------

/// Largest hash / HKDF output in the supported profile (SHA-384 = 48 bytes).
pub const max_digest_len = 48;
/// Largest AEAD key in the supported profile (AES-256 / ChaCha20 = 32 bytes).
pub const max_aead_key_len = 32;
/// AEAD nonce length. Every supported AEAD (AES-GCM, ChaCha20-Poly1305 in the
/// TLS/QUIC profile) uses a 12-byte nonce.
pub const aead_nonce_len = 12;
/// AEAD authentication tag length. Every supported AEAD uses a 16-byte tag.
pub const aead_tag_len = 16;
/// Largest key-exchange public value (uncompressed P-256 point = 65 bytes).
pub const max_public_key_len = 65;
/// Largest key-exchange private scalar in the supported profile (32 bytes).
pub const max_private_scalar_len = 32;
/// Largest shared secret an ECDH group in the supported profile derives.
pub const max_shared_secret_len = 32;

// ---------------------------------------------------------------------------
// Error taxonomy
// ---------------------------------------------------------------------------

/// The caller or peer supplied malformed or wrong-sized input. Recoverable at
/// the protocol layer — typically a `decode_error` / `illegal_parameter` alert
/// or a QUIC `CRYPTO_ERROR`. Never the provider's fault.
pub const InputError = error{
    /// Input was structurally invalid (bad point encoding, wrong-length key,
    /// output buffer too small, mismatched ciphertext/plaintext lengths).
    InvalidInput,
};

/// The requested algorithm or parameter is well-formed but this provider does
/// not implement it. Explicit capability negotiation is meant to prevent this;
/// reaching it is a configuration or negotiation bug, not peer misbehaviour.
pub const CapabilityError = error{
    UnsupportedCapability,
};

/// The provider itself failed for reasons unrelated to the input: the entropy
/// source returned an error, or an internal invariant broke. Not recoverable
/// by renegotiating algorithms.
pub const ProviderError = error{
    EntropyFailure,
    ProviderFailure,
};

/// Authentication failed: an AEAD tag did not verify, or a signature did not
/// check out. Kept separate from `InputError` because it is the security-
/// relevant "these bytes are not authentic" signal, and protocol code must not
/// treat it as a benign decode error.
pub const AuthError = error{
    AuthenticationFailed,
};

/// HKDF extract/expand cannot fail on authentication and does not touch
/// entropy; only capability and input sizing can go wrong.
pub const HkdfError = InputError || CapabilityError;
/// AEAD seal produces output; it can reject bad sizes or an unsupported AEAD.
pub const SealError = InputError || CapabilityError;
/// AEAD open additionally authenticates, so it adds `AuthenticationFailed`.
pub const OpenError = InputError || CapabilityError || AuthError;
/// Key-share generation draws entropy, can reject an unsupported group, and
/// rejects wrong-sized caller output buffers as `InvalidInput`.
pub const KeyShareError = InputError || CapabilityError || ProviderError;
/// Shared-secret derivation validates the peer's public value (`InvalidInput`
/// covers a low-order / all-zero point) and can reject an unsupported group.
pub const DeriveError = InputError || CapabilityError;
/// Signing draws entropy for some schemes and can fail inside the provider.
pub const SignError = InputError || CapabilityError || ProviderError;
/// Verification authenticates, so it carries `AuthenticationFailed`.
pub const VerifyError = InputError || CapabilityError || AuthError;
/// Random-byte generation only fails when the entropy source does.
pub const RandomError = ProviderError;

/// Entropy sources report failure with this narrow set; the provider maps it
/// onto `ProviderError.EntropyFailure`.
pub const EntropyError = error{
    EntropyFailure,
};

// ---------------------------------------------------------------------------
// Algorithm identifiers
// ---------------------------------------------------------------------------

/// Hash / HKDF families the boundary can name. The wire never sees these
/// directly; they parameterise HKDF and the HMAC inside signature schemes.
pub const Hash = enum {
    sha256,
    sha384,

    /// Output length in bytes of this hash (and of its HKDF PRK).
    pub fn digestLength(self: Hash) usize {
        return switch (self) {
            .sha256 => 32,
            .sha384 => 48,
        };
    }
};

/// AEAD profiles for record and packet protection.
pub const Aead = enum {
    aes_128_gcm,
    aes_256_gcm,
    chacha20_poly1305,

    pub fn keyLength(self: Aead) usize {
        return switch (self) {
            .aes_128_gcm => 16,
            .aes_256_gcm, .chacha20_poly1305 => 32,
        };
    }

    /// Nonce length. Uniform across the supported profile, exposed per-AEAD so
    /// call sites stay algorithm-agnostic.
    pub fn nonceLength(self: Aead) usize {
        _ = self;
        return aead_nonce_len;
    }

    pub fn tagLength(self: Aead) usize {
        _ = self;
        return aead_tag_len;
    }
};

/// Key-exchange groups (ECDH). Names match the TLS `NamedGroup` registry.
pub const Group = enum {
    x25519,
    secp256r1,

    /// Length of the public key share this group puts on the wire.
    pub fn publicKeyLength(self: Group) usize {
        return switch (self) {
            .x25519 => 32,
            .secp256r1 => 65, // uncompressed point: 0x04 || X || Y
        };
    }

    /// Length of the raw shared secret ECDH derives for this group.
    pub fn sharedSecretLength(self: Group) usize {
        return switch (self) {
            .x25519 => 32,
            .secp256r1 => 32, // the X coordinate
        };
    }
};

/// Signature schemes for CertificateVerify and (future) ticket authentication.
/// Names match the TLS `SignatureScheme` registry.
pub const SignatureScheme = enum {
    ed25519,
    ecdsa_secp256r1_sha256,
    rsa_pss_rsae_sha256,
};

// ---------------------------------------------------------------------------
// Capability discovery
// ---------------------------------------------------------------------------

/// The exact algorithm set a provider can perform. Negotiation selects only
/// from these sets, and every operation re-checks membership, so an
/// unsupported algorithm is always a typed error and never reaches a primitive
/// that cannot handle it.
pub const Capabilities = struct {
    hashes: std.EnumSet(Hash) = .{},
    aeads: std.EnumSet(Aead) = .{},
    groups: std.EnumSet(Group) = .{},
    signatures: std.EnumSet(SignatureScheme) = .{},

    pub fn supportsHash(self: Capabilities, hash: Hash) bool {
        return self.hashes.contains(hash);
    }
    pub fn supportsAead(self: Capabilities, aead: Aead) bool {
        return self.aeads.contains(aead);
    }
    pub fn supportsGroup(self: Capabilities, group: Group) bool {
        return self.groups.contains(group);
    }
    pub fn supportsSignature(self: Capabilities, scheme: SignatureScheme) bool {
        return self.signatures.contains(scheme);
    }

    /// Walk `preferences` in caller order and return the first algorithm this
    /// provider supports, or null when the sets do not intersect. The generic
    /// form backs the typed `select*` helpers below; negotiation code should
    /// prefer those so the element type is checked.
    fn selectFrom(comptime T: type, set: std.EnumSet(T), preferences: []const T) ?T {
        for (preferences) |candidate| {
            if (set.contains(candidate)) return candidate;
        }
        return null;
    }

    pub fn selectAead(self: Capabilities, preferences: []const Aead) ?Aead {
        return selectFrom(Aead, self.aeads, preferences);
    }
    pub fn selectGroup(self: Capabilities, preferences: []const Group) ?Group {
        return selectFrom(Group, self.groups, preferences);
    }
    pub fn selectSignature(self: Capabilities, preferences: []const SignatureScheme) ?SignatureScheme {
        return selectFrom(SignatureScheme, self.signatures, preferences);
    }
};

// ---------------------------------------------------------------------------
// Entropy source
// ---------------------------------------------------------------------------

/// A caller-supplied randomness source. The composition root wires this to the
/// OS CSPRNG in production and to a deterministic generator in tests, matching
/// the "entropy is injected, never ambient" rule the QUIC stack already
/// follows. A provider draws all randomness — ephemeral scalars, nonces,
/// signature noise — through this.
pub const Entropy = struct {
    context: *anyopaque,
    fillFn: *const fn (context: *anyopaque, buffer: []u8) EntropyError!void,

    /// Fill `buffer` with cryptographically strong random bytes, or fail.
    pub fn fill(self: Entropy, buffer: []u8) EntropyError!void {
        return self.fillFn(self.context, buffer);
    }
};

// ---------------------------------------------------------------------------
// Signing keys (opaque private-key handles)
// ---------------------------------------------------------------------------

/// An opaque handle to a private signing key. This is the single abstraction
/// the epic calls out for supporting software keys today and hardware or
/// remote signers later without changing TLS state: the TLS engine holds a
/// `SigningKey` and calls `sign`, oblivious to whether the private key lives in
/// process memory, an HSM, or a network signer.
///
/// The handle borrows nothing from the caller across `sign`; its own private
/// material is owned by whatever produced it (e.g. a `pure_zig` software key)
/// and released by that owner, not here.
pub const SigningKey = struct {
    context: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// The scheme this key signs with; negotiation must offer only this.
        scheme: *const fn (context: *anyopaque) SignatureScheme,
        /// Sign `message`, writing the signature into `out` and returning its
        /// length. `out` must be large enough for the scheme's signature
        /// (`error.InvalidInput` otherwise). `entropy` supplies any randomness
        /// the scheme needs (ECDSA/RSA-PSS); Ed25519 ignores it.
        sign: *const fn (
            context: *anyopaque,
            message: []const u8,
            entropy: Entropy,
            out: []u8,
        ) SignError!usize,
    };

    pub fn scheme(self: SigningKey) SignatureScheme {
        return self.vtable.scheme(self.context);
    }

    pub fn sign(self: SigningKey, message: []const u8, entropy: Entropy, out: []u8) SignError!usize {
        return self.vtable.sign(self.context, message, entropy, out);
    }
};

// ---------------------------------------------------------------------------
// The provider interface
// ---------------------------------------------------------------------------

/// The cryptographic-provider boundary. All symmetric operations move key
/// material through caller-owned slices (borrowed for the call only); the sole
/// provider-owned secret handle is `SigningKey`.
pub const CryptoProvider = struct {
    context: *anyopaque,
    vtable: *const VTable,
    /// Entropy the provider draws all randomness from. Held here so the
    /// interface documents that a provider has exactly one injected source.
    entropy: Entropy,

    pub const VTable = struct {
        capabilities: *const fn (context: *anyopaque) Capabilities,

        /// HKDF-Extract: `out` receives `hash.digestLength()` PRK bytes.
        hkdfExtract: *const fn (
            context: *anyopaque,
            hash: Hash,
            salt: []const u8,
            ikm: []const u8,
            out: []u8,
        ) HkdfError!void,

        /// HKDF-Expand-Label (RFC 8446 §7.1): derive `out.len` bytes bound to
        /// `label` (the bare label, without the "tls13 " prefix the provider
        /// adds) and `context`.
        hkdfExpandLabel: *const fn (
            context: *anyopaque,
            hash: Hash,
            secret: []const u8,
            label: []const u8,
            hash_context: []const u8,
            out: []u8,
        ) HkdfError!void,

        /// AEAD seal. `ciphertext.len` must equal `plaintext.len`; the tag is
        /// written separately to `tag` (`aead.tagLength()` bytes).
        aeadSeal: *const fn (
            context: *anyopaque,
            aead: Aead,
            key: []const u8,
            nonce: []const u8,
            associated_data: []const u8,
            plaintext: []const u8,
            ciphertext: []u8,
            tag: []u8,
        ) SealError!void,

        /// AEAD open. Authenticates `tag` over `ciphertext` + `associated_data`
        /// and writes `plaintext` on success. On `error.AuthenticationFailed`
        /// the `plaintext` buffer is zeroed/invalidated — a provider must never
        /// leave partially decrypted, unauthenticated output for the caller to
        /// read.
        aeadOpen: *const fn (
            context: *anyopaque,
            aead: Aead,
            key: []const u8,
            nonce: []const u8,
            associated_data: []const u8,
            ciphertext: []const u8,
            tag: []const u8,
            plaintext: []u8,
        ) OpenError!void,

        /// Generate an ephemeral key share for `group`. Writes the public value
        /// to `public_out` and the private scalar to `private_out` (both sized
        /// to the group). The private scalar is caller-owned; the caller wipes
        /// it after `deriveSharedSecret`.
        generateKeyShare: *const fn (
            context: *anyopaque,
            group: Group,
            public_out: []u8,
            private_out: []u8,
        ) KeyShareError!void,

        /// Derive the ECDH shared secret from our `private_scalar` and the
        /// peer's `peer_public`. Rejects invalid peer points as
        /// `error.InvalidInput`.
        deriveSharedSecret: *const fn (
            context: *anyopaque,
            group: Group,
            private_scalar: []const u8,
            peer_public: []const u8,
            out: []u8,
        ) DeriveError!void,

        /// Verify `signature` over `message` against `public_key` under
        /// `scheme`. `public_key` is the scheme's raw public encoding.
        verify: *const fn (
            context: *anyopaque,
            scheme: SignatureScheme,
            public_key: []const u8,
            message: []const u8,
            signature: []const u8,
        ) VerifyError!void,
    };

    pub fn capabilities(self: CryptoProvider) Capabilities {
        return self.vtable.capabilities(self.context);
    }

    /// Fill `buffer` with random bytes from the injected entropy source,
    /// classifying any failure as a provider error.
    pub fn randomBytes(self: CryptoProvider, buffer: []u8) RandomError!void {
        self.entropy.fill(buffer) catch return error.EntropyFailure;
    }

    pub fn hkdfExtract(self: CryptoProvider, hash: Hash, salt: []const u8, ikm: []const u8, out: []u8) HkdfError!void {
        return self.vtable.hkdfExtract(self.context, hash, salt, ikm, out);
    }

    pub fn hkdfExpandLabel(
        self: CryptoProvider,
        hash: Hash,
        secret: []const u8,
        label: []const u8,
        hash_context: []const u8,
        out: []u8,
    ) HkdfError!void {
        return self.vtable.hkdfExpandLabel(self.context, hash, secret, label, hash_context, out);
    }

    pub fn aeadSeal(
        self: CryptoProvider,
        aead: Aead,
        key: []const u8,
        nonce: []const u8,
        associated_data: []const u8,
        plaintext: []const u8,
        ciphertext: []u8,
        tag: []u8,
    ) SealError!void {
        return self.vtable.aeadSeal(self.context, aead, key, nonce, associated_data, plaintext, ciphertext, tag);
    }

    pub fn aeadOpen(
        self: CryptoProvider,
        aead: Aead,
        key: []const u8,
        nonce: []const u8,
        associated_data: []const u8,
        ciphertext: []const u8,
        tag: []const u8,
        plaintext: []u8,
    ) OpenError!void {
        return self.vtable.aeadOpen(self.context, aead, key, nonce, associated_data, ciphertext, tag, plaintext);
    }

    pub fn generateKeyShare(self: CryptoProvider, group: Group, public_out: []u8, private_out: []u8) KeyShareError!void {
        return self.vtable.generateKeyShare(self.context, group, public_out, private_out);
    }

    pub fn deriveSharedSecret(
        self: CryptoProvider,
        group: Group,
        private_scalar: []const u8,
        peer_public: []const u8,
        out: []u8,
    ) DeriveError!void {
        return self.vtable.deriveSharedSecret(self.context, group, private_scalar, peer_public, out);
    }

    pub fn verify(
        self: CryptoProvider,
        scheme: SignatureScheme,
        public_key: []const u8,
        message: []const u8,
        signature: []const u8,
    ) VerifyError!void {
        return self.vtable.verify(self.context, scheme, public_key, message, signature);
    }
};

// ---------------------------------------------------------------------------
// Algorithm-independent helpers
//
// Constant-time comparison and secure zeroing do not depend on which provider
// is in use, so they live here as free functions the whole stack shares rather
// than as per-provider vtable entries.
// ---------------------------------------------------------------------------

/// Compare two byte slices in constant time with respect to their contents.
/// The length check short-circuits (lengths are not secret), but for equal
/// lengths the running time is independent of where — or whether — the bytes
/// differ. Use this for MACs, Finished values, and any secret-derived tag.
pub fn constantTimeEqual(a: []const u8, b: []const u8) bool {
    return secrets.constantTimeEqual(a, b);
}

/// Overwrite `buffer` with zeros in a way the optimiser may not elide. Call
/// this on any stack or heap copy of secret material before it goes out of
/// scope.
pub fn secureZero(buffer: []u8) void {
    secrets.secureZero(buffer);
}

// ---------------------------------------------------------------------------
// Tests for the pure interface (no implementation required)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "algorithm metadata is self-consistent" {
    try testing.expectEqual(@as(usize, 32), Hash.sha256.digestLength());
    try testing.expectEqual(@as(usize, 48), Hash.sha384.digestLength());
    try testing.expect(Hash.sha384.digestLength() <= max_digest_len);

    try testing.expectEqual(@as(usize, 16), Aead.aes_128_gcm.keyLength());
    try testing.expectEqual(@as(usize, 32), Aead.aes_256_gcm.keyLength());
    try testing.expectEqual(@as(usize, 32), Aead.chacha20_poly1305.keyLength());
    inline for (.{ Aead.aes_128_gcm, Aead.aes_256_gcm, Aead.chacha20_poly1305 }) |aead| {
        try testing.expect(aead.keyLength() <= max_aead_key_len);
        try testing.expectEqual(aead_nonce_len, aead.nonceLength());
        try testing.expectEqual(aead_tag_len, aead.tagLength());
    }

    try testing.expect(Group.secp256r1.publicKeyLength() <= max_public_key_len);
    try testing.expect(Group.x25519.sharedSecretLength() <= max_shared_secret_len);
}

test "capability negotiation only selects supported algorithms" {
    var caps = Capabilities{};
    caps.aeads.insert(.aes_128_gcm);
    caps.aeads.insert(.chacha20_poly1305);

    try testing.expect(caps.supportsAead(.aes_128_gcm));
    try testing.expect(!caps.supportsAead(.aes_256_gcm));

    // Caller prefers AES-256 first, but the provider lacks it, so negotiation
    // falls through to the first supported preference.
    const prefer = [_]Aead{ .aes_256_gcm, .chacha20_poly1305, .aes_128_gcm };
    try testing.expectEqual(Aead.chacha20_poly1305, caps.selectAead(&prefer).?);

    // No overlap yields null rather than an arbitrary pick.
    const only_unsupported = [_]Aead{.aes_256_gcm};
    try testing.expectEqual(@as(?Aead, null), caps.selectAead(&only_unsupported));
}

test "constantTimeEqual matches semantic equality" {
    try testing.expect(constantTimeEqual("abcd", "abcd"));
    try testing.expect(!constantTimeEqual("abcd", "abce"));
    try testing.expect(!constantTimeEqual("abc", "abcd"));
    try testing.expect(constantTimeEqual("", ""));
}

test "secureZero clears a buffer" {
    var buf = [_]u8{0xAB} ** 16;
    secureZero(&buf);
    for (buf) |b| try testing.expectEqual(@as(u8, 0), b);
}

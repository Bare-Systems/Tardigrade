//! Pure-Zig `CryptoProvider` (#370, epic #327).
//!
//! Satisfies the `provider.CryptoProvider` boundary using only `std.crypto`
//! primitives — no external TLS/crypto library. This is the experimental
//! backend the epic grows alongside OpenSSL; it implements the native TLS/QUIC
//! profile and advertises exactly those provider capabilities, so anything
//! outside it is a typed `error.UnsupportedCapability` rather than a silent
//! gap.
//!
//! Implemented here (the overlap where a pure-Zig and an OpenSSL provider must
//! agree):
//!
//!   * HKDF-Extract / Expand-Label over SHA-256 and SHA-384
//!   * AEAD seal/open for AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//!   * QUIC header protection for AES-128, AES-256, and ChaCha20
//!   * X25519 and secp256r1 key-share generation and shared-secret derivation
//!   * Ed25519 signing (via `SoftwareSigningKey`) and verification
//!   * ECDSA-P256/SHA-256 signing (via
//!     `SoftwareEcdsaP256SigningKey`) and verification
//!   * RSA-PSS-RSAE/SHA-256 signing (via `SoftwareRsaSigningKey`) and
//!     verification
//!   * injected-entropy random bytes, constant-time compare, secure zero
//!
//! RSA-PSS-RSAE/SHA-256 verification and the private-key owner/signing path
//! are implemented in `rsa.zig` with strict DER, 2048/3072/4096-bit RSA
//! key-size, and EMSA-PSS validation.
//!
//! The provider never draws ambient randomness: it fills key-share scalars and
//! any per-signature noise from the `provider.Entropy` handed in at
//! construction, exactly like the rest of `src/quic/`.

const std = @import("std");
const crypto = std.crypto;
const provider = @import("provider.zig");
const profile = @import("profile.zig");
const rsa = @import("rsa.zig");
const secrets = @import("crypto_secrets");

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const Aes128 = crypto.core.aes.Aes128;
const Aes256 = crypto.core.aes.Aes256;
const ChaCha20IETF = crypto.stream.chacha.ChaCha20IETF;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;
const P256 = crypto.ecc.P256;
const P256Scalar = crypto.ecc.P256.scalar.Scalar;

const p256_keygen_attempts = 16;

/// The pure-Zig provider. Construct with an entropy source, then hand the
/// interface view to protocol code via `cryptoProvider`.
pub const Provider = struct {
    entropy: provider.Entropy,

    pub fn init(entropy: provider.Entropy) Provider {
        return .{ .entropy = entropy };
    }

    /// Erase to the boundary type. The returned view borrows `self`, so `self`
    /// must outlive every use of it. Takes a const pointer because no vtable
    /// entry mutates the provider; this lets comptime-constant `Provider`
    /// values (e.g. a package-default instance) erase without a runtime copy.
    pub fn cryptoProvider(self: *const Provider) provider.CryptoProvider {
        return .{ .context = @constCast(self), .vtable = &vtable, .entropy = self.entropy };
    }

    /// The static algorithm profile this backend advertises.
    pub fn capabilities() provider.Capabilities {
        var caps = provider.Capabilities{};
        caps.hashes.insert(.sha256);
        caps.hashes.insert(.sha384);
        caps.aeads.insert(.aes_128_gcm);
        caps.aeads.insert(.aes_256_gcm);
        caps.aeads.insert(.chacha20_poly1305);
        caps.quic_header_protection.insert(.aes_128);
        caps.quic_header_protection.insert(.aes_256);
        caps.quic_header_protection.insert(.chacha20);
        caps.groups.insert(.x25519);
        caps.groups.insert(.secp256r1);
        caps.signatures.insert(.ed25519);
        caps.signatures.insert(.ecdsa_secp256r1_sha256);
        caps.signatures.insert(.rsa_pss_rsae_sha256);
        caps.signatures.insert(.rsa_pkcs1_sha256);
        caps.signatures.insert(.rsa_pkcs1_sha384);
        return caps;
    }

    const vtable = provider.CryptoProvider.VTable{
        .capabilities = capabilitiesImpl,
        .hkdfExtract = hkdfExtractImpl,
        .hkdfExpandLabel = hkdfExpandLabelImpl,
        .aeadSeal = aeadSealImpl,
        .aeadOpen = aeadOpenImpl,
        .quicHeaderProtectionMask = quicHeaderProtectionMaskImpl,
        .generateKeyShare = generateKeyShareImpl,
        .deriveSharedSecret = deriveSharedSecretImpl,
        .verify = verifyImpl,
    };
};

// ---------------------------------------------------------------------------
// Capability discovery
// ---------------------------------------------------------------------------

fn capabilitiesImpl(context: *anyopaque) provider.Capabilities {
    _ = context;
    return Provider.capabilities();
}

// ---------------------------------------------------------------------------
// HKDF
// ---------------------------------------------------------------------------

fn hkdfExtractImpl(
    context: *anyopaque,
    hash: provider.Hash,
    salt: []const u8,
    ikm: []const u8,
    out: []u8,
) provider.HkdfError!void {
    _ = context;
    switch (hash) {
        .sha256 => return extractWith(HmacSha256, salt, ikm, out),
        .sha384 => return extractWith(HmacSha384, salt, ikm, out),
    }
}

fn extractWith(comptime Hmac: type, salt: []const u8, ikm: []const u8, out: []u8) provider.HkdfError!void {
    // HKDF-Extract(salt, IKM) = HMAC-Hash(key = salt, data = IKM). An empty
    // salt matches the RFC 5869 default of HashLen zero bytes, because HMAC
    // zero-pads its key to the block size either way.
    if (out.len != Hmac.mac_length) return error.InvalidInput;
    var prk: [Hmac.mac_length]u8 = undefined;
    Hmac.create(&prk, ikm, salt);
    @memcpy(out, &prk);
    secrets.secureZero(&prk);
}

fn hkdfExpandLabelImpl(
    context: *anyopaque,
    hash: provider.Hash,
    secret: []const u8,
    label: []const u8,
    hash_context: []const u8,
    out: []u8,
) provider.HkdfError!void {
    _ = context;
    switch (hash) {
        .sha256 => return expandLabelWith(HmacSha256, secret, label, hash_context, out),
        .sha384 => return expandLabelWith(HmacSha384, secret, label, hash_context, out),
    }
}

/// HKDF-Expand-Label (RFC 8446 §7.1) implemented over HMAC so it can write an
/// arbitrary runtime-length `out`. Cross-checked against
/// `std.crypto.tls.hkdfExpandLabel` in the tests below.
fn expandLabelWith(
    comptime Hmac: type,
    secret: []const u8,
    label: []const u8,
    context: []const u8,
    out: []u8,
) provider.HkdfError!void {
    const mac_len = Hmac.mac_length;
    if (secret.len != mac_len) return error.InvalidInput;

    const label_prefix = "tls13 ";
    const full_label_len = label_prefix.len + label.len;
    if (full_label_len > 255) return error.InvalidInput;
    if (context.len > 255) return error.InvalidInput;
    if (out.len == 0 or out.len > 255 * mac_len) return error.InvalidInput;

    // Build the HkdfLabel structure:
    //   uint16 length; opaque label<7..255>; opaque context<0..255>;
    var info: [2 + 1 + 255 + 1 + 255]u8 = undefined;
    var info_len: usize = 0;
    info[0] = @intCast((out.len >> 8) & 0xff);
    info[1] = @intCast(out.len & 0xff);
    info_len = 2;
    info[info_len] = @intCast(full_label_len);
    info_len += 1;
    @memcpy(info[info_len..][0..label_prefix.len], label_prefix);
    info_len += label_prefix.len;
    @memcpy(info[info_len..][0..label.len], label);
    info_len += label.len;
    info[info_len] = @intCast(context.len);
    info_len += 1;
    @memcpy(info[info_len..][0..context.len], context);
    info_len += context.len;
    const info_slice = info[0..info_len];

    var prk: [mac_len]u8 = undefined;
    @memcpy(&prk, secret);
    defer secrets.secureZero(&prk);

    // HKDF-Expand: T(i) = HMAC(PRK, T(i-1) || info || i), truncated to out.len.
    // Both `block` (a raw output block) and `message` (which carries T(i-1))
    // hold secret-derived material, so wipe them on every exit path.
    var block: [mac_len]u8 = undefined;
    var message: [mac_len + info.len + 1]u8 = undefined;
    defer secrets.secureZero(&block);
    defer secrets.secureZero(&message);
    var have_previous = false;
    var counter: usize = 1;
    var written: usize = 0;
    while (written < out.len) : (counter += 1) {
        var m: usize = 0;
        if (have_previous) {
            @memcpy(message[0..mac_len], &block);
            m = mac_len;
        }
        @memcpy(message[m..][0..info_slice.len], info_slice);
        m += info_slice.len;
        message[m] = @intCast(counter); // counter <= 255 by the guard above
        m += 1;
        Hmac.create(&block, message[0..m], &prk);
        const take = @min(mac_len, out.len - written);
        @memcpy(out[written..][0..take], block[0..take]);
        written += take;
        have_previous = true;
    }
}

// ---------------------------------------------------------------------------
// AEAD
// ---------------------------------------------------------------------------

fn aeadSealImpl(
    context: *anyopaque,
    aead: provider.Aead,
    key: []const u8,
    nonce: []const u8,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: []u8,
) provider.SealError!void {
    _ = context;
    switch (aead) {
        .aes_128_gcm => return sealWith(Aes128Gcm, key, nonce, associated_data, plaintext, ciphertext, tag),
        .aes_256_gcm => return sealWith(Aes256Gcm, key, nonce, associated_data, plaintext, ciphertext, tag),
        .chacha20_poly1305 => return sealWith(ChaCha20Poly1305, key, nonce, associated_data, plaintext, ciphertext, tag),
    }
}

fn sealWith(
    comptime Cipher: type,
    key: []const u8,
    nonce: []const u8,
    associated_data: []const u8,
    plaintext: []const u8,
    ciphertext: []u8,
    tag: []u8,
) provider.SealError!void {
    if (key.len != Cipher.key_length) return error.InvalidInput;
    if (nonce.len != Cipher.nonce_length) return error.InvalidInput;
    if (tag.len != Cipher.tag_length) return error.InvalidInput;
    if (ciphertext.len != plaintext.len) return error.InvalidInput;

    var k: [Cipher.key_length]u8 = undefined;
    var n: [Cipher.nonce_length]u8 = undefined;
    @memcpy(&k, key);
    @memcpy(&n, nonce);
    defer secrets.secureZero(&k);

    var t: [Cipher.tag_length]u8 = undefined;
    Cipher.encrypt(ciphertext, &t, plaintext, associated_data, n, k);
    @memcpy(tag, &t);
}

fn aeadOpenImpl(
    context: *anyopaque,
    aead: provider.Aead,
    key: []const u8,
    nonce: []const u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    plaintext: []u8,
) provider.OpenError!void {
    _ = context;
    switch (aead) {
        .aes_128_gcm => return openWith(Aes128Gcm, key, nonce, associated_data, ciphertext, tag, plaintext),
        .aes_256_gcm => return openWith(Aes256Gcm, key, nonce, associated_data, ciphertext, tag, plaintext),
        .chacha20_poly1305 => return openWith(ChaCha20Poly1305, key, nonce, associated_data, ciphertext, tag, plaintext),
    }
}

fn openWith(
    comptime Cipher: type,
    key: []const u8,
    nonce: []const u8,
    associated_data: []const u8,
    ciphertext: []const u8,
    tag: []const u8,
    plaintext: []u8,
) provider.OpenError!void {
    if (key.len != Cipher.key_length) return error.InvalidInput;
    if (nonce.len != Cipher.nonce_length) return error.InvalidInput;
    if (tag.len != Cipher.tag_length) return error.InvalidInput;
    if (plaintext.len != ciphertext.len) return error.InvalidInput;

    var k: [Cipher.key_length]u8 = undefined;
    var n: [Cipher.nonce_length]u8 = undefined;
    var t: [Cipher.tag_length]u8 = undefined;
    @memcpy(&k, key);
    @memcpy(&n, nonce);
    @memcpy(&t, tag);
    defer secrets.secureZero(&k);

    Cipher.decrypt(plaintext, ciphertext, t, associated_data, n, k) catch {
        // Never leak partial plaintext on authentication failure.
        secrets.secureZero(plaintext);
        return error.AuthenticationFailed;
    };
}

fn quicHeaderProtectionMaskImpl(
    context: *anyopaque,
    hp: provider.QuicHeaderProtection,
    key: []const u8,
    sample: []const u8,
    mask: []u8,
) provider.QuicHeaderProtectionError!void {
    _ = context;
    switch (hp) {
        .aes_128, .aes_256 => {
            if (key.len != hp.keyLength()) return error.InvalidInput;
            if (sample.len != provider.quic_header_protection_sample_len) return error.InvalidInput;
            if (mask.len != provider.quic_header_protection_mask_len) return error.InvalidInput;

            var k: [provider.max_aead_key_len]u8 = undefined;
            var s: [provider.quic_header_protection_sample_len]u8 = undefined;
            @memcpy(k[0..key.len], key);
            @memcpy(&s, sample);
            defer secrets.secureZero(&k);
            defer secrets.secureZero(&s);

            var block: [provider.quic_header_protection_sample_len]u8 = undefined;
            switch (hp) {
                .aes_128 => {
                    var aes = Aes128.initEnc(k[0..16].*);
                    defer secrets.secureZero(std.mem.asBytes(&aes));
                    aes.encrypt(&block, &s);
                },
                .aes_256 => {
                    var aes = Aes256.initEnc(k[0..32].*);
                    defer secrets.secureZero(std.mem.asBytes(&aes));
                    aes.encrypt(&block, &s);
                },
                .chacha20 => unreachable,
            }
            @memcpy(mask, block[0..provider.quic_header_protection_mask_len]);
            secrets.secureZero(&block);
        },
        .chacha20 => {
            if (key.len != provider.QuicHeaderProtection.chacha20.keyLength()) return error.InvalidInput;
            if (sample.len != provider.quic_header_protection_sample_len) return error.InvalidInput;
            if (mask.len != provider.quic_header_protection_mask_len) return error.InvalidInput;

            var k: [ChaCha20IETF.key_length]u8 = undefined;
            var nonce: [ChaCha20IETF.nonce_length]u8 = undefined;
            @memcpy(&k, key);
            @memcpy(&nonce, sample[4..16]);
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            defer secrets.secureZero(&k);
            defer secrets.secureZero(&nonce);

            var block: [ChaCha20IETF.block_length]u8 = undefined;
            ChaCha20IETF.stream(&block, counter, k, nonce);
            @memcpy(mask, block[0..provider.quic_header_protection_mask_len]);
            secrets.secureZero(&block);
        },
    }
}

// ---------------------------------------------------------------------------
// Key exchange
// ---------------------------------------------------------------------------

fn generateKeyShareImpl(
    context: *anyopaque,
    group: provider.Group,
    public_out: []u8,
    private_out: []u8,
) provider.KeyShareError!void {
    const self: *Provider = @ptrCast(@alignCast(context));
    switch (group) {
        .x25519 => {
            // A wrong-sized caller output buffer violates the output-slice
            // contract (see InputError); it is a caller bug, not an internal
            // provider failure, so classify it as InvalidInput.
            if (public_out.len != X25519.public_length) return error.InvalidInput;
            if (private_out.len != X25519.secret_length) return error.InvalidInput;

            var seed: [X25519.seed_length]u8 = undefined;
            // Register the wipe before filling, so a source that partially
            // fills and then fails does not leave seed bytes on the stack.
            defer secrets.secureZero(&seed);
            self.entropy.fill(&seed) catch return error.EntropyFailure;

            var key_pair = X25519.KeyPair.generateDeterministic(seed) catch return error.ProviderFailure;
            // The local key pair keeps a copy of the private scalar after it is
            // handed to the caller; scrub it on return.
            defer secrets.secureZero(&key_pair.secret_key);
            @memcpy(public_out, &key_pair.public_key);
            @memcpy(private_out, &key_pair.secret_key);
        },
        .secp256r1 => {
            if (public_out.len != provider.Group.secp256r1.publicKeyLength()) return error.InvalidInput;
            if (private_out.len != provider.max_private_scalar_len) return error.InvalidInput;

            var scalar_bytes: [provider.max_private_scalar_len]u8 = undefined;
            defer secrets.secureZero(&scalar_bytes);

            var attempts: usize = 0;
            while (attempts < p256_keygen_attempts) : (attempts += 1) {
                self.entropy.fill(&scalar_bytes) catch return error.EntropyFailure;
                _ = validateP256ScalarBytes(scalar_bytes) catch continue;

                var public_point = P256.basePoint.mul(scalar_bytes, .big) catch return error.ProviderFailure;
                defer secrets.secureZero(std.mem.asBytes(&public_point));
                const sec1 = public_point.toUncompressedSec1();
                @memcpy(public_out, &sec1);
                @memcpy(private_out, &scalar_bytes);
                return;
            }
            return error.EntropyFailure;
        },
    }
}

fn deriveSharedSecretImpl(
    context: *anyopaque,
    group: provider.Group,
    private_scalar: []const u8,
    peer_public: []const u8,
    out: []u8,
) provider.DeriveError!void {
    _ = context;
    switch (group) {
        .x25519 => {
            if (private_scalar.len != X25519.secret_length) return error.InvalidInput;
            if (peer_public.len != X25519.public_length) return error.InvalidInput;
            if (out.len != X25519.shared_length) return error.InvalidInput;

            var scalar: [X25519.secret_length]u8 = undefined;
            var point: [X25519.public_length]u8 = undefined;
            @memcpy(&scalar, private_scalar);
            @memcpy(&point, peer_public);
            defer secrets.secureZero(&scalar);

            // scalarmult rejects the low-order / all-zero points that would
            // yield an all-zero (identity) shared secret: peer input error.
            var shared = X25519.scalarmult(scalar, point) catch return error.InvalidInput;
            // The shared secret is a backend-created temporary; scrub our copy
            // once it has been handed to the caller.
            defer secrets.secureZero(&shared);
            @memcpy(out, &shared);
        },
        .secp256r1 => {
            if (private_scalar.len != provider.max_private_scalar_len) return error.InvalidInput;
            if (peer_public.len != provider.Group.secp256r1.publicKeyLength()) return error.InvalidInput;
            if (out.len != provider.Group.secp256r1.sharedSecretLength()) return error.InvalidInput;
            if (peer_public[0] != 0x04) return error.InvalidInput;

            var scalar: [provider.max_private_scalar_len]u8 = undefined;
            @memcpy(&scalar, private_scalar);
            defer secrets.secureZero(&scalar);
            try validateP256ScalarBytes(scalar);

            var peer = P256.fromSec1(peer_public) catch return error.InvalidInput;
            defer secrets.secureZero(std.mem.asBytes(&peer));
            peer.rejectIdentity() catch return error.InvalidInput;
            const canonical = peer.toUncompressedSec1();
            if (!std.mem.eql(u8, &canonical, peer_public)) return error.InvalidInput;

            var shared_point = peer.mul(scalar, .big) catch return error.InvalidInput;
            defer secrets.secureZero(std.mem.asBytes(&shared_point));
            var affine = shared_point.affineCoordinates();
            defer secrets.secureZero(std.mem.asBytes(&affine));
            var shared_x = affine.x.toBytes(.big);
            defer secrets.secureZero(&shared_x);
            @memcpy(out, &shared_x);
        },
    }
}

fn validateP256ScalarBytes(bytes: [provider.max_private_scalar_len]u8) provider.InputError!void {
    var scalar = P256Scalar.fromBytes(bytes, .big) catch return error.InvalidInput;
    defer secrets.secureZero(std.mem.asBytes(&scalar));
    if (scalar.isZero()) return error.InvalidInput;
}

// ---------------------------------------------------------------------------
// Signature verification
// ---------------------------------------------------------------------------

fn verifyImpl(
    context: *anyopaque,
    scheme: provider.SignatureScheme,
    public_key: []const u8,
    message: []const u8,
    signature: []const u8,
) provider.VerifyError!void {
    _ = context;
    switch (scheme) {
        .ed25519 => {
            // Malformed/invalid *public-key* material is `InvalidInput` — the
            // caller's certificate is structurally defective, distinct from a
            // proof-of-possession failure. A malformed *signature* encoding
            // is `AuthenticationFailed`, not `InvalidInput` (#490 review): a
            // signature that cannot even be parsed is, per RFC 8446 §4.4.3,
            // the same `decrypt_error` outcome as one that parses but does
            // not verify — TLS does not distinguish "your signature bytes
            // are the wrong shape" from "your signature bytes are wrong" the
            // way it distinguishes a bad key from a bad signature.
            if (public_key.len != Ed25519.PublicKey.encoded_length) return error.InvalidInput;
            const pk = Ed25519.PublicKey.fromBytes(public_key[0..Ed25519.PublicKey.encoded_length].*) catch
                return error.InvalidInput;
            if (signature.len != Ed25519.Signature.encoded_length) return error.AuthenticationFailed;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            sig.verify(message, pk) catch return error.AuthenticationFailed;
        },
        .ecdsa_secp256r1_sha256 => {
            // `public_key` is the SEC1 point (uncompressed 0x04||X||Y or
            // compressed); `signature` is the DER SEQUENCE { r, s } used by
            // both TLS CertificateVerify and X.509. Same split as Ed25519
            // above: a malformed key is `InvalidInput`, a malformed
            // signature DER encoding is `AuthenticationFailed` (not
            // `InvalidInput`), matching a well-formed-but-wrong signature.
            // `src/pki/verify.zig`'s chain-signature path is unaffected: it
            // pre-validates DER signature structure itself
            // (`validateEcdsaDerSignature`) before ever calling this, so a
            // malformed signature never reaches this function from that
            // caller in the first place.
            const pk = EcdsaP256Sha256.PublicKey.fromSec1(public_key) catch return error.InvalidInput;
            const sig = EcdsaP256Sha256.Signature.fromDer(signature) catch return error.AuthenticationFailed;
            sig.verify(message, pk) catch return error.AuthenticationFailed;
        },
        .rsa_pss_rsae_sha256 => {
            try rsa.verifyPssSha256(public_key, message, signature);
        },
        // Certificate-chain signature verification only (#645): reachable
        // from src/pki/verify.zig, never from TLS 1.3 CertificateVerify
        // (src/tls/crypto_profile.zig's supportsSignatureScheme refuses to
        // advertise or select rsa_pkcs1 schemes there regardless of this
        // provider capability).
        .rsa_pkcs1_sha256 => {
            try rsa.verifyPkcs1v15Sha256(public_key, message, signature);
        },
        .rsa_pkcs1_sha384 => {
            try rsa.verifyPkcs1v15Sha384(public_key, message, signature);
        },
    }
}

// ---------------------------------------------------------------------------
// Software signing key (opaque private-key handle)
// ---------------------------------------------------------------------------

/// A software Ed25519 signing key. Produces a `provider.SigningKey` whose
/// private material lives inside this value; keep it alive for as long as the
/// handle is used, and call `deinit` to erase the private key when retiring it
/// — Zig does not zero a value's bytes on scope exit, so dropping it is not
/// enough. A future HSM/remote signer implements the same `provider.SigningKey`
/// vtable without the TLS engine noticing.
pub const SoftwareSigningKey = struct {
    key_pair: Ed25519.KeyPair,

    /// Load from a 32-byte Ed25519 seed (RFC 8032 secret scalar seed).
    /// General-purpose entry point for callers (tests, fixtures) that do not
    /// carry the seed in a typed secret container; production callers
    /// holding one should prefer `fromSeedSecret` instead, which avoids this
    /// by-value parameter's own caller-side copy.
    pub fn fromSeed(seed: [Ed25519.KeyPair.seed_length]u8) provider.SignError!SoftwareSigningKey {
        // The by-value parameter is itself a caller-owned copy of secret seed
        // bytes; wipe this frame's copy once the deterministic key pair has
        // been derived from it, matching the wipe-after-use pattern used for
        // key-share seeds elsewhere in this file.
        var local_seed = seed;
        defer secrets.secureZero(&local_seed);
        const key_pair = Ed25519.KeyPair.generateDeterministic(local_seed) catch return error.ProviderFailure;
        return .{ .key_pair = key_pair };
    }

    /// Load from a seed already held in a typed `secrets.FixedSecret`
    /// container (#372), consuming and clearing it. This is the narrow
    /// bridge a caller with typed secret ownership should use instead of
    /// `fromSeed`: `seed`'s bytes are copied exactly once into a scoped
    /// local wiped in the same function, `seed` itself is cleared before
    /// key derivation runs, and no other by-value copy of the caller's seed
    /// is created at this boundary.
    pub fn fromSeedSecret(seed: *secrets.FixedSecret(Ed25519.KeyPair.seed_length)) provider.SignError!SoftwareSigningKey {
        var bridge: [Ed25519.KeyPair.seed_length]u8 = undefined;
        defer secrets.secureZero(&bridge);
        @memcpy(&bridge, seed.slice());
        seed.deinit();
        const key_pair = Ed25519.KeyPair.generateDeterministic(bridge) catch return error.ProviderFailure;
        return .{ .key_pair = key_pair };
    }

    /// Securely erase the private key material. Callers must invoke this when
    /// the key is no longer needed; letting the value go out of scope does not
    /// scrub its bytes.
    pub fn deinit(self: *SoftwareSigningKey) void {
        secrets.secureZero(&self.key_pair.secret_key.bytes);
    }

    pub fn format(
        _: SoftwareSigningKey,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("signing keys must not be formatted or logged");
    }

    /// Raw 32-byte Ed25519 public key, for pinning or CertificateVerify checks.
    pub fn publicKey(self: *const SoftwareSigningKey) [Ed25519.PublicKey.encoded_length]u8 {
        return self.key_pair.public_key.toBytes();
    }

    /// Erase to the opaque signing-key interface. Borrows `self`.
    pub fn signingKey(self: *SoftwareSigningKey) provider.SigningKey {
        return .{ .context = self, .vtable = &signing_vtable };
    }

    const signing_vtable = provider.SigningKey.VTable{
        .scheme = signingSchemeImpl,
        .sign = signingSignImpl,
    };

    fn signingSchemeImpl(context: *anyopaque) provider.SignatureScheme {
        _ = context;
        return .ed25519;
    }

    fn signingSignImpl(
        context: *anyopaque,
        message: []const u8,
        entropy: provider.Entropy,
        out: []u8,
    ) provider.SignError!usize {
        _ = entropy; // Ed25519 signatures are deterministic (RFC 8032); no noise needed.
        const self: *SoftwareSigningKey = @ptrCast(@alignCast(context));
        if (out.len < Ed25519.Signature.encoded_length) return error.InvalidInput;
        const signature = self.key_pair.sign(message, null) catch return error.ProviderFailure;
        const bytes = signature.toBytes();
        @memcpy(out[0..bytes.len], &bytes);
        return bytes.len;
    }
};

// ---------------------------------------------------------------------------
// Software signing key (opaque private-key handle) — ECDSA-P256/SHA-256
// ---------------------------------------------------------------------------

/// A software ECDSA-P256/SHA-256 signing key, the P-256 sibling of
/// `SoftwareSigningKey` (#490): TLS `credentials.zig` holds one of these (or
/// the Ed25519 variant) behind the opaque `provider.SigningKey` handle rather
/// than a raw `std.crypto.sign.ecdsa.EcdsaP256Sha256.KeyPair`, so private-key
/// bytes never cross into `Identity.sign`'s caller. Same lifetime contract as
/// `SoftwareSigningKey`: keep it alive for as long as the handle is used and
/// call `deinit` explicitly — Zig does not zero a value's bytes on scope exit.
pub const SoftwareEcdsaP256SigningKey = struct {
    key_pair: EcdsaP256Sha256.KeyPair,

    /// Deterministically derive a P-256 key pair from fixture seed material.
    /// This mirrors `std.crypto`'s deterministic constructor while wiping this
    /// frame's seed copy after derivation.
    pub fn fromSeed(seed: [EcdsaP256Sha256.KeyPair.seed_length]u8) provider.SignError!SoftwareEcdsaP256SigningKey {
        var local_seed = seed;
        defer secrets.secureZero(&local_seed);
        const key_pair = EcdsaP256Sha256.KeyPair.generateDeterministic(local_seed) catch return error.ProviderFailure;
        return .{ .key_pair = key_pair };
    }

    /// Load from a seed already held in a typed secret container, consuming
    /// and clearing it before key derivation.
    pub fn fromSeedSecret(seed: *secrets.FixedSecret(EcdsaP256Sha256.KeyPair.seed_length)) provider.SignError!SoftwareEcdsaP256SigningKey {
        defer seed.deinit();
        if (seed.len != EcdsaP256Sha256.KeyPair.seed_length) return error.InvalidInput;
        var bridge: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
        defer secrets.secureZero(&bridge);
        @memcpy(&bridge, seed.slice());
        seed.deinit();
        const key_pair = EcdsaP256Sha256.KeyPair.generateDeterministic(bridge) catch return error.ProviderFailure;
        return .{ .key_pair = key_pair };
    }

    /// Load a raw 32-byte P-256 private scalar, rejecting malformed,
    /// zero-valued, and non-canonical/out-of-range material before deriving
    /// the retained key pair.
    pub fn fromScalarBytes(scalar: []const u8) provider.SignError!SoftwareEcdsaP256SigningKey {
        if (scalar.len != EcdsaP256Sha256.SecretKey.encoded_length) return error.InvalidInput;
        var local_scalar: [EcdsaP256Sha256.SecretKey.encoded_length]u8 = undefined;
        defer secrets.secureZero(&local_scalar);
        @memcpy(&local_scalar, scalar);
        var secret_key = try validatedSecretKey(local_scalar);
        defer secrets.secureZero(&secret_key.bytes);
        return deriveValidatedSecretKey(&secret_key);
    }

    /// Load a raw scalar from typed secret storage, consuming and clearing the
    /// source container before key derivation.
    pub fn fromScalarSecret(scalar: *secrets.FixedSecret(EcdsaP256Sha256.SecretKey.encoded_length)) provider.SignError!SoftwareEcdsaP256SigningKey {
        defer scalar.deinit();
        if (scalar.len != EcdsaP256Sha256.SecretKey.encoded_length) return error.InvalidInput;
        var bridge: [EcdsaP256Sha256.SecretKey.encoded_length]u8 = undefined;
        defer secrets.secureZero(&bridge);
        @memcpy(&bridge, scalar.slice());
        scalar.deinit();
        var secret_key = try validatedSecretKey(bridge);
        defer secrets.secureZero(&secret_key.bytes);
        return deriveValidatedSecretKey(&secret_key);
    }

    /// Load from an already-parsed P-256 private scalar, consuming and wiping
    /// the caller-owned typed secret before returning.
    pub fn fromSecretKey(secret_key: *EcdsaP256Sha256.SecretKey) provider.SignError!SoftwareEcdsaP256SigningKey {
        defer secrets.secureZero(&secret_key.bytes);
        try validateScalarBytes(secret_key.bytes);
        return deriveValidatedSecretKey(secret_key);
    }

    fn deriveValidatedSecretKey(secret_key: *const EcdsaP256Sha256.SecretKey) provider.SignError!SoftwareEcdsaP256SigningKey {
        const key_pair = EcdsaP256Sha256.KeyPair.fromSecretKey(secret_key.*) catch return error.ProviderFailure;
        return .{ .key_pair = key_pair };
    }

    fn validatedSecretKey(bytes: [EcdsaP256Sha256.SecretKey.encoded_length]u8) provider.SignError!EcdsaP256Sha256.SecretKey {
        try validateScalarBytes(bytes);
        return EcdsaP256Sha256.SecretKey.fromBytes(bytes) catch return error.InvalidInput;
    }

    fn validateScalarBytes(bytes: [EcdsaP256Sha256.SecretKey.encoded_length]u8) provider.SignError!void {
        var non_zero: u8 = 0;
        for (bytes) |byte| non_zero |= byte;
        if (non_zero == 0) return error.InvalidInput;
        _ = P256Scalar.fromBytes(bytes, .big) catch return error.InvalidInput;
    }

    /// Securely erase the private key material. Callers must invoke this when
    /// the key is no longer needed; letting the value go out of scope does not
    /// scrub its bytes.
    pub fn deinit(self: *SoftwareEcdsaP256SigningKey) void {
        secrets.secureZero(&self.key_pair.secret_key.bytes);
    }

    pub fn format(
        _: SoftwareEcdsaP256SigningKey,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("signing keys must not be formatted or logged");
    }

    /// Raw SEC1 uncompressed public key, for pinning or diagnostics.
    pub fn publicKeySec1(self: *const SoftwareEcdsaP256SigningKey) [EcdsaP256Sha256.PublicKey.uncompressed_sec1_encoded_length]u8 {
        return self.key_pair.public_key.toUncompressedSec1();
    }

    /// Erase to the opaque signing-key interface. Borrows `self`.
    pub fn signingKey(self: *SoftwareEcdsaP256SigningKey) provider.SigningKey {
        return .{ .context = self, .vtable = &signing_vtable };
    }

    const signing_vtable = provider.SigningKey.VTable{
        .scheme = signingSchemeImpl,
        .sign = signingSignImpl,
    };

    fn signingSchemeImpl(context: *anyopaque) provider.SignatureScheme {
        _ = context;
        return .ecdsa_secp256r1_sha256;
    }

    fn signingSignImpl(
        context: *anyopaque,
        message: []const u8,
        entropy: provider.Entropy,
        out: []u8,
    ) provider.SignError!usize {
        const self: *SoftwareEcdsaP256SigningKey = @ptrCast(@alignCast(context));
        if (out.len < EcdsaP256Sha256.Signature.der_encoded_length_max) return error.InvalidInput;

        var noise: [EcdsaP256Sha256.noise_length]u8 = undefined;
        defer secrets.secureZero(&noise);
        entropy.fill(&noise) catch return error.EntropyFailure;

        const signature = self.key_pair.sign(message, noise) catch return error.ProviderFailure;
        var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
        defer secrets.secureZero(&der_buf);
        const der = signature.toDer(&der_buf);
        @memcpy(out[0..der.len], der);
        return der.len;
    }
};

/// A software RSA-PSS-RSAE-SHA256 signing key. Produces a `provider.SigningKey`
/// whose private state is `rsa.PrivateKey`: only the modulus and private
/// exponent are retained (see that type's doc comment for why the CRT
/// components are validated but not kept). Same lifetime contract as
/// `SoftwareEcdsaP256SigningKey`: keep it alive for as long as the handle is
/// used and call `deinit` explicitly.
pub const SoftwareRsaSigningKey = struct {
    key: rsa.PrivateKey,

    /// Parse and validate a PKCS#1 `RSAPrivateKey` DER encoding. `entropy`
    /// draws the random Miller-Rabin witnesses used to verify `p`/`q` are
    /// actually prime (see `rsa.parsePrivateKeyDer`) — a one-time draw at
    /// key import, not on the per-signature path.
    pub fn fromDer(der: []const u8, entropy: provider.Entropy) provider.SignError!SoftwareRsaSigningKey {
        const key = rsa.parsePrivateKeyDer(der, entropy) catch |err| return switch (err) {
            error.InvalidInput => error.InvalidInput,
            error.EntropyFailure => error.EntropyFailure,
        };
        return .{ .key = key };
    }

    /// Securely erase the private key material. Callers must invoke this when
    /// the key is no longer needed; letting the value go out of scope does not
    /// scrub its bytes.
    pub fn deinit(self: *SoftwareRsaSigningKey) void {
        self.key.deinit();
    }

    /// Whether `public_key_der` (a DER `RSAPublicKey`) is the exact public
    /// counterpart of this private key — see `rsa.PrivateKey.
    /// matchesPublicKeyDer`.
    pub fn matchesPublicKeyDer(self: *const SoftwareRsaSigningKey, public_key_der: []const u8) bool {
        return self.key.matchesPublicKeyDer(public_key_der);
    }

    pub fn format(
        _: SoftwareRsaSigningKey,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        _: anytype,
    ) !void {
        @compileError("signing keys must not be formatted or logged");
    }

    /// Erase to the opaque signing-key interface. Borrows `self`.
    pub fn signingKey(self: *SoftwareRsaSigningKey) provider.SigningKey {
        return .{ .context = self, .vtable = &signing_vtable };
    }

    const signing_vtable = provider.SigningKey.VTable{
        .scheme = signingSchemeImpl,
        .sign = signingSignImpl,
    };

    fn signingSchemeImpl(context: *anyopaque) provider.SignatureScheme {
        _ = context;
        return .rsa_pss_rsae_sha256;
    }

    fn signingSignImpl(
        context: *anyopaque,
        message: []const u8,
        entropy: provider.Entropy,
        out: []u8,
    ) provider.SignError!usize {
        const self: *SoftwareRsaSigningKey = @ptrCast(@alignCast(context));
        if (out.len < self.key.modulusLen()) return error.InvalidInput;

        var salt: [rsa.pss_salt_len]u8 = undefined;
        defer secrets.secureZero(&salt);
        entropy.fill(&salt) catch return error.EntropyFailure;

        return rsa.signPssSha256(&self.key, message, salt, out) catch return error.InvalidInput;
    }
};

// ---------------------------------------------------------------------------
// Deterministic entropy (tests and reproducible flows)
// ---------------------------------------------------------------------------

/// A seedable, deterministic byte source built on splitmix64. It is **not** a
/// CSPRNG and must never back a production provider; it exists so tests and
/// reproducible fixtures can inject predictable "randomness" through the same
/// `provider.Entropy` seam the OS CSPRNG uses in production.
pub const DeterministicEntropy = struct {
    state: u64,

    pub fn init(seed: u64) DeterministicEntropy {
        return .{ .state = seed };
    }

    pub fn entropy(self: *DeterministicEntropy) provider.Entropy {
        return .{ .context = self, .fillFn = fillImpl };
    }

    fn fillImpl(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
        const self: *DeterministicEntropy = @ptrCast(@alignCast(context));
        for (buffer) |*byte| {
            self.state +%= 0x9E3779B97F4A7C15;
            var z = self.state;
            z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
            z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
            z = z ^ (z >> 31);
            byte.* = @truncate(z);
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hexBytes(comptime hex: []const u8) [hex.len / 2]u8 {
    var bytes: [hex.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&bytes, hex) catch unreachable;
    return bytes;
}

test "capabilities advertise exactly the implemented profile" {
    const caps = Provider.capabilities();
    const profiled = profile.capabilities(.pure_zig);
    try testing.expectEqual(caps.hashes, profiled.hashes);
    try testing.expectEqual(caps.aeads, profiled.aeads);
    try testing.expectEqual(caps.quic_header_protection, profiled.quic_header_protection);
    try testing.expectEqual(caps.groups, profiled.groups);
    try testing.expectEqual(caps.signatures, profiled.signatures);
    try testing.expect(caps.supportsHash(.sha256));
    try testing.expect(caps.supportsHash(.sha384));
    try testing.expect(caps.supportsAead(.aes_128_gcm));
    try testing.expect(caps.supportsAead(.aes_256_gcm));
    try testing.expect(caps.supportsAead(.chacha20_poly1305));
    try testing.expect(caps.supportsQuicHeaderProtection(.aes_128));
    try testing.expect(caps.supportsQuicHeaderProtection(.aes_256));
    try testing.expect(caps.supportsQuicHeaderProtection(.chacha20));
    try testing.expect(caps.supportsGroup(.x25519));
    try testing.expect(caps.supportsGroup(.secp256r1));
    try testing.expect(caps.supportsSignature(.ed25519));
    try testing.expect(caps.supportsSignature(.ecdsa_secp256r1_sha256));
    try testing.expect(caps.supportsSignature(.rsa_pss_rsae_sha256));
    try testing.expect(caps.supportsSignature(.rsa_pkcs1_sha256));
    try testing.expect(caps.supportsSignature(.rsa_pkcs1_sha384));
}

test "QUIC AES header protection mask matches std.crypto directly" {
    var det = DeterministicEntropy.init(9);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    const key = [_]u8{0x11} ** 16;
    const sample = [_]u8{0x22} ** provider.quic_header_protection_sample_len;

    const aes = Aes128.initEnc(key);
    var block: [provider.quic_header_protection_sample_len]u8 = undefined;
    aes.encrypt(&block, &sample);

    var mask: [provider.quic_header_protection_mask_len]u8 = undefined;
    try cp.quicHeaderProtectionMask(.aes_128, &key, &sample, &mask);
    try testing.expectEqualSlices(u8, block[0..provider.quic_header_protection_mask_len], &mask);
    try testing.expectError(error.InvalidInput, cp.quicHeaderProtectionMask(.aes_128, key[0..15], &sample, &mask));
}

test "QUIC AES-256 and ChaCha20 header protection masks match std.crypto directly" {
    var det = DeterministicEntropy.init(10);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    const aes_key = [_]u8{0x33} ** 32;
    const aes_sample = [_]u8{0x44} ** provider.quic_header_protection_sample_len;
    const aes = Aes256.initEnc(aes_key);
    var aes_block: [provider.quic_header_protection_sample_len]u8 = undefined;
    aes.encrypt(&aes_block, &aes_sample);

    var aes_mask: [provider.quic_header_protection_mask_len]u8 = undefined;
    try cp.quicHeaderProtectionMask(.aes_256, &aes_key, &aes_sample, &aes_mask);
    try testing.expectEqualSlices(u8, aes_block[0..provider.quic_header_protection_mask_len], &aes_mask);
    try testing.expectError(error.InvalidInput, cp.quicHeaderProtectionMask(.aes_256, aes_key[0..31], &aes_sample, &aes_mask));

    const chacha_key = [_]u8{0x55} ** 32;
    const chacha_sample = hexBytes("01000000aabbccddeeff001122334455");
    const counter = std.mem.readInt(u32, chacha_sample[0..4], .little);
    const nonce = chacha_sample[4..16].*;
    var stream_block: [ChaCha20IETF.block_length]u8 = undefined;
    ChaCha20IETF.stream(&stream_block, counter, chacha_key, nonce);

    var chacha_mask: [provider.quic_header_protection_mask_len]u8 = undefined;
    try cp.quicHeaderProtectionMask(.chacha20, &chacha_key, &chacha_sample, &chacha_mask);
    try testing.expectEqualSlices(u8, stream_block[0..provider.quic_header_protection_mask_len], &chacha_mask);
    try testing.expectError(error.InvalidInput, cp.quicHeaderProtectionMask(.chacha20, &chacha_key, chacha_sample[0..15], &chacha_mask));
}

test "unsupported algorithms return UnsupportedCapability, not undefined behaviour" {
    var det = DeterministicEntropy.init(1);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    // Malformed RSA-PSS inputs are rejected as ordinary input errors.
    var sig: [8]u8 = @splat(0);
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pss_rsae_sha256, &sig, "m", &sig));
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pss_rsae_sha256, "", "m", ""));
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pss_rsae_sha256, "\x30", "m", "\x00"));
}

test "provider verify wires RSA PKCS#1 v1.5 to the rsa.zig primitive for certificate-chain use" {
    var det = DeterministicEntropy.init(1);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    try cp.verify(.rsa_pkcs1_sha256, rsa.testdata.public_key_der, rsa.testdata.pkcs1_message, rsa.testdata.pkcs1_signature_sha256);
    try testing.expectError(
        error.AuthenticationFailed,
        cp.verify(.rsa_pkcs1_sha256, rsa.testdata.public_key_der, "tampered message", rsa.testdata.pkcs1_signature_sha256),
    );

    try cp.verify(.rsa_pkcs1_sha384, rsa.testdata.public_key_der, rsa.testdata.pkcs1_message, rsa.testdata.pkcs1_signature_sha384);
    try testing.expectError(
        error.AuthenticationFailed,
        cp.verify(.rsa_pkcs1_sha384, rsa.testdata.public_key_der, "tampered message", rsa.testdata.pkcs1_signature_sha384),
    );

    // Malformed inputs are ordinary input errors, same taxonomy as RSA-PSS.
    var sig: [8]u8 = @splat(0);
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pkcs1_sha256, &sig, "m", &sig));
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pkcs1_sha256, "", "m", ""));
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pkcs1_sha256, "\x30", "m", "\x00"));
}

test "ECDSA-P256 verification round-trips and rejects tamper and wrong key" {
    var det = DeterministicEntropy.init(7);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    try cp.randomBytes(&seed);
    const kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    const message = "x509 tbs certificate bytes";
    const sig = try kp.sign(message, null);
    var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const der_sig = sig.toDer(&der_buf);
    const sec1 = kp.public_key.toUncompressedSec1();

    try cp.verify(.ecdsa_secp256r1_sha256, &sec1, message, der_sig);
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &sec1, "tampered", der_sig));

    var other_seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    try cp.randomBytes(&other_seed);
    const other = try EcdsaP256Sha256.KeyPair.generateDeterministic(other_seed);
    const other_sec1 = other.public_key.toUncompressedSec1();
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &other_sec1, message, der_sig));
}

test "ECDSA-P256 verification rejects malformed encodings" {
    var det = DeterministicEntropy.init(1);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    // Not a valid SEC1 point / DER signature.
    var junk: [8]u8 = @splat(0);
    try testing.expectError(error.InvalidInput, cp.verify(.ecdsa_secp256r1_sha256, &junk, "m", &junk));
    // Empty and one-byte slices must not fault the underlying parsers.
    try testing.expectError(error.InvalidInput, cp.verify(.ecdsa_secp256r1_sha256, "", "m", ""));
    try testing.expectError(error.InvalidInput, cp.verify(.ecdsa_secp256r1_sha256, "\x04", "m", "\x30"));
}

test "HKDF-Extract matches std.crypto.kdf.hkdf" {
    var det = DeterministicEntropy.init(2);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    const salt = "salty";
    const ikm = [_]u8{0xAB} ** 40;

    const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    const expected = HkdfSha256.extract(salt, &ikm);
    var out: [32]u8 = undefined;
    try cp.hkdfExtract(.sha256, salt, &ikm, &out);
    try testing.expectEqualSlices(u8, &expected, &out);
}

test "HKDF-Expand-Label matches std.crypto.tls" {
    var det = DeterministicEntropy.init(3);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    const HkdfSha256 = crypto.kdf.hkdf.HkdfSha256;
    const secret = [_]u8{0x01} ** 32;

    // A QUIC key derivation with empty context, and a longer output that spans
    // two HKDF blocks, both cross-checked against the standard library.
    const expected_key = crypto.tls.hkdfExpandLabel(HkdfSha256, secret, "quic key", "", 16);
    var key: [16]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &secret, "quic key", "", &key);
    try testing.expectEqualSlices(u8, &expected_key, &key);

    const context = [_]u8{0x99} ** 32;
    const expected_long = crypto.tls.hkdfExpandLabel(HkdfSha256, secret, "derived", &context, 40);
    var long: [40]u8 = undefined;
    try cp.hkdfExpandLabel(.sha256, &secret, "derived", &context, &long);
    try testing.expectEqualSlices(u8, &expected_long, &long);
}

test "AEAD seal then open round-trips for every supported cipher" {
    var det = DeterministicEntropy.init(4);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    const plaintext = "the tardigrade survives the vacuum of space";
    const associated_data = "quic header";

    inline for (.{ provider.Aead.aes_128_gcm, provider.Aead.aes_256_gcm, provider.Aead.chacha20_poly1305 }) |aead| {
        var key = [_]u8{0} ** 32;
        var nonce = [_]u8{0} ** provider.aead_nonce_len;
        try cp.randomBytes(key[0..aead.keyLength()]);
        try cp.randomBytes(&nonce);

        var ciphertext: [plaintext.len]u8 = undefined;
        var tag: [provider.aead_tag_len]u8 = undefined;
        try cp.aeadSeal(aead, key[0..aead.keyLength()], &nonce, associated_data, plaintext, &ciphertext, &tag);

        var recovered: [plaintext.len]u8 = undefined;
        try cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, associated_data, &ciphertext, &tag, &recovered);
        try testing.expectEqualSlices(u8, plaintext, &recovered);

        // A single flipped ciphertext bit must fail authentication, and the
        // output buffer must be zeroed rather than left holding unauthenticated
        // plaintext (the documented open contract).
        var tampered = ciphertext;
        tampered[0] ^= 0x01;
        try testing.expectError(
            error.AuthenticationFailed,
            cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, associated_data, &tampered, &tag, &recovered),
        );
        for (recovered) |byte| try testing.expectEqual(@as(u8, 0), byte);

        // Mismatched associated data must also fail.
        try testing.expectError(
            error.AuthenticationFailed,
            cp.aeadOpen(aead, key[0..aead.keyLength()], &nonce, "wrong ad", &ciphertext, &tag, &recovered),
        );
    }
}

test "X25519 key shares agree and match std directly" {
    var det = DeterministicEntropy.init(5);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    var a_pub: [32]u8 = undefined;
    var a_priv: [32]u8 = undefined;
    var b_pub: [32]u8 = undefined;
    var b_priv: [32]u8 = undefined;
    try cp.generateKeyShare(.x25519, &a_pub, &a_priv);
    try cp.generateKeyShare(.x25519, &b_pub, &b_priv);

    var a_shared: [32]u8 = undefined;
    var b_shared: [32]u8 = undefined;
    try cp.deriveSharedSecret(.x25519, &a_priv, &b_pub, &a_shared);
    try cp.deriveSharedSecret(.x25519, &b_priv, &a_pub, &b_shared);
    try testing.expectEqualSlices(u8, &a_shared, &b_shared);

    const direct = try X25519.scalarmult(a_priv, b_pub);
    try testing.expectEqualSlices(u8, &direct, &a_shared);
}

test "X25519 rejects an all-zero (low-order) peer point as InvalidInput" {
    var det = DeterministicEntropy.init(6);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    var a_pub: [32]u8 = undefined;
    var a_priv: [32]u8 = undefined;
    try cp.generateKeyShare(.x25519, &a_pub, &a_priv);

    const zero_point = [_]u8{0} ** 32;
    var out: [32]u8 = undefined;
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.x25519, &a_priv, &zero_point, &out));
}

test "secp256r1 fixed scalar vector derives affine X coordinate" {
    var det = DeterministicEntropy.init(563);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    const scalar_one = [_]u8{0} ** 31 ++ [_]u8{1};
    const base_point = hexBytes("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    const scalar_two_public = hexBytes("047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1");
    const expected_shared = hexBytes("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978");

    var shared: [provider.max_shared_secret_len]u8 = undefined;
    try cp.deriveSharedSecret(.secp256r1, &scalar_one, &scalar_two_public, &shared);
    try testing.expectEqualSlices(u8, &expected_shared, &shared);

    var base_shared: [provider.max_shared_secret_len]u8 = undefined;
    try cp.deriveSharedSecret(.secp256r1, &scalar_one, &base_point, &base_shared);
    try testing.expectEqualSlices(u8, base_point[1..33], &base_shared);
}

test "secp256r1 generated key shares are deterministic and symmetric" {
    var alice_entropy = DeterministicEntropy.init(0x563);
    var alice_provider = Provider.init(alice_entropy.entropy());
    const alice_cp = alice_provider.cryptoProvider();
    var bob_entropy = DeterministicEntropy.init(0x564);
    var bob_provider = Provider.init(bob_entropy.entropy());
    const bob_cp = bob_provider.cryptoProvider();

    var alice_pub: [65]u8 = undefined;
    var alice_priv: [32]u8 = undefined;
    var bob_pub: [65]u8 = undefined;
    var bob_priv: [32]u8 = undefined;
    try alice_cp.generateKeyShare(.secp256r1, &alice_pub, &alice_priv);
    try bob_cp.generateKeyShare(.secp256r1, &bob_pub, &bob_priv);

    var alice_repeat_entropy = DeterministicEntropy.init(0x563);
    var alice_repeat_provider = Provider.init(alice_repeat_entropy.entropy());
    const alice_repeat_cp = alice_repeat_provider.cryptoProvider();
    var alice_repeat_pub: [65]u8 = undefined;
    var alice_repeat_priv: [32]u8 = undefined;
    try alice_repeat_cp.generateKeyShare(.secp256r1, &alice_repeat_pub, &alice_repeat_priv);
    try testing.expectEqualSlices(u8, &alice_pub, &alice_repeat_pub);
    try testing.expectEqualSlices(u8, &alice_priv, &alice_repeat_priv);

    const parsed_alice = try P256.fromSec1(&alice_pub);
    try parsed_alice.rejectIdentity();
    const parsed_bob = try P256.fromSec1(&bob_pub);
    try parsed_bob.rejectIdentity();

    var alice_shared: [32]u8 = undefined;
    var bob_shared: [32]u8 = undefined;
    try alice_cp.deriveSharedSecret(.secp256r1, &alice_priv, &bob_pub, &alice_shared);
    try bob_cp.deriveSharedSecret(.secp256r1, &bob_priv, &alice_pub, &bob_shared);
    try testing.expectEqualSlices(u8, &alice_shared, &bob_shared);
}

test "secp256r1 rejects invalid scalars, peer encodings, and preserves outputs on failure" {
    var det = DeterministicEntropy.init(563);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    const valid_scalar = [_]u8{0} ** 31 ++ [_]u8{1};
    const valid_peer = hexBytes("046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5");
    var out = [_]u8{0xcc} ** 32;

    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &([_]u8{0} ** 32), &valid_peer, &out));
    for (out) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &([_]u8{0xff} ** 32), &valid_peer, &out));
    for (out) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);

    var wrong_prefix = valid_peer;
    wrong_prefix[0] = 0x02;
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &valid_scalar, &wrong_prefix, &out));
    var off_curve = valid_peer;
    off_curve[64] ^= 0x01;
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &valid_scalar, &off_curve, &out));
    var identity = [_]u8{0} ** 65;
    identity[0] = 0x04;
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &valid_scalar, &identity, &out));
    var noncanonical = valid_peer;
    @memset(noncanonical[1..33], 0xff);
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &valid_scalar, &noncanonical, &out));
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &valid_scalar, valid_peer[0..64], &out));
    try testing.expectError(error.InvalidInput, cp.deriveSharedSecret(.secp256r1, &valid_scalar, &valid_peer, out[0..31]));
    for (out) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);
}

test "secp256r1 key-share generation rejects bad buffers before entropy and handles entropy failure" {
    const CountingEntropy = struct {
        calls: usize = 0,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            @memset(buffer, 0x01);
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };
    const FailingEntropy = struct {
        calls: usize = 0,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (buffer.len > 0) buffer[0] = 0xa5;
            return error.EntropyFailure;
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };
    const UnusableEntropy = struct {
        calls: usize = 0,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            @memset(buffer, 0);
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };

    var counting = CountingEntropy{};
    var counting_provider = Provider.init(counting.entropy());
    const counting_cp = counting_provider.cryptoProvider();
    var full_pub = [_]u8{0xcc} ** 65;
    var full_priv = [_]u8{0xdd} ** 32;
    try testing.expectError(error.InvalidInput, counting_cp.generateKeyShare(.secp256r1, full_pub[0..64], &full_priv));
    try testing.expectError(error.InvalidInput, counting_cp.generateKeyShare(.secp256r1, &full_pub, full_priv[0..31]));
    try testing.expectEqual(@as(usize, 0), counting.calls);
    for (full_pub) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);
    for (full_priv) |byte| try testing.expectEqual(@as(u8, 0xdd), byte);

    var failing = FailingEntropy{};
    var failing_provider = Provider.init(failing.entropy());
    const failing_cp = failing_provider.cryptoProvider();
    try testing.expectError(error.EntropyFailure, failing_cp.generateKeyShare(.secp256r1, &full_pub, &full_priv));
    try testing.expectEqual(@as(usize, 1), failing.calls);
    for (full_pub) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);
    for (full_priv) |byte| try testing.expectEqual(@as(u8, 0xdd), byte);

    var unusable = UnusableEntropy{};
    var unusable_provider = Provider.init(unusable.entropy());
    const unusable_cp = unusable_provider.cryptoProvider();
    try testing.expectError(error.EntropyFailure, unusable_cp.generateKeyShare(.secp256r1, &full_pub, &full_priv));
    try testing.expectEqual(@as(usize, p256_keygen_attempts), unusable.calls);
    for (full_pub) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);
    for (full_priv) |byte| try testing.expectEqual(@as(u8, 0xdd), byte);
}

test "key-share generation rejects wrong-sized output buffers as InvalidInput" {
    var det = DeterministicEntropy.init(8);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    // A wrong-sized caller buffer is a contract violation, not a provider
    // failure — protocol code must not map it to an internal crypto error.
    var full: [32]u8 = undefined;
    var too_small: [16]u8 = undefined;
    try testing.expectError(error.InvalidInput, cp.generateKeyShare(.x25519, &too_small, &full));
    try testing.expectError(error.InvalidInput, cp.generateKeyShare(.x25519, &full, &too_small));

    var p256_pub: [65]u8 = undefined;
    try testing.expectError(error.InvalidInput, cp.generateKeyShare(.secp256r1, p256_pub[0..64], &full));
    try testing.expectError(error.InvalidInput, cp.generateKeyShare(.secp256r1, &p256_pub, too_small[0..]));
}

test "Ed25519 sign then verify, with tamper and wrong-key rejection" {
    var det = DeterministicEntropy.init(7);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    var seed: [32]u8 = undefined;
    try cp.randomBytes(&seed);
    var software_key = try SoftwareSigningKey.fromSeed(seed);
    defer software_key.deinit();
    const signer = software_key.signingKey();
    try testing.expectEqual(provider.SignatureScheme.ed25519, signer.scheme());

    const message = "certificate verify transcript";
    var signature: [64]u8 = undefined;
    const sig_len = try signer.sign(message, cp.entropy, &signature);
    try testing.expectEqual(@as(usize, 64), sig_len);

    const public_key = software_key.publicKey();
    try cp.verify(.ed25519, &public_key, message, &signature);

    // Flip a signature bit: authentication must fail.
    var bad_sig = signature;
    bad_sig[0] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &public_key, message, &bad_sig));

    // Verify under an unrelated key: authentication must fail.
    var other_seed: [32]u8 = undefined;
    try cp.randomBytes(&other_seed);
    var other_key = try SoftwareSigningKey.fromSeed(other_seed);
    defer other_key.deinit();
    const other_public = other_key.publicKey();
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ed25519, &other_public, message, &signature));
}

test "SoftwareEcdsaP256SigningKey signs then verifies, with tamper and wrong-key rejection" {
    var det = DeterministicEntropy.init(10);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    var seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    try cp.randomBytes(&seed);
    var kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(seed);
    var software_key = try SoftwareEcdsaP256SigningKey.fromSecretKey(&kp.secret_key);
    defer software_key.deinit();
    const signer = software_key.signingKey();
    try testing.expectEqual(provider.SignatureScheme.ecdsa_secp256r1_sha256, signer.scheme());

    const message = "certificate verify transcript";
    var signature: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const sig_len = try signer.sign(message, cp.entropy, &signature);
    const public_key = software_key.publicKeySec1();

    try cp.verify(.ecdsa_secp256r1_sha256, &public_key, message, signature[0..sig_len]);

    // Flip a signature byte: authentication must fail.
    var bad_sig = signature;
    bad_sig[sig_len - 1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &public_key, message, bad_sig[0..sig_len]));

    // Verify under an unrelated key: authentication must fail.
    var other_seed: [EcdsaP256Sha256.KeyPair.seed_length]u8 = undefined;
    try cp.randomBytes(&other_seed);
    var other_kp = try EcdsaP256Sha256.KeyPair.generateDeterministic(other_seed);
    var other_key = try SoftwareEcdsaP256SigningKey.fromSecretKey(&other_kp.secret_key);
    defer other_key.deinit();
    const other_public = other_key.publicKeySec1();
    try testing.expectError(error.AuthenticationFailed, cp.verify(.ecdsa_secp256r1_sha256, &other_public, message, signature[0..sig_len]));

    // An output buffer too small for any DER-encoded ECDSA signature
    // reports InvalidInput rather than silently truncating.
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.InvalidInput, signer.sign(message, cp.entropy, &tiny));
}

fn readDerLen(bytes: []const u8, pos: *usize) !usize {
    if (pos.* >= bytes.len) return error.InvalidDer;
    const first = bytes[pos.*];
    pos.* += 1;
    if (first < 0x80) return first;
    const len_len = first & 0x7f;
    if (len_len == 0 or len_len > 2 or pos.* + len_len > bytes.len) return error.InvalidDer;
    var len: usize = 0;
    for (0..len_len) |_| {
        len = (len << 8) | bytes[pos.*];
        pos.* += 1;
    }
    return len;
}

fn readDerInteger32(der: []const u8, pos: *usize) ![32]u8 {
    if (pos.* >= der.len or der[pos.*] != 0x02) return error.InvalidDer;
    pos.* += 1;
    const len = try readDerLen(der, pos);
    if (len == 0 or len > 33 or pos.* + len > der.len) return error.InvalidDer;
    const int_bytes = der[pos.*..][0..len];
    pos.* += len;

    if (int_bytes[0] & 0x80 != 0) return error.InvalidDer;
    if (len > 1 and int_bytes[0] == 0 and int_bytes[1] & 0x80 == 0) return error.InvalidDer;

    const unsigned = if (len == 33) blk: {
        if (int_bytes[0] != 0) return error.InvalidDer;
        break :blk int_bytes[1..];
    } else int_bytes;
    var out = [_]u8{0} ** 32;
    @memcpy(out[32 - unsigned.len ..], unsigned);
    var non_zero: u8 = 0;
    for (out) |byte| non_zero |= byte;
    if (non_zero == 0) return error.InvalidDer;
    _ = P256Scalar.fromBytes(out, .big) catch return error.InvalidDer;
    return out;
}

fn expectCanonicalEcdsaDer(der: []const u8) !void {
    _ = try parseDerSignatureScalars(der);
}

fn parseDerSignatureScalars(der: []const u8) !struct { r: [32]u8, s: [32]u8 } {
    var pos: usize = 0;
    if (der.len == 0 or der[pos] != 0x30) return error.InvalidDer;
    pos += 1;
    const seq_len = try readDerLen(der, &pos);
    if (seq_len != der.len - pos) return error.InvalidDer;
    const r = try readDerInteger32(der, &pos);
    const s = try readDerInteger32(der, &pos);
    if (pos != der.len) return error.InvalidDer;
    return .{ .r = r, .s = s };
}

test "SoftwareEcdsaP256SigningKey uses injected entropy and emits canonical DER" {
    const FixedEntropy = struct {
        bytes: [EcdsaP256Sha256.noise_length]u8,

        fn init(bytes: [EcdsaP256Sha256.noise_length]u8) @This() {
            return .{ .bytes = bytes };
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }

        fn fill(context: *anyopaque, out: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            if (out.len != self.bytes.len) return error.EntropyFailure;
            @memcpy(out, &self.bytes);
        }
    };

    const key_seed = [_]u8{0x42} ** EcdsaP256Sha256.KeyPair.seed_length;
    var key = try SoftwareEcdsaP256SigningKey.fromSeed(key_seed);
    defer key.deinit();
    const signer = key.signingKey();
    const public_key = key.publicKeySec1();
    const message = "ecdsa provider entropy contract";

    var det_a1 = DeterministicEntropy.init(0x432);
    var det_a2 = DeterministicEntropy.init(0x432);
    var det_b = DeterministicEntropy.init(0x433);
    var cp_entropy = DeterministicEntropy.init(0x434);
    var cp_state = Provider.init(cp_entropy.entropy());
    const cp = cp_state.cryptoProvider();

    var sig_a1: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    var sig_a2: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    var sig_b: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const len_a1 = try signer.sign(message, det_a1.entropy(), &sig_a1);
    const len_a2 = try signer.sign(message, det_a2.entropy(), &sig_a2);
    const len_b = try signer.sign(message, det_b.entropy(), &sig_b);

    try testing.expectEqualSlices(u8, sig_a1[0..len_a1], sig_a2[0..len_a2]);
    try testing.expect(!std.mem.eql(u8, sig_a1[0..len_a1], sig_b[0..len_b]));
    try expectCanonicalEcdsaDer(sig_a1[0..len_a1]);
    try expectCanonicalEcdsaDer(sig_b[0..len_b]);
    try cp.verify(.ecdsa_secp256r1_sha256, &public_key, message, sig_a1[0..len_a1]);
    try cp.verify(.ecdsa_secp256r1_sha256, &public_key, message, sig_b[0..len_b]);

    const fixed_noise = [_]u8{0xa5} ** EcdsaP256Sha256.noise_length;
    var fixed_entropy = FixedEntropy.init(fixed_noise);
    var actual_der: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    const actual_len = try signer.sign(message, fixed_entropy.entropy(), &actual_der);
    const direct_signature = try key.key_pair.sign(message, fixed_noise);
    var expected_der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    defer secrets.secureZero(&expected_der_buf);
    const expected_der = direct_signature.toDer(&expected_der_buf);
    try testing.expectEqualSlices(u8, expected_der, actual_der[0..actual_len]);

    const scalars = try parseDerSignatureScalars(sig_a1[0..len_a1]);
    const s_scalar = try P256Scalar.fromBytes(scalars.s, .big);
    const alternate_s = s_scalar.neg().toBytes(.big);
    try testing.expect(!std.mem.eql(u8, &scalars.s, &alternate_s));
    var alternate_raw: [EcdsaP256Sha256.Signature.encoded_length]u8 = undefined;
    @memcpy(alternate_raw[0..32], &scalars.r);
    @memcpy(alternate_raw[32..64], &alternate_s);
    const alternate_signature = EcdsaP256Sha256.Signature.fromBytes(alternate_raw);
    var alternate_der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
    defer secrets.secureZero(&alternate_der_buf);
    const alternate_der = alternate_signature.toDer(&alternate_der_buf);
    try expectCanonicalEcdsaDer(alternate_der);
    try cp.verify(.ecdsa_secp256r1_sha256, &public_key, message, alternate_der);
}

test "SoftwareEcdsaP256SigningKey rejects small output before entropy and leaves output unchanged on entropy failure" {
    const CountingEntropy = struct {
        calls: usize = 0,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            @memset(buffer, 0xa5);
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };
    const FailingEntropy = struct {
        calls: usize = 0,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (buffer.len > 0) buffer[0] = 0x5a;
            return error.EntropyFailure;
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };

    var key = try SoftwareEcdsaP256SigningKey.fromSeed([_]u8{0x24} ** EcdsaP256Sha256.KeyPair.seed_length);
    defer key.deinit();
    const signer = key.signingKey();

    var counting = CountingEntropy{};
    var small = [_]u8{0xcc} ** (EcdsaP256Sha256.Signature.der_encoded_length_max - 1);
    try testing.expectError(error.InvalidInput, signer.sign("msg", counting.entropy(), &small));
    try testing.expectEqual(@as(usize, 0), counting.calls);
    for (small) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);

    var failing = FailingEntropy{};
    var out = [_]u8{0xcc} ** EcdsaP256Sha256.Signature.der_encoded_length_max;
    try testing.expectError(error.EntropyFailure, signer.sign("msg", failing.entropy(), &out));
    try testing.expectEqual(@as(usize, 1), failing.calls);
    for (out) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);
}

test "SoftwareEcdsaP256SigningKey rejects invalid scalar inputs and clears typed sources" {
    try testing.expect(@hasDecl(SoftwareSigningKey, "format"));
    try testing.expect(@hasDecl(SoftwareEcdsaP256SigningKey, "format"));

    try testing.expectError(error.InvalidInput, SoftwareEcdsaP256SigningKey.fromScalarBytes(&.{0x01}));
    try testing.expectError(error.InvalidInput, SoftwareEcdsaP256SigningKey.fromScalarBytes(&([_]u8{0} ** 32)));
    try testing.expectError(error.InvalidInput, SoftwareEcdsaP256SigningKey.fromScalarBytes(&([_]u8{0xff} ** 32)));

    var invalid_secret = EcdsaP256Sha256.SecretKey.fromBytes([_]u8{0xff} ** 32) catch unreachable;
    try testing.expectError(error.InvalidInput, SoftwareEcdsaP256SigningKey.fromSecretKey(&invalid_secret));
    try testing.expect(std.mem.allEqual(u8, &invalid_secret.bytes, 0));

    var scalar_bytes = [_]u8{0} ** 32;
    scalar_bytes[31] = 1;
    var scalar_secret = try secrets.FixedSecret(32).init(&scalar_bytes);
    var key = try SoftwareEcdsaP256SigningKey.fromScalarSecret(&scalar_secret);
    try testing.expectEqual(@as(usize, 0), scalar_secret.len);
    for (scalar_secret.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);
    key.deinit();
    try testing.expect(std.mem.allEqual(u8, &key.key_pair.secret_key.bytes, 0));

    var short_scalar_secret = try secrets.FixedSecret(32).init(&[_]u8{0x01});
    try testing.expectError(error.InvalidInput, SoftwareEcdsaP256SigningKey.fromScalarSecret(&short_scalar_secret));
    try testing.expectEqual(@as(usize, 0), short_scalar_secret.len);
    for (short_scalar_secret.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);

    var short_seed_secret = try secrets.FixedSecret(EcdsaP256Sha256.KeyPair.seed_length).init(&[_]u8{0x02});
    try testing.expectError(error.InvalidInput, SoftwareEcdsaP256SigningKey.fromSeedSecret(&short_seed_secret));
    try testing.expectEqual(@as(usize, 0), short_seed_secret.len);
    for (short_seed_secret.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);
}

test "SoftwareRsaSigningKey signs then verifies, with tamper and wrong-key/message rejection" {
    var det = DeterministicEntropy.init(11);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    var software_key = try SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, det.entropy());
    defer software_key.deinit();
    const signer = software_key.signingKey();
    try testing.expectEqual(provider.SignatureScheme.rsa_pss_rsae_sha256, signer.scheme());

    const message = "certificate verify transcript";
    var signature: [rsa.max_modulus_bytes]u8 = undefined;
    const sig_len = try signer.sign(message, cp.entropy, &signature);
    try testing.expectEqual(@as(usize, 256), sig_len);

    try cp.verify(.rsa_pss_rsae_sha256, rsa.testdata.public_key_der, message, signature[0..sig_len]);

    // Flip a signature byte: authentication must fail.
    var bad_sig = signature;
    bad_sig[sig_len - 1] ^= 0x01;
    try testing.expectError(error.AuthenticationFailed, cp.verify(.rsa_pss_rsae_sha256, rsa.testdata.public_key_der, message, bad_sig[0..sig_len]));

    // A different message under the same key must fail.
    try testing.expectError(error.AuthenticationFailed, cp.verify(.rsa_pss_rsae_sha256, rsa.testdata.public_key_der, "wrong message", signature[0..sig_len]));

    // An output buffer too small for the modulus-sized signature reports
    // InvalidInput rather than silently truncating.
    var tiny: [4]u8 = undefined;
    try testing.expectError(error.InvalidInput, signer.sign(message, cp.entropy, &tiny));
}

test "SoftwareRsaSigningKey draws the PSS salt from injected entropy" {
    const FixedEntropy = struct {
        byte: u8,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            @memset(buffer, self.byte);
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };

    var import_entropy = DeterministicEntropy.init(0x51a1);
    var key = try SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, import_entropy.entropy());
    defer key.deinit();
    const signer = key.signingKey();

    var entropy_a = FixedEntropy{ .byte = 0x11 };
    var entropy_b = FixedEntropy{ .byte = 0x22 };
    var sig_a: [rsa.max_modulus_bytes]u8 = undefined;
    var sig_b: [rsa.max_modulus_bytes]u8 = undefined;
    const len_a = try signer.sign("same message", entropy_a.entropy(), &sig_a);
    const len_b = try signer.sign("same message", entropy_b.entropy(), &sig_b);

    // Different injected "randomness" (the PSS salt) must produce different
    // signatures over the same message and key.
    try testing.expect(!std.mem.eql(u8, sig_a[0..len_a], sig_b[0..len_b]));
    try rsa.verifyPssSha256(rsa.testdata.public_key_der, "same message", sig_a[0..len_a]);
    try rsa.verifyPssSha256(rsa.testdata.public_key_der, "same message", sig_b[0..len_b]);
}

test "SoftwareRsaSigningKey rejects small output before entropy and leaves output unchanged on entropy failure" {
    const CountingEntropy = struct {
        calls: usize = 0,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            @memset(buffer, 0xa5);
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };
    const FailingEntropy = struct {
        calls: usize = 0,

        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.calls += 1;
            if (buffer.len > 0) buffer[0] = 0x5a;
            return error.EntropyFailure;
        }

        fn entropy(self: *@This()) provider.Entropy {
            return .{ .context = self, .fillFn = fill };
        }
    };

    var import_entropy = DeterministicEntropy.init(0x51a2);
    var key = try SoftwareRsaSigningKey.fromDer(rsa.testdata.private_key_pkcs1_der, import_entropy.entropy());
    defer key.deinit();
    const signer = key.signingKey();

    var counting = CountingEntropy{};
    var small = [_]u8{0xcc} ** 255; // one byte short of the 256-byte RSA-2048 signature
    try testing.expectError(error.InvalidInput, signer.sign("msg", counting.entropy(), &small));
    try testing.expectEqual(@as(usize, 0), counting.calls);
    for (small) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);

    var failing = FailingEntropy{};
    var out = [_]u8{0xcc} ** rsa.max_modulus_bytes;
    try testing.expectError(error.EntropyFailure, signer.sign("msg", failing.entropy(), &out));
    try testing.expectEqual(@as(usize, 1), failing.calls);
    for (out) |byte| try testing.expectEqual(@as(u8, 0xcc), byte);
}

test "SoftwareRsaSigningKey format is banned and fromDer rejects malformed DER" {
    var det = DeterministicEntropy.init(0x51a3);
    try testing.expect(@hasDecl(SoftwareRsaSigningKey, "format"));
    try testing.expectError(error.InvalidInput, SoftwareRsaSigningKey.fromDer(&[_]u8{0x30}, det.entropy()));
    try testing.expectError(error.InvalidInput, SoftwareRsaSigningKey.fromDer(&[_]u8{}, det.entropy()));
}

test "fromSeedSecret clears the caller's typed secret immediately and derives the same key as fromSeed" {
    const seed_bytes = [_]u8{0x5a} ** Ed25519.KeyPair.seed_length;

    var via_secret = try secrets.FixedSecret(Ed25519.KeyPair.seed_length).init(&seed_bytes);
    var from_secret_key = try SoftwareSigningKey.fromSeedSecret(&via_secret);
    defer from_secret_key.deinit();

    // The source container is cleared by `fromSeedSecret` itself — this
    // observes the call boundary directly rather than scanning an allocator
    // arena, which cannot see stack/parameter copies.
    try testing.expectEqual(@as(usize, 0), via_secret.len);
    for (via_secret.bytes) |byte| try testing.expectEqual(@as(u8, 0), byte);

    // Same seed through the by-value entry point derives the identical key.
    var from_array_key = try SoftwareSigningKey.fromSeed(seed_bytes);
    defer from_array_key.deinit();
    try testing.expectEqualSlices(u8, &from_array_key.publicKey(), &from_secret_key.publicKey());
}

test "randomBytes surfaces entropy failure as a provider error" {
    const Failing = struct {
        fn fill(context: *anyopaque, buffer: []u8) provider.EntropyError!void {
            _ = context;
            _ = buffer;
            return error.EntropyFailure;
        }
    };
    var sentinel: u8 = 0;
    var p = Provider.init(.{ .context = &sentinel, .fillFn = Failing.fill });
    const cp = p.cryptoProvider();
    var buf: [16]u8 = undefined;
    try testing.expectError(error.EntropyFailure, cp.randomBytes(&buf));
}

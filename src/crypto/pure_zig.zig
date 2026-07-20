//! Pure-Zig `CryptoProvider` (#370, epic #327).
//!
//! Satisfies the `provider.CryptoProvider` boundary using only `std.crypto`
//! primitives — no external TLS/crypto library. This is the experimental
//! backend the epic grows alongside OpenSSL; it implements the narrow first
//! profile the TLS/QUIC engines target and advertises exactly that profile
//! through capability discovery, so anything outside it is a typed
//! `error.UnsupportedCapability` rather than a silent gap.
//!
//! Implemented here (the overlap where a pure-Zig and an OpenSSL provider must
//! agree):
//!
//!   * HKDF-Extract / Expand-Label over SHA-256 and SHA-384
//!   * AEAD seal/open for AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305
//!   * X25519 key-share generation and shared-secret derivation
//!   * Ed25519 signing (via `SoftwareSigningKey`) and verification
//!   * ECDSA-P256/SHA-256 signature verification (certificate and
//!     CertificateVerify signatures; #343)
//!   * injected-entropy random bytes, constant-time compare, secure zero
//!
//! Declared by the interface but not yet implemented here — capability
//! discovery reports them absent, and every entry point returns
//! `error.UnsupportedCapability`:
//!
//!   * secp256r1 (P-256) ECDH key-share generation and shared-secret
//!     derivation (the signature scheme over the same curve is implemented;
//!     the ECDH group is not)
//! RSA-PSS-RSAE/SHA-256 verification is implemented in `rsa.zig` with strict
//! DER, 2048/3072/4096-bit RSA key-size, and EMSA-PSS validation.
//!
//! The provider never draws ambient randomness: it fills key-share scalars and
//! any per-signature noise from the `provider.Entropy` handed in at
//! construction, exactly like the rest of `src/quic/`.

const std = @import("std");
const crypto = std.crypto;
const provider = @import("provider.zig");
const profile = @import("profile.zig");
const rsa = @import("rsa.zig");

const HmacSha256 = crypto.auth.hmac.sha2.HmacSha256;
const HmacSha384 = crypto.auth.hmac.sha2.HmacSha384;
const Aes128Gcm = crypto.aead.aes_gcm.Aes128Gcm;
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;
const X25519 = crypto.dh.X25519;
const Ed25519 = crypto.sign.Ed25519;
const EcdsaP256Sha256 = crypto.sign.ecdsa.EcdsaP256Sha256;

/// The pure-Zig provider. Construct with an entropy source, then hand the
/// interface view to protocol code via `cryptoProvider`.
pub const Provider = struct {
    entropy: provider.Entropy,

    pub fn init(entropy: provider.Entropy) Provider {
        return .{ .entropy = entropy };
    }

    /// Erase to the boundary type. The returned view borrows `self`, so `self`
    /// must outlive every use of it.
    pub fn cryptoProvider(self: *Provider) provider.CryptoProvider {
        return .{ .context = self, .vtable = &vtable, .entropy = self.entropy };
    }

    /// The static algorithm profile this backend advertises.
    pub fn capabilities() provider.Capabilities {
        var caps = provider.Capabilities{};
        caps.hashes.insert(.sha256);
        caps.hashes.insert(.sha384);
        caps.aeads.insert(.aes_128_gcm);
        caps.aeads.insert(.aes_256_gcm);
        caps.aeads.insert(.chacha20_poly1305);
        caps.groups.insert(.x25519);
        caps.signatures.insert(.ed25519);
        caps.signatures.insert(.ecdsa_secp256r1_sha256);
        caps.signatures.insert(.rsa_pss_rsae_sha256);
        return caps;
    }

    const vtable = provider.CryptoProvider.VTable{
        .capabilities = capabilitiesImpl,
        .hkdfExtract = hkdfExtractImpl,
        .hkdfExpandLabel = hkdfExpandLabelImpl,
        .aeadSeal = aeadSealImpl,
        .aeadOpen = aeadOpenImpl,
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
    crypto.secureZero(u8, &prk);
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
    defer crypto.secureZero(u8, &prk);

    // HKDF-Expand: T(i) = HMAC(PRK, T(i-1) || info || i), truncated to out.len.
    // Both `block` (a raw output block) and `message` (which carries T(i-1))
    // hold secret-derived material, so wipe them on every exit path.
    var block: [mac_len]u8 = undefined;
    var message: [mac_len + info.len + 1]u8 = undefined;
    defer crypto.secureZero(u8, &block);
    defer crypto.secureZero(u8, &message);
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
    defer crypto.secureZero(u8, &k);

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
    defer crypto.secureZero(u8, &k);

    Cipher.decrypt(plaintext, ciphertext, t, associated_data, n, k) catch {
        // Never leak partial plaintext on authentication failure.
        crypto.secureZero(u8, plaintext);
        return error.AuthenticationFailed;
    };
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
            defer crypto.secureZero(u8, &seed);
            self.entropy.fill(&seed) catch return error.EntropyFailure;

            var key_pair = X25519.KeyPair.generateDeterministic(seed) catch return error.ProviderFailure;
            // The local key pair keeps a copy of the private scalar after it is
            // handed to the caller; scrub it on return.
            defer crypto.secureZero(u8, &key_pair.secret_key);
            @memcpy(public_out, &key_pair.public_key);
            @memcpy(private_out, &key_pair.secret_key);
        },
        .secp256r1 => return error.UnsupportedCapability,
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
            defer crypto.secureZero(u8, &scalar);

            // scalarmult rejects the low-order / all-zero points that would
            // yield an all-zero (identity) shared secret: peer input error.
            var shared = X25519.scalarmult(scalar, point) catch return error.InvalidInput;
            // The shared secret is a backend-created temporary; scrub our copy
            // once it has been handed to the caller.
            defer crypto.secureZero(u8, &shared);
            @memcpy(out, &shared);
        },
        .secp256r1 => return error.UnsupportedCapability,
    }
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
            if (public_key.len != Ed25519.PublicKey.encoded_length) return error.InvalidInput;
            if (signature.len != Ed25519.Signature.encoded_length) return error.InvalidInput;
            const pk = Ed25519.PublicKey.fromBytes(public_key[0..Ed25519.PublicKey.encoded_length].*) catch
                return error.InvalidInput;
            const sig = Ed25519.Signature.fromBytes(signature[0..Ed25519.Signature.encoded_length].*);
            sig.verify(message, pk) catch return error.AuthenticationFailed;
        },
        .ecdsa_secp256r1_sha256 => {
            // `public_key` is the SEC1 point (uncompressed 0x04||X||Y or
            // compressed); `signature` is the DER SEQUENCE { r, s } used by
            // both TLS CertificateVerify and X.509. A malformed key or
            // signature encoding is InputError; a well-formed but wrong
            // signature is AuthenticationFailed.
            const pk = EcdsaP256Sha256.PublicKey.fromSec1(public_key) catch return error.InvalidInput;
            const sig = EcdsaP256Sha256.Signature.fromDer(signature) catch return error.InvalidInput;
            sig.verify(message, pk) catch return error.AuthenticationFailed;
        },
        .rsa_pss_rsae_sha256 => {
            try rsa.verifyPssSha256(public_key, message, signature);
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
    pub fn fromSeed(seed: [Ed25519.KeyPair.seed_length]u8) provider.SignError!SoftwareSigningKey {
        // The by-value parameter is itself a caller-owned copy of secret seed
        // bytes; wipe this frame's copy once the deterministic key pair has
        // been derived from it, matching the wipe-after-use pattern used for
        // key-share seeds elsewhere in this file.
        var local_seed = seed;
        defer crypto.secureZero(u8, &local_seed);
        const key_pair = Ed25519.KeyPair.generateDeterministic(local_seed) catch return error.ProviderFailure;
        return .{ .key_pair = key_pair };
    }

    /// Securely erase the private key material. Callers must invoke this when
    /// the key is no longer needed; letting the value go out of scope does not
    /// scrub its bytes.
    pub fn deinit(self: *SoftwareSigningKey) void {
        crypto.secureZero(u8, &self.key_pair.secret_key.bytes);
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

test "capabilities advertise exactly the implemented profile" {
    const caps = Provider.capabilities();
    const profiled = profile.capabilities(.pure_zig);
    try testing.expectEqual(caps.hashes, profiled.hashes);
    try testing.expectEqual(caps.aeads, profiled.aeads);
    try testing.expectEqual(caps.groups, profiled.groups);
    try testing.expectEqual(caps.signatures, profiled.signatures);
    try testing.expect(caps.supportsHash(.sha256));
    try testing.expect(caps.supportsHash(.sha384));
    try testing.expect(caps.supportsAead(.aes_128_gcm));
    try testing.expect(caps.supportsAead(.aes_256_gcm));
    try testing.expect(caps.supportsAead(.chacha20_poly1305));
    try testing.expect(caps.supportsGroup(.x25519));
    try testing.expect(!caps.supportsGroup(.secp256r1));
    try testing.expect(caps.supportsSignature(.ed25519));
    try testing.expect(caps.supportsSignature(.ecdsa_secp256r1_sha256));
    try testing.expect(caps.supportsSignature(.rsa_pss_rsae_sha256));
}

test "unsupported algorithms return UnsupportedCapability, not undefined behaviour" {
    var det = DeterministicEntropy.init(1);
    var p = Provider.init(det.entropy());
    const cp = p.cryptoProvider();

    // The secp256r1 ECDH group remains unimplemented (only the signature
    // scheme over that curve is implemented), so key-share operations still
    // fail closed.
    var pub_buf: [65]u8 = undefined;
    var priv_buf: [32]u8 = undefined;
    try testing.expectError(error.UnsupportedCapability, cp.generateKeyShare(.secp256r1, &pub_buf, &priv_buf));
    try testing.expectError(error.UnsupportedCapability, cp.deriveSharedSecret(.secp256r1, &priv_buf, pub_buf[0..32], priv_buf[0..32]));

    // Malformed RSA-PSS inputs are rejected as ordinary input errors.
    var sig: [8]u8 = @splat(0);
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pss_rsae_sha256, &sig, "m", &sig));
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pss_rsae_sha256, "", "m", ""));
    try testing.expectError(error.InvalidInput, cp.verify(.rsa_pss_rsae_sha256, "\x30", "m", "\x00"));
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

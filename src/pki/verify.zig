//! X.509 certificate signature verification matrix (#343).
//!
//! Verifies a certificate's signature under an issuer's public key for the
//! initial practical TLS algorithm matrix — Ed25519, ECDSA P-256/SHA-256, and
//! RSA-PSS-RSAE/SHA-256 — entirely through the #327 crypto-provider seam and
//! the #341 parsed certificate views. No cryptographic primitive is named
//! here and there is no OpenSSL fallback: unsupported algorithms fail closed
//! with a typed outcome.
//!
//! ## Separation of concerns
//!
//! This module answers exactly one question: is `certificate`'s signature
//! valid under `issuer` public key material, for a supported algorithm? It
//! does not build or order chains, check validity dates, enforce Basic
//! Constraints/Key Usage, or match names — those are path-building and policy
//! layers (#324-F/G) that call this as a primitive.
//!
//! ## Outcome taxonomy
//!
//! - `UnsupportedSignatureAlgorithm` — the signature OID, its parameters, or
//!   the issuer key type is outside the supported matrix. Callers fail closed.
//! - `IssuerKeyMismatch` — the signature algorithm and the issuer key type are
//!   individually supported but inconsistent (e.g. an ECDSA signature against
//!   an RSA key).
//! - `MalformedPublicKey` / `MalformedSignature` — the issuer SPKI key or the
//!   signature encoding is structurally invalid (bad length, non-canonical
//!   DER, invalid EC point, nonzero BIT STRING padding).
//! - `InvalidSignature` — well-formed inputs, but the signature does not
//!   authenticate the TBS bytes.

const std = @import("std");
const crypto = @import("crypto");
const der = @import("der.zig");
const oid = @import("oid.zig");
const x509 = @import("x509.zig");

const provider = crypto.provider;
const wk = oid.well_known;

pub const Error = error{
    UnsupportedSignatureAlgorithm,
    IssuerKeyMismatch,
    MalformedPublicKey,
    MalformedSignature,
    InvalidSignature,
};

/// A supported certificate signature algorithm resolved from the cert's
/// `signatureAlgorithm` and validated parameters, paired with the issuer key
/// type it requires.
const Resolved = struct {
    scheme: provider.SignatureScheme,
    required_key_type: x509.PublicKeyType,
};

/// Verify `certificate`'s signature using `issuer`'s SubjectPublicKeyInfo.
/// Both are borrowed parsed views (#341); the certificate's exact
/// TBSCertificate bytes are the signed message. Inner/outer signature
/// algorithm identity is already enforced by the #341 parser, so only the
/// outer `signature_algorithm` is consulted here.
pub fn verifyCertificateSignature(
    crypto_provider: provider.CryptoProvider,
    certificate: *const x509.Certificate,
    issuer: *const x509.SubjectPublicKeyInfo,
) Error!void {
    const resolved = try resolveScheme(&certificate.signature_algorithm);

    // Individually-supported algorithm and key, but inconsistent pairing.
    if (issuer.key_type != resolved.required_key_type) return error.IssuerKeyMismatch;

    // The issuer key's algorithm parameters must conform, independent of the
    // OID-only classification.
    try validateIssuerKeyParameters(resolved.scheme, issuer);

    // Fail closed before touching key material if the provider cannot perform
    // the scheme, so an unsupported algorithm is never a silent no-op.
    if (!crypto_provider.capabilities().supportsSignature(resolved.scheme)) {
        return error.UnsupportedSignatureAlgorithm;
    }

    const public_key = try issuerPublicKey(resolved.scheme, issuer);
    const signature = try signatureBytes(resolved.scheme, certificate, issuer);

    crypto_provider.verify(resolved.scheme, public_key, certificate.tbs_raw, signature) catch |err| return switch (err) {
        error.AuthenticationFailed => error.InvalidSignature,
        // Signatures are structurally pre-validated above, so a remaining
        // input rejection is the key/point (e.g. an off-curve EC point).
        error.InvalidInput => error.MalformedPublicKey,
        error.UnsupportedCapability => error.UnsupportedSignatureAlgorithm,
    };
}

/// Convenience wrapper for a self-issued certificate: verify its signature
/// against its own SubjectPublicKeyInfo. This proves the key-to-signature
/// binding only; it is not a trust decision.
pub fn verifySelfSignature(
    crypto_provider: provider.CryptoProvider,
    certificate: *const x509.Certificate,
) Error!void {
    return verifyCertificateSignature(crypto_provider, certificate, &certificate.subject_public_key_info);
}

fn resolveScheme(algorithm: *const x509.AlgorithmIdentifier) Error!Resolved {
    return switch (x509.SignatureAlgorithm.classify(algorithm)) {
        .ed25519 => blk: {
            // RFC 8410 §3: the Ed25519 signatureAlgorithm parameters MUST be
            // absent. `classify` only matches the OID, so enforce it here.
            if (algorithm.parameters_raw != null) return error.UnsupportedSignatureAlgorithm;
            break :blk .{ .scheme = .ed25519, .required_key_type = .ed25519 };
        },
        .ecdsa_sha256 => blk: {
            // RFC 5758 §3.2: ecdsa-with-SHA256 parameters MUST be absent.
            if (algorithm.parameters_raw != null) return error.UnsupportedSignatureAlgorithm;
            break :blk .{ .scheme = .ecdsa_secp256r1_sha256, .required_key_type = .ecdsa_p256 };
        },
        .rsa_pss => blk: {
            // RSASSA-PSS carries its hash/MGF/salt in parameters; only the
            // SHA-256/MGF1-SHA-256/salt-32 (rsae) configuration is supported.
            try validatePssSha256(algorithm);
            break :blk .{ .scheme = .rsa_pss_rsae_sha256, .required_key_type = .rsa };
        },
        // RSA PKCS#1 v1.5, ECDSA over other curves/hashes, and anything the
        // parser did not recognize are outside the matrix.
        else => error.UnsupportedSignatureAlgorithm,
    };
}

/// Enforce the issuer SubjectPublicKeyInfo `AlgorithmIdentifier` parameters
/// beyond the OID/key-type classification `x509` performs: Ed25519 keys carry
/// no parameters (RFC 8410 §3), rsaEncryption keys carry explicit NULL or
/// none (RFC 3279 §2.3.1; arbitrary values are rejected), and the ECDSA
/// named-curve is already pinned to P-256 by the `ecdsa_p256` key type.
fn validateIssuerKeyParameters(scheme: provider.SignatureScheme, issuer: *const x509.SubjectPublicKeyInfo) Error!void {
    switch (scheme) {
        .ed25519 => {
            if (issuer.algorithm.parameters_raw != null) return error.MalformedPublicKey;
        },
        .rsa_pss_rsae_sha256 => {
            if (issuer.algorithm.parameters_raw != null and !issuer.algorithm.parameters_null) {
                return error.MalformedPublicKey;
            }
        },
        .ecdsa_secp256r1_sha256 => {},
    }
}

fn issuerPublicKey(scheme: provider.SignatureScheme, issuer: *const x509.SubjectPublicKeyInfo) Error![]const u8 {
    // A public key's BIT STRING must be octet-aligned.
    if (issuer.subject_public_key.unused_bits != 0) return error.MalformedPublicKey;
    const key = issuer.subject_public_key.data;
    switch (scheme) {
        .ed25519 => {
            if (key.len != 32) return error.MalformedPublicKey;
        },
        .ecdsa_secp256r1_sha256 => {
            // SEC1: uncompressed 0x04||X||Y (65) or compressed 0x02/0x03||X (33).
            const uncompressed = key.len == 65 and key[0] == 0x04;
            const compressed = key.len == 33 and (key[0] == 0x02 or key[0] == 0x03);
            if (!uncompressed and !compressed) return error.MalformedPublicKey;
        },
        .rsa_pss_rsae_sha256 => {
            // Confirm the SPKI carries a well-formed DER RSAPublicKey before
            // handing it to the provider, so a later input rejection is the
            // signature, not the key.
            _ = rsaModulusLen(key) catch return error.MalformedPublicKey;
        },
    }
    return key;
}

fn signatureBytes(
    scheme: provider.SignatureScheme,
    certificate: *const x509.Certificate,
    issuer: *const x509.SubjectPublicKeyInfo,
) Error![]const u8 {
    if (certificate.signature_value.unused_bits != 0) return error.MalformedSignature;
    const sig = certificate.signature_value.data;
    switch (scheme) {
        .ed25519 => {
            if (sig.len != 64) return error.MalformedSignature;
        },
        .ecdsa_secp256r1_sha256 => {
            // Reject non-canonical ECDSA DER (non-minimal integers, trailing
            // junk, wrong shape) up front for a precise typed outcome.
            try validateEcdsaDerSignature(sig);
        },
        .rsa_pss_rsae_sha256 => {
            // A PSS signature is exactly one modulus in length; a mismatch is
            // a signature defect, distinct from a malformed key.
            const modulus_len = rsaModulusLen(issuer.subject_public_key.data) catch return error.MalformedPublicKey;
            if (sig.len != modulus_len) return error.MalformedSignature;
        },
    }
    return sig;
}

/// Validate an ECDSA `SEQUENCE { r INTEGER, s INTEGER }` with strict DER,
/// rejecting non-canonical encodings before the provider sees them. Exposed
/// for direct testing of the signature-encoding rules.
pub fn validateEcdsaDerSignature(sig: []const u8) Error!void {
    var reader = der.Reader.init(sig, .{});
    var seq = reader.readSequence() catch return error.MalformedSignature;
    reader.expectEnd() catch return error.MalformedSignature;
    const r = seq.readInteger() catch return error.MalformedSignature;
    const s = seq.readInteger() catch return error.MalformedSignature;
    seq.expectEnd() catch return error.MalformedSignature;
    // ECDSA r and s are positive and, over P-256, fit in a 32-byte scalar.
    // Bounding the magnitude here keeps an oversized-but-canonical integer
    // (which the provider would reject as InvalidInput, blurring the error
    // taxonomy) a precise MalformedSignature.
    try validateP256Scalar(r);
    try validateP256Scalar(s);
}

/// A P-256 scalar INTEGER is positive and at most 32 magnitude bytes; a
/// leading 0x00 sign byte is allowed only when the value's top bit is set
/// (33-byte content).
fn validateP256Scalar(view: der.IntegerView) Error!void {
    if (view.isNegative()) return error.MalformedSignature;
    var magnitude = view.content;
    if (magnitude.len >= 1 and magnitude[0] == 0x00) magnitude = magnitude[1..];
    if (magnitude.len == 0 or magnitude.len > 32) return error.MalformedSignature;
}

/// Return the RSA modulus length in bytes (minimal, leading-zero stripped)
/// from a DER `RSAPublicKey`, validating the two-INTEGER structure and that
/// both the modulus and the public exponent are strictly positive. `readInteger`
/// enforces minimal DER but not sign; a negative or zero modulus/exponent that
/// the unsigned `std.crypto` RSA parser would misinterpret is rejected here.
/// Exposed for direct testing of the key-encoding rules.
pub fn rsaModulusLen(rsa_public_key_der: []const u8) Error!usize {
    var reader = der.Reader.init(rsa_public_key_der, .{});
    var seq = reader.readSequence() catch return error.MalformedPublicKey;
    reader.expectEnd() catch return error.MalformedPublicKey;
    const modulus = seq.readInteger() catch return error.MalformedPublicKey;
    const exponent = seq.readInteger() catch return error.MalformedPublicKey;
    seq.expectEnd() catch return error.MalformedPublicKey;
    if (modulus.isNegative() or modulus.isZero()) return error.MalformedPublicKey;
    if (exponent.isNegative() or exponent.isZero()) return error.MalformedPublicKey;
    // DER INTEGER may carry a single leading 0x00 to keep it positive; the
    // effective modulus length excludes it.
    var content = modulus.content;
    if (content.len >= 1 and content[0] == 0x00) content = content[1..];
    if (content.len == 0) return error.MalformedPublicKey;
    return content.len;
}

// RSASSA-PSS-params bare-hash OIDs (not the signature-combination OIDs).
const oid_sha256 = [_]u32{ 2, 16, 840, 1, 101, 3, 4, 2, 1 };
const oid_mgf1 = [_]u32{ 1, 2, 840, 113549, 1, 1, 8 };

/// Enforce that RSASSA-PSS parameters select SHA-256, MGF1 over SHA-256, and a
/// 32-byte salt — the single PSS configuration this matrix supports. Any other
/// (including the SHA-1 DEFAULTs when a field is absent) is unsupported; a
/// structurally broken parameter block is malformed. Exposed for direct
/// testing of the parameter rules.
pub fn validatePssSha256(algorithm: *const x509.AlgorithmIdentifier) Error!void {
    const params = algorithm.parameters_raw orelse return error.UnsupportedSignatureAlgorithm;
    var reader = der.Reader.init(params, .{});
    var seq = reader.readSequence() catch return error.MalformedSignature;
    reader.expectEnd() catch return error.MalformedSignature;

    // hashAlgorithm [0] EXPLICIT AlgorithmIdentifier — must be present and SHA-256.
    const hash_alg = seq.readExplicitContext(0) catch return error.UnsupportedSignatureAlgorithm;
    try expectAlgorithmOid(hash_alg, &oid_sha256);

    // maskGenAlgorithm [1] EXPLICIT AlgorithmIdentifier — MGF1 over SHA-256.
    const mgf_alg = seq.readExplicitContext(1) catch return error.UnsupportedSignatureAlgorithm;
    try expectMgf1Sha256(mgf_alg);

    // saltLength [2] EXPLICIT INTEGER — must equal the SHA-256 digest length.
    const salt_elem = seq.readExplicitContext(2) catch return error.UnsupportedSignatureAlgorithm;
    if (!salt_elem.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.integer), false))) {
        return error.MalformedSignature;
    }
    if (salt_elem.content.len != 1 or salt_elem.content[0] != 32) return error.UnsupportedSignatureAlgorithm;

    // trailerField [3] is DEFAULT 1; reject any explicit override we would not honor.
    if (seq.remaining() > 0) return error.UnsupportedSignatureAlgorithm;
}

/// A child reader over an `AlgorithmIdentifier` SEQUENCE element's content.
/// `elem.encoded` is a complete TLV, so re-reading it as a sequence descends
/// into its fields without depending on the parent buffer's offsets.
fn algorithmIdentifierFields(elem: der.Element) Error!der.Reader {
    if (!elem.tag.eql(der.Tag.universal(@intFromEnum(der.UniversalTag.sequence), true))) {
        return error.MalformedSignature;
    }
    var outer = der.Reader.init(elem.encoded, .{});
    const fields = outer.readSequence() catch return error.MalformedSignature;
    return fields;
}

/// Verify that `elem` is an `AlgorithmIdentifier` SEQUENCE whose OID matches
/// `expected` and whose parameters are absent or explicit NULL.
fn expectAlgorithmOid(elem: der.Element, expected: []const u32) Error!void {
    var inner = try algorithmIdentifierFields(elem);
    const alg_oid = inner.readObjectIdentifier() catch return error.MalformedSignature;
    if (!alg_oid.eqlComponents(expected)) return error.UnsupportedSignatureAlgorithm;
    // Optional parameters: only absent or NULL are acceptable for these hashes.
    if (inner.remaining() > 0) {
        inner.readNull() catch return error.UnsupportedSignatureAlgorithm;
    }
    inner.expectEnd() catch return error.MalformedSignature;
}

/// Verify `elem` is `AlgorithmIdentifier` = { mgf1, AlgorithmIdentifier{ sha256 } }.
fn expectMgf1Sha256(elem: der.Element) Error!void {
    var inner = try algorithmIdentifierFields(elem);
    const mgf_oid = inner.readObjectIdentifier() catch return error.MalformedSignature;
    if (!mgf_oid.eqlComponents(&oid_mgf1)) return error.UnsupportedSignatureAlgorithm;
    // MGF1's parameter is the underlying hash AlgorithmIdentifier.
    const hash_elem = inner.readElement() catch return error.UnsupportedSignatureAlgorithm;
    inner.expectEnd() catch return error.MalformedSignature;
    try expectAlgorithmOid(hash_elem, &oid_sha256);
}

const testing = std.testing;

test {
    testing.refAllDecls(@This());
}

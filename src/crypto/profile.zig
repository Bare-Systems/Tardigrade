//! Checked-in cryptographic capability profile (#371, epic #327).
//!
//! This file is intentionally data-heavy. It is the build-visible matrix that
//! maps protocol algorithms to the implementation family that supplies them,
//! the current provider status, test coverage, and consumers.

const std = @import("std");
const provider = @import("provider.zig");

pub const zig_version_floor = "0.16.0";

pub const ProviderKind = enum {
    pure_zig,
    openssl,
};

pub const Status = enum {
    supported,
    provider_deferred,
    unsupported,
};

pub const Implementation = enum {
    zig_std_crypto,
    project_code,
    openssl_provider,
    unavailable,
};

pub const Category = enum {
    hash,
    hkdf,
    aead,
    group,
    signature,
    certificate_helper,
    entropy,
};

pub const Consumer = enum {
    tls_handshake,
    tls_record,
    quic_packet_protection,
    quic_tls_bridge,
    pki,
    resumption,
};

pub const CertificateHelper = enum {
    der_parser,
    chain_builder,
    webpki_validation,
};

pub const EntropyCapability = enum {
    injected_random_bytes,
    secure_zero,
    constant_time_compare,
};

pub const Algorithm = union(Category) {
    hash: provider.Hash,
    hkdf: provider.Hash,
    aead: provider.Aead,
    group: provider.Group,
    signature: provider.SignatureScheme,
    certificate_helper: CertificateHelper,
    entropy: EntropyCapability,
};

pub const ConsumerSet = std.EnumSet(Consumer);

pub const Row = struct {
    algorithm: Algorithm,
    name: []const u8,
    pure_zig_implementation: Implementation,
    pure_zig_status: Status,
    openssl_implementation: Implementation,
    openssl_status: Status,
    tests: []const u8,
    consumers: ConsumerSet,
    review: []const u8,
};

pub const rows = [_]Row{
    row(.{ .hash = .sha256 }, "SHA-256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "std.crypto cross-checks, transcript tests", .{ .tls_handshake, .quic_tls_bridge }, "Hash additions require transcript/HKDF vectors."),
    row(.{ .hash = .sha384 }, "SHA-384", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "provider capability and HKDF tests", .{.tls_handshake}, "Hash additions require TLS 1.3 suite mapping."),
    row(.{ .hkdf = .sha256 }, "HKDF-SHA256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "RFC 5869/std.crypto and TLS expand-label parity", .{ .tls_handshake, .quic_tls_bridge, .quic_packet_protection }, "HKDF additions require extract and expand-label vectors."),
    row(.{ .hkdf = .sha384 }, "HKDF-SHA384", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "provider capability and expand-label tests", .{.tls_handshake}, "HKDF additions require TLS 1.3 label coverage."),
    row(.{ .aead = .aes_128_gcm }, "AES-128-GCM", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{ .tls_record, .quic_packet_protection }, "AEAD additions require auth-failure zeroing tests."),
    row(.{ .aead = .aes_256_gcm }, "AES-256-GCM", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{ .tls_record, .quic_packet_protection }, "AEAD additions require TLS cipher-suite mapping."),
    row(.{ .aead = .chacha20_poly1305 }, "ChaCha20-Poly1305", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "seal/open round-trip, tamper rejection, AD mismatch", .{ .tls_record, .quic_packet_protection }, "AEAD additions require QUIC packet-protection coverage."),
    row(.{ .group = .x25519 }, "X25519", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "std.crypto scalar multiplication parity, low-order rejection", .{ .tls_handshake, .quic_tls_bridge }, "Group additions require key-share and shared-secret vectors."),
    row(.{ .group = .secp256r1 }, "secp256r1 (P-256)", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "capability rejection tests", .{ .tls_handshake, .quic_tls_bridge, .pki }, "P-256 support requires explicit provider implementation and ECDH vectors."),
    row(.{ .signature = .ed25519 }, "Ed25519", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "sign/verify, tamper rejection, wrong-key rejection", .{ .tls_handshake, .pki }, "Signature additions require CertificateVerify vectors."),
    row(.{ .signature = .ecdsa_secp256r1_sha256 }, "ECDSA-P256-SHA256", .zig_std_crypto, .supported, .openssl_provider, .provider_deferred, "SEC1 key/DER signature verify, tamper, wrong-key, non-canonical-signature rejection (#343)", .{ .tls_handshake, .pki }, "ECDSA verification only; the secp256r1 ECDH group remains deferred."),
    row(.{ .signature = .rsa_pss_rsae_sha256 }, "RSA-PSS-RSAE-SHA256", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "capability rejection tests", .{ .tls_handshake, .pki }, "Deferred: Zig 0.16 std EMSA-PSS-VERIFY does not validate the full PS zero-padding region (RFC 8017); re-enable with a conformant verifier (#343)."),
    row(.{ .certificate_helper = .der_parser }, "DER/X.509 parser helpers", .project_code, .provider_deferred, .openssl_provider, .provider_deferred, "module-local parser fixtures", .{.pki}, "Certificate helpers require malformed-input and corpus tests."),
    row(.{ .certificate_helper = .chain_builder }, "certificate chain builder", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "tracked by PKI stories", .{.pki}, "Chain validation requires path-building fixtures."),
    row(.{ .certificate_helper = .webpki_validation }, "WebPKI validation", .unavailable, .provider_deferred, .openssl_provider, .provider_deferred, "tracked by PKI stories", .{.pki}, "WebPKI support requires policy and time-validation review."),
    row(.{ .entropy = .injected_random_bytes }, "injected random bytes", .project_code, .supported, .openssl_provider, .provider_deferred, "deterministic and failing entropy tests", .{ .tls_handshake, .quic_packet_protection, .resumption }, "Randomness changes require no-ambient-RNG review."),
    row(.{ .entropy = .secure_zero }, "secure zero", .project_code, .supported, .project_code, .supported, "secret-container and provider wipe tests", .{ .tls_handshake, .tls_record, .quic_packet_protection, .pki, .resumption }, "Secret handling changes require wipe-on-error review."),
    row(.{ .entropy = .constant_time_compare }, "constant-time compare", .project_code, .supported, .project_code, .supported, "crypto secret helper tests", .{ .tls_handshake, .tls_record, .pki }, "Comparison changes require timing-safe API review."),
};

fn row(
    algorithm: Algorithm,
    name: []const u8,
    pure_zig_implementation: Implementation,
    pure_zig_status: Status,
    openssl_implementation: Implementation,
    openssl_status: Status,
    tests: []const u8,
    comptime consumers_list: anytype,
    review: []const u8,
) Row {
    return .{
        .algorithm = algorithm,
        .name = name,
        .pure_zig_implementation = pure_zig_implementation,
        .pure_zig_status = pure_zig_status,
        .openssl_implementation = openssl_implementation,
        .openssl_status = openssl_status,
        .tests = tests,
        .consumers = consumerSet(consumers_list),
        .review = review,
    };
}

fn consumerSet(comptime items: anytype) ConsumerSet {
    var set = ConsumerSet{};
    inline for (items) |item| set.insert(item);
    return set;
}

pub fn status(kind: ProviderKind, algorithm: Algorithm) Status {
    for (rows) |entry| {
        if (algorithmEql(entry.algorithm, algorithm)) {
            return switch (kind) {
                .pure_zig => entry.pure_zig_status,
                .openssl => entry.openssl_status,
            };
        }
    }
    return .unsupported;
}

pub fn capabilities(kind: ProviderKind) provider.Capabilities {
    var caps = provider.Capabilities{};
    for (rows) |entry| {
        if (rowStatus(kind, entry) != .supported) continue;
        switch (entry.algorithm) {
            .hash => |hash| caps.hashes.insert(hash),
            .aead => |aead| caps.aeads.insert(aead),
            .group => |group| caps.groups.insert(group),
            .signature => |scheme| caps.signatures.insert(scheme),
            .hkdf, .certificate_helper, .entropy => {},
        }
    }
    return caps;
}

fn rowStatus(kind: ProviderKind, entry: Row) Status {
    return switch (kind) {
        .pure_zig => entry.pure_zig_status,
        .openssl => entry.openssl_status,
    };
}

fn algorithmEql(a: Algorithm, b: Algorithm) bool {
    return switch (a) {
        .hash => |value| b == .hash and b.hash == value,
        .hkdf => |value| b == .hkdf and b.hkdf == value,
        .aead => |value| b == .aead and b.aead == value,
        .group => |value| b == .group and b.group == value,
        .signature => |value| b == .signature and b.signature == value,
        .certificate_helper => |value| b == .certificate_helper and b.certificate_helper == value,
        .entropy => |value| b == .entropy and b.entropy == value,
    };
}

fn expectRow(algorithm: Algorithm) !void {
    for (rows) |entry| {
        if (algorithmEql(entry.algorithm, algorithm)) return;
    }
    std.debug.print("missing crypto profile row for {any}\n", .{algorithm});
    return error.MissingProfileRow;
}

test "matrix covers every provider algorithm enum" {
    inline for (std.enums.values(provider.Hash)) |hash| {
        try expectRow(.{ .hash = hash });
        try expectRow(.{ .hkdf = hash });
    }
    inline for (std.enums.values(provider.Aead)) |aead| try expectRow(.{ .aead = aead });
    inline for (std.enums.values(provider.Group)) |group| try expectRow(.{ .group = group });
    inline for (std.enums.values(provider.SignatureScheme)) |scheme| try expectRow(.{ .signature = scheme });
    inline for (std.enums.values(CertificateHelper)) |helper| try expectRow(.{ .certificate_helper = helper });
    inline for (std.enums.values(EntropyCapability)) |capability| try expectRow(.{ .entropy = capability });
}

test "pure-Zig profile capabilities are queryable" {
    const caps = capabilities(.pure_zig);
    try std.testing.expect(caps.supportsHash(.sha256));
    try std.testing.expect(caps.supportsHash(.sha384));
    try std.testing.expect(caps.supportsAead(.aes_128_gcm));
    try std.testing.expect(caps.supportsAead(.aes_256_gcm));
    try std.testing.expect(caps.supportsAead(.chacha20_poly1305));
    try std.testing.expect(caps.supportsGroup(.x25519));
    try std.testing.expect(!caps.supportsGroup(.secp256r1));
    try std.testing.expect(caps.supportsSignature(.ed25519));
    try std.testing.expect(caps.supportsSignature(.ecdsa_secp256r1_sha256));
    // RSA-PSS verification is deferred pending a conformant PSS verifier.
    try std.testing.expect(!caps.supportsSignature(.rsa_pss_rsae_sha256));
}

//! TLS 1.3 algorithm and extension registries.
//!
//! These values are protocol identifiers, not implementation choices. The
//! policy layer decides which identifiers are enabled and preferred for a
//! particular transport or provider.

const std = @import("std");

pub const ProtocolVersion = enum(u16) {
    tls13 = 0x0304,
};

pub const legacy_version: u16 = 0x0303;

pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
};

/// Transcript/HKDF hash identifiers a `CipherSuite` can bind to. Callers must
/// derive this from the cipher suite (`transcriptHash`) rather than
/// persisting or selecting it independently, so the two can never disagree.
pub const TranscriptHash = enum {
    sha256,
    sha384,

    pub fn digestLen(self: TranscriptHash) usize {
        return switch (self) {
            .sha256 => std.crypto.hash.sha2.Sha256.digest_length,
            .sha384 => std.crypto.hash.sha2.Sha384.digest_length,
        };
    }
};

/// The canonical transcript/HKDF hash for a cipher suite. This is the single
/// source of truth other modules (key schedule, resumable-session model)
/// must use instead of maintaining their own suite-to-hash switch.
pub fn transcriptHash(suite: CipherSuite) TranscriptHash {
    return switch (suite) {
        .tls_aes_128_gcm_sha256, .tls_chacha20_poly1305_sha256 => .sha256,
        .tls_aes_256_gcm_sha384 => .sha384,
    };
}

pub const NamedGroup = enum(u16) {
    x25519 = 0x001d,
    secp256r1 = 0x0017,
    secp384r1 = 0x0018,
};

pub const SignatureScheme = enum(u16) {
    rsa_pkcs1_sha256 = 0x0401,
    ecdsa_secp256r1_sha256 = 0x0403,
    rsa_pss_rsae_sha256 = 0x0804,
    ed25519 = 0x0807,
};

pub const ExtensionType = enum(u16) {
    server_name = 0,
    supported_groups = 10,
    signature_algorithms = 13,
    application_layer_protocol_negotiation = 16,
    supported_versions = 43,
    key_share = 51,
    quic_transport_parameters = 57,
};

pub const ProtocolName = struct {
    bytes: []const u8,

    pub fn eql(self: ProtocolName, other: ProtocolName) bool {
        return std.mem.eql(u8, self.bytes, other.bytes);
    }
};

pub const alpn = struct {
    pub const h3: ProtocolName = .{ .bytes = "h3" };
    pub const h2: ProtocolName = .{ .bytes = "h2" };
    pub const http_1_1: ProtocolName = .{ .bytes = "http/1.1" };
};

pub fn fromInt(comptime T: type, value: u16) ?T {
    return std.enums.fromInt(T, value);
}

test "registry exposes current TLS identifiers" {
    try std.testing.expectEqual(@as(u16, 0x1301), @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
    try std.testing.expectEqual(@as(u16, 0x001d), @intFromEnum(NamedGroup.x25519));
    try std.testing.expectEqual(@as(u16, 0x0807), @intFromEnum(SignatureScheme.ed25519));
    try std.testing.expect(alpn.h3.eql(.{ .bytes = "h3" }));
}

test "transcriptHash derives the correct hash and digest length per suite" {
    try std.testing.expectEqual(TranscriptHash.sha256, transcriptHash(.tls_aes_128_gcm_sha256));
    try std.testing.expectEqual(TranscriptHash.sha256, transcriptHash(.tls_chacha20_poly1305_sha256));
    try std.testing.expectEqual(TranscriptHash.sha384, transcriptHash(.tls_aes_256_gcm_sha384));

    try std.testing.expectEqual(@as(usize, 32), TranscriptHash.sha256.digestLen());
    try std.testing.expectEqual(@as(usize, 48), TranscriptHash.sha384.digestLen());
}

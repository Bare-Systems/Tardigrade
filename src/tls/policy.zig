//! TLS negotiation policy and provider capability vocabulary.

const state = @import("state.zig");
const algorithms = @import("algorithms.zig");
const record_size = @import("record_size.zig");

pub const CipherSuite = algorithms.CipherSuite;
pub const NamedGroup = algorithms.NamedGroup;
pub const SignatureScheme = algorithms.SignatureScheme;
pub const ProtocolVersion = algorithms.ProtocolVersion;
pub const ProtocolName = algorithms.ProtocolName;

const default_protocol_versions = [_]ProtocolVersion{.tls13};
const default_cipher_suites = [_]CipherSuite{.tls_aes_128_gcm_sha256};
const quic_cipher_suites = [_]CipherSuite{
    .tls_aes_128_gcm_sha256,
    .tls_aes_256_gcm_sha384,
    .tls_chacha20_poly1305_sha256,
};
const default_named_groups = [_]NamedGroup{.x25519};
// #565: RSA-PSS is deliberately left out of `default_signature_schemes`. Many
// tests pin transcript-derived secrets against the exact default ClientHello
// wire bytes (see `tls13_backend_tests.zig`'s golden-secret tests); widening
// the default `signature_algorithms` offer would silently reflow every one
// of those goldens. Callers that want RSA-PSS reachable — an RSA identity via
// `fromIdentity`, or the engine's full native capability set via
// `tls13_backend.native_capabilities` — opt in explicitly instead.
const default_signature_schemes = [_]SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256 };
const ed25519_signature_schemes = [_]SignatureScheme{.ed25519};
const ecdsa_p256_signature_schemes = [_]SignatureScheme{.ecdsa_secp256r1_sha256};
const rsa_signature_schemes = [_]SignatureScheme{.rsa_pss_rsae_sha256};
const quic_alpns = [_]ProtocolName{algorithms.alpn.h3};
const record_h2_alpns = [_]ProtocolName{algorithms.alpn.h2};
const record_http1_alpns = [_]ProtocolName{algorithms.alpn.http_1_1};
const record_alpns = [_]ProtocolName{ algorithms.alpn.h2, algorithms.alpn.http_1_1 };

pub const Error = error{UnsupportedIdentitySignature};

pub const IdentityKey = enum {
    ed25519,
    ecdsa_secp256r1,
    rsa,
};

pub const Capabilities = struct {
    protocol_versions: []const ProtocolVersion = &default_protocol_versions,
    cipher_suites: []const CipherSuite = &default_cipher_suites,
    named_groups: []const NamedGroup = &default_named_groups,
    signature_schemes: []const SignatureScheme = &default_signature_schemes,
};

pub const Policy = struct {
    transport_mode: state.TransportMode,
    protocol_versions: []const ProtocolVersion = &default_protocol_versions,
    cipher_suites: []const CipherSuite,
    named_groups: []const NamedGroup,
    signature_schemes: []const SignatureScheme,
    alpn_protocols: []const ProtocolName,
    require_sni: bool = false,
    allow_absent_alpn: bool = false,
    /// Protocols that may only be negotiated when the ClientHello's *entire*
    /// offered ALPN list is exactly that one protocol (#939, RFC 8737
    /// TLS-ALPN-01): never for an absent, ordinary, mixed, or duplicated
    /// offer. Every entry here must also appear in `alpn_protocols` (so the
    /// ordinary encode-length/duplicate validation already covers it); this
    /// list only narrows *when* `negotiateServerHello` is willing to select
    /// it. Empty by default -- every existing policy negotiates exactly as
    /// before.
    exclusive_only_alpn_protocols: []const ProtocolName = &.{},
    /// The `record_size_limit` this endpoint advertises (RFC 8449, #359): the
    /// largest `TLSInnerPlaintext` it is willing to *receive*. Defaults to the
    /// TLS 1.3 protocol maximum, so the extension is offered but constrains
    /// nothing until an operator lowers it — an endpoint that supports every
    /// record size interoperates most widely by saying exactly that.
    ///
    /// Record transport only. RFC 8449 is defined over TLS/DTLS records, which
    /// QUIC does not use (RFC 9001 carries handshake bytes in CRYPTO frames
    /// and bounds application data with its own flow control), so a
    /// `.quic` policy never puts this on the wire.
    record_size_limit: u16 = record_size.default_limit,

    pub fn quicDefault() Policy {
        return .{
            .transport_mode = .quic,
            .protocol_versions = &default_protocol_versions,
            .cipher_suites = &quic_cipher_suites,
            .named_groups = &default_named_groups,
            .signature_schemes = &default_signature_schemes,
            .alpn_protocols = &quic_alpns,
        };
    }

    pub fn recordDefault() Policy {
        return .{
            .transport_mode = .record,
            .protocol_versions = &default_protocol_versions,
            .cipher_suites = &default_cipher_suites,
            .named_groups = &default_named_groups,
            .signature_schemes = &default_signature_schemes,
            .alpn_protocols = &record_alpns,
        };
    }

    pub fn recordH2Only() Policy {
        return .{
            .transport_mode = .record,
            .protocol_versions = &default_protocol_versions,
            .cipher_suites = &default_cipher_suites,
            .named_groups = &default_named_groups,
            .signature_schemes = &default_signature_schemes,
            .alpn_protocols = &record_h2_alpns,
        };
    }

    pub fn recordHttp1Only(allow_absent_alpn: bool) Policy {
        return .{
            .transport_mode = .record,
            .protocol_versions = &default_protocol_versions,
            .cipher_suites = &default_cipher_suites,
            .named_groups = &default_named_groups,
            .signature_schemes = &default_signature_schemes,
            .alpn_protocols = &record_http1_alpns,
            .allow_absent_alpn = allow_absent_alpn,
        };
    }

    pub fn fromCapabilities(transport_mode: state.TransportMode, capabilities: Capabilities, alpn_protocols: []const ProtocolName) Policy {
        return .{
            .transport_mode = transport_mode,
            .protocol_versions = capabilities.protocol_versions,
            .cipher_suites = capabilities.cipher_suites,
            .named_groups = capabilities.named_groups,
            .signature_schemes = capabilities.signature_schemes,
            .alpn_protocols = alpn_protocols,
        };
    }

    pub fn fromIdentity(transport_mode: state.TransportMode, capabilities: Capabilities, alpn_protocols: []const ProtocolName, identity_key: IdentityKey) Error!Policy {
        const identity_schemes = signatureSchemesForIdentity(identity_key);
        for (identity_schemes) |scheme| {
            if (!containsSignature(capabilities.signature_schemes, scheme)) return error.UnsupportedIdentitySignature;
        }
        return .{
            .transport_mode = transport_mode,
            .protocol_versions = capabilities.protocol_versions,
            .cipher_suites = capabilities.cipher_suites,
            .named_groups = capabilities.named_groups,
            .signature_schemes = identity_schemes,
            .alpn_protocols = alpn_protocols,
        };
    }

    pub fn containsProtocolVersion(self: Policy, version: ProtocolVersion) bool {
        return containsEnum(ProtocolVersion, self.protocol_versions, version);
    }

    pub fn containsCipherSuite(self: Policy, cipher_suite: CipherSuite) bool {
        return containsEnum(CipherSuite, self.cipher_suites, cipher_suite);
    }

    pub fn containsNamedGroup(self: Policy, group: NamedGroup) bool {
        return containsEnum(NamedGroup, self.named_groups, group);
    }

    pub fn containsSignatureScheme(self: Policy, scheme: SignatureScheme) bool {
        return containsEnum(SignatureScheme, self.signature_schemes, scheme);
    }

    pub fn containsAlpn(self: Policy, name: []const u8) bool {
        for (self.alpn_protocols) |protocol| {
            if (protocol.eql(.{ .bytes = name })) return true;
        }
        return false;
    }

    pub fn firstAlpn(self: Policy) []const u8 {
        return if (self.alpn_protocols.len > 0) self.alpn_protocols[0].bytes else "";
    }
};

pub fn signatureSchemesForIdentity(identity_key: IdentityKey) []const SignatureScheme {
    return switch (identity_key) {
        .ed25519 => &ed25519_signature_schemes,
        .ecdsa_secp256r1 => &ecdsa_p256_signature_schemes,
        .rsa => &rsa_signature_schemes,
    };
}

fn containsSignature(schemes: []const SignatureScheme, needle: SignatureScheme) bool {
    return containsEnum(SignatureScheme, schemes, needle);
}

fn containsEnum(comptime T: type, values: []const T, needle: T) bool {
    for (values) |value| {
        if (value == needle) return true;
    }
    return false;
}

pub fn alpnFromBytes(bytes: []const u8) ProtocolName {
    return .{ .bytes = bytes };
}

pub fn alpnListFromByteNames(out: []ProtocolName, names: []const []const u8) []const ProtocolName {
    for (names, 0..) |name, i| {
        out[i] = .{ .bytes = name };
    }
    return out[0..names.len];
}

test "default policies keep QUIC and record ALPN choices separate" {
    const quic = Policy.quicDefault();
    try @import("std").testing.expect(quic.alpn_protocols[0].eql(algorithms.alpn.h3));

    const record = Policy.recordDefault();
    try @import("std").testing.expect(record.alpn_protocols[0].eql(algorithms.alpn.h2));
    try @import("std").testing.expect(record.alpn_protocols[1].eql(algorithms.alpn.http_1_1));
}

test "identity policies constrain usable signature schemes" {
    const std = @import("std");
    const alpns = [_]ProtocolName{algorithms.alpn.h3};

    const p256 = try Policy.fromIdentity(.quic, .{}, &alpns, .ecdsa_secp256r1);
    try std.testing.expectEqual(@as(usize, 1), p256.signature_schemes.len);
    try std.testing.expectEqual(SignatureScheme.ecdsa_secp256r1_sha256, p256.signature_schemes[0]);

    const ed25519_only = Capabilities{ .signature_schemes = &ed25519_signature_schemes };
    try std.testing.expectError(error.UnsupportedIdentitySignature, Policy.fromIdentity(.quic, ed25519_only, &alpns, .ecdsa_secp256r1));

    const rsa_capable = Capabilities{ .signature_schemes = &.{ .ed25519, .ecdsa_secp256r1_sha256, .rsa_pss_rsae_sha256 } };
    const rsa = try Policy.fromIdentity(.quic, rsa_capable, &alpns, .rsa);
    try std.testing.expectEqual(@as(usize, 1), rsa.signature_schemes.len);
    try std.testing.expectEqual(SignatureScheme.rsa_pss_rsae_sha256, rsa.signature_schemes[0]);
    try std.testing.expectError(error.UnsupportedIdentitySignature, Policy.fromIdentity(.quic, ed25519_only, &alpns, .rsa));
    try std.testing.expectError(error.UnsupportedIdentitySignature, Policy.fromIdentity(.quic, .{}, &alpns, .rsa));
}

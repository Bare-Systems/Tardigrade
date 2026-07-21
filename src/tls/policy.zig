//! TLS negotiation policy and provider capability vocabulary.

const state = @import("state.zig");
const algorithms = @import("algorithms.zig");

pub const CipherSuite = algorithms.CipherSuite;
pub const NamedGroup = algorithms.NamedGroup;
pub const SignatureScheme = algorithms.SignatureScheme;
pub const ProtocolVersion = algorithms.ProtocolVersion;
pub const ProtocolName = algorithms.ProtocolName;

const default_protocol_versions = [_]ProtocolVersion{.tls13};
const default_cipher_suites = [_]CipherSuite{.tls_aes_128_gcm_sha256};
const default_named_groups = [_]NamedGroup{.x25519};
const default_signature_schemes = [_]SignatureScheme{ .ed25519, .ecdsa_secp256r1_sha256 };
const ed25519_signature_schemes = [_]SignatureScheme{.ed25519};
const ecdsa_p256_signature_schemes = [_]SignatureScheme{.ecdsa_secp256r1_sha256};
const quic_alpns = [_]ProtocolName{algorithms.alpn.h3};
const record_h2_alpns = [_]ProtocolName{algorithms.alpn.h2};
const record_http1_alpns = [_]ProtocolName{algorithms.alpn.http_1_1};
const record_alpns = [_]ProtocolName{ algorithms.alpn.h2, algorithms.alpn.http_1_1 };

pub const Error = error{UnsupportedIdentitySignature};

pub const IdentityKey = enum {
    ed25519,
    ecdsa_secp256r1,
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

    pub fn quicDefault() Policy {
        return .{
            .transport_mode = .quic,
            .protocol_versions = &default_protocol_versions,
            .cipher_suites = &default_cipher_suites,
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
}

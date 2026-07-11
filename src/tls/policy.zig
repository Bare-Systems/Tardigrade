//! TLS negotiation policy and provider capability vocabulary.

const state = @import("state.zig");
const algorithms = @import("algorithms.zig");

pub const CipherSuite = algorithms.CipherSuite;
pub const NamedGroup = algorithms.NamedGroup;
pub const SignatureScheme = algorithms.SignatureScheme;
pub const ProtocolName = algorithms.ProtocolName;

const default_cipher_suites = [_]CipherSuite{.tls_aes_128_gcm_sha256};
const default_named_groups = [_]NamedGroup{.x25519};
const default_signature_schemes = [_]SignatureScheme{.ed25519};
const quic_alpns = [_]ProtocolName{algorithms.alpn.h3};
const record_alpns = [_]ProtocolName{ algorithms.alpn.h2, algorithms.alpn.http_1_1 };

pub const Capabilities = struct {
    cipher_suites: []const CipherSuite = &default_cipher_suites,
    named_groups: []const NamedGroup = &default_named_groups,
    signature_schemes: []const SignatureScheme = &default_signature_schemes,
};

pub const Policy = struct {
    transport_mode: state.TransportMode,
    cipher_suites: []const CipherSuite,
    named_groups: []const NamedGroup,
    signature_schemes: []const SignatureScheme,
    alpn_protocols: []const ProtocolName,
    require_sni: bool = false,

    pub fn quicDefault() Policy {
        return .{
            .transport_mode = .quic,
            .cipher_suites = &default_cipher_suites,
            .named_groups = &default_named_groups,
            .signature_schemes = &default_signature_schemes,
            .alpn_protocols = &quic_alpns,
        };
    }

    pub fn recordDefault() Policy {
        return .{
            .transport_mode = .record,
            .cipher_suites = &default_cipher_suites,
            .named_groups = &default_named_groups,
            .signature_schemes = &default_signature_schemes,
            .alpn_protocols = &record_alpns,
        };
    }

    pub fn fromCapabilities(transport_mode: state.TransportMode, capabilities: Capabilities, alpn_protocols: []const ProtocolName) Policy {
        return .{
            .transport_mode = transport_mode,
            .cipher_suites = capabilities.cipher_suites,
            .named_groups = capabilities.named_groups,
            .signature_schemes = capabilities.signature_schemes,
            .alpn_protocols = alpn_protocols,
        };
    }
};

test "default policies keep QUIC and record ALPN choices separate" {
    const quic = Policy.quicDefault();
    try @import("std").testing.expect(quic.alpn_protocols[0].eql(algorithms.alpn.h3));

    const record = Policy.recordDefault();
    try @import("std").testing.expect(record.alpn_protocols[0].eql(algorithms.alpn.h2));
    try @import("std").testing.expect(record.alpn_protocols[1].eql(algorithms.alpn.http_1_1));
}

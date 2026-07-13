//! TLS-side adapter for the provider-neutral crypto capability matrix.

const std = @import("std");
const crypto = @import("crypto");
const provider = crypto.provider;
const profile = crypto.profile;
const policy_mod = @import("policy.zig");
const state = @import("state.zig");

pub const TlsCapabilityError = error{UnsupportedCapability};

pub const TlsCapabilities = struct {
    cipher_suites: [3]policy_mod.CipherSuite = undefined,
    cipher_suites_len: usize = 0,
    named_groups: [2]policy_mod.NamedGroup = undefined,
    named_groups_len: usize = 0,
    signature_schemes: [3]policy_mod.SignatureScheme = undefined,
    signature_schemes_len: usize = 0,

    pub fn asPolicyCapabilities(self: *const TlsCapabilities) policy_mod.Capabilities {
        return .{
            .cipher_suites = self.cipher_suites[0..self.cipher_suites_len],
            .named_groups = self.named_groups[0..self.named_groups_len],
            .signature_schemes = self.signature_schemes[0..self.signature_schemes_len],
        };
    }

    pub fn policy(self: *const TlsCapabilities, transport_mode: state.TransportMode, alpns: []const policy_mod.ProtocolName) policy_mod.Policy {
        return policy_mod.Policy.fromCapabilities(transport_mode, self.asPolicyCapabilities(), alpns);
    }

    fn appendCipher(self: *TlsCapabilities, suite: policy_mod.CipherSuite) void {
        self.cipher_suites[self.cipher_suites_len] = suite;
        self.cipher_suites_len += 1;
    }

    fn appendGroup(self: *TlsCapabilities, group: policy_mod.NamedGroup) void {
        self.named_groups[self.named_groups_len] = group;
        self.named_groups_len += 1;
    }

    fn appendSignature(self: *TlsCapabilities, scheme: policy_mod.SignatureScheme) void {
        self.signature_schemes[self.signature_schemes_len] = scheme;
        self.signature_schemes_len += 1;
    }
};

pub fn fromProvider(caps: provider.Capabilities) TlsCapabilities {
    var out = TlsCapabilities{};
    if (supportsCipherSuite(caps, .tls_aes_128_gcm_sha256)) out.appendCipher(.tls_aes_128_gcm_sha256);
    if (supportsCipherSuite(caps, .tls_aes_256_gcm_sha384)) out.appendCipher(.tls_aes_256_gcm_sha384);
    if (supportsCipherSuite(caps, .tls_chacha20_poly1305_sha256)) out.appendCipher(.tls_chacha20_poly1305_sha256);
    if (supportsNamedGroup(caps, .x25519)) out.appendGroup(.x25519);
    if (supportsNamedGroup(caps, .secp256r1)) out.appendGroup(.secp256r1);
    if (supportsSignatureScheme(caps, .ed25519)) out.appendSignature(.ed25519);
    if (supportsSignatureScheme(caps, .ecdsa_secp256r1_sha256)) out.appendSignature(.ecdsa_secp256r1_sha256);
    if (supportsSignatureScheme(caps, .rsa_pss_rsae_sha256)) out.appendSignature(.rsa_pss_rsae_sha256);
    return out;
}

pub fn validateAgainstProvider(caps: provider.Capabilities, tls_caps: policy_mod.Capabilities) TlsCapabilityError!void {
    for (tls_caps.cipher_suites) |suite| {
        if (!supportsCipherSuite(caps, suite)) return error.UnsupportedCapability;
    }
    for (tls_caps.named_groups) |group| {
        if (!supportsNamedGroup(caps, group)) return error.UnsupportedCapability;
    }
    for (tls_caps.signature_schemes) |scheme| {
        if (!supportsSignatureScheme(caps, scheme)) return error.UnsupportedCapability;
    }
}

pub fn supportsCipherSuite(caps: provider.Capabilities, suite: policy_mod.CipherSuite) bool {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => caps.supportsAead(.aes_128_gcm) and caps.supportsHash(.sha256),
        .tls_aes_256_gcm_sha384 => caps.supportsAead(.aes_256_gcm) and caps.supportsHash(.sha384),
        .tls_chacha20_poly1305_sha256 => caps.supportsAead(.chacha20_poly1305) and caps.supportsHash(.sha256),
    };
}

pub fn supportsNamedGroup(caps: provider.Capabilities, group: policy_mod.NamedGroup) bool {
    return switch (group) {
        .x25519 => caps.supportsGroup(.x25519),
        .secp256r1 => caps.supportsGroup(.secp256r1),
        .secp384r1 => false,
    };
}

pub fn supportsSignatureScheme(caps: provider.Capabilities, scheme: policy_mod.SignatureScheme) bool {
    return switch (scheme) {
        .ed25519 => caps.supportsSignature(.ed25519),
        .ecdsa_secp256r1_sha256 => caps.supportsSignature(.ecdsa_secp256r1_sha256),
        .rsa_pss_rsae_sha256 => caps.supportsSignature(.rsa_pss_rsae_sha256),
        .rsa_pkcs1_sha256 => false,
    };
}

test "TLS policy capabilities are derived from provider support" {
    const tls_caps = fromProvider(profile.capabilities(.pure_zig));
    try std.testing.expectEqual(@as(usize, 3), tls_caps.cipher_suites_len);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_aes_128_gcm_sha256, tls_caps.cipher_suites[0]);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_aes_256_gcm_sha384, tls_caps.cipher_suites[1]);
    try std.testing.expectEqual(policy_mod.CipherSuite.tls_chacha20_poly1305_sha256, tls_caps.cipher_suites[2]);
    try std.testing.expectEqual(@as(usize, 1), tls_caps.named_groups_len);
    try std.testing.expectEqual(policy_mod.NamedGroup.x25519, tls_caps.named_groups[0]);
    // Ed25519 and ECDSA-P256/SHA-256 verification are provider-backed since
    // #343; RSA-PSS is deferred pending a conformant PSS verifier.
    try std.testing.expectEqual(@as(usize, 2), tls_caps.signature_schemes_len);
    try std.testing.expectEqual(policy_mod.SignatureScheme.ed25519, tls_caps.signature_schemes[0]);
    try std.testing.expectEqual(policy_mod.SignatureScheme.ecdsa_secp256r1_sha256, tls_caps.signature_schemes[1]);
}

test "hand-written TLS policy capabilities are rejected when provider cannot support them" {
    const caps = profile.capabilities(.pure_zig);
    const derived = fromProvider(caps);
    try validateAgainstProvider(caps, derived.asPolicyCapabilities());

    // The secp256r1 ECDH group is still provider-deferred (only the signature
    // scheme over that curve is implemented).
    const bad_groups = [_]policy_mod.NamedGroup{.secp256r1};
    try std.testing.expectError(error.UnsupportedCapability, validateAgainstProvider(caps, .{ .named_groups = &bad_groups }));

    // RSA schemes remain unsupported: PKCS#1 v1.5 is out of scope, and RSA-PSS
    // is deferred pending a conformant PSS verifier.
    const bad_pkcs1 = [_]policy_mod.SignatureScheme{.rsa_pkcs1_sha256};
    try std.testing.expectError(error.UnsupportedCapability, validateAgainstProvider(caps, .{ .signature_schemes = &bad_pkcs1 }));
    const bad_pss = [_]policy_mod.SignatureScheme{.rsa_pss_rsae_sha256};
    try std.testing.expectError(error.UnsupportedCapability, validateAgainstProvider(caps, .{ .signature_schemes = &bad_pss }));
}

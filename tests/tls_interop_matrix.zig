//! Shared interoperability/conformance matrix vocabulary (#338).
//!
//! The external conformance suite drives the *same* TLS 1.3 engine over two
//! transports: the record transport (`tls_interop_tool`) and the QUIC
//! transport (`h3_interop_tool`). Both need to name the same negotiation
//! tuple on a command line, turn it into a `tls_core.policy.Policy`, and
//! report what was actually negotiated in the same words. That mapping lives
//! here exactly once, so a row in the matrix means the same thing on either
//! transport and adding a suite/group/signature cannot drift between them.
//!
//! This module deliberately owns *only* the vocabulary and the policy
//! construction. Carrier I/O, process lifetime, and result reporting belong
//! to the individual tools -- those genuinely differ between a TCP record
//! stream and a UDP QUIC connection, and pretending otherwise would produce
//! an abstraction neither tool wants.

const std = @import("std");
const tls_core = @import("tls_core");

const algorithms = tls_core.algorithms;
const tls_policy = tls_core.policy;
const tls_state = tls_core.state;

pub const CipherSuite = algorithms.CipherSuite;
pub const NamedGroup = algorithms.NamedGroup;
pub const SignatureScheme = algorithms.SignatureScheme;

pub const ParseError = error{ UnknownCipherSuite, UnknownNamedGroup, UnknownSignatureScheme, TooManyValues };

/// Every cipher suite the shared engine can negotiate, in the order the
/// matrix enumerates them. Derived from the engine's own capability set
/// rather than restated, so a suite added to `native_capabilities` shows up
/// as a new matrix row instead of being silently skipped.
pub const cipher_suites: []const CipherSuite = tls_core.tls13_backend.native_capabilities.cipher_suites;
pub const named_groups: []const NamedGroup = tls_core.tls13_backend.native_capabilities.named_groups;
pub const signature_schemes: []const SignatureScheme = tls_core.tls13_backend.native_capabilities.signature_schemes;

/// Upper bound on how many values of one dimension a single run may select.
/// Sized from the engine's capability lists so a caller can always offer
/// "everything supported" without a heap allocation.
pub const max_values = @max(cipher_suites.len, @max(named_groups.len, signature_schemes.len));
pub const max_alpn_protocols = 4;

/// The matrix's own spelling of each identifier. These strings are the
/// stable contract between the runner script, the tools' `--cipher-suite`/
/// `--group`/`--signature` flags, and the emitted result lines -- a grep for
/// `suite=chacha20-poly1305-sha256` in CI logs must keep working.
pub fn cipherSuiteName(suite: CipherSuite) []const u8 {
    return switch (suite) {
        .tls_aes_128_gcm_sha256 => "aes128-gcm-sha256",
        .tls_aes_256_gcm_sha384 => "aes256-gcm-sha384",
        .tls_chacha20_poly1305_sha256 => "chacha20-poly1305-sha256",
    };
}

pub fn namedGroupName(group: NamedGroup) []const u8 {
    return switch (group) {
        .x25519 => "x25519",
        .secp256r1 => "secp256r1",
        .secp384r1 => "secp384r1",
    };
}

pub fn signatureSchemeName(scheme: SignatureScheme) []const u8 {
    return switch (scheme) {
        .ed25519 => "ed25519",
        .ecdsa_secp256r1_sha256 => "ecdsa-p256-sha256",
        .rsa_pss_rsae_sha256 => "rsa-pss-rsae-sha256",
        .rsa_pkcs1_sha256 => "rsa-pkcs1-sha256",
    };
}

pub fn parseCipherSuite(name: []const u8) ParseError!CipherSuite {
    inline for (comptime std.enums.values(CipherSuite)) |suite| {
        if (std.mem.eql(u8, name, cipherSuiteName(suite))) return suite;
    }
    return error.UnknownCipherSuite;
}

pub fn parseNamedGroup(name: []const u8) ParseError!NamedGroup {
    inline for (comptime std.enums.values(NamedGroup)) |group| {
        if (std.mem.eql(u8, name, namedGroupName(group))) return group;
    }
    return error.UnknownNamedGroup;
}

pub fn parseSignatureScheme(name: []const u8) ParseError!SignatureScheme {
    inline for (comptime std.enums.values(SignatureScheme)) |scheme| {
        if (std.mem.eql(u8, name, signatureSchemeName(scheme))) return scheme;
    }
    return error.UnknownSignatureScheme;
}

/// Which private-key type a signature scheme requires the local identity to
/// hold. The runner uses the matrix's signature dimension to pick the
/// certificate/key pair it hands the tool, so the two can never disagree
/// about which credential a row needs.
pub fn identityKeyForSignature(scheme: SignatureScheme) tls_policy.IdentityKey {
    return switch (scheme) {
        .ed25519 => .ed25519,
        .ecdsa_secp256r1_sha256 => .ecdsa_secp256r1,
        .rsa_pss_rsae_sha256, .rsa_pkcs1_sha256 => .rsa,
    };
}

/// A bounded, ordered selection along one matrix dimension. Empty means
/// "offer everything the engine supports", which is what a positive row
/// wants for the dimensions it is not pinning.
pub fn Selection(comptime T: type) type {
    return struct {
        const Self = @This();

        values: [max_values]T = undefined,
        len: usize = 0,

        pub fn append(self: *Self, value: T) ParseError!void {
            if (self.len == max_values) return error.TooManyValues;
            self.values[self.len] = value;
            self.len += 1;
        }

        /// `fallback` is used verbatim when nothing was selected, so an
        /// unpinned dimension offers the engine's full capability list
        /// rather than a silently narrowed subset.
        pub fn slice(self: *const Self, fallback: []const T) []const T {
            return if (self.len == 0) fallback else self.values[0..self.len];
        }
    };
}

/// The complete negotiation surface one interop run offers, independent of
/// transport. `alpn_protocols` is stored as borrowed byte slices: the caller
/// owns the argv strings for the process's lifetime.
pub const Config = struct {
    cipher_suites: Selection(CipherSuite) = .{},
    named_groups: Selection(NamedGroup) = .{},
    signature_schemes: Selection(SignatureScheme) = .{},
    alpn_storage: [max_alpn_protocols]algorithms.ProtocolName = undefined,
    alpn_len: usize = 0,
    require_sni: bool = false,
    allow_absent_alpn: bool = false,

    pub fn addCipherSuite(self: *Config, name: []const u8) ParseError!void {
        try self.cipher_suites.append(try parseCipherSuite(name));
    }

    pub fn addNamedGroup(self: *Config, name: []const u8) ParseError!void {
        try self.named_groups.append(try parseNamedGroup(name));
    }

    pub fn addSignatureScheme(self: *Config, name: []const u8) ParseError!void {
        try self.signature_schemes.append(try parseSignatureScheme(name));
    }

    pub fn addAlpn(self: *Config, name: []const u8) ParseError!void {
        if (self.alpn_len == max_alpn_protocols) return error.TooManyValues;
        self.alpn_storage[self.alpn_len] = .{ .bytes = name };
        self.alpn_len += 1;
    }

    pub fn alpnProtocols(self: *const Config, fallback: []const algorithms.ProtocolName) []const algorithms.ProtocolName {
        return if (self.alpn_len == 0) fallback else self.alpn_storage[0..self.alpn_len];
    }

    /// Build the engine policy for `transport_mode`. `default_alpns` is the
    /// transport's own default protocol list (h3 for QUIC, h2/http-1.1 for
    /// the record transport) -- the one genuinely transport-specific input,
    /// passed in rather than branched on here.
    ///
    /// Capabilities are *narrowed* from the engine's native set, never
    /// widened: a row can only ask for a tuple the engine already claims to
    /// support, so a passing matrix cell is evidence about production
    /// behaviour rather than about a test-only capability.
    pub fn policy(
        self: *const Config,
        transport_mode: tls_state.TransportMode,
        default_alpns: []const algorithms.ProtocolName,
    ) tls_policy.Policy {
        var result = tls_policy.Policy.fromCapabilities(transport_mode, .{
            .protocol_versions = tls_core.tls13_backend.native_capabilities.protocol_versions,
            .cipher_suites = self.cipher_suites.slice(cipher_suites),
            .named_groups = self.named_groups.slice(named_groups),
            .signature_schemes = self.signature_schemes.slice(signature_schemes),
        }, self.alpnProtocols(default_alpns));
        result.require_sni = self.require_sni;
        result.allow_absent_alpn = self.allow_absent_alpn;
        return result;
    }
};

/// One-line usage fragment shared by both tools' `--help` output, so the two
/// cannot document different spellings of the same flags.
pub const flag_usage =
    "  --cipher-suite NAME   repeatable: aes128-gcm-sha256 | aes256-gcm-sha384 | chacha20-poly1305-sha256\n" ++
    "  --group NAME          repeatable: x25519 | secp256r1\n" ++
    "  --signature NAME      repeatable: ed25519 | ecdsa-p256-sha256 | rsa-pss-rsae-sha256\n" ++
    "  --alpn NAME           repeatable application protocol name\n";

test "every engine-supported identifier has a matrix name that round-trips" {
    for (cipher_suites) |suite| {
        try std.testing.expectEqual(suite, try parseCipherSuite(cipherSuiteName(suite)));
    }
    for (named_groups) |group| {
        try std.testing.expectEqual(group, try parseNamedGroup(namedGroupName(group)));
    }
    for (signature_schemes) |scheme| {
        try std.testing.expectEqual(scheme, try parseSignatureScheme(signatureSchemeName(scheme)));
    }
}

test "matrix names are distinct across every enum value, not just the native subset" {
    // A name collision would make two matrix rows indistinguishable in a CI
    // log while still parsing, so check the whole registry -- including
    // identifiers the engine does not negotiate natively yet.
    inline for (comptime std.enums.values(SignatureScheme)) |a| {
        inline for (comptime std.enums.values(SignatureScheme)) |b| {
            if (a != b) try std.testing.expect(!std.mem.eql(u8, signatureSchemeName(a), signatureSchemeName(b)));
        }
    }
    inline for (comptime std.enums.values(NamedGroup)) |a| {
        inline for (comptime std.enums.values(NamedGroup)) |b| {
            if (a != b) try std.testing.expect(!std.mem.eql(u8, namedGroupName(a), namedGroupName(b)));
        }
    }
}

test "unknown identifiers are rejected rather than silently defaulted" {
    try std.testing.expectError(error.UnknownCipherSuite, parseCipherSuite("aes128-gcm"));
    try std.testing.expectError(error.UnknownNamedGroup, parseNamedGroup("X25519"));
    try std.testing.expectError(error.UnknownSignatureScheme, parseSignatureScheme("ed448"));
}

test "an unpinned dimension offers the engine's full native capability list" {
    var config = Config{};
    const record = config.policy(.record, &.{algorithms.alpn.http_1_1});
    try std.testing.expectEqualSlices(CipherSuite, cipher_suites, record.cipher_suites);
    try std.testing.expectEqualSlices(NamedGroup, named_groups, record.named_groups);
    try std.testing.expectEqualSlices(SignatureScheme, signature_schemes, record.signature_schemes);
    try std.testing.expectEqual(@as(usize, 1), record.alpn_protocols.len);
    try std.testing.expect(record.alpn_protocols[0].eql(algorithms.alpn.http_1_1));
}

test "a pinned tuple narrows every dimension to exactly what the row asked for" {
    var config = Config{};
    try config.addCipherSuite("chacha20-poly1305-sha256");
    try config.addNamedGroup("secp256r1");
    try config.addSignatureScheme("rsa-pss-rsae-sha256");
    try config.addAlpn("h2");

    const record = config.policy(.record, &.{algorithms.alpn.http_1_1});
    try std.testing.expectEqualSlices(CipherSuite, &.{.tls_chacha20_poly1305_sha256}, record.cipher_suites);
    try std.testing.expectEqualSlices(NamedGroup, &.{.secp256r1}, record.named_groups);
    try std.testing.expectEqualSlices(SignatureScheme, &.{.rsa_pss_rsae_sha256}, record.signature_schemes);
    try std.testing.expect(record.alpn_protocols[0].eql(algorithms.alpn.h2));
}

test "the same config yields the same tuple on both transports" {
    // The whole point of the shared vocabulary: a matrix row pinned once
    // produces identical negotiation inputs for the record and QUIC
    // transports, so a QUIC-only or record-only discrepancy is a real engine
    // difference rather than two harnesses disagreeing about the row.
    var config = Config{};
    try config.addCipherSuite("aes256-gcm-sha384");
    try config.addNamedGroup("x25519");
    try config.addSignatureScheme("ecdsa-p256-sha256");

    const record = config.policy(.record, &.{algorithms.alpn.h2});
    const quic = config.policy(.quic, &.{algorithms.alpn.h3});

    try std.testing.expectEqualSlices(CipherSuite, record.cipher_suites, quic.cipher_suites);
    try std.testing.expectEqualSlices(NamedGroup, record.named_groups, quic.named_groups);
    try std.testing.expectEqualSlices(SignatureScheme, record.signature_schemes, quic.signature_schemes);
    try std.testing.expectEqual(tls_state.TransportMode.record, record.transport_mode);
    try std.testing.expectEqual(tls_state.TransportMode.quic, quic.transport_mode);
}

test "a dimension cannot be selected beyond the engine's capability count" {
    var selection = Selection(CipherSuite){};
    for (cipher_suites) |suite| try selection.append(suite);
    try std.testing.expectError(error.TooManyValues, selection.append(.tls_aes_128_gcm_sha256));
}

test "each signature scheme names the identity key its row must be issued" {
    try std.testing.expectEqual(tls_policy.IdentityKey.ed25519, identityKeyForSignature(.ed25519));
    try std.testing.expectEqual(tls_policy.IdentityKey.ecdsa_secp256r1, identityKeyForSignature(.ecdsa_secp256r1_sha256));
    try std.testing.expectEqual(tls_policy.IdentityKey.rsa, identityKeyForSignature(.rsa_pss_rsae_sha256));
}

test "require_sni and allow_absent_alpn reach the built policy" {
    var config = Config{};
    config.require_sni = true;
    config.allow_absent_alpn = true;
    const record = config.policy(.record, &.{algorithms.alpn.http_1_1});
    try std.testing.expect(record.require_sni);
    try std.testing.expect(record.allow_absent_alpn);
}

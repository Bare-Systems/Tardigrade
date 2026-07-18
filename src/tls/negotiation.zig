//! Policy-driven TLS 1.3 ClientHello negotiation.

const std = @import("std");
const algorithms = @import("algorithms.zig");
const dns_name = @import("dns_name.zig");
const messages = @import("messages.zig");
const policy_mod = @import("policy.zig");

pub const Error = messages.Error || error{
    MalformedExtension,
    MissingSupportedVersions,
    UnsupportedProtocolVersion,
    MissingCipherSuites,
    NoMutualCipherSuite,
    NoMutualNamedGroup,
    MissingKeyShare,
    NoMutualSignatureScheme,
    NoMutualAlpn,
    MissingServerName,
    OfferVectorTooLarge,
};

pub const max_offers = 64;

pub const KeyShareOffer = struct {
    group: algorithms.NamedGroup,
    key_exchange: []const u8,
};

pub const ClientHelloOffers = struct {
    versions: [max_offers]algorithms.ProtocolVersion = undefined,
    versions_len: usize = 0,
    cipher_suites: [max_offers]algorithms.CipherSuite = undefined,
    cipher_suites_len: usize = 0,
    supported_groups: [max_offers]algorithms.NamedGroup = undefined,
    supported_groups_len: usize = 0,
    key_shares: [max_offers]KeyShareOffer = undefined,
    key_shares_len: usize = 0,
    signature_schemes: [max_offers]algorithms.SignatureScheme = undefined,
    signature_schemes_len: usize = 0,
    alpn_protocols: [max_offers]algorithms.ProtocolName = undefined,
    alpn_protocols_len: usize = 0,
    server_name: ?[]const u8 = null,

    fn appendVersion(self: *ClientHelloOffers, value: algorithms.ProtocolVersion) Error!void {
        if (self.versions_len == self.versions.len) return error.OfferVectorTooLarge;
        self.versions[self.versions_len] = value;
        self.versions_len += 1;
    }

    fn appendCipherSuite(self: *ClientHelloOffers, value: algorithms.CipherSuite) Error!void {
        if (self.cipher_suites_len == self.cipher_suites.len) return error.OfferVectorTooLarge;
        self.cipher_suites[self.cipher_suites_len] = value;
        self.cipher_suites_len += 1;
    }

    fn appendSupportedGroup(self: *ClientHelloOffers, value: algorithms.NamedGroup) Error!void {
        if (self.supported_groups_len == self.supported_groups.len) return error.OfferVectorTooLarge;
        self.supported_groups[self.supported_groups_len] = value;
        self.supported_groups_len += 1;
    }

    fn appendKeyShare(self: *ClientHelloOffers, value: KeyShareOffer) Error!void {
        if (self.key_shares_len == self.key_shares.len) return error.OfferVectorTooLarge;
        self.key_shares[self.key_shares_len] = value;
        self.key_shares_len += 1;
    }

    fn appendSignatureScheme(self: *ClientHelloOffers, value: algorithms.SignatureScheme) Error!void {
        if (self.signature_schemes_len == self.signature_schemes.len) return error.OfferVectorTooLarge;
        self.signature_schemes[self.signature_schemes_len] = value;
        self.signature_schemes_len += 1;
    }

    fn appendAlpn(self: *ClientHelloOffers, value: algorithms.ProtocolName) Error!void {
        if (self.alpn_protocols_len == self.alpn_protocols.len) return error.OfferVectorTooLarge;
        self.alpn_protocols[self.alpn_protocols_len] = value;
        self.alpn_protocols_len += 1;
    }

    pub fn containsVersion(self: *const ClientHelloOffers, value: algorithms.ProtocolVersion) bool {
        return containsEnum(algorithms.ProtocolVersion, self.versions[0..self.versions_len], value);
    }

    pub fn keyShareFor(self: *const ClientHelloOffers, group: algorithms.NamedGroup) ?[]const u8 {
        for (self.key_shares[0..self.key_shares_len]) |share| {
            if (share.group == group) return share.key_exchange;
        }
        return null;
    }
};

pub const Selection = struct {
    version: algorithms.ProtocolVersion,
    cipher_suite: algorithms.CipherSuite,
    named_group: algorithms.NamedGroup,
    key_share: []const u8,
    signature_scheme: algorithms.SignatureScheme,
    alpn: algorithms.ProtocolName,
    server_name: ?[]const u8,
};

pub fn parseClientHello(body: []const u8) Error!ClientHelloOffers {
    var offers = ClientHelloOffers{};
    var r = messages.Reader{ .bytes = body };
    if (try r.u16_() != algorithms.legacy_version) return error.MalformedHandshake;
    _ = try r.slice(32);
    _ = try r.slice(try r.u8_());

    var cipher_reader = messages.Reader{ .bytes = try r.slice(try r.u16_()) };
    if (cipher_reader.remaining() == 0 or cipher_reader.remaining() % 2 != 0) return error.MissingCipherSuites;
    while (cipher_reader.remaining() > 0) {
        if (algorithms.fromInt(algorithms.CipherSuite, try cipher_reader.u16_())) |cipher| {
            try offers.appendCipherSuite(cipher);
        }
    }

    var compression_reader = messages.Reader{ .bytes = try r.slice(try r.u8_()) };
    var has_null_compression = false;
    while (compression_reader.remaining() > 0) {
        if (try compression_reader.u8_() == 0) has_null_compression = true;
    }
    if (!has_null_compression) return error.MalformedHandshake;

    var extensions = messages.ExtensionIterator.init(try r.slice(try r.u16_()));
    try r.expectEnd();
    while (try extensions.next()) |extension| {
        switch (algorithms.fromInt(algorithms.ExtensionType, extension.id) orelse continue) {
            .supported_versions => try parseSupportedVersions(extension.data, &offers),
            .supported_groups => try parseSupportedGroups(extension.data, &offers),
            .signature_algorithms => try parseSignatureAlgorithms(extension.data, &offers),
            .key_share => try parseKeyShares(extension.data, &offers),
            .server_name => try parseServerName(extension.data, &offers),
            .application_layer_protocol_negotiation => try parseAlpn(extension.data, &offers),
            else => {},
        }
    }
    if (offers.versions_len == 0) return error.MissingSupportedVersions;
    return offers;
}

pub fn negotiateServer(policy: policy_mod.Policy, offers: *const ClientHelloOffers) Error!Selection {
    if (!offers.containsVersion(.tls13)) return error.UnsupportedProtocolVersion;
    if (policy.require_sni and offers.server_name == null) return error.MissingServerName;
    const cipher_suite = pickEnum(algorithms.CipherSuite, policy.cipher_suites, offers.cipher_suites[0..offers.cipher_suites_len]) orelse
        return error.NoMutualCipherSuite;
    const named_group = pickEnum(algorithms.NamedGroup, policy.named_groups, offers.supported_groups[0..offers.supported_groups_len]) orelse
        return error.NoMutualNamedGroup;
    const key_share = offers.keyShareFor(named_group) orelse return error.MissingKeyShare;
    const signature_scheme = pickEnum(algorithms.SignatureScheme, policy.signature_schemes, offers.signature_schemes[0..offers.signature_schemes_len]) orelse
        return error.NoMutualSignatureScheme;
    const alpn = pickAlpn(policy.alpn_protocols, offers.alpn_protocols[0..offers.alpn_protocols_len]) orelse
        return error.NoMutualAlpn;
    return .{
        .version = .tls13,
        .cipher_suite = cipher_suite,
        .named_group = named_group,
        .key_share = key_share,
        .signature_scheme = signature_scheme,
        .alpn = alpn,
        .server_name = offers.server_name,
    };
}

pub const ServerSelection = struct {
    version: algorithms.ProtocolVersion,
    cipher_suite: algorithms.CipherSuite,
    named_group: algorithms.NamedGroup,
    alpn: algorithms.ProtocolName,
};

pub fn validateServerSelection(policy: policy_mod.Policy, selection: ServerSelection) Error!void {
    if (selection.version != .tls13) return error.UnsupportedProtocolVersion;
    if (!containsEnum(algorithms.CipherSuite, policy.cipher_suites, selection.cipher_suite)) return error.NoMutualCipherSuite;
    if (!containsEnum(algorithms.NamedGroup, policy.named_groups, selection.named_group)) return error.NoMutualNamedGroup;
    if (!containsAlpn(policy.alpn_protocols, selection.alpn)) return error.NoMutualAlpn;
}

fn parseSupportedVersions(bytes: []const u8, offers: *ClientHelloOffers) Error!void {
    var r = messages.Reader{ .bytes = bytes };
    var versions = messages.Reader{ .bytes = try r.slice(try r.u8_()) };
    try r.expectEnd();
    if (versions.remaining() == 0 or versions.remaining() % 2 != 0) return error.MalformedExtension;
    while (versions.remaining() > 0) {
        if (algorithms.fromInt(algorithms.ProtocolVersion, try versions.u16_())) |version| {
            try offers.appendVersion(version);
        }
    }
}

fn parseSupportedGroups(bytes: []const u8, offers: *ClientHelloOffers) Error!void {
    var r = messages.Reader{ .bytes = bytes };
    var groups = messages.Reader{ .bytes = try r.slice(try r.u16_()) };
    try r.expectEnd();
    if (groups.remaining() == 0 or groups.remaining() % 2 != 0) return error.MalformedExtension;
    while (groups.remaining() > 0) {
        if (algorithms.fromInt(algorithms.NamedGroup, try groups.u16_())) |group| {
            try offers.appendSupportedGroup(group);
        }
    }
}

fn parseSignatureAlgorithms(bytes: []const u8, offers: *ClientHelloOffers) Error!void {
    var r = messages.Reader{ .bytes = bytes };
    var algorithms_reader = messages.Reader{ .bytes = try r.slice(try r.u16_()) };
    try r.expectEnd();
    if (algorithms_reader.remaining() == 0 or algorithms_reader.remaining() % 2 != 0) return error.MalformedExtension;
    while (algorithms_reader.remaining() > 0) {
        if (algorithms.fromInt(algorithms.SignatureScheme, try algorithms_reader.u16_())) |scheme| {
            try offers.appendSignatureScheme(scheme);
        }
    }
}

fn parseKeyShares(bytes: []const u8, offers: *ClientHelloOffers) Error!void {
    var r = messages.Reader{ .bytes = bytes };
    var shares = messages.Reader{ .bytes = try r.slice(try r.u16_()) };
    try r.expectEnd();
    while (shares.remaining() > 0) {
        const group_id = try shares.u16_();
        const share = try shares.slice(try shares.u16_());
        if (algorithms.fromInt(algorithms.NamedGroup, group_id)) |group| {
            try offers.appendKeyShare(.{ .group = group, .key_exchange = share });
        }
    }
}

fn parseServerName(bytes: []const u8, offers: *ClientHelloOffers) Error!void {
    var r = messages.Reader{ .bytes = bytes };
    const list_len = try r.u16_();
    if (list_len == 0) return error.MalformedExtension;
    var names = messages.Reader{ .bytes = try r.slice(list_len) };
    try r.expectEnd();
    while (names.remaining() > 0) {
        const name_type = try names.u8_();
        const name = try names.slice(try names.u16_());
        if (name_type == 0) {
            if (offers.server_name != null) return error.MalformedExtension;
            dns_name.validateHostName(name) catch return error.MalformedExtension;
            offers.server_name = name;
        }
    }
}

fn parseAlpn(bytes: []const u8, offers: *ClientHelloOffers) Error!void {
    var r = messages.Reader{ .bytes = bytes };
    var protocols = messages.Reader{ .bytes = try r.slice(try r.u16_()) };
    try r.expectEnd();
    while (protocols.remaining() > 0) {
        const name = try protocols.slice(try protocols.u8_());
        if (name.len == 0) return error.MalformedExtension;
        try offers.appendAlpn(.{ .bytes = name });
    }
}

fn pickEnum(comptime T: type, local_preference: []const T, peer_offers: []const T) ?T {
    for (local_preference) |local| {
        if (containsEnum(T, peer_offers, local)) return local;
    }
    return null;
}

fn containsEnum(comptime T: type, list: []const T, value: T) bool {
    for (list) |item| {
        if (item == value) return true;
    }
    return false;
}

fn pickAlpn(local_preference: []const algorithms.ProtocolName, peer_offers: []const algorithms.ProtocolName) ?algorithms.ProtocolName {
    for (local_preference) |local| {
        if (containsAlpn(peer_offers, local)) return local;
    }
    return null;
}

fn containsAlpn(list: []const algorithms.ProtocolName, value: algorithms.ProtocolName) bool {
    for (list) |item| {
        if (item.eql(value)) return true;
    }
    return false;
}

const testing = std.testing;

test "server negotiation follows policy preference order and surfaces SNI" {
    var offers = ClientHelloOffers{};
    try offers.appendVersion(.tls13);
    try offers.appendCipherSuite(.tls_chacha20_poly1305_sha256);
    try offers.appendCipherSuite(.tls_aes_128_gcm_sha256);
    try offers.appendSupportedGroup(.x25519);
    try offers.appendKeyShare(.{ .group = .x25519, .key_exchange = "share" });
    try offers.appendSignatureScheme(.ed25519);
    try offers.appendAlpn(algorithms.alpn.http_1_1);
    try offers.appendAlpn(algorithms.alpn.h2);
    offers.server_name = "example.test";

    const selected = try negotiateServer(policy_mod.Policy.recordDefault(), &offers);
    try testing.expectEqual(algorithms.CipherSuite.tls_aes_128_gcm_sha256, selected.cipher_suite);
    try testing.expectEqual(algorithms.NamedGroup.x25519, selected.named_group);
    try testing.expectEqual(algorithms.SignatureScheme.ed25519, selected.signature_scheme);
    try testing.expect(selected.alpn.eql(algorithms.alpn.h2));
    try testing.expectEqualStrings("example.test", selected.server_name.?);
}

test "configured provider capabilities change negotiated tuples" {
    const ciphers = [_]algorithms.CipherSuite{.tls_chacha20_poly1305_sha256};
    const groups = [_]algorithms.NamedGroup{.x25519};
    const signatures = [_]algorithms.SignatureScheme{.ed25519};
    const alpns = [_]algorithms.ProtocolName{algorithms.alpn.h3};
    const configured = policy_mod.Policy.fromCapabilities(.quic, .{
        .cipher_suites = &ciphers,
        .named_groups = &groups,
        .signature_schemes = &signatures,
    }, &alpns);

    var offers = ClientHelloOffers{};
    try offers.appendVersion(.tls13);
    try offers.appendCipherSuite(.tls_chacha20_poly1305_sha256);
    try offers.appendSupportedGroup(.x25519);
    try offers.appendKeyShare(.{ .group = .x25519, .key_exchange = "share" });
    try offers.appendSignatureScheme(.ed25519);
    try offers.appendAlpn(algorithms.alpn.h3);

    const selected = try negotiateServer(configured, &offers);
    try testing.expectEqual(algorithms.CipherSuite.tls_chacha20_poly1305_sha256, selected.cipher_suite);
}

test "identity-constrained policy selects the active certificate signature scheme" {
    const alpns = [_]algorithms.ProtocolName{algorithms.alpn.h3};
    const p256_policy = try policy_mod.Policy.fromIdentity(.quic, .{}, &alpns, .ecdsa_secp256r1);

    var offers = ClientHelloOffers{};
    try offers.appendVersion(.tls13);
    try offers.appendCipherSuite(.tls_aes_128_gcm_sha256);
    try offers.appendSupportedGroup(.x25519);
    try offers.appendKeyShare(.{ .group = .x25519, .key_exchange = "share" });
    try offers.appendSignatureScheme(.ed25519);
    try offers.appendSignatureScheme(.ecdsa_secp256r1_sha256);
    try offers.appendAlpn(algorithms.alpn.h3);

    const selected = try negotiateServer(p256_policy, &offers);
    try testing.expectEqual(algorithms.SignatureScheme.ecdsa_secp256r1_sha256, selected.signature_scheme);
}

test "ClientHello parser feeds policy negotiation with ALPN and SNI offers" {
    var body: [256]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&([_]u8{0} ** 32));
    try w.u8_(0);
    try w.u16_(4);
    try w.u16_(@intFromEnum(algorithms.CipherSuite.tls_chacha20_poly1305_sha256));
    try w.u16_(@intFromEnum(algorithms.CipherSuite.tls_aes_128_gcm_sha256));
    try w.u8_(1);
    try w.u8_(0);

    const extensions_len = try w.reserve(2);
    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_versions));
    try w.u16_(3);
    try w.u8_(2);
    try w.u16_(@intFromEnum(algorithms.ProtocolVersion.tls13));

    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_groups));
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.NamedGroup.x25519));

    try w.u16_(@intFromEnum(algorithms.ExtensionType.signature_algorithms));
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.SignatureScheme.ed25519));

    try w.u16_(@intFromEnum(algorithms.ExtensionType.key_share));
    const key_share_ext = try w.reserve(2);
    const key_shares = try w.reserve(2);
    try w.u16_(@intFromEnum(algorithms.NamedGroup.x25519));
    try w.u16_(5);
    try w.bytes("share");
    w.patch(2, key_shares);
    w.patch(2, key_share_ext);

    try w.u16_(@intFromEnum(algorithms.ExtensionType.server_name));
    const sni_ext = try w.reserve(2);
    const sni_list = try w.reserve(2);
    try w.u8_(0);
    try w.u16_(12);
    try w.bytes("example.test");
    w.patch(2, sni_list);
    w.patch(2, sni_ext);

    try w.u16_(@intFromEnum(algorithms.ExtensionType.application_layer_protocol_negotiation));
    const alpn_ext = try w.reserve(2);
    const alpn_list = try w.reserve(2);
    try w.u8_(2);
    try w.bytes("h2");
    try w.u8_(8);
    try w.bytes("http/1.1");
    w.patch(2, alpn_list);
    w.patch(2, alpn_ext);
    w.patch(2, extensions_len);

    const offers = try parseClientHello(w.written());
    const selected = try negotiateServer(policy_mod.Policy.recordDefault(), &offers);
    try testing.expectEqual(algorithms.CipherSuite.tls_aes_128_gcm_sha256, selected.cipher_suite);
    try testing.expect(selected.alpn.eql(algorithms.alpn.h2));
    try testing.expectEqualStrings("example.test", selected.server_name.?);
    try testing.expectEqualStrings("share", selected.key_share);
}

fn clientHelloWithServerNameExtension(buf: []u8, server_name_payload: []const u8) ![]const u8 {
    var w = messages.Writer{ .buf = buf };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&([_]u8{0} ** 32));
    try w.u8_(0);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.CipherSuite.tls_aes_128_gcm_sha256));
    try w.u8_(1);
    try w.u8_(0);

    const extensions_len = try w.reserve(2);
    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_versions));
    try w.u16_(3);
    try w.u8_(2);
    try w.u16_(@intFromEnum(algorithms.ProtocolVersion.tls13));

    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_groups));
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.NamedGroup.x25519));

    try w.u16_(@intFromEnum(algorithms.ExtensionType.signature_algorithms));
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.SignatureScheme.ed25519));

    try w.u16_(@intFromEnum(algorithms.ExtensionType.key_share));
    const key_share_ext = try w.reserve(2);
    const key_shares = try w.reserve(2);
    try w.u16_(@intFromEnum(algorithms.NamedGroup.x25519));
    try w.u16_(5);
    try w.bytes("share");
    w.patch(2, key_shares);
    w.patch(2, key_share_ext);

    try w.u16_(@intFromEnum(algorithms.ExtensionType.server_name));
    try w.u16_(@intCast(server_name_payload.len));
    try w.bytes(server_name_payload);
    w.patch(2, extensions_len);
    return w.written();
}

test "ClientHello parser rejects empty SNI ServerNameList" {
    var body: [192]u8 = undefined;
    const empty_server_name_list = [_]u8{ 0, 0 };
    const hello = try clientHelloWithServerNameExtension(&body, &empty_server_name_list);
    try testing.expectError(error.MalformedExtension, parseClientHello(hello));
}

test "ClientHello parser rejects duplicate SNI host_name entries" {
    var sni_payload: [2 + 2 * (1 + 2 + 12)]u8 = undefined;
    var sni = messages.Writer{ .buf = &sni_payload };
    const list_len = try sni.reserve(2);
    inline for (0..2) |_| {
        try sni.u8_(0);
        try sni.u16_(12);
        try sni.bytes("example.test");
    }
    sni.patch(2, list_len);

    var body: [256]u8 = undefined;
    const hello = try clientHelloWithServerNameExtension(&body, sni.written());
    try testing.expectError(error.MalformedExtension, parseClientHello(hello));
}

test "recognized offer vectors allow general-purpose client sizes" {
    var offers = ClientHelloOffers{};
    try offers.appendVersion(.tls13);
    for (0..max_offers) |_| {
        try offers.appendSignatureScheme(.rsa_pkcs1_sha256);
    }
    try testing.expectEqual(@as(usize, max_offers), offers.signature_schemes_len);
    try testing.expectError(error.OfferVectorTooLarge, offers.appendSignatureScheme(.ed25519));
}

test "negotiation reports no-overlap failures without logging offer contents" {
    var offers = ClientHelloOffers{};
    try offers.appendVersion(.tls13);
    try offers.appendCipherSuite(.tls_chacha20_poly1305_sha256);
    try offers.appendSupportedGroup(.x25519);
    try offers.appendKeyShare(.{ .group = .x25519, .key_exchange = "share" });
    try offers.appendSignatureScheme(.ed25519);
    try offers.appendAlpn(algorithms.alpn.h3);

    try testing.expectError(error.NoMutualCipherSuite, negotiateServer(policy_mod.Policy.quicDefault(), &offers));
}

test "client validates server selection against configured policy" {
    try validateServerSelection(policy_mod.Policy.quicDefault(), .{
        .version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .named_group = .x25519,
        .alpn = algorithms.alpn.h3,
    });

    try testing.expectError(error.NoMutualAlpn, validateServerSelection(policy_mod.Policy.quicDefault(), .{
        .version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .named_group = .x25519,
        .alpn = algorithms.alpn.h2,
    }));
}

test "malformed required extensions fail deterministically" {
    var body: [128]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&([_]u8{0} ** 32));
    try w.u8_(0);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.CipherSuite.tls_aes_128_gcm_sha256));
    try w.u8_(1);
    try w.u8_(0);
    const extensions_len = try w.reserve(2);
    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_versions));
    try w.u16_(2);
    try w.u8_(2);
    try w.u8_(0x03);
    w.patch(2, extensions_len);

    try testing.expectError(error.MalformedHandshake, parseClientHello(w.written()));
}

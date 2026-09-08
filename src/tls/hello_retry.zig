//! TLS 1.3 HelloRetryRequest codec and validation helpers.

const std = @import("std");
const alerts = @import("alerts.zig");
const algorithms = @import("algorithms.zig");
const events = @import("events.zig");
const messages = @import("messages.zig");
const negotiation = @import("negotiation.zig");
const pre_shared_key = @import("pre_shared_key.zig");

pub const random = [32]u8{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
};

pub const Error = events.HandshakeError || messages.Error || error{HandshakeBufferOverflow};

pub const Request = struct {
    selected_version: algorithms.ProtocolVersion,
    cipher_suite: algorithms.CipherSuite,
    selected_group: ?algorithms.NamedGroup,
    cookie: ?[]const u8,
};

pub const EncodeRequest = struct {
    legacy_session_id_echo: []const u8,
    selected_version: algorithms.ProtocolVersion = .tls13,
    cipher_suite: algorithms.CipherSuite,
    selected_group: ?algorithms.NamedGroup = null,
    cookie: ?[]const u8 = null,
};

pub fn isHelloRetryRequest(server_hello_body: []const u8) bool {
    if (server_hello_body.len < 2 + random.len) return false;
    return std.mem.eql(u8, server_hello_body[2..][0..random.len], &random);
}

pub fn decode(
    body: []const u8,
    original_session_id: []const u8,
    original_offers: *const negotiation.ClientHelloOffers,
) Error!Request {
    var r = messages.Reader{ .bytes = body };
    if ((try r.u16_()) != algorithms.legacy_version) return error.IllegalParameter;
    const server_random = try r.slice(32);
    if (!std.mem.eql(u8, server_random, &random)) return error.IllegalParameter;
    const session_id = try r.slice(try r.u8_());
    if (!std.mem.eql(u8, session_id, original_session_id)) return error.IllegalParameter;
    const cipher_suite = algorithms.fromInt(algorithms.CipherSuite, try r.u16_()) orelse return error.IllegalParameter;
    if (!containsEnum(algorithms.CipherSuite, original_offers.cipher_suites[0..original_offers.cipher_suites_len], cipher_suite))
        return error.IllegalParameter;
    if ((try r.u8_()) != 0) return error.IllegalParameter;

    const extensions_bytes = try r.slice(try r.u16_());
    try r.expectEnd();
    var extensions = messages.ExtensionIterator.init(extensions_bytes);
    var selected_version: ?algorithms.ProtocolVersion = null;
    var selected_group: ?algorithms.NamedGroup = null;
    var cookie: ?[]const u8 = null;

    while (try nextExtension(&extensions)) |extension| {
        const ext_type = algorithms.fromInt(algorithms.ExtensionType, extension.id) orelse
            return error.UnsupportedExtension;
        switch (ext_type) {
            .supported_versions => {
                if (selected_version != null) return error.IllegalParameter;
                selected_version = try decodeSelectedVersion(extension.data, original_offers);
            },
            .key_share => {
                if (!original_offers.key_share_seen) return error.UnsupportedExtension;
                if (selected_group != null) return error.IllegalParameter;
                selected_group = try decodeSelectedGroup(extension.data, original_offers);
            },
            .cookie => {
                if (cookie != null) return error.IllegalParameter;
                cookie = try decodeCookie(extension.data);
            },
            else => return error.IllegalParameter,
        }
    }
    if (selected_group == null and cookie == null) return error.IllegalParameter;

    return .{
        .selected_version = selected_version orelse return error.MissingExtension,
        .cipher_suite = cipher_suite,
        .selected_group = selected_group,
        .cookie = cookie,
    };
}

pub fn encode(request: EncodeRequest, out: []u8) Error![]const u8 {
    if (request.selected_group == null and request.cookie == null) return error.IllegalParameter;
    if (request.legacy_session_id_echo.len > 32) return error.IllegalParameter;
    if (request.cookie) |cookie| {
        if (cookie.len == 0 or cookie.len > std.math.maxInt(u16) - 2) return error.IllegalParameter;
    }
    const encoded_body_len =
        2 + random.len +
        1 + request.legacy_session_id_echo.len +
        2 + 1 +
        2 +
        4 + 2 +
        (if (request.selected_group != null) @as(usize, 4 + 2) else 0) +
        (if (request.cookie) |cookie| @as(usize, 4 + 2 + cookie.len) else 0);
    if (encoded_body_len > 512 or encoded_body_len > messages.max_message_len) return error.IllegalParameter;

    var body: [512]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&random);
    try w.u8_(@intCast(request.legacy_session_id_echo.len));
    try w.bytes(request.legacy_session_id_echo);
    try w.u16_(@intFromEnum(request.cipher_suite));
    try w.u8_(0);
    const extensions_len = try w.reserve(2);

    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_versions));
    try w.u16_(2);
    try w.u16_(@intFromEnum(request.selected_version));

    if (request.selected_group) |group| {
        try w.u16_(@intFromEnum(algorithms.ExtensionType.key_share));
        try w.u16_(2);
        try w.u16_(@intFromEnum(group));
    }

    if (request.cookie) |cookie| {
        try w.u16_(@intFromEnum(algorithms.ExtensionType.cookie));
        try w.u16_(@intCast(2 + cookie.len));
        try w.u16_(@intCast(cookie.len));
        try w.bytes(cookie);
    }

    w.patch(2, extensions_len);
    return messages.encode(.server_hello, w.written(), out) catch |err| switch (err) {
        error.HandshakeBufferOverflow => error.HandshakeBufferOverflow,
        error.MessageTooLarge => error.MalformedHandshake,
        else => error.MalformedHandshake,
    };
}

pub fn validateSecondClientHello(
    first_raw: []const u8,
    second_raw: []const u8,
    request: Request,
) Error!void {
    const first_message = messages.decode(first_raw) catch return error.MalformedHandshake;
    const second_message = messages.decode(second_raw) catch return error.MalformedHandshake;
    if (first_message.kind != .client_hello or second_message.kind != .client_hello)
        return error.UnexpectedHandshakeMessage;

    const first = try ClientHelloView.parse(first_message.body);
    const second = try ClientHelloView.parse(second_message.body);
    try requirePskLast(first.extensions());
    try requirePskLast(second.extensions());
    try validatePadding(first.extensions());
    try validatePadding(second.extensions());

    if (!std.mem.eql(u8, first.legacy_version, second.legacy_version) or
        !std.mem.eql(u8, first.random, second.random) or
        !std.mem.eql(u8, first.legacy_session_id, second.legacy_session_id) or
        !std.mem.eql(u8, first.cipher_suites, second.cipher_suites) or
        !std.mem.eql(u8, first.compression_methods, second.compression_methods))
        return error.IllegalParameter;

    try compareExtensions(first.extensions(), second.extensions(), request);
}

const ExtensionView = struct {
    id: u16,
    data: []const u8,
};

const ClientHelloView = struct {
    legacy_version: []const u8,
    random: []const u8,
    legacy_session_id: []const u8,
    cipher_suites: []const u8,
    compression_methods: []const u8,
    extension_storage: [messages.ExtensionGuard.max_extensions]ExtensionView = undefined,
    extension_len: usize = 0,

    fn parse(body: []const u8) Error!ClientHelloView {
        var r = messages.Reader{ .bytes = body };
        const legacy_version = try r.slice(2);
        const client_random = try r.slice(32);
        const session_id = try r.slice(try r.u8_());
        const cipher_suites = try r.slice(try r.u16_());
        const compression_methods = try r.slice(try r.u8_());
        const extension_bytes = try r.slice(try r.u16_());
        try r.expectEnd();

        var view = ClientHelloView{
            .legacy_version = legacy_version,
            .random = client_random,
            .legacy_session_id = session_id,
            .cipher_suites = cipher_suites,
            .compression_methods = compression_methods,
        };
        var iter = messages.ExtensionIterator.init(extension_bytes);
        while (try nextExtension(&iter)) |extension| {
            if (view.extension_len == view.extension_storage.len) return error.MalformedHandshake;
            view.extension_storage[view.extension_len] = .{ .id = extension.id, .data = extension.data };
            view.extension_len += 1;
        }
        return view;
    }

    fn extensions(self: *const ClientHelloView) []const ExtensionView {
        return self.extension_storage[0..self.extension_len];
    }
};

fn compareExtensions(first: []const ExtensionView, second: []const ExtensionView, request: Request) Error!void {
    try compareStableExtensionOrder(first, second);

    for (first) |lhs| {
        if (!isComparable(lhs.id, false)) continue;
        const rhs = findComparable(second, lhs.id, true) orelse return error.IllegalParameter;
        try compareExtensionPayload(lhs, rhs, request);
    }

    for (second) |rhs| {
        if (!isComparable(rhs.id, true)) continue;
        _ = findComparable(first, rhs.id, false) orelse return error.IllegalParameter;
    }

    if (findExtension(second, @intFromEnum(algorithms.ExtensionType.early_data)) != null)
        return error.IllegalParameter;

    if (request.cookie) |expected_cookie| {
        const cookie = findExtension(second, @intFromEnum(algorithms.ExtensionType.cookie)) orelse return error.IllegalParameter;
        try expectCookiePayload(expected_cookie, cookie.data);
    } else if (findExtension(second, @intFromEnum(algorithms.ExtensionType.cookie)) != null) {
        return error.IllegalParameter;
    }
}

fn compareStableExtensionOrder(first: []const ExtensionView, second: []const ExtensionView) Error!void {
    var i: usize = 0;
    var j: usize = 0;
    while (true) {
        while (i < first.len and !isOrderStable(first[i].id)) : (i += 1) {}
        while (j < second.len and !isOrderStable(second[j].id)) : (j += 1) {}
        if (i == first.len or j == second.len) break;
        if (first[i].id != second[j].id) return error.IllegalParameter;
        i += 1;
        j += 1;
    }
    while (i < first.len and !isOrderStable(first[i].id)) : (i += 1) {}
    while (j < second.len and !isOrderStable(second[j].id)) : (j += 1) {}
    if (i != first.len or j != second.len) return error.IllegalParameter;
}

fn isOrderStable(id: u16) bool {
    return id != @intFromEnum(algorithms.ExtensionType.padding) and
        id != @intFromEnum(algorithms.ExtensionType.early_data) and
        id != @intFromEnum(algorithms.ExtensionType.cookie) and
        id != @intFromEnum(algorithms.ExtensionType.key_share) and
        id != @intFromEnum(algorithms.ExtensionType.pre_shared_key);
}

fn isComparable(id: u16, skip_cookie: bool) bool {
    return id != @intFromEnum(algorithms.ExtensionType.padding) and
        id != @intFromEnum(algorithms.ExtensionType.early_data) and
        !(skip_cookie and id == @intFromEnum(algorithms.ExtensionType.cookie));
}

fn findComparable(extensions: []const ExtensionView, id: u16, skip_cookie: bool) ?ExtensionView {
    for (extensions) |extension| {
        if (!isComparable(extension.id, skip_cookie)) continue;
        if (extension.id == id) return extension;
    }
    return null;
}

fn compareExtensionPayload(lhs: ExtensionView, rhs: ExtensionView, request: Request) Error!void {
    if (lhs.id == @intFromEnum(algorithms.ExtensionType.key_share)) {
        if (request.selected_group) |group| {
            try expectSingleKeyShare(group, rhs.data);
        } else if (!std.mem.eql(u8, lhs.data, rhs.data)) {
            return error.IllegalParameter;
        }
        return;
    }
    if (lhs.id == @intFromEnum(algorithms.ExtensionType.pre_shared_key)) {
        try requireSamePskIdentityOrder(lhs.data, rhs.data);
        return;
    }
    if (!std.mem.eql(u8, lhs.data, rhs.data)) return error.IllegalParameter;
}

fn expectSingleKeyShare(group: algorithms.NamedGroup, data: []const u8) Error!void {
    var r = messages.Reader{ .bytes = data };
    var shares = messages.Reader{ .bytes = try r.slice(try r.u16_()) };
    try r.expectEnd();
    // RFC 9846 §4.2.2 (§4.3.8 for key_share): after an HRR that named a
    // group, ClientHello2's key_share must contain solely one share for
    // that group. A list that parses cleanly but is empty, holds extra
    // shares, names a different group, or carries an empty key_exchange
    // is a well-formed message violating that requirement —
    // illegal_parameter, not decode_error
    // (#675 campaign finding: the empty list previously surfaced as a
    // Reader underflow and was misreported as MalformedHandshake).
    // Structural truncation inside the list remains MalformedHandshake.
    var count: usize = 0;
    var single_share_matches = false;
    while (shares.remaining() != 0) {
        const share_group = try shares.u16_();
        const key_exchange = try shares.slice(try shares.u16_());
        count += 1;
        if (count == 1 and share_group == @intFromEnum(group) and key_exchange.len != 0)
            single_share_matches = true;
    }
    if (count != 1 or !single_share_matches) return error.IllegalParameter;
}

fn expectCookiePayload(expected: []const u8, data: []const u8) Error!void {
    var r = messages.Reader{ .bytes = data };
    const cookie = try r.slice(try r.u16_());
    try r.expectEnd();
    if (!std.mem.eql(u8, cookie, expected)) return error.IllegalParameter;
}

fn findExtension(extensions: []const ExtensionView, id: u16) ?ExtensionView {
    for (extensions) |extension| {
        if (extension.id == id) return extension;
    }
    return null;
}

fn requirePskLast(extensions: []const ExtensionView) Error!void {
    for (extensions, 0..) |extension, index| {
        if (extension.id == @intFromEnum(algorithms.ExtensionType.pre_shared_key) and
            index + 1 != extensions.len)
            return error.IllegalParameter;
    }
}

fn validatePadding(extensions: []const ExtensionView) Error!void {
    for (extensions) |extension| {
        if (extension.id == @intFromEnum(algorithms.ExtensionType.padding) and
            !std.mem.allEqual(u8, extension.data, 0))
            return error.IllegalParameter;
    }
}

fn requireSamePskIdentityOrder(first: []const u8, second: []const u8) Error!void {
    const first_psks = pre_shared_key.OfferedPsks.parse(first) catch return error.IllegalParameter;
    const second_psks = pre_shared_key.OfferedPsks.parse(second) catch return error.IllegalParameter;
    if (first_psks.count != second_psks.count) return error.IllegalParameter;

    var first_pairs = first_psks.pairs();
    var second_pairs = second_psks.pairs();
    while (nextPskPair(&first_pairs)) |lhs| {
        const rhs = nextPskPair(&second_pairs) orelse return error.IllegalParameter;
        if (!std.mem.eql(u8, lhs.identity.identity, rhs.identity.identity))
            return error.IllegalParameter;
    }
    if (nextPskPair(&second_pairs) != null) return error.IllegalParameter;
}

fn nextPskPair(iter: *pre_shared_key.OfferedPsks.PairIterator) ?pre_shared_key.OfferedPsks.PairIterator.Pair {
    return iter.next() catch return null;
}

fn nextExtension(iter: *messages.ExtensionIterator) Error!?messages.Extension {
    return iter.next() catch |err| switch (err) {
        error.DuplicateExtension => return error.IllegalParameter,
        else => return err,
    };
}

fn decodeSelectedVersion(bytes: []const u8, original_offers: *const negotiation.ClientHelloOffers) Error!algorithms.ProtocolVersion {
    var r = messages.Reader{ .bytes = bytes };
    const version = algorithms.fromInt(algorithms.ProtocolVersion, try r.u16_()) orelse return error.IllegalParameter;
    try r.expectEnd();
    if (version != .tls13 or !original_offers.containsVersion(version)) return error.IllegalParameter;
    return version;
}

fn decodeSelectedGroup(bytes: []const u8, original_offers: *const negotiation.ClientHelloOffers) Error!algorithms.NamedGroup {
    var r = messages.Reader{ .bytes = bytes };
    const group = algorithms.fromInt(algorithms.NamedGroup, try r.u16_()) orelse return error.IllegalParameter;
    try r.expectEnd();
    if (!containsEnum(algorithms.NamedGroup, original_offers.supported_groups[0..original_offers.supported_groups_len], group))
        return error.IllegalParameter;
    if (original_offers.keyShareFor(group) != null) return error.IllegalParameter;
    return group;
}

fn decodeCookie(bytes: []const u8) Error![]const u8 {
    var r = messages.Reader{ .bytes = bytes };
    const cookie = try r.slice(try r.u16_());
    try r.expectEnd();
    if (cookie.len == 0) return error.IllegalParameter;
    return cookie;
}

fn containsEnum(comptime T: type, list: []const T, value: T) bool {
    for (list) |item| {
        if (item == value) return true;
    }
    return false;
}

const testing = std.testing;

fn baseOffers() !negotiation.ClientHelloOffers {
    var offers = negotiation.ClientHelloOffers{};
    offers.versions[0] = .tls13;
    offers.versions_len = 1;
    offers.cipher_suites[0] = .tls_aes_128_gcm_sha256;
    offers.cipher_suites_len = 1;
    offers.supported_groups[0] = .x25519;
    offers.supported_groups_len = 1;
    offers.key_share_seen = true;
    return offers;
}

test "detects HelloRetryRequest sentinel" {
    var raw: [256]u8 = undefined;
    const encoded = try encode(.{
        .legacy_session_id_echo = "sid",
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
    }, &raw);
    const message = try messages.decode(encoded);
    try testing.expect(isHelloRetryRequest(message.body));
}

test "decodes key-share and cookie HRR" {
    var offers = try baseOffers();
    var raw: [256]u8 = undefined;
    const encoded = try encode(.{
        .legacy_session_id_echo = "sid",
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = "cookie",
    }, &raw);
    const message = try messages.decode(encoded);
    const request = try decode(message.body, "sid", &offers);
    try testing.expectEqual(algorithms.ProtocolVersion.tls13, request.selected_version);
    try testing.expectEqual(algorithms.CipherSuite.tls_aes_128_gcm_sha256, request.cipher_suite);
    try testing.expectEqual(algorithms.NamedGroup.x25519, request.selected_group.?);
    try testing.expectEqualStrings("cookie", request.cookie.?);
}

test "HRR key_share is unsupported when ClientHello1 omitted key_share extension" {
    var offers = try baseOffers();
    offers.key_share_seen = false;
    var raw: [256]u8 = undefined;
    const encoded = try encode(.{
        .legacy_session_id_echo = "",
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
    }, &raw);
    const message = try messages.decode(encoded);
    try testing.expectError(error.UnsupportedExtension, decode(message.body, "", &offers));
    try testing.expectEqual(alerts.AlertDescription.unsupported_extension, alerts.fromHandshakeError(error.UnsupportedExtension));

    offers.key_share_seen = true;
    _ = try decode(message.body, "", &offers);
}

test "rejects no-op and empty-cookie HRR" {
    var out: [256]u8 = undefined;
    try testing.expectError(error.IllegalParameter, encode(.{
        .legacy_session_id_echo = "",
        .cipher_suite = .tls_aes_128_gcm_sha256,
    }, &out));
    try testing.expectError(error.IllegalParameter, encode(.{
        .legacy_session_id_echo = "",
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .cookie = "",
    }, &out));
}

test "rejects HRR that requests a group already shared in ClientHello1" {
    var offers = try baseOffers();
    offers.key_shares[0] = .{ .group = .x25519, .key_exchange = "share" };
    offers.key_shares_len = 1;
    var raw: [256]u8 = undefined;
    const encoded = try encode(.{
        .legacy_session_id_echo = "",
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
    }, &raw);
    const message = try messages.decode(encoded);
    try testing.expectError(error.IllegalParameter, decode(message.body, "", &offers));
}

fn hrrWithDuplicateExtension(out: []u8, duplicate_id: u16) ![]const u8 {
    var body: [256]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&random);
    try w.u8_(0);
    try w.u16_(@intFromEnum(algorithms.CipherSuite.tls_aes_128_gcm_sha256));
    try w.u8_(0);
    const extensions_len = try w.reserve(2);
    inline for (0..2) |_| {
        try w.u16_(duplicate_id);
        switch (duplicate_id) {
            @intFromEnum(algorithms.ExtensionType.supported_versions) => {
                try w.u16_(2);
                try w.u16_(@intFromEnum(algorithms.ProtocolVersion.tls13));
            },
            @intFromEnum(algorithms.ExtensionType.key_share) => {
                try w.u16_(2);
                try w.u16_(@intFromEnum(algorithms.NamedGroup.x25519));
            },
            @intFromEnum(algorithms.ExtensionType.cookie) => {
                try w.u16_(3);
                try w.u16_(1);
                try w.u8_(0xaa);
            },
            else => unreachable,
        }
    }
    w.patch(2, extensions_len);
    return messages.encode(.server_hello, w.written(), out);
}

test "duplicate HRR extensions map to illegal_parameter alert" {
    var offers = try baseOffers();
    inline for (.{
        @intFromEnum(algorithms.ExtensionType.supported_versions),
        @intFromEnum(algorithms.ExtensionType.key_share),
        @intFromEnum(algorithms.ExtensionType.cookie),
    }) |duplicate_id| {
        var raw: [256]u8 = undefined;
        const encoded = try hrrWithDuplicateExtension(&raw, duplicate_id);
        const message = try messages.decode(encoded);
        try testing.expectError(error.IllegalParameter, decode(message.body, "", &offers));
        try testing.expectEqual(alerts.AlertDescription.illegal_parameter, alerts.fromHandshakeError(error.IllegalParameter));
    }
}

test "HRR encoder validates session-id and cookie bounds before narrowing casts" {
    var out: [768]u8 = undefined;
    const sid32 = [_]u8{0xaa} ** 32;
    _ = try encode(.{
        .legacy_session_id_echo = &sid32,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
    }, &out);

    const sid33 = [_]u8{0xbb} ** 33;
    try testing.expectError(error.IllegalParameter, encode(.{
        .legacy_session_id_echo = &sid33,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
    }, &out));

    const max_cookie = [_]u8{0xcc} ** 460;
    _ = try encode(.{
        .legacy_session_id_echo = "",
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .cookie = &max_cookie,
    }, &out);
    const oversized_cookie = [_]u8{0xdd} ** 461;
    try testing.expectError(error.IllegalParameter, encode(.{
        .legacy_session_id_echo = "",
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .cookie = &oversized_cookie,
    }, &out));
}

fn clientHello(
    out: []u8,
    random_byte: u8,
    key_share_group: ?algorithms.NamedGroup,
    cookie: ?[]const u8,
    extra_extension: ?ExtensionView,
) ![]const u8 {
    return clientHelloWithShare(out, random_byte, key_share_group, "share", cookie, extra_extension);
}

fn clientHelloWithShare(
    out: []u8,
    random_byte: u8,
    key_share_group: ?algorithms.NamedGroup,
    key_share: []const u8,
    cookie: ?[]const u8,
    extra_extension: ?ExtensionView,
) ![]const u8 {
    var body: [512]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&([_]u8{random_byte} ** 32));
    try w.u8_(3);
    try w.bytes("sid");
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
    try w.u16_(@intFromEnum(algorithms.ExtensionType.key_share));
    const key_share_ext = try w.reserve(2);
    const key_shares = try w.reserve(2);
    if (key_share_group) |group| {
        try w.u16_(@intFromEnum(group));
        try w.u16_(@intCast(key_share.len));
        try w.bytes(key_share);
    }
    w.patch(2, key_shares);
    w.patch(2, key_share_ext);
    if (cookie) |value| {
        try w.u16_(@intFromEnum(algorithms.ExtensionType.cookie));
        try w.u16_(@intCast(2 + value.len));
        try w.u16_(@intCast(value.len));
        try w.bytes(value);
    }
    if (extra_extension) |extension| {
        try w.u16_(extension.id);
        try w.u16_(@intCast(extension.data.len));
        try w.bytes(extension.data);
    }
    w.patch(2, extensions_len);
    return messages.encode(.client_hello, w.written(), out);
}

fn clientHelloWithExtensionList(
    out: []u8,
    random_byte: u8,
    key_share_group: ?algorithms.NamedGroup,
    extensions: []const ExtensionView,
) ![]const u8 {
    var body: [768]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&([_]u8{random_byte} ** 32));
    try w.u8_(3);
    try w.bytes("sid");
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
    try w.u16_(@intFromEnum(algorithms.ExtensionType.key_share));
    const key_share_ext = try w.reserve(2);
    const key_shares = try w.reserve(2);
    if (key_share_group) |group| {
        try w.u16_(@intFromEnum(group));
        try w.u16_(5);
        try w.bytes("share");
    }
    w.patch(2, key_shares);
    w.patch(2, key_share_ext);
    for (extensions) |extension| {
        try w.u16_(extension.id);
        try w.u16_(@intCast(extension.data.len));
        try w.bytes(extension.data);
    }
    w.patch(2, extensions_len);
    return messages.encode(.client_hello, w.written(), out);
}

fn clientHelloWithReorderedExtensions(
    out: []u8,
    random_byte: u8,
    key_share_group: algorithms.NamedGroup,
) ![]const u8 {
    var body: [512]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&([_]u8{random_byte} ** 32));
    try w.u8_(3);
    try w.bytes("sid");
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.CipherSuite.tls_aes_128_gcm_sha256));
    try w.u8_(1);
    try w.u8_(0);
    const extensions_len = try w.reserve(2);
    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_versions));
    try w.u16_(3);
    try w.u8_(2);
    try w.u16_(@intFromEnum(algorithms.ProtocolVersion.tls13));
    try w.u16_(@intFromEnum(algorithms.ExtensionType.key_share));
    const key_share_ext = try w.reserve(2);
    const key_shares = try w.reserve(2);
    try w.u16_(@intFromEnum(key_share_group));
    try w.u16_(5);
    try w.bytes("share");
    w.patch(2, key_shares);
    w.patch(2, key_share_ext);
    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_groups));
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.NamedGroup.x25519));
    w.patch(2, extensions_len);
    return messages.encode(.client_hello, w.written(), out);
}

fn clientHelloWithReorderedStableExtensions(
    out: []u8,
    random_byte: u8,
    key_share_group: algorithms.NamedGroup,
) ![]const u8 {
    var body: [512]u8 = undefined;
    var w = messages.Writer{ .buf = &body };
    try w.u16_(algorithms.legacy_version);
    try w.bytes(&([_]u8{random_byte} ** 32));
    try w.u8_(3);
    try w.bytes("sid");
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.CipherSuite.tls_aes_128_gcm_sha256));
    try w.u8_(1);
    try w.u8_(0);
    const extensions_len = try w.reserve(2);
    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_groups));
    try w.u16_(4);
    try w.u16_(2);
    try w.u16_(@intFromEnum(algorithms.NamedGroup.x25519));
    try w.u16_(@intFromEnum(algorithms.ExtensionType.supported_versions));
    try w.u16_(3);
    try w.u8_(2);
    try w.u16_(@intFromEnum(algorithms.ProtocolVersion.tls13));
    try w.u16_(@intFromEnum(algorithms.ExtensionType.key_share));
    const key_share_ext = try w.reserve(2);
    const key_shares = try w.reserve(2);
    try w.u16_(@intFromEnum(key_share_group));
    try w.u16_(5);
    try w.bytes("share");
    w.patch(2, key_shares);
    w.patch(2, key_share_ext);
    w.patch(2, extensions_len);
    return messages.encode(.client_hello, w.written(), out);
}

fn pskExtension(
    out: []u8,
    identity_a: []const u8,
    age_a: u32,
    identity_b: ?[]const u8,
    age_b: u32,
    binder_byte: u8,
) ![]const u8 {
    var w = messages.Writer{ .buf = out };
    const ids_len = try w.reserve(2);
    try w.u16_(@intCast(identity_a.len));
    try w.bytes(identity_a);
    var age_bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &age_bytes, age_a, .big);
    try w.bytes(&age_bytes);
    if (identity_b) |id| {
        try w.u16_(@intCast(id.len));
        try w.bytes(id);
        std.mem.writeInt(u32, &age_bytes, age_b, .big);
        try w.bytes(&age_bytes);
    }
    w.patch(2, ids_len);
    const binders_len = try w.reserve(2);
    try w.u8_(32);
    try w.bytes(&([_]u8{binder_byte} ** 32));
    if (identity_b != null) {
        try w.u8_(32);
        try w.bytes(&([_]u8{binder_byte +% 1} ** 32));
    }
    w.patch(2, binders_len);
    return w.written();
}

test "ClientHello2 validator permits requested key share and cookie" {
    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHello(&first_buf, 0xaa, null, null, null);
    const second = try clientHello(&second_buf, 0xaa, .x25519, "cookie", null);
    try validateSecondClientHello(first, second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = "cookie",
    });
}

test "ClientHello2 validator permits key_share relocation" {
    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHello(&first_buf, 0xaa, null, null, null);
    const second = try clientHelloWithReorderedExtensions(&second_buf, 0xaa, .x25519);
    try validateSecondClientHello(first, second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = null,
    });
}

test "ClientHello2 validator rejects reordered unaffected extensions" {
    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHello(&first_buf, 0xaa, null, null, null);
    const second = try clientHelloWithReorderedStableExtensions(&second_buf, 0xaa, .x25519);
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = null,
    }));
}

test "ClientHello2 validator rejects changed random and cookie" {
    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHello(&first_buf, 0xaa, null, null, null);
    const changed_random = try clientHello(&second_buf, 0xbb, .x25519, "cookie", null);
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, changed_random, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = "cookie",
    }));

    const changed_cookie = try clientHello(&second_buf, 0xaa, .x25519, "other", null);
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, changed_cookie, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = "cookie",
    }));
}

test "ClientHello2 validator normalizes duplicate extensions to illegal_parameter" {
    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHello(&first_buf, 0xaa, null, null, null);
    const second = try clientHello(&second_buf, 0xaa, .x25519, null, .{
        .id = @intFromEnum(algorithms.ExtensionType.supported_groups),
        .data = &.{ 0, 2, 0, @intFromEnum(algorithms.NamedGroup.x25519) },
    });
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = null,
    }));
    try testing.expectEqual(alerts.AlertDescription.illegal_parameter, alerts.fromHandshakeError(error.IllegalParameter));
}

test "ClientHello2 validator accepts cookie-only HRR with unchanged key share" {
    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHello(&first_buf, 0xaa, .x25519, null, null);
    const second = try clientHello(&second_buf, 0xaa, .x25519, "cookie", null);
    try validateSecondClientHello(first, second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = "cookie",
    });

    const changed_share = try clientHelloWithShare(&second_buf, 0xaa, .x25519, "other", "cookie", null);
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, changed_share, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = "cookie",
    }));
}

test "ClientHello2 validator permits only zero-filled padding mutations" {
    const empty_padding = ExtensionView{ .id = @intFromEnum(algorithms.ExtensionType.padding), .data = "" };
    const zero_padding = ExtensionView{ .id = @intFromEnum(algorithms.ExtensionType.padding), .data = &.{ 0, 0, 0, 0 } };
    const nonzero_padding = ExtensionView{ .id = @intFromEnum(algorithms.ExtensionType.padding), .data = &.{ 0, 1, 0 } };

    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHelloWithExtensionList(&first_buf, 0xaa, .x25519, &.{empty_padding});
    const resized_zero = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{zero_padding});
    try validateSecondClientHello(first, resized_zero, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = null,
    });

    const invalid = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{nonzero_padding});
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, invalid, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = null,
    }));
}

test "ClientHello2 validator enforces pre_shared_key final extension ordering" {
    var psk_buf: [256]u8 = undefined;
    const psk = try pskExtension(&psk_buf, "ticket-a", 1, null, 0, 0xaa);
    const psk_ext = ExtensionView{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = psk };
    const cookie_ext = ExtensionView{ .id = @intFromEnum(algorithms.ExtensionType.cookie), .data = &.{ 0, 6, 'c', 'o', 'o', 'k', 'i', 'e' } };

    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHelloWithExtensionList(&first_buf, 0xaa, .x25519, &.{psk_ext});
    const valid_second = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{ cookie_ext, psk_ext });
    try validateSecondClientHello(first, valid_second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = "cookie",
    });

    const invalid_second = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{ psk_ext, cookie_ext });
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, invalid_second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = "cookie",
    }));
}

test "ClientHello2 validator compares PSK identities while allowing ages and binders" {
    var psk_first_buf: [256]u8 = undefined;
    var psk_second_buf: [256]u8 = undefined;
    const psk_first = try pskExtension(&psk_first_buf, "ticket-a", 1, "ticket-b", 2, 0xaa);
    const psk_second = try pskExtension(&psk_second_buf, "ticket-a", 99, "ticket-b", 100, 0xbb);

    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHelloWithExtensionList(&first_buf, 0xaa, .x25519, &.{
        .{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = psk_first },
    });
    const second = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{
        .{ .id = @intFromEnum(algorithms.ExtensionType.cookie), .data = &.{ 0, 6, 'c', 'o', 'o', 'k', 'i', 'e' } },
        .{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = psk_second },
    });
    try validateSecondClientHello(first, second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = "cookie",
    });

    const changed_identity = try pskExtension(&psk_second_buf, "ticket-x", 99, "ticket-b", 100, 0xbb);
    const changed_second = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{
        .{ .id = @intFromEnum(algorithms.ExtensionType.cookie), .data = &.{ 0, 6, 'c', 'o', 'o', 'k', 'i', 'e' } },
        .{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = changed_identity },
    });
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, changed_second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = "cookie",
    }));

    const reordered = try pskExtension(&psk_second_buf, "ticket-b", 99, "ticket-a", 100, 0xbb);
    const reordered_second = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{
        .{ .id = @intFromEnum(algorithms.ExtensionType.cookie), .data = &.{ 0, 6, 'c', 'o', 'o', 'k', 'i', 'e' } },
        .{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = reordered },
    });
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, reordered_second, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = null,
        .cookie = "cookie",
    }));
}

test "ClientHello2 validator rejects malformed PSK binder vectors" {
    var first_psk_buf: [256]u8 = undefined;
    const psk_first = try pskExtension(&first_psk_buf, "ticket-a", 1, null, 0, 0xaa);

    var malformed_buf: [64]u8 = undefined;
    var w = messages.Writer{ .buf = &malformed_buf };
    const ids_len = try w.reserve(2);
    try w.u16_(8);
    try w.bytes("ticket-a");
    try w.bytes(&.{ 0, 0, 0, 1 });
    w.patch(2, ids_len);
    try w.u16_(1);
    try w.u8_(31);
    const malformed_binder = w.written();

    var mismatch_buf: [128]u8 = undefined;
    var mw = messages.Writer{ .buf = &mismatch_buf };
    const mismatch_ids = try mw.reserve(2);
    try mw.u16_(8);
    try mw.bytes("ticket-a");
    try mw.bytes(&.{ 0, 0, 0, 1 });
    mw.patch(2, mismatch_ids);
    const mismatch_binders = try mw.reserve(2);
    try mw.u8_(32);
    try mw.bytes(&([_]u8{0xaa} ** 32));
    try mw.u8_(32);
    try mw.bytes(&([_]u8{0xbb} ** 32));
    mw.patch(2, mismatch_binders);
    const count_mismatch = mw.written();

    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHelloWithExtensionList(&first_buf, 0xaa, .x25519, &.{
        .{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = psk_first },
    });

    inline for (.{ malformed_binder, count_mismatch }) |bad_psk| {
        const second = try clientHelloWithExtensionList(&second_buf, 0xaa, .x25519, &.{
            .{ .id = @intFromEnum(algorithms.ExtensionType.cookie), .data = &.{ 0, 6, 'c', 'o', 'o', 'k', 'i', 'e' } },
            .{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = bad_psk },
        });
        try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, second, .{
            .selected_version = .tls13,
            .cipher_suite = .tls_aes_128_gcm_sha256,
            .selected_group = null,
            .cookie = "cookie",
        }));
    }
}

test "ClientHello2 validator rejects a well-formed empty key share list with illegal_parameter" {
    // Found 2026-09-01 by the #675 campaign (test-tls-protocol-fuzz --fuzz):
    // a ClientHello2 whose key_share list parses cleanly but is empty
    // violates RFC 8446 §4.1.2's exactly-one-share requirement. It was
    // previously misclassified as MalformedHandshake (decode_error alert)
    // via a Reader underflow; the wire bytes are well-formed, so the
    // server must answer illegal_parameter.
    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    const first = try clientHello(&first_buf, 0xaa, null, null, null);
    const missing_share = try clientHello(&second_buf, 0xaa, null, "cookie", null);
    try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, missing_share, .{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = "cookie",
    }));
}

test "expectSingleKeyShare separates HRR share-rule violations from structural truncation" {
    const x25519 = @intFromEnum(algorithms.NamedGroup.x25519);
    const secp = @intFromEnum(algorithms.NamedGroup.secp256r1);

    // Exactly one non-empty share for the selected group: accepted.
    try expectSingleKeyShare(.x25519, &.{ 0, 7, @intCast(x25519 >> 8), @intCast(x25519 & 0xff), 0, 3, 'k', 'e', 'y' });
    // Well-formed but empty list: illegal_parameter, not decode_error.
    try testing.expectError(error.IllegalParameter, expectSingleKeyShare(.x25519, &.{ 0, 0 }));
    // Well-formed list with the right share followed by a second share:
    // violates "solely one share" — illegal_parameter.
    try testing.expectError(error.IllegalParameter, expectSingleKeyShare(.x25519, &.{ 0, 14, @intCast(x25519 >> 8), @intCast(x25519 & 0xff), 0, 3, 'k', 'e', 'y', @intCast(secp >> 8), @intCast(secp & 0xff), 0, 3, 'k', 'e', 'y' }));
    // Wrong group and empty key_exchange remain illegal_parameter.
    try testing.expectError(error.IllegalParameter, expectSingleKeyShare(.x25519, &.{ 0, 7, @intCast(secp >> 8), @intCast(secp & 0xff), 0, 3, 'k', 'e', 'y' }));
    try testing.expectError(error.IllegalParameter, expectSingleKeyShare(.x25519, &.{ 0, 4, @intCast(x25519 >> 8), @intCast(x25519 & 0xff), 0, 0 }));
    // Structural truncation inside the list is still a decode failure.
    try testing.expectError(error.MalformedHandshake, expectSingleKeyShare(.x25519, &.{ 0, 3, @intCast(x25519 >> 8), @intCast(x25519 & 0xff), 0 }));
    try testing.expectError(error.MalformedHandshake, expectSingleKeyShare(.x25519, &.{ 0, 9, @intCast(x25519 >> 8), @intCast(x25519 & 0xff), 0, 3, 'k', 'e', 'y' }));
}

test "fuzz: TLS protocol: HRR decode and ClientHello2 validation reject malformed ordering deterministically" {
    try testing.fuzz({}, fuzzHrrAndClientHello2, .{ .corpus = &.{
        "",
        &[_]u8{ 3, 3 } ++ random ++ [_]u8{ 0, 0x13, 0x01, 0, 0, 0 },
        &([_]u8{0xff} ** 128),
    } });
}

fn fuzzHrrAndClientHello2(_: void, smith: *testing.Smith) !void {
    var offers = try baseOffers();
    if (smith.index(2) == 0) {
        offers.key_shares[0] = .{ .group = .x25519, .key_exchange = "share" };
        offers.key_shares_len = 1;
    }
    if (smith.index(2) == 0) offers.key_share_seen = false;

    var raw_body: [384]u8 = undefined;
    const raw_len = smith.index(raw_body.len + 1);
    smith.bytes(raw_body[0..raw_len]);
    if (decode(raw_body[0..raw_len], "sid", &offers)) |request| {
        try testing.expectEqual(algorithms.ProtocolVersion.tls13, request.selected_version);
        try testing.expect(containsEnum(algorithms.CipherSuite, offers.cipher_suites[0..offers.cipher_suites_len], request.cipher_suite));
        if (request.selected_group) |group| {
            try testing.expect(containsEnum(algorithms.NamedGroup, offers.supported_groups[0..offers.supported_groups_len], group));
            try testing.expect(offers.keyShareFor(group) == null);
        }
        if (request.cookie) |cookie| try testing.expect(cookie.len > 0);
    } else |err| switch (err) {
        error.MalformedHandshake,
        error.IllegalParameter,
        error.UnexpectedHandshakeMessage,
        error.MissingExtension,
        error.UnsupportedExtension,
        error.AlpnMismatch,
        error.UnsupportedCertificate,
        error.CertificateInvalid,
        error.SecretExportFailed,
        error.InvalidHandshakeState,
        error.TicketTooLarge,
        error.NoApplicableCredential,
        error.CredentialProviderFailed,
        error.ClientCertificateRequired,
        error.DecryptError,
        error.HandshakeBufferOverflow,
        error.DuplicateExtension,
        error.TooManyExtensions,
        error.MessageTooLarge,
        error.IncompleteHandshake,
        // #338: part of the shared handshake error set. Neither is reachable
        // from HelloRetryRequest coding — an HRR is validated against the
        // offers this client already sent, not negotiated afresh — but the
        // set is enumerated exhaustively here so a newly added failure class
        // cannot be silently swallowed by a catch-all.
        error.NoMutualParameters,
        error.UnsupportedProtocolVersion,
        => {},
    }

    var first_buf: [768]u8 = undefined;
    var second_buf: [768]u8 = undefined;
    var mutated_buf: [768]u8 = undefined;
    var psk_first_buf: [768]u8 = undefined;
    var psk_buf: [256]u8 = undefined;

    const first_random: u8 = @intCast(smith.index(256));
    const second_cookie = "cookie";
    const first = try clientHello(&first_buf, first_random, null, null, null);
    const second = try clientHello(&second_buf, first_random, .x25519, second_cookie, null);
    const valid_request = Request{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = second_cookie,
    };
    try validateSecondClientHello(first, second, valid_request);

    switch (smith.index(8)) {
        0 => {
            const bad_random = try clientHello(&mutated_buf, first_random ^ 0xff, .x25519, second_cookie, null);
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, bad_random, valid_request));
        },
        1 => {
            const missing_cookie = try clientHello(&mutated_buf, first_random, .x25519, null, null);
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, missing_cookie, valid_request));
        },
        2 => {
            const wrong_cookie = try clientHello(&mutated_buf, first_random, .x25519, "other", null);
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, wrong_cookie, valid_request));
        },
        3 => {
            const missing_share = try clientHello(&mutated_buf, first_random, null, second_cookie, null);
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, missing_share, valid_request));
        },
        4 => {
            const early_data = try clientHello(
                &mutated_buf,
                first_random,
                .x25519,
                second_cookie,
                .{ .id = @intFromEnum(algorithms.ExtensionType.early_data), .data = "" },
            );
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, early_data, valid_request));
        },
        5 => {
            const nonzero_padding = try clientHello(
                &mutated_buf,
                first_random,
                .x25519,
                second_cookie,
                .{ .id = @intFromEnum(algorithms.ExtensionType.padding), .data = &.{ 0, @intCast(1 + smith.index(255)) } },
            );
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, nonzero_padding, valid_request));
        },
        6 => {
            const reordered_stable = try clientHelloWithReorderedStableExtensions(&mutated_buf, first_random, .x25519);
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first, reordered_stable, .{
                .selected_version = .tls13,
                .cipher_suite = .tls_aes_128_gcm_sha256,
                .selected_group = .x25519,
                .cookie = null,
            }));
        },
        else => {
            const psk = try pskExtension(&psk_buf, "ticket-a", @intCast(smith.index(1024)), null, 0, @intCast(smith.index(256)));
            const psk_ext = ExtensionView{ .id = @intFromEnum(algorithms.ExtensionType.pre_shared_key), .data = psk };
            const cookie_ext = ExtensionView{ .id = @intFromEnum(algorithms.ExtensionType.cookie), .data = &.{ 0, 6, 'c', 'o', 'o', 'k', 'i', 'e' } };
            const first_with_psk = try clientHelloWithExtensionList(&psk_first_buf, first_random, .x25519, &.{psk_ext});
            const invalid_psk_order = try clientHelloWithExtensionList(&mutated_buf, first_random, .x25519, &.{ psk_ext, cookie_ext });
            try testing.expectError(error.IllegalParameter, validateSecondClientHello(first_with_psk, invalid_psk_order, .{
                .selected_version = .tls13,
                .cipher_suite = .tls_aes_128_gcm_sha256,
                .selected_group = null,
                .cookie = second_cookie,
            }));
        },
    }

    const second_random = if (smith.index(4) == 0) first_random ^ 0xff else first_random;
    const sampled_second = try clientHello(
        &second_buf,
        second_random,
        if (smith.index(2) == 0) .x25519 else null,
        if (smith.index(2) == 0) second_cookie else null,
        null,
    );
    const sampled_request = Request{
        .selected_version = .tls13,
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .selected_group = .x25519,
        .cookie = second_cookie,
    };
    validateSecondClientHello(first, sampled_second, sampled_request) catch |err| switch (err) {
        error.MalformedHandshake,
        error.IllegalParameter,
        error.UnexpectedHandshakeMessage,
        error.MissingExtension,
        error.UnsupportedExtension,
        error.AlpnMismatch,
        error.UnsupportedCertificate,
        error.CertificateInvalid,
        error.SecretExportFailed,
        error.InvalidHandshakeState,
        error.TicketTooLarge,
        error.NoApplicableCredential,
        error.CredentialProviderFailed,
        error.ClientCertificateRequired,
        error.DecryptError,
        error.HandshakeBufferOverflow,
        error.DuplicateExtension,
        error.TooManyExtensions,
        error.MessageTooLarge,
        error.IncompleteHandshake,
        // #338: part of the shared handshake error set. Neither is reachable
        // from HelloRetryRequest coding — an HRR is validated against the
        // offers this client already sent, not negotiated afresh — but the
        // set is enumerated exhaustively here so a newly added failure class
        // cannot be silently swallowed by a catch-all.
        error.NoMutualParameters,
        error.UnsupportedProtocolVersion,
        => {},
    };
}

const std = @import("std");
const Headers = @import("headers.zig").Headers;

pub const MAGIC_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const OpCode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xA,
};

pub const Frame = struct {
    fin: bool,
    opcode: OpCode,
    payload: []u8,
};

pub fn isUpgradeRequest(headers: *const Headers) bool {
    const connection = headers.get("connection") orelse return false;
    const upgrade = headers.get("upgrade") orelse return false;
    const ws_key = headers.get("sec-websocket-key") orelse return false;
    const ws_version = headers.get("sec-websocket-version") orelse return false;
    if (!std.ascii.eqlIgnoreCase(upgrade, "websocket")) return false;
    if (std.ascii.indexOfIgnoreCase(connection, "upgrade") == null) return false;
    if (!std.mem.eql(u8, std.mem.trim(u8, ws_version, " \t\r\n"), "13")) return false;
    return ws_key.len > 0;
}

pub fn acceptKey(allocator: std.mem.Allocator, client_key: []const u8) ![]u8 {
    const concat = try std.fmt.allocPrint(allocator, "{s}{s}", .{ client_key, MAGIC_GUID });
    defer allocator.free(concat);
    var digest: [20]u8 = undefined;
    std.crypto.hash.Sha1.hash(concat, &digest, .{});
    const encoded_len = std.base64.standard.Encoder.calcSize(digest.len);
    const out = try allocator.alloc(u8, encoded_len);
    _ = std.base64.standard.Encoder.encode(out, digest[0..]);
    return out;
}

pub fn writeServerHandshake(
    writer: anytype,
    accept_key: []const u8,
    protocol: ?[]const u8,
) !void {
    try writer.writeAll("HTTP/1.1 101 Switching Protocols\r\n");
    try writer.writeAll("Upgrade: websocket\r\n");
    try writer.writeAll("Connection: Upgrade\r\n");
    try writer.print("Sec-WebSocket-Accept: {s}\r\n", .{accept_key});
    if (protocol) |p| {
        try writer.print("Sec-WebSocket-Protocol: {s}\r\n", .{p});
    }
    try writer.writeAll("\r\n");
}

/// Length of a `Sec-WebSocket-Accept` value: base64 of a 20-byte SHA-1.
pub const ACCEPT_KEY_LEN = 28;

/// `Sec-WebSocket-Accept` for `client_key` (RFC 6455 §4.2.2), written into
/// `out` without allocating.
pub fn computeAcceptKey(client_key: []const u8, out: *[ACCEPT_KEY_LEN]u8) []const u8 {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(client_key);
    sha.update(MAGIC_GUID);
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    return std.base64.standard.Encoder.encode(out, &digest);
}

/// True when the comma-separated field `value` lists `token` (any case).
pub fn headerHasToken(value: []const u8, token: []const u8) bool {
    var it = std.mem.splitScalar(u8, value, ',');
    while (it.next()) |raw| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, raw, " \t"), token)) return true;
    }
    return false;
}

/// True when any `name` field on `headers` lists `token`.
fn anyHeaderHasToken(headers: *const Headers, name: []const u8, token: []const u8) bool {
    for (headers.iterator()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name) and headerHasToken(header.value, token)) return true;
    }
    return false;
}

/// A `Sec-WebSocket-Key` must be the base64 encoding of 16 bytes (RFC 6455
/// §4.1): exactly 24 characters ending in `==`.
pub fn isValidClientKey(key: []const u8) bool {
    if (key.len != 24) return false;
    var decoded: [16]u8 = undefined;
    const size = std.base64.standard.Decoder.calcSizeForSlice(key) catch return false;
    if (size != decoded.len) return false;
    std.base64.standard.Decoder.decode(&decoded, key) catch return false;
    return true;
}

/// What a client request is, as far as WebSocket relaying is concerned.
pub const ClientHandshake = union(enum) {
    /// No `Upgrade: websocket`; an ordinary request.
    not_websocket,
    /// A well-formed RFC 6455 opening handshake.
    valid: struct { key: []const u8 },
    /// `Sec-WebSocket-Version` other than 13: answered with 426 and
    /// `Sec-WebSocket-Version: 13` (RFC 6455 §4.4).
    unsupported_version,
    /// Asks for `Upgrade: websocket` but is not a valid handshake.
    invalid: []const u8,
};

/// Classify an HTTP/1.1 request that may be a WebSocket opening handshake.
/// Anything naming `websocket` in `Upgrade` is held to RFC 6455 §4.1 exactly:
/// a GET over HTTP/1.1 with `Connection: upgrade`, one valid key, version 13,
/// and no request body or body framing, so a handshake can never smuggle a
/// second message.
pub fn classifyClientHandshake(is_get: bool, is_http11: bool, headers: *const Headers) ClientHandshake {
    if (!anyHeaderHasToken(headers, "upgrade", "websocket")) return .not_websocket;
    if (!is_get) return .{ .invalid = "WebSocket handshake must use GET" };
    if (!is_http11) return .{ .invalid = "WebSocket handshake requires HTTP/1.1" };
    if (!anyHeaderHasToken(headers, "connection", "upgrade")) return .{ .invalid = "WebSocket handshake requires Connection: Upgrade" };
    if (headers.get("transfer-encoding") != null) return .{ .invalid = "WebSocket handshake must not carry a body" };
    if (headers.get("content-length")) |raw| {
        const length = std.fmt.parseInt(usize, std.mem.trim(u8, raw, " \t"), 10) catch return .{ .invalid = "WebSocket handshake must not carry a body" };
        if (length != 0) return .{ .invalid = "WebSocket handshake must not carry a body" };
    }
    var key: ?[]const u8 = null;
    var version: ?[]const u8 = null;
    var origins: usize = 0;
    for (headers.iterator()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "origin")) {
            // The Origin allowlist and the origin application must judge the
            // same value; two fields make that ambiguous.
            origins += 1;
            if (origins > 1) return .{ .invalid = "Duplicate Origin" };
        } else if (std.ascii.eqlIgnoreCase(header.name, "sec-websocket-key")) {
            if (key != null) return .{ .invalid = "Duplicate Sec-WebSocket-Key" };
            key = std.mem.trim(u8, header.value, " \t");
        } else if (std.ascii.eqlIgnoreCase(header.name, "sec-websocket-version")) {
            if (version != null) return .{ .invalid = "Duplicate Sec-WebSocket-Version" };
            version = std.mem.trim(u8, header.value, " \t");
        }
    }
    const client_key = key orelse return .{ .invalid = "Missing Sec-WebSocket-Key" };
    if (!isValidClientKey(client_key)) return .{ .invalid = "Invalid Sec-WebSocket-Key" };
    const client_version = version orelse return .unsupported_version;
    if (!std.mem.eql(u8, client_version, "13")) return .unsupported_version;
    return .{ .valid = .{ .key = client_key } };
}

/// True when `origin` (the request's `Origin` value) is allowed by `allowed`.
/// An empty allowlist allows everything; a request without `Origin` did not
/// come from a browser and cannot be a cross-site WebSocket hijack, so it is
/// allowed too.
pub fn originAllowed(allowed: []const []const u8, origin: ?[]const u8) bool {
    if (allowed.len == 0) return true;
    const value = std.mem.trim(u8, origin orelse return true, " \t");
    for (allowed) |candidate| {
        if (std.ascii.eqlIgnoreCase(candidate, value)) return true;
    }
    return false;
}

pub fn readFrame(conn: anytype, allocator: std.mem.Allocator, max_payload: usize) !Frame {
    var hdr: [2]u8 = undefined;
    try readExact(conn, hdr[0..]);
    const fin = (hdr[0] & 0x80) != 0;
    const opcode: OpCode = @enumFromInt(@as(u4, @truncate(hdr[0])));
    const masked = (hdr[1] & 0x80) != 0;
    var len: usize = hdr[1] & 0x7F;

    if (len == 126) {
        var ext: [2]u8 = undefined;
        try readExact(conn, ext[0..]);
        len = std.mem.readInt(u16, ext[0..2], .big);
    } else if (len == 127) {
        var ext: [8]u8 = undefined;
        try readExact(conn, ext[0..]);
        len = @intCast(std.mem.readInt(u64, ext[0..8], .big));
    }
    if (len > max_payload) return error.FrameTooLarge;

    var mask_key: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) try readExact(conn, mask_key[0..]);

    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    try readExact(conn, payload);
    if (masked) {
        for (payload, 0..) |*b, i| b.* ^= mask_key[i % 4];
    }
    return .{ .fin = fin, .opcode = opcode, .payload = payload };
}

pub fn deinitFrame(allocator: std.mem.Allocator, frame: *Frame) void {
    allocator.free(frame.payload);
    frame.* = undefined;
}

pub fn writeFrame(writer: anytype, opcode: OpCode, payload: []const u8, fin: bool) !void {
    var first: u8 = @intFromEnum(opcode);
    if (fin) first |= 0x80;
    try writer.writeByte(first);

    if (payload.len < 126) {
        try writer.writeByte(@intCast(payload.len));
    } else if (payload.len <= std.math.maxInt(u16)) {
        try writer.writeByte(126);
        var ext: [2]u8 = undefined;
        std.mem.writeInt(u16, ext[0..2], @intCast(payload.len), .big);
        try writer.writeAll(ext[0..]);
    } else {
        try writer.writeByte(127);
        var ext: [8]u8 = undefined;
        std.mem.writeInt(u64, ext[0..8], payload.len, .big);
        try writer.writeAll(ext[0..]);
    }
    try writer.writeAll(payload);
}

fn readExact(conn: anytype, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try conn.read(out[off..]);
        if (n == 0) return error.ConnectionClosed;
        off += n;
    }
}

test "acceptKey generates deterministic output" {
    const allocator = std.testing.allocator;
    const out = try acceptKey(allocator, "dGhlIHNhbXBsZSBub25jZQ==");
    defer allocator.free(out);
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", out);
}

test "computeAcceptKey matches the RFC 6455 example without allocating" {
    var buf: [ACCEPT_KEY_LEN]u8 = undefined;
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", computeAcceptKey("dGhlIHNhbXBsZSBub25jZQ==", &buf));
}

fn handshakeHeadersForTest(pairs: []const [2][]const u8) !Headers {
    var headers = Headers.init(std.testing.allocator);
    errdefer headers.deinit();
    for (pairs) |pair| try headers.append(pair[0], pair[1]);
    return headers;
}

test "classifyClientHandshake accepts a well-formed handshake and token lists" {
    var headers = try handshakeHeadersForTest(&.{
        .{ "Host", "example.test" },
        .{ "Upgrade", "WebSocket" },
        .{ "Connection", "keep-alive, Upgrade" },
        .{ "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==" },
        .{ "Sec-WebSocket-Version", "13" },
    });
    defer headers.deinit();
    const result = classifyClientHandshake(true, true, &headers);
    try std.testing.expectEqualStrings("dGhlIHNhbXBsZSBub25jZQ==", result.valid.key);
}

test "classifyClientHandshake leaves requests without Upgrade: websocket alone" {
    var plain = try handshakeHeadersForTest(&.{.{ "Host", "example.test" }});
    defer plain.deinit();
    try std.testing.expect(classifyClientHandshake(true, true, &plain) == .not_websocket);

    var h2c = try handshakeHeadersForTest(&.{ .{ "Upgrade", "h2c" }, .{ "Connection", "Upgrade" } });
    defer h2c.deinit();
    try std.testing.expect(classifyClientHandshake(true, true, &h2c) == .not_websocket);
}

test "classifyClientHandshake rejects malformed and smuggling-shaped handshakes" {
    const base = [_][2][]const u8{
        .{ "Upgrade", "websocket" },
        .{ "Connection", "Upgrade" },
        .{ "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==" },
        .{ "Sec-WebSocket-Version", "13" },
    };
    var ok = try handshakeHeadersForTest(&base);
    defer ok.deinit();
    try std.testing.expect(classifyClientHandshake(false, true, &ok) == .invalid);
    try std.testing.expect(classifyClientHandshake(true, false, &ok) == .invalid);

    const cases = [_][]const [2][]const u8{
        &.{ base[0], base[2], base[3] },
        &.{ base[0], base[1], base[3] },
        &.{ base[0], base[1], .{ "Sec-WebSocket-Key", "short" }, base[3] },
        &.{ base[0], base[1], .{ "Sec-WebSocket-Key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAA" }, base[3] },
        &.{ base[0], base[1], base[2], base[2], base[3] },
        &.{ base[0], base[1], base[2], base[3], .{ "Content-Length", "5" } },
        &.{ base[0], base[1], base[2], base[3], .{ "Transfer-Encoding", "chunked" } },
        &.{ base[0], base[1], base[2], base[3], .{ "Origin", "https://app.example.test" }, .{ "origin", "https://evil.example.test" } },
    };
    for (cases) |pairs| {
        var headers = try handshakeHeadersForTest(pairs);
        defer headers.deinit();
        try std.testing.expect(classifyClientHandshake(true, true, &headers) == .invalid);
    }

    var zero_length = try handshakeHeadersForTest(&.{ base[0], base[1], base[2], base[3], .{ "Content-Length", "0" } });
    defer zero_length.deinit();
    try std.testing.expect(classifyClientHandshake(true, true, &zero_length) == .valid);

    var old_version = try handshakeHeadersForTest(&.{ base[0], base[1], base[2], .{ "Sec-WebSocket-Version", "8" } });
    defer old_version.deinit();
    try std.testing.expect(classifyClientHandshake(true, true, &old_version) == .unsupported_version);
}

test "originAllowed enforces a configured allowlist only for browser requests" {
    try std.testing.expect(originAllowed(&.{}, "https://evil.test"));
    const allowed = [_][]const u8{"https://app.example.test"};
    try std.testing.expect(originAllowed(&allowed, "https://APP.example.test"));
    try std.testing.expect(!originAllowed(&allowed, "https://evil.test"));
    try std.testing.expect(!originAllowed(&allowed, "null"));
    try std.testing.expect(originAllowed(&allowed, null));
}

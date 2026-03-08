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

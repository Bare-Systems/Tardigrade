const std = @import("std");

pub const Type = enum(u8) {
    data = 0x0,
    headers = 0x1,
    priority = 0x2,
    rst_stream = 0x3,
    settings = 0x4,
    push_promise = 0x5,
    ping = 0x6,
    goaway = 0x7,
    window_update = 0x8,
    continuation = 0x9,
};

pub const Flags = struct {
    pub const END_STREAM: u8 = 0x1;
    pub const END_HEADERS: u8 = 0x4;
    pub const ACK: u8 = 0x1;
};

pub const Frame = struct {
    typ: Type,
    flags: u8,
    stream_id: u31,
    payload: []u8,
};

pub const HEADER_LEN: usize = 9;

pub fn readFrame(conn: anytype, allocator: std.mem.Allocator, max_frame_size: usize) !Frame {
    var header: [HEADER_LEN]u8 = undefined;
    try readExact(conn, header[0..]);
    const len = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | @as(usize, header[2]);
    if (len > max_frame_size) return error.Http2FrameTooLarge;
    const typ: Type = @enumFromInt(header[3]);
    const flags = header[4];
    const sid = std.mem.readInt(u32, header[5..9], .big) & 0x7FFF_FFFF;
    const payload = try allocator.alloc(u8, len);
    errdefer allocator.free(payload);
    try readExact(conn, payload);
    return .{
        .typ = typ,
        .flags = flags,
        .stream_id = @intCast(sid),
        .payload = payload,
    };
}

pub fn deinitFrame(allocator: std.mem.Allocator, frame: *Frame) void {
    allocator.free(frame.payload);
    frame.* = undefined;
}

pub fn writeFrame(writer: anytype, typ: Type, flags: u8, stream_id: u31, payload: []const u8) !void {
    var header: [HEADER_LEN]u8 = undefined;
    header[0] = @as(u8, @intCast((payload.len >> 16) & 0xFF));
    header[1] = @as(u8, @intCast((payload.len >> 8) & 0xFF));
    header[2] = @as(u8, @intCast(payload.len & 0xFF));
    header[3] = @intFromEnum(typ);
    header[4] = flags;
    const sid: u32 = @as(u32, stream_id) & 0x7FFF_FFFF;
    std.mem.writeInt(u32, header[5..9], sid, .big);
    try writer.writeAll(header[0..]);
    try writer.writeAll(payload);
}

pub fn writeSettings(writer: anytype, entries: []const [2]u32) !void {
    var buf = std.ArrayList(u8).init(std.heap.page_allocator);
    defer buf.deinit();
    for (entries) |e| {
        var raw: [6]u8 = undefined;
        std.mem.writeInt(u16, raw[0..2], @intCast(e[0]), .big);
        std.mem.writeInt(u32, raw[2..6], e[1], .big);
        try buf.appendSlice(raw[0..]);
    }
    try writeFrame(writer, .settings, 0, 0, buf.items);
}

pub fn writeSettingsAck(writer: anytype) !void {
    try writeFrame(writer, .settings, Flags.ACK, 0, &[_]u8{});
}

pub fn writePingAck(writer: anytype, payload: []const u8) !void {
    if (payload.len != 8) return error.InvalidPingPayload;
    try writeFrame(writer, .ping, Flags.ACK, 0, payload);
}

pub fn writeGoaway(writer: anytype, last_stream: u31, err_code: u32) !void {
    var payload: [8]u8 = undefined;
    std.mem.writeInt(u32, payload[0..4], @as(u32, last_stream), .big);
    std.mem.writeInt(u32, payload[4..8], err_code, .big);
    try writeFrame(writer, .goaway, 0, 0, payload[0..]);
}

fn readExact(conn: anytype, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try conn.read(out[off..]);
        if (n == 0) return error.ConnectionClosed;
        off += n;
    }
}

test "write and parse frame header values" {
    var buf: [64]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    try writeFrame(fbs.writer(), .settings, 0, 0, &[_]u8{ 1, 2, 3 });
    const out = fbs.getWritten();
    try std.testing.expectEqual(@as(u8, 0), out[0]);
    try std.testing.expectEqual(@as(u8, 0), out[1]);
    try std.testing.expectEqual(@as(u8, 3), out[2]);
    try std.testing.expectEqual(@as(u8, 0x4), out[3]);
}

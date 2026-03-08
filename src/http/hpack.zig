const std = @import("std");

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

pub const DecodeResult = struct {
    headers: []HeaderField,
};

const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

const static_table = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

pub fn decode(allocator: std.mem.Allocator, block: []const u8) !DecodeResult {
    var out = std.ArrayList(HeaderField).init(allocator);
    errdefer {
        for (out.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        out.deinit();
    }

    var i: usize = 0;
    while (i < block.len) {
        const b = block[i];
        if ((b & 0x80) != 0) {
            const indexed = try decodeInteger(block, &i, 7);
            const entry = staticByIndex(indexed) orelse return error.InvalidHpackIndex;
            try out.append(.{
                .name = try allocator.dupe(u8, entry.name),
                .value = try allocator.dupe(u8, entry.value),
            });
            continue;
        }
        if ((b & 0xE0) == 0x20) {
            _ = try decodeInteger(block, &i, 5);
            continue;
        }
        if ((b & 0xF0) == 0x10 or (b & 0xF0) == 0x00 or (b & 0xC0) == 0x40) {
            const prefix_bits: u3 = if ((b & 0xC0) == 0x40) 6 else 4;
            const name_index = try decodeInteger(block, &i, prefix_bits);
            const name = if (name_index == 0)
                try decodeStringAlloc(allocator, block, &i)
            else blk: {
                const entry = staticByIndex(name_index) orelse return error.InvalidHpackIndex;
                break :blk try allocator.dupe(u8, entry.name);
            };
            errdefer allocator.free(name);
            const value = try decodeStringAlloc(allocator, block, &i);
            errdefer allocator.free(value);
            try out.append(.{ .name = name, .value = value });
            continue;
        }
        return error.UnsupportedHpackRepresentation;
    }
    return .{ .headers = try out.toOwnedSlice() };
}

pub fn deinitDecoded(allocator: std.mem.Allocator, decoded: *DecodeResult) void {
    for (decoded.headers) |h| {
        allocator.free(h.name);
        allocator.free(h.value);
    }
    allocator.free(decoded.headers);
    decoded.* = undefined;
}

pub fn encodeLiteralHeaderBlock(allocator: std.mem.Allocator, headers: []const HeaderField) ![]u8 {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();
    for (headers) |h| {
        try out.append(0x00);
        try encodeString(&out, h.name);
        try encodeString(&out, h.value);
    }
    return out.toOwnedSlice();
}

fn decodeInteger(buf: []const u8, idx: *usize, prefix_bits: u3) !usize {
    if (idx.* >= buf.len) return error.TruncatedHpack;
    const prefix_mask: u8 = (@as(u8, 1) << prefix_bits) - 1;
    var value: usize = buf[idx.*] & prefix_mask;
    idx.* += 1;
    if (value < prefix_mask) return value;

    var m: usize = 0;
    while (true) {
        if (idx.* >= buf.len) return error.TruncatedHpack;
        const b = buf[idx.*];
        idx.* += 1;
        value += @as(usize, b & 0x7F) << @intCast(m);
        if ((b & 0x80) == 0) break;
        m += 7;
        if (m > 56) return error.InvalidHpackInteger;
    }
    return value;
}

fn decodeStringAlloc(allocator: std.mem.Allocator, buf: []const u8, idx: *usize) ![]u8 {
    if (idx.* >= buf.len) return error.TruncatedHpack;
    const huffman = (buf[idx.*] & 0x80) != 0;
    if (huffman) return error.HuffmanUnsupported;
    const len = try decodeInteger(buf, idx, 7);
    if (idx.* + len > buf.len) return error.TruncatedHpack;
    const out = try allocator.dupe(u8, buf[idx.* .. idx.* + len]);
    idx.* += len;
    return out;
}

fn encodeInteger(out: *std.ArrayList(u8), value: usize, prefix_bits: u3, first_prefix: u8) !void {
    const prefix_max: usize = (@as(usize, 1) << prefix_bits) - 1;
    if (value < prefix_max) {
        try out.append(first_prefix | @as(u8, @intCast(value)));
        return;
    }
    try out.append(first_prefix | @as(u8, @intCast(prefix_max)));
    var rem = value - prefix_max;
    while (rem >= 128) {
        try out.append(@as(u8, @intCast(rem % 128 + 128)));
        rem /= 128;
    }
    try out.append(@as(u8, @intCast(rem)));
}

fn encodeString(out: *std.ArrayList(u8), value: []const u8) !void {
    try encodeInteger(out, value.len, 7, 0x00);
    try out.appendSlice(value);
}

fn staticByIndex(index: usize) ?StaticEntry {
    if (index == 0 or index > static_table.len) return null;
    return static_table[index - 1];
}

test "hpack decode indexed and literal headers" {
    const allocator = std.testing.allocator;
    // Indexed :method GET (2), literal new-name "x-test: abc"
    const block = [_]u8{
        0x82,
        0x00,
        0x06,
        'x',
        '-',
        't',
        'e',
        's',
        't',
        0x03,
        'a',
        'b',
        'c',
    };
    var decoded = try decode(allocator, block[0..]);
    defer deinitDecoded(allocator, &decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.headers.len);
    try std.testing.expectEqualStrings(":method", decoded.headers[0].name);
    try std.testing.expectEqualStrings("GET", decoded.headers[0].value);
    try std.testing.expectEqualStrings("x-test", decoded.headers[1].name);
    try std.testing.expectEqualStrings("abc", decoded.headers[1].value);
}

test "hpack encode literal header block" {
    const allocator = std.testing.allocator;
    const headers = [_]HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/json" },
    };
    const encoded = try encodeLiteralHeaderBlock(allocator, headers[0..]);
    defer allocator.free(encoded);
    try std.testing.expect(encoded.len > 0);
}

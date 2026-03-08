const std = @import("std");

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

pub const Encoded = struct {
    data: []u8,
    required_insert_count: u64,
    base: u64,
};

pub fn encodeLiteralHeaderBlock(allocator: std.mem.Allocator, headers: []const HeaderField) !Encoded {
    var out = std.ArrayList(u8).init(allocator);
    errdefer out.deinit();

    // Prefix: Required Insert Count = 0, Delta Base = 0
    try out.append(0x00);
    try out.append(0x00);

    for (headers) |h| {
        // Literal field line with literal name (no dynamic table reference).
        try out.append(0x20);
        try encodeString(&out, h.name);
        try encodeString(&out, h.value);
    }
    return .{
        .data = try out.toOwnedSlice(),
        .required_insert_count = 0,
        .base = 0,
    };
}

pub fn decodeLiteralHeaderBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
    if (block.len < 2) return error.InvalidQpackBlock;
    var i: usize = 2; // skip required insert count / base
    var out = std.ArrayList(HeaderField).init(allocator);
    errdefer {
        for (out.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        out.deinit();
    }
    while (i < block.len) {
        const prefix = block[i];
        if ((prefix & 0xE0) != 0x20) return error.UnsupportedQpackRepresentation;
        i += 1;
        const name = try decodeStringAlloc(allocator, block, &i);
        errdefer allocator.free(name);
        const value = try decodeStringAlloc(allocator, block, &i);
        errdefer allocator.free(value);
        try out.append(.{ .name = name, .value = value });
    }
    return out.toOwnedSlice();
}

pub fn deinitDecoded(allocator: std.mem.Allocator, headers: []HeaderField) void {
    for (headers) |h| {
        allocator.free(h.name);
        allocator.free(h.value);
    }
    allocator.free(headers);
}

fn encodeString(out: *std.ArrayList(u8), value: []const u8) !void {
    if (value.len > 127) return error.QpackStringTooLarge;
    try out.append(@as(u8, @intCast(value.len)));
    try out.appendSlice(value);
}

fn decodeStringAlloc(allocator: std.mem.Allocator, block: []const u8, idx: *usize) ![]u8 {
    if (idx.* >= block.len) return error.InvalidQpackBlock;
    const len = block[idx.*] & 0x7F;
    idx.* += 1;
    if (idx.* + len > block.len) return error.InvalidQpackBlock;
    const out = try allocator.dupe(u8, block[idx.* .. idx.* + len]);
    idx.* += len;
    return out;
}

test "qpack encode/decode literal header block" {
    const allocator = std.testing.allocator;
    const headers = [_]HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "application/json" },
    };
    const encoded = try encodeLiteralHeaderBlock(allocator, headers[0..]);
    defer allocator.free(encoded.data);
    const decoded = try decodeLiteralHeaderBlock(allocator, encoded.data);
    defer deinitDecoded(allocator, decoded);
    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings(":status", decoded[0].name);
    try std.testing.expectEqualStrings("200", decoded[0].value);
}

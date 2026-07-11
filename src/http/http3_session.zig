const std = @import("std");
const Headers = @import("headers.zig").Headers;
const Response = @import("response.zig").Response;

pub const Http3SessionError = error{
    NotYetImplemented,
    InvalidStreamHeaders,
};

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

pub const EncodedHeaderBlock = struct {
    data: []u8,
    required_insert_count: u64,
    base: u64,
};

pub const StreamRequest = struct {
    allocator: std.mem.Allocator,
    method: []u8,
    path: []u8,
    authority: ?[]u8,
    headers: Headers,
    body: []u8,

    pub fn deinit(self: *StreamRequest) void {
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        if (self.authority) |authority| self.allocator.free(authority);
        self.headers.deinit();
        self.allocator.free(self.body);
        self.* = undefined;
    }
};

pub const StreamAssembler = struct {
    allocator: std.mem.Allocator,
    method: ?[]u8 = null,
    path: ?[]u8 = null,
    authority: ?[]u8 = null,
    headers: Headers,
    body: std.ArrayList(u8),

    pub fn init(allocator: std.mem.Allocator) StreamAssembler {
        return .{
            .allocator = allocator,
            .headers = Headers.init(allocator),
            .body = .empty,
        };
    }

    pub fn deinit(self: *StreamAssembler) void {
        if (self.method) |value| self.allocator.free(value);
        if (self.path) |value| self.allocator.free(value);
        if (self.authority) |value| self.allocator.free(value);
        self.headers.deinit();
        self.body.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn appendHeaderBlock(self: *StreamAssembler, fields: []const HeaderField) !void {
        for (fields) |field| {
            if (std.mem.eql(u8, field.name, ":method")) {
                try replaceOwnedString(self.allocator, &self.method, field.value);
                continue;
            }
            if (std.mem.eql(u8, field.name, ":path")) {
                try replaceOwnedString(self.allocator, &self.path, field.value);
                continue;
            }
            if (std.mem.eql(u8, field.name, ":authority")) {
                try replaceOwnedString(self.allocator, &self.authority, field.value);
                continue;
            }
            if (field.name.len > 0 and field.name[0] == ':') continue;
            try self.headers.append(field.name, field.value);
        }
    }

    pub fn appendBody(self: *StreamAssembler, chunk: []const u8) !void {
        try self.body.appendSlice(self.allocator, chunk);
    }

    pub fn finish(self: *StreamAssembler) !StreamRequest {
        const method = self.method orelse return error.InvalidStreamHeaders;
        const path = self.path orelse return error.InvalidStreamHeaders;

        var headers = Headers.init(self.allocator);
        errdefer headers.deinit();
        for (self.headers.iterator()) |header| {
            try headers.append(header.name, header.value);
        }
        if (self.authority) |authority| {
            if (headers.get("host") == null) try headers.append("Host", authority);
        }

        return .{
            .allocator = self.allocator,
            .method = try self.allocator.dupe(u8, method),
            .path = try self.allocator.dupe(u8, path),
            .authority = if (self.authority) |authority| try self.allocator.dupe(u8, authority) else null,
            .headers = headers,
            .body = try self.body.toOwnedSlice(self.allocator),
        };
    }
};

/// Returns true for HTTP methods that are safe (no observable side effects) and
/// therefore eligible to be replayed as 0-RTT early data without replay risk.
/// POST, PUT, PATCH, DELETE, and CONNECT are considered unsafe and must not be
/// served from early data when 0-RTT is enabled.
pub fn isMethodSafe(method: []const u8) bool {
    return std.mem.eql(u8, method, "GET") or
        std.mem.eql(u8, method, "HEAD") or
        std.mem.eql(u8, method, "OPTIONS") or
        std.mem.eql(u8, method, "TRACE");
}

pub fn encodeResponseHeaderBlock(allocator: std.mem.Allocator, response: *const Response) !EncodedHeaderBlock {
    var fields = std.ArrayList(HeaderField).empty;
    defer fields.deinit(allocator);

    var status_buf: [3]u8 = undefined;
    const status_text = try std.fmt.bufPrint(&status_buf, "{d}", .{response.status.code()});
    try fields.append(allocator, .{ .name = ":status", .value = status_text });
    for (response.headers.iterator()) |header| {
        try fields.append(allocator, .{ .name = header.name, .value = header.value });
    }
    return encodeLiteralHeaderBlock(allocator, fields.items);
}

fn replaceOwnedString(allocator: std.mem.Allocator, slot: *?[]u8, value: []const u8) !void {
    if (slot.*) |existing| allocator.free(existing);
    slot.* = try allocator.dupe(u8, value);
}

fn appendH3Frame(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frame_type: u8, payload: []const u8) !void {
    try appendQuicVarInt(allocator, out, frame_type);
    try appendQuicVarInt(allocator, out, payload.len);
    try out.appendSlice(allocator, payload);
}

fn appendQuicVarInt(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: usize) !void {
    if (value < 64) {
        try out.append(allocator, @intCast(value));
        return;
    }
    if (value < 16_384) {
        const encoded: u16 = @intCast(0x4000 | value);
        try out.append(allocator, @intCast(encoded >> 8));
        try out.append(allocator, @intCast(encoded & 0xff));
        return;
    }
    return error.NotYetImplemented;
}

pub fn encodeLiteralHeaderBlock(allocator: std.mem.Allocator, headers: []const HeaderField) !EncodedHeaderBlock {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.append(allocator, 0x00);
    try out.append(allocator, 0x00);

    for (headers) |h| {
        try out.append(allocator, 0x20);
        try encodeHeaderString(allocator, &out, h.name);
        try encodeHeaderString(allocator, &out, h.value);
    }
    return .{
        .data = try out.toOwnedSlice(allocator),
        .required_insert_count = 0,
        .base = 0,
    };
}

pub fn decodeLiteralHeaderBlock(allocator: std.mem.Allocator, block: []const u8) ![]HeaderField {
    if (block.len < 2) return error.InvalidQpackBlock;
    var i: usize = 2;
    var out = std.ArrayList(HeaderField).empty;
    errdefer {
        for (out.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        out.deinit(allocator);
    }
    while (i < block.len) {
        const prefix = block[i];
        if ((prefix & 0xE0) != 0x20) return error.UnsupportedQpackRepresentation;
        i += 1;
        const name = try decodeHeaderStringAlloc(allocator, block, &i);
        errdefer allocator.free(name);
        const value = try decodeHeaderStringAlloc(allocator, block, &i);
        errdefer allocator.free(value);
        try out.append(allocator, .{ .name = name, .value = value });
    }
    return out.toOwnedSlice(allocator);
}

pub fn deinitDecodedHeaderBlock(allocator: std.mem.Allocator, headers: []HeaderField) void {
    for (headers) |h| {
        allocator.free(h.name);
        allocator.free(h.value);
    }
    allocator.free(headers);
}

fn encodeHeaderString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    if (value.len > 127) return error.QpackStringTooLarge;
    try out.append(allocator, @as(u8, @intCast(value.len)));
    try out.appendSlice(allocator, value);
}

fn decodeHeaderStringAlloc(allocator: std.mem.Allocator, block: []const u8, idx: *usize) ![]u8 {
    if (idx.* >= block.len) return error.InvalidQpackBlock;
    const len = block[idx.*] & 0x7F;
    idx.* += 1;
    if (idx.* + len > block.len) return error.InvalidQpackBlock;
    const out = try allocator.dupe(u8, block[idx.* .. idx.* + len]);
    idx.* += len;
    return out;
}

test "http3 stream assembler builds request parts from split header and body frames" {
    const allocator = std.testing.allocator;
    var assembler = StreamAssembler.init(allocator);
    defer assembler.deinit();

    try assembler.appendHeaderBlock(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/api/messages?mode=test" },
    });
    try assembler.appendHeaderBlock(&.{
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "content-type", .value = "application/json" },
    });
    try assembler.appendBody("{\"hello\":");
    try assembler.appendBody("\"world\"}");

    var request = try assembler.finish();
    defer request.deinit();

    try std.testing.expectEqualStrings("POST", request.method);
    try std.testing.expectEqualStrings("/api/messages?mode=test", request.path);
    try std.testing.expectEqualStrings("example.com", request.authority.?);
    try std.testing.expectEqualStrings("example.com", request.headers.get("Host").?);
    try std.testing.expectEqualStrings("application/json", request.headers.get("content-type").?);
    try std.testing.expectEqualStrings("{\"hello\":\"world\"}", request.body);
}

test "http3 response header encoding includes status pseudo header" {
    const allocator = std.testing.allocator;
    var response = Response.init(allocator);
    defer response.deinit();
    _ = response.setStatus(.accepted).setHeader("content-type", "application/json");

    const encoded = try encodeResponseHeaderBlock(allocator, &response);
    defer allocator.free(encoded.data);
    const decoded = try decodeLiteralHeaderBlock(allocator, encoded.data);
    defer deinitDecodedHeaderBlock(allocator, decoded);

    try std.testing.expectEqual(@as(usize, 2), decoded.len);
    try std.testing.expectEqualStrings(":status", decoded[0].name);
    try std.testing.expectEqualStrings("202", decoded[0].value);
    try std.testing.expectEqualStrings("content-type", decoded[1].name);
}

test "isMethodSafe identifies safe versus unsafe HTTP methods" {
    // Safe (idempotent and side-effect-free) methods should be accepted as 0-RTT.
    try std.testing.expect(isMethodSafe("GET"));
    try std.testing.expect(isMethodSafe("HEAD"));
    try std.testing.expect(isMethodSafe("OPTIONS"));
    try std.testing.expect(isMethodSafe("TRACE"));
    // Unsafe methods must not be replayed as 0-RTT early data.
    try std.testing.expect(!isMethodSafe("POST"));
    try std.testing.expect(!isMethodSafe("PUT"));
    try std.testing.expect(!isMethodSafe("PATCH"));
    try std.testing.expect(!isMethodSafe("DELETE"));
    try std.testing.expect(!isMethodSafe("CONNECT"));
    try std.testing.expect(!isMethodSafe(""));
}

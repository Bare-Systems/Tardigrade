const std = @import("std");
const huffman = @import("hpack_huffman");

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

const DYNAMIC_TABLE_ENTRY_OVERHEAD: usize = 32;

/// HPACK dynamic table per RFC 7541 §2.3.2.
///
/// Entries are stored oldest-first: index 0 holds the oldest entry and the
/// last element holds the most recently inserted. HPACK dynamic index 0
/// (absolute index 62) therefore maps to the last element. Each insert
/// evicts the oldest entries as needed to stay within `max_size`. Max size
/// is 4 096 bytes by default and may be reduced by a table-size update
/// instruction in the header block.
pub const DynamicTable = struct {
    entries: std.Deque(HeaderField),
    size: usize,
    max_size: usize,

    pub fn init() DynamicTable {
        return .{ .entries = .empty, .size = 0, .max_size = 4096 };
    }

    pub fn deinit(self: *DynamicTable, allocator: std.mem.Allocator) void {
        var it = self.entries.iterator();
        while (it.next()) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        self.entries.deinit(allocator);
        self.* = undefined;
    }

    pub fn insert(self: *DynamicTable, allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
        const cost = name.len + value.len + DYNAMIC_TABLE_ENTRY_OVERHEAD;
        if (cost > self.max_size) {
            self.evictAll(allocator);
            return;
        }
        while (self.size + cost > self.max_size) self.evictOldest(allocator);
        const name_copy = try allocator.dupe(u8, name);
        errdefer allocator.free(name_copy);
        const value_copy = try allocator.dupe(u8, value);
        errdefer allocator.free(value_copy);
        try self.entries.pushBack(allocator, .{ .name = name_copy, .value = value_copy });
        self.size += cost;
    }

    pub fn setMaxSize(self: *DynamicTable, allocator: std.mem.Allocator, new_max: usize) void {
        self.max_size = new_max;
        while (self.size > self.max_size) self.evictOldest(allocator);
    }

    /// dyn_idx 0 = most recently inserted (last element in oldest-first storage).
    pub fn getByDynIndex(self: *const DynamicTable, dyn_idx: usize) ?StaticEntry {
        if (dyn_idx >= self.entries.len) return null;
        const actual = self.entries.len - 1 - dyn_idx;
        const h = self.entries.at(actual);
        return .{ .name = h.name, .value = h.value };
    }

    fn evictOldest(self: *DynamicTable, allocator: std.mem.Allocator) void {
        const oldest = self.entries.popFront() orelse return;
        self.size -= oldest.name.len + oldest.value.len + DYNAMIC_TABLE_ENTRY_OVERHEAD;
        allocator.free(oldest.name);
        allocator.free(oldest.value);
    }

    fn evictAll(self: *DynamicTable, allocator: std.mem.Allocator) void {
        while (self.entries.popFront()) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        self.size = 0;
    }
};

/// Stateful HPACK decoder.
///
/// Maintains the dynamic table across decode calls so that incremental
/// indexing accumulates correctly over the lifetime of an HTTP/2
/// connection. One Decoder per connection direction (one for requests,
/// one for responses if acting as a client).
pub const Decoder = struct {
    dynamic: DynamicTable,

    pub fn init() Decoder {
        return .{ .dynamic = DynamicTable.init() };
    }

    pub fn deinit(self: *Decoder, allocator: std.mem.Allocator) void {
        self.dynamic.deinit(allocator);
    }

    pub fn decode(self: *Decoder, allocator: std.mem.Allocator, block: []const u8) !DecodeResult {
        return decodeWithTable(allocator, block, &self.dynamic);
    }
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

/// Decode an HPACK header block without maintaining a dynamic table.
/// Suitable for one-shot decoding and tests; does not persist state
/// across calls. Use `Decoder` for per-connection stateful decoding.
pub fn decode(allocator: std.mem.Allocator, block: []const u8) !DecodeResult {
    return decodeWithTable(allocator, block, null);
}

/// Decode an HPACK header block using an optional dynamic table.
/// When `dyn` is non-null, table-size updates and incremental indexing
/// are applied to the table so state is preserved across calls.
fn decodeWithTable(allocator: std.mem.Allocator, block: []const u8, dyn: ?*DynamicTable) !DecodeResult {
    var out = std.ArrayList(HeaderField).empty;
    errdefer {
        for (out.items) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        out.deinit(allocator);
    }

    var i: usize = 0;
    while (i < block.len) {
        const b = block[i];

        if ((b & 0x80) != 0) {
            // Indexed header field (RFC 7541 §6.1): reference to static or dynamic table.
            const indexed = try decodeInteger(block, &i, 7);
            const entry = entryByIndex(indexed, dyn) orelse return error.InvalidHpackIndex;
            try out.append(allocator, .{
                .name = try allocator.dupe(u8, entry.name),
                .value = try allocator.dupe(u8, entry.value),
            });
            continue;
        }

        if ((b & 0xE0) == 0x20) {
            // Dynamic table size update (RFC 7541 §6.3).
            const new_max = try decodeInteger(block, &i, 5);
            if (dyn) |d| d.setMaxSize(allocator, new_max);
            continue;
        }

        if ((b & 0xC0) == 0x40) {
            // Literal with incremental indexing (RFC 7541 §6.2.1): add to dynamic table.
            const name_index = try decodeInteger(block, &i, 6);
            const name = if (name_index == 0)
                try decodeStringAlloc(allocator, block, &i)
            else blk: {
                const entry = entryByIndex(name_index, dyn) orelse return error.InvalidHpackIndex;
                break :blk try allocator.dupe(u8, entry.name);
            };
            errdefer allocator.free(name);
            const value = try decodeStringAlloc(allocator, block, &i);
            errdefer allocator.free(value);
            if (dyn) |d| try d.insert(allocator, name, value);
            try out.append(allocator, .{ .name = name, .value = value });
            continue;
        }

        if ((b & 0xF0) == 0x00 or (b & 0xF0) == 0x10) {
            // Literal without indexing (0x00) or never indexed (0x10) — RFC 7541 §6.2.2/6.2.3.
            // Do not add to dynamic table.
            const name_index = try decodeInteger(block, &i, 4);
            const name = if (name_index == 0)
                try decodeStringAlloc(allocator, block, &i)
            else blk: {
                const entry = entryByIndex(name_index, dyn) orelse return error.InvalidHpackIndex;
                break :blk try allocator.dupe(u8, entry.name);
            };
            errdefer allocator.free(name);
            const value = try decodeStringAlloc(allocator, block, &i);
            errdefer allocator.free(value);
            try out.append(allocator, .{ .name = name, .value = value });
            continue;
        }

        return error.UnsupportedHpackRepresentation;
    }
    return .{ .headers = try out.toOwnedSlice(allocator) };
}

/// Look up an HPACK index across the static table and optional dynamic table.
/// Index 1..61 are static; 62+ are dynamic (newest first).
fn entryByIndex(index: usize, dyn: ?*DynamicTable) ?StaticEntry {
    if (index == 0) return null;
    if (index <= static_table.len) return static_table[index - 1];
    if (dyn == null) return null;
    return dyn.?.getByDynIndex(index - static_table.len - 1);
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
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    for (headers) |h| {
        try out.append(allocator, 0x00);
        try encodeString(allocator, &out, h.name);
        try encodeString(allocator, &out, h.value);
    }
    return out.toOwnedSlice(allocator);
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
    const is_huffman = (buf[idx.*] & 0x80) != 0;
    const len = try decodeInteger(buf, idx, 7);
    if (idx.* + len > buf.len) return error.TruncatedHpack;
    const raw = buf[idx.* .. idx.* + len];
    idx.* += len;
    if (is_huffman) return huffman.decodeAlloc(allocator, raw);
    return allocator.dupe(u8, raw);
}

fn encodeInteger(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: usize, prefix_bits: u3, first_prefix: u8) !void {
    const prefix_max: usize = (@as(usize, 1) << prefix_bits) - 1;
    if (value < prefix_max) {
        try out.append(allocator, first_prefix | @as(u8, @intCast(value)));
        return;
    }
    try out.append(allocator, first_prefix | @as(u8, @intCast(prefix_max)));
    var rem = value - prefix_max;
    while (rem >= 128) {
        try out.append(allocator, @as(u8, @intCast(rem % 128 + 128)));
        rem /= 128;
    }
    try out.append(allocator, @as(u8, @intCast(rem)));
}

fn encodeString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    try encodeInteger(allocator, out, value.len, 7, 0x00);
    try out.appendSlice(allocator, value);
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

test "DynamicTable insert and lookup by dyn index" {
    const allocator = std.testing.allocator;
    var table = DynamicTable.init();
    defer table.deinit(allocator);

    try table.insert(allocator, "x-custom", "value1");
    try table.insert(allocator, "x-other", "value2");

    // Most recently inserted is at dyn index 0.
    const newest = table.getByDynIndex(0).?;
    try std.testing.expectEqualStrings("x-other", newest.name);
    try std.testing.expectEqualStrings("value2", newest.value);

    const older = table.getByDynIndex(1).?;
    try std.testing.expectEqualStrings("x-custom", older.name);
    try std.testing.expectEqualStrings("value1", older.value);

    try std.testing.expect(table.getByDynIndex(2) == null);
}

test "DynamicTable evicts oldest entries to stay within max_size" {
    const allocator = std.testing.allocator;
    var table = DynamicTable.init();
    defer table.deinit(allocator);

    // Each entry costs name.len + value.len + 32.
    // Set a small max so the second insert evicts the first.
    const name = "a";
    const val = "b";
    const entry_cost = name.len + val.len + DYNAMIC_TABLE_ENTRY_OVERHEAD;
    table.setMaxSize(allocator, entry_cost); // room for exactly one entry

    try table.insert(allocator, name, val);
    try std.testing.expectEqual(@as(usize, 1), table.entries.len);

    try table.insert(allocator, "c", "d");
    try std.testing.expectEqual(@as(usize, 1), table.entries.len);
    const e = table.getByDynIndex(0).?;
    try std.testing.expectEqualStrings("c", e.name);
}

test "DynamicTable setMaxSize zero evicts everything" {
    const allocator = std.testing.allocator;
    var table = DynamicTable.init();
    defer table.deinit(allocator);

    try table.insert(allocator, "key", "val");
    try std.testing.expectEqual(@as(usize, 1), table.entries.len);

    table.setMaxSize(allocator, 0);
    try std.testing.expectEqual(@as(usize, 0), table.entries.len);
    try std.testing.expectEqual(@as(usize, 0), table.size);
}

test "Decoder accumulates dynamic table across calls" {
    const allocator = std.testing.allocator;
    var dec = Decoder.init();
    defer dec.deinit(allocator);

    // First call: literal with incremental indexing (0x40 prefix, name index 0).
    // Encodes: name="x-hdr", value="hello"
    const block1 = [_]u8{
        0x40, // literal + incremental indexing, name follows
        0x05,
        'x',
        '-',
        'h',
        'd',
        'r',
        0x05,
        'h',
        'e',
        'l',
        'l',
        'o',
    };
    var r1 = try dec.decode(allocator, block1[0..]);
    defer deinitDecoded(allocator, &r1);
    try std.testing.expectEqual(@as(usize, 1), r1.headers.len);
    try std.testing.expectEqualStrings("x-hdr", r1.headers[0].name);

    // Second call: reference dynamic table entry (index 62 = first dynamic).
    const block2 = [_]u8{0x80 | 62}; // indexed representation, index 62
    var r2 = try dec.decode(allocator, block2[0..]);
    defer deinitDecoded(allocator, &r2);
    try std.testing.expectEqual(@as(usize, 1), r2.headers.len);
    try std.testing.expectEqualStrings("x-hdr", r2.headers[0].name);
    try std.testing.expectEqualStrings("hello", r2.headers[0].value);
}

test "fuzz: decode never panics on arbitrary HPACK header blocks" {
    try std.testing.fuzz({}, fuzzHpackDecode, .{
        .corpus = &.{
            "\x82", // indexed: :method GET (static index 2)
            "\x82\x86\x84", // :method GET + :scheme http + :path /
            "\x82\x86\x84\x41\x0f\x77\x77\x77\x2e\x65\x78\x61\x6d\x70" ++ // RFC 7541 §C.3.1 first request
                "\x6c\x65\x2e\x63\x6f\x6d",
            "",
        },
    });
}

fn fuzzHpackDecode(_: void, smith: *std.testing.Smith) !void {
    const allocator = std.testing.allocator;
    var buf: [512]u8 = undefined;
    const len = smith.slice(&buf);
    var result = decode(allocator, buf[0..len]) catch return;
    deinitDecoded(allocator, &result);
}

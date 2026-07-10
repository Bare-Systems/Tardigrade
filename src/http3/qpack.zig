//! QPACK header compression (#252/#253, RFC 9204).
//!
//! Encodes/decodes the HEADERS payloads carried by `frame.zig` for the first
//! pure Zig HTTP/3 path. The simple `encode`/`decode` functions remain
//! static-table-only safe fallbacks. `DynamicTable`, `EncoderStream`, and
//! `DynamicDecoder` add bounded dynamic-table support, encoder/decoder stream
//! accounting, and blocked-stream handling for peers that negotiate non-zero
//! QPACK settings.

const std = @import("std");
const http3_frame = @import("frame.zig");
const huffman = @import("hpack_huffman");

/// A decoded or to-be-encoded header field. Slices borrow their backing storage
/// (the static table, the input block, or a caller scratch buffer) and stay
/// valid only as long as that storage does.
pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

// ---------------------------------------------------------------------------
// Static table (RFC 9204 Appendix A)
// ---------------------------------------------------------------------------

pub const static_table = [_]HeaderField{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":path", .value = "/" },
    .{ .name = "age", .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length", .value = "0" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = ":method", .value = "CONNECT" },
    .{ .name = ":method", .value = "DELETE" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "HEAD" },
    .{ .name = ":method", .value = "OPTIONS" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":method", .value = "PUT" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "103" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "503" },
    .{ .name = "accept", .value = "*/*" },
    .{ .name = "accept", .value = "application/dns-message" },
    .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges", .value = "bytes" },
    .{ .name = "access-control-allow-headers", .value = "cache-control" },
    .{ .name = "access-control-allow-headers", .value = "content-type" },
    .{ .name = "access-control-allow-origin", .value = "*" },
    .{ .name = "cache-control", .value = "max-age=0" },
    .{ .name = "cache-control", .value = "max-age=2592000" },
    .{ .name = "cache-control", .value = "max-age=604800" },
    .{ .name = "cache-control", .value = "no-cache" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cache-control", .value = "public, max-age=31536000" },
    .{ .name = "content-encoding", .value = "br" },
    .{ .name = "content-encoding", .value = "gzip" },
    .{ .name = "content-type", .value = "application/dns-message" },
    .{ .name = "content-type", .value = "application/javascript" },
    .{ .name = "content-type", .value = "application/json" },
    .{ .name = "content-type", .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type", .value = "image/gif" },
    .{ .name = "content-type", .value = "image/jpeg" },
    .{ .name = "content-type", .value = "image/png" },
    .{ .name = "content-type", .value = "text/css" },
    .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    .{ .name = "content-type", .value = "text/plain" },
    .{ .name = "content-type", .value = "text/plain;charset=utf-8" },
    .{ .name = "range", .value = "bytes=0-" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    .{ .name = "vary", .value = "accept-encoding" },
    .{ .name = "vary", .value = "origin" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection", .value = "1; mode=block" },
    .{ .name = ":status", .value = "100" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "302" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "403" },
    .{ .name = ":status", .value = "421" },
    .{ .name = ":status", .value = "425" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers", .value = "*" },
    .{ .name = "access-control-allow-methods", .value = "get" },
    .{ .name = "access-control-allow-methods", .value = "get, post, options" },
    .{ .name = "access-control-allow-methods", .value = "options" },
    .{ .name = "access-control-expose-headers", .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method", .value = "get" },
    .{ .name = "access-control-request-method", .value = "post" },
    .{ .name = "alt-svc", .value = "clear" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data", .value = "1" },
    .{ .name = "expect-ct", .value = "" },
    .{ .name = "forwarded", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "origin", .value = "" },
    .{ .name = "purpose", .value = "prefetch" },
    .{ .name = "server", .value = "" },
    .{ .name = "timing-allow-origin", .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "x-forwarded-for", .value = "" },
    .{ .name = "x-frame-options", .value = "deny" },
    .{ .name = "x-frame-options", .value = "sameorigin" },
};

pub const static_table_len = static_table.len;

/// Look up a static entry by index (RFC 9204 §3.1). Returns null for an
/// out-of-range index.
pub fn staticEntry(index: usize) ?HeaderField {
    if (index >= static_table_len) return null;
    return static_table[index];
}

/// Find the static index whose name and value both match, else the first index
/// whose name matches (name-only), else null.
fn findStatic(name: []const u8, value: []const u8) struct { name_value: ?usize, name_only: ?usize } {
    var name_only: ?usize = null;
    for (static_table, 0..) |entry, index| {
        if (std.mem.eql(u8, entry.name, name)) {
            if (std.mem.eql(u8, entry.value, value)) return .{ .name_value = index, .name_only = index };
            if (name_only == null) name_only = index;
        }
    }
    return .{ .name_value = null, .name_only = name_only };
}

// ---------------------------------------------------------------------------
// Prefix integers (RFC 7541 §5.1, reused by QPACK)
// ---------------------------------------------------------------------------

const IntError = error{ TruncatedBlock, IntegerOverflow };

/// Decode an `n`-bit prefix integer starting at `bytes[0]`. Returns the value
/// and the number of bytes consumed. `n` is 1..8.
fn decodeInteger(bytes: []const u8, n: u4) IntError!struct { value: u64, len: usize } {
    if (bytes.len == 0) return error.TruncatedBlock;
    const prefix_max: u64 = (@as(u64, 1) << n) - 1;
    var value: u64 = bytes[0] & @as(u8, @intCast(prefix_max));
    if (value < prefix_max) return .{ .value = value, .len = 1 };

    var index: usize = 1;
    var shift: u6 = 0;
    while (true) {
        if (index >= bytes.len) return error.TruncatedBlock;
        const byte = bytes[index];
        index += 1;
        // Guard the 7-bit continuation shift against overflowing u64.
        if (shift >= 63 and (byte & 0x7f) > 1) return error.IntegerOverflow;
        const addend = @as(u64, byte & 0x7f);
        value = std.math.add(u64, value, std.math.shl(u64, addend, shift)) catch return error.IntegerOverflow;
        if (byte & 0x80 == 0) break;
        if (shift > 56) return error.IntegerOverflow;
        shift += 7;
    }
    return .{ .value = value, .len = index };
}

/// Encode `value` as an `n`-bit prefix integer, OR-ing `high_bits` into the
/// first byte's top `8-n` bits. Returns the number of bytes written.
fn encodeInteger(value: u64, n: u4, high_bits: u8, out: []u8) error{OutputOverflow}!usize {
    const prefix_max: u64 = (@as(u64, 1) << n) - 1;
    if (out.len == 0) return error.OutputOverflow;
    if (value < prefix_max) {
        out[0] = high_bits | @as(u8, @intCast(value));
        return 1;
    }
    out[0] = high_bits | @as(u8, @intCast(prefix_max));
    var remaining = value - prefix_max;
    var index: usize = 1;
    while (remaining >= 128) {
        if (index >= out.len) return error.OutputOverflow;
        out[index] = @as(u8, @intCast(remaining & 0x7f)) | 0x80;
        index += 1;
        remaining >>= 7;
    }
    if (index >= out.len) return error.OutputOverflow;
    out[index] = @as(u8, @intCast(remaining));
    return index + 1;
}

// ---------------------------------------------------------------------------
// Encoder
// ---------------------------------------------------------------------------

pub const EncodeError = error{OutputOverflow};

/// Encode `fields` as a QPACK encoded field section into `out` (static-only:
/// Required Insert Count 0, Base 0). Returns the written slice.
pub fn encode(fields: []const HeaderField, out: []u8) EncodeError![]u8 {
    var pos: usize = 0;
    // Encoded Field Section Prefix: Required Insert Count = 0, Delta Base = 0.
    pos += try writeAll(out, pos, &.{ 0x00, 0x00 });

    for (fields) |field| {
        const match = findStatic(field.name, field.value);
        if (match.name_value) |index| {
            // Indexed Field Line, static (1 T=1 + 6-bit index).
            pos += try encodeInto(out, pos, index, 6, 0xc0);
        } else if (match.name_only) |index| {
            // Literal Field Line With Name Reference, static (01 N=0 T=1 + 4-bit index).
            pos += try encodeInto(out, pos, index, 4, 0x50);
            pos += try encodeString(field.value, out, pos);
        } else {
            // Literal Field Line With Literal Name (001 N=0 H + 3-bit name len).
            pos += try encodeStringWithPrefix(field.name, 3, 0x20, out, pos);
            pos += try encodeString(field.value, out, pos);
        }
    }
    return out[0..pos];
}

fn encodeInto(out: []u8, pos: usize, value: u64, n: u4, high_bits: u8) EncodeError!usize {
    return encodeInteger(value, n, high_bits, out[pos..]);
}

/// Encode a string literal using Huffman coding when it is smaller than raw.
fn encodeString(bytes: []const u8, out: []u8, pos: usize) EncodeError!usize {
    return encodeStringWithPrefix(bytes, 7, 0x00, out, pos);
}

fn encodeStringWithPrefix(bytes: []const u8, n: u4, high_bits: u8, out: []u8, pos: usize) EncodeError!usize {
    const huffman_len = huffman.encodedLen(bytes);
    if (huffman_len < bytes.len) {
        var written = try encodeInteger(huffman_len, n, high_bits | (@as(u8, 1) << @intCast(n)), out[pos..]);
        written += try huffman.encode(bytes, out[pos + written ..]);
        return written;
    }

    var written = try encodeInteger(bytes.len, n, high_bits, out[pos..]);
    written += try writeAll(out, pos + written, bytes);
    return written;
}

fn writeAll(out: []u8, pos: usize, bytes: []const u8) EncodeError!usize {
    if (bytes.len > out.len - pos) return error.OutputOverflow;
    @memcpy(out[pos..][0..bytes.len], bytes);
    return bytes.len;
}

// ---------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    /// Field-line representation refers to an out-of-range static index.
    InvalidStaticIndex,
    /// A dynamic-table reference appeared; forbidden in static-only mode.
    DynamicTableReference,
    /// Required Insert Count was non-zero; impossible with an empty dynamic table.
    InvalidRequiredInsertCount,
    /// Base was non-zero; impossible in static-only mode.
    InvalidBase,
    /// The block ended in the middle of a representation.
    TruncatedBlock,
    /// A prefix integer overflowed u64.
    IntegerOverflow,
    /// A dynamic-table reference points below the eviction frontier.
    InvalidDynamicIndex,
    /// Decoding needs encoder-stream instructions that have not arrived yet.
    Blocked,
    /// A new blocked stream would exceed SETTINGS_QPACK_BLOCKED_STREAMS.
    BlockedStreamLimitExceeded,
    /// Dynamic table capacity would be exceeded by a single entry.
    EntryTooLarge,
    /// Encoder/decoder stream instruction was malformed.
    MalformedInstruction,
    /// A peer tried to grow the dynamic table above the negotiated maximum.
    CapacityExceeded,
    /// A Huffman-coded string was malformed.
    InvalidHuffmanCode,
    /// Caller scratch storage was too small for decoded Huffman strings.
    ScratchOverflow,
    /// More header fields than the caller-provided output can hold.
    TooManyFields,
    /// Allocator failed while owning dynamic table/header data.
    OutOfMemory,
};

/// Decode a QPACK encoded field section into `fields_out`, returning the number
/// of fields. Decoded name/value slices borrow the static table or the input
/// `block` or `scratch`; no allocation is performed and no dynamic/blocked
/// state exists.
pub fn decode(block: []const u8, fields_out: []HeaderField, scratch: []u8) DecodeError!usize {
    var pos: usize = 0;
    var scratch_pos: usize = 0;

    // Encoded Field Section Prefix. Static-only: RIC and Base must both be 0.
    const ric = try decodeInteger(block[pos..], 8);
    if (ric.value != 0) return error.InvalidRequiredInsertCount;
    pos += ric.len;
    if (pos >= block.len) return error.TruncatedBlock;
    if (block[pos] & 0x80 != 0) return error.InvalidBase;
    const base = try decodeInteger(block[pos..], 7);
    if (base.value != 0) return error.InvalidBase;
    pos += base.len;

    var count: usize = 0;
    while (pos < block.len) {
        if (count >= fields_out.len) return error.TooManyFields;
        const first = block[pos];
        if (first & 0x80 != 0) {
            // Indexed Field Line (1 T ......).
            if (first & 0x40 == 0) return error.DynamicTableReference;
            const int = try decodeInteger(block[pos..], 6);
            pos += int.len;
            fields_out[count] = staticEntry(@intCast(int.value)) orelse return error.InvalidStaticIndex;
        } else if (first & 0xc0 == 0x40) {
            // Literal Field Line With Name Reference (01 N T ....).
            if (first & 0x10 == 0) return error.DynamicTableReference;
            const int = try decodeInteger(block[pos..], 4);
            pos += int.len;
            const entry = staticEntry(@intCast(int.value)) orelse return error.InvalidStaticIndex;
            const value = try decodeString(block, &pos, scratch, &scratch_pos);
            fields_out[count] = .{ .name = entry.name, .value = value };
        } else if (first & 0xe0 == 0x20) {
            // Literal Field Line With Literal Name (001 N H ...).
            const is_huffman = first & 0x08 != 0;
            const name_len = try decodeInteger(block[pos..], 3);
            pos += name_len.len;
            const name_bytes = try readBytes(block, &pos, @intCast(name_len.value));
            const name = if (is_huffman) try decodeHuffman(name_bytes, scratch, &scratch_pos) else name_bytes;
            const value = try decodeString(block, &pos, scratch, &scratch_pos);
            fields_out[count] = .{ .name = name, .value = value };
        } else {
            // 0001.... post-base indexed, 0000.... post-base name ref: dynamic.
            return error.DynamicTableReference;
        }
        count += 1;
    }
    return count;
}

/// Decode a string literal at `block[pos.*]`, advancing `pos`.
fn decodeString(block: []const u8, pos: *usize, scratch: []u8, scratch_pos: *usize) DecodeError![]const u8 {
    if (pos.* >= block.len) return error.TruncatedBlock;
    const is_huffman = block[pos.*] & 0x80 != 0;
    const len = try decodeInteger(block[pos.*..], 7);
    pos.* += len.len;
    const bytes = try readBytes(block, pos, @intCast(len.value));
    return if (is_huffman) try decodeHuffman(bytes, scratch, scratch_pos) else bytes;
}

fn decodeHuffman(bytes: []const u8, scratch: []u8, scratch_pos: *usize) DecodeError![]const u8 {
    const written = huffman.decode(bytes, scratch[scratch_pos.*..]) catch |err| switch (err) {
        error.InvalidHuffmanCode => return error.InvalidHuffmanCode,
        error.OutputOverflow => return error.ScratchOverflow,
    };
    const decoded = scratch[scratch_pos.*..][0..written];
    scratch_pos.* += written;
    return decoded;
}

fn readBytes(block: []const u8, pos: *usize, len: usize) DecodeError![]const u8 {
    if (len > block.len - pos.*) return error.TruncatedBlock;
    const bytes = block[pos.*..][0..len];
    pos.* += len;
    return bytes;
}

// ---------------------------------------------------------------------------
// Dynamic table and streams (#253)
// ---------------------------------------------------------------------------

pub const DynamicEntry = struct {
    absolute_index: u64,
    name: []u8,
    value: []u8,

    pub fn size(self: DynamicEntry) u64 {
        const with_name = std.math.add(u64, 32, self.name.len) catch return std.math.maxInt(u64);
        return std.math.add(u64, with_name, self.value.len) catch return std.math.maxInt(u64);
    }

    fn field(self: DynamicEntry) HeaderField {
        return .{ .name = self.name, .value = self.value };
    }

    fn deinit(self: DynamicEntry, allocator: std.mem.Allocator) void {
        allocator.free(self.name);
        allocator.free(self.value);
    }
};

pub const DynamicMetrics = struct {
    insertions: u64 = 0,
    evictions: u64 = 0,
    blocked_streams: u64 = 0,
    unblocked_streams: u64 = 0,
    cancelled_streams: u64 = 0,
    table_bytes: u64 = 0,
    decode_failures: u64 = 0,
};

pub const DynamicSettings = struct {
    max_table_capacity: u64 = 0,
    blocked_streams: u64 = 0,

    pub fn fromHttp3(settings: http3_frame.Settings) DynamicSettings {
        return .{
            .max_table_capacity = settings.qpack_max_table_capacity,
            .blocked_streams = settings.qpack_blocked_streams,
        };
    }

    pub fn initTable(self: DynamicSettings, allocator: std.mem.Allocator) DynamicTable {
        return DynamicTable.initNegotiated(allocator, self.max_table_capacity);
    }

    pub fn initDecoder(self: DynamicSettings, allocator: std.mem.Allocator, table: *DynamicTable) DynamicDecoder {
        return DynamicDecoder.init(allocator, table, self.blocked_streams);
    }
};

pub const DynamicTable = struct {
    allocator: std.mem.Allocator,
    max_capacity: u64,
    capacity: u64,
    entries: std.ArrayList(DynamicEntry) = .empty,
    bytes_used: u64 = 0,
    inserted_count: u64 = 0,
    evicted_count: u64 = 0,
    metrics: DynamicMetrics = .{},

    pub fn init(allocator: std.mem.Allocator, capacity: u64) DynamicTable {
        return .{ .allocator = allocator, .max_capacity = capacity, .capacity = capacity };
    }

    pub fn initNegotiated(allocator: std.mem.Allocator, max_capacity: u64) DynamicTable {
        return .{ .allocator = allocator, .max_capacity = max_capacity, .capacity = 0 };
    }

    pub fn deinit(self: *DynamicTable) void {
        for (self.entries.items) |entry| entry.deinit(self.allocator);
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn setCapacity(self: *DynamicTable, capacity: u64) !void {
        if (capacity > self.max_capacity) return error.CapacityExceeded;
        self.capacity = capacity;
        try self.evictToCapacity();
    }

    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) !u64 {
        const name_size = std.math.add(u64, 32, name.len) catch return error.IntegerOverflow;
        const entry_size = std.math.add(u64, name_size, value.len) catch return error.IntegerOverflow;
        if (entry_size > self.capacity) return error.EntryTooLarge;

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);
        const owned_value = try self.allocator.dupe(u8, value);
        errdefer self.allocator.free(owned_value);

        while (self.bytes_used + entry_size > self.capacity) {
            try self.evictOldest();
        }

        self.inserted_count = std.math.add(u64, self.inserted_count, 1) catch return error.IntegerOverflow;
        try self.entries.append(self.allocator, .{
            .absolute_index = self.inserted_count,
            .name = owned_name,
            .value = owned_value,
        });
        self.bytes_used += entry_size;
        self.metrics.insertions += 1;
        self.metrics.table_bytes = self.bytes_used;
        return self.inserted_count;
    }

    pub fn duplicate(self: *DynamicTable, absolute_index: u64) !u64 {
        const entry = try self.getAbsolute(absolute_index);
        return self.insert(entry.name, entry.value);
    }

    pub fn getAbsolute(self: *const DynamicTable, absolute_index: u64) !HeaderField {
        if (absolute_index <= self.evicted_count) return error.InvalidDynamicIndex;
        if (absolute_index == 0 or absolute_index > self.inserted_count) return error.Blocked;
        for (self.entries.items) |entry| {
            if (entry.absolute_index == absolute_index) return entry.field();
        }
        return error.InvalidDynamicIndex;
    }

    pub fn getRelative(self: *const DynamicTable, base: u64, relative_index: u64) !HeaderField {
        if (relative_index > base) return error.InvalidDynamicIndex;
        return self.getAbsolute(base - relative_index);
    }

    pub fn getPostBase(self: *const DynamicTable, base: u64, post_base_index: u64) !HeaderField {
        const plus_index = std.math.add(u64, base, post_base_index) catch return error.IntegerOverflow;
        const absolute = std.math.add(u64, plus_index, 1) catch return error.IntegerOverflow;
        return self.getAbsolute(absolute);
    }

    fn evictToCapacity(self: *DynamicTable) !void {
        while (self.bytes_used > self.capacity) try self.evictOldest();
        self.metrics.table_bytes = self.bytes_used;
    }

    fn evictOldest(self: *DynamicTable) !void {
        if (self.entries.items.len == 0) return;
        const removed = self.entries.orderedRemove(0);
        self.bytes_used -= removed.size();
        self.evicted_count = removed.absolute_index;
        self.metrics.evictions += 1;
        removed.deinit(self.allocator);
    }
};

pub const BlockedStream = struct {
    stream_id: u64,
    required_insert_count: u64,
};

pub const BlockedStreams = struct {
    allocator: std.mem.Allocator,
    max_blocked: u64,
    streams: std.AutoHashMap(u64, BlockedStream),

    pub fn init(allocator: std.mem.Allocator, max_blocked: u64) BlockedStreams {
        return .{
            .allocator = allocator,
            .max_blocked = max_blocked,
            .streams = std.AutoHashMap(u64, BlockedStream).init(allocator),
        };
    }

    pub fn deinit(self: *BlockedStreams) void {
        self.streams.deinit();
    }

    pub fn waitFor(self: *BlockedStreams, stream_id: u64, required_insert_count: u64, metrics: *DynamicMetrics) !void {
        if (self.streams.get(stream_id)) |blocked| {
            if (required_insert_count > blocked.required_insert_count) {
                try self.streams.put(stream_id, .{ .stream_id = stream_id, .required_insert_count = required_insert_count });
            }
            return;
        }
        if (self.streams.count() >= self.max_blocked) return error.BlockedStreamLimitExceeded;
        try self.streams.put(stream_id, .{ .stream_id = stream_id, .required_insert_count = required_insert_count });
        metrics.blocked_streams += 1;
    }

    pub fn cancel(self: *BlockedStreams, stream_id: u64, metrics: *DynamicMetrics) void {
        if (self.streams.fetchRemove(stream_id) != null) metrics.cancelled_streams += 1;
    }

    pub fn unblockAvailable(self: *BlockedStreams, inserted_count: u64, out: []u64, metrics: *DynamicMetrics) usize {
        var count: usize = 0;
        var it = self.streams.iterator();
        while (it.next()) |entry| {
            if (entry.value_ptr.required_insert_count <= inserted_count) {
                if (count < out.len) out[count] = entry.key_ptr.*;
                count += 1;
            }
        }
        const remove_count = @min(count, out.len);
        for (out[0..remove_count]) |stream_id| {
            _ = self.streams.remove(stream_id);
            metrics.unblocked_streams += 1;
        }
        return remove_count;
    }
};

pub const DynamicDecodeResult = union(enum) {
    decoded: usize,
    blocked: u64,
};

pub const DynamicDecoder = struct {
    table: *DynamicTable,
    blocked: BlockedStreams,

    pub fn init(allocator: std.mem.Allocator, table: *DynamicTable, max_blocked: u64) DynamicDecoder {
        return .{ .table = table, .blocked = BlockedStreams.init(allocator, max_blocked) };
    }

    pub fn deinit(self: *DynamicDecoder) void {
        self.blocked.deinit();
    }

    pub fn decodeOrBlock(self: *DynamicDecoder, stream_id: u64, block: []const u8, fields_out: []HeaderField, scratch: []u8) !DynamicDecodeResult {
        const prefix = try decodeFieldSectionPrefix(block, self.table);
        if (prefix.required_insert_count > self.table.inserted_count) {
            try self.blocked.waitFor(stream_id, prefix.required_insert_count, &self.table.metrics);
            return .{ .blocked = prefix.required_insert_count };
        }
        const count = decodeDynamicWithPrefix(block[prefix.len..], prefix, self.table, fields_out, scratch) catch |err| {
            self.table.metrics.decode_failures += 1;
            return err;
        };
        self.blocked.cancel(stream_id, &self.table.metrics);
        return .{ .decoded = count };
    }
};

const FieldSectionPrefix = struct {
    required_insert_count: u64,
    base: u64,
    len: usize,
};

fn decodeFieldSectionPrefix(block: []const u8, table: *const DynamicTable) DecodeError!FieldSectionPrefix {
    var pos: usize = 0;
    const encoded_ric = try decodeInteger(block[pos..], 8);
    pos += encoded_ric.len;
    const required_insert_count = try decodeRequiredInsertCount(encoded_ric.value, table);
    if (pos >= block.len) return error.TruncatedBlock;
    const base_sign = block[pos] & 0x80 != 0;
    const base_delta = try decodeInteger(block[pos..], 7);
    pos += base_delta.len;
    const base = if (!base_sign) blk: {
        break :blk std.math.add(u64, required_insert_count, base_delta.value) catch return error.IntegerOverflow;
    } else blk: {
        if (required_insert_count <= base_delta.value) return error.InvalidBase;
        break :blk required_insert_count - base_delta.value - 1;
    };
    return .{ .required_insert_count = required_insert_count, .base = base, .len = pos };
}

fn decodeRequiredInsertCount(encoded: u64, table: *const DynamicTable) DecodeError!u64 {
    if (encoded == 0) return 0;
    const max_entries = table.max_capacity / 32;
    const full_range = std.math.mul(u64, 2, max_entries) catch return error.IntegerOverflow;
    if (full_range == 0 or encoded > full_range) return error.InvalidRequiredInsertCount;

    const max_value = std.math.add(u64, table.inserted_count, max_entries) catch return error.IntegerOverflow;
    const max_wrapped = (max_value / full_range) * full_range;
    var required = std.math.add(u64, max_wrapped, encoded - 1) catch return error.IntegerOverflow;
    if (required == 0) return error.InvalidRequiredInsertCount;
    if (required > max_value) required -= full_range;
    if (required == 0) return error.InvalidRequiredInsertCount;
    return required;
}

fn decodeDynamicWithPrefix(block: []const u8, prefix: FieldSectionPrefix, table: *const DynamicTable, fields_out: []HeaderField, scratch: []u8) DecodeError!usize {
    var pos: usize = 0;
    var scratch_pos: usize = 0;
    var count: usize = 0;
    while (pos < block.len) {
        if (count >= fields_out.len) return error.TooManyFields;
        const first = block[pos];
        if (first & 0x80 != 0) {
            const int = try decodeInteger(block[pos..], 6);
            pos += int.len;
            fields_out[count] = if (first & 0x40 != 0)
                staticEntry(@intCast(int.value)) orelse return error.InvalidStaticIndex
            else
                try table.getRelative(prefix.base, int.value);
        } else if (first & 0xc0 == 0x40) {
            const int = try decodeInteger(block[pos..], 4);
            pos += int.len;
            const name = if (first & 0x10 != 0)
                (staticEntry(@intCast(int.value)) orelse return error.InvalidStaticIndex).name
            else
                (try table.getRelative(prefix.base, int.value)).name;
            const value = try decodeString(block, &pos, scratch, &scratch_pos);
            fields_out[count] = .{ .name = name, .value = value };
        } else if (first & 0xe0 == 0x20) {
            const is_huffman = first & 0x08 != 0;
            const name_len = try decodeInteger(block[pos..], 3);
            pos += name_len.len;
            const name_bytes = try readBytes(block, &pos, @intCast(name_len.value));
            const name = if (is_huffman) try decodeHuffman(name_bytes, scratch, &scratch_pos) else name_bytes;
            const value = try decodeString(block, &pos, scratch, &scratch_pos);
            fields_out[count] = .{ .name = name, .value = value };
        } else if (first & 0xf0 == 0x10) {
            const int = try decodeInteger(block[pos..], 4);
            pos += int.len;
            fields_out[count] = try table.getPostBase(prefix.base, int.value);
        } else {
            const int = try decodeInteger(block[pos..], 3);
            pos += int.len;
            const name = (try table.getPostBase(prefix.base, int.value)).name;
            const value = try decodeString(block, &pos, scratch, &scratch_pos);
            fields_out[count] = .{ .name = name, .value = value };
        }
        count += 1;
    }
    return count;
}

pub fn encodeDynamicIndexed(table: *const DynamicTable, absolute_index: u64, out: []u8) ![]u8 {
    if (absolute_index == 0 or absolute_index > table.inserted_count) return error.InvalidDynamicIndex;
    var pos: usize = 0;
    pos += try encodeInteger(try encodeRequiredInsertCount(table, table.inserted_count), 8, 0x00, out[pos..]);
    pos += try encodeInteger(0, 7, 0x00, out[pos..]);
    pos += try encodeInteger(table.inserted_count - absolute_index, 6, 0x80, out[pos..]);
    return out[0..pos];
}

fn encodeRequiredInsertCount(table: *const DynamicTable, required_insert_count: u64) !u64 {
    if (required_insert_count == 0) return 0;
    const full_range = try std.math.mul(u64, 2, table.max_capacity / 32);
    if (full_range == 0) return error.InvalidRequiredInsertCount;
    return (required_insert_count % full_range) + 1;
}

pub const EncoderStream = struct {
    pub fn encodeSetCapacity(capacity: u64, out: []u8) ![]u8 {
        const len = try encodeInteger(capacity, 5, 0x20, out);
        return out[0..len];
    }

    pub fn encodeInsertNameRefStatic(static_index: u64, value: []const u8, out: []u8) ![]u8 {
        var pos: usize = 0;
        pos += try encodeInteger(static_index, 6, 0xc0, out[pos..]);
        pos += try encodeString(value, out, pos);
        return out[0..pos];
    }

    pub fn encodeInsertNameRefDynamic(relative_index: u64, value: []const u8, out: []u8) ![]u8 {
        var pos: usize = 0;
        pos += try encodeInteger(relative_index, 6, 0x80, out[pos..]);
        pos += try encodeString(value, out, pos);
        return out[0..pos];
    }

    pub fn encodeInsertLiteral(name: []const u8, value: []const u8, out: []u8) ![]u8 {
        var pos: usize = 0;
        pos += try encodeStringWithPrefix(name, 5, 0x40, out, pos);
        pos += try encodeString(value, out, pos);
        return out[0..pos];
    }

    pub fn encodeDuplicate(relative_index: u64, out: []u8) ![]u8 {
        const len = try encodeInteger(relative_index, 5, 0x00, out);
        return out[0..len];
    }

    pub fn apply(table: *DynamicTable, bytes: []const u8) !usize {
        var pos: usize = 0;
        while (pos < bytes.len) {
            const consumed = try applyOne(table, bytes[pos..]) orelse return error.TruncatedBlock;
            pos += consumed;
        }
        return pos;
    }

    fn applyOne(table: *DynamicTable, bytes: []const u8) !?usize {
        if (bytes.len == 0) return null;
        var pos: usize = 0;
        const first = bytes[pos];
        if (first & 0x80 != 0) {
            const is_static = first & 0x40 != 0;
            const name_ref = decodeInteger(bytes[pos..], 6) catch |err| return if (err == error.TruncatedBlock) null else err;
            pos += name_ref.len;
            const name = if (is_static)
                (staticEntry(@intCast(name_ref.value)) orelse return error.InvalidStaticIndex).name
            else
                (try table.getRelative(table.inserted_count, name_ref.value)).name;
            const value = decodeStringForInsert(table, bytes, &pos) catch |err| return if (err == error.TruncatedBlock) null else err;
            defer value.deinit(table.allocator);
            _ = try table.insert(name, value.bytes);
        } else if (first & 0xe0 == 0x20) {
            const cap = decodeInteger(bytes[pos..], 5) catch |err| return if (err == error.TruncatedBlock) null else err;
            pos += cap.len;
            try table.setCapacity(cap.value);
        } else if (first & 0xc0 == 0x40) {
            const name = decodeStringWithPrefixForInsert(table, bytes, &pos, 5) catch |err| return if (err == error.TruncatedBlock) null else err;
            defer name.deinit(table.allocator);
            const value = decodeStringForInsert(table, bytes, &pos) catch |err| return if (err == error.TruncatedBlock) null else err;
            defer value.deinit(table.allocator);
            _ = try table.insert(name.bytes, value.bytes);
        } else if (first & 0xe0 == 0x00) {
            const rel = decodeInteger(bytes[pos..], 5) catch |err| return if (err == error.TruncatedBlock) null else err;
            pos += rel.len;
            if (rel.value > table.inserted_count) return error.InvalidDynamicIndex;
            const absolute = table.inserted_count - rel.value;
            _ = try table.duplicate(absolute);
        } else {
            return error.MalformedInstruction;
        }
        return pos;
    }
};

pub const EncoderStreamReader = struct {
    pending: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *EncoderStreamReader, allocator: std.mem.Allocator) void {
        self.pending.deinit(allocator);
    }

    pub fn ingest(self: *EncoderStreamReader, allocator: std.mem.Allocator, table: *DynamicTable, bytes: []const u8) !usize {
        try self.pending.appendSlice(allocator, bytes);
        var consumed: usize = 0;
        while (consumed < self.pending.items.len) {
            const applied = try EncoderStream.applyOne(table, self.pending.items[consumed..]) orelse break;
            consumed += applied;
        }
        discardPendingPrefix(&self.pending, consumed);
        return bytes.len;
    }
};

const DecodedInsertString = struct {
    bytes: []const u8,
    allocation: ?[]u8 = null,

    fn deinit(self: DecodedInsertString, allocator: std.mem.Allocator) void {
        if (self.allocation) |allocation| allocator.free(allocation);
    }
};

fn decodeStringForInsert(table: *DynamicTable, block: []const u8, pos: *usize) !DecodedInsertString {
    return decodeStringWithPrefixForInsert(table, block, pos, 7);
}

fn decodeStringWithPrefixForInsert(table: *DynamicTable, block: []const u8, pos: *usize, n: u4) !DecodedInsertString {
    if (pos.* >= block.len) return error.TruncatedBlock;
    const huffman_bit: u8 = @as(u8, 1) << @intCast(n);
    const is_huffman = block[pos.*] & huffman_bit != 0;
    const len = try decodeInteger(block[pos.*..], n);
    pos.* += len.len;
    const bytes = try readBytes(block, pos, @intCast(len.value));
    if (!is_huffman) return .{ .bytes = bytes };

    if (table.capacity > std.math.maxInt(usize)) return error.IntegerOverflow;
    const scratch = try table.allocator.alloc(u8, @intCast(table.capacity));
    errdefer table.allocator.free(scratch);
    var scratch_pos: usize = 0;
    const decoded = try decodeHuffman(bytes, scratch, &scratch_pos);
    return .{ .bytes = decoded, .allocation = scratch };
}

pub const DecoderInstruction = union(enum) {
    section_ack: u64,
    stream_cancel: u64,
    insert_count_increment: u64,
};

pub const DecoderStream = struct {
    known_received_count: u64 = 0,
    section_acks: u64 = 0,
    stream_cancellations: u64 = 0,

    pub fn encode(instruction: DecoderInstruction, out: []u8) ![]u8 {
        const len = switch (instruction) {
            .section_ack => |stream_id| try encodeInteger(stream_id, 7, 0x80, out),
            .stream_cancel => |stream_id| try encodeInteger(stream_id, 6, 0x40, out),
            .insert_count_increment => |increment| try encodeInteger(increment, 6, 0x00, out),
        };
        return out[0..len];
    }

    pub fn apply(self: *DecoderStream, bytes: []const u8) !usize {
        var pos: usize = 0;
        while (pos < bytes.len) {
            const consumed = try self.applyOne(bytes[pos..]) orelse return error.TruncatedBlock;
            pos += consumed;
        }
        return pos;
    }

    fn applyOne(self: *DecoderStream, bytes: []const u8) !?usize {
        if (bytes.len == 0) return null;
        var pos: usize = 0;
        const first = bytes[pos];
        if (first & 0x80 != 0) {
            const stream_id = decodeInteger(bytes[pos..], 7) catch |err| return if (err == error.TruncatedBlock) null else err;
            _ = stream_id.value;
            pos += stream_id.len;
            self.section_acks = std.math.add(u64, self.section_acks, 1) catch return error.IntegerOverflow;
        } else if (first & 0xc0 == 0x40) {
            const stream_id = decodeInteger(bytes[pos..], 6) catch |err| return if (err == error.TruncatedBlock) null else err;
            _ = stream_id.value;
            pos += stream_id.len;
            self.stream_cancellations = std.math.add(u64, self.stream_cancellations, 1) catch return error.IntegerOverflow;
        } else {
            const inc = decodeInteger(bytes[pos..], 6) catch |err| return if (err == error.TruncatedBlock) null else err;
            pos += inc.len;
            self.known_received_count = std.math.add(u64, self.known_received_count, inc.value) catch return error.IntegerOverflow;
        }
        return pos;
    }
};

pub const DecoderStreamReader = struct {
    pending: std.ArrayList(u8) = .empty,

    pub fn deinit(self: *DecoderStreamReader, allocator: std.mem.Allocator) void {
        self.pending.deinit(allocator);
    }

    pub fn ingest(self: *DecoderStreamReader, allocator: std.mem.Allocator, stream: *DecoderStream, bytes: []const u8) !usize {
        try self.pending.appendSlice(allocator, bytes);
        var consumed: usize = 0;
        while (consumed < self.pending.items.len) {
            const applied = try stream.applyOne(self.pending.items[consumed..]) orelse break;
            consumed += applied;
        }
        discardPendingPrefix(&self.pending, consumed);
        return bytes.len;
    }
};

fn discardPendingPrefix(list: *std.ArrayList(u8), len: usize) void {
    if (len == 0) return;
    if (len >= list.items.len) {
        list.clearRetainingCapacity();
        return;
    }
    std.mem.copyForwards(u8, list.items[0 .. list.items.len - len], list.items[len..]);
    list.shrinkRetainingCapacity(list.items.len - len);
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

/// Operator counter for QPACK decode failures (issue #252 metric hook).
pub const Metrics = struct {
    decode_failures: u64 = 0,

    pub fn recordDecode(self: *Metrics, result: anytype) void {
        if (result) |_| {} else |_| {
            self.decode_failures += 1;
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "static table has the RFC 9204 size and boundary entries" {
    try testing.expectEqual(@as(usize, 99), static_table_len);
    try testing.expectEqualStrings(":authority", static_table[0].name);
    try testing.expectEqualStrings(":path", static_table[1].name);
    try testing.expectEqualStrings("GET", static_table[17].value);
    try testing.expectEqualStrings("x-frame-options", static_table[98].name);
    try testing.expectEqualStrings("sameorigin", static_table[98].value);
    try testing.expectEqual(@as(?HeaderField, null), staticEntry(99));
}

test "prefix integer round-trips across the single/multi-byte boundary" {
    for ([_]u64{ 0, 1, 10, 30, 31, 32, 127, 128, 1337, 100000, std.math.maxInt(u32) }) |value| {
        inline for ([_]u4{ 3, 4, 5, 6, 7 }) |n| {
            var buf: [12]u8 = undefined;
            const written = try encodeInteger(value, n, 0, &buf);
            const decoded = try decodeInteger(buf[0..written], n);
            try testing.expectEqual(value, decoded.value);
            try testing.expectEqual(written, decoded.len);
        }
    }
}

test "prefix integer rejects excessive continuation bytes deterministically" {
    try testing.expectError(error.IntegerOverflow, decodeInteger(&.{ 0x3f, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 }, 6));
}

fn expectRoundTrip(fields: []const HeaderField) !void {
    var buf: [1024]u8 = undefined;
    const block = try encode(fields, &buf);
    var out: [64]HeaderField = undefined;
    var scratch: [1024]u8 = undefined;
    const count = try decode(block, &out, &scratch);
    try testing.expectEqual(fields.len, count);
    for (fields, 0..) |field, i| {
        try testing.expectEqualStrings(field.name, out[i].name);
        try testing.expectEqualStrings(field.value, out[i].value);
    }
}

test "indexed static fields round-trip" {
    try expectRoundTrip(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":status", .value = "200" },
    });
}

test "representative request headers round-trip (name-ref and literal)" {
    try expectRoundTrip(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.com" }, // name ref, literal value
        .{ .name = ":path", .value = "/index.html" },
        .{ .name = "user-agent", .value = "tardigrade/0.5" },
        .{ .name = "x-custom-header", .value = "custom-value" }, // literal name + value
    });
}

test "representative response headers round-trip" {
    try expectRoundTrip(&.{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html; charset=utf-8" }, // exact static index
        .{ .name = "content-length", .value = "1234" },
        .{ .name = "server", .value = "tardigrade" },
    });
}

test "encoder picks the exact static index when name and value match" {
    var buf: [64]u8 = undefined;
    // ":status" "200" is static index 25; the field line is a single indexed byte.
    const block = try encode(&.{.{ .name = ":status", .value = "200" }}, &buf);
    try testing.expectEqual(@as(usize, 3), block.len); // 2-byte prefix + 1-byte indexed line
    try testing.expectEqual(@as(u8, 0xc0 | 25), block[2]);
}

test "encoder emits Huffman strings when smaller" {
    var buf: [128]u8 = undefined;
    const block = try encode(&.{.{ .name = ":authority", .value = "www.example.com" }}, &buf);

    // Prefix (0,0), literal name-ref :authority (static index 0), then a
    // Huffman-coded value string using the RFC 7541 C.4.1 bytes.
    try testing.expectEqualSlices(u8, &.{ 0x00, 0x00, 0x50, 0x8c }, block[0..4]);
    try testing.expectEqualSlices(u8, &.{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff }, block[4..]);
}

test "decoder accepts Huffman literal names and values" {
    var block: [64]u8 = undefined;
    var pos: usize = 0;
    block[pos] = 0x00;
    pos += 1;
    block[pos] = 0x00;
    pos += 1;
    block[pos] = 0x2f; // literal name, Huffman-coded, 3-bit length extended
    pos += 1;
    block[pos] = 0x01; // Huffman-encoded "custom-key" is 8 bytes: 7 + 1
    pos += 1;
    pos += try huffman.encode("custom-key", block[pos..]);
    block[pos] = 0x89; // Huffman-coded value length 9
    pos += 1;
    pos += try huffman.encode("custom-value", block[pos..]);

    var out: [1]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    const count = try decode(block[0..pos], &out, &scratch);
    try testing.expectEqual(@as(usize, 1), count);
    try testing.expectEqualStrings("custom-key", out[0].name);
    try testing.expectEqualStrings("custom-value", out[0].value);
}

test "decoder rejects an out-of-range static index" {
    // Prefix (0,0) then an indexed static line for index 99 (invalid).
    var buf: [8]u8 = undefined;
    var pos: usize = 2;
    pos += try encodeInteger(99, 6, 0xc0, buf[2..]);
    buf[0] = 0;
    buf[1] = 0;
    var out: [4]HeaderField = undefined;
    var scratch: [16]u8 = undefined;
    try testing.expectError(error.InvalidStaticIndex, decode(buf[0..pos], &out, &scratch));
}

test "decoder rejects dynamic-table references" {
    var out: [4]HeaderField = undefined;
    var scratch: [16]u8 = undefined;
    // Indexed line with T=0 (dynamic): first byte 0x80.
    try testing.expectError(error.DynamicTableReference, decode(&.{ 0x00, 0x00, 0x80 }, &out, &scratch));
    // Literal with name reference, T=0 (dynamic): 0x40.
    try testing.expectError(error.DynamicTableReference, decode(&.{ 0x00, 0x00, 0x40, 0x00 }, &out, &scratch));
    // Post-base indexed (0x10) is dynamic-only.
    try testing.expectError(error.DynamicTableReference, decode(&.{ 0x00, 0x00, 0x10 }, &out, &scratch));
}

test "decoder rejects a non-zero required insert count and base" {
    var out: [4]HeaderField = undefined;
    var scratch: [16]u8 = undefined;
    try testing.expectError(error.InvalidRequiredInsertCount, decode(&.{ 0x01, 0x00 }, &out, &scratch));
    try testing.expectError(error.InvalidBase, decode(&.{ 0x00, 0x01 }, &out, &scratch));
    try testing.expectError(error.InvalidBase, decode(&.{ 0x00, 0x80 }, &out, &scratch));
}

test "decoder rejects truncated blocks and malformed Huffman strings without leaking" {
    var out: [4]HeaderField = undefined;
    var scratch: [16]u8 = undefined;
    // Literal name-ref line claiming a 5-byte value but truncated.
    try testing.expectError(error.TruncatedBlock, decode(&.{ 0x00, 0x00, 0x51, 0x05, 'a', 'b' }, &out, &scratch));
    // Value string with invalid Huffman padding.
    try testing.expectError(error.InvalidHuffmanCode, decode(&.{ 0x00, 0x00, 0x51, 0x81, 0x00 }, &out, &scratch));
    try testing.expectError(error.ScratchOverflow, decode(&.{ 0x00, 0x00, 0x51, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf }, &out, scratch[0..3]));
}

test "static-only mode keeps zero dynamic capacity and no blocked streams" {
    // The simple decode API remains the safe static-only fallback: dynamic refs
    // still fail deterministically unless callers opt into DynamicDecoder.
    var out: [4]HeaderField = undefined;
    var scratch: [16]u8 = undefined;
    try testing.expectError(error.DynamicTableReference, decode(&.{ 0x00, 0x00, 0x80 }, &out, &scratch));
}

test "metrics count decode failures" {
    var metrics = Metrics{};
    var out: [4]HeaderField = undefined;
    var scratch: [16]u8 = undefined;
    metrics.recordDecode(decode(&.{ 0x00, 0x00, 0xc0 | 17 }, &out, &scratch)); // ok (:method GET)
    metrics.recordDecode(decode(&.{ 0x00, 0x00, 0x80 }, &out, &scratch)); // dynamic ref -> failure
    try testing.expectEqual(@as(u64, 1), metrics.decode_failures);
}

test "dynamic table inserts evicts and enforces capacity" {
    var table = DynamicTable.init(testing.allocator, 96);
    defer table.deinit();

    const first = try table.insert("a", "one");
    const second = try table.insert("b", "two");
    try testing.expectEqual(@as(u64, 1), first);
    try testing.expectEqual(@as(u64, 2), second);
    try testing.expectEqual(@as(u64, 2), table.inserted_count);
    try testing.expectEqualStrings("one", (try table.getAbsolute(first)).value);

    _ = try table.insert("c", "three");
    try testing.expectError(error.InvalidDynamicIndex, table.getAbsolute(first));
    try testing.expectEqual(@as(u64, 1), table.metrics.evictions);
    try testing.expect(table.bytes_used <= table.capacity);

    try testing.expectError(error.EntryTooLarge, table.insert("oversized", "this-value-is-larger-than-the-small-table-capacity-by-a-wide-margin"));
}

test "dynamic settings initialize table capacity and blocked-stream limit" {
    var payload: [32]u8 = undefined;
    const encoded = try http3_frame.encodeSettings(&.{
        .{ .id = .qpack_max_table_capacity, .id_value = 0x01, .value = 128 },
        .{ .id = .qpack_blocked_streams, .id_value = 0x07, .value = 2 },
    }, &payload);
    var scratch_settings: [4]http3_frame.Setting = undefined;
    const decoded = try http3_frame.decodeSettings(encoded, &scratch_settings);

    const settings = DynamicSettings.fromHttp3(decoded.parsed);
    var table = settings.initTable(testing.allocator);
    defer table.deinit();
    var decoder = settings.initDecoder(testing.allocator, &table);
    defer decoder.deinit();

    try testing.expectEqual(@as(u64, 128), table.max_capacity);
    try testing.expectEqual(@as(u64, 0), table.capacity);
    try testing.expectEqual(@as(u64, 2), decoder.blocked.max_blocked);
}

test "dynamic table capacity is capped by negotiated SETTINGS and can be lowered to zero" {
    var table = DynamicTable.initNegotiated(testing.allocator, 128);
    defer table.deinit();

    try table.setCapacity(128);
    _ = try table.insert("x-test", "one");
    try testing.expect(table.bytes_used > 0);

    try testing.expectError(error.CapacityExceeded, table.setCapacity(129));
    try testing.expectEqual(@as(u64, 128), table.capacity);

    try table.setCapacity(0);
    try testing.expectEqual(@as(u64, 0), table.capacity);
    try testing.expectEqual(@as(u64, 0), table.bytes_used);
    try testing.expectEqual(@as(usize, 0), table.entries.items.len);
}

test "encoder stream applies capacity insert and duplicate instructions" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();

    var stream: [256]u8 = undefined;
    var pos: usize = 0;
    pos += (try EncoderStream.encodeSetCapacity(128, stream[pos..])).len;
    pos += (try EncoderStream.encodeInsertLiteral("x-test", "one", stream[pos..])).len;
    pos += (try EncoderStream.encodeDuplicate(0, stream[pos..])).len;

    try testing.expectEqual(pos, try EncoderStream.apply(&table, stream[0..pos]));
    try testing.expectEqual(@as(u64, 2), table.inserted_count);
    try testing.expectEqualStrings("one", (try table.getAbsolute(2)).value);
}

test "encoder stream inserts entries with static and dynamic name references" {
    var table = DynamicTable.init(testing.allocator, 256);
    defer table.deinit();

    var stream: [256]u8 = undefined;
    var pos: usize = 0;
    pos += (try EncoderStream.encodeInsertNameRefStatic(0, "https", stream[pos..])).len;
    pos += (try EncoderStream.encodeInsertNameRefDynamic(0, "https-alt", stream[pos..])).len;

    try testing.expectEqual(pos, try EncoderStream.apply(&table, stream[0..pos]));
    const static_ref = try table.getAbsolute(1);
    try testing.expectEqualStrings(":authority", static_ref.name);
    try testing.expectEqualStrings("https", static_ref.value);
    const dynamic_ref = try table.getAbsolute(2);
    try testing.expectEqualStrings(":authority", dynamic_ref.name);
    try testing.expectEqualStrings("https-alt", dynamic_ref.value);
}

test "encoder stream accepts values larger than fixed scratch buffers" {
    var table = DynamicTable.init(testing.allocator, 4096);
    defer table.deinit();

    var value: [1500]u8 = undefined;
    @memset(&value, 'a');
    var stream: [2048]u8 = undefined;
    const encoded = try EncoderStream.encodeInsertLiteral("x-large", &value, &stream);

    try testing.expectEqual(encoded.len, try EncoderStream.apply(&table, encoded));
    const entry = try table.getAbsolute(1);
    try testing.expectEqualStrings("x-large", entry.name);
    try testing.expectEqualStrings(&value, entry.value);
}

test "encoder stream rejects oversized duplicate relative index" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();

    var stream: [16]u8 = undefined;
    const encoded = try EncoderStream.encodeDuplicate(1, &stream);
    try testing.expectError(error.InvalidDynamicIndex, EncoderStream.apply(&table, encoded));
}

test "encoder stream reader handles split instructions without replay" {
    var table = DynamicTable.initNegotiated(testing.allocator, 256);
    defer table.deinit();
    var reader = EncoderStreamReader{};
    defer reader.deinit(testing.allocator);

    var set_capacity_buf: [16]u8 = undefined;
    const set_capacity = try EncoderStream.encodeSetCapacity(128, &set_capacity_buf);
    try testing.expectEqual(@as(usize, 1), try reader.ingest(testing.allocator, &table, set_capacity[0..1]));
    try testing.expectEqual(@as(u64, 0), table.capacity);
    try testing.expectEqual(@as(usize, 1), reader.pending.items.len);
    try testing.expectEqual(@as(usize, set_capacity.len - 1), try reader.ingest(testing.allocator, &table, set_capacity[1..]));
    try testing.expectEqual(@as(u64, 128), table.capacity);
    try testing.expectEqual(@as(usize, 0), reader.pending.items.len);

    var insert_buf: [64]u8 = undefined;
    const insert = try EncoderStream.encodeInsertLiteral("x-split", "value", &insert_buf);
    try testing.expectEqual(@as(usize, 2), try reader.ingest(testing.allocator, &table, insert[0..2]));
    try testing.expectEqual(@as(u64, 0), table.inserted_count);
    try testing.expectEqual(insert.len - 2, try reader.ingest(testing.allocator, &table, insert[2..]));
    try testing.expectEqual(@as(u64, 1), table.inserted_count);

    var combined: [128]u8 = undefined;
    var pos: usize = 0;
    pos += (try EncoderStream.encodeSetCapacity(128, combined[pos..])).len;
    const second_insert = try EncoderStream.encodeInsertLiteral("x-once", "one", combined[pos..]);
    pos += 1;
    try testing.expectEqual(pos, try reader.ingest(testing.allocator, &table, combined[0..pos]));
    try testing.expectEqual(@as(u64, 1), table.inserted_count);
    try testing.expectEqual(second_insert.len - 1, try reader.ingest(testing.allocator, &table, combined[pos .. pos + second_insert.len - 1]));
    try testing.expectEqual(@as(u64, 2), table.inserted_count);
}

test "dynamic indexed field section decodes once encoder stream arrives" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();
    const absolute = try table.insert("x-dyn", "value");

    var block_buf: [64]u8 = undefined;
    const block = try encodeDynamicIndexed(&table, absolute, &block_buf);
    var out: [4]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    var decoder = DynamicDecoder.init(testing.allocator, &table, 4);
    defer decoder.deinit();

    const result = try decoder.decodeOrBlock(1, block, &out, &scratch);
    try testing.expectEqual(DynamicDecodeResult{ .decoded = 1 }, result);
    try testing.expectEqualStrings("x-dyn", out[0].name);
    try testing.expectEqualStrings("value", out[0].value);
}

test "dynamic field prefix handles both base directions" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();
    _ = try table.insert("first", "one");
    _ = try table.insert("second", "two");
    var out: [4]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    var decoder = DynamicDecoder.init(testing.allocator, &table, 4);
    defer decoder.deinit();

    // Encoded RIC 2 => Required Insert Count 1; S=0, DeltaBase=1 => Base 2.
    const positive_delta = [_]u8{ 0x02, 0x01, 0x80 };
    const positive = try decoder.decodeOrBlock(1, &positive_delta, &out, &scratch);
    try testing.expectEqual(DynamicDecodeResult{ .decoded = 1 }, positive);
    try testing.expectEqualStrings("second", out[0].name);

    // Encoded RIC 3 => Required Insert Count 2; S=1, DeltaBase=0 => Base 1.
    const negative_delta = [_]u8{ 0x03, 0x80, 0x80 };
    const negative = try decoder.decodeOrBlock(3, &negative_delta, &out, &scratch);
    try testing.expectEqual(DynamicDecodeResult{ .decoded = 1 }, negative);
    try testing.expectEqualStrings("first", out[0].name);
}

test "dynamic field prefix reconstructs wrapped required insert count" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();
    for (0..10) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "x-{d}", .{i});
        _ = try table.insert(name, "v");
    }
    var out: [4]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    var decoder = DynamicDecoder.init(testing.allocator, &table, 4);
    defer decoder.deinit();

    // max_entries=4, full_range=8, inserted_count=10. Encoded RIC 2
    // reconstructs Required Insert Count 9.
    const block = [_]u8{ 0x02, 0x00, 0x80 };
    const result = try decoder.decodeOrBlock(9, &block, &out, &scratch);
    try testing.expectEqual(DynamicDecodeResult{ .decoded = 1 }, result);
    try testing.expectEqualStrings("x-8", out[0].name);
}

test "dynamic decoder blocks then unblocks delayed encoder instructions" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();
    var decoder = DynamicDecoder.init(testing.allocator, &table, 1);
    defer decoder.deinit();

    // Encoded Required Insert Count 2 => Required Insert Count 1, Base 1,
    // relative dynamic index 0.
    const block = [_]u8{ 0x02, 0x00, 0x80 };
    var out: [4]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    const blocked = try decoder.decodeOrBlock(9, &block, &out, &scratch);
    try testing.expectEqual(DynamicDecodeResult{ .blocked = 1 }, blocked);
    try testing.expectEqual(@as(u64, 1), table.metrics.blocked_streams);

    _ = try table.insert("late", "arrived");
    var unblocked: [4]u64 = undefined;
    try testing.expectEqual(@as(usize, 1), decoder.blocked.unblockAvailable(table.inserted_count, &unblocked, &table.metrics));
    try testing.expectEqual(@as(u64, 9), unblocked[0]);

    const decoded = try decoder.decodeOrBlock(9, &block, &out, &scratch);
    try testing.expectEqual(DynamicDecodeResult{ .decoded = 1 }, decoded);
    try testing.expectEqualStrings("late", out[0].name);
    try testing.expectEqualStrings("arrived", out[0].value);
}

test "dynamic decoder rejects post-base index overflow" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();
    var decoder = DynamicDecoder.init(testing.allocator, &table, 1);
    defer decoder.deinit();

    var block: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try encodeInteger(0, 8, 0x00, block[pos..]);
    pos += try encodeInteger(0, 7, 0x00, block[pos..]);
    pos += try encodeInteger(std.math.maxInt(u64), 4, 0x10, block[pos..]);
    var out: [4]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    try testing.expectError(error.IntegerOverflow, decoder.decodeOrBlock(1, block[0..pos], &out, &scratch));
}

test "dynamic decoder rejects invalid base delta before blocking" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();
    var decoder = DynamicDecoder.init(testing.allocator, &table, 1);
    defer decoder.deinit();

    // Required Insert Count 1 with a negative base delta equal to RIC.
    const block = [_]u8{ 0x02, 0x81, 0x80 };
    var out: [4]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    try testing.expectError(error.InvalidBase, decoder.decodeOrBlock(9, &block, &out, &scratch));
    try testing.expectEqual(@as(u64, 0), decoder.blocked.streams.count());
}

test "blocked stream limit and cancellation are enforced" {
    var table = DynamicTable.init(testing.allocator, 128);
    defer table.deinit();
    var decoder = DynamicDecoder.init(testing.allocator, &table, 1);
    defer decoder.deinit();

    const block = [_]u8{ 0x03, 0x00, 0x80 };
    var out: [4]HeaderField = undefined;
    var scratch: [64]u8 = undefined;
    _ = try decoder.decodeOrBlock(1, &block, &out, &scratch);
    try testing.expectError(error.BlockedStreamLimitExceeded, decoder.decodeOrBlock(2, &block, &out, &scratch));

    decoder.blocked.cancel(1, &table.metrics);
    try testing.expectEqual(@as(u64, 1), table.metrics.cancelled_streams);
    _ = try decoder.decodeOrBlock(2, &block, &out, &scratch);
}

test "decoder stream instructions update acknowledgement state" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += (try DecoderStream.encode(.{ .section_ack = 11 }, buf[pos..])).len;
    pos += (try DecoderStream.encode(.{ .stream_cancel = 13 }, buf[pos..])).len;
    pos += (try DecoderStream.encode(.{ .insert_count_increment = 3 }, buf[pos..])).len;

    var stream = DecoderStream{};
    try testing.expectEqual(pos, try stream.apply(buf[0..pos]));
    try testing.expectEqual(@as(u64, 1), stream.section_acks);
    try testing.expectEqual(@as(u64, 1), stream.stream_cancellations);
    try testing.expectEqual(@as(u64, 3), stream.known_received_count);
}

test "decoder stream rejects insert count overflow" {
    var buf: [16]u8 = undefined;
    const encoded = try DecoderStream.encode(.{ .insert_count_increment = 1 }, &buf);
    var stream = DecoderStream{ .known_received_count = std.math.maxInt(u64) };
    try testing.expectError(error.IntegerOverflow, stream.apply(encoded));
}

test "decoder stream reader handles split varints" {
    var buf: [16]u8 = undefined;
    const encoded = try DecoderStream.encode(.{ .insert_count_increment = 128 }, &buf);
    var stream = DecoderStream{};
    var reader = DecoderStreamReader{};
    defer reader.deinit(testing.allocator);

    try testing.expectEqual(@as(usize, 1), try reader.ingest(testing.allocator, &stream, encoded[0..1]));
    try testing.expectEqual(@as(u64, 0), stream.known_received_count);
    try testing.expectEqual(@as(usize, 1), reader.pending.items.len);
    try testing.expectEqual(encoded.len - 1, try reader.ingest(testing.allocator, &stream, encoded[1..]));
    try testing.expectEqual(@as(u64, 128), stream.known_received_count);
    try testing.expectEqual(@as(usize, 0), reader.pending.items.len);
}

test "dynamic table memory remains bounded under repeated inserts" {
    var table = DynamicTable.init(testing.allocator, 160);
    defer table.deinit();

    for (0..20) |i| {
        var name_buf: [16]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "x-{d}", .{i});
        _ = try table.insert(name, "payload");
        try testing.expect(table.bytes_used <= table.capacity);
    }
    try testing.expect(table.metrics.evictions > 0);
}

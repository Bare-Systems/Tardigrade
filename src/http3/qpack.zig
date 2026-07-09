//! QPACK header compression — static-table-only mode (#252, RFC 9204).
//!
//! Encodes/decodes the HEADERS payloads carried by `frame.zig` for the first
//! pure Zig HTTP/3 path. This mode uses the static table only: the dynamic
//! table capacity is zero, no encoder/decoder-stream state exists, and no
//! stream can ever be blocked. Any dynamic-table reference in an incoming block
//! is rejected deterministically. The dynamic table, encoder/decoder streams,
//! and blocked-stream accounting land in #253.
//!
//! Huffman string literals are added in a follow-up slice; until then the
//! decoder rejects Huffman-coded strings with `error.HuffmanNotSupported` and
//! the encoder emits raw (non-Huffman) strings.

const std = @import("std");

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
        shift += 7;
        if (shift > 63) return error.IntegerOverflow;
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
            // Literal Field Line With Literal Name (001 N=0 H=0 + 3-bit name len).
            pos += try encodeInto(out, pos, field.name.len, 3, 0x20);
            pos += try writeAll(out, pos, field.name);
            pos += try encodeString(field.value, out, pos);
        }
    }
    return out[0..pos];
}

fn encodeInto(out: []u8, pos: usize, value: u64, n: u4, high_bits: u8) EncodeError!usize {
    return encodeInteger(value, n, high_bits, out[pos..]);
}

/// Encode a string literal (H=0: 7-bit length prefix + raw bytes).
fn encodeString(bytes: []const u8, out: []u8, pos: usize) EncodeError!usize {
    var written = try encodeInteger(bytes.len, 7, 0x00, out[pos..]);
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
    /// A Huffman-coded string was present (not yet supported).
    HuffmanNotSupported,
    /// More header fields than the caller-provided output can hold.
    TooManyFields,
};

/// Decode a QPACK encoded field section into `fields_out`, returning the number
/// of fields. Decoded name/value slices borrow the static table or the input
/// `block`; no allocation is performed and no dynamic/blocked state exists.
pub fn decode(block: []const u8, fields_out: []HeaderField) DecodeError!usize {
    var pos: usize = 0;

    // Encoded Field Section Prefix. Static-only: RIC and Base must both be 0.
    const ric = try decodeInteger(block[pos..], 8);
    if (ric.value != 0) return error.InvalidRequiredInsertCount;
    pos += ric.len;
    const base = try decodeInteger(block[pos..], 7); // ignores the sign bit
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
            const value = try decodeString(block, &pos);
            fields_out[count] = .{ .name = entry.name, .value = value };
        } else if (first & 0xe0 == 0x20) {
            // Literal Field Line With Literal Name (001 N H ...).
            const huffman = first & 0x08 != 0;
            const name_len = try decodeInteger(block[pos..], 3);
            pos += name_len.len;
            const name = try readBytes(block, &pos, @intCast(name_len.value));
            if (huffman) return error.HuffmanNotSupported;
            const value = try decodeString(block, &pos);
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
fn decodeString(block: []const u8, pos: *usize) DecodeError![]const u8 {
    if (pos.* >= block.len) return error.TruncatedBlock;
    const huffman = block[pos.*] & 0x80 != 0;
    const len = try decodeInteger(block[pos.*..], 7);
    pos.* += len.len;
    const bytes = try readBytes(block, pos, @intCast(len.value));
    if (huffman) return error.HuffmanNotSupported;
    return bytes;
}

fn readBytes(block: []const u8, pos: *usize, len: usize) DecodeError![]const u8 {
    if (len > block.len - pos.*) return error.TruncatedBlock;
    const bytes = block[pos.*..][0..len];
    pos.* += len;
    return bytes;
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

fn expectRoundTrip(fields: []const HeaderField) !void {
    var buf: [1024]u8 = undefined;
    const block = try encode(fields, &buf);
    var out: [64]HeaderField = undefined;
    const count = try decode(block, &out);
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

test "decoder rejects an out-of-range static index" {
    // Prefix (0,0) then an indexed static line for index 99 (invalid).
    var buf: [8]u8 = undefined;
    var pos: usize = 2;
    pos += try encodeInteger(99, 6, 0xc0, buf[2..]);
    buf[0] = 0;
    buf[1] = 0;
    var out: [4]HeaderField = undefined;
    try testing.expectError(error.InvalidStaticIndex, decode(buf[0..pos], &out));
}

test "decoder rejects dynamic-table references" {
    var out: [4]HeaderField = undefined;
    // Indexed line with T=0 (dynamic): first byte 0x80.
    try testing.expectError(error.DynamicTableReference, decode(&.{ 0x00, 0x00, 0x80 }, &out));
    // Literal with name reference, T=0 (dynamic): 0x40.
    try testing.expectError(error.DynamicTableReference, decode(&.{ 0x00, 0x00, 0x40, 0x00 }, &out));
    // Post-base indexed (0x10) is dynamic-only.
    try testing.expectError(error.DynamicTableReference, decode(&.{ 0x00, 0x00, 0x10 }, &out));
}

test "decoder rejects a non-zero required insert count and base" {
    var out: [4]HeaderField = undefined;
    try testing.expectError(error.InvalidRequiredInsertCount, decode(&.{ 0x01, 0x00 }, &out));
    try testing.expectError(error.InvalidBase, decode(&.{ 0x00, 0x01 }, &out));
}

test "decoder rejects truncated blocks and Huffman strings without leaking" {
    var out: [4]HeaderField = undefined;
    // Literal name-ref line claiming a 5-byte value but truncated.
    try testing.expectError(error.TruncatedBlock, decode(&.{ 0x00, 0x00, 0x51, 0x05, 'a', 'b' }, &out));
    // Value string with the Huffman bit set.
    try testing.expectError(error.HuffmanNotSupported, decode(&.{ 0x00, 0x00, 0x51, 0x82, 0x00, 0x00 }, &out));
}

test "static-only mode keeps zero dynamic capacity and no blocked streams" {
    // These invariants are structural: there is no dynamic table state to grow
    // and no blocked-stream accounting in this module.
    try testing.expect(!@hasDecl(@This(), "DynamicTable"));
    try testing.expect(!@hasDecl(@This(), "BlockedStreams"));
}

test "metrics count decode failures" {
    var metrics = Metrics{};
    var out: [4]HeaderField = undefined;
    metrics.recordDecode(decode(&.{ 0x00, 0x00, 0xc0 | 17 }, &out)); // ok (:method GET)
    metrics.recordDecode(decode(&.{ 0x00, 0x00, 0x80 }, &out)); // dynamic ref -> failure
    try testing.expectEqual(@as(u64, 1), metrics.decode_failures);
}

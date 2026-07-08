//! QUIC variable-length integer codec (#243, RFC 9000 §16).
//!
//! The first two bits of the first byte encode the length (00→1, 01→2, 10→4,
//! 11→8 bytes); the value is the remaining big-endian bits. Range is 0 ..
//! 2^62-1. Decoding accepts non-minimal encodings (RFC 9000 §16); encoding
//! always uses the minimal length.

const std = @import("std");

/// Largest value representable by a QUIC varint (2^62 - 1).
pub const max_value: u64 = (1 << 62) - 1;

pub const DecodeError = error{BufferTooShort};
pub const EncodeError = error{ ValueTooLarge, BufferTooShort };

pub const Decoded = struct {
    value: u64,
    /// Number of bytes consumed.
    len: usize,
};

/// Number of bytes a varint occupies, read from its first byte's 2-bit prefix.
pub fn decodedLen(first_byte: u8) usize {
    return @as(usize, 1) << @intCast(first_byte >> 6);
}

/// Decode a varint from the front of `bytes`.
pub fn decode(bytes: []const u8) DecodeError!Decoded {
    if (bytes.len == 0) return error.BufferTooShort;
    const len = decodedLen(bytes[0]);
    if (bytes.len < len) return error.BufferTooShort;
    var value: u64 = bytes[0] & 0x3f;
    var i: usize = 1;
    while (i < len) : (i += 1) {
        value = (value << 8) | bytes[i];
    }
    return .{ .value = value, .len = len };
}

/// Minimal number of bytes needed to encode `value` (1, 2, 4, or 8).
pub fn encodedLen(value: u64) EncodeError!usize {
    if (value <= 0x3f) return 1;
    if (value <= 0x3fff) return 2;
    if (value <= 0x3fff_ffff) return 4;
    if (value <= max_value) return 8;
    return error.ValueTooLarge;
}

/// Encode `value` into the front of `buf` using the minimal length; returns the
/// number of bytes written.
pub fn encode(value: u64, buf: []u8) EncodeError!usize {
    const len = try encodedLen(value);
    if (buf.len < len) return error.BufferTooShort;
    switch (len) {
        1 => buf[0] = @intCast(value),
        2 => {
            std.mem.writeInt(u16, buf[0..2], @intCast(value), .big);
            buf[0] |= 0x40;
        },
        4 => {
            std.mem.writeInt(u32, buf[0..4], @intCast(value), .big);
            buf[0] |= 0x80;
        },
        8 => {
            std.mem.writeInt(u64, buf[0..8], value, .big);
            buf[0] |= 0xc0;
        },
        else => unreachable,
    }
    return len;
}

const testing = std.testing;

test "decode RFC 9000 Appendix A sample varints" {
    const D = struct { bytes: []const u8, value: u64, len: usize };
    const cases = [_]D{
        .{ .bytes = &.{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c }, .value = 151288809941952652, .len = 8 },
        .{ .bytes = &.{ 0x9d, 0x7f, 0x3e, 0x7d }, .value = 494878333, .len = 4 },
        .{ .bytes = &.{ 0x7b, 0xbd }, .value = 15293, .len = 2 },
        .{ .bytes = &.{0x25}, .value = 37, .len = 1 },
        // Non-minimal 2-byte encoding of 37 is still valid on decode.
        .{ .bytes = &.{ 0x40, 0x25 }, .value = 37, .len = 2 },
    };
    for (cases) |c| {
        const got = try decode(c.bytes);
        try testing.expectEqual(c.value, got.value);
        try testing.expectEqual(c.len, got.len);
    }
}

test "encode uses the minimal length and round-trips" {
    var buf: [8]u8 = undefined;
    const values = [_]u64{ 0, 1, 37, 63, 64, 15293, 16383, 16384, 494878333, 0x3fff_ffff, 0x4000_0000, 151288809941952652, max_value };
    for (values) |v| {
        const n = try encode(v, &buf);
        try testing.expectEqual(try encodedLen(v), n);
        const got = try decode(buf[0..n]);
        try testing.expectEqual(v, got.value);
        try testing.expectEqual(n, got.len);
    }
}

test "encodedLen boundaries" {
    try testing.expectEqual(@as(usize, 1), try encodedLen(63));
    try testing.expectEqual(@as(usize, 2), try encodedLen(64));
    try testing.expectEqual(@as(usize, 2), try encodedLen(16383));
    try testing.expectEqual(@as(usize, 4), try encodedLen(16384));
    try testing.expectEqual(@as(usize, 4), try encodedLen(0x3fff_ffff));
    try testing.expectEqual(@as(usize, 8), try encodedLen(0x4000_0000));
    try testing.expectEqual(@as(usize, 8), try encodedLen(max_value));
    try testing.expectError(error.ValueTooLarge, encodedLen(max_value + 1));
}

test "malformed and boundary inputs" {
    try testing.expectError(error.BufferTooShort, decode(&.{}));
    // 8-byte prefix but only one byte present.
    try testing.expectError(error.BufferTooShort, decode(&.{0xc2}));
    // 2-byte prefix, one byte present.
    try testing.expectError(error.BufferTooShort, decode(&.{0x40}));
    var small: [1]u8 = undefined;
    try testing.expectError(error.BufferTooShort, encode(64, &small)); // needs 2 bytes
    try testing.expectError(error.ValueTooLarge, encode(max_value + 1, &small));
}

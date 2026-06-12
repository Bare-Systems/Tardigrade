const std = @import("std");

pub const ByteRange = struct {
    start: usize,
    end_inclusive: usize,

    pub fn len(self: ByteRange) usize {
        return self.end_inclusive - self.start + 1;
    }
};

pub fn parseSingle(header_value: []const u8, size: usize) !ByteRange {
    const trimmed = std.mem.trim(u8, header_value, " \t");
    if (!std.mem.startsWith(u8, trimmed, "bytes=")) return error.InvalidRange;

    const spec = trimmed["bytes=".len..];
    if (std.mem.findScalar(u8, spec, ',')) |_| return error.MultiRangeUnsupported;

    const dash = std.mem.findScalar(u8, spec, '-') orelse return error.InvalidRange;
    const start_raw = std.mem.trim(u8, spec[0..dash], " \t");
    const end_raw = std.mem.trim(u8, spec[dash + 1 ..], " \t");

    if (size == 0) return error.RangeNotSatisfiable;

    if (start_raw.len == 0) {
        const suffix_len = std.fmt.parseInt(usize, end_raw, 10) catch return error.InvalidRange;
        if (suffix_len == 0) return error.InvalidRange;
        if (suffix_len >= size) {
            return .{ .start = 0, .end_inclusive = size - 1 };
        }
        return .{
            .start = size - suffix_len,
            .end_inclusive = size - 1,
        };
    }

    const start = std.fmt.parseInt(usize, start_raw, 10) catch return error.InvalidRange;
    if (start >= size) return error.RangeNotSatisfiable;

    const end_inclusive = if (end_raw.len == 0)
        size - 1
    else
        std.fmt.parseInt(usize, end_raw, 10) catch return error.InvalidRange;

    if (end_inclusive < start) return error.InvalidRange;

    return .{
        .start = start,
        .end_inclusive = @min(end_inclusive, size - 1),
    };
}

pub fn formatContentRange(allocator: std.mem.Allocator, byte_range: ByteRange, size: usize) ![]u8 {
    return std.fmt.allocPrint(allocator, "bytes {d}-{d}/{d}", .{
        byte_range.start,
        byte_range.end_inclusive,
        size,
    });
}

test "parseSingle parses closed range" {
    const parsed = try parseSingle("bytes=0-999", 2000);
    try std.testing.expectEqual(@as(usize, 0), parsed.start);
    try std.testing.expectEqual(@as(usize, 999), parsed.end_inclusive);
    try std.testing.expectEqual(@as(usize, 1000), parsed.len());
}

test "parseSingle parses suffix range" {
    const parsed = try parseSingle("bytes=-128", 1000);
    try std.testing.expectEqual(@as(usize, 872), parsed.start);
    try std.testing.expectEqual(@as(usize, 999), parsed.end_inclusive);
}

test "parseSingle rejects unsatisfiable range" {
    try std.testing.expectError(error.RangeNotSatisfiable, parseSingle("bytes=999-1000", 10));
}

test "parseSingle parses open-ended range (bytes=N-)" {
    const parsed = try parseSingle("bytes=5-", 20);
    try std.testing.expectEqual(@as(usize, 5), parsed.start);
    try std.testing.expectEqual(@as(usize, 19), parsed.end_inclusive);
    try std.testing.expectEqual(@as(usize, 15), parsed.len());
}

test "parseSingle clamps end to file size" {
    const parsed = try parseSingle("bytes=0-9999", 50);
    try std.testing.expectEqual(@as(usize, 0), parsed.start);
    try std.testing.expectEqual(@as(usize, 49), parsed.end_inclusive);
}

test "parseSingle rejects reversed range (end < start)" {
    try std.testing.expectError(error.InvalidRange, parseSingle("bytes=10-5", 100));
}

test "parseSingle rejects multi-range" {
    try std.testing.expectError(error.MultiRangeUnsupported, parseSingle("bytes=0-9,20-29", 100));
}

test "formatContentRange produces correct header value" {
    const br = ByteRange{ .start = 10, .end_inclusive = 19 };
    const hdr = try formatContentRange(std.testing.allocator, br, 100);
    defer std.testing.allocator.free(hdr);
    try std.testing.expectEqualStrings("bytes 10-19/100", hdr);
}

test "fuzz: parseSingle never panics and valid results satisfy range invariants" {
    try std.testing.fuzz({}, fuzzParseSingle, .{ .corpus = &.{
        "bytes=0-99",
        "bytes=-128",
        "bytes=100-",
        "bytes=0-0",
        "bytes=0-9,20-29",
        "",
    } });
}

fn fuzzParseSingle(_: void, smith: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    const len = smith.slice(&buf);
    const file_size: usize = smith.value(u32);
    const result = parseSingle(buf[0..len], file_size) catch return;
    // Invariant: start must be <= end_inclusive, and both within [0, file_size).
    try std.testing.expect(result.start <= result.end_inclusive);
    if (file_size > 0) try std.testing.expect(result.end_inclusive < file_size);
}

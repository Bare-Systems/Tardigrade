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
    if (std.mem.indexOfScalar(u8, spec, ',')) |_| return error.MultiRangeUnsupported;

    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return error.InvalidRange;
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

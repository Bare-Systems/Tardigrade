const std = @import("std");

pub fn generateETag(allocator: std.mem.Allocator, size: usize, mtime: ?usize) ![]const u8 {
    // Format: "{hex_size}-{hex_mtime}"
    const m = if (mtime) |t| t else 0;
    return try std.fmt.allocPrint(allocator, "\"{x}-{x}\"", .{ size, m });
}

pub fn matchesIfNoneMatch(etag: []const u8, header: []const u8) bool {
    // If header is '*', it always matches
    if (std.mem.eql(u8, std.mem.trim(u8, header, " \t"), "*")) return true;
    // Simple substring match handles lists like '"a","b"'
    return std.mem.find(u8, header, etag) != null;
}

test "generateETag produces quoted hex size-mtime format" {
    const tag = try generateETag(std.testing.allocator, 1024, 1_700_000_000);
    defer std.testing.allocator.free(tag);
    // Verify wrapping quotes and dash separator
    try std.testing.expect(tag[0] == '"');
    try std.testing.expect(tag[tag.len - 1] == '"');
    try std.testing.expect(std.mem.findScalar(u8, tag, '-') != null);
}

test "generateETag is deterministic for same inputs" {
    const a = try generateETag(std.testing.allocator, 512, 1000);
    defer std.testing.allocator.free(a);
    const b = try generateETag(std.testing.allocator, 512, 1000);
    defer std.testing.allocator.free(b);
    try std.testing.expectEqualStrings(a, b);
}

test "generateETag differs for different sizes" {
    const a = try generateETag(std.testing.allocator, 100, 1000);
    defer std.testing.allocator.free(a);
    const b = try generateETag(std.testing.allocator, 200, 1000);
    defer std.testing.allocator.free(b);
    try std.testing.expect(!std.mem.eql(u8, a, b));
}

test "matchesIfNoneMatch matches exact etag" {
    try std.testing.expect(matchesIfNoneMatch("\"abc-123\"", "\"abc-123\""));
}

test "matchesIfNoneMatch matches wildcard" {
    try std.testing.expect(matchesIfNoneMatch("\"abc-123\"", "*"));
    try std.testing.expect(matchesIfNoneMatch("\"abc-123\"", "  *  "));
}

test "matchesIfNoneMatch rejects different etag" {
    try std.testing.expect(!matchesIfNoneMatch("\"abc-123\"", "\"xyz-456\""));
}

test "matchesIfNoneMatch matches etag within a list" {
    try std.testing.expect(matchesIfNoneMatch("\"b-2\"", "\"a-1\", \"b-2\", \"c-3\""));
}

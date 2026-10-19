const std = @import("std");

pub fn generateETag(allocator: std.mem.Allocator, size: usize, mtime: ?usize) ![]const u8 {
    // Format: "{hex_size}-{hex_mtime}"
    const m = if (mtime) |t| t else 0;
    return try std.fmt.allocPrint(allocator, "\"{x}-{x}\"", .{ size, m });
}

fn stripWeakPrefix(tag: []const u8) []const u8 {
    if (std.mem.startsWith(u8, tag, "W/")) return tag[2..];
    return tag;
}

/// RFC 9110 §13.1.2 requires weak comparison for `If-None-Match` on GET/HEAD:
/// entity-tags match if their opaque-tag is identical once any `W/` prefix is
/// stripped from both sides, regardless of which side (if either) was weak.
pub fn matchesIfNoneMatch(etag: []const u8, header: []const u8) bool {
    // If header is '*', it always matches
    if (std.mem.eql(u8, std.mem.trim(u8, header, " \t"), "*")) return true;

    const target = stripWeakPrefix(etag);

    // Walk the comma-separated list of entity-tags by locating each
    // opaque-tag's quoted span, rather than doing a raw substring search:
    // a substring match would wrongly treat a strong `"v1"` and weak
    // `W/"v1"` as different tags (or collide on text that merely contains
    // another tag's bytes).
    var i: usize = 0;
    while (std.mem.indexOfScalarPos(u8, header, i, '"')) |open_quote| {
        const close_quote = std.mem.indexOfScalarPos(u8, header, open_quote + 1, '"') orelse break;
        var tag_start = open_quote;
        if (open_quote >= 2 and header[open_quote - 2] == 'W' and header[open_quote - 1] == '/') {
            tag_start = open_quote - 2;
        }
        const candidate = stripWeakPrefix(header[tag_start .. close_quote + 1]);
        if (std.mem.eql(u8, candidate, target)) return true;
        i = close_quote + 1;
    }
    return false;
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

test "matchesIfNoneMatch uses weak comparison: stored weak vs client strong" {
    try std.testing.expect(matchesIfNoneMatch("W/\"rev1\"", "\"rev1\""));
}

test "matchesIfNoneMatch uses weak comparison: stored strong vs client weak" {
    try std.testing.expect(matchesIfNoneMatch("\"rev1\"", "W/\"rev1\""));
}

test "matchesIfNoneMatch uses weak comparison: both weak" {
    try std.testing.expect(matchesIfNoneMatch("W/\"rev1\"", "W/\"rev1\""));
}

test "matchesIfNoneMatch weak comparison still rejects a genuinely different tag" {
    try std.testing.expect(!matchesIfNoneMatch("W/\"rev1\"", "W/\"rev2\""));
    try std.testing.expect(!matchesIfNoneMatch("W/\"rev1\"", "\"rev2\""));
}

test "matchesIfNoneMatch weak comparison matches within a mixed-strength list" {
    try std.testing.expect(matchesIfNoneMatch("W/\"rev1\"", "\"other\", \"rev1\", W/\"third\""));
    try std.testing.expect(matchesIfNoneMatch("\"rev1\"", "\"other\", W/\"rev1\", \"third\""));
}

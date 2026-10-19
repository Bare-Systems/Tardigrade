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

/// RFC 9110 §13.1.2 `etagc`: `%x21 / %x23-7E / obs-text` -- a `VCHAR` minus
/// `DQUOTE`, plus any high-bit byte. There is no quoted-pair escaping in
/// entity-tag syntax, so a literal `"` always ends the opaque-tag span.
fn isEtagc(c: u8) bool {
    return c == 0x21 or (c >= 0x23 and c <= 0x7E) or c >= 0x80;
}

fn skipOws(header: []const u8, start: usize) usize {
    var i = start;
    while (i < header.len and (header[i] == ' ' or header[i] == '\t')) i += 1;
    return i;
}

/// RFC 9110 §13.1.2 requires weak comparison for `If-None-Match` on GET/HEAD:
/// entity-tags match if their opaque-tag is identical once any `W/` prefix is
/// stripped from both sides, regardless of which side (if either) was weak.
///
/// `header` must parse as a strict `If-None-Match = "*" / 1#entity-tag`
/// (RFC 9110 §13.1.1, §8.8.3): a comma-separated list of
/// `[ "W/" ] DQUOTE *etagc DQUOTE` tokens with no unparsed bytes anywhere in
/// the field. A raw substring/quote search would accept a token embedded in
/// otherwise-malformed text (e.g. `garbage"rev1"`, or a match followed by
/// trailing junk) as if the client had actually sent that validator; any
/// syntax violation instead makes the whole field indeterminate and this
/// returns `false`, even if a valid-looking tag was found before the
/// violation.
pub fn matchesIfNoneMatch(etag: []const u8, header: []const u8) bool {
    if (std.mem.eql(u8, std.mem.trim(u8, header, " \t"), "*")) return true;

    const target = stripWeakPrefix(etag);
    var cursor: usize = skipOws(header, 0);
    var found = false;
    while (cursor < header.len) {
        if (std.mem.startsWith(u8, header[cursor..], "W/")) cursor += 2;
        if (cursor >= header.len or header[cursor] != '"') return false;
        const quote_start = cursor;
        cursor += 1;
        while (cursor < header.len and header[cursor] != '"') {
            if (!isEtagc(header[cursor])) return false;
            cursor += 1;
        }
        if (cursor >= header.len) return false; // unterminated quoted-string
        const candidate = header[quote_start .. cursor + 1];
        cursor += 1;
        if (!found and std.mem.eql(u8, candidate, target)) found = true;

        cursor = skipOws(header, cursor);
        if (cursor >= header.len) break;
        if (header[cursor] != ',') return false;
        cursor = skipOws(header, cursor + 1);
    }
    return found;
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

test "matchesIfNoneMatch rejects a tag embedded in a malformed leading token" {
    try std.testing.expect(!matchesIfNoneMatch("W/\"rev1\"", "garbage\"rev1\""));
}

test "matchesIfNoneMatch rejects a tag embedded in a malformed later token" {
    try std.testing.expect(!matchesIfNoneMatch("W/\"rev1\"", "\"other\", junk\"rev1\""));
}

test "matchesIfNoneMatch rejects an otherwise-matching tag followed by trailing junk" {
    try std.testing.expect(!matchesIfNoneMatch("\"rev1\"", "\"rev1\"suffix"));
}

test "matchesIfNoneMatch rejects a tag followed by a later malformed token" {
    try std.testing.expect(!matchesIfNoneMatch("\"b-2\"", "\"b-2\", garbage"));
}

test "matchesIfNoneMatch still matches a valid mixed strong/weak list after fix" {
    try std.testing.expect(matchesIfNoneMatch("W/\"rev1\"", "\"a-1\", W/\"rev1\", \"c-3\""));
}

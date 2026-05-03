const std = @import("std");
const Headers = @import("headers.zig").Headers;

pub const HEADER_NAME = "X-Correlation-ID";
pub const REQUEST_HEADER_NAME = "X-Request-ID";
pub const MAX_CORRELATION_ID_LEN: usize = 128;

/// Allowed token characters for correlation IDs.
fn isAllowedChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.';
}

/// Validate correlation ID to keep response headers predictable and safe.
pub fn isValid(id: []const u8) bool {
    if (id.len == 0 or id.len > MAX_CORRELATION_ID_LEN) return false;
    for (id) |c| {
        if (!isAllowedChar(c)) return false;
    }
    return true;
}

/// Return client-provided correlation ID if valid; otherwise generate one.
pub fn fromHeadersOrGenerate(allocator: std.mem.Allocator, headers: *const Headers) ![]u8 {
    if (headers.get("x-request-id")) |incoming| {
        if (isValid(incoming)) {
            return allocator.dupe(u8, incoming);
        }
    }
    if (headers.get("x-correlation-id")) |incoming| {
        if (isValid(incoming)) {
            return allocator.dupe(u8, incoming);
        }
    }
    return generate(allocator);
}

/// Generate a compact ID suitable for logs and response headers.
pub fn generate(allocator: std.mem.Allocator) ![]u8 {
    var random: [8]u8 = undefined;
    std.crypto.random.bytes(&random);
    return std.fmt.allocPrint(allocator, "tg-{d}-{s}", .{
        std.time.milliTimestamp(),
        std.fmt.fmtSliceHexLower(&random),
    });
}

test "isValid accepts expected forms" {
    const testing = std.testing;
    try testing.expect(isValid("abc-123_DEF.9"));
    try testing.expect(!isValid(""));
    try testing.expect(!isValid("bad space"));
    try testing.expect(!isValid("bad:colon"));
}

test "fromHeadersOrGenerate reuses valid incoming header" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var headers = Headers.init(allocator);
    defer headers.deinit();
    try headers.append("X-Correlation-ID", "req-123");

    const correlation_id = try fromHeadersOrGenerate(allocator, &headers);
    defer allocator.free(correlation_id);

    try testing.expectEqualStrings("req-123", correlation_id);
}

test "fromHeadersOrGenerate prefers valid request id header" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var headers = Headers.init(allocator);
    defer headers.deinit();
    try headers.append("X-Request-ID", "req-789");
    try headers.append("X-Correlation-ID", "req-123");

    const correlation_id = try fromHeadersOrGenerate(allocator, &headers);
    defer allocator.free(correlation_id);

    try testing.expectEqualStrings("req-789", correlation_id);
}

test "fromHeadersOrGenerate falls back when incoming header is invalid" {
    const testing = std.testing;
    const allocator = testing.allocator;

    var headers = Headers.init(allocator);
    defer headers.deinit();
    try headers.append("X-Correlation-ID", "bad id");

    const correlation_id = try fromHeadersOrGenerate(allocator, &headers);
    defer allocator.free(correlation_id);

    try testing.expect(correlation_id.len > 0);
    try testing.expect(std.mem.startsWith(u8, correlation_id, "tg-"));
    try testing.expect(isValid(correlation_id));
}

const std = @import("std");

/// Minimum response body size to consider compressing (bytes).
/// Bodies smaller than this are not worth the CPU cost.
pub const DEFAULT_MIN_SIZE: usize = 256;

/// MIME types that should be compressed.
fn isCompressibleMime(mime: []const u8) bool {
    // Text types
    if (std.mem.startsWith(u8, mime, "text/")) return true;
    // JSON / XML / JS application types
    if (std.mem.indexOf(u8, mime, "application/json") != null) return true;
    if (std.mem.indexOf(u8, mime, "application/xml") != null) return true;
    if (std.mem.indexOf(u8, mime, "application/javascript") != null) return true;
    if (std.mem.indexOf(u8, mime, "application/x-javascript") != null) return true;
    if (std.mem.indexOf(u8, mime, "application/xhtml+xml") != null) return true;
    if (std.mem.indexOf(u8, mime, "application/rss+xml") != null) return true;
    if (std.mem.indexOf(u8, mime, "application/atom+xml") != null) return true;
    if (std.mem.indexOf(u8, mime, "image/svg+xml") != null) return true;
    if (std.mem.indexOf(u8, mime, "application/wasm") != null) return true;
    // Already compressed — do NOT compress
    // image/png, image/jpeg, font/woff2, application/gzip, etc. are excluded by default
    return false;
}

/// Check if a client supports gzip encoding via Accept-Encoding header.
pub fn clientAcceptsGzip(accept_encoding: ?[]const u8) bool {
    const ae = accept_encoding orelse return false;
    // Simple check: does Accept-Encoding contain "gzip"?
    var lower_buf: [512]u8 = undefined;
    const len = @min(ae.len, lower_buf.len);
    const lower = std.ascii.lowerString(lower_buf[0..len], ae[0..len]);
    return std.mem.indexOf(u8, lower, "gzip") != null;
}

/// Configuration for response compression.
pub const CompressionConfig = struct {
    enabled: bool = true,
    /// Minimum body size to compress.
    min_size: usize = DEFAULT_MIN_SIZE,
    /// Compression level.
    level: std.compress.gzip.Options = .{ .level = .default },
};

/// Result of attempting compression.
pub const CompressionResult = struct {
    /// Compressed body (owned by allocator). Null if compression was skipped.
    body: ?[]u8,
    /// Whether compression was applied.
    compressed: bool,
};

/// Compress a response body with gzip if beneficial.
///
/// Returns the compressed body or null if compression was skipped.
/// Caller owns the returned memory.
pub fn compressResponse(
    allocator: std.mem.Allocator,
    body: []const u8,
    content_type: ?[]const u8,
    accept_encoding: ?[]const u8,
    config: CompressionConfig,
) CompressionResult {
    // Check if compression is enabled
    if (!config.enabled) return .{ .body = null, .compressed = false };

    // Check body size threshold
    if (body.len < config.min_size) return .{ .body = null, .compressed = false };

    // Check client support
    if (!clientAcceptsGzip(accept_encoding)) return .{ .body = null, .compressed = false };

    // Check MIME type
    const mime = content_type orelse return .{ .body = null, .compressed = false };
    if (!isCompressibleMime(mime)) return .{ .body = null, .compressed = false };

    // Perform gzip compression
    var compressed = std.ArrayList(u8).init(allocator);
    errdefer compressed.deinit();

    var input_stream = std.io.fixedBufferStream(body);

    std.compress.gzip.compress(input_stream.reader(), compressed.writer(), config.level) catch {
        compressed.deinit();
        return .{ .body = null, .compressed = false };
    };

    // Only use compressed version if it's actually smaller
    if (compressed.items.len >= body.len) {
        compressed.deinit();
        return .{ .body = null, .compressed = false };
    }

    return .{
        .body = compressed.toOwnedSlice() catch {
            compressed.deinit();
            return .{ .body = null, .compressed = false };
        },
        .compressed = true,
    };
}

// Tests

test "clientAcceptsGzip detects gzip support" {
    try std.testing.expect(clientAcceptsGzip("gzip, deflate, br"));
    try std.testing.expect(clientAcceptsGzip("gzip"));
    try std.testing.expect(clientAcceptsGzip("deflate, gzip"));
    try std.testing.expect(clientAcceptsGzip("Gzip, Deflate"));
    try std.testing.expect(!clientAcceptsGzip("deflate, br"));
    try std.testing.expect(!clientAcceptsGzip("identity"));
    try std.testing.expect(!clientAcceptsGzip(null));
}

test "isCompressibleMime identifies compressible types" {
    try std.testing.expect(isCompressibleMime("text/html"));
    try std.testing.expect(isCompressibleMime("text/css"));
    try std.testing.expect(isCompressibleMime("text/plain"));
    try std.testing.expect(isCompressibleMime("application/json"));
    try std.testing.expect(isCompressibleMime("application/javascript"));
    try std.testing.expect(isCompressibleMime("application/xml"));
    try std.testing.expect(isCompressibleMime("image/svg+xml"));
    try std.testing.expect(isCompressibleMime("application/wasm"));
}

test "isCompressibleMime rejects non-compressible types" {
    try std.testing.expect(!isCompressibleMime("image/png"));
    try std.testing.expect(!isCompressibleMime("image/jpeg"));
    try std.testing.expect(!isCompressibleMime("font/woff2"));
    try std.testing.expect(!isCompressibleMime("application/gzip"));
    try std.testing.expect(!isCompressibleMime("application/octet-stream"));
}

test "compressResponse compresses text body" {
    const allocator = std.testing.allocator;
    // Create a body large enough to be worth compressing
    const body = "Hello, World! " ** 50; // 700 bytes of repetitive text

    const result = compressResponse(
        allocator,
        body,
        "text/html",
        "gzip, deflate",
        .{},
    );

    if (result.body) |compressed| {
        defer allocator.free(compressed);
        try std.testing.expect(result.compressed);
        // Compressed size should be significantly smaller for repetitive data
        try std.testing.expect(compressed.len < body.len);
    } else {
        // Compression should have worked for this input
        return error.TestUnexpectedResult;
    }
}

test "compressResponse skips small bodies" {
    const allocator = std.testing.allocator;
    const result = compressResponse(
        allocator,
        "tiny",
        "text/html",
        "gzip",
        .{},
    );
    try std.testing.expect(!result.compressed);
    try std.testing.expect(result.body == null);
}

test "compressResponse skips when client does not accept gzip" {
    const allocator = std.testing.allocator;
    const body = "x" ** 500;
    const result = compressResponse(
        allocator,
        body,
        "text/html",
        "deflate, br",
        .{},
    );
    try std.testing.expect(!result.compressed);
}

test "compressResponse skips non-compressible MIME types" {
    const allocator = std.testing.allocator;
    const body = "x" ** 500;
    const result = compressResponse(
        allocator,
        body,
        "image/png",
        "gzip",
        .{},
    );
    try std.testing.expect(!result.compressed);
}

test "compressResponse skips when disabled" {
    const allocator = std.testing.allocator;
    const body = "x" ** 500;
    const result = compressResponse(
        allocator,
        body,
        "text/html",
        "gzip",
        .{ .enabled = false },
    );
    try std.testing.expect(!result.compressed);
}

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

pub const Encoding = enum {
    gzip,
    br,

    pub fn headerValue(self: Encoding) []const u8 {
        return switch (self) {
            .gzip => "gzip",
            .br => "br",
        };
    }
};

/// Configuration for response compression.
pub const CompressionConfig = struct {
    enabled: bool = true,
    /// Minimum body size to compress.
    min_size: usize = DEFAULT_MIN_SIZE,
    /// Enable Brotli compression when library is available at runtime.
    brotli_enabled: bool = true,
    /// Brotli quality [0..11].
    brotli_quality: u32 = 5,
    /// Compression level.
    level: std.compress.gzip.Options = .{ .level = .default },
};

/// Result of attempting compression.
pub const CompressionResult = struct {
    /// Compressed body (owned by allocator). Null if compression was skipped.
    body: ?[]u8,
    /// Whether compression was applied.
    compressed: bool,
    /// Applied encoding when compressed.
    encoding: ?Encoding = null,
};

fn parseEncodingQ(raw: []const u8) f32 {
    const part = std.mem.trim(u8, raw, " \t\r\n");
    if (part.len == 0) return 1.0;
    return std.fmt.parseFloat(f32, part) catch 0.0;
}

fn parseAcceptEncodingQ(accept_encoding: []const u8, token: []const u8) f32 {
    var it = std.mem.splitScalar(u8, accept_encoding, ',');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;

        var seg_it = std.mem.splitScalar(u8, entry, ';');
        const enc = std.mem.trim(u8, seg_it.next() orelse "", " \t\r\n");
        if (!std.ascii.eqlIgnoreCase(enc, token)) continue;

        var q: f32 = 1.0;
        while (seg_it.next()) |param_raw| {
            const param = std.mem.trim(u8, param_raw, " \t\r\n");
            if (!std.ascii.startsWithIgnoreCase(param, "q=")) continue;
            q = parseEncodingQ(param[2..]);
        }
        return if (q < 0) 0 else q;
    }
    return -1.0;
}

fn pickEncoding(accept_encoding: ?[]const u8, enable_brotli: bool) ?Encoding {
    const ae = accept_encoding orelse return null;
    const br_q = if (enable_brotli) parseAcceptEncodingQ(ae, "br") else -1.0;
    const gzip_q = parseAcceptEncodingQ(ae, "gzip");
    const wildcard_q = parseAcceptEncodingQ(ae, "*");
    const identity_q = parseAcceptEncodingQ(ae, "identity");

    const br_effective = if (br_q >= 0) br_q else wildcard_q;
    const gzip_effective = if (gzip_q >= 0) gzip_q else wildcard_q;
    if (br_effective <= 0 and gzip_effective <= 0) {
        if (identity_q == 0) return null;
        return null;
    }
    if (br_effective >= gzip_effective and br_effective > 0) return .br;
    if (gzip_effective > 0) return .gzip;
    if (br_effective > 0) return .br;
    return null;
}

fn isLikelyGzip(body: []const u8) bool {
    return body.len >= 2 and body[0] == 0x1f and body[1] == 0x8b;
}

const BrotliEncoderMode = enum(c_int) {
    generic = 0,
    text = 1,
    font = 2,
};

const BrotliEncoderCompressFn = *const fn (
    quality: c_int,
    lgwin: c_int,
    mode: BrotliEncoderMode,
    input_size: usize,
    input_buffer: [*]const u8,
    encoded_size: *usize,
    encoded_buffer: [*]u8,
) callconv(.c) c_int;

const BrotliEncoderMaxCompressedSizeFn = *const fn (input_size: usize) callconv(.c) usize;

fn tryCompressBrotli(allocator: std.mem.Allocator, body: []const u8, quality: u32) ?[]u8 {
    const candidates: []const []const u8 = switch (@import("builtin").os.tag) {
        .macos, .ios, .tvos, .watchos, .visionos => &[_][]const u8{ "libbrotlienc.dylib", "/opt/homebrew/lib/libbrotlienc.dylib" },
        .linux => &[_][]const u8{ "libbrotlienc.so.1", "libbrotlienc.so" },
        else => &[_][]const u8{},
    };

    var lib_opt: ?std.DynLib = null;
    for (candidates) |name| {
        lib_opt = std.DynLib.open(name) catch null;
        if (lib_opt != null) break;
    }
    var lib = lib_opt orelse return null;
    defer lib.close();

    const max_fn = lib.lookup(BrotliEncoderMaxCompressedSizeFn, "BrotliEncoderMaxCompressedSize") orelse return null;
    const compress_fn = lib.lookup(BrotliEncoderCompressFn, "BrotliEncoderCompress") orelse return null;

    const max_size = max_fn(body.len);
    if (max_size == 0) return null;
    var out = allocator.alloc(u8, max_size) catch return null;
    defer if (out.len > 0) allocator.free(out);

    var encoded_size = max_size;
    const ok = compress_fn(
        @intCast(@min(quality, 11)),
        22,
        .generic,
        body.len,
        body.ptr,
        &encoded_size,
        out.ptr,
    );
    if (ok == 0 or encoded_size >= body.len or encoded_size == 0) return null;

    if (encoded_size == max_size) {
        const owned = out;
        out = &[_]u8{};
        return owned;
    }
    const final = allocator.alloc(u8, encoded_size) catch return null;
    @memcpy(final, out[0..encoded_size]);
    return final;
}

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

    // Check client support / preferred encoding
    const preferred = pickEncoding(accept_encoding, config.brotli_enabled) orelse return .{ .body = null, .compressed = false };

    // Check MIME type
    const mime = content_type orelse return .{ .body = null, .compressed = false };
    if (!isCompressibleMime(mime)) return .{ .body = null, .compressed = false };

    // gzip_static-like behavior: preserve already gzip-compressed payloads when accepted.
    if (preferred == .gzip and isLikelyGzip(body)) {
        const dup = allocator.dupe(u8, body) catch return .{ .body = null, .compressed = false };
        return .{ .body = dup, .compressed = true, .encoding = .gzip };
    }

    // Prefer Brotli when requested and runtime encoder is available.
    if (preferred == .br) {
        if (tryCompressBrotli(allocator, body, config.brotli_quality)) |compressed| {
            return .{ .body = compressed, .compressed = true, .encoding = .br };
        }
    }

    // Perform gzip compression
    var compressed = std.ArrayList(u8).init(allocator);
    errdefer compressed.deinit();

    var input_stream = std.io.fixedBufferStream(body);

    std.compress.gzip.compress(input_stream.reader(), compressed.writer(), config.level) catch {
        compressed.deinit();
        return .{ .body = null, .compressed = false, .encoding = null };
    };

    // Only use compressed version if it's actually smaller
    if (compressed.items.len >= body.len) {
        compressed.deinit();
        return .{ .body = null, .compressed = false, .encoding = null };
    }

    return .{
        .body = compressed.toOwnedSlice() catch {
            compressed.deinit();
            return .{ .body = null, .compressed = false, .encoding = null };
        },
        .compressed = true,
        .encoding = .gzip,
    };
}

// Tests

test "pickEncoding prefers br over gzip when both available" {
    try std.testing.expectEqual(Encoding.br, pickEncoding("gzip, br", true).?);
    try std.testing.expectEqual(Encoding.gzip, pickEncoding("gzip, br", false).?);
    try std.testing.expectEqual(Encoding.gzip, pickEncoding("gzip;q=0.8, br;q=0.2", true).?);
    try std.testing.expectEqual(Encoding.br, pickEncoding("gzip;q=0, br;q=0.5", true).?);
    try std.testing.expect(pickEncoding("identity", true) == null);
    try std.testing.expect(pickEncoding(null, true) == null);
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
        try std.testing.expectEqual(Encoding.gzip, result.encoding.?);
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
        "deflate, identity",
        .{},
    );
    try std.testing.expect(!result.compressed);
}

test "compressResponse preserves precompressed gzip payload" {
    const allocator = std.testing.allocator;
    // gzip magic bytes + dummy bytes
    const body = [_]u8{ 0x1f, 0x8b, 0x08, 0x00, 0x01, 0x02, 0x03 };
    const result = compressResponse(allocator, body[0..], "text/plain", "gzip", .{ .min_size = 0 });
    defer if (result.body) |b| allocator.free(b);
    try std.testing.expect(result.compressed);
    try std.testing.expectEqual(Encoding.gzip, result.encoding.?);
    try std.testing.expectEqualSlices(u8, body[0..], result.body.?);
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

const std = @import("std");

/// Configurable request validation limits.
///
/// Controls maximum sizes for various request components.
/// Values of 0 mean "use the parser defaults".
pub const RequestLimits = struct {
    /// Maximum request body size in bytes (0 = use default 1MB).
    max_body_size: usize,
    /// Maximum URI length in bytes (0 = use default 8KB).
    max_uri_length: usize,
    /// Maximum number of headers (0 = use default 100).
    max_header_count: usize,
    /// Maximum single header size in bytes (0 = use default 8KB).
    max_header_size: usize,
    /// Client body read timeout in milliseconds (0 = no timeout).
    body_timeout_ms: u32,
    /// Client header read timeout in milliseconds (0 = no timeout).
    header_timeout_ms: u32,

    pub const default = RequestLimits{
        .max_body_size = 1 * 1024 * 1024, // 1MB
        .max_uri_length = 8 * 1024, // 8KB
        .max_header_count = 100,
        .max_header_size = 8 * 1024, // 8KB
        .body_timeout_ms = 30_000, // 30s
        .header_timeout_ms = 10_000, // 10s
    };

    /// Effective max body size (returns default if 0).
    pub fn effectiveMaxBodySize(self: RequestLimits) usize {
        return if (self.max_body_size > 0) self.max_body_size else default.max_body_size;
    }

    /// Effective max URI length (returns default if 0).
    pub fn effectiveMaxUriLength(self: RequestLimits) usize {
        return if (self.max_uri_length > 0) self.max_uri_length else default.max_uri_length;
    }

    /// Effective max header count (returns default if 0).
    pub fn effectiveMaxHeaderCount(self: RequestLimits) usize {
        return if (self.max_header_count > 0) self.max_header_count else default.max_header_count;
    }

    /// Effective max header size (returns default if 0).
    pub fn effectiveMaxHeaderSize(self: RequestLimits) usize {
        return if (self.max_header_size > 0) self.max_header_size else default.max_header_size;
    }
};

/// Validation result with specific rejection reason.
pub const ValidationResult = union(enum) {
    ok: void,
    body_too_large: struct { size: usize, limit: usize },
    uri_too_long: struct { length: usize, limit: usize },
};

/// Validate a request body size against limits.
pub fn validateBodySize(body_len: usize, limits: RequestLimits) ValidationResult {
    const max = limits.effectiveMaxBodySize();
    if (body_len > max) {
        return .{ .body_too_large = .{ .size = body_len, .limit = max } };
    }
    return .ok;
}

/// Validate a URI length against limits.
pub fn validateUriLength(uri_len: usize, limits: RequestLimits) ValidationResult {
    const max = limits.effectiveMaxUriLength();
    if (uri_len > max) {
        return .{ .uri_too_long = .{ .length = uri_len, .limit = max } };
    }
    return .ok;
}

/// Format a human-readable rejection message.
pub fn rejectionMessage(result: ValidationResult, buf: []u8) []const u8 {
    return switch (result) {
        .ok => "OK",
        .body_too_large => |info| std.fmt.bufPrint(buf, "Request body too large: {d} bytes exceeds {d} byte limit", .{ info.size, info.limit }) catch "Request body too large",
        .uri_too_long => |info| std.fmt.bufPrint(buf, "URI too long: {d} bytes exceeds {d} byte limit", .{ info.length, info.limit }) catch "URI too long",
    };
}

// Tests

test "RequestLimits default values" {
    const limits = RequestLimits.default;
    try std.testing.expectEqual(@as(usize, 1 * 1024 * 1024), limits.max_body_size);
    try std.testing.expectEqual(@as(usize, 8 * 1024), limits.max_uri_length);
    try std.testing.expectEqual(@as(usize, 100), limits.max_header_count);
    try std.testing.expectEqual(@as(u32, 30_000), limits.body_timeout_ms);
    try std.testing.expectEqual(@as(u32, 10_000), limits.header_timeout_ms);
}

test "RequestLimits effective returns custom values" {
    const limits = RequestLimits{
        .max_body_size = 512,
        .max_uri_length = 256,
        .max_header_count = 50,
        .max_header_size = 4096,
        .body_timeout_ms = 5000,
        .header_timeout_ms = 2000,
    };
    try std.testing.expectEqual(@as(usize, 512), limits.effectiveMaxBodySize());
    try std.testing.expectEqual(@as(usize, 256), limits.effectiveMaxUriLength());
    try std.testing.expectEqual(@as(usize, 50), limits.effectiveMaxHeaderCount());
    try std.testing.expectEqual(@as(usize, 4096), limits.effectiveMaxHeaderSize());
}

test "RequestLimits effective falls back to default when 0" {
    const limits = RequestLimits{
        .max_body_size = 0,
        .max_uri_length = 0,
        .max_header_count = 0,
        .max_header_size = 0,
        .body_timeout_ms = 0,
        .header_timeout_ms = 0,
    };
    try std.testing.expectEqual(RequestLimits.default.max_body_size, limits.effectiveMaxBodySize());
    try std.testing.expectEqual(RequestLimits.default.max_uri_length, limits.effectiveMaxUriLength());
}

test "validateBodySize accepts under limit" {
    const limits = RequestLimits{ .max_body_size = 1024, .max_uri_length = 0, .max_header_count = 0, .max_header_size = 0, .body_timeout_ms = 0, .header_timeout_ms = 0 };
    try std.testing.expectEqual(ValidationResult.ok, validateBodySize(512, limits));
    try std.testing.expectEqual(ValidationResult.ok, validateBodySize(1024, limits));
}

test "validateBodySize rejects over limit" {
    const limits = RequestLimits{ .max_body_size = 1024, .max_uri_length = 0, .max_header_count = 0, .max_header_size = 0, .body_timeout_ms = 0, .header_timeout_ms = 0 };
    const result = validateBodySize(2048, limits);
    switch (result) {
        .body_too_large => |info| {
            try std.testing.expectEqual(@as(usize, 2048), info.size);
            try std.testing.expectEqual(@as(usize, 1024), info.limit);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "validateUriLength accepts under limit" {
    const limits = RequestLimits{ .max_body_size = 0, .max_uri_length = 256, .max_header_count = 0, .max_header_size = 0, .body_timeout_ms = 0, .header_timeout_ms = 0 };
    try std.testing.expectEqual(ValidationResult.ok, validateUriLength(100, limits));
}

test "validateUriLength rejects over limit" {
    const limits = RequestLimits{ .max_body_size = 0, .max_uri_length = 256, .max_header_count = 0, .max_header_size = 0, .body_timeout_ms = 0, .header_timeout_ms = 0 };
    const result = validateUriLength(512, limits);
    switch (result) {
        .uri_too_long => |info| {
            try std.testing.expectEqual(@as(usize, 512), info.length);
            try std.testing.expectEqual(@as(usize, 256), info.limit);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "rejectionMessage formats body_too_large" {
    const result = ValidationResult{ .body_too_large = .{ .size = 2048, .limit = 1024 } };
    var buf: [256]u8 = undefined;
    const msg = rejectionMessage(result, &buf);
    try std.testing.expect(std.mem.indexOf(u8, msg, "2048") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "1024") != null);
}

test "rejectionMessage formats uri_too_long" {
    const result = ValidationResult{ .uri_too_long = .{ .length = 10000, .limit = 8192 } };
    var buf: [256]u8 = undefined;
    const msg = rejectionMessage(result, &buf);
    try std.testing.expect(std.mem.indexOf(u8, msg, "10000") != null);
}

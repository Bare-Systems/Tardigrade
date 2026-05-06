const std = @import("std");
const compat = @import("../zig_compat.zig");
const Response = @import("response.zig").Response;

/// Cache-Control directives configuration.
pub const CachePolicy = struct {
    /// max-age in seconds (0 means don't set max-age).
    max_age: u32 = 0,
    /// Whether the response may be stored by any cache.
    public: bool = false,
    /// Whether the response is for a single user only.
    private: bool = false,
    /// Require revalidation before using cached copy.
    no_cache: bool = false,
    /// Do not store any part of the request/response.
    no_store: bool = false,
    /// Require revalidation once stale.
    must_revalidate: bool = false,
    /// Shared caches must revalidate once stale.
    proxy_revalidate: bool = false,
    /// Immutable — content will never change during max-age.
    immutable: bool = false,

    /// No caching at all — suitable for sensitive or dynamic content.
    pub const no_caching = CachePolicy{
        .no_cache = true,
        .no_store = true,
        .must_revalidate = true,
    };

    /// Static assets with long cache lifetime (1 year, immutable).
    pub const static_immutable = CachePolicy{
        .public = true,
        .max_age = 31_536_000, // 1 year
        .immutable = true,
    };

    /// Standard static file caching (1 hour, public).
    pub const static_default = CachePolicy{
        .public = true,
        .max_age = 3600, // 1 hour
    };

    /// API response — short cache or revalidate.
    pub const api_default = CachePolicy{
        .no_cache = true,
        .must_revalidate = true,
    };

    /// Format the Cache-Control header value into the provided buffer.
    pub fn format(self: CachePolicy, buf: []u8) []const u8 {
        var stream = compat.fixedBufferStream(buf);
        const writer = stream.writer();
        var first = true;

        const directives = .{
            .{ self.public, "public" },
            .{ self.private, "private" },
            .{ self.no_cache, "no-cache" },
            .{ self.no_store, "no-store" },
            .{ self.must_revalidate, "must-revalidate" },
            .{ self.proxy_revalidate, "proxy-revalidate" },
            .{ self.immutable, "immutable" },
        };

        inline for (directives) |d| {
            if (d[0]) {
                if (!first) writer.writeAll(", ") catch return stream.getWritten();
                writer.writeAll(d[1]) catch return stream.getWritten();
                first = false;
            }
        }

        if (self.max_age > 0) {
            if (!first) writer.writeAll(", ") catch return stream.getWritten();
            writer.print("max-age={d}", .{self.max_age}) catch return stream.getWritten();
        }

        return stream.getWritten();
    }

    /// Apply Cache-Control and Expires headers to a response.
    pub fn apply(self: CachePolicy, response: *Response) void {
        var buf: [256]u8 = undefined;
        const value = self.format(&buf);
        if (value.len > 0) {
            _ = response.setHeader("Cache-Control", value);
        }

        // Set Expires header if max-age is specified
        if (self.max_age > 0) {
            var expires_buf: [40]u8 = undefined;
            const expires = formatExpires(self.max_age, &expires_buf);
            _ = response.setHeader("Expires", expires);
        }
    }
};

/// Choose a cache policy based on Content-Type / MIME type.
pub fn policyForMimeType(mime: []const u8) CachePolicy {
    // Immutable fingerprinted assets
    if (std.mem.find(u8, mime, "font/") != null) {
        return CachePolicy.static_immutable;
    }

    // Long-cache static assets
    if (std.mem.find(u8, mime, "image/") != null) {
        return .{ .public = true, .max_age = 86_400 }; // 1 day
    }
    if (endsWith(mime, "/css") or endsWith(mime, "/javascript") or endsWith(mime, "/js")) {
        return .{ .public = true, .max_age = 3600 }; // 1 hour
    }

    // HTML — short cache with revalidation
    if (std.mem.find(u8, mime, "text/html") != null) {
        return .{ .public = true, .max_age = 300, .must_revalidate = true }; // 5 min
    }

    // API / JSON
    if (std.mem.find(u8, mime, "application/json") != null) {
        return CachePolicy.api_default;
    }

    // Default: short cache
    return CachePolicy.static_default;
}

/// Format an RFC 7231 Expires date given a max-age offset from now.
fn formatExpires(max_age: u32, buf: *[40]u8) []const u8 {
    const now = compat.unixTimestamp();
    const expires_ts = now + @as(i64, max_age);
    const epoch_secs: std.time.epoch.EpochSeconds = .{ .secs = @intCast(expires_ts) };
    const day_secs = epoch_secs.getDaySeconds();
    const epoch_day = epoch_secs.getEpochDay();
    const year_day = epoch_day.calculateYearDay();
    const month_day = year_day.calculateMonthDay();

    const day_names = [_][]const u8{ "Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed" };
    const month_names = [_][]const u8{ "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };

    const day_of_week = @mod(epoch_day.day, 7);

    return std.fmt.bufPrint(buf, "{s}, {d:0>2} {s} {d} {d:0>2}:{d:0>2}:{d:0>2} GMT", .{
        day_names[day_of_week],
        month_day.day_index + 1,
        month_names[@intFromEnum(month_day.month) - 1],
        year_day.year,
        day_secs.getHoursIntoDay(),
        day_secs.getMinutesIntoHour(),
        day_secs.getSecondsIntoMinute(),
    }) catch "Thu, 01 Jan 1970 00:00:00 GMT";
}

fn endsWith(haystack: []const u8, suffix: []const u8) bool {
    return std.mem.endsWith(u8, haystack, suffix);
}

// Tests

test "CachePolicy.format empty policy" {
    const policy = CachePolicy{};
    var buf: [256]u8 = undefined;
    const result = policy.format(&buf);
    try std.testing.expectEqualStrings("", result);
}

test "CachePolicy.format no_caching preset" {
    var buf: [256]u8 = undefined;
    const result = CachePolicy.no_caching.format(&buf);
    try std.testing.expect(std.mem.find(u8, result, "no-cache") != null);
    try std.testing.expect(std.mem.find(u8, result, "no-store") != null);
    try std.testing.expect(std.mem.find(u8, result, "must-revalidate") != null);
}

test "CachePolicy.format static_immutable preset" {
    var buf: [256]u8 = undefined;
    const result = CachePolicy.static_immutable.format(&buf);
    try std.testing.expect(std.mem.find(u8, result, "public") != null);
    try std.testing.expect(std.mem.find(u8, result, "immutable") != null);
    try std.testing.expect(std.mem.find(u8, result, "max-age=31536000") != null);
}

test "CachePolicy.format static_default preset" {
    var buf: [256]u8 = undefined;
    const result = CachePolicy.static_default.format(&buf);
    try std.testing.expect(std.mem.find(u8, result, "public") != null);
    try std.testing.expect(std.mem.find(u8, result, "max-age=3600") != null);
}

test "CachePolicy.format custom policy" {
    const policy = CachePolicy{
        .private = true,
        .max_age = 600,
        .must_revalidate = true,
    };
    var buf: [256]u8 = undefined;
    const result = policy.format(&buf);
    try std.testing.expect(std.mem.find(u8, result, "private") != null);
    try std.testing.expect(std.mem.find(u8, result, "must-revalidate") != null);
    try std.testing.expect(std.mem.find(u8, result, "max-age=600") != null);
    // Should not contain public
    try std.testing.expect(std.mem.find(u8, result, "public") == null);
}

test "policyForMimeType returns correct policies" {
    // Image
    const img_policy = policyForMimeType("image/png");
    try std.testing.expect(img_policy.public);
    try std.testing.expectEqual(@as(u32, 86_400), img_policy.max_age);

    // CSS
    const css_policy = policyForMimeType("text/css");
    try std.testing.expect(css_policy.public);
    try std.testing.expectEqual(@as(u32, 3600), css_policy.max_age);

    // HTML
    const html_policy = policyForMimeType("text/html");
    try std.testing.expect(html_policy.must_revalidate);
    try std.testing.expectEqual(@as(u32, 300), html_policy.max_age);

    // JSON
    const json_policy = policyForMimeType("application/json");
    try std.testing.expect(json_policy.no_cache);
    try std.testing.expect(json_policy.must_revalidate);

    // Font
    const font_policy = policyForMimeType("font/woff2");
    try std.testing.expect(font_policy.immutable);
    try std.testing.expectEqual(@as(u32, 31_536_000), font_policy.max_age);
}

test "CachePolicy.apply sets headers" {
    const allocator = std.testing.allocator;
    const policy = CachePolicy{
        .public = true,
        .max_age = 3600,
    };
    var response = Response.init(allocator);
    defer response.deinit();

    policy.apply(&response);

    // Check Cache-Control header was set
    const cc = response.headers.get("Cache-Control");
    try std.testing.expect(cc != null);
    try std.testing.expect(std.mem.find(u8, cc.?, "public") != null);
    try std.testing.expect(std.mem.find(u8, cc.?, "max-age=3600") != null);

    // Check Expires header was set
    const exp = response.headers.get("Expires");
    try std.testing.expect(exp != null);
    try std.testing.expect(std.mem.find(u8, exp.?, "GMT") != null);
}

test "formatExpires produces valid HTTP date" {
    var buf: [40]u8 = undefined;
    const result = formatExpires(3600, &buf);
    try std.testing.expect(std.mem.find(u8, result, "GMT") != null);
    try std.testing.expect(result.len >= 25);
}

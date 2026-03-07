const std = @import("std");
const Allocator = std.mem.Allocator;

/// Token-bucket rate limiter keyed by client IP.
///
/// Each bucket starts with `burst` tokens. Tokens are consumed on each
/// request and refilled at `rate` tokens per second. When a bucket is
/// empty the request is rejected (429 Too Many Requests).
pub const RateLimiter = struct {
    allocator: Allocator,
    buckets: std.StringHashMap(Bucket),
    rate: f64, // tokens per second
    burst: u32, // max tokens (burst capacity)
    cleanup_interval_ns: i128, // how often to prune stale entries
    last_cleanup: i128,

    const Bucket = struct {
        tokens: f64,
        last_refill: i128, // nanosecond timestamp
    };

    pub fn init(allocator: Allocator, rate: f64, burst: u32) RateLimiter {
        return .{
            .allocator = allocator,
            .buckets = std.StringHashMap(Bucket).init(allocator),
            .rate = rate,
            .burst = burst,
            .cleanup_interval_ns = 60 * std.time.ns_per_s, // 60 seconds
            .last_cleanup = std.time.nanoTimestamp(),
        };
    }

    pub fn deinit(self: *RateLimiter) void {
        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.buckets.deinit();
    }

    /// Check whether `key` is allowed. Returns remaining tokens if allowed,
    /// or null if the request should be rejected.
    pub fn allow(self: *RateLimiter, key: []const u8) ?AllowResult {
        const now = std.time.nanoTimestamp();

        // Periodic cleanup of stale buckets
        if (now - self.last_cleanup > self.cleanup_interval_ns) {
            self.cleanup(now);
            self.last_cleanup = now;
        }

        if (self.buckets.getPtr(key)) |bucket| {
            self.refill(bucket, now);
            if (bucket.tokens >= 1.0) {
                bucket.tokens -= 1.0;
                return .{
                    .remaining = @intFromFloat(@max(0.0, bucket.tokens)),
                    .limit = self.burst,
                };
            }
            return null; // rate limited
        }

        // New client: create bucket with burst-1 tokens (this request consumes one)
        const owned_key = self.allocator.dupe(u8, key) catch return null;
        self.buckets.put(owned_key, .{
            .tokens = @as(f64, @floatFromInt(self.burst)) - 1.0,
            .last_refill = now,
        }) catch {
            self.allocator.free(owned_key);
            return null;
        };

        return .{
            .remaining = self.burst - 1,
            .limit = self.burst,
        };
    }

    fn refill(self: *RateLimiter, bucket: *Bucket, now: i128) void {
        const elapsed_ns = now - bucket.last_refill;
        if (elapsed_ns <= 0) return;

        const elapsed_secs: f64 = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(std.time.ns_per_s));
        const new_tokens = elapsed_secs * self.rate;
        bucket.tokens = @min(bucket.tokens + new_tokens, @as(f64, @floatFromInt(self.burst)));
        bucket.last_refill = now;
    }

    fn cleanup(self: *RateLimiter, now: i128) void {
        const stale_threshold_ns: i128 = 300 * std.time.ns_per_s; // 5 minutes
        var keys_to_remove = std.ArrayList([]const u8).init(self.allocator);
        defer keys_to_remove.deinit();

        var it = self.buckets.iterator();
        while (it.next()) |entry| {
            if (now - entry.value_ptr.last_refill > stale_threshold_ns) {
                keys_to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (keys_to_remove.items) |key| {
            _ = self.buckets.remove(key);
            self.allocator.free(key);
        }
    }

    /// Format X-RateLimit-* response headers into provided buffer.
    pub fn formatHeaders(result: AllowResult, buf: *[256]u8) RateLimitHeaders {
        const remaining_len = std.fmt.bufPrint(buf[0..32], "{d}", .{result.remaining}) catch return .{ .remaining = "0", .limit = "0" };
        const limit_len = std.fmt.bufPrint(buf[32..64], "{d}", .{result.limit}) catch return .{ .remaining = "0", .limit = "0" };
        return .{
            .remaining = buf[0..remaining_len.len],
            .limit = buf[32 .. 32 + limit_len.len],
        };
    }
};

pub const AllowResult = struct {
    remaining: u32,
    limit: u32,
};

pub const RateLimitHeaders = struct {
    remaining: []const u8,
    limit: []const u8,
};

// Tests

test "rate limiter allows requests within burst" {
    const allocator = std.testing.allocator;
    var limiter = RateLimiter.init(allocator, 10.0, 5);
    defer limiter.deinit();

    // First 5 requests should succeed (burst = 5)
    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        const result = limiter.allow("192.168.1.1");
        try std.testing.expect(result != null);
    }
}

test "rate limiter rejects when burst exhausted" {
    const allocator = std.testing.allocator;
    var limiter = RateLimiter.init(allocator, 0.001, 2); // very slow refill
    defer limiter.deinit();

    // Use up all tokens
    _ = limiter.allow("10.0.0.1");
    _ = limiter.allow("10.0.0.1");

    // Next request should be rejected
    const result = limiter.allow("10.0.0.1");
    try std.testing.expect(result == null);
}

test "rate limiter tracks keys independently" {
    const allocator = std.testing.allocator;
    var limiter = RateLimiter.init(allocator, 1.0, 1);
    defer limiter.deinit();

    const r1 = limiter.allow("client-a");
    try std.testing.expect(r1 != null);

    const r2 = limiter.allow("client-b");
    try std.testing.expect(r2 != null);

    // client-a is now exhausted
    try std.testing.expect(limiter.allow("client-a") == null);

    // client-b is also exhausted
    try std.testing.expect(limiter.allow("client-b") == null);
}

test "formatHeaders produces valid strings" {
    var buf: [256]u8 = undefined;
    const headers = RateLimiter.formatHeaders(.{ .remaining = 42, .limit = 100 }, &buf);
    try std.testing.expectEqualStrings("42", headers.remaining);
    try std.testing.expectEqualStrings("100", headers.limit);
}

const std = @import("std");

pub const EdgeConfig = struct {
    listen_host: []const u8,
    listen_port: u16,
    tls_cert_path: []const u8,
    tls_key_path: []const u8,
    upstream_base_url: []const u8,
    auth_token_hashes: [][]const u8,
    max_message_chars: usize,
    upstream_timeout_ms: u32,
    /// Requests per second per client IP (0 = disabled).
    rate_limit_rps: f64,
    /// Burst capacity for rate limiter.
    rate_limit_burst: u32,
    /// Whether to add security headers to responses.
    security_headers_enabled: bool,
    /// Idempotency cache TTL in seconds (0 = disabled).
    idempotency_ttl_seconds: u32,

    pub fn deinit(self: *EdgeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.listen_host);
        allocator.free(self.tls_cert_path);
        allocator.free(self.tls_key_path);
        allocator.free(self.upstream_base_url);
        for (self.auth_token_hashes) |h| allocator.free(h);
        allocator.free(self.auth_token_hashes);
        self.* = undefined;
    }
};

pub fn loadFromEnv(allocator: std.mem.Allocator) !EdgeConfig {
    const listen_host = envOrDefault(allocator, "TARDIGRADE_LISTEN_HOST", "0.0.0.0") catch unreachable;
    errdefer allocator.free(listen_host);

    const listen_port_str = envOrDefault(allocator, "TARDIGRADE_LISTEN_PORT", "8069") catch unreachable;
    defer allocator.free(listen_port_str);
    const listen_port = std.fmt.parseInt(u16, listen_port_str, 10) catch 8069;

    const tls_cert_path = envOrDefault(allocator, "TARDIGRADE_TLS_CERT_PATH", "") catch unreachable;
    errdefer allocator.free(tls_cert_path);

    const tls_key_path = envOrDefault(allocator, "TARDIGRADE_TLS_KEY_PATH", "") catch unreachable;
    errdefer allocator.free(tls_key_path);

    const upstream_base_url = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_BASE_URL", "http://127.0.0.1:8080") catch unreachable;
    errdefer allocator.free(upstream_base_url);

    const max_message_chars_str = envOrDefault(allocator, "TARDIGRADE_MAX_MESSAGE_CHARS", "4000") catch unreachable;
    defer allocator.free(max_message_chars_str);
    const max_message_chars = std.fmt.parseInt(usize, max_message_chars_str, 10) catch 4000;

    const timeout_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TIMEOUT_MS", "10000") catch unreachable;
    defer allocator.free(timeout_str);
    const upstream_timeout_ms = std.fmt.parseInt(u32, timeout_str, 10) catch 10000;

    const raw_hashes = envOrDefault(allocator, "TARDIGRADE_AUTH_TOKEN_HASHES", "") catch unreachable;
    defer allocator.free(raw_hashes);
    const hashes = try parseHashes(allocator, raw_hashes);

    const rate_rps_str = envOrDefault(allocator, "TARDIGRADE_RATE_LIMIT_RPS", "10") catch unreachable;
    defer allocator.free(rate_rps_str);
    const rate_limit_rps = std.fmt.parseFloat(f64, rate_rps_str) catch 10.0;

    const rate_burst_str = envOrDefault(allocator, "TARDIGRADE_RATE_LIMIT_BURST", "20") catch unreachable;
    defer allocator.free(rate_burst_str);
    const rate_limit_burst = std.fmt.parseInt(u32, rate_burst_str, 10) catch 20;

    const sec_headers_str = envOrDefault(allocator, "TARDIGRADE_SECURITY_HEADERS", "true") catch unreachable;
    defer allocator.free(sec_headers_str);
    const security_headers_enabled = std.mem.eql(u8, sec_headers_str, "true") or std.mem.eql(u8, sec_headers_str, "1");

    const idem_ttl_str = envOrDefault(allocator, "TARDIGRADE_IDEMPOTENCY_TTL", "300") catch unreachable;
    defer allocator.free(idem_ttl_str);
    const idempotency_ttl_seconds = std.fmt.parseInt(u32, idem_ttl_str, 10) catch 300;

    return .{
        .listen_host = listen_host,
        .listen_port = listen_port,
        .tls_cert_path = tls_cert_path,
        .tls_key_path = tls_key_path,
        .upstream_base_url = upstream_base_url,
        .auth_token_hashes = hashes,
        .max_message_chars = max_message_chars,
        .upstream_timeout_ms = upstream_timeout_ms,
        .rate_limit_rps = rate_limit_rps,
        .rate_limit_burst = rate_limit_burst,
        .security_headers_enabled = security_headers_enabled,
        .idempotency_ttl_seconds = idempotency_ttl_seconds,
    };
}

fn envOrDefault(allocator: std.mem.Allocator, key: []const u8, default_value: []const u8) ![]u8 {
    return std.process.getEnvVarOwned(allocator, key) catch try allocator.dupe(u8, default_value);
}

fn parseHashes(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (out.items) |h| allocator.free(h);
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        if (trimmed.len != 64) return error.InvalidTokenHashLength;

        var lower = try allocator.alloc(u8, trimmed.len);
        for (trimmed, 0..) |c, i| {
            if (!std.ascii.isHex(c)) {
                allocator.free(lower);
                return error.InvalidTokenHashHex;
            }
            lower[i] = std.ascii.toLower(c);
        }
        try out.append(lower);
    }

    return out.toOwnedSlice();
}

pub fn hasTlsFiles(cfg: *const EdgeConfig) bool {
    return cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0;
}

test "parse token hashes from csv" {
    const allocator = std.testing.allocator;
    const hashes = try parseHashes(allocator, "aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11aa11, BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22BB22");
    defer {
        for (hashes) |h| allocator.free(h);
        allocator.free(hashes);
    }

    try std.testing.expectEqual(@as(usize, 2), hashes.len);
    try std.testing.expectEqualStrings("bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22bb22", hashes[1]);
}

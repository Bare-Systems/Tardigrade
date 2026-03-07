const std = @import("std");
const http = @import("http.zig");

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
    /// Session idle TTL in seconds (0 = sessions disabled).
    session_ttl_seconds: u32,
    /// Maximum concurrent sessions (0 = unlimited).
    session_max: u32,
    /// IP access control rules (empty = disabled).
    /// Format: "allow 10.0.0.0/8, deny 0.0.0.0/0"
    access_control_rules: []const u8,
    /// Request validation limits.
    request_limits: http.request_limits.RequestLimits,
    /// Basic auth credential hashes (SHA-256 of "user:password", empty = disabled).
    basic_auth_hashes: [][]const u8,
    /// Minimum log level (debug, info, warn, error).
    log_level: http.logger.Level,
    /// Whether response compression is enabled.
    compression_enabled: bool,
    /// Minimum response body size to compress (bytes).
    compression_min_size: usize,

    pub fn deinit(self: *EdgeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.listen_host);
        allocator.free(self.tls_cert_path);
        allocator.free(self.tls_key_path);
        allocator.free(self.upstream_base_url);
        for (self.auth_token_hashes) |h| allocator.free(h);
        allocator.free(self.auth_token_hashes);
        allocator.free(self.access_control_rules);
        for (self.basic_auth_hashes) |h| allocator.free(h);
        allocator.free(self.basic_auth_hashes);
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

    const session_ttl_str = envOrDefault(allocator, "TARDIGRADE_SESSION_TTL", "3600") catch unreachable;
    defer allocator.free(session_ttl_str);
    const session_ttl_seconds = std.fmt.parseInt(u32, session_ttl_str, 10) catch 3600;

    const session_max_str = envOrDefault(allocator, "TARDIGRADE_SESSION_MAX", "1000") catch unreachable;
    defer allocator.free(session_max_str);
    const session_max = std.fmt.parseInt(u32, session_max_str, 10) catch 1000;

    const access_control_rules = envOrDefault(allocator, "TARDIGRADE_ACCESS_CONTROL", "") catch unreachable;
    errdefer allocator.free(access_control_rules);

    // Request limits
    const max_body_str = envOrDefault(allocator, "TARDIGRADE_MAX_BODY_SIZE", "0") catch unreachable;
    defer allocator.free(max_body_str);
    const max_body_size = std.fmt.parseInt(usize, max_body_str, 10) catch 0;

    const max_uri_str = envOrDefault(allocator, "TARDIGRADE_MAX_URI_LENGTH", "0") catch unreachable;
    defer allocator.free(max_uri_str);
    const max_uri_length = std.fmt.parseInt(usize, max_uri_str, 10) catch 0;

    const max_hdr_count_str = envOrDefault(allocator, "TARDIGRADE_MAX_HEADER_COUNT", "0") catch unreachable;
    defer allocator.free(max_hdr_count_str);
    const max_header_count = std.fmt.parseInt(usize, max_hdr_count_str, 10) catch 0;

    const max_hdr_size_str = envOrDefault(allocator, "TARDIGRADE_MAX_HEADER_SIZE", "0") catch unreachable;
    defer allocator.free(max_hdr_size_str);
    const max_header_size = std.fmt.parseInt(usize, max_hdr_size_str, 10) catch 0;

    const body_timeout_str = envOrDefault(allocator, "TARDIGRADE_BODY_TIMEOUT_MS", "0") catch unreachable;
    defer allocator.free(body_timeout_str);
    const body_timeout_ms = std.fmt.parseInt(u32, body_timeout_str, 10) catch 0;

    const header_timeout_str = envOrDefault(allocator, "TARDIGRADE_HEADER_TIMEOUT_MS", "0") catch unreachable;
    defer allocator.free(header_timeout_str);
    const header_timeout_ms = std.fmt.parseInt(u32, header_timeout_str, 10) catch 0;

    // Basic auth
    const raw_basic_hashes = envOrDefault(allocator, "TARDIGRADE_BASIC_AUTH_HASHES", "") catch unreachable;
    defer allocator.free(raw_basic_hashes);
    const basic_auth_hashes = try parseHashes(allocator, raw_basic_hashes);

    // Log level
    const log_level_str = envOrDefault(allocator, "TARDIGRADE_LOG_LEVEL", "info") catch unreachable;
    defer allocator.free(log_level_str);
    const log_level = http.logger.Level.parse(log_level_str) orelse .info;

    // Compression
    const comp_enabled_str = envOrDefault(allocator, "TARDIGRADE_COMPRESSION_ENABLED", "true") catch unreachable;
    defer allocator.free(comp_enabled_str);
    const compression_enabled = std.mem.eql(u8, comp_enabled_str, "true") or std.mem.eql(u8, comp_enabled_str, "1");

    const comp_min_str = envOrDefault(allocator, "TARDIGRADE_COMPRESSION_MIN_SIZE", "256") catch unreachable;
    defer allocator.free(comp_min_str);
    const compression_min_size = std.fmt.parseInt(usize, comp_min_str, 10) catch 256;

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
        .session_ttl_seconds = session_ttl_seconds,
        .session_max = session_max,
        .access_control_rules = access_control_rules,
        .request_limits = .{
            .max_body_size = max_body_size,
            .max_uri_length = max_uri_length,
            .max_header_count = max_header_count,
            .max_header_size = max_header_size,
            .body_timeout_ms = body_timeout_ms,
            .header_timeout_ms = header_timeout_ms,
        },
        .basic_auth_hashes = basic_auth_hashes,
        .log_level = log_level,
        .compression_enabled = compression_enabled,
        .compression_min_size = compression_min_size,
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

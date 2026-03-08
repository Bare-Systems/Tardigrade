const std = @import("std");
const http = @import("http.zig");

pub const UpstreamLbAlgorithm = enum {
    round_robin,
    least_connections,
    ip_hash,

    pub fn parse(value: []const u8) ?UpstreamLbAlgorithm {
        if (std.ascii.eqlIgnoreCase(value, "round_robin") or std.ascii.eqlIgnoreCase(value, "round-robin")) return .round_robin;
        if (std.ascii.eqlIgnoreCase(value, "least_connections") or std.ascii.eqlIgnoreCase(value, "least-connections")) return .least_connections;
        if (std.ascii.eqlIgnoreCase(value, "ip_hash") or std.ascii.eqlIgnoreCase(value, "ip-hash")) return .ip_hash;
        return null;
    }
};

pub const EdgeConfig = struct {
    listen_host: []const u8,
    listen_port: u16,
    tls_cert_path: []const u8,
    tls_key_path: []const u8,
    upstream_base_url: []const u8,
    upstream_base_urls: [][]const u8,
    upstream_lb_algorithm: UpstreamLbAlgorithm,
    /// Proxy target for /v1/chat. Supports absolute URL or path.
    proxy_pass_chat: []const u8,
    /// Proxy target prefix for /v1/commands upstream subpaths.
    /// Supports absolute URL prefix or path prefix.
    proxy_pass_commands_prefix: []const u8,
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
    /// Circuit breaker failure threshold (0 = disabled).
    cb_threshold: u32,
    /// Circuit breaker open timeout in milliseconds before half-open probe.
    cb_timeout_ms: u64,
    /// Number of worker threads for connection handling (0 = auto CPU count).
    worker_threads: u32,
    /// Maximum queued accepted connections waiting for workers.
    worker_queue_size: usize,
    /// Desired soft file-descriptor limit (RLIMIT_NOFILE). 0 leaves OS default.
    fd_soft_limit: u64,
    /// Maximum active connections per client IP (0 = unlimited).
    max_connections_per_ip: u32,
    /// Maximum total active client connections across all IPs (0 = unlimited).
    max_active_connections: u32,
    /// Idle keep-alive timeout for client connections (ms, 0 = disabled).
    keep_alive_timeout_ms: u32,
    /// Maximum requests served per client connection (0 = unlimited).
    max_requests_per_connection: u32,
    /// Maximum idle connection sessions cached for reuse.
    connection_pool_size: usize,
    /// Maximum in-memory bytes retained per active connection (0 = unlimited).
    max_connection_memory_bytes: usize,
    /// Maximum estimated total connection memory across active clients (0 = unlimited).
    max_total_connection_memory_bytes: usize,
    /// Whether to stream all upstream statuses directly (including non-200) instead of mapping.
    proxy_stream_all_statuses: bool,
    /// Number of upstream attempt retries for proxy requests (minimum 1).
    upstream_retry_attempts: u32,
    /// Total timeout budget across all upstream attempts for a request (ms, 0 = disabled).
    upstream_timeout_budget_ms: u64,
    /// Passive health threshold: mark upstream as failed after this many failed attempts (0 = disabled).
    upstream_max_fails: u32,
    /// Passive health timeout (ms) for failed upstreams before retry eligibility.
    upstream_fail_timeout_ms: u64,
    /// Active health-check probe interval (ms, 0 = disabled).
    upstream_active_health_interval_ms: u64,
    /// Active health-check probe path.
    upstream_active_health_path: []const u8,
    /// Active health-check per-probe timeout in ms.
    upstream_active_health_timeout_ms: u32,
    /// Consecutive active probe failures required before marking backend unhealthy.
    upstream_active_health_fail_threshold: u32,
    /// Consecutive active probe successes required before clearing unhealthy state.
    upstream_active_health_success_threshold: u32,
    /// Slow-start window (ms) for recovered upstreams before receiving full traffic (0 = disabled).
    upstream_slow_start_ms: u64,

    pub fn deinit(self: *EdgeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.listen_host);
        allocator.free(self.tls_cert_path);
        allocator.free(self.tls_key_path);
        allocator.free(self.upstream_base_url);
        for (self.upstream_base_urls) |u| allocator.free(u);
        allocator.free(self.upstream_base_urls);
        allocator.free(self.proxy_pass_chat);
        allocator.free(self.proxy_pass_commands_prefix);
        for (self.auth_token_hashes) |h| allocator.free(h);
        allocator.free(self.auth_token_hashes);
        allocator.free(self.access_control_rules);
        for (self.basic_auth_hashes) |h| allocator.free(h);
        allocator.free(self.basic_auth_hashes);
        allocator.free(self.upstream_active_health_path);
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
    const upstream_base_urls_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_BASE_URLS", "") catch unreachable;
    defer allocator.free(upstream_base_urls_raw);
    const upstream_base_urls = try parseCsvValues(allocator, upstream_base_urls_raw);
    errdefer {
        for (upstream_base_urls) |u| allocator.free(u);
        allocator.free(upstream_base_urls);
    }
    const lb_algo_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_LB_ALGORITHM", "round_robin") catch unreachable;
    defer allocator.free(lb_algo_str);
    const upstream_lb_algorithm = UpstreamLbAlgorithm.parse(lb_algo_str) orelse .round_robin;
    const proxy_pass_chat = envOrDefault(allocator, "TARDIGRADE_PROXY_PASS_CHAT", "/v1/chat") catch unreachable;
    errdefer allocator.free(proxy_pass_chat);
    const proxy_pass_commands_prefix = envOrDefault(allocator, "TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX", "") catch unreachable;
    errdefer allocator.free(proxy_pass_commands_prefix);

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

    // Circuit breaker
    const cb_threshold_str = envOrDefault(allocator, "TARDIGRADE_CB_THRESHOLD", "0") catch unreachable;
    defer allocator.free(cb_threshold_str);
    const cb_threshold = std.fmt.parseInt(u32, cb_threshold_str, 10) catch 0;

    const cb_timeout_str = envOrDefault(allocator, "TARDIGRADE_CB_TIMEOUT_MS", "30000") catch unreachable;
    defer allocator.free(cb_timeout_str);
    const cb_timeout_ms = std.fmt.parseInt(u64, cb_timeout_str, 10) catch 30_000;

    // Worker pool
    const worker_threads_str = envOrDefault(allocator, "TARDIGRADE_WORKER_THREADS", "0") catch unreachable;
    defer allocator.free(worker_threads_str);
    const worker_threads = std.fmt.parseInt(u32, worker_threads_str, 10) catch 0;

    const worker_queue_str = envOrDefault(allocator, "TARDIGRADE_WORKER_QUEUE_SIZE", "1024") catch unreachable;
    defer allocator.free(worker_queue_str);
    const worker_queue_size = std.fmt.parseInt(usize, worker_queue_str, 10) catch 1024;

    const fd_soft_limit_str = envOrDefault(allocator, "TARDIGRADE_FD_SOFT_LIMIT", "0") catch unreachable;
    defer allocator.free(fd_soft_limit_str);
    const fd_soft_limit = std.fmt.parseInt(u64, fd_soft_limit_str, 10) catch 0;

    const max_conn_ip_str = envOrDefault(allocator, "TARDIGRADE_MAX_CONNECTIONS_PER_IP", "0") catch unreachable;
    defer allocator.free(max_conn_ip_str);
    const max_connections_per_ip = std.fmt.parseInt(u32, max_conn_ip_str, 10) catch 0;

    const max_active_conn_str = envOrDefault(allocator, "TARDIGRADE_MAX_ACTIVE_CONNECTIONS", "0") catch unreachable;
    defer allocator.free(max_active_conn_str);
    const max_active_connections = std.fmt.parseInt(u32, max_active_conn_str, 10) catch 0;

    const keep_alive_timeout_str = envOrDefault(allocator, "TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS", "5000") catch unreachable;
    defer allocator.free(keep_alive_timeout_str);
    const keep_alive_timeout_ms = std.fmt.parseInt(u32, keep_alive_timeout_str, 10) catch 5000;

    const max_req_conn_str = envOrDefault(allocator, "TARDIGRADE_MAX_REQUESTS_PER_CONNECTION", "100") catch unreachable;
    defer allocator.free(max_req_conn_str);
    const max_requests_per_connection = std.fmt.parseInt(u32, max_req_conn_str, 10) catch 100;

    const conn_pool_size_str = envOrDefault(allocator, "TARDIGRADE_CONNECTION_POOL_SIZE", "256") catch unreachable;
    defer allocator.free(conn_pool_size_str);
    const connection_pool_size = std.fmt.parseInt(usize, conn_pool_size_str, 10) catch 256;

    const max_conn_mem_str = envOrDefault(allocator, "TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES", "2097152") catch unreachable;
    defer allocator.free(max_conn_mem_str);
    const max_connection_memory_bytes = std.fmt.parseInt(usize, max_conn_mem_str, 10) catch 2 * 1024 * 1024;

    const max_total_conn_mem_str = envOrDefault(allocator, "TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES", "0") catch unreachable;
    defer allocator.free(max_total_conn_mem_str);
    const max_total_connection_memory_bytes = std.fmt.parseInt(usize, max_total_conn_mem_str, 10) catch 0;

    const stream_all_statuses_str = envOrDefault(allocator, "TARDIGRADE_PROXY_STREAM_ALL_STATUSES", "false") catch unreachable;
    defer allocator.free(stream_all_statuses_str);
    const proxy_stream_all_statuses = std.mem.eql(u8, stream_all_statuses_str, "true") or std.mem.eql(u8, stream_all_statuses_str, "1");

    const retry_attempts_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS", "1") catch unreachable;
    defer allocator.free(retry_attempts_str);
    const upstream_retry_attempts = @max(std.fmt.parseInt(u32, retry_attempts_str, 10) catch 1, 1);

    const timeout_budget_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS", "0") catch unreachable;
    defer allocator.free(timeout_budget_str);
    const upstream_timeout_budget_ms = std.fmt.parseInt(u64, timeout_budget_str, 10) catch 0;

    const max_fails_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_MAX_FAILS", "0") catch unreachable;
    defer allocator.free(max_fails_str);
    const upstream_max_fails = std.fmt.parseInt(u32, max_fails_str, 10) catch 0;

    const fail_timeout_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS", "10000") catch unreachable;
    defer allocator.free(fail_timeout_str);
    const upstream_fail_timeout_ms = std.fmt.parseInt(u64, fail_timeout_str, 10) catch 10_000;

    const active_health_interval_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_INTERVAL_MS", "0") catch unreachable;
    defer allocator.free(active_health_interval_str);
    const upstream_active_health_interval_ms = std.fmt.parseInt(u64, active_health_interval_str, 10) catch 0;

    const upstream_active_health_path = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_PATH", "/health") catch unreachable;
    errdefer allocator.free(upstream_active_health_path);

    const active_health_timeout_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_TIMEOUT_MS", "2000") catch unreachable;
    defer allocator.free(active_health_timeout_str);
    const upstream_active_health_timeout_ms = std.fmt.parseInt(u32, active_health_timeout_str, 10) catch 2000;

    const active_health_fail_threshold_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_FAIL_THRESHOLD", "1") catch unreachable;
    defer allocator.free(active_health_fail_threshold_str);
    const upstream_active_health_fail_threshold = @max(std.fmt.parseInt(u32, active_health_fail_threshold_str, 10) catch 1, 1);

    const active_health_success_threshold_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD", "1") catch unreachable;
    defer allocator.free(active_health_success_threshold_str);
    const upstream_active_health_success_threshold = @max(std.fmt.parseInt(u32, active_health_success_threshold_str, 10) catch 1, 1);

    const slow_start_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_SLOW_START_MS", "0") catch unreachable;
    defer allocator.free(slow_start_str);
    const upstream_slow_start_ms = std.fmt.parseInt(u64, slow_start_str, 10) catch 0;

    return .{
        .listen_host = listen_host,
        .listen_port = listen_port,
        .tls_cert_path = tls_cert_path,
        .tls_key_path = tls_key_path,
        .upstream_base_url = upstream_base_url,
        .upstream_base_urls = upstream_base_urls,
        .upstream_lb_algorithm = upstream_lb_algorithm,
        .proxy_pass_chat = proxy_pass_chat,
        .proxy_pass_commands_prefix = proxy_pass_commands_prefix,
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
        .cb_threshold = cb_threshold,
        .cb_timeout_ms = cb_timeout_ms,
        .worker_threads = worker_threads,
        .worker_queue_size = worker_queue_size,
        .fd_soft_limit = fd_soft_limit,
        .max_connections_per_ip = max_connections_per_ip,
        .max_active_connections = max_active_connections,
        .keep_alive_timeout_ms = keep_alive_timeout_ms,
        .max_requests_per_connection = max_requests_per_connection,
        .connection_pool_size = connection_pool_size,
        .max_connection_memory_bytes = max_connection_memory_bytes,
        .max_total_connection_memory_bytes = max_total_connection_memory_bytes,
        .proxy_stream_all_statuses = proxy_stream_all_statuses,
        .upstream_retry_attempts = upstream_retry_attempts,
        .upstream_timeout_budget_ms = upstream_timeout_budget_ms,
        .upstream_max_fails = upstream_max_fails,
        .upstream_fail_timeout_ms = upstream_fail_timeout_ms,
        .upstream_active_health_interval_ms = upstream_active_health_interval_ms,
        .upstream_active_health_path = upstream_active_health_path,
        .upstream_active_health_timeout_ms = upstream_active_health_timeout_ms,
        .upstream_active_health_fail_threshold = upstream_active_health_fail_threshold,
        .upstream_active_health_success_threshold = upstream_active_health_success_threshold,
        .upstream_slow_start_ms = upstream_slow_start_ms,
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

fn parseCsvValues(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (out.items) |v| allocator.free(v);
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const duped = try allocator.dupe(u8, trimmed);
        try out.append(duped);
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

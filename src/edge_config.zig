const std = @import("std");
const http = @import("http.zig");

pub const UpstreamLbAlgorithm = enum {
    round_robin,
    least_connections,
    ip_hash,
    generic_hash,
    random_two_choices,

    pub fn parse(value: []const u8) ?UpstreamLbAlgorithm {
        if (std.ascii.eqlIgnoreCase(value, "round_robin") or std.ascii.eqlIgnoreCase(value, "round-robin")) return .round_robin;
        if (std.ascii.eqlIgnoreCase(value, "least_connections") or std.ascii.eqlIgnoreCase(value, "least-connections")) return .least_connections;
        if (std.ascii.eqlIgnoreCase(value, "ip_hash") or std.ascii.eqlIgnoreCase(value, "ip-hash")) return .ip_hash;
        if (std.ascii.eqlIgnoreCase(value, "generic_hash") or std.ascii.eqlIgnoreCase(value, "generic-hash")) return .generic_hash;
        if (std.ascii.eqlIgnoreCase(value, "random_two_choices") or std.ascii.eqlIgnoreCase(value, "random-two-choices")) return .random_two_choices;
        return null;
    }
};

pub const ProxyProtocolMode = enum {
    off,
    auto,
    v1,
    v2,

    pub fn parse(value: []const u8) ?ProxyProtocolMode {
        if (std.ascii.eqlIgnoreCase(value, "off")) return .off;
        if (std.ascii.eqlIgnoreCase(value, "auto")) return .auto;
        if (std.ascii.eqlIgnoreCase(value, "v1")) return .v1;
        if (std.ascii.eqlIgnoreCase(value, "v2")) return .v2;
        return null;
    }
};

pub const EdgeConfig = struct {
    pub const HeaderPair = struct {
        name: []const u8,
        value: []const u8,
    };
    pub const TlsSniCert = struct {
        server_name: []const u8,
        cert_path: []const u8,
        key_path: []const u8,
    };

    listen_host: []const u8,
    listen_port: u16,
    tls_cert_path: []const u8,
    tls_key_path: []const u8,
    tls_min_version: []const u8,
    tls_max_version: []const u8,
    tls_cipher_list: []const u8,
    tls_cipher_suites: []const u8,
    tls_sni_certs: []TlsSniCert,
    tls_session_cache_enabled: bool,
    tls_session_cache_size: u32,
    tls_session_timeout_seconds: u32,
    tls_session_tickets_enabled: bool,
    tls_ocsp_stapling_enabled: bool,
    tls_ocsp_response_path: []const u8,
    tls_client_ca_path: []const u8,
    tls_client_verify: bool,
    tls_client_verify_depth: u32,
    tls_crl_path: []const u8,
    tls_crl_check: bool,
    tls_dynamic_reload_interval_ms: u64,
    tls_acme_enabled: bool,
    tls_acme_cert_dir: []const u8,
    proxy_protocol_mode: ProxyProtocolMode,
    /// Gateway identity used in signed upstream trust headers.
    trust_gateway_id: []const u8,
    /// Shared secret used for upstream header signing/verification (empty = disabled).
    trust_shared_secret: []const u8,
    /// Trusted upstream identities accepted when signature verification is enabled.
    trusted_upstream_identities: [][]const u8,
    /// Whether to require signed upstream identity headers on responses.
    trust_require_upstream_identity: bool,
    upstream_base_url: []const u8,
    upstream_base_urls: [][]const u8,
    upstream_base_url_weights: []u32,
    upstream_backup_base_urls: [][]const u8,
    upstream_chat_base_urls: [][]const u8,
    upstream_chat_base_url_weights: []u32,
    upstream_chat_backup_base_urls: [][]const u8,
    upstream_commands_base_urls: [][]const u8,
    upstream_commands_base_url_weights: []u32,
    upstream_commands_backup_base_urls: [][]const u8,
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
    /// Proxy response cache TTL in seconds (0 = disabled).
    proxy_cache_ttl_seconds: u32,
    /// Optional proxy cache path for disk-backed/tiered caching.
    proxy_cache_path: []const u8,
    /// Proxy cache key template, colon-separated tokens:
    /// method,path,payload_sha256,identity,api_version
    proxy_cache_key_template: []const u8,
    /// Additional stale serving window after TTL expiry (seconds).
    proxy_cache_stale_while_revalidate_seconds: u32,
    /// Max time to wait for another request populating the same cache key.
    proxy_cache_lock_timeout_ms: u32,
    /// Proxy cache manager maintenance interval in milliseconds.
    proxy_cache_manager_interval_ms: u64,
    /// Optional comma-separated ISO country codes to block (requires external country header input).
    geo_blocked_countries: [][]const u8,
    /// Header containing country code provided by external edge/CDN.
    geo_country_header: []const u8,
    /// Optional auth subrequest URL; non-2xx denies protected routes.
    auth_request_url: []const u8,
    /// Timeout for auth subrequest in milliseconds.
    auth_request_timeout_ms: u32,
    /// Optional JWT shared secret for HS256 bearer validation.
    jwt_secret: []const u8,
    /// Optional JWT issuer constraint.
    jwt_issuer: []const u8,
    /// Optional JWT audience constraint.
    jwt_audience: []const u8,
    /// Additional response headers from add_header directive.
    add_headers: []HeaderPair,
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
        allocator.free(self.tls_min_version);
        allocator.free(self.tls_max_version);
        allocator.free(self.tls_cipher_list);
        allocator.free(self.tls_cipher_suites);
        for (self.tls_sni_certs) |sc| {
            allocator.free(sc.server_name);
            allocator.free(sc.cert_path);
            allocator.free(sc.key_path);
        }
        allocator.free(self.tls_sni_certs);
        allocator.free(self.tls_ocsp_response_path);
        allocator.free(self.tls_client_ca_path);
        allocator.free(self.tls_crl_path);
        allocator.free(self.tls_acme_cert_dir);
        allocator.free(self.trust_gateway_id);
        allocator.free(self.trust_shared_secret);
        for (self.trusted_upstream_identities) |id| allocator.free(id);
        allocator.free(self.trusted_upstream_identities);
        allocator.free(self.upstream_base_url);
        for (self.upstream_base_urls) |u| allocator.free(u);
        allocator.free(self.upstream_base_urls);
        allocator.free(self.upstream_base_url_weights);
        for (self.upstream_backup_base_urls) |u| allocator.free(u);
        allocator.free(self.upstream_backup_base_urls);
        for (self.upstream_chat_base_urls) |u| allocator.free(u);
        allocator.free(self.upstream_chat_base_urls);
        allocator.free(self.upstream_chat_base_url_weights);
        for (self.upstream_chat_backup_base_urls) |u| allocator.free(u);
        allocator.free(self.upstream_chat_backup_base_urls);
        for (self.upstream_commands_base_urls) |u| allocator.free(u);
        allocator.free(self.upstream_commands_base_urls);
        allocator.free(self.upstream_commands_base_url_weights);
        for (self.upstream_commands_backup_base_urls) |u| allocator.free(u);
        allocator.free(self.upstream_commands_backup_base_urls);
        allocator.free(self.proxy_pass_chat);
        allocator.free(self.proxy_pass_commands_prefix);
        for (self.auth_token_hashes) |h| allocator.free(h);
        allocator.free(self.auth_token_hashes);
        allocator.free(self.access_control_rules);
        allocator.free(self.proxy_cache_path);
        allocator.free(self.proxy_cache_key_template);
        for (self.geo_blocked_countries) |c| allocator.free(c);
        allocator.free(self.geo_blocked_countries);
        allocator.free(self.geo_country_header);
        allocator.free(self.auth_request_url);
        allocator.free(self.jwt_secret);
        allocator.free(self.jwt_issuer);
        allocator.free(self.jwt_audience);
        for (self.add_headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(self.add_headers);
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
    const tls_min_version = envOrDefault(allocator, "TARDIGRADE_TLS_MIN_VERSION", "1.2") catch unreachable;
    errdefer allocator.free(tls_min_version);
    const tls_max_version = envOrDefault(allocator, "TARDIGRADE_TLS_MAX_VERSION", "1.3") catch unreachable;
    errdefer allocator.free(tls_max_version);
    const tls_cipher_list = envOrDefault(allocator, "TARDIGRADE_TLS_CIPHER_LIST", "") catch unreachable;
    errdefer allocator.free(tls_cipher_list);
    const tls_cipher_suites = envOrDefault(allocator, "TARDIGRADE_TLS_CIPHER_SUITES", "") catch unreachable;
    errdefer allocator.free(tls_cipher_suites);
    const tls_sni_certs_raw = envOrDefault(allocator, "TARDIGRADE_TLS_SNI_CERTS", "") catch unreachable;
    defer allocator.free(tls_sni_certs_raw);
    const tls_sni_certs = try parseTlsSniCerts(allocator, tls_sni_certs_raw);
    errdefer {
        for (tls_sni_certs) |sc| {
            allocator.free(sc.server_name);
            allocator.free(sc.cert_path);
            allocator.free(sc.key_path);
        }
        allocator.free(tls_sni_certs);
    }
    const tls_session_cache_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_SESSION_CACHE", true);
    const tls_session_cache_size = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_SESSION_CACHE_SIZE", 20_480);
    const tls_session_timeout_seconds = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_SESSION_TIMEOUT_SECONDS", 300);
    const tls_session_tickets_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_SESSION_TICKETS", true);
    const tls_ocsp_stapling_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_OCSP_STAPLING", false);
    const tls_ocsp_response_path = envOrDefault(allocator, "TARDIGRADE_TLS_OCSP_RESPONSE_PATH", "") catch unreachable;
    errdefer allocator.free(tls_ocsp_response_path);
    const tls_client_ca_path = envOrDefault(allocator, "TARDIGRADE_TLS_CLIENT_CA_PATH", "") catch unreachable;
    errdefer allocator.free(tls_client_ca_path);
    const tls_client_verify = parseBoolEnv(allocator, "TARDIGRADE_TLS_CLIENT_VERIFY", false);
    const tls_client_verify_depth = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH", 3);
    const tls_crl_path = envOrDefault(allocator, "TARDIGRADE_TLS_CRL_PATH", "") catch unreachable;
    errdefer allocator.free(tls_crl_path);
    const tls_crl_check = parseBoolEnv(allocator, "TARDIGRADE_TLS_CRL_CHECK", false);
    const tls_dynamic_reload_interval_ms = parseIntEnv(u64, allocator, "TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS", 5000);
    const tls_acme_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_ACME_ENABLED", false);
    const tls_acme_cert_dir = envOrDefault(allocator, "TARDIGRADE_TLS_ACME_CERT_DIR", "") catch unreachable;
    errdefer allocator.free(tls_acme_cert_dir);
    const proxy_protocol_mode_str = envOrDefault(allocator, "TARDIGRADE_PROXY_PROTOCOL", "off") catch unreachable;
    defer allocator.free(proxy_protocol_mode_str);
    const proxy_protocol_mode = ProxyProtocolMode.parse(proxy_protocol_mode_str) orelse .off;
    const trust_gateway_id = envOrDefault(allocator, "TARDIGRADE_TRUST_GATEWAY_ID", "tardigrade-edge") catch unreachable;
    errdefer allocator.free(trust_gateway_id);
    const trust_shared_secret = envOrDefault(allocator, "TARDIGRADE_TRUST_SHARED_SECRET", "") catch unreachable;
    errdefer allocator.free(trust_shared_secret);
    const trusted_upstream_identities_raw = envOrDefault(allocator, "TARDIGRADE_TRUSTED_UPSTREAM_IDENTITIES", "") catch unreachable;
    defer allocator.free(trusted_upstream_identities_raw);
    const trusted_upstream_identities = try parseCsvValues(allocator, trusted_upstream_identities_raw);
    errdefer {
        for (trusted_upstream_identities) |id| allocator.free(id);
        allocator.free(trusted_upstream_identities);
    }
    const trust_require_upstream_identity_str = envOrDefault(allocator, "TARDIGRADE_TRUST_REQUIRE_UPSTREAM_IDENTITY", "false") catch unreachable;
    defer allocator.free(trust_require_upstream_identity_str);
    const trust_require_upstream_identity = std.mem.eql(u8, trust_require_upstream_identity_str, "true") or std.mem.eql(u8, trust_require_upstream_identity_str, "1");

    const upstream_base_url = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_BASE_URL", "http://127.0.0.1:8080") catch unreachable;
    errdefer allocator.free(upstream_base_url);
    const upstream_base_urls_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_BASE_URLS", "") catch unreachable;
    defer allocator.free(upstream_base_urls_raw);
    const upstream_base_urls = try parseCsvValues(allocator, upstream_base_urls_raw);
    errdefer {
        for (upstream_base_urls) |u| allocator.free(u);
        allocator.free(upstream_base_urls);
    }
    const upstream_base_url_weights_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_BASE_URL_WEIGHTS", "") catch unreachable;
    defer allocator.free(upstream_base_url_weights_raw);
    const upstream_base_url_weights = try parseCsvU32Values(allocator, upstream_base_url_weights_raw);
    errdefer allocator.free(upstream_base_url_weights);
    if (upstream_base_url_weights.len > 0 and upstream_base_url_weights.len != upstream_base_urls.len) {
        return error.InvalidUpstreamBaseUrlWeightsCount;
    }
    const upstream_backup_base_urls_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_BACKUP_BASE_URLS", "") catch unreachable;
    defer allocator.free(upstream_backup_base_urls_raw);
    const upstream_backup_base_urls = try parseCsvValues(allocator, upstream_backup_base_urls_raw);
    errdefer {
        for (upstream_backup_base_urls) |u| allocator.free(u);
        allocator.free(upstream_backup_base_urls);
    }
    const upstream_chat_base_urls_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_CHAT_BASE_URLS", "") catch unreachable;
    defer allocator.free(upstream_chat_base_urls_raw);
    const upstream_chat_base_urls = try parseCsvValues(allocator, upstream_chat_base_urls_raw);
    errdefer {
        for (upstream_chat_base_urls) |u| allocator.free(u);
        allocator.free(upstream_chat_base_urls);
    }
    const upstream_chat_base_url_weights_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_CHAT_BASE_URL_WEIGHTS", "") catch unreachable;
    defer allocator.free(upstream_chat_base_url_weights_raw);
    const upstream_chat_base_url_weights = try parseCsvU32Values(allocator, upstream_chat_base_url_weights_raw);
    errdefer allocator.free(upstream_chat_base_url_weights);
    if (upstream_chat_base_url_weights.len > 0 and upstream_chat_base_url_weights.len != upstream_chat_base_urls.len) {
        return error.InvalidUpstreamChatBaseUrlWeightsCount;
    }
    const upstream_chat_backup_base_urls_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_CHAT_BACKUP_BASE_URLS", "") catch unreachable;
    defer allocator.free(upstream_chat_backup_base_urls_raw);
    const upstream_chat_backup_base_urls = try parseCsvValues(allocator, upstream_chat_backup_base_urls_raw);
    errdefer {
        for (upstream_chat_backup_base_urls) |u| allocator.free(u);
        allocator.free(upstream_chat_backup_base_urls);
    }
    const upstream_commands_base_urls_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_COMMANDS_BASE_URLS", "") catch unreachable;
    defer allocator.free(upstream_commands_base_urls_raw);
    const upstream_commands_base_urls = try parseCsvValues(allocator, upstream_commands_base_urls_raw);
    errdefer {
        for (upstream_commands_base_urls) |u| allocator.free(u);
        allocator.free(upstream_commands_base_urls);
    }
    const upstream_commands_base_url_weights_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_COMMANDS_BASE_URL_WEIGHTS", "") catch unreachable;
    defer allocator.free(upstream_commands_base_url_weights_raw);
    const upstream_commands_base_url_weights = try parseCsvU32Values(allocator, upstream_commands_base_url_weights_raw);
    errdefer allocator.free(upstream_commands_base_url_weights);
    if (upstream_commands_base_url_weights.len > 0 and upstream_commands_base_url_weights.len != upstream_commands_base_urls.len) {
        return error.InvalidUpstreamCommandsBaseUrlWeightsCount;
    }
    const upstream_commands_backup_base_urls_raw = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_COMMANDS_BACKUP_BASE_URLS", "") catch unreachable;
    defer allocator.free(upstream_commands_backup_base_urls_raw);
    const upstream_commands_backup_base_urls = try parseCsvValues(allocator, upstream_commands_backup_base_urls_raw);
    errdefer {
        for (upstream_commands_backup_base_urls) |u| allocator.free(u);
        allocator.free(upstream_commands_backup_base_urls);
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
    const proxy_cache_ttl_str = envOrDefault(allocator, "TARDIGRADE_PROXY_CACHE_TTL_SECONDS", "0") catch unreachable;
    defer allocator.free(proxy_cache_ttl_str);
    const proxy_cache_ttl_seconds = std.fmt.parseInt(u32, proxy_cache_ttl_str, 10) catch 0;
    const proxy_cache_path = envOrDefault(allocator, "TARDIGRADE_PROXY_CACHE_PATH", "") catch unreachable;
    errdefer allocator.free(proxy_cache_path);
    const proxy_cache_key_template = envOrDefault(allocator, "TARDIGRADE_PROXY_CACHE_KEY_TEMPLATE", "method:path:payload_sha256") catch unreachable;
    errdefer allocator.free(proxy_cache_key_template);
    const proxy_cache_stale_str = envOrDefault(allocator, "TARDIGRADE_PROXY_CACHE_STALE_WHILE_REVALIDATE_SECONDS", "0") catch unreachable;
    defer allocator.free(proxy_cache_stale_str);
    const proxy_cache_stale_while_revalidate_seconds = std.fmt.parseInt(u32, proxy_cache_stale_str, 10) catch 0;
    const proxy_cache_lock_timeout_ms_str = envOrDefault(allocator, "TARDIGRADE_PROXY_CACHE_LOCK_TIMEOUT_MS", "250") catch unreachable;
    defer allocator.free(proxy_cache_lock_timeout_ms_str);
    const proxy_cache_lock_timeout_ms = std.fmt.parseInt(u32, proxy_cache_lock_timeout_ms_str, 10) catch 250;
    const proxy_cache_manager_interval_ms_str = envOrDefault(allocator, "TARDIGRADE_PROXY_CACHE_MANAGER_INTERVAL_MS", "30000") catch unreachable;
    defer allocator.free(proxy_cache_manager_interval_ms_str);
    const proxy_cache_manager_interval_ms = std.fmt.parseInt(u64, proxy_cache_manager_interval_ms_str, 10) catch 30_000;
    const geo_blocked_countries_raw = envOrDefault(allocator, "TARDIGRADE_GEO_BLOCKED_COUNTRIES", "") catch unreachable;
    defer allocator.free(geo_blocked_countries_raw);
    const geo_blocked_countries = try parseCsvValues(allocator, geo_blocked_countries_raw);
    errdefer {
        for (geo_blocked_countries) |c| allocator.free(c);
        allocator.free(geo_blocked_countries);
    }
    for (geo_blocked_countries) |c| {
        for (c) |ch| {
            if (!std.ascii.isAlphabetic(ch)) return error.InvalidGeoCountryCode;
        }
    }
    const geo_country_header = envOrDefault(allocator, "TARDIGRADE_GEO_COUNTRY_HEADER", "CF-IPCountry") catch unreachable;
    errdefer allocator.free(geo_country_header);
    const auth_request_url = envOrDefault(allocator, "TARDIGRADE_AUTH_REQUEST_URL", "") catch unreachable;
    errdefer allocator.free(auth_request_url);
    const auth_request_timeout_ms_str = envOrDefault(allocator, "TARDIGRADE_AUTH_REQUEST_TIMEOUT_MS", "2000") catch unreachable;
    defer allocator.free(auth_request_timeout_ms_str);
    const auth_request_timeout_ms = std.fmt.parseInt(u32, auth_request_timeout_ms_str, 10) catch 2000;
    const jwt_secret = envOrDefault(allocator, "TARDIGRADE_JWT_SECRET", "") catch unreachable;
    errdefer allocator.free(jwt_secret);
    const jwt_issuer = envOrDefault(allocator, "TARDIGRADE_JWT_ISSUER", "") catch unreachable;
    errdefer allocator.free(jwt_issuer);
    const jwt_audience = envOrDefault(allocator, "TARDIGRADE_JWT_AUDIENCE", "") catch unreachable;
    errdefer allocator.free(jwt_audience);
    const add_headers_raw = envOrDefault(allocator, "TARDIGRADE_ADD_HEADERS", "") catch unreachable;
    defer allocator.free(add_headers_raw);
    const add_headers = try parseHeaderPairs(allocator, add_headers_raw);
    errdefer {
        for (add_headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(add_headers);
    }

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
    const limit_conn_ip_str = envOrDefault(allocator, "TARDIGRADE_LIMIT_CONN_PER_IP", "") catch unreachable;
    defer allocator.free(limit_conn_ip_str);
    const max_connections_per_ip = if (limit_conn_ip_str.len > 0)
        (std.fmt.parseInt(u32, limit_conn_ip_str, 10) catch 0)
    else
        (std.fmt.parseInt(u32, max_conn_ip_str, 10) catch 0);

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
        .tls_min_version = tls_min_version,
        .tls_max_version = tls_max_version,
        .tls_cipher_list = tls_cipher_list,
        .tls_cipher_suites = tls_cipher_suites,
        .tls_sni_certs = tls_sni_certs,
        .tls_session_cache_enabled = tls_session_cache_enabled,
        .tls_session_cache_size = tls_session_cache_size,
        .tls_session_timeout_seconds = tls_session_timeout_seconds,
        .tls_session_tickets_enabled = tls_session_tickets_enabled,
        .tls_ocsp_stapling_enabled = tls_ocsp_stapling_enabled,
        .tls_ocsp_response_path = tls_ocsp_response_path,
        .tls_client_ca_path = tls_client_ca_path,
        .tls_client_verify = tls_client_verify,
        .tls_client_verify_depth = tls_client_verify_depth,
        .tls_crl_path = tls_crl_path,
        .tls_crl_check = tls_crl_check,
        .tls_dynamic_reload_interval_ms = tls_dynamic_reload_interval_ms,
        .tls_acme_enabled = tls_acme_enabled,
        .tls_acme_cert_dir = tls_acme_cert_dir,
        .proxy_protocol_mode = proxy_protocol_mode,
        .trust_gateway_id = trust_gateway_id,
        .trust_shared_secret = trust_shared_secret,
        .trusted_upstream_identities = trusted_upstream_identities,
        .trust_require_upstream_identity = trust_require_upstream_identity,
        .upstream_base_url = upstream_base_url,
        .upstream_base_urls = upstream_base_urls,
        .upstream_base_url_weights = upstream_base_url_weights,
        .upstream_backup_base_urls = upstream_backup_base_urls,
        .upstream_chat_base_urls = upstream_chat_base_urls,
        .upstream_chat_base_url_weights = upstream_chat_base_url_weights,
        .upstream_chat_backup_base_urls = upstream_chat_backup_base_urls,
        .upstream_commands_base_urls = upstream_commands_base_urls,
        .upstream_commands_base_url_weights = upstream_commands_base_url_weights,
        .upstream_commands_backup_base_urls = upstream_commands_backup_base_urls,
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
        .proxy_cache_ttl_seconds = proxy_cache_ttl_seconds,
        .proxy_cache_path = proxy_cache_path,
        .proxy_cache_key_template = proxy_cache_key_template,
        .proxy_cache_stale_while_revalidate_seconds = proxy_cache_stale_while_revalidate_seconds,
        .proxy_cache_lock_timeout_ms = proxy_cache_lock_timeout_ms,
        .proxy_cache_manager_interval_ms = proxy_cache_manager_interval_ms,
        .geo_blocked_countries = geo_blocked_countries,
        .geo_country_header = geo_country_header,
        .auth_request_url = auth_request_url,
        .auth_request_timeout_ms = auth_request_timeout_ms,
        .jwt_secret = jwt_secret,
        .jwt_issuer = jwt_issuer,
        .jwt_audience = jwt_audience,
        .add_headers = add_headers,
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

fn parseBoolEnv(allocator: std.mem.Allocator, key: []const u8, default_value: bool) bool {
    const raw = envOrDefault(allocator, key, if (default_value) "true" else "false") catch return default_value;
    defer allocator.free(raw);
    return std.mem.eql(u8, raw, "true") or std.mem.eql(u8, raw, "1");
}

fn parseIntEnv(comptime T: type, allocator: std.mem.Allocator, key: []const u8, default_value: T) T {
    const raw = envOrDefault(allocator, key, "") catch return default_value;
    defer allocator.free(raw);
    if (raw.len == 0) return default_value;
    return std.fmt.parseInt(T, raw, 10) catch default_value;
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

fn parseCsvU32Values(allocator: std.mem.Allocator, raw: []const u8) ![]u32 {
    var out = std.ArrayList(u32).init(allocator);
    errdefer out.deinit();

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const value = try std.fmt.parseInt(u32, trimmed, 10);
        if (value == 0) return error.InvalidUpstreamBaseUrlWeight;
        try out.append(value);
    }

    return out.toOwnedSlice();
}

fn parseHeaderPairs(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.HeaderPair {
    var out = std.ArrayList(EdgeConfig.HeaderPair).init(allocator);
    errdefer {
        for (out.items) |pair| {
            allocator.free(pair.name);
            allocator.free(pair.value);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, '|');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse return error.InvalidAddHeaderFormat;
        const name_raw = std.mem.trim(u8, trimmed[0..colon], " \t\r\n");
        const value_raw = std.mem.trim(u8, trimmed[colon + 1 ..], " \t\r\n");
        if (name_raw.len == 0) return error.InvalidAddHeaderFormat;
        const name = try allocator.dupe(u8, name_raw);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, value_raw);
        errdefer allocator.free(value);
        try out.append(.{ .name = name, .value = value });
    }
    return out.toOwnedSlice();
}

fn parseTlsSniCerts(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.TlsSniCert {
    var out = std.ArrayList(EdgeConfig.TlsSniCert).init(allocator);
    errdefer {
        for (out.items) |sc| {
            allocator.free(sc.server_name);
            allocator.free(sc.cert_path);
            allocator.free(sc.key_path);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, '|');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        var fields = std.mem.splitScalar(u8, trimmed, ':');
        const host_raw = fields.next() orelse return error.InvalidTlsSniCertFormat;
        const cert_raw = fields.next() orelse return error.InvalidTlsSniCertFormat;
        const key_raw = fields.next() orelse return error.InvalidTlsSniCertFormat;
        if (fields.next() != null) return error.InvalidTlsSniCertFormat;
        const host = std.mem.trim(u8, host_raw, " \t\r\n");
        const cert = std.mem.trim(u8, cert_raw, " \t\r\n");
        const key = std.mem.trim(u8, key_raw, " \t\r\n");
        if (host.len == 0 or cert.len == 0 or key.len == 0) return error.InvalidTlsSniCertFormat;
        try out.append(.{
            .server_name = try allocator.dupe(u8, host),
            .cert_path = try allocator.dupe(u8, cert),
            .key_path = try allocator.dupe(u8, key),
        });
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

test "parse upstream lb algorithm aliases" {
    try std.testing.expectEqual(UpstreamLbAlgorithm.round_robin, UpstreamLbAlgorithm.parse("round_robin").?);
    try std.testing.expectEqual(UpstreamLbAlgorithm.least_connections, UpstreamLbAlgorithm.parse("least-connections").?);
    try std.testing.expectEqual(UpstreamLbAlgorithm.ip_hash, UpstreamLbAlgorithm.parse("ip-hash").?);
    try std.testing.expectEqual(UpstreamLbAlgorithm.generic_hash, UpstreamLbAlgorithm.parse("generic-hash").?);
    try std.testing.expectEqual(UpstreamLbAlgorithm.random_two_choices, UpstreamLbAlgorithm.parse("random_two_choices").?);
    try std.testing.expect(UpstreamLbAlgorithm.parse("unknown") == null);
}

test "parse upstream base url weights csv" {
    const allocator = std.testing.allocator;
    const weights = try parseCsvU32Values(allocator, "3, 1,2");
    defer allocator.free(weights);

    try std.testing.expectEqual(@as(usize, 3), weights.len);
    try std.testing.expectEqual(@as(u32, 3), weights[0]);
    try std.testing.expectEqual(@as(u32, 1), weights[1]);
    try std.testing.expectEqual(@as(u32, 2), weights[2]);
    try std.testing.expectError(error.InvalidUpstreamBaseUrlWeight, parseCsvU32Values(allocator, "0"));
}

test "parse proxy protocol mode aliases" {
    try std.testing.expectEqual(ProxyProtocolMode.off, ProxyProtocolMode.parse("off").?);
    try std.testing.expectEqual(ProxyProtocolMode.auto, ProxyProtocolMode.parse("AUTO").?);
    try std.testing.expectEqual(ProxyProtocolMode.v1, ProxyProtocolMode.parse("v1").?);
    try std.testing.expectEqual(ProxyProtocolMode.v2, ProxyProtocolMode.parse("v2").?);
    try std.testing.expect(ProxyProtocolMode.parse("unknown") == null);
}

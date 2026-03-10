const std = @import("std");
const http = @import("http.zig");

var active_file_overrides: ?*const http.config_file.Overrides = null;
var active_secret_overrides: ?*const http.secrets.Overrides = null;

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
    pub const HealthStatusRange = struct {
        min: u16,
        max: u16,

        pub fn contains(self: HealthStatusRange, status_code: u16) bool {
            return status_code >= self.min and status_code <= self.max;
        }
    };
    pub const UpstreamHealthSuccessStatusOverride = struct {
        upstream_base_url: []const u8,
        range: HealthStatusRange,
    };
    pub const HeaderPair = struct {
        name: []const u8,
        value: []const u8,
    };
    pub const TlsSniCert = struct {
        server_name: []const u8,
        cert_path: []const u8,
        key_path: []const u8,
    };
    pub const RewriteRule = http.rewrite.RewriteRule;
    pub const ReturnRule = http.rewrite.ReturnRule;
    pub const ConditionalRule = http.rewrite.ConditionalRule;
    pub const InternalRedirectRule = struct {
        method: []const u8,
        pattern: []const u8,
        target: []const u8,
    };
    pub const NamedLocation = struct {
        name: []const u8,
        path: []const u8,
    };
    pub const MirrorRule = struct {
        method: []const u8,
        pattern: []const u8,
        target_url: []const u8,
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
    http2_enabled: bool,
    http3_enabled: bool,
    quic_port: u16,
    http3_enable_0rtt: bool,
    http3_connection_migration: bool,
    http3_max_datagram_size: usize,
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
    /// Policy engine route rules (`METHOD|REGEX|required_scope|require_approval|hours|device_regex`; semicolon-separated).
    policy_rules_raw: []const u8,
    /// Policy scope mapping (`identity:scope1,scope2;...`).
    policy_user_scopes_raw: []const u8,
    /// Routes requiring approval (`METHOD|REGEX;...`).
    policy_approval_routes_raw: []const u8,
    /// Session idle TTL in seconds (0 = sessions disabled).
    session_ttl_seconds: u32,
    /// Maximum concurrent sessions (0 = unlimited).
    session_max: u32,
    /// Device identity registry path (line format: `device_id|key`).
    device_registry_path: []const u8,
    /// Require registered device key proof headers for protected API routes.
    device_auth_required: bool,
    /// Access token ttl seconds for issued device tokens.
    access_token_ttl_seconds: u32,
    /// Refresh token ttl seconds for issued device tokens.
    refresh_token_ttl_seconds: u32,
    /// IP access control rules (empty = disabled).
    /// Format: "allow 10.0.0.0/8, deny 0.0.0.0/0"
    access_control_rules: []const u8,
    /// Request validation limits.
    request_limits: http.request_limits.RequestLimits,
    /// Basic auth credential hashes (SHA-256 of "user:password", empty = disabled).
    basic_auth_hashes: [][]const u8,
    /// Minimum log level (debug, info, warn, error).
    log_level: http.logger.Level,
    /// Optional error log destination path (`stderr` keeps current behavior).
    error_log_path: []const u8,
    /// Optional pid file path.
    pid_file: []const u8,
    /// Optional target user for post-bind privilege drop.
    run_user: []const u8,
    /// Optional target group for post-bind privilege drop.
    run_group: []const u8,
    /// Optional chroot directory applied after bind.
    chroot_dir: []const u8,
    /// Require runtime to be unprivileged after startup.
    require_unprivileged_user: bool,
    /// Optional accepted Host patterns for virtual-host matching.
    server_names: [][]const u8,
    /// Optional document root for try_files/static fallback handling.
    doc_root: []const u8,
    /// Optional `try_files` candidate list (comma-separated paths; supports `$uri`).
    try_files: []const u8,
    /// Access log output format (json, plain, custom).
    access_log_format: http.access_log.Format,
    /// Access log custom template when format=custom.
    access_log_template: []const u8,
    /// Minimum status code required to emit access logs (0 = all).
    access_log_min_status: u16,
    /// Access log in-memory buffer size before flush (0 = no buffering).
    access_log_buffer_size: usize,
    /// Optional syslog UDP endpoint (host:port).
    access_log_syslog_udp: []const u8,
    /// Whether response compression is enabled.
    compression_enabled: bool,
    /// Minimum response body size to compress (bytes).
    compression_min_size: usize,
    /// Whether Brotli response compression is enabled.
    compression_brotli_enabled: bool,
    /// Brotli compression quality [0..11].
    compression_brotli_quality: u32,
    /// Whether to request gzip-compressed upstream responses and gunzip in gateway.
    upstream_gunzip_enabled: bool,
    /// Circuit breaker failure threshold (0 = disabled).
    cb_threshold: u32,
    /// Circuit breaker open timeout in milliseconds before half-open probe.
    cb_timeout_ms: u64,
    /// Number of worker threads for connection handling (0 = auto CPU count).
    worker_threads: u32,
    /// Enable master process supervision mode.
    master_process_enabled: bool,
    /// Number of worker processes when master mode is enabled.
    worker_processes: u32,
    /// Enable binary upgrade signaling path (SIGUSR2).
    binary_upgrade_enabled: bool,
    /// Worker recycle interval in seconds (0 = disabled).
    worker_recycle_seconds: u32,
    /// Optional cpu affinity list (`0,1,2`) for worker role pinning.
    worker_cpu_affinity: []const u8,
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
    /// Default success-status range used by active health probes.
    upstream_active_health_success_status: HealthStatusRange,
    /// Exact upstream URL overrides for active health probe success-status matching.
    upstream_active_health_success_status_overrides: []UpstreamHealthSuccessStatusOverride,
    /// Slow-start window (ms) for recovered upstreams before receiving full traffic (0 = disabled).
    upstream_slow_start_ms: u64,
    /// Enable WebSocket upgrade routes.
    websocket_enabled: bool,
    /// Idle timeout for WebSocket connections in milliseconds.
    websocket_idle_timeout_ms: u32,
    /// Maximum payload size per WebSocket frame in bytes.
    websocket_max_frame_size: usize,
    /// Ping interval for WebSocket keepalive frames in milliseconds (0 = disabled).
    websocket_ping_interval_ms: u32,
    /// Enable SSE publish/stream routes.
    sse_enabled: bool,
    /// Maximum retained events per topic in the in-memory SSE hub.
    sse_max_events_per_topic: usize,
    /// SSE polling interval in milliseconds for long-lived stream loops.
    sse_poll_interval_ms: u32,
    /// Maximum tolerated replay backlog before forcing reconnect.
    sse_max_backlog: usize,
    /// Idle timeout for SSE streams in milliseconds (0 = disabled).
    sse_idle_timeout_ms: u32,
    /// Rewrite rules evaluated before route dispatch.
    rewrite_rules: []RewriteRule,
    /// Return rules evaluated after rewrites and before route dispatch.
    return_rules: []ReturnRule,
    /// Conditional inline `if (...) return|rewrite` rules.
    conditional_rules: []ConditionalRule,
    /// Internal redirect rules evaluated before route dispatch.
    internal_redirect_rules: []InternalRedirectRule,
    /// Named location map for redirect targets prefixed with '@'.
    named_locations: []NamedLocation,
    /// Mirror request rules (best-effort asynchronous copies).
    mirror_rules: []MirrorRule,
    /// FastCGI upstream endpoint (`host:port`).
    fastcgi_upstream: []const u8,
    /// Additional `fastcgi_param` CGI variables injected into FastCGI requests.
    fastcgi_params: []HeaderPair,
    /// Default index script for directory-style FastCGI requests.
    fastcgi_index: []const u8,
    /// uWSGI upstream endpoint (`host:port`).
    uwsgi_upstream: []const u8,
    /// SCGI upstream endpoint (`host:port`).
    scgi_upstream: []const u8,
    /// gRPC upstream base URL (`http://host:port`).
    grpc_upstream: []const u8,
    /// Memcached endpoint (`host:port`).
    memcached_upstream: []const u8,
    /// SMTP upstream endpoint (`host:port`).
    smtp_upstream: []const u8,
    /// IMAP upstream endpoint (`host:port`).
    imap_upstream: []const u8,
    /// POP3 upstream endpoint (`host:port`).
    pop3_upstream: []const u8,
    /// Generic TCP proxy upstream endpoint (`host:port`).
    tcp_proxy_upstream: []const u8,
    /// Generic UDP proxy upstream endpoint (`host:port`).
    udp_proxy_upstream: []const u8,
    /// Enable stream-module SSL termination mode for stream proxy routes.
    stream_ssl_termination: bool,

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
        allocator.free(self.policy_rules_raw);
        allocator.free(self.policy_user_scopes_raw);
        allocator.free(self.policy_approval_routes_raw);
        allocator.free(self.device_registry_path);
        for (self.basic_auth_hashes) |h| allocator.free(h);
        allocator.free(self.basic_auth_hashes);
        allocator.free(self.error_log_path);
        allocator.free(self.pid_file);
        allocator.free(self.run_user);
        allocator.free(self.run_group);
        allocator.free(self.chroot_dir);
        for (self.server_names) |name| allocator.free(name);
        allocator.free(self.server_names);
        allocator.free(self.doc_root);
        allocator.free(self.try_files);
        allocator.free(self.access_log_template);
        allocator.free(self.access_log_syslog_udp);
        allocator.free(self.worker_cpu_affinity);
        allocator.free(self.upstream_active_health_path);
        for (self.upstream_active_health_success_status_overrides) |entry| {
            allocator.free(entry.upstream_base_url);
        }
        allocator.free(self.upstream_active_health_success_status_overrides);
        for (self.rewrite_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.replacement);
        }
        allocator.free(self.rewrite_rules);
        for (self.return_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.body);
        }
        allocator.free(self.return_rules);
        for (self.conditional_rules) |rule| {
            allocator.free(rule.pattern);
            switch (rule.action) {
                .rewrite => |rw| allocator.free(rw.replacement),
                .returned => |ret| allocator.free(ret.body),
            }
        }
        allocator.free(self.conditional_rules);
        for (self.internal_redirect_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target);
        }
        allocator.free(self.internal_redirect_rules);
        for (self.named_locations) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.path);
        }
        allocator.free(self.named_locations);
        for (self.mirror_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target_url);
        }
        allocator.free(self.mirror_rules);
        allocator.free(self.fastcgi_upstream);
        for (self.fastcgi_params) |pair| {
            allocator.free(pair.name);
            allocator.free(pair.value);
        }
        allocator.free(self.fastcgi_params);
        allocator.free(self.fastcgi_index);
        allocator.free(self.uwsgi_upstream);
        allocator.free(self.scgi_upstream);
        allocator.free(self.grpc_upstream);
        allocator.free(self.memcached_upstream);
        allocator.free(self.smtp_upstream);
        allocator.free(self.imap_upstream);
        allocator.free(self.pop3_upstream);
        allocator.free(self.tcp_proxy_upstream);
        allocator.free(self.udp_proxy_upstream);
        self.* = undefined;
    }
};

pub fn loadFromEnv(allocator: std.mem.Allocator) !EdgeConfig {
    var secret_overrides = try http.secrets.loadOverrides(allocator);
    defer secret_overrides.deinit(allocator);
    active_secret_overrides = &secret_overrides;
    defer active_secret_overrides = null;

    var file_overrides = try http.config_file.loadOverrides(allocator);
    defer file_overrides.deinit(allocator);
    active_file_overrides = &file_overrides;
    defer active_file_overrides = null;

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
    const http2_enabled = parseBoolEnv(allocator, "TARDIGRADE_HTTP2_ENABLED", true);
    const http3_enabled = parseBoolEnv(allocator, "TARDIGRADE_HTTP3_ENABLED", false);
    const quic_port_str = envOrDefault(allocator, "TARDIGRADE_QUIC_PORT", "443") catch unreachable;
    defer allocator.free(quic_port_str);
    const quic_port = std.fmt.parseInt(u16, quic_port_str, 10) catch 443;
    const http3_enable_0rtt = parseBoolEnv(allocator, "TARDIGRADE_HTTP3_ENABLE_0RTT", false);
    const http3_connection_migration = parseBoolEnv(allocator, "TARDIGRADE_HTTP3_CONNECTION_MIGRATION", false);
    const http3_max_datagram_size = parseIntEnv(usize, allocator, "TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE", 1350);
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
    const policy_rules_raw = envOrDefault(allocator, "TARDIGRADE_POLICY_RULES", "") catch unreachable;
    errdefer allocator.free(policy_rules_raw);
    const policy_user_scopes_raw = envOrDefault(allocator, "TARDIGRADE_POLICY_USER_SCOPES", "") catch unreachable;
    errdefer allocator.free(policy_user_scopes_raw);
    const policy_approval_routes_raw = envOrDefault(allocator, "TARDIGRADE_POLICY_APPROVAL_ROUTES", "") catch unreachable;
    errdefer allocator.free(policy_approval_routes_raw);

    const session_ttl_str = envOrDefault(allocator, "TARDIGRADE_SESSION_TTL", "3600") catch unreachable;
    defer allocator.free(session_ttl_str);
    const session_ttl_seconds = std.fmt.parseInt(u32, session_ttl_str, 10) catch 3600;

    const session_max_str = envOrDefault(allocator, "TARDIGRADE_SESSION_MAX", "1000") catch unreachable;
    defer allocator.free(session_max_str);
    const session_max = std.fmt.parseInt(u32, session_max_str, 10) catch 1000;
    const device_registry_path = envOrDefault(allocator, "TARDIGRADE_DEVICE_REGISTRY_PATH", "") catch unreachable;
    errdefer allocator.free(device_registry_path);
    const device_auth_required = parseBoolEnv(allocator, "TARDIGRADE_DEVICE_AUTH_REQUIRED", false);
    const access_token_ttl_seconds = parseIntEnv(u32, allocator, "TARDIGRADE_ACCESS_TOKEN_TTL_SECONDS", 900);
    const refresh_token_ttl_seconds = parseIntEnv(u32, allocator, "TARDIGRADE_REFRESH_TOKEN_TTL_SECONDS", 86_400);

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
    const error_log_path = envOrDefault(allocator, "TARDIGRADE_ERROR_LOG_PATH", "") catch unreachable;
    errdefer allocator.free(error_log_path);
    const pid_file = envOrDefault(allocator, "TARDIGRADE_PID_FILE", "") catch unreachable;
    errdefer allocator.free(pid_file);
    const run_user = envOrDefault(allocator, "TARDIGRADE_RUN_USER", "") catch unreachable;
    errdefer allocator.free(run_user);
    const run_group = envOrDefault(allocator, "TARDIGRADE_RUN_GROUP", "") catch unreachable;
    errdefer allocator.free(run_group);
    const chroot_dir = envOrDefault(allocator, "TARDIGRADE_CHROOT_DIR", "") catch unreachable;
    errdefer allocator.free(chroot_dir);
    const require_unprivileged_user = parseBoolEnv(allocator, "TARDIGRADE_REQUIRE_UNPRIVILEGED_USER", false);
    const server_names_raw = envOrDefault(allocator, "TARDIGRADE_SERVER_NAMES", "") catch unreachable;
    defer allocator.free(server_names_raw);
    const server_names = try parseServerNames(allocator, server_names_raw);
    errdefer {
        for (server_names) |name| allocator.free(name);
        allocator.free(server_names);
    }
    const doc_root = envOrDefault(allocator, "TARDIGRADE_DOC_ROOT", "") catch unreachable;
    errdefer allocator.free(doc_root);
    const try_files = envOrDefault(allocator, "TARDIGRADE_TRY_FILES", "") catch unreachable;
    errdefer allocator.free(try_files);
    const access_log_format_str = envOrDefault(allocator, "TARDIGRADE_ACCESS_LOG_FORMAT", "json") catch unreachable;
    defer allocator.free(access_log_format_str);
    const access_log_format = http.access_log.Format.parse(access_log_format_str) orelse .json;
    const access_log_template = envOrDefault(allocator, "TARDIGRADE_ACCESS_LOG_TEMPLATE", "") catch unreachable;
    errdefer allocator.free(access_log_template);
    const access_log_min_status = parseIntEnv(u16, allocator, "TARDIGRADE_ACCESS_LOG_MIN_STATUS", 0);
    const access_log_buffer_size = parseIntEnv(usize, allocator, "TARDIGRADE_ACCESS_LOG_BUFFER_SIZE", 0);
    const access_log_syslog_udp = envOrDefault(allocator, "TARDIGRADE_ACCESS_LOG_SYSLOG_UDP", "") catch unreachable;
    errdefer allocator.free(access_log_syslog_udp);

    // Compression
    const comp_enabled_str = envOrDefault(allocator, "TARDIGRADE_COMPRESSION_ENABLED", "true") catch unreachable;
    defer allocator.free(comp_enabled_str);
    const compression_enabled = std.mem.eql(u8, comp_enabled_str, "true") or std.mem.eql(u8, comp_enabled_str, "1");

    const comp_min_str = envOrDefault(allocator, "TARDIGRADE_COMPRESSION_MIN_SIZE", "256") catch unreachable;
    defer allocator.free(comp_min_str);
    const compression_min_size = std.fmt.parseInt(usize, comp_min_str, 10) catch 256;
    const comp_br_enabled_str = envOrDefault(allocator, "TARDIGRADE_COMPRESSION_BROTLI_ENABLED", "true") catch unreachable;
    defer allocator.free(comp_br_enabled_str);
    const compression_brotli_enabled = std.mem.eql(u8, comp_br_enabled_str, "true") or std.mem.eql(u8, comp_br_enabled_str, "1");
    const comp_br_quality_str = envOrDefault(allocator, "TARDIGRADE_COMPRESSION_BROTLI_QUALITY", "5") catch unreachable;
    defer allocator.free(comp_br_quality_str);
    const compression_brotli_quality = std.fmt.parseInt(u32, comp_br_quality_str, 10) catch 5;
    const upstream_gunzip_enabled_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_GUNZIP_ENABLED", "true") catch unreachable;
    defer allocator.free(upstream_gunzip_enabled_str);
    const upstream_gunzip_enabled = std.mem.eql(u8, upstream_gunzip_enabled_str, "true") or std.mem.eql(u8, upstream_gunzip_enabled_str, "1");

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
    const master_process_enabled = parseBoolEnv(allocator, "TARDIGRADE_MASTER_PROCESS", false);
    const worker_processes = parseIntEnv(u32, allocator, "TARDIGRADE_WORKER_PROCESSES", 1);
    const binary_upgrade_enabled = parseBoolEnv(allocator, "TARDIGRADE_BINARY_UPGRADE", true);
    const worker_recycle_seconds = parseIntEnv(u32, allocator, "TARDIGRADE_WORKER_RECYCLE_SECONDS", 0);
    const worker_cpu_affinity = envOrDefault(allocator, "TARDIGRADE_WORKER_CPU_AFFINITY", "") catch unreachable;
    errdefer allocator.free(worker_cpu_affinity);

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

    const active_health_interval_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_HEALTH_INTERVAL_MS",
        "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_INTERVAL_MS",
        "0",
    ) catch unreachable;
    defer allocator.free(active_health_interval_str);
    const upstream_active_health_interval_ms = std.fmt.parseInt(u64, active_health_interval_str, 10) catch 0;

    const upstream_active_health_path = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_HEALTH_PATH",
        "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_PATH",
        "/health",
    ) catch unreachable;
    errdefer allocator.free(upstream_active_health_path);

    const active_health_timeout_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_HEALTH_TIMEOUT_MS",
        "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_TIMEOUT_MS",
        "2000",
    ) catch unreachable;
    defer allocator.free(active_health_timeout_str);
    const upstream_active_health_timeout_ms = std.fmt.parseInt(u32, active_health_timeout_str, 10) catch 2000;

    const active_health_fail_threshold_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_HEALTH_THRESHOLD",
        "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_FAIL_THRESHOLD",
        "1",
    ) catch unreachable;
    defer allocator.free(active_health_fail_threshold_str);
    const upstream_active_health_fail_threshold = @max(std.fmt.parseInt(u32, active_health_fail_threshold_str, 10) catch 1, 1);

    const active_health_success_threshold_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_THRESHOLD", "1") catch unreachable;
    defer allocator.free(active_health_success_threshold_str);
    const upstream_active_health_success_threshold = @max(std.fmt.parseInt(u32, active_health_success_threshold_str, 10) catch 1, 1);

    const active_health_success_status_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_HEALTH_SUCCESS_STATUS",
        "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_STATUS",
        "200-299",
    ) catch unreachable;
    defer allocator.free(active_health_success_status_str);
    const upstream_active_health_success_status = parseHealthStatusRange(active_health_success_status_str) catch EdgeConfig.HealthStatusRange{ .min = 200, .max = 299 };

    const active_health_success_status_overrides_raw = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_HEALTH_SUCCESS_STATUS_OVERRIDES",
        "TARDIGRADE_UPSTREAM_ACTIVE_HEALTH_SUCCESS_STATUS_OVERRIDES",
        "",
    ) catch unreachable;
    defer allocator.free(active_health_success_status_overrides_raw);
    const upstream_active_health_success_status_overrides = try parseUpstreamHealthSuccessStatusOverrides(
        allocator,
        active_health_success_status_overrides_raw,
    );
    errdefer {
        for (upstream_active_health_success_status_overrides) |entry| {
            allocator.free(entry.upstream_base_url);
        }
        allocator.free(upstream_active_health_success_status_overrides);
    }

    const slow_start_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_SLOW_START_MS", "0") catch unreachable;
    defer allocator.free(slow_start_str);
    const upstream_slow_start_ms = std.fmt.parseInt(u64, slow_start_str, 10) catch 0;
    const websocket_enabled = parseBoolEnv(allocator, "TARDIGRADE_WEBSOCKET_ENABLED", true);
    const websocket_idle_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS", 60_000);
    const websocket_max_frame_size = parseIntEnv(usize, allocator, "TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE", 1024 * 1024);
    const websocket_ping_interval_ms = parseIntEnv(u32, allocator, "TARDIGRADE_WEBSOCKET_PING_INTERVAL_MS", 15_000);
    const sse_enabled = parseBoolEnv(allocator, "TARDIGRADE_SSE_ENABLED", true);
    const sse_max_events_per_topic = parseIntEnv(usize, allocator, "TARDIGRADE_SSE_MAX_EVENTS_PER_TOPIC", 1024);
    const sse_poll_interval_ms = parseIntEnv(u32, allocator, "TARDIGRADE_SSE_POLL_INTERVAL_MS", 250);
    const sse_max_backlog = parseIntEnv(usize, allocator, "TARDIGRADE_SSE_MAX_BACKLOG", 1024);
    const sse_idle_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_SSE_IDLE_TIMEOUT_MS", 60_000);
    const rewrite_rules_raw = envOrDefault(allocator, "TARDIGRADE_REWRITE_RULES", "") catch unreachable;
    defer allocator.free(rewrite_rules_raw);
    const rewrite_rules = try parseRewriteRules(allocator, rewrite_rules_raw);
    errdefer {
        for (rewrite_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.replacement);
        }
        allocator.free(rewrite_rules);
    }
    const return_rules_raw = envOrDefault(allocator, "TARDIGRADE_RETURN_RULES", "") catch unreachable;
    defer allocator.free(return_rules_raw);
    const return_rules = try parseReturnRules(allocator, return_rules_raw);
    errdefer {
        for (return_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.body);
        }
        allocator.free(return_rules);
    }
    const conditional_rules_raw = envOrDefault(allocator, "TARDIGRADE_CONDITIONAL_RULES", "") catch unreachable;
    defer allocator.free(conditional_rules_raw);
    const conditional_rules = try parseConditionalRules(allocator, conditional_rules_raw);
    errdefer {
        for (conditional_rules) |rule| {
            allocator.free(rule.pattern);
            switch (rule.action) {
                .rewrite => |rw| allocator.free(rw.replacement),
                .returned => |ret| allocator.free(ret.body),
            }
        }
        allocator.free(conditional_rules);
    }
    const internal_redirects_raw = envOrDefault(allocator, "TARDIGRADE_INTERNAL_REDIRECT_RULES", "") catch unreachable;
    defer allocator.free(internal_redirects_raw);
    const internal_redirect_rules = try parseInternalRedirectRules(allocator, internal_redirects_raw);
    errdefer {
        for (internal_redirect_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target);
        }
        allocator.free(internal_redirect_rules);
    }
    const named_locations_raw = envOrDefault(allocator, "TARDIGRADE_NAMED_LOCATIONS", "") catch unreachable;
    defer allocator.free(named_locations_raw);
    const named_locations = try parseNamedLocations(allocator, named_locations_raw);
    errdefer {
        for (named_locations) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.path);
        }
        allocator.free(named_locations);
    }
    const mirror_rules_raw = envOrDefault(allocator, "TARDIGRADE_MIRROR_RULES", "") catch unreachable;
    defer allocator.free(mirror_rules_raw);
    const mirror_rules = try parseMirrorRules(allocator, mirror_rules_raw);
    errdefer {
        for (mirror_rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target_url);
        }
        allocator.free(mirror_rules);
    }
    const fastcgi_upstream = envOrDefault(allocator, "TARDIGRADE_FASTCGI_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(fastcgi_upstream);
    const fastcgi_params_raw = envOrDefault(allocator, "TARDIGRADE_FASTCGI_PARAMS", "") catch unreachable;
    defer allocator.free(fastcgi_params_raw);
    const fastcgi_params = try parseFastcgiParams(allocator, fastcgi_params_raw);
    errdefer {
        for (fastcgi_params) |pair| {
            allocator.free(pair.name);
            allocator.free(pair.value);
        }
        allocator.free(fastcgi_params);
    }
    const fastcgi_index = envOrDefault(allocator, "TARDIGRADE_FASTCGI_INDEX", "index.php") catch unreachable;
    errdefer allocator.free(fastcgi_index);
    const uwsgi_upstream = envOrDefault(allocator, "TARDIGRADE_UWSGI_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(uwsgi_upstream);
    const scgi_upstream = envOrDefault(allocator, "TARDIGRADE_SCGI_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(scgi_upstream);
    const grpc_upstream = envOrDefault(allocator, "TARDIGRADE_GRPC_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(grpc_upstream);
    const memcached_upstream = envOrDefault(allocator, "TARDIGRADE_MEMCACHED_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(memcached_upstream);
    const smtp_upstream = envOrDefault(allocator, "TARDIGRADE_SMTP_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(smtp_upstream);
    const imap_upstream = envOrDefault(allocator, "TARDIGRADE_IMAP_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(imap_upstream);
    const pop3_upstream = envOrDefault(allocator, "TARDIGRADE_POP3_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(pop3_upstream);
    const tcp_proxy_upstream = envOrDefault(allocator, "TARDIGRADE_TCP_PROXY_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(tcp_proxy_upstream);
    const udp_proxy_upstream = envOrDefault(allocator, "TARDIGRADE_UDP_PROXY_UPSTREAM", "") catch unreachable;
    errdefer allocator.free(udp_proxy_upstream);
    const stream_ssl_termination = parseBoolEnv(allocator, "TARDIGRADE_STREAM_SSL_TERMINATION", false);

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
        .http2_enabled = http2_enabled,
        .http3_enabled = http3_enabled,
        .quic_port = quic_port,
        .http3_enable_0rtt = http3_enable_0rtt,
        .http3_connection_migration = http3_connection_migration,
        .http3_max_datagram_size = http3_max_datagram_size,
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
        .policy_rules_raw = policy_rules_raw,
        .policy_user_scopes_raw = policy_user_scopes_raw,
        .policy_approval_routes_raw = policy_approval_routes_raw,
        .session_ttl_seconds = session_ttl_seconds,
        .session_max = session_max,
        .device_registry_path = device_registry_path,
        .device_auth_required = device_auth_required,
        .access_token_ttl_seconds = access_token_ttl_seconds,
        .refresh_token_ttl_seconds = refresh_token_ttl_seconds,
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
        .error_log_path = error_log_path,
        .pid_file = pid_file,
        .run_user = run_user,
        .run_group = run_group,
        .chroot_dir = chroot_dir,
        .require_unprivileged_user = require_unprivileged_user,
        .server_names = server_names,
        .doc_root = doc_root,
        .try_files = try_files,
        .access_log_format = access_log_format,
        .access_log_template = access_log_template,
        .access_log_min_status = access_log_min_status,
        .access_log_buffer_size = access_log_buffer_size,
        .access_log_syslog_udp = access_log_syslog_udp,
        .compression_enabled = compression_enabled,
        .compression_min_size = compression_min_size,
        .compression_brotli_enabled = compression_brotli_enabled,
        .compression_brotli_quality = compression_brotli_quality,
        .upstream_gunzip_enabled = upstream_gunzip_enabled,
        .cb_threshold = cb_threshold,
        .cb_timeout_ms = cb_timeout_ms,
        .worker_threads = worker_threads,
        .master_process_enabled = master_process_enabled,
        .worker_processes = worker_processes,
        .binary_upgrade_enabled = binary_upgrade_enabled,
        .worker_recycle_seconds = worker_recycle_seconds,
        .worker_cpu_affinity = worker_cpu_affinity,
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
        .upstream_active_health_success_status = upstream_active_health_success_status,
        .upstream_active_health_success_status_overrides = upstream_active_health_success_status_overrides,
        .upstream_slow_start_ms = upstream_slow_start_ms,
        .websocket_enabled = websocket_enabled,
        .websocket_idle_timeout_ms = websocket_idle_timeout_ms,
        .websocket_max_frame_size = websocket_max_frame_size,
        .websocket_ping_interval_ms = websocket_ping_interval_ms,
        .sse_enabled = sse_enabled,
        .sse_max_events_per_topic = sse_max_events_per_topic,
        .sse_poll_interval_ms = sse_poll_interval_ms,
        .sse_max_backlog = sse_max_backlog,
        .sse_idle_timeout_ms = sse_idle_timeout_ms,
        .rewrite_rules = rewrite_rules,
        .return_rules = return_rules,
        .conditional_rules = conditional_rules,
        .internal_redirect_rules = internal_redirect_rules,
        .named_locations = named_locations,
        .mirror_rules = mirror_rules,
        .fastcgi_upstream = fastcgi_upstream,
        .fastcgi_params = fastcgi_params,
        .fastcgi_index = fastcgi_index,
        .uwsgi_upstream = uwsgi_upstream,
        .scgi_upstream = scgi_upstream,
        .grpc_upstream = grpc_upstream,
        .memcached_upstream = memcached_upstream,
        .smtp_upstream = smtp_upstream,
        .imap_upstream = imap_upstream,
        .pop3_upstream = pop3_upstream,
        .tcp_proxy_upstream = tcp_proxy_upstream,
        .udp_proxy_upstream = udp_proxy_upstream,
        .stream_ssl_termination = stream_ssl_termination,
    };
}

fn envOrDefault(allocator: std.mem.Allocator, key: []const u8, default_value: []const u8) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, key)) |owned| {
        return owned;
    } else |_| {}

    if (active_file_overrides) |ov| {
        if (ov.map.get(key)) |value| {
            return allocator.dupe(u8, value);
        }
    }
    if (active_secret_overrides) |ov| {
        if (ov.map.get(key)) |value| {
            return allocator.dupe(u8, value);
        }
    }
    return allocator.dupe(u8, default_value);
}

fn envOrDefaultAlias(allocator: std.mem.Allocator, primary_key: []const u8, fallback_key: []const u8, default_value: []const u8) ![]u8 {
    if (std.process.getEnvVarOwned(allocator, primary_key)) |owned| {
        return owned;
    } else |_| {}

    return envOrDefault(allocator, fallback_key, default_value);
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

fn parseServerNames(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).init(allocator);
    errdefer {
        for (out.items) |name| allocator.free(name);
        out.deinit();
    }

    var it = std.mem.tokenizeAny(u8, raw, ", \t\r\n");
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        try out.append(try allocator.dupe(u8, trimmed));
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

fn parseHealthStatusRange(raw: []const u8) !EdgeConfig.HealthStatusRange {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidHealthStatusRange;
    if (std.mem.indexOfScalar(u8, trimmed, '-')) |dash| {
        const min_raw = std.mem.trim(u8, trimmed[0..dash], " \t\r\n");
        const max_raw = std.mem.trim(u8, trimmed[dash + 1 ..], " \t\r\n");
        const min = std.fmt.parseInt(u16, min_raw, 10) catch return error.InvalidHealthStatusRange;
        const max = std.fmt.parseInt(u16, max_raw, 10) catch return error.InvalidHealthStatusRange;
        if (min > max) return error.InvalidHealthStatusRange;
        return .{ .min = min, .max = max };
    }
    const code = std.fmt.parseInt(u16, trimmed, 10) catch return error.InvalidHealthStatusRange;
    return .{ .min = code, .max = code };
}

fn parseUpstreamHealthSuccessStatusOverrides(
    allocator: std.mem.Allocator,
    raw: []const u8,
) ![]EdgeConfig.UpstreamHealthSuccessStatusOverride {
    var out = std.ArrayList(EdgeConfig.UpstreamHealthSuccessStatusOverride).init(allocator);
    errdefer {
        for (out.items) |entry| allocator.free(entry.upstream_base_url);
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        const sep = std.mem.lastIndexOfScalar(u8, entry, '|') orelse return error.InvalidHealthStatusOverride;
        const upstream_base_url = std.mem.trim(u8, entry[0..sep], " \t\r\n");
        const status_raw = std.mem.trim(u8, entry[sep + 1 ..], " \t\r\n");
        if (upstream_base_url.len == 0 or status_raw.len == 0) return error.InvalidHealthStatusOverride;
        try out.append(.{
            .upstream_base_url = try allocator.dupe(u8, upstream_base_url),
            .range = try parseHealthStatusRange(status_raw),
        });
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

fn parseFastcgiParams(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.HeaderPair {
    var out = std.ArrayList(EdgeConfig.HeaderPair).init(allocator);
    errdefer {
        for (out.items) |pair| {
            allocator.free(pair.name);
            allocator.free(pair.value);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, '|');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, trimmed, '=') orelse return error.InvalidFastcgiParamFormat;
        const name = std.mem.trim(u8, trimmed[0..eq], " \t\r\n");
        const value = std.mem.trim(u8, trimmed[eq + 1 ..], " \t\r\n");
        if (name.len == 0) return error.InvalidFastcgiParamFormat;
        try out.append(.{
            .name = try allocator.dupe(u8, name),
            .value = try allocator.dupe(u8, value),
        });
    }
    return out.toOwnedSlice();
}

fn parseRewriteRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.RewriteRule {
    var out = std.ArrayList(EdgeConfig.RewriteRule).init(allocator);
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.replacement);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        var fields = std.mem.splitScalar(u8, trimmed, '|');
        const method_raw = fields.next() orelse return error.InvalidRewriteRuleFormat;
        const pattern_raw = fields.next() orelse return error.InvalidRewriteRuleFormat;
        const replacement_raw = fields.next() orelse return error.InvalidRewriteRuleFormat;
        const flag_raw = fields.next() orelse return error.InvalidRewriteRuleFormat;
        if (fields.next() != null) return error.InvalidRewriteRuleFormat;

        const method = std.mem.trim(u8, method_raw, " \t\r\n");
        const pattern = std.mem.trim(u8, pattern_raw, " \t\r\n");
        const replacement = std.mem.trim(u8, replacement_raw, " \t\r\n");
        const flag_name = std.mem.trim(u8, flag_raw, " \t\r\n");
        if (method.len == 0 or pattern.len == 0 or replacement.len == 0 or flag_name.len == 0) {
            return error.InvalidRewriteRuleFormat;
        }
        const flag = http.rewrite.RewriteFlag.parse(flag_name) orelse return error.InvalidRewriteRuleFlag;

        const owned_method = try allocator.dupe(u8, method);
        errdefer allocator.free(owned_method);
        const owned_pattern = try allocator.dupe(u8, pattern);
        errdefer allocator.free(owned_pattern);
        const owned_replacement = try allocator.dupe(u8, replacement);
        errdefer allocator.free(owned_replacement);
        try out.append(.{
            .method = owned_method,
            .pattern = owned_pattern,
            .replacement = owned_replacement,
            .flag = flag,
        });
    }
    return out.toOwnedSlice();
}

fn parseReturnRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.ReturnRule {
    var out = std.ArrayList(EdgeConfig.ReturnRule).init(allocator);
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.body);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        var fields = std.mem.splitScalar(u8, trimmed, '|');
        const method_raw = fields.next() orelse return error.InvalidReturnRuleFormat;
        const pattern_raw = fields.next() orelse return error.InvalidReturnRuleFormat;
        const status_raw = fields.next() orelse return error.InvalidReturnRuleFormat;
        const body_raw = fields.next() orelse return error.InvalidReturnRuleFormat;
        if (fields.next() != null) return error.InvalidReturnRuleFormat;

        const method = std.mem.trim(u8, method_raw, " \t\r\n");
        const pattern = std.mem.trim(u8, pattern_raw, " \t\r\n");
        const status_str = std.mem.trim(u8, status_raw, " \t\r\n");
        const body = std.mem.trim(u8, body_raw, " \t\r\n");
        if (method.len == 0 or pattern.len == 0 or status_str.len == 0) {
            return error.InvalidReturnRuleFormat;
        }
        const status = std.fmt.parseInt(u16, status_str, 10) catch return error.InvalidReturnRuleStatus;

        const owned_method = try allocator.dupe(u8, method);
        errdefer allocator.free(owned_method);
        const owned_pattern = try allocator.dupe(u8, pattern);
        errdefer allocator.free(owned_pattern);
        const owned_body = try allocator.dupe(u8, body);
        errdefer allocator.free(owned_body);
        try out.append(.{
            .method = owned_method,
            .pattern = owned_pattern,
            .status = status,
            .body = owned_body,
        });
    }
    return out.toOwnedSlice();
}

fn parseConditionalRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.ConditionalRule {
    var out = std.ArrayList(EdgeConfig.ConditionalRule).init(allocator);
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.pattern);
            switch (rule.action) {
                .rewrite => |rw| allocator.free(rw.replacement),
                .returned => |ret| allocator.free(ret.body),
            }
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        var fields = std.mem.splitScalar(u8, trimmed, '|');
        const variable_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;
        const sensitivity_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;
        const pattern_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;
        const action_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;

        const variable_name = std.mem.trim(u8, variable_raw, " \t\r\n");
        const sensitivity_name = std.mem.trim(u8, sensitivity_raw, " \t\r\n");
        const pattern = std.mem.trim(u8, pattern_raw, " \t\r\n");
        const action_name = std.mem.trim(u8, action_raw, " \t\r\n");
        if (variable_name.len == 0 or sensitivity_name.len == 0 or pattern.len == 0 or action_name.len == 0) {
            return error.InvalidConditionalRuleFormat;
        }

        const variable = http.rewrite.ConditionalVariable.parse(variable_name) orelse return error.InvalidConditionalVariable;
        const case_insensitive = if (std.ascii.eqlIgnoreCase(sensitivity_name, "ci"))
            true
        else if (std.ascii.eqlIgnoreCase(sensitivity_name, "cs"))
            false
        else
            return error.InvalidConditionalRuleFormat;

        const owned_pattern = try allocator.dupe(u8, pattern);
        errdefer allocator.free(owned_pattern);

        if (std.ascii.eqlIgnoreCase(action_name, "rewrite")) {
            const replacement_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;
            const flag_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;
            if (fields.next() != null) return error.InvalidConditionalRuleFormat;
            const replacement = std.mem.trim(u8, replacement_raw, " \t\r\n");
            const flag_name = std.mem.trim(u8, flag_raw, " \t\r\n");
            if (replacement.len == 0 or flag_name.len == 0) return error.InvalidConditionalRuleFormat;
            const flag = http.rewrite.RewriteFlag.parse(flag_name) orelse return error.InvalidRewriteRuleFlag;
            const owned_replacement = try allocator.dupe(u8, replacement);
            errdefer allocator.free(owned_replacement);
            try out.append(.{
                .variable = variable,
                .case_insensitive = case_insensitive,
                .pattern = owned_pattern,
                .action = .{ .rewrite = .{
                    .replacement = owned_replacement,
                    .flag = flag,
                } },
            });
            continue;
        }

        if (std.ascii.eqlIgnoreCase(action_name, "return")) {
            const status_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;
            const body_raw = fields.next() orelse return error.InvalidConditionalRuleFormat;
            if (fields.next() != null) return error.InvalidConditionalRuleFormat;
            const status_str = std.mem.trim(u8, status_raw, " \t\r\n");
            const body = std.mem.trim(u8, body_raw, " \t\r\n");
            if (status_str.len == 0) return error.InvalidConditionalRuleFormat;
            const status = std.fmt.parseInt(u16, status_str, 10) catch return error.InvalidReturnRuleStatus;
            const owned_body = try allocator.dupe(u8, body);
            errdefer allocator.free(owned_body);
            try out.append(.{
                .variable = variable,
                .case_insensitive = case_insensitive,
                .pattern = owned_pattern,
                .action = .{ .returned = .{
                    .status = status,
                    .body = owned_body,
                } },
            });
            continue;
        }

        return error.InvalidConditionalRuleFormat;
    }
    return out.toOwnedSlice();
}

fn parseInternalRedirectRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.InternalRedirectRule {
    var out = std.ArrayList(EdgeConfig.InternalRedirectRule).init(allocator);
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        var fields = std.mem.splitScalar(u8, trimmed, '|');
        const method_raw = fields.next() orelse return error.InvalidInternalRedirectRuleFormat;
        const pattern_raw = fields.next() orelse return error.InvalidInternalRedirectRuleFormat;
        const target_raw = fields.next() orelse return error.InvalidInternalRedirectRuleFormat;
        if (fields.next() != null) return error.InvalidInternalRedirectRuleFormat;
        const method = std.mem.trim(u8, method_raw, " \t\r\n");
        const pattern = std.mem.trim(u8, pattern_raw, " \t\r\n");
        const target = std.mem.trim(u8, target_raw, " \t\r\n");
        if (method.len == 0 or pattern.len == 0 or target.len == 0) return error.InvalidInternalRedirectRuleFormat;
        try out.append(.{
            .method = try allocator.dupe(u8, method),
            .pattern = try allocator.dupe(u8, pattern),
            .target = try allocator.dupe(u8, target),
        });
    }
    return out.toOwnedSlice();
}

fn parseNamedLocations(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.NamedLocation {
    var out = std.ArrayList(EdgeConfig.NamedLocation).init(allocator);
    errdefer {
        for (out.items) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.path);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        const sep = std.mem.indexOfScalar(u8, entry, '|') orelse return error.InvalidNamedLocationFormat;
        const name = std.mem.trim(u8, entry[0..sep], " \t\r\n");
        const path = std.mem.trim(u8, entry[sep + 1 ..], " \t\r\n");
        if (name.len == 0 or path.len == 0) return error.InvalidNamedLocationFormat;
        try out.append(.{
            .name = try allocator.dupe(u8, name),
            .path = try allocator.dupe(u8, path),
        });
    }
    return out.toOwnedSlice();
}

fn parseMirrorRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.MirrorRule {
    var out = std.ArrayList(EdgeConfig.MirrorRule).init(allocator);
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target_url);
        }
        out.deinit();
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        var fields = std.mem.splitScalar(u8, trimmed, '|');
        const method_raw = fields.next() orelse return error.InvalidMirrorRuleFormat;
        const pattern_raw = fields.next() orelse return error.InvalidMirrorRuleFormat;
        const target_raw = fields.next() orelse return error.InvalidMirrorRuleFormat;
        if (fields.next() != null) return error.InvalidMirrorRuleFormat;
        const method = std.mem.trim(u8, method_raw, " \t\r\n");
        const pattern = std.mem.trim(u8, pattern_raw, " \t\r\n");
        const target = std.mem.trim(u8, target_raw, " \t\r\n");
        if (method.len == 0 or pattern.len == 0 or target.len == 0) return error.InvalidMirrorRuleFormat;
        try out.append(.{
            .method = try allocator.dupe(u8, method),
            .pattern = try allocator.dupe(u8, pattern),
            .target_url = try allocator.dupe(u8, target),
        });
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

test "parse health status range" {
    try std.testing.expectEqualDeep(
        EdgeConfig.HealthStatusRange{ .min = 200, .max = 299 },
        try parseHealthStatusRange("200-299"),
    );
    try std.testing.expectEqualDeep(
        EdgeConfig.HealthStatusRange{ .min = 304, .max = 304 },
        try parseHealthStatusRange("304"),
    );
    try std.testing.expectError(error.InvalidHealthStatusRange, parseHealthStatusRange("500-200"));
}

test "parse upstream health success status overrides" {
    const allocator = std.testing.allocator;
    const overrides = try parseUpstreamHealthSuccessStatusOverrides(
        allocator,
        "http://127.0.0.1:8080|304;http://127.0.0.1:8081|200-204",
    );
    defer {
        for (overrides) |entry| allocator.free(entry.upstream_base_url);
        allocator.free(overrides);
    }

    try std.testing.expectEqual(@as(usize, 2), overrides.len);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080", overrides[0].upstream_base_url);
    try std.testing.expectEqualDeep(EdgeConfig.HealthStatusRange{ .min = 304, .max = 304 }, overrides[0].range);
    try std.testing.expectEqualDeep(EdgeConfig.HealthStatusRange{ .min = 200, .max = 204 }, overrides[1].range);
}

test "parse rewrite rules csv" {
    const allocator = std.testing.allocator;
    const rules = try parseRewriteRules(allocator, "GET|^/old$|/new|last;*|^/foo$|/bar|redirect");
    defer {
        for (rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.replacement);
        }
        allocator.free(rules);
    }
    try std.testing.expectEqual(@as(usize, 2), rules.len);
    try std.testing.expectEqualStrings("GET", rules[0].method);
    try std.testing.expectEqual(http.rewrite.RewriteFlag.last, rules[0].flag);
    try std.testing.expectEqual(http.rewrite.RewriteFlag.redirect, rules[1].flag);
}

test "parse return rules csv" {
    const allocator = std.testing.allocator;
    const rules = try parseReturnRules(allocator, "GET|^/healthz$|204|;*|^/blocked$|403|blocked");
    defer {
        for (rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.body);
        }
        allocator.free(rules);
    }
    try std.testing.expectEqual(@as(usize, 2), rules.len);
    try std.testing.expectEqual(@as(u16, 204), rules[0].status);
    try std.testing.expectEqualStrings("blocked", rules[1].body);
}

test "parse conditional rules csv" {
    const allocator = std.testing.allocator;
    const rules = try parseConditionalRules(
        allocator,
        "request_uri|ci|^/legacy/(.*)$|rewrite|/$1|last;http_host|ci|^admin\\.example\\.com$|return|301|https://example.com$request_uri",
    );
    defer {
        for (rules) |rule| {
            allocator.free(rule.pattern);
            switch (rule.action) {
                .rewrite => |rw| allocator.free(rw.replacement),
                .returned => |ret| allocator.free(ret.body),
            }
        }
        allocator.free(rules);
    }

    try std.testing.expectEqual(@as(usize, 2), rules.len);
    try std.testing.expectEqual(http.rewrite.ConditionalVariable.request_uri, rules[0].variable);
    try std.testing.expect(rules[0].case_insensitive);
    switch (rules[0].action) {
        .rewrite => |rw| try std.testing.expectEqual(http.rewrite.RewriteFlag.last, rw.flag),
        else => return error.UnexpectedTestResult,
    }
    try std.testing.expectEqual(http.rewrite.ConditionalVariable.http_host, rules[1].variable);
    switch (rules[1].action) {
        .returned => |ret| try std.testing.expectEqual(@as(u16, 301), ret.status),
        else => return error.UnexpectedTestResult,
    }
}

test "parse internal redirect rules csv" {
    const allocator = std.testing.allocator;
    const rules = try parseInternalRedirectRules(allocator, "GET|^/a$|/b;*|^/x$|@named");
    defer {
        for (rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target);
        }
        allocator.free(rules);
    }
    try std.testing.expectEqual(@as(usize, 2), rules.len);
    try std.testing.expectEqualStrings("@named", rules[1].target);
}

test "parse named locations csv" {
    const allocator = std.testing.allocator;
    const entries = try parseNamedLocations(allocator, "admin|/v1/chat;metrics|/metrics");
    defer {
        for (entries) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.path);
        }
        allocator.free(entries);
    }
    try std.testing.expectEqual(@as(usize, 2), entries.len);
    try std.testing.expectEqualStrings("metrics", entries[1].name);
}

test "parse mirror rules csv" {
    const allocator = std.testing.allocator;
    const rules = try parseMirrorRules(allocator, "POST|^/v1/chat$|http://127.0.0.1:9000/mirror");
    defer {
        for (rules) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target_url);
        }
        allocator.free(rules);
    }
    try std.testing.expectEqual(@as(usize, 1), rules.len);
    try std.testing.expectEqualStrings("POST", rules[0].method);
}

test "parse server names" {
    const allocator = std.testing.allocator;
    const names = try parseServerNames(allocator, "example.com, *.example.org api.internal");
    defer {
        for (names) |name| allocator.free(name);
        allocator.free(names);
    }
    try std.testing.expectEqual(@as(usize, 3), names.len);
    try std.testing.expectEqualStrings("*.example.org", names[1]);
}

test "parse fastcgi params" {
    const allocator = std.testing.allocator;
    const params = try parseFastcgiParams(allocator, "APP_ENV=prod|APP_ROLE=api");
    defer {
        for (params) |pair| {
            allocator.free(pair.name);
            allocator.free(pair.value);
        }
        allocator.free(params);
    }

    try std.testing.expectEqual(@as(usize, 2), params.len);
    try std.testing.expectEqualStrings("APP_ENV", params[0].name);
    try std.testing.expectEqualStrings("prod", params[0].value);
    try std.testing.expectEqualStrings("APP_ROLE", params[1].name);
    try std.testing.expectEqualStrings("api", params[1].value);
}

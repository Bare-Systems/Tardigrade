const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const compat = @import("zig_compat.zig");
const http = @import("http.zig");
const tls_core = @import("tls_core");

const encrypted_stream = tls_core.encrypted_stream;

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

pub const ProxyStreamingMode = enum {
    off,
    response,
    full,

    pub fn parse(value: []const u8) ?ProxyStreamingMode {
        if (std.ascii.eqlIgnoreCase(value, "off") or std.ascii.eqlIgnoreCase(value, "buffered")) return .off;
        if (std.ascii.eqlIgnoreCase(value, "response") or std.ascii.eqlIgnoreCase(value, "responses")) return .response;
        if (std.ascii.eqlIgnoreCase(value, "full") or std.ascii.eqlIgnoreCase(value, "request_response") or std.ascii.eqlIgnoreCase(value, "request-response")) return .full;
        return null;
    }

    pub fn responseStreamingEnabled(self: ProxyStreamingMode) bool {
        return self == .response or self == .full;
    }

    pub fn requestStreamingEnabled(self: ProxyStreamingMode) bool {
        return self == .full;
    }
};

/// Preferred application protocol for HTTPS upstream connections (#145).
/// `http1` requires HTTP/1.1 via ALPN, `h2` requires HTTP/2 via ALPN, and
/// `auto` prefers h2 while allowing HTTP/1.1 fallback. Only applies to TLS
/// upstreams (ALPN requires TLS).
pub const UpstreamProtocol = enum {
    http1,
    h2,
    auto,
    /// Like `h2` for HTTPS upstreams (ALPN), and additionally speaks
    /// **prior-knowledge cleartext h2c** to plain-HTTP upstreams (#237).
    /// A separate explicit value because cleartext has no negotiation: an
    /// h1-only plain origin would break under it, so `h2`/`auto` must never
    /// imply it.
    h2c,

    pub fn parse(value: []const u8) ?UpstreamProtocol {
        if (std.ascii.eqlIgnoreCase(value, "http1") or std.ascii.eqlIgnoreCase(value, "http/1.1") or std.ascii.eqlIgnoreCase(value, "h1")) return .http1;
        if (std.ascii.eqlIgnoreCase(value, "h2") or std.ascii.eqlIgnoreCase(value, "http2")) return .h2;
        if (std.ascii.eqlIgnoreCase(value, "auto")) return .auto;
        if (std.ascii.eqlIgnoreCase(value, "h2c")) return .h2c;
        return null;
    }

    /// Whether HTTP/2 should be offered via ALPN (HTTPS upstreams).
    pub fn offersH2(self: UpstreamProtocol) bool {
        return self != .http1;
    }

    /// Whether plain-HTTP upstreams speak prior-knowledge cleartext h2c.
    pub fn h2cPriorKnowledge(self: UpstreamProtocol) bool {
        return self == .h2c;
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
    pub const LocationBlock = http.location_router.LocationBlock;
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
    pub const ServerBlock = struct {
        server_names: [][]const u8,
        doc_root: []const u8,
        try_files: []const u8,
        location_blocks: []LocationBlock,
        tls_cert_path: []const u8,
        tls_key_path: []const u8,
        upstream_base_url: []const u8,
        proxy_pass_chat: []const u8,
        proxy_pass_commands_prefix: []const u8,

        pub fn deinit(self: *ServerBlock, allocator: std.mem.Allocator) void {
            for (self.server_names) |name| allocator.free(name);
            allocator.free(self.server_names);
            allocator.free(self.doc_root);
            allocator.free(self.try_files);
            for (self.location_blocks) |*block| block.deinit(allocator);
            allocator.free(self.location_blocks);
            allocator.free(self.tls_cert_path);
            allocator.free(self.tls_key_path);
            allocator.free(self.upstream_base_url);
            allocator.free(self.proxy_pass_chat);
            allocator.free(self.proxy_pass_commands_prefix);
            self.* = undefined;
        }
    };

    listen_host: []const u8,
    listen_port: u16,
    tls_cert_path: []const u8,
    tls_key_path: []const u8,
    tls_min_version: []const u8,
    tls_max_version: []const u8,
    tls_cipher_list: []const u8,
    tls_cipher_suites: []const u8,
    /// The one exact DNS host name served by the fixed appliance TLS identity
    /// (#392). Required (and strictly validated) in the appliance TLS profile;
    /// unused by the general OpenSSL terminator.
    tls_server_name: []const u8,
    tls_sni_certs: []TlsSniCert,
    tls_session_cache_enabled: bool,
    tls_session_cache_size: u32,
    tls_session_timeout_seconds: u32,
    tls_session_tickets_enabled: bool,
    tls_ocsp_stapling_enabled: bool,
    tls_ocsp_response_path: []const u8,
    tls_ocsp_auto_refresh: bool,
    tls_ocsp_refresh_interval_ms: u64,
    tls_ocsp_refresh_timeout_ms: u32,
    tls_client_ca_path: []const u8,
    tls_client_verify: bool,
    tls_client_verify_depth: u32,
    tls_crl_path: []const u8,
    tls_crl_check: bool,
    tls_dynamic_reload_interval_ms: u64,
    tls_acme_enabled: bool,
    tls_acme_cert_dir: []const u8,
    /// ACME directory URL (e.g. Let's Encrypt production or staging).
    tls_acme_directory_url: []const u8,
    /// Comma-separated list of domain names to obtain/renew certificates for.
    tls_acme_domains: [][]const u8,
    /// Contact email for ACME account registration.
    tls_acme_email: []const u8,
    /// Path to the PEM-encoded ECDSA P-256 account private key (created on first run).
    tls_acme_account_key_path: []const u8,
    /// Days before certificate expiry at which renewal is triggered.
    tls_acme_renew_days_before_expiry: u32,
    http1_enabled: bool,
    http2_enabled: bool,
    tls_http1_no_alpn_fallback: bool,
    /// Preferred application protocol for HTTPS upstream connections (#145).
    upstream_protocol: UpstreamProtocol,
    /// Verify TLS certificates presented by HTTPS upstream backends (default: true).
    upstream_tls_verify: bool,
    /// Path to a PEM CA bundle used to verify upstream TLS certificates.
    /// When empty, the system default CA bundle is used.
    upstream_tls_ca_bundle: []const u8,
    /// Override the SNI hostname sent to upstream HTTPS backends.
    /// When empty, the hostname from the upstream URL is used.
    upstream_tls_server_name: []const u8,
    /// Path to the PEM client certificate for upstream mTLS connections.
    upstream_tls_client_cert: []const u8,
    /// Path to the PEM client private key for upstream mTLS connections.
    upstream_tls_client_key: []const u8,
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
    upstream_timeout_ms: u32,
    auth_request_url: []const u8,
    jwt_secret: []const u8,
    jwt_issuer: []const u8,
    jwt_audience: []const u8,
    /// Requests per second per client IP (0 = disabled).
    rate_limit_rps: f64,
    /// Burst capacity for rate limiter.
    rate_limit_burst: u32,
    /// Whether to add security headers to responses.
    security_headers_enabled: bool,
    /// Emit Strict-Transport-Security header on HTTPS responses.
    /// Has no effect when TLS is not configured.
    hsts_enabled: bool,
    /// HSTS max-age in seconds (default: 31536000 = 1 year).
    hsts_max_age: u32,
    /// Include the includeSubDomains directive in the HSTS header.
    hsts_include_subdomains: bool,
    /// Include the preload directive in the HSTS header.
    hsts_preload: bool,
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
    /// Additional response headers from add_header directive.
    add_headers: []HeaderPair,
    /// IP access control rules (empty = disabled).
    /// Format: "allow 10.0.0.0/8, deny 0.0.0.0/0"
    access_control_rules: []const u8,
    /// Request validation limits.
    request_limits: http.request_limits.RequestLimits,
    /// Basic auth credential hashes (SHA-256 of "user:password", empty = disabled).
    basic_auth_hashes: [][]const u8,
    /// Bearer token hashes (SHA-256 of the raw bearer token, empty = disabled).
    auth_token_hashes: [][]const u8,
    session_ttl_seconds: u32,
    session_max: u32,
    session_store_path: []const u8,
    device_registry_path: []const u8,
    policy_rules_raw: []const u8,
    policy_user_scopes_raw: []const u8,
    policy_approval_routes_raw: []const u8,
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
    /// Optional per-host server blocks loaded from config file.
    server_blocks: []ServerBlock = &.{},
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
    /// Header names (lowercase) that must never appear in log output.
    /// Set via TARDIGRADE_REDACT_HEADERS (comma-separated).
    /// Defaults to the built-in redaction list when empty.
    log_redact_headers: []const []const u8,
    /// Prometheus metrics route path (empty disables the endpoint).
    metrics_path: []const u8,
    /// Require request auth before serving the metrics endpoint.
    metrics_require_auth: bool,
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
    /// Maximum connections queued per individual worker thread (0 = no per-worker limit).
    /// When all worker queues are at this depth, new connections are rejected with 503.
    /// Set via TARDIGRADE_WORKER_MAX_QUEUE_DEPTH.
    worker_max_queue_depth: usize,
    /// Graceful shutdown drain timeout in milliseconds (TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS).
    /// On shutdown signal, tardigrade waits up to this long for in-flight requests to complete
    /// before force-closing any remaining queued connections. 0 force-closes immediately.
    shutdown_drain_timeout_ms: u64,
    /// Desired soft file-descriptor limit (RLIMIT_NOFILE). 0 leaves OS default.
    fd_soft_limit: u64,
    /// Maximum active connections per client IP (0 = unlimited).
    max_connections_per_ip: u32,
    /// Maximum total active client connections across all IPs (0 = unlimited).
    max_active_connections: u32,
    /// Maximum concurrent in-flight HTTP requests across all connections (0 = unlimited).
    /// Distinct from max_active_connections: a single keep-alive connection counts as
    /// one connection but may serve many sequential requests.
    /// Returns 503 when exceeded. Set via TARDIGRADE_MAX_IN_FLIGHT_REQUESTS.
    max_in_flight_requests: u32,
    /// Idle keep-alive timeout for client connections (ms, 0 = disabled).
    keep_alive_timeout_ms: u32,
    /// Overall request deadline from first byte received to response fully written (ms, 0 = disabled).
    /// Caps all downstream work (auth, upstream calls, response streaming) for a single request.
    /// Set via TARDIGRADE_REQUEST_TOTAL_TIMEOUT_MS.
    request_total_timeout_ms: u32,
    /// TLS handshake timeout in milliseconds (TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS).
    /// Applied as SO_RCVTIMEO before SSL_accept to bound slow or stalled clients.
    /// 0 falls back to keep_alive_timeout_ms. Default: 5000.
    tls_handshake_timeout_ms: u32,
    /// Runtime-effective TLS record-stream watermarks for the native pure-Zig
    /// listener path. Defaults are derived from the fixed record-stream queues.
    tls_buffer_limits: encrypted_stream.BufferLimits,
    /// Downstream write timeout in milliseconds (TARDIGRADE_DOWNSTREAM_WRITE_TIMEOUT_MS).
    /// Applied as SO_SNDTIMEO during response writes; distinct from read timeouts.
    /// 0 = no explicit write deadline. Default: 30000.
    downstream_write_timeout_ms: u32,
    /// Maximum requests served per client connection (0 = unlimited).
    max_requests_per_connection: u32,
    /// Maximum idle connection sessions cached for reuse.
    connection_pool_size: usize,
    /// Maximum in-memory bytes retained per active connection (0 = unlimited).
    max_connection_memory_bytes: usize,
    /// Maximum buffered bytes accepted from an upstream HTTP response body.
    max_buffered_upstream_response_bytes: usize,
    /// Shared proxy body-buffer watermarks and future aggregate hard limits.
    proxy_buffer_limits: http.proxy_buffer_account.Limits,
    /// Proxy streaming policy for data-plane HTTP proxy routes.
    proxy_streaming_mode: ProxyStreamingMode,
    /// Maximum relay buffer used per direction for streaming proxy transfers.
    proxy_stream_buffer_size: usize,
    /// Maximum estimated total connection memory across active clients (0 = unlimited).
    max_total_connection_memory_bytes: usize,
    /// Whether to stream all upstream statuses directly (including non-200) instead of mapping.
    proxy_stream_all_statuses: bool,
    /// Number of upstream attempt retries for proxy requests (minimum 1).
    upstream_retry_attempts: u32,
    /// When true, retries are limited to idempotent HTTP methods (GET, HEAD, PUT, DELETE, OPTIONS, TRACE).
    /// POST and PATCH are never retried when this is enabled (TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY).
    upstream_retry_idempotent_only: bool,
    /// Connect timeout for upstream TCP connections in milliseconds (0 = no limit).
    /// Applied independently of the per-attempt read/write timeout (TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS).
    upstream_connect_timeout_ms: u32,
    /// Maximum time (ms) to wait for the upstream to begin sending a response after the
    /// request is fully sent (0 = disabled, falls back to upstream_timeout_ms).
    /// Only enforced on Unix socket upstreams. Set via TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS.
    upstream_response_timeout_ms: u32,
    /// Total timeout budget across all upstream attempts for a request (ms, 0 = disabled).
    upstream_timeout_budget_ms: u64,
    /// Keep-alive pooling of plain-HTTP upstream connections (#141). When false,
    /// every proxied request opens a fresh `Connection: close` connection.
    upstream_pool_enabled: bool,
    /// Maximum idle upstream connections cached per origin.
    upstream_pool_max_idle_per_host: usize,
    /// Evict an idle upstream connection after this long unused (ms).
    upstream_pool_idle_timeout_ms: u64,
    /// Hard cap on total upstream connection age (ms, 0 = unlimited).
    upstream_pool_max_lifetime_ms: u64,
    /// Fail-fast cap on concurrently checked-out upstream connections per
    /// origin (0 = unlimited). At the cap, requests get 503 upstream_saturated
    /// instead of opening more connections (#239).
    upstream_pool_max_active_per_host: usize,
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
    /// Rewrite rules evaluated before route dispatch.
    rewrite_rules: []RewriteRule,
    /// Return rules evaluated after rewrites and before route dispatch.
    return_rules: []ReturnRule,
    /// Conditional inline `if (...) return|rewrite` rules.
    conditional_rules: []ConditionalRule,
    /// Location blocks loaded from env/config for nginx-style route matching.
    location_blocks: []LocationBlock,
    /// Internal redirect rules evaluated before route dispatch.
    internal_redirect_rules: []InternalRedirectRule,
    /// Named location map for redirect targets prefixed with '@'.
    named_locations: []NamedLocation,
    /// Mirror request rules (best-effort asynchronous copies).
    mirror_rules: []MirrorRule,
    proxy_pass_chat: []const u8,
    proxy_pass_commands_prefix: []const u8,
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
    websocket_enabled: bool,
    websocket_idle_timeout_ms: u32,
    websocket_max_frame_size: usize,
    websocket_ping_interval_ms: u32,
    sse_enabled: bool,
    sse_max_events_per_topic: usize,
    sse_poll_interval_ms: u32,
    sse_max_backlog: u32,
    sse_idle_timeout_ms: u32,
    approval_store_path: []const u8,
    approval_escalation_webhook: []const u8,
    approval_ttl_ms: i64,
    approval_max_pending_per_identity: u32,
    transcript_store_path: []const u8,
    /// Enable W3C Trace Context propagation and OTLP export (TARDIGRADE_OTEL_ENABLED).
    otel_enabled: bool,
    /// OTLP/HTTP endpoint for span export, e.g. `http://jaeger:4318/v1/traces` (TARDIGRADE_OTEL_ENDPOINT).
    otel_endpoint: []const u8,
    /// Sampling rate as an integer percentage 0-100; 100 = sample everything (TARDIGRADE_OTEL_SAMPLE_RATE).
    otel_sample_rate: u32,
    /// Hostname for DNS A/AAAA-based upstream discovery (TARDIGRADE_UPSTREAM_DNS_DISCOVERY_HOST).
    /// When non-empty, Tardigrade periodically resolves this hostname and merges the resulting
    /// addresses into the upstream pool.
    upstream_dns_discovery_host: []const u8,
    /// Port to assign to DNS-discovered upstream addresses (TARDIGRADE_UPSTREAM_DNS_DISCOVERY_PORT).
    upstream_dns_discovery_port: u16,
    /// Whether to use HTTPS for DNS-discovered upstreams (TARDIGRADE_UPSTREAM_DNS_DISCOVERY_TLS).
    upstream_dns_discovery_tls: bool,
    /// How often to re-resolve the discovery hostname in milliseconds (TARDIGRADE_UPSTREAM_DNS_REFRESH_INTERVAL_MS).
    upstream_dns_refresh_interval_ms: u64,

    pub fn deinit(self: *EdgeConfig, allocator: std.mem.Allocator) void {
        allocator.free(self.listen_host);
        allocator.free(self.tls_cert_path);
        allocator.free(self.tls_key_path);
        allocator.free(self.tls_min_version);
        allocator.free(self.tls_max_version);
        allocator.free(self.tls_cipher_list);
        allocator.free(self.tls_cipher_suites);
        allocator.free(self.tls_server_name);
        for (self.tls_sni_certs) |sc| {
            allocator.free(sc.server_name);
            allocator.free(sc.cert_path);
            allocator.free(sc.key_path);
        }
        allocator.free(self.tls_sni_certs);
        allocator.free(self.tls_ocsp_response_path);
        allocator.free(self.tls_acme_directory_url);
        for (self.tls_acme_domains) |d| allocator.free(d);
        allocator.free(self.tls_acme_domains);
        allocator.free(self.tls_acme_email);
        allocator.free(self.tls_acme_account_key_path);
        allocator.free(self.upstream_tls_ca_bundle);
        allocator.free(self.upstream_tls_server_name);
        allocator.free(self.upstream_tls_client_cert);
        allocator.free(self.upstream_tls_client_key);
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
        allocator.free(self.auth_request_url);
        allocator.free(self.jwt_secret);
        allocator.free(self.jwt_issuer);
        allocator.free(self.jwt_audience);
        allocator.free(self.access_control_rules);
        allocator.free(self.proxy_cache_path);
        allocator.free(self.proxy_cache_key_template);
        for (self.geo_blocked_countries) |c| allocator.free(c);
        allocator.free(self.geo_blocked_countries);
        allocator.free(self.geo_country_header);
        for (self.add_headers) |h| {
            allocator.free(h.name);
            allocator.free(h.value);
        }
        allocator.free(self.add_headers);
        for (self.basic_auth_hashes) |h| allocator.free(h);
        allocator.free(self.basic_auth_hashes);
        for (self.auth_token_hashes) |h| allocator.free(h);
        allocator.free(self.auth_token_hashes);
        allocator.free(self.session_store_path);
        allocator.free(self.device_registry_path);
        allocator.free(self.policy_rules_raw);
        allocator.free(self.policy_user_scopes_raw);
        allocator.free(self.policy_approval_routes_raw);
        allocator.free(self.error_log_path);
        allocator.free(self.pid_file);
        allocator.free(self.run_user);
        allocator.free(self.run_group);
        allocator.free(self.chroot_dir);
        for (self.server_names) |name| allocator.free(name);
        allocator.free(self.server_names);
        for (self.server_blocks) |*block| block.deinit(allocator);
        if (self.server_blocks.len > 0) allocator.free(self.server_blocks);
        allocator.free(self.doc_root);
        allocator.free(self.try_files);
        allocator.free(self.access_log_template);
        allocator.free(self.access_log_syslog_udp);
        for (self.log_redact_headers) |name| allocator.free(name);
        allocator.free(self.log_redact_headers);
        allocator.free(self.metrics_path);
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
        for (self.location_blocks) |*block| {
            block.deinit(allocator);
        }
        allocator.free(self.location_blocks);
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
        allocator.free(self.proxy_pass_chat);
        allocator.free(self.proxy_pass_commands_prefix);
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
        allocator.free(self.approval_store_path);
        allocator.free(self.approval_escalation_webhook);
        allocator.free(self.transcript_store_path);
        allocator.free(self.otel_endpoint);
        allocator.free(self.upstream_dns_discovery_host);
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
    const listen_port = try parseConfigPort("listen_port", listen_port_str);

    var tls_cert_path = envOrDefault(allocator, "TARDIGRADE_TLS_CERT_PATH", "") catch unreachable;
    errdefer allocator.free(tls_cert_path);

    var tls_key_path = envOrDefault(allocator, "TARDIGRADE_TLS_KEY_PATH", "") catch unreachable;
    errdefer allocator.free(tls_key_path);
    // The appliance profile's native engine is TLS 1.3-only regardless of
    // this setting; default it to "1.3" there instead of the general
    // profile's "1.2" so an operator who never touches it gets a config
    // that accurately describes what the engine does, and an explicit
    // override to anything else is caught by validateApplianceTlsProfile.
    const tls_min_version = envOrDefault(allocator, "TARDIGRADE_TLS_MIN_VERSION", if (is_appliance_tls_profile) "1.3" else "1.2") catch unreachable;
    errdefer allocator.free(tls_min_version);
    const tls_max_version = envOrDefault(allocator, "TARDIGRADE_TLS_MAX_VERSION", "1.3") catch unreachable;
    errdefer allocator.free(tls_max_version);
    const tls_cipher_list = envOrDefault(allocator, "TARDIGRADE_TLS_CIPHER_LIST", "") catch unreachable;
    errdefer allocator.free(tls_cipher_list);
    const tls_cipher_suites = envOrDefault(allocator, "TARDIGRADE_TLS_CIPHER_SUITES", "") catch unreachable;
    errdefer allocator.free(tls_cipher_suites);
    const tls_server_name = envOrDefault(allocator, "TARDIGRADE_TLS_SERVER_NAME", "") catch unreachable;
    errdefer allocator.free(tls_server_name);
    const tls_sni_certs_raw = envOrDefault(allocator, "TARDIGRADE_TLS_SNI_CERTS", "") catch unreachable;
    defer allocator.free(tls_sni_certs_raw);
    var tls_sni_certs = try parseTlsSniCerts(allocator, tls_sni_certs_raw);
    errdefer {
        for (tls_sni_certs) |sc| {
            allocator.free(sc.server_name);
            allocator.free(sc.cert_path);
            allocator.free(sc.key_path);
        }
        allocator.free(tls_sni_certs);
    }
    // Session cache/tickets are OpenSSL-terminator-only features this
    // owner never constructs in the appliance profile; default them off
    // there (general profile keeps its on-by-default resumption behavior)
    // so an operator who never touches these gets an accurate config, and
    // an explicit override to `true` is caught by validateApplianceTlsProfile.
    const tls_session_cache_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_SESSION_CACHE", !is_appliance_tls_profile);
    const tls_session_cache_size = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_SESSION_CACHE_SIZE", 20_480);
    const tls_session_timeout_seconds = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_SESSION_TIMEOUT_SECONDS", 300);
    const tls_session_tickets_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_SESSION_TICKETS", !is_appliance_tls_profile);
    const tls_ocsp_stapling_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_OCSP_STAPLING", false);
    const tls_ocsp_response_path = envOrDefault(allocator, "TARDIGRADE_TLS_OCSP_RESPONSE_PATH", "") catch unreachable;
    errdefer allocator.free(tls_ocsp_response_path);
    const tls_ocsp_auto_refresh = parseBoolEnv(allocator, "TARDIGRADE_TLS_OCSP_AUTO_REFRESH", false);
    const tls_ocsp_refresh_interval_ms = parseIntEnv(u64, allocator, "TARDIGRADE_TLS_OCSP_REFRESH_INTERVAL_MS", 3_600_000);
    const tls_ocsp_refresh_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_OCSP_REFRESH_TIMEOUT_MS", 10_000);
    const tls_client_ca_path = envOrDefault(allocator, "TARDIGRADE_TLS_CLIENT_CA_PATH", "") catch unreachable;
    errdefer allocator.free(tls_client_ca_path);
    const tls_client_verify = parseBoolEnv(allocator, "TARDIGRADE_TLS_CLIENT_VERIFY", false);
    const tls_client_verify_depth = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_CLIENT_VERIFY_DEPTH", 3);
    const tls_crl_path = envOrDefault(allocator, "TARDIGRADE_TLS_CRL_PATH", "") catch unreachable;
    errdefer allocator.free(tls_crl_path);
    const tls_crl_check = parseBoolEnv(allocator, "TARDIGRADE_TLS_CRL_CHECK", false);
    // Dynamic file-watching is an OpenSSL-terminator-only feature this
    // owner never constructs in the appliance profile; default it off
    // there (general profile keeps its on-by-default watcher) so an
    // operator who never touches this gets an accurate config, and an
    // explicit nonzero override is caught by validateApplianceTlsProfile.
    const tls_dynamic_reload_interval_ms = parseIntEnv(u64, allocator, "TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS", if (is_appliance_tls_profile) 0 else 5000);
    const tls_acme_enabled = parseBoolEnv(allocator, "TARDIGRADE_TLS_ACME_ENABLED", false);
    const tls_acme_cert_dir = envOrDefault(allocator, "TARDIGRADE_TLS_ACME_CERT_DIR", "") catch unreachable;
    errdefer allocator.free(tls_acme_cert_dir);
    const tls_acme_directory_url = envOrDefault(allocator, "TARDIGRADE_TLS_ACME_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory") catch unreachable;
    errdefer allocator.free(tls_acme_directory_url);
    const tls_acme_domains_raw = envOrDefault(allocator, "TARDIGRADE_TLS_ACME_DOMAINS", "") catch unreachable;
    defer allocator.free(tls_acme_domains_raw);
    const tls_acme_domains = try parseCsvValues(allocator, tls_acme_domains_raw);
    errdefer {
        for (tls_acme_domains) |d| allocator.free(d);
        allocator.free(tls_acme_domains);
    }
    const tls_acme_email = envOrDefault(allocator, "TARDIGRADE_TLS_ACME_EMAIL", "") catch unreachable;
    errdefer allocator.free(tls_acme_email);
    const tls_acme_account_key_path = envOrDefault(allocator, "TARDIGRADE_TLS_ACME_ACCOUNT_KEY_PATH", "") catch unreachable;
    errdefer allocator.free(tls_acme_account_key_path);
    const tls_acme_renew_days_before_expiry = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_ACME_RENEW_DAYS_BEFORE_EXPIRY", 30);
    const upstream_protocol_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_PROTOCOL", "http1") catch unreachable;
    defer allocator.free(upstream_protocol_str);
    const upstream_protocol = try parseUpstreamProtocolConfig(upstream_protocol_str);
    const upstream_tls_verify = parseBoolEnv(allocator, "TARDIGRADE_UPSTREAM_TLS_VERIFY", true);
    const upstream_tls_ca_bundle = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TLS_CA_BUNDLE", "") catch unreachable;
    errdefer allocator.free(upstream_tls_ca_bundle);
    const upstream_tls_server_name = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TLS_SERVER_NAME", "") catch unreachable;
    errdefer allocator.free(upstream_tls_server_name);
    const upstream_tls_client_cert = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TLS_CLIENT_CERT", "") catch unreachable;
    errdefer allocator.free(upstream_tls_client_cert);
    const upstream_tls_client_key = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TLS_CLIENT_KEY", "") catch unreachable;
    errdefer allocator.free(upstream_tls_client_key);
    const http1_enabled = parseBoolEnv(allocator, "TARDIGRADE_HTTP1_ENABLED", true);
    const http2_enabled = parseBoolEnv(allocator, "TARDIGRADE_HTTP2_ENABLED", true);
    const tls_http1_no_alpn_fallback = parseBoolEnv(allocator, "TARDIGRADE_TLS_HTTP1_NO_ALPN_FALLBACK", false);
    const http3_enabled = parseBoolEnv(allocator, "TARDIGRADE_HTTP3_ENABLED", false);
    const quic_port_str = envOrDefault(allocator, "TARDIGRADE_QUIC_PORT", "443") catch unreachable;
    defer allocator.free(quic_port_str);
    const quic_port = try parseConfigPort("quic_port", quic_port_str);
    const http3_enable_0rtt = parseBoolEnv(allocator, "TARDIGRADE_HTTP3_ENABLE_0RTT", false);
    const http3_connection_migration = parseBoolEnv(allocator, "TARDIGRADE_HTTP3_CONNECTION_MIGRATION", false);
    const http3_max_datagram_size = parseIntEnv(usize, allocator, "TARDIGRADE_HTTP3_MAX_DATAGRAM_SIZE", 1350);
    const proxy_protocol_mode_str = envOrDefault(allocator, "TARDIGRADE_PROXY_PROTOCOL", "off") catch unreachable;
    defer allocator.free(proxy_protocol_mode_str);
    const proxy_protocol_mode = try parseProxyProtocolModeConfig(proxy_protocol_mode_str);
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
        return error.InvalidUpstreamBaseUrlWeightsCount;
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
        return error.InvalidUpstreamBaseUrlWeightsCount;
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
    const upstream_lb_algorithm = try parseUpstreamLbAlgorithmConfig(lb_algo_str);

    const timeout_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TIMEOUT_MS", "10000") catch unreachable;
    defer allocator.free(timeout_str);
    const upstream_timeout_ms = std.fmt.parseInt(u32, timeout_str, 10) catch 10000;
    const auth_request_url = envOrDefault(allocator, "TARDIGRADE_AUTH_REQUEST_URL", "") catch unreachable;
    errdefer allocator.free(auth_request_url);
    const jwt_secret = envOrDefault(allocator, "TARDIGRADE_JWT_SECRET", "") catch unreachable;
    errdefer allocator.free(jwt_secret);
    const jwt_issuer = envOrDefault(allocator, "TARDIGRADE_JWT_ISSUER", "") catch unreachable;
    errdefer allocator.free(jwt_issuer);
    const jwt_audience = envOrDefault(allocator, "TARDIGRADE_JWT_AUDIENCE", "") catch unreachable;
    errdefer allocator.free(jwt_audience);

    const rate_rps_str = envOrDefault(allocator, "TARDIGRADE_RATE_LIMIT_RPS", "10") catch unreachable;
    defer allocator.free(rate_rps_str);
    const rate_limit_rps = std.fmt.parseFloat(f64, rate_rps_str) catch 10.0;

    const rate_burst_str = envOrDefault(allocator, "TARDIGRADE_RATE_LIMIT_BURST", "20") catch unreachable;
    defer allocator.free(rate_burst_str);
    const rate_limit_burst = std.fmt.parseInt(u32, rate_burst_str, 10) catch 20;

    const sec_headers_str = envOrDefault(allocator, "TARDIGRADE_SECURITY_HEADERS", "true") catch unreachable;
    defer allocator.free(sec_headers_str);
    const security_headers_enabled = std.mem.eql(u8, sec_headers_str, "true") or std.mem.eql(u8, sec_headers_str, "1");
    const hsts_enabled = parseBoolEnv(allocator, "TARDIGRADE_HSTS_ENABLED", false);
    const hsts_max_age = parseIntEnv(u32, allocator, "TARDIGRADE_HSTS_MAX_AGE", 31536000);
    const hsts_include_subdomains = parseBoolEnv(allocator, "TARDIGRADE_HSTS_INCLUDE_SUBDOMAINS", true);
    const hsts_preload = parseBoolEnv(allocator, "TARDIGRADE_HSTS_PRELOAD", false);

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

    const max_hdr_total_str = envOrDefault(allocator, "TARDIGRADE_MAX_HEADERS_TOTAL_SIZE", "0") catch unreachable;
    defer allocator.free(max_hdr_total_str);
    const max_headers_total_size = std.fmt.parseInt(usize, max_hdr_total_str, 10) catch 0;

    const body_timeout_str = envOrDefault(allocator, "TARDIGRADE_BODY_TIMEOUT_MS", "0") catch unreachable;
    defer allocator.free(body_timeout_str);
    const body_timeout_ms = std.fmt.parseInt(u32, body_timeout_str, 10) catch 0;

    const header_timeout_str = envOrDefault(allocator, "TARDIGRADE_HEADER_TIMEOUT_MS", "10000") catch unreachable;
    defer allocator.free(header_timeout_str);
    const header_timeout_ms = std.fmt.parseInt(u32, header_timeout_str, 10) catch 10_000;

    // Basic auth
    const raw_basic_hashes = envOrDefault(allocator, "TARDIGRADE_BASIC_AUTH_HASHES", "") catch unreachable;
    defer allocator.free(raw_basic_hashes);
    const basic_auth_hashes = try parseHashes(allocator, raw_basic_hashes);
    const raw_auth_token_hashes = envOrDefault(allocator, "TARDIGRADE_AUTH_TOKEN_HASHES", "") catch unreachable;
    defer allocator.free(raw_auth_token_hashes);
    const auth_token_hashes = try parseHashes(allocator, raw_auth_token_hashes);
    const session_ttl_seconds = parseIntEnv(u32, allocator, "TARDIGRADE_SESSION_TTL_SECONDS", 3600);
    const session_max = parseIntEnv(u32, allocator, "TARDIGRADE_SESSION_MAX", 128);
    const session_store_path = envOrDefault(allocator, "TARDIGRADE_SESSION_STORE_PATH", "") catch unreachable;
    errdefer allocator.free(session_store_path);
    const device_registry_path = envOrDefault(allocator, "TARDIGRADE_DEVICE_REGISTRY_PATH", "") catch unreachable;
    errdefer allocator.free(device_registry_path);
    const policy_rules_raw = envOrDefault(allocator, "TARDIGRADE_POLICY_RULES", "") catch unreachable;
    errdefer allocator.free(policy_rules_raw);
    const policy_user_scopes_raw = envOrDefault(allocator, "TARDIGRADE_POLICY_USER_SCOPES", "") catch unreachable;
    errdefer allocator.free(policy_user_scopes_raw);
    const policy_approval_routes_raw = envOrDefault(allocator, "TARDIGRADE_POLICY_APPROVAL_ROUTES", "") catch unreachable;
    errdefer allocator.free(policy_approval_routes_raw);

    // Log level
    const log_level_str = envOrDefault(allocator, "TARDIGRADE_LOG_LEVEL", "info") catch unreachable;
    defer allocator.free(log_level_str);
    const log_level = try parseLogLevelConfig(log_level_str);
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
    const server_blocks_raw = envOrDefault(allocator, "TARDIGRADE_SERVER_BLOCKS", "") catch unreachable;
    defer allocator.free(server_blocks_raw);
    const server_blocks = try parseServerBlocks(allocator, server_blocks_raw);
    errdefer {
        for (server_blocks) |*block| block.deinit(allocator);
        allocator.free(server_blocks);
    }
    try applyServerBlockTlsConfig(allocator, &tls_cert_path, &tls_key_path, &tls_sni_certs, server_blocks);
    const doc_root = envOrDefault(allocator, "TARDIGRADE_DOC_ROOT", "") catch unreachable;
    errdefer allocator.free(doc_root);
    const try_files = envOrDefault(allocator, "TARDIGRADE_TRY_FILES", "") catch unreachable;
    errdefer allocator.free(try_files);
    const access_log_format_str = envOrDefault(allocator, "TARDIGRADE_ACCESS_LOG_FORMAT", "json") catch unreachable;
    defer allocator.free(access_log_format_str);
    const access_log_format = try parseAccessLogFormatConfig(access_log_format_str);
    const access_log_template = envOrDefault(allocator, "TARDIGRADE_ACCESS_LOG_TEMPLATE", "") catch unreachable;
    errdefer allocator.free(access_log_template);
    const access_log_min_status = parseIntEnv(u16, allocator, "TARDIGRADE_ACCESS_LOG_MIN_STATUS", 0);
    const access_log_buffer_size = parseIntEnv(usize, allocator, "TARDIGRADE_ACCESS_LOG_BUFFER_SIZE", 0);
    const access_log_syslog_udp = envOrDefault(allocator, "TARDIGRADE_ACCESS_LOG_SYSLOG_UDP", "") catch unreachable;
    errdefer allocator.free(access_log_syslog_udp);
    const log_redact_headers_raw = envOrDefault(allocator, "TARDIGRADE_REDACT_HEADERS", "") catch unreachable;
    defer allocator.free(log_redact_headers_raw);
    const log_redact_headers = try parseCsvValues(allocator, log_redact_headers_raw);
    errdefer {
        for (log_redact_headers) |name| allocator.free(name);
        allocator.free(log_redact_headers);
    }
    const metrics_path = envOrDefault(allocator, "TARDIGRADE_METRICS_PATH", "/status/metrics") catch unreachable;
    errdefer allocator.free(metrics_path);
    const metrics_require_auth = parseBoolEnv(allocator, "TARDIGRADE_METRICS_REQUIRE_AUTH", false);

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
    const worker_max_queue_depth = parseIntEnv(usize, allocator, "TARDIGRADE_WORKER_MAX_QUEUE_DEPTH", 0);
    const shutdown_drain_timeout_ms = parseIntEnv(u64, allocator, "TARDIGRADE_SHUTDOWN_DRAIN_TIMEOUT_MS", 30_000);
    const websocket_enabled = parseBoolEnv(allocator, "TARDIGRADE_WEBSOCKET_ENABLED", false);
    const websocket_idle_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_WEBSOCKET_IDLE_TIMEOUT_MS", 30_000);
    const websocket_max_frame_size = parseIntEnv(usize, allocator, "TARDIGRADE_WEBSOCKET_MAX_FRAME_SIZE", 64 * 1024);
    const websocket_ping_interval_ms = parseIntEnv(u32, allocator, "TARDIGRADE_WEBSOCKET_PING_INTERVAL_MS", 15_000);
    const sse_enabled = parseBoolEnv(allocator, "TARDIGRADE_SSE_ENABLED", false);
    const sse_max_events_per_topic = parseIntEnv(usize, allocator, "TARDIGRADE_SSE_MAX_EVENTS_PER_TOPIC", 128);
    const sse_poll_interval_ms = parseIntEnv(u32, allocator, "TARDIGRADE_SSE_POLL_INTERVAL_MS", 250);
    const sse_max_backlog = parseIntEnv(u32, allocator, "TARDIGRADE_SSE_MAX_BACKLOG", 128);
    const sse_idle_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_SSE_IDLE_TIMEOUT_MS", 30_000);
    const approval_store_path = envOrDefault(allocator, "TARDIGRADE_APPROVAL_STORE_PATH", "") catch unreachable;
    errdefer allocator.free(approval_store_path);
    const approval_escalation_webhook = envOrDefault(allocator, "TARDIGRADE_APPROVAL_ESCALATION_WEBHOOK", "") catch unreachable;
    errdefer allocator.free(approval_escalation_webhook);
    const approval_ttl_ms = parseIntEnv(i64, allocator, "TARDIGRADE_APPROVAL_TTL_MS", 300_000);
    const approval_max_pending_per_identity = parseIntEnv(u32, allocator, "TARDIGRADE_APPROVAL_MAX_PENDING_PER_IDENTITY", 0);
    const transcript_store_path = envOrDefault(allocator, "TARDIGRADE_TRANSCRIPT_STORE_PATH", "") catch unreachable;
    errdefer allocator.free(transcript_store_path);
    const otel_enabled = parseBoolEnv(allocator, "TARDIGRADE_OTEL_ENABLED", false);
    const otel_endpoint = envOrDefault(allocator, "TARDIGRADE_OTEL_ENDPOINT", "") catch unreachable;
    errdefer allocator.free(otel_endpoint);
    const otel_sample_rate = parseIntEnv(u32, allocator, "TARDIGRADE_OTEL_SAMPLE_RATE", 100);
    const upstream_dns_discovery_host = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_DNS_DISCOVERY_HOST", "") catch unreachable;
    errdefer allocator.free(upstream_dns_discovery_host);
    const upstream_dns_discovery_port = parseIntEnv(u16, allocator, "TARDIGRADE_UPSTREAM_DNS_DISCOVERY_PORT", 80);
    const upstream_dns_discovery_tls = parseBoolEnv(allocator, "TARDIGRADE_UPSTREAM_DNS_DISCOVERY_TLS", false);
    const upstream_dns_refresh_interval_ms = parseIntEnv(u64, allocator, "TARDIGRADE_UPSTREAM_DNS_REFRESH_INTERVAL_MS", 30_000);

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

    const max_in_flight_requests = parseIntEnv(u32, allocator, "TARDIGRADE_MAX_IN_FLIGHT_REQUESTS", 0);

    const keep_alive_timeout_str = envOrDefault(allocator, "TARDIGRADE_KEEP_ALIVE_TIMEOUT_MS", "5000") catch unreachable;
    defer allocator.free(keep_alive_timeout_str);
    const keep_alive_timeout_ms = std.fmt.parseInt(u32, keep_alive_timeout_str, 10) catch 5000;

    const request_total_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_REQUEST_TOTAL_TIMEOUT_MS", 0);
    const tls_handshake_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_TLS_HANDSHAKE_TIMEOUT_MS", 5_000);
    const tls_buffer_limits = tlsBufferLimitsFromEnv(allocator);
    const downstream_write_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_DOWNSTREAM_WRITE_TIMEOUT_MS", 30_000);

    const max_req_conn_str = envOrDefault(allocator, "TARDIGRADE_MAX_REQUESTS_PER_CONNECTION", "100") catch unreachable;
    defer allocator.free(max_req_conn_str);
    const max_requests_per_connection = std.fmt.parseInt(u32, max_req_conn_str, 10) catch 100;

    const conn_pool_size_str = envOrDefault(allocator, "TARDIGRADE_CONNECTION_POOL_SIZE", "256") catch unreachable;
    defer allocator.free(conn_pool_size_str);
    const connection_pool_size = std.fmt.parseInt(usize, conn_pool_size_str, 10) catch 256;

    const max_conn_mem_str = envOrDefault(allocator, "TARDIGRADE_MAX_CONNECTION_MEMORY_BYTES", "2097152") catch unreachable;
    defer allocator.free(max_conn_mem_str);
    const max_connection_memory_bytes = std.fmt.parseInt(usize, max_conn_mem_str, 10) catch 2 * 1024 * 1024;

    const max_buffered_upstream_resp_str = envOrDefault(allocator, "TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES", "262144") catch unreachable;
    defer allocator.free(max_buffered_upstream_resp_str);
    const max_buffered_upstream_response_bytes = std.fmt.parseInt(usize, max_buffered_upstream_resp_str, 10) catch 256 * 1024;
    const proxy_buffer_limits = http.proxy_buffer_account.Limits{
        .per_stream_low_watermark = parseIntEnv(usize, allocator, "TARDIGRADE_PROXY_BUFFER_PER_STREAM_LOW_WATERMARK_BYTES", 256 * 1024),
        .per_stream_high_watermark = parseIntEnv(usize, allocator, "TARDIGRADE_PROXY_BUFFER_PER_STREAM_HIGH_WATERMARK_BYTES", 768 * 1024),
        .per_stream_hard_limit = parseIntEnv(usize, allocator, "TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES", 1024 * 1024),
        .per_origin_hard_limit = parseIntEnv(usize, allocator, "TARDIGRADE_PROXY_BUFFER_PER_ORIGIN_HARD_LIMIT_BYTES", 0),
        .global_hard_limit = parseIntEnv(usize, allocator, "TARDIGRADE_PROXY_BUFFER_GLOBAL_HARD_LIMIT_BYTES", 0),
    };

    const proxy_streaming_mode_str = envOrDefault(allocator, "TARDIGRADE_PROXY_STREAMING_MODE", "off") catch unreachable;
    defer allocator.free(proxy_streaming_mode_str);
    const proxy_streaming_mode = try parseProxyStreamingModeConfig(proxy_streaming_mode_str);
    const proxy_stream_buffer_size = parseIntEnv(usize, allocator, "TARDIGRADE_PROXY_STREAM_BUFFER_SIZE", 16 * 1024);

    const max_total_conn_mem_str = envOrDefault(allocator, "TARDIGRADE_MAX_TOTAL_CONNECTION_MEMORY_BYTES", "0") catch unreachable;
    defer allocator.free(max_total_conn_mem_str);
    const max_total_connection_memory_bytes = std.fmt.parseInt(usize, max_total_conn_mem_str, 10) catch 0;

    const stream_all_statuses_str = envOrDefault(allocator, "TARDIGRADE_PROXY_STREAM_ALL_STATUSES", "false") catch unreachable;
    defer allocator.free(stream_all_statuses_str);
    const proxy_stream_all_statuses = std.mem.eql(u8, stream_all_statuses_str, "true") or std.mem.eql(u8, stream_all_statuses_str, "1");

    const retry_attempts_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS", "1") catch unreachable;
    defer allocator.free(retry_attempts_str);
    const upstream_retry_attempts = @max(std.fmt.parseInt(u32, retry_attempts_str, 10) catch 1, 1);
    const upstream_retry_idempotent_only = parseBoolEnv(allocator, "TARDIGRADE_UPSTREAM_RETRY_IDEMPOTENT_ONLY", true);
    const upstream_connect_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_UPSTREAM_CONNECT_TIMEOUT_MS", 5_000);
    const upstream_response_timeout_ms = parseIntEnv(u32, allocator, "TARDIGRADE_UPSTREAM_RESPONSE_TIMEOUT_MS", 0);

    const timeout_budget_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS", "0") catch unreachable;
    defer allocator.free(timeout_budget_str);
    const upstream_timeout_budget_ms = std.fmt.parseInt(u64, timeout_budget_str, 10) catch 0;

    const upstream_pool_enabled = parseBoolEnv(allocator, "TARDIGRADE_UPSTREAM_POOL_ENABLED", true);
    const upstream_pool_max_idle_per_host = parseIntEnv(usize, allocator, "TARDIGRADE_UPSTREAM_POOL_MAX_IDLE_PER_HOST", 32);
    const upstream_pool_idle_timeout_ms = parseIntEnv(u64, allocator, "TARDIGRADE_UPSTREAM_POOL_IDLE_TIMEOUT_MS", 90_000);
    const upstream_pool_max_lifetime_ms = parseIntEnv(u64, allocator, "TARDIGRADE_UPSTREAM_POOL_MAX_LIFETIME_MS", 0);
    const upstream_pool_max_active_per_host = parseIntEnv(usize, allocator, "TARDIGRADE_UPSTREAM_POOL_MAX_ACTIVE_PER_HOST", 0);

    const max_fails_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_MAX_FAILS", "0") catch unreachable;
    defer allocator.free(max_fails_str);
    const upstream_max_fails = std.fmt.parseInt(u32, max_fails_str, 10) catch 0;

    const fail_timeout_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_FAIL_TIMEOUT_MS", "10000") catch unreachable;
    defer allocator.free(fail_timeout_str);
    const upstream_fail_timeout_ms = std.fmt.parseInt(u64, fail_timeout_str, 10) catch 10_000;

    const active_health_interval_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_PROBE_INTERVAL_MS",
        "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_INTERVAL_MS",
        "0",
    ) catch unreachable;
    defer allocator.free(active_health_interval_str);
    const upstream_active_health_interval_ms = std.fmt.parseInt(u64, active_health_interval_str, 10) catch 0;

    const upstream_active_health_path = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_PROBE_PATH",
        "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_PATH",
        "/",
    ) catch unreachable;
    errdefer allocator.free(upstream_active_health_path);

    const active_health_timeout_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_PROBE_TIMEOUT_MS",
        "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_TIMEOUT_MS",
        "2000",
    ) catch unreachable;
    defer allocator.free(active_health_timeout_str);
    const upstream_active_health_timeout_ms = std.fmt.parseInt(u32, active_health_timeout_str, 10) catch 2000;

    const active_health_fail_threshold_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_PROBE_FAIL_THRESHOLD",
        "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_FAIL_THRESHOLD",
        "1",
    ) catch unreachable;
    defer allocator.free(active_health_fail_threshold_str);
    const upstream_active_health_fail_threshold = @max(std.fmt.parseInt(u32, active_health_fail_threshold_str, 10) catch 1, 1);

    const active_health_success_threshold_str = envOrDefault(allocator, "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_THRESHOLD", "1") catch unreachable;
    defer allocator.free(active_health_success_threshold_str);
    const upstream_active_health_success_threshold = @max(std.fmt.parseInt(u32, active_health_success_threshold_str, 10) catch 1, 1);

    const active_health_success_status_str = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS",
        "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS",
        "200-299",
    ) catch unreachable;
    defer allocator.free(active_health_success_status_str);
    const upstream_active_health_success_status = parseHealthStatusRange(active_health_success_status_str) catch EdgeConfig.HealthStatusRange{ .min = 200, .max = 299 };

    const active_health_success_status_overrides_raw = envOrDefaultAlias(
        allocator,
        "TARDIGRADE_UPSTREAM_PROBE_SUCCESS_STATUS_OVERRIDES",
        "TARDIGRADE_UPSTREAM_ACTIVE_PROBE_SUCCESS_STATUS_OVERRIDES",
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
    const location_blocks_raw = envOrDefault(allocator, "TARDIGRADE_LOCATION_BLOCKS", "") catch unreachable;
    defer allocator.free(location_blocks_raw);
    const location_blocks = try parseLocationBlocks(allocator, location_blocks_raw);
    errdefer {
        for (location_blocks) |*block| {
            block.deinit(allocator);
        }
        allocator.free(location_blocks);
    }
    const location_error_pages_raw = envOrDefault(allocator, "TARDIGRADE_LOCATION_ERROR_PAGES", "") catch unreachable;
    defer allocator.free(location_error_pages_raw);
    try applyLocationErrorPages(allocator, location_blocks, location_error_pages_raw);
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
    const proxy_pass_chat = envOrDefault(allocator, "TARDIGRADE_PROXY_PASS_CHAT", "") catch unreachable;
    errdefer allocator.free(proxy_pass_chat);
    const proxy_pass_commands_prefix = envOrDefault(allocator, "TARDIGRADE_PROXY_PASS_COMMANDS_PREFIX", "") catch unreachable;
    errdefer allocator.free(proxy_pass_commands_prefix);
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
        .tls_server_name = tls_server_name,
        .tls_sni_certs = tls_sni_certs,
        .tls_session_cache_enabled = tls_session_cache_enabled,
        .tls_session_cache_size = tls_session_cache_size,
        .tls_session_timeout_seconds = tls_session_timeout_seconds,
        .tls_session_tickets_enabled = tls_session_tickets_enabled,
        .tls_ocsp_stapling_enabled = tls_ocsp_stapling_enabled,
        .tls_ocsp_response_path = tls_ocsp_response_path,
        .tls_ocsp_auto_refresh = tls_ocsp_auto_refresh,
        .tls_ocsp_refresh_interval_ms = tls_ocsp_refresh_interval_ms,
        .tls_ocsp_refresh_timeout_ms = tls_ocsp_refresh_timeout_ms,
        .tls_client_ca_path = tls_client_ca_path,
        .tls_client_verify = tls_client_verify,
        .tls_client_verify_depth = tls_client_verify_depth,
        .tls_crl_path = tls_crl_path,
        .tls_crl_check = tls_crl_check,
        .tls_dynamic_reload_interval_ms = tls_dynamic_reload_interval_ms,
        .tls_acme_enabled = tls_acme_enabled,
        .tls_acme_cert_dir = tls_acme_cert_dir,
        .tls_acme_directory_url = tls_acme_directory_url,
        .tls_acme_domains = tls_acme_domains,
        .tls_acme_email = tls_acme_email,
        .tls_acme_account_key_path = tls_acme_account_key_path,
        .tls_acme_renew_days_before_expiry = tls_acme_renew_days_before_expiry,
        .http1_enabled = http1_enabled,
        .http2_enabled = http2_enabled,
        .tls_http1_no_alpn_fallback = tls_http1_no_alpn_fallback,
        .upstream_protocol = upstream_protocol,
        .upstream_tls_verify = upstream_tls_verify,
        .upstream_tls_ca_bundle = upstream_tls_ca_bundle,
        .upstream_tls_server_name = upstream_tls_server_name,
        .upstream_tls_client_cert = upstream_tls_client_cert,
        .upstream_tls_client_key = upstream_tls_client_key,
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
        .upstream_timeout_ms = upstream_timeout_ms,
        .auth_request_url = auth_request_url,
        .jwt_secret = jwt_secret,
        .jwt_issuer = jwt_issuer,
        .jwt_audience = jwt_audience,
        .rate_limit_rps = rate_limit_rps,
        .rate_limit_burst = rate_limit_burst,
        .security_headers_enabled = security_headers_enabled,
        .hsts_enabled = hsts_enabled,
        .hsts_max_age = hsts_max_age,
        .hsts_include_subdomains = hsts_include_subdomains,
        .hsts_preload = hsts_preload,
        .idempotency_ttl_seconds = idempotency_ttl_seconds,
        .proxy_cache_ttl_seconds = proxy_cache_ttl_seconds,
        .proxy_cache_path = proxy_cache_path,
        .proxy_cache_key_template = proxy_cache_key_template,
        .proxy_cache_stale_while_revalidate_seconds = proxy_cache_stale_while_revalidate_seconds,
        .proxy_cache_lock_timeout_ms = proxy_cache_lock_timeout_ms,
        .proxy_cache_manager_interval_ms = proxy_cache_manager_interval_ms,
        .geo_blocked_countries = geo_blocked_countries,
        .geo_country_header = geo_country_header,
        .add_headers = add_headers,
        .access_control_rules = access_control_rules,
        .request_limits = .{
            .max_body_size = max_body_size,
            .max_uri_length = max_uri_length,
            .max_header_count = max_header_count,
            .max_header_size = max_header_size,
            .max_headers_total_size = max_headers_total_size,
            .body_timeout_ms = body_timeout_ms,
            .header_timeout_ms = header_timeout_ms,
        },
        .basic_auth_hashes = basic_auth_hashes,
        .auth_token_hashes = auth_token_hashes,
        .session_ttl_seconds = session_ttl_seconds,
        .session_max = session_max,
        .session_store_path = session_store_path,
        .device_registry_path = device_registry_path,
        .policy_rules_raw = policy_rules_raw,
        .policy_user_scopes_raw = policy_user_scopes_raw,
        .policy_approval_routes_raw = policy_approval_routes_raw,
        .log_level = log_level,
        .error_log_path = error_log_path,
        .pid_file = pid_file,
        .run_user = run_user,
        .run_group = run_group,
        .chroot_dir = chroot_dir,
        .require_unprivileged_user = require_unprivileged_user,
        .server_names = server_names,
        .server_blocks = server_blocks,
        .doc_root = doc_root,
        .try_files = try_files,
        .access_log_format = access_log_format,
        .access_log_template = access_log_template,
        .access_log_min_status = access_log_min_status,
        .access_log_buffer_size = access_log_buffer_size,
        .access_log_syslog_udp = access_log_syslog_udp,
        .log_redact_headers = log_redact_headers,
        .metrics_path = metrics_path,
        .metrics_require_auth = metrics_require_auth,
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
        .worker_max_queue_depth = worker_max_queue_depth,
        .shutdown_drain_timeout_ms = shutdown_drain_timeout_ms,
        .fd_soft_limit = fd_soft_limit,
        .max_connections_per_ip = max_connections_per_ip,
        .max_active_connections = max_active_connections,
        .max_in_flight_requests = max_in_flight_requests,
        .keep_alive_timeout_ms = keep_alive_timeout_ms,
        .request_total_timeout_ms = request_total_timeout_ms,
        .tls_handshake_timeout_ms = tls_handshake_timeout_ms,
        .tls_buffer_limits = tls_buffer_limits,
        .downstream_write_timeout_ms = downstream_write_timeout_ms,
        .max_requests_per_connection = max_requests_per_connection,
        .connection_pool_size = connection_pool_size,
        .max_connection_memory_bytes = max_connection_memory_bytes,
        .max_buffered_upstream_response_bytes = max_buffered_upstream_response_bytes,
        .proxy_buffer_limits = proxy_buffer_limits,
        .proxy_streaming_mode = proxy_streaming_mode,
        .proxy_stream_buffer_size = proxy_stream_buffer_size,
        .max_total_connection_memory_bytes = max_total_connection_memory_bytes,
        .proxy_stream_all_statuses = proxy_stream_all_statuses,
        .upstream_retry_attempts = upstream_retry_attempts,
        .upstream_retry_idempotent_only = upstream_retry_idempotent_only,
        .upstream_connect_timeout_ms = upstream_connect_timeout_ms,
        .upstream_response_timeout_ms = upstream_response_timeout_ms,
        .upstream_timeout_budget_ms = upstream_timeout_budget_ms,
        .upstream_pool_enabled = upstream_pool_enabled,
        .upstream_pool_max_idle_per_host = upstream_pool_max_idle_per_host,
        .upstream_pool_idle_timeout_ms = upstream_pool_idle_timeout_ms,
        .upstream_pool_max_lifetime_ms = upstream_pool_max_lifetime_ms,
        .upstream_pool_max_active_per_host = upstream_pool_max_active_per_host,
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
        .rewrite_rules = rewrite_rules,
        .return_rules = return_rules,
        .conditional_rules = conditional_rules,
        .location_blocks = location_blocks,
        .internal_redirect_rules = internal_redirect_rules,
        .named_locations = named_locations,
        .mirror_rules = mirror_rules,
        .proxy_pass_chat = proxy_pass_chat,
        .proxy_pass_commands_prefix = proxy_pass_commands_prefix,
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
        .websocket_enabled = websocket_enabled,
        .websocket_idle_timeout_ms = websocket_idle_timeout_ms,
        .websocket_max_frame_size = websocket_max_frame_size,
        .websocket_ping_interval_ms = websocket_ping_interval_ms,
        .sse_enabled = sse_enabled,
        .sse_max_events_per_topic = sse_max_events_per_topic,
        .sse_poll_interval_ms = sse_poll_interval_ms,
        .sse_max_backlog = sse_max_backlog,
        .sse_idle_timeout_ms = sse_idle_timeout_ms,
        .approval_store_path = approval_store_path,
        .approval_escalation_webhook = approval_escalation_webhook,
        .approval_ttl_ms = approval_ttl_ms,
        .approval_max_pending_per_identity = approval_max_pending_per_identity,
        .transcript_store_path = transcript_store_path,
        .otel_enabled = otel_enabled,
        .otel_endpoint = otel_endpoint,
        .otel_sample_rate = otel_sample_rate,
        .upstream_dns_discovery_host = upstream_dns_discovery_host,
        .upstream_dns_discovery_port = upstream_dns_discovery_port,
        .upstream_dns_discovery_tls = upstream_dns_discovery_tls,
        .upstream_dns_refresh_interval_ms = upstream_dns_refresh_interval_ms,
    };
}

const server_block_record_sep = "\x1e";
const server_block_field_sep = "\x1f";

fn parseServerBlocks(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.ServerBlock {
    if (std.mem.trim(u8, raw, " \t\r\n").len == 0) return &.{};
    var out = std.ArrayList(EdgeConfig.ServerBlock).empty;
    errdefer {
        for (out.items) |*block| block.deinit(allocator);
        out.deinit(allocator);
    }
    var records = std.mem.splitSequence(u8, raw, server_block_record_sep);
    while (records.next()) |record| {
        if (record.len == 0) continue;
        var fields = std.mem.splitSequence(u8, record, server_block_field_sep);
        const names_raw = fields.next() orelse return error.InvalidServerBlockFormat;
        const doc_root = fields.next() orelse return error.InvalidServerBlockFormat;
        const try_files = fields.next() orelse return error.InvalidServerBlockFormat;
        const tls_cert_path = fields.next() orelse return error.InvalidServerBlockFormat;
        const tls_key_path = fields.next() orelse return error.InvalidServerBlockFormat;
        const upstream_base_url = fields.next() orelse return error.InvalidServerBlockFormat;
        const rem_a = fields.next() orelse return error.InvalidServerBlockFormat;
        const rem_b = fields.next();
        const rem_c = fields.next();
        if (fields.next() != null) return error.InvalidServerBlockFormat;

        const route_fields = try parseServerBlockRouteFields(rem_a, rem_b, rem_c);

        const names = try parseServerNames(allocator, names_raw);
        errdefer {
            for (names) |name| allocator.free(name);
            allocator.free(names);
        }
        const location_blocks = try parseLocationBlocks(allocator, route_fields.location_blocks_raw);
        errdefer {
            for (location_blocks) |*block| block.deinit(allocator);
            allocator.free(location_blocks);
        }
        try out.append(allocator, .{
            .server_names = names,
            .doc_root = try allocator.dupe(u8, doc_root),
            .try_files = try allocator.dupe(u8, try_files),
            .location_blocks = location_blocks,
            .tls_cert_path = try allocator.dupe(u8, tls_cert_path),
            .tls_key_path = try allocator.dupe(u8, tls_key_path),
            .upstream_base_url = try allocator.dupe(u8, upstream_base_url),
            .proxy_pass_chat = try allocator.dupe(u8, route_fields.proxy_pass_chat),
            .proxy_pass_commands_prefix = try allocator.dupe(u8, route_fields.proxy_pass_commands_prefix),
        });
    }
    return out.toOwnedSlice(allocator);
}

const ParsedServerBlockRouteFields = struct {
    location_blocks_raw: []const u8,
    proxy_pass_chat: []const u8,
    proxy_pass_commands_prefix: []const u8,
};

fn parseServerBlockRouteFields(
    rem_a: []const u8,
    rem_b: ?[]const u8,
    rem_c: ?[]const u8,
) !ParsedServerBlockRouteFields {
    if (rem_b == null and rem_c == null) {
        return .{
            .location_blocks_raw = rem_a,
            .proxy_pass_chat = "",
            .proxy_pass_commands_prefix = "",
        };
    }

    if (rem_c) |location_blocks_raw| {
        return .{
            .location_blocks_raw = location_blocks_raw,
            .proxy_pass_chat = rem_a,
            .proxy_pass_commands_prefix = rem_b.?,
        };
    }

    if (rem_b) |value_b| {
        if (looksLikeLocationBlockBlob(rem_a)) {
            return .{
                .location_blocks_raw = rem_a,
                .proxy_pass_chat = value_b,
                .proxy_pass_commands_prefix = "",
            };
        }
        if (looksLikeLocationBlockBlob(value_b)) {
            return .{
                .location_blocks_raw = value_b,
                .proxy_pass_chat = rem_a,
                .proxy_pass_commands_prefix = "",
            };
        }
    }

    return error.InvalidServerBlockFormat;
}

fn looksLikeLocationBlockBlob(value: []const u8) bool {
    if (value.len == 0) return true;
    return std.mem.findScalar(u8, value, '|') != null;
}

fn applyServerBlockTlsConfig(
    allocator: std.mem.Allocator,
    tls_cert_path: *[]u8,
    tls_key_path: *[]u8,
    tls_sni_certs: *[]EdgeConfig.TlsSniCert,
    server_blocks: []const EdgeConfig.ServerBlock,
) !void {
    var extra_sni: usize = 0;
    var default_block: ?*const EdgeConfig.ServerBlock = null;
    for (server_blocks) |*block| {
        if (block.server_names.len == 0 and default_block == null) default_block = block;
        if (block.tls_cert_path.len == 0 and block.tls_key_path.len == 0) continue;
        if (block.server_names.len > 0) extra_sni += block.server_names.len;
    }

    if ((tls_cert_path.*.len == 0 or tls_key_path.*.len == 0) and default_block != null) {
        const block = default_block.?;
        if (block.tls_cert_path.len > 0 and block.tls_key_path.len > 0) {
            allocator.free(tls_cert_path.*);
            allocator.free(tls_key_path.*);
            tls_cert_path.* = try allocator.dupe(u8, block.tls_cert_path);
            tls_key_path.* = try allocator.dupe(u8, block.tls_key_path);
        }
    }

    if (extra_sni == 0) return;
    const existing = tls_sni_certs.*;
    const merged = try allocator.alloc(EdgeConfig.TlsSniCert, existing.len + extra_sni);
    errdefer allocator.free(merged);

    var idx: usize = 0;
    for (existing) |entry| {
        merged[idx] = .{
            .server_name = entry.server_name,
            .cert_path = entry.cert_path,
            .key_path = entry.key_path,
        };
        idx += 1;
    }
    for (server_blocks) |block| {
        if (block.server_names.len == 0) continue;
        if (block.tls_cert_path.len == 0 or block.tls_key_path.len == 0) continue;
        for (block.server_names) |name| {
            merged[idx] = .{
                .server_name = try allocator.dupe(u8, name),
                .cert_path = try allocator.dupe(u8, block.tls_cert_path),
                .key_path = try allocator.dupe(u8, block.tls_key_path),
            };
            idx += 1;
        }
    }
    allocator.free(existing);
    tls_sni_certs.* = merged;
}

fn parseConfigPort(label: []const u8, raw: []const u8) !u16 {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    const port = std.fmt.parseInt(u16, value, 10) catch {
        logConfigDiagnostic("config validation failed: {s} must be an integer port between 1 and 65535", .{label});
        return error.InvalidConfigPort;
    };
    if (port == 0) {
        logConfigDiagnostic("config validation failed: {s} must be between 1 and 65535", .{label});
        return error.InvalidConfigPort;
    }
    return port;
}

fn parseUpstreamProtocolConfig(raw: []const u8) !UpstreamProtocol {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    return UpstreamProtocol.parse(value) orelse {
        logConfigDiagnostic("config validation failed: upstream_protocol must be one of http1, h2, auto, h2c", .{});
        return error.InvalidConfigValue;
    };
}

fn parseProxyProtocolModeConfig(raw: []const u8) !ProxyProtocolMode {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    return ProxyProtocolMode.parse(value) orelse {
        logConfigDiagnostic("config validation failed: proxy_protocol must be one of off, auto, v1, v2", .{});
        return error.InvalidConfigValue;
    };
}

fn parseUpstreamLbAlgorithmConfig(raw: []const u8) !UpstreamLbAlgorithm {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    return UpstreamLbAlgorithm.parse(value) orelse {
        logConfigDiagnostic("config validation failed: upstream_lb_algorithm must be one of round_robin, least_connections, ip_hash, generic_hash, random_two_choices", .{});
        return error.InvalidConfigValue;
    };
}

fn parseLogLevelConfig(raw: []const u8) !http.logger.Level {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    return http.logger.Level.parse(value) orelse {
        logConfigDiagnostic("config validation failed: log_level must be one of debug, info, warn, error", .{});
        return error.InvalidConfigValue;
    };
}

fn parseAccessLogFormatConfig(raw: []const u8) !http.access_log.Format {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    return http.access_log.Format.parse(value) orelse {
        logConfigDiagnostic("config validation failed: access_log_format must be one of json, plain, custom", .{});
        return error.InvalidConfigValue;
    };
}

fn parseProxyStreamingModeConfig(raw: []const u8) !ProxyStreamingMode {
    const value = std.mem.trim(u8, raw, " \t\r\n");
    return ProxyStreamingMode.parse(value) orelse {
        logConfigDiagnostic("config validation failed: proxy_streaming_mode must be one of off, buffered, response, full, request-response", .{});
        return error.InvalidConfigValue;
    };
}

fn logConfigDiagnostic(comptime fmt: []const u8, args: anytype) void {
    if (!builtin.is_test) std.log.err(fmt, args);
}

fn envOrDefault(allocator: std.mem.Allocator, key: []const u8, default_value: []const u8) ![]u8 {
    if (compat.getEnvVarOwned(allocator, key)) |owned| {
        if (conflictingFileOverrideValue(key, owned)) |file_value| {
            std.log.warn("config override conflict for {s}: env value '{s}' overrides file-config value '{s}'", .{
                key,
                configValueForLog(key, owned),
                configValueForLog(key, file_value),
            });
        }
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

fn configValueForLog(key: []const u8, value: []const u8) []const u8 {
    return if (isSensitiveConfigKey(key)) "<redacted>" else value;
}

fn isSensitiveConfigKey(key: []const u8) bool {
    return std.mem.indexOf(u8, key, "SECRET") != null or
        std.mem.indexOf(u8, key, "TOKEN") != null or
        std.mem.indexOf(u8, key, "PASSWORD") != null or
        std.mem.indexOf(u8, key, "PRIVATE_KEY") != null or
        std.mem.indexOf(u8, key, "KEY_PATH") != null;
}

fn conflictingFileOverrideValue(key: []const u8, env_value: []const u8) ?[]const u8 {
    const overrides = active_file_overrides orelse return null;
    const file_value = overrides.map.get(key) orelse return null;
    if (std.mem.eql(u8, file_value, env_value)) return null;
    return file_value;
}

fn envOrDefaultAlias(allocator: std.mem.Allocator, primary_key: []const u8, fallback_key: []const u8, default_value: []const u8) ![]u8 {
    if (compat.getEnvVarOwned(allocator, primary_key)) |owned| {
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
    var out = std.ArrayList([]const u8).empty;
    errdefer {
        for (out.items) |h| allocator.free(h);
        out.deinit(allocator);
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
        try out.append(allocator, lower);
    }

    return out.toOwnedSlice(allocator);
}

fn parseCsvValues(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).empty;
    errdefer {
        for (out.items) |v| allocator.free(v);
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const duped = try allocator.dupe(u8, trimmed);
        try out.append(allocator, duped);
    }

    return out.toOwnedSlice(allocator);
}

fn parseServerNames(allocator: std.mem.Allocator, raw: []const u8) ![][]const u8 {
    var out = std.ArrayList([]const u8).empty;
    errdefer {
        for (out.items) |name| allocator.free(name);
        out.deinit(allocator);
    }

    var it = std.mem.tokenizeAny(u8, raw, ", \t\r\n");
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        try out.append(allocator, try allocator.dupe(u8, trimmed));
    }
    return out.toOwnedSlice(allocator);
}

fn parseCsvU32Values(allocator: std.mem.Allocator, raw: []const u8) ![]u32 {
    var out = std.ArrayList(u32).empty;
    errdefer out.deinit(allocator);

    var it = std.mem.splitScalar(u8, raw, ',');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const value = try std.fmt.parseInt(u32, trimmed, 10);
        if (value == 0) return error.InvalidUpstreamBaseUrlWeight;
        try out.append(allocator, value);
    }

    return out.toOwnedSlice(allocator);
}

fn parseHealthStatusRange(raw: []const u8) !EdgeConfig.HealthStatusRange {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0) return error.InvalidHealthStatusRange;
    if (std.mem.findScalar(u8, trimmed, '-')) |dash| {
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
    var out = std.ArrayList(EdgeConfig.UpstreamHealthSuccessStatusOverride).empty;
    errdefer {
        for (out.items) |entry| allocator.free(entry.upstream_base_url);
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        const sep = std.mem.findScalarLast(u8, entry, '|') orelse return error.InvalidHealthStatusOverride;
        const upstream_base_url = std.mem.trim(u8, entry[0..sep], " \t\r\n");
        const status_raw = std.mem.trim(u8, entry[sep + 1 ..], " \t\r\n");
        if (upstream_base_url.len == 0 or status_raw.len == 0) return error.InvalidHealthStatusOverride;
        try out.append(allocator, .{
            .upstream_base_url = try allocator.dupe(u8, upstream_base_url),
            .range = try parseHealthStatusRange(status_raw),
        });
    }
    return out.toOwnedSlice(allocator);
}

fn parseHeaderPairs(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.HeaderPair {
    var out = std.ArrayList(EdgeConfig.HeaderPair).empty;
    errdefer {
        for (out.items) |pair| {
            allocator.free(pair.name);
            allocator.free(pair.value);
        }
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, '|');
    while (it.next()) |part| {
        const trimmed = std.mem.trim(u8, part, " \t\r\n");
        if (trimmed.len == 0) continue;
        const colon = std.mem.findScalar(u8, trimmed, ':') orelse return error.InvalidAddHeaderFormat;
        const name_raw = std.mem.trim(u8, trimmed[0..colon], " \t\r\n");
        const value_raw = std.mem.trim(u8, trimmed[colon + 1 ..], " \t\r\n");
        if (name_raw.len == 0) return error.InvalidAddHeaderFormat;
        const name = try allocator.dupe(u8, name_raw);
        errdefer allocator.free(name);
        const value = try allocator.dupe(u8, value_raw);
        errdefer allocator.free(value);
        try out.append(allocator, .{ .name = name, .value = value });
    }
    return out.toOwnedSlice(allocator);
}

fn parseFastcgiParams(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.HeaderPair {
    var out = std.ArrayList(EdgeConfig.HeaderPair).empty;
    errdefer {
        for (out.items) |pair| {
            allocator.free(pair.name);
            allocator.free(pair.value);
        }
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, '|');
    while (it.next()) |entry| {
        const trimmed = std.mem.trim(u8, entry, " \t\r\n");
        if (trimmed.len == 0) continue;
        const eq = std.mem.findScalar(u8, trimmed, '=') orelse return error.InvalidFastcgiParamFormat;
        const name = std.mem.trim(u8, trimmed[0..eq], " \t\r\n");
        const value = std.mem.trim(u8, trimmed[eq + 1 ..], " \t\r\n");
        if (name.len == 0) return error.InvalidFastcgiParamFormat;
        try out.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .value = try allocator.dupe(u8, value),
        });
    }
    return out.toOwnedSlice(allocator);
}

fn parseRewriteRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.RewriteRule {
    var out = std.ArrayList(EdgeConfig.RewriteRule).empty;
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.replacement);
        }
        out.deinit(allocator);
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
        try out.append(allocator, .{
            .method = owned_method,
            .pattern = owned_pattern,
            .replacement = owned_replacement,
            .flag = flag,
        });
    }
    return out.toOwnedSlice(allocator);
}

fn parseReturnRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.ReturnRule {
    var out = std.ArrayList(EdgeConfig.ReturnRule).empty;
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.body);
        }
        out.deinit(allocator);
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
        try out.append(allocator, .{
            .method = owned_method,
            .pattern = owned_pattern,
            .status = status,
            .body = owned_body,
        });
    }
    return out.toOwnedSlice(allocator);
}

fn parseConditionalRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.ConditionalRule {
    var out = std.ArrayList(EdgeConfig.ConditionalRule).empty;
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.pattern);
            switch (rule.action) {
                .rewrite => |rw| allocator.free(rw.replacement),
                .returned => |ret| allocator.free(ret.body),
            }
        }
        out.deinit(allocator);
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
            try out.append(allocator, .{
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
            try out.append(allocator, .{
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
    return out.toOwnedSlice(allocator);
}

fn parseLocationBlocks(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.LocationBlock {
    var out = std.ArrayList(EdgeConfig.LocationBlock).empty;
    errdefer {
        for (out.items) |*block| {
            block.deinit(allocator);
        }
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    var priority: usize = 0;
    while (it.next()) |entry_raw| : (priority += 1) {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;

        var fields = std.mem.splitScalar(u8, entry, '|');
        const match_type_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
        const pattern_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
        const action_kind_raw = fields.next() orelse return error.InvalidLocationBlockFormat;

        const match_type = http.location_router.MatchType.parse(std.mem.trim(u8, match_type_raw, " \t\r\n")) orelse return error.InvalidLocationBlockFormat;
        const pattern = std.mem.trim(u8, pattern_raw, " \t\r\n");
        const action_kind = std.mem.trim(u8, action_kind_raw, " \t\r\n");
        if (pattern.len == 0 or action_kind.len == 0) return error.InvalidLocationBlockFormat;

        var action: http.location_router.Action = undefined;
        if (std.ascii.eqlIgnoreCase(action_kind, "proxy_pass")) {
            const target_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const target = std.mem.trim(u8, target_raw, " \t\r\n");
            if (target.len == 0) return error.InvalidLocationBlockFormat;
            action = .{ .proxy_pass = try allocator.dupe(u8, target) };
        } else if (std.ascii.eqlIgnoreCase(action_kind, "fastcgi_pass")) {
            const target_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const target = std.mem.trim(u8, target_raw, " \t\r\n");
            if (target.len == 0) return error.InvalidLocationBlockFormat;
            action = .{ .fastcgi_pass = try allocator.dupe(u8, target) };
        } else if (std.ascii.eqlIgnoreCase(action_kind, "return")) {
            const status_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const body_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const status = std.fmt.parseInt(u16, std.mem.trim(u8, status_raw, " \t\r\n"), 10) catch return error.InvalidLocationBlockFormat;
            action = .{ .return_response = .{
                .status = status,
                .body = try allocator.dupe(u8, std.mem.trim(u8, body_raw, " \t\r\n")),
            } };
        } else if (std.ascii.eqlIgnoreCase(action_kind, "rewrite")) {
            const replacement_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const flag_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const replacement = std.mem.trim(u8, replacement_raw, " \t\r\n");
            const flag = http.rewrite.RewriteFlag.parse(std.mem.trim(u8, flag_raw, " \t\r\n")) orelse return error.InvalidLocationBlockFormat;
            if (replacement.len == 0) return error.InvalidLocationBlockFormat;
            action = .{ .rewrite = .{
                .replacement = try allocator.dupe(u8, replacement),
                .flag = flag,
            } };
        } else if (std.ascii.eqlIgnoreCase(action_kind, "static_root")) {
            const root_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const alias_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const autoindex_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const index_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const try_files_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
            const root = std.mem.trim(u8, root_raw, " \t\r\n");
            if (root.len == 0) return error.InvalidLocationBlockFormat;
            const alias = parseBoolish(std.mem.trim(u8, alias_raw, " \t\r\n")) orelse return error.InvalidLocationBlockFormat;
            const autoindex = parseBoolish(std.mem.trim(u8, autoindex_raw, " \t\r\n")) orelse return error.InvalidLocationBlockFormat;
            action = .{ .static_root = .{
                .root = try allocator.dupe(u8, root),
                .alias = alias,
                .autoindex = autoindex,
                .index = try allocator.dupe(u8, std.mem.trim(u8, index_raw, " \t\r\n")),
                .try_files = try allocator.dupe(u8, std.mem.trim(u8, try_files_raw, " \t\r\n")),
            } };
        } else {
            return error.InvalidLocationBlockFormat;
        }

        var auth: http.location_router.AuthMode = .off;
        var proxy_streaming_policy: http.location_router.ProxyStreamingPolicy = .inherit;
        while (fields.next()) |option_raw| {
            const option = std.mem.trim(u8, option_raw, " \t\r\n");
            if (std.mem.startsWith(u8, option, "auth:")) {
                auth = http.location_router.AuthMode.parse(option["auth:".len..]) orelse return error.InvalidLocationBlockFormat;
            } else if (std.mem.startsWith(u8, option, "stream:")) {
                proxy_streaming_policy = http.location_router.ProxyStreamingPolicy.parse(option["stream:".len..]) orelse return error.InvalidLocationBlockFormat;
            } else {
                return error.InvalidLocationBlockFormat;
            }
        }

        try out.append(allocator, .{
            .match_type = match_type,
            .pattern = try allocator.dupe(u8, pattern),
            .priority = priority,
            .action = action,
            .error_pages = &.{},
            .auth = auth,
            .proxy_streaming_policy = proxy_streaming_policy,
        });
    }

    return out.toOwnedSlice(allocator);
}

fn applyLocationErrorPages(allocator: std.mem.Allocator, blocks: []EdgeConfig.LocationBlock, raw: []const u8) !void {
    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;

        var fields = std.mem.splitScalar(u8, entry, '|');
        const match_type_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
        const pattern_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
        const status_codes_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
        const target_raw = fields.next() orelse return error.InvalidLocationBlockFormat;
        if (fields.next() != null) return error.InvalidLocationBlockFormat;

        const match_type = http.location_router.MatchType.parse(std.mem.trim(u8, match_type_raw, " \t\r\n")) orelse return error.InvalidLocationBlockFormat;
        const pattern = std.mem.trim(u8, pattern_raw, " \t\r\n");
        const target = std.mem.trim(u8, target_raw, " \t\r\n");
        if (pattern.len == 0 or target.len == 0) return error.InvalidLocationBlockFormat;

        var code_tokens = std.mem.splitScalar(u8, status_codes_raw, ',');
        var status_codes = std.ArrayList(u16).empty;
        defer status_codes.deinit(allocator);
        while (code_tokens.next()) |code_raw| {
            const code = std.fmt.parseInt(u16, std.mem.trim(u8, code_raw, " \t\r\n"), 10) catch return error.InvalidLocationBlockFormat;
            try status_codes.append(allocator, code);
        }
        if (status_codes.items.len == 0) return error.InvalidLocationBlockFormat;

        var matched_block: ?*EdgeConfig.LocationBlock = null;
        for (blocks) |*block| {
            if (block.match_type == match_type and std.mem.eql(u8, block.pattern, pattern)) {
                matched_block = block;
                break;
            }
        }
        const block = matched_block orelse return error.InvalidLocationBlockFormat;

        const existing_len = block.error_pages.len;
        const merged = try allocator.alloc(http.location_router.ErrorPageRule, existing_len + 1);
        for (block.error_pages, 0..) |existing, idx| merged[idx] = existing;
        merged[existing_len] = .{
            .status_codes = try allocator.dupe(u16, status_codes.items),
            .target = try allocator.dupe(u8, target),
        };
        if (existing_len > 0) allocator.free(block.error_pages);
        block.error_pages = merged;
    }
}

fn parseBoolish(raw: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(raw, "1") or std.ascii.eqlIgnoreCase(raw, "true") or std.ascii.eqlIgnoreCase(raw, "on") or std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.ascii.eqlIgnoreCase(raw, "0") or std.ascii.eqlIgnoreCase(raw, "false") or std.ascii.eqlIgnoreCase(raw, "off") or std.ascii.eqlIgnoreCase(raw, "no")) return false;
    return null;
}

fn parseInternalRedirectRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.InternalRedirectRule {
    var out = std.ArrayList(EdgeConfig.InternalRedirectRule).empty;
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target);
        }
        out.deinit(allocator);
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
        try out.append(allocator, .{
            .method = try allocator.dupe(u8, method),
            .pattern = try allocator.dupe(u8, pattern),
            .target = try allocator.dupe(u8, target),
        });
    }
    return out.toOwnedSlice(allocator);
}

fn parseNamedLocations(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.NamedLocation {
    var out = std.ArrayList(EdgeConfig.NamedLocation).empty;
    errdefer {
        for (out.items) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.path);
        }
        out.deinit(allocator);
    }

    var it = std.mem.splitScalar(u8, raw, ';');
    while (it.next()) |entry_raw| {
        const entry = std.mem.trim(u8, entry_raw, " \t\r\n");
        if (entry.len == 0) continue;
        const sep = std.mem.findScalar(u8, entry, '|') orelse return error.InvalidNamedLocationFormat;
        const name = std.mem.trim(u8, entry[0..sep], " \t\r\n");
        const path = std.mem.trim(u8, entry[sep + 1 ..], " \t\r\n");
        if (name.len == 0 or path.len == 0) return error.InvalidNamedLocationFormat;
        try out.append(allocator, .{
            .name = try allocator.dupe(u8, name),
            .path = try allocator.dupe(u8, path),
        });
    }
    return out.toOwnedSlice(allocator);
}

fn parseMirrorRules(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.MirrorRule {
    var out = std.ArrayList(EdgeConfig.MirrorRule).empty;
    errdefer {
        for (out.items) |rule| {
            allocator.free(rule.method);
            allocator.free(rule.pattern);
            allocator.free(rule.target_url);
        }
        out.deinit(allocator);
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
        try out.append(allocator, .{
            .method = try allocator.dupe(u8, method),
            .pattern = try allocator.dupe(u8, pattern),
            .target_url = try allocator.dupe(u8, target),
        });
    }
    return out.toOwnedSlice(allocator);
}

fn parseTlsSniCerts(allocator: std.mem.Allocator, raw: []const u8) ![]EdgeConfig.TlsSniCert {
    var out = std.ArrayList(EdgeConfig.TlsSniCert).empty;
    errdefer {
        for (out.items) |sc| {
            allocator.free(sc.server_name);
            allocator.free(sc.cert_path);
            allocator.free(sc.key_path);
        }
        out.deinit(allocator);
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
        try out.append(allocator, .{
            .server_name = try allocator.dupe(u8, host),
            .cert_path = try allocator.dupe(u8, cert),
            .key_path = try allocator.dupe(u8, key),
        });
    }
    return out.toOwnedSlice(allocator);
}

pub fn hasTlsFiles(cfg: *const EdgeConfig) bool {
    return cfg.tls_cert_path.len > 0 and cfg.tls_key_path.len > 0;
}

/// True when this binary was built with the Bare Systems appliance TLS
/// profile (#379/#392): pure-Zig TLS only, fixed single-identity credential
/// contract, no OpenSSL linkage.
pub const is_appliance_tls_profile =
    std.mem.eql(u8, build_options.tls_profile, "appliance");

/// Server-name policy for the downstream TLS identity (#392). A configured
/// name must always be one valid, non-wildcard DNS host name. The appliance
/// profile additionally requires exactly one identity: a server name must be
/// present when TLS is enabled and the multi-identity `tls_sni_certs`
/// mechanism is rejected.
fn validateTlsServerNamePolicy(cfg: *const EdgeConfig) !void {
    if (cfg.tls_server_name.len > 0) {
        tls_core.appliance_credentials.validateServerName(cfg.tls_server_name) catch {
            std.log.err("config validation failed: TARDIGRADE_TLS_SERVER_NAME must be a single non-wildcard DNS host name", .{});
            return error.InvalidConfigValue;
        };
    }
    if (!is_appliance_tls_profile) return;

    // Self-contained cert/key cardinality check: the appliance profile must
    // never treat a cert-only or key-only configuration as "TLS disabled"
    // and silently fall through to plaintext. This does not rely on
    // `hasTlsFiles()` (AND semantics: false for either half missing) or on
    // `validateTlsCertKeyPair` running later in `validate()`.
    if ((cfg.tls_cert_path.len == 0) != (cfg.tls_key_path.len == 0)) {
        std.log.err("config validation failed: the appliance TLS profile requires TARDIGRADE_TLS_CERT_PATH and TARDIGRADE_TLS_KEY_PATH to both be set or both be empty", .{});
        return error.InvalidConfigPath;
    }

    // Exactly one identity, configured directly: no SNI bundle, and no
    // per-server-block TLS certificates (even a single "default" block,
    // which `applyServerBlockTlsConfig` folds into the top-level cert/key
    // path and would otherwise pass unnoticed).
    if (cfg.tls_sni_certs.len > 0) {
        std.log.err("config validation failed: the appliance TLS profile supports exactly one identity; TARDIGRADE_TLS_SNI_CERTS must be empty", .{});
        return error.InvalidConfigValue;
    }
    for (cfg.server_blocks) |block| {
        if (block.tls_cert_path.len > 0 or block.tls_key_path.len > 0) {
            std.log.err("config validation failed: the appliance TLS profile does not support per-server-block TLS certificates; configure TARDIGRADE_TLS_CERT_PATH/TARDIGRADE_TLS_KEY_PATH directly", .{});
            return error.InvalidConfigValue;
        }
    }

    if (hasTlsFiles(cfg) and cfg.tls_server_name.len == 0) {
        std.log.err("config validation failed: the appliance TLS profile requires TARDIGRADE_TLS_SERVER_NAME when TLS is enabled", .{});
        return error.InvalidConfigValue;
    }
}

/// Reject appliance-profile configuration that requests behavior the native
/// engine cannot honor, rather than silently accepting it and either
/// dropping every connection at runtime (client-cert verification), doing
/// nothing (OCSP/CRL/ACME/session resumption — all OpenSSL-terminator-only
/// features this owner never constructs), or binding a UDP socket that can
/// never bootstrap (HTTP/3 without a complete identity). Every check here
/// is a request the operator explicitly made — none of the fields checked
/// default to a rejected value in the appliance profile (`loadFromEnv` sets
/// appliance-appropriate defaults for `tls_min_version` and the session
/// cache/ticket flags), so a config that never touches these settings
/// always passes.
fn validateApplianceTlsProfile(cfg: *const EdgeConfig) !void {
    if (!is_appliance_tls_profile) return;

    // A configured server name with no credential files is inert — the
    // owner is never constructed, so the appliance silently starts
    // plaintext despite `tls_server_name` implying TLS was intended.
    if (cfg.tls_server_name.len > 0 and !hasTlsFiles(cfg)) {
        logConfigDiagnostic("config validation failed: TARDIGRADE_TLS_SERVER_NAME is set but TARDIGRADE_TLS_CERT_PATH/TARDIGRADE_TLS_KEY_PATH are not; the appliance profile would start in plaintext with an inert server-name setting", .{});
        return error.UnsupportedApplianceConfiguration;
    }

    if (cfg.http3_enabled and !hasTlsFiles(cfg)) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile requires TARDIGRADE_TLS_CERT_PATH/TARDIGRADE_TLS_KEY_PATH when TARDIGRADE_HTTP3_ENABLED is true; HTTP/3 cannot bootstrap without a complete identity", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.http3_enabled and cfg.http3_enable_0rtt) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_HTTP3_ENABLE_0RTT", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.http3_enabled and cfg.http3_connection_migration) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_HTTP3_CONNECTION_MIGRATION", .{});
        return error.UnsupportedApplianceConfiguration;
    }

    if (!hasTlsFiles(cfg)) return;

    if (!std.mem.eql(u8, cfg.tls_min_version, "1.3") or !std.mem.eql(u8, cfg.tls_max_version, "1.3")) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile is TLS 1.3-only; TARDIGRADE_TLS_MIN_VERSION and TARDIGRADE_TLS_MAX_VERSION must both be \"1.3\"", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_cipher_list.len > 0 or cfg.tls_cipher_suites.len > 0) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile has a fixed cipher (TLS_AES_128_GCM_SHA256); TARDIGRADE_TLS_CIPHER_LIST/TARDIGRADE_TLS_CIPHER_SUITES must be empty", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_client_verify) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_CLIENT_VERIFY (downstream client certificate verification)", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_session_cache_enabled) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_SESSION_CACHE", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_session_tickets_enabled) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_SESSION_TICKETS", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_ocsp_stapling_enabled) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_OCSP_STAPLING", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_crl_check) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_CRL_CHECK", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_acme_enabled) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_ACME_ENABLED", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_ocsp_auto_refresh) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_OCSP_AUTO_REFRESH", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.tls_dynamic_reload_interval_ms != 0) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_TLS_DYNAMIC_RELOAD_INTERVAL_MS (no filesystem credential watcher)", .{});
        return error.UnsupportedApplianceConfiguration;
    }
    if (cfg.proxy_protocol_mode != .off) {
        logConfigDiagnostic("config validation failed: the appliance TLS profile does not support TARDIGRADE_PROXY_PROTOCOL; the native TLS path closes every connection before the handshake when a PROXY preface is expected", .{});
        return error.UnsupportedApplianceConfiguration;
    }
}

pub fn validate(cfg: *const EdgeConfig) !void {
    if (cfg.listen_port == 0) {
        std.log.err("config validation failed: listen_port must be between 1 and 65535", .{});
        return error.InvalidConfigPort;
    }
    if (cfg.http3_enabled and cfg.quic_port == 0) {
        std.log.err("config validation failed: quic_port must be between 1 and 65535 when HTTP/3 is enabled", .{});
        return error.InvalidConfigPort;
    }
    try validateListenerProtocolPolicy(cfg.http1_enabled, cfg.http2_enabled, hasTlsFiles(cfg), true);

    if (std.mem.eql(u8, cfg.tls_min_version, "1.0") or std.mem.eql(u8, cfg.tls_min_version, "1.1") or
        std.mem.eql(u8, cfg.tls_max_version, "1.0") or std.mem.eql(u8, cfg.tls_max_version, "1.1"))
    {
        std.log.err("config validation failed: TLS 1.0 and 1.1 are not supported; set tls_min_version to 1.2 or 1.3", .{});
        return error.InvalidConfigTlsVersion;
    }
    try validateOptionalFile(cfg.tls_cert_path, "tls_cert_path");
    try validateOptionalFile(cfg.tls_key_path, "tls_key_path");
    try validateTlsServerNamePolicy(cfg);
    try validateApplianceTlsProfile(cfg);
    for (cfg.tls_sni_certs) |entry| {
        try validateOptionalFile(entry.cert_path, "tls_sni_cert.cert_path");
        try validateOptionalFile(entry.key_path, "tls_sni_cert.key_path");
    }
    for (cfg.server_blocks) |block| {
        if ((block.tls_cert_path.len == 0) != (block.tls_key_path.len == 0)) {
            std.log.err("config validation failed: server block TLS config requires both tls_cert_path and tls_key_path", .{});
            return error.InvalidConfigPath;
        }
        try validateOptionalFile(block.tls_cert_path, "server_block.tls_cert_path");
        try validateOptionalFile(block.tls_key_path, "server_block.tls_key_path");
        try validateOptionalUpstreamBaseUrl(block.upstream_base_url, "server_block.upstream_base_url");
    }
    try validateOptionalFile(cfg.tls_ocsp_response_path, "tls_ocsp_response_path");
    try validateOptionalFile(cfg.tls_client_ca_path, "tls_client_ca_path");
    try validateOptionalFile(cfg.tls_crl_path, "tls_crl_path");
    try validateOptionalDir(cfg.tls_acme_cert_dir, "tls_acme_cert_dir");
    try validateOptionalDir(cfg.chroot_dir, "chroot_dir");
    try validateOptionalPathForErrorLog(cfg.error_log_path, "error_log_path");
    for (cfg.location_blocks) |block| {
        if (block.error_pages.len > 0) switch (block.action) {
            .static_root => |root| try validateOptionalDir(root.root, "location.error_page_root"),
            else => {},
        };
        for (block.error_pages) |rule| {
            if (isAbsoluteHttpUrl(rule.target)) continue;
            if (rule.target.len == 0) {
                std.log.err("config validation failed: location error_page target must not be empty", .{});
                return error.InvalidConfigPath;
            }
        }
    }

    try validateOptionalUpstreamBaseUrl(cfg.upstream_base_url, "upstream_base_url");
    try validateUpstreamBaseUrlList(cfg.upstream_base_urls, "upstream_base_urls");
    try validateUpstreamBaseUrlList(cfg.upstream_backup_base_urls, "upstream_backup_base_urls");
    try validateOptionalAbsoluteUrl(cfg.grpc_upstream, "grpc_upstream");
    for (cfg.mirror_rules) |rule| try validateOptionalAbsoluteUrl(rule.target_url, "mirror_rule.target_url");
    for (cfg.location_blocks) |block| {
        switch (block.action) {
            .proxy_pass => |target| if (isAbsoluteHttpUrl(target) or isUnixEndpoint(target)) try validateOptionalUpstreamBaseUrl(target, "location.proxy_pass"),
            .fastcgi_pass => |target| try validateOptionalSocketEndpoint(target, "location.fastcgi_pass"),
            else => {},
        }
    }

    try validateOptionalSocketEndpoint(cfg.fastcgi_upstream, "fastcgi_upstream");
    try validateOptionalSocketEndpoint(cfg.uwsgi_upstream, "uwsgi_upstream");
    try validateOptionalSocketEndpoint(cfg.scgi_upstream, "scgi_upstream");
    try validateOptionalSocketEndpoint(cfg.memcached_upstream, "memcached_upstream");
    try validateOptionalSocketEndpoint(cfg.smtp_upstream, "smtp_upstream");
    try validateOptionalSocketEndpoint(cfg.imap_upstream, "imap_upstream");
    try validateOptionalSocketEndpoint(cfg.pop3_upstream, "pop3_upstream");
    try validateOptionalSocketEndpoint(cfg.tcp_proxy_upstream, "tcp_proxy_upstream");
    try validateOptionalSocketEndpoint(cfg.udp_proxy_upstream, "udp_proxy_upstream");

    // TLS cert and key must both be present or both absent.
    validateTlsCertKeyPair(cfg.tls_cert_path, cfg.tls_key_path) catch {
        std.log.err("config validation failed: TARDIGRADE_TLS_CERT_PATH and TARDIGRADE_TLS_KEY_PATH must both be set or both be empty", .{});
        return error.InvalidConfigPath;
    };

    // mTLS: CA path required when client verification is enabled.
    validateMtlsConsistency(cfg.tls_client_verify, cfg.tls_client_ca_path) catch {
        std.log.err("config validation failed: TARDIGRADE_TLS_CLIENT_CA_PATH must be set when TARDIGRADE_TLS_CLIENT_VERIFY is enabled", .{});
        return error.InvalidConfigPath;
    };

    // Numeric range validations.
    validateOtelSampleRate(cfg.otel_sample_rate) catch {
        std.log.err("config validation failed: TARDIGRADE_OTEL_SAMPLE_RATE must be between 0 and 100 (got {})", .{cfg.otel_sample_rate});
        return error.InvalidConfigValue;
    };
    validateBrotliQuality(cfg.compression_brotli_quality) catch {
        std.log.err("config validation failed: TARDIGRADE_COMPRESSION_BROTLI_QUALITY must be between 0 and 11 (got {})", .{cfg.compression_brotli_quality});
        return error.InvalidConfigValue;
    };
    validateUpstreamRetryAttempts(cfg.upstream_retry_attempts) catch {
        std.log.err("config validation failed: TARDIGRADE_UPSTREAM_RETRY_ATTEMPTS must be at least 1", .{});
        return error.InvalidConfigValue;
    };
    validateBufferedUpstreamResponseLimit(cfg.max_buffered_upstream_response_bytes) catch {
        std.log.err("config validation failed: TARDIGRADE_MAX_BUFFERED_UPSTREAM_RESPONSE_BYTES must be at least 1", .{});
        return error.InvalidConfigValue;
    };
    cfg.tls_buffer_limits.validate() catch {
        std.log.err("config validation failed: TLS buffer watermarks must satisfy low < high <= hard, fit native queue capacity, and preserve record/handshake reserves", .{});
        return error.InvalidConfigValue;
    };
    cfg.proxy_buffer_limits.validate() catch {
        std.log.err("config validation failed: proxy buffer watermarks must satisfy low < high <= hard and aggregate hard limits must be 0 or at least the per-stream hard limit", .{});
        return error.InvalidConfigValue;
    };
    validateProxyStreamBufferSize(cfg.proxy_stream_buffer_size) catch {
        std.log.err("config validation failed: TARDIGRADE_PROXY_STREAM_BUFFER_SIZE must be between 1 and 1048576 bytes", .{});
        return error.InvalidConfigValue;
    };
    validateProxyBufferLimitsCoverRelayAllocations(cfg.proxy_buffer_limits, cfg.proxy_stream_buffer_size) catch {
        std.log.err("config validation failed: TARDIGRADE_PROXY_BUFFER_PER_STREAM_HARD_LIMIT_BYTES must be at least the effective streaming relay allocation", .{});
        return error.InvalidConfigValue;
    };

    // Timeout relationship sanity checks — warn only, these are not hard errors
    // because operators may have intentional unusual configurations.
    if (cfg.upstream_timeout_budget_ms > 0 and cfg.upstream_timeout_ms > 0 and
        cfg.upstream_timeout_budget_ms < cfg.upstream_timeout_ms)
    {
        std.log.warn("config: TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS ({d}) is less than TARDIGRADE_UPSTREAM_TIMEOUT_MS ({d}); budget expires before a single attempt can complete", .{
            cfg.upstream_timeout_budget_ms,
            cfg.upstream_timeout_ms,
        });
    }
    if (cfg.request_total_timeout_ms > 0 and cfg.upstream_timeout_budget_ms > 0 and
        cfg.request_total_timeout_ms < cfg.upstream_timeout_budget_ms)
    {
        std.log.warn("config: TARDIGRADE_REQUEST_TOTAL_TIMEOUT_MS ({d}) is less than TARDIGRADE_UPSTREAM_TIMEOUT_BUDGET_MS ({d}); request deadline fires before upstream budget is exhausted", .{
            cfg.request_total_timeout_ms,
            cfg.upstream_timeout_budget_ms,
        });
    }
}

fn validateTlsCertKeyPair(cert_path: []const u8, key_path: []const u8) !void {
    if ((cert_path.len == 0) != (key_path.len == 0)) return error.InvalidConfigPath;
}

fn validateMtlsConsistency(client_verify: bool, ca_path: []const u8) !void {
    if (client_verify and ca_path.len == 0) return error.InvalidConfigPath;
}

fn validateOtelSampleRate(rate: u32) !void {
    if (rate > 100) return error.InvalidConfigValue;
}

fn validateBrotliQuality(quality: u32) !void {
    if (quality > 11) return error.InvalidConfigValue;
}

fn validateUpstreamRetryAttempts(attempts: u32) !void {
    if (attempts == 0) return error.InvalidConfigValue;
}

fn validateBufferedUpstreamResponseLimit(limit: usize) !void {
    if (limit == 0) return error.InvalidConfigValue;
}

fn tlsBufferLimitsFromEnv(allocator: std.mem.Allocator) encrypted_stream.BufferLimits {
    const defaults = encrypted_stream.BufferLimits.defaults();
    return .{
        .inbound_ciphertext = tlsWatermarkFromEnv(allocator, "TARDIGRADE_TLS_INBOUND_CIPHERTEXT", defaults.inbound_ciphertext),
        .inbound_plaintext = tlsWatermarkFromEnv(allocator, "TARDIGRADE_TLS_INBOUND_PLAINTEXT", defaults.inbound_plaintext),
        .outbound_ciphertext = tlsWatermarkFromEnv(allocator, "TARDIGRADE_TLS_OUTBOUND_CIPHERTEXT", defaults.outbound_ciphertext),
        .handshake = tlsWatermarkFromEnv(allocator, "TARDIGRADE_TLS_HANDSHAKE", defaults.handshake),
    };
}

fn tlsWatermarkFromEnv(allocator: std.mem.Allocator, comptime prefix: []const u8, defaults: encrypted_stream.Watermark) encrypted_stream.Watermark {
    return .{
        .low = parseIntEnv(usize, allocator, prefix ++ "_LOW_WATERMARK_BYTES", defaults.low),
        .high = parseIntEnv(usize, allocator, prefix ++ "_HIGH_WATERMARK_BYTES", defaults.high),
        .hard = parseIntEnv(usize, allocator, prefix ++ "_HARD_LIMIT_BYTES", defaults.hard),
    };
}

fn validateProxyStreamBufferSize(size: usize) !void {
    if (size == 0 or size > 1024 * 1024) return error.InvalidConfigValue;
}

fn validateProxyBufferLimitsCoverRelayAllocations(limits: http.proxy_buffer_account.Limits, proxy_stream_buffer_size: usize) !void {
    const effective_relay_bytes = @max(proxy_stream_buffer_size, 16 * 1024);
    if (limits.per_stream_hard_limit < effective_relay_bytes) return error.InvalidConfigValue;
}

/// Emit log warnings for configurations that are valid but operationally risky.
/// Call this after validate() succeeds.
pub fn warnRiskyConfig(cfg: *const EdgeConfig) void {
    if (!cfg.upstream_tls_verify) {
        std.log.warn("config warning: TARDIGRADE_UPSTREAM_TLS_VERIFY is false — upstream TLS certificates are not verified (MITM risk)", .{});
    }
    if (cfg.rate_limit_rps == 0) {
        std.log.warn("config warning: TARDIGRADE_RATE_LIMIT_RPS is 0 — rate limiting is disabled; consider enabling it to protect against DoS", .{});
    }
    if (cfg.http3_enable_0rtt) {
        std.log.warn("config warning: TARDIGRADE_HTTP3_ENABLE_0RTT is true — 0-RTT enables replay attacks; only use on idempotent services", .{});
    }
    if (cfg.tls_acme_enabled and cfg.tls_acme_domains.len == 0) {
        std.log.warn("config warning: TARDIGRADE_TLS_ACME_ENABLED is true but TARDIGRADE_TLS_ACME_DOMAINS is empty — ACME will not obtain any certificates", .{});
    }
    if (hasTlsFiles(cfg) and !cfg.hsts_enabled) {
        std.log.warn("config warning: TLS is configured but TARDIGRADE_HSTS_ENABLED is false — consider enabling HSTS to prevent downgrade attacks", .{});
    }
    if (cfg.tls_client_ca_path.len > 0 and !cfg.tls_client_verify) {
        std.log.warn("config warning: TARDIGRADE_TLS_CLIENT_CA_PATH is set but TARDIGRADE_TLS_CLIENT_VERIFY is false — the CA path is ignored", .{});
    }
}

fn validateListenerProtocolPolicy(http1_enabled: bool, http2_enabled: bool, tls_enabled: bool, log_errors: bool) !void {
    if (!http1_enabled and !http2_enabled) {
        if (log_errors) std.log.err("config validation failed: at least one of HTTP/1.1 or HTTP/2 must be enabled", .{});
        return error.InvalidConfigValue;
    }
    if (!tls_enabled and !http1_enabled) {
        if (log_errors) std.log.err("config validation failed: plaintext listener requires HTTP/1.1; h2c is not supported", .{});
        return error.InvalidConfigValue;
    }
}

fn validateOptionalFile(path: []const u8, label: []const u8) !void {
    validateOptionalFileChecked(path) catch {
        std.log.err("config validation failed: {s} path does not exist: {s}", .{ label, path });
        return error.InvalidConfigPath;
    };
}

fn validateOptionalDir(path: []const u8, label: []const u8) !void {
    validateOptionalDirChecked(path) catch |err| {
        if (err == error.InvalidConfigPath) {
            std.log.err("config validation failed: {s} path does not exist: {s}", .{ label, path });
        } else {
            std.log.err("config validation failed: {s} must be a directory: {s}", .{ label, path });
        }
        return err;
    };
}

fn validateOptionalPathForErrorLog(path: []const u8, label: []const u8) !void {
    validateOptionalPathForErrorLogChecked(path) catch |err| {
        std.log.err("config validation failed: {s} directory must exist: {s}", .{ label, path });
        return err;
    };
}

fn validateUpstreamBaseUrlList(values: []const []const u8, label: []const u8) !void {
    for (values) |value| try validateOptionalUpstreamBaseUrl(value, label);
}

fn validateOptionalAbsoluteUrl(raw: []const u8, label: []const u8) !void {
    validateOptionalAbsoluteUrlChecked(raw) catch |err| {
        if (!isAbsoluteHttpUrl(raw)) {
            std.log.err("config validation failed: {s} must be an absolute http/https URL", .{label});
        } else {
            std.log.err("config validation failed: {s} is not a valid URL", .{label});
        }
        return err;
    };
}

fn validateOptionalUpstreamBaseUrl(raw: []const u8, label: []const u8) !void {
    if (isUnixEndpoint(raw)) {
        validateUnixEndpoint(raw, label) catch |err| return err;
        return;
    }
    try validateOptionalAbsoluteUrl(raw, label);
}

fn validateOptionalSocketEndpoint(raw: []const u8, label: []const u8) !void {
    validateOptionalSocketEndpointChecked(raw) catch |err| {
        switch (err) {
            error.InvalidConfigPort => std.log.err("config validation failed: {s} port must be between 1 and 65535: {s}", .{ label, raw }),
            else => std.log.err("config validation failed: {s} must be host:port, unix:/path, starttls://host:port, or tls://host:port: {s}", .{ label, raw }),
        }
        return err;
    };
}

fn validateUnixEndpoint(raw: []const u8, label: []const u8) !void {
    validateUnixEndpointChecked(raw) catch |err| {
        std.log.err("config validation failed: {s} unix endpoint path must not be empty: {s}", .{ label, raw });
        return err;
    };
}

fn validateOptionalFileChecked(path: []const u8) !void {
    if (path.len == 0) return;
    var file = compat.cwd().openFile(path, .{}) catch return error.InvalidConfigPath;
    defer file.close();
}

fn validateOptionalDirChecked(path: []const u8) !void {
    if (path.len == 0) return;
    var dir = std.Io.Dir.cwd().openDir(compat.io(), path, .{}) catch return error.InvalidConfigPath;
    defer dir.close(compat.io());
}

fn validateOptionalPathForErrorLogChecked(path: []const u8) !void {
    if (path.len == 0 or std.ascii.eqlIgnoreCase(path, "stderr")) return;
    const dir_path = std.Io.Dir.path.dirname(path) orelse ".";
    try validateOptionalDirChecked(dir_path);
}

fn validateOptionalAbsoluteUrlChecked(raw: []const u8) !void {
    if (raw.len == 0) return;
    if (!isAbsoluteHttpUrl(raw)) {
        return error.InvalidConfigUrl;
    }
    _ = std.Uri.parse(raw) catch return error.InvalidConfigUrl;
}

fn validateOptionalSocketEndpointChecked(raw: []const u8) !void {
    if (raw.len == 0) return;
    if (isUnixEndpoint(raw)) {
        try validateUnixEndpointChecked(raw);
        return;
    }
    const normalized = if (std.mem.startsWith(u8, raw, "starttls://"))
        raw["starttls://".len..]
    else if (std.mem.startsWith(u8, raw, "smtp+starttls://"))
        raw["smtp+starttls://".len..]
    else if (std.mem.startsWith(u8, raw, "tls://"))
        raw["tls://".len..]
    else if (std.mem.startsWith(u8, raw, "smtps://"))
        raw["smtps://".len..]
    else
        raw;
    if (std.mem.findScalar(u8, normalized, ':') == null) {
        return error.InvalidConfigEndpoint;
    }
    const parts = splitHostPort(normalized) orelse return error.InvalidConfigEndpoint;
    if (parts[0].len == 0) {
        return error.InvalidConfigEndpoint;
    }
    if (std.fmt.parseInt(u16, parts[1], 10) catch 0 == 0) {
        return error.InvalidConfigPort;
    }
}

fn validateUnixEndpointChecked(raw: []const u8) !void {
    const path = if (std.mem.startsWith(u8, raw, "unix:///"))
        raw["unix://".len..]
    else if (std.mem.startsWith(u8, raw, "unix:/"))
        raw["unix:".len..]
    else
        raw[0..0];
    if (path.len == 0) {
        return error.InvalidConfigEndpoint;
    }
}

fn isAbsoluteHttpUrl(raw: []const u8) bool {
    return std.mem.startsWith(u8, raw, "http://") or std.mem.startsWith(u8, raw, "https://");
}

fn isUnixEndpoint(raw: []const u8) bool {
    return std.mem.startsWith(u8, raw, "unix:/");
}

fn splitHostPort(raw: []const u8) ?struct { []const u8, []const u8 } {
    const idx = std.mem.findScalarLast(u8, raw, ':') orelse return null;
    if (idx == 0 or idx + 1 >= raw.len) return null;
    return .{ std.mem.trim(u8, raw[0..idx], " \t\r\n"), std.mem.trim(u8, raw[idx + 1 ..], " \t\r\n") };
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

test "parse proxy streaming mode aliases" {
    try std.testing.expectEqual(ProxyStreamingMode.off, ProxyStreamingMode.parse("off").?);
    try std.testing.expectEqual(ProxyStreamingMode.off, ProxyStreamingMode.parse("buffered").?);
    try std.testing.expectEqual(ProxyStreamingMode.response, ProxyStreamingMode.parse("RESPONSE").?);
    try std.testing.expectEqual(ProxyStreamingMode.full, ProxyStreamingMode.parse("request-response").?);
    try std.testing.expect(ProxyStreamingMode.response.responseStreamingEnabled());
    try std.testing.expect(!ProxyStreamingMode.response.requestStreamingEnabled());
    try std.testing.expect(ProxyStreamingMode.full.responseStreamingEnabled());
    try std.testing.expect(ProxyStreamingMode.full.requestStreamingEnabled());
    try std.testing.expect(ProxyStreamingMode.parse("invalid") == null);
}

test "parse route proxy streaming policy aliases" {
    try std.testing.expectEqual(http.location_router.ProxyStreamingPolicy.inherit, http.location_router.ProxyStreamingPolicy.parse("inherit").?);
    try std.testing.expectEqual(http.location_router.ProxyStreamingPolicy.off, http.location_router.ProxyStreamingPolicy.parse("buffered").?);
    try std.testing.expectEqual(http.location_router.ProxyStreamingPolicy.response, http.location_router.ProxyStreamingPolicy.parse("responses").?);
    try std.testing.expectEqual(http.location_router.ProxyStreamingPolicy.full, http.location_router.ProxyStreamingPolicy.parse("request-response").?);
    try std.testing.expect(!http.location_router.ProxyStreamingPolicy.off.responseStreamingEnabled(true));
    try std.testing.expect(http.location_router.ProxyStreamingPolicy.inherit.responseStreamingEnabled(true));
    try std.testing.expect(http.location_router.ProxyStreamingPolicy.full.requestStreamingEnabled(false));
    try std.testing.expect(http.location_router.ProxyStreamingPolicy.parse("sometimes") == null);
}

test "config port parser rejects invalid listener values" {
    try std.testing.expectEqual(@as(u16, 8069), try parseConfigPort("listen_port", "8069"));
    try std.testing.expectError(error.InvalidConfigPort, parseConfigPort("listen_port", "0"));
    try std.testing.expectError(error.InvalidConfigPort, parseConfigPort("listen_port", "not-a-port"));
}

test "config enum parsers reject invalid values" {
    try std.testing.expectEqual(ProxyStreamingMode.full, try parseProxyStreamingModeConfig("request-response"));
    try std.testing.expectError(error.InvalidConfigValue, parseProxyStreamingModeConfig("streaming"));
    try std.testing.expectEqual(ProxyProtocolMode.v2, try parseProxyProtocolModeConfig("v2"));
    try std.testing.expectError(error.InvalidConfigValue, parseProxyProtocolModeConfig("v3"));
    try std.testing.expectEqual(UpstreamProtocol.h2c, try parseUpstreamProtocolConfig("h2c"));
    try std.testing.expectError(error.InvalidConfigValue, parseUpstreamProtocolConfig("spdy"));
}

test "listener protocol validation rejects plaintext h2-only" {
    try validateListenerProtocolPolicy(true, false, false, false);
    try validateListenerProtocolPolicy(true, true, false, false);
    try validateListenerProtocolPolicy(false, true, true, false);
    try std.testing.expectError(error.InvalidConfigValue, validateListenerProtocolPolicy(false, true, false, false));
    try std.testing.expectError(error.InvalidConfigValue, validateListenerProtocolPolicy(false, false, true, false));
}

test "sensitive config values are redacted for logs" {
    try std.testing.expectEqualStrings("<redacted>", configValueForLog("TARDIGRADE_JWT_SECRET", "super-secret"));
    try std.testing.expectEqualStrings("<redacted>", configValueForLog("TARDIGRADE_AUTH_TOKEN_HASHES", "abc"));
    try std.testing.expectEqualStrings("8069", configValueForLog("TARDIGRADE_LISTEN_PORT", "8069"));
}

test "UpstreamProtocol parses h2c and gates prior-knowledge separately from ALPN" {
    try std.testing.expectEqual(UpstreamProtocol.h2c, UpstreamProtocol.parse("h2c").?);
    try std.testing.expectEqual(UpstreamProtocol.h2c, UpstreamProtocol.parse("H2C").?);
    // h2c implies ALPN h2 for HTTPS upstreams...
    try std.testing.expect(UpstreamProtocol.h2c.offersH2());
    try std.testing.expect(UpstreamProtocol.h2c.h2cPriorKnowledge());
    // ...but h2/auto must never imply cleartext h2c (no negotiation exists,
    // an h1-only plain origin would break).
    try std.testing.expect(!UpstreamProtocol.h2.h2cPriorKnowledge());
    try std.testing.expect(!UpstreamProtocol.auto.h2cPriorKnowledge());
    try std.testing.expect(!UpstreamProtocol.http1.h2cPriorKnowledge());
    try std.testing.expect(!UpstreamProtocol.http1.offersH2());
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

test "validate absolute upstream URL accepts http and rejects malformed input" {
    try validateOptionalAbsoluteUrlChecked("http://127.0.0.1:8080");
    try validateOptionalAbsoluteUrlChecked("https://example.com/api");
    try std.testing.expectError(error.InvalidConfigUrl, validateOptionalAbsoluteUrlChecked("127.0.0.1:8080"));
    try std.testing.expectError(error.InvalidConfigUrl, validateOptionalAbsoluteUrlChecked("http://"));
}

test "validate socket endpoint accepts host port, unix path, and tls schemes" {
    try validateOptionalSocketEndpointChecked("127.0.0.1:9000");
    try validateOptionalSocketEndpointChecked("unix:/tmp/php-fpm.sock");
    try validateOptionalSocketEndpointChecked("starttls://127.0.0.1:587");
    try validateOptionalSocketEndpointChecked("tls://127.0.0.1:465");
    try std.testing.expectError(error.InvalidConfigEndpoint, validateOptionalSocketEndpointChecked("missing-port"));
    try std.testing.expectError(error.InvalidConfigPort, validateOptionalSocketEndpointChecked("127.0.0.1:0"));
}

test "missing tls cert path helper returns InvalidConfigPath" {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var file = try compat.wrapDir(tmp.dir).createFile("exists.pem", .{});
    file.close();

    const existing_path = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, "exists.pem");
    defer std.testing.allocator.free(existing_path);
    const missing_path = try compat.wrapDir(tmp.dir).realpathAlloc(std.testing.allocator, ".");
    defer std.testing.allocator.free(missing_path);
    const missing_file = try std.fmt.allocPrint(std.testing.allocator, "{s}/missing.pem", .{missing_path});
    defer std.testing.allocator.free(missing_file);

    try validateOptionalFileChecked(existing_path);
    try std.testing.expectError(error.InvalidConfigPath, validateOptionalFileChecked(missing_file));
}

test "parse server blocks" {
    const allocator = std.testing.allocator;
    const raw =
        "api.example.test" ++ "\x1f" ++ "/srv/api" ++ "\x1f" ++ "$uri /index.html" ++ "\x1f" ++ "/certs/api.crt" ++ "\x1f" ++ "/certs/api.key" ++ "\x1f" ++ "http://127.0.0.1:9101" ++ "\x1f" ++ "prefix|/|proxy_pass|http://127.0.0.1:9101";
    const blocks = try parseServerBlocks(allocator, raw);
    defer {
        for (blocks) |*block| block.deinit(allocator);
        allocator.free(blocks);
    }

    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqual(@as(usize, 1), blocks[0].server_names.len);
    try std.testing.expectEqualStrings("api.example.test", blocks[0].server_names[0]);
    try std.testing.expectEqualStrings("/srv/api", blocks[0].doc_root);
    try std.testing.expectEqualStrings("$uri /index.html", blocks[0].try_files);
    try std.testing.expectEqualStrings("/certs/api.crt", blocks[0].tls_cert_path);
    try std.testing.expectEqualStrings("/certs/api.key", blocks[0].tls_key_path);
    try std.testing.expectEqualStrings("http://127.0.0.1:9101", blocks[0].upstream_base_url);
    try std.testing.expectEqual(@as(usize, 1), blocks[0].location_blocks.len);
}

test "parse server blocks with explicit proxy route fields" {
    const allocator = std.testing.allocator;
    const raw =
        "api.example.test" ++ "\x1f" ++ "/srv/api" ++ "\x1f" ++ "$uri /index.html" ++ "\x1f" ++ "/certs/api.crt" ++ "\x1f" ++ "/certs/api.key" ++ "\x1f" ++ "http://127.0.0.1:9101" ++ "\x1f" ++ "http://127.0.0.1:9201/v1/chat" ++ "\x1f" ++ "http://127.0.0.1:9202/v1" ++ "\x1f" ++ "prefix|/|proxy_pass|http://127.0.0.1:9101";
    const blocks = try parseServerBlocks(allocator, raw);
    defer {
        for (blocks) |*block| block.deinit(allocator);
        allocator.free(blocks);
    }

    try std.testing.expectEqual(@as(usize, 1), blocks.len);
    try std.testing.expectEqualStrings("http://127.0.0.1:9201/v1/chat", blocks[0].proxy_pass_chat);
    try std.testing.expectEqualStrings("http://127.0.0.1:9202/v1", blocks[0].proxy_pass_commands_prefix);
    try std.testing.expectEqual(@as(usize, 1), blocks[0].location_blocks.len);
}

test "conflicting file override value detects env/file mismatch" {
    const allocator = std.testing.allocator;
    var overrides = http.config_file.Overrides.init(allocator);
    defer overrides.deinit(allocator);

    try overrides.map.put(try allocator.dupe(u8, "TARDIGRADE_LISTEN_PORT"), try allocator.dupe(u8, "8069"));
    const previous = active_file_overrides;
    active_file_overrides = &overrides;
    defer active_file_overrides = previous;

    try std.testing.expectEqualStrings("8069", conflictingFileOverrideValue("TARDIGRADE_LISTEN_PORT", "18069").?);
    try std.testing.expect(conflictingFileOverrideValue("TARDIGRADE_LISTEN_PORT", "8069") == null);
    try std.testing.expect(conflictingFileOverrideValue("TARDIGRADE_WORKER_THREADS", "4") == null);
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

test "parse location blocks csv" {
    const allocator = std.testing.allocator;
    const blocks = try parseLocationBlocks(
        allocator,
        "exact|/health|return|200|ok;prefix_priority|/api/private/|proxy_pass|http://127.0.0.1:9001;regex_case_insensitive|^/assets/.*$|static_root|/srv/www|on|on|index.html|$uri",
    );
    defer {
        for (blocks) |*block| {
            block.deinit(allocator);
        }
        allocator.free(blocks);
    }

    try std.testing.expectEqual(@as(usize, 3), blocks.len);
    try std.testing.expectEqual(http.location_router.MatchType.exact, blocks[0].match_type);
    try std.testing.expectEqual(@as(usize, 1), blocks[1].priority);
    switch (blocks[0].action) {
        .return_response => |response| try std.testing.expectEqual(@as(u16, 200), response.status),
        else => return error.UnexpectedTestResult,
    }
    switch (blocks[2].action) {
        .static_root => |root| {
            try std.testing.expect(root.alias);
            try std.testing.expect(root.autoindex);
            try std.testing.expectEqualStrings("index.html", root.index);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "parse location blocks include route streaming policy option" {
    const allocator = std.testing.allocator;
    const blocks = try parseLocationBlocks(
        allocator,
        "prefix|/buffered/|proxy_pass|http://127.0.0.1:9001|stream:off;prefix|/full/|proxy_pass|http://127.0.0.1:9002|auth:required|stream:full",
    );
    defer {
        for (blocks) |*block| {
            block.deinit(allocator);
        }
        allocator.free(blocks);
    }

    try std.testing.expectEqual(@as(usize, 2), blocks.len);
    try std.testing.expectEqual(http.location_router.ProxyStreamingPolicy.off, blocks[0].proxy_streaming_policy);
    try std.testing.expectEqual(http.location_router.ProxyStreamingPolicy.full, blocks[1].proxy_streaming_policy);
    try std.testing.expectEqual(http.location_router.AuthMode.required, blocks[1].auth);
}

test "apply location error pages csv" {
    const allocator = std.testing.allocator;
    const blocks = try parseLocationBlocks(
        allocator,
        "prefix|/|static_root|/srv/www|off|off|index.html|;exact|/health|return|200|ok",
    );
    defer {
        for (blocks) |*block| block.deinit(allocator);
        allocator.free(blocks);
    }

    try applyLocationErrorPages(allocator, blocks, "prefix|/|404|/errors/404.html;prefix|/|500,502,503,504|https://example.com/50x");

    try std.testing.expectEqual(@as(usize, 2), blocks[0].error_pages.len);
    try std.testing.expectEqual(@as(u16, 404), blocks[0].error_pages[0].status_codes[0]);
    try std.testing.expectEqualStrings("/errors/404.html", blocks[0].error_pages[0].target);
    try std.testing.expectEqual(@as(usize, 4), blocks[0].error_pages[1].status_codes.len);
    try std.testing.expectEqualStrings("https://example.com/50x", blocks[0].error_pages[1].target);
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
    const entries = try parseNamedLocations(allocator, "admin|/api/messages;metrics|/status/metrics");
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
    const rules = try parseMirrorRules(allocator, "POST|^/api/messages$|http://127.0.0.1:9000/mirror");
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

test "validate TLS cert/key pair rejects mismatched presence" {
    try validateTlsCertKeyPair("", "");
    try validateTlsCertKeyPair("/cert.pem", "/key.pem");
    try std.testing.expectError(error.InvalidConfigPath, validateTlsCertKeyPair("/cert.pem", ""));
    try std.testing.expectError(error.InvalidConfigPath, validateTlsCertKeyPair("", "/key.pem"));
}

test "appliance profile defaults never trip validateApplianceTlsProfile" {
    if (!is_appliance_tls_profile) return;
    const allocator = std.testing.allocator;
    var cfg = try loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try validateApplianceTlsProfile(&cfg);
}

test "appliance profile rejects unsupported TLS settings one at a time" {
    if (!is_appliance_tls_profile) return;
    const allocator = std.testing.allocator;

    const cert_path = "tests/fixtures/tls/native_ed25519.crt";
    const key_path = "tests/fixtures/tls/native_ed25519.key";

    var base = try loadFromEnv(allocator);
    defer base.deinit(allocator);
    allocator.free(base.tls_cert_path);
    base.tls_cert_path = try allocator.dupe(u8, cert_path);
    allocator.free(base.tls_key_path);
    base.tls_key_path = try allocator.dupe(u8, key_path);
    allocator.free(base.tls_server_name);
    base.tls_server_name = try allocator.dupe(u8, "tardigrade.test");
    try validateApplianceTlsProfile(&base);

    {
        // `cfg` is a shallow copy of `base` (aliasing its owned slices); do
        // not free the aliased original, only the fresh override, so
        // `base.deinit` at the end of this test frees each allocation once.
        var cfg = base;
        cfg.tls_min_version = "1.2";
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_cipher_list = "ECDHE-RSA-AES128-GCM-SHA256";
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_client_verify = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_session_cache_enabled = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_session_tickets_enabled = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_ocsp_stapling_enabled = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_crl_check = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_acme_enabled = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.http3_enabled = true;
        cfg.http3_enable_0rtt = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.http3_enabled = true;
        cfg.http3_connection_migration = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
}

test "appliance profile rejects HTTP/3 without a complete identity" {
    if (!is_appliance_tls_profile) return;
    const allocator = std.testing.allocator;
    var cfg = try loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    cfg.http3_enabled = true;
    try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
}

test "appliance profile rejects a configured server name with no credential files" {
    if (!is_appliance_tls_profile) return;
    const allocator = std.testing.allocator;
    var cfg = try loadFromEnv(allocator);
    defer cfg.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), cfg.tls_cert_path.len);
    try std.testing.expectEqual(@as(usize, 0), cfg.tls_key_path.len);
    allocator.free(cfg.tls_server_name);
    cfg.tls_server_name = try allocator.dupe(u8, "tardigrade.test");
    try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
}

test "appliance profile rejects PROXY protocol, credential watching, and OCSP auto-refresh with TLS active" {
    if (!is_appliance_tls_profile) return;
    const allocator = std.testing.allocator;

    var base = try loadFromEnv(allocator);
    defer base.deinit(allocator);
    allocator.free(base.tls_cert_path);
    base.tls_cert_path = try allocator.dupe(u8, "tests/fixtures/tls/native_ed25519.crt");
    allocator.free(base.tls_key_path);
    base.tls_key_path = try allocator.dupe(u8, "tests/fixtures/tls/native_ed25519.key");
    allocator.free(base.tls_server_name);
    base.tls_server_name = try allocator.dupe(u8, "tardigrade.test");
    try validateApplianceTlsProfile(&base);

    {
        var cfg = base;
        cfg.proxy_protocol_mode = .v1;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_dynamic_reload_interval_ms = 5000;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
    {
        var cfg = base;
        cfg.tls_ocsp_auto_refresh = true;
        try std.testing.expectError(error.UnsupportedApplianceConfiguration, validateApplianceTlsProfile(&cfg));
    }
}

test "validate mTLS consistency requires CA path when verify is enabled" {
    try validateMtlsConsistency(false, "");
    try validateMtlsConsistency(false, "/ca.pem");
    try validateMtlsConsistency(true, "/ca.pem");
    try std.testing.expectError(error.InvalidConfigPath, validateMtlsConsistency(true, ""));
}

test "validate OTEL sample rate rejects values above 100" {
    try validateOtelSampleRate(0);
    try validateOtelSampleRate(50);
    try validateOtelSampleRate(100);
    try std.testing.expectError(error.InvalidConfigValue, validateOtelSampleRate(101));
    try std.testing.expectError(error.InvalidConfigValue, validateOtelSampleRate(200));
}

test "validate Brotli quality rejects values above 11" {
    try validateBrotliQuality(0);
    try validateBrotliQuality(6);
    try validateBrotliQuality(11);
    try std.testing.expectError(error.InvalidConfigValue, validateBrotliQuality(12));
}

test "validate upstream retry attempts rejects zero" {
    try validateUpstreamRetryAttempts(1);
    try validateUpstreamRetryAttempts(3);
    try std.testing.expectError(error.InvalidConfigValue, validateUpstreamRetryAttempts(0));
}

test "validate buffered upstream response limit rejects zero" {
    try validateBufferedUpstreamResponseLimit(256 * 1024);
    try validateBufferedUpstreamResponseLimit(1024 * 1024);
    try std.testing.expectError(error.InvalidConfigValue, validateBufferedUpstreamResponseLimit(0));
}

test "validate proxy stream buffer size rejects zero and oversized buffers" {
    try validateProxyStreamBufferSize(1);
    try validateProxyStreamBufferSize(16 * 1024);
    try validateProxyStreamBufferSize(1024 * 1024);
    try std.testing.expectError(error.InvalidConfigValue, validateProxyStreamBufferSize(0));
    try std.testing.expectError(error.InvalidConfigValue, validateProxyStreamBufferSize(1024 * 1024 + 1));
}

test "proxy buffer hard limit covers effective streaming relay allocation" {
    const limits = http.proxy_buffer_account.Limits{
        .per_stream_low_watermark = 1024,
        .per_stream_high_watermark = 2048,
        .per_stream_hard_limit = 4096,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    };
    try std.testing.expectError(error.InvalidConfigValue, validateProxyBufferLimitsCoverRelayAllocations(limits, 16 * 1024));
}

test "proxy buffer limits validate low high hard ordering" {
    try (http.proxy_buffer_account.Limits{
        .per_stream_low_watermark = 256 * 1024,
        .per_stream_high_watermark = 768 * 1024,
        .per_stream_hard_limit = 1024 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }).validate();

    try std.testing.expectError(error.InvalidBufferLimits, (http.proxy_buffer_account.Limits{
        .per_stream_low_watermark = 768 * 1024,
        .per_stream_high_watermark = 256 * 1024,
        .per_stream_hard_limit = 1024 * 1024,
        .per_origin_hard_limit = 0,
        .global_hard_limit = 0,
    }).validate());

    try std.testing.expectError(error.InvalidBufferLimits, (http.proxy_buffer_account.Limits{
        .per_stream_low_watermark = 256 * 1024,
        .per_stream_high_watermark = 768 * 1024,
        .per_stream_hard_limit = 1024 * 1024,
        .per_origin_hard_limit = 512 * 1024,
        .global_hard_limit = 0,
    }).validate());
}

test "TLS buffer limits default from TLS core" {
    const allocator = std.testing.allocator;
    var cfg = try loadFromEnv(allocator);
    defer cfg.deinit(allocator);

    try std.testing.expectEqualDeep(encrypted_stream.BufferLimits.defaults(), cfg.tls_buffer_limits);
    cfg.tls_buffer_limits.inbound_plaintext.low = cfg.tls_buffer_limits.inbound_plaintext.high;
    try std.testing.expectError(error.InvalidBufferLimits, cfg.tls_buffer_limits.validate());
}

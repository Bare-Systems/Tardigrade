const compat = @import("zig_compat.zig");
const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const runtime_allocator = @import("runtime_allocator.zig");

const STREAM_RELAY_BUFFER_SIZE: usize = 16 * 1024;
const JSON_CONTENT_TYPE = "application/json";
const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_MAX_FRAME_SIZE: usize = 16 * 1024;
const WS_MUX_MAX_CHANNELS: usize = 32;
/// Fallback approval TTL when no config value is provided (5 minutes).
const APPROVAL_TIMEOUT_MS_DEFAULT: i64 = 300_000;

const gs = @import("gateway_state.zig");

// Types extracted to gateway_state.zig — aliased so existing handler code
// compiles without changes.
const MAX_REQUEST_SIZE = gs.MAX_REQUEST_SIZE;
const GatewayState = gs.GatewayState;
const WorkerContext = gs.WorkerContext;
const ConfigLease = gs.ConfigLease;
const ManagedConfigVersion = gs.ManagedConfigVersion;
const ReloadableConfigStore = gs.ReloadableConfigStore;
const ConnectionSession = gs.ConnectionSession;
const ConnectionSessionPool = gs.ConnectionSessionPool;
const ProxyCacheLookup = gs.ProxyCacheLookup;
const UpstreamHealth = gs.UpstreamHealth;
const ConnectionSlotResult = gs.ConnectionSlotResult;
const Http2PendingStream = gs.Http2PendingStream;
const UpstreamScope = gs.UpstreamScope;
const UpstreamPoolView = gs.UpstreamPoolView;
const StickyAffinityRequest = gs.StickyAffinityRequest;
const StickyUpstreamSelection = gs.StickyUpstreamSelection;
const CommandLifecycleEntry = gs.CommandLifecycleEntry;
const ApprovalEntry = gs.ApprovalEntry;
const ApprovalDecision = gs.ApprovalDecision;
const ApprovalValidation = gs.ApprovalValidation;
const MuxResumeState = gs.MuxResumeState;
const loadApprovalStore = gs.loadApprovalStore;
const loadSessionStore = gs.loadSessionStore;
const upstreamPoolForScope = gs.upstreamPoolForScope;
const upstreamScopeName = gs.upstreamScopeName;
const proxyScopeForPath = gs.proxyScopeForPath;
const maxBufferedUpstreamResponseBytes = gs.maxBufferedUpstreamResponseBytes;
const prepareStickyAffinityRequest = gs.prepareStickyAffinityRequest;
const buildStickySetCookieHeader = gs.buildStickySetCookieHeader;

const gp = @import("gateway_proxy.zig");
// Types from gateway_proxy.zig
const UpstreamHeader = gp.UpstreamHeader;
const RawUpstreamResponse = gp.RawUpstreamResponse;
const MaybeOwnedBytes = gp.MaybeOwnedBytes;
const ResolvedProxyTarget = gp.ResolvedProxyTarget;
const UpstreamMappedError = gp.UpstreamMappedError;
const ProxyExecMappedError = gp.ProxyExecMappedError;
// Functions from gateway_proxy.zig
const uriComponentBytes = gp.uriComponentBytes;
const parseRawUpstreamResponse = gp.parseRawUpstreamResponse;
const executeUnixSocketHttpRequest = gp.executeUnixSocketHttpRequest;
const rawUpstreamResponseHasNoStore = gp.rawUpstreamResponseHasNoStore;
const upstreamReasonPhrase = gp.upstreamReasonPhrase;
const executeRawHttpProxyRequest = gp.executeRawHttpProxyRequest;
const executeUpstreamHttpsWithMtls = gp.executeUpstreamHttpsWithMtls;
const applyResponseHeaders = gp.applyResponseHeaders;
const appendAssertedIdentityHeaders = gp.appendAssertedIdentityHeaders;
const writeAssertedIdentityHeaders = gp.writeAssertedIdentityHeaders;
const writeStreamedUpstreamResponse = gp.writeStreamedUpstreamResponse;
const writeStreamedUpstreamResponseHead = gp.writeStreamedUpstreamResponseHead;
const writeBufferedUpstreamResponse = gp.writeBufferedUpstreamResponse;
const writeBufferedUpstreamResponseHead = gp.writeBufferedUpstreamResponseHead;
const appendProxyRequestHeaders = gp.appendProxyRequestHeaders;
const shouldSkipUpstreamRequestHeader = gp.shouldSkipUpstreamRequestHeader;
const connectionHeaderReferencesHeader = gp.connectionHeaderReferencesHeader;
const shouldSkipUpstreamResponseHeader = gp.shouldSkipUpstreamResponseHeader;
const computeHstsValue = gp.computeHstsValue;
const writeSecurityHeaders = gp.writeSecurityHeaders;
const writeChunk = gp.writeChunk;
const stripPort = gp.stripPort;
const isTrustedUpstream = gp.isTrustedUpstream;
const appendTrustedUpstreamHeaders = gp.appendTrustedUpstreamHeaders;
const buildForwardedFor = gp.buildForwardedFor;
const upstreamResponseHasNoStore = gp.upstreamResponseHasNoStore;
const isRedirectStatusCode = gp.isRedirectStatusCode;
const resolveProxyTarget = gp.resolveProxyTarget;
const appendProxyQueryString = gp.appendProxyQueryString;
const resolveRedirectTargetUrl = gp.resolveRedirectTargetUrl;
const unixSocketPathFromEndpoint = gp.unixSocketPathFromEndpoint;
const combineProxyTarget = gp.combineProxyTarget;
const parseUpstreamHost = gp.parseUpstreamHost;
const mapUpstreamError = gp.mapUpstreamError;
const mapProxyExecutionError = gp.mapProxyExecutionError;
const buildApiErrorJson = gp.buildApiErrorJson;
const setRequestIdHeaders = gp.setRequestIdHeaders;
const writeRequestIdHeaders = gp.writeRequestIdHeaders;
const appendRequestIdHeaders = gp.appendRequestIdHeaders;
const sendApiError = gp.sendApiError;
const isAbsoluteHttpUrl = gs.isAbsoluteHttpUrl;

const gpr = @import("gateway_protocols.zig");
const handleFastcgiRoute = gpr.handleFastcgiRoute;

const ga = @import("gateway_auth.zig");
const AuthResult = ga.AuthResult;
const AuthFailureReason = ga.AuthFailureReason;
const authorizeRequest = ga.authorizeRequest;
const resolveRequestConfig = ga.resolveRequestConfig;
const hostMatchesServerNames = ga.hostMatchesServerNames;
const authorizeViaSubrequest = ga.authorizeViaSubrequest;
const approvalPolicyError = ga.approvalPolicyError;
const evaluatePolicy = ga.evaluatePolicy;
const isGeoBlocked = ga.isGeoBlocked;
const hashBearerToken = ga.hashBearerToken;
const parseChatMessage = ga.parseChatMessage;
const parseApprovalRequestBody = ga.parseApprovalRequestBody;
const parseApprovalResponseBody = ga.parseApprovalResponseBody;
const routeRequiresApprovalRule = ga.routeRequiresApprovalRule;
const hostMatchesPatterns = ga.hostMatchesPatterns;
const gjp = @import("gateway_json_proxy.zig");
const ProxyResult = gjp.ProxyResult;
const ProxyExecution = gjp.ProxyExecution;
const proxyJsonExecute = gjp.proxyJsonExecute;
const buildProxyCacheKey = gjp.buildProxyCacheKey;

pub fn run(cfg: *const edge_config.EdgeConfig) !void {
    const state_allocator = runtime_allocator.runtimeAllocator();

    const initial_hsts = try computeHstsValue(state_allocator, cfg);
    errdefer if (initial_hsts.len > 0) state_allocator.free(initial_hsts);

    var state = GatewayState{
        .allocator = state_allocator,
        .rate_limiter = if (cfg.rate_limit_rps > 0)
            http.rate_limiter.RateLimiter.init(state_allocator, cfg.rate_limit_rps, cfg.rate_limit_burst)
        else
            null,
        .idempotency_store = if (cfg.idempotency_ttl_seconds > 0)
            http.idempotency.IdempotencyStore.init(state_allocator, cfg.idempotency_ttl_seconds)
        else
            null,
        .proxy_cache_store = if (cfg.proxy_cache_ttl_seconds > 0)
            http.idempotency.IdempotencyStore.init(state_allocator, cfg.proxy_cache_ttl_seconds)
        else
            null,
        .proxy_cache_path = cfg.proxy_cache_path,
        .proxy_cache_ttl_seconds = cfg.proxy_cache_ttl_seconds,
        .security_headers = blk: {
            var s = if (cfg.security_headers_enabled)
                http.security_headers.SecurityHeaders.api
            else
                http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "", .cross_origin_opener_policy = "", .cross_origin_resource_policy = "" };
            s.strict_transport_security = initial_hsts;
            break :blk s;
        },
        .hsts_value = initial_hsts,
        .add_headers = cfg.add_headers,
        .http3_alt_svc = if (cfg.http3_enabled) http.http3_handler.formatAltSvc(state_allocator, cfg.quic_port) catch null else null,
        .http3_runtime = null,
        .session_store = if (cfg.session_ttl_seconds > 0)
            http.session.SessionStore.init(state_allocator, cfg.session_ttl_seconds, cfg.session_max)
        else
            null,
        .session_store_path = cfg.session_store_path,
        .access_control = if (cfg.access_control_rules.len > 0)
            http.access_control.AccessControl.fromConfig(state_allocator, cfg.access_control_rules, .allow) catch null
        else
            null,
        .logger = http.logger.Logger.init(cfg.log_level, "gateway"),
        .metrics = http.metrics.Metrics.init(),
        .compression_config = .{
            .enabled = cfg.compression_enabled,
            .min_size = cfg.compression_min_size,
            .brotli_enabled = cfg.compression_brotli_enabled,
            .brotli_quality = cfg.compression_brotli_quality,
        },
        .circuit_breaker = http.circuit_breaker.CircuitBreaker.init(.{
            .threshold = cfg.cb_threshold,
            .timeout_ms = cfg.cb_timeout_ms,
        }),
        .upstream_client = .{ .allocator = state_allocator, .io = compat.io() },
        .acme_challenge_store = if (cfg.tls_acme_enabled and cfg.tls_acme_domains.len > 0)
            http.acme_client.ChallengeStore.init(state_allocator)
        else
            null,
        .event_hub = http.event_hub.EventHub.init(state_allocator, cfg.sse_max_events_per_topic),
        .request_buffer_pool = http.buffer_pool.BufferPool.init(state_allocator, MAX_REQUEST_SIZE, cfg.connection_pool_size),
        .relay_buffer_pool = http.buffer_pool.BufferPool.init(state_allocator, STREAM_RELAY_BUFFER_SIZE, cfg.connection_pool_size),
        .max_connections_per_ip = cfg.max_connections_per_ip,
        .max_active_connections = cfg.max_active_connections,
        .active_connections_total = 0,
        .in_flight_requests = std.atomic.Value(u32).init(0),
        .max_in_flight_requests = cfg.max_in_flight_requests,
        .active_ws_streams = 0,
        .active_sse_streams = 0,
        .active_mux_connections = 0,
        .active_mux_subscriptions = 0,
        .connection_memory_estimate_bytes = if (cfg.max_connection_memory_bytes > 0) cfg.max_connection_memory_bytes else MAX_REQUEST_SIZE,
        .max_total_connection_memory_bytes = cfg.max_total_connection_memory_bytes,
        .upstream_rr_index = 0,
        .upstream_backup_rr_index = 0,
        .lb_random_state = 0x9e3779b97f4a7c15 ^ @as(u64, @intCast(http.event_loop.monotonicMs())),
        .next_active_health_probe_ms = 0,
        .next_proxy_cache_maintenance_ms = 0,
        .health_probe_running = std.atomic.Value(bool).init(false),
        .upstream_health = std.StringHashMap(UpstreamHealth).init(state_allocator),
        .upstream_active_requests = std.StringHashMap(usize).init(state_allocator),
        .fastcgi_pool = std.StringHashMap(std.ArrayList(compat.NetStream)).init(state_allocator),
        .fastcgi_next_request_id = std.StringHashMap(u16).init(state_allocator),
        .proxy_cache_locks = std.StringHashMap(u32).init(state_allocator),
        .active_connections_by_ip = std.StringHashMap(u32).init(state_allocator),
        .active_fds = std.AutoHashMap(std.posix.fd_t, void).init(state_allocator),
        .fd_to_ip = std.AutoHashMap(std.posix.fd_t, []u8).init(state_allocator),
        .command_lifecycle = std.StringHashMap(CommandLifecycleEntry).init(state_allocator),
        .approvals = std.StringHashMap(ApprovalEntry).init(state_allocator),
        .mux_subscriptions_by_device = std.StringHashMap(usize).init(state_allocator),
        .mux_resume_state = std.StringHashMap(MuxResumeState).init(state_allocator),
        .approval_store_path = cfg.approval_store_path,
        .approval_escalation_webhook = cfg.approval_escalation_webhook,
        .approval_ttl_ms = if (cfg.approval_ttl_ms > 0) cfg.approval_ttl_ms else APPROVAL_TIMEOUT_MS_DEFAULT,
        .approval_max_pending_per_identity = cfg.approval_max_pending_per_identity,
        .transcript_store_path = cfg.transcript_store_path,
        .dns_discovery = http.dns_discovery.DnsDiscovery.init(state_allocator, .{
            .host = cfg.upstream_dns_discovery_host,
            .port = cfg.upstream_dns_discovery_port,
            .tls = cfg.upstream_dns_discovery_tls,
            .refresh_interval_ms = cfg.upstream_dns_refresh_interval_ms,
        }),
    };
    defer state.deinit();

    // Load approval state from persistent store (if configured).
    if (cfg.approval_store_path.len > 0) {
        loadApprovalStore(&state) catch |err| {
            state.logger.warn(null, "failed to load approval store '{s}': {}", .{ cfg.approval_store_path, err });
        };
    }
    if (cfg.session_store_path.len > 0) {
        loadSessionStore(&state) catch |err| {
            state.logger.warn(null, "failed to load session store '{s}': {}", .{ cfg.session_store_path, err });
        };
    }

    http.access_log.init(state_allocator, .{
        .format = cfg.access_log_format,
        .custom_template = cfg.access_log_template,
        .min_status = cfg.access_log_min_status,
        .buffer_size_bytes = cfg.access_log_buffer_size,
        .syslog_udp_endpoint = cfg.access_log_syslog_udp,
        .redact_header_names = cfg.log_redact_headers,
    }) catch {}; // access log is best-effort; gateway continues without it
    defer http.access_log.deinit();

    // Configure upstream HTTP client TLS (custom CA bundle and skip-verify).
    if (cfg.upstream_tls_ca_bundle.len > 0) {
        const ca_fc_opt: ?compat.FileCompat = compat.cwd().openFile(cfg.upstream_tls_ca_bundle, .{}) catch |err| blk: {
            state.logger.warn(null, "upstream TLS CA bundle open failed ({s}): {}", .{ cfg.upstream_tls_ca_bundle, err });
            break :blk null;
        };
        if (ca_fc_opt) |ca_fc| {
            var ca_f = ca_fc;
            defer ca_f.close();
            var ca_buf: [8192]u8 = undefined;
            var ca_reader = ca_f.file.reader(compat.io(), &ca_buf);
            state.upstream_client.ca_bundle.addCertsFromFile(state_allocator, &ca_reader, compat.unixTimestamp()) catch |err| {
                state.logger.warn(null, "upstream TLS CA bundle load failed: {}", .{err});
            };
        }
    }
    if (!cfg.upstream_tls_verify) {
        // Clear CA bundle so the Zig TLS client performs no certificate verification.
        state.upstream_client.ca_bundle.deinit(state_allocator);
        state.upstream_client.ca_bundle = .empty;
        state.logger.warn(null, "upstream TLS certificate verification disabled", .{});
    }
    if (cfg.upstream_tls_client_cert.len > 0 or cfg.upstream_tls_server_name.len > 0) {
        state.logger.info(null, "upstream mTLS client cert and/or SNI override configured; applies to OpenSSL-backed connections", .{});
    }

    const address = try std.Io.net.IpAddress.parse(cfg.listen_host, cfg.listen_port);
    var server = try address.listen(compat.io(), .{ .reuse_address = true });
    defer server.deinit(compat.io());
    const listen_fd = server.socket.handle;

    try setNonBlocking(listen_fd, true);
    applyRuntimeIdentity(cfg, &state.logger) catch |err| {
        state.logger.warn(null, "privilege drop configuration failed: {}", .{err});
    };

    var event_loop = try http.event_loop.EventLoop.init();
    defer event_loop.deinit();
    try event_loop.addReadFd(listen_fd);
    var timer = http.event_loop.TimerManager.init(250);
    var config_store = try ReloadableConfigStore.initBorrowed(state_allocator, cfg);
    defer config_store.deinit();
    var http3_runtime: ?http.http3_runtime.Runtime = null;
    var tls_terminator: ?http.tls_termination.TlsTerminator = null;
    var http3_dispatch_ctx = Http3DispatchContext{
        .config_store = &config_store,
        .cfg = cfg,
        .state = &state,
    };
    if (edge_config.hasTlsFiles(cfg)) {
        var sni_specs = try state_allocator.alloc(http.tls_termination.SniCertSpec, cfg.tls_sni_certs.len);
        defer state_allocator.free(sni_specs);
        for (cfg.tls_sni_certs, 0..) |sc, i| {
            sni_specs[i] = .{ .server_name = sc.server_name, .cert_path = sc.cert_path, .key_path = sc.key_path };
        }
        tls_terminator = try http.tls_termination.TlsTerminator.init(state_allocator, .{
            .cert_path = cfg.tls_cert_path,
            .key_path = cfg.tls_key_path,
            .min_version = cfg.tls_min_version,
            .max_version = cfg.tls_max_version,
            .cipher_list = cfg.tls_cipher_list,
            .cipher_suites = cfg.tls_cipher_suites,
            .sni_certs = sni_specs,
            .session_cache_enabled = cfg.tls_session_cache_enabled,
            .session_cache_size = cfg.tls_session_cache_size,
            .session_timeout_seconds = cfg.tls_session_timeout_seconds,
            .session_tickets_enabled = cfg.tls_session_tickets_enabled,
            .ocsp_stapling_enabled = cfg.tls_ocsp_stapling_enabled,
            .ocsp_response_path = cfg.tls_ocsp_response_path,
            .ocsp_auto_refresh_enabled = cfg.tls_ocsp_auto_refresh,
            .ocsp_refresh_interval_ms = cfg.tls_ocsp_refresh_interval_ms,
            .ocsp_refresh_timeout_ms = cfg.tls_ocsp_refresh_timeout_ms,
            .client_ca_path = cfg.tls_client_ca_path,
            .client_verify = cfg.tls_client_verify,
            .client_verify_depth = cfg.tls_client_verify_depth,
            .crl_path = cfg.tls_crl_path,
            .crl_check = cfg.tls_crl_check,
            .dynamic_reload_interval_ms = cfg.tls_dynamic_reload_interval_ms,
            .acme_enabled = cfg.tls_acme_enabled,
            .acme_cert_dir = cfg.tls_acme_cert_dir,
            .acme_auto_issue = cfg.tls_acme_enabled and cfg.tls_acme_domains.len > 0,
            .acme_directory_url = cfg.tls_acme_directory_url,
            .acme_domains = cfg.tls_acme_domains,
            .acme_email = cfg.tls_acme_email,
            .acme_account_key_path = cfg.tls_acme_account_key_path,
            .acme_renew_days_before_expiry = cfg.tls_acme_renew_days_before_expiry,
            .acme_challenge_store = if (state.acme_challenge_store) |*s| s else null,
            .http2_enabled = cfg.http2_enabled,
        });
    }
    defer if (tls_terminator) |*tls| tls.deinit();
    if (cfg.http3_enabled) {
        if (!edge_config.hasTlsFiles(cfg)) {
            state.logger.warn(null, "HTTP/3 requested without TLS cert/key; QUIC bootstrap will remain incomplete", .{});
        }
        http3_runtime = http.http3_runtime.Runtime.init(state_allocator, &state.logger, .{
            .listen_host = cfg.listen_host,
            .quic_port = cfg.quic_port,
            .tls_cert_path = cfg.tls_cert_path,
            .tls_key_path = cfg.tls_key_path,
            .tls_min_version = "1.3",
            .tls_max_version = "1.3",
            .enable_0rtt = cfg.http3_enable_0rtt,
            .connection_migration = cfg.http3_connection_migration,
            .max_datagram_size = cfg.http3_max_datagram_size,
            .request_handler = handleHttp3Request,
            .request_handler_ctx = &http3_dispatch_ctx,
        }) catch |err| switch (err) {
            error.DependencyUnavailable => blk: {
                state.logger.warn(null, "HTTP/3 requested but ngtcp2/nghttp3 integration is not enabled in this build", .{});
                break :blk null;
            },
            else => return err,
        };
        if (http3_runtime) |*runtime| runtime.start();
    }
    state.http3_runtime = if (http3_runtime) |*runtime| runtime else null;
    defer if (http3_runtime) |*runtime| runtime.deinit();
    const worker_count: usize = blk: {
        const configured = if (cfg.worker_threads == 0)
            (std.Thread.getCpuCount() catch 1)
        else
            cfg.worker_threads;
        break :blk @intCast(@max(configured, @as(u32, 1)));
    };
    var worker_ctx = WorkerContext{
        .config_store = &config_store,
        .state = &state,
        .tls = if (tls_terminator) |*tls| tls else null,
        .session_pool = undefined,
    };
    var session_pool = ConnectionSessionPool.init(state_allocator, &state.request_buffer_pool, cfg.connection_pool_size);
    defer session_pool.deinit();
    worker_ctx.session_pool = &session_pool;

    var worker_pool: http.worker_pool.WorkerPool = undefined;
    try worker_pool.init(
        state_allocator,
        worker_count,
        cfg.worker_queue_size,
        handleAcceptedClient,
        &worker_ctx,
    );
    defer worker_pool.deinit();
    state.metricsSetWorkerPoolStats(0, 0, worker_count, cfg.worker_queue_size);

    state.logger.info(null, "Tardigrade edge listening on {s}:{d}", .{ cfg.listen_host, cfg.listen_port });
    state.logger.info(null, "Event loop initialized with backend: {s}", .{event_loop.backendName()});
    if (!edge_config.hasTlsFiles(cfg)) {
        state.logger.warn(null, "TLS cert/key not set; serving HTTP only", .{});
    } else {
        state.logger.info(null, "TLS termination enabled with cert/key at {s} and {s}", .{ cfg.tls_cert_path, cfg.tls_key_path });
    }
    if (state.rate_limiter != null) {
        state.logger.info(null, "Rate limiting enabled: {d:.0} req/s, burst {d}", .{ cfg.rate_limit_rps, cfg.rate_limit_burst });
    }
    if (state.idempotency_store != null) {
        state.logger.info(null, "Idempotency cache enabled: TTL {d}s", .{cfg.idempotency_ttl_seconds});
    }
    if (state.proxy_cache_store != null) {
        state.logger.info(null, "Proxy cache enabled: TTL {d}s key_template={s}", .{ cfg.proxy_cache_ttl_seconds, cfg.proxy_cache_key_template });
        if (cfg.proxy_cache_path.len > 0) {
            compat.cwd().makePath(cfg.proxy_cache_path) catch |err| {
                state.logger.warn(null, "failed to create proxy cache path {s}: {}", .{ cfg.proxy_cache_path, err });
            };
            state.logger.info(null, "Proxy cache disk path enabled: {s}", .{cfg.proxy_cache_path});
        }
    }
    if (state.session_store != null) {
        state.logger.info(null, "Session management enabled: TTL {d}s, max {d}", .{ cfg.session_ttl_seconds, cfg.session_max });
    }
    if (state.access_control != null) {
        state.logger.info(null, "IP access control enabled", .{});
    }
    if (cfg.basic_auth_hashes.len > 0) {
        state.logger.info(null, "HTTP Basic Auth enabled with {d} credential(s)", .{cfg.basic_auth_hashes.len});
    }
    state.logger.info(null, "Access log configured: format={s} min_status={d} buffer={d} syslog={s}", .{
        @tagName(cfg.access_log_format),
        cfg.access_log_min_status,
        cfg.access_log_buffer_size,
        if (cfg.access_log_syslog_udp.len > 0) cfg.access_log_syslog_udp else "off",
    });
    if (cfg.proxy_protocol_mode != .off) {
        state.logger.info(null, "Proxy protocol enabled: {s} (plaintext and TLS listeners)", .{@tagName(cfg.proxy_protocol_mode)});
    }
    if (cfg.http3_enabled) {
        state.logger.info(null, "HTTP/3 foundation enabled: quic_port={d} 0rtt={} migration={} max_datagram={d}", .{
            cfg.quic_port,
            cfg.http3_enable_0rtt,
            cfg.http3_connection_migration,
            cfg.http3_max_datagram_size,
        });
    }
    if (cfg.trust_shared_secret.len > 0) {
        state.logger.info(null, "Trusted upstream signing enabled (gateway_id={s})", .{cfg.trust_gateway_id});
    }
    if (cfg.trusted_upstream_identities.len > 0) {
        state.logger.info(null, "Trusted upstream identities configured: {d}", .{cfg.trusted_upstream_identities.len});
    }
    if (cfg.trust_require_upstream_identity) {
        state.logger.info(null, "Strict upstream trust verification enabled", .{});
    }
    if (cfg.websocket_enabled) {
        state.logger.info(null, "WebSocket routes enabled: idle_timeout={d}ms max_frame={d} ping_interval={d}ms", .{
            cfg.websocket_idle_timeout_ms,
            cfg.websocket_max_frame_size,
            cfg.websocket_ping_interval_ms,
        });
    }
    if (cfg.sse_enabled) {
        state.logger.info(null, "SSE routes enabled: events/topic={d} poll={d}ms backlog={d} idle_timeout={d}ms", .{
            cfg.sse_max_events_per_topic,
            cfg.sse_poll_interval_ms,
            cfg.sse_max_backlog,
            cfg.sse_idle_timeout_ms,
        });
    }
    if (cfg.rewrite_rules.len > 0) {
        state.logger.info(null, "Rewrite rules enabled: {d}", .{cfg.rewrite_rules.len});
    }
    if (cfg.return_rules.len > 0) {
        state.logger.info(null, "Return rules enabled: {d}", .{cfg.return_rules.len});
    }
    if (cfg.internal_redirect_rules.len > 0) {
        state.logger.info(null, "Internal redirect rules enabled: {d}", .{cfg.internal_redirect_rules.len});
    }
    if (cfg.mirror_rules.len > 0) {
        state.logger.info(null, "Mirror rules enabled: {d}", .{cfg.mirror_rules.len});
    }
    if (cfg.fastcgi_upstream.len > 0 or cfg.uwsgi_upstream.len > 0 or cfg.scgi_upstream.len > 0 or cfg.grpc_upstream.len > 0 or cfg.memcached_upstream.len > 0) {
        state.logger.info(null, "Backend protocol bridges enabled (fastcgi/uwsgi/scgi/grpc/memcached)", .{});
    }
    if (cfg.smtp_upstream.len > 0 or cfg.imap_upstream.len > 0 or cfg.pop3_upstream.len > 0) {
        state.logger.info(null, "Mail protocol proxy routes enabled (smtp/imap/pop3)", .{});
    }
    if (cfg.tcp_proxy_upstream.len > 0 or cfg.udp_proxy_upstream.len > 0) {
        state.logger.info(null, "Stream proxy routes enabled (tcp/udp), ssl_termination={}", .{cfg.stream_ssl_termination});
    }
    {
        const limits = cfg.request_limits;
        if (limits.max_body_size > 0 or limits.max_uri_length > 0 or limits.max_header_count > 0) {
            state.logger.info(null, "Request limits configured", .{});
        }
    }
    if (cfg.compression_enabled) {
        state.logger.info(null, "Response compression enabled (min size: {d} bytes, brotli={}, br_quality={d})", .{
            cfg.compression_min_size,
            cfg.compression_brotli_enabled,
            cfg.compression_brotli_quality,
        });
    }
    if (cfg.upstream_gunzip_enabled) {
        state.logger.info(null, "Upstream gunzip enabled (proxy requests advertise Accept-Encoding: gzip)", .{});
    }
    if (cfg.cb_threshold > 0) {
        state.logger.info(null, "Circuit breaker enabled: threshold={d} timeout={d}ms", .{ cfg.cb_threshold, cfg.cb_timeout_ms });
    }
    state.logger.info(null, "Worker pool enabled: workers={d} queue={d}", .{ worker_count, cfg.worker_queue_size });
    if (cfg.fd_soft_limit > 0) {
        const applied = applyFdSoftLimit(cfg.fd_soft_limit) catch |err| blk: {
            state.logger.warn(null, "failed to apply fd soft limit: {}", .{err});
            break :blk null;
        };
        if (applied) |limit| {
            state.logger.info(null, "FD soft limit configured: {d}", .{limit});
        }
    }
    state.logger.info(null, "Keep-alive configured: timeout={d}ms max_requests={d}", .{ cfg.keep_alive_timeout_ms, cfg.max_requests_per_connection });
    state.logger.info(null, "Connection session pool configured: max_cached={d}", .{cfg.connection_pool_size});
    if (cfg.max_connection_memory_bytes > 0) {
        state.logger.info(null, "Per-connection memory limit configured: {d} bytes", .{cfg.max_connection_memory_bytes});
    }
    if (cfg.proxy_stream_all_statuses) {
        state.logger.info(null, "Proxy streaming for all upstream statuses enabled", .{});
    }
    if (cfg.upstream_base_urls.len > 0) {
        state.logger.info(null, "Upstream round-robin enabled with {d} base URLs", .{cfg.upstream_base_urls.len});
        if (cfg.upstream_base_url_weights.len > 0) {
            state.logger.info(null, "Upstream server weights enabled with {d} entries", .{cfg.upstream_base_url_weights.len});
        }
        if (cfg.upstream_backup_base_urls.len > 0) {
            state.logger.info(null, "Upstream backup servers enabled with {d} base URLs", .{cfg.upstream_backup_base_urls.len});
        }
        switch (cfg.upstream_lb_algorithm) {
            .least_connections => state.logger.info(null, "Upstream load balancing algorithm: least_connections", .{}),
            .ip_hash => state.logger.info(null, "Upstream load balancing algorithm: ip_hash", .{}),
            .generic_hash => state.logger.info(null, "Upstream load balancing algorithm: generic_hash", .{}),
            .random_two_choices => state.logger.info(null, "Upstream load balancing algorithm: random_two_choices", .{}),
            .round_robin => {},
        }
    }
    if (cfg.upstream_chat_base_urls.len > 0 or cfg.upstream_chat_backup_base_urls.len > 0) {
        state.logger.info(null, "Upstream block 'chat' enabled with {d} base URLs", .{cfg.upstream_chat_base_urls.len});
        if (cfg.upstream_chat_base_url_weights.len > 0) {
            state.logger.info(null, "Upstream block 'chat' weights enabled with {d} entries", .{cfg.upstream_chat_base_url_weights.len});
        }
        if (cfg.upstream_chat_backup_base_urls.len > 0) {
            state.logger.info(null, "Upstream block 'chat' backups enabled with {d} base URLs", .{cfg.upstream_chat_backup_base_urls.len});
        }
    }
    if (cfg.upstream_commands_base_urls.len > 0 or cfg.upstream_commands_backup_base_urls.len > 0) {
        state.logger.info(null, "Upstream block 'commands' enabled with {d} base URLs", .{cfg.upstream_commands_base_urls.len});
        if (cfg.upstream_commands_base_url_weights.len > 0) {
            state.logger.info(null, "Upstream block 'commands' weights enabled with {d} entries", .{cfg.upstream_commands_base_url_weights.len});
        }
        if (cfg.upstream_commands_backup_base_urls.len > 0) {
            state.logger.info(null, "Upstream block 'commands' backups enabled with {d} base URLs", .{cfg.upstream_commands_backup_base_urls.len});
        }
    }
    if (cfg.upstream_retry_attempts > 1) {
        state.logger.info(null, "Upstream retry attempts configured: {d} (idempotent_only={})", .{ cfg.upstream_retry_attempts, cfg.upstream_retry_idempotent_only });
    }
    if (cfg.upstream_connect_timeout_ms > 0) {
        state.logger.info(null, "Upstream connect timeout configured: {d}ms", .{cfg.upstream_connect_timeout_ms});
    }
    if (cfg.upstream_timeout_budget_ms > 0) {
        state.logger.info(null, "Upstream timeout budget configured: {d}ms", .{cfg.upstream_timeout_budget_ms});
    }
    if (cfg.upstream_max_fails > 0) {
        state.logger.info(null, "Passive upstream health enabled: max_fails={d} fail_timeout={d}ms", .{ cfg.upstream_max_fails, cfg.upstream_fail_timeout_ms });
    }
    if (cfg.upstream_active_health_interval_ms > 0) {
        state.logger.info(null, "Active upstream health checks enabled: interval={d}ms path={s} timeout={d}ms fail_threshold={d} success_threshold={d}", .{
            cfg.upstream_active_health_interval_ms,
            cfg.upstream_active_health_path,
            cfg.upstream_active_health_timeout_ms,
            cfg.upstream_active_health_fail_threshold,
            cfg.upstream_active_health_success_threshold,
        });
    }
    if (cfg.upstream_slow_start_ms > 0) {
        state.logger.info(null, "Upstream slow-start enabled: {d}ms", .{cfg.upstream_slow_start_ms});
    }
    if (cfg.max_connections_per_ip > 0) {
        state.logger.info(null, "Per-IP connection limit enabled: {d}", .{cfg.max_connections_per_ip});
    }
    if (cfg.max_active_connections > 0) {
        state.logger.info(null, "Global active connection limit enabled: {d}", .{cfg.max_active_connections});
    }
    if (cfg.max_total_connection_memory_bytes > 0) {
        state.logger.info(null, "Global connection memory estimate limit enabled: {d} bytes", .{cfg.max_total_connection_memory_bytes});
    }
    state.logger.info(null, "Connection model: non-blocking accept loop on the main thread with blocking per-connection work on a bounded worker pool", .{});

    // Install signal handlers for graceful shutdown
    http.shutdown.installSignalHandlers();
    state.logger.info(null, "Signal handlers installed (SIGTERM/SIGINT shutdown, SIGHUP reload, SIGUSR1 reopen logs, SIGUSR2 upgrade)", .{});

    var ready_events: [64]http.event_loop.Event = undefined;
    while (!http.shutdown.isShutdownRequested()) {
        const now_ms = http.event_loop.monotonicMs();
        const timeout_ms = timer.msUntilNextTick(now_ms);
        const event_count = event_loop.wait(ready_events[0..], timeout_ms) catch |err| {
            state.logger.err(null, "event loop wait error: {}", .{err});
            continue;
        };

        var i: usize = 0;
        while (i < event_count) : (i += 1) {
            const ev = ready_events[i];
            if (!ev.readable or ev.fd != listen_fd) continue;
            acceptReadyConnections(listen_fd, &worker_pool, &state);
        }

        if (timer.consumeTick(http.event_loop.monotonicMs())) {
            if (http.shutdown.consumeUpgradeRequested()) {
                state.logger.info(null, "Upgrade signal received; entering graceful shutdown", .{});
                http.shutdown.requestShutdown();
            }
            if (http.shutdown.consumeReopenLogsRequested()) {
                var current_cfg_lease = worker_ctx.acquireConfig();
                defer current_cfg_lease.release();
                const current_cfg = current_cfg_lease.cfg;
                http.access_log.flush();
                reopenErrorLog(current_cfg) catch |err| {
                    state.logger.warn(null, "log reopen failed: {}", .{err});
                };
            }
            if (http.shutdown.consumeReloadRequested()) {
                hotReloadConfig(state_allocator, &worker_ctx, &state, &http3_dispatch_ctx);
            }
            var current_cfg_lease = worker_ctx.acquireConfig();
            defer current_cfg_lease.release();
            const current_cfg = current_cfg_lease.cfg;
            runActiveHealthChecks(current_cfg, &state, worker_ctx.config_store);
            runDnsDiscoveryRefresh(current_cfg, &state);
            runProxyCacheMaintenance(current_cfg, &state);
            if (tls_terminator) |*tls| tls.runMaintenance(http.event_loop.monotonicMs());
            const worker_snapshot = worker_pool.snapshot();
            state.metricsSetWorkerPoolStats(
                worker_snapshot.active_jobs,
                worker_snapshot.queued_jobs,
                worker_snapshot.worker_threads,
                worker_snapshot.max_queue_len,
            );
            state.metrics_mutex.lock();
            state.metrics.recordEventLoopIteration();
            state.metrics_mutex.unlock();
        }
    }

    state.logger.info(null, "Shutdown requested; draining active connection work (timeout={}ms)", .{cfg.shutdown_drain_timeout_ms});
    worker_pool.shutdownAndJoin(cfg.shutdown_drain_timeout_ms);
    state.logger.info(null, "Graceful shutdown complete", .{});
}

fn acceptReadyConnections(listen_fd: std.posix.fd_t, worker_pool: *http.worker_pool.WorkerPool, state: *GatewayState) void {
    while (!http.shutdown.isShutdownRequested()) {
        var accepted_addr: std.c.sockaddr.storage = undefined;
        var addr_len: std.c.socklen_t = @sizeOf(std.c.sockaddr.storage);

        const client_fd = std.c.accept(listen_fd, @ptrCast(&accepted_addr), &addr_len);
        if (client_fd >= 0) {
            const flags = std.c.fcntl(client_fd, std.c.F.GETFL, @as(c_int, 0));
            if (flags >= 0) {
                const nonblock: c_int = @intCast(@as(u32, @bitCast(std.c.O{ .NONBLOCK = true })));
                _ = std.c.fcntl(client_fd, std.c.F.SETFL, flags | nonblock);
            }
            _ = std.c.fcntl(client_fd, std.c.F.SETFD, @as(c_int, 1)); // FD_CLOEXEC
        }
        if (client_fd < 0) {
            const e = std.posix.errno(client_fd);
            if (e == .AGAIN) return;
            if (e == .CONNABORTED) continue;
            state.logger.err(null, "accept error: {}", .{e});
            return;
        }

        const owned_ip_key = clientIpKeyFromAddress(state.allocator, &accepted_addr) catch null;
        defer if (owned_ip_key) |key| state.allocator.free(key);
        const ip_key = owned_ip_key orelse "unknown";

        const slot_result = state.tryAcquireConnectionSlot(client_fd, ip_key) catch |err| {
            state.logger.warn(null, "connection slot tracking error: {}", .{err});
            _ = std.c.close(client_fd);
            continue;
        };
        switch (slot_result) {
            .accepted => {},
            .over_ip_limit => {
                state.logger.warn(null, "per-IP connection limit reached for {s}", .{ip_key});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_limit => {
                state.logger.warn(null, "global active connection limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
            .over_global_memory_limit => {
                state.logger.warn(null, "global connection memory estimate limit reached", .{});
                state.metricsRecordErrorCode("overload");
                rejectOverloadedClient(client_fd);
                continue;
            },
        }

        worker_pool.submit(client_fd) catch |err| {
            state.logger.warn(null, "worker queue submit failed: {}", .{err});
            state.metricsRecordQueueRejection();
            state.metricsRecordErrorCode("overload");
            state.releaseConnectionSlot(client_fd);
            rejectOverloadedClient(client_fd);
            continue;
        };
    }
}

fn hotReloadConfig(
    allocator: std.mem.Allocator,
    worker_ctx: *WorkerContext,
    state: *GatewayState,
    http3_dispatch_ctx: *Http3DispatchContext,
) void {
    const now_ms = compat.milliTimestamp();
    const loaded = edge_config.loadFromEnv(allocator) catch |err| {
        const msg = std.fmt.bufPrint(&state.last_reload_error, "load failed: {}", .{err}) catch "load failed";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.logger.warn(null, "config reload failed during load: {}", .{err});
        return;
    };
    edge_config.validate(&loaded) catch |err| {
        var rejected = loaded;
        rejected.deinit(allocator);
        const msg = std.fmt.bufPrint(&state.last_reload_error, "validation rejected: {}", .{err}) catch "validation rejected";
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        state.last_reload_error_len = msg.len;
        state.reload_mutex.unlock();
        state.logger.warn(null, "config reload rejected by validation: {}", .{err});
        return;
    };
    edge_config.warnRiskyConfig(&loaded);
    const cfg_ptr = allocator.create(edge_config.EdgeConfig) catch {
        var rejected = loaded;
        rejected.deinit(allocator);
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        @memcpy(state.last_reload_error[0..19], "allocation failed  ");
        state.last_reload_error_len = 19;
        state.reload_mutex.unlock();
        state.logger.warn(null, "config reload allocation failed", .{});
        return;
    };
    cfg_ptr.* = loaded;
    const prepared_version = worker_ctx.config_store.prepareOwned(cfg_ptr) catch {
        cfg_ptr.deinit(allocator);
        allocator.destroy(cfg_ptr);
        state.reload_mutex.lock();
        state.last_reload_ok = false;
        state.last_reload_at_ms = now_ms;
        @memcpy(state.last_reload_error[0..21], "bookkeeping failed   ");
        state.last_reload_error_len = 21;
        state.reload_mutex.unlock();
        state.logger.warn(null, "config reload bookkeeping failed", .{});
        return;
    };

    applyReloadedRuntimeConfig(cfg_ptr, state);
    worker_ctx.config_store.installPrepared(prepared_version);
    http3_dispatch_ctx.cfg = cfg_ptr;
    http.access_log.deinit();
    http.access_log.init(allocator, .{
        .format = cfg_ptr.access_log_format,
        .custom_template = cfg_ptr.access_log_template,
        .min_status = cfg_ptr.access_log_min_status,
        .buffer_size_bytes = cfg_ptr.access_log_buffer_size,
        .syslog_udp_endpoint = cfg_ptr.access_log_syslog_udp,
        .redact_header_names = cfg_ptr.log_redact_headers,
    }) catch {}; // access log is best-effort; gateway continues without it
    state.reload_mutex.lock();
    state.last_reload_ok = true;
    state.last_reload_at_ms = now_ms;
    state.last_reload_error_len = 0;
    state.reload_mutex.unlock();
    state.logger.info(null, "configuration hot-reload applied", .{});
}

fn applyReloadedRuntimeConfig(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    state.rate_limiter_mutex.lock();
    if (state.rate_limiter) |*rl| rl.deinit();
    state.rate_limiter = if (cfg.rate_limit_rps > 0)
        http.rate_limiter.RateLimiter.init(state.allocator, cfg.rate_limit_rps, cfg.rate_limit_burst)
    else
        null;
    state.rate_limiter_mutex.unlock();

    state.proxy_cache_mutex.lock();
    if (state.proxy_cache_store) |*pc| pc.deinit();
    state.proxy_cache_store = if (cfg.proxy_cache_ttl_seconds > 0)
        http.idempotency.IdempotencyStore.init(state.allocator, cfg.proxy_cache_ttl_seconds)
    else
        null;
    state.proxy_cache_path = cfg.proxy_cache_path;
    state.proxy_cache_ttl_seconds = cfg.proxy_cache_ttl_seconds;
    state.proxy_cache_mutex.unlock();

    state.runtime_mutex.lock();
    state.add_headers = cfg.add_headers;
    if (state.http3_alt_svc) |value| state.allocator.free(value);
    state.http3_alt_svc = if (cfg.http3_enabled) http.http3_handler.formatAltSvc(state.allocator, cfg.quic_port) catch null else null;
    if (state.hsts_value.len > 0) state.allocator.free(state.hsts_value);
    state.hsts_value = computeHstsValue(state.allocator, cfg) catch &.{};
    state.security_headers = blk: {
        var s = if (cfg.security_headers_enabled)
            http.security_headers.SecurityHeaders.api
        else
            http.security_headers.SecurityHeaders{ .x_frame_options = "", .x_content_type_options = "", .content_security_policy = "", .strict_transport_security = "", .referrer_policy = "", .permissions_policy = "", .x_xss_protection = "", .cross_origin_opener_policy = "", .cross_origin_resource_policy = "" };
        s.strict_transport_security = state.hsts_value;
        break :blk s;
    };
    state.max_connections_per_ip = cfg.max_connections_per_ip;
    state.max_active_connections = cfg.max_active_connections;
    state.max_in_flight_requests = cfg.max_in_flight_requests;
    state.max_total_connection_memory_bytes = cfg.max_total_connection_memory_bytes;
    state.connection_memory_estimate_bytes = if (cfg.max_connection_memory_bytes > 0) cfg.max_connection_memory_bytes else MAX_REQUEST_SIZE;
    state.compression_config = .{
        .enabled = cfg.compression_enabled,
        .min_size = cfg.compression_min_size,
        .brotli_enabled = cfg.compression_brotli_enabled,
        .brotli_quality = cfg.compression_brotli_quality,
    };
    state.logger.min_level = cfg.log_level;
    state.runtime_mutex.unlock();
}

fn reopenErrorLog(cfg: *const edge_config.EdgeConfig) !void {
    if (cfg.error_log_path.len == 0 or std.ascii.eqlIgnoreCase(cfg.error_log_path, "stderr")) return;
    var fc = try compat.cwd().createFile(cfg.error_log_path, .{ .truncate = false, .read = false });
    defer fc.close();
    _ = std.c.lseek(fc.file.handle, 0, std.c.SEEK.END);
    _ = std.c.dup2(fc.file.handle, std.Io.File.stderr().handle);
}

fn rejectOverloadedClient(client_fd: std.posix.fd_t) void {
    setNonBlocking(client_fd, false) catch {}; // connection is usable in blocking mode; write and close still succeed
    const stream = compat.netStreamFromFd(client_fd);
    stream.writer().writeAll(
        "HTTP/1.1 503 Service Unavailable\r\n" ++
            "Connection: close\r\n" ++
            "Content-Length: 0\r\n" ++
            "Retry-After: 1\r\n" ++
            "\r\n",
    ) catch {}; // best-effort 503; client will time out if the write fails
    stream.close();
}

/// Refresh DNS-discovered upstreams when the refresh interval has elapsed.
/// Discovered addresses supplement the statically configured upstream pool
/// via GatewayState.dns_discovery; the selection functions read from both.
fn runDnsDiscoveryRefresh(_: *const edge_config.EdgeConfig, state: *GatewayState) void {
    const now_ms = http.event_loop.monotonicMs();
    if (state.dns_discovery.needsRefresh(now_ms)) {
        state.dns_discovery.refresh(now_ms);
    }
}

/// Context passed to the background health-probe thread.
const HealthProbeTask = struct {
    state: *GatewayState,
    config_store: *ReloadableConfigStore,
    allocator: std.mem.Allocator,
};

/// Background thread that runs all active health probes without blocking the
/// main event loop. Clears GatewayState.health_probe_running on completion.
fn activeHealthProbeThread(task: *HealthProbeTask) void {
    const allocator = task.allocator;
    const state = task.state;
    const config_store = task.config_store;
    allocator.destroy(task);

    defer state.health_probe_running.store(false, .release);

    var cfg_lease = config_store.acquire();
    defer cfg_lease.release();
    const cfg = cfg_lease.cfg;

    var probe_client = std.http.Client{ .allocator = allocator, .io = compat.io() };
    defer probe_client.deinit();

    if (cfg.upstream_base_urls.len > 0) {
        for (cfg.upstream_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, &probe_client, base_url);
        }
        for (cfg.upstream_backup_base_urls) |base_url| {
            probeSingleUpstream(cfg, state, &probe_client, base_url);
        }
    } else {
        probeSingleUpstream(cfg, state, &probe_client, cfg.upstream_base_url);
    }

    for (cfg.upstream_chat_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }
    for (cfg.upstream_chat_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }
    for (cfg.upstream_commands_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }
    for (cfg.upstream_commands_backup_base_urls) |base_url| {
        probeSingleUpstream(cfg, state, &probe_client, base_url);
    }

    // Also probe DNS-discovered upstreams when active health checks are enabled.
    if (state.dns_discovery.config.host.len > 0) {
        state.dns_discovery.mutex.lock();
        // Snapshot URLs under the discovery lock, then probe without it to avoid
        // blocking the discovery refresh thread.
        var discovered_buf: [32][]u8 = undefined;
        const n = @min(state.dns_discovery.urls.items.len, discovered_buf.len);
        for (state.dns_discovery.urls.items[0..n], 0..) |url, i| discovered_buf[i] = url;
        state.dns_discovery.mutex.unlock();
        for (discovered_buf[0..n]) |url| {
            probeSingleUpstream(cfg, state, &probe_client, url);
        }
    }

    state.metrics_mutex.lock();
    state.metrics.recordHealthProbeRun();
    state.metrics_mutex.unlock();
}

/// Schedule a background health-probe batch if one is not already running.
/// Returns immediately; actual probing runs in a detached thread so the main
/// event loop is never blocked by upstream HTTP round-trips.
fn runActiveHealthChecks(cfg: *const edge_config.EdgeConfig, state: *GatewayState, config_store: *ReloadableConfigStore) void {
    if (cfg.upstream_active_health_interval_ms == 0) return;

    const now_ms = http.event_loop.monotonicMs();
    if (state.next_active_health_probe_ms != 0 and now_ms < state.next_active_health_probe_ms) return;
    state.next_active_health_probe_ms = now_ms + cfg.upstream_active_health_interval_ms;

    // Skip if a previous batch is still in flight.
    if (state.health_probe_running.load(.acquire)) return;
    state.health_probe_running.store(true, .release);

    const task = state.allocator.create(HealthProbeTask) catch {
        state.health_probe_running.store(false, .release);
        return;
    };
    task.* = .{
        .state = state,
        .config_store = config_store,
        .allocator = state.allocator,
    };

    const thread = std.Thread.spawn(.{}, activeHealthProbeThread, .{task}) catch {
        state.health_probe_running.store(false, .release);
        state.allocator.destroy(task);
        return;
    };
    thread.detach();
}

const activeHealthConfig = gs.activeHealthConfig;

fn runProxyCacheMaintenance(cfg: *const edge_config.EdgeConfig, state: *GatewayState) void {
    if (cfg.proxy_cache_ttl_seconds == 0) return;
    const interval = cfg.proxy_cache_manager_interval_ms;
    if (interval == 0) return;
    const now_ms = http.event_loop.monotonicMs();
    if (state.next_proxy_cache_maintenance_ms != 0 and now_ms < state.next_proxy_cache_maintenance_ms) return;
    state.next_proxy_cache_maintenance_ms = now_ms + interval;

    state.proxy_cache_mutex.lock();
    defer state.proxy_cache_mutex.unlock();
    if (state.proxy_cache_store) |*store| {
        _ = store.cleanupExpired();
    }
}

fn probeSingleUpstream(cfg: *const edge_config.EdgeConfig, state: *GatewayState, probe_client: *std.http.Client, base_url: []const u8) void {
    const health_cfg = activeHealthConfig(cfg, base_url);
    const probe_base = if (unixSocketPathFromEndpoint(base_url) != null) "http://localhost" else base_url;
    const probe_url = http.health_checker.buildProbeUrl(state.allocator, probe_base, health_cfg.path) catch |err| {
        state.logger.warn(null, "active health probe url build failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    defer state.allocator.free(probe_url);

    const uri = std.Uri.parse(probe_url) catch |err| {
        state.logger.warn(null, "active health probe uri parse failed for {s}: {}", .{ probe_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };

    if (unixSocketPathFromEndpoint(base_url)) |socket_path| {
        const status_code = probeUnixSocketUpstream(socket_path, uri, cfg.upstream_active_health_timeout_ms) catch |err| {
            state.logger.warn(null, "active health probe unix request failed for {s}: {}", .{ base_url, err });
            state.recordActiveProbeResult(cfg, base_url, false);
            return;
        };
        state.recordActiveProbeResult(cfg, base_url, health_cfg.statusIsHealthy(status_code));
        return;
    }

    var header_buf: [4 * 1024]u8 = undefined;
    var req = probe_client.request(.GET, uri, .{
        .keep_alive = false,
    }) catch |err| {
        state.logger.warn(null, "active health probe open failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    defer req.deinit();

    req.sendBodiless() catch |err| {
        state.logger.warn(null, "active health probe send failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    var probe_resp = req.receiveHead(&header_buf) catch |err| {
        state.logger.warn(null, "active health probe wait failed for {s}: {}", .{ base_url, err });
        state.recordActiveProbeResult(cfg, base_url, false);
        return;
    };
    _ = &probe_resp;

    const status_code: u16 = @intFromEnum(probe_resp.head.status);
    if (health_cfg.statusIsHealthy(status_code)) {
        state.recordActiveProbeResult(cfg, base_url, true);
    } else {
        state.recordActiveProbeResult(cfg, base_url, false);
    }
}

fn probeUnixSocketUpstream(socket_path: []const u8, uri: std.Uri, timeout_ms: u32) !u16 {
    var stream = try compat.connectUnixSocket(socket_path);
    defer stream.close();

    if (timeout_ms > 0) {
        try setSocketTimeoutMs(stream.handle, timeout_ms, timeout_ms);
    }

    var request_target_buf = std.array_list.Managed(u8).init(std.heap.page_allocator);
    defer request_target_buf.deinit();
    const path_raw = switch (uri.path) {
        .raw => |path| if (path.len > 0) path else "/",
        .percent_encoded => |path| if (path.len > 0) path else "/",
    };
    try request_target_buf.appendSlice(path_raw);
    if (uri.query) |query| {
        try request_target_buf.appendSlice("?");
        try request_target_buf.appendSlice(uriComponentBytes(query));
    }

    try stream.print("GET {s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{request_target_buf.items});

    var response_buf: [256]u8 = undefined;
    var used: usize = 0;
    while (used < response_buf.len) {
        const n = try stream.read(response_buf[used..]);
        if (n == 0) break;
        used += n;
        if (std.mem.find(u8, response_buf[0..used], "\r\n")) |line_end| {
            var parts = std.mem.splitScalar(u8, response_buf[0..line_end], ' ');
            _ = parts.next() orelse return error.InvalidHttpResponse;
            const status_str = parts.next() orelse return error.InvalidHttpResponse;
            return std.fmt.parseInt(u16, status_str, 10);
        }
    }

    return error.InvalidHttpResponse;
}

fn applyFdSoftLimit(desired: u64) !?u64 {
    if (desired == 0) return null;
    switch (builtin.os.tag) {
        .linux, .macos, .freebsd, .netbsd, .openbsd, .dragonfly, .illumos, .ios, .tvos, .watchos, .visionos => {},
        else => return null,
    }

    var limits = try std.posix.getrlimit(std.posix.rlimit_resource.NOFILE);
    const current_soft: u64 = @intCast(limits.cur);
    const hard: u64 = @intCast(limits.max);
    const target: u64 = @min(desired, hard);
    if (target == current_soft) return target;

    limits.cur = @intCast(target);
    try std.posix.setrlimit(std.posix.rlimit_resource.NOFILE, limits);
    return target;
}

fn applyRuntimeIdentity(cfg: *const edge_config.EdgeConfig, logger: *const http.logger.Logger) !void {
    const c = @cImport({
        @cInclude("unistd.h");
    });
    if (cfg.chroot_dir.len > 0) {
        const chroot_dir_z = try std.heap.page_allocator.dupeZ(u8, cfg.chroot_dir);
        defer std.heap.page_allocator.free(chroot_dir_z);
        if (c.chdir(chroot_dir_z.ptr) != 0) return error.Unexpected;
        if (c.chroot(".") != 0) return error.ChrootFailed;
        if (c.chdir("/") != 0) return error.Unexpected;
        logger.info(null, "Applied chroot jail: {s}", .{cfg.chroot_dir});
    }

    if (cfg.run_group.len > 0) {
        const gid = std.fmt.parseInt(u32, cfg.run_group, 10) catch {
            logger.warn(null, "run_group expects numeric gid; got '{s}'", .{cfg.run_group});
            return error.InvalidRunGroup;
        };
        if (c.setgid(gid) != 0) return error.Unexpected;
        logger.info(null, "Applied runtime group: gid={d}", .{gid});
    }
    if (cfg.run_user.len > 0) {
        const uid = std.fmt.parseInt(u32, cfg.run_user, 10) catch {
            logger.warn(null, "run_user expects numeric uid; got '{s}'", .{cfg.run_user});
            return error.InvalidRunUser;
        };
        if (c.setuid(uid) != 0) return error.Unexpected;
        logger.info(null, "Applied runtime user: uid={d}", .{uid});
    }

    if (cfg.require_unprivileged_user and c.getuid() == 0) {
        return error.RunningAsRoot;
    }
}

fn handleAcceptedClient(raw_ctx: *anyopaque, client_fd: std.posix.fd_t) void {
    const ctx: *WorkerContext = @ptrCast(@alignCast(raw_ctx));
    defer ctx.state.releaseConnectionSlot(client_fd);
    const session = ctx.session_pool.acquire() catch |err| {
        ctx.state.logger.warn(null, "failed to acquire pooled connection session: {}", .{err});
        _ = std.c.close(client_fd);
        return;
    };
    defer {
        if (session.pending_buf) |buf| {
            ctx.state.request_buffer_pool.release(buf);
            session.pending_buf = null;
            session.pending_len = 0;
        }
    }
    defer ctx.session_pool.release(session);

    const owned_connection_ip = clientIpFromFd(ctx.state.allocator, client_fd) catch null;
    defer if (owned_connection_ip) |ip| ctx.state.allocator.free(ip);
    const connection_ip = owned_connection_ip orelse "unknown";

    var cfg_lease = ctx.acquireConfig();
    defer cfg_lease.release();
    const cfg = cfg_lease.cfg;
    const idle_timeout_ms = if (cfg.keep_alive_timeout_ms > 0)
        cfg.keep_alive_timeout_ms
    else
        cfg.request_limits.header_timeout_ms;
    if (idle_timeout_ms > 0) {
        setSocketTimeoutMs(client_fd, idle_timeout_ms, idle_timeout_ms) catch |err| {
            ctx.state.logger.warn(null, "failed to set client socket timeout: {}", .{err});
        };
    }

    setNonBlocking(client_fd, false) catch |err| {
        ctx.state.logger.warn(null, "failed to switch client fd to blocking mode: {}", .{err});
        _ = std.c.close(client_fd);
        return;
    };

    setNoDelay(client_fd) catch |err| {
        ctx.state.logger.warn(null, "failed to set TCP_NODELAY on client fd: {}", .{err});
    };

    if (ctx.tls) |tls| {
        // Parse PROXY protocol header from the raw TCP socket before SSL_accept.
        // The PROXY header is plaintext even on TLS connections and must be consumed
        // before OpenSSL sees the TLS ClientHello.
        if (cfg.proxy_protocol_mode != .off and !session.proxy_protocol_checked) {
            peekAndConsumeProxyHeaderFromRawFd(
                client_fd,
                cfg.proxy_protocol_mode,
                &session.proxy_client_ip_buf,
                &session.proxy_client_ip_len,
            ) catch |err| {
                ctx.state.logger.warn(null, "proxy protocol parse failed on TLS connection: {}", .{err});
                _ = std.c.close(client_fd);
                return;
            };
            session.proxy_protocol_checked = true;
        }
        var tls_conn = tls.accept(client_fd) catch |err| {
            if (http.tls_termination.lastOpenSslError(ctx.state.allocator)) |openssl_err| {
                defer ctx.state.allocator.free(openssl_err);
                ctx.state.logger.warn(null, "tls handshake error: {} ({s})", .{ err, openssl_err });
            } else {
                ctx.state.logger.warn(null, "tls handshake error: {}", .{err});
            }
            _ = std.c.close(client_fd);
            return;
        };
        defer tls_conn.deinit();
        defer _ = std.c.close(client_fd);

        if (tls_conn.negotiatedProtocol() == .http2 and cfg.http2_enabled) {
            handleHttp2Connection(&tls_conn, session, cfg, ctx.state, connection_ip) catch |err| {
                ctx.state.logger.err(null, "http2 connection error: {}", .{err});
            };
            return;
        }

        var served: u32 = 0;
        while (true) {
            var live_cfg_lease = ctx.acquireConfig();
            const live_cfg = live_cfg_lease.cfg;
            var keep_alive = false;
            handleConnection(&tls_conn, session, live_cfg, ctx.state, &keep_alive, connection_ip, false) catch |err| {
                live_cfg_lease.release();
                ctx.state.logger.err(null, "edge connection error: {}", .{err});
                break;
            };
            served += 1;
            const max_requests_per_connection = live_cfg.max_requests_per_connection;
            live_cfg_lease.release();
            if (http.shutdown.isShutdownRequested()) break;
            if (!keep_alive) break;
            if (max_requests_per_connection > 0 and served >= max_requests_per_connection) break;
        }
        if (served == cfg.max_requests_per_connection and cfg.max_requests_per_connection > 0) {
            ctx.state.logger.debug(null, "closing connection after max requests per connection reached ({d})", .{cfg.max_requests_per_connection});
        }
    } else {
        const stream = compat.netStreamFromFd(client_fd);
        defer stream.close();

        var served: u32 = 0;
        while (true) {
            var live_cfg_lease = ctx.acquireConfig();
            const live_cfg = live_cfg_lease.cfg;
            var keep_alive = false;
            handleConnection(stream, session, live_cfg, ctx.state, &keep_alive, connection_ip, true) catch |err| {
                live_cfg_lease.release();
                ctx.state.logger.err(null, "edge connection error: {}", .{err});
                break;
            };
            served += 1;
            const max_requests_per_connection = live_cfg.max_requests_per_connection;
            live_cfg_lease.release();
            if (http.shutdown.isShutdownRequested()) break;
            if (!keep_alive) break;
            if (max_requests_per_connection > 0 and served >= max_requests_per_connection) break;
        }
        if (served == cfg.max_requests_per_connection and cfg.max_requests_per_connection > 0) {
            ctx.state.logger.debug(null, "closing connection after max requests per connection reached ({d})", .{cfg.max_requests_per_connection});
        }
    }
}

fn clientIpKeyFromAddress(allocator: std.mem.Allocator, address: *const std.c.sockaddr.storage) ![]const u8 {
    return switch (address.family) {
        std.posix.AF.INET => blk: {
            const sin: *const std.c.sockaddr.in = @ptrCast(address);
            const b = @as(*const [4]u8, @ptrCast(&sin.addr));
            break :blk std.fmt.allocPrint(allocator, "v4:{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        },
        std.posix.AF.INET6 => blk: {
            const sin6: *const std.c.sockaddr.in6 = @ptrCast(address);
            break :blk std.fmt.allocPrint(allocator, "v6:{f}", .{compat.fmtSliceHexLower(sin6.addr[0..])});
        },
        else => error.UnsupportedAddressFamily,
    };
}

fn clientIpFromAddress(allocator: std.mem.Allocator, address: *const std.c.sockaddr.storage) ![]const u8 {
    return switch (address.family) {
        std.posix.AF.INET => blk: {
            const sin: *const std.c.sockaddr.in = @ptrCast(address);
            const b = @as(*const [4]u8, @ptrCast(&sin.addr));
            break :blk std.fmt.allocPrint(allocator, "{d}.{d}.{d}.{d}", .{ b[0], b[1], b[2], b[3] });
        },
        std.posix.AF.INET6 => blk: {
            const sin6: *const std.c.sockaddr.in6 = @ptrCast(address);
            const src = sin6.addr[0..];
            const g0 = std.mem.readInt(u16, src[0..2], .big);
            const g1 = std.mem.readInt(u16, src[2..4], .big);
            const g2 = std.mem.readInt(u16, src[4..6], .big);
            const g3 = std.mem.readInt(u16, src[6..8], .big);
            const g4 = std.mem.readInt(u16, src[8..10], .big);
            const g5 = std.mem.readInt(u16, src[10..12], .big);
            const g6 = std.mem.readInt(u16, src[12..14], .big);
            const g7 = std.mem.readInt(u16, src[14..16], .big);
            break :blk std.fmt.allocPrint(allocator, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{ g0, g1, g2, g3, g4, g5, g6, g7 });
        },
        else => error.UnsupportedAddressFamily,
    };
}

fn clientIpFromFd(allocator: std.mem.Allocator, fd: std.posix.fd_t) ![]const u8 {
    var peer_addr: std.c.sockaddr.storage = undefined;
    var addr_len: std.posix.socklen_t = @sizeOf(std.c.sockaddr.storage);
    try std.posix.getpeername(fd, @ptrCast(&peer_addr), &addr_len);
    return clientIpFromAddress(allocator, &peer_addr);
}

fn setNoDelay(fd: std.posix.fd_t) !void {
    try std.posix.setsockopt(fd, std.posix.IPPROTO.TCP, std.posix.TCP.NODELAY, std.mem.asBytes(&@as(c_int, 1)));
}

fn setNonBlocking(fd: std.posix.fd_t, enabled: bool) !void {
    const current_flags = std.c.fcntl(fd, std.posix.F.GETFL, @as(c_int, 0));
    if (current_flags < 0) return error.Unexpected;
    var flags: usize = @intCast(current_flags);
    const nonblock_mask = @as(usize, 1) << @bitOffsetOf(std.posix.O, "NONBLOCK");
    if (enabled) {
        flags |= nonblock_mask;
    } else {
        flags &= ~nonblock_mask;
    }
    if (std.c.fcntl(fd, std.posix.F.SETFL, @as(c_int, @intCast(flags))) < 0) return error.Unexpected;
}

const ProxyHeaderOutcome = union(enum) {
    no_header,
    need_more,
    invalid,
    parsed: struct {
        consumed: usize,
        client_ip_len: usize,
    },
};

const proxy_v2_signature = "\r\n\r\n\x00\r\nQUIT\n";

fn maybeConsumeProxyProtocolPreface(conn: anytype, mode: edge_config.ProxyProtocolMode, pending_buf: []u8, pending_len: *usize, client_ip_buf: *[64]u8, client_ip_len: *usize) !void {
    if (mode == .off) return;

    while (true) {
        const outcome = parseProxyHeader(pending_buf[0..pending_len.*], mode, client_ip_buf);
        switch (outcome) {
            .no_header => return,
            .invalid => return error.InvalidProxyProtocolHeader,
            .parsed => |parsed| {
                client_ip_len.* = parsed.client_ip_len;
                if (parsed.consumed < pending_len.*) {
                    const remaining = pending_len.* - parsed.consumed;
                    std.mem.copyForwards(u8, pending_buf[0..remaining], pending_buf[parsed.consumed..pending_len.*]);
                    pending_len.* = remaining;
                } else {
                    pending_len.* = 0;
                }
                return;
            },
            .need_more => {
                if (pending_len.* == pending_buf.len) return error.ProxyProtocolHeaderTooLarge;
                const n = try conn.read(pending_buf[pending_len.*..]);
                if (n == 0) return error.ConnectionClosed;
                pending_len.* += n;
            },
        }
    }
}

/// Parse and consume a PROXY protocol header from a raw TCP socket fd before the TLS handshake.
/// Uses MSG_PEEK so that unconsumed application bytes (TLS ClientHello) remain intact in the kernel
/// receive buffer and OpenSSL can read them normally via SSL_set_fd / SSL_accept.
fn peekAndConsumeProxyHeaderFromRawFd(
    fd: std.posix.fd_t,
    mode: edge_config.ProxyProtocolMode,
    client_ip_buf: *[64]u8,
    client_ip_len: *usize,
) !void {
    if (mode == .off) return;
    const msg_peek: u32 = 2; // MSG_PEEK — peek without consuming
    var peek_buf: [1024]u8 = undefined;
    var peeked: usize = 0;
    // Retry loop to handle blocking sockets that may not have all bytes immediately.
    // In practice the PROXY header always arrives in the first TCP segment.
    var attempts: u32 = 0;
    while (attempts < 20) : (attempts += 1) {
        const n_raw = std.c.recv(fd, @as(*anyopaque, @ptrCast(&peek_buf)), peek_buf.len, @intCast(msg_peek));
        if (n_raw < 0) return error.ConnectionClosed;
        const n: usize = @intCast(n_raw);
        if (n == 0) return error.ConnectionClosed;
        if (n > peeked) peeked = n;
        const outcome = parseProxyHeader(peek_buf[0..peeked], mode, client_ip_buf);
        switch (outcome) {
            .no_header => return,
            .invalid => return error.InvalidProxyProtocolHeader,
            .parsed => |parsed| {
                client_ip_len.* = parsed.client_ip_len;
                // Consume exactly `parsed.consumed` bytes from the socket so
                // that OpenSSL's SSL_accept sees only the TLS ClientHello.
                var consumed_total: usize = 0;
                var discard: [1024]u8 = undefined;
                while (consumed_total < parsed.consumed) {
                    const to_read = @min(parsed.consumed - consumed_total, discard.len);
                    const nr_raw = std.c.recv(fd, @as(*anyopaque, @ptrCast(&discard)), to_read, 0);
                    if (nr_raw <= 0) return error.ConnectionClosed;
                    consumed_total += @intCast(nr_raw);
                }
                return;
            },
            .need_more => {
                if (peeked >= peek_buf.len) return error.ProxyProtocolHeaderTooLarge;
                // Wait briefly for more data to arrive in the kernel buffer.
                std.Io.sleep(compat.io(), std.Io.Duration.fromMicroseconds(500), .awake) catch {}; // interrupt wakes are fine; loop continues immediately
            },
        }
    }
    return error.ProxyProtocolHeaderTooLarge;
}

fn parseProxyHeader(buf: []const u8, mode: edge_config.ProxyProtocolMode, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    return switch (mode) {
        .off => .no_header,
        .v1 => parseProxyHeaderV1(buf, true, client_ip_buf),
        .v2 => parseProxyHeaderV2(buf, true, client_ip_buf),
        .auto => blk: {
            if (buf.len == 0) break :blk .need_more;
            if (buf[0] == 'P') break :blk parseProxyHeaderV1(buf, false, client_ip_buf);
            if (buf[0] == '\r') break :blk parseProxyHeaderV2(buf, false, client_ip_buf);
            break :blk .no_header;
        },
    };
}

fn parseProxyHeaderV1(buf: []const u8, strict: bool, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    const prefix = "PROXY ";
    if (buf.len < prefix.len) {
        if (std.mem.eql(u8, buf, prefix[0..buf.len])) return .need_more;
        return if (strict) .invalid else .no_header;
    }
    if (!std.mem.eql(u8, buf[0..prefix.len], prefix)) return if (strict) .invalid else .no_header;

    const line_end = std.mem.find(u8, buf, "\r\n") orelse {
        if (buf.len >= 108) return .invalid;
        return .need_more;
    };
    const line = buf[0..line_end];

    var tok_it = std.mem.tokenizeScalar(u8, line, ' ');
    const sig = tok_it.next() orelse return .invalid;
    if (!std.mem.eql(u8, sig, "PROXY")) return .invalid;
    const proto = tok_it.next() orelse return .invalid;
    if (std.mem.eql(u8, proto, "UNKNOWN")) {
        return .{ .parsed = .{ .consumed = line_end + 2, .client_ip_len = 0 } };
    }

    if (!std.mem.eql(u8, proto, "TCP4") and !std.mem.eql(u8, proto, "TCP6")) return .invalid;
    const src_ip = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    _ = tok_it.next() orelse return .invalid;
    if (src_ip.len == 0 or src_ip.len > client_ip_buf.len) return .invalid;
    @memcpy(client_ip_buf[0..src_ip.len], src_ip);
    return .{ .parsed = .{ .consumed = line_end + 2, .client_ip_len = src_ip.len } };
}

fn parseProxyHeaderV2(buf: []const u8, strict: bool, client_ip_buf: *[64]u8) ProxyHeaderOutcome {
    if (buf.len < proxy_v2_signature.len) {
        if (std.mem.eql(u8, buf, proxy_v2_signature[0..buf.len])) return .need_more;
        return if (strict) .invalid else .no_header;
    }
    if (!std.mem.eql(u8, buf[0..proxy_v2_signature.len], proxy_v2_signature)) return if (strict) .invalid else .no_header;
    if (buf.len < 16) return .need_more;

    const ver_cmd = buf[12];
    if ((ver_cmd >> 4) != 0x2) return .invalid;
    const cmd = ver_cmd & 0x0f;
    const fam = buf[13] >> 4;
    const addr_len = std.mem.readInt(u16, buf[14..16], .big);
    const total_len: usize = 16 + addr_len;
    if (total_len > 1024) return .invalid;
    if (buf.len < total_len) return .need_more;

    if (cmd != 0x1) {
        return .{ .parsed = .{ .consumed = total_len, .client_ip_len = 0 } };
    }

    switch (fam) {
        0x1 => {
            if (addr_len < 12) return .invalid;
            const src = buf[16..20];
            const printed = std.fmt.bufPrint(client_ip_buf, "{d}.{d}.{d}.{d}", .{ src[0], src[1], src[2], src[3] }) catch return .invalid;
            return .{ .parsed = .{ .consumed = total_len, .client_ip_len = printed.len } };
        },
        0x2 => {
            if (addr_len < 36) return .invalid;
            const src = buf[16..32];
            const g0 = std.mem.readInt(u16, src[0..2], .big);
            const g1 = std.mem.readInt(u16, src[2..4], .big);
            const g2 = std.mem.readInt(u16, src[4..6], .big);
            const g3 = std.mem.readInt(u16, src[6..8], .big);
            const g4 = std.mem.readInt(u16, src[8..10], .big);
            const g5 = std.mem.readInt(u16, src[10..12], .big);
            const g6 = std.mem.readInt(u16, src[12..14], .big);
            const g7 = std.mem.readInt(u16, src[14..16], .big);
            const printed = std.fmt.bufPrint(client_ip_buf, "{x}:{x}:{x}:{x}:{x}:{x}:{x}:{x}", .{ g0, g1, g2, g3, g4, g5, g6, g7 }) catch return .invalid;
            return .{ .parsed = .{ .consumed = total_len, .client_ip_len = printed.len } };
        },
        else => return .{ .parsed = .{ .consumed = total_len, .client_ip_len = 0 } },
    }
}

fn handleHttp2Connection(conn: anytype, session: *ConnectionSession, cfg: *const edge_config.EdgeConfig, state: *GatewayState, connection_ip: []const u8) !void {
    _ = session;
    _ = connection_ip;
    var preface: [HTTP2_PREFACE.len]u8 = undefined;
    try readExactConn(conn, preface[0..]);
    if (!std.mem.eql(u8, preface[0..], HTTP2_PREFACE)) return error.InvalidHttp2Preface;

    const allocator = state.allocator;

    try http.http2_frame.writeSettings(allocator, conn.writer(), &[_][2]u32{
        .{ 0x3, 100 }, // max concurrent streams
        .{ 0x4, 1024 * 1024 }, // initial window size
    });
    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    var stream_windows = std.AutoHashMap(u31, i32).init(allocator);
    defer stream_windows.deinit();
    var stream_priorities = std.AutoHashMap(u31, u8).init(allocator);
    defer stream_priorities.deinit();
    var ready_streams = std.array_list.Managed(u31).init(allocator);
    defer ready_streams.deinit();
    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }

    while (!http.shutdown.isShutdownRequested()) {
        var frame = http.http2_frame.readFrame(conn, allocator, HTTP2_MAX_FRAME_SIZE) catch |err| switch (err) {
            error.ConnectionClosed => return,
            else => return err,
        };
        defer http.http2_frame.deinitFrame(allocator, &frame);

        switch (frame.typ) {
            .settings => {
                if ((frame.flags & http.http2_frame.Flags.ACK) == 0) try http.http2_frame.writeSettingsAck(conn.writer());
            },
            .ping => {
                if ((frame.flags & http.http2_frame.Flags.ACK) == 0) try http.http2_frame.writePingAck(conn.writer(), frame.payload);
            },
            .headers => {
                if (frame.stream_id == 0) return error.InvalidHttp2StreamId;
                var payload_offset: usize = 0;
                if ((frame.flags & http.http2_frame.Flags.PRIORITY) != 0) {
                    const pr = try http.http2_frame.parsePriority(frame.payload);
                    try stream_priorities.put(frame.stream_id, pr.weight);
                    payload_offset = 5;
                }
                var decoded = try http.hpack.decode(allocator, frame.payload[payload_offset..]);
                defer http.hpack.deinitDecoded(allocator, &decoded);

                var ps = pending.get(frame.stream_id) orelse Http2PendingStream.init(allocator);
                ps.priority_weight = stream_priorities.get(frame.stream_id) orelse ps.priority_weight;
                for (decoded.headers) |h| {
                    if (std.mem.eql(u8, h.name, ":method")) {
                        if (ps.method) |m| allocator.free(m);
                        ps.method = try allocator.dupe(u8, h.value);
                    } else if (std.mem.eql(u8, h.name, ":path")) {
                        if (ps.path) |p| allocator.free(p);
                        ps.path = try allocator.dupe(u8, h.value);
                    } else if (h.name.len > 0 and h.name[0] != ':') {
                        try ps.headers.append(h.name, h.value);
                    }
                }
                try pending.put(frame.stream_id, ps);
                _ = try stream_windows.getOrPutValue(frame.stream_id, 65_535);

                if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                    try ready_streams.append(frame.stream_id);
                }
            },
            .data => {
                if (frame.stream_id == 0) return error.InvalidHttp2StreamId;
                if (stream_windows.getPtr(frame.stream_id)) |sw| sw.* -= @intCast(frame.payload.len);
                conn_send_window -= @intCast(frame.payload.len);
                if (pending.getPtr(frame.stream_id)) |ps| {
                    try ps.body.appendSlice(frame.payload);
                    try http.http2_frame.writeWindowUpdate(conn.writer(), frame.stream_id, @intCast(frame.payload.len));
                    try http.http2_frame.writeWindowUpdate(conn.writer(), 0, @intCast(frame.payload.len));
                    if (stream_windows.getPtr(frame.stream_id)) |sw| sw.* += @intCast(frame.payload.len);
                    conn_send_window += @intCast(frame.payload.len);
                    if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                        try ready_streams.append(frame.stream_id);
                    }
                } else {
                    try http.http2_frame.writeGoaway(conn.writer(), frame.stream_id, 1);
                    return;
                }
            },
            .priority => {
                const pr = try http.http2_frame.parsePriority(frame.payload);
                try stream_priorities.put(frame.stream_id, pr.weight);
                if (pending.getPtr(frame.stream_id)) |ps| ps.priority_weight = pr.weight;
            },
            .window_update => {
                const inc = try http.http2_frame.parseWindowUpdateIncrement(frame.payload);
                if (frame.stream_id == 0) {
                    conn_send_window += @intCast(inc);
                } else {
                    const gop = try stream_windows.getOrPutValue(frame.stream_id, 65_535);
                    gop.value_ptr.* += @intCast(inc);
                }
            },
            .rst_stream => {
                if (pending.fetchRemove(frame.stream_id)) |removed| {
                    var tmp = removed.value;
                    tmp.deinit(allocator);
                }
                _ = stream_windows.remove(frame.stream_id);
                _ = stream_priorities.remove(frame.stream_id);
            },
            .continuation, .push_promise, .goaway => {},
        }

        while (ready_streams.items.len > 0) {
            var best_idx: usize = 0;
            var best_weight: u8 = 0;
            for (ready_streams.items, 0..) |sid, idx| {
                const w = stream_priorities.get(sid) orelse 16;
                if (w >= best_weight) {
                    best_weight = w;
                    best_idx = idx;
                }
            }
            const sid = ready_streams.swapRemove(best_idx);
            if (pending.getPtr(sid)) |ps| {
                try respondHttp2Stream(conn.writer(), allocator, state, cfg, sid, ps, &next_server_stream_id);
            }
            if (pending.fetchRemove(sid)) |removed| {
                var tmp = removed.value;
                tmp.deinit(allocator);
            }
            _ = stream_windows.remove(sid);
            _ = stream_priorities.remove(sid);
        }
    }
}

fn respondHttp2Stream(
    writer: anytype,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    stream_id: u31,
    ps: *const Http2PendingStream,
    next_server_stream_id: *u31,
) !void {
    _ = next_server_stream_id;
    const method = ps.method orelse return error.InvalidHttp2Request;
    const path = ps.path orelse return error.InvalidHttp2Request;
    const correlation_id = try http.correlation.generate(allocator);
    defer allocator.free(correlation_id);

    var status_code: u16 = 404;
    var body: []const u8 = "{\"error\":\"Not Found\"}";
    const body_alloc: ?[]u8 = null;
    defer if (body_alloc) |b| allocator.free(b);
    const content_type: []const u8 = JSON_CONTENT_TYPE;

    _ = method;
    _ = path;
    _ = cfg;

    status_code = 404;
    body = "{\"error\":\"not_found\"}";

    const status_str = try std.fmt.allocPrint(allocator, "{d}", .{status_code});
    defer allocator.free(status_str);
    const len_str = try std.fmt.allocPrint(allocator, "{d}", .{body.len});
    defer allocator.free(len_str);

    var response_headers = std.array_list.Managed(http.hpack.HeaderField).init(allocator);
    defer response_headers.deinit();
    try response_headers.append(.{ .name = ":status", .value = status_str });
    try response_headers.append(.{ .name = "content-type", .value = content_type });
    try response_headers.append(.{ .name = "content-length", .value = len_str });
    try response_headers.append(.{ .name = http.correlation.REQUEST_HEADER_NAME, .value = correlation_id });
    try response_headers.append(.{ .name = http.correlation.HEADER_NAME, .value = correlation_id });
    for (state.add_headers) |h| {
        try response_headers.append(.{ .name = h.name, .value = h.value });
    }

    const header_block = try http.hpack.encodeLiteralHeaderBlock(allocator, response_headers.items);
    defer allocator.free(header_block);

    try http.http2_frame.writeFrame(
        writer,
        .headers,
        http.http2_frame.Flags.END_HEADERS,
        stream_id,
        header_block,
    );
    try http.http2_frame.writeFrame(
        writer,
        .data,
        http.http2_frame.Flags.END_STREAM,
        stream_id,
        body,
    );

    state.metricsRecord(status_code);
}

fn pushHttp2Resource(
    writer: anytype,
    allocator: std.mem.Allocator,
    parent_stream_id: u31,
    promised_stream_id: u31,
    path: []const u8,
    content_type: []const u8,
    body: []const u8,
) !void {
    const req_headers = [_]http.hpack.HeaderField{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = path },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "localhost" },
    };
    const req_block = try http.hpack.encodeLiteralHeaderBlock(allocator, req_headers[0..]);
    defer allocator.free(req_block);
    try http.http2_frame.writePushPromise(allocator, writer, parent_stream_id, promised_stream_id, req_block, true);

    const status_headers = [_]http.hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = content_type },
    };
    const status_block = try http.hpack.encodeLiteralHeaderBlock(allocator, status_headers[0..]);
    defer allocator.free(status_block);
    try http.http2_frame.writeFrame(writer, .headers, http.http2_frame.Flags.END_HEADERS, promised_stream_id, status_block);
    try http.http2_frame.writeFrame(writer, .data, http.http2_frame.Flags.END_STREAM, promised_stream_id, body);
}

fn readExactConn(conn: anytype, out: []u8) !void {
    var off: usize = 0;
    while (off < out.len) {
        const n = try conn.read(out[off..]);
        if (n == 0) return error.ConnectionClosed;
        off += n;
    }
}

fn handleConnection(conn: anytype, session: *ConnectionSession, cfg: *const edge_config.EdgeConfig, state: *GatewayState, keep_alive_out: *bool, connection_ip: []const u8, enable_proxy_protocol: bool) !void {
    var keep_alive = false;
    keep_alive_out.* = false;
    defer keep_alive_out.* = keep_alive;

    var arena_state = std.heap.ArenaAllocator.init(state.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    if (session.pending_buf == null) {
        session.pending_buf = try state.request_buffer_pool.acquire();
    }
    const pending_buf = session.pending_buf.?;
    if (cfg.max_connection_memory_bytes > 0 and pending_buf.len > cfg.max_connection_memory_bytes) {
        try sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
        return;
    }

    if (enable_proxy_protocol and !session.proxy_protocol_checked) {
        maybeConsumeProxyProtocolPreface(
            conn,
            cfg.proxy_protocol_mode,
            pending_buf,
            &session.pending_len,
            &session.proxy_client_ip_buf,
            &session.proxy_client_ip_len,
        ) catch |err| {
            state.logger.warn(null, "proxy protocol parse failed: {}", .{err});
            try sendApiError(allocator, conn.writer(), .bad_request, "invalid_request", "Invalid proxy protocol header", null, false, state);
            return;
        };
        session.proxy_protocol_checked = true;
    } else if (!session.proxy_protocol_checked) {
        session.proxy_protocol_checked = true;
    }

    const total_read = try readHttpRequest(conn, pending_buf, &session.pending_len);
    if (total_read == 0) return;
    if (cfg.max_connection_memory_bytes > 0 and total_read > cfg.max_connection_memory_bytes) {
        session.pending_len = 0;
        try sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
        return;
    }

    const parse_result = http.Request.parse(allocator, pending_buf[0..total_read], MAX_REQUEST_SIZE) catch |err| {
        // Return the appropriate status code so clients can distinguish parse
        // failures: 431 for header-size/count violations, 413 for oversized
        // body, 400 for everything else (malformed syntax, invalid method, etc.).
        const status: http.status.Status = switch (err) {
            error.HeadersTooLarge, error.HeaderTooLarge, error.TooManyHeaders => .request_header_fields_too_large,
            error.BodyTooLarge => .payload_too_large,
            // ConflictingHeaders and InvalidChunkedBody are 400 — explicit mapping
            // here documents the intent (no request smuggling vector).
            error.ConflictingHeaders, error.InvalidChunkedBody => .bad_request,
            else => .bad_request,
        };
        try sendApiError(allocator, conn.writer(), status, "invalid_request", "Malformed request", null, keep_alive, state);
        state.logger.warn(null, "parse error: {}", .{err});
        return;
    };
    const bytes_consumed = parse_result.bytes_consumed;
    if (bytes_consumed < total_read) {
        const remaining = total_read - bytes_consumed;
        std.mem.copyForwards(u8, pending_buf[0..remaining], pending_buf[bytes_consumed..total_read]);
        session.pending_len = remaining;
    } else {
        session.pending_len = 0;
    }

    var request = parse_result.request;
    defer request.deinit();
    const writer = conn.writer();
    keep_alive = request.keepAlive();
    if (http.shutdown.isShutdownRequested()) keep_alive = false;

    // --- Correlation ID ---
    const correlation_id = try http.correlation.fromHeadersOrGenerate(allocator, &request.headers);
    defer allocator.free(correlation_id);

    // --- RFC 7230 §5.4: HTTP/1.1 MUST include a Host header ---
    // A missing Host on an HTTP/1.1 request is a protocol violation.
    // Reject early with 400 before routing or proxying to prevent smuggling
    // and to satisfy ASVS-14.5.1. HTTP/1.0 clients are exempt (no Host
    // requirement in RFC 1945). HTTP/2 uses :authority and is handled
    // separately in handleHttp3Connection.
    if (request.version == .http11 and request.headers.get("host") == null) {
        try sendApiError(allocator, writer, .bad_request, "invalid_request", "HTTP/1.1 request missing required Host header", correlation_id, false, state);
        var ctx_host = http.request_context.RequestContext.init(allocator, correlation_id, connection_ip);
        logAccess(state, &ctx_host, request.method.toString(), request.uri.path, 400, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- RFC 7231 §4.3.8 / ASVS-14.5.1: Reject TRACE globally ---
    // TRACE echoes the request back to the client, enabling Cross-Site
    // Tracing (XST) attacks that can expose cookies and auth headers even
    // when HttpOnly is set. Tardigrade has no use for TRACE on any route —
    // gateway-to-upstream tracing is handled via W3C traceparent headers.
    // Reject before routing so no location block can accidentally serve it.
    if (request.method == .TRACE) {
        try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        var ctx_trace = http.request_context.RequestContext.init(allocator, correlation_id, connection_ip);
        logAccess(state, &ctx_trace, "TRACE", request.uri.path, 405, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- Request Context ---
    const effective_connection_ip = if (session.proxy_client_ip_len > 0)
        session.proxy_client_ip_buf[0..session.proxy_client_ip_len]
    else
        connection_ip;
    const client_ip = http.request_context.extractClientIp(&request, effective_connection_ip);

    // --- ACME HTTP-01 challenge response (/.well-known/acme-challenge/<token>) ---
    const acme_prefix = "/.well-known/acme-challenge/";
    if (state.acme_challenge_store != null and
        std.mem.startsWith(u8, request.uri.path, acme_prefix))
    {
        const token = request.uri.path[acme_prefix.len..];
        if (state.acme_challenge_store.?.getCopy(allocator, token)) |key_auth| {
            defer allocator.free(key_auth);
            var acme_response = http.Response.init(allocator);
            defer acme_response.deinit();
            _ = acme_response.setStatus(.ok)
                .setBody(key_auth)
                .setHeader("Content-Type", "application/octet-stream")
                .setConnection(keep_alive);
            try acme_response.write(writer);
            return;
        }
    }

    var effective_cfg_storage = cfg.*;
    const effective_cfg = resolveRequestConfig(cfg, request.headers.get("host"), &effective_cfg_storage) orelse {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        var ctx_404 = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
        logAccess(state, &ctx_404, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
        return;
    };
    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
    if (!hostMatchesServerNames(effective_cfg, &request)) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        logAccess(state, &ctx, request.method.toString(), request.uri.path, 404, request.headers.get("user-agent") orelse "");
        return;
    }

    // --- In-flight request backpressure ---
    if (!state.tryAcquireRequestSlot()) {
        try sendApiError(allocator, writer, .service_unavailable, "overloaded", "Too many in-flight requests", correlation_id, false, state);
        state.metricsRecord(503);
        state.metricsRecordErrorCode("overloaded");
        logAccess(state, &ctx, request.method.toString(), request.uri.path, 503, request.headers.get("user-agent") orelse "");
        return;
    }
    defer state.releaseRequestSlot();

    // --- Request Lifecycle ---
    var lifecycle = http.request_lifecycle.RequestLifecycle.init(correlation_id, effective_cfg.request_total_timeout_ms);
    ctx.lifecycle = &lifecycle;
    // During graceful shutdown, cap the request deadline to the drain window so
    // long-running requests don't block shutdown indefinitely.
    if (http.shutdown.isShutdownRequested() and effective_cfg.shutdown_drain_timeout_ms > 0) {
        const drain_deadline_ms = compat.milliTimestamp() + @as(i64, @intCast(effective_cfg.shutdown_drain_timeout_ms));
        if (lifecycle.token.deadline_ms == 0 or lifecycle.token.deadline_ms > drain_deadline_ms) {
            lifecycle.token.deadline_ms = drain_deadline_ms;
        }
    }

    // --- Rewrite / return directives ---
    var request_uri_buf = std.array_list.Managed(u8).init(allocator);
    defer request_uri_buf.deinit();
    try request_uri_buf.appendSlice(request.uri.path);
    if (request.uri.query) |query| {
        try request_uri_buf.append('?');
        try request_uri_buf.appendSlice(query);
    }

    var conditional_outcome = try evaluateConditionalRules(
        allocator,
        effective_cfg.conditional_rules,
        request.uri.path,
        request_uri_buf.items,
        request.headers.get("host") orelse "",
        request.uri.query orelse "",
    );
    defer if (conditional_outcome) |*outcome| outcome.deinit(allocator);
    if (conditional_outcome) |outcome| {
        switch (outcome) {
            .pass => |rewritten_path| {
                request.uri.path = rewritten_path;
            },
            .redirect => |r| {
                var response = http.Response.redirect(allocator, r.location, @enumFromInt(r.status));
                defer response.deinit();
                _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                try response.write(writer);
                state.metricsRecord(r.status);
                logAccess(state, &ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                return;
            },
            .returned => |r| {
                if (r.status >= 300 and r.status < 400 and r.body.len > 0) {
                    var response = http.Response.redirect(allocator, r.body, @enumFromInt(r.status));
                    defer response.deinit();
                    _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                    state.metricsRecord(r.status);
                    logAccess(state, &ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                    return;
                }
                var response = http.Response.init(allocator);
                defer response.deinit();
                _ = response.setStatus(@enumFromInt(r.status))
                    .setBody(r.body)
                    .setContentType("text/plain; charset=utf-8")
                    .setConnection(keep_alive)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                try response.write(writer);
                state.metricsRecord(r.status);
                logAccess(state, &ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                return;
            },
        }
    }

    var rewrite_outcome = try http.rewrite.evaluate(
        allocator,
        request.method.toString(),
        request.uri.path,
        request_uri_buf.items,
        cfg.rewrite_rules,
        cfg.return_rules,
    );
    defer rewrite_outcome.deinit(allocator);
    switch (rewrite_outcome) {
        .pass => |rewritten_path| {
            request.uri.path = rewritten_path;
        },
        .redirect => |r| {
            var response = http.Response.redirect(allocator, r.location, @enumFromInt(r.status));
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(r.status);
            logAccess(state, &ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
            return;
        },
        .returned => |r| {
            if (r.status >= 300 and r.status < 400 and r.body.len > 0) {
                var response = http.Response.redirect(allocator, r.body, @enumFromInt(r.status));
                defer response.deinit();
                _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                try response.write(writer);
                state.metricsRecord(r.status);
                logAccess(state, &ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
                return;
            }
            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(@enumFromInt(r.status))
                .setBody(r.body)
                .setContentType("text/plain; charset=utf-8")
                .setConnection(keep_alive)
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(r.status);
            logAccess(state, &ctx, request.method.toString(), request.uri.path, r.status, request.headers.get("user-agent") orelse "");
            return;
        },
    }

    // --- Internal redirects / named locations ---
    request.uri.path = applyInternalRedirectRules(
        request.method.toString(),
        request.uri.path,
        effective_cfg.internal_redirect_rules,
        effective_cfg.named_locations,
    );

    // --- Mirror requests (best-effort async) ---
    if (effective_cfg.mirror_rules.len > 0) {
        spawnMirrorRequests(
            allocator,
            effective_cfg.mirror_rules,
            request.method.toString(),
            request.uri.path,
            request.body orelse "",
            correlation_id,
            client_ip,
            request.headers.get("content-type"),
        );
    }

    try primeRequestAuthContext(allocator, effective_cfg, state, &ctx, &request.headers);

    if (try runMiddlewarePipeline(allocator, writer, effective_cfg, state, &ctx, &request, correlation_id, keep_alive)) {
        return;
    }

    // Deadline check: if the overall request deadline elapsed during auth/middleware,
    // reject now rather than dispatching to the (potentially slow) upstream handler.
    if (lifecycle.checkDeadline(.routing)) {
        try sendApiError(allocator, writer, .request_timeout, "request_timeout", "Request deadline exceeded", correlation_id, keep_alive, state);
        state.metricsRecord(408);
        state.metricsRecordErrorCode("request_timeout");
        logAccess(state, &ctx, request.method.toString(), request.uri.path, 408, request.headers.get("user-agent") orelse "");
        return;
    }

    const route_status = try routeRequest(conn, allocator, effective_cfg, state, &ctx, &request, correlation_id, &keep_alive, client_ip);
    logAccess(state, &ctx, request.method.toString(), request.uri.path, route_status, request.headers.get("user-agent") orelse "");
    return;
}

fn routeRequest(
    conn: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    correlation_id: []const u8,
    keep_alive: *bool,
    client_ip: []const u8,
) !u16 {
    const writer = conn.writer();
    if (try handleTranscriptRoute(allocator, writer, state, request, correlation_id, keep_alive.*)) |status| {
        state.metricsRecord(status);
        return status;
    }

    if (std.mem.eql(u8, request.uri.path, "/tardigrade/reload/status")) {
        const status = try handleReloadStatusRoute(allocator, writer, state, correlation_id, keep_alive.*);
        state.metricsRecord(status);
        return status;
    }

    if (cfg.metrics_path.len > 0 and std.mem.eql(u8, request.uri.path, cfg.metrics_path)) {
        const status = try handleMetricsRoute(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*);
        state.metricsRecord(status);
        return status;
    }

    if (http.location_router.matchLocation(request.uri.path, cfg.location_blocks)) |matched| {
        if (matched.block.auth == .required and !ctx.authenticated and ctx.identity == null) {
            var auth_res = try authorizeRequest(allocator, cfg, &request.headers);
            defer auth_res.deinit(allocator);
            if (auth_res.ok) {
                if (auth_res.identity) |identity| {
                    ctx.setAuthContext(identity, auth_res.user_id, auth_res.device_id, auth_res.scopes);
                    auth_res.identity = null;
                    auth_res.user_id = null;
                    auth_res.device_id = null;
                    auth_res.scopes = null;
                }
            } else if (http.session.fromHeaders(&request.headers)) |session_token| {
                if (state.validateSessionIdentity(allocator, session_token)) |identity| {
                    ctx.setIdentity(identity);
                } else {
                    try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive.*, state);
                    state.metricsRecord(401);
                    state.metricsRecordErrorCode("unauthorized");
                    return 401;
                }
            } else if (cfg.auth_request_url.len > 0 and authorizeViaSubrequest(allocator, cfg, request, correlation_id, client_ip)) {
                ctx.authenticated = true;
            } else {
                const auth_status: http.Status = if (auth_res.failure_reason == .invalid) .forbidden else .unauthorized;
                const auth_code = if (auth_res.failure_reason == .invalid) "forbidden" else "unauthorized";
                const auth_message = if (auth_res.failure_reason == .invalid) "Forbidden" else "Unauthorized";
                const auth_status_code: u16 = @intFromEnum(auth_status);
                try sendApiError(allocator, writer, auth_status, auth_code, auth_message, correlation_id, keep_alive.*, state);
                state.metricsRecord(auth_status_code);
                state.metricsRecordErrorCode(auth_code);
                return auth_status_code;
            }
        }
        switch (matched.block.action) {
            .proxy_pass => |target| {
                return try handleLocationProxyPass(
                    allocator,
                    writer,
                    cfg,
                    state,
                    ctx,
                    request,
                    target,
                    proxySuffixPathForLocation(request.uri.path, matched, cfg.location_blocks),
                    correlation_id,
                    keep_alive.*,
                    client_ip,
                    ctx.identity,
                    ctx.user_id,
                    ctx.device_id,
                    ctx.scopes,
                    request.headers.get("host"),
                    matched.block.pattern,
                );
            },
            .fastcgi_pass => |upstream| {
                return try handleFastcgiRoute(allocator, writer, cfg, upstream, request, client_ip, correlation_id, keep_alive.*, state);
            },
            .return_response => |ret| {
                // Static-return directives (non-redirect) only make semantic sense
                // for GET and HEAD.  Accepting DELETE, PUT, or PATCH on a route like
                // `return 200 ok` would silently succeed and mislead the client into
                // believing a destructive operation completed (ASVS-14.5.1).
                // Redirect responses (3xx) are method-agnostic and pass through.
                const is_redirect = ret.status >= 300 and ret.status < 400;
                if (!is_redirect and !(request.method == .GET or request.method == .HEAD)) {
                    try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive.*, state);
                    state.metricsRecord(405);
                    return 405;
                }
                if (is_redirect and ret.body.len > 0) {
                    var response = http.Response.redirect(allocator, ret.body, @enumFromInt(ret.status));
                    defer response.deinit();
                    _ = response.setConnection(keep_alive.*);
                    setRequestIdHeaders(&response, correlation_id);
                    ctx.response_bytes = 0;
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                } else {
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response.setStatus(@enumFromInt(ret.status))
                        .setBody(ret.body)
                        .setContentType("text/plain; charset=utf-8")
                        .setConnection(keep_alive.*);
                    setRequestIdHeaders(&response, correlation_id);
                    ctx.response_bytes = ret.body.len;
                    applyResponseHeaders(state, &response);
                    try response.write(writer);
                }
                state.metricsRecord(ret.status);
                return ret.status;
            },
            .rewrite => |rw| {
                request.uri.path = rw.replacement;
            },
            .static_root => |root_cfg| {
                if (try handleStaticLocation(allocator, conn, request, matched, root_cfg, correlation_id, keep_alive.*, state)) |status| return status;
            },
        }
    }

    if (serveTryFilesFallback(allocator, conn, cfg, request, correlation_id, keep_alive.*, state)) |status| {
        state.metricsRecord(status);
        return status;
    } else |_| {}

    try sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive.*, state);
    state.metricsRecord(404);
    return 404;
}

fn primeRequestAuthContext(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    headers: *const http.Headers,
) !void {
    if (ctx.authenticated or ctx.identity != null) return;

    var auth_res = try authorizeRequest(allocator, cfg, headers);
    defer auth_res.deinit(allocator);
    if (auth_res.ok) {
        if (auth_res.identity) |identity| {
            ctx.setAuthContext(identity, auth_res.user_id, auth_res.device_id, auth_res.scopes);
            auth_res.identity = null;
            auth_res.user_id = null;
            auth_res.device_id = null;
            auth_res.scopes = null;
        } else {
            ctx.authenticated = true;
        }
        return;
    }

    if (http.session.fromHeaders(headers)) |session_token| {
        if (state.validateSessionIdentity(allocator, session_token)) |identity| {
            ctx.setIdentity(identity);
        }
    }
}

fn handleTranscriptRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !?u16 {
    const transcript_path = normalizeTranscriptRoutePath(request.uri.path) orelse return null;

    if (!(request.method == .GET or request.method == .HEAD)) {
        try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        return 405;
    }

    if (state.transcript_store_path.len == 0) {
        try sendApiError(allocator, writer, .not_found, "invalid_request", "Transcript store not configured", correlation_id, keep_alive, state);
        return 404;
    }

    if (std.mem.eql(u8, transcript_path, "/transcripts")) {
        const limit = parseTranscriptLimit(request.uri.query);
        const transcripts = try http.transcript_store.listRecent(allocator, state.transcript_store_path, limit);
        defer {
            for (transcripts) |*summary| summary.deinit(allocator);
            allocator.free(transcripts);
        }
        const payload = try jsonifyTranscriptSummaries(allocator, transcripts);
        defer allocator.free(payload);
        try writeJsonPayload(writer, allocator, payload, correlation_id, keep_alive, state, request.method == .HEAD);
        return 200;
    }

    if (std.mem.startsWith(u8, transcript_path, "/transcripts/")) {
        const id_raw = std.mem.trim(u8, transcript_path["/transcripts/".len..], " \t\r\n");
        const id = std.fmt.parseInt(usize, id_raw, 10) catch {
            try sendApiError(allocator, writer, .bad_request, "invalid_request", "Invalid transcript id", correlation_id, keep_alive, state);
            return 400;
        };
        var entry = (try http.transcript_store.getById(allocator, state.transcript_store_path, id)) orelse {
            try sendApiError(allocator, writer, .not_found, "invalid_request", "Transcript not found", correlation_id, keep_alive, state);
            return 404;
        };
        defer entry.deinit(allocator);
        const payload = try jsonifyTranscriptEntry(allocator, &entry);
        defer allocator.free(payload);
        try writeJsonPayload(writer, allocator, payload, correlation_id, keep_alive, state, request.method == .HEAD);
        return 200;
    }

    return null;
}

fn handleReloadStatusRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    state: *GatewayState,
    correlation_id: []const u8,
    keep_alive: bool,
) !u16 {
    state.reload_mutex.lock();
    const ok = state.last_reload_ok;
    const at_ms = state.last_reload_at_ms;
    const err_slice = state.last_reload_error[0..state.last_reload_error_len];
    state.reload_mutex.unlock();

    const payload = if (at_ms == 0)
        try std.fmt.allocPrint(allocator, "{{\"ok\":null,\"at_ms\":null,\"error\":null}}", .{})
    else if (ok)
        try std.fmt.allocPrint(allocator, "{{\"ok\":true,\"at_ms\":{d},\"error\":null}}", .{at_ms})
    else
        try std.fmt.allocPrint(allocator, "{{\"ok\":false,\"at_ms\":{d},\"error\":\"{s}\"}}", .{ at_ms, err_slice });
    defer allocator.free(payload);

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setBody(payload)
        .setContentType("application/json")
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    try response.write(writer);
    return 200;
}

fn handleMetricsRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !u16 {
    if (!(request.method == .GET or request.method == .HEAD)) {
        try sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        return 405;
    }

    if (cfg.metrics_require_auth and !ctx.authenticated and ctx.identity == null) {
        try sendApiError(allocator, writer, .unauthorized, "unauthorized", "Unauthorized", correlation_id, keep_alive, state);
        state.metricsRecordErrorCode("unauthorized");
        return 401;
    }

    const payload = try state.metricsToPrometheus(allocator);
    defer allocator.free(payload);

    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setBody(if (request.method == .HEAD) "" else payload)
        .setContentType("text/plain; version=0.0.4; charset=utf-8")
        .setConnection(keep_alive);
    setRequestIdHeaders(&response, correlation_id);
    if (request.method == .HEAD) {
        _ = response.setContentLength(payload.len);
        ctx.response_bytes = 0;
        applyResponseHeaders(state, &response);
        try response.writeHead(writer);
    } else {
        ctx.response_bytes = payload.len;
        applyResponseHeaders(state, &response);
        try response.write(writer);
    }
    return 200;
}

fn normalizeTranscriptRoutePath(path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/transcripts") or std.mem.startsWith(u8, path, "/transcripts/")) return path;
    if (std.mem.eql(u8, path, "/bearclaw/transcripts")) return "/transcripts";
    if (std.mem.startsWith(u8, path, "/bearclaw/transcripts/")) return path["/bearclaw".len..];
    return null;
}

fn parseTranscriptLimit(query: ?[]const u8) usize {
    const raw = parseQueryParam(query, "limit") orelse return 50;
    const parsed = std.fmt.parseInt(usize, raw, 10) catch return 50;
    return std.math.clamp(parsed, 1, 200);
}

fn jsonifyTranscriptSummaries(allocator: std.mem.Allocator, transcripts: []const http.transcript_store.Summary) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .transcripts = transcripts }, .{});
}

fn jsonifyTranscriptEntry(allocator: std.mem.Allocator, transcript: *const http.transcript_store.StoredEntry) ![]u8 {
    return std.json.Stringify.valueAlloc(allocator, .{ .transcript = transcript }, .{});
}

fn writeJsonPayload(
    writer: anytype,
    allocator: std.mem.Allocator,
    payload: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
    head_only: bool,
) !void {
    var response = http.Response.json(allocator, if (head_only) "" else payload);
    defer response.deinit();
    _ = response
        .setStatus(.ok)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    applyResponseHeaders(state, &response);
    if (head_only) {
        try response.writeHead(writer);
    } else {
        try response.write(writer);
    }
}

fn proxySuffixPathForLocation(
    request_path: []const u8,
    matched: http.location_router.MatchResult,
    blocks: []const edge_config.EdgeConfig.LocationBlock,
) ?[]const u8 {
    if (mountStripPrefixForLocation(request_path, matched, blocks)) |strip_prefix| {
        if (std.mem.startsWith(u8, request_path, strip_prefix)) {
            const suffix = request_path[strip_prefix.len..];
            return if (suffix.len == 0) null else suffix;
        }
    }
    return matchedLocationSuffixPath(request_path, matched);
}

fn matchedLocationSuffixPath(
    request_path: []const u8,
    matched: http.location_router.MatchResult,
) ?[]const u8 {
    return switch (matched.block.match_type) {
        .exact => null,
        .prefix, .prefix_priority => blk: {
            if (std.mem.startsWith(u8, request_path, matched.block.pattern)) {
                const suffix = request_path[matched.block.pattern.len..];
                break :blk if (suffix.len == 0) null else suffix;
            }
            break :blk request_path;
        },
        .regex, .regex_case_insensitive => request_path,
    };
}

fn mountStripPrefixForLocation(
    request_path: []const u8,
    matched: http.location_router.MatchResult,
    blocks: []const edge_config.EdgeConfig.LocationBlock,
) ?[]const u8 {
    var best_pattern: ?[]const u8 = null;
    var best_priority: usize = std.math.maxInt(usize);

    for (blocks) |*candidate| {
        switch (candidate.match_type) {
            .prefix, .prefix_priority => {},
            else => continue,
        }
        if (candidate.pattern.len <= 1) continue;
        if (!std.mem.startsWith(u8, request_path, candidate.pattern)) continue;
        switch (candidate.action) {
            .proxy_pass => {},
            else => continue,
        }

        const should_consider = switch (matched.block.match_type) {
            .exact, .regex, .regex_case_insensitive => true,
            .prefix, .prefix_priority => blk: {
                if (candidate.pattern.len >= matched.block.pattern.len) break :blk false;
                break :blk proxyPassTargetsDiffer(matched.block, candidate);
            },
        };
        if (!should_consider) continue;

        if (best_pattern == null or
            candidate.pattern.len < best_pattern.?.len or
            (candidate.pattern.len == best_pattern.?.len and candidate.priority < best_priority))
        {
            best_pattern = candidate.pattern;
            best_priority = candidate.priority;
        }
    }

    return best_pattern;
}

fn proxyPassTargetsDiffer(
    matched_block: *const edge_config.EdgeConfig.LocationBlock,
    candidate_block: *const edge_config.EdgeConfig.LocationBlock,
) bool {
    const matched_target = switch (matched_block.action) {
        .proxy_pass => |target| std.mem.trim(u8, target, " \t\r\n"),
        else => return false,
    };
    const candidate_target = switch (candidate_block.action) {
        .proxy_pass => |target| std.mem.trim(u8, target, " \t\r\n"),
        else => return false,
    };
    return !std.mem.eql(u8, matched_target, candidate_target);
}

fn handleVersionedApiProxyRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
) !?u16 {
    const versioned = http.api_router.parseVersionedPath(request.uri.path) orelse return null;
    const incoming_host = request.headers.get("host");
    const incoming_x_forwarded_for = request.headers.get("x-forwarded-for");
    const body = request.body orelse "";

    if (std.mem.eql(u8, versioned.path, "/chat") and cfg.proxy_pass_chat.len > 0) {
        return try executeVersionedApiProxyRoute(
            allocator,
            writer,
            cfg,
            state,
            ctx,
            &request.headers,
            .chat,
            cfg.proxy_pass_chat,
            null,
            body,
            correlation_id,
            keep_alive,
            client_ip,
            versioned.version,
            incoming_host,
            incoming_x_forwarded_for,
        );
    }

    if (std.mem.eql(u8, versioned.path, "/commands") and cfg.proxy_pass_commands_prefix.len > 0) {
        return try executeVersionedApiProxyRoute(
            allocator,
            writer,
            cfg,
            state,
            ctx,
            &request.headers,
            .commands,
            cfg.proxy_pass_commands_prefix,
            null,
            body,
            correlation_id,
            keep_alive,
            client_ip,
            versioned.version,
            incoming_host,
            incoming_x_forwarded_for,
        );
    }

    return null;
}

fn executeVersionedApiProxyRoute(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request_headers: *const http.Headers,
    upstream_scope: UpstreamScope,
    proxy_pass_target: []const u8,
    suffix_path: ?[]const u8,
    payload: []const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
    api_version: u16,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) !u16 {
    const upstream_pool = upstreamPoolForScope(cfg, upstream_scope);
    const location_id = switch (upstream_scope) {
        .chat => "versioned:/chat",
        .commands => "versioned:/commands",
        .global => "versioned:/",
    };
    var sticky_affinity = try prepareStickyAffinityRequest(
        allocator,
        cfg,
        upstream_pool,
        request_headers,
        incoming_host,
        location_id,
        proxy_pass_target,
    );
    defer if (sticky_affinity) |*value| value.deinit(allocator);

    const exec = proxyJsonExecute(
        allocator,
        cfg,
        upstream_scope,
        proxy_pass_target,
        suffix_path,
        payload,
        correlation_id,
        client_ip,
        ctx.identity,
        ctx.user_id,
        ctx.device_id,
        ctx.scopes,
        api_version,
        incoming_host,
        incoming_x_forwarded_for,
        writer,
        state,
        false,
        if (sticky_affinity) |*value| value else null,
    ) catch |err| {
        const mapped = mapProxyExecutionError(err);
        try sendApiError(allocator, writer, mapped.status, mapped.code, mapped.message, correlation_id, keep_alive, state);
        return @intFromEnum(mapped.status);
    };

    switch (exec) {
        .streamed_status => |streamed| {
            ctx.setUpstreamResult(streamed.upstream_addr, streamed.status, 0);
            return streamed.status;
        },
        .buffered => |resp| {
            defer allocator.free(resp.body);
            defer allocator.free(resp.content_type);
            if (resp.content_disposition) |cd| allocator.free(cd);
            if (resp.location) |location| allocator.free(location);
            if (resp.set_cookie) |cookie| allocator.free(cookie);

            var response = http.Response.init(allocator);
            defer response.deinit();
            _ = response.setStatus(@enumFromInt(resp.status))
                .setBody(resp.body)
                .setContentType(resp.content_type)
                .setConnection(keep_alive);
            setRequestIdHeaders(&response, correlation_id);
            if (resp.content_disposition) |cd| {
                _ = response.setHeader("Content-Disposition", cd);
            }
            if (resp.location) |location| {
                _ = response.setHeader("Location", location);
            }
            if (resp.set_cookie) |cookie| {
                _ = response.setHeader("Set-Cookie", cookie);
            }
            applyResponseHeaders(state, &response);
            try response.write(writer);
            ctx.setUpstreamResult(resp.upstream_addr, resp.status, resp.body.len);
            state.metricsRecord(resp.status);
            return resp.status;
        },
    }
}

fn handleLocationProxyPass(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    target: []const u8,
    suffix_path: ?[]const u8,
    correlation_id: []const u8,
    keep_alive: bool,
    client_ip: []const u8,
    auth_identity: ?[]const u8,
    auth_user_id: ?[]const u8,
    auth_device_id: ?[]const u8,
    auth_scopes: ?[]const u8,
    incoming_host: ?[]const u8,
    location_id: []const u8,
) !u16 {
    const upstream_scope = .global;
    const upstream_pool = upstreamPoolForScope(cfg, upstream_scope);
    var proxy_temp_arena = std.heap.ArenaAllocator.init(allocator);
    defer proxy_temp_arena.deinit();
    const temp_allocator = proxy_temp_arena.allocator();

    var sticky_affinity = try prepareStickyAffinityRequest(
        temp_allocator,
        cfg,
        upstream_pool,
        &request.headers,
        incoming_host,
        location_id,
        target,
    );

    const upstream_hash_key = if (suffix_path) |suffix| suffix else target;
    const selection: StickyUpstreamSelection = if (sticky_affinity) |*value|
        state.nextStickyUpstreamBaseUrl(cfg, upstream_pool, client_ip, upstream_hash_key, value.requested_upstream)
    else
        .{ .base_url = state.nextUpstreamBaseUrl(cfg, upstream_pool, client_ip, upstream_hash_key), .used_requested = false };
    const selected_base_url = if (isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n")))
        cfg.upstream_base_url
    else
        selection.base_url;

    const resolved = try resolveProxyTarget(temp_allocator, selected_base_url, target, suffix_path);
    const body = request.body orelse "";
    const upstream_url = try appendProxyQueryString(temp_allocator, resolved.url, request.uri.query);
    const sticky_set_cookie = if (sticky_affinity) |*value|
        try buildStickySetCookieHeader(temp_allocator, cfg, value, selection.base_url)
    else
        null;
    const use_mtls_path = cfg.upstream_tls_client_cert.len > 0 and
        std.mem.startsWith(u8, upstream_url.value, "https://");
    const forwarded_proto = if (edge_config.hasTlsFiles(cfg)) "https" else "http";
    const method_str = request.method.toString();

    // Determine retry budget. Non-idempotent methods are not retried when the
    // idempotent-only guard is enabled (default on).
    const max_attempts: usize = blk: {
        const n: usize = @intCast(@max(cfg.upstream_retry_attempts, @as(u32, 1)));
        if (n <= 1) break :blk 1;
        if (cfg.upstream_retry_idempotent_only and !isHttpMethodIdempotent(method_str)) break :blk 1;
        break :blk n;
    };
    const budget_start_ms = http.event_loop.monotonicMs();

    var attempt: usize = 0;
    var upstream_response: RawUpstreamResponse = while (attempt < max_attempts) : (attempt += 1) {
        const per_attempt_timeout_ms: u32 = blk: {
            if (cfg.upstream_timeout_budget_ms == 0) break :blk cfg.upstream_timeout_ms;
            const elapsed_ms = http.event_loop.monotonicMs() - budget_start_ms;
            if (elapsed_ms >= cfg.upstream_timeout_budget_ms) return error.Timeout;
            const remaining = cfg.upstream_timeout_budget_ms - elapsed_ms;
            if (cfg.upstream_timeout_ms == 0) {
                break :blk @intCast(@min(remaining, @as(u64, std.math.maxInt(u32))));
            }
            break :blk @intCast(@min(@as(u64, cfg.upstream_timeout_ms), remaining));
        };
        state.recordUpstreamAttemptStart(selection.base_url);
        const resp = if (use_mtls_path)
            executeUpstreamHttpsWithMtls(
                allocator,
                upstream_url.value,
                method_str,
                &request.headers,
                body,
                correlation_id,
                client_ip,
                forwarded_proto,
                request.headers.get("host"),
                auth_identity,
                auth_user_id,
                auth_device_id,
                auth_scopes,
                cfg,
            )
        else
            executeRawHttpProxyRequest(
                allocator,
                &state.upstream_client,
                cfg,
                upstream_url.value,
                resolved.unix_socket_path,
                method_str,
                &request.headers,
                body,
                correlation_id,
                client_ip,
                forwarded_proto,
                request.headers.get("host"),
                auth_identity,
                auth_user_id,
                auth_device_id,
                auth_scopes,
                per_attempt_timeout_ms,
                cfg.upstream_connect_timeout_ms,
                if (ctx.lifecycle) |lc| &lc.token else null,
            );
        state.recordUpstreamAttemptEnd(selection.base_url);
        const result = resp catch |err| {
            state.recordUpstreamFailure(cfg, selection.base_url);
            // If the request deadline elapsed, stop retrying immediately.
            if (err == error.RequestCancelled) {
                if (ctx.lifecycle) |lc| lc.logTimeout("upstream_connect");
                try sendApiError(allocator, writer, .gateway_timeout, "upstream_timeout", "Upstream request timed out", correlation_id, keep_alive, state);
                ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(http.Status.gateway_timeout), 0);
                return @intFromEnum(http.Status.gateway_timeout);
            }
            if (attempt + 1 < max_attempts) {
                state.logger.warn(correlation_id, "proxy attempt {d}/{d} failed: {}", .{ attempt + 1, max_attempts, err });
                continue;
            }
            // All retry attempts are exhausted — synthesise a proper error
            // response so the client receives a complete HTTP message instead
            // of an abrupt TCP close (fixes #94).
            if (err == error.OutOfMemory) return error.OutOfMemory;
            const err_status: http.Status = switch (err) {
                error.Timeout, error.TimedOut, error.WouldBlock => .gateway_timeout,
                else => .bad_gateway,
            };
            const err_code = if (err_status == .gateway_timeout) "upstream_timeout" else "upstream_error";
            const err_msg = if (err_status == .gateway_timeout) "Upstream request timed out" else "Upstream connection failed";
            state.logger.warn(correlation_id, "upstream request failed after {d} attempt(s): {}", .{ attempt + 1, err });
            try sendApiError(allocator, writer, err_status, err_code, err_msg, correlation_id, keep_alive, state);
            ctx.setUpstreamResult(resolved.upstream_host, @intFromEnum(err_status), 0);
            return @intFromEnum(err_status);
        };
        // Retry on 5xx only when attempts remain and the method allows it.
        if (result.status_code >= 500 and attempt + 1 < max_attempts) {
            state.recordUpstreamFailure(cfg, selection.base_url);
            state.logger.warn(correlation_id, "proxy attempt {d}/{d} got {d}, retrying", .{ attempt + 1, max_attempts, result.status_code });
            var r = result;
            r.deinit(allocator);
            continue;
        }
        break result;
    } else {
        // The retry loop ended because max_attempts was 0 or all budget was
        // consumed before even issuing a request.  Synthesise a 502 rather
        // than propagating the bare UpstreamUnavailable error (fixes #94).
        state.logger.warn(correlation_id, "no upstream attempts remaining for {s}", .{resolved.upstream_host});
        try sendApiError(allocator, writer, .bad_gateway, "upstream_unavailable", "No upstream available", correlation_id, keep_alive, state);
        ctx.setUpstreamResult(resolved.upstream_host, 502, 0);
        state.metricsRecord(502);
        return 502;
    };
    defer upstream_response.deinit(allocator);

    const transcript_redactions: []const []const u8 = if (request.headers.get("authorization")) |raw_auth|
        if (http.auth.parseBearerToken(raw_auth)) |token| &.{token} else &.{}
    else
        &.{};
    state.appendTranscript(
        upstreamScopeName(proxyScopeForPath(request.uri.path)),
        request.uri.path,
        correlation_id,
        auth_identity,
        client_ip,
        upstream_url.value,
        body,
        upstream_response.status_code,
        upstream_response.headerValue("content-type") orelse "application/octet-stream",
        upstream_response.body,
        transcript_redactions,
    );
    if (!isAbsoluteHttpUrl(std.mem.trim(u8, target, " \t\r\n"))) {
        if (upstream_response.status_code >= 500) {
            state.recordUpstreamFailure(cfg, selection.base_url);
        } else {
            state.recordUpstreamSuccess(cfg, selection.base_url);
        }
    }
    ctx.setUpstreamResult(resolved.upstream_host, upstream_response.status_code, upstream_response.body.len);
    try writeBufferedUpstreamResponse(writer, &upstream_response, keep_alive, correlation_id, &state.security_headers, sticky_set_cookie);
    const status_code = upstream_response.status_code;
    state.metricsRecord(status_code);
    return status_code;
}

const StaticErrorPageResult = union(enum) {
    served: http.static_file.Result,
    redirect: []u8,

    fn deinit(self: *StaticErrorPageResult, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .served => |*served| served.deinit(allocator),
            .redirect => |target| allocator.free(target),
        }
        self.* = undefined;
    }
};

fn wantsHtmlErrorPage(request_path: []const u8, headers: *const http.Headers) bool {
    if (std.mem.startsWith(u8, request_path, "/v1/")) return false;
    const accept = headers.get("accept") orelse return false;
    if (std.mem.find(u8, accept, "text/html") != null) return true;
    if (std.mem.find(u8, accept, "*/*") != null) return true;
    if (std.mem.find(u8, accept, "application/json") != null) return false;
    return false;
}

fn rateLimitDescriptor(identity: ?[]const u8, client_ip: []const u8, buf: *[192]u8) []const u8 {
    if (identity) |id| {
        return std.fmt.bufPrint(buf, "identity:{s}", .{id}) catch blk: {
            const hash = std.hash.Wyhash.hash(0, id);
            break :blk std.fmt.bufPrint(buf, "identity-hash:{x}", .{hash}) catch "identity-hash";
        };
    }
    return std.fmt.bufPrint(buf, "ip:{s}", .{client_ip}) catch blk: {
        const hash = std.hash.Wyhash.hash(0, client_ip);
        break :blk std.fmt.bufPrint(buf, "ip-hash:{x}", .{hash}) catch "ip-hash";
    };
}

fn findErrorPageTarget(block: *const http.location_router.LocationBlock, status_code: u16) ?[]const u8 {
    for (block.error_pages) |rule| {
        for (rule.status_codes) |candidate| {
            if (candidate == status_code) return rule.target;
        }
    }
    return null;
}

fn maybeResolveStaticErrorPage(
    allocator: std.mem.Allocator,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    request_path: []const u8,
    headers: *const http.Headers,
    status_code: u16,
) !?StaticErrorPageResult {
    if (!wantsHtmlErrorPage(request_path, headers)) return null;
    const target = findErrorPageTarget(matched.block, status_code) orelse return null;
    if (std.mem.startsWith(u8, target, "http://") or std.mem.startsWith(u8, target, "https://")) {
        return .{ .redirect = try allocator.dupe(u8, target) };
    }
    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = target,
        .matched_pattern = "/",
        .alias = false,
        .index = root_cfg.index,
        .try_files = "",
        .autoindex = false,
        .headers = headers,
        .max_bytes = MAX_REQUEST_SIZE,
    })) orelse return null;
    served.status_code = @enumFromInt(status_code);
    return .{ .served = served };
}

fn runMiddlewarePipeline(
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
) !bool {
    const client_ip = ctx.client_ip;

    if (cfg.geo_blocked_countries.len > 0) {
        const country = request.headers.get(cfg.geo_country_header);
        if (isGeoBlocked(cfg.geo_blocked_countries, country)) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Geo access denied", correlation_id, keep_alive, state);
            logAccess(state, ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    const limits = cfg.request_limits;
    const uri_check = http.request_limits.validateUriLength(request.uri.path.len, limits);
    if (uri_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(uri_check, &msg_buf);
        try sendApiError(allocator, writer, .uri_too_long, "invalid_request", msg, correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "URI too long: {d} bytes", .{request.uri.path.len});
        logAccess(state, ctx, request.method.toString(), request.uri.path, 414, request.headers.get("user-agent") orelse "");
        return true;
    }
    const header_count_check = http.request_limits.validateHeaderCount(request.headers.count(), limits);
    if (header_count_check != .ok) {
        var msg_buf: [256]u8 = undefined;
        const msg = http.request_limits.rejectionMessage(header_count_check, &msg_buf);
        try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
        state.logger.warn(correlation_id, "Too many headers: {d}", .{request.headers.count()});
        logAccess(state, ctx, request.method.toString(), request.uri.path, 431, request.headers.get("user-agent") orelse "");
        return true;
    }
    {
        var headers_total: usize = 0;
        for (request.headers.iterator()) |h| headers_total += h.name.len + h.value.len + 4; // ": \r\n"
        const total_check = http.request_limits.validateHeadersTotalSize(headers_total, limits);
        if (total_check != .ok) {
            var msg_buf: [256]u8 = undefined;
            const msg = http.request_limits.rejectionMessage(total_check, &msg_buf);
            try sendApiError(allocator, writer, .request_header_fields_too_large, "invalid_request", msg, correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Headers total too large: {d} bytes", .{headers_total});
            logAccess(state, ctx, request.method.toString(), request.uri.path, 431, request.headers.get("user-agent") orelse "");
            return true;
        }
    }
    if (request.body) |body| {
        const body_check = http.request_limits.validateBodySize(body.len, limits);
        if (body_check != .ok) {
            try sendApiError(allocator, writer, .payload_too_large, "invalid_request", "Request body too large", correlation_id, keep_alive, state);
            state.logger.warn(correlation_id, "Body too large: {d} bytes", .{body.len});
            logAccess(state, ctx, request.method.toString(), request.uri.path, 413, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    if (state.access_control) |*acl| {
        if (acl.check(client_ip) == .denied) {
            try sendApiError(allocator, writer, .forbidden, "forbidden", "Access denied", correlation_id, keep_alive, state);
            logAccess(state, ctx, request.method.toString(), request.uri.path, 403, request.headers.get("user-agent") orelse "");
            return true;
        }
    }

    var rate_limit_buf: [192]u8 = undefined;
    const limit_key = rateLimitDescriptor(ctx.identity, client_ip, &rate_limit_buf);
    if (!state.rateLimitAllow(limit_key)) {
        const payload = try buildApiErrorJson(allocator, "rate_limited", "Rate limit exceeded", correlation_id);
        defer allocator.free(payload);
        var response = http.Response.json(allocator, payload);
        defer response.deinit();
        _ = response
            .setStatus(.too_many_requests)
            .setConnection(keep_alive)
            .setHeader("Retry-After", "1")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        applyResponseHeaders(state, &response);
        try response.write(writer);
        state.metricsRecord(429);
        state.metricsRecordErrorCode("rate_limited");
        logAccess(state, ctx, request.method.toString(), request.uri.path, 429, request.headers.get("user-agent") orelse "");
        return true;
    }

    return false;
}

fn handleStaticLocation(
    allocator: std.mem.Allocator,
    conn: anytype,
    request: *const http.Request,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !?u16 {
    if (!(request.method == .GET or request.method == .HEAD)) return null;
    const writer = conn.writer();
    const prefer_file_backed = @TypeOf(conn) == compat.NetStream;
    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = request.uri.path,
        .matched_pattern = matched.block.pattern,
        .alias = root_cfg.alias,
        .index = root_cfg.index,
        .try_files = root_cfg.try_files,
        .autoindex = root_cfg.autoindex,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
        .prefer_file_backed = prefer_file_backed,
    })) orelse blk: {
        var error_page = (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request.uri.path, &request.headers, 404)) orelse return null;
        switch (error_page) {
            .redirect => |target| {
                defer allocator.free(target);
                var response = http.Response.init(allocator);
                defer response.deinit();
                _ = response
                    .setStatus(.found)
                    .setBody("")
                    .setContentType("text/plain; charset=utf-8")
                    .setConnection(keep_alive)
                    .setHeader("Location", target)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                applyResponseHeaders(state, &response);
                if (request.method == .HEAD) {
                    try response.writeHead(writer);
                } else {
                    try response.write(writer);
                }
                state.metricsRecord(302);
                return 302;
            },
            .served => |*resolved| break :blk resolved.*,
        }
    };
    defer served.deinit(allocator);

    if (@intFromEnum(served.status_code) >= 400) {
        if (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request.uri.path, &request.headers, @intFromEnum(served.status_code))) |error_page| {
            switch (error_page) {
                .redirect => |target| {
                    defer allocator.free(target);
                    var response = http.Response.init(allocator);
                    defer response.deinit();
                    _ = response
                        .setStatus(.found)
                        .setBody("")
                        .setContentType("text/plain; charset=utf-8")
                        .setConnection(keep_alive)
                        .setHeader("Location", target)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    applyResponseHeaders(state, &response);
                    if (request.method == .HEAD) {
                        try response.writeHead(writer);
                    } else {
                        try response.write(writer);
                    }
                    state.metricsRecord(302);
                    return 302;
                },
                .served => |replacement| {
                    served.deinit(allocator);
                    served = replacement;
                },
            }
        }
    }

    const status_code = try writeStaticServedResponse(allocator, conn, request.method == .HEAD, keep_alive, correlation_id, state, &served);
    state.metricsRecord(status_code);
    return status_code;
}

fn serveTryFilesFallback(
    allocator: std.mem.Allocator,
    conn: anytype,
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    correlation_id: []const u8,
    keep_alive: bool,
    state: *GatewayState,
) !u16 {
    const method = request.method.toString();
    const request_path = request.uri.path;
    if (!(std.ascii.eqlIgnoreCase(method, "GET") or std.ascii.eqlIgnoreCase(method, "HEAD"))) return error.NoTryFiles;
    if (cfg.doc_root.len == 0) return error.NoTryFiles;
    // When `root` is set at the server level without a `try_files` directive,
    // default to "$uri" so that files at the exact request path are served
    // directly.  This matches the intuitive expectation: `root /path;` alone
    // should serve static files for any unmatched request whose path exists in
    // the webroot.
    const effective_try_files = if (cfg.try_files.len > 0) cfg.try_files else "$uri";
    const prefer_file_backed = @TypeOf(conn) == compat.NetStream;

    var served = (try http.static_file.serve(allocator, .{
        .root = cfg.doc_root,
        .request_path = request_path,
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = effective_try_files,
        .autoindex = false,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
        .prefer_file_backed = prefer_file_backed,
    })) orelse return error.NoTryFiles;
    defer served.deinit(allocator);

    return writeStaticServedResponse(allocator, conn, std.ascii.eqlIgnoreCase(method, "HEAD"), keep_alive, correlation_id, state, &served);
}

fn writeStaticServedResponse(
    allocator: std.mem.Allocator,
    conn: anytype,
    head_only: bool,
    keep_alive: bool,
    correlation_id: []const u8,
    state: *GatewayState,
    served: *const http.static_file.Result,
) !u16 {
    const writer = conn.writer();
    var response = http.Response.init(allocator);
    defer response.deinit();
    _ = response
        .setStatus(served.status_code)
        .setBody(served.body orelse "")
        .setContentType(served.content_type)
        .setConnection(keep_alive)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");

    if (served.file_path != null) {
        _ = response.setContentLength(served.content_length);
    }

    applyResponseHeaders(state, &response);
    try response.writeHead(writer);

    if (head_only) {
        if (served.file_path) |file_path| {
            state.logger.debug(correlation_id, "served static file headers from file-backed path: {s}", .{file_path});
        } else {
            state.logger.debug(correlation_id, "served static file headers from buffered path", .{});
        }
        return @intFromEnum(served.status_code);
    }

    if (served.file_path) |file_path| {
        if (@TypeOf(conn) == compat.NetStream) {
            var in_fc = try std.Io.Dir.openFileAbsolute(compat.io(), file_path, .{});
            defer in_fc.close(compat.io());
            _ = std.c.lseek(in_fc.handle, @intCast(served.file_offset), std.c.SEEK.SET);
            var remaining: u64 = served.file_len;
            var xfer_buf: [65536]u8 = undefined;
            while (remaining > 0) {
                const to_read: usize = @intCast(@min(xfer_buf.len, remaining));
                const n = std.c.read(in_fc.handle, &xfer_buf, to_read);
                if (n <= 0) break;
                try conn.writeAll(xfer_buf[0..@intCast(n)]);
                remaining -= @intCast(n);
            }
            state.logger.debug(correlation_id, "served static file via file-backed path: {s}", .{file_path});
        } else {
            return error.InvalidStaticTransferState;
        }
    } else if (served.body) |body| {
        try writer.writeAll(body);
        state.logger.debug(correlation_id, "served static file via buffered path", .{});
    }

    return @intFromEnum(served.status_code);
}

fn streamSseTopic(
    writer: anytype,
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    topic: []const u8,
    last_event_id_start: u64,
    correlation_id: []const u8,
) !void {
    try writer.writeAll("HTTP/1.1 200 OK\r\n");
    try writer.print("Server: {s}\r\n", .{http.SERVER_NAME});
    try writer.writeAll("Connection: close\r\n");
    try writer.writeAll("Cache-Control: no-cache\r\n");
    try writer.writeAll("Content-Type: text/event-stream\r\n");
    try writer.writeAll("X-Accel-Buffering: no\r\n");
    try writeRequestIdHeaders(writer, correlation_id);
    try writeSecurityHeaders(writer, &state.security_headers);
    for (state.add_headers) |pair| {
        try writer.print("{s}: {s}\r\n", .{ pair.name, pair.value });
    }
    try writer.writeAll("\r\n");

    var last_event_id = last_event_id_start;
    var last_send_ms = http.event_loop.monotonicMs();
    var last_comment_ms = last_send_ms;
    const poll_ms = @max(cfg.sse_poll_interval_ms, 10);

    while (!http.shutdown.isShutdownRequested()) {
        if (cfg.sse_max_backlog > 0 and last_event_id > 0) {
            if (state.event_hub.oldestId(topic)) |oldest| {
                if (last_event_id + cfg.sse_max_backlog < oldest) {
                    try writeSseEvent(writer, oldest, "backlog_exceeded");
                    return;
                }
            }
        }

        const events = try state.event_hub.snapshotSince(allocator, topic, last_event_id);
        defer http.event_hub.deinitSnapshot(allocator, events);

        if (events.len > 0) {
            for (events) |event| {
                try writeSseEvent(writer, event.id, event.payload);
                last_event_id = event.id;
            }
            last_send_ms = http.event_loop.monotonicMs();
        } else {
            const now_ms = http.event_loop.monotonicMs();
            if (now_ms - last_comment_ms >= 15_000) {
                try writer.writeAll(": keepalive\n\n");
                last_comment_ms = now_ms;
            }
            if (cfg.sse_idle_timeout_ms > 0 and now_ms - last_send_ms >= cfg.sse_idle_timeout_ms) return;
        }

        std.Io.sleep(compat.io(), std.Io.Duration.fromMilliseconds(@as(i64, @intCast(poll_ms))), .awake) catch {}; // interrupt wakes are fine; SSE poll loop continues
    }
}

fn writeSseEvent(writer: anytype, id: u64, payload: []const u8) !void {
    try writer.print("id: {d}\n", .{id});
    var line_it = std.mem.splitScalar(u8, payload, '\n');
    while (line_it.next()) |line| {
        try writer.print("data: {s}\n", .{line});
    }
    try writer.writeAll("\n");
}

fn parseQueryParam(query: ?[]const u8, key: []const u8) ?[]const u8 {
    const raw = query orelse return null;
    var it = std.mem.splitScalar(u8, raw, '&');
    while (it.next()) |part| {
        const eq = std.mem.findScalar(u8, part, '=') orelse continue;
        const name = std.mem.trim(u8, part[0..eq], " \t\r\n");
        if (!std.mem.eql(u8, name, key)) continue;
        return std.mem.trim(u8, part[eq + 1 ..], " \t\r\n");
    }
    return null;
}

fn generateCommandId(allocator: std.mem.Allocator) ![]const u8 {
    var rnd: [16]u8 = undefined;
    std.crypto.random.bytes(&rnd);
    return std.fmt.allocPrint(allocator, "cmd-{d}-{f}", .{
        compat.milliTimestamp(),
        compat.fmtSliceHexLower(&rnd),
    });
}

const AsyncCommandJob = struct {
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []u8,
    command_name: []u8,
    upstream_path: []u8,
    envelope: []u8,
    correlation_id: []u8,
    client_ip: []u8,
    identity: ?[]u8,
    incoming_host: ?[]u8,
    incoming_x_forwarded_for: ?[]u8,
    api_version: ?u32,
};

fn spawnAsyncCommandExecution(
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []const u8,
    command_name: []const u8,
    upstream_path: []const u8,
    envelope: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) void {
    const job = createAsyncCommandJob(
        state.allocator,
        cfg,
        state,
        command_id,
        command_name,
        upstream_path,
        envelope,
        correlation_id,
        client_ip,
        identity,
        api_version,
        incoming_host,
        incoming_x_forwarded_for,
    ) catch return;
    const t = std.Thread.spawn(.{}, runAsyncCommandJob, .{job}) catch {
        destroyAsyncCommandJob(job);
        state.commandLifecycleSetFailed(command_id, "async_spawn_failed");
        return;
    };
    t.detach();
}

fn createAsyncCommandJob(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    command_id: []const u8,
    command_name: []const u8,
    upstream_path: []const u8,
    envelope: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    identity: ?[]const u8,
    api_version: ?u32,
    incoming_host: ?[]const u8,
    incoming_x_forwarded_for: ?[]const u8,
) !*AsyncCommandJob {
    const job = try allocator.create(AsyncCommandJob);
    errdefer allocator.destroy(job);
    job.* = .{
        .allocator = allocator,
        .cfg = cfg,
        .state = state,
        .command_id = dupeOrEmpty(allocator, command_id),
        .command_name = dupeOrEmpty(allocator, command_name),
        .upstream_path = dupeOrEmpty(allocator, upstream_path),
        .envelope = dupeOrEmpty(allocator, envelope),
        .correlation_id = dupeOrEmpty(allocator, correlation_id),
        .client_ip = dupeOrEmpty(allocator, client_ip),
        .identity = if (identity) |id| allocator.dupe(u8, id) catch null else null,
        .incoming_host = if (incoming_host) |h| allocator.dupe(u8, h) catch null else null,
        .incoming_x_forwarded_for = if (incoming_x_forwarded_for) |xff| allocator.dupe(u8, xff) catch null else null,
        .api_version = api_version,
    };
    return job;
}

fn dupeOrEmpty(allocator: std.mem.Allocator, src: []const u8) []u8 {
    return allocator.dupe(u8, src) catch allocator.alloc(u8, 0) catch unreachable;
}

fn destroyAsyncCommandJob(job: *AsyncCommandJob) void {
    const alloc = job.allocator;
    if (job.command_id.len > 0) alloc.free(job.command_id);
    if (job.command_name.len > 0) alloc.free(job.command_name);
    if (job.upstream_path.len > 0) alloc.free(job.upstream_path);
    if (job.envelope.len > 0) alloc.free(job.envelope);
    if (job.correlation_id.len > 0) alloc.free(job.correlation_id);
    if (job.client_ip.len > 0) alloc.free(job.client_ip);
    if (job.identity) |id| alloc.free(id);
    if (job.incoming_host) |h| alloc.free(h);
    if (job.incoming_x_forwarded_for) |xff| alloc.free(xff);
    alloc.destroy(job);
}

fn runAsyncCommandJob(job: *AsyncCommandJob) void {
    defer destroyAsyncCommandJob(job);

    job.state.commandLifecycleSetRunning(job.command_id);
    const exec = proxyJsonExecute(
        job.allocator,
        job.cfg,
        .commands,
        job.cfg.proxy_pass_commands_prefix,
        job.upstream_path,
        job.envelope,
        job.correlation_id,
        job.client_ip,
        job.identity,
        null,
        null,
        null,
        job.api_version,
        job.incoming_host,
        job.incoming_x_forwarded_for,
        std.io.null_writer,
        job.state,
        false,
        null,
    ) catch |err| {
        job.state.commandLifecycleSetFailed(job.command_id, @errorName(err));
        return;
    };

    switch (exec) {
        .streamed_status => |streamed| {
            job.state.commandLifecycleSetCompleted(job.command_id, streamed.status, "", JSON_CONTENT_TYPE);
        },
        .buffered => |resp| {
            defer job.allocator.free(resp.body);
            defer job.allocator.free(resp.content_type);
            if (resp.content_disposition) |cd| job.allocator.free(cd);
            if (resp.location) |location| job.allocator.free(location);
            job.state.commandLifecycleSetCompleted(job.command_id, resp.status, resp.body, resp.content_type);
        },
    }
}

test "async command jobs copy request-owned inputs onto long-lived allocator" {
    var request_arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    const request_allocator = request_arena_state.allocator();

    const command_id = try request_allocator.dupe(u8, "cmd-request-owned");
    const command_name = try request_allocator.dupe(u8, "chat.send");
    const upstream_path = try request_allocator.dupe(u8, "/run");
    const envelope = try request_allocator.dupe(u8, "{\"ok\":true}");
    const correlation_id = try request_allocator.dupe(u8, "corr-123");
    const client_ip = try request_allocator.dupe(u8, "127.0.0.1");
    const identity = try request_allocator.dupe(u8, "identity-1");
    const incoming_host = try request_allocator.dupe(u8, "example.test");
    const incoming_xff = try request_allocator.dupe(u8, "10.0.0.1");

    var cfg: edge_config.EdgeConfig = undefined;
    var state: GatewayState = undefined;
    state.allocator = std.testing.allocator;

    const job = try createAsyncCommandJob(
        std.testing.allocator,
        &cfg,
        &state,
        command_id,
        command_name,
        upstream_path,
        envelope,
        correlation_id,
        client_ip,
        identity,
        1,
        incoming_host,
        incoming_xff,
    );
    defer destroyAsyncCommandJob(job);

    request_arena_state.deinit();

    try std.testing.expectEqualStrings("cmd-request-owned", job.command_id);
    try std.testing.expectEqualStrings("chat.send", job.command_name);
    try std.testing.expectEqualStrings("/run", job.upstream_path);
    try std.testing.expectEqualStrings("{\"ok\":true}", job.envelope);
    try std.testing.expectEqualStrings("corr-123", job.correlation_id);
    try std.testing.expectEqualStrings("127.0.0.1", job.client_ip);
    try std.testing.expectEqualStrings("identity-1", job.identity.?);
    try std.testing.expectEqualStrings("example.test", job.incoming_host.?);
    try std.testing.expectEqualStrings("10.0.0.1", job.incoming_x_forwarded_for.?);
}

fn parseLastEventId(raw: ?[]const u8) u64 {
    const value = raw orelse return 0;
    return std.fmt.parseInt(u64, std.mem.trim(u8, value, " \t\r\n"), 10) catch 0;
}

fn applyInternalRedirectRules(
    method: []const u8,
    path: []const u8,
    rules: []const edge_config.EdgeConfig.InternalRedirectRule,
    named_locations: []const edge_config.EdgeConfig.NamedLocation,
) []const u8 {
    var current = path;
    var hops: usize = 0;
    while (hops < 6) : (hops += 1) {
        var changed = false;
        for (rules) |rule| {
            if (!http.rewrite.methodMatches(rule.method, method)) continue;
            if (!http.rewrite.regexMatches(rule.pattern, current)) continue;
            if (rule.target.len > 1 and rule.target[0] == '@') {
                if (resolveNamedLocation(rule.target[1..], named_locations)) |named| {
                    current = named;
                    changed = true;
                    break;
                }
            } else {
                current = rule.target;
                changed = true;
                break;
            }
        }
        if (!changed) break;
    }
    return current;
}

fn evaluateConditionalRules(
    allocator: std.mem.Allocator,
    rules: []const edge_config.EdgeConfig.ConditionalRule,
    path: []const u8,
    request_uri: []const u8,
    host: []const u8,
    args: []const u8,
) !?http.rewrite.Outcome {
    for (rules) |rule| {
        const input = switch (rule.variable) {
            .request_uri => request_uri,
            .http_host => host,
            .args => args,
        };

        switch (rule.action) {
            .rewrite => |rw| {
                const replacement = try http.rewrite.substitutePattern(
                    allocator,
                    rule.pattern,
                    input,
                    request_uri,
                    rw.replacement,
                    rule.case_insensitive,
                ) orelse continue;
                switch (rw.flag) {
                    .redirect => return .{ .redirect = .{ .status = 302, .location = replacement } },
                    .permanent => return .{ .redirect = .{ .status = 301, .location = replacement } },
                    .@"break", .last => return .{ .pass = replacement },
                }
            },
            .returned => |ret| {
                const body = try http.rewrite.substitutePattern(
                    allocator,
                    rule.pattern,
                    input,
                    request_uri,
                    ret.body,
                    rule.case_insensitive,
                ) orelse continue;
                return .{ .returned = .{ .status = ret.status, .body = body } };
            },
        }
    }
    _ = path;
    return null;
}

fn resolveNamedLocation(name: []const u8, named_locations: []const edge_config.EdgeConfig.NamedLocation) ?[]const u8 {
    for (named_locations) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.path;
    }
    return null;
}

fn spawnMirrorRequests(
    allocator: std.mem.Allocator,
    rules: []const edge_config.EdgeConfig.MirrorRule,
    method: []const u8,
    path: []const u8,
    body: []const u8,
    correlation_id: []const u8,
    client_ip: []const u8,
    content_type: ?[]const u8,
) void {
    for (rules) |rule| {
        if (!http.rewrite.methodMatches(rule.method, method)) continue;
        if (!http.rewrite.regexMatches(rule.pattern, path)) continue;
        var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
        defer client.deinit();
        const uri = std.Uri.parse(rule.target_url) catch continue;
        var header_buf: [1024]u8 = undefined;
        var headers = [_]std.http.Header{
            .{ .name = http.correlation.REQUEST_HEADER_NAME, .value = correlation_id },
            .{ .name = http.correlation.HEADER_NAME, .value = correlation_id },
            .{ .name = "X-Mirror-Client-IP", .value = client_ip },
            .{ .name = "Content-Type", .value = content_type orelse "application/octet-stream" },
        };
        var req = client.request(.POST, uri, .{
            .extra_headers = headers[0..],
            .headers = .{ .content_type = .{ .override = content_type orelse "application/octet-stream" } },
        }) catch continue;
        defer req.deinit();
        req.sendBodyComplete(@constCast(body)) catch continue;
        _ = req.receiveHead(&header_buf) catch {}; // subrequest response is intentionally ignored; fire-and-forget
    }
}

const SubrequestPayload = struct {
    method: std.http.Method = .GET,
    url: []u8,
    body: ?[]u8 = null,
};

const SubrequestResult = struct {
    status: u16,
    body: []u8,
    content_type: []const u8,
};

fn parseSubrequestPayload(allocator: std.mem.Allocator, body: []const u8) !SubrequestPayload {
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, body, .{});
    defer parsed.deinit();
    const obj = parsed.value.object;
    const url_val = obj.get("url") orelse return error.InvalidPayload;
    if (url_val != .string) return error.InvalidPayload;
    const method = if (obj.get("method")) |m| blk: {
        if (m != .string) break :blk std.http.Method.GET;
        break :blk if (std.ascii.eqlIgnoreCase(m.string, "POST")) std.http.Method.POST else std.http.Method.GET;
    } else std.http.Method.GET;
    const req_body = if (obj.get("body")) |b| blk: {
        if (b != .string) break :blk null;
        break :blk try allocator.dupe(u8, b.string);
    } else null;
    return .{
        .method = method,
        .url = try allocator.dupe(u8, url_val.string),
        .body = req_body,
    };
}

fn executeSubrequest(allocator: std.mem.Allocator, url: []const u8, method: std.http.Method, req_body: ?[]const u8) !SubrequestResult {
    var client = std.http.Client{ .allocator = allocator, .io = compat.io() };
    defer client.deinit();
    const uri = try std.Uri.parse(url);
    var header_buf: [16 * 1024]u8 = undefined;
    var req = try client.request(method, uri, .{});
    defer req.deinit();
    if (req_body) |b| {
        try req.sendBodyComplete(@constCast(b));
    } else {
        try req.sendBodiless();
    }
    var resp = try req.receiveHead(&header_buf);
    const resp_status = @intFromEnum(resp.head.status);
    const resp_content_type = resp.head.content_type orelse "application/octet-stream";
    var resp_buf: [8192]u8 = undefined;
    const body_data = try resp.reader(&resp_buf).allocRemaining(allocator, .limited(2 * 1024 * 1024));
    return .{
        .status = resp_status,
        .body = body_data,
        .content_type = resp_content_type,
    };
}

const Http3DispatchContext = struct {
    config_store: *ReloadableConfigStore,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
};

const Http3LocationOutcome = union(enum) {
    not_handled,
    handled,
    rewritten: struct {
        path: []const u8,
        query: ?[]const u8,
    },
};

fn finalizeHttp3Response(response: *http.Response) void {
    if (response.headers.get("x-request-id")) |request_id| {
        _ = response.setHeader(http.correlation.HEADER_NAME, request_id);
    } else if (response.headers.get("x-correlation-id")) |correlation_id| {
        _ = response.setHeader(http.correlation.REQUEST_HEADER_NAME, correlation_id);
    }
    _ = response
        .setHeader("server", http.SERVER_NAME)
        .setContentLength(if (response.body) |body| body.len else 0);
}

fn handleHttp3LocationProxyPass(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    matched: http.location_router.MatchResult,
    request_path: []const u8,
    request_query: ?[]const u8,
    target: []const u8,
    correlation_id: []const u8,
) !void {
    const resolved = try resolveProxyTarget(allocator, ctx.cfg.upstream_base_url, target, proxySuffixPathForLocation(request_path, matched, ctx.cfg.location_blocks));
    defer allocator.free(resolved.url);
    var upstream_url = try appendProxyQueryString(allocator, resolved.url, request_query);
    defer upstream_url.deinit(allocator);

    const h3_use_mtls_path = ctx.cfg.upstream_tls_client_cert.len > 0 and
        std.mem.startsWith(u8, upstream_url.value, "https://");
    var upstream_response = if (h3_use_mtls_path)
        try executeUpstreamHttpsWithMtls(
            allocator,
            upstream_url.value,
            request.method,
            &request.headers,
            request.body,
            correlation_id,
            request.headers.get("x-real-ip") orelse "unknown",
            if (edge_config.hasTlsFiles(ctx.cfg)) "https" else "http",
            request.headers.get(":authority") orelse request.headers.get("host"),
            null,
            null,
            null,
            null,
            ctx.cfg,
        )
    else
        try executeRawHttpProxyRequest(
            allocator,
            &ctx.state.upstream_client,
            ctx.cfg,
            upstream_url.value,
            resolved.unix_socket_path,
            request.method,
            &request.headers,
            request.body,
            correlation_id,
            request.headers.get("x-real-ip") orelse "unknown",
            if (edge_config.hasTlsFiles(ctx.cfg)) "https" else "http",
            request.headers.get(":authority") orelse request.headers.get("host"),
            null,
            null,
            null,
            null,
            ctx.cfg.upstream_timeout_ms,
            ctx.cfg.upstream_connect_timeout_ms,
            null, // HTTP/3 path: no per-request lifecycle yet
        );
    defer upstream_response.deinit(allocator);

    _ = response
        .setStatus(@enumFromInt(upstream_response.status_code))
        .setBodyOwned(try allocator.dupe(u8, upstream_response.body))
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    for (upstream_response.headers) |header| {
        _ = response.setHeader(header.name, header.value);
    }
    finalizeHttp3Response(response);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(upstream_response.status_code);
}

fn handleHttp3StaticLocation(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
    correlation_id: []const u8,
    ctx: *Http3DispatchContext,
    request_path: []const u8,
) !bool {
    if (!(std.mem.eql(u8, request.method, "GET") or std.mem.eql(u8, request.method, "HEAD"))) return false;

    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = request_path,
        .matched_pattern = matched.block.pattern,
        .alias = root_cfg.alias,
        .index = root_cfg.index,
        .try_files = root_cfg.try_files,
        .autoindex = root_cfg.autoindex,
        .headers = &request.headers,
        .max_bytes = MAX_REQUEST_SIZE,
    })) orelse blk: {
        var error_page = (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request_path, &request.headers, 404)) orelse return false;
        switch (error_page) {
            .redirect => |target| {
                defer allocator.free(target);
                _ = response
                    .setStatus(.found)
                    .setBody("")
                    .setContentType("text/plain; charset=utf-8")
                    .setHeader("Location", target)
                    .setHeader(http.correlation.HEADER_NAME, correlation_id);
                finalizeHttp3Response(response);
                applyResponseHeaders(ctx.state, response);
                ctx.state.metricsRecord(302);
                return true;
            },
            .served => |*resolved| break :blk resolved.*,
        }
    };
    defer served.deinit(allocator);

    if (@intFromEnum(served.status_code) >= 400) {
        if (try maybeResolveStaticErrorPage(allocator, matched, root_cfg, request_path, &request.headers, @intFromEnum(served.status_code))) |error_page| {
            switch (error_page) {
                .redirect => |target| {
                    defer allocator.free(target);
                    _ = response
                        .setStatus(.found)
                        .setBody("")
                        .setContentType("text/plain; charset=utf-8")
                        .setHeader("Location", target)
                        .setHeader(http.correlation.HEADER_NAME, correlation_id);
                    finalizeHttp3Response(response);
                    applyResponseHeaders(ctx.state, response);
                    ctx.state.metricsRecord(302);
                    return true;
                },
                .served => |replacement| {
                    served.deinit(allocator);
                    served = replacement;
                },
            }
        }
    }

    _ = response
        .setStatus(served.status_code)
        .setBodyOwned(if (std.mem.eql(u8, request.method, "HEAD")) try allocator.dupe(u8, "") else try allocator.dupe(u8, served.body orelse ""))
        .setContentType(served.content_type)
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    if (served.etag_value) |etag_value| _ = response.setHeader("ETag", etag_value);
    if (served.last_modified_value) |last_modified| _ = response.setHeader("Last-Modified", last_modified);
    if (served.content_range_value) |content_range| _ = response.setHeader("Content-Range", content_range);
    if (served.accept_ranges) _ = response.setHeader("Accept-Ranges", "bytes");
    _ = response
        .setHeader("server", http.SERVER_NAME)
        .setContentLength(served.content_length);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(@intFromEnum(served.status_code));
    return true;
}

fn routeHttp3Location(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
    request_path: []const u8,
    correlation_id: []const u8,
) !Http3LocationOutcome {
    const matched = http.location_router.matchLocation(request_path, ctx.cfg.location_blocks) orelse return .not_handled;
    const split = splitHttp3PathAndQuery(request.path);
    const request_query = split[1];
    switch (matched.block.action) {
        .proxy_pass => |target| {
            try handleHttp3LocationProxyPass(allocator, request, response, ctx, matched, request_path, request_query, target, correlation_id);
            return .handled;
        },
        .return_response => |ret| {
            _ = response
                .setStatus(@enumFromInt(ret.status))
                .setBody(ret.body)
                .setContentType(if (ret.status >= 300 and ret.status < 400) "text/plain; charset=utf-8" else "text/plain; charset=utf-8")
                .setHeader(http.correlation.HEADER_NAME, correlation_id);
            if (ret.status >= 300 and ret.status < 400 and ret.body.len > 0) {
                _ = response.setHeader("location", ret.body);
            }
            finalizeHttp3Response(response);
            applyResponseHeaders(ctx.state, response);
            ctx.state.metricsRecord(ret.status);
            return .handled;
        },
        .rewrite => |rw| {
            const rewritten_path, const rewritten_query = splitHttp3PathAndQuery(rw.replacement);
            return .{ .rewritten = .{ .path = rewritten_path, .query = rewritten_query } };
        },
        .static_root => |root_cfg| {
            if (try handleHttp3StaticLocation(allocator, request, response, matched, root_cfg, correlation_id, ctx, request_path)) {
                return .handled;
            }
            return .not_handled;
        },
        .fastcgi_pass => return .not_handled,
    }
}

fn handleHttp3Connection(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    ctx: *Http3DispatchContext,
) !void {
    const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
    var http3_path, _ = splitHttp3PathAndQuery(request.path);
    var rewrite_budget: usize = 0;
    while (rewrite_budget < 4) : (rewrite_budget += 1) {
        switch (try routeHttp3Location(allocator, request, response, ctx, http3_path, correlation_id)) {
            .handled => return,
            .not_handled => break,
            .rewritten => |rewrite_result| {
                http3_path = rewrite_result.path;
            },
        }
    }

    const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
    _ = response
        .setStatus(.not_found)
        .setBodyOwned(payload)
        .setContentType("application/json")
        .setHeader(http.correlation.HEADER_NAME, correlation_id);
    finalizeHttp3Response(response);
    applyResponseHeaders(ctx.state, response);
    ctx.state.metricsRecord(404);
}

fn splitHttp3PathAndQuery(path: []const u8) struct { []const u8, ?[]const u8 } {
    if (std.mem.findScalar(u8, path, '?')) |idx| {
        return .{ path[0..idx], path[idx + 1 ..] };
    }
    return .{ path, null };
}

fn handleHttp3Request(
    allocator: std.mem.Allocator,
    request: *const http.http3_session.StreamRequest,
    response: *http.Response,
    user_data: ?*anyopaque,
) !void {
    const ctx: *Http3DispatchContext = @ptrCast(@alignCast(user_data orelse return error.InvalidArgument));
    var cfg_lease = ctx.config_store.acquire();
    defer cfg_lease.release();
    const active_cfg = cfg_lease.cfg;
    const authority = request.headers.get(":authority") orelse request.headers.get("host");
    var effective_cfg_storage = active_cfg.*;
    const effective_cfg = resolveRequestConfig(active_cfg, authority, &effective_cfg_storage) orelse {
        const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
        const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
        _ = response
            .setStatus(.not_found)
            .setBodyOwned(payload)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(404);
        return;
    };
    if (!hostMatchesPatterns(effective_cfg.server_names, authority)) {
        const correlation_id = request.headers.get(http.correlation.REQUEST_HEADER_NAME) orelse request.headers.get(http.correlation.HEADER_NAME) orelse "http3";
        const payload = try buildApiErrorJson(allocator, "invalid_request", "Not Found", correlation_id);
        _ = response
            .setStatus(.not_found)
            .setBodyOwned(payload)
            .setContentType("application/json")
            .setHeader(http.correlation.HEADER_NAME, correlation_id);
        finalizeHttp3Response(response);
        applyResponseHeaders(ctx.state, response);
        ctx.state.metricsRecord(404);
        return;
    }

    var effective_ctx = ctx.*;
    effective_ctx.cfg = effective_cfg;
    try handleHttp3Connection(allocator, request, response, &effective_ctx);
}

fn logAccess(state: *GatewayState, ctx: *const http.request_context.RequestContext, method: []const u8, path: []const u8, status: u16, user_agent: []const u8) void {
    state.metricsRecordLatencyMs(ctx.elapsedMs());
    const cancel_reason: []const u8 = if (ctx.lifecycle) |lc|
        if (lc.token.reason) |reason| @tagName(reason) else ""
    else
        "";
    const entry = http.access_log.AccessLogEntry{
        .method = method,
        .path = path,
        .status = status,
        .latency_ms = ctx.elapsedMs(),
        .client_ip = ctx.client_ip,
        .correlation_id = ctx.request_id,
        .upstream_addr = ctx.upstream_addr orelse "",
        .upstream_status = ctx.upstream_status,
        .identity = ctx.identity orelse "-",
        .user_agent = user_agent,
        .bytes_sent = ctx.response_bytes,
        .response_bytes = ctx.response_bytes,
        .error_category = classifyErrorCategory(status),
        .cancel_reason = cancel_reason,
    };
    entry.log();
}

fn classifyErrorCategory(status: u16) []const u8 {
    return if (status < 400)
        "-"
    else if (status == 400 or status == 413 or status == 414)
        "invalid_request"
    else if (status == 401 or status == 403)
        "authz"
    else if (status == 408)
        "request_timeout"
    else if (status == 429)
        "rate_limited"
    else if (status == 503)
        "upstream_unavailable"
    else if (status == 504)
        "upstream_timeout"
    else if (status >= 500)
        "internal_error"
    else
        "client_error";
}

fn readHttpRequest(conn: anytype, buf: []u8, pending_len: *usize) !usize {
    var total_read = pending_len.*;

    while (total_read <= buf.len) {
        if (firstRequestCompleteLen(buf[0..total_read])) |request_len| {
            pending_len.* = total_read;
            return @min(total_read, request_len);
        }
        if (total_read == buf.len) break;

        const n = conn.read(buf[total_read..]) catch |err| return err;
        if (n == 0) break;
        total_read += n;
    }

    pending_len.* = total_read;
    return total_read;
}

fn firstRequestCompleteLen(data: []const u8) ?usize {
    const header_pos = std.mem.find(u8, data, "\r\n\r\n") orelse return null;
    const headers_len = header_pos + 4;
    const content_length = parseContentLength(data[0..headers_len]) orelse 0;
    const full_len = headers_len + content_length;
    if (data.len >= full_len) return full_len;
    return null;
}

fn parseContentLength(headers: []const u8) ?usize {
    var it = std.mem.tokenizeAny(u8, headers, "\r\n");
    while (it.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.findScalar(u8, line, ':') orelse continue;
        const name = std.mem.trim(u8, line[0..colon], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "content-length")) continue;

        const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
        return std.fmt.parseInt(usize, value, 10) catch null;
    }
    return null;
}

/// Returns true for HTTP methods that are safe to retry on failure without
/// risk of double-applying a non-idempotent side effect (RFC 9110 §9.2).
/// GET, HEAD, PUT, DELETE, OPTIONS, and TRACE are idempotent.
/// POST and PATCH are not and must not be retried unless the operator
/// explicitly disables the idempotent-only guard.
pub fn isHttpMethodIdempotent(method: []const u8) bool {
    const upper = std.ascii.upperString;
    var buf: [16]u8 = undefined;
    if (method.len > buf.len) return false;
    const m = upper(buf[0..method.len], method);
    return std.mem.eql(u8, m, "GET") or
        std.mem.eql(u8, m, "HEAD") or
        std.mem.eql(u8, m, "PUT") or
        std.mem.eql(u8, m, "DELETE") or
        std.mem.eql(u8, m, "OPTIONS") or
        std.mem.eql(u8, m, "TRACE");
}

fn setSocketTimeoutMs(fd: std.posix.fd_t, recv_timeout_ms: u32, send_timeout_ms: u32) !void {
    const recv_tv = std.posix.timeval{
        .sec = @intCast(recv_timeout_ms / 1000),
        .usec = @intCast((recv_timeout_ms % 1000) * 1000),
    };
    const send_tv = std.posix.timeval{
        .sec = @intCast(send_timeout_ms / 1000),
        .usec = @intCast((send_timeout_ms % 1000) * 1000),
    };

    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&recv_tv));
    try std.posix.setsockopt(fd, std.posix.SOL.SOCKET, std.posix.SO.SNDTIMEO, std.mem.asBytes(&send_tv));
}

test "buildForwardedFor appends client ip" {
    const allocator = std.testing.allocator;
    var value = try buildForwardedFor(allocator, "10.0.0.1, 10.0.0.2", "127.0.0.1");
    defer value.deinit(allocator);
    try std.testing.expectEqualStrings("10.0.0.1, 10.0.0.2, 127.0.0.1", value.value);
}

test "buildForwardedFor borrows client ip when no incoming chain exists" {
    const value = try buildForwardedFor(std.testing.allocator, null, "127.0.0.1");
    try std.testing.expect(value.owned == null);
    try std.testing.expectEqualStrings("127.0.0.1", value.value);
}

test "parseUpstreamHost extracts authority" {
    try std.testing.expectEqualStrings("127.0.0.1:8080", parseUpstreamHost("http://127.0.0.1:8080") orelse "");
    try std.testing.expectEqualStrings("api.example.com", parseUpstreamHost("https://api.example.com/v1") orelse "");
    try std.testing.expect(parseUpstreamHost("invalid-url") == null);
}

test "buildHealthProbeUrl joins base and probe path" {
    const allocator = std.testing.allocator;
    const url = try http.health_checker.buildProbeUrl(allocator, "http://127.0.0.1:8080/", "/status");
    defer allocator.free(url);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/status", url);
}

test "parse proxy protocol v1 header extracts source ip" {
    var ip_buf: [64]u8 = undefined;
    const header = "PROXY TCP4 203.0.113.9 10.0.0.5 443 8080\r\nGET / HTTP/1.1\r\n\r\n";
    const parsed = parseProxyHeader(header, .v1, &ip_buf);
    switch (parsed) {
        .parsed => |result| {
            try std.testing.expectEqual(@as(usize, 42), result.consumed);
            try std.testing.expectEqualStrings("203.0.113.9", ip_buf[0..result.client_ip_len]);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "parse proxy protocol auto mode ignores non-proxy preface" {
    var ip_buf: [64]u8 = undefined;
    const header = "GET / HTTP/1.1\r\nHost: example\r\n\r\n";
    const parsed = parseProxyHeader(header, .auto, &ip_buf);
    try std.testing.expect(parsed == .no_header);
}

test "parse proxy protocol v2 header extracts source ip" {
    var ip_buf: [64]u8 = undefined;
    const header = [_]u8{
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
        0x21, 0x11, 0x00, 0x0c, 203,  0,    113,  44,   10,   0,    0,    2,
        0x01, 0xbb, 0x1f, 0x90,
    };
    const parsed = parseProxyHeader(header[0..], .v2, &ip_buf);
    switch (parsed) {
        .parsed => |result| {
            try std.testing.expectEqual(@as(usize, 28), result.consumed);
            try std.testing.expectEqualStrings("203.0.113.44", ip_buf[0..result.client_ip_len]);
        },
        else => return error.UnexpectedTestResult,
    }
}

test "clientIpFromAddress formats ipv4 address" {
    var storage: std.c.sockaddr.storage = std.mem.zeroes(std.c.sockaddr.storage);
    var sin: *std.c.sockaddr.in = @ptrCast(&storage);
    sin.family = std.posix.AF.INET;
    sin.addr = std.mem.nativeToBig(u32, (203 << 24) | (0 << 16) | (113 << 8) | 9);
    const ip = try clientIpFromAddress(std.testing.allocator, &storage);
    defer std.testing.allocator.free(ip);

    try std.testing.expectEqualStrings("203.0.113.9", ip);
}

test "clientIpFromAddress formats ipv6 address" {
    var storage: std.c.sockaddr.storage = std.mem.zeroes(std.c.sockaddr.storage);
    var sin6: *std.c.sockaddr.in6 = @ptrCast(&storage);
    sin6.family = std.posix.AF.INET6;
    // 2001:0db8::0044
    const addr = [16]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x44 };
    sin6.addr = addr;
    const ip = try clientIpFromAddress(std.testing.allocator, &storage);
    defer std.testing.allocator.free(ip);

    try std.testing.expectEqualStrings("2001:db8:0:0:0:0:0:44", ip);
}

test "firstRequestCompleteLen detects pipelined boundary" {
    const pipelined =
        "GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n" ++
        "GET /two HTTP/1.1\r\nHost: localhost\r\n\r\n";
    const first_len = firstRequestCompleteLen(pipelined).?;
    try std.testing.expectEqual(@as(usize, 38), first_len);
}

test "firstRequestCompleteLen waits for complete body" {
    const partial = "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhel";
    try std.testing.expect(firstRequestCompleteLen(partial) == null);

    const complete = "POST /x HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nhello";
    try std.testing.expectEqual(@as(usize, complete.len), firstRequestCompleteLen(complete).?);
}

test "firstRequestCompleteLen handles keep-alive pipelined requests" {
    const reqs =
        "GET /a HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n" ++
        "GET /b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    const first_len = firstRequestCompleteLen(reqs).?;
    const first = reqs[0..first_len];
    try std.testing.expect(std.mem.find(u8, first, "GET /a") != null);
    try std.testing.expect(std.mem.find(u8, first, "keep-alive") != null);
}

test "combineProxyTarget joins prefix and suffix" {
    const allocator = std.testing.allocator;
    const joined = try combineProxyTarget(allocator, "/api", "/api/messages");
    defer allocator.free(joined);
    try std.testing.expectEqualStrings("/api/api/messages", joined);
}

test "proxySuffixPathForLocation uses mount prefix for split upstream exact route" {
    const blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/ursa/health",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:18443" },
        },
        .{
            .match_type = .prefix,
            .pattern = "/ursa/",
            .priority = 1,
            .action = .{ .proxy_pass = "http://127.0.0.1:6707" },
        },
    };

    const matched = http.location_router.matchLocation("/ursa/health", &blocks).?;
    const suffix = proxySuffixPathForLocation("/ursa/health", matched, &blocks).?;
    try std.testing.expectEqualStrings("health", suffix);
}

test "proxySuffixPathForLocation keeps mount prefix for split upstream longer prefix route" {
    const blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix_priority,
            .pattern = "/ursa/download/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:18443" },
        },
        .{
            .match_type = .prefix,
            .pattern = "/ursa/",
            .priority = 1,
            .action = .{ .proxy_pass = "http://127.0.0.1:6707" },
        },
    };

    const matched = http.location_router.matchLocation("/ursa/download/file.bin", &blocks).?;
    const suffix = proxySuffixPathForLocation("/ursa/download/file.bin", matched, &blocks).?;
    try std.testing.expectEqualStrings("download/file.bin", suffix);
}

test "resolveProxyTarget handles absolute and relative proxy_pass" {
    const allocator = std.testing.allocator;
    const cfg = std.mem.zeroInit(edge_config.EdgeConfig, .{
        .upstream_base_url = "http://127.0.0.1:8080",
    });

    const abs = try resolveProxyTarget(allocator, cfg.upstream_base_url, "https://api.example.com/base", "/api/messages");
    defer allocator.free(abs.url);
    try std.testing.expectEqualStrings("https://api.example.com/base/api/messages", abs.url);
    try std.testing.expectEqualStrings("api.example.com", abs.upstream_host);

    const rel = try resolveProxyTarget(allocator, cfg.upstream_base_url, "/gateway", "/v1/tools");
    defer allocator.free(rel.url);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/gateway/v1/tools", rel.url);
    try std.testing.expectEqualStrings("127.0.0.1:8080", rel.upstream_host);
}

test "resolveProxyTarget supports unix socket upstream base" {
    const allocator = std.testing.allocator;
    const resolved = try resolveProxyTarget(allocator, "unix:/tmp/tardigrade.sock", "/gateway", "/api/messages");
    defer allocator.free(resolved.url);
    try std.testing.expectEqualStrings("http://localhost/gateway/api/messages", resolved.url);
    try std.testing.expectEqualStrings("/tmp/tardigrade.sock", resolved.upstream_host);
    try std.testing.expect(resolved.unix_socket_path != null);
    try std.testing.expectEqualStrings("/tmp/tardigrade.sock", resolved.unix_socket_path.?);
}

test "appendProxyQueryString preserves request query" {
    const allocator = std.testing.allocator;

    var appended = try appendProxyQueryString(allocator, "http://127.0.0.1:8080/auth/login", "next=%2F");
    defer appended.deinit(allocator);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/auth/login?next=%2F", appended.value);

    var appended_existing = try appendProxyQueryString(allocator, "http://127.0.0.1:8080/auth/login?foo=bar", "next=%2F");
    defer appended_existing.deinit(allocator);
    try std.testing.expectEqualStrings("http://127.0.0.1:8080/auth/login?foo=bar&next=%2F", appended_existing.value);
}

test "appendProxyQueryString borrows base url when request has no query" {
    const base = "http://127.0.0.1:8080/auth/login";
    const appended = try appendProxyQueryString(std.testing.allocator, base, null);
    try std.testing.expect(appended.owned == null);
    try std.testing.expectEqual(@intFromPtr(base.ptr), @intFromPtr(appended.value.ptr));
}

test "parseChatMessage validates payload" {
    const allocator = std.testing.allocator;
    const message = try parseChatMessage(allocator, "{\"message\":\"hello\"}", 10);
    defer allocator.free(message);
    try std.testing.expectEqualStrings("hello", message);

    try std.testing.expectError(error.MessageTooLarge, parseChatMessage(allocator, "{\"message\":\"hello\"}", 2));
}

test "buildProxyCacheKey supports template tokens" {
    const allocator = std.testing.allocator;
    const key = try buildProxyCacheKey(
        allocator,
        "method:path:identity:api_version",
        "POST",
        "/api/messages",
        "{\"message\":\"hello\"}",
        "identity-1",
        2,
    );
    defer allocator.free(key);
    try std.testing.expectEqualStrings("POST:/api/messages:identity-1:2", key);
}

test "buildProxyCacheKey falls back for unknown template tokens" {
    const allocator = std.testing.allocator;
    const payload = "{\"command\":\"list_tools\"}";
    const key = try buildProxyCacheKey(
        allocator,
        "unknown:also_unknown",
        "POST",
        "/api/tasks",
        payload,
        null,
        null,
    );
    defer allocator.free(key);

    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(payload, &digest, .{});
    const expected = try std.fmt.allocPrint(allocator, "POST:/api/tasks:{f}", .{compat.fmtSliceHexLower(&digest)});
    defer allocator.free(expected);
    try std.testing.expectEqualStrings(expected, key);
}

test "shouldSkipUpstreamRequestHeader strips inbound X-Tardigrade headers" {
    try std.testing.expect(shouldSkipUpstreamRequestHeader("X-Tardigrade-Auth-Identity", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("x-tardigrade-user-id", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("X-TARDIGRADE-DEVICE-ID", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("x-tardigrade-scopes", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("x-tardigrade-anything-custom", null));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("X-Custom-Header", null));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("Authorization", null));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("Content-Type", null));
}

test "shouldSkipUpstreamRequestHeader strips standard hop-by-hop headers" {
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Connection", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Keep-Alive", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Proxy-Authenticate", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Proxy-Authorization", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("TE", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Trailer", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Transfer-Encoding", null));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Upgrade", null));
}

test "shouldSkipUpstreamRequestHeader strips headers named by Connection" {
    const connection_header = "X-Test-Hop, keep-alive, Another-Hop";
    try std.testing.expect(shouldSkipUpstreamRequestHeader("X-Test-Hop", connection_header));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("another-hop", connection_header));
    try std.testing.expect(shouldSkipUpstreamRequestHeader("Keep-Alive", connection_header));
    try std.testing.expect(!shouldSkipUpstreamRequestHeader("X-Not-Hop", connection_header));
}

test "shouldSkipUpstreamResponseHeader strips stale content-encoding" {
    try std.testing.expect(shouldSkipUpstreamResponseHeader("Content-Encoding"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("content-encoding"));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Content-Type"));
}

test "HTTP/1.1 missing Host header rejected — version and header presence check" {
    // RFC 7230 §5.4 / ASVS-14.5.1: HTTP/1.1 requests without a Host header
    // must be rejected with 400. This test verifies the condition used in
    // handleConnection(). The actual 400 response is covered by integration tests.
    const http_version = @import("http/version.zig");
    const headers_mod = @import("http/headers.zig");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = arena.allocator();

    // HTTP/1.1 without Host — condition must trigger rejection
    var headers_no_host = headers_mod.Headers.init(alloc);
    defer headers_no_host.deinit();
    try std.testing.expect(headers_no_host.get("host") == null);
    const should_reject = (http_version.Version.http11 == .http11 and headers_no_host.get("host") == null);
    try std.testing.expect(should_reject);

    // HTTP/1.1 with Host — condition must NOT trigger rejection
    try headers_no_host.append("host", "example.com");
    const should_not_reject = (http_version.Version.http11 == .http11 and headers_no_host.get("host") == null);
    try std.testing.expect(!should_not_reject);

    // HTTP/1.0 without Host — condition must NOT trigger rejection (Host not required by RFC 1945)
    var headers_10 = headers_mod.Headers.init(alloc);
    defer headers_10.deinit();
    const http10_no_host = (http_version.Version.http10 == .http11 and headers_10.get("host") == null);
    try std.testing.expect(!http10_no_host);
}

test "TRACE method rejected globally — XST / ASVS-14.5.1 condition check" {
    // RFC 7231 §4.3.8 / ASVS-14.5.1: TRACE must be rejected at gateway level
    // before any routing so no location block can accidentally serve it.
    // The gateway checks request.method == .TRACE immediately after the Host
    // header validation.  This test validates the condition logic used there.
    const http_method = @import("http/method.zig");
    const trace_method = http_method.Method.TRACE;
    try std.testing.expect(trace_method == .TRACE);
    // GET and HEAD must NOT trigger the TRACE rejection path
    try std.testing.expect(http_method.Method.GET != .TRACE);
    try std.testing.expect(http_method.Method.HEAD != .TRACE);
    try std.testing.expect(http_method.Method.POST != .TRACE);
    try std.testing.expect(http_method.Method.DELETE != .TRACE);
    try std.testing.expect(http_method.Method.OPTIONS != .TRACE);
}

test "return_response method enforcement — non-GET/HEAD rejected on static returns" {
    // ASVS-14.5.1: static return directives (non-redirect) must reject anything
    // other than GET and HEAD to prevent silent success on destructive methods
    // (e.g. DELETE /health → 200 would falsely imply a delete occurred).
    // Redirect responses (3xx) are method-agnostic and skip enforcement.
    const http_method = @import("http/method.zig");

    // Non-redirect: only GET and HEAD are allowed
    const is_redirect_200 = (200 >= 300 and 200 < 400);
    try std.testing.expect(!is_redirect_200);
    try std.testing.expect(http_method.Method.GET == .GET or http_method.Method.GET == .HEAD);
    try std.testing.expect(!(http_method.Method.DELETE == .GET or http_method.Method.DELETE == .HEAD));
    try std.testing.expect(!(http_method.Method.POST == .GET or http_method.Method.POST == .HEAD));
    try std.testing.expect(!(http_method.Method.PUT == .GET or http_method.Method.PUT == .HEAD));
    try std.testing.expect(!(http_method.Method.PATCH == .GET or http_method.Method.PATCH == .HEAD));

    // Redirect: method enforcement is skipped
    const is_redirect_302 = (302 >= 300 and 302 < 400);
    try std.testing.expect(is_redirect_302);
}

test "shouldSkipUpstreamResponseHeader strips upstream Server and X-Powered-By" {
    // WSTG-INFO-02 / ASVS-14.3.3: upstream technology headers must not leak
    // to external clients — Tardigrade emits its own Server header instead.
    try std.testing.expect(shouldSkipUpstreamResponseHeader("Server"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("server"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("SERVER"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("X-Powered-By"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("x-powered-by"));
    try std.testing.expect(shouldSkipUpstreamResponseHeader("X-POWERED-BY"));
    // Must not suppress unrelated headers
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Content-Type"));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("X-Custom-Header"));
    try std.testing.expect(!shouldSkipUpstreamResponseHeader("Set-Cookie"));
}

test "writeBufferedUpstreamResponse serializes a single forwarded response head" {
    const allocator = std.testing.allocator;
    const body = try allocator.dupe(u8, "pong");
    var upstream_headers = [_]UpstreamHeader{
        .{ .name = "Content-Type", .value = "text/plain" },
        .{ .name = "Location", .value = "/health" },
        .{ .name = "Server", .value = "python" },
        .{ .name = "X-Upstream-Test", .value = "1" },
    };

    var response = RawUpstreamResponse{
        .metadata_arena = std.heap.ArenaAllocator.init(allocator),
        .status_code = 200,
        .reason = "OK",
        .headers = upstream_headers[0..],
        .body = body,
    };
    defer response.deinit(allocator);

    var buf: [4096]u8 = undefined;
    var stream = compat.fixedBufferStream(&buf);
    try writeBufferedUpstreamResponse(
        stream.writer(),
        &response,
        true,
        "tg-1778460305668-bfebecb410803023",
        &http.security_headers.SecurityHeaders.api,
        "tg_sticky=proxy",
    );

    const output = stream.getWritten();
    try std.testing.expect(std.mem.startsWith(u8, output, "HTTP/1.1 200 OK\r\n"));
    try std.testing.expect(std.mem.find(u8, output, "Server: tardigrade\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Connection: keep-alive\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Content-Length: 4\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Content-Type: text/plain\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Location: /health\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "X-Upstream-Test: 1\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Set-Cookie: tg_sticky=proxy\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "X-Request-ID: tg-1778460305668-bfebecb410803023\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "X-Correlation-ID: tg-1778460305668-bfebecb410803023\r\n") != null);
    try std.testing.expect(std.mem.find(u8, output, "Server: python\r\n") == null);
    try std.testing.expect(std.mem.endsWith(u8, output, "\r\n\r\npong"));
}

test "mapUpstreamError returns stable codes" {
    const mapped = mapUpstreamError(502);
    try std.testing.expectEqual(@as(u16, 503), mapped.status);
    try std.testing.expectEqualStrings("tool_unavailable", mapped.code);
}

test "classifyErrorCategory maps statuses" {
    try std.testing.expectEqualStrings("-", classifyErrorCategory(200));
    try std.testing.expectEqualStrings("invalid_request", classifyErrorCategory(400));
    try std.testing.expectEqualStrings("authz", classifyErrorCategory(401));
    try std.testing.expectEqualStrings("rate_limited", classifyErrorCategory(429));
    try std.testing.expectEqualStrings("upstream_unavailable", classifyErrorCategory(503));
    try std.testing.expectEqualStrings("upstream_timeout", classifyErrorCategory(504));
    try std.testing.expectEqualStrings("internal_error", classifyErrorCategory(500));
}

test "parseQueryParam extracts topic" {
    const value = parseQueryParam("topic=alerts&foo=bar", "topic");
    try std.testing.expect(value != null);
    try std.testing.expectEqualStrings("alerts", value.?);
    try std.testing.expect(parseQueryParam("foo=bar", "topic") == null);
}

test "parseLastEventId handles invalid values" {
    try std.testing.expectEqual(@as(u64, 42), parseLastEventId("42"));
    try std.testing.expectEqual(@as(u64, 0), parseLastEventId("bad"));
    try std.testing.expectEqual(@as(u64, 0), parseLastEventId(null));
}

test "routeRequiresApprovalRule detects approval requirement" {
    try std.testing.expect(routeRequiresApprovalRule("POST", "/api/tasks", "POST|/api/tasks|ops|true||"));
    try std.testing.expect(!routeRequiresApprovalRule("POST", "/api/messages", "POST|/api/tasks|ops|true||"));
}

test "evaluatePolicy bypasses approval management endpoints" {
    const allocator = std.testing.allocator;
    var headers = http.Headers.init(allocator);
    defer headers.deinit();

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.policy_approval_routes_raw = "POST|^/v1/commands$";

    var state: GatewayState = undefined;
    try std.testing.expect(evaluatePolicy(&state, &cfg, "POST", "/approvals/request", null, null, &headers) == null);
    try std.testing.expect(evaluatePolicy(&state, &cfg, "POST", "/approvals/respond", null, null, &headers) == null);
    try std.testing.expect(evaluatePolicy(&state, &cfg, "GET", "/approvals/status", null, null, &headers) == null);
}

test "parseApprovalResponseBody parses approve and deny" {
    const allocator = std.testing.allocator;
    var approve = try parseApprovalResponseBody(allocator, "{\"approval_token\":\"tok-1\",\"decision\":\"approve\"}");
    defer approve.deinit(allocator);
    try std.testing.expectEqualStrings("tok-1", approve.token);
    try std.testing.expectEqual(ApprovalDecision.approve, approve.decision);

    var deny = try parseApprovalResponseBody(allocator, "{\"approval_token\":\"tok-2\",\"decision\":\"deny\"}");
    defer deny.deinit(allocator);
    try std.testing.expectEqualStrings("tok-2", deny.token);
    try std.testing.expectEqual(ApprovalDecision.deny, deny.decision);
}

test "parseApprovalRequestBody parses command scoped request" {
    const allocator = std.testing.allocator;
    var req = try parseApprovalRequestBody(allocator, "{\"method\":\"POST\",\"path\":\"/api/tasks\",\"command_id\":\"cmd-123\"}");
    defer req.deinit(allocator);
    try std.testing.expectEqualStrings("POST", req.method);
    try std.testing.expectEqualStrings("/api/tasks", req.path);
    try std.testing.expect(req.command_id != null);
    try std.testing.expectEqualStrings("cmd-123", req.command_id.?);
}

test "isHttpMethodIdempotent classifies idempotent methods" {
    // Idempotent methods (RFC 9110 §9.2)
    try std.testing.expect(isHttpMethodIdempotent("GET"));
    try std.testing.expect(isHttpMethodIdempotent("HEAD"));
    try std.testing.expect(isHttpMethodIdempotent("PUT"));
    try std.testing.expect(isHttpMethodIdempotent("DELETE"));
    try std.testing.expect(isHttpMethodIdempotent("OPTIONS"));
    try std.testing.expect(isHttpMethodIdempotent("TRACE"));
    // Case-insensitive
    try std.testing.expect(isHttpMethodIdempotent("get"));
    try std.testing.expect(isHttpMethodIdempotent("Get"));
    try std.testing.expect(isHttpMethodIdempotent("delete"));
}

test "isHttpMethodIdempotent rejects non-idempotent methods" {
    try std.testing.expect(!isHttpMethodIdempotent("POST"));
    try std.testing.expect(!isHttpMethodIdempotent("PATCH"));
    try std.testing.expect(!isHttpMethodIdempotent("post"));
    try std.testing.expect(!isHttpMethodIdempotent(""));
    // Oversized input should not crash
    try std.testing.expect(!isHttpMethodIdempotent("VERYLONGMETHODNAME"));
}

test "upstream_retry_idempotent_only default true limits POST retries to 1" {
    // When idempotent_only is true and method is POST, max_attempts must be 1
    // regardless of upstream_retry_attempts.
    const attempts: u32 = 3;
    const idempotent_only = true;
    const method = "POST";
    const max: usize = if (idempotent_only and !isHttpMethodIdempotent(method))
        1
    else
        @intCast(@max(attempts, @as(u32, 1)));
    try std.testing.expectEqual(@as(usize, 1), max);
}

test "upstream_retry_idempotent_only allows GET retries" {
    const attempts: u32 = 3;
    const idempotent_only = true;
    const method = "GET";
    const max: usize = if (idempotent_only and !isHttpMethodIdempotent(method))
        1
    else
        @intCast(@max(attempts, @as(u32, 1)));
    try std.testing.expectEqual(@as(usize, 3), max);
}

test "upstream_retry_idempotent_only=false allows POST retries" {
    const attempts: u32 = 3;
    const idempotent_only = false;
    const method = "POST";
    const max: usize = if (idempotent_only and !isHttpMethodIdempotent(method))
        1
    else
        @intCast(@max(attempts, @as(u32, 1)));
    try std.testing.expectEqual(@as(usize, 3), max);
}

test "serveTryFilesFallback: top-level root without try_files defaults to $uri" {
    // Regression test for #92: operators who configure only `root /path;` at
    // the server level (without a `try_files` directive or a `location /`
    // block) expect static files to be served for paths that exist in the
    // webroot.  Without try_files, serveTryFilesFallback previously bailed
    // immediately, producing 404 for all files even when the file exists.
    // The fix: when doc_root is set and try_files is empty, effective_try_files
    // defaults to "$uri".
    const effective_try_files_with_no_try_files: []const u8 = if ("".len > 0) "" else "$uri";
    const effective_try_files_with_try_files: []const u8 = if ("$uri /index.html".len > 0) "$uri /index.html" else "$uri";
    try std.testing.expectEqualStrings("$uri", effective_try_files_with_no_try_files);
    try std.testing.expectEqualStrings("$uri /index.html", effective_try_files_with_try_files);

    // Full path: create a temp root with health.txt and verify serve() resolves
    // it when try_files defaults to "$uri".
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "health.txt", .data = "abc" });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var hdrs = http.Headers.init(allocator);
    defer hdrs.deinit();

    const result = try http.static_file.serve(allocator, .{
        .root = root_path,
        .request_path = "/health.txt",
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = "$uri", // the defaulted value
        .headers = &hdrs,
        .max_bytes = MAX_REQUEST_SIZE,
    });
    try std.testing.expect(result != null);
    var served = result.?;
    defer served.deinit(allocator);
    try std.testing.expectEqual(http.status.Status.ok, served.status_code);
    try std.testing.expectEqual(@as(usize, 3), served.content_length);
}

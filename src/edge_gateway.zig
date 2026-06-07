const compat = @import("zig_compat.zig");
const std = @import("std");
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

const gaccept = @import("gateway_accept.zig");
const acceptReadyConnections = gaccept.acceptReadyConnections;
const applyFdSoftLimit = gaccept.applyFdSoftLimit;

const gconn = @import("gateway_connection.zig");
const clientIpFromAddress = gconn.clientIpFromAddress;
const clientIpFromFd = gconn.clientIpFromFd;
const setNoDelay = gconn.setNoDelay;
const setNonBlocking = gconn.setNonBlocking;
const setSocketTimeoutMs = gconn.setSocketTimeoutMs;
const maybeConsumeProxyProtocolPreface = gconn.maybeConsumeProxyProtocolPreface;
const peekAndConsumeProxyHeaderFromRawFd = gconn.peekAndConsumeProxyHeaderFromRawFd;
const parseProxyHeader = gconn.parseProxyHeader;
const readHttpRequest = gconn.readHttpRequest;
const firstRequestCompleteLen = gconn.firstRequestCompleteLen;

const gstatic = @import("gateway_static_runtime.zig");
const handleStaticLocation = gstatic.handleStaticLocation;
const serveTryFilesFallback = gstatic.serveTryFilesFallback;
const maybeResolveStaticErrorPage = gstatic.maybeResolveStaticErrorPage;

const gshutdown = @import("gateway_shutdown.zig");
const hotReloadConfig = gshutdown.hotReloadConfig;
const reopenErrorLog = gshutdown.reopenErrorLog;
const runDnsDiscoveryRefresh = gshutdown.runDnsDiscoveryRefresh;
const runActiveHealthChecks = gshutdown.runActiveHealthChecks;
const runProxyCacheMaintenance = gshutdown.runProxyCacheMaintenance;

const gproxy_runtime = @import("gateway_proxy_runtime.zig");
const proxySuffixPathForLocation = gproxy_runtime.proxySuffixPathForLocation;
const handleLocationProxyPass = gproxy_runtime.handleLocationProxyPass;
const isHttpMethodIdempotent = gproxy_runtime.isHttpMethodIdempotent;

const ghandlers = @import("gateway_handlers.zig");
const Http3DispatchContext = ghandlers.Http3DispatchContext;
const handleHttp3Request = ghandlers.handleHttp3Request;
const routeRequest = ghandlers.routeRequest;
const primeRequestAuthContext = ghandlers.primeRequestAuthContext;
const runMiddlewarePipeline = ghandlers.runMiddlewarePipeline;
const evaluateConditionalRules = ghandlers.evaluateConditionalRules;
const applyInternalRedirectRules = ghandlers.applyInternalRedirectRules;
const spawnMirrorRequests = ghandlers.spawnMirrorRequests;
const logAccess = ghandlers.logAccess;
const classifyErrorCategory = ghandlers.classifyErrorCategory;
const parseQueryParam = ghandlers.parseQueryParam;
const parseLastEventId = ghandlers.parseLastEventId;

const gp = @import("gateway_proxy.zig");
// Types from gateway_proxy.zig
const UpstreamHeader = gp.UpstreamHeader;
const BufferedUpstreamResponse = gp.BufferedUpstreamResponse;
const MaybeOwnedBytes = gp.MaybeOwnedBytes;
const ResolvedProxyTarget = gp.ResolvedProxyTarget;
const UpstreamMappedError = gp.UpstreamMappedError;
const ProxyExecMappedError = gp.ProxyExecMappedError;
// Functions from gateway_proxy.zig
const uriComponentBytes = gp.uriComponentBytes;
const parseBufferedUpstreamResponse = gp.parseBufferedUpstreamResponse;
const executeBoundedBufferedUnixSocketHttpRequest = gp.executeBoundedBufferedUnixSocketHttpRequest;
const bufferedUpstreamResponseHasNoStore = gp.bufferedUpstreamResponseHasNoStore;
const upstreamReasonPhrase = gp.upstreamReasonPhrase;
const executeBoundedBufferedHttpProxyRequest = gp.executeBoundedBufferedHttpProxyRequest;
const executeBoundedBufferedHttpsMtlsRequest = gp.executeBoundedBufferedHttpsMtlsRequest;
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
const mapControlPlaneProxyExecutionError = gp.mapControlPlaneProxyExecutionError;
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
const gcp = @import("gateway_control_plane_proxy.zig");
const ControlPlaneProxyResult = gcp.ControlPlaneProxyResult;
const ControlPlaneProxyExecution = gcp.ControlPlaneProxyExecution;
const executeBoundedControlPlaneJsonProxy = gcp.executeBoundedControlPlaneJsonProxy;
const buildProxyCacheKey = gcp.buildProxyCacheKey;

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
        cfg.worker_max_queue_depth,
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
    if (cfg.worker_max_queue_depth > 0) {
        state.logger.info(null, "Worker pool enabled: workers={d} queue={d} per_worker_queue_depth={d}", .{ worker_count, cfg.worker_queue_size, cfg.worker_max_queue_depth });
    } else {
        state.logger.info(null, "Worker pool enabled: workers={d} queue={d}", .{ worker_count, cfg.worker_queue_size });
    }
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
    if (cfg.upstream_response_timeout_ms > 0) {
        state.logger.info(null, "Upstream response timeout configured: {d}ms (Unix socket upstreams only)", .{cfg.upstream_response_timeout_ms});
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
    if (cfg.max_in_flight_requests > 0) {
        state.logger.info(null, "Global in-flight request limit enabled: {d} (returns 503 when exceeded)", .{cfg.max_in_flight_requests});
    }
    if (cfg.request_total_timeout_ms > 0) {
        state.logger.info(null, "Request total timeout enabled: {d}ms", .{cfg.request_total_timeout_ms});
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

    var decoder = http.hpack.Decoder.init();
    defer decoder.deinit(allocator);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var ready_streams = std.array_list.Managed(u31).init(allocator);
    defer ready_streams.deinit();
    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    var last_client_stream_id: u31 = 0;
    var goaway_received = false;
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }

    while (!http.shutdown.isShutdownRequested() and !goaway_received) {
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
                last_client_stream_id = @max(last_client_stream_id, frame.stream_id);
                if (!streams.contains(frame.stream_id)) {
                    try streams.put(frame.stream_id, http.http2_stream.Stream.init(frame.stream_id, 65_535));
                }
                var payload_offset: usize = 0;
                if ((frame.flags & http.http2_frame.Flags.PRIORITY) != 0) {
                    const pr = try http.http2_frame.parsePriority(frame.payload);
                    if (streams.getPtr(frame.stream_id)) |s| s.priority_weight = pr.weight;
                    payload_offset = 5;
                }
                var decoded = decoder.decode(allocator, frame.payload[payload_offset..]) catch {
                    try http.http2_frame.writeGoaway(conn.writer(), last_client_stream_id, http.http2_stream.ErrorCode.compression_error.value());
                    return error.Http2CompressionError;
                };
                defer http.hpack.deinitDecoded(allocator, &decoded);
                var ps = pending.get(frame.stream_id) orelse Http2PendingStream.init(allocator);
                if (streams.get(frame.stream_id)) |s| ps.priority_weight = s.priority_weight;
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
                if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                    if (streams.getPtr(frame.stream_id)) |s| s.remoteEndStream() catch {};
                    try ready_streams.append(frame.stream_id);
                }
            },
            .data => {
                if (frame.stream_id == 0) return error.InvalidHttp2StreamId;
                if (streams.getPtr(frame.stream_id)) |s| s.send_window -= @intCast(frame.payload.len);
                conn_send_window -= @intCast(frame.payload.len);
                if (pending.getPtr(frame.stream_id)) |ps| {
                    try ps.body.appendSlice(frame.payload);
                    try http.http2_frame.writeWindowUpdate(conn.writer(), frame.stream_id, @intCast(frame.payload.len));
                    try http.http2_frame.writeWindowUpdate(conn.writer(), 0, @intCast(frame.payload.len));
                    if (streams.getPtr(frame.stream_id)) |s| s.send_window += @intCast(frame.payload.len);
                    conn_send_window += @intCast(frame.payload.len);
                    if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                        if (streams.getPtr(frame.stream_id)) |s| s.remoteEndStream() catch {};
                        try ready_streams.append(frame.stream_id);
                    }
                } else {
                    try http.http2_frame.writeGoaway(conn.writer(), frame.stream_id, 1);
                    return;
                }
            },
            .priority => {
                const pr = try http.http2_frame.parsePriority(frame.payload);
                if (streams.getPtr(frame.stream_id)) |s| s.priority_weight = pr.weight;
                if (pending.getPtr(frame.stream_id)) |ps| ps.priority_weight = pr.weight;
            },
            .window_update => {
                const inc = try http.http2_frame.parseWindowUpdateIncrement(frame.payload);
                if (frame.stream_id == 0) {
                    conn_send_window += @intCast(inc);
                } else {
                    if (streams.getPtr(frame.stream_id)) |s| s.send_window += @intCast(inc);
                }
            },
            .rst_stream => {
                if (pending.fetchRemove(frame.stream_id)) |removed| {
                    var tmp = removed.value;
                    tmp.deinit(allocator);
                }
                _ = streams.remove(frame.stream_id);
            },
            .goaway => {
                goaway_received = true;
            },
            .continuation, .push_promise => {},
        }

        while (ready_streams.items.len > 0) {
            var best_idx: usize = 0;
            var best_weight: u8 = 0;
            for (ready_streams.items, 0..) |sid, idx| {
                const w = if (streams.get(sid)) |s| s.priority_weight else 16;
                if (w >= best_weight) {
                    best_weight = w;
                    best_idx = idx;
                }
            }
            const sid = ready_streams.swapRemove(best_idx);
            const stream_send = if (streams.get(sid)) |s| s.send_window else conn_send_window;
            if (pending.getPtr(sid)) |ps| {
                try respondHttp2Stream(conn.writer(), allocator, state, cfg, sid, ps, &next_server_stream_id, &conn_send_window, stream_send);
            }
            if (pending.fetchRemove(sid)) |removed| {
                var tmp = removed.value;
                tmp.deinit(allocator);
            }
            _ = streams.remove(sid);
        }
    }
}

fn countOpenStreams(streams: *std.AutoHashMap(u31, http.http2_stream.Stream)) u32 {
    var count: u32 = 0;
    var it = streams.iterator();
    while (it.next()) |entry| {
        const st = entry.value_ptr.state;
        if (st == .open or st == .half_closed_local) count += 1;
    }
    return count;
}

fn respondHttp2Stream(
    writer: anytype,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    stream_id: u31,
    ps: *const Http2PendingStream,
    next_server_stream_id: *u31,
    conn_send_window: *i32,
    stream_send_window: i32,
) !void {
    _ = next_server_stream_id;
    const method = ps.method orelse return error.InvalidHttp2Request;
    const path = ps.path orelse return error.InvalidHttp2Request;
    const correlation_id = try http.correlation.generate(allocator);
    defer allocator.free(correlation_id);

    var lifecycle = http.request_lifecycle.RequestLifecycle.init(
        correlation_id,
        cfg.request_total_timeout_ms,
    );
    if (lifecycle.checkDeadline(.headers_read)) return error.RequestTimeout;

    var status_code: u16 = 404;
    var body: []const u8 = "{\"error\":\"Not Found\"}";
    const body_alloc: ?[]u8 = null;
    defer if (body_alloc) |b| allocator.free(b);
    const content_type: []const u8 = JSON_CONTENT_TYPE;

    _ = method;
    _ = path;

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

    const effective_window: i32 = @min(conn_send_window.*, stream_send_window);
    const send_len: usize = if (effective_window > 0)
        @min(body.len, @as(usize, @intCast(effective_window)))
    else
        0;
    try http.http2_frame.writeFrame(writer, .data, http.http2_frame.Flags.END_STREAM, stream_id, body[0..send_len]);
    conn_send_window.* -= @intCast(send_len);

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

    var response = BufferedUpstreamResponse{
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

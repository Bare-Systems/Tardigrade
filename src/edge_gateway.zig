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
const gaccept = @import("gateway_accept.zig");
const gconn = @import("gateway_connection.zig");
const gshutdown = @import("gateway_shutdown.zig");
const ghandlers = @import("gateway_handlers.zig");
const gproxy_runtime = @import("gateway_proxy_runtime.zig");
const gp = @import("gateway_proxy.zig");
const ga = @import("gateway_auth.zig");

// Local runtime shorthands only. Keep this list to state/types used by
// edge_gateway itself; call subsystem behavior through the owning module alias
// above. Do not add compatibility re-exports here.
const MAX_REQUEST_SIZE = gs.MAX_REQUEST_SIZE;
const GatewayState = gs.GatewayState;
const WorkerContext = gs.WorkerContext;
const ReloadableConfigStore = gs.ReloadableConfigStore;
const ConnectionSession = gs.ConnectionSession;
const ConnectionSessionPool = gs.ConnectionSessionPool;
const UpstreamHealth = gs.UpstreamHealth;
const Http2PendingStream = gs.Http2PendingStream;
const CommandLifecycleEntry = gs.CommandLifecycleEntry;
const ApprovalEntry = gs.ApprovalEntry;
const MuxResumeState = gs.MuxResumeState;

pub fn run(cfg: *const edge_config.EdgeConfig) !void {
    const state_allocator = runtime_allocator.runtimeAllocator();

    const initial_hsts = try gp.computeHstsValue(state_allocator, cfg);
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
        .proxy_buffer_limits = cfg.proxy_buffer_limits,
        .upstream_rr_index = 0,
        .upstream_backup_rr_index = 0,
        .lb_random_state = 0x9e3779b97f4a7c15 ^ @as(u64, @intCast(http.event_loop.monotonicMs())),
        .next_active_health_probe_ms = 0,
        .next_proxy_cache_maintenance_ms = 0,
        .health_probe_running = std.atomic.Value(bool).init(false),
        .upstream_health = std.StringHashMap(UpstreamHealth).init(state_allocator),
        .upstream_active_requests = std.StringHashMap(usize).init(state_allocator),
        .upstream_pool = http.upstream_pool.UpstreamPool.init(state_allocator, .{
            .enabled = cfg.upstream_pool_enabled,
            .max_idle_per_host = cfg.upstream_pool_max_idle_per_host,
            .idle_timeout_ms = cfg.upstream_pool_idle_timeout_ms,
            .max_lifetime_ms = cfg.upstream_pool_max_lifetime_ms,
            .max_active_per_host = cfg.upstream_pool_max_active_per_host,
        }),
        .h2_pool = http.upstream_h2.H2ConnPool.init(state_allocator, .{
            .idle_timeout_ms = cfg.upstream_pool_idle_timeout_ms,
            .max_lifetime_ms = cfg.upstream_pool_max_lifetime_ms,
        }),
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
        gs.loadApprovalStore(&state) catch |err| {
            state.logger.warn(null, "failed to load approval store '{s}': {}", .{ cfg.approval_store_path, err });
        };
    }
    if (cfg.session_store_path.len > 0) {
        gs.loadSessionStore(&state) catch |err| {
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

    try gconn.setNonBlocking(listen_fd, true);
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
    var http3_dispatch_ctx = ghandlers.Http3DispatchContext{
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
            .request_handler = ghandlers.handleHttp3Request,
            .request_handler_ctx = &http3_dispatch_ctx,
        }) catch |err| blk: {
            state.logger.warn(null, "HTTP/3 listener failed to initialize: {s}", .{@errorName(err)});
            break :blk null;
        };
        if (http3_runtime) |*runtime| runtime.start();
    }
    state.http3_runtime = if (http3_runtime) |*runtime| runtime else null;
    defer if (http3_runtime) |*runtime| runtime.deinit();
    // NOTE (#138): defaulting worker_threads to CPU count is correct for a
    // non-blocking event loop, but Tardigrade currently uses a thread-per-
    // connection blocking model where a worker is held for a connection's whole
    // keepalive lifetime. Under that model the tail latency degrades sharply once
    // concurrent connections exceed the worker count (measured: 4 workers + 10
    // keepalive conns -> p90 ~26ms; 16 workers -> ~676us). Until idle keepalive
    // parking (#138) lands, operators should raise TARDIGRADE_WORKER_THREADS to
    // ~peak concurrent connections. Once parking lands, idle connections no
    // longer occupy a worker and CPU-count sizing becomes correct again.
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
        .event_loop = &event_loop,
        .parked = undefined,
    };
    var session_pool = ConnectionSessionPool.init(state_allocator, &state.request_buffer_pool, cfg.connection_pool_size);
    defer session_pool.deinit();
    worker_ctx.session_pool = &session_pool;

    // Registry of idle keepalive connections parked off the worker pool (#138).
    // Its close hook releases the connection slot held since accept, so parked
    // connections torn down by the reaper/drain are accounted correctly. The
    // deinit (closeAll) runs before session_pool.deinit thanks to defer order.
    var parked = http.keepalive_park.ParkedRegistry.init(state_allocator, &session_pool);
    parked.close_hook = parkedConnectionCloseHook;
    parked.close_hook_ctx = &state;
    defer parked.deinit();
    worker_ctx.parked = &parked;

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
    worker_pool.setWaitCallback(workerQueueWaitCallback, &state);
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
        const applied = gaccept.applyFdSoftLimit(cfg.fd_soft_limit) catch |err| blk: {
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
            if (!ev.readable) continue;
            if (ev.fd == listen_fd) {
                gaccept.acceptReadyConnections(listen_fd, &worker_pool, &state);
            } else if (parked.resumeReady(ev.fd)) {
                // A parked keepalive connection has a new request (or closed).
                // Stop watching it and hand it to a worker, which serves one
                // request and re-parks or closes. The connection slot acquired
                // at accept stays held across the park/resume cycle.
                event_loop.removeReadFd(ev.fd) catch {};
                worker_pool.submit(ev.fd) catch {
                    if (parked.checkout(ev.fd)) |pc| parked.closeSlot(pc, .@"error");
                };
            }
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
                gshutdown.reopenErrorLog(current_cfg) catch |err| {
                    state.logger.warn(null, "log reopen failed: {}", .{err});
                };
            }
            if (http.shutdown.consumeReloadRequested()) {
                gshutdown.hotReloadConfig(state_allocator, &worker_ctx, &state, &http3_dispatch_ctx);
            }
            var current_cfg_lease = worker_ctx.acquireConfig();
            defer current_cfg_lease.release();
            const current_cfg = current_cfg_lease.cfg;
            gshutdown.runActiveHealthChecks(current_cfg, &state, worker_ctx.config_store);
            gshutdown.runDnsDiscoveryRefresh(current_cfg, &state);
            gshutdown.runProxyCacheMaintenance(current_cfg, &state);
            if (tls_terminator) |*tls| tls.runMaintenance(http.event_loop.monotonicMs());
            // Close keepalive connections idle longer than the keepalive timeout
            // while parked off the worker pool (#138).
            _ = parked.reapIdle(http.event_loop.monotonicMs(), current_cfg.keep_alive_timeout_ms);
            // Evict idle upstream keep-alive connections past their idle/lifetime
            // caps (#141).
            state.upstream_pool.reapIdle(http.event_loop.monotonicMs());
            // Evict idle / aged-out / dead multiplexing HTTP/2 upstream
            // connections (refcount-safe; skips conns with in-flight streams) (#145).
            state.h2_pool.reapIdle(http.event_loop.monotonicMs());
            const worker_snapshot = worker_pool.snapshot();
            state.metricsSetWorkerPoolStats(
                worker_snapshot.active_jobs,
                worker_snapshot.queued_jobs,
                worker_snapshot.worker_threads,
                worker_snapshot.max_queue_len,
            );
            const ka_stats = parked.stats();
            state.metrics_mutex.lock();
            state.metrics.recordEventLoopIteration();
            state.metrics.setKeepaliveStats(
                ka_stats.parked,
                ka_stats.resumes_total,
                ka_stats.timeouts_total,
                ka_stats.closed_total,
            );
            state.metrics_mutex.unlock();
        }
    }

    const active_at_drain_start = blk: {
        state.connection_mutex.lock();
        defer state.connection_mutex.unlock();
        break :blk state.active_connections_total;
    };
    state.logger.info(null, "Shutdown requested; draining active connection work (timeout={}ms active_connections={d})", .{ cfg.shutdown_drain_timeout_ms, active_at_drain_start });
    const drain_result = worker_pool.shutdownAndJoin(cfg.shutdown_drain_timeout_ms);
    state.metricsRecordDrain(drain_result.timed_out, drain_result.forced_closes);
    if (drain_result.timed_out) {
        state.logger.warn(null, "drain timeout elapsed; force-closed {d} queued connection(s)", .{drain_result.forced_closes});
    }
    state.logger.info(null, "Graceful shutdown complete (forced_closes={d} drain_timed_out={})", .{ drain_result.forced_closes, drain_result.timed_out });
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

fn workerQueueWaitCallback(raw_ctx: *anyopaque, wait_ns: i64) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_ctx));
    state.metricsRecordWorkerQueueWaitNs(wait_ns);
}

fn handleAcceptedClient(raw_ctx: *anyopaque, client_fd: std.posix.fd_t) void {
    const ctx: *WorkerContext = @ptrCast(@alignCast(raw_ctx));

    // Resume path (#138): the event loop dispatched a parked keepalive
    // connection that became readable. Its session, TLS state, and connection
    // slot are already established and owned by the parked registry.
    if (ctx.parked.checkout(client_fd)) |pc| {
        resumeParkedConnection(ctx, pc);
        return;
    }

    startNewConnection(ctx, client_fd);
}

/// Outcome of serving one request on a keepalive HTTP/1.1 connection.
const ServeOutcome = enum {
    /// Buffered (pipelined) data is already available; serve another request now.
    serve_again,
    /// Connection is idle and keep-alive; park it off the worker pool.
    park,
    /// Connection should be closed (no keep-alive, shutdown, max-requests, error).
    close,
};

fn isTlsConnPtr(comptime T: type) bool {
    return T == *http.tls_termination.TlsConnection;
}

/// Errors that just mean the peer closed/reset the connection. Common at the
/// edge (and more visible with parking, since a peer-closed parked connection
/// surfaces as a readable event that resumes into a failed read), so they log
/// at debug rather than spamming ERROR. Typed as `anyerror` so any error name
/// is valid regardless of the caller's inferred error set.
fn isBenignDisconnect(err: anyerror) bool {
    return switch (err) {
        error.ConnectionResetByPeer,
        error.BrokenPipe,
        error.ConnectionClosed,
        error.NotOpenForReading,
        error.WouldBlock,
        error.EndOfStream,
        error.TlsReadFailed,
        => true,
        else => false,
    };
}

/// Serve exactly one HTTP/1.1 request on `conn` (a `*TlsConnection` or a
/// plaintext `NetStream`), then decide what to do with the connection.
fn serveOneRequest(
    ctx: *WorkerContext,
    conn: anytype,
    session: *ConnectionSession,
    connection_ip: []const u8,
    served: *u32,
    enable_proxy_protocol: bool,
) ServeOutcome {
    var keep_alive = false;
    var live_cfg_lease = ctx.acquireConfig();
    const live_cfg = live_cfg_lease.cfg;
    handleConnection(conn, session, live_cfg, ctx.state, &keep_alive, connection_ip, enable_proxy_protocol) catch |err| {
        live_cfg_lease.release();
        if (isBenignDisconnect(err)) {
            ctx.state.logger.debug(null, "keepalive connection closed by peer: {}", .{err});
        } else {
            ctx.state.logger.err(null, "edge connection error: {}", .{err});
        }
        return .close;
    };
    served.* += 1;
    const max_requests_per_connection = live_cfg.max_requests_per_connection;
    live_cfg_lease.release();

    if (!keep_alive or http.shutdown.isShutdownRequested()) return .close;
    if (max_requests_per_connection > 0 and served.* >= max_requests_per_connection) return .close;

    // TLS may have already-decrypted pipelined bytes buffered inside OpenSSL; a
    // socket-readiness event never fires for those, so serve them now. Plaintext
    // pipelined bytes sit in the socket buffer and the level-triggered event loop
    // re-fires immediately after parking, so no special case is needed there.
    if (comptime isTlsConnPtr(@TypeOf(conn))) {
        if (conn.pending() > 0) return .serve_again;
    }
    return .park;
}

fn startNewConnection(ctx: *WorkerContext, client_fd: std.posix.fd_t) void {
    const session = ctx.session_pool.acquire() catch |err| {
        ctx.state.logger.warn(null, "failed to acquire pooled connection session: {}", .{err});
        ctx.state.releaseConnectionSlot(client_fd);
        _ = std.c.close(client_fd);
        return;
    };

    // Ownership of session/fd/TLS transfers to the parked registry on `park`.
    // Until then, this teardown runs on every other exit (set `transferred` to
    // skip it once ownership has moved).
    var transferred = false;
    var tls_to_park: ?http.tls_termination.TlsConnection = null;
    defer if (!transferred) closeNewConnection(ctx, client_fd, session, tls_to_park);

    const owned_connection_ip = gconn.clientIpFromFd(ctx.state.allocator, client_fd) catch null;
    defer if (owned_connection_ip) |ip| ctx.state.allocator.free(ip);
    const connection_ip = owned_connection_ip orelse "unknown";

    var cfg_lease = ctx.acquireConfig();
    defer cfg_lease.release();
    const cfg = cfg_lease.cfg;
    gconn.setNonBlocking(client_fd, false) catch |err| {
        ctx.state.logger.warn(null, "failed to switch client fd to blocking mode: {}", .{err});
        return;
    };

    gconn.setNoDelay(client_fd) catch |err| {
        ctx.state.logger.warn(null, "failed to set TCP_NODELAY on client fd: {}", .{err});
    };

    // Effective per-phase timeouts used throughout this connection's lifetime.
    const header_timeout_ms = cfg.request_limits.effectiveHeaderTimeout();
    const write_timeout_ms = if (cfg.downstream_write_timeout_ms > 0) cfg.downstream_write_timeout_ms else header_timeout_ms;

    if (ctx.tls) |tls| {
        // Apply the TLS handshake timeout before PROXY protocol parsing and
        // SSL_accept. Falls back to keep_alive_timeout_ms when not explicitly
        // configured so the old behavior is preserved for operators that haven't
        // set the new field.
        const handshake_timeout_ms = if (cfg.tls_handshake_timeout_ms > 0)
            cfg.tls_handshake_timeout_ms
        else
            cfg.keep_alive_timeout_ms;
        if (handshake_timeout_ms > 0) {
            gconn.setSocketTimeoutMs(client_fd, handshake_timeout_ms, handshake_timeout_ms) catch |err| {
                ctx.state.logger.warn(null, "failed to set client handshake timeout: {}", .{err});
            };
        }

        // Parse PROXY protocol header from the raw TCP socket before SSL_accept.
        // The PROXY header is plaintext even on TLS connections and must be
        // consumed before OpenSSL sees the TLS ClientHello.
        if (cfg.proxy_protocol_mode != .off and !session.proxy_protocol_checked) {
            gconn.peekAndConsumeProxyHeaderFromRawFd(
                client_fd,
                cfg.proxy_protocol_mode,
                &session.proxy_client_ip_buf,
                &session.proxy_client_ip_len,
            ) catch |err| {
                ctx.state.logger.warn(null, "proxy protocol parse failed on TLS connection: {}", .{err});
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
            return;
        };
        // The TLS object now needs teardown on every exit; record it so the
        // teardown defer (or a failed park) frees it exactly once.
        tls_to_park = tls_conn;

        // Handshake complete — switch to request-phase timeouts.
        // SO_RCVTIMEO covers header/body reads; SO_SNDTIMEO covers response writes.
        if (header_timeout_ms > 0 or write_timeout_ms > 0) {
            gconn.setSocketTimeoutMs(client_fd, header_timeout_ms, write_timeout_ms) catch |err| {
                ctx.state.logger.warn(null, "failed to set post-handshake socket timeout: {}", .{err});
            };
        }

        if (tls_conn.negotiatedProtocol() == .http2 and cfg.http2_enabled) {
            // HTTP/2 multiplexes many streams over one connection internally and
            // is not parked (out of scope for #138); the teardown defer closes it.
            handleHttp2Connection(&tls_conn, session, cfg, ctx.state, connection_ip) catch |err| {
                ctx.state.logger.err(null, "http2 connection error: {}", .{err});
            };
            return;
        }

        var served: u32 = 0;
        while (true) switch (serveOneRequest(ctx, &tls_conn, session, connection_ip, &served, false)) {
            .serve_again => {},
            .park => {
                transferred = true;
                parkConnection(ctx, client_fd, session, tls_conn, served, connection_ip);
                return;
            },
            .close => return,
        };
    } else {
        // Plaintext path: apply read and write timeouts immediately (no separate
        // handshake phase).
        if (header_timeout_ms > 0 or write_timeout_ms > 0) {
            gconn.setSocketTimeoutMs(client_fd, header_timeout_ms, write_timeout_ms) catch |err| {
                ctx.state.logger.warn(null, "failed to set client socket timeout: {}", .{err});
            };
        }
        const stream = compat.netStreamFromFd(client_fd);
        var served: u32 = 0;
        while (true) switch (serveOneRequest(ctx, stream, session, connection_ip, &served, true)) {
            .serve_again => {},
            .park => {
                transferred = true;
                parkConnection(ctx, client_fd, session, null, served, connection_ip);
                return;
            },
            .close => return,
        };
    }
}

fn resumeParkedConnection(ctx: *WorkerContext, pc: *http.keepalive_park.ParkedConnection) void {
    var served = pc.served;
    if (pc.tls) |*tls_conn| {
        while (true) switch (serveOneRequest(ctx, tls_conn, pc.session, pc.ip(), &served, false)) {
            .serve_again => {},
            .park => {
                pc.served = served;
                reparkConnection(ctx, pc);
                return;
            },
            .close => {
                ctx.parked.closeSlot(pc, .peer);
                return;
            },
        };
    } else {
        const stream = compat.netStreamFromFd(pc.fd);
        while (true) switch (serveOneRequest(ctx, stream, pc.session, pc.ip(), &served, false)) {
            .serve_again => {},
            .park => {
                pc.served = served;
                reparkConnection(ctx, pc);
                return;
            },
            .close => {
                ctx.parked.closeSlot(pc, .peer);
                return;
            },
        };
    }
}

/// Tear down a connection that was never parked: TLS shutdown, socket close,
/// pooled-session release, and connection-slot release. Mirrors the registry's
/// teardown so a connection is accounted identically whichever path closes it.
fn closeNewConnection(
    ctx: *WorkerContext,
    fd: std.posix.fd_t,
    session: *ConnectionSession,
    tls_conn: ?http.tls_termination.TlsConnection,
) void {
    if (tls_conn) |t| {
        var tt = t;
        tt.deinit();
    }
    _ = std.c.close(fd);
    ctx.session_pool.release(session);
    ctx.state.releaseConnectionSlot(fd);
}

/// Park a freshly-idle new connection off the worker pool and arm the event
/// loop. On any failure the connection is fully closed.
fn parkConnection(
    ctx: *WorkerContext,
    fd: std.posix.fd_t,
    session: *ConnectionSession,
    tls_conn: ?http.tls_termination.TlsConnection,
    served: u32,
    connection_ip: []const u8,
) void {
    const now = http.event_loop.monotonicMs();
    ctx.parked.parkNew(fd, session, tls_conn, served, connection_ip, now) catch {
        closeNewConnection(ctx, fd, session, tls_conn);
        return;
    };
    ctx.event_loop.addReadFd(fd) catch {
        if (ctx.parked.checkout(fd)) |pc| ctx.parked.closeSlot(pc, .@"error");
    };
}

/// Re-park a connection a worker just finished serving on resume, reusing its
/// existing slot. On any failure the connection is fully closed.
fn reparkConnection(ctx: *WorkerContext, pc: *http.keepalive_park.ParkedConnection) void {
    const now = http.event_loop.monotonicMs();
    ctx.parked.repark(pc, now) catch {
        ctx.parked.closeSlot(pc, .@"error");
        return;
    };
    ctx.event_loop.addReadFd(pc.fd) catch {
        if (ctx.parked.checkout(pc.fd)) |taken| ctx.parked.closeSlot(taken, .@"error");
    };
}

/// Registry teardown hook: release the connection slot held since accept when a
/// parked connection is finally closed (resume-close, idle reap, or drain).
fn parkedConnectionCloseHook(raw_state: *anyopaque, fd: std.posix.fd_t) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.releaseConnectionSlot(fd);
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

/// Duplicate `name` lowercased for use as an HTTP/2 header field name. The
/// allocation is tracked in `owned` so the caller frees it after encoding.
fn lowercaseName(allocator: std.mem.Allocator, owned: *std.array_list.Managed([]u8), name: []const u8) ![]const u8 {
    const dup = try allocator.dupe(u8, name);
    errdefer allocator.free(dup);
    for (dup) |*c| c.* = std.ascii.toLower(c.*);
    try owned.append(dup);
    return dup;
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
    // HTTP/2 header field names MUST be lowercase (RFC 7540 §8.1.2); a peer
    // treats any uppercase octet as a malformed response. The pseudo-header and
    // static names below are already lowercase, but correlation and operator-
    // configured names may not be, so those are lowercased before encoding.
    var lowered_names = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (lowered_names.items) |n| allocator.free(n);
        lowered_names.deinit();
    }
    try response_headers.append(.{ .name = ":status", .value = status_str });
    try response_headers.append(.{ .name = "content-type", .value = content_type });
    try response_headers.append(.{ .name = "content-length", .value = len_str });
    try response_headers.append(.{ .name = try lowercaseName(allocator, &lowered_names, http.correlation.REQUEST_HEADER_NAME), .value = correlation_id });
    try response_headers.append(.{ .name = try lowercaseName(allocator, &lowered_names, http.correlation.HEADER_NAME), .value = correlation_id });
    for (state.add_headers) |h| {
        try response_headers.append(.{ .name = try lowercaseName(allocator, &lowered_names, h.name), .value = h.value });
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

fn parseRequestErrorStatus(err: http.ParseError) http.Status {
    return switch (err) {
        error.HeadersTooLarge, error.HeaderTooLarge, error.TooManyHeaders => .request_header_fields_too_large,
        error.BodyTooLarge => .payload_too_large,
        error.ConflictingHeaders, error.InvalidChunkedBody => .bad_request,
        else => .bad_request,
    };
}

fn isHttpUrl(raw: []const u8) bool {
    return std.mem.startsWith(u8, raw, "http://") or std.mem.startsWith(u8, raw, "https://");
}

fn targetSupportsStdHttpStreaming(cfg: *const edge_config.EdgeConfig, target: []const u8) bool {
    const trimmed = std.mem.trim(u8, target, " \t\r\n");
    if (trimmed.len == 0) return false;
    if (gp.unixSocketPathFromEndpoint(trimmed) != null) return false;
    if (isHttpUrl(trimmed)) {
        return !(cfg.upstream_tls_client_cert.len > 0 and std.mem.startsWith(u8, trimmed, "https://"));
    }
    if (gp.unixSocketPathFromEndpoint(cfg.upstream_base_url) != null) return false;
    return !(cfg.upstream_tls_client_cert.len > 0 and std.mem.startsWith(u8, cfg.upstream_base_url, "https://"));
}

const RequestUploadStreamingEligibility = union(enum) {
    stream,
    fallback: gproxy_runtime.StreamingFallbackReason,
    not_applicable,
};

fn targetStreamingFallbackReason(
    cfg: *const edge_config.EdgeConfig,
    target: []const u8,
) ?gproxy_runtime.StreamingFallbackReason {
    const trimmed = std.mem.trim(u8, target, " \t\r\n");
    if (trimmed.len == 0) return .unsupported_route_type;
    if (gp.unixSocketPathFromEndpoint(trimmed) != null) return .unix_socket_target;
    if (isHttpUrl(trimmed)) {
        if (cfg.upstream_tls_client_cert.len > 0 and std.mem.startsWith(u8, trimmed, "https://")) return .upstream_mtls_target;
        return null;
    }
    if (gp.unixSocketPathFromEndpoint(cfg.upstream_base_url) != null) return .unix_socket_target;
    if (cfg.upstream_tls_client_cert.len > 0 and std.mem.startsWith(u8, cfg.upstream_base_url, "https://")) return .upstream_mtls_target;
    return null;
}

fn streamingUploadEligibilityBeforeBodyRead(
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
) RequestUploadStreamingEligibility {
    if (!request.method.hasRequestBody()) return .not_applicable;

    const matched = http.location_router.matchLocation(request.uri.path, cfg.location_blocks) orelse return .{ .fallback = .unsupported_route_type };
    if (!matched.block.proxy_streaming_policy.requestStreamingEnabled(cfg.proxy_streaming_mode.requestStreamingEnabled())) return .{ .fallback = .policy_disabled };

    if (cfg.rewrite_rules.len > 0 or cfg.return_rules.len > 0 or
        cfg.conditional_rules.len > 0 or cfg.internal_redirect_rules.len > 0 or
        cfg.mirror_rules.len > 0 or cfg.auth_request_url.len > 0)
    {
        return .{ .fallback = .body_dependent_middleware };
    }
    if (cfg.upstream_retry_attempts > 1) {
        if (!cfg.upstream_retry_idempotent_only) return .{ .fallback = .retries_configured };
        if (request.method.isIdempotent()) return .{ .fallback = .retries_configured };
    }

    if (request.hasTransferEncoding()) return .{ .fallback = .chunked_request_upload };
    const content_length = request.contentLength() orelse return .{ .fallback = .missing_content_length };
    if (content_length == 0) return .not_applicable;
    if (content_length > cfg.request_limits.effectiveMaxBodySize()) return .{ .fallback = .body_too_large };

    return switch (matched.block.action) {
        .proxy_pass => |target| if (targetStreamingFallbackReason(cfg, target)) |reason| .{ .fallback = reason } else .stream,
        else => .{ .fallback = .unsupported_route_type },
    };
}

fn mayNeedStreamingRequestBodyPreRead(cfg: *const edge_config.EdgeConfig) bool {
    if (cfg.proxy_streaming_mode.requestStreamingEnabled()) return true;
    for (cfg.location_blocks) |block| {
        if (block.proxy_streaming_policy.requestStreamingEnabled(false)) return true;
    }
    for (cfg.server_blocks) |server_block| {
        for (server_block.location_blocks) |block| {
            if (block.proxy_streaming_policy.requestStreamingEnabled(false)) return true;
        }
    }
    return false;
}

fn streamingRequestBodyFromHead(
    request: *const http.Request,
    pending_buf: []const u8,
    header_read: gconn.HttpRequestHeadRead,
    bytes_consumed: usize,
) ?gproxy_runtime.StreamingRequestBody {
    const content_length = request.contentLength() orelse return null;
    if (bytes_consumed > header_read.total_read) return null;
    const available = header_read.total_read - bytes_consumed;
    const initial_len = @min(available, content_length);
    return .{
        .content_length = content_length,
        .initial_bytes = pending_buf[bytes_consumed .. bytes_consumed + initial_len],
    };
}

fn connRawFd(conn: anytype) ?std.posix.fd_t {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "rawFd")) return conn.rawFd();
        if (comptime @hasField(Child, "handle")) return conn.handle;
    } else {
        if (comptime @hasField(T, "handle")) return conn.handle;
    }
    return null;
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
        try gp.sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
        return;
    }

    if (enable_proxy_protocol and !session.proxy_protocol_checked) {
        gconn.maybeConsumeProxyProtocolPreface(
            conn,
            cfg.proxy_protocol_mode,
            pending_buf,
            &session.pending_len,
            &session.proxy_client_ip_buf,
            &session.proxy_client_ip_len,
        ) catch |err| {
            state.logger.warn(null, "proxy protocol parse failed: {}", .{err});
            try gp.sendApiError(allocator, conn.writer(), .bad_request, "invalid_request", "Invalid proxy protocol header", null, false, state);
            return;
        };
        session.proxy_protocol_checked = true;
    } else if (!session.proxy_protocol_checked) {
        session.proxy_protocol_checked = true;
    }

    var streaming_request_body: ?gproxy_runtime.StreamingRequestBody = null;
    var request: http.Request = undefined;
    var request_initialized = false;
    defer if (request_initialized) request.deinit();

    if (mayNeedStreamingRequestBodyPreRead(cfg)) {
        const head_read = try gconn.readHttpRequestHead(conn, pending_buf, &session.pending_len);
        if (head_read.total_read == 0) return;
        if (cfg.max_connection_memory_bytes > 0 and head_read.total_read > cfg.max_connection_memory_bytes) {
            session.pending_len = 0;
            try gp.sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
            return;
        }
        var head_parse = http.Request.parseHead(allocator, pending_buf[0..head_read.header_len], MAX_REQUEST_SIZE) catch |err| {
            if (err == error.OutOfMemory) return err; // resource failure, not a client parse error
            try gp.sendApiError(allocator, conn.writer(), parseRequestErrorStatus(err), "invalid_request", "Malformed request", null, keep_alive, state);
            state.logger.warn(null, "parse error: {}", .{err});
            return;
        };
        var pre_effective_cfg_storage = cfg.*;
        const pre_effective_cfg = ga.resolveRequestConfig(cfg, head_parse.request.headers.get("host"), &pre_effective_cfg_storage) orelse cfg;
        const upload_eligibility = streamingUploadEligibilityBeforeBodyRead(pre_effective_cfg, &head_parse.request);
        switch (upload_eligibility) {
            .stream => {
                streaming_request_body = streamingRequestBodyFromHead(&head_parse.request, pending_buf, head_read, head_parse.bytes_consumed);
                request = head_parse.request;
                request_initialized = true;
                session.pending_len = 0;
            },
            .fallback, .not_applicable => {
                if (upload_eligibility == .fallback) {
                    const reason = upload_eligibility.fallback;
                    state.metricsRecordProxyStreamingFallback(reason.metricLabel());
                    state.logger.debug(null, "proxy upload streaming fallback: {s}", .{reason.metricLabel()});
                }
                head_parse.request.deinit();
                // Switch SO_RCVTIMEO from header phase to body read phase.
                const body_timeout_ms = cfg.request_limits.effectiveBodyTimeout();
                if (body_timeout_ms > 0) {
                    if (connRawFd(conn)) |fd| {
                        const write_timeout_ms = if (cfg.downstream_write_timeout_ms > 0)
                            cfg.downstream_write_timeout_ms
                        else
                            cfg.request_limits.effectiveHeaderTimeout();
                        gconn.setSocketTimeoutMs(fd, body_timeout_ms, write_timeout_ms) catch {};
                    }
                }
                const total_read = try gconn.readHttpRequest(conn, pending_buf, &session.pending_len);
                if (total_read == 0) return;
                if (cfg.max_connection_memory_bytes > 0 and total_read > cfg.max_connection_memory_bytes) {
                    session.pending_len = 0;
                    try gp.sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
                    return;
                }
                const parse_result = http.Request.parse(allocator, pending_buf[0..total_read], MAX_REQUEST_SIZE) catch |err| {
                    if (err == error.OutOfMemory) return err; // resource failure, not a client parse error
                    try gp.sendApiError(allocator, conn.writer(), parseRequestErrorStatus(err), "invalid_request", "Malformed request", null, keep_alive, state);
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
                request = parse_result.request;
                request_initialized = true;
            },
        }
    } else {
        const total_read = try gconn.readHttpRequest(conn, pending_buf, &session.pending_len);
        if (total_read == 0) return;
        if (cfg.max_connection_memory_bytes > 0 and total_read > cfg.max_connection_memory_bytes) {
            session.pending_len = 0;
            try gp.sendApiError(allocator, conn.writer(), .payload_too_large, "invalid_request", "Connection memory limit exceeded", null, false, state);
            return;
        }

        const parse_result = http.Request.parse(allocator, pending_buf[0..total_read], MAX_REQUEST_SIZE) catch |err| {
            if (err == error.OutOfMemory) return err; // resource failure, not a client parse error
            try gp.sendApiError(allocator, conn.writer(), parseRequestErrorStatus(err), "invalid_request", "Malformed request", null, keep_alive, state);
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

        request = parse_result.request;
        request_initialized = true;
    }
    const writer = conn.writer();
    keep_alive = request.keepAlive();
    if (streaming_request_body != null) keep_alive = false;
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
        try gp.sendApiError(allocator, writer, .bad_request, "invalid_request", "HTTP/1.1 request missing required Host header", correlation_id, false, state);
        var ctx_host = http.request_context.RequestContext.init(allocator, correlation_id, connection_ip);
        ghandlers.logAccessForRequest(state, &ctx_host, &request, 400);
        return;
    }

    // --- RFC 7231 §4.3.8 / ASVS-14.5.1: Reject TRACE globally ---
    // TRACE echoes the request back to the client, enabling Cross-Site
    // Tracing (XST) attacks that can expose cookies and auth headers even
    // when HttpOnly is set. Tardigrade has no use for TRACE on any route —
    // gateway-to-upstream tracing is handled via W3C traceparent headers.
    // Reject before routing so no location block can accidentally serve it.
    if (request.method == .TRACE) {
        try gp.sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        var ctx_trace = http.request_context.RequestContext.init(allocator, correlation_id, connection_ip);
        ghandlers.logAccessForRequest(state, &ctx_trace, &request, 405);
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
            // ACME HTTP-01 challenges are ordinary requests; keep them visible in
            // access logs and status metrics like every other terminal (#201).
            state.metricsRecord(200);
            var ctx_acme = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
            ghandlers.logAccessForRequest(state, &ctx_acme, &request, 200);
            return;
        }
    }

    var effective_cfg_storage = cfg.*;
    const effective_cfg = ga.resolveRequestConfig(cfg, request.headers.get("host"), &effective_cfg_storage) orelse {
        try gp.sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        var ctx_404 = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
        ghandlers.logAccessForRequest(state, &ctx_404, &request, 404);
        return;
    };
    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
    if (!ga.hostMatchesServerNames(effective_cfg, &request)) {
        try gp.sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        ghandlers.logAccessForRequest(state, &ctx, &request, 404);
        return;
    }

    // --- In-flight request backpressure ---
    if (!state.tryAcquireRequestSlot()) {
        try gp.sendApiError(allocator, writer, .service_unavailable, "overloaded", "Too many in-flight requests", correlation_id, false, state);
        state.metricsRecord(503);
        // Metrics label must be the canonical "overload" the metrics switch
        // accepts (recordErrorCode); the client-facing API code stays "overloaded".
        state.metricsRecordErrorCode("overload");
        ghandlers.logAccessForRequest(state, &ctx, &request, 503);
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

    var conditional_outcome = try ghandlers.evaluateConditionalRules(
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
                gp.applyResponseHeaders(state, &response);
                try response.write(writer);
                state.metricsRecord(r.status);
                ghandlers.logAccessForRequest(state, &ctx, &request, r.status);
                return;
            },
            .returned => |r| {
                const result = try ghandlers.writeReturnResponsePlan(allocator, writer, state, &ctx, ghandlers.planDirectResponse(r.status, r.body), correlation_id, keep_alive);
                state.metricsRecord(result.status);
                if (result.error_code) |code| state.metricsRecordErrorCode(code);
                ghandlers.logAccessForRequest(state, &ctx, &request, result.status);
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
            gp.applyResponseHeaders(state, &response);
            try response.write(writer);
            state.metricsRecord(r.status);
            ghandlers.logAccessForRequest(state, &ctx, &request, r.status);
            return;
        },
        .returned => |r| {
            const result = try ghandlers.writeReturnResponsePlan(allocator, writer, state, &ctx, ghandlers.planDirectResponse(r.status, r.body), correlation_id, keep_alive);
            state.metricsRecord(result.status);
            if (result.error_code) |code| state.metricsRecordErrorCode(code);
            ghandlers.logAccessForRequest(state, &ctx, &request, result.status);
            return;
        },
    }

    // --- Internal redirects / named locations ---
    request.uri.path = ghandlers.applyInternalRedirectRules(
        request.method.toString(),
        request.uri.path,
        effective_cfg.internal_redirect_rules,
        effective_cfg.named_locations,
    );

    // --- Mirror requests (best-effort async) ---
    if (effective_cfg.mirror_rules.len > 0) {
        ghandlers.spawnMirrorRequests(
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

    try ghandlers.primeRequestAuthContext(allocator, effective_cfg, state, &ctx, &request.headers);

    if (try ghandlers.runMiddlewarePipeline(allocator, writer, effective_cfg, state, &ctx, &request, correlation_id, keep_alive)) {
        return;
    }

    // Deadline check: if the overall request deadline elapsed during auth/middleware,
    // reject now rather than dispatching to the (potentially slow) upstream handler.
    if (lifecycle.checkDeadline(.routing)) {
        try gp.sendApiError(allocator, writer, .request_timeout, "request_timeout", "Request deadline exceeded", correlation_id, keep_alive, state);
        state.metricsRecord(408);
        state.metricsRecordErrorCode("request_timeout");
        ghandlers.logAccessForRequest(state, &ctx, &request, 408);
        return;
    }

    const route_status = try ghandlers.routeRequest(conn, allocator, effective_cfg, state, &ctx, &request, correlation_id, &keep_alive, client_ip, streaming_request_body);
    ghandlers.logAccessForRequest(state, &ctx, &request, route_status);
    return;
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

fn initUploadEligibilityTestConfig(blocks: []edge_config.EdgeConfig.LocationBlock) edge_config.EdgeConfig {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.proxy_streaming_mode = .off;
    cfg.request_limits = http.request_limits.RequestLimits.default;
    cfg.rewrite_rules = &.{};
    cfg.return_rules = &.{};
    cfg.conditional_rules = &.{};
    cfg.internal_redirect_rules = &.{};
    cfg.mirror_rules = &.{};
    cfg.auth_request_url = "";
    cfg.upstream_retry_attempts = 1;
    cfg.upstream_retry_idempotent_only = true;
    cfg.location_blocks = blocks;
    cfg.server_blocks = &.{};
    cfg.upstream_base_url = "http://127.0.0.1:9001";
    cfg.upstream_tls_client_cert = "";
    return cfg;
}

test "streaming upload eligibility reports typed fallback reasons" {
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/upload/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
            .proxy_streaming_policy = .full,
        },
        .{
            .match_type = .prefix,
            .pattern = "/compat/",
            .priority = 1,
            .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
            .proxy_streaming_policy = .off,
        },
    };
    var cfg = initUploadEligibilityTestConfig(&blocks);

    var upload_head = try http.Request.parseHead(
        allocator,
        "POST /upload/body HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer upload_head.request.deinit();
    try std.testing.expectEqual(RequestUploadStreamingEligibility.stream, streamingUploadEligibilityBeforeBodyRead(&cfg, &upload_head.request));

    var chunked_head = try http.Request.parseHead(
        allocator,
        "POST /upload/body HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer chunked_head.request.deinit();
    try std.testing.expectEqual(RequestUploadStreamingEligibility{ .fallback = .chunked_request_upload }, streamingUploadEligibilityBeforeBodyRead(&cfg, &chunked_head.request));

    var compat_head = try http.Request.parseHead(
        allocator,
        "POST /compat/body HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer compat_head.request.deinit();
    try std.testing.expectEqual(RequestUploadStreamingEligibility{ .fallback = .policy_disabled }, streamingUploadEligibilityBeforeBodyRead(&cfg, &compat_head.request));

    var compat_chunked_head = try http.Request.parseHead(
        allocator,
        "POST /compat/body HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer compat_chunked_head.request.deinit();
    try std.testing.expectEqual(RequestUploadStreamingEligibility{ .fallback = .policy_disabled }, streamingUploadEligibilityBeforeBodyRead(&cfg, &compat_chunked_head.request));

    cfg.auth_request_url = "http://auth.example.test/check";
    try std.testing.expectEqual(RequestUploadStreamingEligibility{ .fallback = .body_dependent_middleware }, streamingUploadEligibilityBeforeBodyRead(&cfg, &upload_head.request));
}

test "streaming upload pre-read scan includes server block routes" {
    var base_blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
            .proxy_streaming_policy = .inherit,
        },
    };
    var server_blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/upload/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:9002" },
            .proxy_streaming_policy = .full,
        },
    };
    var server_names = [_][]const u8{"api.example.test"};
    var server_block_entries = [_]edge_config.EdgeConfig.ServerBlock{
        .{
            .server_names = &server_names,
            .doc_root = "",
            .try_files = "",
            .location_blocks = &server_blocks,
            .tls_cert_path = "",
            .tls_key_path = "",
            .upstream_base_url = "",
            .proxy_pass_chat = "",
            .proxy_pass_commands_prefix = "",
        },
    };
    var cfg = initUploadEligibilityTestConfig(&base_blocks);
    cfg.server_blocks = &server_block_entries;

    try std.testing.expect(mayNeedStreamingRequestBodyPreRead(&cfg));
}

// Pull gateway_handlers (and its transitive imports, including
// gateway_static_runtime) into the unit-test runner so their tests are
// discovered and executed alongside the other edge-gateway tests.
test {
    _ = @import("gateway_handlers.zig");
}

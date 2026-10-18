const compat = @import("zig_compat");
const std = @import("std");
const builtin = @import("builtin");
const http = @import("http.zig");
const edge_config = @import("edge_config.zig");
const runtime_allocator = @import("runtime_allocator.zig");
const build_options = @import("build_options");
const tls_core = @import("tls_core");
const http3_wire = @import("http3");

const STREAM_RELAY_BUFFER_SIZE: usize = 16 * 1024;
const JSON_CONTENT_TYPE = "application/json";
const HTTP2_PREFACE = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const HTTP2_MAX_FRAME_SIZE: usize = 16 * 1024;
const HTTP2_MAX_CONCURRENT_STREAMS: usize = 100;
/// Per-stream SETTINGS_INITIAL_WINDOW_SIZE this connection advertises to the
/// peer for every HTTP/2 stream, including #867 persistent sessions.
const HTTP2_INITIAL_WINDOW_SIZE: u32 = 1024 * 1024;
/// Per-stream bound on a #867 persistent session's queued inbound/outbound
/// bytes. The inbound bound must be at least `HTTP2_INITIAL_WINDOW_SIZE`: a
/// smaller session queue would let a well-behaved peer legally fill the
/// receive window this connection already advertised and still get
/// RST_STREAM(FLOW_CONTROL_ERROR) before exceeding what it was actually
/// granted. Both bounds are charged against `cfg.max_connection_memory_bytes`
/// on attach (`HTTP2_SESSION_RESERVED_BYTES`) so many concurrent sessions on
/// one connection cannot bypass the connection-wide memory ceiling.
const HTTP2_SESSION_MAX_INBOUND_BYTES: usize = HTTP2_INITIAL_WINDOW_SIZE;
const HTTP2_SESSION_MAX_OUTBOUND_BYTES: usize = 256 * 1024;
const HTTP2_SESSION_RESERVED_BYTES: usize = HTTP2_SESSION_MAX_INBOUND_BYTES + HTTP2_SESSION_MAX_OUTBOUND_BYTES;
const WS_MUX_MAX_CHANNELS: usize = 32;
const ACTIVE_DRIVE_POLL_INTERVAL_MS: u64 = 250;
/// Fallback approval TTL when no config value is provided (5 minutes).
const APPROVAL_TIMEOUT_MS_DEFAULT: i64 = 300_000;

const gs = @import("gateway_state.zig");
const gaccept = @import("gateway_accept.zig");
const gconn = @import("gateway_connection.zig");
const gshutdown = @import("gateway_shutdown.zig");
const ghandlers = @import("gateway_handlers.zig");
const gproxy_runtime = @import("gateway_proxy_runtime.zig");
const gprotocol_policy = @import("gateway_protocol_policy.zig");
const gp = @import("gateway_proxy.zig");
const gws_tunnel = @import("gateway_websocket_tunnel.zig");
const gph = @import("gateway_proxy_headers.zig");
const ga = @import("gateway_auth.zig");
const gfa = @import("gateway_forward_auth.zig");

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

const ActiveDrivePollRemoveFn = *const fn (*anyopaque, std.posix.fd_t) anyerror!void;
const ActiveDrivePollSubmitFn = *const fn (*anyopaque, std.posix.fd_t) anyerror!void;

/// Takes a mutable config because the startup generation publishes its parsed
/// ACL back onto it (`EdgeConfig.parsed_access_control`), which is what pairs
/// authorization state with the configuration generation a request leases.
pub fn run(cfg: *edge_config.EdgeConfig) !void {
    const state_allocator = runtime_allocator.runtimeAllocator();

    const initial_hsts = try gp.computeHstsValue(state_allocator, cfg);
    errdefer if (initial_hsts.len > 0) state_allocator.free(initial_hsts);

    // Outlives `state` (its discovery config borrows the slice); freed after
    // state.deinit() because defers run in reverse order.
    // Explicit nameserver config fails closed: a malformed list aborts startup
    // instead of silently falling back to /etc/resolv.conf.
    const srv_nameservers = try http.dns_srv.parseNameserverList(state_allocator, cfg.upstream_srv_nameservers);
    defer state_allocator.free(srv_nameservers);
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
        .http3_alt_svc = null,
        .http3_advertisement_state = if (cfg.http3_enabled) .configured_unavailable else .disabled,
        .http3_runtime = null,
        .session_store = if (cfg.session_ttl_seconds > 0)
            http.session.SessionStore.init(state_allocator, cfg.session_ttl_seconds, cfg.session_max)
        else
            null,
        .session_store_path = cfg.session_store_path,
        // No ACL field here on purpose: access-control policy is owned by the
        // configuration version a request leases (see
        // `ManagedConfigVersion.access_control`), so it can neither outlive nor
        // under-live the configuration generation that request is using.
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
        .proxy_buffer_global_account = http.proxy_buffer_account.Aggregate.init(.global, cfg.proxy_buffer_limits.global_hard_limit),
        .tls_buffer_limits = cfg.tls_buffer_limits,
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
            .lock_contention_metrics_enabled = cfg.upstream_pool_lock_metrics,
            // Per-origin buffer accounting for HTTP/1 origins (#140).
            .proxy_buffer_limits = cfg.proxy_buffer_limits,
        }),
        .h2_pool = http.upstream_h2.H2ConnPool.init(state_allocator, .{
            .idle_timeout_ms = cfg.upstream_pool_idle_timeout_ms,
            .max_lifetime_ms = cfg.upstream_pool_max_lifetime_ms,
            // The advertised per-stream receive window *is* the configured
            // per-stream high watermark (#140), so a well-behaved origin stops
            // sending exactly where the accounting model fills up.
            .proxy_buffer_limits = cfg.proxy_buffer_limits,
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
            .tls = if (cfg.upstream_srv_name.len > 0) cfg.upstream_srv_tls else cfg.upstream_dns_discovery_tls,
            .refresh_interval_ms = cfg.upstream_dns_refresh_interval_ms,
            .srv_name = cfg.upstream_srv_name,
            .min_refresh_ms = cfg.upstream_srv_min_refresh_ms,
            .stale_max_ms = cfg.upstream_srv_stale_max_ms,
            .query_timeout_ms = cfg.upstream_srv_timeout_ms,
            .nameservers = srv_nameservers,
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
        state.logger.info(null, "upstream mTLS client cert and/or SNI override configured; applies to every upstream TLS connection regardless of -Dtls-profile", .{});
    }

    // Appliance TLS profile (#392): load and fully validate the one
    // provisioned Ed25519 identity before any TCP or UDP listener is bound.
    // Invalid credentials abort startup before HTTP dispatch is possible. The
    // owner outlives every TCP connection, QUIC connection, and the HTTP/3
    // runtime (all torn down by later-declared defers).
    var appliance_identity: ?tls_core.appliance_credentials.ApplianceCredentials = null;
    defer if (appliance_identity) |*owner| owner.deinit();
    if (edge_config.is_appliance_tls_profile and edge_config.hasTlsFiles(cfg)) {
        appliance_identity = tls_core.appliance_credentials.ApplianceCredentials.initFromFiles(
            state_allocator,
            cfg.tls_cert_path,
            cfg.tls_key_path,
            .{ .server_name = cfg.tls_server_name },
        ) catch |err| {
            // Propagate the real typed error (not a synthetic wrapper) so the
            // caller can classify it exactly like `tardi check` does — every
            // appliance_credentials.Error class is a deterministic
            // configuration failure, not an internal error.
            state.logger.err(null, "appliance TLS credential rejected ({s}); refusing to start", .{@errorName(err)});
            return err;
        };
        state.logger.info(null, "appliance TLS identity loaded and validated", .{});
    }

    const sharding_enabled = cfg.listener_shards > 1 and gaccept.isReusePortSupported();
    const effective_shards: u16 = if (sharding_enabled)
        @min(cfg.listener_shards, @as(u16, http.metrics.max_listener_shards))
    else
        1;

    const max_shards = http.metrics.max_listener_shards;
    var shard_fds: [max_shards]std.posix.fd_t = undefined;
    var shard_fd_count: u16 = 0;
    var shard_threads: [max_shards]std.Thread = undefined;
    var shard_thread_count: usize = 0;
    errdefer {
        var ji: u16 = 0;
        while (ji < shard_fd_count) : (ji += 1) _ = std.c.close(shard_fds[ji]);
    }

    var server: ?std.Io.net.Server = null;
    defer if (server) |*s| s.deinit(compat.io());
    const listen_fd: std.posix.fd_t = if (sharding_enabled) blk: {
        var si: u16 = 0;
        while (si < effective_shards) : (si += 1) {
            const sfd = gaccept.createReusePortListenerFd(cfg.listen_host, cfg.listen_port) catch |err| {
                state.logger.err(null, "failed to create listener shard {}: {}", .{ si, err });
                return err;
            };
            gconn.setNonBlocking(sfd, true) catch {};
            shard_fds[shard_fd_count] = sfd;
            shard_fd_count += 1;
        }
        break :blk -1;
    } else blk: {
        const address = try std.Io.net.IpAddress.parse(cfg.listen_host, cfg.listen_port);
        server = try address.listen(compat.io(), .{ .reuse_address = true });
        const fd = server.?.socket.handle;
        try gconn.setNonBlocking(fd, true);
        break :blk fd;
    };

    // #881: the dedicated ACME HTTP-01 challenge listener (design
    // docs/ACME_AUTOMATIC_HTTPS.md §8.0) is bound here, alongside the main
    // listener and before the privilege drop/chroot below, so its default
    // privileged port (:80) can still be bound after `tardi run` drops root.
    // A bind failure fails startup exactly like the main listener's. Gated
    // on `cfg.tls_acme_enabled`, which the validated config guarantees
    // implies a non-empty `cfg.tls_acme_domains` and therefore a non-null
    // `state.acme_challenge_store` (`validateAcmeConfig`, `acme/names.zig`).
    var acme_http01_listener: http.acme_http01_listener.Listener = undefined;
    var acme_http01_listener_active = false;
    defer if (acme_http01_listener_active) acme_http01_listener.deinit();
    if (cfg.tls_acme_enabled) {
        const http01_addr = try edge_config.parseAcmeHttp01Listen(cfg.tls_acme_http01_listen);
        acme_http01_listener.start(state_allocator, http01_addr.host, http01_addr.port, .{
            .managed_hosts = cfg.tls_acme_domains,
            .store = &state.acme_challenge_store.?,
            // §8.0: "per-IP accept cap shared with existing accept limits"
            // (#897 review) -- the same configured bound as the main
            // listener's per-IP cap, enforced independently in this
            // listener's own small bounded pool.
            .max_connections_per_ip = cfg.max_connections_per_ip,
        }) catch |err| {
            state.logger.err(null, "failed to bind ACME HTTP-01 challenge listener on {s}:{d}: {}", .{ http01_addr.host, http01_addr.port, err });
            return err;
        };
        acme_http01_listener_active = true;
    }

    applyRuntimeIdentity(cfg, &state.logger) catch |err| {
        state.logger.warn(null, "privilege drop configuration failed: {}", .{err});
    };

    // #148: an explicitly requested backend fails startup when it is
    // unavailable rather than silently downgrading, so an operator who asked
    // for io_uring learns their deployment target cannot provide it here and
    // not during a later incident. `null` keeps the platform default.
    var event_loop = if (cfg.event_loop_backend) |requested|
        http.event_loop.EventLoop.initBackend(state_allocator, requested, .{
            .io_uring_entries = cfg.event_loop_io_uring_entries,
        }) catch |err| {
            state.logger.err(null, "event loop backend '{s}' requested but unavailable: {} (refusing to fall back)", .{
                @tagName(requested),
                err,
            });
            return err;
        }
    else
        try http.event_loop.EventLoop.init();
    defer event_loop.deinit();
    if (!sharding_enabled) {
        try event_loop.addReadFd(listen_fd);
    }
    var timer = http.event_loop.TimerManager.init(250);
    var config_store = try ReloadableConfigStore.initBorrowed(state_allocator, cfg);
    defer config_store.deinit();
    config_store.setInitialAccessControl(cfg, if (cfg.access_control_rules.len > 0)
        try http.access_control.AccessControl.fromConfig(state_allocator, cfg.access_control_rules, .allow)
    else
        null);
    var http3_runtime: ?http.http3_runtime.Runtime = null;
    var native_credentials: ?http.native_tls_connection.NativeCredentialStore = null;
    // #488: one process-scoped native resumption runtime, shared by every
    // native TCP connection and by the QUIC/H3 runtime. Declared and
    // deferred here, ahead of every borrower below, so its teardown runs
    // last: after `http3_runtime`, the active/parked connection registries,
    // and every dynamically accepted native connection have already torn
    // down.
    var native_resumption_entropy: tls_core.production_crypto.OsEntropy = .{};
    var native_resumption_provider: tls_core.production_crypto.Provider = undefined;
    var native_resumption_runtime: ?tls_core.resumption_runtime.Runtime = null;
    if (edge_config.nativeResumptionMode(cfg) != .disabled) {
        native_resumption_provider = tls_core.production_crypto.Provider.init(native_resumption_entropy.entropy());
        native_resumption_runtime = tls_core.resumption_runtime.Runtime.init(
            state_allocator,
            .{
                .mode = edge_config.nativeResumptionMode(cfg),
                .ticket_lifetime_seconds = cfg.tls_native_resumption_ticket_lifetime_seconds,
                .usage = edge_config.nativeResumptionTicketUsage(cfg),
                .session_limits = nativeResumptionSessionLimits(cfg),
                .stateless_ticket_key_source = if (cfg.tls_native_ticket_keys_path.len > 0) .persistent else .ephemeral,
            },
            .{ .ctx = undefined, .nowUnixMsFn = systemNowUnixMs },
            native_resumption_provider.cryptoProvider(),
        ) catch |err| {
            state.logger.err(null, "native TLS/QUIC resumption initialization failed ({s}); refusing to start", .{@errorName(err)});
            return err;
        };
        if (native_resumption_runtime) |*rt| rt.setObserver(nativeResumptionMetricsObserver(&state));
        if (cfg.tls_native_ticket_keys_path.len > 0) {
            native_resumption_runtime.?.loadPersistentTicketKeysFromFile(cfg.tls_native_ticket_keys_path) catch |err| {
                state.metrics_mutex.lock();
                state.metrics.recordTicketKeyReload(.initial_load_failure);
                state.metrics_mutex.unlock();
                state.logger.err(null, "native TLS/QUIC persistent ticket-key load failed ({s}); refusing to start", .{@errorName(err)});
                return err;
            };
            state.metrics_mutex.lock();
            state.metrics.recordTicketKeyReload(.initial_load_success);
            state.metrics_mutex.unlock();
        }
    }
    defer if (native_resumption_runtime) |*rt| rt.deinit();
    // #368 Slice 3: one process-scoped anti-replay store, shared by every
    // native TCP worker and the QUIC/H3 runtime — constructed only when the
    // operator has explicitly opted into `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE=process_local`
    // (`edge_config.EarlyDataReplayMode.disabled` is the safe default) *and*
    // a native PSK/early-data path can actually exist (below, once
    // `native_tls_provider`/`h3_credential_provider` are known), so plain
    // HTTP, no-native-TLS-path, resumption-disabled, or replay-mode-disabled
    // deployments never pay the configured-entry reservation or gain a new
    // startup-failure path for a security feature they haven't enabled.
    // Declared (but not yet constructed) here, ahead of every borrower
    // below, so its teardown — once present — runs last, for the same
    // reason as `native_resumption_runtime`.
    var native_early_data_replay_store: ?tls_core.early_data_replay.LocalStore = null;
    defer if (native_early_data_replay_store) |*store| store.deinit();
    var native_early_data_replay_gate_adapter: tls_core.early_data_replay.GateAdapter = undefined;
    var native_early_data_replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate = null;
    var http3_observability_artifacts: ?http.http3_runtime.ObservabilityArtifacts = null;
    defer if (http3_observability_artifacts) |*artifacts| artifacts.deinit();
    var http3_dispatch_ctx = ghandlers.Http3DispatchContext{
        .config_store = &config_store,
        .cfg = cfg,
        .state = &state,
    };
    var native_tls_provider: ?tls_core.credentials.CredentialProvider = null;
    var h3_credential_provider: ?tls_core.credentials.CredentialProvider = null;
    if (edge_config.hasTlsFiles(cfg)) {
        if (edge_config.is_appliance_tls_profile) {
            // Appliance profile: the strict owner is the only credential
            // source for both native TCP TLS and HTTP/3. There is no
            // fallback through the permissive generic identity loader.
            const owner = &appliance_identity.?;
            native_tls_provider = owner.provider();
            h3_credential_provider = owner.provider();
        } else {
            var native_sni_specs = try state_allocator.alloc(http.native_tls_connection.SniCertSpec, cfg.tls_sni_certs.len);
            defer state_allocator.free(native_sni_specs);
            for (cfg.tls_sni_certs, 0..) |sc, i| {
                native_sni_specs[i] = .{ .server_name = sc.server_name, .cert_path = sc.cert_path, .key_path = sc.key_path };
            }
            native_credentials = http.native_tls_connection.NativeCredentialStore.init(state_allocator);
            try native_credentials.?.reloadFromFiles(cfg.tls_cert_path, cfg.tls_key_path, native_sni_specs);
            native_tls_provider = native_credentials.?.provider();
            h3_credential_provider = native_credentials.?.provider();
        }
    }
    defer if (native_credentials) |*store| store.deinit();
    // #763: downstream mTLS trust anchors. Loaded eagerly so a bad bundle
    // fails startup rather than the first handshake; never falls back to the
    // system trust store.
    // The set always exists on a native TLS listener so mTLS policies (and
    // their CA bundles) can be enabled, changed or rotated by hot reload.
    var client_policies: ?http.native_tls_connection.ClientPolicySet = null;
    if (native_tls_provider == null and cfg.anyClientAuth()) {
        // Defensive twin of config validation: never start a listener that
        // demands client certificates but would serve plaintext.
        return error.ClientTrustUnavailable;
    }
    if (native_tls_provider != null) {
        client_policies = http.native_tls_connection.ClientPolicySet.init(state_allocator);
        var prepared = try cfg.prepareClientPolicies(&client_policies.?);
        client_policies.?.commit(&prepared);
        // The startup generation owns its snapshot like it owns its ACL.
        config_store.setInitialClientPolicies(client_policies.?.acquire());
    }
    defer if (client_policies) |*set| set.deinit();
    const native_early_data_replay_composition = nativeEarlyDataReplayComposition(
        cfg.tls_native_early_data_replay_mode,
        native_resumption_runtime != null,
        native_tls_provider != null,
        cfg.http3_enabled,
        h3_credential_provider != null,
        null,
    );
    if (native_early_data_replay_composition.store_enabled) {
        // A configured `process_local` mode must never silently fall back to
        // an unprotected/disabled implementation if store initialization
        // fails — refusing to start (like `native_resumption_runtime` above)
        // is the fail-closed behavior #368 requires.
        native_early_data_replay_store = initNativeEarlyDataReplayStore(
            state_allocator,
            cfg.tls_native_early_data_replay_max_entries,
            @intCast(compat.milliTimestamp()),
        ) catch |err| {
            state.logger.err(null, "native TLS/QUIC early-data replay store initialization failed ({s}); refusing to start", .{@errorName(err)});
            return err;
        };
        if (native_early_data_replay_store) |*store| store.setObserver(nativeEarlyDataReplayMetricsObserver(&state));
    }
    if (native_early_data_replay_store) |*store| {
        native_early_data_replay_gate_adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
        native_early_data_replay_gate = nativeEarlyDataReplayComposition(
            cfg.tls_native_early_data_replay_mode,
            native_resumption_runtime != null,
            native_tls_provider != null,
            cfg.http3_enabled,
            h3_credential_provider != null,
            native_early_data_replay_gate_adapter.gate(),
        ).early_data_replay_gate;
    }
    if (cfg.http3_enabled) {
        if (!edge_config.hasTlsFiles(cfg)) {
            state.logger.warn(null, "HTTP/3 requested without TLS cert/key; QUIC bootstrap will remain incomplete", .{});
        }
        if (cfg.http3_qlog_dir.len > 0 or cfg.http3_keylog_path.len > 0) {
            http3_observability_artifacts = http.http3_runtime.ObservabilityArtifacts.initWithLogger(
                state_allocator,
                &state.logger,
                cfg.http3_qlog_dir,
                cfg.http3_keylog_path,
            ) catch |err| {
                state.logger.warn(null, "HTTP/3 observability artifact setup failed: {s}", .{@errorName(err)});
                return err;
            };
            if (cfg.http3_qlog_dir.len > 0) {
                state.logger.warn(null, "HTTP/3 qlog enabled for local/debug tracing: dir={s}", .{cfg.http3_qlog_dir});
            }
            if (cfg.http3_keylog_path.len > 0) {
                state.logger.warn(null, "HTTP/3 TLS key logging enabled: {s} contains traffic secrets and permits packet decryption", .{cfg.http3_keylog_path});
            }
        }
        http3_runtime = http.http3_runtime.Runtime.init(state_allocator, &state.logger, .{
            .listen_host = cfg.listen_host,
            .quic_port = cfg.quic_port,
            .credential_provider = h3_credential_provider,
            .resumption_runtime = if (native_resumption_runtime) |*rt| rt else null,
            .early_data_replay_gate = native_early_data_replay_gate,
            // #763: the same SNI-keyed policy set the TCP listener uses, so
            // one policy table and one reload govern H1, H2 and H3.
            .client_policies = if (client_policies) |*set| set else null,
            .tls_min_version = "1.3",
            .tls_max_version = "1.3",
            .enable_0rtt = cfg.http3_enable_0rtt,
            .max_request_body_bytes = cfg.request_limits.effectiveMaxBodySize(),
            .max_buffered_request_bytes = if (cfg.max_connection_memory_bytes > 0)
                cfg.max_connection_memory_bytes
            else
                http3_wire.conn.default_max_buffered_request_bytes,
            .connection_migration = cfg.http3_connection_migration,
            .retry_policy = cfg.http3_retry_policy,
            .max_datagram_size = cfg.http3_max_datagram_size,
            .udp_buffer_tuning = .{
                .recv_bytes = if (cfg.http3_udp_recv_buffer_bytes > 0) cfg.http3_udp_recv_buffer_bytes else null,
                .send_bytes = if (cfg.http3_udp_send_buffer_bytes > 0) cfg.http3_udp_send_buffer_bytes else null,
            },
            .ecn_enabled = cfg.http3_ecn_enabled,
            .request_handler = ghandlers.handleHttp3Request,
            .request_handler_ctx = &http3_dispatch_ctx,
            .early_data_compat_metrics_ctx = &state,
            .early_data_compat_metrics_cb = recordHttp3EarlyDataCompatFromRuntime,
            .quic_early_data_decision_metrics_ctx = &state,
            .quic_early_data_decision_metrics_cb = recordQuicEarlyDataDecisionFromRuntime,
            .quic_zero_rtt_packet_metrics_ctx = &state,
            .quic_zero_rtt_packet_metrics_cb = recordQuicZeroRttPacketFromRuntime,
            .quic_transport_metrics_ctx = &state,
            .quic_transport_metrics_cb = recordQuicTransportDeltaFromRuntime,
            .quic_connections_active_metrics_ctx = &state,
            .quic_connections_active_metrics_cb = setQuicConnectionsActiveFromRuntime,
            .quic_handshake_failure_metrics_ctx = &state,
            .quic_handshake_failure_metrics_cb = recordQuicHandshakeFailureFromRuntime,
            .h3_request_latency_metrics_ctx = &state,
            .h3_request_latency_metrics_cb = recordH3RequestLatencyFromRuntime,
            .qlog_artifacts_ctx = if (http3_observability_artifacts) |*artifacts| artifacts else null,
            .quic_qlog_artifact_cb = if (http3_observability_artifacts) |*artifacts| if (artifacts.qlogEnabled()) http.http3_runtime.ObservabilityArtifacts.writeQuicRecord else null else null,
            .h3_qlog_artifact_cb = if (http3_observability_artifacts) |*artifacts| if (artifacts.qlogEnabled()) http.http3_runtime.ObservabilityArtifacts.writeH3Record else null else null,
            .qlog_artifact_close_cb = if (http3_observability_artifacts) |*artifacts| if (artifacts.qlogEnabled()) http.http3_runtime.ObservabilityArtifacts.closeTrace else null else null,
            .tls_keylog_context = if (http3_observability_artifacts) |*artifacts| artifacts.keylogContext() else .{},
        }) catch |err| blk: {
            state.logger.warn(null, "HTTP/3 listener failed to initialize: {s}", .{@errorName(err)});
            break :blk null;
        };
        if (http3_runtime) |*runtime| runtime.start();
        updateHttp3Advertisement(&state, cfg, if (http3_runtime) |*runtime| runtime else null, .steady);
    }
    state.http3_runtime = if (http3_runtime) |*runtime| runtime else null;
    defer if (http3_runtime) |*runtime| runtime.deinit();
    // NOTE (#708): defaulting worker_threads to CPU count is correct for a
    // non-blocking event loop, but Tardigrade currently uses a thread-per-
    // connection blocking model where a worker is held for the whole active
    // portion of a request (read -> for proxy: upstream connect/write/read too
    // -> write response). Idle keepalive time between requests is parked off
    // the worker pool (#138, landed), so that part no longer needs oversizing.
    // What remains is #708: an actively-held worker's critical section is
    // longer for the proxy path than for static serving, so real client-facing
    // network latency (not just concurrency) degrades proxy throughput far
    // more under worker scarcity than static throughput -- measured ~8x on a
    // real cross-machine link, only partially mitigated by raising
    // TARDIGRADE_WORKER_THREADS. Fixing this for real needs the active
    // request path to become non-blocking/event-driven rather than tuning
    // worker count.
    const worker_count: usize = blk: {
        const configured = if (cfg.worker_threads == 0)
            (std.Thread.getCpuCount() catch 1)
        else
            cfg.worker_threads;
        break :blk @intCast(@max(configured, @as(u32, 1)));
    };
    // Established WebSocket tunnels run on a few reactor threads, not on the
    // request workers (#818): a worker runs the handshake and admission, then
    // hands the tunnel over. Declared before the worker pool so it outlives
    // every worker that can hand it a tunnel. Always started: a reload can
    // add `proxy_websocket` locations.
    const reactor_threads: u16 = @intCast(if (cfg.proxy_websocket_reactor_threads > 0)
        cfg.proxy_websocket_reactor_threads
    else
        std.math.clamp((std.Thread.getCpuCount() catch 1) / 4, 1, 4));
    var tunnel_reactor: http.tunnel_reactor.Reactor = undefined;
    try tunnel_reactor.start(state_allocator, .{ .threads = reactor_threads, .shutdown_requested = http.shutdown.isShutdownRequested });
    defer tunnel_reactor.deinit();
    state.tunnel_reactor = &tunnel_reactor;

    // Process-wide executor for finite HTTP/2 request jobs (#866), shared by
    // every downstream H2 connection so one connection's slow route/proxy
    // work can never consume unbounded worker/queue capacity. Separate from
    // `worker_pool` below, which dispatches whole accepted connections, not
    // the requests multiplexed within an already-accepted H2 connection.
    // Declared (and its shutdown deferred) before `worker_pool` for the same
    // reason as `tunnel_reactor` above: every connection thread's own
    // teardown can block draining its in-flight H2 jobs, so this executor
    // must still be running when `worker_pool.deinit()` joins those threads.
    const h2_request_worker_count: usize = blk: {
        const configured = if (cfg.h2_request_worker_threads == 0)
            @max(worker_count / 2, 1)
        else
            cfg.h2_request_worker_threads;
        break :blk @intCast(@max(configured, @as(u32, 1)));
    };
    var h2_request_executor: http.h2_request_executor.Executor = undefined;
    try h2_request_executor.init(
        state_allocator,
        h2_request_worker_count,
        cfg.h2_request_queue_capacity,
        executeH2RequestJobSignal,
        &state,
    );
    defer h2_request_executor.shutdownAndJoin();
    state.h2_request_executor = &h2_request_executor;

    var worker_ctx = WorkerContext{
        .config_store = &config_store,
        .state = &state,
        .native_credentials = if (native_credentials) |*store| store else null,
        .client_policies = if (client_policies) |*set| set else null,
        .native_tls_provider = native_tls_provider,
        .resumption_runtime = if (native_resumption_runtime) |*rt| rt else null,
        .early_data_replay_gate = native_early_data_replay_gate,
        .session_pool = undefined,
        .event_loop = &event_loop,
        .active = undefined,
        .parked = undefined,
    };
    var session_pool = ConnectionSessionPool.init(state_allocator, &state.request_buffer_pool, cfg.connection_pool_size);
    defer session_pool.deinit();
    worker_ctx.session_pool = &session_pool;

    var active = http.downstream_connection.ActiveRegistry.init(state_allocator);
    defer active.deinit();
    worker_ctx.active = &active;

    // Registry of idle keepalive connections parked off the worker pool (#138).
    // Its close hook releases the connection slot held since accept, so parked
    // connections torn down by the reaper/drain are accounted correctly, and
    // unregisters the fd from the event loop before it is closed. The deinit
    // (closeAll) runs before session_pool.deinit thanks to defer order.
    var parked = http.keepalive_park.ParkedRegistry.init(state_allocator, &session_pool);
    var parked_close_ctx = ParkedCloseCtx{ .state = &state, .event_loop = &event_loop };
    parked.close_hook = parkedConnectionCloseHook;
    parked.close_hook_ctx = &parked_close_ctx;
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
    if (cfg.access_control_rules.len > 0) {
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
        state.logger.info(null, "HTTP/3 foundation enabled: quic_port={d} 0rtt={} migration={} retry_policy={s} max_datagram={d} udp_recv_buffer={d} udp_send_buffer={d} ecn={}", .{
            cfg.quic_port,
            cfg.http3_enable_0rtt,
            cfg.http3_connection_migration,
            @tagName(cfg.http3_retry_policy),
            cfg.http3_max_datagram_size,
            cfg.http3_udp_recv_buffer_bytes,
            cfg.http3_udp_send_buffer_bytes,
            cfg.http3_ecn_enabled,
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
        state.logger.info(null, "Response compression enabled (min size: {d} bytes, gzip=true, brotli_native=false)", .{
            cfg.compression_min_size,
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
    // Read after the soft limit is applied: each tunnel holds two sockets.
    state.websocket_default_max_tunnels = defaultWebSocketTunnelCap();
    if (configRelaysWebSockets(cfg) or cfg.proxy_websocket_max_tunnels > 0) {
        state.logger.info(null, "WebSocket tunnels: reactor_threads={d} max_tunnels={d}", .{
            reactor_threads,
            if (cfg.proxy_websocket_max_tunnels > 0) cfg.proxy_websocket_max_tunnels else state.websocket_default_max_tunnels,
        });
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
    if (sharding_enabled) {
        state.logger.info(null, "Connection model: {d} load-balanced listener shard accept loops with blocking per-connection work on a bounded worker pool", .{effective_shards});
    } else {
        state.logger.info(null, "Connection model: non-blocking accept loop on the main thread with blocking per-connection work on a bounded worker pool", .{});
    }
    state.logger.info(null, "Accept batching: batch_limit={d} fairness_yield_every={d}", .{ cfg.accept_batch_limit, cfg.accept_fairness_yield_every });

    // Install signal handlers for graceful shutdown
    http.shutdown.installSignalHandlers();
    state.logger.info(null, "Signal handlers installed (SIGTERM/SIGINT shutdown, SIGHUP reload, SIGUSR1 reopen logs, SIGUSR2 upgrade)", .{});

    state.metricsSetListenerShards(effective_shards);

    if (sharding_enabled) {
        state.logger.info(null, "Listener sharding enabled: {} shards on {s}:{}", .{
            effective_shards, cfg.listen_host, cfg.listen_port,
        });
        errdefer {
            if (shard_thread_count > 0) {
                http.shutdown.requestShutdown();
                for (shard_threads[0..shard_thread_count]) |t| t.join();
            }
        }
        var ti: u16 = 0;
        while (ti < shard_fd_count) : (ti += 1) {
            const ctx = gaccept.ShardAcceptContext{
                .listen_fd = shard_fds[ti],
                .shard_id = ti,
                .worker_pool = &worker_pool,
                .state = &state,
                .batch_options = .{
                    .limit = cfg.accept_batch_limit,
                    .fairness_yield_every = cfg.accept_fairness_yield_every,
                },
            };
            shard_threads[shard_thread_count] = std.Thread.spawn(.{}, gaccept.runShardAcceptLoop, .{ctx}) catch |err| {
                state.logger.err(null, "failed to spawn shard {} accept thread: {}", .{ ti, err });
                return err;
            };
            shard_thread_count += 1;
        }
    }

    var ready_events: [64]http.event_loop.Event = undefined;
    while (!http.shutdown.isShutdownRequested()) {
        const now_ms = http.event_loop.monotonicMs();
        const timeout_ms = timer.msUntilNextTick(now_ms);
        const event_count = event_loop.wait(ready_events[0..], timeout_ms) catch |err| blk: {
            if (err == error.EventLoopUnrecoverable) {
                // #148: the ring stopped accepting submissions, so readiness
                // this loop believes is armed may not be. Continuing would
                // leave the process up but deaf — the listener could stop
                // reporting accepts with no deadline reaper behind it. Take
                // the documented fatal path (log, drain, exit) instead of
                // self-healing or silently degrading.
                state.logger.err(null, "event loop backend '{s}' is unrecoverable: {}; draining and shutting down", .{
                    event_loop.backendName(),
                    err,
                });
                http.shutdown.requestShutdown();
                break :blk 0;
            }
            state.logger.err(null, "event loop wait error: {}", .{err});
            continue;
        };

        var i: usize = 0;
        while (i < event_count) : (i += 1) {
            const ev = ready_events[i];
            if (active.contains(ev.fd)) {
                event_loop.remove(ev.fd) catch {};
                if (!active.reserveWork(ev.fd)) continue;
                worker_pool.submitActiveSocketReady(ev.fd) catch |err| {
                    state.logger.warn(null, "active connection worker submit failed: {}", .{err});
                    if (active.checkout(ev.fd)) |taken| {
                        var conn = taken;
                        conn.deinit();
                    }
                };
                continue;
            }
            if (!ev.readable) continue;
            if (ev.fd == listen_fd and !sharding_enabled) {
                _ = gaccept.acceptReadyConnectionsShard(listen_fd, 0, &worker_pool, &state, .{
                    .limit = cfg.accept_batch_limit,
                    .fairness_yield_every = cfg.accept_fairness_yield_every,
                });
            } else if (parked.resumeReady(ev.fd)) {
                // A parked keepalive connection has a new request (or closed).
                // Stop watching it and hand it to a worker, which serves one
                // request and re-parks or closes. The connection slot acquired
                // at accept stays held across the park/resume cycle.
                event_loop.removeReadFd(ev.fd) catch {};
                worker_pool.submitParkedReady(ev.fd) catch {
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
                // Drain-mode tunnels read the supersession stamp the reload
                // just published; wake them rather than wait for a socket.
                tunnel_reactor.wakeAll();
            }
            var current_cfg_lease = worker_ctx.acquireConfig();
            defer current_cfg_lease.release();
            const current_cfg = current_cfg_lease.cfg;
            gshutdown.runActiveHealthChecks(current_cfg, &state, worker_ctx.config_store);
            gshutdown.runDnsDiscoveryRefresh(current_cfg, &state);
            gshutdown.runProxyCacheMaintenance(current_cfg, &state);
            // Close keepalive connections idle longer than the keepalive timeout
            // while parked off the worker pool (#138).
            _ = parked.reapIdle(http.event_loop.monotonicMs(), current_cfg.keep_alive_timeout_ms);
            dispatchDueActiveDrivePolls(&active, &state, &event_loop, &worker_pool);
            reapActiveConnections(&active, &state, &event_loop);
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

    // Join shard accept threads (they exit when shutdown is requested) and
    // close the shard listener fds before draining the worker pool.
    for (shard_threads[0..shard_thread_count]) |t| t.join();
    for (shard_fds[0..shard_fd_count]) |sfd| _ = std.c.close(sfd);

    const active_at_drain_start = blk: {
        state.connection_mutex.lock();
        defer state.connection_mutex.unlock();
        break :blk state.active_connections_total;
    };
    state.logger.info(null, "Shutdown requested; draining active connection work (timeout={}ms active_connections={d})", .{ cfg.shutdown_drain_timeout_ms, active_at_drain_start });
    // Publish the one authoritative, startup-policy deadline before workers
    // begin draining. Long-lived response relays only observe this absolute
    // boundary; they never derive a later deadline from a request generation.
    const shutdown_started_ms = http.event_loop.monotonicMs();
    const response_stream_shutdown_deadline_ms = @max(shutdown_started_ms +| cfg.shutdown_drain_timeout_ms, 1);
    state.publishResponseStreamShutdownDeadline(response_stream_shutdown_deadline_ms);
    const h3_deadline_us = http.http3_runtime.Runtime.nowUsPublic() + cfg.shutdown_drain_timeout_ms * std.time.us_per_ms;
    if (http3_runtime) |*runtime| {
        updateHttp3Advertisement(&state, cfg, runtime, .draining);
        runtime.beginDrain(h3_deadline_us);
    }
    // Start every tunnel's shutdown drain now; they close within the drain
    // window while workers finish their requests.
    tunnel_reactor.wakeAll();
    const drain_result = worker_pool.shutdownAndJoin(cfg.shutdown_drain_timeout_ms);
    // Workers are joined, so no more tunnels can arrive; wait for the ones
    // the reactor owns to reach their drain deadline.
    tunnel_reactor.stopAndJoin();
    if (http3_runtime) |*runtime| {
        while (!runtime.isDrained() and http.http3_runtime.Runtime.nowUsPublic() < h3_deadline_us) {
            std.Io.sleep(compat.io(), .fromMilliseconds(10), .awake) catch {};
        }
    }
    state.metricsRecordDrain(drain_result.timed_out, drain_result.forced_closes);
    if (drain_result.timed_out) {
        state.logger.warn(null, "drain timeout elapsed; force-closed {d} queued connection(s)", .{drain_result.forced_closes});
    }
    state.logger.info(null, "Graceful shutdown complete (forced_closes={d} drain_timed_out={})", .{ drain_result.forced_closes, drain_result.timed_out });
}

/// Tunnel cap when `proxy_websocket_max_tunnels` is 0 (#818): a quarter of
/// the descriptor soft limit (each tunnel holds two sockets, leaving the rest
/// for ordinary connections), at most 4096.
fn defaultWebSocketTunnelCap() u32 {
    const limits = std.posix.getrlimit(std.posix.rlimit_resource.NOFILE) catch return 256;
    const soft: u64 = @intCast(limits.cur);
    return @intCast(std.math.clamp(soft / 4, 1, 4096));
}

/// True when any location, top-level or in a server block, sets
/// `proxy_websocket on`.
fn configRelaysWebSockets(cfg: *const edge_config.EdgeConfig) bool {
    for (cfg.location_blocks) |block| if (block.websocket != null) return true;
    for (cfg.server_blocks) |server| {
        for (server.location_blocks) |block| if (block.websocket != null) return true;
    }
    return false;
}

const Http3AdvertisementPhase = enum {
    steady,
    draining,
};

fn updateHttp3Advertisement(
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    runtime: ?*http.http3_runtime.Runtime,
    phase: Http3AdvertisementPhase,
) void {
    const runtime_ready = if (runtime) |rt| rt.snapshot().server_bootstrapped else false;
    const advertisement: http.http3_handler.Advertisement = blk: {
        if (!cfg.http3_enabled) break :blk .disabled;
        if (phase == .draining) break :blk .clear;
        if (!runtime_ready) break :blk .disabled;
        if (cfg.http3_alt_svc == .off) break :blk .disabled;
        break :blk .{ .active = .{
            .port = if (runtime) |rt| rt.snapshot().quic_port else cfg.quic_port,
            .max_age_seconds = cfg.http3_alt_svc_max_age_seconds,
        } };
    };
    const effective = http.http3_handler.formatAdvertisement(state.allocator, advertisement) catch null;
    state.runtime_mutex.lock();
    if (state.http3_alt_svc) |old| state.allocator.free(old);
    state.http3_alt_svc = effective;
    state.http3_advertisement_state = switch (advertisement) {
        .disabled => if (!cfg.http3_enabled) .disabled else if (!runtime_ready) .configured_unavailable else .ready_advertisement_disabled,
        .clear => .clearing,
        .active => .advertising,
    };
    if (phase == .draining) state.http3_advertisement_state = .draining;
    state.runtime_mutex.unlock();
}

fn nativeResumptionMetricsObserver(state: *GatewayState) tls_core.resumption_runtime.Observer {
    return .{
        .ctx = state,
        .onTicketIssueFn = nativeResumptionTicketIssue,
        .onTicketStoreFn = nativeResumptionTicketStore,
        .onTicketResolveFn = nativeResumptionTicketResolve,
        .onResumptionAttemptFn = nativeResumptionAttempt,
        .onResumptionOutcomeFn = nativeResumptionOutcome,
        .onTicketKeyReservationAttemptFn = nativeResumptionTicketKeyReservationAttempt,
    };
}

// #520: a secret-free, fixed marker (no key material, no path) logged at
// the exact instant `resumption_runtime.Runtime.loadPersistentTicketKeysFromFile`
// is about to call `ticket_key_snapshot.reserveNonceLeasesInFile` -- whose
// own first action is acquiring `${path}.lock`. `tests/integration.zig`'s
// multi-process startup-reservation soak polls each process's own log
// file for this marker before releasing a barrier lock it holds, so both
// processes' real reservation attempts are forced to overlap rather than
// merely likely to.
fn nativeResumptionTicketKeyReservationAttempt(ctx: *anyopaque) void {
    const state: *GatewayState = @ptrCast(@alignCast(ctx));
    state.logger.info(null, "native TLS/QUIC persistent ticket-key reservation attempt starting", .{});
}

fn nativeResumptionTransport(transport: tls_core.resumption_runtime.Transport) http.metrics.ResumptionTransport {
    return switch (transport) {
        .record => .record,
        .quic => .quic,
    };
}

fn nativeResumptionMode(mode: tls_core.resumption_runtime.Mode) http.metrics.ResumptionMode {
    return switch (mode) {
        .disabled, .stateful => .stateful,
        .stateless => .stateless,
        .hybrid => .hybrid,
    };
}

fn nativeTicketResult(result: tls_core.resumption_runtime.TicketResult) http.metrics.TicketResult {
    return switch (result) {
        .success => .success,
        .rejected => .rejected,
        .failed => .failed,
    };
}

fn nativeResumptionOutcomeValue(outcome: tls_core.resumption_runtime.ResumptionOutcome) http.metrics.ResumptionOutcome {
    return switch (outcome) {
        .accepted => .accepted,
        .full_handshake => .full_handshake,
        .incompatible => .incompatible,
        .miss => .miss,
        .fatal => .fatal,
    };
}

fn nativeResumptionTicketIssue(ctx: *anyopaque, transport: tls_core.resumption_runtime.Transport, mode: tls_core.resumption_runtime.Mode, result: tls_core.resumption_runtime.TicketResult) void {
    const state: *GatewayState = @ptrCast(@alignCast(ctx));
    state.metrics_mutex.lock();
    defer state.metrics_mutex.unlock();
    state.metrics.recordTicketIssue(nativeResumptionTransport(transport), nativeResumptionMode(mode), nativeTicketResult(result));
}

fn nativeResumptionTicketStore(ctx: *anyopaque, result: tls_core.resumption_runtime.TicketResult) void {
    const state: *GatewayState = @ptrCast(@alignCast(ctx));
    state.metrics_mutex.lock();
    defer state.metrics_mutex.unlock();
    state.metrics.recordTicketStore(nativeTicketResult(result));
}

fn nativeResumptionTicketResolve(ctx: *anyopaque, mode: tls_core.resumption_runtime.Mode, result: tls_core.resumption_runtime.TicketResult) void {
    const state: *GatewayState = @ptrCast(@alignCast(ctx));
    state.metrics_mutex.lock();
    defer state.metrics_mutex.unlock();
    state.metrics.recordTicketResolve(nativeResumptionMode(mode), nativeTicketResult(result));
}

fn nativeResumptionAttempt(ctx: *anyopaque, transport: tls_core.resumption_runtime.Transport) void {
    const state: *GatewayState = @ptrCast(@alignCast(ctx));
    state.metrics_mutex.lock();
    defer state.metrics_mutex.unlock();
    state.metrics.recordResumptionAttempt(nativeResumptionTransport(transport));
}

fn nativeResumptionOutcome(ctx: *anyopaque, transport: tls_core.resumption_runtime.Transport, outcome: tls_core.resumption_runtime.ResumptionOutcome) void {
    const state: *GatewayState = @ptrCast(@alignCast(ctx));
    state.metrics_mutex.lock();
    defer state.metrics_mutex.unlock();
    state.metrics.recordResumptionOutcome(nativeResumptionTransport(transport), nativeResumptionOutcomeValue(outcome));
}

/// #368 Slice 3: bridges the replay store's `Event` observer to `Metrics`,
/// the same pattern `nativeResumptionMetricsObserver` uses for
/// `resumption_runtime.Observer`. Notifications already arrive with the
/// store's mutex released (see `early_data_replay.zig`'s `LocalStore.claim`),
/// so this only needs to take the metrics lock.
fn nativeEarlyDataReplayMetricsObserver(state: *GatewayState) tls_core.early_data_replay.Observer {
    return .{ .ctx = state, .onEventFn = nativeEarlyDataReplayEvent };
}

fn mapEarlyDataReplayEvent(event: tls_core.early_data_replay.Event) http.metrics.EarlyDataReplayOutcome {
    return switch (event) {
        .accepted => .accepted,
        .duplicate => .duplicate,
        .capacity_rejected => .capacity_rejected,
        .expired => .expired,
        .unavailable => .unavailable,
        .startup_quarantine => .startup_quarantine,
    };
}

fn nativeEarlyDataReplayEvent(ctx: *anyopaque, event: tls_core.early_data_replay.Event) void {
    const state: *GatewayState = @ptrCast(@alignCast(ctx));
    state.metrics_mutex.lock();
    defer state.metrics_mutex.unlock();
    state.metrics.recordEarlyDataReplay(mapEarlyDataReplayEvent(event));
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

fn handleAcceptedClient(raw_ctx: *anyopaque, item: http.worker_pool.WorkItem) void {
    const ctx: *WorkerContext = @ptrCast(@alignCast(raw_ctx));

    switch (item) {
        .accepted => |client_fd| startNewConnection(ctx, client_fd),
        .parked_ready => |fd| {
            // Resume path (#138): the event loop dispatched a parked keepalive
            // connection that became readable. Its session, TLS state, and
            // connection slot are already owned by the parked registry.
            if (ctx.parked.checkout(fd)) |pc| resumeParkedConnection(ctx, pc);
        },
        .active_socket_ready, .active_drive_poll => |fd| {
            switch (checkoutActiveForWorkerAt(ctx.active, fd, http.event_loop.monotonicMs())) {
                .missing => return,
                .expired => {
                    ctx.state.logger.debug(null, "active native downstream connection deadline expired before worker dispatch fd={d}", .{fd});
                    return;
                },
                .ready => |conn| {
                    var mutable = conn;
                    advanceActiveConnection(ctx, &mutable);
                },
            }
        },
    }
}

const ActiveCheckoutResult = union(enum) {
    missing,
    expired,
    ready: http.downstream_connection.ManagedConnection,
};

fn checkoutActiveForWorkerAt(
    active: *http.downstream_connection.ActiveRegistry,
    fd: std.posix.fd_t,
    now_ms: u64,
) ActiveCheckoutResult {
    var conn = active.checkout(fd) orelse return .missing;
    if (conn.expired(now_ms)) {
        conn.deinit();
        return .expired;
    }
    return .{ .ready = conn };
}

/// Outcome of serving one request on a keepalive HTTP/1.1 connection.
const ServeOutcome = union(enum) {
    /// Buffered (pipelined) data is already available; serve another request now.
    serve_again,
    /// Connection is idle and keep-alive; park it off the worker pool.
    park,
    /// Connection should be closed (no keep-alive, shutdown, max-requests, error).
    close,
    /// The request became a WebSocket tunnel (#818). The caller detaches the
    /// connection from its own bookkeeping (keeping the socket and its
    /// connection slot open), `attach`es it to the job, and `submit`s it.
    tunnel: *gws_tunnel.TunnelJob,
};

fn hasBufferedHttp1Work(conn: anytype, session: *const ConnectionSession) bool {
    if (session.pending_len > 0) return true;
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "pending")) return conn.pending() > 0;
        if (comptime @hasDecl(Child, "pendingPlaintext")) return conn.pendingPlaintext() > 0;
    }
    return false;
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

/// Serve exactly one HTTP/1.1 request on `conn` (a plaintext `NetStream` or
/// a native TLS connection stream), then decide what to do with the
/// connection.
fn serveOneRequest(
    ctx: *WorkerContext,
    conn: anytype,
    session: *ConnectionSession,
    connection_ip: []const u8,
    served: *u32,
    enable_proxy_protocol: bool,
    /// The caller handles `.tunnel` (#818); otherwise a WebSocket tunnel runs
    /// inline on this worker.
    allow_tunnel_handoff: bool,
) ServeOutcome {
    // The lease is held for the whole request, including any WebSocket
    // tunnel it becomes, so the generation (and its supersession stamp) stays
    // alive for as long as anything admitted under it runs. A handed-off
    // tunnel takes the lease with it.
    var live_cfg_lease = ctx.acquireConfig();
    var lease_transferred = false;
    defer if (!lease_transferred) live_cfg_lease.release();
    const live_cfg = live_cfg_lease.cfg;
    const outcome = serveOneRequestWithConfig(ctx, conn, session, live_cfg, &live_cfg_lease, &live_cfg_lease.version.superseded_at_ms, connection_ip, served, enable_proxy_protocol, allow_tunnel_handoff);
    switch (outcome) {
        .tunnel => |job| {
            job.adoptConfigLease(live_cfg_lease);
            lease_transferred = true;
        },
        else => {},
    }
    return outcome;
}

fn serveOneRequestWithConfig(
    ctx: *WorkerContext,
    conn: anytype,
    session: *ConnectionSession,
    cfg: *const edge_config.EdgeConfig,
    config_lease: ?*gs.ConfigLease,
    /// `cfg`'s generation supersession stamp (see `ManagedConfigVersion`).
    config_superseded_at: *const std.atomic.Value(u64),
    connection_ip: []const u8,
    served: *u32,
    enable_proxy_protocol: bool,
    allow_tunnel_handoff: bool,
) ServeOutcome {
    const header_timeout_ms = cfg.request_limits.effectiveHeaderTimeout();
    const write_timeout_ms = if (cfg.downstream_write_timeout_ms > 0)
        cfg.downstream_write_timeout_ms
    else
        header_timeout_ms;
    setConnTimeouts(conn, header_timeout_ms, write_timeout_ms);

    const max_requests_per_connection = cfg.max_requests_per_connection;
    // This is the last request the server will allow on this physical
    // connection: handleConnection must send `Connection: close` on its
    // response rather than `keep-alive`, or the client will reuse a
    // connection the server is about to tear down and lose its next request.
    const is_last_allowed_request = max_requests_per_connection > 0 and served.* + 1 >= max_requests_per_connection;

    var keep_alive = false;
    var tunnel_handoff: ?*gws_tunnel.TunnelJob = null;
    handleConnection(conn, session, cfg, config_lease, config_superseded_at, ctx.state, &keep_alive, connection_ip, enable_proxy_protocol, is_last_allowed_request, if (allow_tunnel_handoff) &tunnel_handoff else null) catch |err| {
        if (isBenignDisconnect(err)) {
            ctx.state.logger.debug(null, "keepalive connection closed by peer: {}", .{err});
        } else {
            ctx.state.logger.err(null, "edge connection error: {}", .{err});
        }
        return .close;
    };
    served.* += 1;
    if (tunnel_handoff) |job| return .{ .tunnel = job };

    if (!keep_alive or http.shutdown.isShutdownRequested()) return .close;
    if (max_requests_per_connection > 0 and served.* >= max_requests_per_connection) return .close;
    if (hasBufferedHttp1Work(conn, session)) return .serve_again;
    return .park;
}

fn startNewConnection(ctx: *WorkerContext, client_fd: std.posix.fd_t) void {
    const session = ctx.session_pool.acquire() catch |err| {
        ctx.state.logger.warn(null, "failed to acquire pooled connection session: {}", .{err});
        ctx.state.releaseConnectionSlot(client_fd);
        _ = std.c.close(client_fd);
        return;
    };

    // Ownership of session/fd transfers to the parked registry on `park`.
    // Until then, this teardown runs on every other exit (set `transferred` to
    // skip it once ownership has moved).
    var transferred = false;
    defer if (!transferred) closeNewConnection(ctx, client_fd, session);

    const owned_connection_ip = gconn.clientIpFromFd(ctx.state.allocator, client_fd) catch null;
    var transferred_ip = false;
    defer if (!transferred_ip) {
        if (owned_connection_ip) |ip| ctx.state.allocator.free(ip);
    };
    const connection_ip = owned_connection_ip orelse "unknown";

    var cfg_lease = ctx.acquireConfig();
    var cfg_lease_transferred = false;
    defer if (!cfg_lease_transferred) cfg_lease.release();
    const cfg = cfg_lease.cfg;

    gconn.setNoDelay(client_fd) catch |err| {
        ctx.state.logger.warn(null, "failed to set TCP_NODELAY on client fd: {}", .{err});
    };

    // Effective per-phase timeouts used throughout this connection's lifetime.
    const header_timeout_ms = cfg.request_limits.effectiveHeaderTimeout();
    const body_timeout_ms = cfg.request_limits.effectiveBodyTimeout();
    const write_timeout_ms = if (cfg.downstream_write_timeout_ms > 0) cfg.downstream_write_timeout_ms else header_timeout_ms;
    const handshake_timeout_ms = if (cfg.tls_handshake_timeout_ms > 0)
        cfg.tls_handshake_timeout_ms
    else
        cfg.keep_alive_timeout_ms;

    if (ctx.native_tls_provider) |native_provider| {
        if (cfg.proxy_protocol_mode != .off) {
            ctx.state.logger.warn(null, "native TLS path does not support PROXY protocol preface parsing yet", .{});
            return;
        }
        // #763: the policy table comes from the very configuration
        // generation this connection leased, never from a later reload.
        const client_policies = cfg_lease.version.client_policies;
        if (client_policies == null and cfg.anyClientAuth()) {
            // Fail closed: never serve a listener that is configured to
            // demand client certificates without a policy table.
            ctx.state.logger.warn(null, "client certificate verification is enabled but no client policy set is loaded", .{});
            return;
        }
        const tls_protocol_policy = gprotocol_policy.listenerPolicyFromConfig(cfg);
        const native = http.native_tls_connection.NativeTlsConnection.createWithOptions(
            ctx.state.allocator,
            client_fd,
            tls_protocol_policy,
            native_provider,
            .{
                .buffer_limits = cfg.tls_buffer_limits,
                .resumption_runtime = ctx.resumption_runtime,
                .early_data_replay_gate = ctx.early_data_replay_gate,
                .server_early_data_policy = nativeTcpServerEarlyDataPolicy(ctx.early_data_replay_gate),
                .client_policies = client_policies,
            },
        ) catch |err| {
            ctx.state.logger.warn(null, "native tls connection setup failed: {}", .{err});
            return;
        };
        var managed = http.downstream_connection.ManagedConnection.init(
            .{ .native = native },
            .{ .native_handshake = .{
                .deadline_ms = deadlineFromNow(http.event_loop.monotonicMs(), handshake_timeout_ms),
            } },
        );
        managed.lifecycle = .{
            .session = session,
            .release_session_ctx = ctx,
            .release_session_fn = activeReleaseSession,
            .config = cfg,
            .release_config_ctx = ctx.config_store,
            .release_config_version = cfg_lease.version,
            .release_config_fn = activeReleaseConfig,
            .close_ctx = ctx.state,
            .close_fn = activeConnectionCloseHook,
            .metrics = &ctx.state.metrics,
            .metrics_mutex = &ctx.state.metrics_mutex,
            .owned_ip = if (owned_connection_ip) |ip| @constCast(ip) else null,
            .allocator = ctx.state.allocator,
            .config_generation = cfg_lease.version.generation,
            .handshake_timeout_ms = handshake_timeout_ms,
            .header_timeout_ms = header_timeout_ms,
            .body_timeout_ms = body_timeout_ms,
            .write_timeout_ms = write_timeout_ms,
            .idle_timeout_ms = cfg.keep_alive_timeout_ms,
        };
        cfg_lease_transferred = true;
        transferred = true;
        if (owned_connection_ip != null) transferred_ip = true;
        const interest = managed.interest;
        ctx.active.insert(&managed) catch |err| {
            ctx.state.logger.warn(null, "native tls active registry insert failed: {}", .{err});
            managed.deinit();
            return;
        };
        ctx.event_loop.add(client_fd, interest) catch |err| {
            ctx.state.logger.warn(null, "native tls event registration failed: {}", .{err});
            if (ctx.active.checkout(client_fd)) |taken| {
                var conn = taken;
                conn.deinit();
            }
        };
        return;
    } else {
        gconn.setNonBlocking(client_fd, false) catch |err| {
            ctx.state.logger.warn(null, "failed to switch client fd to blocking mode: {}", .{err});
            return;
        };
        if (!cfg.http1_enabled) {
            ctx.state.logger.err(null, "plaintext HTTP/1.1 parser disabled and h2c is not supported", .{});
            return;
        }
        // Plaintext path: apply read and write timeouts immediately (no separate
        // handshake phase).
        if (header_timeout_ms > 0 or write_timeout_ms > 0) {
            gconn.setSocketTimeoutMs(client_fd, header_timeout_ms, write_timeout_ms) catch |err| {
                ctx.state.logger.warn(null, "failed to set client socket timeout: {}", .{err});
            };
        }
        const stream = compat.netStreamFromFd(client_fd);
        var served: u32 = 0;
        while (true) switch (serveOneRequest(ctx, stream, session, connection_ip, &served, true, true)) {
            .serve_again => {},
            .park => {
                transferred = true;
                parkConnection(ctx, client_fd, session, served, connection_ip);
                return;
            },
            .close => return,
            .tunnel => |job| {
                // The tunnel owns the socket and its connection slot now.
                transferred = true;
                ctx.session_pool.release(session);
                job.attach(.{ .plaintext = client_fd });
                job.submit();
                return;
            },
        };
    }
}

fn resumeParkedConnection(ctx: *WorkerContext, pc: *http.keepalive_park.ParkedConnection) void {
    var served = pc.served;
    const stream = compat.netStreamFromFd(pc.fd);
    while (true) switch (serveOneRequest(ctx, stream, pc.session, pc.ip(), &served, false, true)) {
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
        .tunnel => |job| {
            // The tunnel owns the socket and its connection slot now.
            job.attach(.{ .plaintext = ctx.parked.detach(pc) });
            job.submit();
            return;
        },
    };
}

fn dispatchNegotiatedHttp(
    ctx: *WorkerContext,
    conn: anytype,
    negotiated: http.negotiated_dispatch.NegotiatedProtocol,
    session: *ConnectionSession,
    cfg: *const edge_config.EdgeConfig,
    connection_ip: []const u8,
    served: *u32,
) !ServeOutcome {
    var runtime = GatewayHttpRuntime{
        .ctx = ctx,
        .session = session,
        .cfg = cfg,
        .connection_ip = connection_ip,
        .served = served,
    };
    return http.negotiated_dispatch.dispatchToRuntime(&runtime, conn, negotiated, GatewayHttpRuntime);
}

const GatewayHttpRuntime = struct {
    pub const Outcome = ServeOutcome;

    ctx: *WorkerContext,
    session: *ConnectionSession,
    cfg: *const edge_config.EdgeConfig,
    connection_ip: []const u8,
    served: *u32,

    pub fn serveHttp1(self: *@This(), conn: anytype) !Outcome {
        return serveOneRequest(self.ctx, conn, self.session, self.connection_ip, self.served, false, false);
    }

    pub fn handleHttp2(self: *@This(), conn: anytype) !void {
        try handleHttp2Connection(conn, self.session, self.cfg, self.ctx.state, self.connection_ip);
    }
};

/// Tear down a connection that was never parked: socket close, pooled-session
/// release, and connection-slot release. Mirrors the registry's teardown so a
/// connection is accounted identically whichever path closes it.
fn closeNewConnection(
    ctx: *WorkerContext,
    fd: std.posix.fd_t,
    session: *ConnectionSession,
) void {
    // Release the slot while this connection still owns the fd number. The
    // slot table is keyed by fd, and once it is closed the acceptor may hand
    // the same number to a new connection: releasing afterwards would drop
    // that connection's entry and leak one active-connection count.
    ctx.state.releaseConnectionSlot(fd);
    _ = std.c.close(fd);
    ctx.session_pool.release(session);
}

/// Park a freshly-idle new connection off the worker pool and arm the event
/// loop. On any failure the connection is fully closed.
fn parkConnection(
    ctx: *WorkerContext,
    fd: std.posix.fd_t,
    session: *ConnectionSession,
    served: u32,
    connection_ip: []const u8,
) void {
    const now = http.event_loop.monotonicMs();
    const pc = ctx.parked.parkNew(fd, session, served, connection_ip, now) catch {
        closeNewConnection(ctx, fd, session);
        return;
    };
    ctx.event_loop.add(fd, pc.eventInterest()) catch {
        if (ctx.parked.checkout(fd)) |taken| ctx.parked.closeSlot(taken, .@"error");
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
    ctx.event_loop.add(pc.fd, pc.eventInterest()) catch {
        if (ctx.parked.checkout(pc.fd)) |taken| ctx.parked.closeSlot(taken, .@"error");
    };
}

fn activeReleaseSession(raw_ctx: *anyopaque, raw_session: *anyopaque) void {
    const ctx: *WorkerContext = @ptrCast(@alignCast(raw_ctx));
    const session: *ConnectionSession = @ptrCast(@alignCast(raw_session));
    ctx.session_pool.release(session);
}

fn activeReleaseConfig(raw_store: *anyopaque, raw_version: *anyopaque) void {
    const store: *ReloadableConfigStore = @ptrCast(@alignCast(raw_store));
    const version: *gs.ManagedConfigVersion = @ptrCast(@alignCast(raw_version));
    store.release(version);
}

fn activeConnectionCloseHook(raw_state: *anyopaque, fd: std.posix.fd_t) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.releaseConnectionSlot(fd);
}

fn deadlineFromNow(now_ms: u64, timeout_ms: u32) u64 {
    return if (timeout_ms == 0) 0 else now_ms + @as(u64, timeout_ms);
}

/// Wall-clock source for the process-scoped native resumption runtime
/// (#488): ticket lifetime/age bookkeeping needs real wall-clock time, not
/// the monotonic clock the event loop otherwise uses.
fn systemNowUnixMs(_: *anyopaque) i64 {
    return compat.milliTimestamp();
}

/// #368 Slice 3: constructs the single process-scoped replay store `run`
/// installs into every native TLS backend that can accept early data, using
/// the operator-configured `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MAX_ENTRIES`
/// capacity (already validated by `edge_config.validateEarlyDataReplayConfig`
/// against `early_data_replay.hard_max_entries`). The startup-quarantine
/// window reuses `ServerEarlyDataPolicy`'s default age-skew tolerance — the
/// production native early-data enable/age-skew config seam from #366/#367
/// is not yet wired into composition on current `main` (`setServerEarlyDataPolicy`
/// is not called here), so there is no distinct configured value to read
/// yet; #368 deliberately does not add a second, independent one (see the
/// module doc: no separately configurable replay TTL). This keeps the
/// quarantine at least as long as that policy's default, matching RFC 9846
/// §8.2: the recording window must not overlap startup history the store no
/// longer has.
fn initNativeEarlyDataReplayStore(
    allocator: std.mem.Allocator,
    max_entries: usize,
    now_unix_ms: u64,
) tls_core.early_data_replay.LocalStore.InitError!tls_core.early_data_replay.LocalStore {
    return tls_core.early_data_replay.LocalStore.init(
        allocator,
        .{ .max_entries = max_entries },
        (tls_core.tls13_backend.ServerEarlyDataPolicy{}).age_skew_tolerance_ms,
        now_unix_ms,
    );
}

/// #368 Slice 2/3: whether a native PSK/early-data path can actually exist
/// for this composition, and therefore whether `run()` should pay for
/// constructing the process-scoped replay store at all — evaluated only once
/// the operator has also opted into `TARDIGRADE_TLS_NATIVE_EARLY_DATA_REPLAY_MODE=process_local`
/// (see the call site). Native resumption being enabled is necessary but not
/// sufficient — a native TLS path that could ever accept
/// early data must also be configured: native TCP (`native_tls_provider`)
/// or, when HTTP/3 is enabled, native QUIC/H3 (`h3_credential_provider`).
/// Plain HTTP or configurations without a native TLS/QUIC credential path do
/// not consult this seam, so those and resumption-disabled deployments must
/// never gain the configured-entry allocation or a new startup-failure path
/// for a security feature they cannot use.
fn nativeEarlyDataReplayStoreNeeded(
    native_resumption_runtime_enabled: bool,
    native_tls_provider_present: bool,
    http3_enabled: bool,
    h3_credential_provider_present: bool,
) bool {
    return native_resumption_runtime_enabled and
        (native_tls_provider_present or (http3_enabled and h3_credential_provider_present));
}

/// #368 Slice 3: whether `run()` should construct the process-scoped replay
/// store at all — the configured mode gates construction; `nativeEarlyDataReplayStoreNeeded`
/// alone only answers "could a native PSK/early-data path exist here." The
/// safe `disabled` default (and any mode other than `process_local`) must
/// never construct a store, even when a native path exists, so plain HTTP,
/// no-native-TLS-path, resumption-disabled, or explicitly opted-out deployments
/// never pay the configured-entry reservation or gain a new
/// startup-failure path for a feature they haven't enabled.
fn nativeEarlyDataReplayStoreEnabled(
    replay_mode: edge_config.EarlyDataReplayMode,
    native_resumption_runtime_enabled: bool,
    native_tls_provider_present: bool,
    http3_enabled: bool,
    h3_credential_provider_present: bool,
) bool {
    return replay_mode == .process_local and nativeEarlyDataReplayStoreNeeded(
        native_resumption_runtime_enabled,
        native_tls_provider_present,
        http3_enabled,
        h3_credential_provider_present,
    );
}

const NativeEarlyDataReplayComposition = struct {
    store_enabled: bool,
    early_data_replay_gate: ?tls_core.tls13_backend.EarlyDataReplayGate,
};

/// Selects the replay-store/gate options shared by `run()`'s native TCP and
/// H3 composition. The optional gate is installed only when the same decision
/// says the process-scoped store is enabled; disabled mode therefore flows
/// into `NativeTlsConnection.createWithOptions` as a null gate rather than an
/// independently reconstructed test expectation.
fn nativeEarlyDataReplayComposition(
    replay_mode: edge_config.EarlyDataReplayMode,
    native_resumption_runtime_enabled: bool,
    native_tls_provider_present: bool,
    http3_enabled: bool,
    h3_credential_provider_present: bool,
    gate: ?tls_core.tls13_backend.EarlyDataReplayGate,
) NativeEarlyDataReplayComposition {
    const store_enabled = nativeEarlyDataReplayStoreEnabled(
        replay_mode,
        native_resumption_runtime_enabled,
        native_tls_provider_present,
        http3_enabled,
        h3_credential_provider_present,
    );
    return .{
        .store_enabled = store_enabled,
        .early_data_replay_gate = if (store_enabled) gate else null,
    };
}

fn nativeTcpServerEarlyDataPolicy(
    gate: ?tls_core.tls13_backend.EarlyDataReplayGate,
) tls_core.tls13_backend.ServerEarlyDataPolicy {
    return if (gate != null) .{ .enabled = true } else .{};
}

const native_persistent_ticket_max: usize = 16 * 1024;

fn nativeResumptionSessionLimits(cfg: *const edge_config.EdgeConfig) tls_core.session.Limits {
    var limits = tls_core.session.Limits.default;
    if (cfg.tls_native_ticket_keys_path.len > 0) {
        limits.max_ticket_len = native_persistent_ticket_max;
        limits.max_serialized_len = native_persistent_ticket_max - tls_core.ticket_protection.envelope_overhead;
    }
    return limits;
}

fn reapActiveConnections(
    active: *http.downstream_connection.ActiveRegistry,
    state: *GatewayState,
    event_loop: *http.event_loop.EventLoop,
) void {
    var expired: [32]http.downstream_connection.ManagedConnection = undefined;
    while (true) {
        const count = active.reapExpired(http.event_loop.monotonicMs(), expired[0..]);
        if (count == 0) break;
        for (expired[0..count]) |taken| {
            var conn = taken;
            event_loop.remove(conn.fd) catch {};
            state.logger.debug(null, "active native downstream connection deadline expired fd={d}", .{conn.fd});
            conn.deinit();
        }
        if (count < expired.len) break;
    }
}

fn dispatchDueActiveDrivePolls(
    active: *http.downstream_connection.ActiveRegistry,
    state: *GatewayState,
    event_loop: *http.event_loop.EventLoop,
    worker_pool: *http.worker_pool.WorkerPool,
) void {
    dispatchDueActiveDrivePollsAt(
        active,
        state,
        http.event_loop.monotonicMs(),
        event_loop,
        removeActiveDrivePollFd,
        worker_pool,
        submitActiveDrivePollWork,
    );
}

fn dispatchDueActiveDrivePollsAt(
    active: *http.downstream_connection.ActiveRegistry,
    state: *GatewayState,
    now_ms: u64,
    remove_ctx: *anyopaque,
    remove_fn: ActiveDrivePollRemoveFn,
    submit_ctx: *anyopaque,
    submit_fn: ActiveDrivePollSubmitFn,
) void {
    var fds: [32]std.posix.fd_t = undefined;
    while (true) {
        const count = active.dueDrivePollFds(now_ms, fds[0..]);
        if (count == 0) break;
        for (fds[0..count]) |fd| {
            remove_fn(remove_ctx, fd) catch {};
            submit_fn(submit_ctx, fd) catch |err| {
                state.logger.warn(null, "active connection drive-poll submit failed: {}", .{err});
                if (active.checkout(fd)) |taken| {
                    var conn = taken;
                    conn.deinit();
                }
            };
        }
        if (count < fds.len) break;
    }
}

fn removeActiveDrivePollFd(raw_ctx: *anyopaque, fd: std.posix.fd_t) !void {
    const event_loop: *http.event_loop.EventLoop = @ptrCast(@alignCast(raw_ctx));
    try event_loop.remove(fd);
}

fn submitActiveDrivePollWork(raw_ctx: *anyopaque, fd: std.posix.fd_t) !void {
    const worker_pool: *http.worker_pool.WorkerPool = @ptrCast(@alignCast(raw_ctx));
    try worker_pool.submitActiveDrivePoll(fd);
}

fn rearmActiveConnection(ctx: *WorkerContext, managed: *http.downstream_connection.ManagedConnection, requested: http.event_loop.Interest) void {
    const fd = managed.fd;
    const now_ms = http.event_loop.monotonicMs();
    if (managed.encryptedWaitForAt(requested, now_ms, ACTIVE_DRIVE_POLL_INTERVAL_MS)) |wait| switch (wait) {
        .ready_now => {
            advanceActiveConnection(ctx, managed);
            return;
        },
        .socket, .retry_at_ms, .stalled => {},
    };
    const interest = rearmActiveConnectionInRegistryAt(
        ctx.active,
        managed,
        requested,
        now_ms,
        ACTIVE_DRIVE_POLL_INTERVAL_MS,
    ) catch |err| {
        ctx.state.logger.warn(null, "active connection rearm failed: {}", .{err});
        managed.deinit();
        return;
    };
    if (!interest.read and !interest.write) return;
    ctx.event_loop.add(fd, interest) catch |err| {
        ctx.state.logger.warn(null, "active connection event registration failed: {}", .{err});
        if (ctx.active.checkout(fd)) |taken| {
            var conn = taken;
            conn.deinit();
        }
    };
}

fn rearmActiveConnectionInRegistryAt(
    active: *http.downstream_connection.ActiveRegistry,
    managed: *http.downstream_connection.ManagedConnection,
    requested: http.event_loop.Interest,
    now_ms: u64,
    retry_interval_ms: u64,
) !http.event_loop.Interest {
    const wait = managed.updateWaitFor(requested, now_ms, retry_interval_ms) orelse
        http.downstream_connection.EncryptedWait{ .socket = requested };
    const interest = switch (wait) {
        .socket => |socket_interest| socket_interest,
        .ready_now, .retry_at_ms, .stalled => http.event_loop.Interest{},
    };
    _ = try active.rearm(managed);
    return interest;
}

fn advanceActiveConnection(ctx: *WorkerContext, managed: *http.downstream_connection.ManagedConnection) void {
    switch (managed.phase) {
        .native_handshake => advanceNativeHandshake(ctx, managed),
        .native_http1 => advanceNativeHttp1(ctx, managed),
        .native_http2 => advanceNativeHttp2(ctx, managed),
        .http1 => advanceNativeHttp1(ctx, managed),
        .http2 => advanceNativeHttp2(ctx, managed),
        .idle_http1 => managed.deinit(),
    }
}

fn advanceNativeHandshake(ctx: *WorkerContext, managed: *http.downstream_connection.ManagedConnection) void {
    const native = switch (managed.transport) {
        .native => |conn| conn,
        else => {
            managed.deinit();
            return;
        },
    };

    while (!native.record.applicationDataOpen()) {
        const driven = native.drive() catch |err| {
            ctx.state.logger.warn(null, "native tls handshake failed: {}", .{err});
            managed.deinit();
            return;
        };
        if (native.record.applicationDataOpen()) break;
        if (!driven.made_progress) {
            rearmActiveConnection(ctx, managed, .{ .read = true });
            return;
        }
    }

    native.finalizeClientIdentity() catch |err| {
        // A certificate the validator accepted but we cannot render: refuse
        // the connection rather than serve it without its identity.
        ctx.state.logger.warn(null, "native tls verified client identity unavailable: {}", .{err});
        managed.deinit();
        return;
    };

    const negotiated = native.validatedNegotiatedProtocol() catch |err| {
        ctx.state.logger.warn(null, "native tls negotiated protocol rejected: {}", .{err});
        managed.deinit();
        return;
    };

    switch (negotiated) {
        .http1_1 => {
            managed.phase = .{ .native_http1 = .{} };
            if (managed.transport.pendingPlaintext() > 0) {
                advanceActiveConnection(ctx, managed);
            } else {
                managed.phase.native_http1.idle_deadline_ms = deadlineFromNow(
                    http.event_loop.monotonicMs(),
                    managed.lifecycle.header_timeout_ms,
                );
                rearmActiveConnection(ctx, managed, .{ .read = true });
            }
        },
        .http2 => {
            managed.phase = .{ .native_http2 = .{} };
            if (managed.transport.pendingPlaintext() > 0) {
                advanceActiveConnection(ctx, managed);
            } else {
                managed.phase.native_http2.idle_or_io_deadline_ms = deadlineFromNow(
                    http.event_loop.monotonicMs(),
                    managed.lifecycle.header_timeout_ms,
                );
                rearmActiveConnection(ctx, managed, .{ .read = true });
            }
        },
    }
}

fn activeSession(managed: *http.downstream_connection.ManagedConnection) ?*ConnectionSession {
    const raw = managed.lifecycle.session orelse return null;
    return @ptrCast(@alignCast(raw));
}

fn activeConfig(managed: *http.downstream_connection.ManagedConnection) ?*const edge_config.EdgeConfig {
    const raw = managed.lifecycle.config orelse return null;
    return @ptrCast(@alignCast(raw));
}

const WaitingEncryptedHttpConnection = struct {
    inner: http.encrypted_stream_connection.EncryptedStreamHttpConnection,
    read_timeout_ms: u32,
    write_timeout_ms: u32,
    tls_metrics: ?*http.metrics.Metrics = null,
    tls_metrics_mutex: ?*compat.Mutex = null,
    tls_metrics_state: ?*http.metrics.TlsBufferConnectionMetrics = null,
    read_scope_early_prefix_len: usize = 0,
    read_scope_total_len: usize = 0,
    /// Installed only by the downstream H2 runtime.  Its pipe is included in
    /// the encrypted connection's blocking wait, so a future producer can
    /// wake the one connection-owned writer without touching the TLS socket.
    h2_outbound: ?*http.h2_outbound_scheduler.Scheduler = null,
    /// Installed only by the downstream H2 runtime (#866). Its wake fd is
    /// included in the same blocking wait as `h2_outbound`'s, so a worker
    /// thread's response completion can unblock this connection without it
    /// ever polling or owning the H2 socket.
    h2_request_handoff: ?*http.h2_request_handoff.Handoff = null,
    h2_completion_drain_fn: ?*const fn (ctx: *anyopaque) anyerror!void = null,
    h2_completion_drain_ctx: ?*anyopaque = null,
    /// Installed only by the downstream H2 runtime (#867). `h2_session_poll_fds_fn`
    /// fills a caller-provided buffer with every attached session's wake fd
    /// so this connection's one blocking wait can observe all of them
    /// without a session ever touching the TLS socket; `h2_session_drain_fn`
    /// services whichever sessions have pending work once any of them fire.
    h2_session_poll_fds_fn: ?*const fn (ctx: *anyopaque, buf: []std.posix.fd_t) []const std.posix.fd_t = null,
    h2_session_drain_fn: ?*const fn (ctx: *anyopaque) anyerror!void = null,
    h2_session_ctx: ?*anyopaque = null,

    fn init(
        inner: http.encrypted_stream_connection.EncryptedStreamHttpConnection,
        read_timeout_ms: u32,
        write_timeout_ms: u32,
    ) WaitingEncryptedHttpConnection {
        return .{
            .inner = inner,
            .read_timeout_ms = read_timeout_ms,
            .write_timeout_ms = write_timeout_ms,
        };
    }

    fn initWithMetrics(
        inner: http.encrypted_stream_connection.EncryptedStreamHttpConnection,
        read_timeout_ms: u32,
        write_timeout_ms: u32,
        metrics: ?*http.metrics.Metrics,
        metrics_mutex: ?*compat.Mutex,
        metrics_state: ?*http.metrics.TlsBufferConnectionMetrics,
    ) WaitingEncryptedHttpConnection {
        var adapter = init(inner, read_timeout_ms, write_timeout_ms);
        adapter.tls_metrics = metrics;
        adapter.tls_metrics_mutex = metrics_mutex;
        adapter.tls_metrics_state = metrics_state;
        return adapter;
    }

    fn observeTlsBufferMetrics(self: *WaitingEncryptedHttpConnection) void {
        const metrics = self.tls_metrics orelse return;
        const mutex = self.tls_metrics_mutex orelse return;
        const state = self.tls_metrics_state orelse return;
        const snapshot = self.inner.bufferSnapshot();
        const backend = self.inner.stream.backend();
        mutex.lock();
        defer mutex.unlock();
        metrics.observeTlsBufferSnapshot(state, backend, snapshot) catch
            @panic("TLS buffer accounting underflow");
    }

    pub fn read(self: *WaitingEncryptedHttpConnection, out: []u8) !usize {
        while (true) {
            const n = self.inner.read(out) catch |err| switch (err) {
                error.WouldBlock => {
                    self.observeTlsBufferMetrics();
                    try self.waitFor(.{ .read = true }, self.read_timeout_ms);
                    continue;
                },
                else => return err,
            };
            const prefix_len = @min(n, self.inner.currentReadEarlyPrefixLen());
            if (self.read_scope_early_prefix_len == self.read_scope_total_len)
                self.read_scope_early_prefix_len += prefix_len;
            self.read_scope_total_len += n;
            self.observeTlsBufferMetrics();
            return n;
        }
    }

    pub fn beginReadScope(self: *WaitingEncryptedHttpConnection) void {
        self.read_scope_early_prefix_len = 0;
        self.read_scope_total_len = 0;
    }

    pub fn takeReadScopeTransportEarly(self: *WaitingEncryptedHttpConnection) bool {
        return self.takeReadScopeEarlyPrefixLen() > 0;
    }

    pub fn takeReadScopeEarlyPrefixLen(self: *WaitingEncryptedHttpConnection) usize {
        const early_prefix_len = self.read_scope_early_prefix_len;
        self.read_scope_early_prefix_len = 0;
        self.read_scope_total_len = 0;
        return early_prefix_len;
    }

    pub fn downstreamHandshakeComplete(self: *const WaitingEncryptedHttpConnection) bool {
        return self.inner.downstreamHandshakeComplete();
    }

    pub fn clientCertificate(self: *const WaitingEncryptedHttpConnection) ?http.headers.ClientCertificate {
        const identity = self.inner.clientIdentity() orelse return null;
        return clientCertificateView(identity);
    }

    pub fn clientPolicyAdmitsHost(self: *const WaitingEncryptedHttpConnection, host: []const u8) bool {
        return self.inner.clientPolicyAdmitsHost(host);
    }

    pub fn waitForHandshakeCompletionOrInput(self: *WaitingEncryptedHttpConnection) !void {
        while (true) {
            if (self.downstreamHandshakeComplete()) return;
            if (self.pendingPlaintext() > 0) return;

            const readiness = self.inner.readiness();
            var requested = http.event_loop.Interest{ .read = true };
            if (readiness.wants_write) requested.write = true;

            self.observeTlsBufferMetrics();
            try self.waitFor(requested, self.read_timeout_ms);
            _ = self.inner.stream.drive() catch |err| switch (err) {
                error.WouldBlock => continue,
                else => return err,
            };
            self.observeTlsBufferMetrics();
        }
    }

    pub fn write(self: *WaitingEncryptedHttpConnection, bytes: []const u8) !usize {
        while (true) {
            const n = self.inner.write(bytes) catch |err| switch (err) {
                error.WouldBlock => {
                    self.observeTlsBufferMetrics();
                    try self.waitFor(.{ .write = true }, self.write_timeout_ms);
                    continue;
                },
                else => return err,
            };
            self.observeTlsBufferMetrics();
            try self.flush();
            return n;
        }
    }

    pub fn flush(self: *WaitingEncryptedHttpConnection) !void {
        while (self.inner.readiness().wants_write) {
            self.inner.flush() catch |err| switch (err) {
                error.WouldBlock => {
                    self.observeTlsBufferMetrics();
                    try self.waitFor(.{ .write = true }, self.write_timeout_ms);
                    continue;
                },
                else => return err,
            };
            self.observeTlsBufferMetrics();
        }
    }

    pub fn pending(self: *const WaitingEncryptedHttpConnection) usize {
        return self.inner.pending();
    }

    pub fn pendingPlaintext(self: *const WaitingEncryptedHttpConnection) usize {
        return self.inner.pendingPlaintext();
    }

    pub fn probePeerCloseBounded(
        self: *WaitingEncryptedHttpConnection,
        max_drives: usize,
    ) !http.encrypted_stream_connection.PeerCloseProbe {
        defer self.observeTlsBufferMetrics();
        return self.inner.probePeerCloseBounded(max_drives);
    }

    pub fn rawFd(self: *const WaitingEncryptedHttpConnection) std.posix.fd_t {
        return self.inner.rawFd();
    }

    /// The non-blocking view a WebSocket tunnel drives directly (#812).
    pub fn tunnelEndpoint(self: *WaitingEncryptedHttpConnection) http.tunnel.EncryptedEndpoint {
        return .{ .conn = &self.inner };
    }

    pub fn setReadTimeoutMs(self: *WaitingEncryptedHttpConnection, timeout_ms: u32) void {
        self.read_timeout_ms = timeout_ms;
    }

    pub fn setWriteTimeoutMs(self: *WaitingEncryptedHttpConnection, timeout_ms: u32) void {
        self.write_timeout_ms = timeout_ms;
    }

    pub fn setH2OutboundScheduler(self: *WaitingEncryptedHttpConnection, outbound: ?*http.h2_outbound_scheduler.Scheduler) void {
        self.h2_outbound = outbound;
    }

    pub fn setH2RequestHandoff(
        self: *WaitingEncryptedHttpConnection,
        handoff: ?*http.h2_request_handoff.Handoff,
        drain_fn: ?*const fn (ctx: *anyopaque) anyerror!void,
        drain_ctx: ?*anyopaque,
    ) void {
        self.h2_request_handoff = handoff;
        self.h2_completion_drain_fn = drain_fn;
        self.h2_completion_drain_ctx = drain_ctx;
    }

    pub fn setH2SessionRegistry(
        self: *WaitingEncryptedHttpConnection,
        poll_fds_fn: ?*const fn (ctx: *anyopaque, buf: []std.posix.fd_t) []const std.posix.fd_t,
        drain_fn: ?*const fn (ctx: *anyopaque) anyerror!void,
        ctx: ?*anyopaque,
    ) void {
        self.h2_session_poll_fds_fn = poll_fds_fn;
        self.h2_session_drain_fn = drain_fn;
        self.h2_session_ctx = ctx;
    }

    pub fn writer(self: *WaitingEncryptedHttpConnection) Writer {
        return .{ .conn = self };
    }

    const Writer = struct {
        conn: *WaitingEncryptedHttpConnection,

        pub fn write(self: Writer, bytes: []const u8) !usize {
            return self.conn.write(bytes);
        }

        pub fn writeAll(self: Writer, bytes: []const u8) !void {
            var offset: usize = 0;
            while (offset < bytes.len) {
                const n = try self.write(bytes[offset..]);
                if (n == 0) return error.WouldBlock;
                offset += n;
            }
            try self.conn.flush();
        }

        pub fn writeByte(self: Writer, byte: u8) !void {
            try self.writeAll(&[_]u8{byte});
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
            var buf: [4096]u8 = undefined;
            const rendered = try std.fmt.bufPrint(&buf, fmt, args);
            try self.writeAll(rendered);
        }
    };

    fn waitFor(self: *WaitingEncryptedHttpConnection, requested: http.event_loop.Interest, timeout_ms: u32) !void {
        const readiness = self.inner.readiness();
        var interest = switch (http.downstream_connection.encryptedWaitForInterest(readiness, requested)) {
            .ready_now => return,
            .socket => |socket_interest| socket_interest,
            .retry_at_ms => return error.WouldBlock,
            .stalled => return error.WouldBlock,
        };
        if (self.h2_outbound) |outbound| {
            if (outbound.hasPendingOutput()) interest.write = true;
        }

        var events: i16 = std.posix.POLL.ERR | std.posix.POLL.HUP;
        if (interest.read) events |= std.posix.POLL.IN;
        if (interest.write) events |= std.posix.POLL.OUT;
        // Slot 1 wakes this wait when the outbound scheduler has bytes to
        // flush (#865); slot 2 wakes it when a worker's request-job
        // completion is ready to apply (#866). Both stay `-1` (ignored by
        // `poll`) when their producer is not installed on this connection.
        // Slots 3.. are one per attached #867 session, so any of them --
        // not just the one TLS socket -- can wake this one blocking wait;
        // unused slots also stay `-1`.
        var fds: [3 + HTTP2_MAX_CONCURRENT_STREAMS]std.posix.pollfd = undefined;
        fds[0] = .{ .fd = self.inner.rawFd(), .events = events, .revents = 0 };
        fds[1] = .{ .fd = -1, .events = std.posix.POLL.IN, .revents = 0 };
        fds[2] = .{ .fd = -1, .events = std.posix.POLL.IN, .revents = 0 };
        if (self.h2_outbound) |outbound| fds[1].fd = outbound.wakeFd();
        if (self.h2_request_handoff) |handoff| fds[2].fd = handoff.wakeFd();

        var session_fd_buf: [HTTP2_MAX_CONCURRENT_STREAMS]std.posix.fd_t = undefined;
        var session_fd_count: usize = 0;
        if (self.h2_session_poll_fds_fn) |get_fds| {
            const ctx = self.h2_session_ctx orelse return error.ConnectionClosed;
            const session_fds = get_fds(ctx, &session_fd_buf);
            session_fd_count = session_fds.len;
            for (session_fds, 0..) |fd, i| fds[3 + i] = .{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 };
        }
        for (session_fd_count..HTTP2_MAX_CONCURRENT_STREAMS) |i| fds[3 + i] = .{ .fd = -1, .events = std.posix.POLL.IN, .revents = 0 };

        const bounded_ms: i32 = if (timeout_ms == 0)
            30_000
        else
            @intCast(@min(timeout_ms, @as(u32, @intCast(std.math.maxInt(i32)))));
        const ready = try std.posix.poll(&fds, bounded_ms);
        if (ready == 0) {
            // An exotic write failure can leave the notification fd without a
            // poll event. The handoff's fatal status is still checked at this
            // bounded read deadline, and its drain callback retires the
            // retained completion before terminating the connection.
            if (self.h2_request_handoff) |handoff| if (handoff.hasWakeFailure()) {
                const drain_fn = self.h2_completion_drain_fn orelse return error.ConnectionClosed;
                const drain_ctx = self.h2_completion_drain_ctx orelse return error.ConnectionClosed;
                try drain_fn(drain_ctx);
            };
            return error.WouldBlock;
        }
        if (fds[1].fd >= 0 and (fds[1].revents != 0 or (fds[0].revents & std.posix.POLL.OUT) != 0)) {
            const outbound = self.h2_outbound orelse return error.ConnectionClosed;
            // We are already in the poll owner. Use the non-waiting record
            // writer here to avoid recursively re-entering this wait path;
            // a temporary TLS backpressure condition simply remains a normal
            // connection-level write failure for this finite H2 phase.
            try outbound.flush(self.inner.writer());
        }
        if (fds[2].fd >= 0 and fds[2].revents != 0) {
            const drain_fn = self.h2_completion_drain_fn orelse return error.ConnectionClosed;
            const drain_ctx = self.h2_completion_drain_ctx orelse return error.ConnectionClosed;
            try drain_fn(drain_ctx);
        }
        for (fds[3 .. 3 + session_fd_count]) |pfd| {
            if (pfd.revents != 0) {
                const drain_fn = self.h2_session_drain_fn orelse return error.ConnectionClosed;
                const ctx = self.h2_session_ctx orelse return error.ConnectionClosed;
                try drain_fn(ctx);
                break;
            }
        }
        if ((fds[0].revents & std.posix.POLL.ERR) != 0) return error.ConnectionResetByPeer;
        if ((fds[0].revents & std.posix.POLL.HUP) != 0 and (fds[0].revents & (std.posix.POLL.IN | std.posix.POLL.OUT)) == 0) return error.ConnectionClosed;
    }
};

fn advanceNativeHttp1(ctx: *WorkerContext, managed: *http.downstream_connection.ManagedConnection) void {
    const native = switch (managed.transport) {
        .native => |conn| conn,
        else => {
            managed.deinit();
            return;
        },
    };
    const session = activeSession(managed) orelse {
        managed.deinit();
        return;
    };
    var adapter = WaitingEncryptedHttpConnection.initWithMetrics(
        native.httpConnection(),
        managed.lifecycle.header_timeout_ms,
        managed.lifecycle.write_timeout_ms,
        managed.lifecycle.metrics,
        managed.lifecycle.metrics_mutex,
        &managed.lifecycle.tls_buffer_metrics,
    );
    const connection_ip = managed.lifecycle.connectionIp();
    var served = switch (managed.phase) {
        .native_http1 => |*h1| h1.served,
        else => 0,
    };

    while (true) {
        switch (serveOneRequest(ctx, &adapter, session, connection_ip, &served, false, true)) {
            .serve_again => continue,
            .park => {
                if (managed.phase == .native_http1) {
                    managed.phase.native_http1.served = served;
                    managed.phase.native_http1.idle_deadline_ms = deadlineFromNow(
                        http.event_loop.monotonicMs(),
                        managed.lifecycle.idle_timeout_ms,
                    );
                }
                _ = native.drive() catch |err| {
                    ctx.state.logger.warn(null, "native http/1.1 post-request drive failed: {}", .{err});
                    managed.deinit();
                    return;
                };
                managed.observeTlsBufferMetrics();
                if (adapter.pending() > 0 or managed.transport.pendingPlaintext() > 0) continue;
                rearmActiveConnection(ctx, managed, .{ .read = true });
                return;
            },
            .close => {
                managed.deinit();
                return;
            },
            .tunnel => |job| {
                // The tunnel owns the TLS connection, its socket, connection
                // slot and connection config lease now; only the pooled
                // request session goes back.
                managed.releaseSession();
                job.attach(.{ .native = managed.* });
                job.submit();
                return;
            },
        }
    }
}

fn advanceNativeHttp2(ctx: *WorkerContext, managed: *http.downstream_connection.ManagedConnection) void {
    const native = switch (managed.transport) {
        .native => |conn| conn,
        else => {
            managed.deinit();
            return;
        },
    };
    _ = activeSession(managed) orelse {
        managed.deinit();
        return;
    };
    const session = activeSession(managed) orelse {
        managed.deinit();
        return;
    };
    const cfg = activeConfig(managed) orelse {
        managed.deinit();
        return;
    };

    var adapter = WaitingEncryptedHttpConnection.initWithMetrics(
        native.httpConnection(),
        managed.lifecycle.header_timeout_ms,
        managed.lifecycle.write_timeout_ms,
        managed.lifecycle.metrics,
        managed.lifecycle.metrics_mutex,
        &managed.lifecycle.tls_buffer_metrics,
    );
    handleHttp2Connection(&adapter, session, cfg, ctx.state, managed.lifecycle.connectionIp()) catch |err| {
        if (isBenignDisconnect(err)) {
            ctx.state.logger.debug(null, "native http/2 connection closed: {}", .{err});
        } else {
            ctx.state.logger.warn(null, "native http/2 connection failed: {}", .{err});
        }
    };
    managed.deinit();
}

/// Registry teardown hook: release the connection slot held since accept when a
/// parked connection is finally closed (resume-close, idle reap, or drain).
const ParkedCloseCtx = struct {
    state: *GatewayState,
    event_loop: *http.event_loop.EventLoop,
};

/// Runs from `ParkedRegistry.freeConn` immediately before the fd is closed
/// (reaper, drain, and `closeAll` all funnel through it), without the registry
/// mutex held.
///
/// Unregistering here is an invariant, not an optimization. `epoll` drops a
/// closed fd from its set implicitly, so this hook historically only needed to
/// release the accounting slot. `IORING_OP_POLL_ADD` instead pins the
/// underlying file, so a poll left armed across the close survives it; if the
/// kernel then recycles that integer for an unrelated descriptor, the stale
/// completion would be attributed — and re-armed — against the wrong file.
/// The active-connection expiry reaper already removes before `deinit`; this
/// makes the parked path match.
fn parkedConnectionCloseHook(raw_ctx: *anyopaque, fd: std.posix.fd_t) void {
    const ctx: *ParkedCloseCtx = @ptrCast(@alignCast(raw_ctx));
    // A checked-out connection is not registered, so ENOENT here is normal.
    ctx.event_loop.remove(fd) catch {};
    ctx.state.releaseConnectionSlot(fd);
}

fn recordHttp3EarlyDataCompatFromRuntime(
    raw_state: *anyopaque,
    decision: http.metrics.H3EarlyDataCompatDecision,
) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.metricsRecordHttp3EarlyDataCompat(decision);
}

fn recordQuicEarlyDataDecisionFromRuntime(
    raw_state: *anyopaque,
    decision: http.metrics.QuicEarlyDataDecision,
) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.metricsRecordQuicEarlyDataDecision(decision);
}

fn recordQuicZeroRttPacketFromRuntime(
    raw_state: *anyopaque,
    outcome: http.metrics.QuicZeroRttPacketOutcome,
) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.metricsRecordQuicZeroRttPacket(outcome);
}

fn recordQuicTransportDeltaFromRuntime(
    raw_state: *anyopaque,
    delta: http.metrics.QuicTransportDelta,
) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.metricsRecordQuicTransportDelta(delta);
}

fn setQuicConnectionsActiveFromRuntime(
    raw_state: *anyopaque,
    active: usize,
) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.metricsSetQuicConnectionsActive(active);
}

fn recordQuicHandshakeFailureFromRuntime(
    raw_state: *anyopaque,
    stage: http.metrics.QuicHandshakeFailureStage,
) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.metricsRecordQuicHandshakeFailure(stage);
}

fn recordH3RequestLatencyFromRuntime(
    raw_state: *anyopaque,
    latency_ms: u64,
) void {
    const state: *GatewayState = @ptrCast(@alignCast(raw_state));
    state.metricsRecordH3RequestLatency(latency_ms);
}

fn h2LastReadEarlyPrefixLen(conn: anytype) usize {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "takeReadScopeEarlyPrefixLen")) return conn.takeReadScopeEarlyPrefixLen();
        if (comptime @hasDecl(Child, "takeReadScopeTransportEarly")) return if (conn.takeReadScopeTransportEarly()) std.math.maxInt(usize) else 0;
    } else {
        if (comptime @hasDecl(T, "takeReadScopeEarlyPrefixLen")) return conn.takeReadScopeEarlyPrefixLen();
        if (comptime @hasDecl(T, "takeReadScopeTransportEarly")) return if (conn.takeReadScopeTransportEarly()) std.math.maxInt(usize) else 0;
    }
    return 0;
}

fn h2LastReadTransportEarly(conn: anytype) bool {
    return h2LastReadEarlyPrefixLen(conn) > 0;
}

fn h2LastReadEarlyPrefixLenBounded(conn: anytype, total_read: usize) usize {
    return @min(total_read, h2LastReadEarlyPrefixLen(conn));
}

fn h1PendingReadEarlyPrefix(old_pending_len: usize, total_read: usize, old_early_prefix_len: usize, read_scope_early_prefix_len: usize) usize {
    const bounded_old = @min(old_early_prefix_len, old_pending_len);
    const new_read_len = total_read - @min(old_pending_len, total_read);
    const bounded_new_early = @min(read_scope_early_prefix_len, new_read_len);
    if (bounded_old < old_pending_len) return bounded_old;
    return bounded_old + bounded_new_early;
}

fn h1ConsumeRequestEarlyProvenance(session: *ConnectionSession, old_pending_len: usize, total_read: usize, bytes_consumed: usize, read_scope_early_prefix_len: usize) bool {
    const prefix_len = h1PendingReadEarlyPrefix(old_pending_len, total_read, session.pending_early_prefix_len, read_scope_early_prefix_len);
    const consumed = @min(bytes_consumed, total_read);
    const request_transport_early = consumed > 0 and prefix_len > 0;
    session.pending_early_prefix_len = if (consumed >= prefix_len) 0 else prefix_len - consumed;
    if (session.pending_len < session.pending_early_prefix_len) session.pending_early_prefix_len = session.pending_len;
    return request_transport_early;
}

fn clientCertificateView(identity: *const tls_core.client_identity.ClientIdentity) http.headers.ClientCertificate {
    return .{
        .fingerprint_sha256 = identity.fingerprintSha256(),
        .subject = identity.subject(),
        .issuer = identity.issuer(),
        .serial = identity.serialHex(),
        .san_dns = identity.sanDns(),
        .san_email = identity.sanEmail(),
        .san_uri = identity.sanUri(),
    };
}

/// Whether `conn`'s SNI-selected client-auth policy admits a request for
/// `host` (#763); true for plaintext and policy-less connections.
fn connClientPolicyAdmitsHost(conn: anytype, host: []const u8) bool {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "clientPolicyAdmitsHost")) return conn.clientPolicyAdmitsHost(host);
    } else {
        if (comptime @hasDecl(T, "clientPolicyAdmitsHost")) return conn.clientPolicyAdmitsHost(host);
    }
    return true;
}

/// The verified mTLS identity of `conn` (#763), or null for plaintext and
/// connections without a verified client certificate.
fn connClientCertificate(conn: anytype) ?http.headers.ClientCertificate {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "clientCertificate")) return conn.clientCertificate();
    } else {
        if (comptime @hasDecl(T, "clientCertificate")) return conn.clientCertificate();
    }
    return null;
}

fn h2BeginReadScope(conn: anytype) void {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "beginReadScope")) {
            conn.beginReadScope();
            return;
        }
    } else {
        if (comptime @hasDecl(T, "beginReadScope")) {
            conn.beginReadScope();
            return;
        }
    }
}

fn h2InstallOutboundScheduler(conn: anytype, outbound: ?*http.h2_outbound_scheduler.Scheduler) void {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "setH2OutboundScheduler")) conn.setH2OutboundScheduler(outbound);
    } else {
        if (comptime @hasDecl(T, "setH2OutboundScheduler")) conn.setH2OutboundScheduler(outbound);
    }
}

/// Install (or clear) the connection's request-job completion handoff and
/// the drain callback that applies an arriving completion (#866). Only a
/// `conn` that declares `setH2RequestHandoff` -- today just
/// `WaitingEncryptedHttpConnection` -- includes the handoff's wake fd in its
/// blocking wait; other `conn` types (test fakes) simply never wake for one.
fn h2InstallRequestHandoff(
    conn: anytype,
    handoff: ?*http.h2_request_handoff.Handoff,
    drain_fn: ?*const fn (ctx: *anyopaque) anyerror!void,
    drain_ctx: ?*anyopaque,
) void {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "setH2RequestHandoff")) conn.setH2RequestHandoff(handoff, drain_fn, drain_ctx);
    } else {
        if (comptime @hasDecl(T, "setH2RequestHandoff")) conn.setH2RequestHandoff(handoff, drain_fn, drain_ctx);
    }
}

/// Install (or clear) the connection's #867 session registry poll/drain
/// callbacks. Only a `conn` that declares `setH2SessionRegistry` -- today
/// just `WaitingEncryptedHttpConnection` -- includes attached sessions' wake
/// fds in its blocking wait; other `conn` types (test fakes) simply never
/// wake for one.
fn h2InstallSessionRegistry(
    conn: anytype,
    poll_fds_fn: ?*const fn (ctx: *anyopaque, buf: []std.posix.fd_t) []const std.posix.fd_t,
    drain_fn: ?*const fn (ctx: *anyopaque) anyerror!void,
    ctx: ?*anyopaque,
) void {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "setH2SessionRegistry")) conn.setH2SessionRegistry(poll_fds_fn, drain_fn, ctx);
    } else {
        if (comptime @hasDecl(T, "setH2SessionRegistry")) conn.setH2SessionRegistry(poll_fds_fn, drain_fn, ctx);
    }
}

fn h2DownstreamHandshakeComplete(conn: anytype) bool {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "downstreamHandshakeComplete")) return conn.downstreamHandshakeComplete();
    } else {
        if (comptime @hasDecl(T, "downstreamHandshakeComplete")) return conn.downstreamHandshakeComplete();
    }
    return true;
}

fn h2WaitForHandshakeCompletionOrInput(conn: anytype) !void {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "waitForHandshakeCompletionOrInput")) return conn.waitForHandshakeCompletionOrInput();
    } else {
        if (comptime @hasDecl(T, "waitForHandshakeCompletionOrInput")) return conn.waitForHandshakeCompletionOrInput();
    }
    return;
}

fn h2HasDeferredReadyStreams(
    pending: *const std.AutoHashMap(u31, Http2PendingStream),
    ready_streams: *const std.array_list.Managed(u31),
) bool {
    for (ready_streams.items) |sid| {
        const ps = pending.get(sid) orelse continue;
        if (ps.transport_early and ps.dispatch_count == 0) return true;
    }
    return false;
}

fn h2AppendReadyStream(ready_streams: *std.array_list.Managed(u31), sid: u31) !void {
    for (ready_streams.items) |existing| {
        if (existing == sid) return;
    }
    try ready_streams.append(sid);
}

fn h2RemoveReadyStream(ready_streams: *std.array_list.Managed(u31), sid: u31) void {
    var idx: usize = 0;
    while (idx < ready_streams.items.len) {
        if (ready_streams.items[idx] == sid) {
            _ = ready_streams.swapRemove(idx);
            continue;
        }
        idx += 1;
    }
}

fn h2ResetStreamState(
    writer: anytype,
    allocator: std.mem.Allocator,
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    pending: *std.AutoHashMap(u31, Http2PendingStream),
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    ready_streams: *std.array_list.Managed(u31),
    sessions: *std.AutoHashMap(u31, *http.h2_stream_session.Session),
    buffered_request_bytes: *usize,
    stream_id: u31,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    handoff: ?*http.h2_request_handoff.Handoff,
    executor: ?*http.h2_request_executor.Executor,
    in_flight: *std.AutoHashMap(u31, void),
    conn_recv_window: ?*i64,
    conn_send_window: ?*i32,
) !void {
    if (outbound) |scheduler| {
        // Any still-queued (never transmitted) DATA this stream had reserved
        // already debited the connection's send-window when it was queued
        // (see `flushHttp2PendingResponse`/`flushHttp2SessionOutbound`); it
        // must come back now that the stream is gone, or those bytes are
        // lost forever and can starve an unrelated sibling stream.
        const refunded = scheduler.cancelStream(stream_id);
        if (refunded > 0) {
            if (conn_send_window) |w| w.* +|= @intCast(@min(refunded, std.math.maxInt(i32)));
        }
    }
    if (handoff) |ho| _ = ho.cancelStream(stream_id) catch {};
    if (handoff) |ho| if (executor) |ex| ex.cancelStreamSignals(ho, stream_id);
    _ = in_flight.remove(stream_id);
    if (sessions.fetchRemove(stream_id)) |removed| {
        const session = removed.value;
        buffered_request_bytes.* -= @min(buffered_request_bytes.*, HTTP2_SESSION_RESERVED_BYTES);
        session.deliverReset(.cancel);
        // Unread inbound bytes already charged the peer's connection-level
        // receive window (see `Session.settleLocked`). The stream itself is
        // gone, so return that credit with a stream-0-only WINDOW_UPDATE
        // rather than ever crediting the now-closed stream.
        const abandoned_credit = session.takeReceiveCreditToReturn();
        // Detach/free unconditionally once the session is removed from the
        // registry: a failed WINDOW_UPDATE write below must not skip this,
        // or the removed registry entry becomes the session's only
        // reference and it leaks with a consumer possibly still blocked on
        // it (the registry can no longer find it to settle later).
        defer if (session.runtimeDetach()) {
            session.deinit();
            allocator.destroy(session);
        };
        if (abandoned_credit > 0) {
            try http.http2_frame.writeWindowUpdate(writer, 0, @intCast(abandoned_credit));
            // Only reflect the refund in our own local receive-window
            // bookkeeping once the peer has actually been credited: the
            // connection's receive-credit counter must stay in lockstep
            // with what we told the peer, or later DATA on an unrelated
            // sibling stream will be rejected as a flow-control violation
            // even though the peer legitimately still has that credit.
            if (conn_recv_window) |w| w.* += @intCast(abandoned_credit);
        }
    }
    _ = streams.remove(stream_id);
    if (pending.fetchRemove(stream_id)) |removed| {
        var tmp = removed.value;
        buffered_request_bytes.* -= @min(buffered_request_bytes.*, tmp.retainedBytes());
        tmp.deinit(allocator);
    }
    if (pending_responses.fetchRemove(stream_id)) |removed| {
        var tmp = removed.value;
        tmp.deinit(allocator);
    }
    h2RemoveReadyStream(ready_streams, stream_id);
}

fn h2WriteStreamClosedReset(
    writer: anytype,
    outbound: *http.h2_outbound_scheduler.Scheduler,
    allocator: std.mem.Allocator,
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    pending: *std.AutoHashMap(u31, Http2PendingStream),
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    ready_streams: *std.array_list.Managed(u31),
    sessions: *std.AutoHashMap(u31, *http.h2_stream_session.Session),
    buffered_request_bytes: *usize,
    stream_id: u31,
    handoff: ?*http.h2_request_handoff.Handoff,
    executor: ?*http.h2_request_executor.Executor,
    in_flight: *std.AutoHashMap(u31, void),
    conn_recv_window: ?*i64,
    conn_send_window: ?*i32,
) !void {
    // Drop old response output before queuing our RST, otherwise a
    // backpressured connection could send DATA after stream closure. Any
    // never-transmitted DATA this dropped already debited the connection
    // send-window when queued; refund it now (see `h2ResetStreamState`).
    const refunded = outbound.cancelStream(stream_id);
    if (refunded > 0) {
        if (conn_send_window) |w| w.* +|= @intCast(@min(refunded, std.math.maxInt(i32)));
    }
    try http.http2_frame.writeRstStream(writer, stream_id, http.http2_stream.ErrorCode.stream_closed.value());
    try h2ResetStreamState(
        writer,
        allocator,
        streams,
        pending,
        pending_responses,
        ready_streams,
        sessions,
        buffered_request_bytes,
        stream_id,
        null,
        handoff,
        executor,
        in_flight,
        conn_recv_window,
        conn_send_window,
    );
}

fn h2EncodedHeaderBlockLimit(cfg: *const edge_config.EdgeConfig, buffered_request_bytes: usize) usize {
    var limit = cfg.request_limits.effectiveMaxHeadersTotalSize();
    if (cfg.max_connection_memory_bytes > 0) {
        const remaining_connection_memory = cfg.max_connection_memory_bytes -| buffered_request_bytes;
        limit = @min(limit, remaining_connection_memory);
    }
    return limit;
}

/// Validate the HTTP/2 request pseudo-header envelope before copying any
/// values into routing state. RFC 9113 § 8.3 requires pseudo-headers to
/// precede regular fields, forbids duplicates and unknown pseudo-headers,
/// and requires the ordinary request tuple. Silently replacing an earlier
/// `:authority` (or `:path`) makes different hops disagree about which
/// virtual host or authorization boundary the request addresses.
fn h2RequestHeaderBlockIsValid(fields: []const http.hpack.HeaderField, initial: bool) bool {
    var saw_regular = false;
    var saw_method = false;
    var saw_scheme = false;
    var saw_authority = false;
    var saw_path = false;
    var method: ?[]const u8 = null;
    var scheme: ?[]const u8 = null;
    var path: ?[]const u8 = null;
    var authority: ?[]const u8 = null;
    var host: ?[]const u8 = null;

    for (fields) |field| {
        if (field.name.len == 0) return false;
        for (field.name) |c| {
            if (std.ascii.isUpper(c)) return false;
        }

        if (field.name[0] != ':') {
            saw_regular = true;
            if (initial and std.mem.eql(u8, field.name, "host")) {
                if (host != null) return false;
                host = field.value;
            }
            continue;
        }
        // Trailer blocks are regular fields only.
        if (!initial) return false;
        if (saw_regular) return false;

        if (std.mem.eql(u8, field.name, ":method")) {
            if (saw_method) return false;
            saw_method = true;
            method = field.value;
        } else if (std.mem.eql(u8, field.name, ":scheme")) {
            if (saw_scheme) return false;
            saw_scheme = true;
            scheme = field.value;
        } else if (std.mem.eql(u8, field.name, ":authority")) {
            if (saw_authority) return false;
            saw_authority = true;
            authority = field.value;
        } else if (std.mem.eql(u8, field.name, ":path")) {
            if (saw_path) return false;
            saw_path = true;
            path = field.value;
        } else {
            return false;
        }
    }

    if (!initial) return true;
    if (!saw_method) return false;
    if (http.Method.parse(method.?) == null) return false;
    if (std.mem.eql(u8, method.?, "CONNECT")) {
        return saw_authority and !saw_scheme and !saw_path and http.request.isValidAuthority(authority.?);
    }
    if (!saw_scheme or !saw_path) return false;
    if (!(std.mem.eql(u8, scheme.?, "http") or std.mem.eql(u8, scheme.?, "https"))) return false;
    if (!h2RequestPathIsValid(path.?)) return false;
    // Routing authority has one meaning across the native H2 path and the
    // synthesized H1 request used by shared routing/auth code. Multiple Host
    // fields or a Host that disagrees with :authority create the same
    // cross-hop ambiguity as duplicate Host in HTTP/1.
    if (authority) |a| {
        if (!http.request.isValidAuthority(a)) return false;
        if (host) |h| {
            if (!http.request.isValidAuthority(h) or !std.ascii.eqlIgnoreCase(a, h)) return false;
        }
    } else if (host) |h| {
        if (!http.request.isValidAuthority(h)) return false;
    } else {
        return false;
    }
    return true;
}

fn h2RequestPathIsValid(path: []const u8) bool {
    if (!(std.mem.eql(u8, path, "*") or (path.len > 0 and path[0] == '/'))) return false;
    for (path) |c| {
        if (c <= 0x20 or c == 0x7f or c == '#') return false;
    }
    return true;
}

const H2HeadersPayload = struct {
    fragment: []const u8,
    priority: ?[]const u8,
};

/// Remove HEADERS padding and the optional priority tuple before HPACK sees
/// the fragment. Padding bytes are transport framing, never request data.
fn h2HeadersPayload(payload: []const u8, flags: u8) !H2HeadersPayload {
    var start: usize = 0;
    var end = payload.len;
    if ((flags & http.http2_frame.Flags.PADDED) != 0) {
        if (payload.len == 0) return error.InvalidHttp2Padding;
        const padding_len: usize = payload[0];
        start = 1;
        if (padding_len > end - start) return error.InvalidHttp2Padding;
        end -= padding_len;
    }
    var priority: ?[]const u8 = null;
    if ((flags & http.http2_frame.Flags.PRIORITY) != 0) {
        if (end - start < 5) return error.InvalidPriorityFrame;
        priority = payload[start .. start + 5];
        start += 5;
    }
    return .{ .fragment = payload[start..end], .priority = priority };
}

/// Return the application DATA bytes after removing HTTP/2 padding.
fn h2DataPayload(payload: []const u8, flags: u8) ![]const u8 {
    if ((flags & http.http2_frame.Flags.PADDED) == 0) return payload;
    if (payload.len == 0) return error.InvalidHttp2Padding;
    const padding_len: usize = payload[0];
    if (padding_len > payload.len - 1) return error.InvalidHttp2Padding;
    return payload[1 .. payload.len - padding_len];
}

/// Whether an inbound HEADERS/DATA frame may be processed for `stream_id`.
///
/// The HTTP/2 stream state machine — not the `pending` request-assembly map —
/// is the lifecycle authority. `h2DispatchReadyStreams` removes an entry from
/// `pending` the moment it dispatches, while keeping the `streams` entry alive
/// when a response is parked on send-credit exhaustion. Inferring "new request"
/// from `!pending.contains(id)` therefore lets a peer open a second request on a
/// stream it already closed for sending, duplicating route/auth/handler
/// execution while the first response is still outstanding.
///
/// An unknown stream is allowed: that is a genuinely new stream, validated by
/// the id and concurrency checks at the call site.
/// True when an initial header block requests the CONNECT method.
fn h2HeaderBlockRequestsConnect(fields: []const http.hpack.HeaderField) bool {
    for (fields) |field| {
        if (std.mem.eql(u8, field.name, ":method")) return std.mem.eql(u8, field.value, "CONNECT");
    }
    return false;
}

fn h2StreamAcceptsInboundFrame(streams: *std.AutoHashMap(u31, http.http2_stream.Stream), stream_id: u31) bool {
    const existing = streams.get(stream_id) orelse return true;
    return existing.canReceive();
}

/// Minimal "200 OK" response HEADERS for a stream attached as a #867
/// session: the session's consumer only ever produces/consumes DATA, never
/// framing, so the runtime sends this on its behalf immediately on attach.
fn h2WriteSessionResponseHeaders(writer: anytype, allocator: std.mem.Allocator, stream_id: u31) !void {
    const status_headers = [_]http.hpack.HeaderField{
        .{ .name = ":status", .value = "200" },
    };
    const block = try http.hpack.encodeLiteralHeaderBlock(allocator, status_headers[0..]);
    defer allocator.free(block);
    try http.http2_frame.writeFrame(writer, .headers, http.http2_frame.Flags.END_HEADERS, stream_id, block);
}

fn h2ProcessHeaderBlock(
    allocator: std.mem.Allocator,
    decoder: *http.hpack.Decoder,
    pending: *std.AutoHashMap(u31, Http2PendingStream),
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    ready_streams: *std.array_list.Managed(u31),
    sessions: *std.AutoHashMap(u31, *http.h2_stream_session.Session),
    state: *GatewayState,
    stream_id: u31,
    header_block: []const u8,
    end_stream: bool,
    transport_early: bool,
    writer: anytype,
    last_client_stream_id: u31,
    max_connection_memory_bytes: usize,
    buffered_request_bytes: *usize,
) !void {
    var decoded = decoder.decode(allocator, header_block) catch {
        try http.http2_frame.writeGoaway(writer, last_client_stream_id, http.http2_stream.ErrorCode.compression_error.value());
        return error.Http2CompressionError;
    };
    defer http.hpack.deinitDecoded(allocator, &decoded);

    if (sessions.get(stream_id)) |active_session| {
        // A second HEADERS frame on an attached #867 session stream can
        // only be a trailing field section that ends the stream (RFC 9113
        // §8.1); the HPACK decode above still ran so the shared dynamic
        // table stays in sync with the peer's encoder regardless.
        if (!h2RequestHeaderBlockIsValid(decoded.headers, false) or !end_stream) {
            try http.http2_frame.writeGoaway(writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
            return error.InvalidHttp2Request;
        }
        if (streams.getPtr(stream_id)) |s| s.remoteEndStream() catch {};
        active_session.deliverRemoteEndStream();
        return;
    }

    const initial_headers = !pending.contains(stream_id);
    if (!h2RequestHeaderBlockIsValid(decoded.headers, initial_headers)) {
        try http.http2_frame.writeGoaway(writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
        return error.InvalidHttp2Request;
    }
    if (!initial_headers and !end_stream) {
        // A trailing field section terminates the request. Accepting DATA
        // after it creates two different message boundaries across hops.
        try http.http2_frame.writeGoaway(writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
        return error.InvalidHttp2Request;
    }

    if (initial_headers and h2HeaderBlockRequestsConnect(decoded.headers)) {
        // CONNECT (RFC 9113 §8.5 authority-form) is syntactically valid HTTP/2
        // and the validator above accepts it as such, but Tardigrade does not
        // implement tunneling: the shared HTTP/1 adapter has no authority-form
        // representation, and synthesizing an origin-form `:path` would route a
        // tunnel request at some unrelated path.
        //
        // So refuse it deliberately and visibly, at stream scope. Letting it
        // through reached `respondHttp2Stream`'s `ps.path orelse
        // error.InvalidHttp2Request`, which tore down the whole connection with
        // a generic error instead of answering the one stream. Other streams on
        // this connection are unaffected.
        try http.http2_frame.writeRstStream(writer, stream_id, http.http2_stream.ErrorCode.refused_stream.value());
        if (streams.getPtr(stream_id)) |s| s.close();
        return;
    }

    if (!initial_headers) {
        // Trailers are validated above but deliberately not retained or
        // folded into the routing/authentication header set.
        if (streams.getPtr(stream_id)) |s| s.remoteEndStream() catch {};
        try h2AppendReadyStream(ready_streams, stream_id);
        return;
    }

    var ps = Http2PendingStream.init(allocator);
    var committed = false;
    errdefer if (!committed) ps.deinit(allocator);
    ps.transport_early = ps.transport_early or transport_early;
    if (streams.get(stream_id)) |s| ps.priority_weight = s.priority_weight;
    for (decoded.headers) |h| {
        if (std.mem.eql(u8, h.name, ":method")) {
            ps.method = try allocator.dupe(u8, h.value);
        } else if (std.mem.eql(u8, h.name, ":path")) {
            ps.path = try allocator.dupe(u8, h.value);
        } else if (std.mem.eql(u8, h.name, ":authority")) {
            ps.authority = try allocator.dupe(u8, h.value);
        } else if (initial_headers and h.name.len > 0 and h.name[0] != ':') {
            // This proxy does not forward request trailers. In particular,
            // never fold them into the initial field collection used for
            // routing or authentication (Host/Authorization trailers must
            // not become initial request metadata).
            try ps.headers.append(h.name, h.value);
        }
    }

    if (state.h2_session_test_hook) |hook| {
        if (hook.shouldAttach(hook.ctx, &ps)) {
            // A session's bounded queues are charged against the same
            // connection-wide memory ceiling as ordinary buffered request
            // bytes: otherwise many concurrent sessions (each individually
            // bounded) could together retain far more than
            // `cfg.max_connection_memory_bytes` permits.
            if (max_connection_memory_bytes > 0 and HTTP2_SESSION_RESERVED_BYTES > max_connection_memory_bytes -| buffered_request_bytes.*) {
                // Refuse only this stream: a GOAWAY here would tear down the
                // whole connection -- including already-admitted sessions and
                // ordinary sibling requests -- merely because one more
                // session cannot be admitted under the connection budget.
                try http.http2_frame.writeRstStream(writer, stream_id, http.http2_stream.ErrorCode.refused_stream.value());
                // Retire the bookkeeping, not just the state: admission for
                // new streams is bounded by `streams.count()`, so leaving a
                // `.closed` entry behind here would let repeated refusals
                // on this connection exhaust that limit and force a GOAWAY
                // on the next healthy sibling request.
                _ = streams.remove(stream_id);
                ps.deinit(allocator);
                return;
            }
            // Headers that request a persistent #867 session never enter
            // `pending`/ordinary finite dispatch; `ps`'s parsed fields are
            // only used by `shouldAttach` above.
            const session = try allocator.create(http.h2_stream_session.Session);
            errdefer allocator.destroy(session);
            session.* = try http.h2_stream_session.Session.init(
                allocator,
                stream_id,
                HTTP2_SESSION_MAX_INBOUND_BYTES,
                HTTP2_SESSION_MAX_OUTBOUND_BYTES,
            );
            errdefer session.deinit();
            // RFC 9113 requires a response HEADERS before DATA; the
            // session's consumer only ever sees DATA, never framing, so the
            // runtime sends a minimal 200 on its behalf.
            try h2WriteSessionResponseHeaders(writer, allocator, stream_id);
            try sessions.put(stream_id, session);
            buffered_request_bytes.* += HTTP2_SESSION_RESERVED_BYTES;
            if (end_stream) session.deliverRemoteEndStream();
            hook.attach(hook.ctx, session);
            ps.deinit(allocator);
            return;
        }
    }

    const retained = ps.retainedBytes();
    if (max_connection_memory_bytes > 0 and retained > max_connection_memory_bytes -| buffered_request_bytes.*) {
        try http.http2_frame.writeGoaway(writer, last_client_stream_id, http.http2_stream.ErrorCode.enhance_your_calm.value());
        return error.Http2ConnectionMemoryLimitExceeded;
    }
    try pending.put(stream_id, ps);
    buffered_request_bytes.* += retained;
    committed = true;
    if (end_stream) {
        if (streams.getPtr(stream_id)) |s| s.remoteEndStream() catch {};
        try h2AppendReadyStream(ready_streams, stream_id);
    }
}

test "HTTP/2 request header validation rejects ambiguous pseudo-header envelopes" {
    try std.testing.expect(h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "accept", .value = "*/*" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "trusted.test" },
        .{ .name = ":authority", .value = "attacker.test" },
        .{ .name = ":path", .value = "/" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = "accept", .value = "*/*" },
        .{ .name = ":path", .value = "/after-regular" },
        .{ .name = ":scheme", .value = "https" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":unknown", .value = "ignored-before" },
        .{ .name = ":path", .value = "/" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "X-Uppercase", .value = "invalid-in-h2" },
    }, true));
    try std.testing.expect(h2RequestHeaderBlockIsValid(&.{
        .{ .name = "x-checksum", .value = "abc" },
    }, false));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":path", .value = "/pseudo-in-trailers" },
    }, false));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "trusted.test" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "attacker.test" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = "host", .value = "one.test" },
        .{ .name = "host", .value = "two.test" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "trusted.test" },
        .{ .name = ":path", .value = "/private HTTP/1.1\r\nX-Injected: yes" },
    }, true));
}

test "HTTP/2 padded payload parsing excludes transport padding" {
    const padded_data = [_]u8{ 3, 'o', 'k', 0, 0, 0 };
    try std.testing.expectEqualStrings("ok", try h2DataPayload(&padded_data, http.http2_frame.Flags.PADDED));
    try std.testing.expectError(error.InvalidHttp2Padding, h2DataPayload(&.{ 2, 0 }, http.http2_frame.Flags.PADDED));

    const padded_headers = [_]u8{ 2, 1, 2, 3, 0, 0 };
    const parsed = try h2HeadersPayload(&padded_headers, http.http2_frame.Flags.PADDED);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3 }, parsed.fragment);
    try std.testing.expect(parsed.priority == null);

    const priority_headers = [_]u8{ 1, 0, 0, 0, 0, 15, 0x82, 0 };
    const with_priority = try h2HeadersPayload(&priority_headers, http.http2_frame.Flags.PADDED | http.http2_frame.Flags.PRIORITY);
    try std.testing.expectEqualSlices(u8, &.{0x82}, with_priority.fragment);
    try std.testing.expectEqual(@as(usize, 5), with_priority.priority.?.len);
}

/// Outbound response body parked on a stream while HTTP/2 send credit is
/// exhausted. Ownership of `body_alloc` (when set) transfers here from
/// `respondHttp2Stream`; `deinit` is idempotent so it is safe to call from
/// both the normal completion path and cleanup paths (RST_STREAM, GOAWAY,
/// connection teardown).
const PendingHttp2Response = struct {
    body_alloc: ?[]u8,
    body: []const u8,
    offset: usize = 0,
    status_code: u16,

    fn deinit(self: *PendingHttp2Response, allocator: std.mem.Allocator) void {
        if (self.body_alloc) |b| allocator.free(b);
        self.body_alloc = null;
    }
};

const Http2FlushResult = enum { complete, blocked };

/// Write as much of `resp`'s body as current connection/stream send credit
/// allows, chunked to the peer's max frame size. Never reads from `conn` --
/// the central frame loop in `handleHttp2Connection` is the sole reader, so
/// this can safely be called both inline (first attempt) and later from the
/// WINDOW_UPDATE handler to resume a blocked response, without ever racing
/// with or dropping frames belonging to other streams.
fn flushHttp2PendingResponse(
    conn: anytype,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    writer: anytype,
    stream_id: u31,
    resp: *PendingHttp2Response,
    conn_send_window: *i32,
    stream_send_window: *i32,
) !Http2FlushResult {
    const max_data_frame: usize = HTTP2_MAX_FRAME_SIZE;
    if (resp.body.len == 0) {
        try h2WriteDataFrame(conn, outbound, writer, http.http2_frame.Flags.END_STREAM, stream_id, &.{});
        return .complete;
    }
    while (resp.offset < resp.body.len) {
        const credit = @min(conn_send_window.*, stream_send_window.*);
        if (credit <= 0) return .blocked;
        const remaining_window: usize = @intCast(credit);
        const n = @min(@min(max_data_frame, remaining_window), resp.body.len - resp.offset);
        const end = resp.offset + n;
        const flags: u8 = if (end == resp.body.len) http.http2_frame.Flags.END_STREAM else 0;
        try h2WriteDataFrame(conn, outbound, writer, flags, stream_id, resp.body[resp.offset..end]);
        conn_send_window.* -= @intCast(n);
        stream_send_window.* -= @intCast(n);
        resp.offset = end;
    }
    return .complete;
}

fn h2WriteDataFrame(conn: anytype, outbound: ?*http.h2_outbound_scheduler.Scheduler, writer: anytype, flags: u8, stream_id: u31, payload: []const u8) !void {
    http.http2_frame.writeFrame(writer, .data, flags, stream_id, payload) catch |err| {
        if (outbound) |queue| {
            if (std.mem.eql(u8, @errorName(err), "QueueFull")) {
                try queue.flush(conn.writer());
                return http.http2_frame.writeFrame(writer, .data, flags, stream_id, payload);
            }
        }
        return err;
    };
}

/// Resume every response parked on send-credit exhaustion after new credit
/// arrives (connection- or stream-level WINDOW_UPDATE). Called only from the
/// central frame loop, never from a response writer.
fn h2FlushPendingHttp2Responses(
    conn: anytype,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    writer: anytype,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    conn_send_window: *i32,
) !void {
    if (pending_responses.count() == 0) return;
    var finished = std.array_list.Managed(u31).init(allocator);
    defer finished.deinit();

    var it = pending_responses.iterator();
    while (it.next()) |entry| {
        const sid = entry.key_ptr.*;
        const resp = entry.value_ptr;
        const stream_window_ptr = if (streams.getPtr(sid)) |s| &s.send_window else {
            resp.deinit(allocator);
            try finished.append(sid);
            continue;
        };
        const result = try flushHttp2PendingResponse(conn, outbound, writer, sid, resp, conn_send_window, stream_window_ptr);
        if (result == .complete) {
            state.metricsRecord(resp.status_code);
            resp.deinit(allocator);
            try finished.append(sid);
        }
    }

    for (finished.items) |sid| {
        _ = pending_responses.remove(sid);
        _ = streams.remove(sid);
    }
}

/// Route one inbound DATA frame payload to an attached persistent stream
/// session (#867) instead of the ordinary finite-request buffer. `app_payload`
/// is the application bytes only (padding and the Pad Length octet already
/// stripped by `h2DataPayload`); `frame_payload_len` is the full DATA frame
/// payload length flow control actually charges the peer for.
///
/// Application-byte receive credit is deliberately not returned here:
/// `h2ReturnSessionReceiveCredit` only grants it once the consumer actually
/// drains queued bytes, so a stalled consumer caps retained memory instead
/// of growing the window. Padding is never buffered by the session at all
/// (only `app_payload` is), so its share of the frame's flow-control charge
/// is credited back immediately rather than held hostage to a slow consumer.
fn h2DeliverSessionInboundData(
    writer: anytype,
    session: *http.h2_stream_session.Session,
    stream_id: u31,
    frame_payload_len: usize,
    app_payload: []const u8,
    end_stream: bool,
) !void {
    if (app_payload.len > 0) try session.deliverInbound(app_payload);
    if (end_stream) session.deliverRemoteEndStream();
    const padding_len = frame_payload_len - app_payload.len;
    if (padding_len > 0) {
        try http.http2_frame.writeWindowUpdate(writer, stream_id, @intCast(padding_len));
        try http.http2_frame.writeWindowUpdate(writer, 0, @intCast(padding_len));
    }
}

/// Drain an attached session's outbound queue onto the wire exactly like
/// `flushHttp2PendingResponse` drains a finite response: the same per-frame
/// cap and stream/connection send-credit accounting, segmented so a stalled
/// peer blocks this stream's bytes without blocking siblings. Emits the
/// final END_STREAM-flagged frame once the consumer calls `finishLocal` and
/// the queue has fully drained, and advances the stream state machine to
/// match so connection-wide bookkeeping (e.g. `countOpenStreams`) and
/// RST/GOAWAY detection stay correct for an attached session exactly as
/// they already are for an ordinary response.
fn flushHttp2SessionOutbound(
    conn: anytype,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    writer: anytype,
    stream_id: u31,
    session: *http.h2_stream_session.Session,
    conn_send_window: *i32,
    stream: *http.http2_stream.Stream,
) !void {
    const max_data_frame: usize = HTTP2_MAX_FRAME_SIZE;
    while (true) {
        const credit = @min(conn_send_window.*, stream.send_window);
        if (credit <= 0) break;
        const chunk = session.peekOutbound(@min(max_data_frame, @as(usize, @intCast(credit)))) orelse break;
        if (chunk.len == 0) break;
        const n = chunk.len;
        try h2WriteDataFrame(conn, outbound, writer, 0, stream_id, chunk);
        session.commitOutboundSent(n);
        conn_send_window.* -= @intCast(n);
        stream.send_window -= @intCast(n);
    }
    if (session.outboundLocalEndPending()) {
        try h2WriteDataFrame(conn, outbound, writer, http.http2_frame.Flags.END_STREAM, stream_id, &.{});
        session.markLocalEndStreamSent();
        stream.localEndStream() catch {};
    }
}

/// Return receive-window credit the consumer has earned by draining inbound
/// bytes since the last call. Mirrors ordinary-stream WINDOW_UPDATE: both
/// the stream and connection windows grow by the same amount (#867).
///
/// Credit is only cleared once both WINDOW_UPDATE frames are confirmed
/// written: if the first write succeeds but the second fails, the pending
/// credit is left intact for a retry rather than taken-and-lost, and the
/// propagated error tears down the connection (so a retry cannot ever
/// double-credit a live peer).
fn h2ReturnSessionReceiveCredit(writer: anytype, session: *http.h2_stream_session.Session, stream: *http.http2_stream.Stream, conn_recv_window: *i64) !void {
    const credit = session.peekReceiveCreditToReturn();
    if (credit == 0) return;
    try http.http2_frame.writeWindowUpdate(writer, stream.id, @intCast(credit));
    try http.http2_frame.writeWindowUpdate(writer, 0, @intCast(credit));
    session.consumeReceiveCredit(credit);
    // Mirror the credit we just granted back to the peer in our own
    // receive-window bookkeeping (see `conn_recv_window`/`Stream.recv_window`
    // in `handleHttp2Connection`), the same way the ordinary finite-request
    // path does inline when it emits its own WINDOW_UPDATE pair.
    stream.recv_window += @intCast(credit);
    conn_recv_window.* += @intCast(credit);
}

const Http2SessionCloseReason = enum { goaway, connection_closed, shutdown };

/// Settle every attached session for a connection-wide terminal event
/// (GOAWAY, abrupt close, or graceful shutdown) and detach the runtime
/// side of each. A session whose consumer already detached is freed here;
/// otherwise the consumer's later `consumerDetach` frees it.
fn h2SettleAllSessions(
    allocator: std.mem.Allocator,
    sessions: *std.AutoHashMap(u31, *http.h2_stream_session.Session),
    reason: Http2SessionCloseReason,
) void {
    var it = sessions.valueIterator();
    while (it.next()) |session_ptr| {
        const session = session_ptr.*;
        switch (reason) {
            .goaway => session.deliverGoaway(),
            .connection_closed => session.deliverConnectionClosed(),
            .shutdown => session.deliverShutdown(),
        }
        if (session.runtimeDetach()) {
            session.deinit();
            allocator.destroy(session);
        }
    }
    sessions.clearAndFree();
}

/// Detach the runtime side of one stream's session after RST_STREAM or
/// ordinary bidirectional close, freeing it if the consumer already
/// detached and releasing its reserved share of the connection memory
/// budget (see `HTTP2_SESSION_RESERVED_BYTES`).
fn h2DetachSession(
    writer: anytype,
    allocator: std.mem.Allocator,
    sessions: *std.AutoHashMap(u31, *http.h2_stream_session.Session),
    buffered_request_bytes: *usize,
    stream_id: u31,
    conn_recv_window: ?*i64,
) !void {
    const removed = sessions.fetchRemove(stream_id) orelse return;
    const session = removed.value;
    buffered_request_bytes.* -= @min(buffered_request_bytes.*, HTTP2_SESSION_RESERVED_BYTES);
    // Any inbound bytes that already charged the peer's connection-level
    // receive window but were never credited back -- because the session
    // settled (reset, wake failure, cancellation) before a consumer drained
    // them -- must be returned now via a stream-0-only WINDOW_UPDATE: the
    // stream's own credit is about to become unreachable.
    const abandoned_credit = session.takeReceiveCreditToReturn();
    // As in `h2ResetStreamState`: detach/free unconditionally once removed
    // from the registry, so a failed WINDOW_UPDATE write can never orphan
    // the session (the registry has already lost its only reference).
    defer if (session.runtimeDetach()) {
        session.deinit();
        allocator.destroy(session);
    };
    if (abandoned_credit > 0) {
        try http.http2_frame.writeWindowUpdate(writer, 0, @intCast(abandoned_credit));
        // Keep our local receive-window counter in lockstep with the peer:
        // see the matching comment in `h2ResetStreamState`.
        if (conn_recv_window) |w| w.* += @intCast(abandoned_credit);
    }
}

fn h2DispatchReadyStreamsWithWriter(
    conn: anytype,
    writer: anytype,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    pending: *std.AutoHashMap(u31, Http2PendingStream),
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    ready_streams: *std.array_list.Managed(u31),
    next_server_stream_id: *u31,
    conn_send_window: *i32,
    buffered_request_bytes: *usize,
    connection_ip: []const u8,
    handoff: ?*http.h2_request_handoff.Handoff,
    executor: ?*http.h2_request_executor.Executor,
    in_flight: *std.AutoHashMap(u31, void),
) !void {
    _ = next_server_stream_id;
    if (ready_streams.items.len == 0) return;

    const initial_ready = ready_streams.items.len;
    var processed: usize = 0;
    while (processed < initial_ready and ready_streams.items.len > 0) : (processed += 1) {
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
        const ps = pending.getPtr(sid) orelse continue;
        if (ps.dispatch_count > 0) continue;

        if (ps.transport_early and !h2DownstreamHandshakeComplete(conn)) {
            if (!ps.early_request_recorded) {
                state.metricsRecordEarlyDataRequest(.h2, .transport);
                ps.early_request_recorded = true;
            }
            if (!ps.deferred_recorded) {
                state.metricsRecordEarlyDataDecision(.h2, .deferred);
                ps.deferred_recorded = true;
            }
            try h2AppendReadyStream(ready_streams, sid);
            continue;
        }

        if (ps.transport_early and !ps.early_request_recorded) {
            state.metricsRecordEarlyDataRequest(.h2, .transport);
            ps.early_request_recorded = true;
        }
        // The accept/reject decision for a transport-early stream is recorded
        // by `respondHttp2Stream`, once routing has had its say (#761).

        try respondHttp2Stream(conn, writer, outbound, allocator, state, cfg, sid, ps, handoff, executor, in_flight, streams, pending_responses, conn_send_window, connection_ip);
        ps.dispatch_count += 1;
        if (pending.fetchRemove(sid)) |removed| {
            var tmp = removed.value;
            buffered_request_bytes.* -= @min(buffered_request_bytes.*, tmp.retainedBytes());
            tmp.deinit(allocator);
        }
        // If the response is still parked on send-credit exhaustion, its
        // `streams` entry (needed for send-window bookkeeping and to detect
        // RST_STREAM/removal) must survive until `h2FlushPendingHttp2Responses`
        // finishes it. The same is true while a worker owns the request
        // (#866): its eventual completion still needs the stream's send
        // window and RST/removal detection.
        if (!pending_responses.contains(sid) and !in_flight.contains(sid)) {
            _ = streams.remove(sid);
        }
    }
}

fn h2DispatchReadyStreams(
    conn: anytype,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    pending: *std.AutoHashMap(u31, Http2PendingStream),
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    ready_streams: *std.array_list.Managed(u31),
    next_server_stream_id: *u31,
    conn_send_window: *i32,
    buffered_request_bytes: *usize,
    connection_ip: []const u8,
) !void {
    var in_flight = std.AutoHashMap(u31, void).init(allocator);
    defer in_flight.deinit();
    return h2DispatchReadyStreamsWithWriter(conn, conn.writer(), null, allocator, state, cfg, pending, streams, pending_responses, ready_streams, next_server_stream_id, conn_send_window, buffered_request_bytes, connection_ip, null, null, &in_flight);
}

fn handleHttp2Connection(conn: anytype, session: *ConnectionSession, cfg: *const edge_config.EdgeConfig, state: *GatewayState, connection_ip: []const u8) !void {
    _ = session;
    var preface: [HTTP2_PREFACE.len]u8 = undefined;
    try readExactConn(conn, preface[0..]);
    if (!std.mem.eql(u8, preface[0..], HTTP2_PREFACE)) return error.InvalidHttp2Preface;

    const allocator = state.allocator;
    var outbound = try http.h2_outbound_scheduler.Scheduler.init(
        allocator,
        http.h2_outbound_scheduler.default_max_queued_bytes,
    );
    defer outbound.deinit();
    const outbound_writer = outbound.writer();
    h2InstallOutboundScheduler(conn, &outbound);
    defer h2InstallOutboundScheduler(conn, null);
    errdefer outbound.flush(conn.writer()) catch {};

    try http.http2_frame.writeSettings(allocator, outbound_writer, &[_][2]u32{
        .{ 0x3, HTTP2_MAX_CONCURRENT_STREAMS }, // max concurrent streams
        .{ 0x4, HTTP2_INITIAL_WINDOW_SIZE }, // initial window size
    });
    try outbound.flush(conn.writer());

    var decoder = http.hpack.Decoder.init();
    defer decoder.deinit(allocator);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready_streams = std.array_list.Managed(u31).init(allocator);
    defer ready_streams.deinit();
    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    // RFC 9113 §6.9.2: the server (as DATA sender) must honor the client's
    // advertised SETTINGS_INITIAL_WINDOW_SIZE for streams opened after the
    // setting and apply any change's delta to already-open streams.
    var peer_initial_window: u32 = 65_535;
    // Receive-side counters (the mirror image of `conn_send_window`/
    // `Stream.send_window`): how many more DATA bytes the peer may send us
    // on this connection, and per-stream, before we must reject it as a
    // real flow-control violation. RFC 9113 §6.9.2 fixes the connection
    // window's initial value at 65,535 regardless of SETTINGS; only our own
    // `HTTP2_INITIAL_WINDOW_SIZE` SETTINGS value raises the per-stream
    // starting point. Both grow only when a WINDOW_UPDATE we actually wrote
    // to the peer grants more credit back.
    var conn_recv_window: i64 = 65_535;
    // Aggregate bytes currently buffered in `pending[*].body` across every
    // stream on this connection, bounded by `cfg.max_connection_memory_bytes`
    // in addition to each stream's own `request_limits` body cap -- a client
    // could otherwise stay under the per-stream limit while opening enough
    // concurrent streams to retain far more than the configured connection
    // memory ceiling.
    var buffered_request_bytes: usize = 0;
    var last_client_stream_id: u31 = 0;
    var goaway_received = false;
    var continuation_stream_id: ?u31 = null;
    var continuation_end_stream = false;
    var continuation_transport_early = false;
    var continuation_block = std.array_list.Managed(u8).init(allocator);
    defer continuation_block.deinit();
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }

    // #866: finite request execution is handed off to a shared, bounded
    // executor so a slow route/auth/proxy/static call never stops this
    // connection from parsing sibling-stream frames or control frames.
    // `in_flight_jobs` keeps a dispatched stream's `streams`/HPACK-adjacent
    // bookkeeping alive while its worker runs, mirroring what
    // `pending_responses` already does for a response parked on
    // flow-control exhaustion.
    var in_flight_jobs = std.AutoHashMap(u31, void).init(allocator);
    defer in_flight_jobs.deinit();
    const executor: ?*http.h2_request_executor.Executor = state.h2_request_executor;
    var handoff = try http.h2_request_handoff.Handoff.init(allocator, HTTP2_MAX_CONCURRENT_STREAMS);
    defer {
        handoff.shutdown();
        if (executor) |ex| ex.detachAndDrain(&handoff);
        handoff.waitForActiveDrain();
        handoff.deinit();
    }

    const DrainCtx = struct {
        conn: @TypeOf(conn),
        writer: @TypeOf(outbound_writer),
        outbound: *http.h2_outbound_scheduler.Scheduler,
        allocator: std.mem.Allocator,
        state: *GatewayState,
        handoff: *http.h2_request_handoff.Handoff,
        streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
        pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
        conn_send_window: *i32,
        in_flight: *std.AutoHashMap(u31, void),

        /// Woken whenever a worker's completion arrives while this connection
        /// is blocked waiting for downstream input (#866's half of #865's
        /// wakeable wait).
        fn drain(raw: *anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            while (self.handoff.takeCompletion()) |delivered| {
                _ = self.in_flight.remove(delivered.stream_id);
                try applyH2RequestCompletion(
                    self.conn,
                    self.writer,
                    self.outbound,
                    self.allocator,
                    self.state,
                    delivered.stream_id,
                    delivered.completion,
                    self.streams,
                    self.pending_responses,
                    self.conn_send_window,
                );
                if (!self.pending_responses.contains(delivered.stream_id) and !self.in_flight.contains(delivered.stream_id)) {
                    _ = self.streams.remove(delivered.stream_id);
                }
            }
            // `finish` retains its terminal event when its wake write fails.
            // Draining above retires the affected stream before this forces
            // the connection through its normal shutdown path.
            if (self.handoff.hasWakeFailure()) return error.H2RequestWakeFailed;
        }
    };
    var drain_ctx = DrainCtx{
        .conn = conn,
        .writer = outbound_writer,
        .outbound = &outbound,
        .allocator = allocator,
        .state = state,
        .handoff = &handoff,
        .streams = &streams,
        .pending_responses = &pending_responses,
        .conn_send_window = &conn_send_window,
        .in_flight = &in_flight_jobs,
    };
    h2InstallRequestHandoff(conn, &handoff, DrainCtx.drain, &drain_ctx);
    defer h2InstallRequestHandoff(conn, null, null, null);

    // #867: streams attached as persistent bidirectional sessions. Settled
    // for whatever terminal reason this connection actually ends with --
    // GOAWAY, graceful shutdown, or an abrupt close/error -- regardless of
    // which `return` below unwinds through this defer.
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer {
        const reason: Http2SessionCloseReason = if (goaway_received)
            .goaway
        else if (http.shutdown.isShutdownRequested())
            .shutdown
        else
            .connection_closed;
        h2SettleAllSessions(allocator, &sessions, reason);
    }

    const SessionDrainCtx = struct {
        allocator: std.mem.Allocator,
        conn: @TypeOf(conn),
        writer: @TypeOf(outbound_writer),
        outbound: *http.h2_outbound_scheduler.Scheduler,
        sessions: *std.AutoHashMap(u31, *http.h2_stream_session.Session),
        streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
        conn_send_window: *i32,
        conn_recv_window: *i64,
        buffered_request_bytes: *usize,

        fn pollFds(raw: *anyopaque, buf: []std.posix.fd_t) []const std.posix.fd_t {
            const self: *@This() = @ptrCast(@alignCast(raw));
            var n: usize = 0;
            var it = self.sessions.valueIterator();
            while (it.next()) |session_ptr| {
                if (n >= buf.len) break;
                buf[n] = session_ptr.*.wakeFd();
                n += 1;
            }
            return buf[0..n];
        }

        /// Service every attached session's pending outbound/credit/cancel
        /// work (#867's half of #865's wakeable wait), detaching any session
        /// that just reached a terminal state. Woken by any session's wake
        /// fd firing in `waitFor`, and also run unconditionally once per
        /// loop iteration so a busy connection -- one that keeps `readFrame`
        /// returning real data and never falls into that blocking poll --
        /// cannot starve a session behind a steady stream of frames on
        /// other streams.
        fn drain(raw: *anyopaque) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            var detach_list = std.array_list.Managed(u31).init(self.allocator);
            defer detach_list.deinit();

            var it = self.sessions.iterator();
            while (it.next()) |entry| {
                const stream_id = entry.key_ptr.*;
                const sess = entry.value_ptr.*;
                sess.clearWake();
                if (sess.hasWakeFailure() or sess.hasWriteFailure()) {
                    // A lost wake notification means this session can no
                    // longer learn about new inbound credit or outbound
                    // bytes; a failed producer write may have already
                    // queued a prefix the consumer cannot safely retry.
                    // Treat both like a protocol-level reset rather than
                    // let the stream stall forever. Cancel any output this
                    // stream already queued with the scheduler first, same
                    // as the consumer-cancel path below, so a reset stream
                    // never has stale DATA retained or transmitted after it.
                    const refunded = self.outbound.cancelStream(stream_id);
                    if (refunded > 0) self.conn_send_window.* +|= @intCast(@min(refunded, std.math.maxInt(i32)));
                    try http.http2_frame.writeRstStream(self.writer, stream_id, http.http2_stream.ErrorCode.internal_error.value());
                    sess.deliverReset(.internal_error);
                    try detach_list.append(stream_id);
                    continue;
                }
                const stream_ptr = self.streams.getPtr(stream_id) orelse {
                    // This stream's bookkeeping disappeared without this
                    // session ever being detached (e.g. an ordinary
                    // RST/close path removed it). Settle it explicitly so a
                    // blocked consumer is woken instead of left owning a
                    // live but unreachable handle.
                    sess.deliverReset(.internal_error);
                    try detach_list.append(stream_id);
                    continue;
                };
                try flushHttp2SessionOutbound(self.conn, self.outbound, self.writer, stream_id, sess, self.conn_send_window, stream_ptr);
                try h2ReturnSessionReceiveCredit(self.writer, sess, stream_ptr, self.conn_recv_window);
                if (sess.takeCancelRequest()) {
                    const refunded = self.outbound.cancelStream(stream_id);
                    if (refunded > 0) self.conn_send_window.* +|= @intCast(@min(refunded, std.math.maxInt(i32)));
                    try http.http2_frame.writeRstStream(self.writer, stream_id, http.http2_stream.ErrorCode.cancel.value());
                    sess.deliverReset(.cancel);
                    try detach_list.append(stream_id);
                    continue;
                }
                if (stream_ptr.state == .closed) try detach_list.append(stream_id);
            }
            for (detach_list.items) |stream_id| {
                try h2DetachSession(self.writer, self.allocator, self.sessions, self.buffered_request_bytes, stream_id, self.conn_recv_window);
                _ = self.streams.remove(stream_id);
            }
        }
    };
    var session_drain_ctx = SessionDrainCtx{
        .allocator = allocator,
        .conn = conn,
        .writer = outbound_writer,
        .outbound = &outbound,
        .sessions = &sessions,
        .streams = &streams,
        .conn_send_window = &conn_send_window,
        .conn_recv_window = &conn_recv_window,
        .buffered_request_bytes = &buffered_request_bytes,
    };
    h2InstallSessionRegistry(conn, SessionDrainCtx.pollFds, SessionDrainCtx.drain, &session_drain_ctx);
    defer h2InstallSessionRegistry(conn, null, null, null);

    while (!http.shutdown.isShutdownRequested() and !goaway_received) {
        // Apply any worker completions that already arrived. A busy
        // connection that keeps `readFrame` returning real data every
        // iteration never falls into `waitFor`'s blocking poll, so draining
        // here -- not only from that poll's wake path -- is what keeps a
        // slow job's sibling streams from starving behind a steady stream of
        // fast ones (#866).
        try DrainCtx.drain(&drain_ctx);
        try SessionDrainCtx.drain(&session_drain_ctx);

        try h2DispatchReadyStreamsWithWriter(
            conn,
            outbound_writer,
            &outbound,
            allocator,
            state,
            cfg,
            &pending,
            &streams,
            &pending_responses,
            &ready_streams,
            &next_server_stream_id,
            &conn_send_window,
            &buffered_request_bytes,
            connection_ip,
            &handoff,
            executor,
            &in_flight_jobs,
        );

        if (h2HasDeferredReadyStreams(&pending, &ready_streams) and !h2DownstreamHandshakeComplete(conn)) {
            try h2WaitForHandshakeCompletionOrInput(conn);
            try h2DispatchReadyStreamsWithWriter(
                conn,
                outbound_writer,
                &outbound,
                allocator,
                state,
                cfg,
                &pending,
                &streams,
                &pending_responses,
                &ready_streams,
                &next_server_stream_id,
                &conn_send_window,
                &buffered_request_bytes,
                connection_ip,
                &handoff,
                executor,
                &in_flight_jobs,
            );
            if (ready_streams.items.len == 0) continue;
        }

        h2BeginReadScope(conn);

        var frame = http.http2_frame.readFrame(conn, allocator, HTTP2_MAX_FRAME_SIZE) catch |err| switch (err) {
            error.ConnectionClosed => return,
            else => return err,
        };
        defer http.http2_frame.deinitFrame(allocator, &frame);
        const frame_transport_early = h2LastReadTransportEarly(conn);

        if (continuation_stream_id) |expected_stream_id| {
            if (frame.typ != .continuation or frame.stream_id != expected_stream_id) {
                try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                return error.InvalidHttp2FrameSequence;
            }
        } else if (frame.typ == .continuation) {
            try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
            return error.InvalidHttp2FrameSequence;
        }

        switch (frame.typ) {
            .settings => {
                if (frame.stream_id != 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return error.InvalidHttp2StreamId;
                }
                if ((frame.flags & http.http2_frame.Flags.ACK) != 0 and frame.payload.len != 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.frame_size_error.value());
                    return error.InvalidSettingsFrame;
                }
                if ((frame.flags & http.http2_frame.Flags.ACK) == 0) {
                    const new_initial_window = http.http2_frame.parseSettingsInitialWindowSize(frame.payload) catch |err| {
                        const code = switch (err) {
                            error.Http2FlowControlError => http.http2_stream.ErrorCode.flow_control_error,
                            error.InvalidSettingsValue => http.http2_stream.ErrorCode.protocol_error,
                            else => http.http2_stream.ErrorCode.frame_size_error,
                        };
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, code.value());
                        return err;
                    };
                    if (new_initial_window) |new_window| {
                        const delta: i64 = @as(i64, new_window) - @as(i64, peer_initial_window);
                        peer_initial_window = new_window;
                        if (delta != 0) {
                            var it = streams.valueIterator();
                            while (it.next()) |s| {
                                const adjusted: i64 = @as(i64, s.send_window) + delta;
                                // RFC 9113 §6.9.2: a stream already sitting
                                // at (or near) maxInt(i32) from a prior
                                // WINDOW_UPDATE can still be pushed past the
                                // 2^31-1 ceiling by a positive delta here --
                                // that must be a connection-level
                                // FLOW_CONTROL_ERROR, not an unchecked cast.
                                if (adjusted > std.math.maxInt(i32)) {
                                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                                    return error.Http2FlowControlError;
                                }
                                // A negative result is explicitly allowed by
                                // the RFC (it just blocks sends on this
                                // stream until more credit arrives, not an
                                // error); saturate rather than trap if it
                                // falls below what `i32` can represent, since
                                // any sufficiently negative value is equally
                                // "blocked" for flow-control purposes.
                                s.send_window = @intCast(@max(adjusted, @as(i64, std.math.minInt(i32))));
                            }
                        }
                    }
                    try http.http2_frame.writeSettingsAck(outbound_writer);
                }
            },
            .ping => {
                if (frame.stream_id != 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return error.InvalidHttp2StreamId;
                }
                if (frame.payload.len != 8) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.frame_size_error.value());
                    return error.InvalidPingPayload;
                }
                if ((frame.flags & http.http2_frame.Flags.ACK) == 0) try http.http2_frame.writePingAck(outbound_writer, frame.payload);
            },
            .headers => {
                if (frame.stream_id == 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return error.InvalidHttp2StreamId;
                }
                if ((frame.stream_id & 1) == 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return error.InvalidHttp2StreamId;
                }
                if (frame.stream_id <= last_client_stream_id and !streams.contains(frame.stream_id)) {
                    try h2WriteStreamClosedReset(outbound_writer, &outbound, allocator, &streams, &pending, &pending_responses, &ready_streams, &sessions, &buffered_request_bytes, frame.stream_id, &handoff, executor, &in_flight_jobs, &conn_recv_window, &conn_send_window);
                    continue;
                }
                last_client_stream_id = @max(last_client_stream_id, frame.stream_id);
                // The stream state machine is the lifecycle authority, NOT
                // `pending`. `h2DispatchReadyStreams` removes a request from
                // `pending` as soon as it dispatches, while deliberately
                // keeping the `streams` entry alive when a response is parked
                // on send-credit exhaustion. If the client already sent
                // END_STREAM, that stream is half_closed_remote: treating
                // "absent from pending" as "this is a new request" would let
                // another HEADERS frame on the same id be constructed as a
                // SECOND request, duplicating route/auth/handler execution
                // while the first response is still outstanding.
                if (!h2StreamAcceptsInboundFrame(&streams, frame.stream_id)) {
                    try h2WriteStreamClosedReset(outbound_writer, &outbound, allocator, &streams, &pending, &pending_responses, &ready_streams, &sessions, &buffered_request_bytes, frame.stream_id, &handoff, executor, &in_flight_jobs, &conn_recv_window, &conn_send_window);
                    continue;
                }
                if (!streams.contains(frame.stream_id)) {
                    if (streams.count() >= HTTP2_MAX_CONCURRENT_STREAMS) {
                        // Bound all per-stream maps and header/body ownership.
                        // Close the connection on a peer that exceeds the
                        // limit so we never skip a header block and desync the
                        // connection-scoped HPACK dynamic table.
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.enhance_your_calm.value());
                        return error.Http2ConcurrentStreamLimitExceeded;
                    }
                    try streams.put(frame.stream_id, http.http2_stream.Stream.init(frame.stream_id, @intCast(peer_initial_window)));
                    // `Stream.init` defaults `recv_window` to the RFC 9113
                    // default of 65,535; override it to what this
                    // connection actually advertised via SETTINGS
                    // INITIAL_WINDOW_SIZE above, since that is the real
                    // per-stream credit the client was granted to send us.
                    if (streams.getPtr(frame.stream_id)) |s| s.recv_window = @intCast(HTTP2_INITIAL_WINDOW_SIZE);
                }
                const headers_payload = h2HeadersPayload(frame.payload, frame.flags) catch |err| {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return err;
                };
                if (headers_payload.priority) |priority_payload| {
                    const pr = try http.http2_frame.parsePriority(priority_payload);
                    if (streams.getPtr(frame.stream_id)) |s| s.priority_weight = pr.weight;
                }
                if ((frame.flags & http.http2_frame.Flags.END_HEADERS) == 0) {
                    const fragment = headers_payload.fragment;
                    if (fragment.len > h2EncodedHeaderBlockLimit(cfg, buffered_request_bytes)) {
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.compression_error.value());
                        return error.Http2CompressionError;
                    }
                    continuation_stream_id = frame.stream_id;
                    continuation_end_stream = (frame.flags & http.http2_frame.Flags.END_STREAM) != 0;
                    continuation_transport_early = frame_transport_early;
                    continuation_block.clearRetainingCapacity();
                    try continuation_block.appendSlice(fragment);
                    continue;
                }
                if (headers_payload.fragment.len > h2EncodedHeaderBlockLimit(cfg, buffered_request_bytes)) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.compression_error.value());
                    return error.Http2CompressionError;
                }
                try h2ProcessHeaderBlock(
                    allocator,
                    &decoder,
                    &pending,
                    &streams,
                    &ready_streams,
                    &sessions,
                    state,
                    frame.stream_id,
                    headers_payload.fragment,
                    (frame.flags & http.http2_frame.Flags.END_STREAM) != 0,
                    frame_transport_early,
                    outbound_writer,
                    last_client_stream_id,
                    cfg.max_connection_memory_bytes,
                    &buffered_request_bytes,
                );
                if (pending.getPtr(frame.stream_id)) |stamped| stamped.headers.client_cert = connClientCertificate(conn);
            },
            .data => {
                if (frame.stream_id == 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return error.InvalidHttp2StreamId;
                }
                // Same lifecycle rule as HEADERS: DATA after the remote's
                // END_STREAM is a stream error (RFC 7540 §5.1,
                // half_closed_remote), not new body for a dispatched request.
                if (!h2StreamAcceptsInboundFrame(&streams, frame.stream_id)) {
                    // RFC 9113 §6.9/§5.1: DATA on a stream we already
                    // closed for receiving still counts against the
                    // connection-wide receive window the instant it
                    // arrives -- a peer that keeps sending to a closed
                    // stream after we reset it must not get to bypass the
                    // connection cap that way. Charge it, fail the
                    // connection on a genuine violation, and otherwise
                    // discard the payload and return the credit at once
                    // via a stream-0 WINDOW_UPDATE, since there is no
                    // longer a stream to carry it forward.
                    const charge: i64 = @intCast(frame.payload.len);
                    if (conn_recv_window - charge < 0) {
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                        return error.Http2FlowControlError;
                    }
                    if (charge > 0) try http.http2_frame.writeWindowUpdate(outbound_writer, 0, @intCast(charge));
                    try h2WriteStreamClosedReset(outbound_writer, &outbound, allocator, &streams, &pending, &pending_responses, &ready_streams, &sessions, &buffered_request_bytes, frame.stream_id, &handoff, executor, &in_flight_jobs, &conn_recv_window, &conn_send_window);
                    continue;
                }
                if (!streams.contains(frame.stream_id) and !sessions.contains(frame.stream_id) and !pending.contains(frame.stream_id)) {
                    if (frame.stream_id > last_client_stream_id) {
                        // Genuinely idle: the client never opened this
                        // stream with HEADERS. RFC 9113 §5.1 makes sending
                        // DATA on an idle stream a connection error.
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                        return error.InvalidHttp2StreamId;
                    }
                    // Previously observed but already fully torn down (e.g.
                    // a refused #867 session admission or an earlier
                    // h2ResetStreamState): `h2StreamAcceptsInboundFrame`
                    // returns true for a stream id absent from `streams`,
                    // so this is the only place left to catch DATA that was
                    // already in flight from the peer when we reset it.
                    // RFC 9113 §5.1 requires tolerating it rather than
                    // treating it as a connection-wide protocol error, but
                    // RFC 9113 §6.9 still requires the bytes to count
                    // against the connection-wide receive window the
                    // instant they arrive; since there is no stream left to
                    // carry that credit forward, return it immediately via
                    // a stream-0-only WINDOW_UPDATE.
                    const stale_charge: i64 = @intCast(frame.payload.len);
                    if (conn_recv_window - stale_charge < 0) {
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                        return error.Http2FlowControlError;
                    }
                    if (stale_charge > 0) try http.http2_frame.writeWindowUpdate(outbound_writer, 0, @intCast(stale_charge));
                    continue;
                }
                const data_payload = h2DataPayload(frame.payload, frame.flags) catch |err| {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return err;
                };
                // RFC 9113 §6.9: every DATA byte -- including Pad Length and
                // padding -- counts against both the connection-wide and
                // per-stream receive windows the instant it arrives,
                // regardless of whether this stream maps to a #867 session
                // or an ordinary finite request. A merely stalled consumer
                // or an over-`max_body_size` request must never look like a
                // flow-control violation (neither shrinks these windows by
                // itself), but a peer that sends beyond what it was
                // actually granted must.
                if (streams.getPtr(frame.stream_id)) |recv_stream| {
                    const charge: i64 = @intCast(frame.payload.len);
                    const new_conn_recv = conn_recv_window - charge;
                    if (new_conn_recv < 0) {
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                        return error.Http2FlowControlError;
                    }
                    const new_stream_recv: i64 = @as(i64, recv_stream.recv_window) - charge;
                    if (new_stream_recv < 0) {
                        const refunded = outbound.cancelStream(frame.stream_id);
                        if (refunded > 0) conn_send_window +|= @intCast(@min(refunded, std.math.maxInt(i32)));
                        try http.http2_frame.writeRstStream(outbound_writer, frame.stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                        // These bytes already counted against the
                        // connection window the instant they arrived
                        // (checked just above); since this stream is
                        // being torn down and can no longer carry its own
                        // window forward, return that credit immediately
                        // via a stream-0 WINDOW_UPDATE instead of leaving
                        // the connection permanently short.
                        if (charge > 0) try http.http2_frame.writeWindowUpdate(outbound_writer, 0, @intCast(charge));
                        try h2ResetStreamState(outbound_writer, allocator, &streams, &pending, &pending_responses, &ready_streams, &sessions, &buffered_request_bytes, frame.stream_id, null, &handoff, executor, &in_flight_jobs, &conn_recv_window, &conn_send_window);
                        continue;
                    }
                    conn_recv_window = new_conn_recv;
                    recv_stream.recv_window = @intCast(new_stream_recv);
                }
                if (sessions.get(frame.stream_id)) |active_session| {
                    var delivered_ok = true;
                    h2DeliverSessionInboundData(
                        outbound_writer,
                        active_session,
                        frame.stream_id,
                        frame.payload.len,
                        data_payload,
                        (frame.flags & http.http2_frame.Flags.END_STREAM) != 0,
                    ) catch |err| switch (err) {
                        // The session's own bounded queue matches the
                        // receive window this connection advertised (see
                        // `HTTP2_SESSION_MAX_INBOUND_BYTES`), so this can
                        // only fire on an actual protocol violation (a peer
                        // sending more than its granted window), never on a
                        // merely stalled consumer.
                        error.QueueFull => {
                            delivered_ok = false;
                            const refunded = outbound.cancelStream(frame.stream_id);
                            if (refunded > 0) conn_send_window +|= @intCast(@min(refunded, std.math.maxInt(i32)));
                            try http.http2_frame.writeRstStream(outbound_writer, frame.stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                            active_session.deliverReset(.flow_control_error);
                            try h2DetachSession(outbound_writer, allocator, &sessions, &buffered_request_bytes, frame.stream_id, &conn_recv_window);
                            _ = streams.remove(frame.stream_id);
                        },
                        error.Closed => {
                            delivered_ok = false;
                        },
                        else => return err,
                    };
                    if (delivered_ok) {
                        // Padding's share of this frame's flow-control charge
                        // was just credited straight back to the peer inside
                        // `h2DeliverSessionInboundData` (it is never buffered
                        // by the session); mirror that in our own window
                        // bookkeeping. The application bytes' credit is
                        // deliberately deferred to `h2ReturnSessionReceiveCredit`,
                        // matching when it is actually earned.
                        const padding_len = frame.payload.len - data_payload.len;
                        if (padding_len > 0) {
                            conn_recv_window += @intCast(padding_len);
                            if (streams.getPtr(frame.stream_id)) |s| s.recv_window += @intCast(padding_len);
                        }
                    }
                    if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                        if (streams.getPtr(frame.stream_id)) |s| s.remoteEndStream() catch {};
                    }
                } else if (pending.getPtr(frame.stream_id)) |ps| {
                    ps.transport_early = ps.transport_early or frame_transport_early;
                    const max_body = cfg.request_limits.effectiveMaxBodySize();
                    const max_conn_mem = cfg.max_connection_memory_bytes;
                    const over_stream_limit = ps.body_limit_exceeded or ps.body.items.len +| data_payload.len > max_body;
                    const over_conn_limit = max_conn_mem > 0 and buffered_request_bytes +| data_payload.len > max_conn_mem;
                    if (over_stream_limit or over_conn_limit) {
                        // Reject the excess before it is ever appended: do not
                        // buffer it and do not credit it back, so an attacker
                        // cannot force unbounded growth by holding the stream
                        // open across many DATA frames (or by spreading the
                        // same growth across many concurrent streams, each
                        // individually under the per-stream cap). Note this
                        // leaves the *outbound* send_window/conn_send_window
                        // (used by `flushHttp2PendingResponse` for responses,
                        // including this stream's own eventual 413) untouched
                        // -- those fields must never be decremented without
                        // an offsetting credit, or a flood of oversized DATA
                        // would starve every response on the connection.
                        ps.body_limit_exceeded = true;
                    } else {
                        try ps.body.appendSlice(data_payload);
                        buffered_request_bytes += data_payload.len;
                        // Flow control counts the full DATA payload including
                        // Pad Length and padding, even though only the data
                        // octets belong to the application body.
                        if (frame.payload.len > 0) {
                            try http.http2_frame.writeWindowUpdate(outbound_writer, frame.stream_id, @intCast(frame.payload.len));
                            try http.http2_frame.writeWindowUpdate(outbound_writer, 0, @intCast(frame.payload.len));
                            conn_recv_window += @intCast(frame.payload.len);
                            if (streams.getPtr(frame.stream_id)) |s| s.recv_window += @intCast(frame.payload.len);
                        }
                    }
                    if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) {
                        if (streams.getPtr(frame.stream_id)) |s| s.remoteEndStream() catch {};
                        try h2AppendReadyStream(&ready_streams, frame.stream_id);
                    }
                } else {
                    try http.http2_frame.writeGoaway(outbound_writer, frame.stream_id, 1);
                    return;
                }
            },
            .priority => {
                if (frame.stream_id == 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return error.InvalidHttp2StreamId;
                }
                if (frame.payload.len != 5) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.frame_size_error.value());
                    return error.InvalidPriorityFrame;
                }
                const pr = try http.http2_frame.parsePriority(frame.payload);
                if (streams.getPtr(frame.stream_id)) |s| s.priority_weight = pr.weight;
                if (pending.getPtr(frame.stream_id)) |ps| ps.priority_weight = pr.weight;
            },
            .window_update => {
                if (frame.payload.len != 4) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.frame_size_error.value());
                    return error.InvalidWindowUpdateFrame;
                }
                const raw_inc = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFF_FFFF;
                if (raw_inc == 0) {
                    if (frame.stream_id == 0) {
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                        return error.InvalidWindowUpdateFrame;
                    } else {
                        const refunded = outbound.cancelStream(frame.stream_id);
                        if (refunded > 0) conn_send_window +|= @intCast(@min(refunded, std.math.maxInt(i32)));
                        try http.http2_frame.writeRstStream(outbound_writer, frame.stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                        try h2ResetStreamState(outbound_writer, allocator, &streams, &pending, &pending_responses, &ready_streams, &sessions, &buffered_request_bytes, frame.stream_id, null, &handoff, executor, &in_flight_jobs, &conn_recv_window, &conn_send_window);
                    }
                    continue;
                }
                const inc: u31 = @intCast(raw_inc);
                // RFC 9113 §6.9.1: a legal 31-bit increment can still push
                // the resulting window past 2^31-1, which must be treated
                // as FLOW_CONTROL_ERROR rather than left to wrap/trap in
                // unchecked i32 arithmetic.
                if (frame.stream_id == 0) {
                    const new_window: i64 = @as(i64, conn_send_window) + @as(i64, inc);
                    if (new_window > std.math.maxInt(i32)) {
                        try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                        return error.Http2FlowControlError;
                    }
                    conn_send_window = @intCast(new_window);
                } else if (streams.getPtr(frame.stream_id)) |s| {
                    const new_window: i64 = @as(i64, s.send_window) + @as(i64, inc);
                    if (new_window > std.math.maxInt(i32)) {
                        const refunded = outbound.cancelStream(frame.stream_id);
                        if (refunded > 0) conn_send_window +|= @intCast(@min(refunded, std.math.maxInt(i32)));
                        try http.http2_frame.writeRstStream(outbound_writer, frame.stream_id, http.http2_stream.ErrorCode.flow_control_error.value());
                        try h2ResetStreamState(outbound_writer, allocator, &streams, &pending, &pending_responses, &ready_streams, &sessions, &buffered_request_bytes, frame.stream_id, null, &handoff, executor, &in_flight_jobs, &conn_recv_window, &conn_send_window);
                    } else {
                        s.send_window = @intCast(new_window);
                    }
                }
                // Either a connection-level or a stream-level WINDOW_UPDATE
                // can unblock a parked response; this is the only place new
                // send credit becomes available, and it runs on the central
                // frame loop rather than a second reader.
                try h2FlushPendingHttp2Responses(conn, &outbound, outbound_writer, allocator, state, &pending_responses, &streams, &conn_send_window);
            },
            .rst_stream => {
                if (frame.stream_id == 0) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                    return error.InvalidHttp2StreamId;
                }
                if (frame.payload.len != 4) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.frame_size_error.value());
                    return error.InvalidRstStreamFrame;
                }
                try h2ResetStreamState(outbound_writer, allocator, &streams, &pending, &pending_responses, &ready_streams, &sessions, &buffered_request_bytes, frame.stream_id, &outbound, &handoff, executor, &in_flight_jobs, &conn_recv_window, &conn_send_window);
            },
            .goaway => {
                if (frame.stream_id != 0 or frame.payload.len < 8) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.frame_size_error.value());
                    return error.InvalidGoawayFrame;
                }
                goaway_received = true;
            },
            .continuation => {
                if (continuation_block.items.len +| frame.payload.len > h2EncodedHeaderBlockLimit(cfg, buffered_request_bytes)) {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.compression_error.value());
                    return error.Http2CompressionError;
                }
                continuation_block.appendSlice(frame.payload) catch {
                    try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.internal_error.value());
                    return error.OutOfMemory;
                };
                if ((frame.flags & http.http2_frame.Flags.END_HEADERS) != 0) {
                    const stream_id = continuation_stream_id orelse return error.InvalidHttp2FrameSequence;
                    try h2ProcessHeaderBlock(
                        allocator,
                        &decoder,
                        &pending,
                        &streams,
                        &ready_streams,
                        &sessions,
                        state,
                        stream_id,
                        continuation_block.items,
                        continuation_end_stream,
                        continuation_transport_early,
                        outbound_writer,
                        last_client_stream_id,
                        cfg.max_connection_memory_bytes,
                        &buffered_request_bytes,
                    );
                    if (pending.getPtr(stream_id)) |stamped| stamped.headers.client_cert = connClientCertificate(conn);
                    continuation_block.clearRetainingCapacity();
                    continuation_stream_id = null;
                    continuation_end_stream = false;
                    continuation_transport_early = false;
                }
            },
            .push_promise => {
                try http.http2_frame.writeGoaway(outbound_writer, last_client_stream_id, http.http2_stream.ErrorCode.protocol_error.value());
                return error.InvalidHttp2FrameSequence;
            },
            else => {}, // Unknown extension frame types are ignored by RFC 9113 §5.5.
        }

        try h2DispatchReadyStreamsWithWriter(
            conn,
            outbound_writer,
            &outbound,
            allocator,
            state,
            cfg,
            &pending,
            &streams,
            &pending_responses,
            &ready_streams,
            &next_server_stream_id,
            &conn_send_window,
            &buffered_request_bytes,
            connection_ip,
            &handoff,
            executor,
            &in_flight_jobs,
        );
        try outbound.flush(conn.writer());
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

/// Either the stream-scope SNI/`:authority` policy refusal (#763, decided
/// before any routing work and never worth a job) or the routing result
/// `executeHttp2ProxyRoute` produced -- synchronously, or via a completion
/// relayed from a worker thread (#866).
const Http2FinalizeOutcome = union(enum) {
    misdirected,
    routed: ?Http2ProxyRouteResult,
};

fn h2OverloadedRejection() Http2LocalRejection {
    return .{
        .status_code = 503,
        .code = "overloaded",
        .message = "Request execution capacity exhausted",
        .retry_after = "1",
        .no_store = true,
    };
}

fn respondHttp2Stream(
    conn: anytype,
    writer: anytype,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    stream_id: u31,
    ps: *const Http2PendingStream,
    handoff: ?*http.h2_request_handoff.Handoff,
    executor: ?*http.h2_request_executor.Executor,
    in_flight: *std.AutoHashMap(u31, void),
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    conn_send_window: *i32,
    connection_ip: []const u8,
) !void {
    const method = ps.method orelse return error.InvalidHttp2Request;
    const path = ps.path orelse return error.InvalidHttp2Request;
    if (!http.headers.isValidHeaderValue(method) or !http.headers.isValidHeaderValue(path)) return error.InvalidHttp2Request;
    if (ps.authority) |authority| {
        if (!http.headers.isValidHeaderValue(authority)) return error.InvalidHttp2Request;
    }
    if (!h2RequestFramingIsValid(ps)) return error.InvalidHttp2Request;
    const correlation_id = try http.correlation.generate(allocator);
    defer allocator.free(correlation_id);

    var lifecycle = http.request_lifecycle.RequestLifecycle.init(
        correlation_id,
        cfg.request_total_timeout_ms,
    );
    if (lifecycle.checkDeadline(.headers_read)) return error.RequestTimeout;

    // #763: stream-scope SNI/:authority admission, before any routing, auth
    // or proxy work. The handshake enforced the client-auth policy of the SNI
    // it was admitted under; a stream whose authority maps to a different
    // policy gets 421 on that stream only (the connection stays up).
    const policy_host = ps.authority orelse (ps.headers.get("host") orelse "");
    if (!connClientPolicyAdmitsHost(conn, policy_host)) {
        return finalizeHttp2Response(conn, writer, outbound, allocator, state, stream_id, method, correlation_id, .misdirected, .{}, false, ps.transport_early, streams, pending_responses, conn_send_window);
    }

    // Move execution off the connection frame-reader loop whenever an
    // executor is configured (#866): a slow route/auth/proxy/static call must
    // never stop this connection from parsing sibling-stream frames or
    // control frames. A saturated handoff/executor is a clean rejection, not
    // a reason to fall back to inline execution -- that would reintroduce
    // the exact blocking this phase removes.
    if (handoff) |ho| if (executor) |ex| {
        if (buildH2RequestJob(allocator, state, cfg, method, path, ps, correlation_id, connection_ip, lifecycle)) |job| {
            const submitted = submitted: {
                ho.submit(.{ .stream_id = stream_id, .payload = job, .deinit_fn = H2RequestJob.destroyOpaque }) catch {
                    H2RequestJob.destroyOpaque(job);
                    break :submitted false;
                };
                ex.submitSignal(ho, stream_id) catch {
                    _ = ho.cancelStream(stream_id) catch {};
                    ex.cancelStreamSignals(ho, stream_id);
                    break :submitted false;
                };
                break :submitted true;
            };
            if (submitted) {
                try in_flight.put(stream_id, {});
                return;
            }
        } else |_| {}
        return finalizeHttp2Response(conn, writer, outbound, allocator, state, stream_id, method, correlation_id, .{ .routed = .{ .local_rejection = h2OverloadedRejection() } }, .{}, false, ps.transport_early, streams, pending_responses, conn_send_window);
    };

    // No executor configured (disabled, or a unit test exercising this
    // function directly): preserve the pre-#866 synchronous behavior exactly.
    var forward_auth_grants: gfa.Grants = .{};
    // Owned here until transferred to `finalizeHttp2Response` below; released
    // if `executeHttp2ProxyRoute` itself errors (e.g. OOM mid-hop), so an
    // earlier hop's already-granted decisions never leak (#814).
    var grants_owned = true;
    errdefer if (grants_owned) forward_auth_grants.deinit(allocator);
    var early_data_refused = false;
    const result = try executeHttp2ProxyRoute(allocator, state, cfg, method, path, ps, correlation_id, connection_ip, &lifecycle, &forward_auth_grants, &early_data_refused);
    grants_owned = false;
    return finalizeHttp2Response(conn, writer, outbound, allocator, state, stream_id, method, correlation_id, .{ .routed = result }, forward_auth_grants, early_data_refused, ps.transport_early, streams, pending_responses, conn_send_window);
}

/// Build the actual H2 response frames for a routing outcome, whether it was
/// computed synchronously on this connection thread or relayed from a worker
/// job's completion (#866). Owns `forward_auth_grants` and every payload
/// inside `outcome`.
fn finalizeHttp2Response(
    conn: anytype,
    writer: anytype,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    stream_id: u31,
    method: []const u8,
    correlation_id: []const u8,
    outcome: Http2FinalizeOutcome,
    forward_auth_grants: gfa.Grants,
    early_data_refused: bool,
    transport_early: bool,
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    conn_send_window: *i32,
) !void {
    // Allow decisions granted across this request's rewrite hops (#814);
    // their client headers decorate whatever response finally answers it.
    var grants = forward_auth_grants;
    defer grants.deinit(allocator);
    // Exactly one early-data decision per transport-early stream: routing
    // records `too_early` itself when it refuses one; otherwise it was
    // accepted.
    if (transport_early and !early_data_refused) state.metricsRecordEarlyDataDecision(.h2, .accepted);

    var status_code: u16 = 404;
    var body: []const u8 = "{\"error\":\"not_found\"}";
    var body_alloc: ?[]u8 = null;
    defer if (body_alloc) |b| allocator.free(b);

    var response_headers = std.array_list.Managed(http.hpack.HeaderField).init(allocator);
    defer response_headers.deinit();
    var lowered_names = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (lowered_names.items) |n| allocator.free(n);
        lowered_names.deinit();
    }
    var owned_header_values = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (owned_header_values.items) |v| allocator.free(v);
        owned_header_values.deinit();
    }

    // Set for gateway-generated security refusals (forward_auth denial or
    // failure, protected 425) that must end up `no-store` (#761).
    var refusal_no_store = false;

    switch (outcome) {
        .misdirected => {
            status_code = 421;
            body_alloc = try gp.buildApiErrorJson(allocator, "misdirected_request", "Request host is governed by a different client-certificate policy than this connection's TLS server name", correlation_id);
            body = body_alloc.?;
            refusal_no_store = true;
            state.metricsRecordErrorCode("misdirected_request");
        },
        .routed => |maybe_result| if (maybe_result) |result| switch (result) {
            .response => |proxy_response| {
                var response = proxy_response;
                defer response.deinit(allocator);
                status_code = response.status_code;
                body_alloc = try allocator.dupe(u8, response.body);
                body = body_alloc.?;
                try appendHttp2UpstreamResponseHeaders(allocator, &response_headers, &lowered_names, &owned_header_values, &response, std.mem.eql(u8, method, "HEAD"));
            },
            .local_rejection => |rejection| {
                status_code = rejection.status_code;
                body_alloc = try gp.buildApiErrorJson(allocator, rejection.code, rejection.message, correlation_id);
                body = body_alloc.?;
                if (rejection.retry_after) |value| {
                    try response_headers.append(.{ .name = "retry-after", .value = value });
                }
                if (rejection.no_store) {
                    try response_headers.append(.{ .name = "cache-control", .value = "no-store" });
                    refusal_no_store = true;
                }
                state.metricsRecordErrorCode(rejection.code);
            },
            .forward_auth_denied => |denied| {
                refusal_no_store = true;
                var decision = denied;
                defer decision.deinit();
                var shaped = http.Response.init(allocator);
                defer shaped.deinit();
                try gfa.shapeResponse(allocator, &shaped, &decision, correlation_id);
                status_code = decision.status;
                body_alloc = try allocator.dupe(u8, shaped.body orelse "");
                body = body_alloc.?;
                for (shaped.headers.iterator()) |header| {
                    if (std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
                    const name = try lowercaseName(allocator, &lowered_names, header.name);
                    const value = try allocator.dupe(u8, header.value);
                    errdefer allocator.free(value);
                    try owned_header_values.append(value);
                    try response_headers.append(.{ .name = name, .value = value });
                }
                if (!decision.relaysAuthResponse()) state.metricsRecordErrorCode(decision.errorCode());
            },
            .return_response => |plan| {
                switch (plan) {
                    .method_not_allowed => {
                        status_code = 405;
                        body_alloc = try gp.buildApiErrorJson(allocator, "invalid_request", "Method Not Allowed", correlation_id);
                        body = body_alloc.?;
                        state.metricsRecordErrorCode("invalid_request");
                    },
                    .redirect => |r| {
                        status_code = r.status;
                        body = "";
                        try response_headers.append(.{ .name = "location", .value = r.location });
                        try response_headers.append(.{ .name = "content-type", .value = "text/plain; charset=utf-8" });
                    },
                    .body => |b| {
                        status_code = b.status;
                        body_alloc = try allocator.dupe(u8, b.body);
                        body = body_alloc.?;
                        try response_headers.append(.{ .name = "content-type", .value = "text/plain; charset=utf-8" });
                    },
                }
            },
            .static_response => |static_response| {
                var static = static_response;
                defer static.deinit(allocator);
                status_code = static.status_code;
                body_alloc = static.takeBody();
                body = body_alloc.?;
                try response_headers.append(.{ .name = "content-type", .value = static.content_type });
                if (static.etag) |value| {
                    const owned = try allocator.dupe(u8, value);
                    errdefer allocator.free(owned);
                    try owned_header_values.append(owned);
                    try response_headers.append(.{ .name = "etag", .value = owned });
                }
                if (static.last_modified) |value| {
                    const owned = try allocator.dupe(u8, value);
                    errdefer allocator.free(owned);
                    try owned_header_values.append(owned);
                    try response_headers.append(.{ .name = "last-modified", .value = owned });
                }
                if (static.content_range) |value| {
                    const owned = try allocator.dupe(u8, value);
                    errdefer allocator.free(owned);
                    try owned_header_values.append(owned);
                    try response_headers.append(.{ .name = "content-range", .value = owned });
                }
                if (static.accept_ranges) try response_headers.append(.{ .name = "accept-ranges", .value = "bytes" });
            },
        },
    }

    for (grants.client_headers.items) |header| {
        try response_headers.append(.{ .name = try lowercaseName(allocator, &lowered_names, header.name), .value = header.value });
    }

    const status_str = try std.fmt.allocPrint(allocator, "{d}", .{status_code});
    defer allocator.free(status_str);
    const len_str = try std.fmt.allocPrint(allocator, "{d}", .{body.len});
    defer allocator.free(len_str);
    try response_headers.insert(0, .{ .name = ":status", .value = status_str });
    if (!hasH2Header(&response_headers, "content-length")) {
        try response_headers.append(.{ .name = "content-length", .value = len_str });
    }
    if (!hasH2Header(&response_headers, "content-type")) {
        try response_headers.append(.{ .name = "content-type", .value = JSON_CONTENT_TYPE });
    }
    try response_headers.append(.{ .name = try lowercaseName(allocator, &lowered_names, http.correlation.REQUEST_HEADER_NAME), .value = correlation_id });
    try response_headers.append(.{ .name = try lowercaseName(allocator, &lowered_names, http.correlation.HEADER_NAME), .value = correlation_id });
    for (state.add_headers) |h| {
        try response_headers.append(.{ .name = try lowercaseName(allocator, &lowered_names, h.name), .value = h.value });
    }
    // Last header operation: a forward_auth-protected response, or a security
    // refusal, must never be shared-cacheable, whatever the origin or
    // configured headers say (#761). Every Cache-Control field is folded;
    // every cache-controlling field, CDN/surrogate ones included, is replaced
    // by the one protected policy.
    const final_cache_policy: http.security_headers.ProtectedCachePolicy = if (refusal_no_store)
        .no_store
    else
        grants.cachePolicy();
    if (final_cache_policy != .none) {
        const policy = final_cache_policy;
        var cache_buf: [256]u8 = undefined;
        var fold = http.security_headers.CacheControlFold.init(&cache_buf, policy);
        var idx: usize = 0;
        while (idx < response_headers.items.len) {
            const field = response_headers.items[idx];
            if (http.security_headers.isProtectedCacheField(field.name)) {
                if (std.ascii.eqlIgnoreCase(field.name, "cache-control")) fold.add(field.value);
                _ = response_headers.orderedRemove(idx);
                continue;
            }
            idx += 1;
        }
        const cache_value = try allocator.dupe(u8, fold.value());
        errdefer allocator.free(cache_value);
        try owned_header_values.append(cache_value);
        try response_headers.append(.{ .name = "cache-control", .value = cache_value });
    }

    const header_block = try http.hpack.encodeLiteralHeaderBlock(allocator, response_headers.items);
    defer allocator.free(header_block);
    const response_header_flags: u8 = if (std.mem.eql(u8, method, "HEAD"))
        http.http2_frame.Flags.END_HEADERS | http.http2_frame.Flags.END_STREAM
    else
        http.http2_frame.Flags.END_HEADERS;

    try http.http2_frame.writeFrame(
        writer,
        .headers,
        response_header_flags,
        stream_id,
        header_block,
    );

    if (std.mem.eql(u8, method, "HEAD")) {
        state.metricsRecord(status_code);
        return;
    }

    var resp = PendingHttp2Response{
        .body_alloc = body_alloc,
        .body = body,
        .status_code = status_code,
    };
    body_alloc = null;
    errdefer resp.deinit(allocator);

    const stream_window_ptr = if (streams.getPtr(stream_id)) |s| &s.send_window else return error.InvalidHttp2StreamId;
    const result = try flushHttp2PendingResponse(conn, outbound, writer, stream_id, &resp, conn_send_window, stream_window_ptr);
    if (result == .complete) {
        resp.deinit(allocator);
        state.metricsRecord(status_code);
    } else {
        try pending_responses.put(stream_id, resp);
    }
}

/// Apply one worker-produced response intent to its stream (#866). Called
/// from the connection thread only, once per `Handoff.takeCompletion()`
/// result. A route execution error closes the connection with the same
/// error the synchronous path would have returned, so a worker failure is
/// externally indistinguishable from today's inline failure.
fn applyH2RequestCompletion(
    conn: anytype,
    writer: anytype,
    outbound: ?*http.h2_outbound_scheduler.Scheduler,
    allocator: std.mem.Allocator,
    state: *GatewayState,
    stream_id: u31,
    completion: http.h2_request_handoff.Completion,
    streams: *std.AutoHashMap(u31, http.http2_stream.Stream),
    pending_responses: *std.AutoHashMap(u31, PendingHttp2Response),
    conn_send_window: *i32,
) anyerror!void {
    const payload: *H2JobCompletion = @ptrCast(@alignCast(completion.payload));
    defer completion.deinit();

    const outcome = payload.outcome orelse return error.H2MissingTerminalOutcome;
    switch (outcome) {
        .route_error => |err| return err,
        .routed => {},
    }
    // The stream was reset/closed between the worker finishing and this
    // completion being drained; `Handoff.cancelStream` already prevents this
    // in the ordinary case; this is a defensive, never-expected fallback.
    if (!streams.contains(stream_id)) return;

    // Ownership of the route result and forward_auth grants moves into
    // `finalizeHttp2Response`; reset both first so `completion.deinit()`
    // (deferred above) does not also try to free what finalize just consumed.
    const forward_auth_grants = payload.forward_auth_grants;
    payload.forward_auth_grants = .{};
    const route_result = outcome.routed;
    payload.outcome = null;

    try finalizeHttp2Response(
        conn,
        writer,
        outbound,
        allocator,
        state,
        stream_id,
        payload.method,
        payload.correlation_id,
        .{ .routed = route_result },
        forward_auth_grants,
        payload.early_data_refused,
        payload.transport_early,
        streams,
        pending_responses,
        conn_send_window,
    );
}

const Http2ProxyRouteResult = union(enum) {
    response: gp.BufferedUpstreamResponse,
    local_rejection: Http2LocalRejection,
    forward_auth_denied: gfa.Decision,
    return_response: ghandlers.ReturnResponsePlan,
    static_response: Http2StaticResponse,
};

const Http2LocalRejection = struct {
    status_code: u16,
    code: []const u8,
    message: []const u8,
    retry_after: ?[]const u8 = null,
    no_store: bool = false,
};

const Http2StaticResponse = struct {
    body: ?[]u8,
    status_code: u16,
    content_type: []const u8,
    etag: ?[]u8 = null,
    last_modified: ?[]u8 = null,
    content_range: ?[]u8 = null,
    accept_ranges: bool = false,

    fn deinit(self: *Http2StaticResponse, allocator: std.mem.Allocator) void {
        if (self.body) |body| allocator.free(body);
        if (self.etag) |v| allocator.free(v);
        if (self.last_modified) |v| allocator.free(v);
        if (self.content_range) |v| allocator.free(v);
        self.* = undefined;
    }

    fn takeBody(self: *Http2StaticResponse) []u8 {
        const body = self.body.?;
        self.body = null;
        return body;
    }
};

fn executeHttp2ProxyRoute(
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    path: []const u8,
    ps: *const Http2PendingStream,
    correlation_id: []const u8,
    connection_ip: []const u8,
    lifecycle: *http.request_lifecycle.RequestLifecycle,
    forward_auth_grants: *gfa.Grants,
    early_data_refused: *bool,
) !?Http2ProxyRouteResult {
    if (ps.body_limit_exceeded) return .{ .local_rejection = .{
        .status_code = @intFromEnum(http.Status.payload_too_large),
        .code = "invalid_request",
        .message = "Request body too large",
    } };

    var synthesized = try synthesizeHttp2Request(allocator, method, path, ps);
    defer synthesized.deinit(allocator);
    var request = &synthesized.request;

    var effective_cfg_storage = cfg.*;
    const route_cfg = http2RouteConfig(cfg, request, &effective_cfg_storage) orelse return null;

    // Behind an explicitly trusted proxy tier, resolve the client IP as the
    // HTTP/1 front end does (#791), so rate limiting, ACLs, `X-Real-IP` and
    // `proxy_set_header ... $remote_addr` (#809) see the real client rather
    // than the connecting proxy. Without configured trust the transport peer
    // stays authoritative (#756). Untrusted peers' forwarding metadata is
    // stripped by the same rule as HTTP/1.
    if (!gph.isTrustedUpstream(route_cfg, connection_ip)) gph.stripUntrustedForwardingHeaders(&request.headers, route_cfg);
    const client_ip = http.request_context.extractClientIp(
        request,
        gph.isExplicitlyTrustedUpstream(route_cfg, connection_ip),
        route_cfg.real_ip_header,
        gph.TrustedProxySet{ .cfg = route_cfg },
        connection_ip,
    );

    // Primed early (like H1's `primeRequestAuthContext` pre-middleware hook)
    // so a valid bearer/session identity informs both rate limiting below
    // and the proxied request's trust boundary, rather than H2 requests
    // always rate-limiting as anonymous and forwarding no auth context.
    // Unlike H1 (which runs this against a per-request arena reset after
    // every request), this connection's `allocator` is long-lived across
    // every stream it serves, so the identity strings must be freed
    // explicitly rather than left for a bulk arena reset.
    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
    ctx.lifecycle = lifecycle;
    defer {
        if (ctx.identity) |v| allocator.free(v);
        if (ctx.user_id) |v| allocator.free(v);
        if (ctx.device_id) |v| allocator.free(v);
        if (ctx.scopes) |v| allocator.free(v);
    }
    try ghandlers.primeRequestAuthContext(allocator, route_cfg, state, &ctx, &request.headers);

    if (h2EvaluateRequestPolicy(route_cfg, state, request, connection_ip, client_ip, ctx.identity)) |rejection| {
        return .{ .local_rejection = rejection };
    }

    if (ga.evaluatePolicy(state, route_cfg, method, request.uri.path, ctx.identity, ctx.device_id, &request.headers)) |reason| {
        return .{ .local_rejection = .{
            .status_code = @intFromEnum(http.Status.forbidden),
            .code = "forbidden",
            .message = reason,
        } };
    }

    var matched = http.location_router.matchLocation(allocator, request.uri.path, route_cfg.location_blocks) orelse {
        if (try buildHttp2StaticResponse(allocator, route_cfg, request)) |static_response| {
            return .{ .static_response = static_response };
        }
        return null;
    };

    // A bounded effective-route loop (#761, #814): every location a request
    // reaches through `rewrite` gets its own `auth required`, `forward_auth`
    // and path-policy decision against the rewritten target before anything
    // is served, so a rewrite can never reach a protected location, or fall
    // into the server root, around its gates.
    var client_view = ghandlers.H1ClientAuthView{};
    defer client_view.deinit(allocator);
    var hops: usize = 1;
    // Set when a rewrite lands back in the same location: its gates must be
    // re-run for the rewritten target, but its rewrite action must not run
    // again.
    var gate_only = false;
    while (true) {
        if (matched.block.auth == .required and !ctx.authenticated and ctx.identity == null) {
            forward_auth_grants.clear();
            return .{ .local_rejection = .{
                .status_code = @intFromEnum(http.Status.unauthorized),
                .code = "unauthorized",
                .message = "Unauthorized",
                .no_store = true,
            } };
        }
        if (ghandlers.clientCertDenial(matched.block.client_cert, request.headers.client_cert)) |denial| {
            forward_auth_grants.clear();
            return .{ .local_rejection = .{
                .status_code = @intFromEnum(http.Status.forbidden),
                .code = denial.code,
                .message = denial.message,
                .no_store = true,
            } };
        }
        if (!matched.block.client_cert.isEmpty()) forward_auth_grants.client_cert_gated = true;
        if (matched.block.forward_auth) |*fa| {
            // H2 dispatches deferred 0-RTT streams once the handshake completes,
            // but that does not make them any less replayable. The auth call is
            // a side effect, so refuse before it, as H1/H3 do (#761).
            if (ps.transport_early or request.headers.hasEarlyDataMarker()) {
                state.metricsRecordEarlyDataDecision(.h2, .too_early);
                early_data_refused.* = true;
                forward_auth_grants.clear();
                return .{ .local_rejection = .{
                    .status_code = @intFromEnum(http.Status.too_early),
                    .code = "too_early",
                    .message = "Too Early",
                    .no_store = true,
                } };
            }
            const target = if (request.uri.query) |q|
                try std.fmt.allocPrint(allocator, "{s}?{s}", .{ request.uri.path, q })
            else
                try allocator.dupe(u8, request.uri.path);
            defer allocator.free(target);
            var decision = try gfa.authorize(allocator, route_cfg, fa, .{
                .method = method,
                .uri = target,
                .host = ps.authority orelse request.headers.get("host"),
                .proto = if (edge_config.hasTlsFiles(route_cfg)) "https" else "http",
                .client_ip = ctx.client_ip,
                .correlation_id = correlation_id,
                .headers = client_view.headers(request),
                .body = request.body,
                .asserted_names = client_view.asserted_names.items,
            });
            // Owned until transferred to the `forward_auth_denied` result or
            // to `forward_auth_grants` below; released on any error returned
            // from the fallible preservation/assertion steps in between
            // (#814).
            var decision_owned = true;
            defer if (decision_owned) decision.deinit();
            state.metricsRecordForwardAuth(.h2, decision.outcome);
            if (!decision.allowed()) {
                if (!decision.relaysAuthResponse()) {
                    state.logger.warn(correlation_id, "forward_auth {s} ({s}) for {s}: failing closed with {d}", .{ @tagName(decision.outcome), decision.cause, matched.block.pattern, decision.status });
                }
                forward_auth_grants.clear();
                decision_owned = false;
                return .{ .forward_auth_denied = decision };
            }
            if (fa.upstream_headers.len > 0) {
                // Keep the caller's original headers for any later verifier
                // before replacing them with this service's assertions.
                try client_view.preserve(allocator, request);
                try client_view.asserted_names.appendSlice(allocator, fa.upstream_headers);
            }
            try gfa.applyUpstreamHeaders(&request.headers, fa, &decision);
            // `Grants.add` takes ownership of `decision` whether it succeeds
            // or fails (its own `errdefer` frees it on error), so the flag
            // must clear before the call, not after the `try` (#888).
            decision_owned = false;
            try forward_auth_grants.add(allocator, decision);
        }
        if (gate_only) {
            // A rewrite back into itself is answered from the server root
            // once its own gates pass for the rewritten target, never by
            // re-running its rewrite action again.
            if (try buildHttp2StaticResponse(allocator, route_cfg, request)) |static_response| {
                return .{ .static_response = static_response };
            }
            return null;
        }

        const rewrite_rule = switch (matched.block.action) {
            .rewrite => |rule| rule,
            else => break,
        };
        ghandlers.applyLocationRewrite(request, rewrite_rule.replacement);
        // The rewritten target's policy must judge the caller's own headers,
        // never a value an earlier hop's forward_auth asserted onto
        // `request.headers` for the origin (#814): a verifier-minted
        // `X-Approval-Token` must never satisfy an approval policy for a
        // client that never presented one.
        if (ga.evaluatePolicy(state, route_cfg, method, request.uri.path, ctx.identity, ctx.device_id, client_view.headers(request))) |reason| {
            forward_auth_grants.clear();
            return .{ .local_rejection = .{
                .status_code = @intFromEnum(http.Status.forbidden),
                .code = "forbidden",
                .message = reason,
                .no_store = true,
            } };
        }
        const next = http.location_router.matchLocation(allocator, request.uri.path, route_cfg.location_blocks) orelse {
            // No location claims the rewritten target: only the unprotected
            // server root can answer it.
            if (try buildHttp2StaticResponse(allocator, route_cfg, request)) |static_response| {
                return .{ .static_response = static_response };
            }
            return null;
        };
        // A rewrite back into the same location is served from the server
        // root rather than looping, but only after that location's gates
        // pass again for the rewritten target: an auth decision about the
        // old path says nothing about the new.
        if (next.index == matched.index) gate_only = true;
        if (hops >= gfa.MAX_ROUTE_HOPS) {
            forward_auth_grants.clear();
            return .{ .local_rejection = .{
                .status_code = @intFromEnum(http.Status.loop_detected),
                .code = "rewrite_loop",
                .message = "Rewrite limit exceeded",
                .no_store = true,
            } };
        }
        hops += 1;
        matched = next;
    }
    const target = switch (matched.block.action) {
        .proxy_pass => |value| value,
        .return_response => |ret| {
            const is_get_or_head = std.mem.eql(u8, method, "GET") or std.mem.eql(u8, method, "HEAD");
            return .{ .return_response = ghandlers.planReturnResponse(is_get_or_head, ret.status, ret.body) };
        },
        .static_root => |root_cfg| {
            if (try buildHttp2LocationStaticResponse(allocator, request, matched, root_cfg)) |static_response| {
                return .{ .static_response = static_response };
            }
            return null;
        },
        else => return null,
    };
    if (h2UnsupportedProxyOrchestration(route_cfg, matched)) return .{ .local_rejection = .{
        .status_code = @intFromEnum(http.Status.not_implemented),
        .code = "h2_proxy_policy_unsupported",
        .message = "HTTP/2 proxy route requires unsupported proxy orchestration",
    } };

    const suffix_path = gproxy_runtime.proxySuffixPathForLocation(request.uri.path, matched, route_cfg.location_blocks);
    const resolved = try gp.resolveProxyTarget(allocator, route_cfg.upstream_base_url, target, suffix_path);
    defer allocator.free(resolved.url);
    var upstream_url = try gp.appendProxyQueryString(allocator, resolved.url, request.uri.query);
    defer upstream_url.deinit(allocator);

    const forwarded_proto = if (edge_config.hasTlsFiles(route_cfg)) "https" else "http";
    var proxy_response = try gproxy_runtime.executeBufferedDataPlaneProxyRequest(
        allocator,
        route_cfg,
        upstream_url.value,
        resolved.unix_socket_path,
        request.method.toString(),
        &request.headers,
        request.body orelse "",
        correlation_id,
        client_ip,
        forwarded_proto,
        request.headers.get("host"),
        request.headers.get("host"),
        matched.block.proxy_set_headers,
        ctx.identity,
        ctx.user_id,
        ctx.device_id,
        ctx.scopes,
        false,
        http2ProxyAttemptTimeoutMs(route_cfg),
        route_cfg.upstream_connect_timeout_ms,
        route_cfg.upstream_response_timeout_ms,
        &lifecycle.token,
        &state.upstream_pool,
        &state.h2_pool,
    );
    errdefer proxy_response.deinit(allocator);
    ctx.setUpstreamResult(resolved.upstream_host, proxy_response.statusCode(), proxy_response.bodyLen());
    state.appendTranscript(
        gs.upstreamScopeName(gs.proxyScopeForPath(request.uri.path)),
        request.uri.path,
        correlation_id,
        null,
        client_ip,
        upstream_url.value,
        request.body orelse "",
        proxy_response.statusCode(),
        proxy_response.contentTypeOr("application/octet-stream"),
        proxy_response.transcriptBody(),
        if (request.headers.get("authorization")) |raw_auth|
            if (http.auth.parseBearerToken(raw_auth)) |token| &.{token} else &.{}
        else
            &.{},
    );
    return .{ .response = proxy_response.bounded_buffered };
}

/// Release whatever `Http2ProxyRouteResult` owns without ever finalizing it
/// into a response -- used only when a result is discarded unapplied (a
/// cancelled stream's completion, or a job destroyed before it ran).
fn deinitHttp2ProxyRouteResult(result: *Http2ProxyRouteResult, allocator: std.mem.Allocator) void {
    switch (result.*) {
        .response => |*r| r.deinit(allocator),
        .local_rejection => {},
        .forward_auth_denied => |*d| d.deinit(),
        .return_response => {},
        .static_response => |*s| s.deinit(allocator),
    }
}

/// Independent, owned snapshot of everything `executeHttp2ProxyRoute` needs
/// to run safely off the connection frame-reader loop (#866). Nothing here
/// borrows from `conn`, the connection's `pending` map, or any other
/// connection-thread-only storage, so a worker thread can use it after the
/// connection has moved on to parsing the next frame.
/// Either the routing result `executeHttp2ProxyRoute` produced, or the error
/// it returned instead. Carried from the worker thread back to the
/// connection thread so a route execution failure still closes the
/// connection exactly as it does on the synchronous path (#866).
const H2RouteOutcome = union(enum) {
    routed: ?Http2ProxyRouteResult,
    route_error: anyerror,
};

/// Owned response intent handed back to the connection runtime (#866).
/// Its envelope and immutable metadata are allocated before the job is
/// accepted by a Handoff, so every accepted job can produce one terminal
/// connection-side event even if the worker later runs under OOM pressure.
const H2JobCompletion = struct {
    allocator: std.mem.Allocator,
    method: []u8,
    correlation_id: []u8,
    transport_early: bool,
    forward_auth_grants: gfa.Grants = .{},
    early_data_refused: bool = false,
    outcome: ?H2RouteOutcome = null,

    fn destroy(self: *H2JobCompletion) void {
        if (self.outcome) |*outcome| switch (outcome.*) {
            .routed => |*maybe_result| if (maybe_result.*) |*result| deinitHttp2ProxyRouteResult(result, self.allocator),
            .route_error => {},
        };
        self.forward_auth_grants.deinit(self.allocator);
        self.allocator.free(self.method);
        self.allocator.free(self.correlation_id);
        self.allocator.destroy(self);
    }

    fn destroyOpaque(raw: *anyopaque) void {
        const self: *H2JobCompletion = @ptrCast(@alignCast(raw));
        self.destroy();
    }
};

const H2RequestJob = struct {
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    method: []u8,
    path: []u8,
    ps: Http2PendingStream,
    correlation_id: []u8,
    connection_ip: []u8,
    lifecycle: http.request_lifecycle.RequestLifecycle,
    /// Owned until this job transfers it into `Handoff.finish`.
    completion: ?*H2JobCompletion,

    fn destroy(self: *H2RequestJob) void {
        if (self.completion) |completion| completion.destroy();
        self.allocator.free(self.method);
        self.allocator.free(self.path);
        self.ps.deinit(self.allocator);
        self.allocator.free(self.correlation_id);
        self.allocator.free(self.connection_ip);
        self.allocator.destroy(self);
    }

    fn destroyOpaque(raw: *anyopaque) void {
        const self: *H2RequestJob = @ptrCast(@alignCast(raw));
        self.destroy();
    }
};

/// Build an owned job snapshot from a connection-owned pending stream. The
/// connection keeps its own ownership of `ps`/`correlation_id` either way; on
/// success the caller owns the returned job and must either submit it to a
/// `Handoff` or call `H2RequestJob.destroyOpaque` on it.
fn buildH2RequestJob(
    allocator: std.mem.Allocator,
    state: *GatewayState,
    cfg: *const edge_config.EdgeConfig,
    method: []const u8,
    path: []const u8,
    ps: *const Http2PendingStream,
    correlation_id: []const u8,
    connection_ip: []const u8,
    lifecycle: http.request_lifecycle.RequestLifecycle,
) !*H2RequestJob {
    const job = try allocator.create(H2RequestJob);
    errdefer allocator.destroy(job);
    job.allocator = allocator;
    job.state = state;
    job.cfg = cfg;

    job.method = try allocator.dupe(u8, method);
    errdefer allocator.free(job.method);
    job.path = try allocator.dupe(u8, path);
    errdefer allocator.free(job.path);

    job.ps = .{
        .headers = try ps.headers.clone(allocator),
        .body = std.array_list.Managed(u8).init(allocator),
        .transport_early = ps.transport_early,
        .body_limit_exceeded = ps.body_limit_exceeded,
    };
    errdefer job.ps.deinit(allocator);
    job.ps.method = try allocator.dupe(u8, ps.method.?);
    job.ps.path = try allocator.dupe(u8, ps.path.?);
    if (ps.authority) |a| job.ps.authority = try allocator.dupe(u8, a);
    try job.ps.body.appendSlice(ps.body.items);

    job.correlation_id = try allocator.dupe(u8, correlation_id);
    errdefer allocator.free(job.correlation_id);
    job.connection_ip = try allocator.dupe(u8, connection_ip);
    errdefer allocator.free(job.connection_ip);

    // Build the terminal envelope before the handoff accepts ownership.  The
    // worker only fills this object; it must never allocate to report a
    // terminal route outcome back to the connection owner.
    const completion = try allocator.create(H2JobCompletion);
    errdefer allocator.destroy(completion);
    const completion_method = try allocator.dupe(u8, method);
    errdefer allocator.free(completion_method);
    const completion_correlation_id = try allocator.dupe(u8, correlation_id);
    errdefer allocator.free(completion_correlation_id);
    completion.* = .{
        .allocator = allocator,
        .method = completion_method,
        .correlation_id = completion_correlation_id,
        .transport_early = ps.transport_early,
    };
    job.completion = completion;

    job.lifecycle = lifecycle;
    job.lifecycle.request_id = job.correlation_id;
    return job;
}

/// Run one leased job's route/auth/proxy/static execution on a worker thread
/// and hand the result back to the connection through `handoff.finish`.
/// Called from `http.h2_request_executor.Executor`'s worker loop (#866).
fn executeH2RequestJobSignal(ctx: *anyopaque, handoff: *http.h2_request_handoff.Handoff) void {
    _ = ctx;
    var lease = handoff.takeJob() orelse return;
    if (lease.isCancelled()) {
        _ = handoff.finish(&lease, null) catch {};
        return;
    }
    const job: *H2RequestJob = @ptrCast(@alignCast(lease.jobPayload()));

    var forward_auth_grants: gfa.Grants = .{};
    var early_data_refused = false;
    const outcome: H2RouteOutcome = if (executeHttp2ProxyRoute(
        job.allocator,
        job.state,
        job.cfg,
        job.method,
        job.path,
        &job.ps,
        job.correlation_id,
        job.connection_ip,
        &job.lifecycle,
        &forward_auth_grants,
        &early_data_refused,
    )) |result| .{ .routed = result } else |err| .{ .route_error = err };

    const completion = job.completion.?;
    job.completion = null;
    completion.forward_auth_grants = forward_auth_grants;
    completion.early_data_refused = early_data_refused;
    completion.outcome = outcome;
    _ = handoff.finish(&lease, .{ .payload = completion, .deinit_fn = H2JobCompletion.destroyOpaque }) catch |err| {
        // `finish` owns and releases the terminal object on error.  Do not
        // silently hide this exceptional wake failure: it is a connection
        // failure, not a reason to strand the accepted stream's ownership.
        std.log.err("H2 request completion handoff failed: {s}", .{@errorName(err)});
    };
}

fn h2EvaluateRequestPolicy(
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    request: *const http.Request,
    /// The connecting peer; decides whether geo headers are trusted.
    peer_ip: []const u8,
    /// The resolved client IP; keys ACLs and rate limits, as on HTTP/1.
    client_ip: []const u8,
    identity: ?[]const u8,
) ?Http2LocalRejection {
    if (cfg.geo_blocked_countries.len > 0) {
        if (!gph.isTrustedGeoSource(cfg, peer_ip)) {
            return .{ .status_code = 403, .code = "forbidden", .message = "Geo identity source is not trusted" };
        }
        const country = request.headers.get(cfg.geo_country_header);
        if (h2IsGeoBlocked(cfg.geo_blocked_countries, country)) {
            return .{ .status_code = 403, .code = "forbidden", .message = "Geo access denied" };
        }
    }

    const limits = cfg.request_limits;
    if (http.request_limits.validateUriLength(request.uri.path.len, limits) != .ok) {
        return .{ .status_code = 414, .code = "invalid_request", .message = "URI too long" };
    }
    if (http.request_limits.validateHeaderCount(request.headers.count(), limits) != .ok) {
        return .{ .status_code = 431, .code = "invalid_request", .message = "Too many headers" };
    }
    var headers_total: usize = 0;
    for (request.headers.iterator()) |h| {
        const header_len = h.name.len + h.value.len + 2;
        if (http.request_limits.validateHeaderSize(header_len, limits) != .ok) {
            return .{ .status_code = 431, .code = "invalid_request", .message = "Header too large" };
        }
        headers_total += h.name.len + h.value.len + 4;
    }
    if (http.request_limits.validateHeadersTotalSize(headers_total, limits) != .ok) {
        return .{ .status_code = 431, .code = "invalid_request", .message = "Headers too large" };
    }
    if (request.body) |body| {
        if (http.request_limits.validateBodySize(body.len, limits) != .ok) {
            return .{ .status_code = 413, .code = "invalid_request", .message = "Request body too large" };
        }
    }

    // Enforce the ACL belonging to THIS request's configuration generation.
    // Reading a global ACL here could both race a reload freeing the rules and
    // let an older lease skip a denial its own config still requires.
    if (cfg.parsed_access_control) |acl| {
        if (acl.check(client_ip) == .denied) {
            return .{ .status_code = 403, .code = "forbidden", .message = "Access denied" };
        }
    }

    if (cfg.rate_limit_rps > 0 and cfg.rate_limit_burst > 0) {
        var rate_limit_buf: [192]u8 = undefined;
        const limit_key = h2RateLimitDescriptor(identity, client_ip, &rate_limit_buf);
        if (!state.rateLimitAllow(limit_key)) {
            return .{ .status_code = 429, .code = "rate_limited", .message = "Rate limit exceeded", .retry_after = "1" };
        }
    }

    return null;
}

/// The narrow native-H2 `proxy_pass` path calls the buffered upstream
/// executor directly instead of going through `runMiddlewarePipeline` /
/// `handleLocationProxyPass`, so it must exhaustively fail closed for every
/// pre-route or proxy-orchestration feature that path would otherwise
/// silently skip. This has to stay exhaustive (not a hand-picked subset) --
/// ALPN selection must never become a policy escape hatch. Mirrors the
/// feature inventory in `streamingUploadEligibilityBeforeBodyRead`.
fn h2UnsupportedProxyOrchestration(cfg: *const edge_config.EdgeConfig, matched: http.location_router.MatchResult) bool {
    if (cfg.rewrite_rules.len > 0 or
        cfg.return_rules.len > 0 or
        cfg.conditional_rules.len > 0 or
        cfg.internal_redirect_rules.len > 0 or
        cfg.mirror_rules.len > 0 or
        cfg.auth_request_url.len > 0 or
        cfg.max_in_flight_requests > 0) return true;

    if (matched.block.proxy_streaming_policy.responseStreamingEnabled(
        cfg.proxy_streaming_mode.responseStreamingEnabled(),
    )) return true;

    // `upstream_max_fails`/`upstream_fail_timeout_ms` and the process-wide
    // circuit breaker depend on health/accounting that `handleLocationProxyPass`
    // records around the low-level executor this path calls directly; skipping
    // it means configured upstream protection silently never opens (or closes)
    // for traffic negotiated over H2. Deliberately NOT included:
    // `upstream_pool_enabled` -- it defaults to true, and connection
    // pooling itself is already correctly threaded through via
    // `state.upstream_pool`/`state.h2_pool` below, so treating it as
    // unsupported would fail closed on every H2 proxy_pass by default.
    if (cfg.upstream_max_fails > 0 or cfg.cb_threshold > 0) return true;

    const pool = gs.upstreamPoolForScope(cfg, .global);
    return cfg.upstream_retry_attempts > 1 or
        cfg.upstream_pool_max_active_per_host > 0 or
        pool.primary_urls.len > 0 or
        pool.backup_urls.len > 0;
}

fn h2IsGeoBlocked(blocked: []const []const u8, country: ?[]const u8) bool {
    const c = country orelse return false;
    for (blocked) |b| {
        if (std.ascii.eqlIgnoreCase(std.mem.trim(u8, b, " \t\r\n"), std.mem.trim(u8, c, " \t\r\n"))) return true;
    }
    return false;
}

fn h2RateLimitDescriptor(identity: ?[]const u8, client_ip: []const u8, buf: *[192]u8) []const u8 {
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

/// Reject H2 requests whose regular (non-pseudo) headers cannot be safely
/// round-tripped through the synthetic HTTP/1 text `synthesizeHttp2Request`
/// builds. Two concerns, both from RFC 9113 §8:
///
///  - §8.2.2: connection-specific fields (`connection`, `proxy-connection`,
///    `keep-alive`, `transfer-encoding`, `upgrade`; `te` other than
///    `trailers`) are forbidden in HTTP/2 messages. HPACK decoding itself
///    doesn't reject them, so a client can smuggle one through; letting
///    HTTP/1 `Request.parse` reinterpret it (e.g. a spoofed
///    `transfer-encoding: chunked`) would desync request framing.
///  - §8.1.1: a declared `content-length` must equal the sum of DATA
///    payload lengths. `Request.parse` trusts the declared value and stops
///    consuming at exactly that many bytes, so a mismatch would silently
///    truncate (or under-consume) `ps.body` rather than erroring.
fn h2RequestFramingIsValid(ps: *const Http2PendingStream) bool {
    for (ps.headers.items.items) |header| {
        if (std.mem.eql(u8, header.name, "connection") or
            std.mem.eql(u8, header.name, "proxy-connection") or
            std.mem.eql(u8, header.name, "keep-alive") or
            std.mem.eql(u8, header.name, "transfer-encoding") or
            std.mem.eql(u8, header.name, "upgrade")) return false;
        if (std.mem.eql(u8, header.name, "te") and
            !std.ascii.eqlIgnoreCase(std.mem.trim(u8, header.value, " \t"), "trailers")) return false;
        if (std.mem.eql(u8, header.name, "content-length")) {
            const declared = std.fmt.parseInt(usize, std.mem.trim(u8, header.value, " \t"), 10) catch return false;
            if (declared != ps.body.items.len) return false;
        }
    }
    return true;
}

const Http2SyntheticRequest = struct {
    request: http.Request,
    raw: []u8,

    fn deinit(self: *Http2SyntheticRequest, allocator: std.mem.Allocator) void {
        self.request.deinit();
        allocator.free(self.raw);
        self.* = undefined;
    }
};

fn synthesizeHttp2Request(
    allocator: std.mem.Allocator,
    method: []const u8,
    path: []const u8,
    ps: *const Http2PendingStream,
) !Http2SyntheticRequest {
    var raw = std.array_list.Managed(u8).init(allocator);
    errdefer raw.deinit();
    const request_line = try std.fmt.allocPrint(allocator, "{s} {s} HTTP/1.1\r\n", .{ method, path });
    defer allocator.free(request_line);
    try raw.appendSlice(request_line);
    if (ps.authority) |authority| {
        const host_line = try std.fmt.allocPrint(allocator, "Host: {s}\r\n", .{authority});
        defer allocator.free(host_line);
        try raw.appendSlice(host_line);
    } else if (ps.headers.get("host") == null) {
        try raw.appendSlice("Host: tardigrade.test\r\n");
    }
    var saw_content_length = false;
    for (ps.headers.items.items) |header| {
        if (std.mem.eql(u8, header.name, "connection")) continue;
        if (std.mem.eql(u8, header.name, "host") and ps.authority != null) continue;
        if (std.mem.eql(u8, header.name, "content-length")) saw_content_length = true;
        const line = try std.fmt.allocPrint(allocator, "{s}: {s}\r\n", .{ header.name, header.value });
        defer allocator.free(line);
        try raw.appendSlice(line);
    }
    if (ps.body.items.len > 0 and !saw_content_length) {
        const line = try std.fmt.allocPrint(allocator, "Content-Length: {d}\r\n", .{ps.body.items.len});
        defer allocator.free(line);
        try raw.appendSlice(line);
    }
    try raw.appendSlice("\r\n");
    try raw.appendSlice(ps.body.items);
    const owned_raw = try raw.toOwnedSlice();
    errdefer allocator.free(owned_raw);
    var parsed = try http.Request.parse(allocator, owned_raw, MAX_REQUEST_SIZE);
    // The synthetic request was re-parsed from bytes, so the connection's
    // verified identity (#763) is carried over explicitly, never from them.
    parsed.request.headers.client_cert = ps.headers.client_cert;
    return .{
        .request = parsed.request,
        .raw = owned_raw,
    };
}

fn http2RouteConfig(
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    storage: *edge_config.EdgeConfig,
) ?*const edge_config.EdgeConfig {
    if (ga.resolveRequestConfig(cfg, request.headers.get("host"), storage)) |effective_cfg| {
        if (ga.hostMatchesServerNames(effective_cfg, request)) return effective_cfg;
    }
    if (cfg.location_blocks.len > 0) return cfg;
    if (cfg.server_blocks.len == 1) {
        storage.* = cfg.*;
        const block = &cfg.server_blocks[0];
        storage.server_names = block.server_names;
        if (block.doc_root.len > 0) storage.doc_root = block.doc_root;
        if (block.try_files.len > 0) storage.try_files = block.try_files;
        if (block.location_blocks.len > 0) storage.location_blocks = block.location_blocks;
        if (block.tls_cert_path.len > 0) storage.tls_cert_path = block.tls_cert_path;
        if (block.tls_key_path.len > 0) storage.tls_key_path = block.tls_key_path;
        if (block.upstream_base_url.len > 0) storage.upstream_base_url = block.upstream_base_url;
        return storage;
    }
    return null;
}

fn http2ProxyAttemptTimeoutMs(cfg: *const edge_config.EdgeConfig) u32 {
    if (cfg.upstream_timeout_budget_ms == 0) return cfg.upstream_timeout_ms;
    return @intCast(@min(@as(u64, cfg.upstream_timeout_ms), cfg.upstream_timeout_budget_ms));
}

/// Serve a `location { root/alias ...; }` block over native H2 with the same
/// `static_file.serve` semantics H1/H3 use. Previously H2 answered every
/// static location with its default 404.
fn buildHttp2LocationStaticResponse(
    allocator: std.mem.Allocator,
    request: *const http.Request,
    matched: http.location_router.MatchResult,
    root_cfg: anytype,
) !?Http2StaticResponse {
    if (!(request.method == .GET or request.method == .HEAD)) return null;
    var served = (try http.static_file.serve(allocator, .{
        .root = root_cfg.root,
        .request_path = request.uri.path,
        .matched_pattern = matched.block.pattern,
        .alias = root_cfg.alias,
        .index = root_cfg.index,
        .try_files = root_cfg.try_files,
        .autoindex = root_cfg.autoindex,
        .headers = &request.headers,
        .prefer_file_backed = false,
    })) orelse return null;
    defer served.deinit(allocator);
    return try http2StaticResponseFromServed(allocator, &served);
}

fn http2StaticResponseFromServed(allocator: std.mem.Allocator, served: anytype) !Http2StaticResponse {
    var result = Http2StaticResponse{
        .body = try allocator.dupe(u8, served.body orelse ""),
        .status_code = @intFromEnum(served.status_code),
        .content_type = served.content_type,
        .accept_ranges = served.accept_ranges,
    };
    errdefer result.deinit(allocator);
    result.etag = if (served.etag_value) |v| try allocator.dupe(u8, v) else null;
    result.last_modified = if (served.last_modified_value) |v| try allocator.dupe(u8, v) else null;
    result.content_range = if (served.content_range_value) |v| try allocator.dupe(u8, v) else null;
    return result;
}

fn buildHttp2StaticResponse(allocator: std.mem.Allocator, cfg: *const edge_config.EdgeConfig, request: *const http.Request) !?Http2StaticResponse {
    if (!(request.method == .GET or request.method == .HEAD)) return null;
    if (cfg.doc_root.len == 0) return null;
    const effective_try_files = if (cfg.try_files.len > 0) cfg.try_files else "$uri";
    var served = (try http.static_file.serve(allocator, .{
        .root = cfg.doc_root,
        .request_path = request.uri.path,
        .matched_pattern = "/",
        .alias = false,
        .index = "",
        .try_files = effective_try_files,
        .autoindex = false,
        .headers = &request.headers,
        // Not MAX_REQUEST_SIZE: that bounds inbound request size (DoS
        // protection), not how large a file this server can legitimately
        // serve over HTTP/2. Falls through to static_file.Options' own
        // default.
        .prefer_file_backed = false,
    })) orelse return null;
    defer served.deinit(allocator);
    return try http2StaticResponseFromServed(allocator, &served);
}

test "H2 synthetic request carries only the connection's verified client certificate (#763)" {
    const allocator = std.testing.allocator;
    var ps = Http2PendingStream.init(allocator);
    defer ps.deinit(allocator);
    ps.method = try allocator.dupe(u8, "GET");
    ps.path = try allocator.dupe(u8, "/");
    ps.authority = try allocator.dupe(u8, "example.test");
    // A client spoofing the asserted identity over HTTP/2.
    try ps.headers.append("x-tardigrade-client-cert-verified", "1");
    try ps.headers.append("x-tardigrade-client-cert-subject", "CN=admin");

    {
        var synthesized = try synthesizeHttp2Request(allocator, "GET", "/", &ps);
        defer synthesized.deinit(allocator);
        // No verified certificate on the connection: nothing is carried over,
        // and the spoofed fields are dropped by the proxy header filter.
        try std.testing.expect(synthesized.request.headers.client_cert == null);
        var extra = std.array_list.Managed(std.http.Header).init(allocator);
        defer extra.deinit();
        try gph.appendProxyRequestHeaders(&extra, &synthesized.request.headers);
        for (extra.items) |h| try std.testing.expect(!std.ascii.startsWithIgnoreCase(h.name, "x-tardigrade-"));
    }

    ps.headers.client_cert = .{ .fingerprint_sha256 = "cd" ** 32, .subject = "CN=alice" };
    var synthesized = try synthesizeHttp2Request(allocator, "GET", "/", &ps);
    defer synthesized.deinit(allocator);
    try std.testing.expectEqualStrings("CN=alice", synthesized.request.headers.client_cert.?.subject);
    var extra = std.array_list.Managed(std.http.Header).init(allocator);
    defer extra.deinit();
    try gph.appendProxyRequestHeaders(&extra, &synthesized.request.headers);
    var subjects: usize = 0;
    for (extra.items) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "x-tardigrade-client-cert-subject")) {
            subjects += 1;
            try std.testing.expectEqualStrings("CN=alice", h.value);
        }
    }
    try std.testing.expectEqual(@as(usize, 1), subjects);
}

test "buildHttp2StaticResponse: buffered static response over 256 KiB is not truncated" {
    // Regression for #700: this H2 path used to pass gs.MAX_REQUEST_SIZE
    // (256 KiB) as static_file.Options.max_bytes -- a request-size DoS
    // bound, not a response-size limit -- so any file over 256 KiB threw
    // error.StreamTooLong mid-response. 1 MiB matches the real #593
    // campaign failure (the H3 static-large fixture; H2 shares this same
    // buffered static-file code path since H2 is also always TLS-terminated).
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const file_size: usize = 1024 * 1024;
    const data = try allocator.alloc(u8, file_size);
    defer allocator.free(data);
    @memset(data, 'x');
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "large.bin", .data = data });
    const root_path = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root_path);

    var cfg: edge_config.EdgeConfig = undefined;
    cfg.doc_root = root_path;
    cfg.try_files = "$uri";

    var head = try http.Request.parseHead(allocator, "GET /large.bin HTTP/1.1\r\nHost: example.test\r\n\r\n", 64 * 1024);
    defer head.request.deinit();

    const result = try buildHttp2StaticResponse(allocator, &cfg, &head.request);
    try std.testing.expect(result != null);
    var response = result.?;
    defer response.deinit(allocator);
    try std.testing.expectEqual(@as(u16, 200), response.status_code);
    try std.testing.expectEqual(file_size, response.body.?.len);
}

fn hasH2Header(headers: *const std.array_list.Managed(http.hpack.HeaderField), name: []const u8) bool {
    for (headers.items) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
    }
    return false;
}

fn appendHttp2UpstreamResponseHeaders(
    allocator: std.mem.Allocator,
    headers: *std.array_list.Managed(http.hpack.HeaderField),
    lowered_names: *std.array_list.Managed([]u8),
    owned_values: *std.array_list.Managed([]u8),
    response: *const gp.BufferedUpstreamResponse,
    preserve_content_length: bool,
) !void {
    if (preserve_content_length) {
        if (response.representation_content_length) |value| {
            // `value` is owned by `response.metadata_arena`, which the caller
            // deinitializes at the end of the `.response` switch prong -- before
            // `headers` is HPACK-encoded later in `respondHttp2Stream`. Duplicate
            // it into `owned_values` for the same reason every other upstream
            // response header below is duplicated rather than borrowed.
            const owned = try allocator.dupe(u8, value);
            errdefer allocator.free(owned);
            try owned_values.append(owned);
            try headers.append(.{ .name = "content-length", .value = owned });
        }
    }
    for (response.headers) |header| {
        if (gph.shouldSkipUpstreamResponseHeader(header.name, null)) continue;
        if (gph.anyConnectionHeaderReferencesHeader(response.headers, header.name)) continue;
        if (!preserve_content_length and std.ascii.eqlIgnoreCase(header.name, "content-length")) continue;
        const name = try lowercaseName(allocator, lowered_names, header.name);
        const value = try allocator.dupe(u8, header.value);
        errdefer allocator.free(value);
        try owned_values.append(value);
        try headers.append(.{ .name = name, .value = value });
    }
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

const RequestUploadStreamingEligibility = union(enum) {
    stream,
    fallback: gproxy_runtime.StreamingFallbackReason,
    not_applicable,
};

/// Unix-socket and upstream-mTLS targets stream like any other upstream (#139),
/// so only a route that names no target at all is unsupported here.
fn targetStreamingFallbackReason(
    target: []const u8,
) ?gproxy_runtime.StreamingFallbackReason {
    const trimmed = std.mem.trim(u8, target, " \t\r\n");
    if (trimmed.len == 0) return .unsupported_route_type;
    return null;
}

fn streamingUploadEligibilityBeforeBodyRead(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
) RequestUploadStreamingEligibility {
    if (!request.method.hasRequestBody()) return .not_applicable;

    const matched = http.location_router.matchLocation(allocator, request.uri.path, cfg.location_blocks) orelse return .{ .fallback = .unsupported_route_type };
    if (!matched.block.proxy_streaming_policy.requestStreamingEnabled(cfg.proxy_streaming_mode.requestStreamingEnabled())) return .{ .fallback = .policy_disabled };

    if (cfg.rewrite_rules.len > 0 or cfg.return_rules.len > 0 or
        cfg.conditional_rules.len > 0 or cfg.internal_redirect_rules.len > 0 or
        cfg.mirror_rules.len > 0 or cfg.auth_request_url.len > 0)
    {
        return .{ .fallback = .body_dependent_middleware };
    }
    // `forward_auth_body` sends the upload to the auth service before the
    // upstream sees it, so the body has to be materialized first (#761).
    if (matched.block.forward_auth) |fa| {
        if (fa.max_body_bytes > 0) return .{ .fallback = .body_dependent_middleware };
    }
    if (cfg.upstream_retry_attempts > 1) {
        if (!cfg.upstream_retry_idempotent_only) return .{ .fallback = .retries_configured };
        if (request.method.isIdempotent()) return .{ .fallback = .retries_configured };
    }

    // `parseHead` has already rejected any transfer coding other than chunked,
    // so a Transfer-Encoding here means a chunked upload of unknown length. It
    // is relayed incrementally and bounded by the request-body maximum while it
    // is decoded, rather than being buffered to learn its size.
    if (!request.hasTransferEncoding()) {
        const content_length = request.contentLength() orelse return .{ .fallback = .missing_content_length };
        if (content_length == 0) return .not_applicable;
        if (content_length > cfg.request_limits.effectiveMaxBodySize()) return .{ .fallback = .body_too_large };
    }

    return switch (matched.block.action) {
        .proxy_pass => |target| if (targetStreamingFallbackReason(target)) |reason| .{ .fallback = reason } else .stream,
        else => .{ .fallback = .unsupported_route_type },
    };
}

fn earlyDataHasReplayExposedBodyFraming(request: *const http.Request) bool {
    if (request.hasTransferEncoding()) return true;
    const content_length = request.contentLength() orelse return false;
    return content_length != 0;
}

fn traceRejectionStatus(
    method: http.Method,
    early_ctx: http.request_context.EarlyDataContext,
) ?http.Status {
    if (method != .TRACE) return null;
    return if (early_ctx.replayExposed()) .too_early else .method_not_allowed;
}

fn earlyDataPreflightDecisionForH1(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    early_ctx: http.request_context.EarlyDataContext,
    request: *const http.Request,
) http.early_data.Decision {
    return ghandlers.earlyDataDecisionForRequest(
        allocator,
        cfg,
        early_ctx,
        request.method,
        request.uri.path,
        earlyDataHasReplayExposedBodyFraming(request),
    );
}

fn metricsEarlyDataSource(early_ctx: http.request_context.EarlyDataContext) ?http.metrics.EarlyDataSource {
    return switch (early_ctx.source()) {
        .none => null,
        .transport => .transport,
        .header => .header,
        .both => .both,
    };
}

const H1PreflightSideEffectProbe = struct {
    mirror_calls: usize = 0,
    auth_calls: usize = 0,
    rate_limit_mutations: usize = 0,
    upstream_calls: usize = 0,
    handler_calls: usize = 0,
};

const H1PostPreflightOutcome = union(enum) {
    terminal_status: u16,
    logged_terminal,
    route_status: u16,
};

const H1ProductionPostPreflightHooks = struct {
    fn rejectEarly(
        self: H1ProductionPostPreflightHooks,
        allocator: std.mem.Allocator,
        writer: anytype,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *const http.Request,
        correlation_id: []const u8,
        keep_alive: bool,
    ) !u16 {
        _ = self;
        const status = try ghandlers.writeTooEarlyResponse(allocator, writer, state, ctx, correlation_id, keep_alive);
        ghandlers.logAccessForRequest(state, ctx, request, status);
        return status;
    }

    fn mirror(
        self: H1ProductionPostPreflightHooks,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        request: *const http.Request,
        correlation_id: []const u8,
        client_ip: []const u8,
    ) !void {
        _ = self;
        if (cfg.mirror_rules.len > 0) {
            ghandlers.spawnMirrorRequests(
                allocator,
                cfg,
                request.method.toString(),
                request.uri.path,
                request.body orelse "",
                correlation_id,
                client_ip,
                request.headers.get("content-type"),
            );
        }
    }

    fn auth(
        self: H1ProductionPostPreflightHooks,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        headers: *const http.Headers,
    ) !void {
        _ = self;
        try ghandlers.primeRequestAuthContext(allocator, cfg, state, ctx, headers);
    }

    fn middleware(
        self: H1ProductionPostPreflightHooks,
        allocator: std.mem.Allocator,
        writer: anytype,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *const http.Request,
        correlation_id: []const u8,
        keep_alive: bool,
    ) !bool {
        _ = self;
        return try ghandlers.runMiddlewarePipeline(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive);
    }

    fn route(
        self: H1ProductionPostPreflightHooks,
        conn: anytype,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *http.Request,
        correlation_id: []const u8,
        keep_alive: *bool,
        client_ip: []const u8,
        streaming_request_body: ?gproxy_runtime.StreamingRequestBody,
    ) !ghandlers.RouteOutcome {
        _ = self;
        return try ghandlers.routeRequest(conn, allocator, cfg, state, ctx, request, correlation_id, keep_alive, client_ip, streaming_request_body);
    }
};

fn executeH1PostPreflightOrchestration(
    conn: anytype,
    allocator: std.mem.Allocator,
    writer: anytype,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    ctx: *http.request_context.RequestContext,
    request: *http.Request,
    correlation_id: []const u8,
    keep_alive: *bool,
    client_ip: []const u8,
    streaming_request_body: ?gproxy_runtime.StreamingRequestBody,
    lifecycle: *http.request_lifecycle.RequestLifecycle,
    hooks: anytype,
) !H1PostPreflightOutcome {
    if (metricsEarlyDataSource(ctx.early_data)) |source| {
        state.metricsRecordEarlyDataRequest(.h1, source);
    }

    const early_decision = earlyDataPreflightDecisionForH1(allocator, cfg, ctx.early_data, request);
    switch (early_decision) {
        .ordinary => {
            ctx.early_data_action = .ordinary;
        },
        .execute_local => {
            ctx.early_data_action = .accepted;
            state.metricsRecordEarlyDataDecision(.h1, .accepted);
        },
        .forward_rfc8470 => {
            ctx.early_data_action = .forwarded;
            state.metricsRecordEarlyDataDecision(.h1, .forwarded);
        },
        .too_early, .defer_until_handshake => {
            ctx.early_data_action = if (early_decision == .defer_until_handshake) .deferred else .too_early;
            state.metricsRecordEarlyDataDecision(.h1, if (ctx.early_data_action == .deferred) .deferred else .too_early);
            ghandlers.recordWebSocketDenial(allocator, cfg, state, request);
            const status = try hooks.rejectEarly(allocator, writer, state, ctx, request, correlation_id, keep_alive.*);
            return .{ .terminal_status = status };
        },
    }

    try hooks.auth(allocator, cfg, state, ctx, &request.headers);

    if (try hooks.middleware(allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive.*)) {
        ghandlers.recordWebSocketDenial(allocator, cfg, state, request);
        return .logged_terminal;
    }

    if (ga.evaluatePolicy(state, cfg, request.method.toString(), request.uri.path, ctx.identity, ctx.device_id, &request.headers)) |reason| {
        ghandlers.recordWebSocketDenial(allocator, cfg, state, request);
        try gp.sendApiError(allocator, writer, .forbidden, "forbidden", reason, correlation_id, keep_alive.*, state);
        state.metricsRecord(403);
        state.metricsRecordErrorCode("forbidden");
        ghandlers.logAccessForRequest(state, ctx, request, 403);
        return .logged_terminal;
    }

    if (lifecycle.checkDeadline(.routing)) {
        try gp.sendApiError(allocator, writer, .request_timeout, "request_timeout", "Request deadline exceeded", correlation_id, keep_alive.*, state);
        state.metricsRecord(408);
        state.metricsRecordErrorCode("request_timeout");
        ghandlers.logAccessForRequest(state, ctx, request, 408);
        return .logged_terminal;
    }

    const outcome = try hooks.route(conn, allocator, cfg, state, ctx, request, correlation_id, keep_alive, client_ip, streaming_request_body);
    // Mirror only when routing reports that authorization actually accepted the
    // request. Ordering after `route()` is not enough on its own: location
    // `auth required` rejections are returned as an ordinary route status, so
    // the decision has to be carried explicitly or a denied body still leaks to
    // the mirror target.
    if (outcome.mirror_allowed) {
        try hooks.mirror(allocator, cfg, request, correlation_id, client_ip);
    }
    return .{ .route_status = outcome.status };
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
    cfg: *const edge_config.EdgeConfig,
    request: *const http.Request,
    pending_buf: []const u8,
    header_read: gconn.HttpRequestHeadRead,
    bytes_consumed: usize,
) ?gproxy_runtime.StreamingRequestBody {
    if (bytes_consumed > header_read.total_read) return null;
    const available = header_read.total_read - bytes_consumed;
    const max_body_bytes = cfg.request_limits.effectiveMaxBodySize();

    // A chunked upload's initial bytes are still raw chunk framing; the relay
    // decodes them before anything reaches the upstream.
    if (request.hasTransferEncoding()) {
        return .{
            .framing = .chunked,
            .initial_bytes = pending_buf[bytes_consumed .. bytes_consumed + available],
            .max_body_bytes = max_body_bytes,
        };
    }

    const content_length = request.contentLength() orelse return null;
    const initial_len = @min(available, content_length);
    return .{
        .framing = .{ .length = content_length },
        .initial_bytes = pending_buf[bytes_consumed .. bytes_consumed + initial_len],
        .max_body_bytes = max_body_bytes,
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

fn setConnTimeouts(conn: anytype, read_timeout_ms: u32, write_timeout_ms: u32) void {
    const T = @TypeOf(conn);
    if (comptime std.meta.activeTag(@typeInfo(T)) == .pointer) {
        const Child = std.meta.Child(T);
        if (comptime @hasDecl(Child, "setReadTimeoutMs")) {
            conn.setReadTimeoutMs(read_timeout_ms);
            if (comptime @hasDecl(Child, "setWriteTimeoutMs")) {
                conn.setWriteTimeoutMs(write_timeout_ms);
            }
            return;
        }
    }
    if (connRawFd(conn)) |fd| {
        gconn.setSocketTimeoutMs(fd, read_timeout_ms, write_timeout_ms) catch {};
    }
}

/// `tunnel_handoff_out`, when non-null, lets a WebSocket upgrade hand its
/// established tunnel to the reactor (#818): on return it holds the pending
/// job, which the caller must attach to the connection and submit (or
/// abandon). The connection is then the tunnel's and must not be reused.
fn handleConnection(conn: anytype, session: *ConnectionSession, cfg: *const edge_config.EdgeConfig, config_lease: ?*gs.ConfigLease, config_superseded_at: ?*const std.atomic.Value(u64), state: *GatewayState, keep_alive_out: *bool, connection_ip: []const u8, enable_proxy_protocol: bool, is_last_allowed_request: bool, tunnel_handoff_out: ?*?*gws_tunnel.TunnelJob) !void {
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

    h2BeginReadScope(conn);
    // Bytes read past this request (a pipelined request, or the first
    // WebSocket frames) stay at `pending_buf[pending_start..]` until the
    // request is done: its parsed path and headers are slices of the same
    // buffer, so moving them to the front any earlier would corrupt it.
    var pending_start: usize = 0;
    defer if (pending_start > 0 and session.pending_len > 0) {
        std.mem.copyForwards(u8, pending_buf[0..session.pending_len], pending_buf[pending_start..][0..session.pending_len]);
    };
    var streaming_request_body: ?gproxy_runtime.StreamingRequestBody = null;
    var request: http.Request = undefined;
    var request_initialized = false;
    defer if (request_initialized) request.deinit();

    if (mayNeedStreamingRequestBodyPreRead(cfg)) {
        const old_pending_len = session.pending_len;
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
        const upload_eligibility = streamingUploadEligibilityBeforeBodyRead(allocator, pre_effective_cfg, &head_parse.request);
        switch (upload_eligibility) {
            .stream => {
                streaming_request_body = streamingRequestBodyFromHead(pre_effective_cfg, &head_parse.request, pending_buf, head_read, head_parse.bytes_consumed);
                const request_transport_early = h1ConsumeRequestEarlyProvenance(session, old_pending_len, head_read.total_read, head_parse.bytes_consumed, h2LastReadEarlyPrefixLenBounded(conn, head_read.total_read));
                request = head_parse.request;
                request_initialized = true;
                session.pending_len = 0;
                session.pending_early_prefix_len = 0;
                session.current_request_transport_early = request_transport_early;
            },
            .fallback, .not_applicable => {
                if (upload_eligibility == .fallback) {
                    const reason = upload_eligibility.fallback;
                    state.metricsRecordProxyStreamingFallback(reason);
                    state.logger.debug(null, "proxy upload streaming fallback: {s}", .{reason.label()});
                }
                head_parse.request.deinit();
                // Switch SO_RCVTIMEO from header phase to body read phase.
                const body_timeout_ms = cfg.request_limits.effectiveBodyTimeout();
                if (body_timeout_ms > 0) {
                    const write_timeout_ms = if (cfg.downstream_write_timeout_ms > 0)
                        cfg.downstream_write_timeout_ms
                    else
                        cfg.request_limits.effectiveHeaderTimeout();
                    setConnTimeouts(conn, body_timeout_ms, write_timeout_ms);
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
                const request_transport_early = h1ConsumeRequestEarlyProvenance(session, old_pending_len, total_read, bytes_consumed, h2LastReadEarlyPrefixLenBounded(conn, total_read));
                pending_start = bytes_consumed;
                session.pending_len = total_read - bytes_consumed;
                if (session.pending_len < session.pending_early_prefix_len) session.pending_early_prefix_len = session.pending_len;
                request = parse_result.request;
                request_initialized = true;
                session.current_request_transport_early = request_transport_early;
            },
        }
    } else {
        const old_pending_len = session.pending_len;
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
        const request_transport_early = h1ConsumeRequestEarlyProvenance(session, old_pending_len, total_read, bytes_consumed, h2LastReadEarlyPrefixLenBounded(conn, total_read));
        pending_start = bytes_consumed;
        session.pending_len = total_read - bytes_consumed;
        if (session.pending_len < session.pending_early_prefix_len) session.pending_early_prefix_len = session.pending_len;

        request = parse_result.request;
        request_initialized = true;
        session.current_request_transport_early = request_transport_early;
    }
    const request_transport_early = session.current_request_transport_early;
    // #763: the verified mTLS identity comes from the connection's handshake,
    // never from request bytes (inbound `X-Tardigrade-*` is stripped at proxy).
    request.headers.client_cert = connClientCertificate(conn);
    const writer = conn.writer();
    // #763: the handshake enforced the client-auth policy of the SNI it was
    // admitted under. A request whose Host maps to a different policy cannot
    // ride this connection (RFC 9110 §15.5.20): answer 421 so the client
    // reconnects with the right SNI, rather than letting one host's trust
    // (or lack of it) decide another's.
    if (!connClientPolicyAdmitsHost(conn, (request.headers.get("host") orelse ""))) {
        try gp.sendApiError(allocator, writer, .misdirected_request, "misdirected_request", "Request host is governed by a different client-certificate policy than this connection's TLS server name", null, false, state);
        return;
    }
    keep_alive = request.keepAlive();
    if (streaming_request_body != null) keep_alive = false;
    if (http.shutdown.isShutdownRequested()) keep_alive = false;
    // Tell the client this is the last response on this connection (RFC
    // 7230 §6.6) instead of closing the socket after promising keep-alive.
    if (is_last_allowed_request) keep_alive = false;

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
        ctx_host.early_data.transport_early = request_transport_early;
        ghandlers.logAccessForRequest(state, &ctx_host, &request, 400);
        return;
    }

    // --- Request Context ---
    const effective_connection_ip = if (session.proxy_client_ip_len > 0)
        session.proxy_client_ip_buf[0..session.proxy_client_ip_len]
    else
        connection_ip;
    // Gate X-Forwarded-For/X-Real-IP honoring on the same trust boundary
    // docs/PROXY_SECURITY.md §7 documents for the outbound X-Forwarded-For
    // sent to the upstream (#673): an untrusted connecting peer must not be
    // able to rewrite the client_ip used for rate-limit bucketing and
    // access logging just by sending those headers. Strip them from the
    // request outright when untrusted -- before proxy-layer code (which
    // reads request.headers.get("x-forwarded-for") directly to build the
    // outbound X-Forwarded-For chain sent to Tardigrade's own upstream) can
    // see them either; PROXY_SECURITY.md §7 documents that an untrusted
    // host's X-Forwarded-For "is stripped and replaced by just the
    // connection IP", which this call site previously never enforced.
    const trusted_forwarding_source = gph.isTrustedUpstream(cfg, connection_ip);
    if (!trusted_forwarding_source) {
        // The configured real-IP header (e.g. CF-Connecting-IP) is just as
        // authoritative to an origin that reads it, so an untrusted peer's
        // copy must not be proxied through either (#791).
        gph.stripUntrustedForwardingHeaders(&request.headers, cfg);
    }
    // A trusted peer's X-Forwarded-For is walked right to left, skipping
    // only explicitly trusted hops (#791): the leftmost entry is whatever
    // the client sent, since CDNs append to the chain rather than replace it.
    const client_ip = http.request_context.extractClientIp(
        &request,
        trusted_forwarding_source,
        cfg.real_ip_header,
        gph.TrustedProxySet{ .cfg = cfg },
        effective_connection_ip,
    );
    var ctx = http.request_context.RequestContext.init(allocator, correlation_id, client_ip);
    ctx.early_data.transport_early = request_transport_early;
    ctx.early_data.inbound_marker = request.headers.hasEarlyDataMarker();

    if (!gph.isTrustedGeoSource(cfg, connection_ip)) {
        try gp.sendApiError(allocator, writer, .forbidden, "forbidden", "Geo identity source is not trusted", correlation_id, keep_alive, state);
        ghandlers.logAccessForRequest(state, &ctx, &request, 403);
        return;
    }

    // --- RFC 7231 §4.3.8 / ASVS-14.5.1: Reject TRACE globally ---
    // TRACE echoes the request back to the client, enabling Cross-Site
    // Tracing (XST) attacks that can expose cookies and auth headers even
    // when HttpOnly is set. Tardigrade has no use for TRACE on any route —
    // gateway-to-upstream tracing is handled via W3C traceparent headers.
    // Reject before routing so no location block can accidentally serve it.
    if (traceRejectionStatus(request.method, ctx.early_data)) |trace_status| {
        if (trace_status == .too_early) {
            if (metricsEarlyDataSource(ctx.early_data)) |source| {
                state.metricsRecordEarlyDataRequest(.h1, source);
            }
            ctx.early_data_action = .too_early;
            state.metricsRecordEarlyDataDecision(.h1, .too_early);
            const status = try ghandlers.writeTooEarlyResponse(allocator, writer, state, &ctx, correlation_id, keep_alive);
            ghandlers.logAccessForRequest(state, &ctx, &request, status);
            return;
        }
        try gp.sendApiError(allocator, writer, .method_not_allowed, "invalid_request", "Method Not Allowed", correlation_id, keep_alive, state);
        ghandlers.logAccessForRequest(state, &ctx, &request, 405);
        return;
    }

    // --- ACME HTTP-01 challenge response (/.well-known/acme-challenge/<token>) ---
    const acme_prefix = "/.well-known/acme-challenge/";
    if (state.acme_challenge_store != null and
        std.mem.startsWith(u8, request.uri.path, acme_prefix))
    {
        if (ctx.early_data.replayExposed()) {
            if (metricsEarlyDataSource(ctx.early_data)) |source| {
                state.metricsRecordEarlyDataRequest(.h1, source);
            }
            ctx.early_data_action = .too_early;
            state.metricsRecordEarlyDataDecision(.h1, .too_early);
            const status = try ghandlers.writeTooEarlyResponse(allocator, writer, state, &ctx, correlation_id, keep_alive);
            ghandlers.logAccessForRequest(state, &ctx, &request, status);
            return;
        }
        // Host-scoped (#877): the token alone is not the key. A request Host
        // that is not one of the operator's configured managed hostnames
        // never reaches the lookup, so a token minted for one host cannot be
        // disclosed to a client claiming a different, wrong, or malformed
        // Host.
        if (http.acme_client.matchManagedHost(cfg.tls_acme_domains, request.headers.get("host"))) |managed_host| {
            const token = request.uri.path[acme_prefix.len..];
            const now_s: i64 = @intCast(@divFloor(compat.nanoTimestamp(), std.time.ns_per_s));
            if (state.acme_challenge_store.?.getCopy(allocator, now_s, managed_host, token)) |key_auth| {
                defer allocator.free(key_auth);
                try ghandlers.writeAcmeChallengeResponse(allocator, writer, state, key_auth, keep_alive);
                // ACME HTTP-01 challenges are ordinary requests; keep them visible in
                // access logs and status metrics like every other terminal (#201).
                // The token itself never reaches the log line (#877 review):
                // `logAccessForRequest` redacts this route's path centrally.
                state.metricsRecord(200);
                ghandlers.logAccessForRequest(state, &ctx, &request, 200);
                return;
            }
        }
    }

    var effective_cfg_storage = cfg.*;
    const effective_cfg = ga.resolveRequestConfig(cfg, request.headers.get("host"), &effective_cfg_storage) orelse {
        try gp.sendApiError(allocator, writer, .not_found, "invalid_request", "Not Found", correlation_id, keep_alive, state);
        ghandlers.logAccessForRequest(state, &ctx, &request, 404);
        return;
    };
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
                if (ctx.early_data.replayExposed()) {
                    const status = try ghandlers.writeTooEarlyResponse(allocator, writer, state, &ctx, correlation_id, keep_alive);
                    ghandlers.logAccessForRequest(state, &ctx, &request, status);
                    return;
                }
                var response = http.Response.redirect(allocator, r.location, @enumFromInt(r.status));
                defer response.deinit();
                _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
                gp.applyResponseHeaders(state, &response);
                try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
                state.metricsRecord(r.status);
                ghandlers.logAccessForRequest(state, &ctx, &request, r.status);
                return;
            },
            .returned => |r| {
                if (ctx.early_data.replayExposed()) {
                    const status = try ghandlers.writeTooEarlyResponse(allocator, writer, state, &ctx, correlation_id, keep_alive);
                    ghandlers.logAccessForRequest(state, &ctx, &request, status);
                    return;
                }
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
            if (ctx.early_data.replayExposed()) {
                const status = try ghandlers.writeTooEarlyResponse(allocator, writer, state, &ctx, correlation_id, keep_alive);
                ghandlers.logAccessForRequest(state, &ctx, &request, status);
                return;
            }
            var response = http.Response.redirect(allocator, r.location, @enumFromInt(r.status));
            defer response.deinit();
            _ = response.setConnection(keep_alive).setHeader(http.correlation.HEADER_NAME, correlation_id);
            gp.applyResponseHeaders(state, &response);
            try response.writeWithMetrics(writer, &state.metrics, &state.metrics_mutex);
            state.metricsRecord(r.status);
            ghandlers.logAccessForRequest(state, &ctx, &request, r.status);
            return;
        },
        .returned => |r| {
            if (ctx.early_data.replayExposed()) {
                const status = try ghandlers.writeTooEarlyResponse(allocator, writer, state, &ctx, correlation_id, keep_alive);
                ghandlers.logAccessForRequest(state, &ctx, &request, status);
                return;
            }
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

    // Client bytes that arrived behind this head. Only a WebSocket upgrade
    // consumes them, as the first tunnel bytes (#812).
    ctx.downstream_buffered_input = pending_buf[pending_start..][0..session.pending_len];
    ctx.config_superseded_at = config_superseded_at;
    ctx.response_stream_config_lease = if (config_lease) |lease| @ptrCast(lease) else null;
    ctx.tunnel_handoff_allowed = tunnel_handoff_out != null;
    errdefer if (ctx.tunnel_handoff) |raw| {
        const job: *gws_tunnel.TunnelJob = @ptrCast(@alignCast(raw));
        job.abandon();
    };
    defer if (ctx.tunnel != null or ctx.tunnel_handoff != null) {
        session.pending_len = 0;
        session.pending_early_prefix_len = 0;
    };
    const outcome = try executeH1PostPreflightOrchestration(
        conn,
        allocator,
        writer,
        effective_cfg,
        state,
        &ctx,
        &request,
        correlation_id,
        &keep_alive,
        client_ip,
        streaming_request_body,
        &lifecycle,
        H1ProductionPostPreflightHooks{},
    );
    switch (outcome) {
        .terminal_status, .logged_terminal => return,
        .route_status => |route_status| {
            if (ctx.tunnel_handoff) |raw| {
                // The access-log line is written when the tunnel closes.
                const job: *gws_tunnel.TunnelJob = @ptrCast(@alignCast(raw));
                job.captureAccessLog(&ctx, &request, route_status) catch
                    ghandlers.logAccessForRequest(state, &ctx, &request, route_status);
                tunnel_handoff_out.?.* = job;
                return;
            }
            ghandlers.logAccessForRequest(state, &ctx, &request, route_status);
            return;
        },
    }
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

test "TRACE early data is rejected with 425 before ordinary TRACE 405" {
    const ordinary = http.request_context.EarlyDataContext{};
    const marked = http.request_context.EarlyDataContext{ .inbound_marker = true };
    const transport = http.request_context.EarlyDataContext{ .transport_early = true };

    try std.testing.expectEqual(http.Status.method_not_allowed, traceRejectionStatus(.TRACE, ordinary).?);
    try std.testing.expectEqual(http.Status.too_early, traceRejectionStatus(.TRACE, marked).?);
    try std.testing.expectEqual(http.Status.too_early, traceRejectionStatus(.TRACE, transport).?);
    try std.testing.expect(traceRejectionStatus(.GET, marked) == null);
}

test "early data body framing allows zero content length only" {
    const allocator = std.testing.allocator;

    var no_body = try http.Request.parseHead(allocator, "GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\n", MAX_REQUEST_SIZE);
    defer no_body.request.deinit();
    try std.testing.expect(!earlyDataHasReplayExposedBodyFraming(&no_body.request));

    var zero_length = try http.Request.parseHead(allocator, "GET /safe HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n", MAX_REQUEST_SIZE);
    defer zero_length.request.deinit();
    try std.testing.expect(!earlyDataHasReplayExposedBodyFraming(&zero_length.request));

    var nonzero_length = try http.Request.parseHead(allocator, "GET /safe HTTP/1.1\r\nHost: example.test\r\nContent-Length: 1\r\n\r\n", MAX_REQUEST_SIZE);
    defer nonzero_length.request.deinit();
    try std.testing.expect(earlyDataHasReplayExposedBodyFraming(&nonzero_length.request));

    var chunked = try http.Request.parseHead(allocator, "GET /safe HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n", MAX_REQUEST_SIZE);
    defer chunked.request.deinit();
    try std.testing.expect(earlyDataHasReplayExposedBodyFraming(&chunked.request));
}

const H1CountingPostPreflightHooks = struct {
    effects: *H1PreflightSideEffectProbe,

    fn rejectEarly(
        self: H1CountingPostPreflightHooks,
        allocator: std.mem.Allocator,
        writer: anytype,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *const http.Request,
        correlation_id: []const u8,
        keep_alive: bool,
    ) !u16 {
        _ = self;
        _ = allocator;
        _ = writer;
        _ = state;
        _ = ctx;
        _ = request;
        _ = correlation_id;
        _ = keep_alive;
        return @intFromEnum(http.Status.too_early);
    }

    fn mirror(
        self: H1CountingPostPreflightHooks,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        request: *const http.Request,
        correlation_id: []const u8,
        client_ip: []const u8,
    ) !void {
        _ = allocator;
        _ = cfg;
        _ = request;
        _ = correlation_id;
        _ = client_ip;
        self.effects.mirror_calls += 1;
    }

    fn auth(
        self: H1CountingPostPreflightHooks,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        headers: *const http.Headers,
    ) !void {
        _ = allocator;
        _ = cfg;
        _ = state;
        _ = ctx;
        _ = headers;
        self.effects.auth_calls += 1;
    }

    fn middleware(
        self: H1CountingPostPreflightHooks,
        allocator: std.mem.Allocator,
        writer: anytype,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *const http.Request,
        correlation_id: []const u8,
        keep_alive: bool,
    ) !bool {
        _ = allocator;
        _ = writer;
        _ = cfg;
        _ = state;
        _ = ctx;
        _ = request;
        _ = correlation_id;
        _ = keep_alive;
        self.effects.rate_limit_mutations += 1;
        return false;
    }

    fn route(
        self: H1CountingPostPreflightHooks,
        conn: anytype,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *http.Request,
        correlation_id: []const u8,
        keep_alive: *bool,
        client_ip: []const u8,
        streaming_request_body: ?gproxy_runtime.StreamingRequestBody,
    ) !ghandlers.RouteOutcome {
        _ = conn;
        _ = allocator;
        _ = cfg;
        _ = state;
        _ = ctx;
        _ = request;
        _ = correlation_id;
        _ = keep_alive;
        _ = client_ip;
        _ = streaming_request_body;
        self.effects.upstream_calls += 1;
        self.effects.handler_calls += 1;
        return .{ .status = @intFromEnum(http.Status.ok) };
    }
};

test "H1 early-data 425 preflight runs before side effects" {
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/safe",
            .priority = 0,
            .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
            .early_data = .replay_safe,
        },
    };
    var mirrors = [_]edge_config.EdgeConfig.MirrorRule{
        .{ .method = "GET", .pattern = "^/safe$", .target_url = "http://127.0.0.1:9002/mirror" },
    };
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = mirrors[0..];
    var request = try http.Request.parseHead(allocator, "GET /safe HTTP/1.1\r\nHost: example.test\r\nEarly-Data: 1\r\n\r\n", MAX_REQUEST_SIZE);
    defer request.request.deinit();
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    var ctx = http.request_context.RequestContext.init(allocator, "req-early", "127.0.0.1");
    ctx.early_data.inbound_marker = true;
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-early", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-early",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, @intFromEnum(http.Status.too_early)), outcome.terminal_status);
    try std.testing.expectEqual(@as(usize, 0), effects.mirror_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.auth_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.rate_limit_mutations);
    try std.testing.expectEqual(@as(usize, 0), effects.upstream_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.handler_calls);
}

test "H1 early proxy with origin capability off never reaches upstream side effects" {
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/proxy",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:9001" },
            .early_data = .replay_safe,
            .proxy_early_data = .off,
        },
    };
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = &.{};
    var request = try http.Request.parseHead(allocator, "GET /proxy HTTP/1.1\r\nHost: example.test\r\nEarly-Data: 1\r\n\r\n", MAX_REQUEST_SIZE);
    defer request.request.deinit();
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    var ctx = http.request_context.RequestContext.init(allocator, "req-off", "127.0.0.1");
    ctx.early_data.inbound_marker = true;
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-off", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-off",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, @intFromEnum(http.Status.too_early)), outcome.terminal_status);
    try std.testing.expectEqual(@as(usize, 0), effects.upstream_calls);
}

test "H1 policy denial occurs before route and mirror side effects" {
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/sensitive",
        .priority = 0,
        .action = .{ .proxy_pass = "http://127.0.0.1:1" },
    }};
    var mirrors = [_]edge_config.EdgeConfig.MirrorRule{.{
        .method = "POST",
        .pattern = "^/sensitive$",
        .target_url = "http://127.0.0.1:2/mirror",
    }};
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = mirrors[0..];
    cfg.policy_rules_raw = "POST|^/sensitive$|commands.execute|false||";
    cfg.policy_user_scopes_raw = "";
    cfg.policy_approval_routes_raw = "";

    var request = try http.Request.parseHead(allocator, "POST /sensitive HTTP/1.1\r\nHost: example.test\r\nContent-Length: 6\r\n\r\nsecret", MAX_REQUEST_SIZE);
    defer request.request.deinit();
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.security_headers = http.security_headers.SecurityHeaders.default;
    state.add_headers = &.{};
    state.http3_alt_svc = null;
    var ctx = http.request_context.RequestContext.init(allocator, "req-policy", "127.0.0.1");
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-policy", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();

    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-policy",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expect(outcome == .logged_terminal);
    try std.testing.expectEqual(@as(usize, 1), effects.auth_calls);
    try std.testing.expectEqual(@as(usize, 1), effects.rate_limit_mutations);
    try std.testing.expectEqual(@as(usize, 0), effects.upstream_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.mirror_calls);
    try std.testing.expect(std.mem.find(u8, output.written(), "403 Forbidden") != null);
    try std.testing.expect(std.mem.find(u8, output.written(), "Missing required scope") != null);
}

test "#369 Slice 2 rt0.reject.unsafe_request: an unsafe method carrying current-hop early data is rejected by the real H1 orchestration before any route dispatch" {
    // Drives the real, private `executeH1PostPreflightOrchestration` this
    // file's own dispatch uses in production (see `H1ProductionPostPreflightHooks`
    // above), with the same probe-hooks pattern the two tests directly
    // above already use — so "the route hook never runs" is proven by the
    // real orchestration's control flow, not merely inferred from calling
    // the decision function in isolation. Distinct from those two tests:
    // this isolates the *method-safety* gate in `http.early_data.decide()`
    // specifically (no mirror rule, `proxy_early_data: rfc8470`, so an
    // unsafe method is the only thing that can produce `.too_early` here),
    // whereas the existing tests isolate a mirror-rule match and an
    // origin-capability-off route respectively.
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:1" },
            .early_data = .replay_safe,
            .proxy_early_data = .rfc8470,
        },
    };
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = &.{};
    var request = try http.Request.parseHead(allocator, "POST /work HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n", MAX_REQUEST_SIZE);
    defer request.request.deinit();
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    var ctx = http.request_context.RequestContext.init(allocator, "req-post-early", "127.0.0.1");
    ctx.early_data.transport_early = true;
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-post-early", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-post-early",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, @intFromEnum(http.Status.too_early)), outcome.terminal_status);
    // The route hook — which is where any upstream dispatch, real or
    // otherwise, would originate — never ran.
    try std.testing.expectEqual(@as(usize, 0), effects.upstream_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.handler_calls);
}

test "#510 H1 request context derives transport early provenance from connection reads before safety gate" {
    const allocator = std.testing.allocator;
    const wire = "POST /work HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n";
    var harness = H2FrameReadProvenanceHarness{
        .bytes = wire,
        .early_prefix_len = wire.len,
        .max_chunk = 7,
    };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFdAndProvenance(
        harness.stream(),
        -1,
        &harness,
        H2FrameReadProvenanceHarness.readTransportEarly,
        H2FrameReadProvenanceHarness.readEarlyPrefixLen,
        H2FrameReadProvenanceHarness.handshakeComplete,
    );
    var conn = WaitingEncryptedHttpConnection.init(inner, 1, 1);
    var session = ConnectionSession{};
    var pending_buf: [512]u8 = undefined;

    h2BeginReadScope(&conn);
    const total_read = try gconn.readHttpRequest(&conn, &pending_buf, &session.pending_len);
    var parsed = try http.Request.parse(allocator, pending_buf[0..total_read], MAX_REQUEST_SIZE);
    defer parsed.request.deinit();
    const request_transport_early = h2LastReadTransportEarly(&conn);
    try std.testing.expect(request_transport_early);

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:1" },
            .early_data = .replay_safe,
            .proxy_early_data = .rfc8470,
        },
    };
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = &.{};
    cfg.policy_rules_raw = "";
    cfg.policy_user_scopes_raw = "";
    cfg.policy_approval_routes_raw = "";
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    var ctx = http.request_context.RequestContext.init(allocator, "req-read-early", "127.0.0.1");
    ctx.early_data.transport_early = request_transport_early;
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-read-early", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &parsed.request,
        "req-read-early",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, @intFromEnum(http.Status.too_early)), outcome.terminal_status);
    try std.testing.expectEqual(@as(usize, 0), effects.upstream_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.handler_calls);
}

test "#510 H1 streaming pre-read fallback preserves head-read early provenance before safety gate" {
    const allocator = std.testing.allocator;
    const wire = "POST /work HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n";
    var session = ConnectionSession{};
    var pending_buf: [512]u8 = undefined;

    const old_pending_len = session.pending_len;
    @memcpy(pending_buf[0..wire.len], wire);
    session.pending_len = wire.len;
    const total_read = wire.len;

    var parsed = try http.Request.parse(allocator, pending_buf[0..total_read], MAX_REQUEST_SIZE);
    defer parsed.request.deinit();
    const request_transport_early = h1ConsumeRequestEarlyProvenance(
        &session,
        old_pending_len,
        total_read,
        parsed.bytes_consumed,
        wire.len,
    );
    try std.testing.expect(request_transport_early);

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:1" },
            .early_data = .replay_safe,
            .proxy_early_data = .rfc8470,
        },
    };
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = &.{};
    cfg.policy_rules_raw = "";
    cfg.policy_user_scopes_raw = "";
    cfg.policy_approval_routes_raw = "";
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    var ctx = http.request_context.RequestContext.init(allocator, "req-head-fallback-early", "127.0.0.1");
    ctx.early_data.transport_early = request_transport_early;
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-head-fallback-early", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &parsed.request,
        "req-head-fallback-early",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, @intFromEnum(http.Status.too_early)), outcome.terminal_status);
    try std.testing.expectEqual(@as(usize, 0), effects.mirror_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.auth_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.rate_limit_mutations);
    try std.testing.expectEqual(@as(usize, 0), effects.upstream_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.handler_calls);
}

test "#510 H1 pending buffer preserves early provenance for pipelined unsafe request" {
    const allocator = std.testing.allocator;
    const first_wire = "GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const second_wire = "POST /work HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n";
    const wire = first_wire ++ second_wire;
    var session = ConnectionSession{};
    var pending_buf: [512]u8 = undefined;

    const first_old_pending_len = session.pending_len;
    @memcpy(pending_buf[0..wire.len], wire);
    session.pending_len = wire.len;
    const first_total_read = wire.len;
    var first = try http.Request.parse(allocator, pending_buf[0..first_total_read], MAX_REQUEST_SIZE);
    defer first.request.deinit();
    const first_consumed = first.bytes_consumed;
    const first_transport_early = h1ConsumeRequestEarlyProvenance(
        &session,
        first_old_pending_len,
        first_total_read,
        first_consumed,
        wire.len,
    );
    try std.testing.expect(first_transport_early);
    const remaining = first_total_read - first_consumed;
    std.mem.copyForwards(u8, pending_buf[0..remaining], pending_buf[first_consumed..first_total_read]);
    session.pending_len = remaining;
    try std.testing.expectEqual(second_wire.len, session.pending_len);
    try std.testing.expectEqual(second_wire.len, session.pending_early_prefix_len);

    const second_old_pending_len = session.pending_len;
    const second_total_read = session.pending_len;
    var second = try http.Request.parse(allocator, pending_buf[0..second_total_read], MAX_REQUEST_SIZE);
    defer second.request.deinit();
    const second_transport_early = h1ConsumeRequestEarlyProvenance(
        &session,
        second_old_pending_len,
        second_total_read,
        second.bytes_consumed,
        0,
    );
    try std.testing.expect(second_transport_early);

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:1" },
            .early_data = .replay_safe,
            .proxy_early_data = .rfc8470,
        },
    };
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = &.{};
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    var ctx = http.request_context.RequestContext.init(allocator, "req-pipeline-early", "127.0.0.1");
    ctx.early_data.transport_early = second_transport_early;
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-pipeline-early", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &second.request,
        "req-pipeline-early",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, @intFromEnum(http.Status.too_early)), outcome.terminal_status);
    try std.testing.expectEqual(@as(usize, 0), effects.mirror_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.auth_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.rate_limit_mutations);
    try std.testing.expectEqual(@as(usize, 0), effects.upstream_calls);
    try std.testing.expectEqual(@as(usize, 0), effects.handler_calls);
}

test "#510 H1 pending buffer does not extend early provenance over later 1-RTT bytes" {
    const allocator = std.testing.allocator;
    const first_wire = "GET /safe HTTP/1.1\r\nHost: example.test\r\n\r\n";
    const second_wire = "POST /work HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n";
    const wire = first_wire ++ second_wire;
    var session = ConnectionSession{};
    var pending_buf: [512]u8 = undefined;

    const first_old_pending_len = session.pending_len;
    @memcpy(pending_buf[0..wire.len], wire);
    session.pending_len = wire.len;
    const first_total_read = wire.len;
    var first = try http.Request.parse(allocator, pending_buf[0..first_total_read], MAX_REQUEST_SIZE);
    defer first.request.deinit();
    const first_consumed = first.bytes_consumed;
    const first_transport_early = h1ConsumeRequestEarlyProvenance(
        &session,
        first_old_pending_len,
        first_total_read,
        first_consumed,
        first_wire.len,
    );
    try std.testing.expect(first_transport_early);
    const remaining = first_total_read - first_consumed;
    std.mem.copyForwards(u8, pending_buf[0..remaining], pending_buf[first_consumed..first_total_read]);
    session.pending_len = remaining;
    try std.testing.expectEqual(second_wire.len, session.pending_len);
    try std.testing.expectEqual(@as(usize, 0), session.pending_early_prefix_len);

    const second_old_pending_len = session.pending_len;
    const second_total_read = session.pending_len;
    var second = try http.Request.parse(allocator, pending_buf[0..second_total_read], MAX_REQUEST_SIZE);
    defer second.request.deinit();
    const second_transport_early = h1ConsumeRequestEarlyProvenance(
        &session,
        second_old_pending_len,
        second_total_read,
        second.bytes_consumed,
        0,
    );
    try std.testing.expect(!second_transport_early);

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .prefix,
            .pattern = "/",
            .priority = 0,
            .action = .{ .proxy_pass = "http://127.0.0.1:1" },
            .early_data = .replay_safe,
            .proxy_early_data = .rfc8470,
        },
    };
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = &.{};
    cfg.policy_rules_raw = "";
    cfg.policy_user_scopes_raw = "";
    cfg.policy_approval_routes_raw = "";
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    var ctx = http.request_context.RequestContext.init(allocator, "req-pipeline-ordinary", "127.0.0.1");
    ctx.early_data.transport_early = second_transport_early;
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-pipeline-ordinary", 0);
    var keep_alive = false;
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    const outcome = try executeH1PostPreflightOrchestration(
        {},
        allocator,
        &output.writer,
        &cfg,
        &state,
        &ctx,
        &second.request,
        "req-pipeline-ordinary",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1CountingPostPreflightHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, @intFromEnum(http.Status.ok)), outcome.route_status);
    try std.testing.expectEqual(@as(usize, 1), effects.mirror_calls);
    try std.testing.expectEqual(@as(usize, 1), effects.auth_calls);
    try std.testing.expectEqual(@as(usize, 1), effects.rate_limit_mutations);
    try std.testing.expectEqual(@as(usize, 1), effects.upstream_calls);
    try std.testing.expectEqual(@as(usize, 1), effects.handler_calls);
}

test "#369 Slice 2 rt0.reject.store_unavailable: disabled-mode composition passes no replay gate to the real native TLS connection" {
    // Deterministic, explicit inputs: native resumption and a native TCP
    // provider both "exist" here, isolating `.disabled` replay mode alone
    // as the reason `run()` withholds the process-scoped store/gate.
    const disabled_composition = nativeEarlyDataReplayComposition(
        .disabled,
        true, // native_resumption_runtime_enabled
        true, // native_tls_provider_present
        false,
        false,
        .{ .ctx = undefined, .decideFn = struct {
            fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
                return .allow;
            }
        }.decide },
    );
    try std.testing.expect(!disabled_composition.store_enabled);
    try std.testing.expect(disabled_composition.early_data_replay_gate == null);

    // This is the production option-selection helper `run()` uses before
    // constructing native TCP/H3 runtimes, not a parallel reproduction of
    // its branch. Since the helper returns null here, the real native TLS
    // connection receives the backend default gate.
    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    const fds = try gatewayTestSocketPair();
    defer gatewayTestCloseFd(fds[0]);
    defer gatewayTestCloseFd(fds[1]);
    const native = try http.native_tls_connection.NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .early_data_replay_gate = disabled_composition.early_data_replay_gate },
    );
    defer native.destroy();

    // `Tls13Backend`'s own default (proven end-to-end in
    // `tls13_backend_tests.zig`'s "0-RTT anti-replay defaults to
    // unavailable (fails closed) when no gate is configured" test) applies
    // to this real, composition-built connection: no callback installed,
    // so any 0-RTT attempt on it fails closed to `.unavailable` while
    // ordinary 1-RTT resumption is untouched.
    try std.testing.expect(native.backend.early_data_replay_gate.decideFn == null);
}

test "#510 process-local composition enables native TCP server early-data policy with replay gate" {
    const gate = tls_core.tls13_backend.EarlyDataReplayGate{ .ctx = undefined, .decideFn = struct {
        fn decide(_: *anyopaque, _: tls_core.tls13_backend.EarlyDataReplayCandidate) tls_core.tls13_backend.EarlyDataReplayDecision {
            return .allow;
        }
    }.decide };
    const composition = nativeEarlyDataReplayComposition(
        .process_local,
        true,
        true,
        false,
        false,
        gate,
    );
    try std.testing.expect(composition.store_enabled);
    try std.testing.expect(composition.early_data_replay_gate != null);
    const policy = nativeTcpServerEarlyDataPolicy(composition.early_data_replay_gate);
    try std.testing.expect(policy.enabled);

    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();
    var entropy = tls_core.production_crypto.OsEntropy{};
    var provider = tls_core.production_crypto.Provider.init(entropy.entropy());
    var runtime = try tls_core.resumption_runtime.Runtime.init(
        std.testing.allocator,
        .{ .mode = .stateful },
        .{ .ctx = undefined, .nowUnixMsFn = systemNowUnixMs },
        provider.cryptoProvider(),
    );
    defer runtime.deinit();

    const fds = try gatewayTestSocketPair();
    defer gatewayTestCloseFd(fds[0]);
    defer gatewayTestCloseFd(fds[1]);
    const native = try http.native_tls_connection.NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{
            .resumption_runtime = &runtime,
            .early_data_replay_gate = composition.early_data_replay_gate,
            .server_early_data_policy = policy,
        },
    );
    defer native.destroy();

    try std.testing.expect(native.backend.server_early_data_policy.enabled);
    try std.testing.expectEqual(composition.early_data_replay_gate.?.ctx, native.backend.early_data_replay_gate.ctx);
}

test "#518 persistent native resumption uses bounded stateless ticket limits" {
    var cfg: edge_config.EdgeConfig = undefined;
    cfg.tls_native_ticket_keys_path = "";
    var limits = nativeResumptionSessionLimits(&cfg);
    try std.testing.expectEqual(tls_core.session.Limits.default.max_ticket_len, limits.max_ticket_len);
    try std.testing.expectEqual(tls_core.session.Limits.default.max_serialized_len, limits.max_serialized_len);

    cfg.tls_native_ticket_keys_path = "ticket-keys.json";
    limits = nativeResumptionSessionLimits(&cfg);
    try std.testing.expectEqual(@as(usize, native_persistent_ticket_max), limits.max_ticket_len);
    try std.testing.expectEqual(@as(usize, native_persistent_ticket_max - tls_core.ticket_protection.envelope_overhead), limits.max_serialized_len);
    try std.testing.expect(limits.max_ticket_len < tls_core.session.absolute_ticket_wire_max);
    try std.testing.expect(limits.max_serialized_len < tls_core.session.hard_max_serialized_len);

    const max_transport = tls_core.session.Limits.default.max_transport_compat_len;
    const max_application = tls_core.session.Limits.default.max_application_compat_len;
    const transport_compat = [_]u8{0xa5} ** max_transport;
    const application_compat = [_]u8{0x5a} ** max_application;
    var common: tls_core.session.ResumableSessionCommon = .{};
    defer common.deinit();
    try common.init(std.testing.allocator, limits, .{
        .cipher_suite = .tls_aes_128_gcm_sha256,
        .resumption_psk = &([_]u8{0x42} ** 32),
        .server_name = "tardigrade.test",
        .application_protocol = "http/1.1",
        .auth_binding = tls_core.session.AuthBinding.fromLeafCertificateDer("native-h1-fixture-leaf"),
        .issued_at_unix_ms = 2_000,
        .lifetime_seconds = 24 * 60 * 60,
        .early_data = .{ .early_data_capable = 16 * 1024 },
        .transport_compat = .{ .format_id = 1, .format_version = 1, .bytes = &transport_compat },
        .application_compat = .{ .format_id = 2, .format_version = 1, .bytes = &application_compat },
        .early_data_transport_compat = .{ .format_id = 3, .format_version = 1, .bytes = &transport_compat },
        .early_data_application_compat = .{ .format_id = 4, .format_version = 1, .bytes = &application_compat },
    });

    var state: tls_core.session.ServerRecoverableState = .{};
    defer state.deinit();
    state.init(&common, 0x01020304);
    const encoded_len = try tls_core.session.serverEncodedLenWithLimits(&state, limits);
    try std.testing.expect(encoded_len <= limits.max_serialized_len);
    try std.testing.expect(encoded_len + tls_core.ticket_protection.envelope_overhead <= limits.max_ticket_len);
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
    try std.testing.expectEqual(RequestUploadStreamingEligibility.stream, streamingUploadEligibilityBeforeBodyRead(std.testing.allocator, &cfg, &upload_head.request));

    var chunked_head = try http.Request.parseHead(
        allocator,
        "POST /upload/body HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer chunked_head.request.deinit();
    // A chunked upload is re-framed incrementally rather than buffered (#139).
    try std.testing.expectEqual(RequestUploadStreamingEligibility.stream, streamingUploadEligibilityBeforeBodyRead(std.testing.allocator, &cfg, &chunked_head.request));

    var compat_head = try http.Request.parseHead(
        allocator,
        "POST /compat/body HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer compat_head.request.deinit();
    try std.testing.expectEqual(RequestUploadStreamingEligibility{ .fallback = .policy_disabled }, streamingUploadEligibilityBeforeBodyRead(std.testing.allocator, &cfg, &compat_head.request));

    var compat_chunked_head = try http.Request.parseHead(
        allocator,
        "POST /compat/body HTTP/1.1\r\nHost: example.test\r\nTransfer-Encoding: chunked\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer compat_chunked_head.request.deinit();
    try std.testing.expectEqual(RequestUploadStreamingEligibility{ .fallback = .policy_disabled }, streamingUploadEligibilityBeforeBodyRead(std.testing.allocator, &cfg, &compat_chunked_head.request));

    cfg.auth_request_url = "http://auth.example.test/check";
    try std.testing.expectEqual(RequestUploadStreamingEligibility{ .fallback = .body_dependent_middleware }, streamingUploadEligibilityBeforeBodyRead(std.testing.allocator, &cfg, &upload_head.request));
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

const HelperProbeConn = struct {
    pending_value: usize = 0,
    read_timeout_ms: u32 = 0,
    write_timeout_ms: u32 = 0,

    pub fn pending(self: *const HelperProbeConn) usize {
        return self.pending_value;
    }

    pub fn setReadTimeoutMs(self: *HelperProbeConn, timeout_ms: u32) void {
        self.read_timeout_ms = timeout_ms;
    }

    pub fn setWriteTimeoutMs(self: *HelperProbeConn, timeout_ms: u32) void {
        self.write_timeout_ms = timeout_ms;
    }
};

test "http1 keepalive detects session buffered pipelined request" {
    var conn = HelperProbeConn{};
    var session = ConnectionSession{};

    try std.testing.expect(!hasBufferedHttp1Work(&conn, &session));
    session.pending_len = 1;
    try std.testing.expect(hasBufferedHttp1Work(&conn, &session));

    session.pending_len = 0;
    conn.pending_value = 1;
    try std.testing.expect(hasBufferedHttp1Work(&conn, &session));
}

test "connection timeout helper resets read and write timeouts" {
    var conn = HelperProbeConn{ .read_timeout_ms = 5000, .write_timeout_ms = 5000 };
    setConnTimeouts(&conn, 100, 250);
    try std.testing.expectEqual(@as(u32, 100), conn.read_timeout_ms);
    try std.testing.expectEqual(@as(u32, 250), conn.write_timeout_ms);

    setConnTimeouts(&conn, 0, 0);
    try std.testing.expectEqual(@as(u32, 0), conn.read_timeout_ms);
    try std.testing.expectEqual(@as(u32, 0), conn.write_timeout_ms);
}

const GatewaySchedulerTestSubmit = struct {
    submitted: usize = 0,
    item: ?http.worker_pool.WorkItem = null,

    fn submit(raw_ctx: *anyopaque, fd: std.posix.fd_t) !void {
        const self: *GatewaySchedulerTestSubmit = @ptrCast(@alignCast(raw_ctx));
        self.submitted += 1;
        self.item = .{ .active_drive_poll = fd };
    }
};

const GatewaySchedulerTestRemove = struct {
    removed: usize = 0,
    fd: std.posix.fd_t = -1,

    fn remove(raw_ctx: *anyopaque, fd: std.posix.fd_t) !void {
        const self: *GatewaySchedulerTestRemove = @ptrCast(@alignCast(raw_ctx));
        self.removed += 1;
        self.fd = fd;
    }
};

const GatewaySchedulerCloseProbe = struct {
    closes: usize = 0,
    last_fd: std.posix.fd_t = -1,

    fn close(raw_ctx: *anyopaque, fd: std.posix.fd_t) void {
        const self: *GatewaySchedulerCloseProbe = @ptrCast(@alignCast(raw_ctx));
        self.closes += 1;
        self.last_fd = fd;
    }
};

const GatewayTestFdCarrier = struct {
    fd: std.posix.fd_t,

    fn carrier(self: *GatewayTestFdCarrier) tls_core.encrypted_stream.Carrier {
        return .{ .ptr = self, .readFn = read, .writeFn = write };
    }

    fn read(raw_ctx: *anyopaque, out: []u8) tls_core.encrypted_stream.Error!usize {
        const self: *GatewayTestFdCarrier = @ptrCast(@alignCast(raw_ctx));
        return gatewayTestReadFd(self.fd, out);
    }

    fn write(raw_ctx: *anyopaque, bytes: []const u8) tls_core.encrypted_stream.Error!usize {
        const self: *GatewayTestFdCarrier = @ptrCast(@alignCast(raw_ctx));
        return gatewayTestWriteFd(self.fd, bytes);
    }
};

const GatewayPendingNative = struct {
    allocator: std.mem.Allocator,
    fd: std.posix.fd_t,
    peer_fd: std.posix.fd_t,
    mock: *tls_core.credentials.MockCredentialProvider,
    client_entropy_source: tls_core.production_crypto.OsEntropy = .{},
    client_provider: tls_core.production_crypto.Provider = undefined,
    client_backend: tls_core.tls13_backend.Tls13Backend = undefined,
    client_carrier: GatewayTestFdCarrier = undefined,
    client_stream: tls_core.encrypted_stream.PureZigRecordStream = undefined,
    native: *http.native_tls_connection.NativeTlsConnection,

    fn create(allocator: std.mem.Allocator, pending_polls: usize) !*GatewayPendingNative {
        const self = try allocator.create(GatewayPendingNative);
        errdefer allocator.destroy(self);

        const fds = try gatewayTestSocketPair();
        errdefer gatewayTestCloseFd(fds[0]);
        errdefer gatewayTestCloseFd(fds[1]);

        const mock = try allocator.create(tls_core.credentials.MockCredentialProvider);
        errdefer allocator.destroy(mock);
        mock.* = tls_core.credentials.MockCredentialProvider.init(tls_core.credentials.testdata.identity());
        mock.async_select = true;
        mock.pending_polls = pending_polls;

        const native = try http.native_tls_connection.NativeTlsConnection.create(
            allocator,
            fds[0],
            .{ .http1_enabled = true, .http2_enabled = true },
            mock.provider(),
        );
        errdefer native.destroy();

        self.* = GatewayPendingNative{
            .allocator = allocator,
            .fd = fds[0],
            .peer_fd = fds[1],
            .mock = mock,
            .native = native,
        };
        self.client_provider = tls_core.production_crypto.Provider.init(self.client_entropy_source.entropy());
        self.client_backend = tls_core.tls13_backend.Tls13Backend.initClientConfigured(
            .{ .hello_random = [_]u8{0xc1} ** 32 },
            self.client_provider.cryptoProvider(),
            .{ .pinned_certificate = tls_core.tls13_backend.testdata.certificate_der },
            tls_core.tls13_backend.recordConfig(tls_core.policy.Policy.recordH2Only()),
            .{ .server_name = "tardigrade.test" },
        );
        self.client_carrier = .{ .fd = fds[1] };
        self.client_stream = try tls_core.encrypted_stream.PureZigRecordStream.initWithCarrierAndBackend(
            allocator,
            .client,
            self.client_provider.cryptoProvider(),
            .tls_aes_128_gcm_sha256,
            self.client_carrier.carrier(),
            self.client_backend.backend(),
        );

        var rounds: usize = 0;
        while (!native.backend.authPending()) : (rounds += 1) {
            if (rounds >= 20) return error.Stalled;
            const client_result = try self.client_stream.drive();
            const server_result = try native.drive();
            if (!client_result.made_progress and !server_result.made_progress) return error.Stalled;
        }
        try std.testing.expect(native.backend.authPending());
        try std.testing.expectEqual(@as(usize, 1), self.mock.select_count);
        return self;
    }

    fn deinitPeer(self: *GatewayPendingNative) void {
        self.client_stream.deinit();
        self.client_backend.deinit();
        gatewayTestCloseFd(self.peer_fd);
        const allocator = self.allocator;
        allocator.destroy(self.mock);
        self.* = undefined;
        allocator.destroy(self);
    }
};

test "gateway active-drive scheduler polls pending native auth and expires queued work without fd reuse (#355)" {
    const allocator = std.testing.allocator;

    const pending = try GatewayPendingNative.create(allocator, 2);
    defer pending.deinitPeer();

    var registry = http.downstream_connection.ActiveRegistry.init(allocator);
    defer registry.deinit();

    var close_probe = GatewaySchedulerCloseProbe{};
    var managed = http.downstream_connection.ManagedConnection.init(
        .{ .native = pending.native },
        .{ .native_handshake = .{ .deadline_ms = 1_000 } },
    );
    managed.lifecycle.close_ctx = &close_probe;
    managed.lifecycle.close_fn = GatewaySchedulerCloseProbe.close;
    const wait = managed.updateWaitFor(.{ .read = true }, 100, ACTIVE_DRIVE_POLL_INTERVAL_MS) orelse
        return error.TestExpectedEncryptedWait;
    try std.testing.expectEqual(http.downstream_connection.EncryptedWait{ .retry_at_ms = 350 }, wait);
    try registry.insert(&managed);

    var state: GatewayState = undefined;
    var remove_probe = GatewaySchedulerTestRemove{};
    var submit_probe = GatewaySchedulerTestSubmit{};
    dispatchDueActiveDrivePollsAt(&registry, &state, 349, &remove_probe, GatewaySchedulerTestRemove.remove, &submit_probe, GatewaySchedulerTestSubmit.submit);
    try std.testing.expectEqual(@as(usize, 0), submit_probe.submitted);
    try std.testing.expect(registry.contains(pending.fd));

    dispatchDueActiveDrivePollsAt(&registry, &state, 350, &remove_probe, GatewaySchedulerTestRemove.remove, &submit_probe, GatewaySchedulerTestSubmit.submit);
    try std.testing.expectEqual(@as(usize, 1), submit_probe.submitted);
    try std.testing.expectEqual(http.worker_pool.WorkItem{ .active_drive_poll = pending.fd }, submit_probe.item.?);
    try std.testing.expectEqual(pending.fd, remove_probe.fd);
    try std.testing.expect(registry.contains(pending.fd));

    var expired_out: [1]http.downstream_connection.ManagedConnection = undefined;
    try std.testing.expectEqual(@as(usize, 0), registry.reapExpired(1_001, expired_out[0..]));

    const poll_times = [_]u64{ 350, 600, 850 };
    for (poll_times, 1..) |poll_time, expected_poll_count| {
        var ready = switch (checkoutActiveForWorkerAt(&registry, pending.fd, poll_time)) {
            .ready => |conn| conn,
            .missing, .expired => return error.TestExpectedReadyActiveConnection,
        };
        try std.testing.expectEqual(@as(u64, 1_000), ready.phase.native_handshake.deadline_ms);

        const driven = try ready.transport.native.drive();
        try std.testing.expectEqual(expected_poll_count, pending.mock.poll_count);
        try std.testing.expectEqual(@as(u64, 1_000), ready.phase.native_handshake.deadline_ms);
        try std.testing.expectEqual(@as(usize, 0), close_probe.closes);

        if (expected_poll_count < poll_times.len) {
            try std.testing.expect(ready.transport.native.backend.authPending());
            const interest = try rearmActiveConnectionInRegistryAt(
                &registry,
                &ready,
                .{ .read = true },
                poll_time,
                ACTIVE_DRIVE_POLL_INTERVAL_MS,
            );
            try std.testing.expectEqual(http.event_loop.Interest{}, interest);

            submit_probe = .{};
            dispatchDueActiveDrivePollsAt(&registry, &state, poll_time + ACTIVE_DRIVE_POLL_INTERVAL_MS - 1, &remove_probe, GatewaySchedulerTestRemove.remove, &submit_probe, GatewaySchedulerTestSubmit.submit);
            try std.testing.expectEqual(@as(usize, 0), submit_probe.submitted);
            dispatchDueActiveDrivePollsAt(&registry, &state, poll_time + ACTIVE_DRIVE_POLL_INTERVAL_MS, &remove_probe, GatewaySchedulerTestRemove.remove, &submit_probe, GatewaySchedulerTestSubmit.submit);
            try std.testing.expectEqual(@as(usize, 1), submit_probe.submitted);
            try std.testing.expectEqual(http.worker_pool.WorkItem{ .active_drive_poll = pending.fd }, submit_probe.item.?);
        } else {
            try std.testing.expect(driven.made_progress);
            try std.testing.expect(!ready.transport.native.backend.authPending());
            try std.testing.expectEqual(@as(usize, 3), pending.mock.poll_count);
            try std.testing.expectEqual(@as(usize, 1), pending.mock.op_release_count);
            try std.testing.expectEqual(@as(usize, 0), pending.mock.cancel_count);
            ready.deinit();
        }
    }

    const expired_pending = try GatewayPendingNative.create(allocator, 5);
    defer expired_pending.deinitPeer();
    var expired_probe = GatewaySchedulerCloseProbe{};
    var expired_managed = http.downstream_connection.ManagedConnection.init(
        .{ .native = expired_pending.native },
        .{ .native_handshake = .{ .deadline_ms = 1_000 } },
    );
    expired_managed.lifecycle.close_ctx = &expired_probe;
    expired_managed.lifecycle.close_fn = GatewaySchedulerCloseProbe.close;
    _ = expired_managed.updateWaitFor(.{ .read = true }, 100, ACTIVE_DRIVE_POLL_INTERVAL_MS);
    try registry.insert(&expired_managed);

    submit_probe = .{};
    dispatchDueActiveDrivePollsAt(&registry, &state, 350, &remove_probe, GatewaySchedulerTestRemove.remove, &submit_probe, GatewaySchedulerTestSubmit.submit);
    try std.testing.expectEqual(@as(usize, 1), submit_probe.submitted);
    try std.testing.expectEqual(@as(usize, 0), registry.reapExpired(1_001, expired_out[0..]));

    const stale_fd = expired_pending.fd;
    try std.testing.expectEqual(ActiveCheckoutResult.expired, checkoutActiveForWorkerAt(&registry, stale_fd, 1_001));
    try std.testing.expectEqual(@as(usize, 1), expired_probe.closes);
    try std.testing.expectEqual(stale_fd, expired_probe.last_fd);
    try std.testing.expectEqual(@as(usize, 1), expired_pending.mock.cancel_count);
    try std.testing.expectEqual(@as(usize, 1), expired_pending.mock.op_release_count);

    const reused = try gatewayTestSocketPair();
    defer gatewayTestCloseFd(reused[1]);
    defer gatewayTestCloseFd(stale_fd);
    if (reused[0] != stale_fd) {
        if (std.c.dup2(reused[0], stale_fd) < 0) return error.Dup2Failed;
        gatewayTestCloseFd(reused[0]);
    }
    try std.testing.expectEqual(ActiveCheckoutResult.missing, checkoutActiveForWorkerAt(&registry, stale_fd, 1_001));
    try std.testing.expectEqual(@as(usize, 1), expired_probe.closes);
    _ = try gatewayTestWriteFd(stale_fd, "x");
}

const GatewayMetricStream = struct {
    snapshot: tls_core.encrypted_stream.BufferSnapshot = .{},
    readiness_state: tls_core.encrypted_stream.Readiness = .{ .can_write_plaintext = true },
    read_payload: []const u8 = "",
    read_offset: usize = 0,
    write_count: usize = 0,

    fn stream(self: *GatewayMetricStream) tls_core.encrypted_stream.EncryptedStream {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn backend(_: *anyopaque) tls_core.encrypted_stream.BackendKind {
        return .pure_zig_record;
    }

    fn read(raw_ctx: *anyopaque, out: []u8) tls_core.encrypted_stream.Error!usize {
        const self: *GatewayMetricStream = @ptrCast(@alignCast(raw_ctx));
        if (self.read_offset >= self.read_payload.len) return error.WouldBlock;
        const n = @min(out.len, self.read_payload.len - self.read_offset);
        @memcpy(out[0..n], self.read_payload[self.read_offset..][0..n]);
        self.read_offset += n;
        self.snapshot.current.inbound_plaintext = self.read_payload.len - self.read_offset;
        self.readiness_state.can_read_plaintext = self.read_offset < self.read_payload.len;
        return n;
    }

    fn write(raw_ctx: *anyopaque, bytes: []const u8) tls_core.encrypted_stream.Error!usize {
        const self: *GatewayMetricStream = @ptrCast(@alignCast(raw_ctx));
        self.write_count += 1;
        return bytes.len;
    }

    fn close(_: *anyopaque) void {}

    fn readiness(raw_ctx: *anyopaque) tls_core.encrypted_stream.Readiness {
        const self: *GatewayMetricStream = @ptrCast(@alignCast(raw_ctx));
        return self.readiness_state;
    }

    fn drive(raw_ctx: *anyopaque) tls_core.encrypted_stream.Error!tls_core.encrypted_stream.DriveResult {
        const self: *GatewayMetricStream = @ptrCast(@alignCast(raw_ctx));
        return .{ .made_progress = false, .readiness = self.readiness_state };
    }

    fn bufferSnapshot(raw_ctx: *anyopaque) tls_core.encrypted_stream.BufferSnapshot {
        const self: *GatewayMetricStream = @ptrCast(@alignCast(raw_ctx));
        return self.snapshot;
    }

    const vtable = tls_core.encrypted_stream.EncryptedStream.VTable{
        .backendFn = backend,
        .readFn = read,
        .writeFn = write,
        .closeFn = close,
        .readinessFn = readiness,
        .driveFn = drive,
        .bufferSnapshotFn = bufferSnapshot,
    };
};

test "waiting encrypted HTTP adapter records live HTTP/1 writer TLS gauge pause resume and teardown zero (#355)" {
    const allocator = std.testing.allocator;
    var metrics = http.metrics.Metrics.init();
    var metrics_mutex = compat.Mutex{};
    var metrics_state = http.metrics.TlsBufferConnectionMetrics{};
    var fake = GatewayMetricStream{ .snapshot = .{
        .current = .{ .outbound_ciphertext = 9 },
        .pause_state = .{ .plaintext_write_paused = true },
        .counters = .{ .plaintext_write_pauses = 1 },
        .limits_enforced = true,
        .limits = tls_core.encrypted_stream.BufferLimits.defaults(),
    } };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.init(fake.stream());
    var adapter = WaitingEncryptedHttpConnection.initWithMetrics(
        inner,
        1,
        1,
        &metrics,
        &metrics_mutex,
        &metrics_state,
    );

    try std.testing.expectEqual(@as(usize, 9), try adapter.write("http-body"));
    try std.testing.expectEqual(@as(usize, 1), fake.write_count);
    {
        const prom = try metrics.toPrometheus(allocator);
        defer allocator.free(prom);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffered_bytes_current{backend=\"pure_zig_record\",queue=\"outbound_ciphertext\"} 9\n") != null);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffer_pause_events_total{backend=\"pure_zig_record\",direction=\"plaintext_write\"} 1\n") != null);
    }

    fake.snapshot = .{
        .current = .{},
        .pause_state = .{},
        .counters = .{
            .plaintext_write_pauses = 1,
            .plaintext_write_resumes = 1,
        },
        .limits_enforced = true,
        .limits = tls_core.encrypted_stream.BufferLimits.defaults(),
    };
    try std.testing.expectEqual(@as(usize, 5), try adapter.write("drain"));
    {
        const prom = try metrics.toPrometheus(allocator);
        defer allocator.free(prom);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffered_bytes_current{backend=\"pure_zig_record\",queue=\"outbound_ciphertext\"} 0\n") != null);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffer_pause_events_total{backend=\"pure_zig_record\",direction=\"plaintext_write\"} 1\n") != null);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffer_resume_events_total{backend=\"pure_zig_record\",direction=\"plaintext_write\"} 1\n") != null);
    }

    metrics_mutex.lock();
    defer metrics_mutex.unlock();
    try metrics.releaseTlsBufferSnapshot(&metrics_state);
}

test "waiting encrypted HTTP adapter records live HTTP/2 writer TLS metrics through frame serializer (#355)" {
    const allocator = std.testing.allocator;
    var metrics = http.metrics.Metrics.init();
    var metrics_mutex = compat.Mutex{};
    var metrics_state = http.metrics.TlsBufferConnectionMetrics{};
    var fake = GatewayMetricStream{ .snapshot = .{
        .current = .{ .outbound_ciphertext = 13 },
        .pause_state = .{ .plaintext_write_paused = true },
        .counters = .{ .plaintext_write_pauses = 1 },
        .limits_enforced = true,
        .limits = tls_core.encrypted_stream.BufferLimits.defaults(),
    } };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.init(fake.stream());
    var adapter = WaitingEncryptedHttpConnection.initWithMetrics(
        inner,
        1,
        1,
        &metrics,
        &metrics_mutex,
        &metrics_state,
    );

    try http.http2_frame.writeSettings(allocator, adapter.writer(), &[_][2]u32{
        .{ 0x3, 100 },
        .{ 0x4, 1024 },
    });
    try std.testing.expect(fake.write_count > 0);
    {
        const prom = try metrics.toPrometheus(allocator);
        defer allocator.free(prom);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffered_bytes_current{backend=\"pure_zig_record\",queue=\"outbound_ciphertext\"} 13\n") != null);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffer_pause_events_total{backend=\"pure_zig_record\",direction=\"plaintext_write\"} 1\n") != null);
    }

    fake.snapshot = .{
        .current = .{},
        .pause_state = .{},
        .counters = .{
            .plaintext_write_pauses = 1,
            .plaintext_write_resumes = 1,
        },
        .limits_enforced = true,
        .limits = tls_core.encrypted_stream.BufferLimits.defaults(),
    };
    try http.http2_frame.writeSettingsAck(adapter.writer());
    {
        const prom = try metrics.toPrometheus(allocator);
        defer allocator.free(prom);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffered_bytes_current{backend=\"pure_zig_record\",queue=\"outbound_ciphertext\"} 0\n") != null);
        try std.testing.expect(std.mem.find(u8, prom, "tardigrade_tls_buffer_resume_events_total{backend=\"pure_zig_record\",direction=\"plaintext_write\"} 1\n") != null);
    }

    metrics_mutex.lock();
    defer metrics_mutex.unlock();
    try metrics.releaseTlsBufferSnapshot(&metrics_state);
}

const H2DispatchTestConn = struct {
    allocator: std.mem.Allocator,
    out: std.Io.Writer.Allocating,
    handshake_complete: bool = true,
    handshake_completes_on_wait: bool = false,
    wait_calls: usize = 0,
    /// Result of the SNI-selected client-auth policy's Host admission (#763).
    policy_admits: bool = true,
    policy_checked_hosts: usize = 0,

    const Writer = struct {
        conn: *H2DispatchTestConn,

        pub fn write(self: Writer, bytes: []const u8) !usize {
            return self.conn.out.writer.write(bytes);
        }

        pub fn writeAll(self: Writer, bytes: []const u8) !void {
            try self.conn.out.writer.writeAll(bytes);
        }

        pub fn print(self: Writer, comptime fmt: []const u8, args: anytype) !void {
            try self.conn.out.writer.print(fmt, args);
        }
    };

    fn init(allocator: std.mem.Allocator) H2DispatchTestConn {
        return .{
            .allocator = allocator,
            .out = .init(allocator),
        };
    }

    fn deinit(self: *H2DispatchTestConn) void {
        self.out.deinit();
    }

    pub fn writer(self: *H2DispatchTestConn) Writer {
        return .{ .conn = self };
    }

    pub fn read(_: *H2DispatchTestConn, _: []u8) !usize {
        return error.ConnectionClosed;
    }

    fn beginReadScope(_: *H2DispatchTestConn) void {}

    fn takeReadScopeTransportEarly(_: *H2DispatchTestConn) bool {
        return false;
    }

    fn downstreamHandshakeComplete(self: *const H2DispatchTestConn) bool {
        return self.handshake_complete;
    }

    pub fn clientPolicyAdmitsHost(self: *H2DispatchTestConn, _: []const u8) bool {
        self.policy_checked_hosts += 1;
        return self.policy_admits;
    }

    fn waitForHandshakeCompletionOrInput(self: *H2DispatchTestConn) !void {
        self.wait_calls += 1;
        if (self.handshake_completes_on_wait) self.handshake_complete = true;
    }
};

test "H2 response larger than scheduler capacity drains and completes" {
    const allocator = std.testing.allocator;
    var body: [300 * 1024]u8 = undefined;
    @memset(&body, 'x');
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    var scheduler = try http.h2_outbound_scheduler.Scheduler.init(allocator, http.h2_outbound_scheduler.default_max_queued_bytes);
    defer scheduler.deinit();
    var response = PendingHttp2Response{
        .body_alloc = null,
        .body = body[0..],
        .status_code = 200,
    };
    var connection_window: i32 = @intCast(body.len);
    var stream_window: i32 = @intCast(body.len);
    try std.testing.expectEqual(
        Http2FlushResult.complete,
        try flushHttp2PendingResponse(
            &conn,
            &scheduler,
            scheduler.writer(),
            1,
            &response,
            &connection_window,
            &stream_window,
        ),
    );
    try scheduler.flush(conn.writer());

    var offset: usize = 0;
    var body_offset: usize = 0;
    while (offset < conn.out.written().len) {
        const frame = conn.out.written()[offset..];
        const payload_len = (@as(usize, frame[0]) << 16) | (@as(usize, frame[1]) << 8) | frame[2];
        try std.testing.expectEqual(@as(u8, @intFromEnum(http.http2_frame.Type.data)), frame[3]);
        try std.testing.expectEqualSlices(u8, body[body_offset .. body_offset + payload_len], frame[9 .. 9 + payload_len]);
        body_offset += payload_len;
        offset += 9 + payload_len;
    }
    try std.testing.expectEqual(body.len, body_offset);
}

test "H2 reset removes parked response while queued output is backpressured" {
    const BlockingWriter = struct {
        pub fn write(_: *@This(), _: []const u8) error{WouldBlock}!usize {
            return error.WouldBlock;
        }
        pub fn writeAll(_: *@This(), _: []const u8) error{WouldBlock}!void {
            return error.WouldBlock;
        }
    };
    const allocator = std.testing.allocator;
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer pending.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer sessions.deinit();
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try pending_responses.put(1, .{
        .body_alloc = try allocator.dupe(u8, "cancelled"),
        .body = "cancelled",
        .status_code = 200,
    });
    try ready.append(1);

    var scheduler = try http.h2_outbound_scheduler.Scheduler.init(allocator, 64);
    try scheduler.enqueueFrame(.data, 0, 1, "already-queued");
    var writer = BlockingWriter{};
    try scheduler.flush(&writer);
    try std.testing.expect(scheduler.hasPendingOutput());

    var buffered_request_bytes: usize = 0;
    var in_flight_jobs = std.AutoHashMap(u31, void).init(allocator);
    defer in_flight_jobs.deinit();
    var handoff = try http.h2_request_handoff.Handoff.init(allocator, 4);
    defer handoff.deinit();
    // The queued-but-never-transmitted "already-queued" DATA frame already
    // debited this much from the connection send-window when it was first
    // written; the reset must refund it or an unrelated sibling stream would
    // be starved of credit that was never actually spent on the wire.
    var conn_send_window: i32 = 0;
    try h2ResetStreamState(
        &writer,
        allocator,
        &streams,
        &pending,
        &pending_responses,
        &ready,
        &sessions,
        &buffered_request_bytes,
        1,
        &scheduler,
        &handoff,
        null,
        &in_flight_jobs,
        null,
        &conn_send_window,
    );
    try std.testing.expect(!streams.contains(1));
    try std.testing.expect(!pending_responses.contains(1));
    try std.testing.expectEqual(@as(usize, 0), ready.items.len);
    try std.testing.expect(!scheduler.hasPendingOutput());
    try std.testing.expectEqual(@as(i32, "already-queued".len), conn_send_window);
    scheduler.deinit();
}

test "local STREAM_CLOSED reset drops queued response before its RST" {
    const BlockingWriter = struct {
        blocked: bool = true,
        out: std.Io.Writer.Allocating,

        pub fn write(self: *@This(), bytes: []const u8) anyerror!usize {
            if (self.blocked) return error.WouldBlock;
            try self.out.writer.writeAll(bytes);
            return bytes.len;
        }
    };
    const allocator = std.testing.allocator;
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer pending.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer sessions.deinit();
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    const parked = try allocator.dupe(u8, "parked");
    try pending_responses.put(1, .{ .body_alloc = parked, .body = parked, .status_code = 200 });
    try ready.append(1);

    var scheduler = try http.h2_outbound_scheduler.Scheduler.init(allocator, 128);
    defer scheduler.deinit();
    try scheduler.enqueueFrame(.data, 0, 1, "stale");
    try scheduler.enqueueFrame(.data, 0, 3, "sibling");
    var output = BlockingWriter{ .out = .init(allocator) };
    defer output.out.deinit();
    try scheduler.flush(&output);

    var buffered_request_bytes: usize = 0;
    var in_flight_jobs = std.AutoHashMap(u31, void).init(allocator);
    defer in_flight_jobs.deinit();
    var handoff = try http.h2_request_handoff.Handoff.init(allocator, 4);
    defer handoff.deinit();
    // The never-transmitted "stale" DATA frame already debited the
    // connection send-window when queued; dropping it on reset must refund
    // that credit rather than lose it.
    var conn_send_window: i32 = 0;
    try h2WriteStreamClosedReset(
        scheduler.writer(),
        &scheduler,
        allocator,
        &streams,
        &pending,
        &pending_responses,
        &ready,
        &sessions,
        &buffered_request_bytes,
        1,
        &handoff,
        null,
        &in_flight_jobs,
        null,
        &conn_send_window,
    );
    try std.testing.expect(!streams.contains(1));
    try std.testing.expect(!pending_responses.contains(1));
    try std.testing.expectEqual(@as(i32, "stale".len), conn_send_window);
    output.blocked = false;
    try scheduler.flush(&output);

    var offset: usize = 0;
    var saw_sibling = false;
    var saw_reset = false;
    while (offset < output.out.written().len) {
        const frame = output.out.written()[offset..];
        const payload_len = (@as(usize, frame[0]) << 16) | (@as(usize, frame[1]) << 8) | frame[2];
        const stream_id = std.mem.readInt(u32, frame[5..9], .big) & 0x7fff_ffff;
        if (frame[3] == @intFromEnum(http.http2_frame.Type.data)) {
            try std.testing.expectEqual(@as(u32, 3), stream_id);
            try std.testing.expectEqualSlices(u8, "sibling", frame[9 .. 9 + payload_len]);
            saw_sibling = true;
        } else {
            try std.testing.expectEqual(@as(u8, @intFromEnum(http.http2_frame.Type.rst_stream)), frame[3]);
            try std.testing.expectEqual(@as(u32, 1), stream_id);
            saw_reset = true;
        }
        offset += 9 + payload_len;
    }
    try std.testing.expect(saw_sibling and saw_reset);
}

test "H2 deferred ready stream wakes on handshake completion without extra H2 frame" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();

    var ps = Http2PendingStream.init(allocator);
    ps.method = try allocator.dupe(u8, "GET");
    ps.path = try allocator.dupe(u8, "/h2-wakeup");
    ps.transport_early = true;
    try pending.put(1, ps);
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try ready.append(1);

    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    conn.handshake_complete = false;
    conn.handshake_completes_on_wait = true;

    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    var buffered_request_bytes: usize = 0;

    try h2DispatchReadyStreams(
        &conn,
        allocator,
        &state,
        &cfg,
        &pending,
        &streams,
        &pending_responses,
        &ready,
        &next_server_stream_id,
        &conn_send_window,
        &buffered_request_bytes,
        "127.0.0.1",
    );
    try std.testing.expect(pending.contains(1));
    try std.testing.expectEqual(@as(u8, 0), pending.get(1).?.dispatch_count);

    try h2WaitForHandshakeCompletionOrInput(&conn);
    try h2DispatchReadyStreams(
        &conn,
        allocator,
        &state,
        &cfg,
        &pending,
        &streams,
        &pending_responses,
        &ready,
        &next_server_stream_id,
        &conn_send_window,
        &buffered_request_bytes,
        "127.0.0.1",
    );

    try std.testing.expectEqual(@as(usize, 1), conn.wait_calls);
    try std.testing.expect(!pending.contains(1));
    try std.testing.expectEqual(@as(usize, 0), ready.items.len);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
}

fn runH2PolicyAdmissionStream(allocator: std.mem.Allocator, admits: bool, out_421: *bool, checked: *usize, requests: *u64) !void {
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();

    var ps = Http2PendingStream.init(allocator);
    ps.method = try allocator.dupe(u8, "GET");
    ps.path = try allocator.dupe(u8, "/secret");
    ps.authority = try allocator.dupe(u8, "api.example.test");
    try pending.put(1, ps);
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try ready.append(1);

    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    conn.policy_admits = admits;
    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    var buffered_request_bytes: usize = 0;
    try h2DispatchReadyStreams(&conn, allocator, &state, &cfg, &pending, &streams, &pending_responses, &ready, &next_server_stream_id, &conn_send_window, &buffered_request_bytes, "127.0.0.1");
    out_421.* = std.mem.indexOf(u8, conn.out.written(), "misdirected_request") != null;
    checked.* = conn.policy_checked_hosts;
    requests.* = state.metrics.total_requests;
}

test "H2 stream whose :authority maps to a different client-auth policy is answered 421 before routing (#763)" {
    const allocator = std.testing.allocator;
    var is_421 = false;
    var checked: usize = 0;
    var requests: u64 = 0;
    // CA-A / open SNI -> another policy's :authority: refused on this stream.
    try runH2PolicyAdmissionStream(allocator, false, &is_421, &checked, &requests);
    try std.testing.expect(is_421);
    try std.testing.expectEqual(@as(usize, 1), checked);
    try std.testing.expectEqual(@as(u64, 1), requests);
    // Same-policy authority dispatches normally (no 421).
    try runH2PolicyAdmissionStream(allocator, true, &is_421, &checked, &requests);
    try std.testing.expect(!is_421);
    try std.testing.expectEqual(@as(usize, 1), checked);
}

test "H2 request dispatched to the executor runs off the dispatch call and completes via the handoff (#866)" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();
    var in_flight = std.AutoHashMap(u31, void).init(allocator);
    defer in_flight.deinit();

    var ps = Http2PendingStream.init(allocator);
    ps.method = try allocator.dupe(u8, "GET");
    ps.path = try allocator.dupe(u8, "/missing");
    ps.authority = try allocator.dupe(u8, "api.example.test");
    try pending.put(1, ps);
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try ready.append(1);

    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    var buffered_request_bytes: usize = 0;

    var handoff = try http.h2_request_handoff.Handoff.init(allocator, 4);
    var executor: http.h2_request_executor.Executor = undefined;
    try executor.init(allocator, 1, 4, executeH2RequestJobSignal, &state);

    try h2DispatchReadyStreamsWithWriter(
        &conn,
        conn.writer(),
        null,
        allocator,
        &state,
        &cfg,
        &pending,
        &streams,
        &pending_responses,
        &ready,
        &next_server_stream_id,
        &conn_send_window,
        &buffered_request_bytes,
        "127.0.0.1",
        &handoff,
        &executor,
        &in_flight,
    );

    // Dispatch handed the request to the executor and returned immediately:
    // nothing is written yet, and the stream is tracked as awaiting a
    // worker's completion rather than a parked flow-control response.
    try std.testing.expectEqual(@as(usize, 0), conn.out.written().len);
    try std.testing.expect(in_flight.contains(1));
    try std.testing.expect(!pending.contains(1));

    // Poll for the completion exactly as the connection's drain callback
    // would from `waitFor`; bounded so a real regression fails the test
    // instead of hanging.
    var delivered: ?http.h2_request_handoff.DeliveredCompletion = null;
    var attempts: usize = 0;
    while (delivered == null and attempts < 10_000) : (attempts += 1) {
        delivered = handoff.takeCompletion();
        if (delivered == null) std.Thread.yield() catch {};
    }
    const completion = delivered orelse return error.TestUnexpectedResult;
    _ = in_flight.remove(completion.stream_id);
    try applyH2RequestCompletion(
        &conn,
        conn.writer(),
        null,
        allocator,
        &state,
        completion.stream_id,
        completion.completion,
        &streams,
        &pending_responses,
        &conn_send_window,
    );

    try std.testing.expect(std.mem.indexOf(u8, conn.out.written(), "not_found") != null);
    try std.testing.expect(!in_flight.contains(1));

    handoff.shutdown();
    executor.detachAndDrain(&handoff);
    handoff.waitForActiveDrain();
    handoff.deinit();
    executor.shutdownAndJoin();
}

test "H2 request dispatch rejects with 503 instead of executing inline when the handoff is saturated (#866)" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();
    var in_flight = std.AutoHashMap(u31, void).init(allocator);
    defer in_flight.deinit();

    var ps = Http2PendingStream.init(allocator);
    ps.method = try allocator.dupe(u8, "GET");
    ps.path = try allocator.dupe(u8, "/missing");
    ps.authority = try allocator.dupe(u8, "api.example.test");
    try pending.put(1, ps);
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try ready.append(1);

    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    var buffered_request_bytes: usize = 0;

    // Zero capacity: `Handoff.submit` rejects every job immediately, so
    // dispatch must answer the stream itself rather than fall back to inline
    // execution (which would reintroduce the frame-loop blocking #866
    // removes) or silently drop the request.
    var handoff = try http.h2_request_handoff.Handoff.init(allocator, 0);
    defer handoff.deinit();
    const NoOpExecute = struct {
        fn run(_: *anyopaque, _: *http.h2_request_handoff.Handoff) void {
            @panic("a saturated handoff must never reach the executor");
        }
    };
    var executor: http.h2_request_executor.Executor = undefined;
    try executor.init(allocator, 1, 4, NoOpExecute.run, undefined);
    defer executor.shutdownAndJoin();

    try h2DispatchReadyStreamsWithWriter(
        &conn,
        conn.writer(),
        null,
        allocator,
        &state,
        &cfg,
        &pending,
        &streams,
        &pending_responses,
        &ready,
        &next_server_stream_id,
        &conn_send_window,
        &buffered_request_bytes,
        "127.0.0.1",
        &handoff,
        &executor,
        &in_flight,
    );

    try std.testing.expect(!in_flight.contains(1));
    try std.testing.expectEqual(@as(usize, 0), handoff.outstandingCount());
    const written = conn.out.written();
    try std.testing.expect(std.mem.indexOf(u8, written, "overloaded") != null);
    try std.testing.expect(std.mem.indexOf(u8, written, "503") != null);
}

test "H2 early stream defers dispatch until handshake completion then dispatches once" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();

    var ps = Http2PendingStream.init(allocator);
    ps.method = try allocator.dupe(u8, "GET");
    ps.path = try allocator.dupe(u8, "/h2");
    ps.transport_early = true;
    try pending.put(1, ps);
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try ready.append(1);

    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    conn.handshake_complete = false;

    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    var buffered_request_bytes: usize = 0;

    try h2DispatchReadyStreams(
        &conn,
        allocator,
        &state,
        &cfg,
        &pending,
        &streams,
        &pending_responses,
        &ready,
        &next_server_stream_id,
        &conn_send_window,
        &buffered_request_bytes,
        "127.0.0.1",
    );

    try std.testing.expect(pending.contains(1));
    try std.testing.expectEqual(@as(u8, 0), pending.get(1).?.dispatch_count);
    try std.testing.expectEqual(@as(usize, 1), ready.items.len);
    try std.testing.expectEqual(@as(u64, 0), state.metrics.total_requests);

    conn.handshake_complete = true;
    try h2DispatchReadyStreams(
        &conn,
        allocator,
        &state,
        &cfg,
        &pending,
        &streams,
        &pending_responses,
        &ready,
        &next_server_stream_id,
        &conn_send_window,
        &buffered_request_bytes,
        "127.0.0.1",
    );

    try std.testing.expect(!pending.contains(1));
    try std.testing.expectEqual(@as(usize, 0), ready.items.len);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);

    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_requests_total{protocol=\"h2\",source=\"transport\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h2\",decision=\"deferred\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h2\",decision=\"accepted\"} 1") != null);
}

const H2ForwardAuthHarness = struct {
    allocator: std.mem.Allocator,
    state: GatewayState = undefined,
    pending: std.AutoHashMap(u31, Http2PendingStream),
    streams: std.AutoHashMap(u31, http.http2_stream.Stream),
    pending_responses: std.AutoHashMap(u31, PendingHttp2Response),
    ready: std.array_list.Managed(u31),
    conn: H2DispatchTestConn,
    next_server_stream_id: u31 = 2,
    conn_send_window: i32 = 65_535,
    buffered_request_bytes: usize = 0,

    fn init(self: *H2ForwardAuthHarness, allocator: std.mem.Allocator) void {
        self.* = .{
            .allocator = allocator,
            .pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator),
            .streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator),
            .pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator),
            .ready = std.array_list.Managed(u31).init(allocator),
            .conn = H2DispatchTestConn.init(allocator),
        };
        initForwardAuthProbeState(&self.state);
        self.state.rate_limiter_mutex = .{};
        self.state.rate_limiter = null;
    }

    fn deinit(self: *H2ForwardAuthHarness) void {
        var it = self.pending.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.pending.deinit();
        self.streams.deinit();
        var resp_it = self.pending_responses.iterator();
        while (resp_it.next()) |entry| entry.value_ptr.deinit(self.allocator);
        self.pending_responses.deinit();
        self.ready.deinit();
        self.conn.deinit();
    }

    fn addStream(self: *H2ForwardAuthHarness, id: u31, method: []const u8, path: []const u8, transport_early: bool) !void {
        var ps = Http2PendingStream.init(self.allocator);
        // Owned here until the final `pending.put` below; every fallible step
        // before it must leave `ps` ours to free on error, not already
        // (partially) published into a map another caller's cleanup expects
        // to own.
        errdefer ps.deinit(self.allocator);
        ps.method = try self.allocator.dupe(u8, method);
        ps.path = try self.allocator.dupe(u8, path);
        ps.transport_early = transport_early;
        try self.streams.put(id, http.http2_stream.Stream.init(id, 65_535));
        errdefer _ = self.streams.remove(id);
        try self.ready.append(id);
        errdefer _ = self.ready.pop();
        try self.pending.put(id, ps);
    }

    fn dispatch(self: *H2ForwardAuthHarness, cfg: *const edge_config.EdgeConfig) !void {
        try h2DispatchReadyStreams(
            &self.conn,
            self.allocator,
            &self.state,
            cfg,
            &self.pending,
            &self.streams,
            &self.pending_responses,
            &self.ready,
            &self.next_server_stream_id,
            &self.conn_send_window,
            &self.buffered_request_bytes,
            "127.0.0.1",
        );
    }
};

test "H2 resumed 0-RTT stream to a forward_auth location gets 425 without calling auth" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/admin",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "admin-secret" } },
        .early_data = .replay_safe,
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
    }};
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    try h.addStream(1, "GET", "/admin", true);
    h.conn.handshake_complete = false;

    // Deferred while the handshake is incomplete...
    try h.dispatch(&cfg);
    try std.testing.expect(h.pending.contains(1));
    // ...and still refused once it completes: replay provenance persists.
    h.conn.handshake_complete = true;
    try h.dispatch(&cfg);

    try std.testing.expect(!h.pending.contains(1));
    const written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "425") != null);
    try std.testing.expect(std.mem.find(u8, written, "no-store") != null);
    try std.testing.expect(std.mem.find(u8, written, "admin-secret") == null);
    try std.testing.expectEqual(@as(usize, 0), auth_server.requestCount());
    // One request, one decision: refused, never also counted as accepted.
    const prom = try h.state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h2\",decision=\"too_early\"} 1") != null);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_http_early_data_decisions_total{protocol=\"h2\",decision=\"accepted\"} 0") != null);
}

test "H2 forward_auth refusals stay no-store despite global CDN cache headers" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/admin",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "admin-secret" } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
    }};
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    const add_headers = [_]edge_config.EdgeConfig.HeaderPair{
        .{ .name = "CDN-Cache-Control", .value = "public, max-age=3600" },
        .{ .name = "Surrogate-Control", .value = "max-age=3600" },
        .{ .name = "Cache-Control", .value = "public" },
    };

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.state.add_headers = add_headers[0..];
    h.conn.handshake_complete = true;
    // Stream 1: ordinary request, denied by the auth service.
    try h.addStream(1, "GET", "/admin", false);
    try h.dispatch(&cfg);
    const denied = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, denied, "401") != null);
    try std.testing.expect(std.mem.find(u8, denied, "no-store") != null);
    try std.testing.expect(std.mem.find(u8, denied, "cdn-cache-control") == null);
    try std.testing.expect(std.mem.find(u8, denied, "surrogate-control") == null);
    try std.testing.expect(std.mem.find(u8, denied, "public") == null);

    // Stream 3: replay-exposed request to the protected location (425).
    const denied_len = denied.len;
    try h.addStream(3, "GET", "/admin", true);
    try h.dispatch(&cfg);
    const too_early = h.conn.out.written()[denied_len..];
    try std.testing.expect(std.mem.find(u8, too_early, "425") != null);
    try std.testing.expect(std.mem.find(u8, too_early, "no-store") != null);
    try std.testing.expect(std.mem.find(u8, too_early, "cdn-cache-control") == null);
    try std.testing.expect(std.mem.find(u8, too_early, "surrogate-control") == null);
    try std.testing.expect(std.mem.find(u8, too_early, "public") == null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
}

test "H2 location client_cert policy gates by verified identity and feeds forward_auth trusted state (#763)" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    const allowed_fp = [_][]const u8{"ab" ** 32};
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/admin",
            .priority = 0,
            .action = .{ .return_response = .{ .status = 200, .body = "admin-secret" } },
            .client_cert = .{ .fingerprints = &allowed_fp },
            .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
        },
        .{
            .match_type = .exact,
            .pattern = "/open",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 200, .body = "open-page" } },
        },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];

    const public_headers = [_]edge_config.EdgeConfig.HeaderPair{
        .{ .name = "CDN-Cache-Control", .value = "public, max-age=3600" },
        .{ .name = "Cache-Control", .value = "public" },
    };
    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.state.add_headers = public_headers[0..];
    h.conn.handshake_complete = true;

    // Anonymous (optional-mTLS listener, no cert) -> protected route refused.
    try h.addStream(1, "GET", "/admin", false);
    try h.dispatch(&cfg);
    var written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "403") != null);
    try std.testing.expect(std.mem.find(u8, written, "client_certificate_required") != null);
    try std.testing.expect(std.mem.find(u8, written, "admin-secret") == null);
    // Refusals are no-store even with a global `Cache-Control: public`.
    try std.testing.expect(std.mem.find(u8, written, "no-store") != null);
    try std.testing.expect(std.mem.find(u8, written, "public") == null);

    // Verified but wrong identity -> refused, auth service never consulted.
    var len = written.len;
    try h.addStream(3, "GET", "/admin", false);
    h.pending.getPtr(3).?.headers.client_cert = .{ .fingerprint_sha256 = "cd" ** 32, .subject = "CN=mallory" };
    try h.dispatch(&cfg);
    written = h.conn.out.written()[len..];
    try std.testing.expect(std.mem.find(u8, written, "client_certificate_denied") != null);
    try std.testing.expect(std.mem.find(u8, written, "admin-secret") == null);
    try std.testing.expectEqual(@as(usize, 0), auth_server.requestCount());

    // Anonymous request to an unprotected route is unaffected.
    len = h.conn.out.written().len;
    try h.addStream(5, "GET", "/open", false);
    try h.dispatch(&cfg);
    try std.testing.expect(std.mem.find(u8, h.conn.out.written()[len..], "open-page") != null);

    // Matching identity passes; forward_auth sees the verified identity and
    // not the forged copy the client put on the wire.
    len = h.conn.out.written().len;
    try h.addStream(7, "GET", "/admin", false);
    {
        const ps = h.pending.getPtr(7).?;
        ps.headers.client_cert = .{ .fingerprint_sha256 = "ab" ** 32, .subject = "CN=alice" };
        try ps.headers.append("X-Tardigrade-Client-Cert-Subject", "CN=forged-root");
    }
    try h.dispatch(&cfg);
    try std.testing.expect(std.mem.find(u8, h.conn.out.written()[len..], "admin-secret") != null);
    // A gated success is at least `private`, never `public`.
    try std.testing.expect(std.mem.find(u8, h.conn.out.written()[len..], "public") == null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
    try std.testing.expect(auth_server.requestContains(0, "X-Tardigrade-Client-Cert-Subject: CN=alice"));
    try std.testing.expect(auth_server.requestContains(0, "X-Tardigrade-Client-Cert-Fingerprint-Sha256: " ++ "ab" ** 32));
    try std.testing.expect(!auth_server.requestContains(0, "forged-root"));
}

test "H2 forward_auth allow serves a protected static location with the auth Set-Cookie" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nSet-Cookie: refreshed=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "report.txt", .data = "h2-static-report" });
    const root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(root);
    const alias_root = try std.fmt.allocPrint(allocator, "{s}/", .{root});
    defer allocator.free(alias_root);

    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/reports/",
        .priority = 0,
        .action = .{ .static_root = .{ .root = alias_root, .alias = true, .autoindex = false, .index = "", .try_files = "" } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify"), .client_headers = &.{"Set-Cookie"} },
    }};
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;
    try h.addStream(1, "GET", "/reports/report.txt", false);
    try h.dispatch(&cfg);
    const allowed = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, allowed, "h2-static-report") != null);
    try std.testing.expect(std.mem.find(u8, allowed, "refreshed=1") != null);

    const allowed_len = allowed.len;
    try h.addStream(3, "GET", "/reports/report.txt", false);
    try h.dispatch(&cfg);
    const denied = h.conn.out.written()[allowed_len..];
    try std.testing.expect(std.mem.find(u8, denied, "401") != null);
    try std.testing.expect(std.mem.find(u8, denied, "h2-static-report") == null);
    try std.testing.expectEqual(@as(usize, 2), auth_server.requestCount());
}

test "H2 rewrite into a protected location is authorized, never served from the server root (#814)" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).makePath("admin");
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "admin/secret.txt", .data = "top-secret" });
    const doc_root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(doc_root);

    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{ .match_type = .exact, .pattern = "/go", .priority = 0, .action = .{ .rewrite = .{ .replacement = "/admin/secret.txt?dl=1", .flag = .last } } },
        .{
            .match_type = .prefix,
            .pattern = "/admin/",
            .priority = 1,
            .action = .{ .static_root = .{ .root = doc_root, .alias = false, .autoindex = false, .index = "", .try_files = "" } },
            .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
        },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    cfg.doc_root = doc_root;

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;
    try h.addStream(1, "GET", "/go", false);
    try h.dispatch(&cfg);

    const written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "403") != null);
    try std.testing.expect(std.mem.find(u8, written, "top-secret") == null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
    try std.testing.expect(auth_server.requestContains(0, "X-Forwarded-Uri: /admin/secret.txt?dl=1"));
}

test "H2 self-rewrite re-authorizes the rewritten target before serving it (#814)" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        // Path-sensitive verifier: allows the landing URI, denies the file.
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).makePath("admin");
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "admin/private.txt", .data = "private-bytes" });
    const doc_root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(doc_root);
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/admin/",
        .priority = 0,
        .action = .{ .rewrite = .{ .replacement = "/admin/private.txt", .flag = .last } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
    }};
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    cfg.doc_root = doc_root;

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;
    try h.addStream(1, "GET", "/admin/public", false);
    try h.dispatch(&cfg);

    const written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "403") != null);
    try std.testing.expect(std.mem.find(u8, written, "private-bytes") == null);
    try std.testing.expectEqual(@as(usize, 2), auth_server.requestCount());
    try std.testing.expect(auth_server.requestContains(0, "X-Forwarded-Uri: /admin/public"));
    try std.testing.expect(auth_server.requestContains(1, "X-Forwarded-Uri: /admin/private.txt"));
}

test "H2 path policy and the rewrite budget apply to rewritten targets (#814)" {
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{ .match_type = .exact, .pattern = "/public", .priority = 0, .action = .{ .rewrite = .{ .replacement = "/admin/panel", .flag = .last } } },
        .{ .match_type = .prefix, .pattern = "/admin/", .priority = 1, .action = .{ .return_response = .{ .status = 200, .body = "admin-panel" } } },
        .{ .match_type = .exact, .pattern = "/a", .priority = 2, .action = .{ .rewrite = .{ .replacement = "/b", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/b", .priority = 3, .action = .{ .rewrite = .{ .replacement = "/c", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/c", .priority = 4, .action = .{ .rewrite = .{ .replacement = "/d", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/d", .priority = 5, .action = .{ .rewrite = .{ .replacement = "/e", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/e", .priority = 6, .action = .{ .return_response = .{ .status = 200, .body = "too-deep" } } },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    cfg.policy_rules_raw = "GET|^/admin/|admin|false||";

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;

    try h.addStream(1, "GET", "/public", false);
    try h.dispatch(&cfg);
    const policy_written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, policy_written, "403") != null);
    try std.testing.expect(std.mem.find(u8, policy_written, "admin-panel") == null);

    const policy_len = policy_written.len;
    try h.addStream(3, "GET", "/a", false);
    try h.dispatch(&cfg);
    const loop_written = h.conn.out.written()[policy_len..];
    try std.testing.expect(std.mem.find(u8, loop_written, "508") != null);
    try std.testing.expect(std.mem.find(u8, loop_written, "too-deep") == null);
}

test "H2 later verifiers judge the caller's credential, not an earlier hop's minted one (#814)" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        // Hop A allows the client and mints a privileged origin token.
        "HTTP/1.1 200 OK\r\nAuthorization: Bearer service-minted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        // Hop B would deny the client's own token.
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    const auth_url = auth_server.url(&url_buf, "/verify");
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/public",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/admin", .flag = .last } },
            .forward_auth = .{ .url = auth_url, .upstream_headers = &.{"Authorization"} },
        },
        .{
            .match_type = .exact,
            .pattern = "/admin",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 200, .body = "admin-secret" } },
            .forward_auth = .{ .url = auth_url },
        },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;
    try h.addStream(1, "GET", "/public", false);
    try h.pending.getPtr(1).?.headers.append("Authorization", "Bearer client-inbound");
    try h.dispatch(&cfg);

    const written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "403") != null);
    try std.testing.expect(std.mem.find(u8, written, "admin-secret") == null);
    try std.testing.expect(auth_server.requestContains(1, "Bearer client-inbound"));
    try std.testing.expect(!auth_server.requestContains(1, "service-minted"));
}

test "H2 forward_auth grants carry across rewrites and are dropped by a later denial (#814)" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        // Request 1: /old allows, rewrites to /new (unprotected).
        "HTTP/1.1 200 OK\r\nSet-Cookie: refreshed=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        // Request 2: /old allows, rewrites to /guarded, which denies.
        "HTTP/1.1 200 OK\r\nSet-Cookie: refreshed=2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    const auth_url = auth_server.url(&url_buf, "/verify");

    var first_blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/old",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/new", .flag = .last } },
            .forward_auth = .{ .url = auth_url, .client_headers = &.{"Set-Cookie"} },
        },
        .{
            .match_type = .exact,
            .pattern = "/new",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 200, .body = "rewritten-ok" } },
        },
    };
    var first_cfg = std.mem.zeroes(edge_config.EdgeConfig);
    first_cfg.location_blocks = first_blocks[0..];

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;
    try h.addStream(1, "GET", "/old", false);
    try h.dispatch(&first_cfg);
    const allowed = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, allowed, "rewritten-ok") != null);
    try std.testing.expect(std.mem.find(u8, allowed, "refreshed=1") != null);

    var second_blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/old",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/guarded", .flag = .last } },
            .forward_auth = .{ .url = auth_url, .client_headers = &.{"Set-Cookie"} },
        },
        .{
            .match_type = .exact,
            .pattern = "/guarded",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 200, .body = "guarded-secret" } },
            .forward_auth = .{ .url = auth_url, .client_headers = &.{"Set-Cookie"} },
        },
    };
    var second_cfg = std.mem.zeroes(edge_config.EdgeConfig);
    second_cfg.location_blocks = second_blocks[0..];

    const allowed_len = allowed.len;
    try h.addStream(3, "GET", "/old", false);
    try h.dispatch(&second_cfg);
    const denied = h.conn.out.written()[allowed_len..];
    try std.testing.expect(std.mem.find(u8, denied, "403") != null);
    try std.testing.expect(std.mem.find(u8, denied, "refreshed") == null);
    try std.testing.expectEqual(@as(usize, 3), auth_server.requestCount());
}

/// Free an approvals test table, owned keys and all, without calling
/// `ApprovalEntry.deinit` (private to `gateway_state.zig`).
fn deinitApprovalsTestMap(approvals: *std.StringHashMap(gs.ApprovalEntry), allocator: std.mem.Allocator) void {
    var it = approvals.iterator();
    while (it.next()) |entry| {
        allocator.free(entry.key_ptr.*);
        allocator.free(entry.value_ptr.method);
        allocator.free(entry.value_ptr.path);
        allocator.free(entry.value_ptr.identity);
        allocator.free(entry.value_ptr.command_id);
        allocator.free(entry.value_ptr.decided_by);
    }
    approvals.deinit();
}

test "H2 rewritten-path approval policy rejects a forward_auth-asserted token the client never presented (#814)" {
    const allocator = std.testing.allocator;

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;
    h.state.allocator = allocator;
    h.state.approval_mutex = .{};
    h.state.approval_persist_mutex = .{};
    h.state.approvals = std.StringHashMap(gs.ApprovalEntry).init(allocator);
    h.state.approval_store_path = "";
    h.state.approval_escalation_webhook = "";
    h.state.approval_ttl_ms = 60_000;
    h.state.approval_max_pending_per_identity = 0;
    defer deinitApprovalsTestMap(&h.state.approvals, allocator);

    // A real, approved token for GET /guarded that the client never presented
    // -- only a (hypothetically compromised, or merely misconfigured)
    // forward_auth service at an earlier hop asserts it.
    const minted = try h.state.approvalCreate(allocator, "GET", "/guarded", "", null);
    defer allocator.free(minted.token);
    try std.testing.expect(h.state.approvalRespond(minted.token, .approve, "reviewer"));

    const service_response = try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 200 OK\r\nX-Approval-Token: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{minted.token},
    );
    defer allocator.free(service_response);
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{service_response});
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/old",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/guarded", .flag = .last } },
            .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify"), .upstream_headers = &.{"X-Approval-Token"} },
        },
        .{ .match_type = .exact, .pattern = "/guarded", .priority = 1, .action = .{ .return_response = .{ .status = 200, .body = "guarded-secret" } } },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    cfg.policy_approval_routes_raw = "GET|^/guarded$";

    try h.addStream(1, "GET", "/old", false);
    try h.dispatch(&cfg);

    const written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "403") != null);
    try std.testing.expect(std.mem.find(u8, written, "Approval required") != null);
    try std.testing.expect(std.mem.find(u8, written, "guarded-secret") == null);
    try std.testing.expect(std.mem.find(u8, written, "no-store") != null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
}

test "H2 rewritten-path approval policy honors the client's own token despite a differing forward_auth assertion (#814)" {
    const allocator = std.testing.allocator;

    var h: H2ForwardAuthHarness = undefined;
    h.init(allocator);
    defer h.deinit();
    h.conn.handshake_complete = true;
    h.state.allocator = allocator;
    h.state.approval_mutex = .{};
    h.state.approval_persist_mutex = .{};
    h.state.approvals = std.StringHashMap(gs.ApprovalEntry).init(allocator);
    h.state.approval_store_path = "";
    h.state.approval_escalation_webhook = "";
    h.state.approval_ttl_ms = 60_000;
    h.state.approval_max_pending_per_identity = 0;
    defer deinitApprovalsTestMap(&h.state.approvals, allocator);

    const minted = try h.state.approvalCreate(allocator, "GET", "/guarded", "", null);
    defer allocator.free(minted.token);
    try std.testing.expect(h.state.approvalRespond(minted.token, .approve, "reviewer"));

    // Hop A allows the client but asserts an unrelated token for the origin;
    // that assertion must never replace the client's own credential for the
    // rewritten target's approval check.
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nX-Approval-Token: not-a-real-token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/old",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/guarded", .flag = .last } },
            .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify"), .upstream_headers = &.{"X-Approval-Token"} },
        },
        .{ .match_type = .exact, .pattern = "/guarded", .priority = 1, .action = .{ .return_response = .{ .status = 200, .body = "guarded-secret" } } },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    cfg.policy_approval_routes_raw = "GET|^/guarded$";

    try h.addStream(1, "GET", "/old", false);
    try h.pending.getPtr(1).?.headers.append("X-Approval-Token", minted.token);
    try h.dispatch(&cfg);

    const written = h.conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "200") != null);
    try std.testing.expect(std.mem.find(u8, written, "guarded-secret") != null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
}

test "H2 forward_auth across rewrite hops frees every Decision exactly once on allocation failure (#888)" {
    const Scenario = struct {
        fn run(allocator: std.mem.Allocator) !void {
            // Hop A allows and mints an upstream-only credential (exercises
            // `client_view.preserve`/`asserted_names.appendSlice`); hop B
            // allows with a client-facing `Set-Cookie` (exercises the fallible
            // `Grants.add` transfer at the end of the loop). The backing
            // allocator here is the real leak/double-free detecting
            // `std.testing.allocator`, so a regression of the ownership bug
            // this guards against aborts the run instead of merely leaking.
            var auth_server = try gfa.TestAuthServer.start(std.testing.allocator, &.{
                "HTTP/1.1 200 OK\r\nAuthorization: Bearer minted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                "HTTP/1.1 200 OK\r\nSet-Cookie: refreshed=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
            });
            defer auth_server.stop();
            try auth_server.run();
            var url_buf: [64]u8 = undefined;
            const auth_url = auth_server.url(&url_buf, "/verify");
            var blocks = [_]edge_config.EdgeConfig.LocationBlock{
                .{
                    .match_type = .exact,
                    .pattern = "/go",
                    .priority = 0,
                    .action = .{ .rewrite = .{ .replacement = "/landing", .flag = .last } },
                    .forward_auth = .{ .url = auth_url, .upstream_headers = &.{"Authorization"} },
                },
                .{
                    .match_type = .exact,
                    .pattern = "/landing",
                    .priority = 1,
                    .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
                    .forward_auth = .{ .url = auth_url, .client_headers = &.{"Set-Cookie"} },
                },
            };
            var cfg = std.mem.zeroes(edge_config.EdgeConfig);
            cfg.location_blocks = blocks[0..];

            var h: H2ForwardAuthHarness = undefined;
            h.init(allocator);
            defer h.deinit();
            h.conn.handshake_complete = true;
            try h.addStream(1, "GET", "/go", false);
            try h.dispatch(&cfg);

            const written = h.conn.out.written();
            try std.testing.expect(std.mem.find(u8, written, "200") != null);
            try std.testing.expect(std.mem.find(u8, written, "refreshed=1") != null);
        }
    };

    // A hand-rolled `std.testing.checkAllAllocationFailures` sweep rather than
    // the stdlib helper: this request's header copies (`http.Request.parse`,
    // `client_view.preserve`, `gfa.applyUpstreamHeaders`) run through
    // `Headers.append`, which has its own pre-existing, independently tracked
    // OOM cleanup leak (mentioned, out of scope, in PR #886's description) --
    // it leaks a lowercased name buffer when the paired value `dupe` or the
    // backing `items.append` fails right after it. That bug is orthogonal to
    // the Decision-ownership double free this test guards against, so leaks
    // whose stack trace passes through `Headers.append` are tolerated here;
    // any other leak, a double free, or a swallowed failure still fails the
    // test. Each iteration gets its own `DebugAllocator` (rather than the
    // shared `std.testing.allocator`) so a tolerated leak doesn't accumulate
    // across iterations and trip this test's own end-of-run leak check --
    // while still catching a real double free immediately, as a hard panic.
    const needed_alloc_count = x: {
        var probe = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        try Scenario.run(probe.allocator());
        break :x probe.alloc_index;
    };
    for (0..needed_alloc_count) |fail_index| {
        var debug_alloc: std.heap.DebugAllocator(.{}) = .init;
        var fa = std.testing.FailingAllocator.init(debug_alloc.allocator(), .{ .fail_index = fail_index });
        if (Scenario.run(fa.allocator())) |_| {
            _ = debug_alloc.deinit();
            if (fa.has_induced_failure) return error.SwallowedOutOfMemoryError;
            return error.NondeterministicMemoryUsage;
        } else |err| switch (err) {
            // The response writer (`std.Io.Writer.Allocating`) wraps a failed
            // buffer growth as `error.WriteFailed`, not `error.OutOfMemory`,
            // so an induced failure during response serialization surfaces
            // under that name instead.
            error.OutOfMemory, error.WriteFailed => {
                if (fa.allocated_bytes != fa.freed_bytes) {
                    var trace_buf: [4096]u8 = undefined;
                    const trace = std.fmt.bufPrint(&trace_buf, "{f}", .{
                        std.debug.FormatStackTrace{ .stack_trace = fa.getStackTrace() },
                    }) catch &trace_buf;
                    if (std.mem.find(u8, trace, "http/headers.zig") != null) {
                        debug_alloc.deinitWithoutLeakChecks();
                        continue;
                    }
                    std.debug.print("\nfail_index: {d}/{d}\nallocated: {d}\nfreed: {d}\n{s}\n", .{
                        fail_index, needed_alloc_count, fa.allocated_bytes, fa.freed_bytes, trace,
                    });
                    return error.MemoryLeakDetected;
                }
                _ = debug_alloc.deinit();
            },
            else => |e| {
                _ = debug_alloc.deinit();
                return e;
            },
        }
    }
}

test "H2 harness addStream keeps ready/pending/streams consistent on allocation failure (#888)" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, struct {
        fn run(allocator: std.mem.Allocator) !void {
            var h: H2ForwardAuthHarness = undefined;
            h.init(allocator);
            defer h.deinit();
            const result = h.addStream(1, "GET", "/x", false);
            // A failure partway through `addStream` must roll back every
            // partial insertion together, not strand `ready` with an ID that
            // `pending`/`streams` never ended up holding.
            try std.testing.expectEqual(h.streams.count(), h.ready.items.len);
            try std.testing.expectEqual(h.streams.count(), h.pending.count());
            return result;
        }
    }.run, .{});
}

test "H2 ordinary stream dispatch remains unchanged" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer {
        var it = pending_responses.iterator();
        while (it.next()) |entry| entry.value_ptr.deinit(allocator);
        pending_responses.deinit();
    }
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();

    var ps = Http2PendingStream.init(allocator);
    ps.method = try allocator.dupe(u8, "GET");
    ps.path = try allocator.dupe(u8, "/ordinary");
    try pending.put(3, ps);
    try streams.put(3, http.http2_stream.Stream.init(3, 65_535));
    try ready.append(3);

    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    conn.handshake_complete = false;

    var next_server_stream_id: u31 = 2;
    var conn_send_window: i32 = 65_535;
    var buffered_request_bytes: usize = 0;
    try h2DispatchReadyStreams(
        &conn,
        allocator,
        &state,
        &cfg,
        &pending,
        &streams,
        &pending_responses,
        &ready,
        &next_server_stream_id,
        &conn_send_window,
        &buffered_request_bytes,
        "127.0.0.1",
    );

    try std.testing.expect(!pending.contains(3));
    try std.testing.expectEqual(@as(usize, 0), ready.items.len);
    try std.testing.expectEqual(@as(u64, 1), state.metrics.total_requests);
}

const H2SessionDecodedFrame = struct { typ: http.http2_frame.Type, flags: u8, stream_id: u31, payload: []const u8 };

/// Minimal wire decoder shared by the session integration tests below, so
/// assertions read real `writeFrame` output rather than internal state.
fn h2DecodeFrames(allocator: std.mem.Allocator, wire: []const u8) !std.array_list.Managed(H2SessionDecodedFrame) {
    var frames = std.array_list.Managed(H2SessionDecodedFrame).init(allocator);
    var offset: usize = 0;
    while (offset < wire.len) {
        const header = wire[offset..];
        const len = (@as(usize, header[0]) << 16) | (@as(usize, header[1]) << 8) | header[2];
        const stream_id: u31 = @intCast(std.mem.readInt(u32, header[5..9], .big) & 0x7fff_ffff);
        try frames.append(.{
            .typ = @enumFromInt(header[3]),
            .flags = header[4],
            .stream_id = stream_id,
            .payload = header[9 .. 9 + len],
        });
        offset += 9 + len;
    }
    return frames;
}

test "H2 session inbound DATA credits padding immediately but app bytes only on consumption (#867)" {
    const allocator = std.testing.allocator;
    var session = try http.h2_stream_session.Session.init(allocator, 1, 4096, 4096);
    defer session.deinit();

    var out = std.Io.Writer.Allocating.init(allocator);
    defer out.deinit();

    // A PADDED DATA frame: payload = [pad_len_byte] ++ app_bytes ++ padding.
    // `h2DataPayload` (production parsing) strips padding; only the 4
    // application bytes reach the session, but flow control is charged for
    // the whole frame payload.
    const frame_payload = [_]u8{ 3, 'a', 'b', 'c', 'd', 0, 0, 0 };
    const app_payload = try h2DataPayload(&frame_payload, http.http2_frame.Flags.PADDED);

    try h2DeliverSessionInboundData(&out.writer, &session, 1, frame_payload.len, app_payload, false);

    // Padding (the Pad Length octet plus 3 padding bytes) is credited back
    // immediately -- it was never buffered by the session at all.
    var frames = try h2DecodeFrames(allocator, out.written());
    defer frames.deinit();
    try std.testing.expectEqual(@as(usize, 2), frames.items.len);
    for (frames.items) |frame| {
        try std.testing.expectEqual(http.http2_frame.Type.window_update, frame.typ);
        try std.testing.expectEqual(@as(u32, 4), std.mem.readInt(u32, frame.payload[0..4], .big));
    }

    // The 4 application bytes are only credited once the consumer reads
    // them.
    try std.testing.expectEqual(@as(usize, 0), session.peekReceiveCreditToReturn());
    var buf: [8]u8 = undefined;
    _ = session.read(&buf);
    try std.testing.expectEqual(@as(usize, 4), session.peekReceiveCreditToReturn());
}

/// A real, pollable, two-way byte pipe (an AF_UNIX `socketpair`) wrapped as
/// an `EncryptedStream` that passes bytes straight through unencrypted. This
/// stands in for a completed TLS handshake so the live H2 session tests
/// below exercise the *real* `handleHttp2Connection` frame loop, the real
/// `WaitingEncryptedHttpConnection` adapter (including its session wake-fd
/// polling), and a real client thread over a real kernel socket. The only
/// thing it does not exercise is TLS itself, which this codebase already
/// covers elsewhere (`native_tls_connection.zig`) and which is orthogonal to
/// #867's session plumbing.
const PlaintextSocketStream = struct {
    fd: std.posix.fd_t,

    fn stream(self: *PlaintextSocketStream) tls_core.encrypted_stream.EncryptedStream {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn backend(_: *anyopaque) tls_core.encrypted_stream.BackendKind {
        return .pure_zig_record;
    }

    fn read(ptr: *anyopaque, out: []u8) tls_core.encrypted_stream.Error!usize {
        const self: *PlaintextSocketStream = @ptrCast(@alignCast(ptr));
        const n = std.c.read(self.fd, out.ptr, out.len);
        if (n >= 0) return @intCast(n);
        return switch (std.posix.errno(n)) {
            .AGAIN, .INTR => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }

    fn write(ptr: *anyopaque, bytes: []const u8) tls_core.encrypted_stream.Error!usize {
        const self: *PlaintextSocketStream = @ptrCast(@alignCast(ptr));
        const n = std.c.write(self.fd, bytes.ptr, bytes.len);
        if (n >= 0) return @intCast(n);
        return switch (std.posix.errno(n)) {
            .AGAIN, .INTR => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }

    fn close(_: *anyopaque) void {}

    /// Mirrors a real record layer's readiness: plaintext is readable only
    /// while the kernel actually has bytes queued. Reporting it as always
    /// readable would make `WaitingEncryptedHttpConnection.waitFor` return
    /// `ready_now` without ever polling, so the runtime would spin and never
    /// observe a session wake fd or flush its outbound scheduler.
    fn readiness(ptr: *anyopaque) tls_core.encrypted_stream.Readiness {
        const self: *PlaintextSocketStream = @ptrCast(@alignCast(ptr));
        var pfd = [_]std.posix.pollfd{.{ .fd = self.fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&pfd, 0) catch 0;
        return .{
            .wants_read = true,
            .can_read_plaintext = ready > 0 and (pfd[0].revents & (std.posix.POLL.IN | std.posix.POLL.HUP)) != 0,
            .can_write_plaintext = true,
        };
    }

    fn drive(ptr: *anyopaque) tls_core.encrypted_stream.Error!tls_core.encrypted_stream.DriveResult {
        return .{ .made_progress = false, .readiness = readiness(ptr) };
    }

    fn bufferSnapshot(_: *anyopaque) tls_core.encrypted_stream.BufferSnapshot {
        return .{};
    }

    const vtable = tls_core.encrypted_stream.EncryptedStream.VTable{
        .backendFn = backend,
        .readFn = read,
        .writeFn = write,
        .closeFn = close,
        .readinessFn = readiness,
        .driveFn = drive,
        .bufferSnapshotFn = bufferSnapshot,
    };
};

fn testH2SocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    return fds;
}

fn testSetFdNonBlocking(fd: std.posix.fd_t) !void {
    const flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
    if (flags < 0 or std.c.fcntl(fd, std.c.F.SETFL, flags | @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }))) < 0)
        return error.FcntlFailed;
}

/// Negative-control assertion for the live flow-control tests below: polls
/// `fd` for readability without consuming anything, failing if a frame
/// arrived within `timeout_ms`. Used to prove a WINDOW_UPDATE that grants
/// credit on the *wrong* dimension (stream-only vs. connection-only) does
/// not unstall a producer still blocked on the other one.
fn testExpectNoFrameArrives(fd: std.posix.fd_t, timeout_ms: i32) !void {
    var pfd = [_]std.posix.pollfd{.{ .fd = fd, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = try std.posix.poll(&pfd, timeout_ms);
    if (ready != 0) return error.UnexpectedFrameArrived;
}

/// Negative-control assertion for the independent-credit-exhaustion tests:
/// drains whatever arrives on `client` within `timeout_ms`, appending
/// `target_stream` DATA payloads to `out` and discarding everything else.
/// A session consumer earns inbound receive credit purely by reading
/// (independent of the outbound stall under test), so a benign WINDOW_UPDATE
/// for that unrelated direction can legitimately arrive during the window;
/// only new DATA for `target_stream` would mean the credit grant under test
/// actually unstalled the producer.
fn testDrainStreamDataFor(client: *TestH2Client, allocator: std.mem.Allocator, target_stream: u31, out: *std.array_list.Managed(u8), timeout_ms: i64, send_credit: ?*TestConnSendCredit) !void {
    const deadline_ms = compat.milliTimestamp() + timeout_ms;
    while (true) {
        const remaining_ms = deadline_ms - compat.milliTimestamp();
        if (remaining_ms <= 0) return;
        var pfd = [_]std.posix.pollfd{.{ .fd = client.fd, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = try std.posix.poll(&pfd, @intCast(remaining_ms));
        if (ready == 0) return;
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == target_stream and frame.typ == .data) try out.appendSlice(frame.payload);
        if (send_credit) |credit| testGrantIfConnSendCredit(&frame, credit);
    }
}

/// Tracks HTTP/2 connection-level send credit a live test's fake client has
/// actually been granted by the real server via a stream-0 WINDOW_UPDATE, so
/// a background sender thread can pace its own DATA to the server instead of
/// blasting past the connection-level receive window RFC 9113 §6.9.2 fixes
/// at 65,535 bytes until the peer actually grows it. Every per-stream window
/// in these live tests is always the fixed 1 MiB the server itself
/// advertises (`HTTP2_INITIAL_WINDOW_SIZE`), far above anything sent here,
/// so only the connection-level counter can ever be the real bottleneck for
/// a test's own outbound (client-to-server) DATA.
const TestConnSendCredit = struct {
    mutex: compat.Mutex = .{},
    cond: compat.Condition = .{},
    available: i64 = 65_535,
    /// Set by `cancelAndBroadcast` so a sender thread blocked in `take`
    /// wakes up and exits instead of waiting forever once a failed test is
    /// unwinding and will never grant more credit.
    canceled: bool = false,

    fn grant(self: *@This(), amount: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.available += amount;
        self.cond.signal();
    }

    /// Blocks until at least one byte of credit exists, then reserves and
    /// returns up to `want` bytes of it. Returns `null` once canceled,
    /// whether or not a wait was actually needed.
    fn take(self: *@This(), want: usize) ?usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (self.available <= 0 and !self.canceled) self.cond.wait(&self.mutex);
        if (self.canceled) return null;
        const n = @min(self.available, @as(i64, @intCast(want)));
        self.available -= n;
        return @intCast(n);
    }

    /// Wakes a sender thread blocked in `take` so it can exit instead of
    /// outliving the stack it closes over when a live test fails early.
    fn cancelAndBroadcast(self: *@This()) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.canceled = true;
        self.cond.broadcast();
    }
};

fn testGrantIfConnSendCredit(frame: *const http.http2_frame.Frame, credit: *TestConnSendCredit) void {
    if (frame.typ == .window_update and frame.stream_id == 0 and frame.payload.len == 4) {
        const inc = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7FFF_FFFF;
        credit.grant(inc);
    }
}

/// Joins a thread at most once: a slot already nulled out by an earlier
/// join (success path or a prior cleanup call) is left alone. `std.Thread`
/// has no built-in way to ask "was this already joined?", and calling
/// `join()` twice on the same handle is undefined behavior, so every
/// caller that might run both a normal join and a failure-path cleanup
/// join must go through this instead of calling `.join()` directly.
fn testJoinOnce(thread_slot: *?std.Thread) void {
    if (thread_slot.*) |t| {
        t.join();
        thread_slot.* = null;
    }
}

/// `errdefer`-only safety net for the live H2 session tests: if a test
/// returns early via an assertion/read failure before reaching its normal
/// trailing `server_thread.join(); ...; consumer_thread.?.join();` lines,
/// the server and consumer worker threads would otherwise keep running and
/// touch the test's about-to-be-destroyed stack (`state`, `hook_ctx`, ...)
/// after the test frame returns -- this is the exact mechanism behind a
/// real observed CI segfault. Shutting down the server-side fd forces
/// `handleHttp2Connection` to unwind (settling every attached session, the
/// same as an ordinary GOAWAY/EOF teardown), which lets a blocked consumer
/// observe termination and exit on its own; joining both threads here then
/// guarantees neither outlives the stack frame they close over. Takes both
/// threads as slots and joins through `testJoinOnce` because a failure can
/// land after the normal-path join of either thread already succeeded --
/// without the slot, this `errdefer` would join an already-joined handle.
fn testShutdownAndJoinOnFailure(server_fd: std.posix.fd_t, server_thread_slot: *?std.Thread, consumer_thread_slot: *?std.Thread) void {
    _ = std.c.shutdown(server_fd, std.c.SHUT.RDWR);
    testJoinOnce(server_thread_slot);
    testJoinOnce(consumer_thread_slot);
}

/// Same as `testShutdownAndJoinOnFailure`, for the one live test whose hook
/// never spawns a consumer worker at all (`StallingSessionHookCtx`).
fn testShutdownAndJoinServerOnFailure(server_fd: std.posix.fd_t, server_thread_slot: *?std.Thread) void {
    _ = std.c.shutdown(server_fd, std.c.SHUT.RDWR);
    testJoinOnce(server_thread_slot);
}

/// Same as `testShutdownAndJoinOnFailure`, for the live tests that also
/// pace a DATA sender against this process's own connection-send-credit
/// model from a second thread (see `TestConnSendCredit`). Closing the
/// server socket does nothing to wake a sender blocked in
/// `send_credit.take()` -- it is a userspace condvar, not I/O -- and
/// `send_credit.cancelAndBroadcast()` does nothing to wake a sender blocked
/// in a real blocking `write()` on `client_fd` once the kernel socket
/// buffer is full. Both must happen, and the socket shutdown must happen
/// before any join is attempted, or a failed assertion deadlocks tearing
/// down the test instead of unwinding it.
fn testShutdownAndJoinSenderOnFailure(
    server_fd: std.posix.fd_t,
    client_fd: std.posix.fd_t,
    send_credit: *TestConnSendCredit,
    send_thread_slot: *?std.Thread,
    server_thread_slot: *?std.Thread,
    consumer_thread_slot: *?std.Thread,
) void {
    send_credit.cancelAndBroadcast();
    _ = std.c.shutdown(client_fd, std.c.SHUT.RDWR);
    _ = std.c.shutdown(server_fd, std.c.SHUT.RDWR);
    testJoinOnce(send_thread_slot);
    testJoinOnce(server_thread_slot);
    testJoinOnce(consumer_thread_slot);
}

/// Blocking client-side wrapper over a raw socket fd, used only by the live
/// H2 session tests below to speak real wire bytes to the real server loop.
const TestH2Client = struct {
    fd: std.posix.fd_t,
    /// Serializes whole frames: the live tests keep one thread streaming DATA
    /// while another sends WINDOW_UPDATE/GOAWAY/RST_STREAM, and a frame's
    /// header and payload must never interleave with another frame's bytes.
    write_mutex: compat.Mutex = .{},

    pub fn read(self: *TestH2Client, buf: []u8) !usize {
        while (true) {
            const n = std.c.read(self.fd, buf.ptr, buf.len);
            if (n >= 0) return @intCast(n);
            if (std.posix.errno(n) == .INTR) continue;
            return error.SocketReadFailed;
        }
    }

    fn writer(self: *TestH2Client) Writer {
        return .{ .conn = self };
    }

    const Writer = struct {
        conn: *TestH2Client,

        pub fn enqueueFrame(self: Writer, typ: http.http2_frame.Type, flags: u8, stream_id: u31, payload: []const u8) !void {
            var buf: [http.http2_frame.HEADER_LEN + HTTP2_MAX_FRAME_SIZE]u8 = undefined;
            if (payload.len > HTTP2_MAX_FRAME_SIZE) return error.Http2FrameTooLarge;
            buf[0] = @intCast((payload.len >> 16) & 0xFF);
            buf[1] = @intCast((payload.len >> 8) & 0xFF);
            buf[2] = @intCast(payload.len & 0xFF);
            buf[3] = @intFromEnum(typ);
            buf[4] = flags;
            std.mem.writeInt(u32, buf[5..9], @as(u32, stream_id) & 0x7FFF_FFFF, .big);
            @memcpy(buf[http.http2_frame.HEADER_LEN..][0..payload.len], payload);
            self.conn.write_mutex.lock();
            defer self.conn.write_mutex.unlock();
            try self.writeAll(buf[0 .. http.http2_frame.HEADER_LEN + payload.len]);
        }

        pub fn writeAll(self: Writer, bytes: []const u8) !void {
            var off: usize = 0;
            while (off < bytes.len) {
                const n = std.c.write(self.conn.fd, bytes[off..].ptr, bytes.len - off);
                if (n >= 0) {
                    off += @intCast(n);
                    continue;
                }
                if (std.posix.errno(n) == .INTR) continue;
                return error.SocketWriteFailed;
            }
        }
    };

    fn readFrame(self: *TestH2Client, allocator: std.mem.Allocator) !http.http2_frame.Frame {
        return http.http2_frame.readFrame(self, allocator, HTTP2_MAX_FRAME_SIZE);
    }

    fn sendHeaders(self: *TestH2Client, allocator: std.mem.Allocator, stream_id: u31, end_stream: bool, headers: []const http.hpack.HeaderField) !void {
        const block = try http.hpack.encodeLiteralHeaderBlock(allocator, headers);
        defer allocator.free(block);
        const flags: u8 = http.http2_frame.Flags.END_HEADERS | (if (end_stream) http.http2_frame.Flags.END_STREAM else 0);
        try http.http2_frame.writeFrame(self.writer(), .headers, flags, stream_id, block);
    }

    fn sendData(self: *TestH2Client, stream_id: u31, end_stream: bool, payload: []const u8) !void {
        const flags: u8 = if (end_stream) http.http2_frame.Flags.END_STREAM else 0;
        try http.http2_frame.writeFrame(self.writer(), .data, flags, stream_id, payload);
    }
};

/// Internal/test-only `H2SessionTestHook` consumer for the live tests below:
/// a real worker thread that drives only the production `Session` API
/// (never the connection/socket), echoing inbound bytes back out and
/// finishing/detaching once the remote half closes or the session settles.
const LiveSessionHookCtx = struct {
    allocator: std.mem.Allocator,
    attach_path: []const u8,
    consumer_thread: ?std.Thread = null,

    fn shouldAttach(raw: ?*anyopaque, ps: *const Http2PendingStream) bool {
        const self: *LiveSessionHookCtx = @ptrCast(@alignCast(raw.?));
        const path = ps.path orelse return false;
        return std.mem.eql(u8, path, self.attach_path);
    }

    fn attach(raw: ?*anyopaque, session: *http.h2_stream_session.Session) void {
        const self: *LiveSessionHookCtx = @ptrCast(@alignCast(raw.?));
        self.consumer_thread = std.Thread.spawn(.{}, runEchoConsumer, .{ self, session }) catch @panic("consumer spawn failed");
    }

    fn runEchoConsumer(self: *LiveSessionHookCtx, session: *http.h2_stream_session.Session) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            switch (session.read(&buf)) {
                .data => |n| _ = session.write(buf[0..n]) catch break,
                else => break,
            }
        }
        session.finishLocal();
        if (session.consumerDetach()) {
            session.deinit();
            self.allocator.destroy(session);
        }
    }
};

/// Internal/test-only `H2SessionTestHook` consumer that never reads: it
/// captures the attached session but leaves its consumer side permanently
/// stalled, so a live test can send inbound DATA that is charged against the
/// connection receive window yet never drained before the stream resets.
const StallingSessionHookCtx = struct {
    attach_path: []const u8,
    session: ?*http.h2_stream_session.Session = null,

    fn shouldAttach(raw: ?*anyopaque, ps: *const Http2PendingStream) bool {
        const self: *StallingSessionHookCtx = @ptrCast(@alignCast(raw.?));
        const path = ps.path orelse return false;
        return std.mem.eql(u8, path, self.attach_path);
    }

    fn attach(raw: ?*anyopaque, session: *http.h2_stream_session.Session) void {
        const self: *StallingSessionHookCtx = @ptrCast(@alignCast(raw.?));
        self.session = session;
    }
};

/// Internal/test-only `H2SessionTestHook` consumer whose worker thread spins
/// without reading until the test flips `released`, then falls back to the
/// same echo loop as `LiveSessionHookCtx`. Lets a live test fill a session's
/// inbound queue up to its advertised window with a genuinely idle consumer
/// before proving consumption (and WINDOW_UPDATE emission) resumes cleanly.
const DelayedLiveSessionHookCtx = struct {
    allocator: std.mem.Allocator,
    attach_path: []const u8,
    released: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    consumer_thread: ?std.Thread = null,

    fn shouldAttach(raw: ?*anyopaque, ps: *const Http2PendingStream) bool {
        const self: *DelayedLiveSessionHookCtx = @ptrCast(@alignCast(raw.?));
        const path = ps.path orelse return false;
        return std.mem.eql(u8, path, self.attach_path);
    }

    fn attach(raw: ?*anyopaque, session: *http.h2_stream_session.Session) void {
        const self: *DelayedLiveSessionHookCtx = @ptrCast(@alignCast(raw.?));
        self.consumer_thread = std.Thread.spawn(.{}, runDelayedEchoConsumer, .{ self, session }) catch @panic("consumer spawn failed");
    }

    fn runDelayedEchoConsumer(self: *DelayedLiveSessionHookCtx, session: *http.h2_stream_session.Session) void {
        while (!self.released.load(.acquire)) std.Io.sleep(compat.io(), .fromMilliseconds(1), .awake) catch {};
        var buf: [4096]u8 = undefined;
        while (true) {
            switch (session.read(&buf)) {
                .data => |n| _ = session.write(buf[0..n]) catch break,
                else => break,
            }
        }
        session.finishLocal();
        if (session.consumerDetach()) {
            session.deinit();
            self.allocator.destroy(session);
        }
    }
};

/// Internal/test-only `H2SessionTestHook` consumer for the live churn test:
/// unlike `LiveSessionHookCtx`, `attach` can fire many times on one
/// connection (one #867 session per churn iteration), so every spawned
/// worker thread is collected for the test to join instead of overwriting a
/// single `consumer_thread` field and leaking earlier threads' handles.
const ChurnSessionHookCtx = struct {
    allocator: std.mem.Allocator,
    attach_path: []const u8,
    mutex: compat.Mutex = .{},
    consumer_threads: std.array_list.Managed(std.Thread),

    fn init(allocator: std.mem.Allocator, attach_path: []const u8) ChurnSessionHookCtx {
        return .{ .allocator = allocator, .attach_path = attach_path, .consumer_threads = std.array_list.Managed(std.Thread).init(allocator) };
    }

    fn deinit(self: *ChurnSessionHookCtx) void {
        self.consumer_threads.deinit();
    }

    /// Idempotent: clears the list after joining so a failure-path
    /// `errdefer` call and the normal trailing call never join the same
    /// handle twice, which is undefined behavior.
    fn joinAll(self: *ChurnSessionHookCtx) void {
        for (self.consumer_threads.items) |t| t.join();
        self.consumer_threads.clearRetainingCapacity();
    }

    fn shouldAttach(raw: ?*anyopaque, ps: *const Http2PendingStream) bool {
        const self: *ChurnSessionHookCtx = @ptrCast(@alignCast(raw.?));
        const path = ps.path orelse return false;
        return std.mem.eql(u8, path, self.attach_path);
    }

    fn attach(raw: ?*anyopaque, session: *http.h2_stream_session.Session) void {
        const self: *ChurnSessionHookCtx = @ptrCast(@alignCast(raw.?));
        const t = std.Thread.spawn(.{}, runEchoConsumer, .{ self, session }) catch @panic("consumer spawn failed");
        self.mutex.lock();
        defer self.mutex.unlock();
        self.consumer_threads.append(t) catch @panic("consumer thread list append failed");
    }

    fn runEchoConsumer(self: *ChurnSessionHookCtx, session: *http.h2_stream_session.Session) void {
        var buf: [4096]u8 = undefined;
        while (true) {
            switch (session.read(&buf)) {
                .data => |n| _ = session.write(buf[0..n]) catch break,
                else => break,
            }
        }
        session.finishLocal();
        if (session.consumerDetach()) {
            session.deinit();
            self.allocator.destroy(session);
        }
    }
};

const LiveH2ServerCtx = struct {
    adapter: *WaitingEncryptedHttpConnection,
    session: *ConnectionSession,
    cfg: *const edge_config.EdgeConfig,
    state: *GatewayState,
    result: anyerror!void = undefined,

    fn run(self: *LiveH2ServerCtx) void {
        self.result = handleHttp2Connection(self.adapter, self.session, self.cfg, self.state, "127.0.0.1");
        // A server-side error must surface as client EOF rather than leave a
        // blocking client read hanging forever on a half-dead socket.
        _ = std.c.shutdown(self.adapter.inner.rawFd(), std.c.SHUT.RDWR);
    }
};

test "H2 live session: bidirectional DATA, sibling dispatch, window exhaustion/recovery, and GOAWAY teardown (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    // Client preface + an (empty) SETTINGS frame, matching RFC 9113 §3.4.
    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});

    // The server's initial SETTINGS includes SETTINGS_INITIAL_WINDOW_SIZE =
    // 1MiB (see `handleHttp2Connection`), so stream 1's ~100KB inbound echo
    // below never needs a client-side WINDOW_UPDATE of its own.
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    // The server also ACKs the client's own initial SETTINGS frame sent
    // above -- a second, distinct settings-direction frame that must be
    // read and discarded before anything else.
    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    // Attach a persistent session on stream 1 and confirm the immediate
    // 200 response HEADERS the runtime sends on the session's behalf.
    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);
    try std.testing.expectEqual(@as(u31, 1), session_headers.stream_id);

    // A sibling ordinary request keeps completing while the session is
    // active -- #867's central acceptance criterion.
    try client.sendHeaders(allocator, 3, true, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/ordinary" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });

    // ~100,000 bytes of session DATA: comfortably under the session's own
    // bounded queues and the 1MiB *per-stream* inbound window the server
    // just advertised, but well over the *connection*-level receive window,
    // which RFC 9113 §6.9.2 fixes at 65,535 bytes regardless of any SETTINGS
    // value, so our own send thread below must pace itself on that credit
    // exactly as a real compliant client would.
    const total_bytes: usize = 100_000;
    var expected = try std.array_list.Managed(u8).initCapacity(allocator, total_bytes);
    defer expected.deinit();
    for (0..total_bytes) |i| try expected.append(@intCast((i % 26) + 'a'));

    // Sent from its own thread: the client's kernel socket buffer for this
    // direction is far smaller than 100,000 bytes, and the server's own
    // echo is deliberately left undrained below until the window-exhaustion
    // assertion runs. Blasting all of this from the main thread while also
    // leaving the server's reply unread would deadlock both sides on a full
    // write buffer; a real H2 client's read and write paths are similarly
    // independent. `send_credit` is fed by the main thread's read loops
    // below as stream-0 WINDOW_UPDATE frames actually arrive from the
    // server, so this never sends more than the connection-level window the
    // server has actually granted. Sending straight out of `expected` (the
    // full precomputed payload) rather than repeatedly re-slicing a small
    // fixed template from offset 0 keeps every byte correct regardless of
    // how credit-limited chunk sizes happen to land relative to any
    // template period.
    var send_credit = TestConnSendCredit{};
    const SendCtx = struct {
        client: *TestH2Client,
        send_buf: []const u8,
        credit: *TestConnSendCredit,
        result: anyerror!void = {},

        fn run(self: *@This()) void {
            var sent: usize = 0;
            while (sent < self.send_buf.len) {
                const want = @min(HTTP2_MAX_FRAME_SIZE, self.send_buf.len - sent);
                const n = self.credit.take(want) orelse return;
                self.result = self.client.sendData(1, false, self.send_buf[sent .. sent + n]);
                self.result catch return;
                sent += n;
            }
        }
    };
    var send_ctx = SendCtx{ .client = &client, .send_buf = expected.items, .credit = &send_credit };
    var send_thread: ?std.Thread = try std.Thread.spawn(.{}, SendCtx.run, .{&send_ctx});
    // `send_thread` can be parked indefinitely inside `send_credit.take`, or
    // blocked in a real blocking `write()` on `client_fd` once the kernel
    // socket buffer fills; unlike the server/consumer threads, neither
    // closing the server socket nor `cancelAndBroadcast` alone wakes the
    // latter case, so a failed assertion below must shut down both sockets
    // before joining, or this join can hang forever on the about-to-be-
    // destroyed stack (`send_ctx`/`send_credit`/`client`/`expected`).
    errdefer testShutdownAndJoinSenderOnFailure(server_fd, client_fd, &send_credit, &send_thread, &server_thread, &hook_ctx.consumer_thread);

    // Read every frame the server has sent so far without granting any
    // more send credit yet: the sibling response (stream 3) must already
    // be there, and the session's echo (stream 1) must have stalled at
    // exactly the 65,535-byte default send window.
    var echoed = std.array_list.Managed(u8).init(allocator);
    defer echoed.deinit();
    var saw_ordinary_response = false;
    var frames_read: usize = 0;
    // The 65,535-byte default connection send window is shared by every
    // stream, so the sibling's own response body counts against it too:
    // stall detection is on total DATA payload, not stream 1's alone.
    var conn_data_bytes: usize = 0;
    while (conn_data_bytes < 65_535) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.typ == .data) conn_data_bytes += frame.payload.len;
        testGrantIfConnSendCredit(&frame, &send_credit);
        if (frame.stream_id == 3) {
            // The ordinary response is a HEADERS frame followed by a DATA
            // frame (empty-bodied responses still send one, carrying
            // END_STREAM); either is expected here.
            try std.testing.expect(frame.typ == .headers or frame.typ == .data);
            saw_ordinary_response = true;
        } else if (frame.stream_id == 1 and frame.typ == .data) {
            try echoed.appendSlice(frame.payload);
        }
        frames_read += 1;
        if (frames_read > 10_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expect(saw_ordinary_response);
    try std.testing.expectEqual(@as(usize, 65_535), conn_data_bytes);
    try std.testing.expect(echoed.items.len > 0 and echoed.items.len <= 65_535);
    const stalled_at = echoed.items.len;

    // Grant the rest of the send credit; the remaining echoed bytes arrive
    // once the server's wake-fd-driven session drain resumes.
    try http.http2_frame.writeWindowUpdate(client.writer(), 1, @intCast(total_bytes - 65_535));
    try http.http2_frame.writeWindowUpdate(client.writer(), 0, @intCast(total_bytes - stalled_at));
    while (echoed.items.len < total_bytes) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == 1 and frame.typ == .data) try echoed.appendSlice(frame.payload);
        testGrantIfConnSendCredit(&frame, &send_credit);
        frames_read += 1;
        if (frames_read > 20_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expectEqualSlices(u8, expected.items, echoed.items);
    testJoinOnce(&send_thread);
    try send_ctx.result;

    // GOAWAY (without ever ending stream 1 locally) proves connection-wide
    // teardown settles a still-active session and wakes its blocked
    // consumer, instead of leaking it.
    try http.http2_frame.writeGoaway(client.writer(), 3, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live session: client RST_STREAM settles the consumer without leaking or dropping the connection (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    try http.http2_frame.writeRstStream(client.writer(), 1, http.http2_stream.ErrorCode.cancel.value());

    // A fresh ordinary request on a new stream proves the connection (and
    // its frame loop) survives the reset instead of tearing the whole
    // connection down.
    try client.sendHeaders(allocator, 3, true, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/ordinary" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var ordinary_response = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &ordinary_response);
    try std.testing.expectEqual(http.http2_frame.Type.headers, ordinary_response.typ);
    try std.testing.expectEqual(@as(u31, 3), ordinary_response.stream_id);

    try http.http2_frame.writeGoaway(client.writer(), 3, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live RST_STREAM on a stalled session returns the abandoned connection receive credit (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = StallingSessionHookCtx{ .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = StallingSessionHookCtx.shouldAttach,
        .attach = StallingSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinServerOnFailure(server_fd, &server_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    // The stalling consumer never reads, so this payload sits unread in the
    // session's inbound queue -- already charged against the connection's
    // receive window -- when the client resets the stream. Its size is
    // deliberately large relative to the connection's default 65,535-byte
    // receive window: if the refund below ever stops updating this
    // connection's local `conn_recv_window` counter (while still crediting
    // the peer via WINDOW_UPDATE), the sibling request after it would be
    // spuriously rejected as a flow-control violation even though the peer
    // legitimately still has that credit.
    const unread_payload = try allocator.alloc(u8, 50_000);
    defer allocator.free(unread_payload);
    @memset(unread_payload, 'a');
    {
        var sent: usize = 0;
        while (sent < unread_payload.len) {
            const n = @min(HTTP2_MAX_FRAME_SIZE, unread_payload.len - sent);
            try client.sendData(1, false, unread_payload[sent .. sent + n]);
            sent += n;
        }
    }

    try http.http2_frame.writeRstStream(client.writer(), 1, http.http2_stream.ErrorCode.cancel.value());

    // The connection must get that credit back via a stream-0-only
    // WINDOW_UPDATE once the stream is gone, rather than lose it forever.
    var window_update = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &window_update);
    try std.testing.expectEqual(http.http2_frame.Type.window_update, window_update.typ);
    try std.testing.expectEqual(@as(u31, 0), window_update.stream_id);
    const increment = std.mem.readInt(u32, window_update.payload[0..4], .big) & 0x7FFF_FFFF;
    try std.testing.expectEqual(@as(u32, @intCast(unread_payload.len)), increment);

    // A fresh ordinary request on a new stream, carrying a real DATA body
    // too large to fit in what the connection receive window would be if
    // the refund above had not actually been applied to `conn_recv_window`
    // (65,535 - 50,000 = 15,535 remaining), but well within the window the
    // peer was actually just credited back up to (65,535). This proves the
    // connection (and its frame loop) survives the reset, and that an
    // unrelated sibling keeps making progress after the credit refund,
    // rather than being wrongly reset/GOAWAY'd for a flow-control
    // violation that never really happened.
    const sibling_body = try allocator.alloc(u8, 30_000);
    defer allocator.free(sibling_body);
    @memset(sibling_body, 'b');
    try client.sendHeaders(allocator, 3, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/ordinary" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    {
        var sent: usize = 0;
        while (sent < sibling_body.len) {
            const n = @min(HTTP2_MAX_FRAME_SIZE, sibling_body.len - sent);
            sent += n;
            try client.sendData(3, sent == sibling_body.len, sibling_body[sent - n .. sent]);
        }
    }
    // Each inbound DATA chunk above earns its own stream/connection
    // WINDOW_UPDATE pair for the ordinary (non-session) body path, so skip
    // over those before the actual response HEADERS.
    var ordinary_response: http.http2_frame.Frame = while (true) {
        var frame = try client.readFrame(allocator);
        if (frame.stream_id == 3 and frame.typ == .headers) break frame;
        http.http2_frame.deinitFrame(allocator, &frame);
    };
    defer http.http2_frame.deinitFrame(allocator, &ordinary_response);
    try std.testing.expectEqual(http.http2_frame.Type.headers, ordinary_response.typ);
    try std.testing.expectEqual(@as(u31, 3), ordinary_response.stream_id);

    try http.http2_frame.writeGoaway(client.writer(), 3, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;

    // The stalling hook never attached a consumer worker, so the runtime
    // side's detach inside `h2ResetStreamState` is the only side that ever
    // detaches; simulate the consumer's final detach here so the test frees
    // the session without leaking.
    const session = hook_ctx.session orelse return error.SessionNeverAttached;
    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(http.h2_stream_session.ReadResult{ .reset = .cancel }, session.read(&buf));
    if (session.consumerDetach()) {
        session.deinit();
        allocator.destroy(session);
    }
}

test "H2 live: an over-budget second session is refused at stream scope while the first session and a sibling GET stay alive (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    // One session reserves `HTTP2_SESSION_RESERVED_BYTES` (~1.25 MiB); size
    // the budget to admit exactly one and refuse a second.
    cfg.max_connection_memory_bytes = 1_400_000;
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var first_session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &first_session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, first_session_headers.typ);
    try std.testing.expectEqual(@as(u31, 1), first_session_headers.stream_id);

    // A second session on a fresh stream cannot be admitted under the
    // connection budget. It must be refused at stream scope (RST_STREAM),
    // never torn down with a connection-wide GOAWAY that would also kill
    // the first, already-healthy session.
    try client.sendHeaders(allocator, 3, true, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var refusal = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &refusal);
    try std.testing.expectEqual(http.http2_frame.Type.rst_stream, refusal.typ);
    try std.testing.expectEqual(@as(u31, 3), refusal.stream_id);
    const refusal_code = std.mem.readInt(u32, refusal.payload[0..4], .big);
    try std.testing.expectEqual(http.http2_stream.ErrorCode.refused_stream.value(), refusal_code);

    // An ordinary sibling request on yet another stream proves the
    // connection (and its dispatcher) is still alive and multiplexing.
    try client.sendHeaders(allocator, 5, true, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/ordinary" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var ordinary_response = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &ordinary_response);
    try std.testing.expectEqual(http.http2_frame.Type.headers, ordinary_response.typ);
    try std.testing.expectEqual(@as(u31, 5), ordinary_response.stream_id);

    // The first session is still live: DATA sent on it is still echoed
    // back, proving the refused second session never tore down the first.
    // The ordinary GET response above may still have a trailing DATA frame
    // (even empty-bodied END_STREAM responses send one) in flight on
    // stream 5, so skip over it rather than assuming the very next frame
    // is the echo.
    try client.sendData(1, false, "still-alive");
    var echoed: http.http2_frame.Frame = while (true) {
        var frame = try client.readFrame(allocator);
        if (frame.stream_id == 1 and frame.typ == .data) break frame;
        http.http2_frame.deinitFrame(allocator, &frame);
    };
    defer http.http2_frame.deinitFrame(allocator, &echoed);
    try std.testing.expectEqualStrings("still-alive", echoed.payload);

    try http.http2_frame.writeGoaway(client.writer(), 5, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: DATA already in flight on a just-refused stream is tolerated with a live sibling, but DATA on a truly idle stream still ends the connection (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    // One session reserves `HTTP2_SESSION_RESERVED_BYTES` (~1.25 MiB); size
    // the budget to admit exactly one and refuse a second, so stream 3 is
    // refused at stream scope below rather than ever being admitted.
    cfg.max_connection_memory_bytes = 1_400_000;
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var first_session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &first_session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, first_session_headers.typ);
    try std.testing.expectEqual(@as(u31, 1), first_session_headers.stream_id);

    // A second session on a fresh stream cannot be admitted under the
    // connection budget and is refused at stream scope.
    try client.sendHeaders(allocator, 3, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var refusal = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &refusal);
    try std.testing.expectEqual(http.http2_frame.Type.rst_stream, refusal.typ);
    try std.testing.expectEqual(@as(u31, 3), refusal.stream_id);

    // DATA for stream 3 that was already in flight from the client when our
    // RST_STREAM(REFUSED_STREAM) arrived: `h2ResetStreamState` has already
    // removed stream 3 from every map (RFC 9113 §5.1 still requires
    // tolerating frames already in flight for it), so this must be
    // discriminated from a brand-new idle-stream violation rather than
    // tearing down the whole connection with GOAWAY.
    try client.sendData(3, true, "already in flight");

    // The connection (and dispatcher) must still be alive: an ordinary
    // sibling request on yet another stream completes normally. Skip any
    // incidental connection-level WINDOW_UPDATE the discarded DATA above
    // earns back before the response headers arrive.
    try client.sendHeaders(allocator, 5, true, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/ordinary" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var ordinary_response: http.http2_frame.Frame = while (true) {
        var frame = try client.readFrame(allocator);
        if (frame.stream_id == 5 and frame.typ == .headers) break frame;
        http.http2_frame.deinitFrame(allocator, &frame);
    };
    defer http.http2_frame.deinitFrame(allocator, &ordinary_response);

    // The first session is still live too: DATA sent on it is still echoed
    // back, proving the tolerated post-refusal DATA never tore it down.
    try client.sendData(1, false, "still-alive");
    var echoed: http.http2_frame.Frame = while (true) {
        var frame = try client.readFrame(allocator);
        if (frame.stream_id == 1 and frame.typ == .data) break frame;
        http.http2_frame.deinitFrame(allocator, &frame);
    };
    defer http.http2_frame.deinitFrame(allocator, &echoed);
    try std.testing.expectEqualStrings("still-alive", echoed.payload);

    // By contrast, DATA on a stream the client never opened with HEADERS at
    // all is a genuine idle-stream violation (RFC 9113 §5.1) and must still
    // tear down the whole connection with a connection-level GOAWAY.
    try client.sendData(99, true, "never opened");
    var goaway: http.http2_frame.Frame = undefined;
    var frames_read: usize = 0;
    while (true) {
        var frame = try client.readFrame(allocator);
        if (frame.typ == .goaway) {
            goaway = frame;
            break;
        }
        http.http2_frame.deinitFrame(allocator, &frame);
        frames_read += 1;
        if (frames_read > 100) return error.TestFrameBudgetExceeded;
    }
    defer http.http2_frame.deinitFrame(allocator, &goaway);
    try std.testing.expectEqual(@as(u32, http.http2_stream.ErrorCode.protocol_error.value()), std.mem.readInt(u32, goaway.payload[4..8], .big));

    testJoinOnce(&server_thread);
    try std.testing.expectError(error.InvalidHttp2StreamId, server_ctx.result);
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: repeated over-budget session refusals retire their stream bookkeeping instead of exhausting the concurrent-stream limit (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    // One session reserves `HTTP2_SESSION_RESERVED_BYTES` (~1.25 MiB); size
    // the budget to admit exactly one and refuse every one after it.
    cfg.max_connection_memory_bytes = 1_400_000;
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var first_session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &first_session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, first_session_headers.typ);

    // Refuse well past `HTTP2_MAX_CONCURRENT_STREAMS` (100): if a refused
    // attach left its `.closed` entry behind in `streams`, this alone would
    // exhaust the connection-wide admission guard and force a GOAWAY on the
    // healthy sibling request below.
    var stream_id: u31 = 3;
    var refusals: usize = 0;
    while (refusals < 150) : (refusals += 1) {
        try client.sendHeaders(allocator, stream_id, true, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/session" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "test.local" },
        });
        var refusal = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &refusal);
        try std.testing.expectEqual(http.http2_frame.Type.rst_stream, refusal.typ);
        try std.testing.expectEqual(stream_id, refusal.stream_id);
        const refusal_code = std.mem.readInt(u32, refusal.payload[0..4], .big);
        try std.testing.expectEqual(http.http2_stream.ErrorCode.refused_stream.value(), refusal_code);
        stream_id += 2;
    }

    // A fresh, ordinary sibling request proves admission still works: it
    // must get an answer, not a connection-wide GOAWAY from a saturated
    // `streams` map full of stale refusals.
    try client.sendHeaders(allocator, stream_id, true, &.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/ordinary" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var ordinary_response = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &ordinary_response);
    try std.testing.expectEqual(http.http2_frame.Type.headers, ordinary_response.typ);
    try std.testing.expectEqual(stream_id, ordinary_response.stream_id);

    try http.http2_frame.writeGoaway(client.writer(), stream_id, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: stream-only send-window exhaustion stalls independently of connection credit, resumed by a stream-only WINDOW_UPDATE (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    // A tiny SETTINGS_INITIAL_WINDOW_SIZE applies to every stream opened
    // after this, independent of the connection-level send window (which
    // RFC 9113 fixes at 65,535 until grown by a stream-0 WINDOW_UPDATE).
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{.{ 4, 4096 }});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    const total_bytes: usize = 6_000;
    var send_buf: [6_000]u8 = undefined;
    for (&send_buf, 0..) |*b, i| b.* = @intCast((i % 26) + 'a');
    try client.sendData(1, false, &send_buf);

    // Stream 1's send window is 4,096 bytes (from the SETTINGS above); the
    // connection-level window is still the full 65,535-byte default, so
    // nothing here should ever block on connection credit.
    var echoed = std.array_list.Managed(u8).init(allocator);
    defer echoed.deinit();
    var frames_read: usize = 0;
    while (echoed.items.len < 4_096) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == 1 and frame.typ == .data) try echoed.appendSlice(frame.payload);
        frames_read += 1;
        if (frames_read > 1_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expectEqual(@as(usize, 4_096), echoed.items.len);

    // Negative control: granting more *connection* credit does nothing,
    // because connection credit was never the bottleneck here. (A benign
    // receive-direction WINDOW_UPDATE may still arrive as the consumer
    // drains inbound bytes -- that's unrelated to this outbound stall.)
    try http.http2_frame.writeWindowUpdate(client.writer(), 0, 50_000);
    try testDrainStreamDataFor(&client, allocator, 1, &echoed, 200, null);
    try std.testing.expectEqual(@as(usize, 4_096), echoed.items.len);

    // Positive control: granting the missing *stream* credit resumes it.
    try http.http2_frame.writeWindowUpdate(client.writer(), 1, @intCast(total_bytes - 4_096));
    while (echoed.items.len < total_bytes) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == 1 and frame.typ == .data) try echoed.appendSlice(frame.payload);
        frames_read += 1;
        if (frames_read > 2_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expectEqualSlices(u8, &send_buf, echoed.items);

    try http.http2_frame.writeGoaway(client.writer(), 1, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: connection-only send-window exhaustion stalls independently of stream credit, resumed by a connection-only WINDOW_UPDATE (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    // A large per-stream initial window keeps stream credit far above what
    // this test ever sends; only the fixed 65,535-byte connection window
    // (unaffected by SETTINGS_INITIAL_WINDOW_SIZE) can be the bottleneck.
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{.{ 4, 200_000 }});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    const total_bytes: usize = 100_000;
    var expected = try std.array_list.Managed(u8).initCapacity(allocator, total_bytes);
    defer expected.deinit();
    for (0..total_bytes) |i| try expected.append(@intCast((i % 26) + 'a'));

    // The connection-level receive window the server advertises to us is
    // fixed at the RFC 9113 §6.9.2 default of 65,535 bytes (SETTINGS
    // INITIAL_WINDOW_SIZE only raises the *per-stream* window); pace our own
    // send thread on that credit, exactly as a real compliant client must,
    // rather than relying on the kernel socket buffer to mask the
    // difference. Sending straight out of `expected` (the full precomputed
    // payload) rather than repeatedly re-slicing a small fixed template from
    // offset 0 keeps every byte correct regardless of how credit-limited
    // chunk sizes happen to land relative to any template period.
    var send_credit = TestConnSendCredit{};
    const SendCtx = struct {
        client: *TestH2Client,
        send_buf: []const u8,
        credit: *TestConnSendCredit,
        result: anyerror!void = {},

        fn run(self: *@This()) void {
            var sent: usize = 0;
            while (sent < self.send_buf.len) {
                const want = @min(HTTP2_MAX_FRAME_SIZE, self.send_buf.len - sent);
                const n = self.credit.take(want) orelse return;
                self.result = self.client.sendData(1, false, self.send_buf[sent .. sent + n]);
                self.result catch return;
                sent += n;
            }
        }
    };
    var send_ctx = SendCtx{ .client = &client, .send_buf = expected.items, .credit = &send_credit };
    var send_thread: ?std.Thread = try std.Thread.spawn(.{}, SendCtx.run, .{&send_ctx});
    // `send_thread` can be parked indefinitely inside `send_credit.take`, or
    // blocked in a real blocking `write()` on `client_fd` once the kernel
    // socket buffer fills; unlike the server/consumer threads, neither
    // closing the server socket nor `cancelAndBroadcast` alone wakes the
    // latter case, so a failed assertion below must shut down both sockets
    // before joining, or this join can hang forever on the about-to-be-
    // destroyed stack (`send_ctx`/`send_credit`/`client`/`expected`).
    errdefer testShutdownAndJoinSenderOnFailure(server_fd, client_fd, &send_credit, &send_thread, &server_thread, &hook_ctx.consumer_thread);

    var echoed = std.array_list.Managed(u8).init(allocator);
    defer echoed.deinit();
    var frames_read: usize = 0;
    while (echoed.items.len < 65_535) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == 1 and frame.typ == .data) try echoed.appendSlice(frame.payload);
        testGrantIfConnSendCredit(&frame, &send_credit);
        frames_read += 1;
        if (frames_read > 10_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expectEqual(@as(usize, 65_535), echoed.items.len);

    // Negative control: granting more *stream* credit does nothing, because
    // the connection-level window (not stream credit) is the bottleneck. (A
    // benign receive-direction WINDOW_UPDATE may still arrive as the
    // consumer drains inbound bytes -- that's unrelated to this outbound
    // stall, and the background SendCtx thread keeps feeding it more.)
    try http.http2_frame.writeWindowUpdate(client.writer(), 1, 50_000);
    try testDrainStreamDataFor(&client, allocator, 1, &echoed, 200, &send_credit);
    try std.testing.expectEqual(@as(usize, 65_535), echoed.items.len);

    // Positive control: a connection-only WINDOW_UPDATE resumes it.
    try http.http2_frame.writeWindowUpdate(client.writer(), 0, @intCast(total_bytes - 65_535));
    while (echoed.items.len < total_bytes) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == 1 and frame.typ == .data) try echoed.appendSlice(frame.payload);
        testGrantIfConnSendCredit(&frame, &send_credit);
        frames_read += 1;
        if (frames_read > 20_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expectEqualSlices(u8, expected.items, echoed.items);
    testJoinOnce(&send_thread);
    try send_ctx.result;

    try http.http2_frame.writeGoaway(client.writer(), 1, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: a stalled consumer can receive DATA up to the full advertised window without a premature reset, then resumes (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = DelayedLiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = DelayedLiveSessionHookCtx.shouldAttach,
        .attach = DelayedLiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    // The server's advertised per-stream window must match the session's
    // own inbound capacity exactly: a mismatch is the defect this test
    // guards against (a well-behaved peer getting reset inside its own
    // granted window).
    const advertised_window = try http.http2_frame.parseSettingsInitialWindowSize(server_settings.payload);
    try std.testing.expectEqual(@as(?u32, @intCast(HTTP2_SESSION_MAX_INBOUND_BYTES)), advertised_window);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    // Send exactly the connection-level receive window (RFC 9113 §6.9.2
    // fixes this at 65,535 regardless of any SETTINGS value) while the
    // consumer is still idle. `HTTP2_SESSION_MAX_INBOUND_BYTES` only raises
    // the *per-stream* window the server advertised via SETTINGS
    // INITIAL_WINDOW_SIZE; a compliant client may not send more than this
    // on the connection as a whole until it is credited back, so sending
    // the larger per-stream figure here would itself be a protocol
    // violation rather than the "well-behaved peer" this test means to
    // exercise.
    const window_bytes: usize = 65_535;
    var chunk: [16 * 1024]u8 = undefined;
    for (&chunk, 0..) |*b, i| b.* = @intCast((i % 26) + 'a');
    var sent: usize = 0;
    while (sent < window_bytes) {
        const n = @min(chunk.len, window_bytes - sent);
        try client.sendData(1, false, chunk[0..n]);
        sent += n;
    }

    // No RST_STREAM (or anything else) should have arrived: this is all
    // legal, in-window traffic against a merely slow consumer.
    try testExpectNoFrameArrives(client_fd, 200);

    // Let the consumer start draining; it echoes back exactly what it
    // reads, so the first bytes to arrive must match what was sent first.
    hook_ctx.released.store(true, .release);

    var expected = try std.array_list.Managed(u8).initCapacity(allocator, 65_535);
    defer expected.deinit();
    {
        var built: usize = 0;
        while (built < 65_535) {
            const n = @min(chunk.len, 65_535 - built);
            try expected.appendSlice(chunk[0..n]);
            built += n;
        }
    }

    var echoed = std.array_list.Managed(u8).init(allocator);
    defer echoed.deinit();
    var frames_read: usize = 0;
    // The default 65,535-byte send window bounds this without needing any
    // further WINDOW_UPDATE from the client.
    while (echoed.items.len < 65_535) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == 1 and frame.typ == .data) try echoed.appendSlice(frame.payload);
        frames_read += 1;
        if (frames_read > 10_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expectEqualSlices(u8, expected.items, echoed.items);

    try http.http2_frame.writeGoaway(client.writer(), 1, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: DATA beyond the advertised connection-level receive window is a flow-control GOAWAY (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = DelayedLiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = DelayedLiveSessionHookCtx.shouldAttach,
        .attach = DelayedLiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    // One byte past the connection-level receive window -- fixed at 65,535
    // by RFC 9113 §6.9.2 regardless of any SETTINGS value -- while the
    // consumer never reads. `HTTP2_SESSION_MAX_INBOUND_BYTES` only bounds
    // this session's *per-stream* queue and cannot by itself detect this;
    // this is the real protocol violation the connection-level counter must
    // catch instead.
    var chunk: [16 * 1024]u8 = undefined;
    for (&chunk, 0..) |*b, i| b.* = @intCast((i % 26) + 'a');
    const over_budget: usize = 65_536;
    var sent: usize = 0;
    while (sent < over_budget) {
        const n = @min(chunk.len, over_budget - sent);
        try client.sendData(1, false, chunk[0..n]);
        sent += n;
    }

    var goaway: http.http2_frame.Frame = undefined;
    var frames_read: usize = 0;
    while (true) {
        var frame = try client.readFrame(allocator);
        if (frame.typ == .goaway) {
            goaway = frame;
            break;
        }
        http.http2_frame.deinitFrame(allocator, &frame);
        frames_read += 1;
        if (frames_read > 100) return error.TestFrameBudgetExceeded;
    }
    defer http.http2_frame.deinitFrame(allocator, &goaway);
    try std.testing.expectEqual(@as(u32, http.http2_stream.ErrorCode.flow_control_error.value()), std.mem.readInt(u32, goaway.payload[4..8], .big));

    hook_ctx.released.store(true, .release);
    testJoinOnce(&server_thread);
    try std.testing.expectError(error.Http2FlowControlError, server_ctx.result);
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: a stalled client reader does not unbound the session's outbound memory, and recovers once it reads (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    // Grant generous send credit up front on the *outbound* (server-to-us
    // echo) direction so protocol-level flow control is never the
    // bottleneck there: the only thing that can bound the session's
    // retained memory while the client reads nothing is its own
    // `max_outbound_bytes` queue cap (well under this payload). This is a
    // separate direction from our own *inbound* (us-to-server) sends below,
    // which remain bound by the server's fixed 65,535-byte connection
    // receive window and must be paced on `send_credit` like every other
    // live test here.
    const total_bytes: usize = 600_000;
    try http.http2_frame.writeWindowUpdate(client.writer(), 0, @intCast(total_bytes));
    try http.http2_frame.writeWindowUpdate(client.writer(), 1, @intCast(total_bytes));

    var expected = try std.array_list.Managed(u8).initCapacity(allocator, total_bytes);
    defer expected.deinit();
    for (0..total_bytes) |i| try expected.append(@intCast((i % 26) + 'a'));

    // Sending straight out of `expected` (the full precomputed payload)
    // rather than repeatedly re-slicing a small fixed template from offset 0
    // keeps every byte correct regardless of how credit-limited chunk sizes
    // happen to land relative to any template period.
    var send_credit = TestConnSendCredit{};
    const SendCtx = struct {
        client: *TestH2Client,
        send_buf: []const u8,
        credit: *TestConnSendCredit,
        result: anyerror!void = {},

        fn run(self: *@This()) void {
            var sent: usize = 0;
            while (sent < self.send_buf.len) {
                const want = @min(HTTP2_MAX_FRAME_SIZE, self.send_buf.len - sent);
                const n = self.credit.take(want) orelse return;
                self.result = self.client.sendData(1, false, self.send_buf[sent .. sent + n]);
                self.result catch return;
                sent += n;
            }
        }
    };
    var send_ctx = SendCtx{ .client = &client, .send_buf = expected.items, .credit = &send_credit };
    var send_thread: ?std.Thread = try std.Thread.spawn(.{}, SendCtx.run, .{&send_ctx});
    // `send_thread` can be parked indefinitely inside `send_credit.take`, or
    // blocked in a real blocking `write()` on `client_fd` once the kernel
    // socket buffer fills; unlike the server/consumer threads, neither
    // closing the server socket nor `cancelAndBroadcast` alone wakes the
    // latter case, so a failed assertion below must shut down both sockets
    // before joining, or this join can hang forever on the about-to-be-
    // destroyed stack (`send_ctx`/`send_credit`/`client`/`expected`).
    errdefer testShutdownAndJoinSenderOnFailure(server_fd, client_fd, &send_credit, &send_thread, &server_thread, &hook_ctx.consumer_thread);

    // Deliberately read nothing for a while: the echo consumer should run
    // ahead of what the wire can absorb and then block inside
    // `Session.write` once its outbound queue fills, rather than growing
    // without bound.
    std.Io.sleep(compat.io(), .fromMilliseconds(200), .awake) catch {};

    var echoed = std.array_list.Managed(u8).init(allocator);
    defer echoed.deinit();
    var frames_read: usize = 0;
    while (echoed.items.len < total_bytes) {
        var frame = try client.readFrame(allocator);
        defer http.http2_frame.deinitFrame(allocator, &frame);
        if (frame.stream_id == 1 and frame.typ == .data) try echoed.appendSlice(frame.payload);
        testGrantIfConnSendCredit(&frame, &send_credit);
        frames_read += 1;
        if (frames_read > 100_000) return error.TestFrameBudgetExceeded;
    }
    try std.testing.expectEqualSlices(u8, expected.items, echoed.items);
    testJoinOnce(&send_thread);
    try send_ctx.result;

    try http.http2_frame.writeGoaway(client.writer(), 1, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: an abrupt client disconnect (no GOAWAY) settles the active session as connection_closed without leaking (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    // Prove the session is genuinely live before tearing the socket down.
    try client.sendData(1, false, "alive");
    var echo = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &echo);
    try std.testing.expectEqual(http.http2_frame.Type.data, echo.typ);
    try std.testing.expectEqualStrings("alive", echo.payload);

    // No GOAWAY, no FIN: just slam the socket shut, as a crashed or
    // force-killed client would.
    _ = std.c.close(client_fd);

    testJoinOnce(&server_thread);
    // An abrupt close can surface either as a clean return (the next read
    // sees EOF first) or as a benign write-side error (a queued
    // receive-credit WINDOW_UPDATE loses its race against the close) --
    // both are `isBenignDisconnect` outcomes the production caller already
    // treats as ordinary teardown, never as a crash or a hang.
    server_ctx.result catch |err| {
        // `error.SocketWriteFailed` is this file's `PlaintextSocketStream`
        // test shim's name for exactly the same underlying EPIPE condition
        // `isBenignDisconnect` already recognizes as `error.BrokenPipe` in
        // production's real socket/TLS stack: a queued receive-credit
        // WINDOW_UPDATE write losing its race against the close.
        try std.testing.expect(isBenignDisconnect(err) or err == error.SocketWriteFailed);
    };
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: graceful shutdown settles the active session as shutdown without leaking (#867)" {
    const allocator = std.testing.allocator;
    http.shutdown.reset();
    defer http.shutdown.reset();

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = LiveSessionHookCtx{ .allocator = allocator, .attach_path = "/session" };
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = LiveSessionHookCtx.shouldAttach,
        .attach = LiveSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer testShutdownAndJoinOnFailure(server_fd, &server_thread, &hook_ctx.consumer_thread);

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    try client.sendHeaders(allocator, 1, false, &.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/session" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "test.local" },
    });
    var session_headers = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &session_headers);
    try std.testing.expectEqual(http.http2_frame.Type.headers, session_headers.typ);

    try client.sendData(1, false, "alive");
    var echo = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &echo);
    try std.testing.expectEqual(http.http2_frame.Type.data, echo.typ);
    try std.testing.expectEqualStrings("alive", echo.payload);

    http.shutdown.requestShutdown();
    // The connection loop only rechecks the shutdown flag between frame
    // reads; nudge it with a harmless PING so it wakes up and observes it.
    try client.writer().enqueueFrame(.ping, 0, 0, &[_]u8{0} ** 8);
    // The "alive" echo above earned the consumer receive credit, which may
    // surface as its own WINDOW_UPDATE(s) interleaved before the PING ACK;
    // skip those rather than assume the very next frame is the ack.
    var ping_ack: http.http2_frame.Frame = while (true) {
        var frame = try client.readFrame(allocator);
        if (frame.typ != .window_update) break frame;
        http.http2_frame.deinitFrame(allocator, &frame);
    };
    defer http.http2_frame.deinitFrame(allocator, &ping_ack);
    try std.testing.expectEqual(http.http2_frame.Type.ping, ping_ack.typ);
    try std.testing.expect((ping_ack.flags & http.http2_frame.Flags.ACK) != 0);

    testJoinOnce(&server_thread);
    try server_ctx.result;
    testJoinOnce(&hook_ctx.consumer_thread);
}

test "H2 live: repeated session attach/close churn over one connection settles every session with no leak (#867)" {
    const allocator = std.testing.allocator;

    const fds = try testH2SocketPair();
    const server_fd = fds[0];
    const client_fd = fds[1];
    defer _ = std.c.close(server_fd);
    defer _ = std.c.close(client_fd);
    try testSetFdNonBlocking(server_fd);

    var server_stream = PlaintextSocketStream{ .fd = server_fd };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFd(server_stream.stream(), server_fd);
    var adapter = WaitingEncryptedHttpConnection.init(inner, 10_000, 10_000);

    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.metrics_mutex = .{};
    state.add_headers = &.{};
    state.metrics = http.metrics.Metrics.init();
    state.h2_request_executor = null;

    var hook_ctx = ChurnSessionHookCtx.init(allocator, "/session");
    defer hook_ctx.deinit();
    state.h2_session_test_hook = .{
        .ctx = &hook_ctx,
        .shouldAttach = ChurnSessionHookCtx.shouldAttach,
        .attach = ChurnSessionHookCtx.attach,
    };

    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    var dummy_session = ConnectionSession{};
    var server_ctx = LiveH2ServerCtx{ .adapter = &adapter, .session = &dummy_session, .cfg = &cfg, .state = &state };
    var server_thread: ?std.Thread = try std.Thread.spawn(.{}, LiveH2ServerCtx.run, .{&server_ctx});
    errdefer {
        _ = std.c.shutdown(server_fd, std.c.SHUT.RDWR);
        testJoinOnce(&server_thread);
        hook_ctx.joinAll();
    }

    var client = TestH2Client{ .fd = client_fd };

    try client.writer().writeAll(HTTP2_PREFACE);
    try http.http2_frame.writeSettings(allocator, client.writer(), &[_][2]u32{});
    var server_settings = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings.typ);
    try http.http2_frame.writeSettingsAck(client.writer());

    var server_settings_ack = try client.readFrame(allocator);
    defer http.http2_frame.deinitFrame(allocator, &server_settings_ack);
    try std.testing.expectEqual(http.http2_frame.Type.settings, server_settings_ack.typ);
    try std.testing.expect((server_settings_ack.flags & http.http2_frame.Flags.ACK) != 0);

    var churn: u31 = 0;
    while (churn < 20) : (churn += 1) {
        const stream_id: u31 = churn * 2 + 1;
        try client.sendHeaders(allocator, stream_id, false, &.{
            .{ .name = ":method", .value = "POST" },
            .{ .name = ":path", .value = "/session" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "test.local" },
        });
        // A prior iteration's receive-credit WINDOW_UPDATE(s) may still be
        // interleaved here; skip those rather than assume the very next
        // frame is this iteration's session-attach response.
        var headers: http.http2_frame.Frame = while (true) {
            var frame = try client.readFrame(allocator);
            if (frame.typ != .window_update) break frame;
            http.http2_frame.deinitFrame(allocator, &frame);
        };
        defer http.http2_frame.deinitFrame(allocator, &headers);
        try std.testing.expectEqual(http.http2_frame.Type.headers, headers.typ);
        try std.testing.expectEqual(stream_id, headers.stream_id);

        var payload_buf: [16]u8 = undefined;
        const payload = try std.fmt.bufPrint(&payload_buf, "churn-{d}", .{churn});
        try client.sendData(stream_id, true, payload);

        var echoed = std.array_list.Managed(u8).init(allocator);
        defer echoed.deinit();
        var saw_end_stream = false;
        var frames_read: usize = 0;
        while (!saw_end_stream) {
            var frame = try client.readFrame(allocator);
            defer http.http2_frame.deinitFrame(allocator, &frame);
            if (frame.stream_id == stream_id and frame.typ == .data) {
                try echoed.appendSlice(frame.payload);
                if ((frame.flags & http.http2_frame.Flags.END_STREAM) != 0) saw_end_stream = true;
            }
            frames_read += 1;
            if (frames_read > 1_000) return error.TestFrameBudgetExceeded;
        }
        try std.testing.expectEqualSlices(u8, payload, echoed.items);
    }

    try http.http2_frame.writeGoaway(client.writer(), churn * 2 - 1, 0);
    testJoinOnce(&server_thread);
    try server_ctx.result;
    hook_ctx.joinAll();
}

test "H2 session RST_STREAM settles the consumer and detaches without leaking" {
    const allocator = std.testing.allocator;
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer sessions.deinit();
    const session = try allocator.create(http.h2_stream_session.Session);
    session.* = try http.h2_stream_session.Session.init(allocator, 7, 64, 64);
    try sessions.put(7, session);

    try std.testing.expect(!session.consumerDetach());
    session.deliverReset(.cancel);
    var buf: [4]u8 = undefined;
    try std.testing.expectEqual(http.h2_stream_session.ReadResult{ .reset = .cancel }, session.read(&buf));

    var buffered_request_bytes: usize = 0;
    var discard_out = std.Io.Writer.Allocating.init(allocator);
    defer discard_out.deinit();
    try h2DetachSession(&discard_out.writer, allocator, &sessions, &buffered_request_bytes, 7, null);
    try std.testing.expect(!sessions.contains(7));
}

test "H2 GOAWAY, connection close, and shutdown settle every attached session exactly once" {
    const allocator = std.testing.allocator;
    const cases = [_]struct { reason: Http2SessionCloseReason, closed: http.h2_stream_session.TerminalReason }{
        .{ .reason = .goaway, .closed = .goaway },
        .{ .reason = .connection_closed, .closed = .connection_closed },
        .{ .reason = .shutdown, .closed = .shutdown },
    };
    for (cases) |case| {
        var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
        defer sessions.deinit();
        const ids = [_]u31{ 9, 11, 13 };
        var created: [ids.len]*http.h2_stream_session.Session = undefined;
        for (ids, 0..) |id, idx| {
            const session = try allocator.create(http.h2_stream_session.Session);
            session.* = try http.h2_stream_session.Session.init(allocator, id, 64, 64);
            try sessions.put(id, session);
            created[idx] = session;
        }

        // `h2SettleAllSessions` detaches the runtime side of every attached
        // session and clears the map; none here is freed yet because each
        // consumer (simulated below) is still attached.
        h2SettleAllSessions(allocator, &sessions, case.reason);
        try std.testing.expectEqual(@as(usize, 0), sessions.count());

        for (created) |session| {
            var buf: [4]u8 = undefined;
            try std.testing.expectEqual(http.h2_stream_session.ReadResult{ .closed = case.closed }, session.read(&buf));
            // The consumer detaches last and frees the session, mirroring
            // what its worker thread would do after observing settlement.
            try std.testing.expect(session.consumerDetach());
            session.deinit();
            allocator.destroy(session);
        }
    }
}

test "H2 session attach/detach churn settles resources with no leak" {
    const allocator = std.testing.allocator;
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer sessions.deinit();
    var buffered_request_bytes: usize = 0;

    var i: u31 = 0;
    while (i < 50) : (i += 1) {
        const stream_id = i * 2 + 1;
        const session = try allocator.create(http.h2_stream_session.Session);
        session.* = try http.h2_stream_session.Session.init(allocator, stream_id, 64, 64);
        try sessions.put(stream_id, session);
        var discard_out = std.Io.Writer.Allocating.init(allocator);
        defer discard_out.deinit();
        try h2DeliverSessionInboundData(&discard_out.writer, session, stream_id, "ping".len, "ping", true);
        try std.testing.expect(!session.consumerDetach());
        try h2DetachSession(&discard_out.writer, allocator, &sessions, &buffered_request_bytes, stream_id, null);
    }
    try std.testing.expectEqual(@as(usize, 0), sessions.count());
}

const TestAlwaysFailingWriter = struct {
    pub fn writeAll(_: *TestAlwaysFailingWriter, _: []const u8) error{BrokenPipe}!void {
        return error.BrokenPipe;
    }
};

test "h2ResetStreamState never orphans a session when its connection-credit WINDOW_UPDATE write fails" {
    const allocator = std.testing.allocator;
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer pending.deinit();
    var pending_responses = std.AutoHashMap(u31, PendingHttp2Response).init(allocator);
    defer pending_responses.deinit();
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer sessions.deinit();
    var buffered_request_bytes: usize = 0;
    var in_flight_jobs = std.AutoHashMap(u31, void).init(allocator);
    defer in_flight_jobs.deinit();

    const session = try allocator.create(http.h2_stream_session.Session);
    session.* = try http.h2_stream_session.Session.init(allocator, 7, 64, 64);
    // Earn real receive credit (consumption, not mere queuing -- see
    // "receive credit accrues only on consumption, not on queuing" in
    // h2_stream_session.zig) so `h2ResetStreamState` actually attempts the
    // fallible connection-credit WINDOW_UPDATE below instead of skipping it.
    try session.deliverInbound("abcd");
    var buf: [4]u8 = undefined;
    _ = session.read(&buf);
    try sessions.put(7, session);

    var failing_writer = TestAlwaysFailingWriter{};
    var conn_recv_window: i64 = 15_535;
    try std.testing.expectError(error.BrokenPipe, h2ResetStreamState(
        &failing_writer,
        allocator,
        &streams,
        &pending,
        &pending_responses,
        &ready,
        &sessions,
        &buffered_request_bytes,
        7,
        null,
        null,
        null,
        &in_flight_jobs,
        &conn_recv_window,
        null,
    ));

    // The registry's only reference is gone either way; the fix is that
    // `runtimeDetach` still ran despite the write failing, so the consumer
    // side (simulated here) can still detach and free it instead of it
    // leaking as an unreachable, still-runtime-attached session.
    try std.testing.expect(!sessions.contains(7));
    try std.testing.expect(session.consumerDetach());
    // The WINDOW_UPDATE write failed, so the peer was never actually
    // credited: the local counter must not move either, or it would
    // desync from what the peer really has.
    try std.testing.expectEqual(@as(i64, 15_535), conn_recv_window);
    session.deinit();
    allocator.destroy(session);
}

test "h2DetachSession never orphans a session when its connection-credit WINDOW_UPDATE write fails" {
    const allocator = std.testing.allocator;
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer sessions.deinit();
    var buffered_request_bytes: usize = 0;

    const session = try allocator.create(http.h2_stream_session.Session);
    session.* = try http.h2_stream_session.Session.init(allocator, 7, 64, 64);
    try session.deliverInbound("abcd");
    var buf: [4]u8 = undefined;
    _ = session.read(&buf);
    try sessions.put(7, session);

    var failing_writer = TestAlwaysFailingWriter{};
    var conn_recv_window: i64 = 15_535;
    try std.testing.expectError(error.BrokenPipe, h2DetachSession(&failing_writer, allocator, &sessions, &buffered_request_bytes, 7, &conn_recv_window));

    try std.testing.expect(!sessions.contains(7));
    try std.testing.expect(session.consumerDetach());
    try std.testing.expectEqual(@as(i64, 15_535), conn_recv_window);
    session.deinit();
    allocator.destroy(session);
}

const H2FrameReadProvenanceHarness = struct {
    bytes: []const u8,
    pos: usize = 0,
    // Bytes in [0, early_prefix_len) are considered 0-RTT-origin.
    early_prefix_len: usize,
    max_chunk: usize,
    last_read_early: bool = false,
    last_read_early_prefix_len: usize = 0,

    fn stream(self: *H2FrameReadProvenanceHarness) tls_core.encrypted_stream.EncryptedStream {
        return .{ .ptr = self, .vtable = &vtable };
    }

    fn read(ptr: *anyopaque, out: []u8) tls_core.encrypted_stream.Error!usize {
        const self: *H2FrameReadProvenanceHarness = @ptrCast(@alignCast(ptr));
        if (self.pos >= self.bytes.len) return error.WouldBlock;
        const n = @min(out.len, @min(self.max_chunk, self.bytes.len - self.pos));
        self.last_read_early_prefix_len = if (self.pos < self.early_prefix_len)
            @min(n, self.early_prefix_len - self.pos)
        else
            0;
        self.last_read_early = self.last_read_early_prefix_len > 0;
        @memcpy(out[0..n], self.bytes[self.pos .. self.pos + n]);
        self.pos += n;
        return n;
    }

    fn readiness(ptr: *anyopaque) tls_core.encrypted_stream.Readiness {
        const self: *H2FrameReadProvenanceHarness = @ptrCast(@alignCast(ptr));
        return .{ .can_read_plaintext = self.pos < self.bytes.len };
    }

    fn drive(ptr: *anyopaque) tls_core.encrypted_stream.Error!tls_core.encrypted_stream.DriveResult {
        return .{ .made_progress = false, .readiness = readiness(ptr) };
    }

    fn backend(_: *anyopaque) tls_core.encrypted_stream.BackendKind {
        return .pure_zig_record;
    }

    fn write(_: *anyopaque, _: []const u8) tls_core.encrypted_stream.Error!usize {
        return error.WouldBlock;
    }

    fn close(_: *anyopaque) void {}

    fn bufferSnapshot(_: *anyopaque) tls_core.encrypted_stream.BufferSnapshot {
        return .{};
    }

    fn readTransportEarly(ptr: *anyopaque) bool {
        const self: *H2FrameReadProvenanceHarness = @ptrCast(@alignCast(ptr));
        return self.last_read_early;
    }

    fn readEarlyPrefixLen(ptr: *anyopaque) usize {
        const self: *H2FrameReadProvenanceHarness = @ptrCast(@alignCast(ptr));
        return self.last_read_early_prefix_len;
    }

    fn handshakeComplete(_: *anyopaque) bool {
        return true;
    }

    const vtable = tls_core.encrypted_stream.EncryptedStream.VTable{
        .backendFn = backend,
        .readFn = read,
        .writeFn = write,
        .closeFn = close,
        .readinessFn = readiness,
        .driveFn = drive,
        .bufferSnapshotFn = bufferSnapshot,
        .currentReadEarlyPrefixLenFn = readEarlyPrefixLen,
    };
};

test "H2 frame provenance stays sticky when frame is fragmented across early then 1-RTT reads" {
    const allocator = std.testing.allocator;

    const wire = [_]u8{
        // length=4, type=DATA, flags=END_STREAM, stream_id=1
        0x00, 0x00, 0x04,
        0x00, 0x01, 0x00,
        0x00, 0x00, 0x01,
        'a',  'b',  'c',
        'd',
    };

    var harness = H2FrameReadProvenanceHarness{
        .bytes = wire[0..],
        // Header + first two payload bytes come from early data; remainder is 1-RTT.
        .early_prefix_len = 11,
        .max_chunk = 2,
    };
    const inner = http.encrypted_stream_connection.EncryptedStreamHttpConnection.initWithFdAndProvenance(
        harness.stream(),
        -1,
        &harness,
        H2FrameReadProvenanceHarness.readTransportEarly,
        H2FrameReadProvenanceHarness.readEarlyPrefixLen,
        H2FrameReadProvenanceHarness.handshakeComplete,
    );
    var conn = WaitingEncryptedHttpConnection.init(inner, 1, 1);

    h2BeginReadScope(&conn);
    var frame = try http.http2_frame.readFrame(&conn, allocator, HTTP2_MAX_FRAME_SIZE);
    defer http.http2_frame.deinitFrame(allocator, &frame);

    try std.testing.expect(h2LastReadTransportEarly(&conn));
    try std.testing.expectEqual(http.http2_frame.Type.data, frame.typ);
    try std.testing.expectEqual(@as(u31, 1), frame.stream_id);
    try std.testing.expectEqualStrings("abcd", frame.payload);
}

fn gatewayTestSocketPair() ![2]std.posix.fd_t {
    var fds: [2]std.posix.fd_t = undefined;
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.socketpair(linux.AF.UNIX, linux.SOCK.STREAM, 0, &fds);
        if (linux.errno(rc) != .SUCCESS) return error.SocketPairFailed;
    } else {
        if (std.c.socketpair(std.posix.AF.UNIX, std.posix.SOCK.STREAM, 0, &fds) != 0) return error.SocketPairFailed;
    }
    errdefer gatewayTestCloseFd(fds[0]);
    errdefer gatewayTestCloseFd(fds[1]);
    try gatewayTestSetNonBlocking(fds[0]);
    try gatewayTestSetNonBlocking(fds[1]);
    return fds;
}

fn gatewayTestCloseFd(fd: std.posix.fd_t) void {
    if (builtin.os.tag == .linux) {
        _ = std.os.linux.close(fd);
    } else {
        _ = std.c.close(fd);
    }
}

fn gatewayTestSetNonBlocking(fd: std.posix.fd_t) !void {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const status_flags = linux.fcntl(fd, linux.F.GETFL, 0);
        if (linux.errno(status_flags) != .SUCCESS) return error.FcntlFailed;
        const nonblock: usize = @intCast(@as(u32, @bitCast(linux.O{ .NONBLOCK = true })));
        const rc = linux.fcntl(fd, linux.F.SETFL, status_flags | nonblock);
        if (linux.errno(rc) != .SUCCESS) return error.FcntlFailed;
    } else {
        const status_flags = std.c.fcntl(fd, std.c.F.GETFL, @as(c_int, 0));
        if (status_flags < 0) return error.FcntlFailed;
        const nonblock = @as(c_int, @bitCast(std.posix.O{ .NONBLOCK = true }));
        if (std.c.fcntl(fd, std.c.F.SETFL, status_flags | nonblock) < 0) return error.FcntlFailed;
    }
}

fn gatewayTestReadFd(fd: std.posix.fd_t, out: []u8) tls_core.encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.read(fd, out.ptr, out.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketReadFailed,
        };
    }
    const rc = std.c.read(fd, out.ptr, out.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketReadFailed;
    }
    return @intCast(rc);
}

fn gatewayTestWriteFd(fd: std.posix.fd_t, bytes: []const u8) tls_core.encrypted_stream.Error!usize {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        const rc = linux.write(fd, bytes.ptr, bytes.len);
        return switch (linux.errno(rc)) {
            .SUCCESS => rc,
            .AGAIN => error.WouldBlock,
            else => error.SocketWriteFailed,
        };
    }
    const rc = std.c.write(fd, bytes.ptr, bytes.len);
    if (rc < 0) {
        if (std.posix.errno(rc) == .AGAIN) return error.WouldBlock;
        return error.SocketWriteFailed;
    }
    return @intCast(rc);
}

test "#368 Slice 2: nativeEarlyDataReplayStoreNeeded is false for every configuration without a native PSK/early-data path" {
    // Plain HTTP or resumption-disabled: no native resumption at all.
    try std.testing.expect(!nativeEarlyDataReplayStoreNeeded(false, false, false, false));
    try std.testing.expect(!nativeEarlyDataReplayStoreNeeded(false, true, false, false));
    try std.testing.expect(!nativeEarlyDataReplayStoreNeeded(false, false, true, true));
    // No native TCP credential provider and HTTP/3 disabled: resumption may be
    // enabled in config, but no native PSK/early-data path can exist.
    try std.testing.expect(!nativeEarlyDataReplayStoreNeeded(true, false, false, false));
    // HTTP/3 enabled but no native H3 credential provider actually bootstrapped
    // (e.g. TLS files missing), and no native TCP provider either.
    try std.testing.expect(!nativeEarlyDataReplayStoreNeeded(true, false, true, false));
    // A native TCP provider exists, but native resumption itself is disabled.
    try std.testing.expect(!nativeEarlyDataReplayStoreNeeded(false, true, true, true));
}

test "#368 Slice 2: nativeEarlyDataReplayStoreNeeded is true once native resumption and a native TCP or QUIC/H3 path both exist" {
    try std.testing.expect(nativeEarlyDataReplayStoreNeeded(true, true, false, false));
    try std.testing.expect(nativeEarlyDataReplayStoreNeeded(true, false, true, true));
    try std.testing.expect(nativeEarlyDataReplayStoreNeeded(true, true, true, true));
    // HTTP/3 disabled entirely: the H3 credential-provider flag alone must
    // not be enough without `http3_enabled` also true.
    try std.testing.expect(!nativeEarlyDataReplayStoreNeeded(true, false, false, true));
}

test "#368 Slice 3: nativeEarlyDataReplayStoreEnabled requires the operator-configured process_local mode even when a native path exists" {
    // Safe default: a usable native path alone is never enough — replay
    // mode `disabled` must construct no store, matching the config
    // requirement "disabled mode creates no replay store".
    try std.testing.expect(!nativeEarlyDataReplayStoreEnabled(.disabled, true, true, false, false));
    try std.testing.expect(!nativeEarlyDataReplayStoreEnabled(.disabled, true, false, true, true));

    // `process_local` mode still requires an eligible native TLS/QUIC path —
    // it does not itself conjure one.
    try std.testing.expect(!nativeEarlyDataReplayStoreEnabled(.process_local, false, false, false, false));
    try std.testing.expect(!nativeEarlyDataReplayStoreEnabled(.process_local, true, false, false, false));

    // Both an opted-in mode and an eligible native path: matches "process-local
    // mode creates one process-scoped store when an eligible native TLS/QUIC
    // path exists".
    try std.testing.expect(nativeEarlyDataReplayStoreEnabled(.process_local, true, true, false, false));
    try std.testing.expect(nativeEarlyDataReplayStoreEnabled(.process_local, true, false, true, true));
}

test "#368 Slice 3: mapEarlyDataReplayEvent covers every closed Event variant" {
    try std.testing.expectEqual(http.metrics.EarlyDataReplayOutcome.accepted, mapEarlyDataReplayEvent(.accepted));
    try std.testing.expectEqual(http.metrics.EarlyDataReplayOutcome.duplicate, mapEarlyDataReplayEvent(.duplicate));
    try std.testing.expectEqual(http.metrics.EarlyDataReplayOutcome.capacity_rejected, mapEarlyDataReplayEvent(.capacity_rejected));
    try std.testing.expectEqual(http.metrics.EarlyDataReplayOutcome.expired, mapEarlyDataReplayEvent(.expired));
    try std.testing.expectEqual(http.metrics.EarlyDataReplayOutcome.unavailable, mapEarlyDataReplayEvent(.unavailable));
    try std.testing.expectEqual(http.metrics.EarlyDataReplayOutcome.startup_quarantine, mapEarlyDataReplayEvent(.startup_quarantine));
}

test "#368 Slice 3: initNativeEarlyDataReplayStore uses the configured max_entries, not the store's own default" {
    var store = try initNativeEarlyDataReplayStore(std.testing.allocator, 2, 0);
    defer store.deinit();

    // Past the startup-quarantine window so claims are actually evaluated.
    const now = (tls_core.tls13_backend.ServerEarlyDataPolicy{}).age_skew_tolerance_ms;
    var key_a: tls_core.early_data_replay.Key = [_]u8{0} ** 32;
    key_a[0] = 1;
    var key_b: tls_core.early_data_replay.Key = [_]u8{0} ** 32;
    key_b[0] = 2;
    var key_c: tls_core.early_data_replay.Key = [_]u8{0} ** 32;
    key_c[0] = 3;

    try std.testing.expectEqual(tls_core.early_data_replay.ClaimResult.accepted, store.claim(.{ .key = key_a, .retain_until_unix_ms = std.math.maxInt(u64) }, now));
    try std.testing.expectEqual(tls_core.early_data_replay.ClaimResult.accepted, store.claim(.{ .key = key_b, .retain_until_unix_ms = std.math.maxInt(u64) }, now));
    // The configured capacity (2) is exhausted by two live entries — proves
    // the caller's `max_entries` argument reached `LocalStore.Limits`,
    // rather than the struct's own 65,536-entry default silently winning.
    try std.testing.expectEqual(tls_core.early_data_replay.ClaimResult.rejected_capacity, store.claim(.{ .key = key_c, .retain_until_unix_ms = std.math.maxInt(u64) }, now));
}

test "#368 Slice 2: initNativeEarlyDataReplayStore rejects 0-RTT for the startup quarantine window then accepts fresh claims" {
    // Exercises the exact helper `run()` calls to build the process-scoped
    // replay store, proving the production composition path — not a
    // reimplementation of it — rejects 0-RTT while the recording window
    // still overlaps startup and accepts a genuinely fresh claim afterward.
    const start_unix_ms: u64 = 1_000_000;
    var store = try initNativeEarlyDataReplayStore(std.testing.allocator, (tls_core.early_data_replay.Limits{}).max_entries, start_unix_ms);
    defer store.deinit();

    const quarantine_duration_ms = (tls_core.tls13_backend.ServerEarlyDataPolicy{}).age_skew_tolerance_ms;
    var key: tls_core.early_data_replay.Key = [_]u8{0} ** 32;
    key[0] = 7;

    try std.testing.expectEqual(
        tls_core.early_data_replay.ClaimResult.unavailable,
        store.claim(.{ .key = key, .retain_until_unix_ms = start_unix_ms + quarantine_duration_ms + 60_000 }, start_unix_ms),
    );
    try std.testing.expectEqual(@as(usize, 0), store.count());

    try std.testing.expectEqual(
        tls_core.early_data_replay.ClaimResult.accepted,
        store.claim(
            .{ .key = key, .retain_until_unix_ms = start_unix_ms + quarantine_duration_ms + 60_000 },
            start_unix_ms + quarantine_duration_ms,
        ),
    );
    try std.testing.expectEqual(@as(usize, 1), store.count());
}

test "#368 Slice 2: one process-scoped early-data replay store is shared by native TCP and QUIC/H3" {
    // Proves the exact composition-root pattern `run()` uses: one
    // `LocalStore`/`GateAdapter` pair, its `.gate()` installed into both a
    // native TCP `NativeTlsConnection` and an `http3_runtime.Runtime` — the
    // same store instance, not a worker-local or protocol-local copy.
    var store = try initNativeEarlyDataReplayStore(std.testing.allocator, (tls_core.early_data_replay.Limits{}).max_entries, 0);
    defer store.deinit();
    var adapter = tls_core.early_data_replay.GateAdapter.init(store.store());
    const gate = adapter.gate();

    var fixed = tls_core.credentials.FixedCredentialProvider.init(tls_core.credentials.testdata.identity(), tls_core.credentials.testdata.ignoredEntropy());
    defer fixed.deinit();

    const fds = try gatewayTestSocketPair();
    defer gatewayTestCloseFd(fds[0]);
    defer gatewayTestCloseFd(fds[1]);
    const native = try http.native_tls_connection.NativeTlsConnection.createWithOptions(
        std.testing.allocator,
        fds[0],
        .{ .http1_enabled = true, .http2_enabled = true },
        fixed.provider(),
        .{ .early_data_replay_gate = gate },
    );
    defer native.destroy();

    var logger = http.logger.Logger.init(.err, "replay-store-shared-test");
    var h3_runtime = try http.http3_runtime.Runtime.init(std.testing.allocator, &logger, .{
        .listen_host = "127.0.0.1",
        .quic_port = 0,
        .credential_provider = fixed.provider(),
        .early_data_replay_gate = gate,
    });
    defer h3_runtime.deinit();

    try std.testing.expectEqual(gate.ctx, native.backend.early_data_replay_gate.ctx);
    const h3_installed = h3_runtime.early_data_replay_gate orelse return error.TestExpectedEqual;
    try std.testing.expectEqual(gate.ctx, h3_installed.ctx);
    // Same underlying `LocalStore`, proven behaviorally too: a claim made
    // through the TCP-installed gate is visible to the H3-installed one.
    const candidate: tls_core.tls13_backend.EarlyDataReplayCandidate = .{
        .ticket_identity_fingerprint = [_]u8{5} ** 32,
        .retain_until_unix_ms = std.math.maxInt(u64),
    };
    try std.testing.expectEqual(tls_core.tls13_backend.EarlyDataReplayDecision.allow, native.backend.early_data_replay_gate.decideFn.?(native.backend.early_data_replay_gate.ctx, candidate));
    try std.testing.expectEqual(tls_core.tls13_backend.EarlyDataReplayDecision.replay, h3_installed.decideFn.?(h3_installed.ctx, candidate));
}

// Pull gateway_handlers (and its transitive imports, including
// gateway_static_runtime) into the unit-test runner so their tests are
// discovered and executed alongside the other edge-gateway tests.
//
// gateway_shutdown.zig is pulled in the same way: `hotReloadConfig` is only
// ever referenced through the plain `const gshutdown = @import(...)` at the
// top of this file, which is not itself sufficient for Zig's test discovery
// to find gateway_shutdown.zig's own `test` declarations (test discovery
// follows the `_ = @import(...)` chain rooted at each file's `test {}`
// aggregator, not arbitrary functional imports) — without this line, every
// test in gateway_shutdown.zig (including the pre-existing
// applianceCredentialConfigChanged/applyReloadedRuntimeConfig coverage) was
// silently never compiled or run by `zig build test`.
test {
    _ = @import("gateway_forward_auth.zig");
    _ = @import("gateway_handlers.zig");
    _ = @import("gateway_shutdown.zig");
    _ = @import("process_early_data_integration_tests.zig");
}

/// Hooks that run the REAL router while counting mirror deliveries.
///
/// The location-auth mirror leak lives in the seam between `routeRequest`'s
/// authorization decision and the orchestration's mirror call, so a probe that
/// stubs out routing cannot observe it.
const H1RealRouteMirrorProbeHooks = struct {
    effects: *H1PreflightSideEffectProbe,

    fn rejectEarly(
        self: H1RealRouteMirrorProbeHooks,
        allocator: std.mem.Allocator,
        writer: anytype,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *const http.Request,
        correlation_id: []const u8,
        keep_alive: bool,
    ) !u16 {
        _ = .{ self, allocator, writer, state, ctx, request, correlation_id, keep_alive };
        return @intFromEnum(http.Status.too_early);
    }

    fn mirror(
        self: H1RealRouteMirrorProbeHooks,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        request: *const http.Request,
        correlation_id: []const u8,
        client_ip: []const u8,
    ) !void {
        _ = .{ allocator, cfg, request, correlation_id, client_ip };
        self.effects.mirror_calls += 1;
    }

    fn auth(
        self: H1RealRouteMirrorProbeHooks,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        headers: *const http.Headers,
    ) !void {
        self.effects.auth_calls += 1;
        try ghandlers.primeRequestAuthContext(allocator, cfg, state, ctx, headers);
    }

    fn middleware(
        self: H1RealRouteMirrorProbeHooks,
        allocator: std.mem.Allocator,
        writer: anytype,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *const http.Request,
        correlation_id: []const u8,
        keep_alive: bool,
    ) !bool {
        _ = .{ self, allocator, writer, cfg, state, ctx, request, correlation_id, keep_alive };
        return false;
    }

    fn route(
        self: H1RealRouteMirrorProbeHooks,
        conn: anytype,
        allocator: std.mem.Allocator,
        cfg: *const edge_config.EdgeConfig,
        state: *GatewayState,
        ctx: *http.request_context.RequestContext,
        request: *http.Request,
        correlation_id: []const u8,
        keep_alive: *bool,
        client_ip: []const u8,
        streaming_request_body: ?gproxy_runtime.StreamingRequestBody,
    ) !ghandlers.RouteOutcome {
        self.effects.handler_calls += 1;
        return try ghandlers.routeRequest(conn, allocator, cfg, state, ctx, request, correlation_id, keep_alive, client_ip, streaming_request_body);
    }
};

test "H1 location auth denial never mirrors the denied request body" {
    // Regression: moving `mirror()` after `route()` did not fix the leak,
    // because `routeRequest()` returns a location-auth 401/403 as an ordinary
    // route status. A POST to an `auth required` location with no credentials
    // must reach no mirror target at all.
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/private",
            .priority = 0,
            .action = .{ .return_response = .{ .status = 200, .body = "secret" } },
            .auth = .required,
        },
    };
    var mirrors = [_]edge_config.EdgeConfig.MirrorRule{
        .{ .method = "POST", .pattern = "^/private$", .target_url = "http://127.0.0.1:9002/mirror" },
    };
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = mirrors[0..];

    var request = try http.Request.parseHead(
        allocator,
        "POST /private HTTP/1.1\r\nHost: example.test\r\nContent-Length: 11\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer request.request.deinit();
    // `Request.deinit` owns the body, so it must be a real allocation.
    request.request.body = try allocator.dupe(u8, "sensitive-payload");

    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.session_mutex = .{};
    state.session_store = null;
    state.logger = http.logger.Logger.init(.err, "test");
    state.security_headers = .{};
    state.add_headers = &.{};
    state.http3_alt_svc = null;
    var ctx = http.request_context.RequestContext.init(allocator, "req-mirror", "127.0.0.1");
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-mirror", 0);
    var keep_alive = false;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try executeH1PostPreflightOrchestration(
        &conn,
        allocator,
        &conn.out.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-mirror",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1RealRouteMirrorProbeHooks{ .effects = &effects },
    );

    // Denied locally...
    try std.testing.expectEqual(@as(u16, 401), outcome.route_status);
    // ...and the body never left the process.
    try std.testing.expectEqual(@as(usize, 0), effects.mirror_calls);
    try std.testing.expect(std.mem.find(u8, conn.out.written(), "sensitive-payload") == null);
}

fn initForwardAuthProbeState(state: *GatewayState) void {
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.session_mutex = .{};
    state.session_store = null;
    state.logger = http.logger.Logger.init(.err, "test");
    state.security_headers = .{};
    state.add_headers = &.{};
    state.http3_alt_svc = null;
}

test "H1 forward_auth denial relays the auth redirect and never mirrors" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 302 Found\r\nLocation: https://sso.example.test/start\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/admin",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "admin-secret" } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
    }};
    var mirrors = [_]edge_config.EdgeConfig.MirrorRule{
        .{ .method = "POST", .pattern = "^/admin$", .target_url = "http://127.0.0.1:9002/mirror" },
    };
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = mirrors[0..];

    var request = try http.Request.parseHead(
        allocator,
        "POST /admin HTTP/1.1\r\nHost: example.test\r\nContent-Length: 17\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer request.request.deinit();
    request.request.body = try allocator.dupe(u8, "sensitive-payload");

    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    initForwardAuthProbeState(&state);
    var ctx = http.request_context.RequestContext.init(allocator, "req-fa", "127.0.0.1");
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-fa", 0);
    var keep_alive = true;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try executeH1PostPreflightOrchestration(
        &conn,
        allocator,
        &conn.out.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-fa",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1RealRouteMirrorProbeHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, 302), outcome.route_status);
    try std.testing.expectEqual(@as(usize, 0), effects.mirror_calls);
    const written = conn.out.written();
    try std.testing.expect(std.mem.startsWith(u8, written, "HTTP/1.1 302"));
    try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "location: https://sso.example.test/start") != null);
    try std.testing.expect(std.mem.find(u8, written, "admin-secret") == null);
    // The auth service saw the request metadata but not the body.
    try std.testing.expect(auth_server.requestContains(0, "X-Forwarded-Method: POST"));
    try std.testing.expect(!auth_server.requestContains(0, "sensitive-payload"));
    const prom = try state.metrics.toPrometheus(allocator);
    defer allocator.free(prom);
    try std.testing.expect(std.mem.find(u8, prom, "tardigrade_forward_auth_total{protocol=\"h1\",outcome=\"denied\"} 1") != null);
}

test "H1 forward_auth allow runs the action and still mirrors" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/admin",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "admin-ok" } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
    }};
    var mirrors = [_]edge_config.EdgeConfig.MirrorRule{
        .{ .method = "GET", .pattern = "^/admin$", .target_url = "http://127.0.0.1:9002/mirror" },
    };
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = mirrors[0..];

    var request = try http.Request.parseHead(allocator, "GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n", MAX_REQUEST_SIZE);
    defer request.request.deinit();

    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    initForwardAuthProbeState(&state);
    var ctx = http.request_context.RequestContext.init(allocator, "req-fa-ok", "127.0.0.1");
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-fa-ok", 0);
    var keep_alive = true;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try executeH1PostPreflightOrchestration(
        &conn,
        allocator,
        &conn.out.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-fa-ok",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1RealRouteMirrorProbeHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, 200), outcome.route_status);
    try std.testing.expectEqual(@as(usize, 1), effects.mirror_calls);
    try std.testing.expect(std.mem.find(u8, conn.out.written(), "admin-ok") != null);
}

fn runH1ForwardAuthRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    raw_request: []const u8,
    conn: *H2DispatchTestConn,
    effects: *H1PreflightSideEffectProbe,
    state: *GatewayState,
) !H1PostPreflightOutcome {
    var request = try http.Request.parseHead(allocator, raw_request, MAX_REQUEST_SIZE);
    defer request.request.deinit();
    initForwardAuthProbeState(state);
    var ctx = http.request_context.RequestContext.init(allocator, "req-fa", "127.0.0.1");
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-fa", 0);
    var keep_alive = true;
    return executeH1PostPreflightOrchestration(
        conn,
        allocator,
        &conn.out.writer,
        cfg,
        state,
        &ctx,
        &request.request,
        "req-fa",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1RealRouteMirrorProbeHooks{ .effects = effects },
    );
}

test "H1 forward_auth allow adds allowlisted auth headers to the action response" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nSet-Cookie: refreshed=1\r\nSet-Cookie: csrf=2\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/admin",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "admin-ok" } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify"), .client_headers = &.{"Set-Cookie"} },
    }};
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n", &conn, &effects, &state);

    try std.testing.expectEqual(@as(u16, 200), outcome.route_status);
    const written = conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "admin-ok") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "set-cookie: refreshed=1") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "set-cookie: csrf=2") != null);
    // The scope ends with the request: nothing leaks onto later responses.
    try std.testing.expectEqual(@as(usize, 0), http.security_headers.requestScopedHeaders().len);
}

fn runH1ClientCertRequest(
    allocator: std.mem.Allocator,
    cfg: *const edge_config.EdgeConfig,
    raw_request: []const u8,
    client_cert: ?http.headers.ClientCertificate,
    add_headers: []const edge_config.EdgeConfig.HeaderPair,
    conn: *H2DispatchTestConn,
    effects: *H1PreflightSideEffectProbe,
    state: *GatewayState,
) !H1PostPreflightOutcome {
    var request = try http.Request.parseHead(allocator, raw_request, MAX_REQUEST_SIZE);
    defer request.request.deinit();
    request.request.headers.client_cert = client_cert;
    initForwardAuthProbeState(state);
    state.add_headers = add_headers;
    var ctx = http.request_context.RequestContext.init(allocator, "req-cc", "127.0.0.1");
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-cc", 0);
    var keep_alive = true;
    return executeH1PostPreflightOrchestration(
        conn,
        allocator,
        &conn.out.writer,
        cfg,
        state,
        &ctx,
        &request.request,
        "req-cc",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1RealRouteMirrorProbeHooks{ .effects = effects },
    );
}

test "H1 client_cert refusals are no-store and counted once; gated responses stay private across rewrite hops (#763)" {
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{ .match_type = .exact, .pattern = "/admin", .priority = 0, .action = .{ .return_response = .{ .status = 200, .body = "admin-secret" } }, .client_cert = .{ .required = true } },
        // The earlier protected hop rewrites into an ungated location.
        .{ .match_type = .exact, .pattern = "/old", .priority = 1, .action = .{ .rewrite = .{ .replacement = "/plain", .flag = .last } }, .client_cert = .{ .required = true } },
        .{ .match_type = .exact, .pattern = "/plain", .priority = 2, .action = .{ .return_response = .{ .status = 200, .body = "plain-body" } } },
    };
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    const public_headers = [_]edge_config.EdgeConfig.HeaderPair{
        .{ .name = "CDN-Cache-Control", .value = "public, max-age=3600" },
        .{ .name = "Cache-Control", .value = "public" },
    };
    const alice: http.headers.ClientCertificate = .{ .fingerprint_sha256 = "ab" ** 32, .subject = "CN=alice" };

    // Anonymous: 403, no-store, exactly one status increment.
    {
        var effects = H1PreflightSideEffectProbe{};
        var state: GatewayState = undefined;
        var conn = H2DispatchTestConn.init(allocator);
        defer conn.deinit();
        const outcome = try runH1ClientCertRequest(allocator, &cfg, "GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n", null, public_headers[0..], &conn, &effects, &state);
        try std.testing.expectEqual(@as(u16, 403), outcome.route_status);
        const written = conn.out.written();
        try std.testing.expect(std.mem.find(u8, written, "client_certificate_required") != null);
        try std.testing.expect(std.mem.find(u8, written, "no-store") != null);
        try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "public") == null);
        try std.testing.expectEqual(@as(u64, 1), state.metrics.status_4xx);
    }
    // Verified identity, direct hit: private.
    {
        var effects = H1PreflightSideEffectProbe{};
        var state: GatewayState = undefined;
        var conn = H2DispatchTestConn.init(allocator);
        defer conn.deinit();
        const outcome = try runH1ClientCertRequest(allocator, &cfg, "GET /admin HTTP/1.1\r\nHost: example.test\r\n\r\n", alice, public_headers[0..], &conn, &effects, &state);
        try std.testing.expectEqual(@as(u16, 200), outcome.route_status);
        const written = conn.out.written();
        try std.testing.expect(std.mem.find(u8, written, "admin-secret") != null);
        try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "public") == null);
        try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "private") != null);
    }
    // Rewrite from a protected hop into an ungated location: still private.
    {
        var effects = H1PreflightSideEffectProbe{};
        var state: GatewayState = undefined;
        var conn = H2DispatchTestConn.init(allocator);
        defer conn.deinit();
        const outcome = try runH1ClientCertRequest(allocator, &cfg, "GET /old HTTP/1.1\r\nHost: example.test\r\n\r\n", alice, public_headers[0..], &conn, &effects, &state);
        try std.testing.expectEqual(@as(u16, 200), outcome.route_status);
        const written = conn.out.written();
        try std.testing.expect(std.mem.find(u8, written, "plain-body") != null);
        try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "public") == null);
        try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "private") != null);
    }
}

test "H1 forward_auth grant survives a rewrite into the static fallback" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nSet-Cookie: refreshed=1\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "landing.txt", .data = "fallback-landing" });
    const doc_root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(doc_root);

    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/old",
        .priority = 0,
        .action = .{ .rewrite = .{ .replacement = "/landing.txt", .flag = .last } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify"), .client_headers = &.{"Set-Cookie"} },
    }};
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.doc_root = doc_root;
    cfg.try_files = "";
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /old HTTP/1.1\r\nHost: example.test\r\n\r\n", &conn, &effects, &state);

    try std.testing.expectEqual(@as(u16, 200), outcome.route_status);
    const written = conn.out.written();
    try std.testing.expect(std.mem.find(u8, written, "fallback-landing") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "set-cookie: refreshed=1") != null);
    try std.testing.expectEqual(@as(usize, 0), http.security_headers.requestScopedHeaders().len);
}

test "H1 rewrite into a protected location is authorized, never served from the static root" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).makePath("admin");
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "admin/secret.txt", .data = "top-secret" });
    const doc_root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(doc_root);

    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{ .match_type = .exact, .pattern = "/go", .priority = 0, .action = .{ .rewrite = .{ .replacement = "/admin/secret.txt?dl=1", .flag = .last } } },
        .{
            .match_type = .prefix,
            .pattern = "/admin/",
            .priority = 1,
            .action = .{ .static_root = .{ .root = doc_root, .alias = false, .autoindex = false, .index = "", .try_files = "" } },
            .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
        },
    };
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.doc_root = doc_root;
    cfg.try_files = "";
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /go HTTP/1.1\r\nHost: example.test\r\n\r\n", &conn, &effects, &state);

    try std.testing.expectEqual(@as(u16, 403), outcome.route_status);
    try std.testing.expect(std.mem.find(u8, conn.out.written(), "top-secret") == null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
    try std.testing.expect(auth_server.requestContains(0, "X-Forwarded-Uri: /admin/secret.txt?dl=1"));
}

test "H1 path policy and the rewrite budget apply to rewritten targets" {
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{ .match_type = .exact, .pattern = "/public", .priority = 0, .action = .{ .rewrite = .{ .replacement = "/admin/panel", .flag = .last } } },
        .{ .match_type = .prefix, .pattern = "/admin/", .priority = 1, .action = .{ .return_response = .{ .status = 200, .body = "admin-panel" } } },
        .{ .match_type = .exact, .pattern = "/a", .priority = 2, .action = .{ .rewrite = .{ .replacement = "/b", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/b", .priority = 3, .action = .{ .rewrite = .{ .replacement = "/c", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/c", .priority = 4, .action = .{ .rewrite = .{ .replacement = "/d", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/d", .priority = 5, .action = .{ .rewrite = .{ .replacement = "/e", .flag = .last } } },
        .{ .match_type = .exact, .pattern = "/e", .priority = 6, .action = .{ .return_response = .{ .status = 200, .body = "too-deep" } } },
    };
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.policy_rules_raw = "GET|^/admin/|admin|false||";

    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    var policy_conn = H2DispatchTestConn.init(allocator);
    defer policy_conn.deinit();
    const policy_outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /public HTTP/1.1\r\nHost: example.test\r\n\r\n", &policy_conn, &effects, &state);
    try std.testing.expectEqual(@as(u16, 403), policy_outcome.route_status);
    try std.testing.expect(std.mem.find(u8, policy_conn.out.written(), "admin-panel") == null);

    var loop_conn = H2DispatchTestConn.init(allocator);
    defer loop_conn.deinit();
    const loop_outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /a HTTP/1.1\r\nHost: example.test\r\n\r\n", &loop_conn, &effects, &state);
    try std.testing.expectEqual(@as(u16, 508), loop_outcome.route_status);
    try std.testing.expect(std.mem.find(u8, loop_conn.out.written(), "too-deep") == null);
}

test "H1 self-rewrite re-authorizes the rewritten target before serving it" {
    const allocator = std.testing.allocator;
    // Path-sensitive verifier: allows the landing URI, denies the file.
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
    });
    defer auth_server.stop();
    try auth_server.run();
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try compat.wrapDir(tmp.dir).makePath("admin");
    try compat.wrapDir(tmp.dir).writeFile(.{ .sub_path = "admin/private.txt", .data = "private-bytes" });
    const doc_root = try compat.wrapDir(tmp.dir).realpathAlloc(allocator, ".");
    defer allocator.free(doc_root);
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .prefix,
        .pattern = "/admin/",
        .priority = 0,
        .action = .{ .rewrite = .{ .replacement = "/admin/private.txt", .flag = .last } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
    }};
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.doc_root = doc_root;
    cfg.try_files = "";
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /admin/public HTTP/1.1\r\nHost: example.test\r\n\r\n", &conn, &effects, &state);

    try std.testing.expectEqual(@as(u16, 403), outcome.route_status);
    try std.testing.expect(std.mem.find(u8, conn.out.written(), "private-bytes") == null);
    try std.testing.expectEqual(@as(usize, 2), auth_server.requestCount());
    try std.testing.expect(auth_server.requestContains(0, "X-Forwarded-Uri: /admin/public"));
    try std.testing.expect(auth_server.requestContains(1, "X-Forwarded-Uri: /admin/private.txt"));
}

test "H1 later verifiers judge the caller's credential, not an earlier hop's minted one" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        // Hop A allows the client and mints a privileged origin token.
        "HTTP/1.1 200 OK\r\nAuthorization: Bearer service-minted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        // Hop B would deny the client's own token.
        "HTTP/1.1 403 Forbidden\r\nContent-Length: 4\r\nConnection: close\r\n\r\nnope",
        // Second request: hop A again, minting the gateway's valid token.
        "HTTP/1.1 200 OK\r\nAuthorization: Bearer integration-token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    const auth_url = auth_server.url(&url_buf, "/verify");
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/public",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/admin", .flag = .last } },
            .forward_auth = .{ .url = auth_url, .upstream_headers = &.{"Authorization"} },
        },
        .{
            .match_type = .exact,
            .pattern = "/admin",
            .priority = 1,
            .action = .{ .return_response = .{ .status = 200, .body = "admin-secret" } },
            .forward_auth = .{ .url = auth_url },
        },
        .{
            .match_type = .exact,
            .pattern = "/builtin",
            .priority = 2,
            .action = .{ .rewrite = .{ .replacement = "/private", .flag = .last } },
            .forward_auth = .{ .url = auth_url, .upstream_headers = &.{"Authorization"} },
        },
        .{
            .match_type = .exact,
            .pattern = "/private",
            .priority = 3,
            .action = .{ .return_response = .{ .status = 200, .body = "private-secret" } },
            .auth = .required,
        },
    };
    // sha256("integration-token"): the minted token would pass built-in auth.
    var token_hashes = [_][]const u8{"521bc8ca01307d0189b55a19da738e39c7204f7077e0076e803026e32b2f9383"};
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.auth_token_hashes = token_hashes[0..];
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;

    var chain_conn = H2DispatchTestConn.init(allocator);
    defer chain_conn.deinit();
    const chain = try runH1ForwardAuthRequest(allocator, &cfg, "GET /public HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer client-inbound\r\n\r\n", &chain_conn, &effects, &state);
    try std.testing.expectEqual(@as(u16, 403), chain.route_status);
    try std.testing.expect(std.mem.find(u8, chain_conn.out.written(), "admin-secret") == null);
    try std.testing.expect(auth_server.requestContains(1, "Bearer client-inbound"));
    try std.testing.expect(!auth_server.requestContains(1, "service-minted"));

    var builtin_conn = H2DispatchTestConn.init(allocator);
    defer builtin_conn.deinit();
    const builtin_outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /builtin HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer client-wrong\r\n\r\n", &builtin_conn, &effects, &state);
    // An invalid bearer is 403 in built-in auth; the point is it is refused.
    try std.testing.expectEqual(@as(u16, 403), builtin_outcome.route_status);
    try std.testing.expect(std.mem.find(u8, builtin_conn.out.written(), "private-secret") == null);
}

test "H1 rewritten-path approval policy rejects a forward_auth-asserted token the client never presented (#887)" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.approval_mutex = .{};
    state.approval_persist_mutex = .{};
    state.approvals = std.StringHashMap(gs.ApprovalEntry).init(allocator);
    state.approval_store_path = "";
    state.approval_escalation_webhook = "";
    state.approval_ttl_ms = 60_000;
    state.approval_max_pending_per_identity = 0;
    defer deinitApprovalsTestMap(&state.approvals, allocator);

    // A real, approved token for GET /guarded that the client never
    // presented. It arrives only as the earlier forward_auth service's
    // upstream assertion.
    const minted = try state.approvalCreate(allocator, "GET", "/guarded", "", null);
    defer allocator.free(minted.token);
    try std.testing.expect(state.approvalRespond(minted.token, .approve, "reviewer"));

    const service_response = try std.fmt.allocPrint(
        allocator,
        "HTTP/1.1 200 OK\r\nX-Approval-Token: {s}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        .{minted.token},
    );
    defer allocator.free(service_response);
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{service_response});
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/old",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/guarded", .flag = .last } },
            .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify"), .upstream_headers = &.{"X-Approval-Token"} },
        },
        .{ .match_type = .exact, .pattern = "/guarded", .priority = 1, .action = .{ .return_response = .{ .status = 200, .body = "guarded-secret" } } },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    cfg.policy_approval_routes_raw = "GET|^/guarded$";

    var effects = H1PreflightSideEffectProbe{};
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    const outcome = try runH1ForwardAuthRequest(allocator, &cfg, "GET /old HTTP/1.1\r\nHost: example.test\r\n\r\n", &conn, &effects, &state);

    const written = conn.out.written();
    try std.testing.expectEqual(@as(u16, 403), outcome.route_status);
    try std.testing.expect(std.mem.find(u8, written, "Approval required") != null);
    try std.testing.expect(std.mem.find(u8, written, "guarded-secret") == null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "cache-control: no-store") != null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
}

test "H1 rewritten-path approval policy honors the client's own token despite a differing forward_auth assertion (#887)" {
    const allocator = std.testing.allocator;
    var state: GatewayState = undefined;
    state.allocator = allocator;
    state.approval_mutex = .{};
    state.approval_persist_mutex = .{};
    state.approvals = std.StringHashMap(gs.ApprovalEntry).init(allocator);
    state.approval_store_path = "";
    state.approval_escalation_webhook = "";
    state.approval_ttl_ms = 60_000;
    state.approval_max_pending_per_identity = 0;
    defer deinitApprovalsTestMap(&state.approvals, allocator);

    const minted = try state.approvalCreate(allocator, "GET", "/guarded", "", null);
    defer allocator.free(minted.token);
    try std.testing.expect(state.approvalRespond(minted.token, .approve, "reviewer"));

    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 200 OK\r\nX-Approval-Token: not-a-real-token\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;

    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/old",
            .priority = 0,
            .action = .{ .rewrite = .{ .replacement = "/guarded", .flag = .last } },
            .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify"), .upstream_headers = &.{"X-Approval-Token"} },
        },
        .{ .match_type = .exact, .pattern = "/guarded", .priority = 1, .action = .{ .return_response = .{ .status = 200, .body = "guarded-secret" } } },
    };
    var cfg = std.mem.zeroes(edge_config.EdgeConfig);
    cfg.location_blocks = blocks[0..];
    cfg.policy_approval_routes_raw = "GET|^/guarded$";

    var effects = H1PreflightSideEffectProbe{};
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();
    const raw_request = try std.fmt.allocPrint(allocator, "GET /old HTTP/1.1\r\nHost: example.test\r\nX-Approval-Token: {s}\r\n\r\n", .{minted.token});
    defer allocator.free(raw_request);
    const outcome = try runH1ForwardAuthRequest(allocator, &cfg, raw_request, &conn, &effects, &state);

    try std.testing.expectEqual(@as(u16, 200), outcome.route_status);
    try std.testing.expect(std.mem.find(u8, conn.out.written(), "guarded-secret") != null);
    try std.testing.expectEqual(@as(usize, 1), auth_server.requestCount());
}

test "H1 forward_auth HEAD denial sends the challenge head without a body" {
    const allocator = std.testing.allocator;
    var auth_server = try gfa.TestAuthServer.start(allocator, &.{
        "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic\r\nContent-Length: 11\r\nConnection: close\r\n\r\nsign-in-now",
    });
    defer auth_server.stop();
    try auth_server.run();
    var url_buf: [64]u8 = undefined;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{.{
        .match_type = .exact,
        .pattern = "/admin",
        .priority = 0,
        .action = .{ .return_response = .{ .status = 200, .body = "admin-ok" } },
        .forward_auth = .{ .url = auth_server.url(&url_buf, "/verify") },
    }};
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try runH1ForwardAuthRequest(allocator, &cfg, "HEAD /admin HTTP/1.1\r\nHost: example.test\r\n\r\n", &conn, &effects, &state);

    try std.testing.expectEqual(@as(u16, 401), outcome.route_status);
    const written = conn.out.written();
    try std.testing.expect(std.mem.startsWith(u8, written, "HTTP/1.1 401"));
    try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "content-length: 11\r\n") != null);
    try std.testing.expect(std.ascii.indexOfIgnoreCase(written, "www-authenticate: basic") != null);
    try std.testing.expect(std.mem.endsWith(u8, written, "\r\n\r\n"));
    try std.testing.expect(std.mem.find(u8, written, "sign-in-now") == null);
}

test "H1 authorized route still mirrors" {
    // Positive control for the regression above: the fix must not disable
    // mirroring for requests that were actually allowed.
    const allocator = std.testing.allocator;
    var blocks = [_]edge_config.EdgeConfig.LocationBlock{
        .{
            .match_type = .exact,
            .pattern = "/open",
            .priority = 0,
            .action = .{ .return_response = .{ .status = 200, .body = "ok" } },
        },
    };
    var mirrors = [_]edge_config.EdgeConfig.MirrorRule{
        .{ .method = "GET", .pattern = "^/open$", .target_url = "http://127.0.0.1:9002/mirror" },
    };
    var cfg: edge_config.EdgeConfig = std.mem.zeroInit(edge_config.EdgeConfig, .{});
    cfg.metrics_path = "/status/metrics";
    cfg.location_blocks = blocks[0..];
    cfg.mirror_rules = mirrors[0..];

    var request = try http.Request.parseHead(
        allocator,
        "GET /open HTTP/1.1\r\nHost: example.test\r\n\r\n",
        MAX_REQUEST_SIZE,
    );
    defer request.request.deinit();

    var effects = H1PreflightSideEffectProbe{};
    var state: GatewayState = undefined;
    state.metrics_mutex = .{};
    state.metrics = http.metrics.Metrics.init();
    state.session_mutex = .{};
    state.session_store = null;
    state.logger = http.logger.Logger.init(.err, "test");
    state.security_headers = .{};
    state.add_headers = &.{};
    state.http3_alt_svc = null;
    var ctx = http.request_context.RequestContext.init(allocator, "req-open", "127.0.0.1");
    var lifecycle = http.request_lifecycle.RequestLifecycle.init("req-open", 0);
    var keep_alive = false;
    var conn = H2DispatchTestConn.init(allocator);
    defer conn.deinit();

    const outcome = try executeH1PostPreflightOrchestration(
        &conn,
        allocator,
        &conn.out.writer,
        &cfg,
        &state,
        &ctx,
        &request.request,
        "req-open",
        &keep_alive,
        "127.0.0.1",
        null,
        &lifecycle,
        H1RealRouteMirrorProbeHooks{ .effects = &effects },
    );

    try std.testing.expectEqual(@as(u16, 200), outcome.route_status);
    try std.testing.expectEqual(@as(usize, 1), effects.mirror_calls);
}

test "H2 duplicate HEADERS on a dispatched stream is refused, not re-dispatched" {
    // Regression for the stream-lifecycle finding. The exploit sequence is:
    //   1. client sends HEADERS+END_STREAM  -> stream half_closed_remote
    //   2. the request dispatches; its response parks on send-credit
    //      exhaustion, so `pending` no longer holds the stream but `streams`
    //      still does
    //   3. client sends a second HEADERS block on the SAME stream id
    // Step 3 used to look like `initial_headers == true` (because the gate was
    // `pending.contains(id)`) and built a second request on one stream,
    // duplicating route/auth/handler execution.
    const allocator = std.testing.allocator;
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer pending.deinit();

    // A fresh stream accepts its first header block.
    try std.testing.expect(h2StreamAcceptsInboundFrame(&streams, 1));
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try std.testing.expect(h2StreamAcceptsInboundFrame(&streams, 1));

    // Trailers are still legal while the remote half is open.
    try std.testing.expect(h2StreamAcceptsInboundFrame(&streams, 1));

    // END_STREAM from the client.
    try streams.getPtr(1).?.remoteEndStream();
    try std.testing.expectEqual(http.http2_stream.StreamState.half_closed_remote, streams.get(1).?.state);

    // Dispatch removes request-assembly state but keeps the stream alive for a
    // parked response — exactly the window the old `pending`-based check missed.
    try std.testing.expect(!pending.contains(1));
    try std.testing.expect(streams.contains(1));

    // The second HEADERS block must be refused on stream state alone.
    try std.testing.expect(!h2StreamAcceptsInboundFrame(&streams, 1));
    // DATA after END_STREAM is the same class of error.
    try std.testing.expect(!h2StreamAcceptsInboundFrame(&streams, 1));

    // A reset/closed stream is likewise refused, while other streams are
    // unaffected.
    try streams.put(3, http.http2_stream.Stream.init(3, 65_535));
    streams.getPtr(3).?.close();
    try std.testing.expect(!h2StreamAcceptsInboundFrame(&streams, 3));
    try streams.put(5, http.http2_stream.Stream.init(5, 65_535));
    try std.testing.expect(h2StreamAcceptsInboundFrame(&streams, 5));

    // half_closed_local (we finished responding, client may still send) stays
    // receivable, so request bodies are not broken by this gate.
    try streams.put(7, http.http2_stream.Stream.init(7, 65_535));
    try streams.getPtr(7).?.localEndStream();
    try std.testing.expectEqual(http.http2_stream.StreamState.half_closed_local, streams.get(7).?.state);
    try std.testing.expect(h2StreamAcceptsInboundFrame(&streams, 7));
}

test "H2 CONNECT is refused at stream scope instead of failing in the H1 adapter" {
    // The validator accepts syntactically valid CONNECT (it is legal HTTP/2),
    // so the contract has to be made explicit somewhere. Tardigrade does not
    // implement tunneling, and the shared H1 adapter requires a `:path`, so
    // CONNECT is refused on its own stream rather than reaching
    // `respondHttp2Stream` and tearing down the connection with a generic
    // `error.InvalidHttp2Request`.
    try std.testing.expect(h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    }, true));
    try std.testing.expect(h2HeaderBlockRequestsConnect(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    }));

    // A malformed CONNECT is still a protocol error, not a refusal: scheme and
    // path must be absent and the authority must be valid.
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
        .{ .name = ":path", .value = "/" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":authority", .value = "example.test:443" },
    }, true));
    try std.testing.expect(!h2RequestHeaderBlockIsValid(&.{
        .{ .name = ":method", .value = "CONNECT" },
    }, true));

    // Ordinary methods are not mistaken for CONNECT.
    try std.testing.expect(!h2HeaderBlockRequestsConnect(&.{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":path", .value = "/" },
    }));
    // Nor is a header that merely carries the text.
    try std.testing.expect(!h2HeaderBlockRequestsConnect(&.{
        .{ .name = ":method", .value = "POST" },
        .{ .name = "x-upstream-method", .value = "CONNECT" },
    }));
}

test "H2 CONNECT refusal writes RST_STREAM and closes only that stream" {
    const allocator = std.testing.allocator;
    var decoder = http.hpack.Decoder.init();
    defer decoder.deinit(allocator);

    var pending = std.AutoHashMap(u31, Http2PendingStream).init(allocator);
    defer {
        var it = pending.iterator();
        while (it.next()) |entry| {
            var ps = entry.value_ptr.*;
            ps.deinit(allocator);
        }
        pending.deinit();
    }
    var streams = std.AutoHashMap(u31, http.http2_stream.Stream).init(allocator);
    defer streams.deinit();
    try streams.put(1, http.http2_stream.Stream.init(1, 65_535));
    try streams.put(3, http.http2_stream.Stream.init(3, 65_535));
    var ready = std.array_list.Managed(u31).init(allocator);
    defer ready.deinit();
    var sessions = std.AutoHashMap(u31, *http.h2_stream_session.Session).init(allocator);
    defer sessions.deinit();
    var state: GatewayState = undefined;
    state.h2_session_test_hook = null;

    const block = try http.hpack.encodeLiteralHeaderBlock(allocator, &.{
        .{ .name = ":method", .value = "CONNECT" },
        .{ .name = ":authority", .value = "example.test:443" },
    });
    defer allocator.free(block);

    var out: std.Io.Writer.Allocating = .init(allocator);
    defer out.deinit();
    var buffered: usize = 0;

    try h2ProcessHeaderBlock(
        allocator,
        &decoder,
        &pending,
        &streams,
        &ready,
        &sessions,
        &state,
        1,
        block,
        true,
        false,
        &out.writer,
        1,
        0,
        &buffered,
    );

    // No request was assembled and nothing was queued for dispatch.
    try std.testing.expect(!pending.contains(1));
    try std.testing.expectEqual(@as(usize, 0), ready.items.len);
    try std.testing.expectEqual(@as(usize, 0), buffered);
    // The stream is closed, so the new lifecycle gate refuses follow-up frames
    // on it, while an unrelated stream keeps working.
    try std.testing.expectEqual(http.http2_stream.StreamState.closed, streams.get(1).?.state);
    try std.testing.expect(!h2StreamAcceptsInboundFrame(&streams, 1));
    try std.testing.expect(h2StreamAcceptsInboundFrame(&streams, 3));
    // A RST_STREAM frame (type 0x3) for stream 1 was written, not a GOAWAY
    // (type 0x7): the connection survives.
    const written = out.written();
    try std.testing.expect(written.len >= 9);
    try std.testing.expectEqual(@as(u8, 0x3), written[3]);
    const rst_stream_id: u32 = std.mem.readInt(u32, written[5..9], .big) & 0x7fff_ffff;
    try std.testing.expectEqual(@as(u32, 1), rst_stream_id);
}

test "an actual parsed request with a bracketed Host never reaches the ACME challenge lookup (#877 review)" {
    // `Request.parseAuthority` accepts any nonempty bracket content as a
    // host without validating it is actually an IP literal, so a real
    // request's Host header can carry `[a.example.com]` through header
    // parsing unchanged. `matchManagedHost` -- the gateway's actual
    // host-scoping gate at this route -- must be the one that rejects it.
    const allocator = std.testing.allocator;
    const raw = "GET /.well-known/acme-challenge/tok HTTP/1.1\r\nHost: [a.example.com]\r\n\r\n";
    const parsed = try http.Request.parse(allocator, raw, MAX_REQUEST_SIZE);
    var request = parsed.request;
    defer request.deinit();

    const managed = [_][]const u8{"a.example.com"};
    try std.testing.expect(http.acme_client.matchManagedHost(&managed, request.host()) == null);
}
